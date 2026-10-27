package com.aegis.core;

import java.io.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Reads IP packets that carry DNS queries, filters them and writes IP packets back.
 * Nothing is persisted: counters and the recent-events list live in memory only. The list holds only names that were blocked or that matched a warn-only threat listing, never ordinary allowed lookups.
 */
public final class DnsProxy implements Closeable {
    public interface PacketSink { void write(byte[] packet, int length) throws IOException; }
    public record Event(Instant time, String name, DnsFilter.Reason reason, DnsFilter.Action action, boolean warnOnly,
                        ThreatDatabase.Category category, ThreatDatabase.Confidence confidence) {}

    public static final int MAX_EVENTS = 200;
    private static final int MTU_PAYLOAD = 1232;

    public final AtomicLong queries = new AtomicLong(), blocked = new AtomicLong(), warned = new AtomicLong(),
        forwarded = new AtomicLong(), failed = new AtomicLong(), dropped = new AtomicLong();

    private final DnsFilter filter;
    private final DnsUpstream upstream;
    private final PacketSink sink;
    private final byte[] dns4, dns6;
    private final java.time.Clock clock;
    private final ThreadPoolExecutor pool;
    private final Deque<Event> events = new ArrayDeque<>();
    private volatile boolean closed;

    public DnsProxy(DnsFilter filter, DnsUpstream upstream, PacketSink sink, byte[] dns4, byte[] dns6, java.time.Clock clock) {
        this.filter = filter; this.upstream = upstream; this.sink = sink; this.dns4 = dns4; this.dns6 = dns6; this.clock = clock;
        this.pool = new ThreadPoolExecutor(2, 8, 20, TimeUnit.SECONDS, new ArrayBlockingQueue<>(64), r -> {
            Thread t = new Thread(r, "aegis-dns-upstream"); t.setDaemon(true); return t;
        }, new ThreadPoolExecutor.AbortPolicy());
        pool.allowCoreThreadTimeOut(true);
    }

    public synchronized List<Event> recentEvents() { return Collections.unmodifiableList(new ArrayList<>(events)); }

    private synchronized void record(Event e) {
        if (events.size() >= MAX_EVENTS) events.removeFirst();
        events.addLast(e);
    }

    /** Blocking read loop; returns at end of stream or after close(). */
    public void run(InputStream tun) throws IOException {
        byte[] buf = new byte[32768];
        while (!closed) {
            int n = tun.read(buf);
            if (n < 0) return;
            if (n > 0) handlePacket(buf, n);
        }
    }

    public void handlePacket(byte[] packet, int length) {
        Optional<IpPacket.DnsRequest> parsed = IpPacket.parseDns(packet, length, dns4, dns6);
        if (!parsed.isPresent()) { dropped.incrementAndGet(); return; }
        IpPacket.DnsRequest req = parsed.get();
        Optional<DnsMessage.Question> q = DnsMessage.parseQuery(req.payload, req.payload.length);
        if (!q.isPresent()) { dropped.incrementAndGet(); return; }
        queries.incrementAndGet();
        DnsFilter.Decision d = filter.decide(q.get().name());
        if (d.action() == DnsFilter.Action.BLOCK) {
            blocked.incrementAndGet();
            record(event(q.get().name(), d));
            reply(req, DnsMessage.errorResponse(req.payload, q.get(), DnsMessage.RCODE_NXDOMAIN));
            return;
        }
        if (d.warnOnly()) { warned.incrementAndGet(); record(event(q.get().name(), d)); }
        try {
            pool.execute(() -> forward(req, q.get()));
        } catch (RejectedExecutionException overloaded) {
            // Never block the packet loop. Answer SERVFAIL at once so the client moves on instead of waiting out its
            // timeout, which keeps one slow resolver from stalling every app's lookups for seconds.
            dropped.incrementAndGet();
            reply(req, DnsMessage.errorResponse(req.payload, q.get(), DnsMessage.RCODE_SERVFAIL));
        }
    }

    private Event event(String name, DnsFilter.Decision d) {
        return new Event(clock.instant(), name, d.reason(), d.action(), d.warnOnly(),
            d.entry() == null ? null : d.entry().category(), d.entry() == null ? null : d.entry().confidence());
    }

    private void forward(IpPacket.DnsRequest req, DnsMessage.Question q) {
        try {
            byte[] r = upstream.resolve(req.payload);
            if (!DnsMessage.matchesQuery(r, r.length, req.payload, q)) throw new IOException("mismatched DNS response");
            forwarded.incrementAndGet();
            reply(req, DnsMessage.fit(r, r.length, q, MTU_PAYLOAD));
        } catch (IOException | RuntimeException e) {
            failed.incrementAndGet();
            reply(req, DnsMessage.errorResponse(req.payload, q, DnsMessage.RCODE_SERVFAIL));
        }
    }

    private void reply(IpPacket.DnsRequest req, byte[] dnsPayload) {
        if (closed) return;
        byte[] out = IpPacket.buildResponse(req, dnsPayload);
        try { synchronized (sink) { sink.write(out, out.length); } } catch (IOException ignored) { dropped.incrementAndGet(); }
    }

    @Override public void close() { closed = true; pool.shutdownNow(); }
}
