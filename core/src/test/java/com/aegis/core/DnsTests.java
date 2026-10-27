package com.aegis.core;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

public final class DnsTests {
    private static int checks;
    private static void check(boolean ok, String message) { checks++; if (!ok) throw new AssertionError(message); }
    private static final byte[] DNS4 = {10, 111, (byte) 222, 2};
    private static final byte[] DNS6 = {(byte) 0xfd, 0, (byte) 0xae, (byte) 0x91, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    private static final byte[] CLIENT4 = {10, 111, (byte) 222, 1};
    private static final byte[] CLIENT6 = {(byte) 0xfd, 0, (byte) 0xae, (byte) 0x91, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

    // ---- independent packet construction/verification so the production code is not checked against itself
    private static byte[] packet4(byte[] dst, int dstPort, byte[] dns) {
        byte[] p = new byte[28 + dns.length];
        p[0] = 0x45; p[2] = (byte) (p.length >> 8); p[3] = (byte) p.length; p[8] = 64; p[9] = 17;
        System.arraycopy(CLIENT4, 0, p, 12, 4); System.arraycopy(dst, 0, p, 16, 4);
        p[20] = (byte) 0xC3; p[21] = 0x50; p[22] = (byte) (dstPort >> 8); p[23] = (byte) dstPort;
        int ul = 8 + dns.length; p[24] = (byte) (ul >> 8); p[25] = (byte) ul;
        System.arraycopy(dns, 0, p, 28, dns.length);
        return p;
    }
    private static byte[] packet6(byte[] dst, int dstPort, byte[] dns) {
        byte[] p = new byte[48 + dns.length];
        p[0] = 0x60; int ul = 8 + dns.length; p[4] = (byte) (ul >> 8); p[5] = (byte) ul; p[6] = 17; p[7] = 64;
        System.arraycopy(CLIENT6, 0, p, 8, 16); System.arraycopy(dst, 0, p, 24, 16);
        p[40] = (byte) 0xC3; p[41] = 0x50; p[42] = (byte) (dstPort >> 8); p[43] = (byte) dstPort; p[44] = (byte) (ul >> 8); p[45] = (byte) ul;
        System.arraycopy(dns, 0, p, 48, dns.length);
        return p;
    }
    private static int onesComplementSum(byte[] b, int off, int len, long seed) {
        long s = seed;
        for (int i = 0; i + 1 < len; i += 2) s += ((b[off + i] & 0xFF) << 8) | (b[off + i + 1] & 0xFF);
        if ((len & 1) == 1) s += (b[off + len - 1] & 0xFF) << 8;
        while ((s >>> 16) != 0) s = (s & 0xFFFF) + (s >>> 16);
        return (int) s;
    }
    /** True when checksums of a response packet verify (sum over pseudo-header + segment is 0xFFFF). */
    private static boolean checksumsValid(byte[] p) {
        if ((p[0] >> 4) == 4) {
            if (onesComplementSum(p, 0, 20, 0) != 0xFFFF) return false;
            int ul = p.length - 20;
            long ph = 0; for (int i = 12; i < 20; i += 2) ph += ((p[i] & 0xFF) << 8) | (p[i + 1] & 0xFF);
            ph += 17 + ul;
            return onesComplementSum(p, 20, ul, ph) == 0xFFFF;
        }
        int ul = p.length - 40;
        long ph = 0; for (int i = 8; i < 40; i += 2) ph += ((p[i] & 0xFF) << 8) | (p[i + 1] & 0xFF);
        ph += 17 + ul;
        return onesComplementSum(p, 40, ul, ph) == 0xFFFF;
    }
    private static int rcodeOfPacket(byte[] p) { int off = (p[0] >> 4) == 4 ? 28 : 48; return p[off + 3] & 0xF; }
    private static byte[] dnsOf(byte[] p) { int off = (p[0] >> 4) == 4 ? 28 : 48; return Arrays.copyOfRange(p, off, p.length); }

    private static DnsFilter filterWith(String... entries) throws Exception {
        var kp = ThreatBundleTool.generateKey();
        var anchors = new ThreatBundleVerifier.TrustAnchors();
        String id = anchors.add(kp.getPublic().getEncoded());
        Instant now = Instant.now();
        byte[] b = ThreatBundleTool.build(kp.getPrivate(), id, 1, now, now.plusSeconds(86400), Arrays.asList(entries));
        ThreatDatabase db = ThreatBundleVerifier.verify(b, anchors, new ThreatBundleVerifier.Policy(0, true, now));
        return new DnsFilter(new ReputationProvider.LocalDatabase(() -> db), new DnsFilter.DomainLists());
    }

    public static void main(String[] args) throws Exception {
        messages(); ipPackets(); filter(); upstream(); proxy();
        System.out.println("DnsTests: " + checks + " checks passed");
    }

    private static boolean accepts(byte[] q) { return DnsMessage.parseQuery(q, q.length).isPresent(); }

    private static void messages() {
        byte[] q = DnsMessage.buildQuery(0x1234, "Evil.Example.COM", 1);
        var parsed = DnsMessage.parseQuery(q, q.length);
        check(parsed.isPresent() && parsed.get().name().equals("evil.example.com") && parsed.get().type() == 1 && parsed.get().qclass() == 1, "basic parse");
        check(DnsMessage.parseQuery(q, q.length - 1).isEmpty(), "truncated question");
        check(DnsMessage.parseQuery(q, 16).isEmpty() && DnsMessage.parseQuery(null, 0).isEmpty(), "too short");
        byte[] resp = q.clone(); resp[2] |= (byte) 0x80;
        check(DnsMessage.parseQuery(resp, resp.length).isEmpty(), "response flag rejected");
        byte[] op = q.clone(); op[2] |= 0x08;
        check(DnsMessage.parseQuery(op, op.length).isEmpty(), "non-QUERY opcode rejected");
        byte[] two = q.clone(); two[5] = 2;
        check(DnsMessage.parseQuery(two, two.length).isEmpty(), "qdcount 2 rejected");
        byte[] an = q.clone(); an[7] = 1;
        check(DnsMessage.parseQuery(an, an.length).isEmpty(), "answers in query rejected");
        byte[] ptr = q.clone(); ptr[12] = (byte) 0xC0;
        check(DnsMessage.parseQuery(ptr, ptr.length).isEmpty(), "compression pointer rejected");
        byte[] bad = q.clone(); bad[13] = (byte) 0xE9;
        check(DnsMessage.parseQuery(bad, bad.length).isEmpty(), "non-ascii byte rejected");
        byte[] space = q.clone(); space[13] = ' ';
        check(DnsMessage.parseQuery(space, space.length).isEmpty(), "space in label rejected");
        check(accepts(DnsMessage.buildQuery(1, "a".repeat(63) + ".example", 1)), "63-char label accepted");
        StringBuilder longName = new StringBuilder(); for (int i = 0; i < 30; i++) longName.append("abcdefghi.");
        byte[] lq = DnsMessage.buildQuery(1, longName + "com", 1);
        check(DnsMessage.parseQuery(lq, lq.length).isEmpty(), "name over 253 rejected");
        check(accepts(DnsMessage.buildQuery(1, "_dmarc.example.com", 16)), "underscore labels are legal");
        byte[] nxd = DnsMessage.errorResponse(q, parsed.get(), DnsMessage.RCODE_NXDOMAIN);
        check(nxd[0] == q[0] && nxd[1] == q[1] && (nxd[2] & 0x80) != 0 && (nxd[2] & 1) == 1 && (nxd[3] & 0xF) == 3 && (nxd[3] & 0x80) != 0, "NXDOMAIN flags/id/RD/RA");
        check(nxd.length == q.length && DnsMessage.u16(nxd, 4) == 1 && DnsMessage.u16(nxd, 6) == 0 && DnsMessage.u16(nxd, 10) == 0, "NXDOMAIN counts");
        check(DnsMessage.matchesQuery(nxd, nxd.length, q, parsed.get()), "own response matches");
        byte[] wrongId = nxd.clone(); wrongId[1] ^= 1;
        check(!DnsMessage.matchesQuery(wrongId, wrongId.length, q, parsed.get()), "wrong ID rejected");
        byte[] notResp = nxd.clone(); notResp[2] &= 0x7F;
        check(!DnsMessage.matchesQuery(notResp, notResp.length, q, parsed.get()), "non-response rejected");
        byte[] oq = DnsMessage.buildQuery(0x1234, "other.example.com", 1);
        byte[] otherName = DnsMessage.errorResponse(oq, DnsMessage.parseQuery(oq, oq.length).get(), 0);
        check(!DnsMessage.matchesQuery(otherName, otherName.length, q, parsed.get()), "different question rejected");
        byte[] mixed = nxd.clone(); mixed[13] = (byte) Character.toUpperCase(mixed[13]);
        check(DnsMessage.matchesQuery(mixed, mixed.length, q, parsed.get()), "0x20 case randomisation tolerated");
        byte[] big = Arrays.copyOf(nxd, 3000);
        byte[] fitted = DnsMessage.fit(big, big.length, parsed.get(), 1232);
        check(fitted.length == q.length && (fitted[2] & 2) != 0, "oversized answer becomes truncated header+question");
        check(DnsMessage.fit(nxd, nxd.length, parsed.get(), 1232).length == nxd.length, "small answer unchanged");
    }

    private static void ipPackets() {
        byte[] dns = DnsMessage.buildQuery(7, "example.com", 1);
        var v4 = IpPacket.parseDns(packet4(DNS4, 53, dns), 28 + dns.length, DNS4, DNS6);
        check(v4.isPresent() && Arrays.equals(v4.get().payload, dns) && v4.get().srcPort == 0xC350, "v4 parse");
        var v6 = IpPacket.parseDns(packet6(DNS6, 53, dns), 48 + dns.length, DNS4, DNS6);
        check(v6.isPresent() && Arrays.equals(v6.get().payload, dns) && v6.get().version == 6, "v6 parse");
        check(IpPacket.parseDns(packet4(new byte[] {8, 8, 8, 8}, 53, dns), 28 + dns.length, DNS4, DNS6).isEmpty(), "other v4 destination ignored");
        check(IpPacket.parseDns(packet4(DNS4, 80, dns), 28 + dns.length, DNS4, DNS6).isEmpty(), "non-53 port ignored");
        byte[] tcp = packet4(DNS4, 53, dns); tcp[9] = 6;
        check(IpPacket.parseDns(tcp, tcp.length, DNS4, DNS6).isEmpty(), "TCP ignored");
        byte[] frag = packet4(DNS4, 53, dns); frag[6] = 0x20;
        check(IpPacket.parseDns(frag, frag.length, DNS4, DNS6).isEmpty(), "more-fragments rejected");
        byte[] fragOff = packet4(DNS4, 53, dns); fragOff[7] = 5;
        check(IpPacket.parseDns(fragOff, fragOff.length, DNS4, DNS6).isEmpty(), "fragment offset rejected");
        byte[] ihl = packet4(DNS4, 53, dns); ihl[0] = 0x44;
        check(IpPacket.parseDns(ihl, ihl.length, DNS4, DNS6).isEmpty(), "bad IHL rejected");
        byte[] total = packet4(DNS4, 53, dns); total[2] = 0x7F;
        check(IpPacket.parseDns(total, total.length, DNS4, DNS6).isEmpty(), "total length beyond buffer rejected");
        byte[] udpLen = packet4(DNS4, 53, dns); udpLen[24] = 0x7F;
        check(IpPacket.parseDns(udpLen, udpLen.length, DNS4, DNS6).isEmpty(), "udp length beyond packet rejected");
        byte[] ext = packet6(DNS6, 53, dns); ext[6] = 0;
        check(IpPacket.parseDns(ext, ext.length, DNS4, DNS6).isEmpty(), "ipv6 extension header rejected");
        byte[] ver = packet4(DNS4, 53, dns); ver[0] = 0x55;
        check(IpPacket.parseDns(ver, ver.length, DNS4, DNS6).isEmpty(), "bad version rejected");
        byte[] resp4 = IpPacket.buildResponse(v4.get(), dns), resp6 = IpPacket.buildResponse(v6.get(), dns);
        check(checksumsValid(resp4), "v4 response checksums verify independently");
        check(checksumsValid(resp6), "v6 response checksums verify independently");
        check(Arrays.equals(Arrays.copyOfRange(resp4, 12, 16), DNS4) && Arrays.equals(Arrays.copyOfRange(resp4, 16, 20), CLIENT4), "v4 addresses swapped");
        check(Arrays.equals(Arrays.copyOfRange(resp6, 8, 24), DNS6) && Arrays.equals(Arrays.copyOfRange(resp6, 24, 40), CLIENT6), "v6 addresses swapped");
        check(DnsMessage.u16(resp4, 20) == 53 && DnsMessage.u16(resp4, 22) == 0xC350, "ports swapped");
        byte[] odd = new byte[33]; odd[0] = 1;
        check(checksumsValid(IpPacket.buildResponse(v4.get(), odd)), "odd-length payload checksum");
        Random r = new Random(3);
        for (int i = 0; i < 20000; i++) {
            byte[] junk = new byte[r.nextInt(120)]; r.nextBytes(junk);
            if (junk.length > 0 && i % 2 == 0) junk[0] = (byte) (i % 4 == 0 ? 0x45 : 0x60);
            IpPacket.parseDns(junk, junk.length, DNS4, DNS6);
            DnsMessage.parseQuery(junk, junk.length);
        }
        check(true, "random packets never throw");
    }

    private static void filter() throws Exception {
        DnsFilter f = filterWith("D phish.example PHISHING CONFIRMED a", "D strong.example SCAM STRONG b", "D maybe.example SCAM SUSPICIOUS c");
        check(f.decide("phish.example").action() == DnsFilter.Action.BLOCK && f.decide("phish.example").reason() == DnsFilter.Reason.THREAT_DB, "confirmed blocked");
        check(f.decide("a.b.phish.example").action() == DnsFilter.Action.BLOCK, "subdomain blocked");
        check(f.decide("strong.example").action() == DnsFilter.Action.BLOCK, "strong blocked");
        var warn = f.decide("maybe.example");
        check(warn.action() == DnsFilter.Action.ALLOW && warn.warnOnly(), "suspicious only warns");
        f.setBlockSuspicious(true);
        check(f.decide("maybe.example").action() == DnsFilter.Action.BLOCK, "suspicious blocked when enabled");
        check(f.decide("fine.example").action() == DnsFilter.Action.ALLOW && f.decide("fine.example").reason() == DnsFilter.Reason.NO_MATCH, "unlisted allowed");
        // Even if a (mistaken or older) feed lists everything, protected names stay reachable and abused sub-domains can still be blocked.
        ThreatDatabase.Entry listedEntry = new ThreatDatabase.Entry(ThreatDatabase.Category.SCAM, ThreatDatabase.Confidence.CONFIRMED, "mistaken-feed");
        DnsFilter listsEverything = new DnsFilter(new ReputationProvider() {
            public String id() { return "stub"; } public Reputation domain(String h) { return Reputation.listed(listedEntry, "stub"); }
            public Reputation sha256(String h) { return null; } public Reputation signerCertificate(String h) { return null; } }, new DnsFilter.DomainLists());
        check(listsEverything.decide("connectivitycheck.gstatic.com").action() == DnsFilter.Action.ALLOW && listsEverything.decide("x.connectivitycheck.gstatic.com").action() == DnsFilter.Action.ALLOW, "connectivity names are never blocked by a feed");
        check(listsEverything.decide("google.com").action() == DnsFilter.Action.ALLOW && listsEverything.decide("www.vipps.no").action() == DnsFilter.Action.ALLOW, "protected registrable domains are never blocked by a feed");
        check(listsEverything.decide("sites.google.com").action() == DnsFilter.Action.BLOCK, "an abused sub-domain of a big platform can still be blocked");
        check(listsEverything.lists().block("google.com") && listsEverything.decide("google.com").action() == DnsFilter.Action.BLOCK, "the person's own block list is not limited by the shield");
        check(f.lists().allow("phish.example"), "user allow accepted");
        check(f.decide("x.phish.example").action() == DnsFilter.Action.ALLOW && f.decide("x.phish.example").reason() == DnsFilter.Reason.USER_ALLOW, "user allow overrides database");
        check(f.lists().block("tracker.example") && f.decide("a.tracker.example").action() == DnsFilter.Action.BLOCK, "user block");
        f.lists().allow("tracker.example");
        check(f.decide("tracker.example").action() == DnsFilter.Action.ALLOW, "allow beats block");
        check(f.lists().unallow("tracker.example") && f.decide("tracker.example").action() == DnsFilter.Action.BLOCK, "unallow restores block");
        for (String bad : new String[] {"com", "", "co.uk", "a b.example", "*.example.com", "1.2.3.4", "-x.example", null}) check(!f.lists().block(bad), "invalid user entry refused: " + bad);
        check(new DnsFilter(null, new DnsFilter.DomainLists()).decide("phish.example").action() == DnsFilter.Action.ALLOW, "no provider fails open");
        DnsFilter empty = new DnsFilter(new ReputationProvider.LocalDatabase(ThreatDatabase::empty), new DnsFilter.DomainLists());
        check(empty.decide("phish.example").action() == DnsFilter.Action.ALLOW, "empty database fails open");
        DnsFilter boom = new DnsFilter(new ReputationProvider() {
            public String id() { return "x"; } public Reputation domain(String h) { throw new IllegalStateException(); }
            public Reputation sha256(String h) { return null; } public Reputation signerCertificate(String h) { return null; } }, new DnsFilter.DomainLists());
        check(boom.decide("a.example").action() == DnsFilter.Action.ALLOW, "provider failure fails open");
    }

    private static void upstream() throws Exception {
        byte[] q = DnsMessage.buildQuery(0x4242, "example.com", 1);
        var parsed = DnsMessage.parseQuery(q, q.length).get();
        byte[] answer = DnsMessage.errorResponse(q, parsed, 0);
        // UDP server answering, after optionally sending a stray datagram first
        try (DatagramSocket server = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
            Thread t = new Thread(() -> {
                try {
                    byte[] buf = new byte[512]; DatagramPacket in = new DatagramPacket(buf, buf.length);
                    server.receive(in);
                    byte[] stray = answer.clone(); stray[0] ^= 0x55;
                    server.send(new DatagramPacket(stray, stray.length, in.getSocketAddress()));
                    server.send(new DatagramPacket(answer, answer.length, in.getSocketAddress()));
                } catch (IOException ignored) { }
            }); t.setDaemon(true); t.start();
            var up = new DnsUpstream.Plain(() -> List.of(new InetSocketAddress(InetAddress.getLoopbackAddress(), server.getLocalPort())), DnsUpstream.Protector.NONE, 1500);
            check(Arrays.equals(up.resolve(q), answer), "udp answer, stray datagram ignored");
        }
        // Dead first server, working second
        try (DatagramSocket dead = new DatagramSocket(0, InetAddress.getLoopbackAddress()); DatagramSocket live = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
            Thread t = new Thread(() -> { try { byte[] b = new byte[512]; DatagramPacket in = new DatagramPacket(b, b.length); live.receive(in); live.send(new DatagramPacket(answer, answer.length, in.getSocketAddress())); } catch (IOException ignored) { } });
            t.setDaemon(true); t.start();
            var up = new DnsUpstream.Plain(() -> List.of(new InetSocketAddress(InetAddress.getLoopbackAddress(), dead.getLocalPort()), new InetSocketAddress(InetAddress.getLoopbackAddress(), live.getLocalPort())), DnsUpstream.Protector.NONE, 300);
            long t0 = System.nanoTime();
            check(Arrays.equals(up.resolve(q), answer), "failover to second server");
            check((System.nanoTime() - t0) / 1_000_000 < 1500, "failover bounded by timeout");
        }
        // Timeout and no servers
        try (DatagramSocket silent = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
            var up = new DnsUpstream.Plain(() -> List.of(new InetSocketAddress(InetAddress.getLoopbackAddress(), silent.getLocalPort())), DnsUpstream.Protector.NONE, 200);
            try { up.resolve(q); check(false, "timeout expected"); } catch (IOException expected) { check(true, "timeout surfaces as IOException"); }
        }
        try { new DnsUpstream.Plain(List::of, DnsUpstream.Protector.NONE, 100).resolve(q); check(false, "no servers"); } catch (IOException expected) { check(true, "no upstream known"); }
        // Truncated UDP answer -> TCP retry on the same port number
        try (DatagramSocket udp = new DatagramSocket(0, InetAddress.getLoopbackAddress()); ServerSocket tcp = new ServerSocket(udp.getLocalPort(), 1, InetAddress.getLoopbackAddress())) {
            byte[] truncated = answer.clone(); truncated[2] |= 2;
            byte[] full = Arrays.copyOf(answer, answer.length + 40);
            Thread tu = new Thread(() -> { try { byte[] b = new byte[512]; DatagramPacket in = new DatagramPacket(b, b.length); udp.receive(in); udp.send(new DatagramPacket(truncated, truncated.length, in.getSocketAddress())); } catch (IOException ignored) { } });
            Thread tt = new Thread(() -> { try (Socket c = tcp.accept()) { DataInputStream in = new DataInputStream(c.getInputStream()); int n = in.readUnsignedShort(); in.readFully(new byte[n]); DataOutputStream out = new DataOutputStream(c.getOutputStream()); out.writeShort(full.length); out.write(full); out.flush(); } catch (IOException ignored) { } });
            tu.setDaemon(true); tt.setDaemon(true); tu.start(); tt.start();
            var up = new DnsUpstream.Plain(() -> List.of(new InetSocketAddress(InetAddress.getLoopbackAddress(), udp.getLocalPort())), DnsUpstream.Protector.NONE, 1500);
            check(up.resolve(q).length == full.length, "truncated answer retried over TCP");
        }
        AtomicInteger protectedSockets = new AtomicInteger();
        try (DatagramSocket server = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
            Thread t = new Thread(() -> { try { byte[] b = new byte[512]; DatagramPacket in = new DatagramPacket(b, b.length); server.receive(in); server.send(new DatagramPacket(answer, answer.length, in.getSocketAddress())); } catch (IOException ignored) { } });
            t.setDaemon(true); t.start();
            DnsUpstream.Protector counting = new DnsUpstream.Protector() { public void protect(Socket s) { protectedSockets.incrementAndGet(); } public void protect(DatagramSocket s) { protectedSockets.incrementAndGet(); } };
            new DnsUpstream.Plain(() -> List.of(new InetSocketAddress(InetAddress.getLoopbackAddress(), server.getLocalPort())), counting, 1000).resolve(q);
            check(protectedSockets.get() == 1, "every upstream socket is passed to the VPN protector");
        }
    }

    private static final class Capture implements DnsProxy.PacketSink {
        final BlockingQueue<byte[]> out = new LinkedBlockingQueue<>();
        public void write(byte[] p, int n) { out.add(Arrays.copyOf(p, n)); }
    }

    private static void proxy() throws Exception {
        DnsFilter f = filterWith("D phish.example PHISHING CONFIRMED campaign", "D maybe.example SCAM SUSPICIOUS watch");
        Capture cap = new Capture();
        AtomicInteger upstreamCalls = new AtomicInteger();
        DnsUpstream good = query -> { upstreamCalls.incrementAndGet(); var q = DnsMessage.parseQuery(query, query.length).get(); return DnsMessage.errorResponse(query, q, 0); };
        try (DnsProxy proxy = new DnsProxy(f, good, cap, DNS4, DNS6, Clock.systemUTC())) {
            byte[] qb = DnsMessage.buildQuery(0x0101, "login.phish.example", 1);
            proxy.handlePacket(packet4(DNS4, 53, qb), 28 + qb.length);
            byte[] r = cap.out.poll(2, TimeUnit.SECONDS);
            check(r != null && rcodeOfPacket(r) == 3 && checksumsValid(r) && upstreamCalls.get() == 0, "blocked name: NXDOMAIN, never sent upstream");
            check(Arrays.equals(Arrays.copyOfRange(dnsOf(r), 0, 2), new byte[] {1, 1}), "response keeps query ID");
            byte[] q6 = DnsMessage.buildQuery(0x0202, "phish.example", 28);
            proxy.handlePacket(packet6(DNS6, 53, q6), 48 + q6.length);
            byte[] r6 = cap.out.poll(2, TimeUnit.SECONDS);
            check(r6 != null && (r6[0] >> 4) == 6 && rcodeOfPacket(r6) == 3 && checksumsValid(r6), "IPv6 query blocked with valid checksum");
            byte[] ok = DnsMessage.buildQuery(0x0303, "fine.example", 1);
            proxy.handlePacket(packet4(DNS4, 53, ok), 28 + ok.length);
            byte[] ra = cap.out.poll(2, TimeUnit.SECONDS);
            check(ra != null && rcodeOfPacket(ra) == 0 && upstreamCalls.get() == 1 && checksumsValid(ra), "allowed name forwarded");
            byte[] w = DnsMessage.buildQuery(0x0404, "maybe.example", 1);
            proxy.handlePacket(packet4(DNS4, 53, w), 28 + w.length);
            check(cap.out.poll(2, TimeUnit.SECONDS) != null && proxy.warned.get() == 1, "suspicious name answered but counted as warning");
            check(proxy.queries.get() == 4 && proxy.blocked.get() == 2 && proxy.forwarded.get() == 2, "counters: " + proxy.queries + "/" + proxy.blocked + "/" + proxy.forwarded);
            var events = proxy.recentEvents();
            check(events.size() == 3 && events.stream().noneMatch(e -> e.name().equals("fine.example")), "events hold blocked/warned names only, never ordinary queries");
            proxy.handlePacket(packet4(new byte[] {8, 8, 8, 8}, 53, qb), 28 + qb.length);
            proxy.handlePacket(new byte[10], 10);
            check(proxy.dropped.get() == 2 && cap.out.isEmpty(), "foreign and malformed packets dropped silently");
        }
        // Upstream failure and mismatched answers become SERVFAIL
        for (int mode = 0; mode < 2; mode++) {
            final int m = mode;
            DnsUpstream bad = query -> { if (m == 0) throw new IOException("down"); var q = DnsMessage.parseQuery(query, query.length).get(); byte[] r = DnsMessage.errorResponse(query, q, 0); r[1] ^= 1; return r; };
            Capture c2 = new Capture();
            try (DnsProxy p = new DnsProxy(f, bad, c2, DNS4, DNS6, Clock.systemUTC())) {
                byte[] qb = DnsMessage.buildQuery(0x0505, "fine.example", 1);
                p.handlePacket(packet4(DNS4, 53, qb), 28 + qb.length);
                byte[] r = c2.out.poll(2, TimeUnit.SECONDS);
                check(r != null && rcodeOfPacket(r) == 2 && p.failed.get() == 1, "SERVFAIL for upstream failure mode " + mode);
            }
        }
        // Overload: slow upstream, many queries; the packet loop must never block and the proxy must recover
        CountDownLatch gate = new CountDownLatch(1);
        DnsUpstream slow = query -> { try { gate.await(5, TimeUnit.SECONDS); } catch (InterruptedException e) { throw new IOException(e); } var q = DnsMessage.parseQuery(query, query.length).get(); return DnsMessage.errorResponse(query, q, 0); };
        Capture c3 = new Capture();
        try (DnsProxy p = new DnsProxy(f, slow, c3, DNS4, DNS6, Clock.systemUTC())) {
            long t0 = System.nanoTime();
            for (int i = 0; i < 300; i++) { byte[] qb = DnsMessage.buildQuery(i, "n" + i + ".example", 1); p.handlePacket(packet4(DNS4, 53, qb), 28 + qb.length); }
            check((System.nanoTime() - t0) / 1_000_000 < 1000, "packet loop does not block on a slow resolver");
            check(p.dropped.get() > 0 && p.dropped.get() < 300, "overload sheds load: dropped " + p.dropped.get());
            gate.countDown();
            int answered = 0; while (c3.out.poll(1, TimeUnit.SECONDS) != null) answered++;
            check(answered == 300, "every query answered: accepted ones after recovery, shed ones at once with SERVFAIL");
        }
        // Event log stays bounded; run() consumes a stream until EOF
        Capture c4 = new Capture();
        try (DnsProxy p = new DnsProxy(f, good, c4, DNS4, DNS6, Clock.systemUTC())) {
            List<byte[]> pkts = new ArrayList<>();
            for (int i = 0; i < 500; i++) { byte[] qb = DnsMessage.buildQuery(i, "k" + i + ".phish.example", 1); pkts.add(packet4(DNS4, 53, qb)); }
            Iterator<byte[]> it = pkts.iterator();
            p.run(new InputStream() {
                public int read() { return -1; }
                public int read(byte[] b) { if (!it.hasNext()) return -1; byte[] n = it.next(); System.arraycopy(n, 0, b, 0, n.length); return n.length; }
            });
            check(p.recentEvents().size() == DnsProxy.MAX_EVENTS && p.blocked.get() == 500, "event log bounded at " + DnsProxy.MAX_EVENTS);
        }
        // Throughput of the filter path (host JVM)
        Capture c5 = new Capture();
        try (DnsProxy p = new DnsProxy(f, good, c5, DNS4, DNS6, Clock.systemUTC())) {
            byte[] qb = DnsMessage.buildQuery(9, "a.phish.example", 1); byte[] pk = packet4(DNS4, 53, qb);
            for (int i = 0; i < 20000; i++) p.handlePacket(pk, pk.length);
            long t0 = System.nanoTime(); int n = 200000;
            for (int i = 0; i < n; i++) p.handlePacket(pk, pk.length);
            System.out.printf("DnsTests measurement (host JVM): blocked-query path %.1f us/query%n", (System.nanoTime() - t0) / 1e3 / n);
            c5.out.clear();
        }
        // Fuzz whole pipeline
        Capture c6 = new Capture();
        try (DnsProxy p = new DnsProxy(f, good, c6, DNS4, DNS6, Clock.systemUTC())) {
            Random r = new Random(77);
            byte[] base = packet4(DNS4, 53, DnsMessage.buildQuery(1, "x.example", 1));
            for (int i = 0; i < 30000; i++) {
                byte[] m = base.clone();
                for (int k = r.nextInt(4); k >= 0; k--) m[r.nextInt(m.length)] = (byte) r.nextInt(256);
                p.handlePacket(m, i % 7 == 0 ? r.nextInt(m.length + 1) : m.length);
            }
            check(true, "mutated packets never throw");
        }
        // Privacy: DNS code has no logging or persistence
        for (String name : new String[] {"DnsMessage", "IpPacket", "DnsFilter", "DnsProxy", "DnsUpstream"}) {
            String src = java.nio.file.Files.readString(java.nio.file.Path.of("src/main/java/com/aegis/core/" + name + ".java"));
            for (String banned : new String[] {"System.out", "System.err", "Logger", "FileOutputStream", "FileWriter", "Files.write", "java.nio.file"})
                check(!src.contains(banned), name + " must not use " + banned);
        }
    }
}
