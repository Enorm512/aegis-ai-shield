package com.aegis.core;

import com.aegis.core.CanaryTokens.*;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/** Host tests for the canary-token tripwire: tokens, registry, decoy text, DNS filter precedence and the proxy path. */
public final class CanaryTests {
    private static int checks;
    private static void check(boolean ok, String message) { checks++; if (!ok) throw new AssertionError(message); }
    private static final byte[] DNS4 = {10, 111, (byte) 222, 2};
    private static final byte[] DNS6 = {(byte) 0xfd, 0, (byte) 0xae, (byte) 0x91, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    private static final byte[] CLIENT4 = {10, 111, (byte) 222, 1};

    // Independent IPv4/UDP framing (same layout as DnsTests) so the proxy is not checked against its own builder.
    private static byte[] packet4(byte[] dns) {
        byte[] p = new byte[28 + dns.length];
        p[0] = 0x45; p[2] = (byte) (p.length >> 8); p[3] = (byte) p.length; p[8] = 64; p[9] = 17;
        System.arraycopy(CLIENT4, 0, p, 12, 4); System.arraycopy(DNS4, 0, p, 16, 4);
        p[20] = (byte) 0xC3; p[21] = 0x50; p[22] = 0; p[23] = 53;
        int ul = 8 + dns.length; p[24] = (byte) (ul >> 8); p[25] = (byte) ul;
        System.arraycopy(dns, 0, p, 28, dns.length);
        return p;
    }

    public static void main(String[] args) throws Exception {
        SecureRandom rnd = new SecureRandom();

        // --- Tokens
        Set<String> ids = new HashSet<>();
        for (int i = 0; i < 2000; i++) { String id = CanaryTokens.newId(rnd); check(CanaryTokens.validId(id), "id format " + id); ids.add(id); }
        check(ids.size() == 2000, "ids are unique (100 random bits)");
        check(!CanaryTokens.validId("short") && !CanaryTokens.validId("ABCDEFGHIJKLMNOPQRST") && !CanaryTokens.validId("abcdefghijklmnopqrs1") && !CanaryTokens.validId(null), "id validation");
        try { new Registry("bad zone!"); check(false, "bad zone accepted"); } catch (IllegalArgumentException e) { check(true, "bad zone refused"); }
        check(CanaryTokens.DEFAULT_ZONE.endsWith(".invalid"), "default zone is under the reserved .invalid TLD");

        // --- Registry: plant, match, remove, persist
        Registry reg = new Registry(CanaryTokens.DEFAULT_ZONE);
        Token contact = reg.plant(Kind.CONTACT, rnd, 1000), note = reg.plant(Kind.NOTE, rnd, 2000), file = reg.plant(Kind.FILE, rnd, 3000);
        check(reg.tokens().equals(Arrays.asList(contact, note, file)), "tokens in planting order");
        for (Token t : reg.tokens()) {
            String h = t.host(reg.zone());
            check(h.matches("[a-z0-9-]+\\.aegis-canary\\.invalid") && h.length() < 64 + 21, "host shape " + h);
            check(reg.match(h).equals(Optional.of(t)) && reg.match("x." + h).equals(Optional.of(t)) && reg.match(h + ".").equals(Optional.of(t)), "exact, subdomain and trailing-dot match");
            check(t.url(reg.zone()).startsWith("https://" + h + "/"), "url carries the host");
        }
        check(!reg.match(CanaryTokens.DEFAULT_ZONE).isPresent() && !reg.match("www-" + CanaryTokens.newId(rnd) + "." + CanaryTokens.DEFAULT_ZONE).isPresent(), "zone itself and unknown ids do not match");
        check(!reg.match("example.com").isPresent() && !reg.match(null).isPresent() && !reg.match("").isPresent(), "ordinary names do not match");
        String suffixTrick = contact.host(reg.zone()).substring(1);
        check(!reg.match(suffixTrick).isPresent() && !reg.match("evil" + contact.host(reg.zone())).isPresent(), "label-boundary matching only");
        Registry reloaded = new Registry(CanaryTokens.DEFAULT_ZONE);
        reloaded.load(reg.serialize());
        check(reloaded.tokens().equals(reg.tokens()), "serialize/load round trip");
        reloaded.load("AEGIS-CANARY 1\nNOTE notanid 5\nBOGUS " + CanaryTokens.newId(rnd) + " 5\nFILE " + CanaryTokens.newId(rnd) + " x\nCONTACT " + CanaryTokens.newId(rnd) + " 7\n");
        check(reloaded.tokens().size() == 1 && reloaded.tokens().get(0).kind() == Kind.CONTACT, "malformed lines skipped");
        reloaded.load("garbage"); check(reloaded.tokens().isEmpty(), "non-registry text clears");
        check(reg.remove(note.id()) && !reg.match(note.host(reg.zone())).isPresent() && !reg.remove(note.id()), "remove");
        Registry full = new Registry(CanaryTokens.DEFAULT_ZONE);
        for (int i = 0; i < CanaryTokens.MAX_TOKENS; i++) full.plant(Kind.NOTE, rnd, i);
        try { full.plant(Kind.NOTE, rnd, 99); check(false, "cap"); } catch (IllegalStateException e) { check(true, "at most " + CanaryTokens.MAX_TOKENS); }

        // --- Decoy content
        String nb = CanaryTokens.noteText(note, CanaryTokens.DEFAULT_ZONE, true), en = CanaryTokens.noteText(note, CanaryTokens.DEFAULT_ZONE, false);
        check(nb.contains(note.url(CanaryTokens.DEFAULT_ZONE)) && en.contains(note.url(CanaryTokens.DEFAULT_ZONE)) && nb.contains("Passord") && en.contains("Password"), "note carries the canary link");
        check(CanaryTokens.fileText(file, CanaryTokens.DEFAULT_ZONE, false).contains(file.url(CanaryTokens.DEFAULT_ZONE)), "file carries the canary link");
        check(CanaryTokens.contactName(contact).matches("[A-Z][a-z]+ [A-Z][a-z]+") && CanaryTokens.contactName(contact).equals(CanaryTokens.contactName(contact)), "stable contact name");
        check(CanaryTokens.decoyPassword(note).matches("[A-Z2-7][a-z2-7]{6}![0-9]{2,3}[a-z2-7]{3}"), "password-looking decoy: " + CanaryTokens.decoyPassword(note));

        // --- DNS filter: tripwire first, even over an allowlist entry; listener errors never break filtering
        DnsFilter f = new DnsFilter(null, new DnsFilter.DomainLists());
        List<String> trips = new CopyOnWriteArrayList<>();
        f.setCanaries(reg, (t, name) -> trips.add(t.id() + " " + name));
        String ch = contact.host(reg.zone());
        DnsFilter.Decision d = f.decide(ch);
        check(d.action() == DnsFilter.Action.BLOCK && d.reason() == DnsFilter.Reason.CANARY && trips.size() == 1 && trips.get(0).equals(contact.id() + " " + ch), "canary blocked and reported");
        check(f.decide("example.com").action() == DnsFilter.Action.ALLOW && trips.size() == 1, "ordinary name unaffected");
        // Precedence over the allowlist, shown with a custom (registrable-style) zone that an allowlist can name.
        Registry custom = new Registry("canary.aegis.example");
        Token ct = custom.plant(Kind.FILE, rnd, 1);
        DnsFilter.DomainLists allowCustom = new DnsFilter.DomainLists();
        check(allowCustom.allow("aegis.example"), "allowlist entry set");
        DnsFilter fc = new DnsFilter(null, allowCustom);
        fc.setCanaries(custom, (t, n) -> { throw new RuntimeException("listener bug"); });
        DnsFilter.Decision dc = fc.decide(ct.host(custom.zone()));
        check(dc.reason() == DnsFilter.Reason.CANARY && dc.action() == DnsFilter.Action.BLOCK, "tripwire wins over the allowlist; listener exception contained");
        check(fc.decide("www.aegis.example").reason() == DnsFilter.Reason.USER_ALLOW, "allowlist still works for other names");
        fc.setCanaries(null, null);
        check(fc.decide(ct.host(custom.zone())).reason() == DnsFilter.Reason.USER_ALLOW, "no registry, no tripwire");

        // --- Proxy path: answered locally with NXDOMAIN, never forwarded, event recorded
        AtomicInteger upstreamCalls = new AtomicInteger();
        DnsUpstream upstream = q -> { upstreamCalls.incrementAndGet(); throw new java.io.IOException("must not be called"); };
        BlockingQueue<byte[]> out = new LinkedBlockingQueue<>();
        try (DnsProxy proxy = new DnsProxy(f, upstream, (p, n) -> out.add(Arrays.copyOf(p, n)), DNS4, DNS6, Clock.systemUTC())) {
            byte[] qb = DnsMessage.buildQuery(0x0707, file.host(reg.zone()), 1);
            proxy.handlePacket(packet4(qb), 28 + qb.length);
            byte[] r = out.poll(2, TimeUnit.SECONDS);
            check(r != null && (r[28 + 3] & 0xF) == DnsMessage.RCODE_NXDOMAIN, "local NXDOMAIN for a canary lookup");
            check(upstreamCalls.get() == 0, "canary lookup never forwarded upstream");
            check(proxy.blocked.get() == 1 && proxy.recentEvents().size() == 1 && proxy.recentEvents().get(0).reason() == DnsFilter.Reason.CANARY, "event recorded with CANARY reason");
            check(trips.size() == 2 && trips.get(1).startsWith(file.id()), "listener called from the proxy path");
        }
        System.out.println("CanaryTests: " + checks + " checks passed");
    }
}
