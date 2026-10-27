package com.aegis.core;

import com.aegis.core.ThreatBundleVerifier.*;
import com.aegis.core.ThreatBundleVerifier.BundleException.Reason;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.KeyPair;
import java.time.*;
import java.util.*;
import static com.aegis.core.Analysis.Verdict.*;

public final class ThreatIntelTests {
    private static int checks;
    private static void check(boolean ok, String message) { checks++; if (!ok) throw new AssertionError(message); }
    private static final Instant NOW = Instant.parse("2026-10-25T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final String HASH = "a".repeat(64), CERT = "b".repeat(64);

    private static KeyPair key;
    private static String keyId;
    private static TrustAnchors anchors;

    private static byte[] bundle(long seq, int validDays, String... entries) throws Exception {
        return ThreatBundleTool.build(key.getPrivate(), keyId, seq, NOW.minusSeconds(3600), NOW.plusSeconds(validDays * 86400L), Arrays.asList(entries));
    }
    private static final String[] STD = {
        "D phish.example PHISHING CONFIRMED bank-campaign", "D scam.example SCAM STRONG invest-scam",
        "D maybe.example PHISHING SUSPICIOUS review-me", "H " + HASH + " MALWARE CONFIRMED test-fixture", "C " + CERT + " MALWARE STRONG bad-signer" };

    private static void rejects(byte[] b, Reason want, String what) {
        try { ThreatBundleVerifier.verify(b, anchors, new Policy(0, true, NOW)); check(false, what + " should be rejected"); }
        catch (BundleException e) { check(e.reason == want, what + ": expected " + want + " got " + e.reason + " (" + e.getMessage() + ")"); }
    }
    private static byte[] replace(byte[] b, String from, String to) {
        return new String(b, StandardCharsets.US_ASCII).replace(from, to).getBytes(StandardCharsets.US_ASCII);
    }
    private static Path tmp() throws Exception { return Files.createTempDirectory("aegis-store"); }
    private static TrustAnchors anchorsOf(KeyPair k) { TrustAnchors a = new TrustAnchors(); a.add(k.getPublic().getEncoded()); return a; }

    public static void main(String[] args) throws Exception {
        key = ThreatBundleTool.generateKey();
        anchors = new TrustAnchors();
        keyId = anchors.add(key.getPublic().getEncoded());

        // --- Valid bundle
        byte[] good = bundle(5, 30, STD);
        ThreatDatabase db = ThreatBundleVerifier.verify(good, anchors, new Policy(0, true, NOW));
        check(db.sequence == 5 && db.size() == 5, "valid bundle parses");
        check(db.domain("phish.example").get().confidence() == ThreatDatabase.Confidence.CONFIRMED, "exact domain");
        check(db.domain("login.a.phish.example").isPresent(), "subdomain matches parent listing");
        check(db.domain("notphish.example").isEmpty(), "sibling suffix text does not match");
        check(db.domain("example").isEmpty() && db.domain("com").isEmpty(), "single label never matches");
        check(db.sha256(HASH.toUpperCase()).isPresent() && db.signerCertificate(CERT).isPresent(), "hash and cert lookup");
        check(db.sha256("c".repeat(64)).isEmpty(), "unlisted hash");

        // --- Authenticity and integrity
        KeyPair other = ThreatBundleTool.generateKey();
        rejects(ThreatBundleTool.build(other.getPrivate(), keyId, 5, NOW, NOW.plusSeconds(99999), Arrays.asList(STD)), Reason.BAD_SIGNATURE, "wrong signer using trusted key id");
        rejects(ThreatBundleTool.build(other.getPrivate(), "0123456789abcdef", 5, NOW, NOW.plusSeconds(99999), Arrays.asList(STD)), Reason.UNTRUSTED_KEY, "unknown key id");
        rejects(replace(good, "phish.example", "phish.exampl3"), Reason.BAD_SIGNATURE, "entry tampered");
        rejects(replace(good, "sequence: 5", "sequence: 9"), Reason.BAD_SIGNATURE, "sequence tampered");
        rejects(replace(good, "CONFIRMED", "SUSPICIOUS"), Reason.BAD_SIGNATURE, "confidence tampered");
        check(new String(good, StandardCharsets.US_ASCII).lines().count() > 8, "sanity");
        String noSig = new String(good, StandardCharsets.US_ASCII);
        rejects(noSig.substring(0, noSig.lastIndexOf("SIGNATURE")).getBytes(StandardCharsets.US_ASCII), Reason.MALFORMED, "signature stripped");
        rejects((noSig + "D extra.example SCAM CONFIRMED appended\n").getBytes(StandardCharsets.US_ASCII), Reason.MALFORMED, "appended content after signature");
        rejects(Arrays.copyOf(good, good.length - 5), Reason.MALFORMED, "truncated");
        rejects(new byte[0], Reason.MALFORMED, "empty");
        rejects(null, Reason.MALFORMED, "null");
        rejects(replace(good, "\n", "\r\n"), Reason.MALFORMED, "CRLF");
        byte[] nonAscii = good.clone(); nonAscii[10] = (byte)0xC3;
        rejects(nonAscii, Reason.MALFORMED, "non-ascii");
        rejects(new byte[ThreatBundleVerifier.MAX_BUNDLE_BYTES + 1], Reason.TOO_LARGE, "oversize");
        // Every single-byte change anywhere in the bundle must be rejected.
        int accepted = 0;
        for (int i = 0; i < good.length; i++) {
            byte[] m = good.clone(); m[i] ^= 0x01;
            try { ThreatBundleVerifier.verify(m, anchors, new Policy(0, true, NOW)); accepted++; } catch (BundleException expected) { }
        }
        check(accepted == 0, "exhaustive single-bit mutation: accepted " + accepted);
        Random rnd = new Random(7);
        for (int i = 0; i < 2000; i++) {
            byte[] junk = new byte[rnd.nextInt(600)]; rnd.nextBytes(junk);
            try { ThreatBundleVerifier.verify(junk, anchors, new Policy(0, true, NOW)); check(false, "random bytes accepted"); } catch (BundleException expected) { }
        }
        check(true, "random bytes rejected");

        // --- Freshness / rollback
        try { ThreatBundleVerifier.verify(good, anchors, new Policy(5, true, NOW)); check(false, "same sequence"); }
        catch (BundleException e) { check(e.reason == Reason.ROLLBACK, "same sequence is a replay"); }
        try { ThreatBundleVerifier.verify(good, anchors, new Policy(6, true, NOW)); check(false, "older sequence"); }
        catch (BundleException e) { check(e.reason == Reason.ROLLBACK, "older sequence is rollback"); }
        byte[] old = ThreatBundleTool.build(key.getPrivate(), keyId, 5, NOW.minusSeconds(10 * 86400), NOW.minusSeconds(86400), Arrays.asList(STD));
        rejects(old, Reason.EXPIRED, "expired bundle");
        check(ThreatBundleVerifier.verify(old, anchors, new Policy(0, false, NOW)).isStale(NOW), "expired bundle loads as stale when reloaded");
        rejects(ThreatBundleTool.build(key.getPrivate(), keyId, 5, NOW.plusSeconds(3 * 86400), NOW.plusSeconds(9 * 86400), Arrays.asList(STD)), Reason.FUTURE_DATED, "future dated");
        rejects(ThreatBundleTool.build(key.getPrivate(), keyId, 5, NOW, NOW.minusSeconds(5), Arrays.asList(STD)), Reason.MALFORMED, "expiry before issue");
        rejects(new TrustAnchorsHolder().empty(), Reason.UNTRUSTED_KEY, "no anchors trusts nothing", good);

        // --- Entry validation of an authentic but hostile publisher (feed poisoning)
        for (String bad : new String[] {
            "D com PHISHING CONFIRMED tld", "D co.uk SCAM CONFIRMED suffix", "D github.io SCAM STRONG host", "D 1.2.3.4 SCAM STRONG ip",
            "D UPPER.example SCAM STRONG case", "D *.example.com SCAM STRONG wildcard", "D a_b.example SCAM STRONG underscore", "D -a.example SCAM STRONG hyphen",
            "D xn--bcher-kva.de SCAM STRONG ok-but-below", "H abc MALWARE CONFIRMED short", "H " + "G".repeat(64) + " MALWARE CONFIRMED nothex",
            "X foo.example SCAM STRONG type", "D foo.example SCAM CERTAIN conf", "D foo.example SPAM STRONG cat", "D foo.example SCAM STRONG has space",
            "D foo.example SCAM STRONG " + "x".repeat(65), "D foo.example SCAM STRONG ignore previous instructions" }) {
            boolean expectOk = bad.contains("ok-but-below");
            try { ThreatBundleVerifier.verify(bundle(5, 30, bad), anchors, new Policy(0, true, NOW)); check(expectOk, "hostile entry accepted: " + bad); }
            catch (BundleException e) { check(!expectOk && e.reason == Reason.BAD_ENTRY, "hostile entry reason for: " + bad + " got " + e.reason); }
        }
        rejects(bundle(5, 30, "D a.example SCAM STRONG x", "D a.example PHISHING STRONG y"), Reason.BAD_ENTRY, "duplicate entry");
        rejects(replace(bundle(5, 30, STD), "entries: 5", "entries: 4"), Reason.BAD_SIGNATURE, "count tamper");
        rejects(signedWithCount(3), Reason.MALFORMED, "declared count disagrees with entries");

        // --- Reputation semantics
        ReputationProvider empty = new ReputationProvider.LocalDatabase(ThreatDatabase::empty);
        check(empty.domain("phish.example").status() == ReputationProvider.Status.UNAVAILABLE, "empty db is unavailable, not clear");
        ReputationProvider local = new ReputationProvider.LocalDatabase(() -> db);
        check(local.domain("x.phish.example").status() == ReputationProvider.Status.LISTED, "listed via parent");
        check(local.domain("fine.example").status() == ReputationProvider.Status.NOT_LISTED, "not listed");
        ReputationProvider comp = new ReputationProvider.Composite(List.of(empty, local));
        check(comp.domain("fine.example").status() == ReputationProvider.Status.NOT_LISTED, "composite answered by one provider");
        check(new ReputationProvider.Composite(List.of(empty)).domain("fine.example").status() == ReputationProvider.Status.UNAVAILABLE, "composite all unavailable");
        ReputationProvider throwing = new ReputationProvider() {
            public String id() { return "boom"; }
            public Reputation domain(String h) { throw new IllegalStateException(); }
            public Reputation sha256(String h) { throw new IllegalStateException(); }
            public Reputation signerCertificate(String h) { throw new IllegalStateException(); }
        };
        check(new ReputationProvider.Composite(List.of(throwing, local)).domain("phish.example").status() == ReputationProvider.Status.LISTED, "failing provider does not hide a listing");
        check(new ReputationProvider.Composite(List.of(throwing)).domain("phish.example").status() == ReputationProvider.Status.UNAVAILABLE, "failing provider is unavailable");

        // --- Integration with analyzers
        check(ThreatChecks.url("https://phish.example/login", local).verdict == CONFIRMED_MALICIOUS, "confirmed listing");
        check(ThreatChecks.url("https://a.b.scam.example", local).verdict == STRONG_INDICATORS, "strong listing");
        check(ThreatChecks.url("https://maybe.example", local).verdict == SUSPICIOUS, "suspicious listing");
        check(ThreatChecks.url("https://xn--bcher-kva.de", local).verdict == NO_KNOWN_WARNING_SIGNS, "unlisted stays heuristic result");
        check(ThreatChecks.url("https://fine.example", local).findings.stream().anyMatch(f -> f.code.equals("THREATDB_NOT_LISTED") && f.detail.contains("does not mean it is safe")), "not-listed wording");
        check(ThreatChecks.url("https://fine.example", empty).findings.stream().anyMatch(f -> f.code.equals("THREATDB_UNAVAILABLE")), "unavailable disclosed");
        check(ThreatChecks.url("https://bankid-login.example", local).verdict == SUSPICIOUS, "heuristic verdict not lowered by miss");
        check(ThreatChecks.url("https://maybe.example@bankid-login.example", local).verdict == STRONG_INDICATORS, "listing never lowers stronger heuristic verdict");
        check(ThreatChecks.url("not a url ::", local).verdict == INSUFFICIENT_EVIDENCE, "invalid input stays insufficient");
        check(ThreatChecks.url("https://127.0.0.1", local).verdict == NO_KNOWN_WARNING_SIGNS, "ip literals are not domain-looked-up");
        check(ThreatChecks.url("https://phish.example", null).verdict == NO_KNOWN_WARNING_SIGNS, "no provider = heuristics only");
        check(ThreatChecks.apkHash(HASH, local).verdict == CONFIRMED_MALICIOUS, "hash listing");
        check(ThreatChecks.apkHash("c".repeat(64), local).verdict == NO_KNOWN_WARNING_SIGNS, "hash not listed");
        check(ThreatChecks.apkHash("c".repeat(64), empty).verdict == INSUFFICIENT_EVIDENCE, "hash with no database is insufficient");
        check(ThreatChecks.apkHash("zz", local).verdict == INSUFFICIENT_EVIDENCE, "invalid hash");
        check(ThreatChecks.signer(ThreatChecks.apkHash("c".repeat(64), local), CERT, local).verdict == STRONG_INDICATORS, "signer listing raises verdict");

        // --- Store: install, rollback, tamper at rest, replay
        Path dir = tmp();
        ThreatStore store = new ThreatStore(dir.toFile(), anchors, CLOCK);
        check(store.current().isEmpty() && store.loadWarning() == null && !store.canRollback(), "fresh store is empty");
        store.install(bundle(10, 30, "D one.example SCAM STRONG first"));
        store.install(bundle(11, 30, "D two.example SCAM STRONG second"));
        check(store.current().sequence == 11 && store.canRollback() && store.floor() == 11, "second install, floor tracks highest");
        for (long replay : new long[] {10, 11}) {
            try { store.install(bundle(replay, 30, "D old.example SCAM STRONG replay")); check(false, "replay " + replay); }
            catch (BundleException e) { check(e.reason == Reason.ROLLBACK, "replay rejected " + replay); }
        }
        check(store.current().sequence == 11 && store.current().domain("two.example").isPresent(), "rejected install leaves state intact");
        check(new ThreatStore(dir.toFile(), anchors, CLOCK).current().sequence == 11, "state survives reopen");
        check(store.rollback() && store.current().sequence == 10 && !store.canRollback(), "rollback to previous");
        check(store.floor() == 11, "floor not lowered by rollback");
        try { store.install(bundle(11, 30, "D two.example SCAM STRONG again")); check(false, "same seq after rollback"); }
        catch (BundleException e) { check(true, "same sequence still refused after rollback"); }
        store.install(bundle(12, 30, "D three.example SCAM STRONG third"));
        check(store.current().sequence == 12, "newer bundle accepted after rollback");
        check(!new ThreatStore(tmp().toFile(), anchors, CLOCK).rollback(), "rollback with nothing previous");
        // An older, correctly signed file swapped in as current.bundle is a replay and is refused at startup.
        Path rdir = tmp();
        ThreatStore rs = new ThreatStore(rdir.toFile(), anchors, CLOCK);
        byte[] old5 = bundle(5, 30, "D five.example SCAM STRONG old");
        rs.install(old5);
        rs.install(bundle(6, 30, "D six.example SCAM STRONG new"));
        Files.write(rdir.resolve("current.bundle"), old5);
        ThreatStore replayed = new ThreatStore(rdir.toFile(), anchors, CLOCK);
        check(replayed.current().isEmpty() && replayed.loadWarning() != null, "replayed older current bundle is refused at startup");
        // A deliberate rollback survives a restart.
        Path pdir = tmp();
        ThreatStore ps = new ThreatStore(pdir.toFile(), anchors, CLOCK);
        ps.install(bundle(5, 30, "D five.example SCAM STRONG old")); ps.install(bundle(6, 30, "D six.example SCAM STRONG new"));
        check(ps.rollback(), "rollback ok");
        check(new ThreatStore(pdir.toFile(), anchors, CLOCK).current().sequence == 5, "deliberate rollback survives restart");
        // Tampering with the stored file is detected on next start; falls back to previous.
        Path cur = dir.resolve("current.bundle");
        byte[] stored = Files.readAllBytes(cur); stored[stored.length / 2] ^= 1; Files.write(cur, stored);
        ThreatStore reopened = new ThreatStore(dir.toFile(), anchors, CLOCK);
        check(reopened.loadWarning() != null && reopened.current().sequence == 10, "tampered current falls back to verified previous: " + reopened.current().sequence);
        Files.write(dir.resolve("previous.bundle"), "garbage".getBytes(StandardCharsets.US_ASCII));
        ThreatStore ruined = new ThreatStore(dir.toFile(), anchors, CLOCK);
        check(ruined.current().isEmpty() && ruined.loadWarning() != null, "all stored bundles invalid -> empty, flagged");
        // A store with no trust anchors never loads or installs anything.
        ThreatStore untrusting = new ThreatStore(dir.toFile(), new TrustAnchors(), CLOCK);
        check(untrusting.current().isEmpty(), "no anchors, nothing loads");
        try { untrusting.install(bundle(99, 30, STD)); check(false, "install without anchors"); } catch (BundleException e) { check(e.reason == Reason.UNTRUSTED_KEY, "install without anchors rejected"); }
        // Regression tests for the independent review (2026-10-26)
        Path d2 = tmp();
        ThreatStore s2 = new ThreatStore(d2.toFile(), anchors, CLOCK);
        s2.install(bundle(20, 30, "D one.example SCAM STRONG first"));
        s2.install(bundle(21, 30, "D two.example SCAM STRONG second"));
        // A device clock days behind must not discard a verified database (future-dating only matters when installing)
        Clock behind = Clock.fixed(NOW.minusSeconds(3 * 86400), ZoneOffset.UTC);
        ThreatStore skewed = new ThreatStore(d2.toFile(), anchors, behind);
        check(skewed.current().sequence == 21 && skewed.loadWarning() == null, "stored database survives a clock that is days behind");
        try { skewed.install(bundle(22, 30, "D three.example SCAM STRONG third")); check(false, "future-dated install"); }
        catch (BundleException e) { check(e.reason == Reason.FUTURE_DATED, "installing a future-dated bundle is still refused"); }
        // Crash between replacing files: current.bundle missing, previous.bundle intact
        Files.delete(d2.resolve("current.bundle"));
        ThreatStore recovered = new ThreatStore(d2.toFile(), anchors, CLOCK);
        check(recovered.current().sequence == 20 && recovered.loadWarning() != null, "missing current falls back to previous and says so");
        // The live file is never absent during an install: previous is a copy, the swap is a rename
        s2.install(bundle(23, 30, "D four.example SCAM STRONG fourth"));
        check(Files.exists(d2.resolve("current.bundle")) && Files.exists(d2.resolve("previous.bundle")) && !Files.exists(d2.resolve("incoming.tmp")), "no temporary files left behind");
        check(new String(Files.readAllBytes(d2.resolve("floors")), StandardCharsets.US_ASCII).trim().equals(keyId + " 23"), "per-key floor follows the install");
        // A lost floor file is re-derived from the verified bundle on the next start
        Files.delete(d2.resolve("floors"));
        check(new ThreatStore(d2.toFile(), anchors, CLOCK).floor() == 23, "floor re-derived after loss");
        // Two simultaneous installs of the same sequence: exactly one wins
        Path d3 = tmp();
        ThreatStore s3 = new ThreatStore(d3.toFile(), anchors, CLOCK);
        byte[] b30 = bundle(30, 30, "D race.example SCAM STRONG race");
        java.util.concurrent.atomic.AtomicInteger wins = new java.util.concurrent.atomic.AtomicInteger();
        Thread[] ts = new Thread[6];
        for (int i = 0; i < ts.length; i++) { ts[i] = new Thread(() -> { try { s3.install(b30); wins.incrementAndGet(); } catch (Exception ignored) { } }); ts[i].start(); }
        for (Thread t : ts) t.join();
        check(wins.get() == 1 && s3.current().sequence == 30, "concurrent identical installs: exactly one succeeds (" + wins.get() + ")");
        // Readers are not blocked while a large bundle is verified and installed
        java.util.List<String> bigEntries = new java.util.ArrayList<>();
        for (int i = 0; i < 60000; i++) bigEntries.add("D d" + i + ".big.example SCAM STRONG bulk");
        byte[] big = bundle(40, 30, bigEntries.toArray(new String[0]));
        java.util.concurrent.atomic.AtomicLong worst = new java.util.concurrent.atomic.AtomicLong();
        java.util.concurrent.atomic.AtomicBoolean done = new java.util.concurrent.atomic.AtomicBoolean();
        Thread reader = new Thread(() -> { while (!done.get()) { long t0 = System.nanoTime(); s3.current().size(); worst.set(Math.max(worst.get(), System.nanoTime() - t0)); } });
        reader.start();
        s3.install(big);
        done.set(true); reader.join();
        check(worst.get() / 1_000_000 < 50, "store reads stay fast during a large install (worst " + worst.get() / 1000 + " us)");
        // Hostile unsigned input is rejected without parsing the body
        byte[] junk = ("AEGIS-THREATDB 1\nkey-id: " + keyId + "\n" + "a\n".repeat(2_000_000) + "SIGNATURE AAAA\n").getBytes(StandardCharsets.US_ASCII);
        long j0 = System.nanoTime();
        rejects(junk, Reason.BAD_SIGNATURE, "large unsigned body");
        check((System.nanoTime() - j0) / 1_000_000 < 3000, "unsigned input is refused quickly");

        // --- Expert review (2026-10-26): key rotation, sequence and validity caps, protected names
        Path d4 = tmp();
        KeyPair key2 = ThreatBundleTool.generateKey();
        TrustAnchors both = new TrustAnchors(); both.add(key.getPublic().getEncoded()); String keyId2 = both.add(key2.getPublic().getEncoded());
        ThreatStore rot = new ThreatStore(d4.toFile(), both, CLOCK);
        rot.install(bundle(100_000, 30, "D one.example SCAM STRONG k1"));
        try { rot.install(bundle(100_000 + ThreatBundleVerifier.MAX_SEQUENCE_JUMP + 1, 30, "D two.example SCAM STRONG big")); check(false, "sequence jump"); }
        catch (BundleException e) { check(e.reason == Reason.SEQUENCE_JUMP, "a sequence far beyond the floor is refused (typo or stolen key): " + e.reason); }
        byte[] fromSecond = ThreatBundleTool.build(key2.getPrivate(), keyId2, 7, NOW.minusSeconds(3600), NOW.plusSeconds(30 * 86400L), Arrays.asList("D rotated.example SCAM STRONG k2"));
        check(rot.install(fromSecond).sequence == 7, "a rotated key starts from its own floor and is not locked out by the first key's sequence");
        check(rot.floorOf(keyId) == 100_000 && rot.floorOf(keyId2) == 7, "floors are tracked per key");
        try { rot.install(bundle(99_999, 30, "D old.example SCAM STRONG replay")); check(false, "old key replay"); }
        catch (BundleException e) { check(e.reason == Reason.ROLLBACK, "the first key's old bundles stay refused after rotation"); }
        ThreatStore revoked = new ThreatStore(d4.toFile(), anchorsOf(key2), CLOCK);
        check(revoked.current().sequence == 7, "removing the first anchor in an app update keeps the second key's database");
        check(ThreatBundleVerifier.keyIdOf(fromSecond).equals(keyId2) && ThreatBundleVerifier.keyIdOf(new byte[3]) == null && ThreatBundleVerifier.keyIdOf("junk\njunk\n".getBytes(StandardCharsets.US_ASCII)) == null, "key id extraction");
        byte[] long100 = ThreatBundleTool.build(key.getPrivate(), keyId, 5, NOW.minusSeconds(60), NOW.plusSeconds(100L * 86400), Arrays.asList(STD));
        ThreatBundleVerifier.verify(long100, anchors, new Policy(0, true, NOW));
        byte[] long101 = ThreatBundleTool.build(key.getPrivate(), keyId, 5, NOW.minusSeconds(60), NOW.plusSeconds(102L * 86400), Arrays.asList(STD));
        rejects(long101, Reason.MALFORMED, "validity of more than 100 days");
        rejects(bundle(5, 30, "D google.com SCAM CONFIRMED mistaken-feed"), Reason.BAD_ENTRY, "protected registrable domain cannot be listed");
        rejects(bundle(5, 30, "D www.paypal.com PHISHING CONFIRMED x"), Reason.BAD_ENTRY, "www. of a protected domain cannot be listed");
        rejects(bundle(5, 30, "D connectivitycheck.gstatic.com SCAM STRONG x"), Reason.BAD_ENTRY, "connectivity name cannot be listed");
        ThreatBundleVerifier.verify(bundle(5, 30, "D sites.google.com PHISHING STRONG abused-subdomain"), anchors, new Policy(0, true, NOW));
        check(ProtectedDomains.shielded("www.google.com") && ProtectedDomains.shielded("x.connectivitycheck.gstatic.com") && !ProtectedDomains.shielded("sites.google.com") && !ProtectedDomains.shielded("evil.example"), "shield rules");

        // Anchor hygiene
        try { new TrustAnchors().add(new byte[] {1, 2, 3}); check(false, "garbage key"); } catch (IllegalArgumentException e) { check(true, "garbage key refused"); }
        java.security.KeyPairGenerator rsa = java.security.KeyPairGenerator.getInstance("RSA"); rsa.initialize(2048);
        try { new TrustAnchors().add(rsa.generateKeyPair().getPublic().getEncoded()); check(false, "rsa key"); } catch (IllegalArgumentException e) { check(true, "non-EC key refused"); }

        System.out.println("ThreatIntelTests: " + checks + " checks passed");
    }

    /** Authentic bundle whose header declares a different number of entries than present. */
    private static byte[] signedWithCount(int declared) throws Exception {
        String body = "AEGIS-THREATDB 1\nkey-id: " + keyId + "\nsequence: 5\nissued: 2026-10-25T11:00:00Z\nexpires: 2026-12-01T00:00:00Z\nentries: " + declared
            + "\nD a.example SCAM STRONG x\nEND\n";
        java.security.Signature s = java.security.Signature.getInstance("SHA256withECDSA");
        s.initSign(key.getPrivate()); s.update(body.getBytes(StandardCharsets.US_ASCII));
        return (body + "SIGNATURE " + Base64.getEncoder().encodeToString(s.sign()) + "\n").getBytes(StandardCharsets.US_ASCII);
    }

    /** Holder so the no-anchor case reads clearly. */
    private static final class TrustAnchorsHolder { TrustAnchors empty() { return new TrustAnchors(); } }
    private static void rejects(TrustAnchors a, Reason want, String what, byte[] b) {
        try { ThreatBundleVerifier.verify(b, a, new Policy(0, true, NOW)); check(false, what); }
        catch (BundleException e) { check(e.reason == want, what + " got " + e.reason); }
    }
}
