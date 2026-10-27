package com.aegis.core;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.KeyPair;
import java.time.*;
import java.time.temporal.ChronoUnit;
import java.util.*;

/** Tests for the publisher/developer data tools: FeedBuilder (threat-feed entries), DatasetImporter and the leakage guard. */
public final class DataToolsTests {
    private static int checks;
    private static void check(boolean ok, String message) { checks++; if (!ok) throw new AssertionError(message); }
    private static Path write(Path dir, String name, String content) throws Exception {
        Path p = dir.resolve(name); Files.write(p, content.getBytes(StandardCharsets.UTF_8)); return p;
    }

    public static void main(String[] args) throws Exception {
        Path dir = Files.createTempDirectory("aegis-feed");

        // --- FeedBuilder: line formats
        check("evil.example".equals(FeedBuilder.hostOf("evil.example")), "plain");
        check("evil.example".equals(FeedBuilder.hostOf("0.0.0.0 evil.example # comment")), "hosts format");
        check("evil.example".equals(FeedBuilder.hostOf("||evil.example^$third-party")), "adblock format");
        check("evil.example".equals(FeedBuilder.hostOf("https://user@evil.example:8443/login?x=1")), "URL format");
        check(FeedBuilder.hostOf("# comment") == null && FeedBuilder.hostOf("! adblock comment") == null && FeedBuilder.hostOf("[Adblock Plus]") == null && FeedBuilder.hostOf("") == null, "comments ignored");
        check(FeedBuilder.hostOf("two words here") == null && FeedBuilder.hostOf("http://[::1]/x") == null, "unsupported lines ignored");

        // --- FeedBuilder: sources manifest and licence gate
        write(dir, "a.txt", "evil.example\n0.0.0.0 phish.example\nwww.dup.example\n*.wild.example\n10.0.0.1\ncom\nlocalhost\ngoogle.com\nbankid.no\nsub.allowed.example\nbücher-login.example\nbad_name!.example\n");
        write(dir, "b.txt", "||dup.example^\nhttps://scam.example/pay\nevil.example\n");
        Path manifest = write(dir, "sources.txt", "# test\nsrcA|MIT|PHISHING|SUSPICIOUS|a.txt|Example A, MIT\nsrcB|CC0-1.0|SCAM|STRONG|b.txt|\n");
        Path allow = write(dir, "allow.txt", "allowed.example\n");
        List<FeedBuilder.Source> src = FeedBuilder.parseSources(manifest);
        check(src.size() == 2 && src.get(0).path().toString().endsWith("a.txt"), "manifest parsed, paths relative to the manifest");
        for (String bad : new String[] {"x|GPL-3.0|PHISHING|STRONG|a.txt|attr", "x|Proprietary|PHISHING|STRONG|a.txt|attr", "x|CC-BY-4.0|PHISHING|STRONG|a.txt|", "x|MIT|EVIL|STRONG|a.txt|a", "x|MIT|PHISHING|HIGH|a.txt|a", "bad id|MIT|PHISHING|STRONG|a.txt|a", "x|MIT|PHISHING"}) {
            Path m = write(dir, "bad.txt", bad + "\n");
            try { FeedBuilder.parseSources(m); check(false, "manifest should be refused: " + bad); } catch (FeedBuilder.SourceException e) { check(true, "refused " + bad); }
        }
        try { FeedBuilder.parseSources(write(dir, "dup.txt", "x|MIT|PHISHING|STRONG|a.txt|a\nx|MIT|PHISHING|STRONG|b.txt|a\n")); check(false, "duplicate id"); } catch (FeedBuilder.SourceException e) { check(true, "duplicate id refused"); }

        // --- FeedBuilder: filtering, merging, output
        FeedBuilder.Result r = FeedBuilder.build(src, FeedBuilder.loadAllowlist(allow), FeedBuilder.DEFAULT_MAX);
        Set<String> domains = new HashSet<>();
        for (String e : r.entries()) domains.add(e.split(" ")[1]);
        check(domains.containsAll(Arrays.asList("evil.example", "phish.example", "dup.example", "scam.example")), "good names kept: " + domains);
        check(domains.contains("xn--bcher-login-thb.example"), "IDN converted to punycode: " + domains);
        for (String gone : new String[] {"wild.example", "10.0.0.1", "com", "localhost", "google.com", "bankid.no", "sub.allowed.example", "allowed.example"}) check(!domains.contains(gone), "dropped " + gone);
        check(r.entries().contains("D evil.example SCAM STRONG srcB"), "duplicate keeps the higher confidence listing: " + r.entries());
        check(r.entries().get(0).contains(" STRONG "), "strongest entries first");
        FeedBuilder.SourceStats a = r.stats().get(0);
        check(a.dropped().get("protected") == 2 && a.dropped().get("allowlisted") == 1 && a.dropped().get("wildcard") == 1 && a.dropped().get("ip") == 1, "drop reasons counted: " + a.dropped());
        check(a.sha256().matches("[0-9a-f]{64}"), "input checksum recorded");
        String attr = FeedBuilder.attribution(r);
        check(attr.contains("srcA | licence MIT | Example A, MIT") && attr.contains("Total entries: " + r.entries().size()), "attribution text");
        check(FeedBuilder.build(src, Collections.emptySet(), FeedBuilder.DEFAULT_MAX).entries().size() == r.entries().size() + 1, "allowlist is optional");
        FeedBuilder.Result capped = FeedBuilder.build(src, Collections.emptySet(), 2);
        check(capped.entries().size() == 2 && capped.truncated() && capped.entries().stream().allMatch(e -> e.contains(" STRONG ")), "cap keeps the strongest entries");
        check(FeedBuilder.build(src, Collections.emptySet(), FeedBuilder.DEFAULT_MAX).entries().equals(FeedBuilder.build(src, Collections.emptySet(), FeedBuilder.DEFAULT_MAX).entries()), "deterministic output");

        // --- Round trip: builder output signs and verifies exactly as the app would load it
        KeyPair kp = ThreatBundleTool.generateKey();
        String keyId = ThreatBundleVerifier.TrustAnchors.keyId(kp.getPublic().getEncoded());
        Instant now = Instant.parse("2026-10-27T10:00:00Z");
        byte[] bundle = ThreatBundleTool.build(kp.getPrivate(), keyId, 1, now, now.plus(30, ChronoUnit.DAYS), r.entries());
        ThreatBundleVerifier.TrustAnchors anchors = new ThreatBundleVerifier.TrustAnchors();
        anchors.add(kp.getPublic().getEncoded());
        ThreatDatabase db = ThreatBundleVerifier.verify(bundle, anchors,
            new ThreatBundleVerifier.Policy(0, true, now.plusSeconds(60)));
        check(db.domain("evil.example").isPresent() && db.domain("scam.example").isPresent() && !db.domain("google.com").isPresent(), "signed builder output verifies and loads");

        // --- DatasetImporter
        check(DatasetImporter.mapLabel("Smishing", false) == 1 && DatasetImporter.mapLabel("ham", false) == 0 && DatasetImporter.mapLabel("spam", false) == null && DatasetImporter.mapLabel("spam", true) == 1 && DatasetImporter.mapLabel("other", false) == null, "label mapping");
        List<DatasetImporter.Row> uci = DatasetImporter.fromUci("ham\tSee you at 5\nspam\tWIN a free cruise, txt now\nham\tok\nnot a row\n", false);
        check(uci.size() == 2 && uci.get(0).label() == 0, "UCI format, spam skipped by default");
        check(DatasetImporter.fromUci("spam\tWIN now\n", true).size() == 1, "spam kept on request");
        List<DatasetImporter.Row> csv = DatasetImporter.fromCsv("﻿LABEL,TEXT,URL\nham,\"Hi, are we still on for \"\"lunch\"\"?\",No\nSmishing,\"Your parcel is held.\nPay at http://x.example\",Yes\nspam,Buy now,No\n", false);
        check(csv.size() == 2 && csv.get(0).text().equals("Hi, are we still on for \"lunch\"?") && csv.get(1).label() == 1 && csv.get(1).text().contains("\n"), "CSV with quotes, embedded newline and BOM: " + csv);
        try { DatasetImporter.fromCsv("a,b\n1,2\n", false); check(false, "missing columns"); } catch (IllegalArgumentException e) { check(true, "CSV without LABEL/TEXT refused"); }
        String line = DatasetImporter.toLine(new DatasetImporter.Row(1, "Your parcel|is held.\r\nPay now"), "en");
        check(line.equals("1|en|Your parcel is held. Pay now") && line.split("\\|", -1).length == 3, "pipes and newlines removed: " + line);
        check(DatasetImporter.toLine(new DatasetImporter.Row(0, "ok"), "en") == null, "too short dropped");

        // --- Leakage guard
        List<String> leaked = DatasetImporter.leaks(Arrays.asList("Pay the fee NOW at http://a.example", "Lunch at 12?"), Arrays.asList("pay the fee now at https://b.example/x"));
        check(leaked.size() == 1, "normalised duplicate across sets is a leak (case, link): " + leaked);
        check(DatasetImporter.leaks(Arrays.asList("Lunch at 12?"), Arrays.asList("Dinner at 7?")).isEmpty(), "distinct messages are not leaks");
        // The shipped training data must not overlap the locked evaluation sets.
        Path data = Paths.get("../ml/data");
        List<String> train = DatasetImporter.textsOf(data.resolve("train.txt"));
        for (String locked : Files.readAllLines(data.resolve("LOCKED"), StandardCharsets.UTF_8)) {
            if (locked.isBlank() || locked.startsWith("#")) continue;
            List<String> l = DatasetImporter.leaks(train, DatasetImporter.textsOf(data.resolve(locked.trim())));
            check(l.isEmpty(), "train.txt overlaps " + locked + ": " + l);
        }
        check(DatasetImporter.leaks(train, DatasetImporter.textsOf(data.resolve("test.txt"))).isEmpty(), "train.txt overlaps test.txt");

        System.out.println("DataToolsTests: " + checks + " checks passed");
    }
}
