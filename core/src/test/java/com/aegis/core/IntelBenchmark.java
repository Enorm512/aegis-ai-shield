package com.aegis.core;

import java.time.*;
import java.util.*;

/** Measures verify+parse time and lookup latency on the machine that runs it. Numbers are host-specific, not device claims. */
public final class IntelBenchmark {
    public static void main(String[] args) throws Exception {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 200_000;
        var kp = ThreatBundleTool.generateKey();
        var anchors = new ThreatBundleVerifier.TrustAnchors();
        String id = anchors.add(kp.getPublic().getEncoded());
        Random r = new Random(1);
        List<String> entries = new ArrayList<>(n);
        List<String> hosts = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            if (i % 2 == 0) { String h = "d" + Integer.toString(r.nextInt(Integer.MAX_VALUE), 36) + i + ".example"; hosts.add(h); entries.add("D " + h + " PHISHING STRONG bench"); }
            else { StringBuilder sb = new StringBuilder(); for (int j = 0; j < 24; j++) sb.append(String.format("%02x", r.nextInt(256))); String hx = sb.append(String.format("%016x", i)).toString(); entries.add("H " + hx + " MALWARE CONFIRMED bench"); }
        }
        Instant now = Instant.now();
        byte[] b = ThreatBundleTool.build(kp.getPrivate(), id, 1, now, now.plusSeconds(86400), entries);
        long t0 = System.nanoTime();
        ThreatDatabase db = null;
        for (int i = 0; i < 5; i++) db = ThreatBundleVerifier.verify(b, anchors, new ThreatBundleVerifier.Policy(0, true, now));
        double verifyMs = (System.nanoTime() - t0) / 5e6;
        int lookups = 2_000_000, hit = 0;
        t0 = System.nanoTime();
        for (int i = 0; i < lookups; i++) {
            String h = (i % 2 == 0) ? hosts.get(i % hosts.size()) : "sub.unlisted" + i + ".test";
            if (db.domain("a." + h).isPresent()) hit++;
        }
        double ns = (System.nanoTime() - t0) / (double) lookups;
        System.out.printf("entries=%d bundleBytes=%d verifyAndParseMs=%.0f domainLookupNs=%.0f hits=%d (JVM %s, %d cpus)%n",
            n, b.length, verifyMs, ns, hit, System.getProperty("java.version"), Runtime.getRuntime().availableProcessors());
    }
}
