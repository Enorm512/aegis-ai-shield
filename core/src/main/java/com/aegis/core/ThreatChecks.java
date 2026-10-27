package com.aegis.core;

import java.util.*;

/** Combines heuristic analysis with reputation lookups. Listings can only raise a verdict, never lower it. */
public final class ThreatChecks {
    private ThreatChecks() {}

    public static Analysis url(String input, ReputationProvider provider) {
        Analysis base = UrlAnalyzer.analyze(input);
        if (provider == null) return base;
        String host = null;
        for (Finding f : base.findings) if (f.code.equals("HOST")) host = f.detail.substring("Destination host: ".length());
        if (host == null || base.findings.stream().anyMatch(f -> f.code.equals("IP_LITERAL"))) return base;
        return merge(base, provider.domain(host), "domain");
    }

    public static Analysis apkHash(String sha256, ReputationProvider provider) {
        if (sha256 == null || !sha256.matches("[a-fA-F0-9]{64}"))
            return new Analysis(Analysis.Verdict.INSUFFICIENT_EVIDENCE, Collections.singletonList(new Finding("INVALID_HASH", "Expected a 64-character SHA-256 hex digest.")), "File hash");
        if (provider == null)
            return new Analysis(Analysis.Verdict.INSUFFICIENT_EVIDENCE, Collections.singletonList(new Finding("NO_HASH_INTELLIGENCE", "A SHA-256 fingerprint alone cannot determine whether a file is malicious.")), sha256);
        ReputationProvider.Reputation r = provider.sha256(sha256.toLowerCase(Locale.ROOT));
        // A hash alone can only clear a file against a database that was actually consulted.
        Analysis start = new Analysis(r.status() == ReputationProvider.Status.UNAVAILABLE
            ? Analysis.Verdict.INSUFFICIENT_EVIDENCE : Analysis.Verdict.NO_KNOWN_WARNING_SIGNS, Collections.emptyList(), sha256);
        return merge(start, r, "file hash");
    }

    public static Analysis signer(Analysis current, String certSha256, ReputationProvider provider) {
        if (provider == null) return current;
        return merge(current, provider.signerCertificate(certSha256.toLowerCase(Locale.ROOT)), "signing certificate");
    }

    static Analysis merge(Analysis base, ReputationProvider.Reputation r, String what) {
        List<Finding> fs = new ArrayList<>(base.findings);
        Analysis.Verdict v = base.verdict;
        switch (r.status()) {
            case LISTED -> {
                ThreatDatabase.Entry e = r.entry();
                fs.add(new Finding("THREATDB_LISTED", "The " + what + " is listed as " + e.category() + " (" + e.confidence()
                    + ") by the signed threat database [" + r.source() + "], label " + e.label() + "."));
                Analysis.Verdict listed = switch (e.confidence()) {
                    case CONFIRMED -> Analysis.Verdict.CONFIRMED_MALICIOUS;
                    case STRONG -> Analysis.Verdict.STRONG_INDICATORS;
                    case SUSPICIOUS -> Analysis.Verdict.SUSPICIOUS;
                };
                if (listed.compareTo(v) > 0) v = listed;
            }
            case NOT_LISTED -> fs.add(new Finding("THREATDB_NOT_LISTED", "The " + what + " is not in the local threat database [" + r.source()
                + "]. This does not mean it is safe; new threats appear before they are listed."));
            case UNAVAILABLE -> fs.add(new Finding("THREATDB_UNAVAILABLE", "No threat database is installed, so the " + what
                + " could not be checked against known threats."));
        }
        return new Analysis(v, fs, base.subject);
    }
}
