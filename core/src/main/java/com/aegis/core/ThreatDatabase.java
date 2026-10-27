package com.aegis.core;

import java.time.Instant;
import java.util.*;

/** Immutable, already-verified threat indicators. Build only through ThreatBundleVerifier. */
public final class ThreatDatabase {
    public enum Category { MALWARE, PHISHING, SCAM, UNWANTED }
    /** Ordered by increasing strength of the publisher's claim. */
    public enum Confidence { SUSPICIOUS, STRONG, CONFIRMED }
    public record Entry(Category category, Confidence confidence, String label) {}

    private static final ThreatDatabase EMPTY = new ThreatDatabase(0, Instant.EPOCH, Instant.EPOCH, "none", Collections.emptyMap(), Collections.emptyMap(), Collections.emptyMap());

    public final long sequence;
    public final Instant issued;
    public final Instant expires;
    public final String keyId;
    private final Map<String, Entry> hashes, domains, certs;

    ThreatDatabase(long sequence, Instant issued, Instant expires, String keyId,
                   Map<String, Entry> hashes, Map<String, Entry> domains, Map<String, Entry> certs) {
        this.sequence = sequence; this.issued = issued; this.expires = expires; this.keyId = keyId;
        this.hashes = hashes; this.domains = domains; this.certs = certs;
    }
    public static ThreatDatabase empty() { return EMPTY; }
    public boolean isEmpty() { return this == EMPTY; }
    public int size() { return hashes.size() + domains.size() + certs.size(); }
    public boolean isStale(Instant now) { return !isEmpty() && now.isAfter(expires); }

    public Optional<Entry> sha256(String hex) { return Optional.ofNullable(hashes.get(hex.toLowerCase(Locale.ROOT))); }
    public Optional<Entry> signerCertificate(String hex) { return Optional.ofNullable(certs.get(hex.toLowerCase(Locale.ROOT))); }

    /** Exact host or any parent domain that has at least two labels. Input must be lowercase ASCII (punycode). */
    public Optional<Entry> domain(String asciiHost) {
        String h = asciiHost;
        while (true) {
            Entry e = domains.get(h);
            if (e != null) return Optional.of(e);
            int dot = h.indexOf('.');
            if (dot < 0 || h.indexOf('.', dot + 1) < 0) return Optional.empty();
            h = h.substring(dot + 1);
        }
    }
}
