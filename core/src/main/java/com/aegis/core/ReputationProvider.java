package com.aegis.core;

import java.util.*;
import java.util.function.Supplier;

/**
 * Replaceable reputation source. UNAVAILABLE means "could not be checked" and must never be shown as "not listed".
 * Only the local signed database is implemented; network providers would implement this same interface
 * and require their own privacy and licence review.
 */
public interface ReputationProvider {
    enum Status { LISTED, NOT_LISTED, UNAVAILABLE }
    record Reputation(Status status, ThreatDatabase.Entry entry, String source) {
        public static Reputation listed(ThreatDatabase.Entry e, String source) { return new Reputation(Status.LISTED, e, source); }
        public static Reputation notListed(String source) { return new Reputation(Status.NOT_LISTED, null, source); }
        public static Reputation unavailable(String source) { return new Reputation(Status.UNAVAILABLE, null, source); }
    }

    String id();
    /** asciiHost must be lowercase punycode (as emitted by UrlAnalyzer's HOST finding). */
    Reputation domain(String asciiHost);
    Reputation sha256(String lowercaseHex);
    Reputation signerCertificate(String lowercaseHex);

    /** Local, offline provider. An empty database is UNAVAILABLE, not an all-clear. */
    final class LocalDatabase implements ReputationProvider {
        private final Supplier<ThreatDatabase> source;
        public LocalDatabase(Supplier<ThreatDatabase> source) { this.source = source; }
        @Override public String id() { return "local-threat-db"; }
        private Reputation wrap(ThreatDatabase db, Optional<ThreatDatabase.Entry> hit) {
            String src = id() + "#" + db.sequence;
            return hit.map(e -> Reputation.listed(e, src)).orElseGet(() -> Reputation.notListed(src));
        }
        @Override public Reputation domain(String h) { ThreatDatabase d = source.get(); return d.isEmpty() ? Reputation.unavailable(id()) : wrap(d, d.domain(h)); }
        @Override public Reputation sha256(String h) { ThreatDatabase d = source.get(); return d.isEmpty() ? Reputation.unavailable(id()) : wrap(d, d.sha256(h)); }
        @Override public Reputation signerCertificate(String h) { ThreatDatabase d = source.get(); return d.isEmpty() ? Reputation.unavailable(id()) : wrap(d, d.signerCertificate(h)); }
    }

    /** Strongest listing wins; NOT_LISTED only if at least one provider actually answered. */
    final class Composite implements ReputationProvider {
        private final List<ReputationProvider> providers;
        public Composite(List<ReputationProvider> providers) { this.providers = Collections.unmodifiableList(new ArrayList<>(providers)); }
        @Override public String id() { return "composite"; }
        private Reputation merge(java.util.function.Function<ReputationProvider, Reputation> q) {
            Reputation best = null; boolean answered = false;
            for (ReputationProvider p : providers) {
                Reputation r;
                try { r = q.apply(p); } catch (RuntimeException ex) { continue; }
                if (r.status() == Status.LISTED && (best == null || r.entry().confidence().compareTo(best.entry().confidence()) > 0)) best = r;
                if (r.status() != Status.UNAVAILABLE) answered = true;
            }
            if (best != null) return best;
            return answered ? Reputation.notListed(id()) : Reputation.unavailable(id());
        }
        @Override public Reputation domain(String h) { return merge(p -> p.domain(h)); }
        @Override public Reputation sha256(String h) { return merge(p -> p.sha256(h)); }
        @Override public Reputation signerCertificate(String h) { return merge(p -> p.signerCertificate(h)); }
    }
}
