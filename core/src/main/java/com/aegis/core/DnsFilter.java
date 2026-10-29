package com.aegis.core;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Decides whether a DNS name is answered or blocked.
 * Precedence: tripwire (canary) names, user allowlist, user blocklist, signed threat database. Fail-open when no database is available.
 */
public final class DnsFilter {
    public enum Action { ALLOW, BLOCK }
    public enum Reason { USER_ALLOW, USER_BLOCK, THREAT_DB, NO_MATCH, CANARY }
    /** Called on the DNS thread when a tripwire name is looked up; must return quickly and never throw into the filter. */
    public interface CanaryListener { void tripped(CanaryTokens.Token token, String name); }
    public record Decision(Action action, Reason reason, ThreatDatabase.Entry entry, boolean warnOnly) {}
    /** Called on the DNS thread when an AI model API is looked up (AgentBehaviour.aiService); must return quickly. */
    public interface AiLookupListener { void looked(String service); }

    /** Connectivity-critical names a feed can never block (limits damage from a mistaken or compromised feed). */
    private static final Set<String> PROTECTED = Collections.unmodifiableSet(new HashSet<>(Arrays.asList("connectivitycheck.gstatic.com", "connectivitycheck.android.com", "clients3.google.com",
        "time.android.com", "captive.apple.com", "dns.google", "one.one.one.one", "dns.quad9.net")));

    /** Thread-safe user lists. Entries are validated domains; a listed domain also covers its subdomains. */
    public static final class DomainLists {
        private final Set<String> allow = ConcurrentHashMap.newKeySet(), block = ConcurrentHashMap.newKeySet();
        public static final int MAX_ENTRIES = 5000;
        private static boolean add(Set<String> s, String d) {
            String n = norm(d);
            if (!ThreatBundleVerifier.validDomain(n) || s.size() >= MAX_ENTRIES) return false;
            return s.add(n) || true;
        }
        public boolean allow(String d) { return add(allow, d); }
        public boolean block(String d) { return add(block, d); }
        public boolean unallow(String d) { return allow.remove(norm(d)); }
        public boolean unblock(String d) { return block.remove(norm(d)); }
        public Set<String> allowed() { return new TreeSet<>(allow); }
        public Set<String> blocked() { return new TreeSet<>(block); }
        private static String norm(String d) {
            String n = d == null ? "" : d.trim().toLowerCase(Locale.ROOT);
            return n.endsWith(".") ? n.substring(0, n.length() - 1) : n;
        }
        boolean matches(Set<String> s, String name) {
            String h = name;
            while (true) {
                if (s.contains(h)) return true;
                int dot = h.indexOf('.');
                if (dot < 0) return false;
                h = h.substring(dot + 1);
            }
        }
    }

    private final ReputationProvider provider;
    private final DomainLists lists;
    private volatile boolean blockSuspicious;
    private volatile CanaryTokens.Registry canaries;
    private volatile CanaryListener canaryListener;
    private volatile AiLookupListener aiListener;

    public DnsFilter(ReputationProvider provider, DomainLists lists) { this.provider = provider; this.lists = lists; }
    public void setBlockSuspicious(boolean v) { blockSuspicious = v; }
    public DomainLists lists() { return lists; }
    public void setCanaries(CanaryTokens.Registry r, CanaryListener l) { canaries = r; canaryListener = l; }
    public void setAiLookupListener(AiLookupListener l) { aiListener = l; }

    /** name must be lowercase ASCII as produced by DnsMessage.parseQuery. */
    public Decision decide(String name) {
        // Tripwires first: a decoy name is always answered locally (blocked) and reported, whatever the lists say,
        // so the token never leaves the phone and an allowlist entry cannot hide a trip.
        CanaryTokens.Registry c = canaries;
        if (c != null) {
            Optional<CanaryTokens.Token> t = c.match(name);
            if (t.isPresent()) {
                CanaryListener l = canaryListener;
                if (l != null) { try { l.tripped(t.get(), name); } catch (RuntimeException ignored) { } }
                return new Decision(Action.BLOCK, Reason.CANARY, null, false);
            }
        }
        AiLookupListener ai = aiListener;
        if (ai != null) {
            String service = AgentBehaviour.aiService(name);
            if (service != null) { try { ai.looked(service); } catch (RuntimeException ignored) { } }
        }
        if (lists.matches(lists.allow, name)) return new Decision(Action.ALLOW, Reason.USER_ALLOW, null, false);
        if (lists.matches(lists.block, name)) return new Decision(Action.BLOCK, Reason.USER_BLOCK, null, false);
        if (ProtectedDomains.shielded(name)) return new Decision(Action.ALLOW, Reason.NO_MATCH, null, false);
        if (provider == null) return new Decision(Action.ALLOW, Reason.NO_MATCH, null, false);
        ReputationProvider.Reputation r;
        try { r = provider.domain(name); } catch (RuntimeException e) { return new Decision(Action.ALLOW, Reason.NO_MATCH, null, false); }
        if (r.status() != ReputationProvider.Status.LISTED) return new Decision(Action.ALLOW, Reason.NO_MATCH, null, false);
        ThreatDatabase.Entry e = r.entry();
        boolean block = e.confidence().compareTo(ThreatDatabase.Confidence.STRONG) >= 0 || blockSuspicious;
        return block ? new Decision(Action.BLOCK, Reason.THREAT_DB, e, false) : new Decision(Action.ALLOW, Reason.THREAT_DB, e, true);
    }
}
