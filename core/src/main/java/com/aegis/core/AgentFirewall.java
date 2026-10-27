package com.aegis.core;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.*;

/**
 * Aegis AI Action Firewall (prototype). A policy gate that an AI assistant voluntarily asks before a consequential
 * action. It cannot see or control assistants that do not call it. Fail-closed: unknown agents, unknown provenance
 * for risky actions, engine errors and oversize requests are denied; "ask" decisions need a human approval that is
 * bound to the exact request and usable once.
 */
public final class AgentFirewall {
    public enum ActionType { SEND_DATA, SHARE_FILE, MESSAGE_AGENT, READ_SENSITIVE, EXECUTE_COMMAND, INSTALL_APP, FINANCIAL_TRANSACTION, USE_CREDENTIAL, MODIFY_SETTINGS }
    /** Where the instruction that led to this action came from. Only the first two are the user's own words. */
    public enum Provenance { USER_DIRECT, USER_CONFIRMED_PLAN, EXTERNAL_CONTENT, AGENT_TO_AGENT, UNKNOWN }
    public enum Verdict { ALLOW, ASK_USER, DENY }

    public static final int MAX_SUMMARY = 2000, MAX_PAYLOAD = 100_000, MAX_PENDING = 20, RATE_PER_MINUTE = 30, MAX_AUDIT = 500;
    private static final Set<ActionType> HIGH_RISK = Collections.unmodifiableSet(EnumSet.of(ActionType.EXECUTE_COMMAND, ActionType.INSTALL_APP,
        ActionType.FINANCIAL_TRANSACTION, ActionType.USE_CREDENTIAL, ActionType.MODIFY_SETTINGS));
    private static final Set<ActionType> OUTBOUND = Collections.unmodifiableSet(EnumSet.of(ActionType.SEND_DATA, ActionType.SHARE_FILE, ActionType.MESSAGE_AGENT));

    /** summary and payload are untrusted text supplied by the agent; amountMinor is in minor units (e.g. øre), or -1. */
    public record Request(String agentId, ActionType type, String destination, String summary, String payload, Provenance provenance, long amountMinor, String currency) {}
    /** dataKinds lists the kinds of sensitive data found in the request (never the values). */
    public record Decision(Verdict verdict, List<String> reasons, String approvalId, Set<String> dataKinds) {}
    /** Actions a newly paired agent gets by default; the risky ones need an explicit grant by the person. */
    public static final Set<ActionType> SAFE_GRANT = Collections.unmodifiableSet(EnumSet.of(ActionType.SEND_DATA, ActionType.SHARE_FILE, ActionType.MESSAGE_AGENT, ActionType.READ_SENSITIVE));
    /** What an audit entry records: a firewall decision, the person's answer, a redemption, a pairing change or the kill switch. */
    public enum Event { DECISION, USER_APPROVED, USER_DENIED, REDEEMED, REDEEM_REFUSED, PAIRED, PAIR_REJECTED, UNPAIRED, KILL_SWITCH_ON, KILL_SWITCH_OFF, LOG_DAMAGED,
        /** Aegis itself carried out a brokered action, or could not. */
        BROKER_PERFORMED, BROKER_FAILED,
        /** Aegis signed an approval token a server can check; reason = how it was granted. */
        TOKEN_ISSUED }
    /** type and verdict are null for events that have none. */
    public record AuditEntry(Instant time, Event event, String agentId, ActionType type, String destinationHost, Verdict verdict, List<String> reasons, String chainHash) {}

    /** brokered = Aegis performs the action itself once approved; the agent can never redeem such an approval for its own use. */
    private static final class Pending { final String hash, agentId, host; final ActionType type; final Instant expires; final boolean brokered; Boolean approved; boolean used;
        Pending(String hash, String agentId, ActionType type, String host, Instant expires, boolean brokered) { this.hash = hash; this.agentId = agentId; this.type = type; this.host = host; this.expires = expires; this.brokered = brokered; } }
    private static final int MAX_PENDING_PER_AGENT = 5;
    /** Expensive scans are computed before taking the lock so one agent cannot stall the others. */
    private record Scan(Set<SensitiveData.Kind> kinds, Set<String> injection, boolean timedOut) {}
    private static final long SCAN_BUDGET_MILLIS = 2000;

    private final Clock clock;
    private final SecureRandom random = new SecureRandom();
    private final Map<String, Set<ActionType>> agents = new HashMap<>();
    private final Set<String> trustedDestinations = new HashSet<>();
    private final Map<String, Deque<Instant>> recent = new HashMap<>();
    private final Map<String, Pending> pending = new LinkedHashMap<>();
    private final Deque<AuditEntry> audit = new ArrayDeque<>();
    private String chain = "genesis", anchor = "genesis"; // anchor = hash of the entry just before the oldest retained one
    private long financialAutoLimit = 0; // any financial action needs approval by default
    private boolean lockdown;

    public AgentFirewall(Clock clock) { this.clock = clock; }

    /**
     * Kill switch: forgets every paired agent and every pending or approved-but-unused approval, and refuses all
     * requests and redemptions until {@link #releaseKillSwitch()}. Returns the agents that were paired.
     */
    public synchronized List<String> killSwitch() {
        List<String> was = new ArrayList<>(new TreeSet<>(agents.keySet()));
        agents.clear(); pending.clear(); recent.clear();
        lockdown = true;
        append(Event.KILL_SWITCH_ON, "", null, "", null, Collections.singletonList("AGENTS_REMOVED_" + was.size()));
        return was;
    }
    public synchronized void releaseKillSwitch() { if (!lockdown) return; lockdown = false; append(Event.KILL_SWITCH_OFF, "", null, "", null, Collections.emptyList()); }
    /** Restores the switch state at start-up without writing an audit entry (the entry was written when it was flipped). */
    public synchronized void restoreLockdown(boolean on) { lockdown = on; if (on) { agents.clear(); pending.clear(); } }
    public synchronized boolean lockdown() { return lockdown; }

    /** The broker records whether it carried out an action (reason codes only, never the content). */
    public synchronized void noteBroker(String agentId, ActionType type, String destination, boolean performed, String reason) {
        append(performed ? Event.BROKER_PERFORMED : Event.BROKER_FAILED, agentId, type, hostOf(destination), null,
            reason == null || reason.isEmpty() ? Collections.emptyList() : Collections.singletonList(reason));
    }

    /** Records that an approval token was signed for this call (grant = USER_APPROVED or POLICY_ALLOW). The token itself is not logged. */
    public synchronized void noteToken(String agentId, ActionType type, String destination, String grant) {
        append(Event.TOKEN_ISSUED, agentId, type, hostOf(destination), null, Collections.singletonList(grant == null ? "" : grant));
    }

    /** The app records pairing decisions the person made, so the log shows who was let in and when. */
    public synchronized void notePairing(String agentId, Event event, boolean risky) {
        if (event != Event.PAIRED && event != Event.PAIR_REJECTED && event != Event.UNPAIRED) throw new IllegalArgumentException("not a pairing event");
        append(event, agentId, null, "", null, event == Event.PAIRED ? Collections.singletonList(risky ? "RISKY_ACTIONS_ALLOWED" : "SAFE_ACTIONS_ONLY") : Collections.emptyList());
    }

    public synchronized void registerAgent(String agentId, Set<ActionType> permitted) { agents.put(agentId, EnumSet.copyOf(permitted.isEmpty() ? EnumSet.noneOf(ActionType.class) : permitted)); }
    /** Also drops that agent's waiting and approved-but-unused approvals: a removed agent keeps nothing it was granted. */
    public synchronized void unregisterAgent(String agentId) { agents.remove(agentId); pending.values().removeIf(p -> p.agentId.equals(agentId)); }
    public synchronized void trustDestination(String domainOrHost) { trustedDestinations.add(domainOrHost.toLowerCase(Locale.ROOT)); }
    public synchronized void untrustDestination(String domainOrHost) { trustedDestinations.remove(domainOrHost.toLowerCase(Locale.ROOT)); }
    /** True for a plain host name the person may trust: 2+ labels of letters, digits and hyphens, not an IP address, at most 253 characters. */
    public static boolean isTrustableHost(String h) {
        if (h == null || h.length() > 253 || !h.matches("[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+")) return false;
        return !h.matches("[0-9.]+") && !h.startsWith("xn--") && !h.contains(".xn--");
    }

    public Decision evaluate(Request r) { return evaluate(r, false); }

    /** Like evaluate, for an action Aegis will carry out itself (the capability broker). An approval it creates is usable only through {@link #redeemBrokered}. */
    public Decision evaluateBrokered(Request r) { return evaluate(r, true); }

    private Decision evaluate(Request r, boolean brokered) {
        Scan scan = null;
        try {
            String sm = r == null || r.summary() == null ? "" : r.summary(), pl = r == null || r.payload() == null ? "" : r.payload();
            if (r != null && sm.length() <= MAX_SUMMARY && pl.length() <= MAX_PAYLOAD) {
                long deadline = Deadline.in(SCAN_BUDGET_MILLIS); // one budget for everything this request needs scanned
                boolean user = r.provenance() == Provenance.USER_DIRECT || r.provenance() == Provenance.USER_CONFIRMED_PLAN;
                // The payload may carry external content, so it is always scanned for injection; the agent's own summary only when the instruction was not the user's.
                Set<String> inj = new LinkedHashSet<>(InjectionIndicators.scan(pl, deadline));
                if (!user) inj.addAll(InjectionIndicators.scan(sm, deadline));
                Set<SensitiveData.Kind> kinds = EnumSet.noneOf(SensitiveData.Kind.class);
                kinds.addAll(SensitiveData.scan(pl, deadline));
                kinds.addAll(SensitiveData.scan(sm, deadline));
                String dest = r.destination() == null ? "" : (r.destination().length() > 4096 ? r.destination().substring(0, 4096) : r.destination());
                kinds.addAll(SensitiveData.scan(dest, deadline)); // secrets can ride in a URL's query string
                scan = new Scan(kinds, inj, false);
            }
        } catch (Deadline.ScanTimeout e) { scan = new Scan(EnumSet.noneOf(SensitiveData.Kind.class), new LinkedHashSet<>(), true);
        } catch (RuntimeException e) { scan = null; }
        synchronized (this) {
            try { return record(r, decide(r, scan, brokered)); }
            catch (RuntimeException e) { return record(r, deny("ENGINE_ERROR")); }
        }
    }

    private Decision decide(Request r, Scan scan, boolean brokered) {
        if (lockdown) return deny("KILL_SWITCH_ON");
        if (r == null || r.agentId() == null || r.type() == null || r.provenance() == null) return deny("MALFORMED_REQUEST");
        String summary = r.summary() == null ? "" : r.summary(), payload = r.payload() == null ? "" : r.payload();
        if (summary.length() > MAX_SUMMARY || payload.length() > MAX_PAYLOAD) return deny("OVERSIZE_REQUEST");
        Set<ActionType> permitted = agents.get(r.agentId());
        if (permitted == null) return deny("UNKNOWN_AGENT");
        if (!permitted.contains(r.type())) return deny("ACTION_NOT_PERMITTED_FOR_AGENT");
        Deque<Instant> window = recent.computeIfAbsent(r.agentId(), k -> new ArrayDeque<>());
        Instant now = clock.instant();
        while (!window.isEmpty() && window.peekFirst().isBefore(now.minusSeconds(60))) window.removeFirst();
        if (window.size() >= RATE_PER_MINUTE) return deny("RATE_LIMITED");
        window.addLast(now);

        boolean userDriven = r.provenance() == Provenance.USER_DIRECT || r.provenance() == Provenance.USER_CONFIRMED_PLAN;
        boolean trusted = destinationTrusted(r.destination());
        if (scan == null) return deny("ENGINE_ERROR");
        if (scan.timedOut()) return deny("SCAN_TIMEOUT");
        Set<SensitiveData.Kind> kinds = scan.kinds();
        boolean secrets = kinds.stream().anyMatch(SensitiveData.SECRETS::contains);
        boolean personal = kinds.stream().anyMatch(k -> !SensitiveData.SECRETS.contains(k));
        Set<String> injection = scan.injection();
        Set<String> kindNames = new TreeSet<>(); for (SensitiveData.Kind k : kinds) kindNames.add(k.name());
        boolean outbound = OUTBOUND.contains(r.type());
        boolean highRisk = HIGH_RISK.contains(r.type());

        List<String> deny = new ArrayList<>(), ask = new ArrayList<>();
        if (secrets && outbound && !trusted) deny.add("SECRET_TO_UNTRUSTED_DESTINATION");
        else if (secrets && outbound) ask.add("SECRET_IN_OUTBOUND_DATA");
        if (highRisk && !userDriven) deny.add("HIGH_RISK_ACTION_WITHOUT_USER_INSTRUCTION");
        if (!injection.isEmpty() && !userDriven && (outbound || highRisk || !kinds.isEmpty())) deny.add("INJECTION_INDICATORS_WITH_RISKY_ACTION");
        else if (!injection.isEmpty()) ask.add("INJECTION_INDICATORS");
        if (personal && outbound && !trusted) { if (userDriven) ask.add("PERSONAL_DATA_TO_UNTRUSTED_DESTINATION"); else deny.add("PERSONAL_DATA_TO_UNTRUSTED_DESTINATION"); }
        if (r.type() == ActionType.FINANCIAL_TRANSACTION && (r.amountMinor() < 0 || r.amountMinor() >= financialAutoLimit)) ask.add("FINANCIAL_ACTION");
        if (r.type() == ActionType.INSTALL_APP) ask.add("INSTALL_APP");
        if (r.type() == ActionType.EXECUTE_COMMAND) ask.add("EXECUTE_COMMAND");
        if (r.type() == ActionType.USE_CREDENTIAL) ask.add("CREDENTIAL_USE");
        if (r.type() == ActionType.MODIFY_SETTINGS) ask.add("MODIFY_SETTINGS");
        if (r.type() == ActionType.SHARE_FILE && !trusted) ask.add("FILE_TO_UNTRUSTED_DESTINATION");
        // Provenance is self-reported by the agent, so it may turn a DENY into a question to the person but never a question into a silent ALLOW.
        if (outbound && !trusted) ask.add(userDriven ? "UNTRUSTED_DESTINATION" : "UNTRUSTED_DESTINATION_WITHOUT_USER_INSTRUCTION");
        if (r.type() == ActionType.READ_SENSITIVE) ask.add(userDriven ? "SENSITIVE_READ" : "SENSITIVE_READ_WITHOUT_USER_INSTRUCTION");

        if (!deny.isEmpty()) return new Decision(Verdict.DENY, dedupe(deny), null, kindNames);
        if (!ask.isEmpty()) {
            expire();
            long open = pending.values().stream().filter(p -> p.approved == null).count();
            long mine = pending.values().stream().filter(p -> p.approved == null && p.agentId.equals(r.agentId())).count();
            if (open >= MAX_PENDING || mine >= MAX_PENDING_PER_AGENT) return deny("TOO_MANY_PENDING_APPROVALS");
            byte[] id = new byte[16]; random.nextBytes(id);
            String approvalId = hex(id);
            pending.put(approvalId, new Pending(requestHash(r), r.agentId(), r.type(), safeHost(hostOf(r.destination())), now.plusSeconds(300), brokered));
            return new Decision(Verdict.ASK_USER, dedupe(ask), approvalId, kindNames);
        }
        return new Decision(Verdict.ALLOW, Collections.singletonList("NO_RISK_SIGNALS"), null, kindNames);
    }

    /** Called by the user interface only. */
    public synchronized boolean resolve(String approvalId, boolean approve) {
        expire();
        Pending p = pending.get(approvalId);
        if (p == null || p.approved != null) return false;
        p.approved = approve;
        if (!approve) pending.remove(approvalId); // a refusal frees its slot immediately
        append(approve ? Event.USER_APPROVED : Event.USER_DENIED, p.agentId, p.type, p.host, null, Collections.emptyList());
        return true;
    }

    /** The agent redeems an approval for the exact same request, once. Anything else returns false. Brokered approvals are refused. */
    public synchronized boolean redeem(String approvalId, Request r) { return redeem(approvalId, r, false); }

    /** Aegis' own broker redeems a brokered approval just before it performs the action. */
    public synchronized boolean redeemBrokered(String approvalId, Request r) { return redeem(approvalId, r, true); }

    private boolean redeem(String approvalId, Request r, boolean broker) {
        expire();
        Pending p = approvalId == null ? null : pending.get(approvalId);
        String agent = r == null ? "" : String.valueOf(r.agentId());
        ActionType type = r == null ? null : r.type();
        String host = r == null ? "" : hostOf(r.destination());
        String refused = lockdown ? "KILL_SWITCH_ON" : p == null ? "UNKNOWN_OR_EXPIRED_APPROVAL" : !agents.containsKey(p.agentId) ? "AGENT_NOT_PAIRED" : p.brokered != broker ? (broker ? "NOT_A_BROKERED_APPROVAL" : "BROKERED_ACTION")
            : p.used || !Boolean.TRUE.equals(p.approved) ? "NOT_APPROVED"
            : r == null || !p.agentId.equals(r.agentId()) || !p.hash.equals(requestHash(r)) ? "REQUEST_CHANGED" : null;
        if (refused != null) { append(Event.REDEEM_REFUSED, agent, type, host, null, Collections.singletonList(refused)); return false; }
        p.used = true;
        pending.remove(approvalId);
        append(Event.REDEEMED, agent, type, host, null, Collections.emptyList());
        return true;
    }

    /** Ids of approvals still waiting for the person, oldest first. */
    public synchronized List<String> openApprovals() {
        expire();
        List<String> out = new ArrayList<>();
        for (Map.Entry<String, Pending> e : pending.entrySet()) if (e.getValue().approved == null) out.add(e.getKey());
        return out;
    }

    public synchronized int pendingCount() { expire(); return (int) pending.values().stream().filter(p -> p.approved == null).count(); }

    private void expire() { Instant now = clock.instant(); pending.values().removeIf(p -> now.isAfter(p.expires)); }

    public synchronized List<AuditEntry> auditLog() { return Collections.unmodifiableList(new ArrayList<>(audit)); }

    /** Recomputes the hash chain over the retained entries; false if any retained entry was altered, reordered or removed from the middle. */
    public synchronized boolean verifyAudit() { return verifyChain(new ArrayList<>(audit), anchor, chain); }

    /** Verifies an exported copy of the log against the anchor and head hashes. */
    public static boolean verifyChain(List<AuditEntry> entries, String anchor, String head) {
        String prev = anchor;
        for (AuditEntry e : entries) {
            if (!sha(prev + auditBody(e)).equals(e.chainHash())) return false;
            prev = e.chainHash();
        }
        return prev.equals(head);
    }
    public synchronized String auditAnchor() { return anchor; }
    public synchronized String auditHead() { return chain; }

    private Decision record(Request r, Decision d) {
        append(Event.DECISION, r == null ? "" : String.valueOf(r.agentId()), r == null ? null : r.type(), r == null ? "" : hostOf(r.destination()), d.verdict(), d.reasons());
        return d;
    }

    /** Every field is reduced to a fixed character set, so stored and exported logs need no escaping and cannot carry agent text. */
    private void append(Event event, String agentId, ActionType type, String host, Verdict verdict, List<String> reasons) {
        List<String> rs = new ArrayList<>();
        for (String x : reasons) rs.add(x.replaceAll("[^A-Z0-9_]", "?"));
        AuditEntry draft = new AuditEntry(clock.instant(), event, safeAgent(agentId), type, safeHost(host), verdict, Collections.unmodifiableList(rs), "");
        String h = sha(chain + auditBody(draft));
        chain = h;
        if (audit.size() >= MAX_AUDIT) anchor = audit.removeFirst().chainHash();
        audit.addLast(new AuditEntry(draft.time(), event, draft.agentId(), type, draft.destinationHost(), verdict, draft.reasons(), h));
    }
    private static String safeAgent(String a) { return a == null ? "" : (a.length() > 255 ? a.substring(0, 255) : a).replaceAll("[^A-Za-z0-9._-]", "?"); }
    private static String safeHost(String h) { return h == null ? "" : (h.length() > 253 ? h.substring(0, 253) : h).replaceAll("[^a-z0-9.:\\[\\]_-]", "?"); }

    private static String auditBody(AuditEntry e) { return e.time() + "|" + e.event() + "|" + e.agentId() + "|" + e.type() + "|" + e.destinationHost() + "|" + e.verdict() + "|" + e.reasons(); }

    // --- Persistence. The app stores these texts encrypted in its private storage; the formats are plain so an export can be read and checked.

    private static final String AUDIT_MAGIC = "AEGIS-AUDIT 1", PENDING_MAGIC = "AEGIS-PENDING 1";
    private static final java.util.regex.Pattern HEX64 = java.util.regex.Pattern.compile("[0-9a-f]{64}"), HEX32 = java.util.regex.Pattern.compile("[0-9a-f]{32}");

    /** The audit log as text: a header with the anchor and head hashes, then one tab-separated line per entry. */
    public synchronized String exportAudit() {
        StringBuilder b = new StringBuilder(AUDIT_MAGIC).append('\n').append("anchor ").append(anchor).append('\n').append("head ").append(chain).append('\n');
        for (AuditEntry e : audit)
            b.append(e.time()).append('\t').append(e.event()).append('\t').append(e.agentId()).append('\t').append(e.type() == null ? "-" : e.type().name()).append('\t')
             .append(e.destinationHost()).append('\t').append(e.verdict() == null ? "-" : e.verdict().name()).append('\t').append(String.join(",", e.reasons())).append('\t').append(e.chainHash()).append('\n');
        return b.toString();
    }

    /** Parses exportAudit() text. Returns null for anything malformed; the chain is not checked here (see verifyChain). */
    public static Restored parseAudit(String text) {
        if (text == null || !text.startsWith(AUDIT_MAGIC + "\n")) return null;
        String[] lines = text.split("\n", -1);
        if (lines.length < 3 || !lines[1].startsWith("anchor ") || !lines[2].startsWith("head ")) return null;
        String a = lines[1].substring(7), h = lines[2].substring(5);
        if (!(a.equals("genesis") || HEX64.matcher(a).matches()) || !(h.equals("genesis") || HEX64.matcher(h).matches())) return null;
        List<AuditEntry> out = new ArrayList<>();
        for (int i = 3; i < lines.length; i++) {
            if (lines[i].isEmpty()) { if (i == lines.length - 1) break; return null; }
            String[] f = lines[i].split("\t", -1);
            if (f.length != 8 || out.size() >= MAX_AUDIT || !HEX64.matcher(f[7]).matches()) return null;
            try {
                List<String> rs = f[6].isEmpty() ? Collections.emptyList() : Collections.unmodifiableList(Arrays.asList(f[6].split(",", -1)));
                if (!f[2].equals(safeAgent(f[2])) || !f[4].equals(safeHost(f[4])) || rs.stream().anyMatch(x -> !x.matches("[A-Z0-9_?]+"))) return null;
                out.add(new AuditEntry(Instant.parse(f[0]), Event.valueOf(f[1]), f[2], f[3].equals("-") ? null : ActionType.valueOf(f[3]), f[4], f[5].equals("-") ? null : Verdict.valueOf(f[5]), rs, f[7]));
            } catch (RuntimeException e) { return null; }
        }
        return new Restored(out, a, h);
    }
    public record Restored(List<AuditEntry> entries, String anchor, String head) {}

    /**
     * Loads a saved log at start-up, before any request. An intact log is continued. A damaged, edited or unreadable one
     * is not trusted: the new log starts from a hash of the damaged text and its first entry says LOG_DAMAGED, so the
     * break stays visible. Returns true when the saved log was intact.
     */
    public synchronized boolean restoreAudit(String text) {
        if (text == null || text.isEmpty()) return true; // nothing saved yet
        Restored r = parseAudit(text);
        if (r != null && verifyChain(r.entries(), r.anchor(), r.head())) {
            audit.clear(); audit.addAll(r.entries()); anchor = r.anchor(); chain = r.head();
            return true;
        }
        audit.clear(); anchor = sha("damaged|" + text); chain = anchor;
        append(Event.LOG_DAMAGED, "", null, "", null, Collections.singletonList(r == null ? "UNREADABLE" : "CHAIN_BROKEN"));
        return false;
    }

    /** Open and approved-but-unused approvals, so an approval survives the app being stopped within its five minutes. */
    public synchronized String exportPending() {
        expire();
        StringBuilder b = new StringBuilder(PENDING_MAGIC).append('\n');
        for (Map.Entry<String, Pending> e : pending.entrySet()) {
            Pending p = e.getValue();
            if (p.used || p.brokered) continue; // brokered actions are held in memory by the broker; without it they cannot be carried out
            b.append(e.getKey()).append('\t').append(p.hash).append('\t').append(p.agentId).append('\t').append(p.type.name()).append('\t').append(p.host.isEmpty() ? "-" : p.host)
             .append('\t').append(p.expires.toEpochMilli()).append('\t').append(p.approved == null ? "-" : p.approved ? "1" : "0").append('\n');
        }
        return b.toString();
    }

    /** Restores exportPending() text. Expired, refused, malformed entries and entries of agents no longer paired are dropped. Returns how many were kept. */
    public synchronized int restorePending(String text) {
        if (text == null || !text.startsWith(PENDING_MAGIC + "\n") || lockdown) return 0;
        Instant now = clock.instant();
        int kept = 0;
        String[] lines = text.split("\n");
        for (int i = 1; i < lines.length && pending.size() < MAX_PENDING; i++) {
            String[] f = lines[i].split("\t", -1);
            if (f.length != 7 || !HEX32.matcher(f[0]).matches() || !HEX64.matcher(f[1]).matches() || pending.containsKey(f[0])) continue;
            try {
                ActionType type = ActionType.valueOf(f[3]);
                Instant exp = Instant.ofEpochMilli(Long.parseLong(f[5]));
                Set<ActionType> permitted = agents.get(f[2]);
                // An expiry further out than any approval could have is not trusted either.
                if (permitted == null || !permitted.contains(type) || !now.isBefore(exp) || exp.isAfter(now.plusSeconds(300)) || f[6].equals("0")) continue;
                if (!(f[6].equals("-") || f[6].equals("1"))) continue;
                String host = f[4].equals("-") ? "" : f[4];
                if (!host.equals(safeHost(host))) continue;
                Pending p = new Pending(f[1], f[2], type, host, exp, false);
                p.approved = f[6].equals("1") ? Boolean.TRUE : null;
                pending.put(f[0], p);
                kept++;
            } catch (RuntimeException ignored) { }
        }
        return kept;
    }

    /** Exact host match only: trusting "api.example.org" does not trust "evil.api.example.org" or a whole multi-tenant suffix. */
    private boolean destinationTrusted(String destination) {
        String h = hostOf(destination);
        return !h.isEmpty() && trustedDestinations.contains(h);
    }

    /** Host extracted by real URI parsing (userinfo and ports ignored). Empty if it cannot be determined. Safe to show to a person. */
    public static String hostOf(String destination) {
        if (destination == null) return "";
        String d = destination.trim().toLowerCase(Locale.ROOT);
        try {
            if (d.contains("://")) { String h = new URI(d).getHost(); return h == null ? "" : h; }
        } catch (Exception e) { return ""; }
        int slash = d.indexOf('/');
        if (slash >= 0) d = d.substring(0, slash);
        return d.matches("[a-z0-9.-]{1,253}") ? d : "";
    }

    private static Decision deny(String reason) { return new Decision(Verdict.DENY, Collections.singletonList(reason), null, Collections.emptySet()); }
    private static List<String> dedupe(List<String> l) { return Collections.unmodifiableList(new ArrayList<>(new LinkedHashSet<>(l))); }

    /** Every field is length-prefixed so no field value can imitate a delimiter or spill into its neighbour. */
    static String requestHash(Request r) {
        StringBuilder b = new StringBuilder();
        for (String f : new String[] {r.agentId(), String.valueOf(r.type()), r.destination(), Long.toString(r.amountMinor()), r.currency(), String.valueOf(r.provenance()), r.summary(), sha(String.valueOf(r.payload()))})
            b.append(f == null ? -1 : f.length()).append(':').append(f == null ? "" : f).append(';');
        return sha(b.toString());
    }
    private static String sha(String s) {
        try { return hex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8))); }
        catch (NoSuchAlgorithmException e) { throw new AssertionError(e); }
    }
    private static String hex(byte[] b) { StringBuilder s = new StringBuilder(); for (byte x : b) s.append(String.format(Locale.ROOT, "%02x", x & 255)); return s.toString(); }

    /**
     * What the person should see of a payload or command: control, format and bidi characters shown as visible code
     * points, line breaks as a symbol, clipped to {@code max} characters. Never hides what a command would do.
     */
    public static String previewSafe(String untrusted, int max) {
        if (untrusted == null) return "";
        StringBuilder b = new StringBuilder();
        int shown = 0;
        for (int i = 0; i < untrusted.length() && shown < max; ) {
            int cp = untrusted.codePointAt(i);
            i += Character.charCount(cp);
            int type = Character.getType(cp);
            if (cp == '\n') b.append('\u23ce');
            else if (cp == '\t') b.append("    ");
            else if (type == Character.CONTROL || type == Character.FORMAT || type == Character.UNASSIGNED || type == Character.PRIVATE_USE || (cp >= 0xE0000 && cp <= 0xE007F)) b.append("<U+").append(String.format("%04X", cp)).append('>');
            else b.appendCodePoint(cp);
            shown++;
        }
        if (shown >= max && untrusted.length() > max) b.append("…");
        return b.toString();
    }

    /** Text safe to show a person: control and format characters removed, length-limited. Always show it as the agent's claim. */
    public static String displaySafe(String untrusted) {
        if (untrusted == null) return "";
        String t = untrusted.length() > 200 ? untrusted.substring(0, 200) + "…" : untrusted;
        return t.replaceAll("[\\p{Cntrl}\\p{Cf}]", " ");
    }
}
