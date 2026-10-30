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
        TOKEN_ISSUED,
        /** Denials beyond the per-minute logging budget for one agent, summarised as one entry (reason NOT_LOGGED_n). */
        DENIALS_SUMMARISED,
        /** An agent hit the request rate limit (security log; at most once per agent per 10 minutes). */
        RATE_LIMIT_HIT,
        /** The person stopped or resumed kinds of action for every agent (reasons = the action types). */
        CAPABILITY_STOPPED, CAPABILITY_RESUMED,
        /** The person put one agent in read-only mode, or took it out. */
        READ_ONLY_ON, READ_ONLY_OFF }

    /**
     * Events that are also written to the separate security log, which ordinary request traffic cannot rotate away:
     * changes the person made, the kill switch, log damage and rate-limit hits. All are bounded by human action or throttled.
     */
    private static final Set<Event> SECURITY_EVENTS = Collections.unmodifiableSet(EnumSet.of(Event.PAIRED, Event.PAIR_REJECTED, Event.UNPAIRED,
        Event.KILL_SWITCH_ON, Event.KILL_SWITCH_OFF, Event.LOG_DAMAGED, Event.USER_APPROVED, Event.USER_DENIED, Event.RATE_LIMIT_HIT,
        Event.CAPABILITY_STOPPED, Event.CAPABILITY_RESUMED, Event.READ_ONLY_ON, Event.READ_ONLY_OFF));
    public static final int MAX_SECURITY = 300;
    /** Denials logged individually per agent per minute; the rest are counted and summarised. */
    public static final int DENIALS_LOGGED_PER_MINUTE = 5;
    private static final int MAX_DENY_WINDOWS = 64;
    private static final long RATE_NOTE_SECONDS = 600;
    /** type and verdict are null for events that have none. */
    public record AuditEntry(Instant time, Event event, String agentId, ActionType type, String destinationHost, Verdict verdict, List<String> reasons, String chainHash) {}

    /** brokered = Aegis performs the action itself once approved; the agent can never redeem such an approval for its own use. */
    private static final class Pending { final String hash, agentId, host; final ActionType type; final Instant expires; final boolean brokered; Boolean approved; boolean used;
        Pending(String hash, String agentId, ActionType type, String host, Instant expires, boolean brokered) { this.hash = hash; this.agentId = agentId; this.type = type; this.host = host; this.expires = expires; this.brokered = brokered; } }
    private static final int MAX_PENDING_PER_AGENT = 5;

    /**
     * Cross-step ("chain") rules. Each request is also judged against what the same agent did earlier in its session, so
     * a sequence is caught when every single step would pass on its own: reading private data and then sending, acting
     * after an earlier step carried hijack wording, switching from "the content told me" to "the person told me", and a
     * secret or card number split across several sends. Chain rules only add questions or refusals. Memory only: a
     * session ends CHAIN_GAP_SECONDS after the agent's last request, and with unpairing or the kill switch.
     */
    public static final long CHAIN_GAP_SECONDS = 600, PROVENANCE_SWITCH_SECONDS = 120;
    public static final int CHAIN_STEPS = 20, CHAIN_TAIL = 2000;
    private static final int MAX_TRAILS = 64, MAX_TAIL_HOSTS = 8;
    public enum StepOutcome { ALLOWED, ASKED, APPROVED, DENIED }
    /** One earlier request of the session, for showing the person the chain. host is safe to show; no content is kept here. */
    public record ChainStep(Instant time, ActionType type, String host, StepOutcome outcome, boolean fromContent) {}
    private static final class Trail {
        Instant last;
        final List<ChainStep> steps = new ArrayList<>();
        /** privateRead: the person approved a sensitive read this session; later sends ask, except to hosts approved since. */
        boolean privateRead, injection;
        final Set<String> approvedAfterRead = new HashSet<>();
        Provenance lastProvenance; Instant lastAt;
        /** The last CHAIN_TAIL characters actually sent to each host (allowed, or approved and used), to catch data split across sends. */
        final LinkedHashMap<String, String> tails = new LinkedHashMap<>();
    }
    /** Expensive scans are computed before taking the lock so one agent cannot stall the others. */
    private record Scan(Set<SensitiveData.Kind> kinds, Set<String> injection, boolean timedOut, Set<SensitiveData.Kind> split) {}
    private static final long SCAN_BUDGET_MILLIS = 2000;

    private final Clock clock;
    private final SecureRandom random = new SecureRandom();
    private final Map<String, Set<ActionType>> agents = new HashMap<>();
    private final Set<String> trustedDestinations = new HashSet<>();
    private final Map<String, Deque<Instant>> recent = new HashMap<>();
    private final Map<String, Pending> pending = new LinkedHashMap<>();
    private final Chain log = new Chain(AUDIT_MAGIC, MAX_AUDIT);
    private final Chain security = new Chain(SECURITY_MAGIC, MAX_SECURITY);
    private static final class DenyWindow { final Instant start; int logged, suppressed; DenyWindow(Instant s) { start = s; } }
    private final Map<String, DenyWindow> denyWindows = new LinkedHashMap<>();
    private final Map<String, Instant> rateNotes = new LinkedHashMap<>();
    /** Agents whose current session looks autonomous (AgentBehaviour): every action asks the person first. */
    private final Set<String> paused = new HashSet<>();
    private final Map<String, Trail> trails = new LinkedHashMap<>();
    /** Emergency stops per kind of action, for every agent; and agents the person limited to reading. Both refuse, never ask. */
    private final Set<ActionType> stopped = EnumSet.noneOf(ActionType.class);
    private final Set<String> readOnly = new HashSet<>();
    private long revision; // changes whenever anything that is saved changes; lets the app skip writes when nothing happened
    private long financialAutoLimit = 0; // any financial action needs approval by default
    private boolean lockdown;

    /**
     * One bounded, SHA-256 hash-chained log. anchor = hash of the entry just before the oldest retained one, so
     * dropping the oldest entries keeps the rest verifiable while any edit, reordering or removal from the middle breaks it.
     */
    private static final class Chain {
        final String magic; final int max;
        final Deque<AuditEntry> entries = new ArrayDeque<>();
        String head = "genesis", anchor = "genesis";
        Chain(String magic, int max) { this.magic = magic; this.max = max; }

        void add(AuditEntry draft) {
            String h = sha(head + auditBody(draft));
            head = h;
            if (entries.size() >= max) anchor = entries.removeFirst().chainHash();
            entries.addLast(new AuditEntry(draft.time(), draft.event(), draft.agentId(), draft.type(), draft.destinationHost(), draft.verdict(), draft.reasons(), h));
        }

        String export() {
            StringBuilder b = new StringBuilder(magic).append('\n').append("anchor ").append(anchor).append('\n').append("head ").append(head).append('\n');
            for (AuditEntry e : entries)
                b.append(e.time()).append('\t').append(e.event()).append('\t').append(e.agentId()).append('\t').append(e.type() == null ? "-" : e.type().name()).append('\t')
                 .append(e.destinationHost()).append('\t').append(e.verdict() == null ? "-" : e.verdict().name()).append('\t').append(String.join(",", e.reasons())).append('\t').append(e.chainHash()).append('\n');
            return b.toString();
        }

        /** True when intact. Otherwise the chain restarts from a hash of the damaged text and the caller records LOG_DAMAGED. */
        boolean restore(String text) {
            Restored r = parse(text, magic, max);
            if (r != null && verifyChain(r.entries(), r.anchor(), r.head())) {
                entries.clear(); entries.addAll(r.entries()); anchor = r.anchor(); head = r.head();
                return true;
            }
            entries.clear(); anchor = sha("damaged|" + text); head = anchor;
            return false;
        }
    }

    public AgentFirewall(Clock clock) { this.clock = clock; }

    /**
     * Kill switch: forgets every paired agent and every pending or approved-but-unused approval, and refuses all
     * requests and redemptions until {@link #releaseKillSwitch()}. Returns the agents that were paired.
     */
    public synchronized List<String> killSwitch() {
        List<String> was = new ArrayList<>(new TreeSet<>(agents.keySet()));
        flushDenials(true);
        agents.clear(); pending.clear(); recent.clear(); trails.clear(); readOnly.clear();
        lockdown = true;
        append(Event.KILL_SWITCH_ON, "", null, "", null, Collections.singletonList("AGENTS_REMOVED_" + was.size()));
        return was;
    }
    public synchronized void releaseKillSwitch() { if (!lockdown) return; lockdown = false; append(Event.KILL_SWITCH_OFF, "", null, "", null, Collections.emptyList()); }
    /** Restores the switch state at start-up without writing an audit entry (the entry was written when it was flipped). */
    public synchronized void restoreLockdown(boolean on) { lockdown = on; if (on) { agents.clear(); pending.clear(); trails.clear(); } }
    public synchronized boolean lockdown() { return lockdown; }

    /**
     * Stops (on = true) or resumes these kinds of action for every agent. A stop also cancels waiting and
     * approved-but-unused approvals of those kinds, and stays until the person resumes it. Pairings are kept.
     */
    public synchronized void setStopped(Set<ActionType> types, boolean on) {
        Set<ActionType> change = EnumSet.noneOf(ActionType.class);
        for (ActionType t : types) if (t != null && stopped.contains(t) != on) change.add(t);
        if (change.isEmpty()) return;
        if (on) { stopped.addAll(change); pending.values().removeIf(p -> change.contains(p.type)); }
        else stopped.removeAll(change);
        List<String> names = new ArrayList<>(); for (ActionType t : change) names.add(t.name());
        append(on ? Event.CAPABILITY_STOPPED : Event.CAPABILITY_RESUMED, "", null, "", null, names);
    }
    public synchronized Set<ActionType> stopped() { return Collections.unmodifiableSet(EnumSet.copyOf(stopped.isEmpty() ? EnumSet.noneOf(ActionType.class) : stopped)); }

    /**
     * Read-only mode for one agent: it may still ask to read (which asks the person as before), and everything else is
     * refused. Turning it on cancels the agent's waiting and approved-but-unused approvals for anything but reading.
     */
    public synchronized void setReadOnly(String agentId, boolean on) {
        if (agentId == null || readOnly.contains(agentId) == on) return;
        if (on) { readOnly.add(agentId); pending.values().removeIf(p -> p.agentId.equals(agentId) && p.type != ActionType.READ_SENSITIVE); }
        else readOnly.remove(agentId);
        append(on ? Event.READ_ONLY_ON : Event.READ_ONLY_OFF, agentId, null, "", null, Collections.emptyList());
    }
    public synchronized boolean readOnly(String agentId) { return readOnly.contains(agentId); }

    /** Restores the stops and read-only agents at start-up without writing audit entries (they were written when set). */
    public synchronized void restoreLimits(Set<ActionType> stoppedTypes, Set<String> readOnlyAgents) {
        stopped.clear(); stopped.addAll(stoppedTypes);
        readOnly.clear(); readOnly.addAll(readOnlyAgents);
    }

    private String limitRefusal(String agentId, ActionType type) {
        if (stopped.contains(type)) return "CAPABILITY_STOPPED";
        if (readOnly.contains(agentId) && type != ActionType.READ_SENSITIVE) return "AGENT_READ_ONLY";
        return null;
    }

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
    /** "Is this you?": while on, every request from this agent that would be allowed asks the person instead. */
    public synchronized void setPaused(String agentId, boolean on) { if (agentId == null) return; if (on) paused.add(agentId); else paused.remove(agentId); }
    public synchronized boolean paused(String agentId) { return paused.contains(agentId); }
    /** Also drops that agent's waiting and approved-but-unused approvals and its session: a removed agent keeps nothing it was granted. */
    public synchronized void unregisterAgent(String agentId) { agents.remove(agentId); trails.remove(agentId); readOnly.remove(agentId); if (pending.values().removeIf(p -> p.agentId.equals(agentId))) revision++; }
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
        // Read before the lock like the other scans; a send that lands in between is checked against the older tail.
        String tail = r == null || r.type() == null || !OUTBOUND.contains(r.type()) ? "" : tail(r.agentId(), hostOf(r.destination()));
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
                Set<SensitiveData.Kind> split = EnumSet.noneOf(SensitiveData.Kind.class);
                if (!tail.isEmpty()) { // only what appears when the earlier sends and this one are joined
                    split.addAll(SensitiveData.scan(tail + pl.substring(0, Math.min(pl.length(), CHAIN_TAIL)), deadline));
                    split.removeAll(SensitiveData.scan(tail, deadline));
                    split.removeAll(kinds);
                }
                scan = new Scan(kinds, inj, false, split);
            }
        } catch (Deadline.ScanTimeout e) { scan = new Scan(EnumSet.noneOf(SensitiveData.Kind.class), new LinkedHashSet<>(), true, EnumSet.noneOf(SensitiveData.Kind.class));
        } catch (RuntimeException e) { scan = null; }
        synchronized (this) {
            Decision d;
            try { d = decide(r, scan, brokered); }
            catch (RuntimeException e) { d = deny("ENGINE_ERROR"); }
            try { track(r, scan, d); } catch (RuntimeException ignored) { }
            return record(r, d);
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
        String limit = limitRefusal(r.agentId(), r.type());
        if (limit != null) return deny(limit);
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
        Set<String> kindNames = new TreeSet<>(); for (SensitiveData.Kind k : kinds) kindNames.add(k.name()); for (SensitiveData.Kind k : scan.split()) kindNames.add(k.name());
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

        // Chain rules: what this agent did earlier in the session.
        Trail t = currentTrail(r.agentId(), now);
        if (t != null) {
            String host = safeHost(hostOf(r.destination()));
            if (outbound && t.privateRead && !t.approvedAfterRead.contains(host)) ask.add("CHAIN_PRIVATE_READ_THEN_SEND");
            if (t.injection && (outbound || highRisk || r.type() == ActionType.READ_SENSITIVE)) ask.add("CHAIN_AFTER_INJECTION_INDICATORS");
            // Provenance is the agent's own claim; switching to "the person said so" right after acting on content is how a hijack would launder it.
            if (userDriven && (outbound || highRisk) && t.lastProvenance != null && !isUser(t.lastProvenance) && !now.isAfter(t.lastAt.plusSeconds(PROVENANCE_SWITCH_SECONDS)))
                ask.add("CHAIN_PROVENANCE_CHANGED");
        }
        if (!scan.split().isEmpty()) {
            if (!trusted && scan.split().stream().anyMatch(SensitiveData.SECRETS::contains)) deny.add("CHAIN_SPLIT_SECRET_TO_UNTRUSTED_DESTINATION");
            else ask.add("CHAIN_SPLIT_SENSITIVE_DATA");
        }

        // Last, so it never hides a refusal; it only turns what would have run silently into a question.
        if (paused.contains(r.agentId())) ask.add("IS_THIS_YOU");
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

    private static boolean isUser(Provenance p) { return p == Provenance.USER_DIRECT || p == Provenance.USER_CONFIRMED_PLAN; }

    /** The agent's session, or null when it has none or it ended. */
    private Trail currentTrail(String agentId, Instant now) {
        Trail t = agentId == null ? null : trails.get(agentId);
        if (t != null && now.isAfter(t.last.plusSeconds(CHAIN_GAP_SECONDS))) { trails.remove(agentId); t = null; }
        return t;
    }

    private Trail trailFor(String agentId, Instant now) {
        Trail t = currentTrail(agentId, now);
        if (t == null) {
            if (trails.size() >= MAX_TRAILS) trails.remove(trails.keySet().iterator().next());
            t = new Trail(); trails.put(agentId, t);
        }
        t.last = now;
        return t;
    }

    private synchronized String tail(String agentId, String host) {
        Trail t = currentTrail(agentId, clock.instant());
        String s = t == null ? null : t.tails.get(safeHost(host));
        return s == null ? "" : s;
    }

    /** Records a decided request of a paired agent in its session. Refusals for flooding or the kill switch are not steps. */
    private void track(Request r, Scan scan, Decision d) {
        if (r == null || r.agentId() == null || r.type() == null || r.provenance() == null || !agents.containsKey(r.agentId())) return;
        if (d.reasons().contains("RATE_LIMITED") || d.reasons().contains("KILL_SWITCH_ON")) return;
        if (d.reasons().contains("CAPABILITY_STOPPED") || d.reasons().contains("AGENT_READ_ONLY")) return; // the person's limit, not the agent's step
        Instant now = clock.instant();
        Trail t = trailFor(r.agentId(), now);
        String host = safeHost(hostOf(r.destination()));
        StepOutcome o = d.verdict() == Verdict.ALLOW ? StepOutcome.ALLOWED : d.verdict() == Verdict.ASK_USER ? StepOutcome.ASKED : StepOutcome.DENIED;
        if (t.steps.size() >= CHAIN_STEPS) t.steps.remove(0);
        t.steps.add(new ChainStep(now, r.type(), host, o, !isUser(r.provenance())));
        if (scan != null && !scan.injection().isEmpty()) t.injection = true;
        t.lastProvenance = r.provenance(); t.lastAt = now;
        if (d.verdict() == Verdict.ALLOW && OUTBOUND.contains(r.type())) addTail(t, host, r.payload());
    }

    /** An approval was used, so the action happened: the step shows as approved, and a read or send counts for the chain. */
    private void trackApproved(Request r) {
        if (r == null || r.agentId() == null || r.type() == null) return;
        Trail t = trailFor(r.agentId(), clock.instant());
        String host = safeHost(hostOf(r.destination()));
        for (int i = t.steps.size() - 1; i >= 0; i--) {
            ChainStep s = t.steps.get(i);
            if (s.outcome() == StepOutcome.ASKED && s.type() == r.type() && s.host().equals(host)) {
                t.steps.set(i, new ChainStep(s.time(), s.type(), s.host(), StepOutcome.APPROVED, s.fromContent()));
                break;
            }
        }
        if (r.type() == ActionType.READ_SENSITIVE) { t.privateRead = true; t.approvedAfterRead.clear(); }
        if (OUTBOUND.contains(r.type())) { addTail(t, host, r.payload()); if (t.privateRead) t.approvedAfterRead.add(host); }
    }

    private static void addTail(Trail t, String host, String payload) {
        if (payload == null || payload.isEmpty()) return;
        String joined = t.tails.getOrDefault(host, "") + payload;
        t.tails.remove(host); // re-inserted as the most recent
        if (t.tails.size() >= MAX_TAIL_HOSTS) t.tails.remove(t.tails.keySet().iterator().next());
        t.tails.put(host, joined.length() > CHAIN_TAIL ? joined.substring(joined.length() - CHAIN_TAIL) : joined);
    }

    /** The agent's current session, oldest step first (empty when it has none). For showing the person how a request was reached. */
    public synchronized List<ChainStep> chain(String agentId) {
        Trail t = currentTrail(agentId, clock.instant());
        return t == null ? Collections.emptyList() : Collections.unmodifiableList(new ArrayList<>(t.steps));
    }

    /**
     * True when approving this request should need the phone's own fingerprint, face or PIN check, not just a tap on
     * Aegis' dialog: risky actions, sensitive reads, requests carrying sensitive data, and anything hijack wording, a
     * chain rule or "Is this you?" flagged. An unknown type counts as sensitive. Takes the stored text form of an approval.
     */
    public static boolean needsStrongConfirmation(String type, Collection<String> reasons, Collection<String> dataKinds) {
        ActionType t = null;
        for (ActionType a : ActionType.values()) if (a.name().equals(type)) t = a;
        if (t == null || HIGH_RISK.contains(t) || t == ActionType.READ_SENSITIVE || !dataKinds.isEmpty()) return true;
        for (String r : reasons) if (r.startsWith("CHAIN_") || r.startsWith("INJECTION_") || r.equals("IS_THIS_YOU") || r.equals("SECRET_IN_OUTBOUND_DATA")) return true;
        return false;
    }

    /** Called by the user interface only. */
    public synchronized boolean resolve(String approvalId, boolean approve) { return resolve(approvalId, approve, false); }

    /** confirmed = the phone's own screen-lock check passed for this answer; the log records it. */
    public synchronized boolean resolve(String approvalId, boolean approve, boolean confirmed) {
        expire();
        Pending p = pending.get(approvalId);
        if (p == null || p.approved != null) return false;
        p.approved = approve;
        if (!approve) pending.remove(approvalId); // a refusal frees its slot immediately
        append(approve ? Event.USER_APPROVED : Event.USER_DENIED, p.agentId, p.type, p.host, null, approve && confirmed ? Collections.singletonList("SCREEN_LOCK_CONFIRMED") : Collections.emptyList());
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
            : limitRefusal(p.agentId, p.type) != null ? limitRefusal(p.agentId, p.type)
            : p.used || !Boolean.TRUE.equals(p.approved) ? "NOT_APPROVED"
            : r == null || !p.agentId.equals(r.agentId()) || !p.hash.equals(requestHash(r)) ? "REQUEST_CHANGED" : null;
        if (refused != null) { append(Event.REDEEM_REFUSED, agent, type, host, null, Collections.singletonList(refused)); return false; }
        p.used = true;
        pending.remove(approvalId);
        trackApproved(r);
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

    public synchronized List<AuditEntry> auditLog() { return Collections.unmodifiableList(new ArrayList<>(log.entries)); }

    /** Recomputes the hash chain over the retained entries; false if any retained entry was altered, reordered or removed from the middle. */
    public synchronized boolean verifyAudit() { return verifyChain(new ArrayList<>(log.entries), log.anchor, log.head); }

    /** The separate security log (see SECURITY_EVENTS): request traffic cannot rotate these entries away. */
    public synchronized List<AuditEntry> securityLog() { return Collections.unmodifiableList(new ArrayList<>(security.entries)); }
    public synchronized boolean verifySecurityLog() { return verifyChain(new ArrayList<>(security.entries), security.anchor, security.head); }
    public synchronized String securityHead() { return security.head; }

    /** Increases whenever saved state (either log or the approvals) changed. */
    public synchronized long revision() { return revision; }

    /** Verifies an exported copy of the log against the anchor and head hashes. */
    public static boolean verifyChain(List<AuditEntry> entries, String anchor, String head) {
        String prev = anchor;
        for (AuditEntry e : entries) {
            if (!sha(prev + auditBody(e)).equals(e.chainHash())) return false;
            prev = e.chainHash();
        }
        return prev.equals(head);
    }
    public synchronized String auditAnchor() { return log.anchor; }
    public synchronized String auditHead() { return log.head; }

    /**
     * Logs a decision. Denials are budgeted per agent per minute: the first DENIALS_LOGGED_PER_MINUTE are logged, the
     * rest only counted and summarised in one DENIALS_SUMMARISED entry, so a flooding agent can neither rotate older
     * evidence out of the log nor force a disk write per request. Rate-limit hits also go to the security log (throttled).
     */
    private Decision record(Request r, Decision d) {
        String agent = r == null ? "" : safeAgent(String.valueOf(r.agentId()));
        Instant now = clock.instant();
        flushDenials(false);
        if (d.reasons().contains("RATE_LIMITED")) {
            Instant last = rateNotes.get(agent);
            if (last == null || !now.isBefore(last.plusSeconds(RATE_NOTE_SECONDS))) {
                if (rateNotes.size() >= MAX_DENY_WINDOWS && !rateNotes.containsKey(agent)) rateNotes.remove(rateNotes.keySet().iterator().next());
                rateNotes.put(agent, now);
                append(Event.RATE_LIMIT_HIT, agent, r == null ? null : r.type(), "", Verdict.DENY, Collections.singletonList("RATE_LIMITED"));
            }
        }
        if (d.verdict() == Verdict.DENY) {
            String key = denyWindows.containsKey(agent) || denyWindows.size() < MAX_DENY_WINDOWS ? agent : "*";
            DenyWindow w = denyWindows.computeIfAbsent(key, k -> new DenyWindow(now));
            if (w.logged >= DENIALS_LOGGED_PER_MINUTE) { w.suppressed++; return d; }
            w.logged++;
        }
        append(Event.DECISION, agent, r == null ? null : r.type(), r == null ? "" : hostOf(r.destination()), d.verdict(), d.reasons());
        return d;
    }

    /** Writes a summary for every denial window that ended (or all windows when all = true). */
    private void flushDenials(boolean all) {
        Instant now = clock.instant();
        Iterator<Map.Entry<String, DenyWindow>> it = denyWindows.entrySet().iterator();
        List<Map.Entry<String, DenyWindow>> done = new ArrayList<>();
        while (it.hasNext()) {
            Map.Entry<String, DenyWindow> e = it.next();
            if (all || !now.isBefore(e.getValue().start.plusSeconds(60))) { done.add(e); it.remove(); }
        }
        for (Map.Entry<String, DenyWindow> e : done)
            if (e.getValue().suppressed > 0) append(Event.DENIALS_SUMMARISED, e.getKey().equals("*") ? "" : e.getKey(), null, "", Verdict.DENY, Collections.singletonList("NOT_LOGGED_" + e.getValue().suppressed));
    }

    /** Every field is reduced to a fixed character set, so stored and exported logs need no escaping and cannot carry agent text. */
    private void append(Event event, String agentId, ActionType type, String host, Verdict verdict, List<String> reasons) {
        List<String> rs = new ArrayList<>();
        for (String x : reasons) rs.add(x.replaceAll("[^A-Z0-9_]", "?"));
        AuditEntry draft = new AuditEntry(clock.instant(), event, safeAgent(agentId), type, safeHost(host), verdict, Collections.unmodifiableList(rs), "");
        log.add(draft);
        if (SECURITY_EVENTS.contains(event)) security.add(draft);
        revision++;
    }
    private static String safeAgent(String a) { return a == null ? "" : (a.length() > 255 ? a.substring(0, 255) : a).replaceAll("[^A-Za-z0-9._-]", "?"); }
    private static String safeHost(String h) { return h == null ? "" : (h.length() > 253 ? h.substring(0, 253) : h).replaceAll("[^a-z0-9.:\\[\\]_-]", "?"); }

    private static String auditBody(AuditEntry e) { return e.time() + "|" + e.event() + "|" + e.agentId() + "|" + e.type() + "|" + e.destinationHost() + "|" + e.verdict() + "|" + e.reasons(); }

    // --- Persistence. The app stores these texts encrypted in its private storage; the formats are plain so an export can be read and checked.

    private static final String AUDIT_MAGIC = "AEGIS-AUDIT 1", SECURITY_MAGIC = "AEGIS-SECURITY 1", PENDING_MAGIC = "AEGIS-PENDING 1";
    private static final java.util.regex.Pattern HEX64 = java.util.regex.Pattern.compile("[0-9a-f]{64}"), HEX32 = java.util.regex.Pattern.compile("[0-9a-f]{32}");

    /** The audit log as text: a header with the anchor and head hashes, then one tab-separated line per entry. Ended denial windows are summarised first. */
    public synchronized String exportAudit() { flushDenials(false); return log.export(); }

    /** The security log in the same format, with its own header and chain. */
    public synchronized String exportSecurityLog() { return security.export(); }

    /** Parses exportAudit() text. Returns null for anything malformed; the chain is not checked here (see verifyChain). */
    public static Restored parseAudit(String text) { return parse(text, AUDIT_MAGIC, MAX_AUDIT); }
    public static Restored parseSecurityLog(String text) { return parse(text, SECURITY_MAGIC, MAX_SECURITY); }

    private static Restored parse(String text, String magic, int max) {
        if (text == null || !text.startsWith(magic + "\n")) return null;
        String[] lines = text.split("\n", -1);
        if (lines.length < 3 || !lines[1].startsWith("anchor ") || !lines[2].startsWith("head ")) return null;
        String a = lines[1].substring(7), h = lines[2].substring(5);
        if (!(a.equals("genesis") || HEX64.matcher(a).matches()) || !(h.equals("genesis") || HEX64.matcher(h).matches())) return null;
        List<AuditEntry> out = new ArrayList<>();
        for (int i = 3; i < lines.length; i++) {
            if (lines[i].isEmpty()) { if (i == lines.length - 1) break; return null; }
            String[] f = lines[i].split("\t", -1);
            if (f.length != 8 || out.size() >= max || !HEX64.matcher(f[7]).matches()) return null;
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
    public synchronized boolean restoreAudit(String text) { return restoreLogs(text, null)[0]; }
    public synchronized boolean restoreSecurityLog(String text) { return restoreLogs(null, text)[1]; }

    /**
     * Loads both saved logs at start-up (null or empty = nothing saved; that log is left as it is). Both are restored
     * before any damage note is written, so a note is never overwritten by the other log's restore. A damaged main log
     * gets LOG_DAMAGED (UNREADABLE / CHAIN_BROKEN), a damaged security log LOG_DAMAGED (SECURITY_LOG_UNREADABLE /
     * SECURITY_LOG_CHAIN_BROKEN); each note goes to both logs. Returns {main intact, security intact}.
     */
    public synchronized boolean[] restoreLogs(String auditText, String securityText) {
        boolean a = auditText == null || auditText.isEmpty() || log.restore(auditText);
        boolean s = securityText == null || securityText.isEmpty() || security.restore(securityText);
        if (!a) append(Event.LOG_DAMAGED, "", null, "", null, Collections.singletonList(parseAudit(auditText) == null ? "UNREADABLE" : "CHAIN_BROKEN"));
        if (!s) append(Event.LOG_DAMAGED, "", null, "", null, Collections.singletonList(parseSecurityLog(securityText) == null ? "SECURITY_LOG_UNREADABLE" : "SECURITY_LOG_CHAIN_BROKEN"));
        return new boolean[] {a, s};
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
