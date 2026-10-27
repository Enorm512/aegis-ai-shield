package com.aegis.core;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * Links signals from the separate watches (power grants, app changes, tripwires, threat lookups, agent refusals) into
 * incidents that no single watch would raise. Pure logic over a small bounded event log; the Android adapter feeds it.
 *
 * Only coarse facts are kept: package names, capability names, categories and reason codes. Never a looked-up domain,
 * message text or payload. DNS lookups cannot be tied to an app on Android, so rules that use them name the apps that
 * changed shortly before as candidates, never as the culprit.
 */
public final class Correlator {
    public enum Kind {
        /** detail = CapabilityWatch.Capability name. */
        POWER_GRANTED,
        /** A MEDIUM or HIGH AppWatch change; detail = AppWatch.Kind name. */
        APP_RISKY_CHANGE,
        /** A decoy's name was looked up; detail = CanaryTokens.Kind name; no package (Android does not say which app). */
        TRIPWIRE,
        /** A lookup matched the threat database; detail = category; no package. */
        THREAT_LOOKUP,
        /** The agent firewall refused a paired agent; detail = first reason code. */
        AGENT_REFUSED,
        /** An app asked the gateway with a different signing key than the one paired. */
        AGENT_SIGNATURE_CHANGED
    }

    public record Signal(Instant time, Kind kind, String packageName, String detail) {}

    public enum Rule {
        /** A new, replaced or re-sourced app gained screen control, notification access or device admin within 24 h. */
        NEW_APP_GAINED_POWER,
        /** A decoy was read within 72 h after an app gained power or changed. */
        DECOY_READ_AFTER_CHANGE,
        /** A decoy was read and a known-bad name was looked up within 1 h. */
        DECOY_AND_THREAT_LOOKUP,
        /** A known-bad name was looked up within 1 h after an app gained power or changed. */
        THREAT_LOOKUP_AFTER_CHANGE,
        /** One agent was refused for risky reasons 3+ times within 1 h, or asked with a changed signing key. */
        AGENT_PROBING
    }

    public record Incident(Rule rule, CapabilityWatch.Risk risk, List<String> packages, Instant first, Instant last, int signals) {
        /** Stable within a run of the same incident, for "already notified" bookkeeping. */
        public String key() { return rule.name() + " " + String.join(",", packages) + " " + first.getEpochSecond() / 3600; }
    }

    public static final int MAX_SIGNALS = 300;
    private static final Duration DEDUPE = Duration.ofMinutes(10), KEEP = Duration.ofDays(7);
    private static final java.util.regex.Pattern DETAIL = java.util.regex.Pattern.compile("[A-Z][A-Z0-9_]{0,47}");
    private static final Set<String> STRONG_POWERS = new HashSet<>(Arrays.asList("ACCESSIBILITY", "NOTIFICATION_ACCESS", "DEVICE_ADMIN"));
    /** Refusal reasons that say the agent tried something risky, as opposed to a malformed or oversized call. */
    private static final Set<String> RISKY_REFUSALS = new HashSet<>(Arrays.asList("SECRET_TO_UNTRUSTED_DESTINATION", "HIGH_RISK_ACTION_WITHOUT_USER_INSTRUCTION",
        "INJECTION_INDICATORS_WITH_RISKY_ACTION", "PERSONAL_DATA_TO_UNTRUSTED_DESTINATION", "ACTION_NOT_PERMITTED_FOR_AGENT", "RATE_LIMITED", "TOO_MANY_PENDING_APPROVALS"));

    private final ArrayDeque<Signal> signals = new ArrayDeque<>();

    /** Adds a signal unless it is invalid or repeats the same fact within 10 minutes. Old and excess signals are dropped. */
    public synchronized boolean add(Signal s) {
        if (s == null || s.time() == null || s.kind() == null) return false;
        boolean needsPackage = s.kind() == Kind.POWER_GRANTED || s.kind() == Kind.APP_RISKY_CHANGE || s.kind() == Kind.AGENT_REFUSED || s.kind() == Kind.AGENT_SIGNATURE_CHANGED;
        String pkg = s.packageName() == null || s.packageName().isEmpty() ? null : s.packageName();
        if (needsPackage ? pkg == null || !CapabilityWatch.validPackage(pkg) : pkg != null) return false;
        String detail = s.detail() == null ? "" : s.detail();
        if (!detail.isEmpty() && !DETAIL.matcher(detail).matches()) return false;
        Signal clean = new Signal(s.time(), s.kind(), pkg, detail);
        for (Signal o : signals)
            if (o.kind() == clean.kind() && Objects.equals(o.packageName(), pkg) && o.detail().equals(detail) && Duration.between(o.time(), clean.time()).abs().compareTo(DEDUPE) < 0) return false;
        signals.addLast(clean);
        prune(clean.time());
        return true;
    }

    private void prune(Instant now) {
        signals.removeIf(o -> o.time().isBefore(now.minus(KEEP)));
        while (signals.size() > MAX_SIGNALS) signals.removeFirst();
    }

    public synchronized List<Signal> signals() { return Collections.unmodifiableList(new ArrayList<>(signals)); }

    /** One "epochSeconds KIND package|- detail|-" line per signal. */
    public synchronized String serialize() {
        StringBuilder b = new StringBuilder("AEGIS-SIGNALS 1\n");
        for (Signal s : signals) b.append(s.time().getEpochSecond()).append(' ').append(s.kind().name()).append(' ')
            .append(s.packageName() == null ? "-" : s.packageName()).append(' ').append(s.detail().isEmpty() ? "-" : s.detail()).append('\n');
        return b.toString();
    }

    /** Replaces the log with parsed text; malformed lines are skipped. */
    public synchronized void restore(String text) {
        signals.clear();
        if (text == null || !text.startsWith("AEGIS-SIGNALS 1\n")) return;
        List<Signal> in = new ArrayList<>();
        for (String line : text.split("\n")) {
            String[] f = line.split(" ");
            if (f.length != 4) continue;
            try { in.add(new Signal(Instant.ofEpochSecond(Long.parseLong(f[0])), Kind.valueOf(f[1]), f[2].equals("-") ? null : f[2], f[3].equals("-") ? "" : f[3])); }
            catch (RuntimeException ignored) { }
        }
        in.sort(Comparator.comparing(Signal::time));
        for (Signal s : in) add(s);
    }

    /**
     * Incidents among the signals at [now], most serious first. [powerHolders] are the packages holding a high-power
     * capability now (an agent that holds one makes probing HIGH). Signals newer than [now] are ignored.
     */
    public synchronized List<Incident> incidents(Instant now, Set<String> powerHolders) {
        List<Signal> s = new ArrayList<>();
        for (Signal x : signals) if (!x.time().isAfter(now)) s.add(x);
        Set<String> holders = powerHolders == null ? Collections.emptySet() : powerHolders;
        List<Incident> out = new ArrayList<>();
        Duration day = Duration.ofHours(24), hour = Duration.ofHours(1), threeDays = Duration.ofHours(72);

        // NEW_APP_GAINED_POWER: per package, a risky change and a strong power grant within 24 h of each other, either order.
        Map<String, List<Signal>> byPkg = new TreeMap<>();
        for (Signal x : s) if (x.packageName() != null && (x.kind() == Kind.APP_RISKY_CHANGE || x.kind() == Kind.POWER_GRANTED)) byPkg.computeIfAbsent(x.packageName(), k -> new ArrayList<>()).add(x);
        for (Map.Entry<String, List<Signal>> e : byPkg.entrySet()) {
            List<Signal> changes = new ArrayList<>(), grants = new ArrayList<>();
            for (Signal x : e.getValue()) if (x.kind() == Kind.APP_RISKY_CHANGE) changes.add(x); else if (STRONG_POWERS.contains(x.detail())) grants.add(x);
            List<Signal> linked = new ArrayList<>();
            for (Signal c : changes) for (Signal g : grants) if (within(c, g, day)) { if (!linked.contains(c)) linked.add(c); if (!linked.contains(g)) linked.add(g); }
            if (!linked.isEmpty()) out.add(incident(Rule.NEW_APP_GAINED_POWER, CapabilityWatch.Risk.HIGH, linked));
        }

        // Tripwire and threat-lookup rules: the suspects are apps that changed or gained power shortly before.
        for (Signal t : s) {
            if (t.kind() != Kind.TRIPWIRE && t.kind() != Kind.THREAT_LOOKUP) continue;
            Duration window = t.kind() == Kind.TRIPWIRE ? threeDays : hour;
            List<Signal> before = new ArrayList<>();
            for (Signal x : s) if ((x.kind() == Kind.POWER_GRANTED || x.kind() == Kind.APP_RISKY_CHANGE) && !x.time().isAfter(t.time()) && Duration.between(x.time(), t.time()).compareTo(window) <= 0) before.add(x);
            if (!before.isEmpty()) {
                before.add(t);
                out.add(incident(t.kind() == Kind.TRIPWIRE ? Rule.DECOY_READ_AFTER_CHANGE : Rule.THREAT_LOOKUP_AFTER_CHANGE,
                    t.kind() == Kind.TRIPWIRE ? CapabilityWatch.Risk.HIGH : CapabilityWatch.Risk.MEDIUM, before));
            }
            if (t.kind() == Kind.TRIPWIRE) {
                List<Signal> lookups = new ArrayList<>();
                for (Signal x : s) if (x.kind() == Kind.THREAT_LOOKUP && within(x, t, hour)) lookups.add(x);
                if (!lookups.isEmpty()) { lookups.add(t); out.add(incident(Rule.DECOY_AND_THREAT_LOOKUP, CapabilityWatch.Risk.HIGH, lookups)); }
            }
        }

        // AGENT_PROBING: per agent, 3+ risky refusals within an hour, or a changed signing key.
        Map<String, List<Signal>> agents = new TreeMap<>();
        for (Signal x : s) if ((x.kind() == Kind.AGENT_REFUSED && RISKY_REFUSALS.contains(x.detail())) || x.kind() == Kind.AGENT_SIGNATURE_CHANGED) agents.computeIfAbsent(x.packageName(), k -> new ArrayList<>()).add(x);
        for (Map.Entry<String, List<Signal>> e : agents.entrySet()) {
            List<Signal> l = e.getValue();
            boolean sig = l.stream().anyMatch(x -> x.kind() == Kind.AGENT_SIGNATURE_CHANGED);
            List<Signal> burst = null;
            List<Signal> refusals = new ArrayList<>();
            for (Signal x : l) if (x.kind() == Kind.AGENT_REFUSED) refusals.add(x);
            for (int i = 0; i + 2 < refusals.size() && burst == null; i++)
                if (Duration.between(refusals.get(i).time(), refusals.get(i + 2).time()).compareTo(hour) <= 0) burst = refusals;
            if (!sig && burst == null) continue;
            boolean power = holders.contains(e.getKey());
            out.add(incident(Rule.AGENT_PROBING, sig || power ? CapabilityWatch.Risk.HIGH : CapabilityWatch.Risk.MEDIUM, l));
        }

        // Several lookups or tripwire hits with the same suspects are one incident, not one per signal.
        Map<String, Incident> merged = new LinkedHashMap<>();
        for (Incident i : out) merged.merge(i.rule().name() + " " + i.packages(), i, (a, b) -> new Incident(a.rule(), a.risk().compareTo(b.risk()) >= 0 ? a.risk() : b.risk(), a.packages(),
            a.first().isBefore(b.first()) ? a.first() : b.first(), a.last().isAfter(b.last()) ? a.last() : b.last(), Math.max(a.signals(), b.signals())));
        List<Incident> result = new ArrayList<>(merged.values());
        result.sort((a, b) -> a.risk() != b.risk() ? b.risk().compareTo(a.risk()) : b.last().compareTo(a.last()));
        return result;
    }

    private static boolean within(Signal a, Signal b, Duration d) { return Duration.between(a.time(), b.time()).abs().compareTo(d) <= 0; }

    private static Incident incident(Rule rule, CapabilityWatch.Risk risk, List<Signal> l) {
        TreeSet<String> pk = new TreeSet<>();
        Instant first = null, last = null;
        for (Signal x : l) {
            if (x.packageName() != null) pk.add(x.packageName());
            if (first == null || x.time().isBefore(first)) first = x.time();
            if (last == null || x.time().isAfter(last)) last = x.time();
        }
        return new Incident(rule, risk, Collections.unmodifiableList(new ArrayList<>(pk)), first, last, l.size());
    }
}
