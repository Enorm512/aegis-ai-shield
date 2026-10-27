package com.aegis.core;

import com.aegis.core.CapabilityWatch.Risk;
import com.aegis.core.Correlator.*;
import java.time.Instant;
import java.util.*;

/** Host tests for cross-module correlation: signal hygiene, persistence and each rule's window and severity. */
public final class CorrelatorTests {
    private static int checks;
    private static void check(boolean ok, String message) { checks++; if (!ok) throw new AssertionError(message); }
    private static final Instant T0 = Instant.parse("2026-10-27T10:00:00Z");
    private static Instant at(long minutes) { return T0.plusSeconds(minutes * 60); }
    private static Signal sig(long min, Kind k, String pkg, String detail) { return new Signal(at(min), k, pkg, detail); }
    private static List<Rule> rules(List<Incident> l) { List<Rule> r = new ArrayList<>(); for (Incident i : l) r.add(i.rule()); return r; }

    public static void main(String[] args) {
        // --- Signal hygiene
        Correlator c = new Correlator();
        check(c.add(sig(0, Kind.POWER_GRANTED, "com.rogue", "ACCESSIBILITY")), "valid signal accepted");
        check(!c.add(sig(5, Kind.POWER_GRANTED, "com.rogue", "ACCESSIBILITY")), "same fact within 10 min deduplicated");
        check(c.add(sig(15, Kind.POWER_GRANTED, "com.rogue", "ACCESSIBILITY")), "same fact later kept");
        check(!c.add(sig(0, Kind.POWER_GRANTED, null, "ACCESSIBILITY")) && !c.add(sig(0, Kind.POWER_GRANTED, "bad name", "X")), "power grant needs a valid package");
        check(!c.add(sig(0, Kind.TRIPWIRE, "com.x", "NOTE")), "tripwire never names an app");
        check(!c.add(sig(0, Kind.THREAT_LOOKUP, null, "evil.example.com")) && !c.add(sig(0, Kind.THREAT_LOOKUP, null, "phishing")), "detail is a code, never a domain or free text");
        check(!c.add(null) && !c.add(new Signal(null, Kind.TRIPWIRE, null, "")) && !c.add(new Signal(T0, null, null, "")), "nulls refused");
        check(c.signals().size() == 2, "two kept: " + c.signals());

        // --- Persistence round trip, bounded size and age
        Correlator r = new Correlator();
        r.restore(c.serialize());
        check(r.signals().equals(c.signals()), "serialize/restore round trip");
        r.restore("AEGIS-SIGNALS 1\nx POWER_GRANTED com.a ACCESSIBILITY\n1 BOGUS com.a X\n1 TRIPWIRE com.a NOTE\n100 TRIPWIRE - NOTE\n");
        check(r.signals().size() == 1, "malformed and invalid lines skipped: " + r.signals());
        r.restore("garbage");
        check(r.signals().isEmpty(), "unknown format gives an empty log");
        Correlator big = new Correlator();
        for (int i = 0; i < 1000; i++) big.add(sig(i * 11L, Kind.THREAT_LOOKUP, null, "PHISHING"));
        check(big.signals().size() <= Correlator.MAX_SIGNALS, "bounded: " + big.signals().size());
        Correlator old = new Correlator();
        old.add(sig(0, Kind.TRIPWIRE, null, "NOTE"));
        old.add(sig(8 * 24 * 60, Kind.TRIPWIRE, null, "FILE"));
        check(old.signals().size() == 1 && old.signals().get(0).detail().equals("FILE"), "signals older than 7 days dropped");

        // --- NEW_APP_GAINED_POWER
        Correlator a = new Correlator();
        a.add(sig(0, Kind.APP_RISKY_CHANGE, "com.rogue", "INSTALLED"));
        a.add(sig(30, Kind.POWER_GRANTED, "com.rogue", "ACCESSIBILITY"));
        a.add(sig(30, Kind.POWER_GRANTED, "com.keyboard", "INPUT_METHOD"));
        a.add(sig(40, Kind.APP_RISKY_CHANGE, "com.keyboard", "INSTALLED"));
        List<Incident> ia = a.incidents(at(60), Set.of());
        check(rules(ia).equals(List.of(Rule.NEW_APP_GAINED_POWER)) && ia.get(0).packages().equals(List.of("com.rogue")) && ia.get(0).risk() == Risk.HIGH, "install then accessibility is HIGH; a keyboard is not a strong power: " + ia);
        Correlator late = new Correlator();
        late.add(sig(0, Kind.APP_RISKY_CHANGE, "com.rogue", "INSTALLED"));
        late.add(sig(25 * 60, Kind.POWER_GRANTED, "com.rogue", "ACCESSIBILITY"));
        check(late.incidents(at(26 * 60), Set.of()).isEmpty(), "more than 24 h apart: not linked");
        Correlator rev = new Correlator();
        rev.add(sig(0, Kind.POWER_GRANTED, "com.x", "NOTIFICATION_ACCESS"));
        rev.add(sig(60, Kind.APP_RISKY_CHANGE, "com.x", "SIGNER_CHANGED"));
        check(rules(rev.incidents(at(61), Set.of())).equals(List.of(Rule.NEW_APP_GAINED_POWER)), "either order");
        check(a.incidents(at(20), Set.of()).isEmpty(), "signals after 'now' are not used");

        // --- Tripwire and threat lookups
        Correlator t = new Correlator();
        t.add(sig(0, Kind.POWER_GRANTED, "com.spy", "NOTIFICATION_ACCESS"));
        t.add(sig(48 * 60, Kind.TRIPWIRE, null, "CONTACT"));
        List<Incident> it = t.incidents(at(48 * 60 + 1), Set.of());
        check(rules(it).equals(List.of(Rule.DECOY_READ_AFTER_CHANGE)) && it.get(0).risk() == Risk.HIGH && it.get(0).packages().equals(List.of("com.spy")), "decoy read 2 days after a grant: HIGH with the candidate named: " + it);
        Correlator t2 = new Correlator();
        t2.add(sig(0, Kind.POWER_GRANTED, "com.spy", "NOTIFICATION_ACCESS"));
        t2.add(sig(80 * 60, Kind.TRIPWIRE, null, "CONTACT"));
        check(t2.incidents(at(81 * 60), Set.of()).isEmpty(), "beyond 72 h: not linked");
        Correlator t3 = new Correlator();
        t3.add(sig(0, Kind.TRIPWIRE, null, "NOTE"));
        t3.add(sig(20, Kind.THREAT_LOOKUP, null, "PHISHING"));
        check(rules(t3.incidents(at(30), Set.of())).equals(List.of(Rule.DECOY_AND_THREAT_LOOKUP)), "decoy plus bad lookup in an hour");
        Correlator t4 = new Correlator();
        t4.add(sig(0, Kind.APP_RISKY_CHANGE, "com.new", "INSTALLED"));
        for (int i = 1; i <= 5; i++) t4.add(sig(i * 11L, Kind.THREAT_LOOKUP, null, "MALWARE"));
        List<Incident> i4 = t4.incidents(at(70), Set.of());
        check(i4.size() == 1 && i4.get(0).rule() == Rule.THREAT_LOOKUP_AFTER_CHANGE && i4.get(0).risk() == Risk.MEDIUM, "lookups after a change merge into one MEDIUM incident: " + i4);
        check(i4.get(0).first().equals(at(0)) && i4.get(0).last().isAfter(at(11)), "merged incident spans its signals");
        Correlator t5 = new Correlator();
        t5.add(sig(0, Kind.THREAT_LOOKUP, null, "MALWARE"));
        t5.add(sig(10, Kind.TRIPWIRE, null, "FILE"));
        check(rules(t5.incidents(at(11), Set.of())).equals(List.of(Rule.DECOY_AND_THREAT_LOOKUP)), "a lone lookup before a decoy hit links only to the decoy");
        check(new Correlator().incidents(at(0), Set.of()).isEmpty(), "nothing, no incident");

        // --- AGENT_PROBING
        Correlator g = new Correlator();
        g.add(sig(0, Kind.AGENT_REFUSED, "com.agent", "SECRET_TO_UNTRUSTED_DESTINATION"));
        g.add(sig(11, Kind.AGENT_REFUSED, "com.agent", "INJECTION_INDICATORS_WITH_RISKY_ACTION"));
        check(g.incidents(at(12), Set.of()).isEmpty(), "two refusals are not yet probing");
        g.add(sig(22, Kind.AGENT_REFUSED, "com.agent", "HIGH_RISK_ACTION_WITHOUT_USER_INSTRUCTION"));
        List<Incident> ig = g.incidents(at(23), Set.of());
        check(rules(ig).equals(List.of(Rule.AGENT_PROBING)) && ig.get(0).risk() == Risk.MEDIUM, "three risky refusals in an hour: MEDIUM");
        check(g.incidents(at(23), Set.of("com.agent")).get(0).risk() == Risk.HIGH, "the same agent holding a power: HIGH");
        Correlator slow = new Correlator();
        for (int i = 0; i < 3; i++) slow.add(sig(i * 40L, Kind.AGENT_REFUSED, "com.agent", "RATE_LIMITED"));
        check(slow.incidents(at(200), Set.of()).isEmpty(), "spread over more than an hour: not a burst");
        Correlator benign = new Correlator();
        for (int i = 0; i < 5; i++) benign.add(sig(i * 11L, Kind.AGENT_REFUSED, "com.agent", "MALFORMED_REQUEST"));
        check(benign.incidents(at(60), Set.of()).isEmpty(), "malformed calls are not probing");
        Correlator sc = new Correlator();
        sc.add(sig(0, Kind.AGENT_SIGNATURE_CHANGED, "com.agent", ""));
        check(sc.incidents(at(1), Set.of()).get(0).risk() == Risk.HIGH, "changed signing key on its own: HIGH");

        // --- Ordering and keys
        Correlator m = new Correlator();
        m.add(sig(0, Kind.APP_RISKY_CHANGE, "com.new", "INSTALLED"));
        m.add(sig(5, Kind.THREAT_LOOKUP, null, "PHISHING"));
        m.add(sig(6, Kind.POWER_GRANTED, "com.new", "ACCESSIBILITY"));
        List<Incident> im = m.incidents(at(10), Set.of());
        check(im.get(0).risk() == Risk.HIGH && im.get(im.size() - 1).risk() == Risk.MEDIUM, "HIGH first: " + im);
        check(im.get(0).key().equals(m.incidents(at(11), Set.of()).get(0).key()), "key stable as time passes");

        System.out.println("CorrelatorTests passed: " + checks + " checks");
    }
}
