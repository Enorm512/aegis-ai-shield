package com.aegis.core;

import com.aegis.core.AgentFirewall.*;
import com.aegis.core.CapabilityWatch.Capability;
import com.aegis.core.CapabilityWatch.Installer;
import com.aegis.core.CapabilityWatch.PairingAdvice;
import com.aegis.core.CapabilityWatch.Risk;
import java.time.*;
import java.util.*;

/** Host tests for the hardened agent path: audit events and persistence, persistent approvals, kill switch, pairing advice. */
public final class AgentShieldTests {
    private static int checks;
    private static void check(boolean ok, String message) { checks++; if (!ok) throw new AssertionError(message); }

    static final class TestClock extends Clock {
        Instant now = Instant.parse("2026-10-27T09:00:00Z");
        public ZoneId getZone() { return ZoneOffset.UTC; }
        public Clock withZone(ZoneId z) { return this; }
        public Instant instant() { return now; }
    }

    private static final String AGENT = "com.example.assistant";
    private static Request send(String dest, String payload) { return new Request(AGENT, ActionType.SEND_DATA, dest, "Send the note", payload, Provenance.USER_DIRECT, -1, ""); }
    private static AgentFirewall fw(TestClock c) { AgentFirewall f = new AgentFirewall(c); f.registerAgent(AGENT, AgentFirewall.SAFE_GRANT); return f; }
    private static AuditEntry last(AgentFirewall f) { List<AuditEntry> l = f.auditLog(); return l.get(l.size() - 1); }

    public static void main(String[] args) {
        TestClock clock = new TestClock();

        // --- Every step is logged: decision, the person's answer, redemption, refused redemption, pairing notes
        AgentFirewall f = fw(clock);
        Request r = send("https://unknown.example.net/x", "hello");
        Decision d = f.evaluate(r);
        check(d.verdict() == Verdict.ASK_USER && last(f).event() == Event.DECISION && last(f).verdict() == Verdict.ASK_USER, "decision logged");
        check(f.openApprovals().equals(List.of(d.approvalId())), "open approval listed");
        check(f.resolve(d.approvalId(), true) && last(f).event() == Event.USER_APPROVED && last(f).destinationHost().equals("unknown.example.net") && last(f).type() == ActionType.SEND_DATA, "approval logged with host and type");
        check(f.openApprovals().isEmpty(), "approved is no longer open");
        check(!f.redeem(d.approvalId(), send("https://unknown.example.net/x", "hello!")) && last(f).event() == Event.REDEEM_REFUSED && last(f).reasons().equals(List.of("REQUEST_CHANGED")), "changed request refused and logged");
        check(f.redeem(d.approvalId(), r) && last(f).event() == Event.REDEEMED, "exact request redeemed and logged");
        check(!f.redeem(d.approvalId(), r) && last(f).reasons().equals(List.of("UNKNOWN_OR_EXPIRED_APPROVAL")), "second redemption refused");
        check(!f.redeem(null, null) && !f.redeem("nope", null), "null and unknown ids refused without error");
        Decision d2 = f.evaluate(send("other.example.net", "x"));
        check(!f.redeem(d2.approvalId(), send("other.example.net", "x")) && last(f).reasons().equals(List.of("NOT_APPROVED")), "unanswered approval cannot be redeemed");
        check(f.resolve(d2.approvalId(), false) && last(f).event() == Event.USER_DENIED, "denial logged");
        f.notePairing(AGENT, Event.PAIRED, true);
        check(last(f).event() == Event.PAIRED && last(f).reasons().equals(List.of("RISKY_ACTIONS_ALLOWED")) && last(f).verdict() == null, "pairing logged");
        f.notePairing("x.y", Event.PAIR_REJECTED, false); check(last(f).event() == Event.PAIR_REJECTED && last(f).reasons().isEmpty(), "rejection logged");
        try { f.notePairing(AGENT, Event.REDEEMED, false); check(false, "non-pairing event accepted"); } catch (IllegalArgumentException e) { check(true, "only pairing events via notePairing"); }
        check(f.verifyAudit(), "chain verifies with all event kinds");

        // --- Audit export / restore
        String text = f.exportAudit();
        check(text.startsWith("AEGIS-AUDIT 1\nanchor genesis\nhead " + f.auditHead() + "\n"), "export header");
        AgentFirewall g = fw(clock);
        check(g.restoreAudit(text) && g.auditLog().equals(f.auditLog()) && g.auditHead().equals(f.auditHead()) && g.verifyAudit(), "intact log restored exactly");
        g.evaluate(send("api.example.org", "x"));
        check(g.verifyAudit() && g.auditLog().size() == f.auditLog().size() + 1, "restored log continues the chain");
        check(new AgentFirewall(clock).restoreAudit(null) && new AgentFirewall(clock).restoreAudit(""), "nothing saved is fine");
        AgentFirewall empty = new AgentFirewall(clock);
        check(empty.restoreAudit(empty.exportAudit()) && empty.auditLog().isEmpty() && empty.verifyAudit(), "empty log round trip");

        // Tampering: edited verdict, removed line, reordered lines, edited header, garbage
        String[] lines = text.split("\n");
        String editedVerdict = text.replace("\tASK_USER\t", "\tALLOW\t");
        check(!editedVerdict.equals(text), "edit applied");
        List<String> removed = new ArrayList<>(Arrays.asList(lines)); removed.remove(5);
        List<String> swapped = new ArrayList<>(Arrays.asList(lines)); Collections.swap(swapped, 4, 5);
        String badHead = text.replace("head " + f.auditHead(), "head " + "0".repeat(64));
        for (String bad : new String[] {editedVerdict, String.join("\n", removed) + "\n", String.join("\n", swapped) + "\n", badHead, "garbage", text.substring(0, text.length() / 2)}) {
            AgentFirewall h = fw(clock);
            check(!h.restoreAudit(bad), "damaged log not trusted");
            check(h.auditLog().size() == 1 && h.auditLog().get(0).event() == Event.LOG_DAMAGED && h.verifyAudit() && !h.auditAnchor().equals("genesis"), "fresh log starts with LOG_DAMAGED");
        }
        AgentFirewall h1 = fw(clock); h1.restoreAudit("garbage");
        check(h1.auditLog().get(0).reasons().equals(List.of("UNREADABLE")), "unreadable reason");
        AgentFirewall h2 = fw(clock); h2.restoreAudit(editedVerdict);
        check(h2.auditLog().get(0).reasons().equals(List.of("CHAIN_BROKEN")), "broken chain reason");
        check(AgentFirewall.parseAudit(text + "extra line\n") == null && AgentFirewall.parseAudit(text.replace("\tDECISION\t", "\tNOPE\t")) == null, "malformed lines rejected");

        // Hostile agent ids and hosts cannot break the line format
        AgentFirewall hostile = new AgentFirewall(clock);
        String evil = "evil\tagent\nAEGIS-AUDIT 1";
        hostile.registerAgent(evil, AgentFirewall.SAFE_GRANT);
        hostile.evaluate(new Request(evil, ActionType.SEND_DATA, "https://[::1]/x", "s", "p", Provenance.USER_DIRECT, -1, ""));
        hostile.notePairing(evil, Event.UNPAIRED, false);
        String ht = hostile.exportAudit();
        check(ht.split("\n").length == 5 && !ht.contains("evil\t") && fw(clock).restoreAudit(ht), "control characters in agent id are neutralised; export restores");

        // Rotation past MAX_AUDIT survives export/restore
        AgentFirewall big = fw(clock);
        big.trustDestination("a.example");
        for (int i = 0; i < AgentFirewall.MAX_AUDIT + 40; i++) { clock.now = clock.now.plusSeconds(3); big.evaluate(new Request(AGENT, ActionType.SEND_DATA, "a.example", "", "", Provenance.USER_DIRECT, -1, "")); }
        AgentFirewall big2 = fw(clock);
        check(big.auditLog().size() == AgentFirewall.MAX_AUDIT && !big.auditAnchor().equals("genesis") && big2.restoreAudit(big.exportAudit()) && big2.verifyAudit(), "rotated log restores");

        // --- Persistent approvals
        clock.now = Instant.parse("2026-10-27T10:00:00Z");
        AgentFirewall p1 = fw(clock);
        Request ra = send("one.example.net", "a"), rb = send("two.example.net", "b"), rc = send("three.example.net", "c");
        Decision da = p1.evaluate(ra), db = p1.evaluate(rb), dc = p1.evaluate(rc);
        p1.resolve(db.approvalId(), true);   // approved, not yet used
        p1.resolve(dc.approvalId(), false);  // refused: gone
        String saved = p1.exportPending();
        check(saved.split("\n").length == 3, "open + approved exported, refused not: " + saved);
        AgentFirewall p2 = fw(clock);
        check(p2.restorePending(saved) == 2 && p2.openApprovals().equals(List.of(da.approvalId())), "restored after restart");
        check(p2.redeem(db.approvalId(), rb), "approval given before the restart is still redeemable once");
        check(!p2.redeem(db.approvalId(), rb), "and only once");
        check(p2.resolve(da.approvalId(), true) && !p2.redeem(da.approvalId(), rb) && p2.redeem(da.approvalId(), ra), "restored open approval is bound to its own request");
        check(!p2.exportPending().contains(db.approvalId()), "used approvals are not exported");
        // Expiry, unpaired agent, lowered grant, forged far-future expiry, malformed lines
        clock.now = clock.now.plusSeconds(301);
        check(fw(clock).restorePending(saved) == 0, "expired approvals dropped");
        clock.now = Instant.parse("2026-10-27T10:00:00Z");
        check(new AgentFirewall(clock).restorePending(saved) == 0, "approvals of agents no longer paired dropped");
        AgentFirewall readOnly = new AgentFirewall(clock); readOnly.registerAgent(AGENT, EnumSet.of(ActionType.READ_SENSITIVE));
        check(readOnly.restorePending(saved) == 0, "approvals for actions the agent may no longer ask for dropped");
        String far = saved.replaceAll("\t\\d{13}\t", "\t" + clock.now.plusSeconds(86_400).toEpochMilli() + "\t");
        check(fw(clock).restorePending(far) == 0, "expiry beyond five minutes not trusted");
        check(fw(clock).restorePending("garbage") == 0 && fw(clock).restorePending(null) == 0 && fw(clock).restorePending("AEGIS-PENDING 1\nzz\tyy\n") == 0, "malformed input ignored");
        check(fw(clock).restorePending(saved + saved.substring("AEGIS-PENDING 1\n".length())) == 2, "duplicate ids kept once");

        // --- Kill switch
        AgentFirewall k = fw(clock);
        k.registerAgent("com.other.agent", AgentFirewall.SAFE_GRANT);
        Decision ka = k.evaluate(send("one.example.net", "a"));
        k.resolve(ka.approvalId(), true);
        Decision kb = k.evaluate(send("two.example.net", "b"));
        List<String> was = k.killSwitch();
        check(was.equals(List.of("com.example.assistant", "com.other.agent")) && k.lockdown(), "kill switch returns the agents it removed");
        check(last(k).event() == Event.KILL_SWITCH_ON && last(k).reasons().equals(List.of("AGENTS_REMOVED_2")), "kill switch logged");
        check(!k.redeem(ka.approvalId(), send("one.example.net", "a")) && last(k).reasons().equals(List.of("KILL_SWITCH_ON")), "approved-but-unused approval revoked");
        check(!k.resolve(kb.approvalId(), true) && k.openApprovals().isEmpty(), "open approvals dropped");
        Decision kd = k.evaluate(send("api.example.org", "x"));
        check(kd.verdict() == Verdict.DENY && kd.reasons().equals(List.of("KILL_SWITCH_ON")), "every request refused while on");
        k.registerAgent(AGENT, AgentFirewall.SAFE_GRANT);
        check(k.evaluate(send("api.example.org", "x")).reasons().equals(List.of("KILL_SWITCH_ON")), "re-pairing during lockdown does not open the gate");
        check(k.restorePending(saved) == 0, "approvals not restored while on");
        k.releaseKillSwitch();
        check(!k.lockdown() && last(k).event() == Event.KILL_SWITCH_OFF, "release logged");
        int before = k.auditLog().size(); k.releaseKillSwitch(); check(k.auditLog().size() == before, "release when off is a no-op");
        AgentFirewall k2 = new AgentFirewall(clock); k2.restoreLockdown(true);
        check(k2.lockdown() && k2.evaluate(send("api.example.org", "x")).reasons().equals(List.of("KILL_SWITCH_ON")) && k2.auditLog().size() == 1, "lockdown restored at start-up");
        check(k.verifyAudit() && fw(clock).restoreAudit(k.exportAudit()), "log with kill-switch events round-trips");

        // --- Pairing advice
        PairingAdvice clean = CapabilityWatch.pairingAdvice(EnumSet.noneOf(Capability.class), false, Installer.STORE);
        check(clean.risk() == Risk.LOW && clean.reasons().isEmpty() && !clean.needsExtraConfirm(), "store app without powers: low");
        PairingAdvice side = CapabilityWatch.pairingAdvice(EnumSet.noneOf(Capability.class), false, Installer.SIDELOADED);
        check(side.risk() == Risk.LOW && side.reasons().equals(List.of("SIDELOADED")) && !side.needsExtraConfirm(), "sideloaded alone: noted");
        PairingAdvice ally = CapabilityWatch.pairingAdvice(EnumSet.of(Capability.ACCESSIBILITY), false, Installer.STORE);
        check(ally.risk() == Risk.HIGH && ally.needsExtraConfirm() && ally.reasons().contains("CAN_APPROVE_ITSELF"), "accessibility: high, extra confirm");
        PairingAdvice worst = CapabilityWatch.pairingAdvice(EnumSet.of(Capability.ACCESSIBILITY, Capability.NOTIFICATION_ACCESS), true, Installer.UNKNOWN);
        check(worst.risk() == Risk.HIGH && worst.reasons().equals(List.of("READ_AND_ACT", "SCREEN_CONTROL", "CAN_APPROVE_ITSELF", "READS_NOTIFICATIONS", "DRAWS_OVER_APPS", "INSTALL_SOURCE_UNKNOWN")), "read-and-act with overlay: " + worst.reasons());
        check(CapabilityWatch.pairingAdvice(EnumSet.of(Capability.DEVICE_ADMIN), false, Installer.STORE).needsExtraConfirm(), "device admin needs extra confirm");
        PairingAdvice notif = CapabilityWatch.pairingAdvice(EnumSet.of(Capability.NOTIFICATION_ACCESS), false, Installer.STORE);
        check(notif.risk() == Risk.MEDIUM && !notif.needsExtraConfirm(), "notification access: medium");
        check(CapabilityWatch.pairingAdvice(null, true, null).reasons().equals(List.of("DRAWS_OVER_APPS", "INSTALL_SOURCE_UNKNOWN")) && CapabilityWatch.pairingAdvice(null, true, null).risk() == Risk.MEDIUM, "null inputs treated cautiously");
        check(CapabilityWatch.installerOf("com.android.vending", false) == Installer.STORE && CapabilityWatch.installerOf("org.fdroid.fdroid", false) == Installer.STORE, "stores");
        check(CapabilityWatch.installerOf("com.google.android.packageinstaller", false) == Installer.SIDELOADED, "package installer = sideloaded");
        check(CapabilityWatch.installerOf("com.android.chrome", false) == Installer.OTHER_APP && CapabilityWatch.installerOf(null, false) == Installer.UNKNOWN
            && CapabilityWatch.installerOf("not a package", false) == Installer.UNKNOWN && CapabilityWatch.installerOf(null, true) == Installer.PREINSTALLED, "other, unknown, preinstalled");

        // --- Flood resistance (audit finding P1-1): a paired agent cannot rotate evidence out, and suppressed denials cost no write
        clock.now = Instant.parse("2026-10-28T08:00:00Z");
        AgentFirewall fl = fw(clock);
        fl.notePairing(AGENT, Event.PAIRED, false);
        fl.trustDestination("ok.example");
        int flBefore = fl.auditLog().size();
        long rev = fl.revision();
        for (int i = 0; i < 5000; i++) fl.evaluate(send("ok.example", "x")); // same instant: 30 allowed, 4,970 rate-limited
        List<AuditEntry> fll = fl.auditLog();
        long denied = fll.stream().filter(e -> e.event() == Event.DECISION && e.verdict() == Verdict.DENY).count();
        long allowed = fll.stream().filter(e -> e.event() == Event.DECISION && e.verdict() == Verdict.ALLOW).count();
        check(allowed == AgentFirewall.RATE_PER_MINUTE && denied == AgentFirewall.DENIALS_LOGGED_PER_MINUTE, "flood: 30 allowed + 5 denials logged, got " + allowed + "/" + denied);
        check(fll.size() == flBefore + allowed + denied + 1 && fll.get(0).event() == Event.PAIRED, "pairing entry is still in the main log (nothing rotated out)");
        check(fll.stream().filter(e -> e.event() == Event.RATE_LIMIT_HIT).count() == 1, "one rate-limit note, not thousands");
        long revAfter = fl.revision();
        fl.evaluate(send("ok.example", "x"));
        check(fl.revision() == revAfter, "a suppressed denial changes nothing that is saved (no disk write needed)");
        check(revAfter > rev, "logged events advance the revision");
        clock.now = clock.now.plusSeconds(61);
        fl.evaluate(send("ok.example", "x")); // new window: ALLOW again, and the old window is summarised first
        List<AuditEntry> after = fl.auditLog();
        AuditEntry summary = after.stream().filter(e -> e.event() == Event.DENIALS_SUMMARISED).findFirst().orElse(null);
        check(summary != null && summary.reasons().equals(List.of("NOT_LOGGED_" + (5000 - 30 - 5 + 1))) && summary.agentId().equals(AGENT), "suppressed denials summarised with their count: " + (summary == null ? "none" : summary.reasons()));
        check(fl.verifyAudit(), "main chain intact after flood");
        // Security log keeps what matters even after the main log rotates fully
        List<AuditEntry> sec = fl.securityLog();
        check(sec.size() == 2 && sec.get(0).event() == Event.PAIRED && sec.get(1).event() == Event.RATE_LIMIT_HIT && fl.verifySecurityLog(), "security log has pairing + rate-limit hit");
        for (int m = 0; m < 40; m++) { clock.now = clock.now.plusSeconds(61); for (int i = 0; i < 40; i++) fl.evaluate(send("ok.example", "y")); }
        check(fl.auditLog().stream().noneMatch(e -> e.event() == Event.PAIRED), "a sustained flood does rotate the main log (bounded) ...");
        check(fl.securityLog().get(0).event() == Event.PAIRED && fl.verifySecurityLog(), "... but the pairing stays in the security log");
        check(fl.securityLog().stream().filter(e -> e.event() == Event.RATE_LIMIT_HIT).count() <= 1 + 40 * 61 / 600 + 1, "rate-limit notes throttled to one per 10 minutes per agent");
        // Many agents cannot multiply the denial budget without bound
        AgentFirewall many = new AgentFirewall(clock);
        for (int i = 0; i < 500; i++) for (int j = 0; j < 10; j++) many.evaluate(new Request("agent" + i + ".x", ActionType.SEND_DATA, "a.example", "", "", Provenance.USER_DIRECT, -1, ""));
        check(many.auditLog().size() <= 64 * AgentFirewall.DENIALS_LOGGED_PER_MINUTE + AgentFirewall.DENIALS_LOGGED_PER_MINUTE, "unknown-agent denials share a bounded budget: " + many.auditLog().size());
        // Kill switch writes the pending summary before its own entry
        AgentFirewall ks = fw(clock);
        for (int i = 0; i < 20; i++) ks.evaluate(new Request("stranger.app", ActionType.SEND_DATA, "a.example", "", "", Provenance.USER_DIRECT, -1, ""));
        ks.killSwitch();
        List<AuditEntry> ksl = ks.auditLog();
        check(ksl.get(ksl.size() - 2).event() == Event.DENIALS_SUMMARISED && ksl.get(ksl.size() - 2).reasons().equals(List.of("NOT_LOGGED_15")) && ksl.get(ksl.size() - 1).event() == Event.KILL_SWITCH_ON, "kill switch flushes the summary first");
        check(ks.securityLog().get(ks.securityLog().size() - 1).event() == Event.KILL_SWITCH_ON, "kill switch in the security log");

        // --- Security log persistence and damage handling
        String secText = fl.exportSecurityLog();
        check(secText.startsWith("AEGIS-SECURITY 1\n") && AgentFirewall.parseAudit(secText) == null && AgentFirewall.parseSecurityLog(fl.exportAudit()) == null, "the two log formats cannot be swapped");
        AgentFirewall rs = fw(clock);
        boolean[] both = rs.restoreLogs(fl.exportAudit(), secText);
        check(both[0] && both[1] && rs.securityLog().equals(fl.securityLog()) && rs.auditLog().equals(fl.auditLog()), "both logs restore exactly");
        AgentFirewall rd = fw(clock);
        boolean[] dmg = rd.restoreLogs(fl.exportAudit(), secText.replace("\tPAIRED\t", "\tUNPAIRED\t"));
        check(dmg[0] && !dmg[1], "edited security log detected, main log fine");
        check(rd.securityLog().size() == 1 && rd.securityLog().get(0).reasons().equals(List.of("SECURITY_LOG_CHAIN_BROKEN")) && rd.verifySecurityLog(), "security log restarts with a damage note");
        check(rd.auditLog().get(rd.auditLog().size() - 1).reasons().equals(List.of("SECURITY_LOG_CHAIN_BROKEN")), "damage note also in the main log");
        AgentFirewall rbad = fw(clock);
        boolean[] bothBad = rbad.restoreLogs("garbage", "garbage");
        check(!bothBad[0] && !bothBad[1] && rbad.securityLog().size() == 2 && rbad.auditLog().size() == 2, "both damaged: two notes in each log, neither overwritten");
        check(rbad.restoreAudit(null) && rbad.restoreSecurityLog(""), "nothing saved is fine");

        System.out.println("AgentShieldTests: " + checks + " checks passed");
    }
}
