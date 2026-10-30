package com.aegis.core;

import com.aegis.core.AgentFirewall.*;
import java.util.*;

/** Host tests for the person's own limits: per-kind emergency stops for every agent, and read-only mode for one agent. */
public final class LimitTests {
    private static int checks;
    private static void check(boolean ok, String message) { checks++; if (!ok) throw new AssertionError(message); }

    private static AgentFirewallTests.TestClock clock;
    private static final String A = "com.agent", B = "com.other";
    private static Request req(String agent, ActionType t, String dest) { return new Request(agent, t, dest, "step", "milk", Provenance.USER_DIRECT, 100, "NOK"); }
    private static Decision ev(AgentFirewall f, Request r) { clock.now = clock.now.plusSeconds(3); return f.evaluate(r); }
    private static AgentFirewall fresh() {
        clock.now = clock.now.plusSeconds(AgentFirewall.CHAIN_GAP_SECONDS + 60);
        AgentFirewall f = new AgentFirewall(clock);
        f.registerAgent(A, EnumSet.allOf(ActionType.class));
        f.registerAgent(B, EnumSet.allOf(ActionType.class));
        f.trustDestination("api.example.org");
        return f;
    }
    private static boolean refusedFor(Decision d, String reason) { return d.verdict() == Verdict.DENY && d.reasons().equals(List.of(reason)); }
    private static long events(AgentFirewall f, Event e) { return f.securityLog().stream().filter(x -> x.event() == e).count(); }

    public static void main(String[] args) {
        clock = new AgentFirewallTests.TestClock();
        Request send = req(A, ActionType.SEND_DATA, "https://api.example.org/notes");
        Request pay = req(A, ActionType.FINANCIAL_TRANSACTION, "https://shop.example.org");
        Request read = req(A, ActionType.READ_SENSITIVE, "");

        // --- Per-kind stops: for every agent, refuse, never ask
        AgentFirewall f = fresh();
        check(ev(f, send).verdict() == Verdict.ALLOW, "allowed before the stop");
        f.setStopped(EnumSet.of(ActionType.SEND_DATA, ActionType.SHARE_FILE, ActionType.MESSAGE_AGENT), true);
        check(f.stopped().equals(EnumSet.of(ActionType.SEND_DATA, ActionType.SHARE_FILE, ActionType.MESSAGE_AGENT)), "stopped kinds are reported");
        check(refusedFor(ev(f, send), "CAPABILITY_STOPPED"), "a stopped kind is refused with only that reason");
        check(refusedFor(ev(f, req(B, ActionType.MESSAGE_AGENT, "https://api.example.org")), "CAPABILITY_STOPPED"), "for every agent");
        check(ev(f, pay).verdict() == Verdict.ASK_USER, "other kinds are untouched");
        check(!f.lockdown() && ev(f, pay).verdict() == Verdict.ASK_USER, "agents stay paired");
        check(events(f, Event.CAPABILITY_STOPPED) == 1, "one security-log entry for the stop");
        AuditEntry stopEntry = f.securityLog().stream().filter(x -> x.event() == Event.CAPABILITY_STOPPED).findFirst().get();
        check(stopEntry.reasons().containsAll(List.of("SEND_DATA", "SHARE_FILE", "MESSAGE_AGENT")) && stopEntry.reasons().size() == 3, "entry names the kinds: " + stopEntry.reasons());
        f.setStopped(EnumSet.of(ActionType.SEND_DATA), true);
        check(events(f, Event.CAPABILITY_STOPPED) == 1, "stopping what is already stopped logs nothing");
        check(f.chain(A).stream().noneMatch(s -> s.type() == ActionType.SEND_DATA && s.outcome() == StepOutcome.DENIED), "the person's stop is not recorded as the agent's step");
        f.setStopped(EnumSet.of(ActionType.SEND_DATA), false);
        check(ev(f, send).verdict() == Verdict.ALLOW, "resumed kind works again");
        check(refusedFor(ev(f, req(A, ActionType.SHARE_FILE, "https://api.example.org")), "CAPABILITY_STOPPED"), "the rest stay stopped");
        check(events(f, Event.CAPABILITY_RESUMED) == 1, "resume logged");

        // A stop cancels waiting and approved-but-unused approvals of that kind, and a later redeem is refused
        f = fresh();
        Decision waiting = ev(f, pay);
        Decision approved = ev(f, req(A, ActionType.FINANCIAL_TRANSACTION, "https://shop.example.org/2"));
        check(f.resolve(approved.approvalId(), true), "approved before the stop");
        Decision otherKind = ev(f, read);
        f.setStopped(EnumSet.of(ActionType.FINANCIAL_TRANSACTION), true);
        check(!f.openApprovals().contains(waiting.approvalId()) && f.openApprovals().contains(otherKind.approvalId()), "waiting approval of that kind is gone, others stay");
        check(!f.redeem(approved.approvalId(), req(A, ActionType.FINANCIAL_TRANSACTION, "https://shop.example.org/2")), "approved-but-unused cannot be used after the stop");
        check(!f.resolve(waiting.approvalId(), true), "the cancelled one cannot be approved");

        // The kill switch does not clear stops; a stop survives an approval issued before it even if it was not cancelled
        f.killSwitch();
        check(f.stopped().contains(ActionType.FINANCIAL_TRANSACTION), "stops are kept through the kill switch");

        // Brokered actions obey stops too
        f = fresh();
        f.setStopped(EnumSet.of(ActionType.SHARE_FILE), true);
        check(refusedFor(f.evaluateBrokered(req(A, ActionType.SHARE_FILE, "https://api.example.org")), "CAPABILITY_STOPPED"), "brokered request refused");

        // Unknown or unpaired agents still get UNKNOWN_AGENT first, so the stop list is not revealed to strangers
        check(refusedFor(ev(f, req("com.stranger", ActionType.SHARE_FILE, "https://api.example.org")), "UNKNOWN_AGENT"), "stranger sees UNKNOWN_AGENT");

        // --- Read-only mode for one agent
        f = fresh();
        Decision aPay = ev(f, pay);
        Decision aRead = ev(f, read);
        f.setReadOnly(A, true);
        check(f.readOnly(A) && !f.readOnly(B), "per agent");
        check(!f.openApprovals().contains(aPay.approvalId()) && f.openApprovals().contains(aRead.approvalId()), "turning it on cancels the agent's non-read approvals only");
        for (ActionType t : ActionType.values()) {
            if (t == ActionType.READ_SENSITIVE) continue;
            check(refusedFor(ev(f, req(A, t, "https://api.example.org")), "AGENT_READ_ONLY"), "read-only refuses " + t);
        }
        Decision stillAsks = ev(f, read);
        check(stillAsks.verdict() == Verdict.ASK_USER && stillAsks.reasons().contains("SENSITIVE_READ"), "a read still asks the person as before: " + stillAsks);
        check(f.resolve(stillAsks.approvalId(), true) && f.redeem(stillAsks.approvalId(), read), "and can be approved and used");
        check(ev(f, req(B, ActionType.SEND_DATA, "https://api.example.org/notes")).verdict() == Verdict.ALLOW, "other agents are untouched");
        check(events(f, Event.READ_ONLY_ON) == 1 && f.securityLog().stream().anyMatch(x -> x.event() == Event.READ_ONLY_ON && x.agentId().equals(A)), "logged with the agent");
        f.setReadOnly(A, true);
        check(events(f, Event.READ_ONLY_ON) == 1, "no duplicate entry");
        // An approval the person gave just before read-only cannot be used after it
        f.setReadOnly(A, false);
        Decision sendAsk = ev(f, req(A, ActionType.SEND_DATA, "https://shop.example.org"));
        check(f.resolve(sendAsk.approvalId(), true), "approved");
        f.setReadOnly(A, true);
        check(!f.redeem(sendAsk.approvalId(), req(A, ActionType.SEND_DATA, "https://shop.example.org")), "read-only blocks a send approved before it");
        f.setReadOnly(A, false);
        check(events(f, Event.READ_ONLY_OFF) == 2, "off logged each time");
        check(ev(f, req(B, ActionType.SEND_DATA, "https://api.example.org/notes")).verdict() == Verdict.ALLOW && ev(f, send).verdict() != Verdict.DENY, "after read-only, normal rules apply again");

        // Unpairing and the kill switch drop read-only (a re-paired agent starts with the person's fresh choice)
        f.setReadOnly(A, true);
        f.unregisterAgent(A);
        check(!f.readOnly(A), "unpair clears it");
        f.registerAgent(A, EnumSet.allOf(ActionType.class));
        f.setReadOnly(A, true);
        f.killSwitch();
        check(!f.readOnly(A), "kill switch clears it");

        // --- Restore at start-up writes nothing
        f = fresh();
        long before = f.securityLog().size();
        f.restoreLimits(EnumSet.of(ActionType.INSTALL_APP), Set.of(B));
        check(f.securityLog().size() == before, "restore writes no entries");
        check(refusedFor(ev(f, req(A, ActionType.INSTALL_APP, "")), "CAPABILITY_STOPPED") && refusedFor(ev(f, req(B, ActionType.SEND_DATA, "https://api.example.org")), "AGENT_READ_ONLY"), "restored limits apply");
        check(f.verifySecurityLog() && f.verifyAudit(), "logs verify");
        // Exported logs with the new events parse back
        check(AgentFirewall.parseSecurityLog(f.exportSecurityLog()) != null, "security log parses");
        f.setStopped(EnumSet.of(ActionType.INSTALL_APP), false);
        check(AgentFirewall.parseSecurityLog(f.exportSecurityLog()).entries().stream().anyMatch(x -> x.event() == Event.CAPABILITY_RESUMED), "new event round-trips");

        // --- Which approvals need the phone's own lock check
        for (ActionType t : ActionType.values()) {
            boolean sensitive = t != ActionType.SEND_DATA && t != ActionType.SHARE_FILE && t != ActionType.MESSAGE_AGENT;
            check(AgentFirewall.needsStrongConfirmation(t.name(), List.of(), List.of()) == sensitive, "by kind: " + t);
        }
        check(!AgentFirewall.needsStrongConfirmation("SEND_DATA", List.of("UNTRUSTED_DESTINATION"), List.of()), "a plain send elsewhere stays a tap");
        check(AgentFirewall.needsStrongConfirmation("SEND_DATA", List.of(), List.of("CARD_NUMBER")), "sensitive data");
        for (String r : List.of("CHAIN_PRIVATE_READ_THEN_SEND", "INJECTION_INDICATORS", "IS_THIS_YOU", "SECRET_IN_OUTBOUND_DATA"))
            check(AgentFirewall.needsStrongConfirmation("SHARE_FILE", List.of(r), List.of()), "flagged: " + r);
        check(AgentFirewall.needsStrongConfirmation("NOT_A_TYPE", List.of(), List.of()), "unknown type is sensitive");

        // The log says when the lock check passed
        f = fresh();
        Decision c1 = ev(f, pay), c2 = ev(f, read);
        check(f.resolve(c1.approvalId(), true, true) && f.resolve(c2.approvalId(), true), "both answered");
        List<AuditEntry> ok = f.securityLog().stream().filter(x -> x.event() == Event.USER_APPROVED).toList();
        check(ok.size() == 2 && ok.get(0).reasons().equals(List.of("SCREEN_LOCK_CONFIRMED")) && ok.get(1).reasons().isEmpty(), "recorded only when it happened: " + ok);
        check(f.verifySecurityLog(), "still verifies");

        System.out.println("LimitTests: " + checks + " checks passed");
    }
}
