package com.aegis.core;

import com.aegis.core.AgentBehaviour.*;
import com.aegis.core.AgentFirewall.ActionType;
import com.aegis.core.AgentFirewall.Decision;
import com.aegis.core.AgentFirewall.Provenance;
import com.aegis.core.AgentFirewall.Request;
import com.aegis.core.AgentFirewall.Verdict;
import java.time.*;
import java.util.*;

/** Host tests for the agent behaviour watch: sessions, ratings, the "Is this you?" pause and AI host matching. */
public final class AgentBehaviourTests {
    private static int checks;
    private static void check(boolean ok, String message) { checks++; if (!ok) throw new AssertionError(message); }
    private static final Instant T0 = Instant.parse("2026-10-29T10:00:00Z");
    private static Event call(long sec, String agent, boolean present) { return new Event(T0.plusSeconds(sec), Source.GATEWAY, agent, present, false); }
    private static Event lookup(long sec, String service, boolean present) { return new Event(T0.plusSeconds(sec), Source.AI_LOOKUP, service, present, false); }

    public static void main(String[] args) {
        // --- AI host matching
        check("OpenAI".equals(AgentBehaviour.aiService("api.openai.com")) && "Anthropic".equals(AgentBehaviour.aiService("api.anthropic.com.")), "api hosts");
        check("Google Gemini".equals(AgentBehaviour.aiService("generativelanguage.googleapis.com")) && "OpenRouter".equals(AgentBehaviour.aiService("openrouter.ai")), "gemini, openrouter");
        check("OpenRouter".equals(AgentBehaviour.aiService("eu.openrouter.ai")), "subdomain of listed host");
        check("Azure OpenAI".equals(AgentBehaviour.aiService("myco.openai.azure.com")) && "Amazon Bedrock".equals(AgentBehaviour.aiService("bedrock-runtime.eu-west-1.amazonaws.com")), "cloud patterns");
        for (String n : new String[] {"openai.com", "chatgpt.com", "claude.ai", "googleapis.com", "www.googleapis.com", "evilapi.openai.com.attacker.net", "api-openai.com", "", "com", "bedrock.eu-west-1.amazonaws.com"})
            check(AgentBehaviour.aiService(n) == null, "not an AI API: " + n);
        check(AgentBehaviour.aiService(null) == null && AgentBehaviour.aiService("a".repeat(300)) == null, "bad input");

        // --- Gateway: an agent the person is using is ASSISTED
        AgentBehaviour w = new AgentBehaviour();
        long[] human = {0, 9, 31, 40, 95, 130, 133, 190, 260, 300};
        for (long t : human) w.record(call(t, "com.agent", true));
        Session s = w.current(Source.GATEWAY, "com.agent", T0.plusSeconds(301));
        check(s != null && s.mode() == Mode.ASSISTED && s.reasons().equals(List.of("AGENT_WHILE_IN_USE")) && s.events() == 10, "assisted: " + s);
        check(!w.shouldPause("com.agent", T0.plusSeconds(301)), "assisted does not pause");

        // --- Calls while the phone is locked are AUTONOMOUS and pause
        w.record(call(400, "com.agent", false));
        check(w.current(Source.GATEWAY, "com.agent", T0.plusSeconds(400)).mode() == Mode.ASSISTED, "one call while away is not enough");
        w.record(call(420, "com.agent", false));
        Session away = w.current(Source.GATEWAY, "com.agent", T0.plusSeconds(421));
        check(away.mode() == Mode.AUTONOMOUS && away.reasons().contains("WHILE_LOCKED") && away.whileAway() == 2, "locked: " + away);
        check(w.shouldPause("com.agent", T0.plusSeconds(421)), "autonomous pauses");
        check(w.needsAnswer(T0.plusSeconds(421)).size() == 1, "needs an answer");
        w.acknowledge(away);
        check(!w.shouldPause("com.agent", T0.plusSeconds(421)) && w.needsAnswer(T0.plusSeconds(421)).isEmpty() && w.acknowledged(w.current(Source.GATEWAY, "com.agent", T0.plusSeconds(421))), "acknowledged session no longer pauses");
        w.record(call(430, "com.agent", false));
        check(!w.shouldPause("com.agent", T0.plusSeconds(431)), "acknowledgement holds for the rest of the session");

        // --- A new session after a gap starts fresh, and needs a new answer
        w.record(call(430 + 301, "com.agent", false));
        w.record(call(430 + 320, "com.agent", false));
        check(w.shouldPause("com.agent", T0.plusSeconds(751)), "new session pauses again");
        check(w.sessions(T0.plusSeconds(751)).stream().filter(x -> x.actor().equals("com.agent")).count() == 2, "two sessions");
        check(!w.shouldPause("com.agent", T0.plusSeconds(750 + 301)), "session over after the gap");

        // --- Machine pace and steady rhythm, with the person present
        AgentBehaviour p = new AgentBehaviour();
        for (int i = 0; i < 8; i++) p.record(call(i * 2L + (i % 2), "com.fast", true));
        Session fast = p.current(Source.GATEWAY, "com.fast", T0.plusSeconds(20));
        check(fast.mode() == Mode.AUTONOMOUS && fast.reasons().contains("MACHINE_PACE") && !fast.reasons().contains("WHILE_LOCKED"), "machine pace: " + fast);
        AgentBehaviour r = new AgentBehaviour();
        for (int i = 0; i < 10; i++) r.record(call(i * 30L, "com.cron", true));
        Session cron = r.current(Source.GATEWAY, "com.cron", T0.plusSeconds(271));
        check(cron.mode() == Mode.AUTONOMOUS && cron.reasons().equals(List.of("STEADY_RHYTHM")) && Math.abs(cron.meanGapSeconds() - 30) < 0.01, "steady rhythm: " + cron);
        AgentBehaviour slow = new AgentBehaviour();
        for (int i = 0; i < 7; i++) slow.record(call(i, "com.seven", true));
        check(slow.current(Source.GATEWAY, "com.seven", T0.plusSeconds(7)).mode() == Mode.ASSISTED, "too few calls for a pace rating");

        // --- AI lookups: unattributed; locked phone is AUTONOMOUS, in use is HUMAN; debounced
        AgentBehaviour d = new AgentBehaviour();
        d.record(lookup(0, "OpenAI", true)); d.record(lookup(5, "OpenAI", true)); d.record(lookup(10, "OpenAI", true));
        Session inUse = d.current(Source.AI_LOOKUP, "OpenAI", T0.plusSeconds(11));
        check(inUse.events() == 1 && inUse.mode() == Mode.HUMAN, "debounced, human: " + inUse);
        AgentBehaviour l = new AgentBehaviour();
        for (int i = 0; i < 2; i++) l.record(lookup(i * 60L, "Anthropic", false));
        check(l.current(Source.AI_LOOKUP, "Anthropic", T0.plusSeconds(61)).mode() == Mode.HUMAN, "two locked lookups are not enough");
        l.record(lookup(130, "Anthropic", false));
        Session bg = l.current(Source.AI_LOOKUP, "Anthropic", T0.plusSeconds(131));
        check(bg.mode() == Mode.AUTONOMOUS && bg.reasons().equals(List.of("WHILE_LOCKED")) && l.needsAnswer(T0.plusSeconds(131)).size() == 1, "locked lookups: " + bg);
        check(!l.shouldPause("Anthropic", T0.plusSeconds(131)), "lookups never pause the gateway");
        AgentBehaviour fastDns = new AgentBehaviour();
        for (int i = 0; i < 20; i++) fastDns.record(lookup(i * 21L, "OpenAI", true));
        check(fastDns.current(Source.AI_LOOKUP, "OpenAI", T0.plusSeconds(400)).mode() == Mode.HUMAN, "pace rules do not apply to DNS");

        // --- Bounds and hostile input
        AgentBehaviour b = new AgentBehaviour();
        b.record(null); b.record(new Event(null, Source.GATEWAY, "x", true, false)); b.record(new Event(T0, null, "x", true, false));
        b.record(new Event(T0, Source.GATEWAY, "", true, false)); b.record(new Event(T0, Source.GATEWAY, "x".repeat(201), true, false));
        check(b.sessions(T0).isEmpty(), "invalid events dropped");
        for (int i = 0; i < 5000; i++) b.record(call(i, "com.flood" + (i % 7), true));
        int total = b.sessions(T0.plusSeconds(5000)).stream().mapToInt(Session::events).sum();
        check(total == AgentBehaviour.MAX_EVENTS, "event cap: " + total);
        check(b.sessions(T0.plusSeconds(5000).plus(Duration.ofHours(25))).isEmpty(), "old events expire");
        AgentBehaviour order = new AgentBehaviour();
        order.record(call(100, "com.o", true)); order.record(call(50, "com.o", true));
        Session os = order.current(Source.GATEWAY, "com.o", T0.plusSeconds(101));
        check(os.start().equals(T0.plusSeconds(50)) && os.end().equals(T0.plusSeconds(100)), "out-of-order events sorted");
        List<Session> sorted = w.sessions(T0.plusSeconds(800));
        for (int i = 1; i < sorted.size(); i++) check(!sorted.get(i).end().isAfter(sorted.get(i - 1).end()), "most recent first");

        // --- Firewall: "Is this you?" turns a silent ALLOW into ASK_USER, never weakens a DENY
        AgentFirewall f = new AgentFirewall(Clock.fixed(T0, ZoneOffset.UTC));
        f.registerAgent("com.agent", EnumSet.allOf(ActionType.class));
        f.trustDestination("api.example.org");
        Request benign = new Request("com.agent", ActionType.SEND_DATA, "https://api.example.org/notes", "Save note", "shopping list: milk", Provenance.USER_DIRECT, -1, null);
        check(f.evaluate(benign).verdict() == Verdict.ALLOW && !f.paused("com.agent"), "allowed when not paused");
        f.setPaused("com.agent", true);
        Decision asked = f.evaluate(benign);
        check(asked.verdict() == Verdict.ASK_USER && asked.reasons().contains("IS_THIS_YOU") && asked.approvalId() != null, "paused asks: " + asked);
        check(f.resolve(asked.approvalId(), true) && f.redeem(asked.approvalId(), benign), "the person can still approve it");
        Request secret = new Request("com.agent", ActionType.SEND_DATA, "https://unknown.example.net/x", "Upload", "my password is hunter2 and AKIAABCDEFGHIJKLMNOP", Provenance.USER_DIRECT, -1, null);
        check(f.evaluate(secret).verdict() == Verdict.DENY, "a refusal stays a refusal");
        f.setPaused("com.agent", false);
        check(f.evaluate(benign).verdict() == Verdict.ALLOW, "unpaused allows again");
        f.setPaused(null, true);
        check(!f.paused("other"), "null agent ignored");

        // --- DNS filter reports AI lookups, without changing its answer
        List<String> seen = new ArrayList<>();
        DnsFilter filter = new DnsFilter(null, new DnsFilter.DomainLists());
        filter.setAiLookupListener(seen::add);
        DnsFilter.Decision dd = filter.decide("api.openai.com");
        filter.decide("example.org");
        check(seen.equals(List.of("OpenAI")) && dd.action() == DnsFilter.Action.ALLOW, "filter reports AI lookups: " + seen);
        filter.setAiLookupListener(x -> { throw new RuntimeException("boom"); });
        check(filter.decide("api.anthropic.com").action() == DnsFilter.Action.ALLOW, "listener failure never breaks DNS");
        DnsFilter.DomainLists lists = new DnsFilter.DomainLists(); lists.block("api.openai.com");
        DnsFilter blocking = new DnsFilter(null, lists); List<String> seen2 = new ArrayList<>(); blocking.setAiLookupListener(seen2::add);
        check(blocking.decide("api.openai.com").action() == DnsFilter.Action.BLOCK && seen2.size() == 1, "blocked lookups still reported");

        System.out.println("AgentBehaviourTests: " + checks + " checks passed");
    }
}
