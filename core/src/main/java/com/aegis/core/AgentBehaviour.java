package com.aegis.core;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * Agent behaviour watch: groups what Aegis can observe of AI agents into sessions and rates each one HUMAN, ASSISTED or
 * AUTONOMOUS. Two sources: calls from paired agents to the gateway (attributed to the app) and DNS lookups of AI model
 * APIs (not attributable to an app on Android). Each event carries whether the person was using the phone at that moment
 * (screen on and unlocked). The rules are fixed and untuned; a rating is a reason to ask the person, never a verdict.
 */
public final class AgentBehaviour {
    public enum Mode { HUMAN, ASSISTED, AUTONOMOUS }
    public enum Source { GATEWAY, AI_LOOKUP }
    /** {@code actor} is the agent's package for GATEWAY, the AI service name for AI_LOOKUP. */
    public record Event(Instant at, Source source, String actor, boolean personPresent, boolean sensitive) {}
    public record Session(Source source, String actor, Instant start, Instant end, int events, int whileAway, int sensitive,
                          double meanGapSeconds, Mode mode, List<String> reasons) {
        public String key() { return source + ":" + actor + ":" + start.toEpochMilli(); }
    }

    public static final Duration SESSION_GAP = Duration.ofMinutes(5);
    public static final Duration KEEP = Duration.ofHours(24);
    public static final int MAX_EVENTS = 3000;
    /** Rule thresholds, also shown in KNOWN_LIMITATIONS.md. */
    static final int AWAY_GATEWAY = 2, AWAY_LOOKUPS = 3, PACE_EVENTS = 8, RHYTHM_EVENTS = 10;
    static final double PACE_SECONDS = 4.0, RHYTHM_CV = 0.25;
    /** Lookups of the same service closer together than this count once (apps resolve the same name several times at start-up). */
    static final Duration LOOKUP_DEBOUNCE = Duration.ofSeconds(20);

    private final ArrayDeque<Event> events = new ArrayDeque<>();
    private final Set<String> acknowledged = new HashSet<>();

    public synchronized void record(Event e) {
        if (e == null || e.at() == null || e.source() == null || e.actor() == null || e.actor().isEmpty() || e.actor().length() > 200) return;
        if (e.source() == Source.AI_LOOKUP) {
            for (Iterator<Event> it = events.descendingIterator(); it.hasNext(); ) {
                Event p = it.next();
                if (Duration.between(p.at(), e.at()).compareTo(LOOKUP_DEBOUNCE) > 0) break;
                if (p.source() == Source.AI_LOOKUP && p.actor().equals(e.actor()) && p.personPresent() == e.personPresent()) return;
            }
        }
        events.addLast(e);
        prune(e.at());
    }

    private void prune(Instant now) {
        while (!events.isEmpty() && (events.size() > MAX_EVENTS || events.peekFirst().at().isBefore(now.minus(KEEP)))) events.removeFirst();
    }

    /** All sessions in the last 24 hours, most recent first. */
    public synchronized List<Session> sessions(Instant now) {
        prune(now);
        Map<String, List<Event>> byActor = new LinkedHashMap<>();
        for (Event e : events) byActor.computeIfAbsent(e.source() + "\u0000" + e.actor(), k -> new ArrayList<>()).add(e);
        List<Session> out = new ArrayList<>();
        for (List<Event> list : byActor.values()) {
            list.sort(Comparator.comparing(Event::at));
            List<Event> run = new ArrayList<>();
            for (Event e : list) {
                if (!run.isEmpty() && Duration.between(run.get(run.size() - 1).at(), e.at()).compareTo(SESSION_GAP) > 0) { out.add(score(run)); run = new ArrayList<>(); }
                run.add(e);
            }
            if (!run.isEmpty()) out.add(score(run));
        }
        out.sort((a, b) -> b.end().compareTo(a.end()));
        return out;
    }

    /** The actor's session still running at {@code now} (last event within {@link #SESSION_GAP}), or null. */
    public synchronized Session current(Source source, String actor, Instant now) {
        for (Session s : sessions(now))
            if (s.source() == source && s.actor().equals(actor) && Duration.between(s.end(), now).compareTo(SESSION_GAP) <= 0) return s;
        return null;
    }

    /**
     * "Is this you?" for a paired agent: true while its running session is rated AUTONOMOUS and the person has not
     * confirmed that session. The gateway then asks the person before every action, even ones policy would allow.
     */
    public synchronized boolean shouldPause(String agent, Instant now) {
        Session s = current(Source.GATEWAY, agent, now);
        return s != null && s.mode() == Mode.AUTONOMOUS && !acknowledged.contains(s.key());
    }

    /** The person said "yes, that was me" for this session; it stays rated as it is but no longer pauses or warns. */
    public synchronized void acknowledge(Session s) { if (s != null) { acknowledged.add(s.key()); if (acknowledged.size() > 500) acknowledged.clear(); } }
    public synchronized boolean acknowledged(Session s) { return s != null && acknowledged.contains(s.key()); }

    /** Sessions the person should be asked about: AUTONOMOUS, not yet confirmed. */
    public synchronized List<Session> needsAnswer(Instant now) {
        List<Session> out = new ArrayList<>();
        for (Session s : sessions(now)) if (s.mode() == Mode.AUTONOMOUS && !acknowledged.contains(s.key())) out.add(s);
        return out;
    }

    public synchronized void clear() { events.clear(); acknowledged.clear(); }

    static Session score(List<Event> run) {
        Event first = run.get(0), last = run.get(run.size() - 1);
        int away = 0, sensitive = 0;
        for (Event e : run) { if (!e.personPresent()) away++; if (e.sensitive()) sensitive++; }
        double mean = 0, cv = Double.NaN;
        if (run.size() > 1) {
            double[] gaps = new double[run.size() - 1];
            for (int i = 1; i < run.size(); i++) gaps[i - 1] = Duration.between(run.get(i - 1).at(), run.get(i).at()).toMillis() / 1000.0;
            for (double g : gaps) mean += g;
            mean /= gaps.length;
            double var = 0;
            for (double g : gaps) var += (g - mean) * (g - mean);
            var /= gaps.length;
            cv = mean > 0 ? Math.sqrt(var) / mean : 0;
        }
        List<String> reasons = new ArrayList<>();
        boolean gateway = first.source() == Source.GATEWAY;
        if (away >= (gateway ? AWAY_GATEWAY : AWAY_LOOKUPS)) reasons.add("WHILE_LOCKED");
        // Pace and rhythm only mean something for agent calls: DNS caching hides how often a service is really used.
        if (gateway && run.size() >= PACE_EVENTS && mean < PACE_SECONDS) reasons.add("MACHINE_PACE");
        if (gateway && run.size() >= RHYTHM_EVENTS && cv < RHYTHM_CV) reasons.add("STEADY_RHYTHM");
        Mode mode;
        if (!reasons.isEmpty()) mode = Mode.AUTONOMOUS;
        else if (gateway) { mode = Mode.ASSISTED; reasons.add("AGENT_WHILE_IN_USE"); }
        else { mode = Mode.HUMAN; reasons.add("AI_USE_WHILE_IN_USE"); }
        return new Session(first.source(), first.actor(), first.at(), last.at(), run.size(), away, sensitive, mean, mode, Collections.unmodifiableList(reasons));
    }

    // -----------------------------------------------------------------------------------------------------------------
    // AI model APIs recognised in DNS lookups. Programmatic endpoints only: the chat websites and apps people use by hand
    // are left out, so a phone in a pocket syncing a chat app is less likely to look like an agent.
    // -----------------------------------------------------------------------------------------------------------------
    private static final Map<String, String> AI_HOSTS = new LinkedHashMap<>();
    static {
        String[][] h = {
            {"api.openai.com", "OpenAI"}, {"api.anthropic.com", "Anthropic"}, {"generativelanguage.googleapis.com", "Google Gemini"},
            {"aiplatform.googleapis.com", "Google Vertex AI"}, {"api.mistral.ai", "Mistral"}, {"api.cohere.com", "Cohere"}, {"api.cohere.ai", "Cohere"},
            {"api.groq.com", "Groq"}, {"api.perplexity.ai", "Perplexity"}, {"api.deepseek.com", "DeepSeek"}, {"openrouter.ai", "OpenRouter"},
            {"api.together.xyz", "Together AI"}, {"api.together.ai", "Together AI"}, {"api.x.ai", "xAI"}, {"api.fireworks.ai", "Fireworks AI"},
            {"api-inference.huggingface.co", "Hugging Face"}, {"router.huggingface.co", "Hugging Face"}, {"api.replicate.com", "Replicate"},
            {"api.moonshot.ai", "Moonshot"}, {"dashscope.aliyuncs.com", "Alibaba Qwen"}, {"dashscope-intl.aliyuncs.com", "Alibaba Qwen"},
        };
        for (String[] e : h) AI_HOSTS.put(e[0], e[1]);
    }

    /** The AI service a lowercase DNS name belongs to, or null. Subdomains of a listed API host count too. */
    public static String aiService(String name) {
        if (name == null || name.isEmpty() || name.length() > 253) return null;
        String n = name.endsWith(".") ? name.substring(0, name.length() - 1) : name;
        if (n.endsWith(".openai.azure.com") || n.endsWith(".services.ai.azure.com")) return "Azure OpenAI";
        if (n.startsWith("bedrock-runtime.") && n.endsWith(".amazonaws.com")) return "Amazon Bedrock";
        String h = n;
        while (true) {
            String s = AI_HOSTS.get(h);
            if (s != null) return s;
            int dot = h.indexOf('.');
            if (dot < 0 || h.indexOf('.', dot + 1) < 0) return null; // never match on a bare registrable domain like "googleapis.com"
            h = h.substring(dot + 1);
        }
    }
}
