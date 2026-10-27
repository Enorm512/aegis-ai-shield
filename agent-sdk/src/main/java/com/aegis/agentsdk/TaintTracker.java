package com.aegis.agentsdk;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * Provenance computed by the agent's harness, not by the language model.
 *
 * Aegis decides between "refuse" and "ask the person" partly on where an instruction came from. If the model picks
 * that label, a hijacked model simply claims the user asked. This tracker is fed by the harness code at the points
 * where content enters the model's context (the person's messages, tool results, web pages, files, other agents,
 * recalled memories), and gives the label for an action the model then proposes.
 *
 * Rule: context-level taint. Once anything not written by the person is in the context, every action the model
 * proposes carries the least-trusted label present, because nobody can tell which part of the context the model
 * followed. The only way back to a user label without clearing the context is an explicit plan confirmation: the
 * harness shows the person the exact actions (kind, destination, content) and they confirm; each confirmed action
 * may then be sent once as USER_CONFIRMED_PLAN. This is conservative on purpose: Aegis will ask more often.
 *
 * Thread-safe. Labels never decrease within a context; only {@link #clearContext()} resets.
 */
public final class TaintTracker {
    /** Ordered from most to least trusted. Names equal Aegis' AgentFirewall.Provenance. */
    public enum Label { USER_DIRECT, USER_CONFIRMED_PLAN, AGENT_TO_AGENT, EXTERNAL_CONTENT, UNKNOWN }

    public static final Duration MAX_PLAN_VALIDITY = Duration.ofMinutes(10);
    public static final int MAX_CONFIRMED = 50;

    private final Clock clock;
    private boolean hasUser;
    private Label worst; // least-trusted non-user label in the context, null when there is none
    private final Map<String, Instant> confirmed = new LinkedHashMap<>();

    public TaintTracker(Clock clock) { this.clock = clock; }
    public TaintTracker() { this(Clock.systemUTC()); }

    /** The person typed or said something to the agent. */
    public synchronized void userMessage() { hasUser = true; }
    /** A web page, email, document, file, search result or tool output entered the context. */
    public synchronized void externalContent() { raise(Label.EXTERNAL_CONTENT); }
    /** A message from another AI agent entered the context. */
    public synchronized void agentMessage() { raise(Label.AGENT_TO_AGENT); }
    /** Content of unknown origin entered the context. */
    public synchronized void unknownContent() { raise(Label.UNKNOWN); }
    /** A stored memory was recalled into the context. Pass the label it was saved with (see {@link #labelForNewMemory()}). */
    public synchronized void memoryRecall(Label savedWith) { raise(savedWith == null ? Label.UNKNOWN : savedWith == Label.USER_CONFIRMED_PLAN ? Label.USER_DIRECT : savedWith); }

    /** What a memory written now should be labelled with, so poisoned memories stay tainted when recalled later. */
    public synchronized Label labelForNewMemory() { return contextLabel(); }

    /** Least-trusted label of everything in the context. Nothing at all in context means UNKNOWN: no instruction came from the person. */
    public synchronized Label contextLabel() {
        if (worst != null) return worst;
        return hasUser ? Label.USER_DIRECT : Label.UNKNOWN;
    }

    /** Starts a fresh context (new conversation, or the context window was really emptied). Plan confirmations are dropped too. */
    public synchronized void clearContext() { hasUser = false; worst = null; confirmed.clear(); }

    /**
     * Call only after the harness has shown the person these exact actions and they confirmed them. Each may then be
     * used once within {@code validity} (at most ten minutes).
     */
    public synchronized void confirmPlan(Collection<ActionSpec> actions, Duration validity) {
        Duration v = validity == null || validity.isNegative() || validity.compareTo(MAX_PLAN_VALIDITY) > 0 ? MAX_PLAN_VALIDITY : validity;
        Instant until = clock.instant().plus(v);
        for (ActionSpec a : actions) {
            if (a == null) continue;
            expire();
            while (confirmed.size() >= MAX_CONFIRMED) confirmed.remove(confirmed.keySet().iterator().next());
            confirmed.put(a.fingerprint(), until);
        }
    }

    /** The label to send with this action. A confirmed, unexpired, unused plan action gets USER_CONFIRMED_PLAN (and is used up). */
    public synchronized Label provenanceFor(ActionSpec action) {
        expire();
        if (action != null && confirmed.remove(action.fingerprint()) != null) return Label.USER_CONFIRMED_PLAN;
        return contextLabel();
    }

    /** Same as provenanceFor without using up a plan confirmation, for showing in a UI. */
    public synchronized Label peekProvenance(ActionSpec action) {
        expire();
        return action != null && confirmed.containsKey(action.fingerprint()) ? Label.USER_CONFIRMED_PLAN : contextLabel();
    }

    private void raise(Label l) { if (l == Label.USER_DIRECT) { hasUser = true; return; } if (worst == null || l.compareTo(worst) > 0) worst = l; }
    private void expire() { Instant now = clock.instant(); confirmed.values().removeIf(t -> !now.isBefore(t)); }
}
