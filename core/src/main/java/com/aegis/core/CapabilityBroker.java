package com.aegis.core;

import java.net.URI;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.*;

/**
 * Capability broker (prototype). Instead of asking "may I?" and then acting itself, an integrated agent asks Aegis to
 * carry out the action. Aegis checks it with the firewall and, once allowed or approved by the person, performs
 * exactly that action itself, from the content it holds. The agent never receives an approval it could reuse for
 * something else. First actions: open a web link, and open the share menu with a text (the person picks the app).
 * Both need no new permission. Pure logic; the Android side builds and starts the intents.
 */
public final class CapabilityBroker {
    private CapabilityBroker() {}

    public enum Kind { OPEN_URL, SHARE_TEXT }

    public static final int MAX_URL = 2048, MAX_TEXT = 10_000, MAX_TICKETS = 20;

    /** value is the link for OPEN_URL and the text for SHARE_TEXT. */
    public record Action(Kind kind, String value) {}

    /**
     * Returns null when the action may be offered to the firewall, otherwise a reason code:
     * URL_TOO_LONG, URL_NOT_PRINTABLE_ASCII, URL_MALFORMED, URL_NOT_HTTPS, URL_HAS_USERINFO, URL_UNUSUAL_PORT, URL_NO_HOST,
     * TEXT_EMPTY, TEXT_TOO_LONG, MALFORMED_ACTION.
     */
    public static String validate(Action a) {
        if (a == null || a.kind() == null || a.value() == null) return "MALFORMED_ACTION";
        String v = a.value();
        if (a.kind() == Kind.SHARE_TEXT) {
            if (v.trim().isEmpty()) return "TEXT_EMPTY";
            return v.length() > MAX_TEXT ? "TEXT_TOO_LONG" : null;
        }
        if (v.length() > MAX_URL) return "URL_TOO_LONG";
        for (int i = 0; i < v.length(); i++) { char c = v.charAt(i); if (c <= 0x20 || c >= 0x7f) return "URL_NOT_PRINTABLE_ASCII"; } // look-alike Unicode must arrive as punycode
        URI u;
        try { u = new URI(v); } catch (Exception e) { return "URL_MALFORMED"; }
        if (u.getScheme() == null || !u.getScheme().equalsIgnoreCase("https")) return "URL_NOT_HTTPS";
        if (u.getRawUserInfo() != null) return "URL_HAS_USERINFO";
        if (u.getPort() != -1 && u.getPort() != 443) return "URL_UNUSUAL_PORT";
        if (u.getHost() == null || AgentFirewall.hostOf(v).isEmpty()) return "URL_NO_HOST";
        return null;
    }

    /**
     * The firewall request for an action. Both are outbound data: a link carries its query string to the site, and
     * shared text goes to whichever app the person picks (so it has no known destination and is always asked about).
     */
    public static AgentFirewall.Request toRequest(String agentId, Action a, String summary, AgentFirewall.Provenance provenance) {
        String dest = a.kind() == Kind.OPEN_URL ? a.value() : "";
        return new AgentFirewall.Request(agentId, AgentFirewall.ActionType.SEND_DATA, dest, summary == null ? "" : summary, a.value(), provenance, -1, "");
    }

    /** What Aegis holds for an action it will carry out: the exact request the firewall saw and the action built from it. */
    public record Ticket(String id, String agentId, Action action, AgentFirewall.Request request, Instant expires) {}

    /**
     * Single-use tickets, kept in memory only. Keyed by the approval id for asked actions, or by a fresh random id for
     * actions the firewall allowed outright (the agent then holds an opaque launcher bound to that id).
     */
    public static final class Tickets {
        private final Clock clock;
        private final SecureRandom random = new SecureRandom();
        private final Map<String, Ticket> map = new LinkedHashMap<>();
        public Tickets(Clock clock) { this.clock = clock; }

        public synchronized String newId() { byte[] b = new byte[16]; random.nextBytes(b); StringBuilder s = new StringBuilder(); for (byte x : b) s.append(String.format(Locale.ROOT, "%02x", x & 255)); return s.toString(); }

        public synchronized void put(String id, String agentId, Action action, AgentFirewall.Request request, long ttlSeconds) {
            if (id == null || action == null || request == null || ttlSeconds <= 0) throw new IllegalArgumentException("incomplete ticket");
            expire();
            while (map.size() >= MAX_TICKETS) map.remove(map.keySet().iterator().next()); // oldest goes first
            map.put(id, new Ticket(id, agentId, action, request, clock.instant().plusSeconds(Math.min(ttlSeconds, 300))));
        }

        /** Removes and returns the ticket; null when unknown or expired. */
        public synchronized Ticket take(String id) { expire(); return id == null ? null : map.remove(id); }
        public synchronized boolean has(String id) { expire(); return id != null && map.containsKey(id); }
        public synchronized void clear() { map.clear(); }
        public synchronized int size() { expire(); return map.size(); }
        private void expire() { Instant now = clock.instant(); map.values().removeIf(t -> !now.isBefore(t.expires())); }
    }
}
