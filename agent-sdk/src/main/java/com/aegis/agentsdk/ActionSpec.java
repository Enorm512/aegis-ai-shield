package com.aegis.agentsdk;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;

/**
 * One concrete action an agent wants to take: what kind, where to, and the exact content. The fingerprint binds a
 * person's plan confirmation to these exact values, so a changed destination or payload is a different action.
 * kind is an {@link AegisProtocol#ACTION_TYPES} name or a broker action ({@link AegisProtocol#BROKER_ACTIONS}).
 */
public final class ActionSpec {
    public final String kind, destination, payload;

    public ActionSpec(String kind, String destination, String payload) {
        if (kind == null || !(AegisProtocol.ACTION_TYPES.contains(kind) || AegisProtocol.BROKER_ACTIONS.contains(kind))) throw new IllegalArgumentException("unknown action kind: " + kind);
        this.kind = kind;
        this.destination = destination == null ? "" : destination;
        this.payload = payload == null ? "" : payload;
    }

    public static ActionSpec sendData(String destination, String payload) { return new ActionSpec("SEND_DATA", destination, payload); }
    public static ActionSpec openUrl(String url) { return new ActionSpec(AegisProtocol.BROKER_OPEN_URL, url, url); }
    public static ActionSpec shareText(String text) { return new ActionSpec(AegisProtocol.BROKER_SHARE_TEXT, "", text); }

    public boolean isBroker() { return AegisProtocol.BROKER_ACTIONS.contains(kind); }

    /** SHA-256 over length-prefixed fields: no value can imitate a separator. */
    public String fingerprint() {
        StringBuilder b = new StringBuilder();
        for (String f : new String[] {kind, destination, payload}) b.append(f.length()).append(':').append(f).append(';');
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(b.toString().getBytes(StandardCharsets.UTF_8));
            StringBuilder s = new StringBuilder();
            for (byte x : d) s.append(String.format(Locale.ROOT, "%02x", x & 255));
            return s.toString();
        } catch (NoSuchAlgorithmException e) { throw new AssertionError(e); }
    }

    @Override public boolean equals(Object o) { return o instanceof ActionSpec && ((ActionSpec) o).fingerprint().equals(fingerprint()); }
    @Override public int hashCode() { return fingerprint().hashCode(); }
    @Override public String toString() { return kind + " -> " + (destination.isEmpty() ? "(you choose)" : destination); }
}
