package com.aegis.agentsdk;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Aegis approval tokens: short-lived, signed statements that Aegis allowed (or the person approved) one exact agent
 * call, so a backend can refuse calls Aegis never saw.
 *
 * Format: {@code AT1.<base64url payload>.<base64url signature>}. The payload is UTF-8 text, one {@code key=value} per
 * line in a fixed order (see {@link Claims}); the signature is ECDSA P-256 with SHA-256 (DER) over the payload bytes,
 * made with a key that lives in the phone's Android Keystore and is pinned by the backend. The body field is the
 * SHA-256 of the exact request payload the agent will send, so the token covers that body and nothing else.
 *
 * Issuing ({@link #issue}) is used by Aegis; {@link Verifier} is the reference check for servers (JDK only).
 */
public final class ApprovalToken {
    private ApprovalToken() {}

    public static final String PREFIX = "AT1.";
    public static final String HEADER = "aegis-approval-token/1";
    /** A token is valid for at most this long; verifiers refuse longer ones. */
    public static final long MAX_LIFETIME_SECONDS = 120;
    public static final long DEFAULT_SKEW_SECONDS = 30;
    public static final int MAX_TOKEN_CHARS = 8192, MAX_DEST = 2048;
    public static final String GRANT_USER_APPROVED = "USER_APPROVED", GRANT_POLICY_ALLOW = "POLICY_ALLOW";

    private static final Pattern HEX32 = Pattern.compile("[0-9a-f]{32}"), HEX64 = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern PACKAGE = Pattern.compile("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)*");
    private static final Pattern HOST = Pattern.compile("[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*");
    private static final Pattern CURRENCY = Pattern.compile("[A-Z]{0,8}");
    private static final Pattern PRINTABLE = Pattern.compile("[\\x21-\\x7e]*");
    private static final String[] KEYS = {"kid", "jti", "iat", "exp", "agent", "aud", "type", "dest", "body", "amount", "currency", "grant"};

    /**
     * What a token states. iat/exp in epoch seconds; aud = the destination host the call goes to; dest = the full
     * destination as the agent gave it; body = SHA-256 hex of the request payload; amount in minor units or -1.
     */
    public record Claims(String kid, String jti, long iat, long exp, String agent, String aud, String type, String dest, String body, long amount, String currency, String grant) {
        /** Null when every field is in its allowed form, otherwise the name of the first bad field. */
        public String invalidField() {
            if (kid == null || !HEX32.matcher(kid).matches()) return "kid";
            if (jti == null || !HEX32.matcher(jti).matches()) return "jti";
            if (iat <= 0 || exp <= iat) return "exp";
            if (agent == null || agent.length() > 255 || !PACKAGE.matcher(agent).matches()) return "agent";
            if (aud == null || aud.length() > 253 || !HOST.matcher(aud).matches()) return "aud";
            if (type == null || !AegisProtocol.ACTION_TYPES.contains(type)) return "type";
            if (dest == null || dest.isEmpty() || dest.length() > MAX_DEST || !PRINTABLE.matcher(dest).matches()) return "dest";
            if (body == null || !HEX64.matcher(body).matches()) return "body";
            if (amount < -1) return "amount";
            if (currency == null || !CURRENCY.matcher(currency).matches()) return "currency";
            if (!GRANT_USER_APPROVED.equals(grant) && !GRANT_POLICY_ALLOW.equals(grant)) return "grant";
            return null;
        }

        String[] values() { return new String[] {kid, jti, Long.toString(iat), Long.toString(exp), agent, aud, type, dest, body, Long.toString(amount), currency, grant}; }
    }

    /** Makes the signature; on Android this is backed by the Keystore key. Returns a DER-encoded ECDSA signature. */
    public interface Signer { byte[] sign(byte[] data) throws Exception; }

    /** The exact bytes that are signed. Throws IllegalArgumentException for any field outside its allowed form. */
    public static byte[] payload(Claims c) {
        String bad = c == null ? "claims" : c.invalidField();
        if (bad != null) throw new IllegalArgumentException("invalid token field: " + bad);
        StringBuilder b = new StringBuilder(HEADER).append('\n');
        String[] v = c.values();
        for (int i = 0; i < KEYS.length; i++) b.append(KEYS[i]).append('=').append(v[i]).append('\n');
        return b.toString().getBytes(StandardCharsets.UTF_8);
    }

    public static String issue(Claims c, Signer signer) throws Exception {
        byte[] p = payload(c);
        byte[] sig = signer.sign(p);
        Base64.Encoder e = Base64.getUrlEncoder().withoutPadding();
        return PREFIX + e.encodeToString(p) + "." + e.encodeToString(sig);
    }

    /** Parses a payload produced by {@link #payload}; null when it is not exactly in that form. */
    static Claims parsePayload(byte[] p) {
        String s = new String(p, StandardCharsets.UTF_8);
        if (!Arrays.equals(s.getBytes(StandardCharsets.UTF_8), p)) return null; // not valid UTF-8
        String[] lines = s.split("\n", -1);
        if (lines.length != KEYS.length + 2 || !lines[0].equals(HEADER) || !lines[lines.length - 1].isEmpty()) return null;
        String[] v = new String[KEYS.length];
        for (int i = 0; i < KEYS.length; i++) {
            String l = lines[i + 1];
            if (!l.startsWith(KEYS[i] + "=")) return null;
            v[i] = l.substring(KEYS[i].length() + 1);
        }
        try {
            Claims c = new Claims(v[0], v[1], Long.parseLong(v[2]), Long.parseLong(v[3]), v[4], v[5], v[6], v[7], v[8], Long.parseLong(v[9]), v[10], v[11]);
            // Re-encoding must give the same bytes: no leading zeros, plus signs or other alternative spellings.
            return c.invalidField() == null && Arrays.equals(payload(c), p) ? c : null;
        } catch (RuntimeException e) { return null; }
    }

    // --- Helpers shared by Aegis and servers

    public static String sha256Hex(byte[] data) {
        try { return hex(MessageDigest.getInstance("SHA-256").digest(data)); } catch (NoSuchAlgorithmException e) { throw new AssertionError(e); }
    }
    public static String bodyHash(String payload) { return sha256Hex((payload == null ? "" : payload).getBytes(StandardCharsets.UTF_8)); }

    /** Key id: first 16 bytes of SHA-256 over the public key's X.509 (SubjectPublicKeyInfo) encoding, as hex. */
    public static String keyId(PublicKey k) { return sha256Hex(k.getEncoded()).substring(0, 32); }

    public static String toPem(PublicKey k) {
        String b = Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(k.getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + b + "\n-----END PUBLIC KEY-----\n";
    }

    /** Reads an EC public key in PEM (or bare base64 SubjectPublicKeyInfo). */
    public static PublicKey fromPem(String pem) throws Exception {
        String b = pem.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replaceAll("\\s", "");
        PublicKey k = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(b)));
        if (!"EC".equals(k.getAlgorithm())) throw new IllegalArgumentException("not an EC key");
        return k;
    }

    private static String hex(byte[] b) { StringBuilder s = new StringBuilder(); for (byte x : b) s.append(String.format(Locale.ROOT, "%02x", x & 255)); return s.toString(); }

    // --- Server side

    /** Remembers token ids until they expire, so each token works once. */
    public interface ReplayCache { /** Returns false if jti was already seen. */ boolean firstUse(String jti, long expEpochSeconds, long nowEpochSeconds); }

    /** In-memory replay cache for a single server process. A cluster needs a shared store with the same contract. */
    public static final class MemoryReplayCache implements ReplayCache {
        private final int max;
        private final LinkedHashMap<String, Long> seen = new LinkedHashMap<>();
        public MemoryReplayCache(int max) { this.max = max; }
        public synchronized boolean firstUse(String jti, long exp, long now) {
            seen.values().removeIf(e -> e + DEFAULT_SKEW_SECONDS < now);
            if (seen.containsKey(jti)) return false;
            // Full: refuse rather than forget an unexpired id (forgetting would allow a replay).
            if (seen.size() >= max) return false;
            seen.put(jti, exp);
            return true;
        }
        public synchronized int size() { return seen.size(); }
    }

    public record Result(boolean ok, String reason, Claims claims) {
        static Result fail(String reason) { return new Result(false, reason, null); }
    }

    /** What the server expects for this call. expectedDestination and allowedAgents/allowedTypes are optional (null = not checked). */
    public record Expect(String audience, byte[] body, String expectedDestination, Set<String> allowedAgents, Set<String> allowedTypes) {}

    /**
     * Reference verifier. Reasons: MALFORMED, UNKNOWN_KEY, BAD_SIGNATURE, NOT_YET_VALID, EXPIRED, LIFETIME_TOO_LONG,
     * WRONG_AUDIENCE, BODY_MISMATCH, DESTINATION_MISMATCH, AGENT_NOT_ALLOWED, TYPE_NOT_ALLOWED, REPLAYED.
     * Order matters: nothing from the payload is trusted before the signature checks out.
     */
    public static final class Verifier {
        private final Map<String, PublicKey> keys = new HashMap<>();
        private final ReplayCache replay;
        private final long skew;

        public Verifier(Collection<PublicKey> trustedKeys, ReplayCache replay, long skewSeconds) {
            for (PublicKey k : trustedKeys) keys.put(keyId(k), k);
            this.replay = replay;
            this.skew = Math.max(0, Math.min(skewSeconds, 300));
        }

        public Result verify(String token, Expect expect, long nowEpochSeconds) {
            try { return check(token, expect, nowEpochSeconds); } catch (RuntimeException e) { return Result.fail("MALFORMED"); }
        }

        private Result check(String token, Expect x, long now) {
            if (token == null || token.length() > MAX_TOKEN_CHARS || !token.startsWith(PREFIX) || x == null || x.audience() == null || x.body() == null) return Result.fail("MALFORMED");
            String[] parts = token.substring(PREFIX.length()).split("\\.", -1);
            if (parts.length != 2) return Result.fail("MALFORMED");
            byte[] p, sig;
            try { p = Base64.getUrlDecoder().decode(parts[0]); sig = Base64.getUrlDecoder().decode(parts[1]); } catch (IllegalArgumentException e) { return Result.fail("MALFORMED"); }
            Claims c = parsePayload(p);
            if (c == null) return Result.fail("MALFORMED");
            PublicKey k = keys.get(c.kid());
            if (k == null) return Result.fail("UNKNOWN_KEY");
            try {
                Signature s = Signature.getInstance("SHA256withECDSA");
                s.initVerify(k); s.update(p);
                if (!s.verify(sig)) return Result.fail("BAD_SIGNATURE");
            } catch (Exception e) { return Result.fail("BAD_SIGNATURE"); }
            if (c.exp() - c.iat() > MAX_LIFETIME_SECONDS) return Result.fail("LIFETIME_TOO_LONG");
            if (c.iat() > now + skew) return Result.fail("NOT_YET_VALID");
            if (now > c.exp() + skew) return Result.fail("EXPIRED");
            if (!c.aud().equals(x.audience().toLowerCase(Locale.ROOT))) return Result.fail("WRONG_AUDIENCE");
            if (!MessageDigest.isEqual(c.body().getBytes(StandardCharsets.US_ASCII), sha256Hex(x.body()).getBytes(StandardCharsets.US_ASCII))) return Result.fail("BODY_MISMATCH");
            if (x.expectedDestination() != null && !x.expectedDestination().equals(c.dest())) return Result.fail("DESTINATION_MISMATCH");
            if (x.allowedAgents() != null && !x.allowedAgents().contains(c.agent())) return Result.fail("AGENT_NOT_ALLOWED");
            if (x.allowedTypes() != null && !x.allowedTypes().contains(c.type())) return Result.fail("TYPE_NOT_ALLOWED");
            if (replay != null && !replay.firstUse(c.jti(), c.exp(), now)) return Result.fail("REPLAYED");
            return new Result(true, "OK", c);
        }
    }
}
