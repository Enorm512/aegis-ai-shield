package com.aegis.core;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.*;
import java.util.regex.*;

/**
 * Verifies and parses a signed threat bundle (format AEGIS-THREATDB 1, see THREAT_DB_FORMAT.md).
 * The signature (ECDSA P-256 / SHA-256) is checked before any entry is parsed.
 */
public final class ThreatBundleVerifier {
    public static final int MAX_BUNDLE_BYTES = 16 * 1024 * 1024;
    public static final int MAX_ENTRIES = 500_000;
    /** One install may advance a key's sequence by at most this much, so a typo or stolen key cannot burn the whole number space. */
    public static final long MAX_SEQUENCE_JUMP = 100_000;
    /** A bundle may be valid for at most this long, so a stale feed is never trusted for years. */
    public static final int MAX_VALIDITY_DAYS = 100;
    private static final int MAX_SIGNATURE_BASE64 = 200;

    public static final class BundleException extends Exception {
        public enum Reason { TOO_LARGE, MALFORMED, UNTRUSTED_KEY, BAD_SIGNATURE, ROLLBACK, EXPIRED, FUTURE_DATED, BAD_ENTRY, SEQUENCE_JUMP }
        public final Reason reason;
        public BundleException(Reason reason, String message) { super(message); this.reason = reason; }
    }

    /** Public keys the app trusts. Empty means no update can ever be accepted. */
    private static final java.math.BigInteger P256_ORDER = new java.math.BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);

    public static final class TrustAnchors {
        private final Map<String, PublicKey> keys = new LinkedHashMap<>();
        public static String keyId(byte[] x509) {
            try {
                byte[] d = MessageDigest.getInstance("SHA-256").digest(x509);
                StringBuilder s = new StringBuilder();
                for (int i = 0; i < 8; i++) s.append(String.format(Locale.ROOT, "%02x", d[i] & 255));
                return s.toString();
            } catch (NoSuchAlgorithmException e) { throw new AssertionError(e); }
        }
        /** Accepts only X.509-encoded EC P-256 public keys. Returns the key id. */
        public String add(byte[] x509) {
            try {
                PublicKey k = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(x509));
                if (!(k instanceof ECPublicKey ec) || !ec.getParams().getOrder().equals(P256_ORDER))
                    throw new IllegalArgumentException("Only EC P-256 keys are supported");
                String id = keyId(x509);
                keys.put(id, k);
                return id;
            } catch (GeneralSecurityException e) { throw new IllegalArgumentException("Invalid public key", e); }
        }
        public boolean isEmpty() { return keys.isEmpty(); }
        PublicKey get(String id) { return keys.get(id); }
    }

    /** minSequenceExclusive: bundle sequence must be strictly greater. checkExpiry false when reloading from disk. */
    public record Policy(long minSequenceExclusive, boolean checkExpiry, Instant now) {}

    private static final Pattern ENTRY = Pattern.compile("([HDC]) ([a-z0-9.-]{1,253}) (MALWARE|PHISHING|SCAM|UNWANTED) (SUSPICIOUS|STRONG|CONFIRMED) ([A-Za-z0-9._-]{1,64})");
    private static final Pattern HEX64 = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern LABEL = Pattern.compile("[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?");
    /** Partial list: multi-label public suffixes that must never be listed as a blocked domain. */
    private static final Set<String> PUBLIC_SUFFIXES = Collections.unmodifiableSet(new HashSet<>(Arrays.asList("co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.nz",
        "com.br", "co.jp", "co.in", "com.cn", "co.za", "com.mx", "co.kr", "github.io", "herokuapp.com", "blogspot.com", "web.app", "pages.dev")));

    private ThreatBundleVerifier() {}

    public static ThreatDatabase verify(byte[] bundle, TrustAnchors anchors, Policy policy) throws BundleException {
        if (bundle == null || bundle.length == 0) throw new BundleException(BundleException.Reason.MALFORMED, "Empty bundle");
        if (bundle.length > MAX_BUNDLE_BYTES) throw new BundleException(BundleException.Reason.TOO_LARGE, "Bundle exceeds size limit");
        for (byte b : bundle) {
            if ((b < 0x20 && b != '\n') || b == 0x7f || b < 0)
                throw new BundleException(BundleException.Reason.MALFORMED, "Bundle must be printable ASCII with LF line ends");
        }
        if (bundle[bundle.length - 1] != '\n') throw new BundleException(BundleException.Reason.MALFORMED, "Missing final newline");
        int sigStart = lastLineStart(bundle);
        String sigLine = new String(bundle, sigStart, bundle.length - 1 - sigStart, StandardCharsets.US_ASCII);
        if (!sigLine.startsWith("SIGNATURE ") || sigLine.length() > 10 + MAX_SIGNATURE_BASE64)
            throw new BundleException(BundleException.Reason.MALFORMED, "Missing signature line");
        byte[] sig;
        try {
            sig = Base64.getDecoder().decode(sigLine.substring(10));
            // Reject non-canonical encodings (nonzero padding bits) so every accepted byte is covered by the signature or canonical.
            if (!Base64.getEncoder().encodeToString(sig).equals(sigLine.substring(10))) throw new IllegalArgumentException();
        } catch (IllegalArgumentException e) { throw new BundleException(BundleException.Reason.MALFORMED, "Signature is not canonical base64"); }

        // Authenticate before any large allocation: only the first two short lines are read to find the key.
        int n1 = indexOf(bundle, (byte) '\n', 0, Math.min(sigStart, 40)), n2 = n1 < 0 ? -1 : indexOf(bundle, (byte) '\n', n1 + 1, Math.min(sigStart, n1 + 1 + 40));
        if (n1 < 0 || n2 < 0) throw new BundleException(BundleException.Reason.MALFORMED, "Truncated bundle");
        if (!new String(bundle, 0, n1, StandardCharsets.US_ASCII).equals("AEGIS-THREATDB 1")) throw new BundleException(BundleException.Reason.MALFORMED, "Unsupported format");
        String keyId = field(new String(bundle, n1 + 1, n2 - n1 - 1, StandardCharsets.US_ASCII), "key-id: ", "[0-9a-f]{16}");
        PublicKey key = anchors.get(keyId);
        if (key == null) throw new BundleException(BundleException.Reason.UNTRUSTED_KEY, "Signing key is not trusted");
        boolean ok;
        try {
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initVerify(key);
            s.update(bundle, 0, sigStart);
            ok = s.verify(sig);
        } catch (GeneralSecurityException e) { ok = false; }
        if (!ok) throw new BundleException(BundleException.Reason.BAD_SIGNATURE, "Signature verification failed");

        String[] lines = new String(bundle, 0, sigStart, StandardCharsets.US_ASCII).split("\n", -1); // trailing "" because text ends with newline
        if (lines.length < 8) throw new BundleException(BundleException.Reason.MALFORMED, "Truncated bundle");

        // Authenticated from here on; still validated strictly.
        long sequence;
        Instant issued, expires;
        int declared;
        try {
            sequence = Long.parseLong(field(lines[2], "sequence: ", "[0-9]{1,15}"));
            issued = Instant.parse(field(lines[3], "issued: ", "[0-9TZ:.-]{20,30}"));
            expires = Instant.parse(field(lines[4], "expires: ", "[0-9TZ:.-]{20,30}"));
            declared = Integer.parseInt(field(lines[5], "entries: ", "[0-9]{1,7}"));
        } catch (NumberFormatException | DateTimeParseException e) { throw new BundleException(BundleException.Reason.MALFORMED, "Bad header value"); }
        if (declared > MAX_ENTRIES) throw new BundleException(BundleException.Reason.TOO_LARGE, "Too many entries");
        if (sequence <= policy.minSequenceExclusive())
            throw new BundleException(BundleException.Reason.ROLLBACK, "Bundle sequence " + sequence + " is not newer than " + policy.minSequenceExclusive());
        if (policy.checkExpiry() && issued.isAfter(policy.now().plusSeconds(86_400))) throw new BundleException(BundleException.Reason.FUTURE_DATED, "Bundle is issued in the future");
        if (!expires.isAfter(issued)) throw new BundleException(BundleException.Reason.MALFORMED, "Expiry precedes issue time");
        if (java.time.Duration.between(issued, expires).toDays() >= MAX_VALIDITY_DAYS + 1) throw new BundleException(BundleException.Reason.MALFORMED, "Validity period is longer than " + MAX_VALIDITY_DAYS + " days");
        if (policy.checkExpiry() && sequence - Math.max(policy.minSequenceExclusive(), 0) > MAX_SEQUENCE_JUMP) throw new BundleException(BundleException.Reason.SEQUENCE_JUMP, "Sequence advances by more than " + MAX_SEQUENCE_JUMP);
        if (policy.checkExpiry() && policy.now().isAfter(expires)) throw new BundleException(BundleException.Reason.EXPIRED, "Bundle has expired");
        if (lines.length != 6 + declared + 2 || !lines[6 + declared].equals("END") || !lines[lines.length - 1].isEmpty())
            throw new BundleException(BundleException.Reason.MALFORMED, "Entry count or END marker mismatch");

        Map<String, ThreatDatabase.Entry> hashes = new HashMap<>(), domains = new HashMap<>(), certs = new HashMap<>();
        for (int i = 0; i < declared; i++) {
            Matcher m = ENTRY.matcher(lines[6 + i]);
            if (!m.matches()) throw new BundleException(BundleException.Reason.BAD_ENTRY, "Malformed entry on line " + (7 + i));
            String type = m.group(1), value = m.group(2);
            ThreatDatabase.Entry e = new ThreatDatabase.Entry(ThreatDatabase.Category.valueOf(m.group(3)), ThreatDatabase.Confidence.valueOf(m.group(4)), m.group(5));
            Map<String, ThreatDatabase.Entry> target;
            if (type.equals("D")) {
                if (!validDomain(value)) throw new BundleException(BundleException.Reason.BAD_ENTRY, "Unacceptable domain on line " + (7 + i));
                if (ProtectedDomains.isProtectedEntry(value)) throw new BundleException(BundleException.Reason.BAD_ENTRY, "Protected domain on line " + (7 + i));
                target = domains;
            } else {
                if (!HEX64.matcher(value).matches()) throw new BundleException(BundleException.Reason.BAD_ENTRY, "Bad digest on line " + (7 + i));
                target = type.equals("H") ? hashes : certs;
            }
            if (target.put(value, e) != null) throw new BundleException(BundleException.Reason.BAD_ENTRY, "Duplicate entry on line " + (7 + i));
        }
        return new ThreatDatabase(sequence, issued, expires, keyId, hashes, domains, certs);
    }

    static boolean validDomain(String d) {
        if (d.length() > 253 || PUBLIC_SUFFIXES.contains(d)) return false;
        String[] labels = d.split("\\.", -1);
        if (labels.length < 2) return false;
        for (String l : labels) if (!LABEL.matcher(l).matches()) return false;
        return !labels[labels.length - 1].matches("[0-9]+"); // reject IPv4-looking names
    }

    private static String field(String line, String prefix, String regex) throws BundleException {
        if (!line.startsWith(prefix)) throw new BundleException(BundleException.Reason.MALFORMED, "Expected header " + prefix.trim());
        String v = line.substring(prefix.length());
        if (!v.matches(regex)) throw new BundleException(BundleException.Reason.MALFORMED, "Bad header " + prefix.trim());
        return v;
    }
    /** The key id named in a bundle's second line, or null. Unauthenticated: use only to pick which floor to compare against. */
    public static String keyIdOf(byte[] bundle) {
        if (bundle == null || bundle.length < 20) return null;
        int n1 = indexOf(bundle, (byte) '\n', 0, Math.min(bundle.length, 40)), n2 = n1 < 0 ? -1 : indexOf(bundle, (byte) '\n', n1 + 1, Math.min(bundle.length, n1 + 1 + 40));
        if (n1 < 0 || n2 < 0) return null;
        String line = new String(bundle, n1 + 1, n2 - n1 - 1, StandardCharsets.US_ASCII);
        return line.matches("key-id: [0-9a-f]{16}") ? line.substring(8) : null;
    }

    private static int indexOf(byte[] b, byte v, int from, int to) {
        for (int i = from; i < to && i < b.length; i++) if (b[i] == v) return i;
        return -1;
    }
    private static int lastLineStart(byte[] b) {
        int i = b.length - 2;
        while (i >= 0 && b[i] != '\n') i--;
        return i + 1;
    }
}
