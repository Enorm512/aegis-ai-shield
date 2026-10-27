package com.aegis.core;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

/**
 * Publisher-side tool (never used by the app at runtime). Keep private keys offline.
 *   keygen <prefix>                                  writes <prefix>.private (PKCS8 base64) and <prefix>.public (X.509 base64)
 *   sign <prefix> <sequence> <validDays> <entries.txt> <out.bundle>
 * entries.txt holds lines like: D evil.example PHISHING CONFIRMED campaign-123
 */
public final class ThreatBundleTool {
    private ThreatBundleTool() {}

    public static KeyPair generateKey() throws GeneralSecurityException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        return g.generateKeyPair();
    }

    public static byte[] build(PrivateKey key, String keyId, long sequence, Instant issued, Instant expires, List<String> entries)
            throws GeneralSecurityException {
        StringBuilder s = new StringBuilder();
        s.append("AEGIS-THREATDB 1\nkey-id: ").append(keyId).append("\nsequence: ").append(sequence)
         .append("\nissued: ").append(issued.truncatedTo(ChronoUnit.SECONDS))
         .append("\nexpires: ").append(expires.truncatedTo(ChronoUnit.SECONDS))
         .append("\nentries: ").append(entries.size()).append('\n');
        for (String e : entries) s.append(e).append('\n');
        s.append("END\n");
        byte[] body = s.toString().getBytes(StandardCharsets.US_ASCII);
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(key);
        sig.update(body);
        byte[] tail = ("SIGNATURE " + Base64.getEncoder().encodeToString(sig.sign()) + "\n").getBytes(StandardCharsets.US_ASCII);
        byte[] out = Arrays.copyOf(body, body.length + tail.length);
        System.arraycopy(tail, 0, out, body.length, tail.length);
        return out;
    }

    public static void main(String[] a) throws Exception {
        if (a.length == 2 && a[0].equals("keygen")) {
            KeyPair kp = generateKey();
            Files.write(Paths.get(a[1] + ".private"), Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded()).getBytes(StandardCharsets.US_ASCII));
            Files.write(Paths.get(a[1] + ".public"), Base64.getEncoder().encodeToString(kp.getPublic().getEncoded()).getBytes(StandardCharsets.US_ASCII));
            System.out.println("key-id " + ThreatBundleVerifier.TrustAnchors.keyId(kp.getPublic().getEncoded()));
        } else if (a.length == 6 && a[0].equals("sign")) {
            PrivateKey pk = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(new String(Files.readAllBytes(Paths.get(a[1] + ".private")), StandardCharsets.US_ASCII).trim())));
            String id = ThreatBundleVerifier.TrustAnchors.keyId(Base64.getDecoder().decode(new String(Files.readAllBytes(Paths.get(a[1] + ".public")), StandardCharsets.US_ASCII).trim()));
            long days = Long.parseLong(a[3]), seq = Long.parseLong(a[2]);
            if (days < 1 || days > ThreatBundleVerifier.MAX_VALIDITY_DAYS) throw new IllegalArgumentException("validDays must be 1.." + ThreatBundleVerifier.MAX_VALIDITY_DAYS + " (apps refuse longer validity)");
            if (seq < 1 || seq > 1_000_000_000L) throw new IllegalArgumentException("sequence looks like a typo; apps refuse jumps above " + ThreatBundleVerifier.MAX_SEQUENCE_JUMP + " over the last installed value");
            Instant now = Instant.now();
            List<String> entries = new ArrayList<>();
            for (String l : Files.readAllLines(Paths.get(a[4]), StandardCharsets.US_ASCII)) if (!l.trim().isEmpty()) entries.add(l.trim());
            byte[] b = build(pk, id, Long.parseLong(a[2]), now, now.plus(Long.parseLong(a[3]), ChronoUnit.DAYS), entries);
            Files.write(Paths.get(a[5]), b);
            System.out.println("wrote " + b.length + " bytes, key-id " + id);
        } else {
            System.err.println("usage: keygen <prefix> | sign <prefix> <sequence> <validDays> <entries.txt> <out.bundle>");
            System.exit(2);
        }
    }
}
