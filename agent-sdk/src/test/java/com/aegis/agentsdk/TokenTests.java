package com.aegis.agentsdk;

import com.aegis.agentsdk.ApprovalToken.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.*;

/** Host tests for Aegis approval tokens: issuing, the reference verifier, replay protection, PEM keys and the CLI. */
public final class TokenTests {
    private static int checks;
    private static void check(boolean ok, String message) { checks++; if (!ok) throw new AssertionError(message); }

    private static KeyPair ec() throws Exception { KeyPairGenerator g = KeyPairGenerator.getInstance("EC"); g.initialize(new ECGenParameterSpec("secp256r1")); return g.generateKeyPair(); }
    private static ApprovalToken.Signer signer(PrivateKey k) { return data -> { Signature s = Signature.getInstance("SHA256withECDSA"); s.initSign(k); s.update(data); return s.sign(); }; }
    private static final long NOW = 1_793_100_000L;
    private static final String BODY = "{\"note\":\"milk, bread\"}";

    private static Claims claims(KeyPair kp, String jti, long iat, long exp) {
        return new Claims(ApprovalToken.keyId(kp.getPublic()), jti, iat, exp, "com.aegis.sampleagent", "api.example.org", "SEND_DATA",
            "https://api.example.org/notes?x=1", ApprovalToken.bodyHash(BODY), -1, "", ApprovalToken.GRANT_USER_APPROVED);
    }
    private static String jti(int i) { return String.format(Locale.ROOT, "%032x", i + 1); }
    private static Expect expect() { return new Expect("api.example.org", BODY.getBytes(StandardCharsets.UTF_8), null, null, null); }

    public static void main(String[] args) throws Exception {
        KeyPair kp = ec(), other = ec();
        Verifier v = new Verifier(List.of(kp.getPublic()), new MemoryReplayCache(1000), ApprovalToken.DEFAULT_SKEW_SECONDS);

        // --- Round trip
        String t = ApprovalToken.issue(claims(kp, jti(0), NOW, NOW + 120), signer(kp.getPrivate()));
        check(t.startsWith("AT1.") && t.split("\\.").length == 3 && t.length() < 1200, "token shape: " + t.length());
        Result ok = v.verify(t, expect(), NOW + 5);
        check(ok.ok() && ok.claims().agent().equals("com.aegis.sampleagent") && ok.claims().grant().equals("USER_APPROVED"), "valid token accepted: " + ok.reason());
        check(v.verify(t, expect(), NOW + 6).reason().equals("REPLAYED"), "second use refused");

        // --- Each binding
        int n = 1;
        String fresh = ApprovalToken.issue(claims(kp, jti(n++), NOW, NOW + 120), signer(kp.getPrivate()));
        check(v.verify(fresh, new Expect("evil.example.net", BODY.getBytes(StandardCharsets.UTF_8), null, null, null), NOW).reason().equals("WRONG_AUDIENCE"), "other server refuses");
        check(v.verify(fresh, new Expect("API.EXAMPLE.ORG", BODY.getBytes(StandardCharsets.UTF_8), null, null, null), NOW).ok(), "audience compared case-insensitively on the server side");
        String f2 = ApprovalToken.issue(claims(kp, jti(n++), NOW, NOW + 120), signer(kp.getPrivate()));
        check(v.verify(f2, new Expect("api.example.org", (BODY + " ").getBytes(StandardCharsets.UTF_8), null, null, null), NOW).reason().equals("BODY_MISMATCH"), "changed body refused");
        check(v.verify(f2, new Expect("api.example.org", BODY.getBytes(StandardCharsets.UTF_8), "https://api.example.org/other", null, null), NOW).reason().equals("DESTINATION_MISMATCH"), "changed destination refused when checked");
        check(v.verify(f2, new Expect("api.example.org", BODY.getBytes(StandardCharsets.UTF_8), null, Set.of("com.other"), null), NOW).reason().equals("AGENT_NOT_ALLOWED"), "agent allowlist");
        check(v.verify(f2, new Expect("api.example.org", BODY.getBytes(StandardCharsets.UTF_8), null, null, Set.of("FINANCIAL_TRANSACTION")), NOW).reason().equals("TYPE_NOT_ALLOWED"), "type allowlist");
        check(v.verify(f2, new Expect("api.example.org", BODY.getBytes(StandardCharsets.UTF_8), "https://api.example.org/notes?x=1", Set.of("com.aegis.sampleagent"), Set.of("SEND_DATA")), NOW).ok(), "refusals did not use up the token; all checks pass");

        // --- Time
        String old = ApprovalToken.issue(claims(kp, jti(n++), NOW, NOW + 120), signer(kp.getPrivate()));
        check(v.verify(old, expect(), NOW + 120 + ApprovalToken.DEFAULT_SKEW_SECONDS + 1).reason().equals("EXPIRED"), "expired");
        check(v.verify(old, expect(), NOW + 120 + ApprovalToken.DEFAULT_SKEW_SECONDS).ok(), "within clock skew");
        String future = ApprovalToken.issue(claims(kp, jti(n++), NOW + 100, NOW + 200), signer(kp.getPrivate()));
        check(v.verify(future, expect(), NOW).reason().equals("NOT_YET_VALID"), "issued in the future");
        String longLived = ApprovalToken.issue(claims(kp, jti(n++), NOW, NOW + 3600), signer(kp.getPrivate()));
        check(v.verify(longLived, expect(), NOW).reason().equals("LIFETIME_TOO_LONG"), "lifetime cap enforced by the server");

        // --- Keys and signatures
        String foreign = ApprovalToken.issue(claims(other, jti(n++), NOW, NOW + 60), signer(other.getPrivate()));
        check(v.verify(foreign, expect(), NOW).reason().equals("UNKNOWN_KEY"), "token from a phone the server never enrolled");
        String forged = ApprovalToken.issue(claims(kp, jti(n++), NOW, NOW + 60), signer(other.getPrivate()));
        check(v.verify(forged, expect(), NOW).reason().equals("BAD_SIGNATURE"), "claims an enrolled key id but signed by another key");
        String[] parts = ApprovalToken.issue(claims(kp, jti(n++), NOW, NOW + 60), signer(kp.getPrivate())).split("\\.");
        byte[] p = Base64.getUrlDecoder().decode(parts[1]);
        String edited = new String(p, StandardCharsets.UTF_8).replace("grant=USER_APPROVED", "grant=POLICY_ALLOW");
        String swapped = "AT1." + Base64.getUrlEncoder().withoutPadding().encodeToString(edited.getBytes(StandardCharsets.UTF_8)) + "." + parts[2];
        check(v.verify(swapped, expect(), NOW).reason().equals("BAD_SIGNATURE"), "edited payload breaks the signature");
        Verifier two = new Verifier(List.of(other.getPublic(), kp.getPublic()), new MemoryReplayCache(10), 30);
        check(two.verify(foreign, expect(), NOW).ok(), "several enrolled phones");

        // --- Malformed input never throws and never verifies
        Random rnd = new Random(7);
        String base = ApprovalToken.issue(claims(kp, jti(n++), NOW, NOW + 60), signer(kp.getPrivate()));
        List<String> junk = new ArrayList<>(List.of("", "AT1.", "AT1..", "AT2." + base.substring(4), base + ".x", base.substring(0, base.length() - 3), "AT1.!!!.###", "x".repeat(ApprovalToken.MAX_TOKEN_CHARS + 1)));
        for (int i = 0; i < 2000; i++) {
            char[] c = base.toCharArray();
            for (int j = 0; j < 1 + rnd.nextInt(4); j++) c[4 + rnd.nextInt(c.length - 4)] = "ABCxyz019-_.=+/".charAt(rnd.nextInt(15));
            junk.add(new String(c));
        }
        int accepted = 0;
        Verifier fuzz = new Verifier(List.of(kp.getPublic()), null, 30);
        for (String j : junk) { Result r = fuzz.verify(j, expect(), NOW); if (r.ok() && !j.equals(base)) accepted++; }
        check(accepted == 0, "no mutated token verifies (" + accepted + ")");
        check(fuzz.verify(null, expect(), NOW).reason().equals("MALFORMED") && fuzz.verify(base, null, NOW).reason().equals("MALFORMED"), "nulls");

        // --- Payload is canonical: alternative spellings of the same claims are rejected even if signed
        String canonical = new String(ApprovalToken.payload(claims(kp, jti(90), NOW, NOW + 60)), StandardCharsets.UTF_8);
        for (String alt : new String[] {canonical.replace("iat=" + NOW, "iat=0" + NOW), canonical.replace("amount=-1", "amount=-01"), canonical.replace("\n", "\r\n"), canonical + "extra=1\n", canonical.replace("aud=api.example.org", "aud=API.example.org")}) {
            byte[] ab = alt.getBytes(StandardCharsets.UTF_8);
            String at = "AT1." + Base64.getUrlEncoder().withoutPadding().encodeToString(ab) + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(signer(kp.getPrivate()).sign(ab));
            check(fuzz.verify(at, expect(), NOW).reason().equals("MALFORMED"), "non-canonical payload refused");
        }

        // --- Issuing refuses fields that could break the format or mislead
        Claims good = claims(kp, jti(91), NOW, NOW + 60);
        Map<String, Claims> bad = new LinkedHashMap<>();
        bad.put("dest", new Claims(good.kid(), good.jti(), good.iat(), good.exp(), good.agent(), good.aud(), good.type(), "https://a.example/\nbody=0", good.body(), -1, "", good.grant()));
        bad.put("agent", new Claims(good.kid(), good.jti(), good.iat(), good.exp(), "evil agent", good.aud(), good.type(), good.dest(), good.body(), -1, "", good.grant()));
        bad.put("aud", new Claims(good.kid(), good.jti(), good.iat(), good.exp(), good.agent(), "[::1]", good.type(), good.dest(), good.body(), -1, "", good.grant()));
        bad.put("type", new Claims(good.kid(), good.jti(), good.iat(), good.exp(), good.agent(), good.aud(), "WIPE_PHONE", good.dest(), good.body(), -1, "", good.grant()));
        bad.put("grant", new Claims(good.kid(), good.jti(), good.iat(), good.exp(), good.agent(), good.aud(), good.type(), good.dest(), good.body(), -1, "", "ADMIN"));
        bad.put("exp", new Claims(good.kid(), good.jti(), good.iat(), good.iat(), good.agent(), good.aud(), good.type(), good.dest(), good.body(), -1, "", good.grant()));
        bad.put("currency", new Claims(good.kid(), good.jti(), good.iat(), good.exp(), good.agent(), good.aud(), good.type(), good.dest(), good.body(), -1, "nok\n", good.grant()));
        bad.put("body", new Claims(good.kid(), good.jti(), good.iat(), good.exp(), good.agent(), good.aud(), good.type(), good.dest(), "abc", -1, "", good.grant()));
        for (Map.Entry<String, Claims> e : bad.entrySet()) {
            check(e.getKey().equals(e.getValue().invalidField()), "invalid field reported: " + e.getKey() + " got " + e.getValue().invalidField());
            try { ApprovalToken.payload(e.getValue()); check(false, "accepted " + e.getKey()); } catch (IllegalArgumentException ex) { check(true, "refused " + e.getKey()); }
        }

        // --- Replay cache: expiry clean-up and refusal when full
        MemoryReplayCache rc = new MemoryReplayCache(3);
        check(rc.firstUse(jti(1), NOW + 10, NOW) && rc.firstUse(jti(2), NOW + 10, NOW) && rc.firstUse(jti(3), NOW + 10, NOW), "fills");
        check(!rc.firstUse(jti(4), NOW + 10, NOW), "full cache refuses instead of forgetting");
        check(rc.firstUse(jti(4), NOW + 100, NOW + 10 + ApprovalToken.DEFAULT_SKEW_SECONDS + 1) && rc.size() == 1, "expired ids are dropped");

        // --- Keys in PEM
        String pem = ApprovalToken.toPem(kp.getPublic());
        check(pem.startsWith("-----BEGIN PUBLIC KEY-----\n") && ApprovalToken.fromPem(pem).equals(kp.getPublic()) && ApprovalToken.keyId(ApprovalToken.fromPem(pem)).equals(ApprovalToken.keyId(kp.getPublic())), "PEM round trip");
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA"); rsa.initialize(2048);
        try { ApprovalToken.fromPem(ApprovalToken.toPem(rsa.generateKeyPair().getPublic())); check(false, "RSA key accepted"); } catch (Exception e) { check(true, "only EC keys"); }

        // --- CLI
        Path dir = Files.createTempDirectory("aegis-token-test");
        Path keyFile = dir.resolve("phone.pem"), bodyFile = dir.resolve("body.json");
        Files.write(keyFile, pem.getBytes(StandardCharsets.US_ASCII));
        Files.write(bodyFile, BODY.getBytes(StandardCharsets.UTF_8));
        String cliTok = ApprovalToken.issue(claims(kp, jti(99), NOW, NOW + 60), signer(kp.getPrivate()));
        check(TokenVerifierCli.run(new String[] {keyFile.toString(), "api.example.org", cliTok, bodyFile.toString()}, NOW).startsWith("OK agent=com.aegis.sampleagent"), "CLI accepts");
        check(TokenVerifierCli.run(new String[] {keyFile.toString(), "api.example.org", cliTok, bodyFile.toString(), "https://api.example.org/x"}, NOW).equals("DESTINATION_MISMATCH"), "CLI destination check");
        check(TokenVerifierCli.run(new String[] {dir.resolve("missing.pem").toString(), "a.example", cliTok, bodyFile.toString()}, NOW).equals("BAD_KEY_FILE"), "CLI bad key file");
        check(TokenVerifierCli.run(new String[] {"x"}, NOW).startsWith("USAGE"), "CLI usage");
        Files.delete(keyFile); Files.delete(bodyFile); Files.delete(dir);

        System.out.println("TokenTests: " + checks + " checks passed");
    }
}
