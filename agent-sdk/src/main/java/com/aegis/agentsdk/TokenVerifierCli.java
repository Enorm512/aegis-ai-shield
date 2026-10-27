package com.aegis.agentsdk;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

/**
 * Command-line check of one Aegis approval token, for scripts and for trying the format out:
 *
 *   java -cp agent-sdk.jar com.aegis.agentsdk.TokenVerifierCli &lt;aegis-key.pem&gt;[,more.pem] &lt;audience-host&gt; &lt;token&gt; &lt;body-file&gt; [expected-destination]
 *
 * Prints "OK agent=... type=... grant=..." and exits 0, or prints the refusal reason and exits 1. A one-off run has no
 * memory of earlier tokens, so it cannot detect replays; a server must keep {@link ApprovalToken.ReplayCache} state.
 */
public final class TokenVerifierCli {
    private TokenVerifierCli() {}

    public static void main(String[] args) throws Exception {
        String out = run(args, System.currentTimeMillis() / 1000);
        System.out.println(out);
        System.exit(out.startsWith("OK ") ? 0 : 1);
    }

    static String run(String[] args, long now) {
        if (args.length < 4 || args.length > 5) return "USAGE: TokenVerifierCli <key.pem>[,key2.pem] <audience-host> <token> <body-file> [expected-destination]";
        List<PublicKey> keys = new ArrayList<>();
        try {
            for (String f : args[0].split(",")) keys.add(ApprovalToken.fromPem(new String(Files.readAllBytes(Paths.get(f)), StandardCharsets.US_ASCII)));
        } catch (Exception e) { return "BAD_KEY_FILE"; }
        byte[] body;
        try { body = Files.readAllBytes(Paths.get(args[3])); } catch (Exception e) { return "BAD_BODY_FILE"; }
        ApprovalToken.Verifier v = new ApprovalToken.Verifier(keys, null, ApprovalToken.DEFAULT_SKEW_SECONDS);
        ApprovalToken.Result r = v.verify(args[2].trim(), new ApprovalToken.Expect(args[1], body, args.length == 5 ? args[4] : null, null, null), now);
        if (!r.ok()) return r.reason();
        ApprovalToken.Claims c = r.claims();
        return "OK agent=" + c.agent() + " type=" + c.type() + " grant=" + c.grant() + " dest=" + c.dest() + " expires_in=" + Math.max(0, c.exp() - now) + "s";
    }
}
