package com.aegis.core;

import java.io.*;
import java.nio.charset.StandardCharsets;

/** Local host demonstration. Read sensitive text through stdin, not shell arguments. */
public final class AnalysisCli {
    public static void main(String[] args) throws Exception {
        if (args.length != 1 || !(args[0].equals("url") || args[0].equals("message"))) {
            System.err.println("Usage: core/demo.sh url|message < input.txt");
            System.exit(2);
        }
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int n;
        while ((n = System.in.read(buffer)) != -1) {
            if (bytes.size() + n > 400000) throw new IOException("Input exceeds CLI byte limit");
            bytes.write(buffer, 0, n);
        }
        String input = new String(bytes.toByteArray(), StandardCharsets.UTF_8);
        // CLI input convention permits one terminal newline, not embedded URL controls.
        if (input.endsWith("\n")) input = input.substring(0, input.length()-1);
        Analysis result = args[0].equals("url") ? UrlAnalyzer.analyze(input) : ScamAnalyzer.analyze(input);
        System.out.println(result.verdict);
        for (Finding finding : result.findings) System.out.println(finding.code + ": " + finding.detail);
        System.out.println("Offline advisory analysis; not a guarantee of safety.");
    }
}
