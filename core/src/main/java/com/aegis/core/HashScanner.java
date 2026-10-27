package com.aegis.core;

import java.io.*;
import java.security.*;
import java.util.*;

/** Streaming SHA-256; caller owns and closes the stream. No file is uploaded. */
public final class HashScanner {
    private HashScanner() {}
    public static String sha256(InputStream input, long maxBytes) throws IOException {
        Objects.requireNonNull(input, "input");
        if (maxBytes < 0) throw new IllegalArgumentException("maxBytes must be nonnegative");
        MessageDigest digest;
        try { digest = MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
        byte[] buffer = new byte[8192];
        long total = 0;
        while (true) {
            int read = input.read(buffer, 0, (int)Math.min(buffer.length, maxBytes-total));
            if (read < 0) break;
            if (read == 0) {
                int one = input.read();
                if (one < 0) break;
                if (total == maxBytes) throw new IOException("File exceeds the configured byte limit");
                digest.update((byte)one); total++;
            } else { digest.update(buffer, 0, read); total += read; }
        }
        StringBuilder hex = new StringBuilder(64);
        for (byte b : digest.digest()) hex.append(String.format(Locale.ROOT, "%02x", b & 255));
        return hex.toString();
    }

    /** Only trusted, independently maintained hash intelligence can confirm a match. */
    public interface HashIntelligence {
        Optional<String> lookupSha256(String lowercaseHex) throws IOException;
    }
    public static Analysis match(String sha256, HashIntelligence intelligence) throws IOException {
        if (sha256 == null || !sha256.matches("[a-fA-F0-9]{64}"))
            return new Analysis(Analysis.Verdict.INSUFFICIENT_EVIDENCE, Arrays.asList(new Finding("INVALID_HASH", "Expected a 64-character SHA-256 hex digest.")), "File hash");
        if (intelligence == null)
            return new Analysis(Analysis.Verdict.INSUFFICIENT_EVIDENCE, Arrays.asList(new Finding("NO_HASH_INTELLIGENCE", "A SHA-256 fingerprint alone cannot determine whether a file is malicious.")), sha256);
        Optional<String> match = intelligence.lookupSha256(sha256.toLowerCase(Locale.ROOT));
        return new Analysis(match.isPresent() ? Analysis.Verdict.CONFIRMED_MALICIOUS : Analysis.Verdict.NO_KNOWN_WARNING_SIGNS,
            Arrays.asList(new Finding(match.isPresent() ? "KNOWN_MALICIOUS_HASH" : "NO_HASH_MATCH", match.isPresent() ? "Exact match in configured hash intelligence: " + match.get() : "No match in the configured hash source. Unknown malware can still be present.")), sha256);
    }
}
