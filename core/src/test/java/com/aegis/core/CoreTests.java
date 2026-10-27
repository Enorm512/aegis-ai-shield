package com.aegis.core;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static com.aegis.core.Analysis.Verdict.*;

public final class CoreTests {
    private static int checks;
    private static void check(boolean ok, String message) { checks++; if (!ok) throw new AssertionError(message); }
    private static void url(String input, Analysis.Verdict wanted) {
        Analysis result = UrlAnalyzer.analyze(input);
        check(result.verdict == wanted, input + " expected " + wanted + " got " + result.verdict);
    }
    public static void main(String[] args) throws Exception {
        for (String benign : Arrays.asList("https://bankid.no/login", "https://login.bankid.no", "https://www.bankid.se", "https://microsoft.com/login", "http://example.com", "https://bücher.de", "https://xn--bcher-kva.de", "https://example.com/paypal/login", "example.com", "https://127.0.0.1", "https://[::1]", "https://[2001:db8::1]:443/a", "https://[::ffff:192.0.2.1]", "https://example.com./")) url(benign, NO_KNOWN_WARNING_SIGNS);
        for (String invalid : Arrays.asList("", "https://", "javascript:alert(1)", "ftp://example.com", "https://example.com:65536", "https://example.com:", "https://a..com", "https://.com", "https://a_b.com", "https://256.0.0.1", "https://0127.0.0.1", "https://2130706433", "https://0x7f000001", "https://[:::]", "https://[1:2:3]", "https://[1:2:3:4:5:6:7:8:9]", "https://[::1]garbage", "https://[fe80::1%25eth0]", "https://a%2ecom", "https://a\\@b.com", "https://a@b@c.com", "https://exa mple.com", "https://a\n.com", "https://\ud800.com", "https://a\u202e.com", "https://a.com/%XX")) url(invalid, INSUFFICIENT_EVIDENCE);
        url(null, INSUFFICIENT_EVIDENCE);
        url("\rhttps://example.com", INSUFFICIENT_EVIDENCE);
        url("https://example.com\n", INSUFFICIENT_EVIDENCE);
        url("  https://example.com  ", NO_KNOWN_WARNING_SIGNS);
        url("https://p\u0430ypal.example", STRONG_INDICATORS); // Stage 5: mixed-script label plus brand look-alike skeleton is now strong evidence
        url("https://bit.ly/example", INSUFFICIENT_EVIDENCE);
        url("https://tinyurl.com/example", INSUFFICIENT_EVIDENCE);
        url("https://bit.ly.attacker.example", NO_KNOWN_WARNING_SIGNS);
        check(UrlAnalyzer.analyze("https://t.co/example").findings.stream().anyMatch(f -> f.code.equals("UNRESOLVED_SHORT_LINK")), "short-link explanation");
        check(ScamAnalyzer.analyze("Visit https://example.com:%ZZ").verdict == INSUFFICIENT_EVIDENCE, "malformed embedded URL cannot clear message");
        check(ScamAnalyzer.analyze("Visit https://bit.ly/example").verdict == INSUFFICIENT_EVIDENCE, "short embedded URL cannot clear message");
        check(ScamAnalyzer.analyze("https://example.com ".repeat(13)).verdict == INSUFFICIENT_EVIDENCE, "capped coverage cannot clear message");
        check(ScamAnalyzer.analyze("Send your password immediately https://example.com:%ZZ").verdict == STRONG_INDICATORS, "strong evidence retained with malformed link");
        url("https://bankid.no.attacker.example", SUSPICIOUS);
        url("https://bankid-security.example", SUSPICIOUS);
        url("https://bankid.no@attacker.example", SUSPICIOUS);
        url("https://trusted.example@bankid-login.example", STRONG_INDICATORS);
        url("https://notbankid.no", NO_KNOWN_WARNING_SIGNS);
        url("https://a.com/" + "x".repeat(8200), INSUFFICIENT_EVIDENCE);
        check(ScamAnalyzer.analyze("Log in to BankID at https://bankid.no when you have time.").verdict == NO_KNOWN_WARNING_SIGNS, "benign BankID login");
        check(ScamAnalyzer.analyze("Logg inn med BankID på https://bankid.no.").verdict == NO_KNOWN_WARNING_SIGNS, "benign Norwegian");
        check(ScamAnalyzer.analyze("Urgent: the meeting starts now.").verdict == NO_KNOWN_WARNING_SIGNS, "urgency alone");
        check(ScamAnalyzer.analyze("Send your password immediately to restore your account").verdict == STRONG_INDICATORS, "secret pressure");
        check(ScamAnalyzer.analyze("Haster! Oppgi BankID engangskode straks").verdict == STRONG_INDICATORS, "Norwegian secret pressure");
        check(ScamAnalyzer.analyze("Pay using gift cards immediately").verdict == STRONG_INDICATORS, "gift cards");
        check(ScamAnalyzer.analyze("You won a prize; pay a fee").verdict == SUSPICIOUS, "prize fee");
        check(ScamAnalyzer.analyze("Please review https://bankid.no.attacker.example.").verdict == SUSPICIOUS, "embedded URL");
        check(ScamAnalyzer.analyze("x".repeat(100001)).verdict == INSUFFICIENT_EVIDENCE, "message limit");
        check(ScamAnalyzer.analyze("https://example.com ".repeat(13)).findings.stream().anyMatch(f -> f.code.equals("LINK_SCAN_LIMIT")), "link limit visible");
        String hash = HashScanner.sha256(new ByteArrayInputStream("abc".getBytes(StandardCharsets.UTF_8)), 3);
        check(hash.equals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), "SHA-256 known vector");
        check(HashScanner.sha256(new ByteArrayInputStream(new byte[0]), 0).equals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), "empty SHA-256");
        try { HashScanner.sha256(new ByteArrayInputStream(new byte[4]), 3); throw new AssertionError("limit accepted"); } catch (IOException expected) { checks++; }
        check(HashScanner.match(hash, null).verdict == INSUFFICIENT_EVIDENCE, "hash alone insufficient");
        check(HashScanner.match(hash, h -> Optional.empty()).verdict == NO_KNOWN_WARNING_SIGNS, "hash miss");
        check(HashScanner.match(hash, h -> Optional.of("test fixture")).verdict == CONFIRMED_MALICIOUS, "exact hash intelligence match");
        Random random = new Random(381091L);
        for (int i=0; i<5000; i++) {
            int len=random.nextInt(180); StringBuilder s=new StringBuilder();
            for (int j=0;j<len;j++) s.append((char)random.nextInt(65536));
            Analysis a = UrlAnalyzer.analyze((i%2==0 ? "https://" : "") + s);
            check(a.verdict != CONFIRMED_MALICIOUS && a.findings != null, "fuzz URL never confirms");
            Analysis b = ScamAnalyzer.analyze(s.toString());
            check(b.verdict != CONFIRMED_MALICIOUS && b.findings != null, "fuzz text never confirms");
        }
        System.out.println("PASS: " + checks + " assertions, including 5,000 deterministic fuzz cases for each analyzer.");
    }
}
