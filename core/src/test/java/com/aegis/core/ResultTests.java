package com.aegis.core;

import com.aegis.core.InputKind.Kind;
import com.aegis.core.ResultSummary.Level;
import com.aegis.core.ResultSummary.Subject;
import java.util.*;

public final class ResultTests {
    private static int checks;
    private static void check(boolean ok, String message) { checks++; if (!ok) throw new AssertionError(message); }

    public static void main(String[] args) {
        // --- Input kind detection
        for (String link : new String[] {"https://example.com", "http://a.b/c?d=e#f", "example.com", "www.example.com/login", "bankid.no", "sub.domain.co.uk/path", "192.168.1.1", "192.168.1.1:8080/x",
            "example.com:8443", "xn--bcher-kva.de", "bücher.de", "  https://example.com  ", "ftp://files.example.com/x", "javascript://x"})
            check(InputKind.detect(link) == Kind.LINK, "link: " + link);
        for (String msg : new String[] {"", "   ", "hello", "Your account is suspended, click https://x.example", "Hei! Se example.com i morgen", "two words", "no.dots.but spaces", "a@b.com", "hello.", "3.14", "v1.2", null})
            check(InputKind.detect(msg) == Kind.MESSAGE, "message: " + msg);
        check(InputKind.detect("a".repeat(UrlAnalyzer.MAX_URL_LENGTH + 5) + ".com") == Kind.MESSAGE, "overlong single token is not treated as a link");
        Random r = new Random(4);
        for (int i = 0; i < 20000; i++) { StringBuilder s = new StringBuilder(); for (int j = r.nextInt(40); j > 0; j--) s.append((char) r.nextInt(65536)); InputKind.detect(s.toString()); }
        check(true, "fuzz");

        // --- Level mapping mirrors the verdict scale
        check(ResultSummary.levelOf(Analysis.Verdict.NO_KNOWN_WARNING_SIGNS) == Level.CLEAR && ResultSummary.levelOf(Analysis.Verdict.INSUFFICIENT_EVIDENCE) == Level.UNCLEAR
            && ResultSummary.levelOf(Analysis.Verdict.SUSPICIOUS) == Level.SUSPICIOUS && ResultSummary.levelOf(Analysis.Verdict.STRONG_INDICATORS) == Level.STRONG
            && ResultSummary.levelOf(Analysis.Verdict.CONFIRMED_MALICIOUS) == Level.CONFIRMED, "level mapping");

        // --- Real analyzers through the summary
        ResultSummary phish = ResultSummary.of(UrlAnalyzer.analyze("https://trusted.example@bankid-login.example/login"), Subject.LINK);
        check(phish.level == Level.STRONG && !phish.reasons.isEmpty() && phish.reasons.size() <= 3, "phish link strong with reasons");
        check(phish.details.stream().anyMatch(f -> f.code.equals("HOST")), "host is detail, not a key reason");
        check(phish.reasons.stream().noneMatch(f -> f.code.equals("HOST") || f.code.equals("SCHEME_ASSUMED")), "informational findings never headline");
        check(phish.advice.contains("DO_NOT_OPEN") && phish.advice.contains("ALREADY_ACTED") && phish.advice.contains("REPORT_IT") && phish.advice.indexOf("DO_NOT_OPEN") == 0, "link advice order");
        ResultSummary scam = ResultSummary.of(ScamAnalyzer.analyze("Urgent! Send your BankID password immediately or your account will be closed. Pay with gift cards."), Subject.MESSAGE);
        check(scam.level.compareTo(Level.SUSPICIOUS) >= 0, "scam message flagged");
        check(scam.reasons.get(0).code.equals("SECRET_REQUEST"), "secret request ranks first: " + scam.reasons.get(0).code);
        check(scam.advice.contains("NEVER_SHARE_CODES") && scam.advice.contains("PAYMENT_HARD_TO_RECOVER") && !scam.advice.contains("DO_NOT_OPEN"), "message advice");
        check(scam.limitations.stream().anyMatch(f -> f.code.equals("HEURISTIC_LIMITS")) && scam.reasons.stream().noneMatch(f -> f.code.equals("HEURISTIC_LIMITS")), "limitation separated");
        ResultSummary clear = ResultSummary.of(UrlAnalyzer.analyze("https://www.paypal.com/signin"), Subject.LINK);
        check(clear.level == Level.CLEAR && clear.reasons.isEmpty() && clear.advice.contains("STAY_CAUTIOUS") && !clear.advice.contains("DO_NOT_OPEN"), "clear link: no alarm, still cautious");
        ResultSummary bad = ResultSummary.of(UrlAnalyzer.analyze("https://exa mple.com"), Subject.LINK);
        check(bad.level == Level.UNCLEAR && bad.advice.contains("CHECK_INPUT"), "invalid link is unclear and asks to check the input");

        // --- Combining APK evidence
        Analysis hashNone = new Analysis(Analysis.Verdict.INSUFFICIENT_EVIDENCE, Arrays.asList(new Finding("THREATDB_UNAVAILABLE", "x")), "file");
        Analysis manifestClear = new Analysis(Analysis.Verdict.NO_KNOWN_WARNING_SIGNS, Arrays.asList(new Finding("APK_PACKAGE", "p"), new Finding("APK_MANIFEST_LIMITS", "l")), "pkg");
        Analysis manifestBad = new Analysis(Analysis.Verdict.SUSPICIOUS, Arrays.asList(new Finding("APK_BANKER_PATTERN", "b"), new Finding("APK_CAPABILITIES", "c"), new Finding("APK_PACKAGE", "p")), "pkg");
        check(ResultSummary.combine(hashNone, manifestClear).verdict == Analysis.Verdict.NO_KNOWN_WARNING_SIGNS, "unanswered database does not hide a read manifest");
        Analysis both = ResultSummary.combine(hashNone, manifestBad);
        check(both.verdict == Analysis.Verdict.SUSPICIOUS && both.findings.size() == 4, "strongest verdict wins, findings merged: " + both.findings.size());
        ResultSummary apk = ResultSummary.of(both, Subject.APK);
        check(apk.advice.get(0).equals("DO_NOT_INSTALL") && apk.advice.contains("ALREADY_INSTALLED") && apk.reasons.get(0).code.equals("APK_BANKER_PATTERN"), "apk advice and ranking");
        check(ResultSummary.of(new Analysis(Analysis.Verdict.CONFIRMED_MALICIOUS, Arrays.asList(new Finding("THREATDB_LISTED", "listed")), "f"), Subject.APK).level == Level.CONFIRMED, "confirmed level");
        check(ResultSummary.combine(manifestClear, hashNone).verdict == Analysis.Verdict.NO_KNOWN_WARNING_SIGNS, "order of combination does not matter for clear + unavailable");

        // --- Never more than three headline reasons, never advice-free
        List<Finding> many = new ArrayList<>(); for (String c : new String[] {"URGENCY", "THREAT_LANGUAGE", "SECRET_REQUEST", "UNUSUAL_PAYMENT", "PRIZE_PAYMENT", "SUSPICIOUS_LINK"}) many.add(new Finding(c, c));
        ResultSummary big = ResultSummary.of(new Analysis(Analysis.Verdict.STRONG_INDICATORS, many, "m"), Subject.MESSAGE);
        check(big.reasons.size() == 3 && big.details.size() == 3, "three headline reasons, rest as details");
        check(big.reasons.get(0).code.equals("SECRET_REQUEST") && big.reasons.get(1).code.equals("UNUSUAL_PAYMENT"), "ranking order");
        for (Level lv : Level.values()) for (Subject sj : Subject.values()) {
            Analysis.Verdict v = lv == Level.CLEAR ? Analysis.Verdict.NO_KNOWN_WARNING_SIGNS : lv == Level.UNCLEAR ? Analysis.Verdict.INSUFFICIENT_EVIDENCE : lv == Level.SUSPICIOUS ? Analysis.Verdict.SUSPICIOUS : lv == Level.STRONG ? Analysis.Verdict.STRONG_INDICATORS : Analysis.Verdict.CONFIRMED_MALICIOUS;
            check(!ResultSummary.of(new Analysis(v, Collections.emptyList(), "x"), sj).advice.isEmpty(), "advice for " + lv + "/" + sj);
        }
        System.out.println("ResultTests: " + checks + " checks passed");
    }
}
