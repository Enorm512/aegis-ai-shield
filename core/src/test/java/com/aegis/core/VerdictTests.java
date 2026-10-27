package com.aegis.core;

import com.aegis.core.ResultSummary.Level;
import com.aegis.core.ResultSummary.Subject;
import java.util.*;
import static com.aegis.core.Analysis.Verdict.*;

/** Regression tests for the verdict-logic findings of the expert reviews (2026-10-26). */
public final class VerdictTests {
    private static int checks;
    private static void check(boolean ok, String message) { checks++; if (!ok) throw new AssertionError(message); }
    private static Analysis.Verdict url(String u) { return UrlAnalyzer.analyze(u).verdict; }
    private static Analysis.Verdict msg(String m) { return ScamAnalyzer.analyze(m).verdict; }
    private static boolean flagged(Analysis.Verdict v) { return v.compareTo(SUSPICIOUS) >= 0; }

    public static void main(String[] args) {
        // --- Hosts that combine a brand with an ordinary word, or hide a brand in a sub-domain
        for (String bad : new String[] {"https://dnb-login.com", "https://secure.nordea.verify-id.com", "https://skatteetaten-refund.com", "https://apple-id-locked.com", "https://netflix-billing.com",
            "https://login.dnb.no.evil-example.com", "https://dnb.evil.com", "https://sparebank1-id.com", "https://app1e-id.com", "https://paypal-secure.com", "https://posten-no.tracking-info.top",
            "https://bankid-login.example", "https://vipps.no.attacker.example", "https://amazon-support.net", "https://g00gle-account.com"})
            check(flagged(url(bad)), "must be flagged: " + bad + " -> " + url(bad));
        // ... but official hosts and unrelated words stay quiet
        for (String ok : new String[] {"https://login.dnb.no", "https://www.nordea.com", "https://apple.com", "https://support.apple.com", "https://www.skatteetaten.no/person", "https://netflix.com/browse",
            "https://notbankid.no", "https://applepie-recipes.example", "https://dnbx.example", "https://example.com/dnb-login", "https://nrk.no", "https://amazonas-travel.example"})
            check(!flagged(url(ok)), "must not be flagged: " + ok + " -> " + url(ok));
        check(UrlAnalyzer.analyze("https://apple-pie.example").findings.stream().noneMatch(f -> f.code.equals("LOOKALIKE_BRAND")), "plain word pairing is not a look-alike");

        // --- Message rules are applied to normalised text
        String base = "Please share your password now";
        check(msg(base) == SUSPICIOUS || msg(base) == STRONG_INDICATORS, "baseline: " + msg(base));
        for (String variant : new String[] {"Please s​hare your pass​word now", "Please share your pаssword now", "Please share your pАssword now", "PLEASE SHARE YOUR PАSSWORD NOW",
            "Please share your p4ssword now", "Please share your passw0rd now", "Please share your p a s s w o r d now", "Please s h a r e your password now", "Please share your p@ssword now", "Please share-your password now"})
            check(flagged(msg(variant)), "evasion variant must still be flagged: " + variant.replace('​', '|'));

        // --- Pressure plus account threat or verification demand is no longer "clear"
        check(flagged(msg("Your account has been suspended. Verify your identity immediately.")), "textbook phishing without a link");
        check(flagged(msg("Din konto er sperret. Bekreft identiteten din umiddelbart.")), "Norwegian textbook phishing");
        check(flagged(msg("Your account will be suspended immediately. Verify at https://dnb-login.com now")), "pressure + risky link");
        check(msg("Urgent: the meeting starts now.") == NO_KNOWN_WARNING_SIGNS, "urgency alone stays clear");
        check(msg("Your account statement is ready. Please verify the numbers when you have time.") == NO_KNOWN_WARNING_SIGNS, "calm verify wording stays clear");

        // --- Warnings about scams are not scams
        for (String benign : new String[] {"Never share your password or PIN with anyone, including bank staff.", "Bank notice: we will never ask for your PIN or BankID codes by phone or message.",
            "Del aldri engangskode med andre.", "Do not share your verification code with anyone."})
            check(msg(benign) == NO_KNOWN_WARNING_SIGNS, "security advice is not a secret request: " + benign + " -> " + msg(benign));

        // --- Bare links in messages are analysed
        check(flagged(msg("Click dnb-login.com/verify now to keep your account")), "bare lookalike domain");
        check(msg("pay fee at bit.ly/3xyz within 24 hours") != NO_KNOWN_WARNING_SIGNS, "bare short link is not clear");
        check(flagged(msg("Logg inn på sparebank1-id.com")), "Norwegian bare domain");
        check(msg("Send the report.pdf and notes.txt to Anna, e.g. tomorrow.") == NO_KNOWN_WARNING_SIGNS, "file names and abbreviations are not links");
        check(msg("Email me at anna@example.com about lunch") == NO_KNOWN_WARNING_SIGNS, "e-mail addresses are not links");
        check(msg("See https://example.com/menu and www.example.org for details") != STRONG_INDICATORS, "ordinary links stay calm");

        // --- Normaliser details
        check(TextNormalizer.tokens("PАSSWORD").equals(Arrays.asList("password")), "capital Cyrillic A folded");
        check(TextNormalizer.tokens("pay $1000 at 10pm on 4G with COVID19").equals(Arrays.asList("pay", "0", "at", "10pm", "on", "4g", "with", "covid19")), "amounts and codes not garbled: " + TextNormalizer.tokens("pay $1000 at 10pm on 4G with COVID19"));
        check(TextNormalizer.tokens("hidden󠁁text").equals(Arrays.asList("hiddentext")), "Unicode tag characters removed");

        // --- APK: a named pattern is never "clear"
        String[][] combos = {
            {"android.permission.RECEIVE_SMS", "android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW"},
            {"android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.INTERNET", "android.permission.RECEIVE_BOOT_COMPLETED"},
        };
        for (String[] perms : combos) {
            ManifestAnalyzer.Info info = new ManifestAnalyzer.Info("com.example.x", "1", 26, 35, false, false, new TreeSet<>(Arrays.asList(perms)), new ArrayList<>(), true);
            Analysis a = ManifestAnalyzer.analyze(info);
            check(a.verdict == SUSPICIOUS, "named pattern combo is suspicious: " + Arrays.toString(perms) + " -> " + a.verdict);
        }
        ManifestAnalyzer.Info access = new ManifestAnalyzer.Info("com.example.x", "1", 26, 35, false, false,
            new TreeSet<>(Arrays.asList("android.permission.SYSTEM_ALERT_WINDOW", "android.permission.RECEIVE_BOOT_COMPLETED")),
            Arrays.asList(new ManifestAnalyzer.Component("service", ".A", true, "android.permission.BIND_ACCESSIBILITY_SERVICE", new ArrayList<String>())), true);
        Analysis banker = ManifestAnalyzer.analyze(access);
        check(banker.findings.stream().anyMatch(f -> f.code.equals("APK_BANKER_PATTERN")) && banker.verdict == SUSPICIOUS, "accessibility+overlay+boot (score 2.75) is suspicious");
        ManifestAnalyzer.Info store = new ManifestAnalyzer.Info("com.example.store", "1", 26, 35, false, false, new TreeSet<>(Arrays.asList("android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.INTERNET")), new ArrayList<>(), true);
        check(ManifestAnalyzer.analyze(store).verdict == NO_KNOWN_WARNING_SIGNS, "a launcher app that merely can request installs is not flagged");

        // --- The result never says "no known warning signs" above a Why list
        ResultSummary calm = ResultSummary.of(new Analysis(NO_KNOWN_WARNING_SIGNS, Arrays.asList(new Finding("URGENCY", "u"), new Finding("THREAT_LANGUAGE", "t")), "m"), Subject.MESSAGE);
        check(calm.level == Level.CLEAR && calm.reasons.isEmpty() && calm.details.stream().anyMatch(f -> f.code.equals("URGENCY")), "CLEAR has no reasons; noticed items move to details");
        ResultSummary hot = ResultSummary.of(msgAnalysis("Your account has been suspended. Verify your identity immediately."), Subject.MESSAGE);
        check(hot.level.compareTo(Level.SUSPICIOUS) >= 0 && !hot.reasons.isEmpty(), "flagged message explains why");
        System.out.println("VerdictTests: " + checks + " checks passed");
    }
    private static Analysis msgAnalysis(String m) { return ScamAnalyzer.analyze(m); }
}
