package com.aegis.core;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/**
 * Regression tests for the Norwegian phishing words, accent look-alikes, suspicious-TLD weight and the extra scam
 * phrasings added after the 2026-10-27 spot test. ml/data/spot-set.txt was used while tuning, so it guards against
 * regressions; it is not an independent measurement. Run from the core/ directory.
 */
public final class SpotTests {
    private static int checks;
    private static void check(boolean ok, String message) { checks++; if (!ok) throw new AssertionError(message); }

    private static ResultSummary.Level level(String kind, String input) {
        Analysis a = kind.equals("U") ? UrlAnalyzer.analyze(input) : ScamAnalyzer.analyze(input);
        return ResultSummary.of(a, kind.equals("U") ? ResultSummary.Subject.LINK : ResultSummary.Subject.MESSAGE).level;
    }
    private static boolean flagged(ResultSummary.Level l) { return l == ResultSummary.Level.SUSPICIOUS || l == ResultSummary.Level.STRONG || l == ResultSummary.Level.CONFIRMED; }
    private static boolean has(Analysis a, String code) { return a.findings.stream().anyMatch(f -> f.code.equals(code)); }

    public static void main(String[] args) throws Exception {
        int bad = 0, ok = 0;
        for (String line : Files.readAllLines(Path.of("../ml/data/spot-set.txt"), StandardCharsets.UTF_8)) {
            if (line.isBlank() || line.startsWith("#")) continue;
            String[] p = line.split("\\|", 3);
            boolean expectBad = p[1].equals("BAD");
            boolean got = flagged(level(p[0], p[2]));
            check(got == expectBad, (expectBad ? "should be flagged: " : "false positive: ") + p[2]);
            if (expectBad) bad++; else ok++;
        }
        check(bad >= 30 && ok >= 30, "set size " + bad + "/" + ok);

        // Suspicious-TLD is a weak signal: it never flags a link alone, but adds weight with a brand.
        Analysis tld = UrlAnalyzer.analyze("https://my-garden-notes.xyz/blog");
        check(has(tld, "SUSPICIOUS_TLD") && tld.verdict == Analysis.Verdict.NO_KNOWN_WARNING_SIGNS, "risky TLD alone is noted, not flagged");
        check(!has(UrlAnalyzer.analyze("https://example.com/"), "SUSPICIOUS_TLD"), "ordinary TLD not noted");

        // Accent look-alikes of brands: folded to ASCII and compared; exact brand and unrelated IDNs stay clear.
        check(LookalikeDetector.check("xn--vipps-9ra.no").isPresent(), "accented extra letter next to vipps");
        check(UrlAnalyzer.analyze("https://vípps-betaling.net").verdict != Analysis.Verdict.NO_KNOWN_WARNING_SIGNS, "accented i in vipps with payment word");
        check(!LookalikeDetector.check("xn--bcher-kva.de").isPresent(), "unrelated IDN (bücher.de) is not a look-alike");
        check(!LookalikeDetector.check("vipps.no").isPresent(), "official domain");

        // Brand glued to a phishy word, and Norwegian phishing words.
        check(LookalikeDetector.brandInLabels("appleid-verify.cfd").isPresent(), "appleid is apple + id");
        check(LookalikeDetector.brandInLabels("dnb-sikkerhet-verifiser.com").map(h -> h.score() > 0).orElse(false), "Norwegian phishing words raise dnb");
        check(LookalikeDetector.brandInLabels("dnb-recipes.com").map(h -> h.score() == 0).orElse(true), "brand beside ordinary words stays weak");
        check(LookalikeDetector.brandInLabels("bring-sporing-pakke.icu").isPresent(), "bring is a known brand");
        check(!LookalikeDetector.brandInLabels("posten.no").isPresent() && !LookalikeDetector.brandInLabels("bring.no").isPresent(), "official domains");

        // Message rules: each new scam type alone, and the legitimate look-alike notices that must stay clear.
        check(flagged(level("M", "Hei mamma, jeg har ny telefon. Kan du sende 4500 kr til dette kontonummeret?")), "family impersonation (nb)");
        check(flagged(level("M", "Mum, I lost my phone, this is my new number. Please transfer 300 euro to my account.")), "family impersonation (en)");
        check(!flagged(level("M", "Hei mamma, jeg har ny telefon, du kan ringe meg på det nye nummeret.")), "new number without a money request");
        check(flagged(level("M", "Buy gift cards and read me the codes to settle your tax debt.")), "gift card demand");
        check(!flagged(level("M", "Gavekort til bursdagen: jeg kjøpte et til deg i går.")), "gift card talk between friends");
        check(flagged(level("M", "Strømregningen din er ubetalt. Betal nå for å unngå utkobling.")), "unpaid utility threat");
        check(!flagged(level("M", "Faktura 20431 forfaller 15. november. Betal via nettbanken.")), "ordinary invoice reminder");
        check(flagged(level("M", "Our members make 300% weekly with crypto signals. DM me to join the VIP group.")), "investment lure");
        check(!flagged(level("M", "The market returned 8% last year according to the annual report, a decent year for long-term savers.")), "annual return statement");
        check(flagged(level("M", "Pakken din venter. Betal 29 kr tollgebyr her innen 24 timer: https://posten-toll.top/betal")), "parcel fee with link");
        check(!flagged(level("M", "Toll og avgift på 129 kr må betales før pakken kan leveres. Betal i Posten-appen eller på hentestedet.")), "genuine customs notice without link or pressure");

        System.out.println("SpotTests: " + checks + " checks passed");
    }
}
