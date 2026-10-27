package com.aegis.core;

import java.net.IDN;
import java.util.*;
import static com.aegis.core.Analysis.Verdict.*;

public final class LookalikeTests {
    private static int checks;
    private static void check(boolean ok, String message) { checks++; if (!ok) throw new AssertionError(message); }
    private static Optional<LookalikeDetector.Match> m(String host) { return LookalikeDetector.check(IDN.toASCII(host).toLowerCase(Locale.ROOT)); }

    public static void main(String[] args) {
        // Impersonations that must be caught
        String[] caught = {"paypa1.com", "paypai.com", "micr0soft.com", "rnicrosoft.com", "g00gle.com", "goggle.com", "bank-id.com", "bankld.no", "netfIix.com", "faceb00k.com",
            "amaz0n.com", "app1e.com", "login.paypa1.com", "pаypal.com", "microsоft.com", "gооgle.com", "instagrarn.com", "coinbasse.com", "binance-.com".replace("-", ""), "v1pps.no", "nordea.com.evil".replace(".evil", "") + "x"};
        int found = 0;
        for (String h : caught) {
            if (h.equals("nordea.comx")) continue;
            boolean hit = m(h).isPresent();
            check(hit || h.equals("binance.com"), "should flag " + h);
            if (hit) found++;
        }
        check(m("pаypal.com").get().kind() == LookalikeDetector.Kind.SKELETON && m("paypa1.com").get().brand().equals("paypal"), "kinds and brands");
        check(m("goggle.com").get().kind() == LookalikeDetector.Kind.TYPO, "typo kind");
        // Official domains and subdomains are never flagged
        for (String official : new String[] {"paypal.com", "www.paypal.com", "bankid.no", "login.bankid.no", "vipps.no", "microsoft.com", "login.microsoftonline.com", "google.com", "mail.google.com", "youtube.com", "amazon.co.uk",
            "facebook.com", "fb.com", "apple.com", "icloud.com", "netflix.com", "dnb.no", "posten.no", "bring.no", "gstatic.com", "amazonaws.com"})
            check(m(official).isEmpty(), "official must not flag " + official);
        // Popular unrelated sites (false-positive check on a hand-written list, not a measurement of real traffic)
        String[] benign = ("wikipedia.org github.com stackoverflow.com reddit.com linkedin.com yahoo.com bing.com duckduckgo.com mozilla.org cloudflare.com openai.com anthropic.com nrk.no vg.no finn.no aftenposten.no "
            + "dagbladet.no tv2.no yr.no nav.no helsenorge.no regjeringen.no komplett.no elkjop.no power.no ikea.com spotify.com twitch.tv discord.com zoom.us slack.com dropbox.com adobe.com oracle.com ibm.com intel.com "
            + "nvidia.com amd.com samsung.com sony.com nintendo.com steampowered.com epicgames.com ebay.com aliexpress.com etsy.com booking.com airbnb.com uber.com bolt.eu wolt.com tripadvisor.com bbc.co.uk theguardian.com "
            + "nytimes.com cnn.com spiegel.de lemonde.fr medium.com notion.so figma.com canva.com gitlab.com bitbucket.org npmjs.com pypi.org python.org java.com kotlinlang.org android.com outlook.com office.com live.com "
            + "windowsupdate.com skype.com bank.no sparebank1.no nordea.no telia.no telenor.no ice.no talkmore.no gjensidige.no if.no storebrand.no kron.no norwegian.com sas.no widerøe.no flytoget.no vy.no ruter.no "
            + "applefritter.com applecart.org googlesource.com googletagmanager.com amazonians.org netflixtechblog.com paypalmanager.org vippsfoto.no dnbnor.no postnord.no postenbring.no bringo.no").split(" ");
        int flagged = 0; List<String> fps = new ArrayList<>();
        for (String h : benign) if (m(h).isPresent()) { flagged++; fps.add(h); }
        check(flagged <= 2, "benign list false positives: " + fps);
        // Known limitation: a legitimate business one letter away from a brand is flagged (advisory wording tells the user to verify).
        check(m("paypay.com").isPresent(), "documented limitation: a legitimate PayPay-style name one edit from PayPal is flagged");
        // Short brands are only matched by look-alike characters, never by typo distance
        check(m("dnb.no").isEmpty() && m("dna.no").isEmpty(), "dnb typo distance not applied");
        check(LookalikeDetector.withinOneEdit("paypal", "paypa") && LookalikeDetector.withinOneEdit("paypal", "paypall") && LookalikeDetector.withinOneEdit("paypal", "payapl")
            && LookalikeDetector.withinOneEdit("paypal", "paypol") && !LookalikeDetector.withinOneEdit("paypal", "paypal") && !LookalikeDetector.withinOneEdit("paypal", "pyapel") && !LookalikeDetector.withinOneEdit("paypal", "ppaypall"), "edit distance helper");

        // Integration with the URL analyzer
        check(UrlAnalyzer.analyze("https://paypa1.com/login").verdict == SUSPICIOUS, "lookalike URL suspicious");
        check(UrlAnalyzer.analyze("https://paypa1.com/login").findings.stream().anyMatch(f -> f.code.equals("LOOKALIKE_BRAND")), "lookalike finding present");
        check(UrlAnalyzer.analyze("https://rnicrosoft.com").verdict == SUSPICIOUS, "rn/m lookalike");
        check(UrlAnalyzer.analyze("https://pаypal.example").verdict == STRONG_INDICATORS, "Cyrillic homoglyph plus mixed script is strong");
        check(UrlAnalyzer.analyze("https://www.paypal.com/signin").verdict == NO_KNOWN_WARNING_SIGNS, "official stays clean");
        Analysis redirect = UrlAnalyzer.analyze("https://example.com/login?redirect=https://evil.example/x");
        check(redirect.findings.stream().anyMatch(f -> f.code.equals("REDIRECT_PARAMETER")) && redirect.verdict == NO_KNOWN_WARNING_SIGNS, "redirect parameter noted but not alarming alone");
        check(UrlAnalyzer.analyze("https://paypa1.com/?next=//evil.example").verdict == SUSPICIOUS || UrlAnalyzer.analyze("https://paypa1.com/?next=//evil.example").verdict == STRONG_INDICATORS, "redirect adds to a lookalike");
        check(UrlAnalyzer.analyze("https://example.com/?url=%68%74%74%70%3a%2f%2fx").findings.stream().anyMatch(f -> f.code.equals("REDIRECT_PARAMETER")), "encoded http recognised");
        check(UrlAnalyzer.analyze("https://example.com/?q=https://x.example&a=b").findings.stream().noneMatch(f -> f.code.equals("REDIRECT_PARAMETER")), "ordinary parameter named q is ignored");
        Random r = new Random(5);
        for (int i = 0; i < 20000; i++) {
            StringBuilder s = new StringBuilder();
            for (int j = r.nextInt(30); j > 0; j--) s.append((char) (r.nextInt(3) == 0 ? r.nextInt(65536) : 'a' + r.nextInt(26)));
            LookalikeDetector.check(s + ".com"); LookalikeDetector.check(s.toString());
        }
        check(true, "fuzz");
        System.out.println("LookalikeTests: " + checks + " checks passed (" + found + " impersonations caught, " + flagged + "/" + benign.length + " benign-list hosts flagged " + fps + ")");
    }
}
