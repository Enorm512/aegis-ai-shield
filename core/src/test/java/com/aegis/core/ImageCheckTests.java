package com.aegis.core;

import com.aegis.core.ImageCheck.QrKind;
import java.util.*;

/** Host tests for the screenshot and QR check: payload kinds, findings, verdicts and advice. */
public final class ImageCheckTests {
    private static int checks;
    private static void check(boolean ok, String message) { checks++; if (!ok) throw new AssertionError(message); }
    private static boolean has(Analysis a, String code) { return a.findings.stream().anyMatch(f -> f.code.equals(code)); }
    private static String detail(Analysis a, String code) { return a.findings.stream().filter(f -> f.code.equals(code)).map(f -> f.detail).findFirst().orElse(""); }
    private static Analysis qr(String... payloads) { return ImageCheck.analyze("", Arrays.asList(payloads), null, null); }

    /** Lists exactly one host as a confirmed phishing domain; everything else is not listed. */
    private static final ReputationProvider DB = new ReputationProvider() {
        public String id() { return "test"; }
        public Reputation domain(String h) { return h.equals("dnb-verify.example") ? Reputation.listed(new ThreatDatabase.Entry(ThreatDatabase.Category.PHISHING, ThreatDatabase.Confidence.CONFIRMED, "test"), "test#1") : Reputation.notListed("test#1"); }
        public Reputation sha256(String h) { return Reputation.notListed("test#1"); }
        public Reputation signerCertificate(String h) { return Reputation.notListed("test#1"); }
    };

    public static void main(String[] args) {
        // --- Payload kinds
        check(ImageCheck.kind("https://example.com/a") == QrKind.WEB_LINK && ImageCheck.kind("HTTP://EXAMPLE.COM") == QrKind.WEB_LINK, "web links");
        check(ImageCheck.kind("tg://login?token=AQIDBAUGBwgJ") == QrKind.DEVICE_LINK, "telegram login");
        check(ImageCheck.kind("sgnl://linkdevice?uuid=abc&pub_key=xyz") == QrKind.DEVICE_LINK && ImageCheck.kind("tsdevice:/?uuid=abc") == QrKind.DEVICE_LINK, "signal link");
        check(ImageCheck.kind("2@Zm9vYmFyYmF6cXV4,aGVsbG93b3JsZA==,c2VjcmV0a2V5,MQ==") == QrKind.DEVICE_LINK, "whatsapp web");
        check(ImageCheck.kind("https://discord.com/ra/AbCdEf123") == QrKind.DEVICE_LINK, "discord login");
        check(ImageCheck.kind("https://discord.com/invite/abc") == QrKind.WEB_LINK, "discord invite is an ordinary link");
        check(ImageCheck.kind("otpauth://totp/Bank:me?secret=JBSWY3DPEHPK3PXP") == QrKind.SIGNIN_SECRET && ImageCheck.kind("otpauth-migration://offline?data=abc") == QrKind.SIGNIN_SECRET, "authenticator");
        check(ImageCheck.kind("bitcoin:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq?amount=0.1") == QrKind.CRYPTO_PAYMENT, "bitcoin uri");
        check(ImageCheck.kind("0x52908400098527886E0F7030069857D2E4169EE7") == QrKind.CRYPTO_PAYMENT && ImageCheck.kind("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq") == QrKind.CRYPTO_PAYMENT, "bare wallets");
        check(ImageCheck.kind("upi://pay?pa=shop@bank&pn=Corner%20Shop&am=10") == QrKind.PAYMENT_REQUEST, "upi");
        check(ImageCheck.kind("BCD\n002\n1\nSCT\nBICXXX\nAcme AS\nNO9386011117947\nEUR12.50\n\n\nInvoice 7") == QrKind.BANK_TRANSFER, "epc");
        check(ImageCheck.kind("WIFI:T:WPA;S:Cafe Free;P:secret;;") == QrKind.WIFI, "wifi");
        check(ImageCheck.kind("SMSTO:2222:WIN") == QrKind.TEXT_MESSAGE && ImageCheck.kind("tel:+4712345678") == QrKind.CONTACT && ImageCheck.kind("BEGIN:VCARD\nFN:A\nEND:VCARD") == QrKind.CONTACT, "sms and contacts");
        check(ImageCheck.kind("market://details?id=com.x") == QrKind.APP_LINK && ImageCheck.kind("intent://scan/#Intent;scheme=zxing;end") == QrKind.APP_LINK, "app links");
        check(ImageCheck.kind("Hello there") == QrKind.TEXT && ImageCheck.kind("Note: call me") == QrKind.TEXT && ImageCheck.kind(null) == QrKind.TEXT && ImageCheck.kind("") == QrKind.TEXT, "plain text");

        // --- Device linking is the strongest QR signal and gets "don't scan"
        Analysis dl = qr("tg://login?token=AQIDBAUGBwgJ");
        check(dl.verdict == Analysis.Verdict.STRONG_INDICATORS && has(dl, "QR_DEVICE_LINK"), "device link is strong: " + dl.verdict);
        check(!detail(dl, "QR_DEVICE_LINK").contains("AQIDBAUG"), "login token is never shown");
        ResultSummary sdl = ResultSummary.of(dl, ResultSummary.Subject.IMAGE);
        check(sdl.reasons.get(0).code.equals("QR_DEVICE_LINK") && sdl.advice.get(0).equals("DO_NOT_SCAN") && sdl.advice.contains("ALREADY_ACTED"), "device link advice: " + sdl.advice);
        check(sdl.limitations.stream().anyMatch(f -> f.code.equals("IMAGE_LIMITS")), "limits shown as a limitation");

        // --- Sign-in secrets: suspicious, secret never echoed
        Analysis sec = qr("otpauth://totp/Bank:me?secret=JBSWY3DPEHPK3PXP&issuer=Bank");
        check(sec.verdict == Analysis.Verdict.SUSPICIOUS && !sec.findings.toString().contains("JBSWY3") && sec.findings.stream().noneMatch(f -> f.detail.contains("JBSWY3")), "otp secret");
        check(ResultSummary.of(sec, ResultSummary.Subject.IMAGE).advice.contains("KEEP_QR_PRIVATE"), "keep private advice");

        // --- Payments
        Analysis btc = qr("bitcoin:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq?amount=0.1");
        check(btc.verdict == Analysis.Verdict.SUSPICIOUS && ResultSummary.of(btc, ResultSummary.Subject.IMAGE).advice.contains("PAYMENT_HARD_TO_RECOVER"), "crypto");
        Analysis upi = qr("upi://pay?pa=shop@bank&pn=Corner%20Shop&am=10");
        check(upi.verdict == Analysis.Verdict.NO_KNOWN_WARNING_SIGNS && detail(upi, "QR_PAYMENT_REQUEST").contains("Corner Shop") && detail(upi, "QR_PAYMENT_REQUEST").contains("never receives"), "upi is information: " + detail(upi, "QR_PAYMENT_REQUEST"));
        Analysis epc = qr("BCD\n002\n1\nSCT\nBICXXX\nAcme AS\nNO9386011117947\nEUR12.50\n\n\nInvoice 7");
        String e = detail(epc, "QR_BANK_TRANSFER");
        check(epc.verdict == Analysis.Verdict.NO_KNOWN_WARNING_SIGNS && e.contains("EUR 12.50") && e.contains("Acme AS") && e.contains("NO9386011117947"), "epc details: " + e);
        check(qr("BCD\n002").verdict == Analysis.Verdict.NO_KNOWN_WARNING_SIGNS && detail(qr("BCD\n002"), "QR_BANK_TRANSFER").startsWith("A QR code in the picture fills in a bank transfer."), "short epc tolerated");

        // --- Wi-Fi, text messages, contacts and app links are information only
        Analysis wifi = qr("WIFI:T:WPA;S:Cafe\\;Free;P:secret;;");
        check(wifi.verdict == Analysis.Verdict.NO_KNOWN_WARNING_SIGNS && detail(wifi, "QR_WIFI").contains("Cafe;Free") && !detail(wifi, "QR_WIFI").contains("secret"), "wifi name, no password: " + detail(wifi, "QR_WIFI"));
        check(detail(qr("SMSTO:2222:WIN NOW"), "QR_TEXT_MESSAGE").contains("2222") && !detail(qr("SMSTO:2222:WIN NOW"), "QR_TEXT_MESSAGE").contains("WIN"), "sms number only");
        check(detail(qr("market://details?id=com.x"), "QR_APP_LINK").contains("(market:)"), "app link scheme");
        check(has(qr("tel:+4712345678"), "QR_CONTACT"), "contact");

        // --- Web links in QR codes go through the link check and the threat database
        Analysis plain = ImageCheck.analyze("", List.of("https://example.org/menu"), DB, null);
        check(plain.verdict == Analysis.Verdict.NO_KNOWN_WARNING_SIGNS && detail(plain, "QR_LINK").contains("example.org") && has(plain, "THREATDB_NOT_LISTED"), "benign qr link: " + plain.verdict);
        Analysis listed = ImageCheck.analyze("", List.of("https://dnb-verify.example/login"), DB, null);
        check(listed.verdict == Analysis.Verdict.CONFIRMED_MALICIOUS && has(listed, "THREATDB_LISTED") && ResultSummary.of(listed, ResultSummary.Subject.IMAGE).advice.contains("DO_NOT_OPEN"), "listed qr link: " + listed.verdict);
        Analysis apk = qr("https://files.example.net/app/BankSecure.APK?x=1");
        check(apk.verdict.compareTo(Analysis.Verdict.SUSPICIOUS) >= 0 && has(apk, "QR_APP_DOWNLOAD") && ResultSummary.of(apk, ResultSummary.Subject.IMAGE).advice.get(0).equals("DO_NOT_SCAN"), "apk download: " + apk.verdict);
        Analysis noDb = qr("https://example.org/");
        check(has(noDb, "QR_LINK") && !has(noDb, "THREATDB_NOT_LISTED"), "no provider, no claim of not listed");

        // --- Text read from the picture goes through the message check
        String scam = "DNB: Your account is suspended. Verify your account immediately at https://dnb-verify.example/login and reply with your BankID code";
        Analysis text = ImageCheck.analyze(scam, List.of(), DB, null);
        check(text.verdict == Analysis.Verdict.STRONG_INDICATORS || text.verdict == Analysis.Verdict.CONFIRMED_MALICIOUS, "scam screenshot flagged: " + text.verdict);
        check(has(text, "SECRET_REQUEST") && has(text, "IMAGE_TEXT_READ") && text.subject.equals("Picture"), "text findings kept");
        ResultSummary ts = ResultSummary.of(text, ResultSummary.Subject.IMAGE);
        check(ts.advice.contains("NEVER_SHARE_CODES") && ts.advice.contains("REPORT_IT") && !ts.advice.contains("DO_NOT_SCAN"), "text advice: " + ts.advice);
        Analysis calm = ImageCheck.analyze("See you at the football practice on Tuesday at six, bring water", List.of(), null, null);
        check(calm.verdict == Analysis.Verdict.NO_KNOWN_WARNING_SIGNS && ResultSummary.of(calm, ResultSummary.Subject.IMAGE).reasons.isEmpty(), "calm text: " + calm.verdict);
        check(ResultSummary.of(calm, ResultSummary.Subject.IMAGE).advice.equals(List.of("VERIFY_OTHER_WAY", "STAY_CAUTIOUS")), "calm advice");

        // --- QR plain text joins the message text; text and QR combine, strongest wins
        Analysis qrText = ImageCheck.analyze("", List.of("You have won a prize! Pay the fee with gift cards to claim it today, act now"), null, null);
        check(qrText.verdict.compareTo(Analysis.Verdict.SUSPICIOUS) >= 0, "qr text checked: " + qrText.verdict);
        Analysis both = ImageCheck.analyze("Scan this code to log in to the support chat. Our agent will help you right away.", List.of("tg://login?token=x1"), null, null);
        check(both.verdict == Analysis.Verdict.STRONG_INDICATORS && has(both, "QR_DEVICE_LINK") && has(both, "IMAGE_TEXT_READ"), "combined");

        // --- Nothing or too little read
        Analysis empty = ImageCheck.analyze("", List.of(), null, null);
        check(empty.verdict == Analysis.Verdict.INSUFFICIENT_EVIDENCE && empty.findings.get(0).code.equals("IMAGE_NOTHING_READ"), "empty");
        check(ResultSummary.of(empty, ResultSummary.Subject.IMAGE).advice.get(0).equals("CHECK_IMAGE"), "unclear advice");
        check(ImageCheck.analyze("Menu  12:30", null, null, null).verdict == Analysis.Verdict.INSUFFICIENT_EVIDENCE && detail(ImageCheck.analyze("Menu 12:30", null, null, null), "IMAGE_NOTHING_READ").startsWith("Too little"), "too little text");
        Analysis noOcr = ImageCheck.analyze(null, List.of("https://example.org/"), null, null);
        check(has(noOcr, "IMAGE_OCR_UNAVAILABLE") && noOcr.verdict == Analysis.Verdict.NO_KNOWN_WARNING_SIGNS, "ocr unavailable but qr read");
        check(ImageCheck.analyze(null, List.of(), null, null).verdict == Analysis.Verdict.INSUFFICIENT_EVIDENCE, "nothing at all");

        // --- Limits and hostile input
        List<String> many = new ArrayList<>();
        for (int i = 0; i < 20; i++) many.add("https://example.org/" + i);
        Analysis lots = qr(many.toArray(new String[0]));
        check(has(lots, "IMAGE_QR_LIMIT") && lots.findings.stream().filter(f -> f.code.equals("QR_LINK")).count() == ImageCheck.MAX_QR, "qr limit, one line per checked code");
        check(qr("https://example.org/a", "https://example.org/a", " https://example.org/a ").findings.stream().filter(f -> f.code.equals("QR_LINK")).count() == 1, "duplicates dropped");
        check(detail(qr("tel:+47\u0000‮123\n456"), "QR_CONTACT").matches("[^\\p{Cntrl}\\p{Cf}]*"), "control and bidi characters removed");
        check(detail(qr("BEGIN:VCARD\nFN:" + "x".repeat(500)), "QR_CONTACT").length() < 200, "contact detail bounded");
        String huge = "x ".repeat(60_000);
        Analysis big = ImageCheck.analyze(huge, List.of("y".repeat(10_000)), null, null);
        check(big.verdict != null, "huge input handled");
        check(ImageCheck.analyze("", Arrays.asList(null, "", "  "), null, null).verdict == Analysis.Verdict.INSUFFICIENT_EVIDENCE, "blank payloads ignored");
        Random r = new Random(7);
        for (int i = 0; i < 3000; i++) {
            StringBuilder s = new StringBuilder();
            String[] starts = {"", "tg://", "BCD\n", "WIFI:", "upi://pay?", "otpauth://", "https://", "smsto:", "bitcoin:", "2@"};
            s.append(starts[r.nextInt(starts.length)]);
            int n = r.nextInt(80);
            for (int j = 0; j < n; j++) s.append((char) (r.nextInt(3) == 0 ? r.nextInt(0x3000) : 32 + r.nextInt(95)));
            Analysis a = ImageCheck.analyze(r.nextBoolean() ? s.toString() : null, List.of(s.toString()), r.nextBoolean() ? DB : null, null);
            check(a.verdict != null && a.findings.stream().anyMatch(f -> f.code.equals("IMAGE_LIMITS")), "fuzz " + i);
        }
        System.out.println("ImageCheckTests: " + checks + " checks passed");
    }
}
