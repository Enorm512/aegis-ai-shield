package com.aegis.core;

import java.util.*;
import java.util.regex.*;

/**
 * Screenshot and QR check. The app reads the picture on the phone (text by OCR, QR codes by a decoder); this class
 * judges what was read. Web links in QR codes go through the normal link check, text through the normal message check,
 * and QR payloads that are not web links get their own findings (device linking, payments, sign-in secrets, Wi-Fi...).
 * Nothing here opens, joins, pays or scans anything.
 */
public final class ImageCheck {
    public static final int MAX_QR = 8;
    public static final int MAX_TEXT = 20_000;
    public static final int MAX_PAYLOAD = 4096;
    private static final int MIN_WORDS = 5;

    public enum QrKind { WEB_LINK, DEVICE_LINK, CRYPTO_PAYMENT, PAYMENT_REQUEST, BANK_TRANSFER, SIGNIN_SECRET, WIFI, TEXT_MESSAGE, CONTACT, APP_LINK, TEXT }

    private static final Pattern WHATSAPP_LINK = Pattern.compile("^[0-9]@[A-Za-z0-9+/=_-]{8,},[A-Za-z0-9+/=_-]{8,},.+");
    private static final Pattern DISCORD_LOGIN = Pattern.compile("^https://(?:www\\.)?discord(?:app)?\\.com/ra/[A-Za-z0-9_-]+", Pattern.CASE_INSENSITIVE);
    private static final Pattern CRYPTO_URI = Pattern.compile("^(bitcoin|bitcoincash|litecoin|ethereum|dogecoin|monero|tron|solana|ripple|xrp|cardano|usdt|tether|binance|bnb|ton):", Pattern.CASE_INSENSITIVE);
    private static final Pattern BARE_WALLET = Pattern.compile("^(?:0x[0-9a-fA-F]{40}|bc1[02-9ac-hj-np-z]{25,87}|[13][1-9A-HJ-NP-Za-km-z]{25,34}|T[1-9A-HJ-NP-Za-km-z]{33})$");
    private static final Pattern SCHEME = Pattern.compile("^([a-z][a-z0-9+.-]{1,31}):", Pattern.CASE_INSENSITIVE);
    private static final Pattern WIFI_NAME = Pattern.compile("(?:^WIFI:|;)S:((?:\\\\.|[^;])*)", Pattern.CASE_INSENSITIVE);

    private ImageCheck() {}

    public static QrKind kind(String payload) {
        String p = payload == null ? "" : payload.trim();
        String lower = p.toLowerCase(Locale.ROOT);
        if (lower.startsWith("tg://login") || lower.startsWith("sgnl://linkdevice") || lower.startsWith("tsdevice:") || WHATSAPP_LINK.matcher(p).matches() || DISCORD_LOGIN.matcher(p).find())
            return QrKind.DEVICE_LINK;
        if (lower.startsWith("otpauth://") || lower.startsWith("otpauth-migration://")) return QrKind.SIGNIN_SECRET;
        if (CRYPTO_URI.matcher(p).find() || BARE_WALLET.matcher(p).matches()) return QrKind.CRYPTO_PAYMENT;
        if (lower.startsWith("upi://pay") || lower.startsWith("upi:pay")) return QrKind.PAYMENT_REQUEST;
        if (lower.startsWith("bcd\n") || lower.startsWith("bcd\r\n")) return QrKind.BANK_TRANSFER;
        if (lower.startsWith("http://") || lower.startsWith("https://")) return QrKind.WEB_LINK;
        if (lower.startsWith("wifi:")) return QrKind.WIFI;
        if (lower.startsWith("smsto:") || lower.startsWith("sms:") || lower.startsWith("mmsto:")) return QrKind.TEXT_MESSAGE;
        if (lower.startsWith("tel:") || lower.startsWith("mailto:") || lower.startsWith("matmsg:") || lower.startsWith("begin:vcard") || lower.startsWith("mecard:") || lower.startsWith("geo:") || lower.startsWith("begin:vevent"))
            return QrKind.CONTACT;
        if (SCHEME.matcher(p).find() && !p.contains(" ")) return QrKind.APP_LINK;
        return QrKind.TEXT;
    }

    /** Shown text for a payload part: no control characters, bounded length. */
    static String shown(String s, int max) {
        String clean = s == null ? "" : s.replaceAll("[\\p{Cntrl}\\p{Cf}]", " ").replaceAll("\\s+", " ").trim();
        return clean.length() > max ? clean.substring(0, max) + "…" : clean;
    }

    private static String hostOf(Analysis a) {
        for (Finding f : a.findings) if (f.code.equals("HOST")) return f.detail.substring("Destination host: ".length());
        return null;
    }

    /**
     * @param ocrText text read from the picture, or null when text recognition could not run on this phone
     * @param qrPayloads decoded QR contents (at most {@link #MAX_QR} are judged)
     */
    public static Analysis analyze(String ocrText, List<String> qrPayloads, ReputationProvider provider, TextClassifier classifier) {
        List<Finding> base = new ArrayList<>();
        List<Analysis> parts = new ArrayList<>();
        Analysis.Verdict own = Analysis.Verdict.NO_KNOWN_WARNING_SIGNS;
        StringBuilder text = new StringBuilder();
        if (ocrText != null) text.append(ocrText.length() > MAX_TEXT ? ocrText.substring(0, MAX_TEXT) : ocrText);

        List<String> qr = new ArrayList<>();
        if (qrPayloads != null) for (String p : qrPayloads) if (p != null && !p.trim().isEmpty() && !qr.contains(p.trim())) qr.add(p.trim());
        if (qr.size() > MAX_QR) {
            base.add(new Finding("IMAGE_QR_LIMIT", "Only the first " + MAX_QR + " of " + qr.size() + " QR codes were checked."));
            qr = new ArrayList<>(qr.subList(0, MAX_QR));
        }
        for (String raw : qr) {
            String p = raw.length() > MAX_PAYLOAD ? raw.substring(0, MAX_PAYLOAD) : raw;
            switch (kind(p)) {
                case DEVICE_LINK -> {
                    base.add(new Finding("QR_DEVICE_LINK", "A QR code in the picture signs a new device in to a messaging or chat account (such as WhatsApp, Telegram, Signal or Discord). "
                        + "Whoever made it gets access to the account and its messages once you scan it. Only scan such a code when it is shown on your own computer."));
                    own = max(own, Analysis.Verdict.STRONG_INDICATORS);
                }
                case SIGNIN_SECRET -> {
                    base.add(new Finding("QR_SIGNIN_SECRET", "A QR code in the picture holds the secret key of a sign-in code generator (two-step login). "
                        + "Anyone with this picture can make your login codes. Never send it to anyone, and don't add a code from someone who contacted you."));
                    own = max(own, Analysis.Verdict.SUSPICIOUS);
                }
                case CRYPTO_PAYMENT -> {
                    base.add(new Finding("QR_CRYPTO_PAYMENT", "A QR code in the picture is a cryptocurrency payment address. Crypto payments cannot be reversed, "
                        + "and requests to pay in crypto are common in scams."));
                    own = max(own, Analysis.Verdict.SUSPICIOUS);
                }
                case PAYMENT_REQUEST -> base.add(new Finding("QR_PAYMENT_REQUEST", "A QR code in the picture is a payment request. Scanning it sends money; it never receives money. "
                    + "Payee: " + shown(param(p, "pn"), 60) + "."));
                case BANK_TRANSFER -> base.add(new Finding("QR_BANK_TRANSFER", "A QR code in the picture fills in a bank transfer" + bankTransfer(p)
                    + ". Check the recipient with the company through a channel you already trust before paying."));
                case WIFI -> {
                    Matcher m = WIFI_NAME.matcher(p);
                    base.add(new Finding("QR_WIFI", "A QR code in the picture joins the Wi-Fi network \"" + (m.find() ? shown(m.group(1).replace("\\", ""), 60) : "?")
                        + "\". A network you don't know can watch traffic that is not encrypted."));
                }
                case TEXT_MESSAGE -> base.add(new Finding("QR_TEXT_MESSAGE", "A QR code in the picture prepares a text message to " + shown(p.replaceFirst("(?i)^(smsto|sms|mmsto):", "").split(":", 2)[0], 30)
                    + ". Texts to short numbers can cost money."));
                case CONTACT -> base.add(new Finding("QR_CONTACT", "A QR code in the picture holds contact details: " + shown(p, 80)));
                case APP_LINK -> {
                    Matcher m = SCHEME.matcher(p);
                    base.add(new Finding("QR_APP_LINK", "A QR code in the picture opens another app (" + (m.find() ? m.group(1).toLowerCase(Locale.ROOT) : "?") + ":). Aegis cannot see where it leads."));
                }
                case WEB_LINK -> {
                    Analysis link = ThreatChecks.url(p, provider);
                    parts.add(link);
                    String host = hostOf(link);
                    base.add(new Finding("QR_LINK", "A QR code in the picture opens " + (host == null ? "a web address that could not be read" : host) + "."));
                    String path = p.toLowerCase(Locale.ROOT).replaceFirst("[?#].*$", "");
                    if (path.endsWith(".apk") || path.endsWith(".apks") || path.endsWith(".xapk")) {
                        base.add(new Finding("QR_APP_DOWNLOAD", "The QR code downloads an app file outside an app store. Scam calls and messages often ask people to install apps this way."));
                        own = max(own, Analysis.Verdict.SUSPICIOUS);
                    }
                }
                case TEXT -> text.append('\n').append(p);
            }
        }

        String all = text.toString().trim();
        int words = TextNormalizer.tokens(all).size();
        if (ocrText == null) base.add(new Finding("IMAGE_OCR_UNAVAILABLE", "Text could not be read from the picture on this phone, so only QR codes were checked."));
        else if (!ocrText.trim().isEmpty()) base.add(new Finding("IMAGE_TEXT_READ", "Text read from the picture: about " + TextNormalizer.tokens(ocrText).size() + " words."));
        if (words > 0) parts.add(MessageAi.analyze(all, classifier));
        base.add(new Finding("IMAGE_LIMITS", "The picture was read on this phone. Text recognition can misread or miss words, which can hide or invent warning signs. "
            + "Pictures, logos, colours and who sent it are not judged."));

        if (qr.isEmpty() && words < MIN_WORDS) {
            base.add(0, new Finding("IMAGE_NOTHING_READ", words == 0 ? "No text or QR code could be read from the picture." : "Too little text was read from the picture to judge it."));
            return new Analysis(Analysis.Verdict.INSUFFICIENT_EVIDENCE, base, "Picture");
        }
        return ResultSummary.combine(new Analysis(own, base, "Picture"), parts.toArray(new Analysis[0]));
    }

    private static Analysis.Verdict max(Analysis.Verdict a, Analysis.Verdict b) { return a.compareTo(b) >= 0 ? a : b; }

    private static String param(String uri, String name) {
        Matcher m = Pattern.compile("[?&]" + name + "=([^&]*)").matcher(uri);
        if (!m.find()) return "?";
        try { return java.net.URLDecoder.decode(m.group(1), "UTF-8"); } catch (Exception e) { return m.group(1); }
    }

    /** EPC069-12 ("BCD") lines: 5 = name, 6 = IBAN, 7 = amount. Any part may be missing. */
    private static String bankTransfer(String p) {
        String[] l = p.split("\r?\n", -1);
        StringBuilder s = new StringBuilder();
        if (l.length > 7 && l[7].trim().length() > 3) s.append(" of ").append(shown(l[7].trim().substring(0, 3), 3)).append(' ').append(shown(l[7].trim().substring(3), 15));
        if (l.length > 5 && !l[5].trim().isEmpty()) s.append(" to ").append(shown(l[5], 70));
        if (l.length > 6 && !l[6].trim().isEmpty()) s.append(" (account ").append(shown(l[6], 40)).append(')');
        return s.toString();
    }
}
