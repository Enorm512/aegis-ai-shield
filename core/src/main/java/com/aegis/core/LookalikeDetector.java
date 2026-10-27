package com.aegis.core;

import java.net.IDN;
import java.text.Normalizer;
import java.util.*;

/**
 * Detects hostnames whose registrable label imitates a well-known brand (homoglyphs, digit swaps, hyphenation,
 * rn/m confusion, single-character typos) without being one of the brand's official domains.
 * Advisory only: imitation of a name is evidence, not proof, and some lookalikes are legitimate unrelated businesses.
 */
public final class LookalikeDetector {
    public enum Kind { SKELETON, TYPO }
    public record Match(String brand, Kind kind) {}

    private static final Map<String, List<String>> BRANDS = new LinkedHashMap<>();
    static {
        add("bankid", "bankid.no", "bankid.com", "bankid.se");
        add("vipps", "vipps.no", "vippsmobilepay.com");
        add("dnb", "dnb.no");
        add("nordea", "nordea.com", "nordea.no", "nordea.se", "nordea.dk", "nordea.fi");
        add("sparebank1", "sparebank1.no");
        add("skatteetaten", "skatteetaten.no");
        add("altinn", "altinn.no");
        add("posten", "posten.no", "bring.no");
        add("telenor", "telenor.no", "telenor.com");
        add("paypal", "paypal.com", "paypalobjects.com", "paypal.me");
        add("microsoft", "microsoft.com", "microsoftonline.com", "live.com", "office.com", "windows.com", "xbox.com");
        add("apple", "apple.com", "icloud.com");
        add("google", "google.com", "google.no", "gmail.com", "youtube.com", "gstatic.com", "googleapis.com");
        add("amazon", "amazon.com", "amazon.de", "amazon.co.uk", "amazonaws.com");
        add("netflix", "netflix.com");
        add("facebook", "facebook.com", "fb.com", "meta.com");
        add("instagram", "instagram.com");
        add("whatsapp", "whatsapp.com", "whatsapp.net");
        add("binance", "binance.com");
        add("coinbase", "coinbase.com");
        add("fedex", "fedex.com");
        add("bring", "bring.no", "bring.com", "posten.no");
        add("postnord", "postnord.no", "postnord.se", "postnord.dk", "postnord.com");
        add("dhl", "dhl.com", "dhl.de", "dhl.no", "dhl.co.uk", "dhl.se");
    }
    private static void add(String brand, String... domains) { BRANDS.put(brand, Arrays.asList(domains)); }
    private static final Set<String> TWO_LEVEL = new HashSet<>(Arrays.asList("co.uk", "org.uk", "com.au", "co.nz", "com.br", "co.jp", "co.in", "com.cn", "co.za"));

    private LookalikeDetector() {}

    /** asciiHost is the lowercase punycode host. Returns the imitated brand, or empty. */
    public static Optional<Match> check(String asciiHost) {
        String unicode;
        try { unicode = IDN.toUnicode(asciiHost); } catch (RuntimeException e) { unicode = asciiHost; }
        String[] labels = unicode.split("\\.");
        if (labels.length < 2) return Optional.empty();
        int tld = labels.length - 1;
        if (labels.length >= 3 && TWO_LEVEL.contains(labels[labels.length - 2] + "." + labels[tld])) tld--;
        String label = labels[tld - 1].toLowerCase(Locale.ROOT);
        if (label.length() < 3 || label.length() > 40) return Optional.empty();
        boolean nonAscii = false;
        for (int i = 0; i < label.length(); i++) if (label.charAt(i) > 127) nonAscii = true;
        for (Map.Entry<String, List<String>> b : BRANDS.entrySet()) {
            String brand = b.getKey();
            if (isOfficial(asciiHost, b.getValue())) continue;
            if (label.equals(brand)) continue; // exact brand label on an unofficial domain is handled by UrlAnalyzer's brand rule
            for (String sk : skeletons(label)) {
                if (sk.equals(brand)) return Optional.of(new Match(brand, Kind.SKELETON));
            }
            if (brand.length() >= 6 && Math.abs(label.length() - brand.length()) <= 1 && withinOneEdit(label, brand)) return Optional.of(new Match(brand, Kind.TYPO));
            // An internationalized label (accents, other scripts) that is one character away from a brand once accents are
            // folded away, such as an accented extra letter before "vipps". Only for non-ASCII labels, so plain short names are unaffected.
            if (nonAscii && brand.length() >= 5) for (String sk : skeletons(label)) if (Math.abs(sk.length() - brand.length()) <= 1 && withinOneEdit(sk, brand)) return Optional.of(new Match(brand, Kind.TYPO));
        }
        return Optional.empty();
    }

    /** A brand name found as a whole word (or a look-alike spelling of one) inside a host label. */
    public record TokenHit(String brand, boolean skeleton, boolean inRegistrableLabel, boolean exactLabel, boolean phishyWordPresent) {
        /** How much this adds to a URL's risk score: strong when the brand sits in a subdomain of someone else's domain or the host also carries a "login/secure/verify" style word. */
        public int score() { return (skeleton || !inRegistrableLabel || exactLabel || phishyWordPresent) ? 2 : 0; }
    }

    private static final Set<String> PHISHY = new HashSet<>(Arrays.asList("login", "logon", "signin", "sign", "secure", "security", "sikker", "verify", "verif", "verification", "verifisering", "account",
        "support", "billing", "refund", "update", "locked", "lock", "id", "pay", "payment", "wallet", "confirm", "auth", "helpdesk", "service", "customer", "kundeservice", "konto", "bekreft",
        "tilbakebetaling", "faktura", "kort", "sikkerhet", "verifiser", "verifiseres", "bekreftelse", "innlogging", "logginn", "logg", "betal", "betaling", "betalings", "toll", "tollgebyr", "pakke", "pakken", "pakketracking", "sporing", "levering", "kunde", "kunden", "regning", "sperret", "sperring", "oppdater", "oppdatering", "kontoen", "tilgang", "refusjon", "avgift", "gebyr", "gevinst", "premie", "tracking", "parcel", "package", "customs", "invoice", "bill", "reward", "prize", "gift", "free", "gratis", "krypto", "crypto", "card", "bank", "online", "portal", "access", "recovery", "restore", "unlock", "suspended", "alert", "notice", "tracking", "delivery", "claim"));

    /**
     * Finds a known brand used as a word in any label except the top-level domain ("dnb-login.com", "dnb.evil.com",
     * "secure.nordea.verify-id.com", "app1e-id.com") when the host is not one of the brand's official domains.
     * A brand word in a registrable label that stands alone among ordinary words ("apple-pie.com") scores 0.
     */
    public static Optional<TokenHit> brandInLabels(String asciiHost) {
        String unicode;
        try { unicode = IDN.toUnicode(asciiHost); } catch (RuntimeException e) { unicode = asciiHost; }
        String[] labels = unicode.toLowerCase(Locale.ROOT).split("\\.");
        if (labels.length < 2) return Optional.empty();
        int tld = labels.length - 1;
        if (labels.length >= 3 && TWO_LEVEL.contains(labels[labels.length - 2] + "." + labels[tld])) tld--;
        boolean phishy = false;
        for (int i = 0; i < tld; i++) for (String tok : labels[i].split("-")) if (PHISHY.contains(tok)) phishy = true;
        for (Map.Entry<String, List<String>> b : BRANDS.entrySet()) {
            if (isOfficial(asciiHost, b.getValue())) continue;
            String brand = b.getKey();
            for (int i = 0; i < tld; i++) {
                String label = labels[i];
                if (label.length() > 63) continue;
                for (String tok : label.split("-")) {
                    if (tok.length() < 3) continue;
                    boolean registrable = i == tld - 1;
                    if (tok.equals(brand)) return Optional.of(new TokenHit(brand, false, registrable, label.equals(brand), phishy));
                    // "appleid", "paypalsupport", "securepaypal": the brand glued to one phishy word.
                    if (tok.length() > brand.length() + 1 && (tok.startsWith(brand) && PHISHY.contains(tok.substring(brand.length())) || tok.endsWith(brand) && PHISHY.contains(tok.substring(0, tok.length() - brand.length()))))
                        return Optional.of(new TokenHit(brand, false, registrable, false, true));
                    for (String sk : skeletons(tok)) if (sk.equals(brand)) return Optional.of(new TokenHit(brand, true, registrable, false, phishy));
                }
            }
        }
        return Optional.empty();
    }

    private static boolean isOfficial(String host, List<String> domains) {
        for (String d : domains) if (host.equals(d) || host.endsWith("." + d)) return true;
        return false;
    }

    /** Two readings of ambiguous "1" (l or i). Folds confusable scripts, digits, hyphens and rn/vv. */
    static Set<String> skeletons(String label) {
        Set<String> out = new LinkedHashSet<>();
        for (char one : new char[] {'l', 'i'}) {
            // Accents are dropped (õ -> o, å -> a) because brand names are plain ASCII; ø and æ are mapped by hand.
            String s = Normalizer.normalize(Normalizer.normalize(label, Normalizer.Form.NFKC).toLowerCase(Locale.ROOT), Normalizer.Form.NFD)
                .replaceAll("\\p{M}+", "").replace('ø', 'o').replace("æ", "ae");
            StringBuilder t = new StringBuilder();
            for (int i = 0; i < s.length(); i++) {
                char c = TextNormalizer.foldConfusable(s.charAt(i));
                switch (c) {
                    case '0' -> t.append('o'); case '1' -> t.append(one); case '3' -> t.append('e'); case '5' -> t.append('s');
                    case '4' -> t.append('a'); case '7' -> t.append('t'); case '-' -> { }
                    default -> t.append(c);
                }
            }
            out.add(t.toString().replace("rn", "m").replace("vv", "w"));
        }
        return out;
    }

    /** True when the strings differ by at most one insertion, deletion, substitution or adjacent transposition (and are not equal). */
    static boolean withinOneEdit(String a, String b) {
        if (a.equals(b)) return false;
        int la = a.length(), lb = b.length();
        if (Math.abs(la - lb) > 1) return false;
        int i = 0;
        while (i < la && i < lb && a.charAt(i) == b.charAt(i)) i++;
        if (la == lb) {
            if (a.substring(i + 1).equals(b.substring(i + 1))) return true; // substitution
            return i + 1 < la && a.charAt(i) == b.charAt(i + 1) && a.charAt(i + 1) == b.charAt(i) && a.substring(i + 2).equals(b.substring(i + 2));
        }
        return la < lb ? a.substring(i).equals(b.substring(i + 1)) : a.substring(i + 1).equals(b.substring(i));
    }
}
