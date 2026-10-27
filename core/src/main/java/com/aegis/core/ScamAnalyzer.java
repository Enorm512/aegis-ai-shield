package com.aegis.core;

import java.util.*;
import java.util.regex.*;

/**
 * English and Norwegian rules; does not infer who or what generated a message. The wording rules run on the
 * normalised text (zero-width characters, look-alike letters, leetspeak and letter-spacing cannot hide a phrase);
 * links are taken from the original text.
 */
public final class ScamAnalyzer {
    public static final int MAX_TEXT_LENGTH = 100_000;
    public static final int MAX_LINKS = 12;
    private static final int FLAGS = Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE;
    private static final Pattern LINKS = Pattern.compile("(?i)https?://[^\\s<>\"']+");
    private static final Pattern URGENT = Pattern.compile("\\b(urgent|immediately|act now|within 0 (hours?|minutes?)|haster|umiddelbart|straks|snarest|innen 0 (timer|minutter))\\b", FLAGS);
    private static final Pattern THREAT = Pattern.compile("\\b(account.{0,35}(suspend|block|clos|lock|limit)|arrest|konto.{0,35}(steng|sperr|begrens)|politi(et)?\\b|inkasso|legal action|rettslige skritt)", FLAGS);
    private static final Pattern SECRETS = Pattern.compile("\\b(send|share|reply with|provide|read me|tell me|oppgi|del|les opp|send oss).{0,60}\\b(password|passord|pin|verification code|one time code|engangskode|sikkerhetskode|bankid|seed phrase|recovery phrase|gjenopprettingsfrase)\\b", FLAGS);
    private static final Pattern NEGATION = Pattern.compile("\\b(never|aldri|ikke|not|no one|nobody|ingen|don t|do not|dont|should not|must not)\\b", FLAGS);
    private static final Pattern PAYMENT = Pattern.compile("\\b(pay|payment|transfer|wire|betal|betaling|overfor|overfør)\\b", FLAGS);
    private static final Pattern IRREVERSIBLE = Pattern.compile("\\b(gift cards?|bitcoin|crypto|cryptocurrency|gavekort|krypto|kryptovaluta)\\b", FLAGS);
    private static final Pattern PRIZE = Pattern.compile("\\b(you (have )?won|lottery|prize|du har vunnet|premie|lotteri|gevinst)\\b", FLAGS);
    private static final Pattern VERIFY = Pattern.compile("\\b(verify|confirm|validate|update|restore|bekreft|verifiser|oppdater|gjenopprett)\\b.{0,30}\\b(identity|account|card|payment (details|information)|banking|login|konto|identitet|kort|betalingsinformasjon|bankkort|kortinformasjon)\\b", FLAGS);
    // Patterns below run on normalised text: lowercase, numbers collapsed to "0", URLs to "urltoken", punctuation to spaces.
    private static final Pattern PARCEL = Pattern.compile("\\b(pakke|pakken|pakka|forsendelse|forsendelsen|levering|leveringen|package|parcel|delivery|shipment)\\b", FLAGS);
    private static final Pattern PARCEL_FEE = Pattern.compile("\\b(toll|\\w*gebyr\\w*|\\w*avgift\\w*|frakt|fraktkostnad|customs|duty|fee|postage|shipping)\\b", FLAGS);
    private static final Pattern PARENT = Pattern.compile("\\b(mamma|mor|pappa|far|mum|mom|dad|bestemor|bestefar|s[oø]nn|datter|son|daughter)\\b", FLAGS);
    private static final Pattern NEW_NUMBER = Pattern.compile("\\b(ny telefon|nytt nummer|nytt telefonnummer|mistet telefonen|knust telefonen|new phone|new number|lost my phone|broke my phone|phone (broke|died)|this is my new)\\b", FLAGS);
    private static final Pattern MONEY_ASK = Pattern.compile("\\b(send|sende|overf[oø]r|overf[oø]re|betale|betal|l[aå]ne|l[aå]n meg|pay|transfer|lend|loan)\\b.{0,50}\\b(0 ?(kr|kroner|nok|usd|eur|dollar|euro)|kontonummer|konto|account|bank)\\b", FLAGS);
    private static final Pattern UNPAID = Pattern.compile("\\b(ubetalt|forfalt|forfalte|utest[aå]ende|unpaid|overdue|outstanding|past due)\\b", FLAGS);
    private static final Pattern CUTOFF = Pattern.compile("\\b(utkobling|kobles ut|koble ut|stenges|avstengt|avstengning|inkasso|disconnect(ed|ion)?|cut off|shut off|collections)\\b", FLAGS);
    private static final Pattern AUTHORITY = Pattern.compile("\\b(irs|interpol|europol|warrant|skatteetaten|skattefogd|skattegjeld|tax debt|tax office|kemner)\\b", FLAGS);
    private static final Pattern GIFTCARD_REQUEST = Pattern.compile("\\b(buy|purchase|get|kj[oø]p|kj[oø]pe|skaff)\\b.{0,40}\\b(gift cards?|gavekort|google play|itunes|apple card|paysafe|steam card)\\b", FLAGS);
    private static final Pattern INVEST_CONTEXT = Pattern.compile("\\b(invest|investment|investering|investor|crypto|krypto|forex|trading|signals?|profit|returns?|avkastning|fortjeneste|bitcoin)\\b", FLAGS);
    private static final Pattern RETURN_RATE = Pattern.compile("\\b0 ?%? ?.{0,40}\\b(weekly|daily|per week|per day|a week|a day|ukentlig|daglig|i uka|hver uke|hver dag|per uke|per dag|monthly|m[aå]nedlig)\\b|\\b(guaranteed|garantert|risk free|risikofri)\\b.{0,25}\\b(profit|returns?|income|avkastning|fortjeneste|inntekt|gevinst)\\b", FLAGS);
    private static final Pattern JOIN = Pattern.compile("\\b(dm me|message me|join|vip|bli med|send meg melding|kontakt meg|whatsapp|telegram)\\b", FLAGS);
    /** Top-level domains that scam links commonly use; used to find "bare" links such as dnb-login.com/verify. */
    private static final Set<String> TLDS = new HashSet<>(Arrays.asList("com", "no", "net", "org", "info", "biz", "xyz", "top", "online", "site", "shop", "store", "live", "app", "io", "co", "me", "ly", "gl",
        "cc", "tk", "ml", "ga", "cf", "gq", "click", "link", "icu", "cyou", "club", "vip", "work", "support", "help", "email", "cloud", "page", "dev", "pw", "ws", "su", "ru", "cn", "de", "uk", "se", "dk",
        "fi", "nl", "fr", "es", "it", "pl", "br", "in", "us", "eu", "ch", "at", "be", "ie", "tv", "to", "ai", "one", "fun", "space", "website", "tech", "digital", "world", "today", "life", "bar", "men", "loan"));
    private static final Pattern BARE = Pattern.compile("(?i)(?<![\\w@./:-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+([a-z]{2,24}))(?![\\w-])(?::[0-9]{1,5})?(?:/[^\\s<>\"']*)?");
    private ScamAnalyzer() {}

    private static boolean has(Pattern p, String text) { return p.matcher(text).find(); }

    /** A secret request counts unless a negation ("never share...", "del aldri...") sits in or just before the phrase. */
    private static boolean secretRequest(String norm) {
        Matcher m = SECRETS.matcher(norm);
        while (m.find()) {
            String window = norm.substring(Math.max(0, m.start() - 25), m.end());
            if (!NEGATION.matcher(window).find()) return true;
        }
        return false;
    }

    public static Analysis analyze(String input) {
        String text = input == null ? "" : input;
        if (text.trim().isEmpty() || text.length() > MAX_TEXT_LENGTH)
            return new Analysis(Analysis.Verdict.INSUFFICIENT_EVIDENCE,
                Arrays.asList(new Finding("INPUT_LIMIT", "Provide nonempty text of at most " + MAX_TEXT_LENGTH + " characters.")), "Message");
        String norm = TextNormalizer.forRules(text);
        List<Finding> fs = new ArrayList<>();
        boolean urgent = has(URGENT, norm);
        boolean threat = has(THREAT, norm);
        boolean secrets = secretRequest(norm);
        boolean payment = has(PAYMENT, norm);
        boolean irreversible = has(IRREVERSIBLE, norm);
        boolean prize = has(PRIZE, norm);
        boolean verify = has(VERIFY, norm);
        boolean parcelBase = has(PARCEL, norm) && has(PARCEL_FEE, norm) && payment; // only a signal with a link or time pressure: genuine customs notices exist
        boolean family = has(PARENT, norm) && has(NEW_NUMBER, norm) && (has(MONEY_ASK, norm) || payment);
        boolean giftcards = has(GIFTCARD_REQUEST, norm);
        boolean invest = has(INVEST_CONTEXT, norm) && has(RETURN_RATE, norm) && (has(JOIN, norm) || has(Pattern.compile("\\b(profit|returns?|avkastning|fortjeneste|weekly|daily)\\b"), norm));
        boolean utility = has(UNPAID, norm) && has(CUTOFF, norm);
        if (utility || (has(AUTHORITY, norm) && (payment || giftcards))) threat = true;
        if (urgent) fs.add(new Finding("URGENCY", "The message uses time pressure. Legitimate messages can also be urgent."));
        if (threat) fs.add(new Finding("THREAT_LANGUAGE", "The message mentions account restrictions or legal consequences."));
        if (verify && (urgent || threat)) fs.add(new Finding("VERIFY_REQUEST", "The message asks you to verify or update account, identity or card details under pressure."));
        if (secrets) fs.add(new Finding("SECRET_REQUEST", "The message appears to ask for a password, code, PIN, or BankID information. Do not disclose authentication secrets."));
        if (payment && irreversible) fs.add(new Finding("UNUSUAL_PAYMENT", "A payment request mentions gift cards or cryptocurrency, which may be difficult to recover."));
        if (prize && payment) fs.add(new Finding("PRIZE_PAYMENT", "The message combines a prize claim with payment language."));
        if (family) fs.add(new Finding("FAMILY_IMPERSONATION", "The message claims to be a family member with a new phone or number and asks for money. Call the person on their known number before sending anything."));
        if (giftcards) fs.add(new Finding("GIFTCARD_REQUEST", "The message asks you to buy gift cards or similar vouchers, which are hard to trace or recover and are a common payment method in scams."));
        if (invest) fs.add(new Finding("INVESTMENT_LURE", "The message promises high or guaranteed returns or crypto signals and invites you to join. Such promises are a hallmark of investment fraud."));

        int riskyLinks = 0, count = 0, anyLink = 0;
        boolean incomplete = false;
        List<String> candidates = new ArrayList<>();
        List<int[]> spans = new ArrayList<>();
        Matcher links = LINKS.matcher(text);
        int seen = 0;
        while (seen < MAX_LINKS && links.find()) {
            String link = links.group();
            while (!link.isEmpty() && ".,;!?)".indexOf(link.charAt(link.length() - 1)) >= 0) link = link.substring(0, link.length() - 1);
            candidates.add(link); spans.add(new int[] {links.start(), links.end()}); seen++;
        }
        boolean moreHttp = seen == MAX_LINKS && links.find();
        Matcher bare = BARE.matcher(text);
        while (candidates.size() < MAX_LINKS && bare.find()) {
            if (!TLDS.contains(bare.group(2).toLowerCase(Locale.ROOT))) continue;
            boolean inside = false;
            for (int[] s : spans) if (bare.start() >= s[0] && bare.start() < s[1]) inside = true;
            if (inside) continue;
            String link = bare.group();
            while (!link.isEmpty() && ".,;!?)".indexOf(link.charAt(link.length() - 1)) >= 0) link = link.substring(0, link.length() - 1);
            candidates.add(link);
        }
        for (String link : candidates) {
            Analysis result = UrlAnalyzer.analyze(link);
            count++; anyLink++;
            if (result.verdict == Analysis.Verdict.SUSPICIOUS || result.verdict == Analysis.Verdict.STRONG_INDICATORS || result.verdict == Analysis.Verdict.CONFIRMED_MALICIOUS) {
                riskyLinks++;
                fs.add(new Finding("SUSPICIOUS_LINK", "Embedded link " + count + " has URL warning signs. Analyze that link separately for details."));
            } else if (result.verdict == Analysis.Verdict.INSUFFICIENT_EVIDENCE) {
                incomplete = true;
                fs.add(new Finding("INCOMPLETE_LINK_ANALYSIS", "Embedded link " + count + " could not be fully assessed because its format or final destination is unresolved."));
            }
        }
        boolean parcelFee = parcelBase && (anyLink > 0 || urgent);
        if (parcelFee) fs.add(new Finding("PARCEL_FEE", "The message asks you to pay a fee for a parcel or delivery. Postal and courier scams commonly use small customs or delivery fees to collect card details."));
        if (moreHttp) {
            incomplete = true;
            fs.add(new Finding("LINK_SCAN_LIMIT", "Only the first " + MAX_LINKS + " embedded links were analyzed."));
        }
        int score = (secrets ? 2 : 0) + (payment && irreversible ? 2 : 0) + (prize && payment ? 2 : 0) + (riskyLinks > 0 ? 2 : 0)
            + (threat && urgent ? 2 : 0) + (verify && (urgent || threat) ? 2 : 0) + (verify && anyLink > 0 ? 1 : 0)
            + (parcelFee ? 2 : 0) + (family ? 2 : 0) + (giftcards ? 2 : 0) + (invest ? 2 : 0) + (utility && payment ? 2 : 0);
        if (score > 0 && (urgent || threat)) score++;
        Analysis.Verdict verdict = score >= 3 ? Analysis.Verdict.STRONG_INDICATORS : score >= 2 ? Analysis.Verdict.SUSPICIOUS : incomplete ? Analysis.Verdict.INSUFFICIENT_EVIDENCE : Analysis.Verdict.NO_KNOWN_WARNING_SIGNS;
        fs.add(new Finding("HEURISTIC_LIMITS", "Offline English/Norwegian rules can miss scams and misread quotations or context. No warning signs is not proof of safety. Authorship or AI provenance is not assessed."));
        return new Analysis(verdict, fs, "Message");
    }
}
