package com.aegis.core;

import java.util.*;
import java.util.regex.*;

/**
 * Detects kinds of sensitive data in text. Only kinds are returned; matched values are never kept or logged.
 * Every scan runs under a wall-clock budget (see {@link Deadline}); a timeout throws and callers fail closed.
 */
public final class SensitiveData {
    public enum Kind { PRIVATE_KEY, CLOUD_KEY, ACCESS_TOKEN, PASSWORD_ASSIGNMENT, PAYMENT_CARD, IBAN, NATIONAL_ID }
    /** Kinds that are credentials rather than personal data. */
    public static final Set<Kind> SECRETS = Collections.unmodifiableSet(EnumSet.of(Kind.PRIVATE_KEY, Kind.CLOUD_KEY, Kind.ACCESS_TOKEN, Kind.PASSWORD_ASSIGNMENT));
    public static final int MAX_SCAN = 200_000;
    public static final long DEFAULT_BUDGET_MILLIS = 1500;

    private static final Pattern PRIVATE_KEY = Pattern.compile("-----BEGIN [A-Z ]{0,30}PRIVATE KEY(?: BLOCK)?-----");
    private static final Pattern CLOUD = Pattern.compile("\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b|(?i:aws[_-]?secret[_-]?(?:access[_-]?)?key)[\"']?\\s{0,20}[:=]|\\bAIza[0-9A-Za-z_-]{35}\\b|\\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\\b");
    private static final Pattern TOKEN = Pattern.compile("\\bgh[pousr]_[A-Za-z0-9]{30,}\\b|\\bxox[abprs]-[A-Za-z0-9-]{10,}|\\bsk-[A-Za-z0-9_-]{20,}|(?i:\\bBearer)\\s{1,5}[A-Za-z0-9._~+/=-]{20,}|(?i:authorization)[\"']?\\s{0,10}:\\s{0,10}[\"']?(?i:basic)\\s{1,5}[A-Za-z0-9+/=]{8,}"
        + "|\\b[a-z][a-z0-9+.-]{2,15}://[^\\s:/@]{1,64}:[^\\s@/]{3,64}@");
    private static final Pattern PASSWORD = Pattern.compile("(?i)(password|passwd|pwd|passord|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)(?:[_-][a-z]{1,12}){0,3}[\"']?\\s{0,20}[:=]\\s{0,20}[\"']?([^\\s\"']{6,})");
    private static final Pattern PLACEHOLDER = Pattern.compile("(?i)^(\\*+|x{3,}|\\$\\{.*|<.*|%.*|\\[.*|required|obligatorisk|none|null|undefined|changeme|example|os\\.environ.*|process\\.env.*|getenv.*|env\\[.*)$");
    private static final Pattern DIGITS = Pattern.compile("(?<![0-9])[0-9](?:[ .-]?[0-9]){10,18}(?![0-9])");
    private static final Pattern IBAN_RE = Pattern.compile("\\b[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]){11,30}\\b");

    private SensitiveData() {}

    public static Set<Kind> scan(String text) { return scan(text, Deadline.in(DEFAULT_BUDGET_MILLIS)); }

    /** deadlineNanos is a System.nanoTime() value (see Deadline.in). Throws Deadline.ScanTimeout when exceeded. */
    static Set<Kind> scan(String text, long deadlineNanos) {
        Set<Kind> out = EnumSet.noneOf(Kind.class);
        if (text == null || text.isEmpty()) return out;
        String s = text.length() > MAX_SCAN ? text.substring(0, MAX_SCAN) : text;
        CharSequence t = new Deadline(s, deadlineNanos);
        if (PRIVATE_KEY.matcher(t).find()) out.add(Kind.PRIVATE_KEY);
        if (CLOUD.matcher(t).find()) out.add(Kind.CLOUD_KEY);
        if (TOKEN.matcher(t).find() || hasJwt(s)) out.add(Kind.ACCESS_TOKEN);
        Matcher pw = PASSWORD.matcher(t);
        while (pw.find()) { if (!PLACEHOLDER.matcher(pw.group(2)).matches()) { out.add(Kind.PASSWORD_ASSIGNMENT); break; } }
        Matcher d = DIGITS.matcher(t);
        while (d.find()) {
            String digits = d.group().replaceAll("[ .-]", "");
            if (digits.length() >= 15 && digits.length() <= 19 && "23456".indexOf(digits.charAt(0)) >= 0 && luhn(digits)) out.add(Kind.PAYMENT_CARD);
            if (digits.length() == 11 && nationalId(digits)) out.add(Kind.NATIONAL_ID);
        }
        Matcher i = IBAN_RE.matcher(t);
        while (i.find()) if (iban(i.group().replace(" ", ""))) out.add(Kind.IBAN);
        return out;
    }

    /** JSON web token: three base64url segments of at least 8 characters, the first starting with "eyJ". Linear time. */
    static boolean hasJwt(String t) {
        int n = t.length(), i = 0;
        while ((i = t.indexOf("eyJ", i)) >= 0) {
            int j = i, seg = 0;
            boolean ok = true;
            for (; seg < 3 && ok; seg++) {
                int start = j;
                while (j < n && j - i < 4096 && isB64url(t.charAt(j))) j++;
                if (j - start < 8) ok = false;
                else if (seg < 2) { if (j < n && t.charAt(j) == '.') j++; else ok = false; }
            }
            if (ok) return true;
            i = Math.max(i + 3, j); // any start inside this run would end at the same place
        }
        return false;
    }
    private static boolean isB64url(char c) { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'; }

    static boolean luhn(String digits) {
        int sum = 0; boolean dbl = false;
        for (int i = digits.length() - 1; i >= 0; i--) {
            int n = digits.charAt(i) - '0';
            if (dbl) { n *= 2; if (n > 9) n -= 9; }
            sum += n; dbl = !dbl;
        }
        return sum % 10 == 0 && !digits.chars().allMatch(c -> c == digits.charAt(0));
    }

    /** Norwegian fødselsnummer / D-number: plausible date part and both mod-11 control digits. */
    static boolean nationalId(String s) {
        int[] d = new int[11];
        for (int i = 0; i < 11; i++) d[i] = s.charAt(i) - '0';
        int day = d[0] * 10 + d[1], month = d[2] * 10 + d[3];
        if (day > 40) day -= 40; // D-number
        if (day < 1 || day > 31 || month < 1 || month > 12) return false;
        int[] w1 = {3, 7, 6, 1, 8, 9, 4, 5, 2}, w2 = {5, 4, 3, 2, 7, 6, 5, 4, 3, 2};
        int s1 = 0; for (int i = 0; i < 9; i++) s1 += w1[i] * d[i];
        int k1 = 11 - (s1 % 11); if (k1 == 11) k1 = 0;
        if (k1 == 10 || k1 != d[9]) return false;
        int s2 = 0; for (int i = 0; i < 9; i++) s2 += w2[i] * d[i]; s2 += w2[9] * k1;
        int k2 = 11 - (s2 % 11); if (k2 == 11) k2 = 0;
        return k2 != 10 && k2 == d[10];
    }

    static boolean iban(String s) {
        if (s.length() < 15 || s.length() > 34) return false;
        String r = s.substring(4) + s.substring(0, 4);
        int mod = 0;
        for (int i = 0; i < r.length(); i++) {
            char c = r.charAt(i);
            int v = Character.isDigit(c) ? c - '0' : c - 'A' + 10;
            if (v < 0 || v > 35) return false;
            mod = (v > 9 ? mod * 100 + v : mod * 10 + v) % 97;
        }
        return mod == 1;
    }
}
