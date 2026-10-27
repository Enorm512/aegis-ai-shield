package com.aegis.core;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Heuristic indicators of prompt injection or agent hijacking in UNTRUSTED text (web pages, emails, tool output,
 * messages from other agents). Indicators raise the level of scrutiny; they never prove or disprove an attack, and
 * their absence is not an assurance. Phrase rules run on the original text and on its normalised form (so zero-width
 * characters, look-alike letters, leetspeak and letter-spacing do not hide a phrase). Every scan runs under a
 * wall-clock budget; a timeout throws and callers fail closed.
 */
public final class InjectionIndicators {
    private static final Map<String, Pattern> PHRASES = new LinkedHashMap<>();
    private static final Pattern HIDDEN = Pattern.compile("[\\u200b\\u202a-\\u202e\\u2060-\\u2064\\ufeff\\x{E0000}-\\x{E007F}]");
    private static void rule(String code, String regex) { PHRASES.put(code, Pattern.compile(regex, Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE)); }
    static {
        rule("OVERRIDE_INSTRUCTIONS", "\\b(?:ignore|disregard|forget|override|bypass)\\b.{0,40}\\b(?:previous|prior|above|earlier|all|your|everything|what)\\b.{0,30}\\b(?:instructions?|rules?|prompts?|guidelines?|directions?|told|asked|said)\\b"
            + "|\\b(?:ignorer|glem|se bort fra)\\b.{0,40}\\b(?:tidligere|forrige|alle)\\b.{0,30}\\b(?:instruksjoner|regler)\\b"
            + "|\\bignoriere?\\b.{0,30}\\b(?:vorherigen|alle|obigen)\\b.{0,20}\\banweisungen\\b|\\bignora\\b.{0,30}\\b(?:instrucciones|anteriores)\\b|\\bignore[zs]?\\b.{0,30}\\b(?:instructions|pr[eé]c[eé]dentes)\\b");
        rule("ROLE_REASSIGNMENT", "\\b(?:from now on,? you|you are now (?:an? |in |the )?(?:unrestricted|jailbroken|dan\\b|developer mode|admin|root|system)|pretend (?:to be|you are)|new instructions?\\s*:|du er nå (?:en )?(?:uten begrensninger|administrator))");
        rule("SECRECY_FROM_USER", "\\b(?:do not|don t|dont|never)\\b.{0,30}\\b(?:tell|inform|notify|alert|ask)\\b.{0,20}\\b(?:the )?user\\b|\\bwithout (?:asking|telling|the user|confirm)|\\bno need to (?:ask|tell|inform|confirm)\\b|\\bikke fortell brukeren\\b|\\buten å spørre\\b");
        rule("EXFILTRATION_REQUEST", "\\b(?:send|forward|post|upload|email|exfiltrate|transmit)\\b.{0,60}\\b(?:passwords?|credentials?|secrets?|api keys?|tokens?|seed phrase|private keys?|passord|hemmeligheter|system prompt)\\b.{0,60}\\b(?:to|til)\\b");
        rule("TOOL_COMMAND", "\\b(?:run|execute|curl|wget|powershell|bash -c|rm -rf|chmod \\+x)\\b.{0,30}(?:https?://|\\||;|&&)");
        rule("PROMPT_EXTRACTION", "\\b(?:reveal|print|show|repeat|output)\\b.{0,30}\\b(?:system prompt|your instructions|hidden instructions|initial prompt)\\b");
    }
    private static final String[] SYSTEM_WORDS = {"system", "assistant", "developer", "admin"};
    private static final Pattern BRACKETS = Pattern.compile("\\[/?(?:system|inst)\\]|<\\|?(?:system|im_start)\\|?>", Pattern.CASE_INSENSITIVE);
    private InjectionIndicators() {}

    public static Set<String> scan(String untrusted) { return scan(untrusted, Deadline.in(SensitiveData.DEFAULT_BUDGET_MILLIS)); }

    /** deadlineNanos is a System.nanoTime() value (see Deadline.in). Throws Deadline.ScanTimeout when exceeded. */
    static Set<String> scan(String untrusted, long deadlineNanos) {
        Set<String> out = new LinkedHashSet<>();
        if (untrusted == null || untrusted.isEmpty()) return out;
        String t = untrusted.length() > 100_000 ? untrusted.substring(0, 100_000) : untrusted;
        String norm = TextNormalizer.forRules(t);
        CharSequence raw = new Deadline(t, deadlineNanos), normalised = new Deadline(norm, deadlineNanos);
        for (Map.Entry<String, Pattern> r : PHRASES.entrySet()) {
            if (r.getValue().matcher(raw).find() || r.getValue().matcher(normalised).find()) out.add(r.getKey());
        }
        if (hasFakeSystemLine(t) || BRACKETS.matcher(raw).find()) out.add("FAKE_SYSTEM_MESSAGE");
        if (HIDDEN.matcher(raw).find() || hasHiddenComment(t)) out.add("HIDDEN_TEXT_MARKERS");
        return out;
    }

    /** A line that starts (after spaces or tabs) with "system:", "assistant:", "developer:" or "admin:". Linear time. */
    private static boolean hasFakeSystemLine(String t) {
        int n = t.length(), i = 0;
        while (i < n) {
            int j = i;
            while (j < n && (t.charAt(j) == ' ' || t.charAt(j) == '\t')) j++;
            for (String w : SYSTEM_WORDS) {
                if (t.regionMatches(true, j, w, 0, w.length())) {
                    int k = j + w.length();
                    while (k < n && (t.charAt(k) == ' ' || t.charAt(k) == '\t')) k++;
                    if (k < n && t.charAt(k) == ':') return true;
                }
            }
            int nl = t.indexOf('\n', i);
            if (nl < 0) break;
            i = nl + 1;
        }
        return false;
    }

    /** An HTML comment whose first 300 characters mention instructions to an assistant. Plain scanning, no backtracking. */
    private static boolean hasHiddenComment(String t) {
        int i = 0;
        while ((i = t.indexOf("<!--", i)) >= 0) {
            int from = i + 4, limit = Math.min(t.length(), from + 300);
            String seg = t.substring(from, limit);
            int close = seg.indexOf("-->"); // bounded search: never scans past the 300-character window
            if (close >= 0) seg = seg.substring(0, close);
            seg = seg.toLowerCase(Locale.ROOT);
            if (seg.contains("instruction") || seg.contains("ignore") || seg.contains("assistant")) return true;
            i = from;
        }
        return false;
    }
}
