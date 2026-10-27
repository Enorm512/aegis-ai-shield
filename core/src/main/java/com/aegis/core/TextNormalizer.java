package com.aegis.core;

import java.text.Normalizer;
import java.util.*;

/** Deterministic text canonicalisation applied before classification and before the scam rules. Treats all input as untrusted data. */
public final class TextNormalizer {
    public static final int MAX_CHARS = 20_000;
    private static final int MAX_TOKEN = 32;
    private static final Map<Character, Character> CONFUSABLE = new HashMap<>();
    static {
        // Cyrillic / Greek letters commonly substituted for Latin ones (lowercase; input is lowercased first).
        String from = "аеорсухіјѕкмтοανριԁнвг";
        String to   = "aeopcyxijskmtoavpidhbr";
        if (from.length() != to.length()) throw new IllegalStateException("confusable table");
        for (int i = 0; i < from.length(); i++) CONFUSABLE.put(from.charAt(i), to.charAt(i));
    }
    private TextNormalizer() {}

    /** Maps a Cyrillic/Greek letter that imitates a Latin one to that Latin letter; other characters unchanged. */
    static char foldConfusable(char c) { Character m = CONFUSABLE.get(c); return m == null ? c : m; }

    /**
     * The text as the scam rules should see it: tokens joined by single spaces. URLs are replaced by "urltoken"
     * (links are judged separately from the original text), numbers collapse to "0".
     */
    public static String forRules(String input) { return String.join(" ", tokens(input)); }

    /** URLs become "urltoken"; number runs become "0". Returns lowercase tokens. */
    public static List<String> tokens(String input) {
        if (input == null) return Collections.emptyList();
        String s = input.length() > MAX_CHARS ? input.substring(0, MAX_CHARS) : input;
        s = Normalizer.normalize(s, Normalizer.Form.NFKC);
        StringBuilder clean = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); ) {
            int cp = s.codePointAt(i);
            i += Character.charCount(cp);
            int type = Character.getType(cp);
            if (type == Character.FORMAT || type == Character.CONTROL && !Character.isWhitespace(cp)) continue; // zero-width, bidi, soft hyphen
            if (cp >= 0xE0000 && cp <= 0xE007F) continue; // Unicode tag characters used for hidden text
            cp = Character.toLowerCase(cp); // lowercase BEFORE folding so capital Cyrillic/Greek lookalikes are caught too
            if (cp < 0x10000 && CONFUSABLE.containsKey((char) cp)) cp = CONFUSABLE.get((char) cp);
            clean.appendCodePoint(Character.isWhitespace(cp) ? ' ' : cp);
        }
        String lower = clean.toString().toLowerCase(Locale.ROOT);
        lower = lower.replaceAll("(?:https?://|www\\.)\\S+", " urltoken ");
        List<String> raw = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        for (int i = 0; i <= lower.length(); i++) {
            char c = i < lower.length() ? lower.charAt(i) : ' ';
            boolean word = Character.isLetterOrDigit(c) || c == '@' || c == '$';
            if (word) cur.append(c);
            else if (cur.length() > 0) { raw.add(cur.toString()); cur.setLength(0); }
        }
        List<String> out = new ArrayList<>();
        StringBuilder spelled = new StringBuilder();
        int singles = 0;
        for (String t : raw) {
            String tok = fold(t);
            if (tok.length() == 1 && Character.isLetter(tok.charAt(0))) { spelled.append(tok); singles++; continue; }
            flushSpelled(out, spelled, singles); singles = 0; spelled.setLength(0);
            if (!tok.isEmpty()) out.add(tok.length() > MAX_TOKEN ? tok.substring(0, MAX_TOKEN) : tok);
        }
        flushSpelled(out, spelled, singles);
        return out;
    }

    /** "p a s s w o r d" (4+ single letters in a row) is rejoined; shorter runs are kept as separate tokens. */
    private static void flushSpelled(List<String> out, StringBuilder spelled, int singles) {
        if (singles == 0) return;
        if (singles >= 4) out.add(spelled.length() > MAX_TOKEN ? spelled.substring(0, MAX_TOKEN) : spelled.toString());
        else for (int i = 0; i < spelled.length(); i++) out.add(String.valueOf(spelled.charAt(i)));
    }

    /**
     * Leetspeak is undone only for a digit or symbol that sits BETWEEN two letters (p4ssword, passw0rd, p@ssword),
     * so amounts, times and codes ("$1000", "10pm", "4G", "covid19") are left alone. Pure numbers become "0".
     */
    private static String fold(String t) {
        boolean letters = false, digits = false;
        for (int i = 0; i < t.length(); i++) { char c = t.charAt(i); letters |= Character.isLetter(c); digits |= Character.isDigit(c); }
        if (!letters) return digits ? "0" : "";
        StringBuilder b = new StringBuilder(t.length());
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            boolean between = i > 0 && i + 1 < t.length() && Character.isLetter(t.charAt(i - 1)) && Character.isLetter(t.charAt(i + 1));
            if (between) {
                switch (c) {
                    case '0' -> { b.append('o'); continue; } case '1' -> { b.append('i'); continue; } case '3' -> { b.append('e'); continue; }
                    case '4', '@' -> { b.append('a'); continue; } case '5', '$' -> { b.append('s'); continue; } case '7' -> { b.append('t'); continue; }
                    default -> { }
                }
            }
            if (Character.isLetterOrDigit(c)) b.append(c);
        }
        return b.toString();
    }
}
