package com.aegis.core;

import java.util.regex.Pattern;

/** Decides whether pasted text should be analysed as a single link or as a message. The person can always override it. */
public final class InputKind {
    public enum Kind { LINK, MESSAGE }
    private static final Pattern SCHEME_URL = Pattern.compile("(?i)^[a-z][a-z0-9+.-]*://\\S+$");
    private static final Pattern BARE_HOST = Pattern.compile("(?iu)^(?:www\\.)?[\\p{L}\\p{N}-]+(?:\\.[\\p{L}\\p{N}-]+)*\\.[\\p{L}]{2,24}(?::[0-9]{1,5})?(?:[/?#]\\S*)?$");
    private static final Pattern IPV4 = Pattern.compile("^[0-9]{1,3}(?:\\.[0-9]{1,3}){3}(?::[0-9]{1,5})?(?:[/?#]\\S*)?$");
    private InputKind() {}

    public static Kind detect(String input) {
        if (input == null) return Kind.MESSAGE;
        String t = input.trim();
        if (t.isEmpty() || t.length() > UrlAnalyzer.MAX_URL_LENGTH) return Kind.MESSAGE;
        for (int i = 0; i < t.length(); i++) if (Character.isWhitespace(t.charAt(i))) return Kind.MESSAGE;
        if (SCHEME_URL.matcher(t).matches() || BARE_HOST.matcher(t).matches() || IPV4.matcher(t).matches()) return Kind.LINK;
        return Kind.MESSAGE;
    }
}
