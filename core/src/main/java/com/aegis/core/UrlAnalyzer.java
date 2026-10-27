package com.aegis.core;

import java.net.IDN;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;

/** Bounded, offline URL analysis. Never resolves hosts or visits links. */
public final class UrlAnalyzer {
    public static final int MAX_URL_LENGTH = 8192;
    private static final Map<String, List<String>> BRANDS = new LinkedHashMap<>();
    static {
        BRANDS.put("bankid", Arrays.asList("bankid.no", "bankid.com", "bankid.se"));
        BRANDS.put("paypal", Arrays.asList("paypal.com", "paypalobjects.com"));
        BRANDS.put("microsoft", Arrays.asList("microsoft.com", "microsoftonline.com", "live.com"));
        BRANDS.put("vipps", Arrays.asList("vipps.no", "vippsmobilepay.com"));
    }
    /** Cheap or abuse-heavy top-level domains that appear far more often in phishing than in everyday links. Weak signal: adds 1 point, never flags a link alone. */
    private static final Set<String> RISKY_TLDS = new HashSet<>(Arrays.asList("top", "xyz", "icu", "cyou", "click", "link", "buzz", "sbs", "cfd", "rest", "monster", "quest", "tk", "ml", "ga", "cf", "gq", "cc", "pw", "ws", "su", "work", "support", "help", "loan", "men", "bar", "fit", "autos", "bond", "lol", "mom", "uno", "hair", "beauty", "skin", "makeup", "yachts"));
    private UrlAnalyzer() {}

    public static Analysis analyze(String input) {
        String raw = input == null ? "" : input;
        if (raw.length() > MAX_URL_LENGTH)
            return invalid(raw, "Provide a URL of at most " + MAX_URL_LENGTH + " characters.");
        // Reject controls before trimming ordinary surrounding spaces.
        for (int i = 0; i < raw.length(); i++) {
            if (Character.isISOControl(raw.charAt(i)))
                return invalid(raw, "The URL contains control characters.");
        }
        String text = raw.trim();
        List<Finding> fs = new ArrayList<>();
        if (text.isEmpty() || text.length() > MAX_URL_LENGTH)
            return invalid(text, "Provide a URL of at most " + MAX_URL_LENGTH + " characters.");
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (Character.isISOControl(c) || Character.isWhitespace(c) || c == '\\' ||
                Character.getType(c) == Character.FORMAT || Character.isSurrogate(c) &&
                (!Character.isHighSurrogate(c) || i + 1 >= text.length() || !Character.isLowSurrogate(text.charAt(++i))))
                return invalid(text, "The URL contains unsupported whitespace, control, or malformed Unicode characters.");
        }
        boolean assumed = !text.contains("://");
        if (assumed && text.matches("(?i)^[a-z][a-z0-9+.-]*:.*") && !text.matches("^[^/:]+:[0-9]+(?:/.*)?$"))
            return invalid(text, "Only HTTP and HTTPS URLs can be analyzed.");
        String candidate = assumed ? "https://" + text : text;
        try {
            URI uri = new URI(candidate);
            String scheme = uri.getScheme();
            if (!("https".equalsIgnoreCase(scheme) || "http".equalsIgnoreCase(scheme)))
                return invalid(text, "Only HTTP and HTTPS URLs can be analyzed.");
            String auth = uri.getRawAuthority();
            if (auth == null || auth.isEmpty()) return invalid(text, "A host is required.");
            int at = auth.lastIndexOf('@');
            boolean userInfo = at >= 0;
            if (userInfo) {
                if (at != auth.indexOf('@')) return invalid(text, "The URL has ambiguous user information.");
                auth = auth.substring(at + 1);
            }
            String host;
            String port = null;
            boolean ip = false;
            if (auth.startsWith("[")) {
                int close = auth.indexOf(']');
                if (close < 0) return invalid(text, "The IPv6 address is malformed.");
                host = auth.substring(1, close);
                if (!validIpv6(host)) return invalid(text, "The IPv6 address is malformed or unsupported.");
                String remainder = auth.substring(close + 1);
                if (!remainder.isEmpty()) {
                    if (!remainder.startsWith(":")) return invalid(text, "The host is malformed.");
                    port = remainder.substring(1);
                }
                ip = true;
            } else {
                int colon = auth.lastIndexOf(':');
                host = colon < 0 ? auth : auth.substring(0, colon);
                if (colon >= 0) port = auth.substring(colon + 1);
            }
            if (port != null && (!port.matches("[0-9]{1,5}") || Integer.parseInt(port) > 65535 || Integer.parseInt(port) == 0))
                return invalid(text, "The port must be between 1 and 65535.");
            if (host.endsWith(".")) host = host.substring(0, host.length()-1);
            if (host.isEmpty() || host.contains("%")) return invalid(text, "The host is empty or uses unsupported escaping.");
            String ascii = ip ? host.toLowerCase(Locale.ROOT) : IDN.toASCII(host, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT);
            if (ascii.length() > 253 || ascii.isEmpty()) return invalid(text, "The host name is too long or empty.");
            if (!ip) {
                for (String label : ascii.split("\\.", -1)) if (label.isEmpty() || label.length() > 63)
                    return invalid(text, "The host contains an invalid label.");
                if (ascii.matches("[0-9.]+")) {
                    if (!validIpv4(ascii)) return invalid(text, "Only canonical dotted IPv4 addresses are supported.");
                    ip = true;
                }
                if (ascii.matches("(?i)(?:0x[0-9a-f]+|[0-9]+)(?:\\.(?:0x[0-9a-f]+|[0-9]+))*") && !ip)
                    return invalid(text, "Ambiguous numeric host forms are unsupported.");
            }
            fs.add(new Finding("HOST", "Destination host: " + ascii));
            if (assumed) fs.add(new Finding("SCHEME_ASSUMED", "HTTPS was assumed because no scheme was supplied."));
            if ("http".equalsIgnoreCase(scheme)) fs.add(new Finding("UNENCRYPTED_HTTP", "HTTP does not encrypt traffic. This alone does not establish malicious intent."));
            int score = 0;
            if (userInfo) { score += 2; fs.add(new Finding("USERINFO", "Text before @ is user information; the destination is " + ascii + ".")); }
            if (ip) fs.add(new Finding("IP_LITERAL", "The destination is an IP address; no DNS lookup was performed."));
            if (!ip && (!ascii.equalsIgnoreCase(host) || ascii.contains("xn--"))) {
                fs.add(new Finding("INTERNATIONALIZED_HOST", "The host uses internationalized spelling. ASCII form: " + ascii + "; display form: " + IDN.toUnicode(ascii) + ". This alone is not malicious."));
                String unicode = IDN.toUnicode(ascii);
                if (mixedScriptLabel(unicode)) { score += 2; fs.add(new Finding("MIXED_SCRIPT_HOST", "A host label mixes Latin with Cyrillic or Greek characters, which can create visual confusion.")); }
            }
            boolean unresolved = Arrays.asList("bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "shorturl.at", "cutt.ly", "rb.gy").contains(ascii);
            if (unresolved) fs.add(new Finding("UNRESOLVED_SHORT_LINK", "This is a known link-shortening host. The final destination is unknown because no link was visited."));
            boolean tokenHit = false;
            if (!ip) {
                java.util.Optional<LookalikeDetector.TokenHit> hit = LookalikeDetector.brandInLabels(ascii);
                if (hit.isPresent()) {
                    tokenHit = true;
                    LookalikeDetector.TokenHit h = hit.get();
                    score += h.score() + (h.skeleton() ? 1 : 0);
                    fs.add(new Finding(h.skeleton() ? "LOOKALIKE_BRAND" : "BRAND_OUTSIDE_KNOWN_DOMAIN", h.skeleton()
                        ? "A word in the host name imitates " + h.brand() + " (look-alike characters or spelling) but the host is not one of its official domains. Some look-alikes are unrelated legitimate businesses; verify independently."
                        : "The host name uses the brand name " + h.brand() + (h.inRegistrableLabel() ? "" : " in a sub-domain of another site") + ", but it is not one of its official domains. This can be legitimate; verify independently."));
                }
            }
            if (!ip && !tokenHit) {
                java.util.Optional<LookalikeDetector.Match> look = LookalikeDetector.check(ascii);
                if (look.isPresent()) {
                    boolean skeleton = look.get().kind() == LookalikeDetector.Kind.SKELETON;
                    score += skeleton ? 3 : 2;
                    fs.add(new Finding("LOOKALIKE_BRAND", "The domain name resembles " + look.get().brand() + (skeleton ? " (look-alike characters or spelling)" : " (one character different)")
                        + " but is not one of its official domains. Some look-alikes are unrelated legitimate businesses; verify independently."));
                }
            }
            if (!ip) {
                String tldLabel = ascii.substring(ascii.lastIndexOf('.') + 1);
                if (RISKY_TLDS.contains(tldLabel)) { score += 1; fs.add(new Finding("SUSPICIOUS_TLD", "The address ends in ." + tldLabel + ", a cheap domain ending that is used far more often by scam sites than by established services. Many legitimate sites also use it; this only adds a little weight.")); }
            }
            String query = uri.getRawQuery();
            if (query != null) {
                for (String pair : query.split("&", 50)) {
                    int eq = pair.indexOf('=');
                    if (eq <= 0) continue;
                    String key = pair.substring(0, eq).toLowerCase(Locale.ROOT), value = pair.substring(eq + 1).toLowerCase(Locale.ROOT);
                    boolean redirectKey = key.equals("url") || key.equals("redirect") || key.equals("redirect_uri") || key.equals("redirecturl") || key.equals("next")
                        || key.equals("return") || key.equals("returnurl") || key.equals("goto") || key.equals("dest") || key.equals("destination") || key.equals("continue") || key.equals("target");
                    if (redirectKey && (value.startsWith("http") || value.startsWith("%68%74%74%70") || value.startsWith("//") || value.startsWith("%2f%2f"))) {
                        score += 1;
                        fs.add(new Finding("REDIRECT_PARAMETER", "The link carries a parameter (" + key.replaceAll("[^a-z_]", "?") + ") that points to another web address, which can forward you somewhere else. Common in legitimate sign-in flows; check where it leads."));
                        break;
                    }
                }
            }
            return new Analysis(score >= 4 ? Analysis.Verdict.STRONG_INDICATORS : score >= 2 ? Analysis.Verdict.SUSPICIOUS : unresolved ? Analysis.Verdict.INSUFFICIENT_EVIDENCE : Analysis.Verdict.NO_KNOWN_WARNING_SIGNS, fs, text);
        } catch (URISyntaxException | IllegalArgumentException ex) {
            return invalid(text, "The URL is malformed or uses an unsupported host format.");
        }
    }

    private static Analysis invalid(String text, String detail) {
        return new Analysis(Analysis.Verdict.INSUFFICIENT_EVIDENCE, Arrays.asList(new Finding("INVALID_URL", detail)), text.length() > MAX_URL_LENGTH ? text.substring(0, MAX_URL_LENGTH) : text);
    }
    private static boolean mixedScriptLabel(String host) {
        for (String label : host.split("\\.")) {
            boolean latin=false, other=false;
            for (int cp : label.codePoints().toArray()) {
                Character.UnicodeScript s = Character.UnicodeScript.of(cp);
                latin |= s == Character.UnicodeScript.LATIN;
                other |= s == Character.UnicodeScript.CYRILLIC || s == Character.UnicodeScript.GREEK;
            }
            if (latin && other) return true;
        }
        return false;
    }
    static boolean validIpv4(String host) {
        String[] parts = host.split("\\.", -1);
        if (parts.length != 4) return false;
        for (String part : parts) if (!part.matches("0|[1-9][0-9]{0,2}") || Integer.parseInt(part) > 255) return false;
        return true;
    }
    static boolean validIpv6(String host) {
        if (host.isEmpty() || host.contains("%") || !host.matches("[0-9a-fA-F:.]+")) return false;
        int compressed = host.indexOf("::");
        if (compressed != host.lastIndexOf("::")) return false;
        if (compressed < 0 && (host.startsWith(":") || host.endsWith(":"))) return false;
        String[] groups = host.split(":", -1);
        int count = 0;
        for (int i=0;i<groups.length;i++) {
            String group=groups[i];
            if (group.isEmpty()) continue;
            if (group.contains(".")) {
                if (i != groups.length-1 || !validIpv4(group)) return false;
                count += 2;
            } else { if (!group.matches("[0-9a-fA-F]{1,4}")) return false; count++; }
        }
        return compressed >= 0 ? count < 8 && !host.contains(":::") : count == 8;
    }
}
