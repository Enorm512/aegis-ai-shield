package com.aegis.core;

import java.io.IOException;
import java.net.IDN;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/**
 * Publisher-side tool (never used by the app at runtime): turns local copies of licence-cleared domain lists into
 * entry lines for ThreatBundleTool, plus an attribution file. It does no network access; download the lists yourself
 * after reading each source's terms.
 *
 *   java com.aegis.core.FeedBuilder <sources.txt> <allowlist.txt or -> <out-entries.txt> <out-attribution.txt> [maxEntries]
 *
 * sources.txt, one source per line (# comments allowed):
 *   id|licence|category|confidence|path|attribution
 *   e.g. phishdb|MIT|PHISHING|SUSPICIOUS|lists/phishing-domains-ACTIVE.txt|Phishing.Database, https://github.com/Phishing-Database/Phishing.Database
 * Accepted list formats per line: plain domain, hosts file ("0.0.0.0 name"), adblock ("||name^"), or a full URL.
 * A source whose licence is not on the allowed list is refused; licences with conditions (CC-BY) need the attribution field.
 * Every domain passes the same checks the app's verifier applies, and protected or allowlisted names are dropped,
 * so a bad upstream entry cannot make the app block a bank, a government service or a connectivity check.
 */
public final class FeedBuilder {
    private FeedBuilder() {}

    /** Licences whose terms allow bundling in a free or commercial app. Anything else needs a human licence review first. */
    public static final Set<String> ALLOWED_LICENCES = Collections.unmodifiableSet(new LinkedHashSet<>(Arrays.asList(
        "OWN", "CC0-1.0", "Unlicense", "MIT", "0BSD", "ISC", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "CC-BY-4.0")));
    private static final Set<String> NEEDS_ATTRIBUTION = new HashSet<>(Arrays.asList("MIT", "ISC", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "CC-BY-4.0"));
    private static final Set<String> CATEGORIES = new HashSet<>(Arrays.asList("MALWARE", "PHISHING", "SCAM", "UNWANTED"));
    private static final List<String> CONFIDENCE = Arrays.asList("SUSPICIOUS", "STRONG", "CONFIRMED");
    public static final int DEFAULT_MAX = 500_000;

    public record Source(String id, String licence, String category, String confidence, Path path, String attribution) {}
    public record SourceStats(Source source, int lines, int accepted, Map<String, Integer> dropped, String sha256) {}
    public record Result(List<String> entries, List<SourceStats> stats, boolean truncated) {}

    public static final class SourceException extends Exception {
        public SourceException(String m) { super(m); }
    }

    public static List<Source> parseSources(Path manifest) throws IOException, SourceException {
        List<Source> out = new ArrayList<>();
        Set<String> ids = new HashSet<>();
        int n = 0;
        for (String raw : Files.readAllLines(manifest, StandardCharsets.UTF_8)) {
            n++;
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            String[] f = line.split("\\|", 6);
            if (f.length != 6) throw new SourceException("line " + n + ": expected id|licence|category|confidence|path|attribution");
            String id = f[0].trim(), lic = f[1].trim(), cat = f[2].trim(), conf = f[3].trim(), attr = f[5].trim();
            if (!id.matches("[A-Za-z0-9._-]{1,64}")) throw new SourceException("line " + n + ": id must match [A-Za-z0-9._-]{1,64}: " + id);
            if (!ids.add(id)) throw new SourceException("line " + n + ": duplicate id " + id);
            if (!ALLOWED_LICENCES.contains(lic)) throw new SourceException("line " + n + ": licence '" + lic + "' is not on the allowed list " + ALLOWED_LICENCES + "; get a licence review first");
            if (NEEDS_ATTRIBUTION.contains(lic) && attr.isEmpty()) throw new SourceException("line " + n + ": licence " + lic + " requires an attribution text");
            if (!CATEGORIES.contains(cat)) throw new SourceException("line " + n + ": unknown category " + cat);
            if (!CONFIDENCE.contains(conf)) throw new SourceException("line " + n + ": unknown confidence " + conf);
            Path p = manifest.toAbsolutePath().getParent().resolve(f[4].trim()).normalize();
            out.add(new Source(id, lic, cat, conf, p, attr));
        }
        return out;
    }

    /** Extracts one candidate host from a list line, or null for comments, blanks and unsupported forms. */
    static String hostOf(String raw) {
        String s = raw.trim();
        int hash = s.indexOf('#');
        if (hash >= 0) s = s.substring(0, hash).trim();
        if (s.isEmpty() || s.startsWith("!") || s.startsWith("[")) return null;
        if (s.startsWith("||")) { // adblock: ||name^ or ||name^$options
            s = s.substring(2);
            int end = 0;
            while (end < s.length() && "^/$|".indexOf(s.charAt(end)) < 0) end++;
            s = s.substring(0, end);
        } else if (s.contains("://")) {
            s = s.substring(s.indexOf("://") + 3);
            int end = 0;
            while (end < s.length() && "/?#".indexOf(s.charAt(end)) < 0) end++;
            s = s.substring(0, end);
            int at = s.lastIndexOf('@');
            if (at >= 0) s = s.substring(at + 1);
            if (s.startsWith("[")) return null; // IPv6 literal
            int colon = s.lastIndexOf(':');
            if (colon >= 0) s = s.substring(0, colon);
        } else {
            String[] parts = s.split("\\s+");
            if (parts.length >= 2 && (parts[0].equals("0.0.0.0") || parts[0].equals("127.0.0.1") || parts[0].equals("::") || parts[0].equals("::1"))) s = parts[1];
            else if (parts.length != 1) return null;
        }
        return s.isEmpty() ? null : s;
    }

    /** Lowercase punycode form that the app's verifier would accept, or a short reason why not. */
    static String normalise(String host, StringBuilder reason) {
        String h = host.toLowerCase(Locale.ROOT);
        if (h.endsWith(".")) h = h.substring(0, h.length() - 1);
        if (h.startsWith("*.") || h.contains("*")) { reason.append("wildcard"); return null; }
        if (h.startsWith("www.")) h = h.substring(4);
        try { h = IDN.toASCII(h, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT); }
        catch (IllegalArgumentException e) { reason.append("invalid"); return null; }
        if (h.matches("[0-9.]+")) { reason.append("ip"); return null; }
        if (!ThreatBundleVerifier.validDomain(h)) { reason.append("invalid-or-public-suffix"); return null; }
        if (ProtectedDomains.isProtectedEntry(h)) { reason.append("protected"); return null; }
        return h;
    }

    static boolean allowlisted(String d, Set<String> allow) {
        if (allow.contains(d)) return true;
        for (int i = d.indexOf('.'); i >= 0; i = d.indexOf('.', i + 1)) if (allow.contains(d.substring(i + 1))) return true;
        return false;
    }

    public static Set<String> loadAllowlist(Path p) throws IOException {
        Set<String> out = new HashSet<>();
        if (p == null) return out;
        for (String raw : Files.readAllLines(p, StandardCharsets.UTF_8)) {
            String h = hostOf(raw);
            if (h == null) continue;
            String d = h.toLowerCase(Locale.ROOT);
            try { d = IDN.toASCII(d.endsWith(".") ? d.substring(0, d.length() - 1) : d).toLowerCase(Locale.ROOT); } catch (IllegalArgumentException e) { continue; }
            out.add(d);
        }
        return out;
    }

    public static Result build(List<Source> sources, Set<String> allow, int max) throws IOException {
        Map<String, String[]> merged = new TreeMap<>(); // domain -> {category, confidence, label}
        List<SourceStats> stats = new ArrayList<>();
        for (Source src : sources) {
            byte[] bytes = Files.readAllBytes(src.path());
            Map<String, Integer> dropped = new TreeMap<>();
            int lines = 0, accepted = 0;
            for (String line : new String(bytes, StandardCharsets.UTF_8).split("\r?\n")) {
                String host = hostOf(line);
                if (host == null) continue;
                lines++;
                StringBuilder why = new StringBuilder();
                String d = normalise(host, why);
                if (d == null) { dropped.merge(why.toString(), 1, Integer::sum); continue; }
                if (allowlisted(d, allow)) { dropped.merge("allowlisted", 1, Integer::sum); continue; }
                String[] prev = merged.get(d);
                if (prev == null) { merged.put(d, new String[] {src.category(), src.confidence(), src.id()}); accepted++; }
                else {
                    if (CONFIDENCE.indexOf(src.confidence()) > CONFIDENCE.indexOf(prev[1])) merged.put(d, new String[] {src.category(), src.confidence(), src.id()});
                    dropped.merge("duplicate", 1, Integer::sum);
                }
            }
            stats.add(new SourceStats(src, lines, accepted, dropped, sha256(bytes)));
        }
        List<String> entries = new ArrayList<>();
        boolean truncated = false;
        // Highest confidence first so a size cap drops the weakest listings, then alphabetical for reproducible output.
        for (int c = CONFIDENCE.size() - 1; c >= 0; c--) {
            for (Map.Entry<String, String[]> e : merged.entrySet()) {
                if (!e.getValue()[1].equals(CONFIDENCE.get(c))) continue;
                if (entries.size() >= max) { truncated = true; break; }
                entries.add("D " + e.getKey() + " " + e.getValue()[0] + " " + e.getValue()[1] + " " + e.getValue()[2]);
            }
        }
        return new Result(entries, stats, truncated);
    }

    public static String attribution(Result r) {
        StringBuilder s = new StringBuilder("Aegis threat-feed sources (generated by FeedBuilder). Each source keeps its own licence.\n\n");
        for (SourceStats st : r.stats()) {
            s.append(st.source().id()).append(" | licence ").append(st.source().licence()).append(" | ").append(st.source().attribution())
             .append("\n  lines ").append(st.lines()).append(", accepted ").append(st.accepted()).append(", dropped ").append(st.dropped())
             .append("\n  input sha256 ").append(st.sha256()).append('\n');
        }
        s.append("\nTotal entries: ").append(r.entries().size()).append(r.truncated() ? " (TRUNCATED at the size cap; lowest-confidence entries dropped)" : "").append('\n');
        return s.toString();
    }

    private static String sha256(byte[] b) {
        try {
            StringBuilder s = new StringBuilder();
            for (byte x : MessageDigest.getInstance("SHA-256").digest(b)) s.append(String.format("%02x", x));
            return s.toString();
        } catch (java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }

    public static void main(String[] a) throws Exception {
        if (a.length < 4 || a.length > 5) {
            System.err.println("usage: FeedBuilder <sources.txt> <allowlist.txt|-> <out-entries.txt> <out-attribution.txt> [maxEntries]");
            System.exit(2);
        }
        int max = a.length == 5 ? Integer.parseInt(a[4]) : DEFAULT_MAX;
        if (max < 1 || max > DEFAULT_MAX) throw new IllegalArgumentException("maxEntries must be 1.." + DEFAULT_MAX);
        Result r = build(parseSources(Paths.get(a[0])), a[1].equals("-") ? Collections.emptySet() : loadAllowlist(Paths.get(a[1])), max);
        Files.write(Paths.get(a[2]), (String.join("\n", r.entries()) + "\n").getBytes(StandardCharsets.US_ASCII));
        Files.write(Paths.get(a[3]), attribution(r).getBytes(StandardCharsets.UTF_8));
        System.out.print(attribution(r));
    }
}
