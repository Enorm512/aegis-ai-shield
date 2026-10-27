package com.aegis.core;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/**
 * Developer tool: converts public labelled SMS datasets into the training format label|lang|text.
 *   java DatasetImporter uci  <SMSSpamCollection> <lang> <out.txt>   (UCI SMS Spam Collection: "ham\ttext" / "spam\ttext")
 *   java DatasetImporter csv  <file.csv>          <lang> <out.txt>   (CSV with a header containing LABEL and TEXT columns,
 *                                                                    e.g. Mishra and Soni's SMS phishing dataset: ham/spam/smishing)
 * Mapping: smishing/phishing/scam/fraud -> 1, ham -> 0. Plain "spam" (mostly marketing) is SKIPPED by default because
 * teaching the classifier that advertising is a scam would raise false positives; pass --spam-as-scam to keep it.
 * Duplicates (after normalisation) are removed. A provenance file <out.txt>.source records input, licence note and counts.
 * Licence: both datasets named above are CC BY 4.0 (attribution required); record the citation in SOURCE_PROVENANCE.md.
 */
public final class DatasetImporter {
    private DatasetImporter() {}

    record Row(int label, String text) {}

    static Integer mapLabel(String raw, boolean spamAsScam) {
        String l = raw.trim().toLowerCase(Locale.ROOT);
        switch (l) {
            case "ham": case "legit": case "legitimate": case "0": return 0;
            case "smishing": case "phishing": case "scam": case "fraud": case "1": return 1;
            case "spam": return spamAsScam ? 1 : null;
            default: return null;
        }
    }

    /** RFC 4180-style CSV: quoted fields, doubled quotes, newlines inside quotes. */
    static List<List<String>> parseCsv(String s) {
        List<List<String>> rows = new ArrayList<>();
        List<String> row = new ArrayList<>();
        StringBuilder f = new StringBuilder();
        boolean quoted = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (quoted) {
                if (c == '"') { if (i + 1 < s.length() && s.charAt(i + 1) == '"') { f.append('"'); i++; } else quoted = false; }
                else f.append(c);
            } else if (c == '"' && f.length() == 0) quoted = true;
            else if (c == ',') { row.add(f.toString()); f.setLength(0); }
            else if (c == '\n' || c == '\r') {
                if (c == '\r' && i + 1 < s.length() && s.charAt(i + 1) == '\n') i++;
                row.add(f.toString()); f.setLength(0);
                if (!(row.size() == 1 && row.get(0).isEmpty())) rows.add(row);
                row = new ArrayList<>();
            } else f.append(c);
        }
        if (f.length() > 0 || !row.isEmpty()) { row.add(f.toString()); rows.add(row); }
        return rows;
    }

    static List<Row> fromUci(String content, boolean spamAsScam) {
        List<Row> out = new ArrayList<>();
        for (String line : content.split("\r?\n")) {
            int tab = line.indexOf('\t');
            if (tab <= 0) continue;
            Integer l = mapLabel(line.substring(0, tab), spamAsScam);
            if (l != null) out.add(new Row(l, line.substring(tab + 1)));
        }
        return out;
    }

    static List<Row> fromCsv(String content, boolean spamAsScam) {
        List<List<String>> rows = parseCsv(content.startsWith("﻿") ? content.substring(1) : content);
        if (rows.isEmpty()) return Collections.emptyList();
        int li = -1, ti = -1;
        for (int i = 0; i < rows.get(0).size(); i++) {
            String h = rows.get(0).get(i).trim().toLowerCase(Locale.ROOT);
            if (h.equals("label") || h.equals("class") || h.equals("category")) li = i;
            if (h.equals("text") || h.equals("message") || h.equals("sms")) ti = i;
        }
        if (li < 0 || ti < 0) throw new IllegalArgumentException("CSV header needs LABEL and TEXT columns: " + rows.get(0));
        List<Row> out = new ArrayList<>();
        for (List<String> r : rows.subList(1, rows.size())) {
            if (r.size() <= Math.max(li, ti)) continue;
            Integer l = mapLabel(r.get(li), spamAsScam);
            if (l != null) out.add(new Row(l, r.get(ti)));
        }
        return out;
    }

    /** One training line; '|' and line breaks become spaces so the three-field format stays intact. Null when unusable. */
    static String toLine(Row r, String lang) {
        String t = r.text().replace('|', ' ').replaceAll("[\\r\\n\\t]+", " ").replaceAll(" {2,}", " ").trim();
        if (t.length() < 3 || t.length() > 2000) return null;
        return r.label() + "|" + lang + "|" + t;
    }

    static String key(String text) { return TextNormalizer.forRules(text); }

    /** Messages of a candidate training set that also occur (after normalisation) in a locked evaluation set. */
    static List<String> leaks(List<String> trainTexts, List<String> lockedTexts) {
        Set<String> locked = new HashSet<>();
        for (String t : lockedTexts) locked.add(key(t));
        List<String> out = new ArrayList<>();
        for (String t : trainTexts) if (locked.contains(key(t))) out.add(t);
        return out;
    }

    static List<String> textsOf(Path p) throws Exception {
        List<String> out = new ArrayList<>();
        for (String line : Files.readAllLines(p, StandardCharsets.UTF_8)) {
            String[] a = line.split("\\|", 3);
            if (a.length == 3) out.add(a[2]);
        }
        return out;
    }

    public static void main(String[] a) throws Exception {
        boolean spamAsScam = Arrays.asList(a).contains("--spam-as-scam");
        List<String> args = new ArrayList<>(Arrays.asList(a));
        args.remove("--spam-as-scam");
        if (args.size() != 4 || !(args.get(0).equals("uci") || args.get(0).equals("csv")) || !args.get(2).matches("[a-z]{2}")) {
            System.err.println("usage: DatasetImporter uci|csv <input> <lang> <out.txt> [--spam-as-scam]");
            System.exit(2);
        }
        String content = new String(Files.readAllBytes(Paths.get(args.get(1))), StandardCharsets.UTF_8);
        List<Row> rows = args.get(0).equals("uci") ? fromUci(content, spamAsScam) : fromCsv(content, spamAsScam);
        Set<String> seen = new HashSet<>();
        List<String> lines = new ArrayList<>();
        int dup = 0, bad = 0, scam = 0;
        for (Row r : rows) {
            String l = toLine(r, args.get(2));
            if (l == null) { bad++; continue; }
            if (!seen.add(key(r.text()))) { dup++; continue; }
            lines.add(l);
            if (r.label() == 1) scam++;
        }
        Files.write(Paths.get(args.get(3)), (String.join("\n", lines) + "\n").getBytes(StandardCharsets.UTF_8));
        String prov = "input " + args.get(1) + "\nformat " + args.get(0) + ", lang " + args.get(2) + ", spam-as-scam " + spamAsScam
            + "\nkept " + lines.size() + " (scam " + scam + ", ordinary " + (lines.size() - scam) + "), duplicates " + dup + ", unusable " + bad + "\n";
        Files.write(Paths.get(args.get(3) + ".source"), prov.getBytes(StandardCharsets.UTF_8));
        System.out.print(prov);
    }
}
