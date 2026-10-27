package com.aegis.core;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * Small deterministic text classifier: hashed word/bigram/character-trigram features into a logistic regression.
 * Pure computation: no I/O, no network, no logging, no state between calls. The model file is data, never code.
 * Output is an advisory score, not a verdict.
 */
public final class TextClassifier {
    public static final int MAX_MODEL_BYTES = 4 * 1024 * 1024;
    public static final int BUCKETS = 1 << 16;

    public static final class ModelException extends Exception { public ModelException(String m) { super(m); } }

    /** Extracted features: bucket indexes, values, and readable terms for explanations (words and bigrams only). */
    static final class Features {
        final int[] index; final float[] value; final Map<Integer, String> terms;
        Features(int[] index, float[] value, Map<Integer, String> terms) { this.index = index; this.value = value; this.terms = terms; }
    }

    public record Result(double score, List<String> influentialTerms) {}

    private final String name;
    private final float[] weights;
    private final float bias;
    private final double threshold;

    private TextClassifier(String name, float[] weights, float bias, double threshold) {
        this.name = name; this.weights = weights; this.bias = bias; this.threshold = threshold;
    }
    public String name() { return name; }
    /** Score at or above which the hybrid analyzer reports a language warning (chosen at training time). */
    public double threshold() { return threshold; }

    static int bucket(String s) {
        int h = 0x811c9dc5;
        for (int i = 0; i < s.length(); i++) { h ^= s.charAt(i); h *= 16777619; }
        return (h ^ (h >>> 16)) & (BUCKETS - 1);
    }

    static Features extract(String text) { return extract(TextNormalizer.tokens(text)); }

    static Features extract(List<String> toks) {
        Map<Integer, Float> counts = new HashMap<>();
        Map<Integer, String> terms = new HashMap<>();
        for (int i = 0; i < toks.size(); i++) {
            String t = toks.get(i);
            int w = bucket("w:" + t); counts.merge(w, 1f, Float::sum); terms.putIfAbsent(w, t);
            if (i + 1 < toks.size()) { String bg = t + " " + toks.get(i + 1); int b = bucket("b:" + bg); counts.merge(b, 1f, Float::sum); terms.putIfAbsent(b, bg); }
            String padded = "<" + t + ">";
            for (int j = 0; j + 3 <= padded.length(); j++) counts.merge(bucket("c:" + padded.substring(j, j + 3)), 1f, Float::sum);
        }
        int n = counts.size();
        int[] idx = new int[n]; float[] val = new float[n];
        int k = 0; double norm = 0;
        for (Map.Entry<Integer, Float> e : new TreeMap<>(counts).entrySet()) {
            idx[k] = e.getKey(); val[k] = (float) (1 + Math.log(e.getValue())); norm += val[k] * val[k]; k++;
        }
        float inv = norm > 0 ? (float) (1 / Math.sqrt(norm)) : 0;
        for (int i = 0; i < n; i++) val[i] *= inv;
        return new Features(idx, val, terms);
    }

    private static final int WINDOW = 32, STRIDE = 16;

    /**
     * Scores the whole text and, for longer texts, every 32-token window; the highest score wins. This stops a scam
     * sentence from being diluted by appended harmless filler. Explanation terms come from the winning window.
     */
    public Result classify(String text) {
        List<String> toks = TextNormalizer.tokens(text);
        Result best = score(toks);
        if (toks.size() > WINDOW) {
            for (int from = 0; from < toks.size(); from += STRIDE) {
                Result r = score(toks.subList(from, Math.min(toks.size(), from + WINDOW)));
                if (r.score() > best.score()) best = r;
                if (from + WINDOW >= toks.size()) break;
            }
        }
        return best;
    }

    private Result score(List<String> toks) {
        Features f = extract(toks);
        double z = bias;
        for (int i = 0; i < f.index.length; i++) z += weights[f.index[i]] * f.value[i];
        double score = 1 / (1 + Math.exp(-z));
        List<Map.Entry<String, Double>> contrib = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < f.index.length; i++) {
            String term = f.terms.get(f.index[i]);
            double c = weights[f.index[i]] * f.value[i];
            if (term != null && c > 0.05 && seen.add(term)) contrib.add(new AbstractMap.SimpleImmutableEntry<>(term, c));
        }
        contrib.sort((a, b) -> Double.compare(b.getValue(), a.getValue()));
        List<String> top = new ArrayList<>();
        for (int i = 0; i < Math.min(3, contrib.size()); i++) top.add(contrib.get(i).getKey());
        return new Result(score, Collections.unmodifiableList(top));
    }

    // ---- Model file: "AEGIS-MODEL 1" (integrity checksum only; a signature is required before models become downloadable)

    public static byte[] serialize(String name, float[] weights, float bias, double threshold) {
        StringBuilder s = new StringBuilder("AEGIS-MODEL 1\nname: ").append(name).append("\nbuckets: ").append(BUCKETS)
            .append("\nbias: ").append(bias).append("\nthreshold: ").append(threshold).append('\n');
        int n = 0;
        StringBuilder body = new StringBuilder();
        for (int i = 0; i < weights.length; i++) if (Math.abs(weights[i]) >= 1e-3f) { body.append(i).append(' ').append(weights[i]).append('\n'); n++; }
        s.append("weights: ").append(n).append('\n').append(body).append("END\n");
        byte[] b = s.toString().getBytes(StandardCharsets.US_ASCII);
        return (s + "SHA256 " + sha256(b) + "\n").getBytes(StandardCharsets.US_ASCII);
    }

    public static TextClassifier load(byte[] data) throws ModelException {
        if (data == null || data.length == 0 || data.length > MAX_MODEL_BYTES) throw new ModelException("size");
        for (byte b : data) if ((b < 0x20 && b != '\n') || b < 0) throw new ModelException("characters");
        String all = new String(data, StandardCharsets.US_ASCII);
        int cut = all.lastIndexOf("SHA256 ");
        if (cut <= 0 || all.charAt(cut - 1) != '\n' || !all.endsWith("\n")) throw new ModelException("checksum line");
        String sum = all.substring(cut + 7, all.length() - 1);
        if (!sum.equals(sha256(all.substring(0, cut).getBytes(StandardCharsets.US_ASCII)))) throw new ModelException("checksum mismatch");
        String[] l = all.substring(0, cut).split("\n", -1);
        try {
            if (l.length < 8 || !l[0].equals("AEGIS-MODEL 1")) throw new ModelException("format");
            String name = field(l[1], "name: "); if (!name.matches("[A-Za-z0-9._-]{1,64}")) throw new ModelException("name");
            if (Integer.parseInt(field(l[2], "buckets: ")) != BUCKETS) throw new ModelException("buckets");
            float bias = Float.parseFloat(field(l[3], "bias: ")); double thr = Double.parseDouble(field(l[4], "threshold: "));
            int n = Integer.parseInt(field(l[5], "weights: "));
            if (!Float.isFinite(bias) || Math.abs(bias) > 100 || !(thr > 0 && thr < 1) || n < 0 || n > BUCKETS) throw new ModelException("header values");
            if (l.length != 6 + n + 2 || !l[6 + n].equals("END") || !l[l.length - 1].isEmpty()) throw new ModelException("weight count");
            float[] w = new float[BUCKETS];
            int prev = -1;
            for (int i = 0; i < n; i++) {
                String[] p = l[6 + i].split(" ");
                if (p.length != 2) throw new ModelException("weight line");
                int idx = Integer.parseInt(p[0]); float v = Float.parseFloat(p[1]);
                if (idx <= prev || idx >= BUCKETS || !Float.isFinite(v) || Math.abs(v) > 100) throw new ModelException("weight value");
                w[idx] = v; prev = idx;
            }
            return new TextClassifier(name, w, bias, thr);
        } catch (NumberFormatException e) { throw new ModelException("number"); }
    }

    private static String field(String line, String prefix) throws ModelException {
        if (!line.startsWith(prefix)) throw new ModelException("header");
        return line.substring(prefix.length());
    }
    private static String sha256(byte[] b) {
        try {
            StringBuilder h = new StringBuilder();
            for (byte x : MessageDigest.getInstance("SHA-256").digest(b)) h.append(String.format(Locale.ROOT, "%02x", x & 255));
            return h.toString();
        } catch (NoSuchAlgorithmException e) { throw new AssertionError(e); }
    }
}
