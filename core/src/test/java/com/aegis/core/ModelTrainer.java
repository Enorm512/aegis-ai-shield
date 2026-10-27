package com.aegis.core;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/**
 * Developer tool: trains the hashed logistic-regression model and reports held-out metrics.
 *   java ModelTrainer <train.txt> <test.txt> <out.model> <model-name> [--class-weight=auto]
 * --class-weight=auto multiplies the loss of scam examples by a weight chosen from {1, 2, 4, 8, ordinary/scam ratio}
 * by 5-fold cross-validation on the training file only (highest out-of-fold recall at the usual 2% false-positive
 * threshold rule; ties go to the smaller weight). Without the flag the weight is 1 (the original behaviour).
 * Data lines: label|lang|text (label 1 = scam-style, 0 = ordinary). The decision threshold is chosen from
 * cross-validation on the TRAINING file only; the test file is used once, for reporting.
 */
public final class ModelTrainer {
    record Example(int label, String lang, String text, TextClassifier.Features f) {}

    static List<Example> load(Path p) throws Exception {
        List<Example> out = new ArrayList<>();
        for (String line : Files.readAllLines(p, StandardCharsets.UTF_8)) {
            if (line.isBlank()) continue;
            String[] a = line.split("\\|", 3);
            out.add(new Example(Integer.parseInt(a[0]), a[1], a[2], TextClassifier.extract(a[2])));
        }
        return out;
    }

    /** Returns {weights..., bias} packed as float[BUCKETS + 1]. */
    static float[] train(List<Example> data, long seed) { return train(data, seed, 1.0); }

    /** posWeight scales the gradient of scam (label 1) examples, a standard way to counter class imbalance. */
    static float[] train(List<Example> data, long seed, double posWeight) {
        float[] w = new float[TextClassifier.BUCKETS + 1];
        List<Example> order = new ArrayList<>(data);
        Random rnd = new Random(seed);
        double l2 = 1e-4;
        for (int epoch = 0; epoch < 120; epoch++) {
            Collections.shuffle(order, rnd);
            double lr = 2.0 / (1 + 0.05 * epoch);
            for (Example e : order) {
                double z = w[TextClassifier.BUCKETS];
                for (int i = 0; i < e.f.index.length; i++) z += w[e.f.index[i]] * e.f.value[i];
                double err = (1 / (1 + Math.exp(-z)) - e.label) * (e.label == 1 ? posWeight : 1.0);
                for (int i = 0; i < e.f.index.length; i++) {
                    int k = e.f.index[i];
                    w[k] -= (float) (lr * (err * e.f.value[i] + l2 * w[k]));
                }
                w[TextClassifier.BUCKETS] -= (float) (lr * err);
            }
        }
        return w;
    }

    static double score(float[] w, Example e) {
        double z = w[TextClassifier.BUCKETS];
        for (int i = 0; i < e.f.index.length; i++) z += w[e.f.index[i]] * e.f.value[i];
        return 1 / (1 + Math.exp(-z));
    }

    /** Smallest threshold >= 0.80 whose out-of-fold false-positive rate on ordinary messages is at most 2%. */
    static double chooseThreshold(List<Example> train) { return cv(train, 1.0, true)[0]; }

    /** {threshold, out-of-fold recall} under the 2% false-positive rule, for one class weight. */
    static double[] cv(List<Example> train, double posWeight, boolean print) {
        int folds = 5;
        List<Example> shuffled = new ArrayList<>(train);
        Collections.shuffle(shuffled, new Random(11));
        List<double[]> oof = new ArrayList<>(); // {score, label}
        for (int f = 0; f < folds; f++) {
            List<Example> tr = new ArrayList<>(), te = new ArrayList<>();
            for (int i = 0; i < shuffled.size(); i++) (i % folds == f ? te : tr).add(shuffled.get(i));
            float[] w = train(tr, 100 + f, posWeight);
            for (Example e : te) oof.add(new double[] {score(w, e), e.label});
        }
        long benign = oof.stream().filter(x -> x[1] == 0).count();
        for (double t = 0.80; t < 0.999; t += 0.005) {
            final double th = t;
            long fp = oof.stream().filter(x -> x[1] == 0 && x[0] >= th).count();
            if (fp <= 0.02 * benign) {
                long tp = oof.stream().filter(x -> x[1] == 1 && x[0] >= th).count();
                long pos = oof.size() - benign;
                if (print) System.out.printf("cross-validation (train only, class weight %.2f): threshold %.3f -> OOF false positives %d/%d, recall %d/%d%n", posWeight, t, fp, benign, tp, pos);
                return new double[] {t, tp / (double) Math.max(1, pos)};
            }
        }
        return new double[] {0.99, 0};
    }

    public static void main(String[] args) throws Exception {
        List<Example> train = load(Path.of(args[0])), test = load(Path.of(args[1]));
        // Leakage guard: no training message may also appear in the test file or in any locked evaluation set
        // (file names listed one per line in LOCKED next to the training file).
        List<String> trainTexts = new ArrayList<>();
        for (Example e : train) trainTexts.add(e.text());
        List<Path> guarded = new ArrayList<>(List.of(Path.of(args[1])));
        Path lockFile = Path.of(args[0]).toAbsolutePath().getParent().resolve("LOCKED");
        if (Files.exists(lockFile)) for (String l : Files.readAllLines(lockFile, StandardCharsets.UTF_8)) if (!l.isBlank() && !l.startsWith("#")) guarded.add(lockFile.getParent().resolve(l.trim()));
        for (Path g : guarded) {
            List<String> leaked = DatasetImporter.leaks(trainTexts, DatasetImporter.textsOf(g));
            if (!leaked.isEmpty()) throw new IllegalStateException(leaked.size() + " training messages also occur in " + g.getFileName() + ", e.g. \"" + leaked.get(0) + "\"; remove them before training");
        }
        double posWeight = 1.0;
        if (Arrays.asList(args).contains("--class-weight=auto")) {
            long pos = train.stream().filter(e -> e.label == 1).count();
            double ratio = (train.size() - pos) / (double) Math.max(1, pos);
            double best = -1;
            for (double cand : new double[] {1, 2, 4, 8, ratio}) {
                double recall = cv(train, cand, true)[1];
                if (recall > best + 1e-9) { best = recall; posWeight = cand; }
            }
            System.out.printf("chosen class weight %.2f (out-of-fold recall %.3f)%n", posWeight, best);
        }
        double threshold = cv(train, posWeight, true)[0];
        float[] w = train(train, 42, posWeight);
        float[] weights = Arrays.copyOf(w, TextClassifier.BUCKETS);
        byte[] model = TextClassifier.serialize(args[3], weights, w[TextClassifier.BUCKETS], threshold);
        Files.write(Path.of(args[2]), model);
        System.out.println("model bytes: " + model.length);
        report("TRAIN (resubstitution, optimistic)", w, train, threshold);
        report("HELD-OUT TEST", w, test, threshold);
    }

    static void report(String title, float[] w, List<Example> data, double threshold) {
        for (String lang : new String[] {"all", "en", "no"}) {
            int tp = 0, fp = 0, tn = 0, fn = 0;
            for (Example e : data) {
                if (!lang.equals("all") && !e.lang.equals(lang)) continue;
                boolean flagged = score(w, e) >= threshold;
                if (e.label == 1) { if (flagged) tp++; else fn++; } else { if (flagged) fp++; else tn++; }
            }
            System.out.printf("%s [%s] n=%d: TP=%d FN=%d FP=%d TN=%d recall=%.2f falsePositiveRate=%.2f%n",
                title, lang, tp + fp + tn + fn, tp, fn, fp, tn, tp / (double) Math.max(1, tp + fn), fp / (double) Math.max(1, fp + tn));
        }
    }
}
