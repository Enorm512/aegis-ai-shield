package com.aegis.core;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/**
 * Prints recall and false-positive counts, with Wilson 95% intervals, for the three message detectors on each data
 * set: rules only (the default product), the classifier alone at its shipped threshold, and the hybrid.
 *   java com.aegis.core.ModelEval   (run from the core/ directory)
 * "Flagged" means a verdict of SUSPICIOUS or stronger (rules, hybrid) or score >= threshold (classifier).
 */
public final class ModelEval {
    static double[] wilson(int k, int n) {
        if (n == 0) return new double[] {0, 1};
        double z = 1.96, p = (double) k / n, d = 1 + z * z / n, c = p + z * z / (2 * n), m = z * Math.sqrt(p * (1 - p) / n + z * z / (4.0 * n * n));
        return new double[] {Math.max(0, (c - m) / d), Math.min(1, (c + m) / d)};
    }
    static String pct(int k, int n) { double[] w = wilson(k, n); return String.format(Locale.ROOT, "%d/%d (%.0f%%, 95%% CI %.0f-%.0f%%)", k, n, 100.0 * k / Math.max(1, n), 100 * w[0], 100 * w[1]); }

    public static void main(String[] args) throws Exception {
        TextClassifier clf = TextClassifier.load(Files.readAllBytes(Path.of(args.length > 0 ? args[0] : "../ml/model/message_model.txt"))); // optional: a candidate model
        for (String file : new String[] {"train.txt", "test.txt", "reviewer-novel.txt"}) {
            int[] scam = new int[4], ok = new int[4]; // total, rules, model, hybrid
            for (String line : Files.readAllLines(Path.of("../ml/data/" + file), StandardCharsets.UTF_8)) {
                if (line.isBlank()) continue;
                String[] p = line.split("\\|", 3);
                boolean isScam = p[0].equals("1");
                int[] c = isScam ? scam : ok;
                c[0]++;
                if (ScamAnalyzer.analyze(p[2]).verdict.compareTo(Analysis.Verdict.SUSPICIOUS) >= 0) c[1]++;
                if (clf.classify(p[2]).score() >= clf.threshold()) c[2]++;
                if (MessageAi.analyze(p[2], clf).verdict.compareTo(Analysis.Verdict.SUSPICIOUS) >= 0) c[3]++;
            }
            System.out.println("== " + file + "  (scam n=" + scam[0] + ", ordinary n=" + ok[0] + ")");
            String[] names = {"", "rules only", "classifier alone", "hybrid (rules + classifier)"};
            for (int i = 1; i < 4; i++) System.out.println("  " + String.format("%-30s", names[i]) + " recall " + pct(scam[i], scam[0]) + "   false positives " + pct(ok[i], ok[0]));
        }
    }
}
