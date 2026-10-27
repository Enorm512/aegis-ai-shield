package com.aegis.core;

import java.util.*;

/**
 * Hybrid message analysis: deterministic rules first, classifier as a secondary signal.
 * The classifier can raise a verdict to SUSPICIOUS at most. It never lowers one, never confirms, and a low score
 * produces no statement at all (absence of a warning is not evidence of safety).
 */
public final class MessageAi {
    private static final int MIN_TOKENS = 5;
    private MessageAi() {}

    public static Analysis analyze(String input, TextClassifier classifier) {
        Analysis base = ScamAnalyzer.analyze(input);
        if (classifier == null || base.subject.equals("Message") && base.findings.stream().anyMatch(f -> f.code.equals("INPUT_LIMIT"))) return base;
        if (TextNormalizer.tokens(input).size() < MIN_TOKENS) return base;
        TextClassifier.Result r = classifier.classify(input);
        if (r.score() < classifier.threshold()) return base;
        List<Finding> fs = new ArrayList<>(base.findings);
        Analysis.Verdict v = base.verdict;
        // No "influential terms" are shown: most of the evidence sits in character fragments that cannot be displayed, and the visible words are mostly filler.
        if (base.verdict.compareTo(Analysis.Verdict.SUSPICIOUS) >= 0) {
            fs.add(new Finding("ML_AGREES", "The experimental on-device text classifier also scores this wording like known scam messages. It was built from examples similar to the rules, so this is not independent confirmation."));
        } else {
            v = Analysis.Verdict.SUSPICIOUS;
            fs.add(new Finding("ML_SCAM_LANGUAGE", "The experimental on-device text classifier gives this wording a high score against known scam messages, although no rule matched. This is a weak signal and it can be wrong; verify through an official channel."));
        }
        return new Analysis(v, fs, base.subject);
    }
}
