package com.aegis.core;

import java.util.*;

/** Heuristic results are evidence, not an assurance of safety. */
public final class Analysis {
    public enum Verdict {
        INSUFFICIENT_EVIDENCE, NO_KNOWN_WARNING_SIGNS, SUSPICIOUS,
        STRONG_INDICATORS, CONFIRMED_MALICIOUS
    }
    public final Verdict verdict;
    public final List<Finding> findings;
    public final String subject;
    public Analysis(Verdict verdict, List<Finding> findings, String subject) {
        this.verdict = verdict;
        this.findings = Collections.unmodifiableList(new ArrayList<>(findings));
        this.subject = subject;
    }
}
