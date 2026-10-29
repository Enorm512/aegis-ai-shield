package com.aegis.core;

import java.util.*;

/**
 * Turns an {@link Analysis} into what a person needs first: a level, the few reasons that matter most, what to do
 * next, and the rest as optional detail. Pure logic so it is host-tested; wording and translation live in the app.
 */
public final class ResultSummary {
    public enum Subject { LINK, MESSAGE, APK, IMAGE }
    /** Same order as Analysis.Verdict from weakest to strongest evidence of a problem, with UNCLEAR for "could not assess". */
    public enum Level { CLEAR, UNCLEAR, SUSPICIOUS, STRONG, CONFIRMED }

    public final Level level;
    public final Subject subject;
    /** At most 3, most important first. Empty when nothing matched. */
    public final List<Finding> reasons;
    /** Everything else that is informative (hosts, notes, hardening hints). */
    public final List<Finding> details;
    /** Standing caveats about what the check cannot do. */
    public final List<Finding> limitations;
    /** Stable codes for next-step advice, most important first. */
    public final List<String> advice;

    private ResultSummary(Level level, Subject subject, List<Finding> reasons, List<Finding> details, List<Finding> limitations, List<String> advice) {
        this.level = level; this.subject = subject;
        this.reasons = Collections.unmodifiableList(reasons); this.details = Collections.unmodifiableList(details);
        this.limitations = Collections.unmodifiableList(limitations); this.advice = Collections.unmodifiableList(advice);
    }

    private static final Map<String, Integer> WEIGHT = new HashMap<>();
    private static final Set<String> LIMITATIONS = new HashSet<>(Arrays.asList("HEURISTIC_LIMITS", "APK_MANIFEST_LIMITS", "IMAGE_LIMITS"));
    static {
        String[] ranked = {"KNOWN_MALICIOUS_HASH", "THREATDB_LISTED", "QR_DEVICE_LINK", "SECRET_REQUEST", "QR_SIGNIN_SECRET", "APK_BANKER_PATTERN", "LOOKALIKE_BRAND", "APK_SMS_EXFIL_PATTERN", "APK_DROPPER_PATTERN",
            "BRAND_OUTSIDE_KNOWN_DOMAIN", "GIFTCARD_REQUEST", "FAMILY_IMPERSONATION", "PARCEL_FEE", "INVESTMENT_LURE", "QR_CRYPTO_PAYMENT", "QR_APP_DOWNLOAD", "MIXED_SCRIPT_HOST", "VERIFY_REQUEST", "USERINFO", "UNUSUAL_PAYMENT", "PRIZE_PAYMENT", "SUSPICIOUS_LINK", "THREAT_LANGUAGE",
            "APK_CAPABILITIES", "ML_SCAM_LANGUAGE", "URGENCY", "APK_NO_LAUNCHER", "REDIRECT_PARAMETER", "SUSPICIOUS_TLD", "ML_AGREES"};
        for (int i = 0; i < ranked.length; i++) WEIGHT.put(ranked[i], 1000 - i * 10);
    }

    public static Level levelOf(Analysis.Verdict v) {
        switch (v) {
            case CONFIRMED_MALICIOUS: return Level.CONFIRMED;
            case STRONG_INDICATORS: return Level.STRONG;
            case SUSPICIOUS: return Level.SUSPICIOUS;
            case INSUFFICIENT_EVIDENCE: return Level.UNCLEAR;
            default: return Level.CLEAR;
        }
    }

    /** Strongest verdict wins; findings are concatenated without repeating a code. Subject comes from the first analysis. */
    public static Analysis combine(Analysis first, Analysis... more) {
        Analysis.Verdict v = first.verdict;
        List<Finding> all = new ArrayList<>(first.findings);
        Set<String> seen = new HashSet<>(); for (Finding f : all) seen.add(f.code);
        for (Analysis a : more) {
            // A hash lookup that was never answered must not make a manifest-only review look "unclear" when the manifest was read.
            if (a.verdict.compareTo(v) > 0) v = a.verdict;
            for (Finding f : a.findings) if (seen.add(f.code)) all.add(f);
        }
        if (v == Analysis.Verdict.INSUFFICIENT_EVIDENCE) {
            for (Analysis a : more) if (a.verdict == Analysis.Verdict.NO_KNOWN_WARNING_SIGNS) v = Analysis.Verdict.NO_KNOWN_WARNING_SIGNS;
        }
        return new Analysis(v, all, first.subject);
    }

    public static ResultSummary of(Analysis a, Subject subject) {
        Level level = levelOf(a.verdict);
        List<Finding> keyed = new ArrayList<>(), details = new ArrayList<>(), limits = new ArrayList<>();
        Set<String> codes = new HashSet<>();
        for (Finding f : a.findings) {
            codes.add(f.code);
            if (LIMITATIONS.contains(f.code)) limits.add(f);
            else if (WEIGHT.containsKey(f.code)) keyed.add(f);
            else details.add(f);
        }
        keyed.sort((x, y) -> WEIGHT.get(y.code) - WEIGHT.get(x.code));
        // "No known warning signs" must never sit above a list of reasons: anything noticed but not enough to flag is shown only as a detail.
        List<Finding> reasons = level == Level.CLEAR ? new ArrayList<Finding>() : new ArrayList<>(keyed.subList(0, Math.min(3, keyed.size())));
        details.addAll(0, keyed.subList(reasons.size(), keyed.size()));
        return new ResultSummary(level, subject, reasons, details, limits, advice(level, subject, codes));
    }

    private static List<String> advice(Level level, Subject subject, Set<String> codes) {
        List<String> out = new ArrayList<>();
        boolean flagged = level.compareTo(Level.SUSPICIOUS) >= 0;
        boolean strong = level.compareTo(Level.STRONG) >= 0;
        if (subject == Subject.APK) {
            if (flagged) { out.add("DO_NOT_INSTALL"); out.add("INSTALL_FROM_STORE"); out.add("ALREADY_INSTALLED"); out.add("REPORT_IT"); }
            else if (level == Level.UNCLEAR) { out.add("CHECK_INPUT"); out.add("INSTALL_FROM_STORE"); }
            else { out.add("INSTALL_FROM_STORE"); out.add("STAY_CAUTIOUS"); }
            return out;
        }
        if (subject == Subject.IMAGE) {
            if (flagged) {
                if (codes.contains("QR_DEVICE_LINK") || codes.contains("QR_APP_DOWNLOAD")) out.add("DO_NOT_SCAN");
                if (codes.contains("QR_SIGNIN_SECRET")) out.add("KEEP_QR_PRIVATE");
                if (codes.contains("QR_LINK") && !codes.contains("QR_DEVICE_LINK")) out.add("DO_NOT_OPEN");
                out.add("GO_OFFICIAL_ROUTE");
                out.add("NEVER_SHARE_CODES");
                if (codes.contains("UNUSUAL_PAYMENT") || codes.contains("QR_CRYPTO_PAYMENT")) out.add("PAYMENT_HARD_TO_RECOVER");
                if (strong) out.add("ALREADY_ACTED");
                out.add("REPORT_IT");
            } else if (level == Level.UNCLEAR) { out.add("CHECK_IMAGE"); out.add("VERIFY_OTHER_WAY"); }
            else { out.add("VERIFY_OTHER_WAY"); out.add("STAY_CAUTIOUS"); }
            return out;
        }
        if (flagged) {
            if (subject == Subject.LINK) out.add("DO_NOT_OPEN");
            out.add("GO_OFFICIAL_ROUTE");
            if (codes.contains("SECRET_REQUEST") || subject == Subject.MESSAGE) out.add("NEVER_SHARE_CODES");
            if (codes.contains("UNUSUAL_PAYMENT") || codes.contains("PRIZE_PAYMENT")) out.add("PAYMENT_HARD_TO_RECOVER");
            if (strong) out.add("ALREADY_ACTED");
            out.add("REPORT_IT");
        } else if (level == Level.UNCLEAR) {
            out.add("CHECK_INPUT"); out.add("VERIFY_OTHER_WAY");
        } else {
            out.add("VERIFY_OTHER_WAY"); out.add("STAY_CAUTIOUS");
        }
        return out;
    }
}
