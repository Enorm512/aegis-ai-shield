package com.aegis.core;

/**
 * A CharSequence that throws once a wall-clock deadline passes. Regex engines read their input through charAt, so
 * wrapping the text bounds the time any pattern can take, whatever the input. Callers treat a timeout as "could not
 * be assessed" and fail closed.
 */
final class Deadline implements CharSequence {
    static final class ScanTimeout extends RuntimeException {
        ScanTimeout() { super("scan time budget exceeded", null, false, false); }
    }
    static long in(long millis) { return System.nanoTime() + millis * 1_000_000L; }

    private final CharSequence s;
    private final long limit;
    private int ticks;

    Deadline(CharSequence s, long deadlineNanos) { this.s = s; this.limit = deadlineNanos; }

    @Override public int length() { return s.length(); }
    @Override public char charAt(int i) {
        if ((++ticks & 0x3FF) == 0 && System.nanoTime() - limit > 0) throw new ScanTimeout();
        return s.charAt(i);
    }
    @Override public CharSequence subSequence(int a, int b) { return s.subSequence(a, b); }
    @Override public String toString() { return s.toString(); }
}
