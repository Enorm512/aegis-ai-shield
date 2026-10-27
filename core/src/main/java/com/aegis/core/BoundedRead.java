package com.aegis.core;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/** Reads at most {@code limit} bytes (API 26-safe replacement for InputStream.readNBytes, which needs API 33). */
public final class BoundedRead {
    private BoundedRead() {}
    /** Returns up to {@code limit} bytes; if the stream is longer, exactly {@code limit} bytes so callers can detect overflow with limit = max + 1. */
    public static byte[] atMost(InputStream in, int limit) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(limit, 65536));
        byte[] buf = new byte[8192];
        while (out.size() < limit) {
            int n = in.read(buf, 0, Math.min(buf.length, limit - out.size()));
            if (n < 0) break;
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }
}
