package com.aegis.core;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/** Minimal, strict DNS wire handling for filtering. All input is attacker-controlled. */
public final class DnsMessage {
    public static final int RCODE_FORMERR = 1, RCODE_SERVFAIL = 2, RCODE_NXDOMAIN = 3;
    public record Question(String name, int type, int qclass, int questionEnd) {}
    private DnsMessage() {}

    /** Accepts only a standard query with exactly one uncompressed question. Anything else returns empty. */
    public static Optional<Question> parseQuery(byte[] m, int len) {
        if (m == null || len < 17 || len > m.length || len > 4096) return Optional.empty();
        int flags = u16(m, 2);
        if ((flags & 0x8000) != 0 || ((flags >> 11) & 0xF) != 0) return Optional.empty(); // must be a query, opcode QUERY
        if (u16(m, 4) != 1 || u16(m, 6) != 0 || u16(m, 8) != 0) return Optional.empty();
        StringBuilder name = new StringBuilder();
        int p = 12, total = 1;
        while (true) {
            if (p >= len) return Optional.empty();
            int l = m[p++] & 0xFF;
            if (l == 0) break;
            if (l > 63) return Optional.empty(); // also rejects compression pointers (0xC0)
            total += l + 1;
            if (total > 255 || p + l > len) return Optional.empty();
            if (name.length() > 0) name.append('.');
            for (int i = 0; i < l; i++) {
                int c = m[p + i] & 0xFF;
                if (c <= 0x20 || c >= 0x7F || c == '.') return Optional.empty();
                name.append((char) (c >= 'A' && c <= 'Z' ? c + 32 : c));
            }
            p += l;
        }
        if (name.length() == 0 || p + 4 > len) return Optional.empty();
        return Optional.of(new Question(name.toString(), u16(m, p), u16(m, p + 2), p + 4));
    }

    /** Response copying ID, RD and the question, with the given rcode and no records. */
    public static byte[] errorResponse(byte[] query, Question q, int rcode) {
        byte[] r = new byte[q.questionEnd()];
        System.arraycopy(query, 0, r, 0, q.questionEnd());
        int rd = query[2] & 0x01;
        r[2] = (byte) (0x80 | rd);             // QR=1, opcode 0, AA=0, TC=0, RD copied
        r[3] = (byte) (0x80 | (rcode & 0xF));  // RA=1
        r[6] = r[7] = r[8] = r[9] = r[10] = r[11] = 0;
        return r;
    }

    /** Valid-looking upstream answer for the same query? Checks QR, ID and the question echo. */
    public static boolean matchesQuery(byte[] resp, int rlen, byte[] query, Question q) {
        if (resp == null || rlen < q.questionEnd() || rlen > resp.length) return false;
        if ((resp[2] & 0x80) == 0) return false;
        if (resp[0] != query[0] || resp[1] != query[1]) return false;
        if (u16(resp, 4) != 1) return false;
        for (int i = 12; i < q.questionEnd(); i++) {
            int a = resp[i] & 0xFF, b = query[i] & 0xFF;
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) return false; // 0x20 case randomisation is tolerated
        }
        return true;
    }

    public static boolean truncated(byte[] resp, int len) { return len >= 4 && (resp[2] & 0x02) != 0; }

    /** If the answer cannot fit, return header+question with TC set so the client knows it is incomplete. */
    public static byte[] fit(byte[] resp, int len, Question q, int maxLen) {
        if (len <= maxLen) return java.util.Arrays.copyOf(resp, len);
        byte[] r = java.util.Arrays.copyOf(resp, q.questionEnd());
        r[2] |= 0x02;
        r[6] = r[7] = r[8] = r[9] = r[10] = r[11] = 0;
        return r;
    }

    static int u16(byte[] b, int o) { return ((b[o] & 0xFF) << 8) | (b[o + 1] & 0xFF); }

    /** Test helper and tool support: build a standard A/AAAA/etc. query. */
    public static byte[] buildQuery(int id, String name, int type) {
        java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
        o.write(id >> 8); o.write(id); o.write(0x01); o.write(0); o.write(0); o.write(1); o.write(0); o.write(0); o.write(0); o.write(0); o.write(0); o.write(0);
        for (String label : name.split("\\.")) { byte[] l = label.getBytes(StandardCharsets.US_ASCII); o.write(l.length); o.write(l, 0, l.length); }
        o.write(0); o.write(type >> 8); o.write(type); o.write(0); o.write(1);
        return o.toByteArray();
    }
}
