package com.aegis.core;

import java.util.Arrays;
import java.util.Optional;

/** IPv4/IPv6 + UDP framing for DNS queries read from, and answers written to, a VPN interface. */
public final class IpPacket {
    public static final class DnsRequest {
        public final int version;
        public final byte[] src, dst;
        public final int srcPort, dstPort;
        public final byte[] payload;
        DnsRequest(int version, byte[] src, byte[] dst, int srcPort, int dstPort, byte[] payload) {
            this.version = version; this.src = src; this.dst = dst; this.srcPort = srcPort; this.dstPort = dstPort; this.payload = payload;
        }
    }
    private IpPacket() {}

    /**
     * Returns the DNS payload of a UDP datagram addressed to {@code dns4}/{@code dns6} port 53. Fragments, IPv6
     * extension headers, other protocols and inconsistent lengths are rejected (the interface only routes DNS).
     */
    public static Optional<DnsRequest> parseDns(byte[] p, int len, byte[] dns4, byte[] dns6) {
        if (p == null || len < 28 || len > p.length) return Optional.empty();
        int version = (p[0] & 0xFF) >> 4;
        int udp;
        byte[] src, dst;
        if (version == 4) {
            int ihl = (p[0] & 0x0F) * 4;
            int total = DnsMessage.u16(p, 2);
            if (ihl < 20 || total < ihl + 8 || total > len) return Optional.empty();
            if ((DnsMessage.u16(p, 6) & 0x3FFF) != 0) return Optional.empty(); // MF flag or fragment offset
            if ((p[9] & 0xFF) != 17) return Optional.empty();
            src = Arrays.copyOfRange(p, 12, 16); dst = Arrays.copyOfRange(p, 16, 20);
            if (!Arrays.equals(dst, dns4)) return Optional.empty();
            udp = ihl; len = total;
        } else if (version == 6) {
            if (len < 48 || (p[6] & 0xFF) != 17) return Optional.empty();
            int payloadLen = DnsMessage.u16(p, 4);
            if (payloadLen < 8 || 40 + payloadLen > len) return Optional.empty();
            src = Arrays.copyOfRange(p, 8, 24); dst = Arrays.copyOfRange(p, 24, 40);
            if (!Arrays.equals(dst, dns6)) return Optional.empty();
            udp = 40; len = 40 + payloadLen;
        } else return Optional.empty();
        int srcPort = DnsMessage.u16(p, udp), dstPort = DnsMessage.u16(p, udp + 2), udpLen = DnsMessage.u16(p, udp + 4);
        if (dstPort != 53 || udpLen < 8 || udp + udpLen > len) return Optional.empty();
        return Optional.of(new DnsRequest(version, src, dst, srcPort, dstPort, Arrays.copyOfRange(p, udp + 8, udp + udpLen)));
    }

    /** UDP datagram from the DNS server address back to the requester. */
    public static byte[] buildResponse(DnsRequest req, byte[] dns) {
        int udpLen = 8 + dns.length;
        byte[] out;
        if (req.version == 4) {
            out = new byte[20 + udpLen];
            out[0] = 0x45; put16(out, 2, out.length); out[6] = 0x40; out[8] = 64; out[9] = 17;
            System.arraycopy(req.dst, 0, out, 12, 4); System.arraycopy(req.src, 0, out, 16, 4);
            put16(out, 10, checksum(out, 0, 20, 0));
            writeUdp(out, 20, req.dstPort, req.srcPort, dns);
            int c = udpChecksum(out, 20, udpLen, pseudo(req.dst, req.src, udpLen));
            put16(out, 26, c == 0 ? 0xFFFF : c);
        } else {
            out = new byte[40 + udpLen];
            out[0] = 0x60; put16(out, 4, udpLen); out[6] = 17; out[7] = 64;
            System.arraycopy(req.dst, 0, out, 8, 16); System.arraycopy(req.src, 0, out, 24, 16);
            writeUdp(out, 40, req.dstPort, req.srcPort, dns);
            int c = udpChecksum(out, 40, udpLen, pseudo(req.dst, req.src, udpLen));
            put16(out, 46, c == 0 ? 0xFFFF : c);
        }
        return out;
    }

    private static void writeUdp(byte[] out, int off, int srcPort, int dstPort, byte[] payload) {
        put16(out, off, srcPort); put16(out, off + 2, dstPort); put16(out, off + 4, 8 + payload.length);
        System.arraycopy(payload, 0, out, off + 8, payload.length);
    }
    private static byte[] pseudo(byte[] src, byte[] dst, int udpLen) {
        byte[] ph = new byte[src.length * 2 + (src.length == 4 ? 4 : 8)];
        System.arraycopy(src, 0, ph, 0, src.length); System.arraycopy(dst, 0, ph, src.length, dst.length);
        int o = src.length * 2;
        if (src.length == 4) { ph[o + 1] = 17; put16(ph, o + 2, udpLen); }
        else { put16(ph, o + 2, udpLen); ph[o + 7] = 17; }
        return ph;
    }
    private static int udpChecksum(byte[] pkt, int off, int len, byte[] pseudo) {
        return checksum(pkt, off, len, sum(pseudo, 0, pseudo.length, 0));
    }
    private static int sum(byte[] b, int off, int len, int seed) {
        int s = seed;
        for (int i = 0; i + 1 < len; i += 2) s += ((b[off + i] & 0xFF) << 8) | (b[off + i + 1] & 0xFF);
        if ((len & 1) == 1) s += (b[off + len - 1] & 0xFF) << 8;
        return s;
    }
    static int checksum(byte[] b, int off, int len, int seed) {
        int s = sum(b, off, len, seed);
        while ((s >>> 16) != 0) s = (s & 0xFFFF) + (s >>> 16);
        return ~s & 0xFFFF;
    }
    private static void put16(byte[] b, int o, int v) { b[o] = (byte) (v >> 8); b[o + 1] = (byte) v; }
}
