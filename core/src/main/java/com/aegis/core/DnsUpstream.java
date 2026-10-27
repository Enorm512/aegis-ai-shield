package com.aegis.core;

import java.io.*;
import java.net.*;
import java.util.List;
import java.util.function.Supplier;

/** Forwards an already-filtered DNS query to a real resolver. Implementations must not log query names. */
public interface DnsUpstream {
    /** Returns the raw DNS response, or throws IOException when no server answered in time. */
    byte[] resolve(byte[] query) throws IOException;

    /** Called on each outgoing socket so the VPN service can exclude it from the tunnel (VpnService.protect). */
    interface Protector { void protect(Socket s) throws IOException; void protect(DatagramSocket s) throws IOException; Protector NONE = new Protector() {
        public void protect(Socket s) {} public void protect(DatagramSocket s) {} }; }

    /** Plain DNS over UDP with TCP retry on truncation. Servers are tried in order. */
    final class Plain implements DnsUpstream {
        private final Supplier<List<InetSocketAddress>> servers;
        private final Protector protector;
        private final int timeoutMs;
        public Plain(Supplier<List<InetSocketAddress>> servers, Protector protector, int timeoutMs) {
            this.servers = servers; this.protector = protector; this.timeoutMs = timeoutMs;
        }
        @Override public byte[] resolve(byte[] query) throws IOException {
            List<InetSocketAddress> list = servers.get();
            if (list == null || list.isEmpty()) throw new IOException("no upstream resolver known");
            IOException last = null;
            for (InetSocketAddress server : list) {
                try {
                    byte[] r = udp(server, query);
                    if (DnsMessage.truncated(r, r.length)) {
                        try { return tcp(server, query); } catch (IOException tcpFailure) { return r; } // still better than nothing
                    }
                    return r;
                } catch (IOException e) { last = e; }
            }
            throw last;
        }
        private byte[] udp(InetSocketAddress server, byte[] query) throws IOException {
            try (DatagramSocket s = new DatagramSocket()) {
                protector.protect(s);
                s.setSoTimeout(timeoutMs);
                s.connect(server);
                s.send(new DatagramPacket(query, query.length));
                byte[] buf = new byte[4096];
                DatagramPacket p = new DatagramPacket(buf, buf.length);
                while (true) {
                    s.receive(p);
                    byte[] r = java.util.Arrays.copyOf(buf, p.getLength());
                    if (r.length >= 2 && r[0] == query[0] && r[1] == query[1]) return r; // ignore stray datagrams
                }
            }
        }
        private byte[] tcp(InetSocketAddress server, byte[] query) throws IOException {
            try (Socket s = new Socket()) {
                protector.protect(s);
                s.setSoTimeout(timeoutMs);
                s.connect(server, timeoutMs);
                DataOutputStream out = new DataOutputStream(s.getOutputStream());
                out.writeShort(query.length); out.write(query); out.flush();
                DataInputStream in = new DataInputStream(s.getInputStream());
                int n = in.readUnsignedShort();
                if (n < 12) throw new IOException("short DNS response");
                byte[] r = new byte[n];
                in.readFully(r);
                return r;
            }
        }
    }
}
