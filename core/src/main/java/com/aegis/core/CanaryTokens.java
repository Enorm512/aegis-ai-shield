package com.aegis.core;

import java.security.SecureRandom;
import java.util.*;

/**
 * Tripwires: decoy data (a contact, a note, a file) that carries a link to a unique, never-real host name. Nobody has
 * a reason to open that link except something that read the decoy and acted on it: a rogue agent, spyware, or a
 * person who got into the phone. While DNS protection runs, a lookup of the name is answered locally (never forwarded)
 * and reported as a tripped canary.
 *
 * Default zone is under ".invalid" (RFC 2606/6761: guaranteed never to exist), so even when Aegis is not running a
 * lookup only reaches the network's resolver and fails; the token leaks to nobody who could register it.
 * Limits: only actions taken ON this phone through its normal DNS are seen. Data copied off the phone and used
 * elsewhere, or apps using their own encrypted DNS, are not detected.
 */
public final class CanaryTokens {
    private CanaryTokens() {}

    public static final String DEFAULT_ZONE = "aegis-canary.invalid";
    public static final int MAX_TOKENS = 20;
    private static final String ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"; // base32: 20 chars = 100 random bits

    public enum Kind {
        CONTACT("www"), NOTE("secure-login"), FILE("share");
        final String prefix;
        Kind(String prefix) { this.prefix = prefix; }
    }

    /** One planted decoy. id is the random part; the host name is "<prefix>-<id>.<zone>". */
    public record Token(String id, Kind kind, long createdMillis) {
        public String host(String zone) { return kind.prefix + "-" + id + "." + zone; }
        public String url(String zone) { return "https://" + host(zone) + (kind == Kind.NOTE ? "/login" : kind == Kind.FILE ? "/d/" + id.substring(0, 6) : "/"); }
    }

    public static String newId(SecureRandom rnd) {
        StringBuilder b = new StringBuilder(20);
        for (int i = 0; i < 20; i++) b.append(ALPHABET.charAt(rnd.nextInt(32)));
        return b.toString();
    }

    static boolean validId(String id) { return id != null && id.length() == 20 && id.chars().allMatch(c -> ALPHABET.indexOf(c) >= 0); }

    /** Planted tokens. Thread-safe; the DNS thread only reads a volatile immutable map. */
    public static final class Registry {
        private final String zone;
        private volatile Map<String, Token> byHost = Collections.emptyMap();

        public Registry(String zone) {
            String z = zone == null ? "" : zone.toLowerCase(Locale.ROOT);
            if (!z.matches("[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+") || z.length() > 200) throw new IllegalArgumentException("bad canary zone: " + zone);
            this.zone = z;
        }
        public String zone() { return zone; }

        public synchronized Token plant(Kind kind, SecureRandom rnd, long nowMillis) {
            if (byHost.size() >= MAX_TOKENS) throw new IllegalStateException("at most " + MAX_TOKENS + " tripwires");
            Token t = new Token(newId(rnd), kind, nowMillis);
            Map<String, Token> m = new HashMap<>(byHost);
            m.put(t.host(zone), t);
            byHost = Collections.unmodifiableMap(m);
            return t;
        }

        public synchronized boolean remove(String id) {
            Map<String, Token> m = new HashMap<>(byHost);
            boolean removed = m.values().removeIf(t -> t.id().equals(id));
            byHost = Collections.unmodifiableMap(m);
            return removed;
        }

        public List<Token> tokens() {
            List<Token> l = new ArrayList<>(byHost.values());
            l.sort(Comparator.comparingLong(Token::createdMillis));
            return l;
        }

        /** The token whose host is name or a parent of name (lowercase ASCII DNS name), if any. Cost: one lookup per label. */
        public Optional<Token> match(String name) {
            Map<String, Token> m = byHost;
            if (m.isEmpty() || name == null) return Optional.empty();
            String h = name.endsWith(".") ? name.substring(0, name.length() - 1) : name;
            for (int guard = 0; guard < 128; guard++) {
                Token t = m.get(h);
                if (t != null) return Optional.of(t);
                int dot = h.indexOf('.');
                if (dot < 0) return Optional.empty();
                h = h.substring(dot + 1);
            }
            return Optional.empty();
        }

        /** "<kind> <id> <created>" per line. */
        public String serialize() {
            StringBuilder b = new StringBuilder("AEGIS-CANARY 1\n");
            for (Token t : tokens()) b.append(t.kind().name()).append(' ').append(t.id()).append(' ').append(t.createdMillis()).append('\n');
            return b.toString();
        }

        /** Loads serialize() output, skipping malformed lines; replaces current tokens. */
        public synchronized void load(String text) {
            Map<String, Token> m = new HashMap<>();
            if (text != null && text.startsWith("AEGIS-CANARY 1\n")) {
                for (String line : text.split("\n")) {
                    String[] f = line.split(" ");
                    if (f.length != 3 || !validId(f[1]) || m.size() >= MAX_TOKENS) continue;
                    try {
                        Token t = new Token(f[1], Kind.valueOf(f[0]), Long.parseLong(f[2]));
                        m.put(t.host(zone), t);
                    } catch (IllegalArgumentException ignored) { }
                }
            }
            byHost = Collections.unmodifiableMap(m);
        }
    }

    // --- Decoy content. Plausible to a program skimming for credentials or links; recognisable to the person by name.

    private static final String[] FIRST = {"Kari", "Ola", "Ingrid", "Lars", "Sofie", "Jonas", "Emma", "Henrik"};
    private static final String[] LAST = {"Nordby", "Haugen", "Lunde", "Berg", "Moen", "Dahl", "Strand", "Lie"};

    static int pick(String id, int salt, int n) { return Math.floorMod(id.hashCode() * 31 + salt, n); }

    /** Contact name that the person will recognise in the planted-decoy list. */
    public static String contactName(Token t) { return FIRST[pick(t.id(), 1, FIRST.length)] + " " + LAST[pick(t.id(), 2, LAST.length)]; }

    /** A password-looking string derived from the id (not a real secret: it unlocks nothing). */
    public static String decoyPassword(Token t) {
        String s = t.id();
        return Character.toUpperCase(s.charAt(0)) + s.substring(1, 7) + "!" + (pick(s, 3, 90) + 10) + s.substring(7, 10);
    }

    public static String noteText(Token t, String zone, boolean norwegian) {
        String user = FIRST[pick(t.id(), 4, FIRST.length)].toLowerCase(Locale.ROOT) + "." + LAST[pick(t.id(), 5, LAST.length)].toLowerCase(Locale.ROOT);
        return norwegian
            ? "Innlogging backup (ikke slett)\nSide: " + t.url(zone) + "\nBruker: " + user + "\nPassord: " + decoyPassword(t) + "\n"
            : "Login backup (do not delete)\nSite: " + t.url(zone) + "\nUser: " + user + "\nPassword: " + decoyPassword(t) + "\n";
    }

    public static String fileText(Token t, String zone, boolean norwegian) {
        return norwegian
            ? "Kontoer og koder\n\nNettbank: " + t.url(zone) + "\nKode: " + decoyPassword(t) + "\nLenke til delte dokumenter: " + t.url(zone) + "\n"
            : "Accounts and codes\n\nOnline banking: " + t.url(zone) + "\nCode: " + decoyPassword(t) + "\nShared documents link: " + t.url(zone) + "\n";
    }
}
