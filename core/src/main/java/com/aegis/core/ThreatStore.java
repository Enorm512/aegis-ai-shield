package com.aegis.core;

import java.io.*;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Clock;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

/**
 * Offline persistence of the active and previous verified bundles. Fixed file names only; callers never supply paths.
 *
 * Rollback protection is kept PER SIGNING KEY: the "floors" file records the highest sequence installed for each key
 * id, so replaying an old bundle is refused, yet a freshly rotated key starts from its own floor and can never be
 * locked out by what an earlier (or compromised) key signed. A single install may advance a key's sequence by at most
 * {@link ThreatBundleVerifier#MAX_SEQUENCE_JUMP}.
 *
 * Readers (the DNS packet thread) never take a lock: {@code current} is a volatile reference to an immutable object.
 * Verification and parsing happen outside the write lock; only the file swap is serialised.
 * Crash safety: the live file is only ever replaced by an atomic rename of a fully written, synced temporary file,
 * and the previous bundle is copied (not moved), so a valid current.bundle exists at every instant.
 */
public final class ThreatStore {
    private final Path dir;
    private final ThreatBundleVerifier.TrustAnchors anchors;
    private final Clock clock;
    private volatile ThreatDatabase current = ThreatDatabase.empty();
    private volatile String loadWarning;
    private final Object writeLock = new Object();

    public ThreatStore(File directory, ThreatBundleVerifier.TrustAnchors anchors, Clock clock) throws IOException {
        this.dir = directory.toPath();
        this.anchors = anchors;
        this.clock = clock;
        Files.createDirectories(dir);
        reload();
    }

    public ThreatDatabase current() { return current; }
    /** Non-null when an on-disk bundle failed re-verification or was missing at startup. */
    public String loadWarning() { return loadWarning; }
    public boolean canRollback() { return Files.exists(dir.resolve("previous.bundle")); }

    /** Floor of the signing key of the active database (0 when none). */
    public long floor() { return current.isEmpty() ? 0 : floorOf(current.keyId); }

    /** Highest sequence ever installed for the given key id. */
    public long floorOf(String keyId) { return readFloors().getOrDefault(keyId, 0L); }

    private long minFor(String keyId) {
        long min = floorOf(keyId);
        ThreatDatabase c = current;
        return !c.isEmpty() && c.keyId.equals(keyId) ? Math.max(min, c.sequence) : min;
    }

    public ThreatDatabase install(byte[] bundle) throws ThreatBundleVerifier.BundleException, IOException {
        String keyId = ThreatBundleVerifier.keyIdOf(bundle);
        // Heavy work (signature, parsing) without holding the lock.
        ThreatDatabase db = ThreatBundleVerifier.verify(bundle, anchors,
            new ThreatBundleVerifier.Policy(keyId == null ? 0 : minFor(keyId), true, clock.instant()));
        synchronized (writeLock) {
            if (db.sequence <= minFor(db.keyId)) throw new ThreatBundleVerifier.BundleException(ThreatBundleVerifier.BundleException.Reason.ROLLBACK, "Another update was installed first");
            Path tmp = dir.resolve("incoming.tmp");
            try (FileChannel ch = FileChannel.open(tmp, StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
                ch.write(java.nio.ByteBuffer.wrap(bundle));
                ch.force(true);
            }
            Path cur = dir.resolve("current.bundle");
            if (Files.exists(cur)) Files.copy(cur, dir.resolve("previous.bundle"), StandardCopyOption.REPLACE_EXISTING);
            move(tmp, cur);
            current = db;
            loadWarning = null;
            try { raiseFloor(db.keyId, db.sequence); } catch (IOException ignored) { /* reload() re-derives the floor from the verified current bundle */ }
            return db;
        }
    }

    /** Restores the previous verified bundle. The floors are unchanged, so only a newer bundle can replace it afterwards. */
    public boolean rollback() throws IOException {
        synchronized (writeLock) {
            Path prev = dir.resolve("previous.bundle");
            if (!Files.exists(prev)) return false;
            Optional<ThreatDatabase> db = tryLoad(prev);
            if (!db.isPresent()) { Files.deleteIfExists(prev); return false; }
            move(prev, dir.resolve("current.bundle"));
            current = db.get();
            // Remember that this older bundle was restored on purpose, so the replay check at startup accepts it.
            Files.write(dir.resolve("rolledback"), (db.get().keyId + " " + db.get().sequence + "\n").getBytes(StandardCharsets.US_ASCII));
            return true;
        }
    }

    private void reload() throws IOException {
        Path cur = dir.resolve("current.bundle"), prev = dir.resolve("previous.bundle");
        if (!Files.exists(cur) && !Files.exists(prev)) return;
        Optional<ThreatDatabase> db = Files.exists(cur) ? tryLoad(cur) : Optional.<ThreatDatabase>empty();
        boolean fromCurrent = db.isPresent();
        if (!db.isPresent()) {
            loadWarning = "Installed threat database failed verification or was missing and was not used.";
            if (Files.exists(prev)) db = tryLoad(prev);
        }
        // A correctly signed current bundle that is older than what this device already installed was swapped in (replay
        // of an old file): refuse it and do not fall back to the older previous copy either.
        if (fromCurrent && db.get().sequence < floorOf(db.get().keyId) && !restoredOnPurpose(db.get())) {
            loadWarning = "Installed threat database is older than one installed before and was not used.";
            return;
        }
        if (db.isPresent()) {
            current = db.get();
            if (current.sequence > floorOf(current.keyId)) { try { raiseFloor(current.keyId, current.sequence); } catch (IOException ignored) { } }
        }
    }

    private boolean restoredOnPurpose(ThreatDatabase db) {
        try {
            return (db.keyId + " " + db.sequence).equals(new String(Files.readAllBytes(dir.resolve("rolledback")), StandardCharsets.US_ASCII).trim());
        } catch (IOException e) { return false; }
    }

    private Optional<ThreatDatabase> tryLoad(Path p) {
        try {
            if (Files.size(p) > ThreatBundleVerifier.MAX_BUNDLE_BYTES) return Optional.empty();
            return Optional.of(ThreatBundleVerifier.verify(Files.readAllBytes(p), anchors,
                new ThreatBundleVerifier.Policy(-1, false, clock.instant())));
        } catch (ThreatBundleVerifier.BundleException | IOException e) { return Optional.empty(); }
    }

    private static void move(Path from, Path to) throws IOException {
        try { Files.move(from, to, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING); }
        catch (AtomicMoveNotSupportedException e) { Files.move(from, to, StandardCopyOption.REPLACE_EXISTING); }
    }

    /** One line per key: "<16 hex key id> <highest sequence>". Malformed lines are ignored. */
    private Map<String, Long> readFloors() {
        Map<String, Long> out = new TreeMap<>();
        try {
            for (String line : new String(Files.readAllBytes(dir.resolve("floors")), StandardCharsets.US_ASCII).split("\n")) {
                String[] p = line.trim().split(" ");
                if (p.length == 2 && p[0].matches("[0-9a-f]{16}")) { try { out.put(p[0], Long.parseLong(p[1])); } catch (NumberFormatException ignored) { } }
            }
        } catch (IOException ignored) { }
        return out;
    }

    private void raiseFloor(String keyId, long seq) throws IOException {
        Map<String, Long> floors = readFloors();
        floors.merge(keyId, seq, Math::max);
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, Long> e : floors.entrySet()) sb.append(e.getKey()).append(' ').append(e.getValue()).append('\n');
        Path tmp = dir.resolve("floors.tmp");
        Files.write(tmp, sb.toString().getBytes(StandardCharsets.US_ASCII));
        move(tmp, dir.resolve("floors"));
    }
}
