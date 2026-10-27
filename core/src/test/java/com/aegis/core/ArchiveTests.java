package com.aegis.core;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Random;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** Standalone regression tests; no Android runtime or testing dependency required. */
public final class ArchiveTests {
    private static int assertions;
    public static void main(String[] args) throws Exception {
        byte[] valid = zip(new String[]{"AndroidManifest.xml", "classes.dex"}, new byte[][]{{1,2,3}, {4,5,6}});
        accept(valid);
        reject(new byte[]{1,2,3,4});
        reject(java.util.Arrays.copyOf(valid, valid.length - 1));
        reject(zip(new String[]{"classes.dex"}, new byte[][]{{1}}));
        reject(zip(new String[]{"nested/AndroidManifest.xml"}, new byte[][]{{1}}));
        for (String bad : new String[]{"../escape", "/absolute", "x/../escape", "x\\escape", "C:/escape", "x//y", "./x"}) {
            reject(zip(new String[]{"AndroidManifest.xml", bad}, new byte[][]{{1}, {2}}));
        }
        byte[] duplicate = zip(new String[]{"AndroidManifest.xml", "a", "b"}, new byte[][]{{1}, {2}, {3}});
        replaceEntryName(duplicate, 'b', 'a');
        reject(duplicate);
        byte[] encrypted = valid.clone();
        for (int p = 0; p < encrypted.length - 46; p++) {
            if (signature(encrypted, p, 0x02014b50)) { encrypted[p + 8] |= 1; break; }
        }
        reject(encrypted);
        byte[] unsupported = valid.clone();
        for (int p = 0; p < unsupported.length - 46; p++) {
            if (signature(unsupported, p, 0x02014b50)) { unsupported[p + 10] = 99; break; }
        }
        reject(unsupported);
        byte[] corrupt = stored();
        corrupt[30 + "AndroidManifest.xml".length()] ^= 1;
        reject(corrupt);
        reject(zip(new String[]{"AndroidManifest.xml", "bomb"}, new byte[][]{{1}, new byte[2 * 1024 * 1024]}));
        reject(zip(new String[]{"AndroidManifest.xml"}, new byte[][]{new byte[4 * 1024 * 1024 + 1]}));
        byte[] mismatch = valid.clone();
        mismatch[30] = 'X';
        reject(mismatch);
        reject(zip(new String[]{"AndroidManifest.xml"}, new byte[][]{new byte[0]}));
        accept(stored());
        byte[] localCrc = stored(); localCrc[14] ^= 1; reject(localCrc);
        byte[] localSize = stored(); localSize[18] ^= 1; reject(localSize);
        byte[] overlapping = storedArchive(new String[]{"AndroidManifest.xml", "second"},
                new byte[][]{{1, 2, 3}, {4, 5, 6}});
        int firstCentral = findSignature(overlapping, 0x02014b50);
        put32(overlapping, 18, 4); put32(overlapping, 22, 4);
        put32(overlapping, firstCentral + 20, 4); put32(overlapping, firstCentral + 24, 4);
        rejectWithReason(overlapping, "Overlapping");
        seededMalformedMutations();
        Thread.currentThread().interrupt();
        try { reject(valid); } finally { Thread.interrupted(); }
        System.out.println("ArchiveTests: " + assertions + " checks passed");
    }
    private static void accept(byte[] bytes) throws Exception {
        File file = File.createTempFile("apk-test-", ".apk");
        try { Files.write(file.toPath(), bytes); ApkArchiveInspector.inspect(file); assertions++; }
        finally { Files.deleteIfExists(file.toPath()); }
    }
    private static void reject(byte[] bytes) throws Exception {
        File file = File.createTempFile("apk-test-", ".apk");
        try {
            Files.write(file.toPath(), bytes);
            try { ApkArchiveInspector.inspect(file); }
            catch (IOException expected) { assertions++; return; }
            throw new AssertionError("Unsafe archive accepted");
        } finally { Files.deleteIfExists(file.toPath()); }
    }
    private static byte[] zip(String[] names, byte[][] contents) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream out = new ZipOutputStream(bytes)) {
            for (int i = 0; i < names.length; i++) {
                out.putNextEntry(new ZipEntry(names[i])); out.write(contents[i]); out.closeEntry();
            }
        }
        return bytes.toByteArray();
    }
    private static byte[] stored() throws IOException {
        return storedArchive(new String[]{"AndroidManifest.xml"},
                new byte[][]{"manifest test data".getBytes(StandardCharsets.UTF_8)});
    }
    private static byte[] storedArchive(String[] names, byte[][] contents) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream out = new ZipOutputStream(bytes)) {
            for (int i = 0; i < names.length; i++) {
                byte[] content = contents[i];
                CRC32 crc = new CRC32(); crc.update(content);
                ZipEntry entry = new ZipEntry(names[i]);
                entry.setMethod(ZipEntry.STORED); entry.setSize(content.length);
                entry.setCompressedSize(content.length); entry.setCrc(crc.getValue());
                out.putNextEntry(entry); out.write(content); out.closeEntry();
            }
        }
        return bytes.toByteArray();
    }
    private static void seededMalformedMutations() throws Exception {
        byte[] original = stored();
        int central = findSignature(original, 0x02014b50);
        int end = findSignature(original, 0x06054b50);
        int payload = 30 + "AndroidManifest.xml".length();
        // Every selected range is structural metadata or CRC-protected payload;
        // random harmless timestamp/comment mutations need not be rejected.
        int[][] ranges = {{0, 4}, {14, 12}, {central, 4}, {central + 16, 12},
                {end, 4}, {payload, "manifest test data".length()}};
        Random random = new Random(0x4145474953L);
        for (int i = 0; i < 300; i++) {
            byte[] mutated = original.clone();
            int[] range = ranges[random.nextInt(ranges.length)];
            mutated[range[0] + random.nextInt(range[1])] ^= (byte) (1 + random.nextInt(255));
            reject(mutated);
        }
    }
    private static void rejectWithReason(byte[] bytes, String reason) throws Exception {
        File file = File.createTempFile("apk-test-", ".apk");
        try {
            Files.write(file.toPath(), bytes);
            try { ApkArchiveInspector.inspect(file); }
            catch (IOException expected) {
                if (!expected.getMessage().contains(reason)) throw new AssertionError(expected);
                assertions++; return;
            }
            throw new AssertionError("Unsafe archive accepted");
        } finally { Files.deleteIfExists(file.toPath()); }
    }
    private static int findSignature(byte[] bytes, int value) {
        for (int p = 0; p < bytes.length - 3; p++) if (signature(bytes, p, value)) return p;
        throw new AssertionError("Missing test fixture signature");
    }
    private static void put32(byte[] bytes, int position, int value) {
        for (int i = 0; i < 4; i++) bytes[position + i] = (byte) (value >>> (i * 8));
    }
    private static void replaceEntryName(byte[] bytes, char from, char to) {
        for (int p = 0; p < bytes.length - 30; p++) {
            int nameOffset = signature(bytes, p, 0x04034b50) ? 30 : signature(bytes, p, 0x02014b50) ? 46 : 0;
            int lengthOffset = nameOffset == 30 ? 26 : 28;
            if (nameOffset > 0 && p + nameOffset < bytes.length && bytes[p + lengthOffset] == 1
                    && bytes[p + lengthOffset + 1] == 0 && bytes[p + nameOffset] == from) bytes[p + nameOffset] = (byte) to;
        }
    }
    private static boolean signature(byte[] bytes, int p, int signature) {
        return p + 4 <= bytes.length && (bytes[p] & 255) == (signature & 255)
                && (bytes[p+1] & 255) == ((signature >>> 8) & 255)
                && (bytes[p+2] & 255) == ((signature >>> 16) & 255)
                && (bytes[p+3] & 255) == ((signature >>> 24) & 255);
    }
}
