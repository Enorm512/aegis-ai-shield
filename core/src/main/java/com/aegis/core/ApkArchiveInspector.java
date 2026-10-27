package com.aegis.core;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.RandomAccessFile;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.Map;
import java.util.TreeMap;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Bounded, non-extracting ZIP validation performed before platform APK parsing. */
public final class ApkArchiveInspector {
    private static final long MIB = 1024L * 1024L;
    private static final long MAX_FILE = 128 * MIB;
    private static final long MAX_TOTAL = 256 * MIB;
    private static final long MAX_ENTRY = 64 * MIB;
    private static final long MAX_MANIFEST = 4 * MIB;
    private static final int MAX_ENTRIES = 10000;
    private ApkArchiveInspector() { }

    public static void inspect(File file) throws IOException {
        checkInterrupted();
        if (!file.isFile() || file.length() < 22 || file.length() > MAX_FILE) {
            throw invalid("Archive file size is outside limits");
        }
        int expectedCount = validateHeaders(file);
        Set<String> names = new HashSet<String>();
        long total = 0;
        int count = 0;
        boolean manifest = false;
        byte[] buffer = new byte[32768];
        try (ZipFile zip = new ZipFile(file)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                checkInterrupted();
                ZipEntry entry = entries.nextElement();
                if (++count > MAX_ENTRIES) throw invalid("Too many entries");
                String name = entry.getName();
                validateName(name);
                if (!names.add(name)) throw invalid("Duplicate entry");
                boolean isManifest = "AndroidManifest.xml".equals(name);
                manifest |= isManifest;
                long limit = isManifest ? MAX_MANIFEST : MAX_ENTRY;
                if (entry.getSize() < 0 || (isManifest && entry.getSize() == 0)
                        || entry.getSize() > limit || entry.getCompressedSize() < 0) {
                    throw invalid("Entry size is outside limits");
                }
                CRC32 crc = new CRC32();
                long actual = 0;
                try (InputStream in = zip.getInputStream(entry)) {
                    int zeroReads = 0;
                    while (true) {
                        checkInterrupted();
                        int read = in.read(buffer);
                        if (read == -1) break;
                        if (read == 0) {
                            if (++zeroReads > 8) throw invalid("Non-progressing ZIP stream");
                            continue;
                        }
                        zeroReads = 0;
                        actual += read;
                        total += read;
                        if (actual > limit || total > MAX_TOTAL) throw invalid("Decompression limit exceeded");
                        if (actual > MIB && actual > Math.max(1L, entry.getCompressedSize()) * 200L) {
                            throw invalid("Suspicious compression ratio");
                        }
                        crc.update(buffer, 0, read);
                    }
                }
                if (actual != entry.getSize() || crc.getValue() != entry.getCrc()) {
                    throw invalid("Entry length or CRC mismatch");
                }
                if (entry.isDirectory() && actual != 0) throw invalid("Directory contains data");
            }
        } catch (IllegalArgumentException e) {
            throw new IOException("Invalid ZIP metadata", e);
        }
        if (count != expectedCount || !manifest) throw invalid("Missing root manifest or entry count mismatch");
    }

    private static void validateName(String name) throws IOException {
        if (name.isEmpty() || name.startsWith("/") || name.indexOf('\\') >= 0
                || name.indexOf('\0') >= 0 || name.indexOf(':') >= 0) throw invalid("Unsafe entry path");
        String path = name.endsWith("/") ? name.substring(0, name.length() - 1) : name;
        for (String part : path.split("/", -1)) {
            if (part.isEmpty() || ".".equals(part) || "..".equals(part)) throw invalid("Unsafe entry path");
        }
    }

    // Inspect flags directly: ZipEntry does not expose encryption or disk metadata.
    // Reject ZIP64 and split archives instead of allowing ambiguous parser behavior.
    private static int validateHeaders(File file) throws IOException {
        try (RandomAccessFile in = new RandomAccessFile(file, "r")) {
            long length = in.length();
            long end = -1;
            for (long p = length - 22, min = Math.max(0, length - 65557); p >= min; p--) {
                checkInterrupted();
                in.seek(p);
                if (u32(in) == 0x06054b50L) {
                    in.seek(p + 20);
                    if (p + 22 + u16(in) == length) { end = p; break; }
                }
            }
            if (end < 0) throw invalid("Missing ZIP end record");
            in.seek(end + 4);
            int disk = u16(in), centralDisk = u16(in), onDisk = u16(in), count = u16(in);
            long centralSize = u32(in), centralOffset = u32(in);
            if (disk != 0 || centralDisk != 0 || onDisk != count || count == 0
                    || count > MAX_ENTRIES || centralSize == 0xffffffffL || centralOffset == 0xffffffffL
                    || centralOffset + centralSize != end) throw invalid("Unsupported ZIP directory");
            long position = centralOffset;
            TreeMap<Long, Long> localSpans = new TreeMap<Long, Long>();
            for (int i = 0; i < count; i++) {
                checkInterrupted();
                if (position + 46 > end) throw invalid("Truncated central directory");
                in.seek(position);
                if (u32(in) != 0x02014b50L) throw invalid("Invalid central header");
                in.seek(position + 8);
                int flags = u16(in), method = u16(in);
                if ((flags & (1 | 0x40 | 0x2000)) != 0 || (method != 0 && method != 8)) {
                    throw invalid("Encrypted or unsupported ZIP entry");
                }
                in.seek(position + 16);
                long expectedCrc = u32(in);
                long compressed = u32(in), expanded = u32(in);
                int nameLength = u16(in), extraLength = u16(in), commentLength = u16(in), startDisk = u16(in);
                in.seek(position + 42);
                long local = u32(in);
                long next = position + 46L + nameLength + extraLength + commentLength;
                if (startDisk != 0 || compressed == 0xffffffffL || expanded == 0xffffffffL
                        || local == 0xffffffffL || next > end || local + 30 > centralOffset) throw invalid("Invalid entry bounds");
                byte[] name = new byte[nameLength];
                in.readFully(name);
                in.seek(local);
                if (u32(in) != 0x04034b50L) throw invalid("Missing local header");
                in.seek(local + 6);
                if (u16(in) != flags || u16(in) != method) throw invalid("Conflicting local header");
                if ((flags & 8) == 0) {
                    in.seek(local + 14);
                    if (u32(in) != expectedCrc || u32(in) != compressed || u32(in) != expanded) {
                        throw invalid("Conflicting local CRC or sizes");
                    }
                }
                in.seek(local + 26);
                int localNameLength = u16(in), localExtraLength = u16(in);
                if (localNameLength != nameLength
                        || local + 30L + localNameLength + localExtraLength + compressed > centralOffset) {
                    throw invalid("Invalid local entry bounds");
                }
                byte[] localName = new byte[localNameLength];
                in.readFully(localName);
                if (!Arrays.equals(name, localName)) throw invalid("Conflicting entry names");
                long spanEnd = local + 30L + localNameLength + localExtraLength + compressed;
                if ((flags & 8) != 0) {
                    if (spanEnd + 12 > centralOffset) throw invalid("Truncated data descriptor");
                    in.seek(spanEnd);
                    long descriptorCrc = u32(in);
                    if (descriptorCrc == 0x08074b50L) {
                        if (spanEnd + 16 > centralOffset) throw invalid("Truncated data descriptor");
                        descriptorCrc = u32(in);
                        spanEnd += 4;
                    }
                    if (descriptorCrc != expectedCrc || u32(in) != compressed || u32(in) != expanded) {
                        throw invalid("Conflicting data descriptor");
                    }
                    spanEnd += 12;
                }
                Map.Entry<Long, Long> previous = localSpans.floorEntry(local);
                Map.Entry<Long, Long> following = localSpans.ceilingEntry(local);
                if ((previous != null && previous.getValue() > local)
                        || (following != null && following.getKey() < spanEnd)) {
                    throw invalid("Overlapping local entry spans");
                }
                localSpans.put(local, spanEnd);
                position = next;
            }
            if (position != end) throw invalid("Central directory length mismatch");
            return count;
        }
    }

    private static int u16(RandomAccessFile in) throws IOException {
        int a = in.readUnsignedByte(), b = in.readUnsignedByte();
        return a | (b << 8);
    }
    private static long u32(RandomAccessFile in) throws IOException {
        return (long) u16(in) | ((long) u16(in) << 16);
    }
    private static IOException invalid(String reason) { return new IOException(reason); }
    private static void checkInterrupted() throws InterruptedIOException {
        if (Thread.currentThread().isInterrupted()) throw new InterruptedIOException("APK inspection interrupted");
    }
}
