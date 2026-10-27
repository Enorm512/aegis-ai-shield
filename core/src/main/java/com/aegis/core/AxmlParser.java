package com.aegis.core;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Bounded reader for Android binary XML (AndroidManifest.xml inside an APK). Pure computation on untrusted bytes:
 * every offset and size is validated, element/string counts and depth are capped, and any inconsistency throws.
 * Extracts only what the capability analysis needs.
 */
public final class AxmlParser {
    public static final int MAX_BYTES = 4 * 1024 * 1024, MAX_STRINGS = 100_000, MAX_ELEMENTS = 20_000, MAX_DEPTH = 64, MAX_ATTRS = 256, MAX_STRING_CHARS = 1_000_000;
    private static final String ANDROID_NS = "http://schemas.android.com/apk/res/android";

    public static final class AxmlException extends Exception { public AxmlException(String m) { super(m); } }

    /** One XML element with its attributes resolved to {name -> display value}. Names use the framework attribute name. */
    public static final class Element {
        public final String name;
        public final Map<String, String> attributes = new LinkedHashMap<>();
        public final List<Element> children = new ArrayList<>();
        Element(String name) { this.name = name; }
        public String attr(String n) { return attributes.get(n); }
    }

    // Framework attribute resource ids -> names, so stripped/obfuscated string pools still resolve.
    private static final Map<Integer, String> RES_NAMES = new HashMap<>();
    static {
        RES_NAMES.put(0x01010003, "name"); RES_NAMES.put(0x01010006, "permission"); RES_NAMES.put(0x0101000f, "debuggable");
        RES_NAMES.put(0x01010010, "exported"); RES_NAMES.put(0x01010280, "allowBackup"); RES_NAMES.put(0x010104ec, "usesCleartextTraffic");
        RES_NAMES.put(0x0101020c, "minSdkVersion"); RES_NAMES.put(0x01010270, "targetSdkVersion"); RES_NAMES.put(0x0101021b, "versionCode");
        RES_NAMES.put(0x0101021c, "versionName"); RES_NAMES.put(0x01010001, "label"); RES_NAMES.put(0x01010025, "authorities");
    }

    private final byte[] b;
    private String[] strings;
    private long decodedChars;
    private int[] resIds = new int[0];

    private AxmlParser(byte[] data) { this.b = data; }

    public static Element parse(byte[] data) throws AxmlException {
        if (data == null || data.length < 8 || data.length > MAX_BYTES) throw new AxmlException("size");
        return new AxmlParser(data).run();
    }

    private int u8(int o) throws AxmlException { need(o, 1); return b[o] & 0xFF; }
    private int u16(int o) throws AxmlException { need(o, 2); return (b[o] & 0xFF) | ((b[o + 1] & 0xFF) << 8); }
    private int i32(int o) throws AxmlException { need(o, 4); return (b[o] & 0xFF) | ((b[o + 1] & 0xFF) << 8) | ((b[o + 2] & 0xFF) << 16) | ((b[o + 3] & 0xFF) << 24); }
    private void need(int o, int n) throws AxmlException { if (o < 0 || n < 0 || o > b.length - n) throw new AxmlException("out of bounds"); }

    private Element run() throws AxmlException {
        if (u16(0) != 0x0003 || u16(2) != 8) throw new AxmlException("not binary XML");
        int total = i32(4);
        if (total < 8 || total > b.length) throw new AxmlException("declared size");
        int pos = 8, elements = 0;
        Deque<Element> stack = new ArrayDeque<>();
        Element root = null;
        while (pos < total) {
            need(pos, 8);
            int type = u16(pos), header = u16(pos + 2), size = i32(pos + 4);
            if (size < 8 || header < 8 || header > size || size > total - pos || (size & 3) != 0) throw new AxmlException("chunk bounds");
            switch (type) {
                case 0x0001 -> { if (strings != null) throw new AxmlException("two string pools"); stringPool(pos, size); }
                case 0x0180 -> {
                    int n = (size - header) / 4;
                    if (n > MAX_STRINGS) throw new AxmlException("resource map");
                    resIds = new int[n];
                    for (int i = 0; i < n; i++) resIds[i] = i32(pos + header + i * 4);
                }
                case 0x0102 -> {
                    if (strings == null) throw new AxmlException("element before string pool");
                    if (++elements > MAX_ELEMENTS || stack.size() >= MAX_DEPTH) throw new AxmlException("too large");
                    Element e = startElement(pos, header, size);
                    if (stack.isEmpty()) { if (root != null) throw new AxmlException("multiple roots"); root = e; } else stack.peek().children.add(e);
                    stack.push(e);
                }
                case 0x0103 -> { if (stack.isEmpty()) throw new AxmlException("unbalanced"); stack.pop(); }
                default -> { /* namespaces, CDATA, unknown: skipped */ }
            }
            pos += size;
        }
        if (root == null || !stack.isEmpty()) throw new AxmlException("incomplete document");
        return root;
    }

    private void stringPool(int pos, int size) throws AxmlException {
        int count = i32(pos + 8), flags = i32(pos + 16), start = i32(pos + 20);
        if (count < 0 || count > MAX_STRINGS || start < 0 || start > size) throw new AxmlException("string pool header");
        if (pos + u16(pos + 2) + (long) count * 4 > pos + size) throw new AxmlException("string offsets");
        boolean utf8 = (flags & 0x100) != 0;
        strings = new String[count];
        for (int i = 0; i < count; i++) {
            int off = i32(pos + u16(pos + 2) + i * 4);
            if (off < 0 || off > size - start) throw new AxmlException("string offset");
            strings[i] = readString(pos + start + off, pos + size, utf8);
            decodedChars += strings[i].length();
            if (decodedChars > MAX_STRING_CHARS) throw new AxmlException("string pool expands beyond limit");
        }
    }

    private String readString(int o, int limit, boolean utf8) throws AxmlException {
        if (utf8) {
            int[] lens = new int[2];
            for (int k = 0; k < 2; k++) {
                int l = u8(o++);
                if ((l & 0x80) != 0) l = ((l & 0x7F) << 8) | u8(o++);
                lens[k] = l;
            }
            if (lens[1] > 4096 || o + lens[1] > limit) throw new AxmlException("string length");
            need(o, lens[1]);
            return new String(b, o, lens[1], StandardCharsets.UTF_8);
        }
        int len = u16(o); o += 2;
        if ((len & 0x8000) != 0) { len = ((len & 0x7FFF) << 16) | u16(o); o += 2; }
        if (len > 4096 || o + len * 2L > limit) throw new AxmlException("string length");
        need(o, len * 2);
        return new String(b, o, len * 2, StandardCharsets.UTF_16LE);
    }

    private String str(int i) throws AxmlException {
        if (i < 0) return null;
        if (i >= strings.length) throw new AxmlException("string index");
        return strings[i];
    }

    private Element startElement(int pos, int header, int size) throws AxmlException {
        int ext = pos + header;
        need(ext, 20);
        String name = str(i32(ext + 4));
        if (name == null) throw new AxmlException("element name");
        int attrStart = u16(ext + 8), attrSize = u16(ext + 10), attrCount = u16(ext + 12);
        if (attrCount > MAX_ATTRS || attrSize < 20 || ext + attrStart + (long) attrCount * attrSize > pos + size) throw new AxmlException("attributes");
        Element e = new Element(name);
        for (int i = 0; i < attrCount; i++) {
            int a = ext + attrStart + i * attrSize;
            int nsIdx = i32(a), nameIdx = i32(a + 4), raw = i32(a + 8), dataType = u8(a + 15), data = i32(a + 16);
            // Android honours only android:-namespace attributes (and the namespace-less root "package"); anything else
            // must not be able to shadow or replace them.
            boolean androidNs = nsIdx >= 0 && ANDROID_NS.equals(str(nsIdx));
            String n = androidNs && nameIdx >= 0 && nameIdx < resIds.length && RES_NAMES.containsKey(resIds[nameIdx]) ? RES_NAMES.get(resIds[nameIdx]) : str(nameIdx);
            if (n == null) continue;
            if (!androidNs && !(nsIdx < 0 && n.equals("package"))) continue;
            if (e.attributes.containsKey(n)) throw new AxmlException("duplicate attribute " + n);
            String v;
            switch (dataType) {
                case 0x03 -> v = str(data >= 0 ? data : raw);
                case 0x12 -> v = data != 0 ? "true" : "false";
                case 0x10, 0x11 -> v = Integer.toString(data);
                case 0x01 -> v = "@ref";
                default -> v = raw >= 0 && raw < strings.length ? strings[raw] : "?";
            }
            e.attributes.put(n, v);
        }
        return e;
    }
}
