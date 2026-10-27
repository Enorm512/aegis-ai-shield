package com.aegis.core;

import java.io.File;
import java.nio.file.*;
import java.util.*;
import static com.aegis.core.Analysis.Verdict.*;

public final class ManifestTests {
    private static int checks;
    private static void check(boolean ok, String message) { checks++; if (!ok) throw new AssertionError(message); }
    private static final String DIR = "src/test/fixtures/manifests/";

    public static void main(String[] args) throws Exception {
        // Real binary XML produced by aapt2 from the sources in the same folder.
        ManifestAnalyzer.Info benign = ManifestAnalyzer.parse(ManifestAnalyzer.readManifest(new File(DIR + "benign.apk")));
        check(benign.packageName().equals("com.example.benign") && benign.versionName().equals("1.2.3") && benign.minSdk() == 26 && benign.targetSdk() == 35, "benign header fields");
        check(benign.permissions().equals(Set.of("android.permission.INTERNET")) && benign.hasLauncher() && !benign.debuggable(), "benign permissions/launcher");
        check(benign.components().size() == 2 && Boolean.FALSE.equals(benign.components().get(1).exported()), "explicit exported=false read");
        check(ManifestAnalyzer.analyze(benign).verdict == NO_KNOWN_WARNING_SIGNS, "benign has no warning signs");

        ManifestAnalyzer.Info t = ManifestAnalyzer.parse(ManifestAnalyzer.readManifest(new File(DIR + "trojan_pattern.apk")));
        check(t.targetSdk() == 21 && t.debuggable() && t.cleartext() && !t.hasLauncher() && t.permissions().size() == 7, "capability fixture fields");
        check(t.components().stream().anyMatch(c -> c.kind().equals("service") && "android.permission.BIND_ACCESSIBILITY_SERVICE".equals(c.permission())), "accessibility service detected from component permission");
        Analysis ta = ManifestAnalyzer.analyze(t);
        Set<String> codes = new HashSet<>(); for (Finding f : ta.findings) codes.add(f.code);
        check(ta.verdict == SUSPICIOUS, "capability combination is suspicious");
        check(codes.containsAll(Set.of("APK_BANKER_PATTERN", "APK_SMS_EXFIL_PATTERN", "APK_NO_LAUNCHER", "APK_OLD_TARGET", "APK_DEBUGGABLE", "APK_CLEARTEXT", "APK_CAPABILITIES", "APK_MANIFEST_LIMITS")), "expected findings: " + codes);
        check(ta.verdict.compareTo(SUSPICIOUS) <= 0, "permissions alone never exceed SUSPICIOUS");

        Analysis tool = ManifestAnalyzer.analyze(ManifestAnalyzer.parse(ManifestAnalyzer.readManifest(new File(DIR + "accessibility_tool.apk"))));
        check(tool.verdict == NO_KNOWN_WARNING_SIGNS, "an accessibility service alone is not flagged (false-positive guard)");
        check(tool.findings.stream().anyMatch(f -> f.code.equals("APK_CAPABILITIES")), "but the capability is disclosed");
        check(ManifestAnalyzer.analyzeFile(new File(DIR + "trojan_pattern.apk")).verdict == SUSPICIOUS, "analyzeFile end to end");
        check(ManifestAnalyzer.analyzeFile(new File(DIR + "trojan_pattern.xml")).verdict == INSUFFICIENT_EVIDENCE, "non-zip file -> insufficient");
        check(ManifestAnalyzer.analyzeFile(new File(DIR + "missing.apk")).verdict == INSUFFICIENT_EVIDENCE, "missing file -> insufficient");

        // Hostile input: every truncation, every single-byte corruption, random bytes. Only AxmlException may escape.
        byte[] raw = ManifestAnalyzer.readManifest(new File(DIR + "trojan_pattern.apk"));
        int parsedOk = 0, rejected = 0;
        for (int len = 0; len < raw.length; len++) {
            try { ManifestAnalyzer.parse(Arrays.copyOf(raw, len)); parsedOk++; } catch (AxmlParser.AxmlException e) { rejected++; }
        }
        check(rejected >= raw.length - 1 && parsedOk <= 1, "truncations rejected (parsed " + parsedOk + ")");
        long t0 = System.nanoTime();
        for (int i = 0; i < raw.length; i++) for (int v : new int[] {0x00, 0x01, 0x7F, 0x80, 0xFF, 0xFE}) {
            byte[] m = raw.clone(); m[i] = (byte) v;
            try { ManifestAnalyzer.analyze(ManifestAnalyzer.parse(m)); parsedOk++; } catch (AxmlParser.AxmlException e) { rejected++; }
        }
        check((System.nanoTime() - t0) / 1_000_000 < 20_000, "mutation sweep finished quickly");
        Random r = new Random(11);
        for (int i = 0; i < 5000; i++) {
            byte[] m = raw.clone();
            for (int k = 1 + r.nextInt(8); k > 0; k--) m[r.nextInt(m.length)] = (byte) r.nextInt(256);
            try { ManifestAnalyzer.analyze(ManifestAnalyzer.parse(m)); } catch (AxmlParser.AxmlException e) { }
        }
        for (int i = 0; i < 3000; i++) { byte[] j = new byte[r.nextInt(300)]; r.nextBytes(j); if (j.length > 8) { j[0] = 3; j[1] = 0; j[2] = 8; j[3] = 0; } try { AxmlParser.parse(j); } catch (AxmlParser.AxmlException e) { } }
        check(true, "mutated and random manifests never escape as unchecked exceptions");
        // Mutants that still parse must still produce a bounded, sanitised result
        for (int i = 0; i < raw.length; i++) {
            byte[] m = raw.clone(); m[i] ^= 0x20;
            try {
                ManifestAnalyzer.Info info = ManifestAnalyzer.parse(m);
                check(info.packageName().matches("[A-Za-z0-9._$?]{0,200}") && info.components().size() <= 2000, "sanitised package at byte " + i);
                for (Finding f : ManifestAnalyzer.analyze(info).findings) check(f.detail.chars().noneMatch(c -> c < 0x20), "no control characters in findings");
            } catch (AxmlParser.AxmlException e) { }
        }
        // Regression tests for the independent review (2026-10-26): hand-built hostile binary XML
        String NS = "http://schemas.android.com/apk/res/android";
        // 1. A non-android attribute called "name" must not replace android:name
        byte[] shadow = Axml.manifest(NS, "foo-ns", new String[][] {
            {"uses-permission", "A:name=android.permission.RECEIVE_SMS", "F:name=x"} });
        ManifestAnalyzer.Info si = ManifestAnalyzer.parse(shadow);
        check(si.permissions().contains("android.permission.RECEIVE_SMS") && !si.permissions().contains("x"), "foreign-namespace attribute cannot shadow android:name: " + si.permissions());
        // 2. Duplicate android attributes are rejected rather than resolved by order
        try { ManifestAnalyzer.parse(Axml.manifest(NS, "foo-ns", new String[][] {{"uses-permission", "A:name=a.b", "A:name=c.d"}})); check(false, "duplicate attribute"); }
        catch (AxmlParser.AxmlException e) { check(true, "duplicate attribute rejected"); }
        // 3. Service permission attribute cannot be hidden from the capability analysis
        ManifestAnalyzer.Info hidden = ManifestAnalyzer.parse(Axml.manifest(NS, "foo-ns", new String[][] {
            {"application"}, {"service", "A:name=.S", "A:permission=android.permission.BIND_ACCESSIBILITY_SERVICE", "F:permission=none"}}));
        check(hidden.components().stream().anyMatch(c -> "android.permission.BIND_ACCESSIBILITY_SERVICE".equals(c.permission())), "service permission survives shadowing attempt");
        // 4. A string pool whose offsets all point at one huge string cannot exhaust memory
        long mem0 = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
        byte[] bomb = Axml.poolBomb(100_000, 4000);
        check(bomb.length < AxmlParser.MAX_BYTES, "bomb is a small file: " + bomb.length);
        try { AxmlParser.parse(bomb); check(false, "string pool bomb"); } catch (AxmlParser.AxmlException e) { check(e.getMessage().contains("string pool"), "string pool amplification rejected: " + e.getMessage()); }
        check(AxmlParser.MAX_BYTES == 4 * 1024 * 1024, "limits unchanged");
        try { AxmlParser.parse(new byte[AxmlParser.MAX_BYTES + 1]); check(false, "oversize"); } catch (AxmlParser.AxmlException e) { check(true, "oversize rejected"); }
        System.out.println("ManifestTests: " + checks + " checks passed (" + parsedOk + " mutants still parsed, " + rejected + " rejected)");
    }

    /** Minimal binary-XML writer for hostile test inputs (UTF-16 string pool, no namespaces chunks). */
    static final class Axml {
        private static void le32(java.io.ByteArrayOutputStream o, int v) { o.write(v); o.write(v >> 8); o.write(v >> 16); o.write(v >> 24); }
        private static void le16(java.io.ByteArrayOutputStream o, int v) { o.write(v); o.write(v >> 8); }

        private static byte[] pool(List<String> strings) {
            java.io.ByteArrayOutputStream data = new java.io.ByteArrayOutputStream();
            int[] offsets = new int[strings.size()];
            for (int i = 0; i < offsets.length; i++) {
                offsets[i] = data.size();
                le16(data, strings.get(i).length());
                for (char c : strings.get(i).toCharArray()) le16(data, c);
                le16(data, 0);
            }
            while (data.size() % 4 != 0) data.write(0);
            java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
            int header = 28, stringsStart = header + 4 * offsets.length;
            le16(o, 1); le16(o, header); le32(o, stringsStart + data.size()); le32(o, offsets.length); le32(o, 0); le32(o, 0); le32(o, stringsStart); le32(o, 0);
            for (int off : offsets) le32(o, off);
            o.writeBytes(data.toByteArray());
            return o.toByteArray();
        }

        /** Elements: {name, "A:attr=value" (android namespace) or "F:attr=value" (foreign namespace), ...}; all under <manifest package="p">. */
        static byte[] manifest(String androidNs, String foreignNs, String[][] elements) {
            List<String> pool = new ArrayList<>(List.of(androidNs, foreignNs, "manifest", "package", "p.q"));
            java.util.function.Function<String, Integer> idx = x -> { int i = pool.indexOf(x); if (i < 0) { pool.add(x); i = pool.size() - 1; } return i; };
            java.io.ByteArrayOutputStream body = new java.io.ByteArrayOutputStream();
            startElement(body, -1, idx.apply("manifest"), new int[][] {{-1, idx.apply("package"), idx.apply("p.q")}});
            boolean openApplication = false;
            Map<String, Integer> resId = new HashMap<>();
            resId.put("name", 0x01010003); resId.put("permission", 0x01010006);
            for (String[] e : elements) {
                int[][] attrs = new int[e.length - 1][];
                for (int i = 1; i < e.length; i++) {
                    boolean android = e[i].startsWith("A:");
                    String[] kv = e[i].substring(2).split("=", 2);
                    attrs[i - 1] = new int[] {idx.apply(android ? androidNs : foreignNs), idx.apply(kv[0]), idx.apply(kv[1])};
                }
                startElement(body, -1, idx.apply(e[0]), attrs);
                if (e[0].equals("application")) openApplication = true; // later elements nest inside <application>
                else endElement(body, idx.apply(e[0]));
            }
            if (openApplication) endElement(body, idx.apply("application"));
            endElement(body, idx.apply("manifest"));
            // Resource map: android-namespace attribute names get their framework ids (index-aligned with the pool).
            java.io.ByteArrayOutputStream map = new java.io.ByteArrayOutputStream();
            int n = pool.size();
            le16(map, 0x180); le16(map, 8); le32(map, 8 + 4 * n);
            for (String sname : pool) le32(map, resId.getOrDefault(sname, 0));
            byte[] pl = pool(pool), rm = map.toByteArray(), bd = body.toByteArray();
            java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
            le16(o, 3); le16(o, 8); le32(o, 8 + pl.length + rm.length + bd.length);
            o.writeBytes(pl); o.writeBytes(rm); o.writeBytes(bd);
            return o.toByteArray();
        }

        private static void startElement(java.io.ByteArrayOutputStream o, int ns, int name, int[][] attrs) {
            le16(o, 0x102); le16(o, 16); le32(o, 36 + 20 * attrs.length); le32(o, 1); le32(o, -1);
            le32(o, ns); le32(o, name); le16(o, 0x14); le16(o, 0x14); le16(o, attrs.length); le16(o, 0); le16(o, 0); le16(o, 0);
            for (int[] a : attrs) { le32(o, a[0]); le32(o, a[1]); le32(o, a[2]); le16(o, 8); o.write(0); o.write(3); le32(o, a[2]); }
        }
        private static void endElement(java.io.ByteArrayOutputStream o, int name) { le16(o, 0x103); le16(o, 16); le32(o, 24); le32(o, 1); le32(o, -1); le32(o, -1); le32(o, name); }

        /** count offsets that all point at the same long non-Latin-1 string. */
        static byte[] poolBomb(int count, int chars) {
            java.io.ByteArrayOutputStream data = new java.io.ByteArrayOutputStream();
            le16(data, chars); for (int i = 0; i < chars; i++) le16(data, 0x4e00 + (i % 100)); le16(data, 0);
            while (data.size() % 4 != 0) data.write(0);
            java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
            int header = 28, stringsStart = header + 4 * count;
            le16(o, 1); le16(o, header); le32(o, stringsStart + data.size()); le32(o, count); le32(o, 0); le32(o, 0); le32(o, stringsStart); le32(o, 0);
            for (int i = 0; i < count; i++) le32(o, 0);
            o.writeBytes(data.toByteArray());
            byte[] pl = o.toByteArray();
            java.io.ByteArrayOutputStream all = new java.io.ByteArrayOutputStream();
            le16(all, 3); le16(all, 8); le32(all, 8 + pl.length);
            all.writeBytes(pl);
            return all.toByteArray();
        }
    }
}
