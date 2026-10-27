package com.aegis.core;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Capability analysis of an APK's AndroidManifest.xml. Reads the manifest directly (no installation, no execution)
 * and reports capability combinations that malware commonly abuses. Permissions alone never produce more than
 * SUSPICIOUS, because legitimate apps (screen readers, password managers, messengers) use the same capabilities.
 */
public final class ManifestAnalyzer {
    private static final Pattern SAFE = Pattern.compile("[A-Za-z0-9._$]{1,200}");
    private ManifestAnalyzer() {}

    public record Component(String kind, String name, Boolean exported, String permission, List<String> actions) {}
    public record Info(String packageName, String versionName, int minSdk, int targetSdk, boolean debuggable, boolean cleartext,
                       Set<String> permissions, List<Component> components, boolean hasLauncher) {}

    /** Reads AndroidManifest.xml from an APK file with a size cap. Call after ApkArchiveInspector.inspect. */
    public static byte[] readManifest(File apk) throws IOException {
        try (ZipFile zip = new ZipFile(apk)) {
            ZipEntry e = zip.getEntry("AndroidManifest.xml");
            if (e == null || e.getSize() <= 0 || e.getSize() > AxmlParser.MAX_BYTES) throw new IOException("manifest missing or too large");
            try (InputStream in = zip.getInputStream(e)) {
                byte[] data = BoundedRead.atMost(in, AxmlParser.MAX_BYTES + 1);
                if (data.length > AxmlParser.MAX_BYTES) throw new IOException("manifest too large");
                return data;
            }
        }
    }

    public static Info parse(byte[] manifest) throws AxmlParser.AxmlException {
        AxmlParser.Element root = AxmlParser.parse(manifest);
        if (!root.name.equals("manifest")) throw new AxmlParser.AxmlException("root is not <manifest>");
        String pkg = safe(root.attr("package"));
        Set<String> perms = new TreeSet<>();
        List<Component> comps = new ArrayList<>();
        int min = 1, target = 0;
        boolean debuggable = false, cleartext = false, launcher = false;
        for (AxmlParser.Element c : root.children) {
            switch (c.name) {
                case "uses-permission", "uses-permission-sdk-23" -> { String n = c.attr("name"); if (n != null && perms.size() < 1000) perms.add(clip(n)); }
                case "uses-sdk" -> { min = intOr(c.attr("minSdkVersion"), 1); target = intOr(c.attr("targetSdkVersion"), min); }
                case "application" -> {
                    debuggable = "true".equals(c.attr("debuggable"));
                    cleartext = "true".equals(c.attr("usesCleartextTraffic"));
                    for (AxmlParser.Element k : c.children) {
                        if (!(k.name.equals("activity") || k.name.equals("activity-alias") || k.name.equals("service") || k.name.equals("receiver") || k.name.equals("provider"))) continue;
                        List<String> actions = new ArrayList<>(), categories = new ArrayList<>();
                        boolean filter = false;
                        for (AxmlParser.Element f : k.children) if (f.name.equals("intent-filter")) {
                            filter = true;
                            for (AxmlParser.Element x : f.children) {
                                if (x.name.equals("action") && x.attr("name") != null) actions.add(clip(x.attr("name")));
                                if (x.name.equals("category") && x.attr("name") != null) categories.add(clip(x.attr("name")));
                            }
                        }
                        String exp = k.attr("exported");
                        Boolean exported = exp != null ? Boolean.valueOf("true".equals(exp)) : (filter ? Boolean.TRUE : null);
                        if (k.name.startsWith("activity") && actions.contains("android.intent.action.MAIN") && categories.contains("android.intent.category.LAUNCHER")) launcher = true;
                        if (comps.size() < 2000) comps.add(new Component(k.name, safe(k.attr("name")), exported, k.attr("permission") == null ? null : clip(k.attr("permission")), actions));
                    }
                }
                default -> { }
            }
        }
        return new Info(pkg, root.attr("versionName") == null ? "" : clip(root.attr("versionName")), min, target, debuggable, cleartext, perms, comps, launcher);
    }

    private static int intOr(String s, int d) { try { return s == null ? d : Integer.parseInt(s); } catch (NumberFormatException e) { return d; } }
    private static String clip(String s) { String t = s.length() > 200 ? s.substring(0, 200) : s; return t.replaceAll("[\\p{Cntrl}\\p{Cf}]", "?"); }
    private static String safe(String s) { return s != null && SAFE.matcher(s).matches() ? s : (s == null ? "" : "?"); }

    private static boolean has(Info i, String p) { return i.permissions().contains("android.permission." + p); }
    private static boolean hasComponentPermission(Info i, String kind, String permission) {
        for (Component c : i.components()) if (c.kind().equals(kind) && permission.equals(c.permission())) return true;
        return false;
    }

    public static Analysis analyze(Info i) {
        List<Finding> fs = new ArrayList<>();
        fs.add(new Finding("APK_PACKAGE", "Package " + i.packageName() + (i.versionName().isEmpty() ? "" : ", version " + i.versionName()) + ", target API " + i.targetSdk() + "."));
        double score = 0;
        List<String> caps = new ArrayList<>();
        boolean accessibility = hasComponentPermission(i, "service", "android.permission.BIND_ACCESSIBILITY_SERVICE");
        boolean admin = hasComponentPermission(i, "receiver", "android.permission.BIND_DEVICE_ADMIN");
        boolean listener = hasComponentPermission(i, "service", "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE");
        boolean overlay = has(i, "SYSTEM_ALERT_WINDOW");
        boolean sms = has(i, "RECEIVE_SMS") || has(i, "READ_SMS");
        boolean sendSms = has(i, "SEND_SMS");
        boolean installer = has(i, "REQUEST_INSTALL_PACKAGES") || has(i, "INSTALL_PACKAGES");
        boolean boot = has(i, "RECEIVE_BOOT_COMPLETED");
        boolean network = has(i, "INTERNET");
        if (accessibility) { score += 1.5; caps.add("an accessibility service (can read the screen and act for the user)"); }
        if (overlay) { score += 1; caps.add("drawing over other apps"); }
        if (sms) { score += 1; caps.add("reading incoming SMS (one-time codes)"); }
        if (sendSms) { score += 0.5; caps.add("sending SMS"); }
        if (installer) { score += 1; caps.add("requesting installation of other packages"); }
        if (admin) { score += 1; caps.add("a device-administrator receiver"); }
        if (listener) { score += 1; caps.add("a notification listener (can read notifications)"); }
        if (boot) { score += 0.25; caps.add("starting at boot"); }
        if (has(i, "MANAGE_EXTERNAL_STORAGE")) { score += 0.25; caps.add("all-files storage access"); }
        if (!caps.isEmpty()) fs.add(new Finding("APK_CAPABILITIES", "Declared sensitive capabilities: " + String.join("; ", caps) + ". Legitimate apps use these too; this is not proof of misuse."));
        if (i.targetSdk() > 0 && i.targetSdk() < 23 && (sms || sendSms || accessibility)) { score += 0.5; fs.add(new Finding("APK_OLD_TARGET", "The app targets API " + i.targetSdk() + ", which predates runtime permission prompts on Android 6.")); }
        if (!i.hasLauncher() && score >= 2) { score += 0.5; fs.add(new Finding("APK_NO_LAUNCHER", "The app declares sensitive capabilities but no launcher icon activity.")); }
        boolean namedPattern = false;
        if (accessibility && (overlay || sms || installer)) { namedPattern = true; fs.add(new Finding("APK_BANKER_PATTERN", "An accessibility service combined with overlay, SMS or package-install capability is a pattern seen in banking trojans. Many legitimate accessibility tools exist; verify where the file came from.")); }
        if (sms && network && (accessibility || overlay)) { namedPattern = true; fs.add(new Finding("APK_SMS_EXFIL_PATTERN", "SMS access plus network access plus screen access could capture and forward one-time codes.")); }
        if (installer && network && (boot || !i.hasLauncher())) { namedPattern = true; fs.add(new Finding("APK_DROPPER_PATTERN", "The app can request installation of other packages, can use the network, and either starts at boot or has no launcher icon. That is how malware droppers work; app stores and file managers also request install rights, so check where the file came from.")); }
        if (i.debuggable()) fs.add(new Finding("APK_DEBUGGABLE", "The app is marked debuggable, which is unusual for a released app."));
        if (i.cleartext()) fs.add(new Finding("APK_CLEARTEXT", "The app opts in to unencrypted HTTP traffic."));
        int exportedNoPerm = 0;
        for (Component c : i.components()) if (Boolean.TRUE.equals(c.exported()) && c.permission() == null && !c.kind().startsWith("activity")) exportedNoPerm++;
        if (exportedNoPerm > 0) fs.add(new Finding("APK_EXPORTED_COMPONENTS", exportedNoPerm + " service/receiver/provider component(s) are reachable by other apps without a permission. Common in normal apps; a hardening note, not a threat sign."));
        fs.add(new Finding("APK_MANIFEST_LIMITS", "Only the manifest was read. Code, native libraries and runtime behaviour were not analysed; a clean result does not make an app safe."));
        // A named malware pattern is never presented as "no warning signs", whatever the numeric score.
        Analysis.Verdict v = (score >= 3 || namedPattern) ? Analysis.Verdict.SUSPICIOUS : Analysis.Verdict.NO_KNOWN_WARNING_SIGNS;
        return new Analysis(v, fs, i.packageName());
    }

    /** Convenience for the app: parse and analyse, mapping parser failures to INSUFFICIENT_EVIDENCE. */
    public static Analysis analyzeFile(File apk) {
        try { return analyze(parse(readManifest(apk))); }
        catch (IOException | AxmlParser.AxmlException e) {
            return new Analysis(Analysis.Verdict.INSUFFICIENT_EVIDENCE,
                Collections.singletonList(new Finding("APK_MANIFEST_UNREADABLE", "The manifest could not be read or is malformed, so its capabilities could not be assessed.")), "APK");
        }
    }
}
