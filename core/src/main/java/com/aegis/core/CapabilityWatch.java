package com.aegis.core;

import java.util.*;

/**
 * "Who can control or read this phone": the high-power capabilities a rogue agent or spyware app needs, which apps hold
 * them, what changed since the person last looked, and how worrying each holder is. Pure logic; the Android adapter
 * collects the holders. Aegis never revokes anything itself: it makes the powers visible and links to system settings.
 */
public final class CapabilityWatch {
    private CapabilityWatch() {}

    public enum Capability {
        /** Accessibility service: can read everything on screen and tap, type and swipe for the person. */
        ACCESSIBILITY,
        /** Notification listener: can read all notifications, including one-time codes and messages. */
        NOTIFICATION_ACCESS,
        /** Device administrator: can lock or wipe the phone and resist uninstalling. */
        DEVICE_ADMIN,
        /** Default SMS app: receives every SMS, including bank codes. */
        DEFAULT_SMS,
        /** Enabled keyboard: sees everything typed, including passwords. */
        INPUT_METHOD,
        /** Active VPN that is not Aegis: can see or redirect network traffic. */
        VPN
    }

    public enum Risk { LOW, MEDIUM, HIGH }

    /** One app holding one capability. preinstalled = shipped with the phone (system image). */
    public record Holder(Capability capability, String packageName, boolean preinstalled) implements Comparable<Holder> {
        public int compareTo(Holder o) {
            int c = capability.compareTo(o.capability);
            return c != 0 ? c : packageName.compareTo(o.packageName);
        }
    }

    public record Change(Holder holder, boolean added) {}

    /** All capabilities of one app with an overall risk and stable reason codes for the UI. */
    public record AppSummary(String packageName, boolean preinstalled, Set<Capability> capabilities, Risk risk, List<String> reasons) {}

    public static final int MAX_HOLDERS = 2000;
    /** Package names as Android allows them (letters, digits, underscore, dots); "unknown" is used when a VPN owner cannot be identified. */
    private static final java.util.regex.Pattern PACKAGE = java.util.regex.Pattern.compile("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)*");

    public static boolean validPackage(String p) { return p != null && p.length() <= 255 && PACKAGE.matcher(p).matches(); }

    public static final class Snapshot {
        private final SortedSet<Holder> holders;
        public Snapshot(Collection<Holder> in) {
            TreeSet<Holder> s = new TreeSet<>();
            for (Holder h : in) {
                if (h == null || h.capability() == null || !validPackage(h.packageName())) continue;
                if (s.size() >= MAX_HOLDERS) break;
                s.add(h);
            }
            holders = Collections.unmodifiableSortedSet(s);
        }
        public SortedSet<Holder> holders() { return holders; }

        /** Stable text form, one "CAPABILITY package 0|1" line per holder. */
        public String serialize() {
            StringBuilder b = new StringBuilder("AEGIS-CAPS 1\n");
            for (Holder h : holders) b.append(h.capability().name()).append(' ').append(h.packageName()).append(' ').append(h.preinstalled() ? '1' : '0').append('\n');
            return b.toString();
        }

        /** Parses serialize() output; malformed lines are skipped. Returns null when the text is not a snapshot at all (no baseline yet). */
        public static Snapshot parse(String text) {
            if (text == null || !text.startsWith("AEGIS-CAPS 1\n")) return null;
            List<Holder> out = new ArrayList<>();
            String[] lines = text.split("\n");
            for (int i = 1; i < lines.length && out.size() < MAX_HOLDERS; i++) {
                String[] f = lines[i].split(" ");
                if (f.length != 3 || !(f[2].equals("0") || f[2].equals("1"))) continue;
                try { out.add(new Holder(Capability.valueOf(f[0]), f[1], f[2].equals("1"))); } catch (IllegalArgumentException ignored) { }
            }
            return new Snapshot(out);
        }
    }

    /** What appeared and disappeared, by capability then package. A missing baseline yields no changes (first look is the baseline). */
    public static List<Change> diff(Snapshot before, Snapshot now) {
        List<Change> out = new ArrayList<>();
        if (before == null || now == null) return out;
        Set<String> beforeKeys = keys(before), nowKeys = keys(now);
        for (Holder h : now.holders()) if (!beforeKeys.contains(key(h))) out.add(new Change(h, true));
        for (Holder h : before.holders()) if (!nowKeys.contains(key(h))) out.add(new Change(h, false));
        return out;
    }

    private static String key(Holder h) { return h.capability().name() + " " + h.packageName(); } // the preinstalled flag is not a change
    private static Set<String> keys(Snapshot s) { Set<String> k = new HashSet<>(); for (Holder h : s.holders()) k.add(key(h)); return k; }

    /** Changes that deserve an alert: new grants of a capability, never removals (losing a power is good news). */
    public static List<Change> alerts(List<Change> changes, String ownPackage) {
        List<Change> out = new ArrayList<>();
        for (Change c : changes) if (c.added() && !c.holder().packageName().equals(ownPackage)) out.add(c);
        return out;
    }

    /**
     * Risk per app, highest first. Reason codes:
     *   READ_AND_ACT: accessibility plus notification access in one app (can read codes and act on them: the strongest rogue-agent pattern)
     *   SCREEN_CONTROL, READS_NOTIFICATIONS, DEVICE_ADMIN, SMS_HANDLER, KEYBOARD, VPN: single capabilities
     *   NOT_PREINSTALLED: installed by the person or another app rather than shipped with the phone
     */
    public static List<AppSummary> byApp(Snapshot s, String ownPackage) {
        Map<String, EnumSet<Capability>> caps = new TreeMap<>();
        Map<String, Boolean> pre = new HashMap<>();
        for (Holder h : s.holders()) {
            if (h.packageName().equals(ownPackage)) continue;
            caps.computeIfAbsent(h.packageName(), k -> EnumSet.noneOf(Capability.class)).add(h.capability());
            pre.merge(h.packageName(), h.preinstalled(), Boolean::logicalAnd);
        }
        List<AppSummary> out = new ArrayList<>();
        for (Map.Entry<String, EnumSet<Capability>> e : caps.entrySet()) {
            Set<Capability> c = e.getValue();
            boolean preinstalled = pre.get(e.getKey());
            List<String> reasons = new ArrayList<>();
            int score = 0;
            if (c.contains(Capability.ACCESSIBILITY) && c.contains(Capability.NOTIFICATION_ACCESS)) { reasons.add("READ_AND_ACT"); score += 4; }
            if (c.contains(Capability.ACCESSIBILITY)) { reasons.add("SCREEN_CONTROL"); score += 3; }
            if (c.contains(Capability.NOTIFICATION_ACCESS)) { reasons.add("READS_NOTIFICATIONS"); score += 2; }
            if (c.contains(Capability.DEVICE_ADMIN)) { reasons.add("DEVICE_ADMIN"); score += 2; }
            if (c.contains(Capability.DEFAULT_SMS)) { reasons.add("SMS_HANDLER"); score += 1; }
            if (c.contains(Capability.INPUT_METHOD)) { reasons.add("KEYBOARD"); score += 1; }
            if (c.contains(Capability.VPN)) { reasons.add("VPN"); score += 1; }
            if (!preinstalled) { reasons.add("NOT_PREINSTALLED"); score += 1; }
            // Preinstalled holders are expected on most phones (system keyboard, SMS app, Find My Device): cap them at MEDIUM.
            Risk r = score >= 4 ? Risk.HIGH : score >= 2 ? Risk.MEDIUM : Risk.LOW;
            if (preinstalled && r == Risk.HIGH && !reasons.contains("READ_AND_ACT")) r = Risk.MEDIUM;
            out.add(new AppSummary(e.getKey(), preinstalled, Collections.unmodifiableSet(EnumSet.copyOf(c)), r, Collections.unmodifiableList(reasons)));
        }
        out.sort((a, b) -> a.risk() != b.risk() ? b.risk().compareTo(a.risk()) : a.packageName().compareTo(b.packageName()));
        return out;
    }

    /** Where an app came from, as far as Android reports it. */
    public enum Installer { STORE, PREINSTALLED, SIDELOADED, OTHER_APP, UNKNOWN }

    private static final Set<String> STORES = new HashSet<>(Arrays.asList("com.android.vending", "com.sec.android.app.samsungapps", "com.huawei.appmarket", "com.amazon.venezia", "org.fdroid.fdroid", "com.heytap.market", "com.xiaomi.mipicks"));
    private static final Set<String> PACKAGE_INSTALLERS = new HashSet<>(Arrays.asList("com.google.android.packageinstaller", "com.android.packageinstaller", "com.samsung.android.packageinstaller"));

    /** Classifies the installer package Android reports (null when it reports none). */
    public static Installer installerOf(String installerPackage, boolean systemApp) {
        if (systemApp) return Installer.PREINSTALLED;
        if (installerPackage == null || installerPackage.isEmpty()) return Installer.UNKNOWN;
        if (STORES.contains(installerPackage)) return Installer.STORE;
        if (PACKAGE_INSTALLERS.contains(installerPackage)) return Installer.SIDELOADED;
        return validPackage(installerPackage) ? Installer.OTHER_APP : Installer.UNKNOWN;
    }

    /**
     * What the person should know before letting an app act as an AI agent. needsExtraConfirm = Aegis asks the person to
     * confirm on purpose before Allow works: an app with Accessibility can read Aegis' screen and tap for the person, so it
     * could approve its own requests; device admin and read-and-act are also reasons. Reason codes:
     *   SCREEN_CONTROL, READ_AND_ACT, READS_NOTIFICATIONS, DEVICE_ADMIN, SMS_HANDLER, KEYBOARD, VPN: powers it already holds
     *   CAN_APPROVE_ITSELF: Accessibility means it can tap Allow/Approve in Aegis by itself
     *   DRAWS_OVER_APPS: asks to draw over other apps (can cover or imitate dialogs)
     *   SIDELOADED, INSTALLED_BY_OTHER_APP, INSTALL_SOURCE_UNKNOWN: not from an app store
     */
    public record PairingAdvice(Risk risk, List<String> reasons, boolean needsExtraConfirm) {}

    public static PairingAdvice pairingAdvice(Set<Capability> held, boolean drawsOverApps, Installer installer) {
        Set<Capability> c = held == null ? EnumSet.noneOf(Capability.class) : held;
        List<String> reasons = new ArrayList<>();
        int score = 0;
        boolean screen = c.contains(Capability.ACCESSIBILITY);
        if (screen && c.contains(Capability.NOTIFICATION_ACCESS)) reasons.add("READ_AND_ACT");
        if (screen) { reasons.add("SCREEN_CONTROL"); reasons.add("CAN_APPROVE_ITSELF"); score += 4; }
        if (c.contains(Capability.NOTIFICATION_ACCESS)) { reasons.add("READS_NOTIFICATIONS"); score += 2; }
        if (c.contains(Capability.DEVICE_ADMIN)) { reasons.add("DEVICE_ADMIN"); score += 4; }
        if (c.contains(Capability.DEFAULT_SMS)) { reasons.add("SMS_HANDLER"); score += 1; }
        if (c.contains(Capability.INPUT_METHOD)) { reasons.add("KEYBOARD"); score += 2; }
        if (c.contains(Capability.VPN)) { reasons.add("VPN"); score += 1; }
        if (drawsOverApps) { reasons.add("DRAWS_OVER_APPS"); score += screen ? 2 : 1; }
        switch (installer == null ? Installer.UNKNOWN : installer) {
            case SIDELOADED: reasons.add("SIDELOADED"); score += 1; break;
            case OTHER_APP: reasons.add("INSTALLED_BY_OTHER_APP"); score += 1; break;
            case UNKNOWN: reasons.add("INSTALL_SOURCE_UNKNOWN"); score += 1; break;
            default: break;
        }
        Risk r = score >= 4 ? Risk.HIGH : score >= 2 ? Risk.MEDIUM : Risk.LOW;
        return new PairingAdvice(r, Collections.unmodifiableList(reasons), screen || c.contains(Capability.DEVICE_ADMIN));
    }

    /** Extracts package names from Android's colon-separated component lists ("pkg/.Svc:pkg2/pkg2.Other"). Invalid parts are skipped. */
    public static List<String> packagesFromComponentList(String raw) {
        List<String> out = new ArrayList<>();
        if (raw == null || raw.isEmpty() || raw.length() > 100_000) return out;
        for (String part : raw.split(":")) {
            String p = part.trim();
            int slash = p.indexOf('/');
            if (slash > 0) p = p.substring(0, slash);
            if (validPackage(p) && !out.contains(p)) out.add(p);
        }
        return out;
    }
}
