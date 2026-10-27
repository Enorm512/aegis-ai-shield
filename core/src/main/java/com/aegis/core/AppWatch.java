package com.aegis.core;

import java.util.*;

/**
 * New, updated and replaced apps among those Android lets Aegis see (no QUERY_ALL_PACKAGES: mainly the apps that offer
 * high-power services, see the manifest's queries). Pure logic; the Android adapter collects the apps. The first look is
 * the baseline; later changes are reported until the person marks them reviewed. Aegis never uninstalls anything.
 */
public final class AppWatch {
    private AppWatch() {}

    /** signer = sorted SHA-256 digests of the signing certificates joined by '+', or "" when Android does not give them. */
    public record App(String packageName, long versionCode, String signer, CapabilityWatch.Installer installer) {}

    public enum Kind {
        INSTALLED, UPDATED,
        /** Same package name, different signing key: the app was removed and replaced by someone else's build. */
        SIGNER_CHANGED,
        /** Now attributed to a different source (for example store before, sideloaded now). */
        INSTALLER_CHANGED,
        REMOVED
    }

    /**
     * Reason codes: HOLDS_POWERS (holds a capability from CapabilityWatch), SIDELOADED, INSTALLED_BY_OTHER_APP,
     * INSTALL_SOURCE_UNKNOWN, SIGNER_CHANGED, SOURCE_CHANGED, DOWNGRADED.
     */
    public record Change(Kind kind, String packageName, App before, App now, CapabilityWatch.Risk risk, List<String> reasons) {}

    public static final int MAX_APPS = 3000;
    private static final java.util.regex.Pattern SIGNER = java.util.regex.Pattern.compile("([0-9a-f]{64}(\\+[0-9a-f]{64}){0,7})?");

    public static final class Snapshot {
        private final SortedMap<String, App> apps;
        public Snapshot(Collection<App> in) {
            TreeMap<String, App> m = new TreeMap<>();
            for (App a : in) {
                if (a == null || !CapabilityWatch.validPackage(a.packageName()) || a.installer() == null || a.signer() == null || !SIGNER.matcher(a.signer()).matches()) continue;
                if (m.size() >= MAX_APPS) break;
                m.put(a.packageName(), a);
            }
            apps = Collections.unmodifiableSortedMap(m);
        }
        public SortedMap<String, App> apps() { return apps; }

        /** One "package versionCode signer|- INSTALLER" line per app. */
        public String serialize() {
            StringBuilder b = new StringBuilder("AEGIS-APPS 1\n");
            for (App a : apps.values()) b.append(a.packageName()).append(' ').append(a.versionCode()).append(' ').append(a.signer().isEmpty() ? "-" : a.signer()).append(' ').append(a.installer().name()).append('\n');
            return b.toString();
        }

        /** Null when the text is not a snapshot (no baseline yet); malformed lines are skipped. */
        public static Snapshot parse(String text) {
            if (text == null || !text.startsWith("AEGIS-APPS 1\n")) return null;
            List<App> out = new ArrayList<>();
            String[] lines = text.split("\n");
            for (int i = 1; i < lines.length && out.size() < MAX_APPS; i++) {
                String[] f = lines[i].split(" ");
                if (f.length != 4) continue;
                try { out.add(new App(f[0], Long.parseLong(f[1]), f[2].equals("-") ? "" : f[2], CapabilityWatch.Installer.valueOf(f[3]))); } catch (IllegalArgumentException ignored) { }
            }
            return new Snapshot(out);
        }
    }

    private static boolean offStore(CapabilityWatch.Installer i) {
        return i == CapabilityWatch.Installer.SIDELOADED || i == CapabilityWatch.Installer.OTHER_APP || i == CapabilityWatch.Installer.UNKNOWN;
    }

    private static void sourceReason(CapabilityWatch.Installer i, List<String> r) {
        if (i == CapabilityWatch.Installer.SIDELOADED) r.add("SIDELOADED");
        else if (i == CapabilityWatch.Installer.OTHER_APP) r.add("INSTALLED_BY_OTHER_APP");
        else if (i == CapabilityWatch.Installer.UNKNOWN) r.add("INSTALL_SOURCE_UNKNOWN");
    }

    /**
     * Changes since the baseline, most worrying first. [powerHolders] are the packages that hold a high-power capability
     * now. Risk: a replaced signer is always HIGH; a new or re-sourced app is HIGH when it holds powers and does not come
     * from a store, MEDIUM when only one of the two applies; ordinary updates and removals are LOW.
     */
    public static List<Change> diff(Snapshot before, Snapshot now, Set<String> powerHolders, String ownPackage) {
        List<Change> out = new ArrayList<>();
        if (before == null || now == null) return out;
        Set<String> powers = powerHolders == null ? Collections.emptySet() : powerHolders;
        for (App a : now.apps().values()) {
            if (a.packageName().equals(ownPackage)) continue;
            App b = before.apps().get(a.packageName());
            boolean power = powers.contains(a.packageName());
            List<String> r = new ArrayList<>();
            if (power) r.add("HOLDS_POWERS");
            if (b == null) {
                sourceReason(a.installer(), r);
                boolean off = offStore(a.installer());
                out.add(new Change(Kind.INSTALLED, a.packageName(), null, a, power && off ? CapabilityWatch.Risk.HIGH : power || off ? CapabilityWatch.Risk.MEDIUM : CapabilityWatch.Risk.LOW, Collections.unmodifiableList(new ArrayList<>(r))));
            } else if (!b.signer().isEmpty() && !a.signer().isEmpty() && !b.signer().equals(a.signer())) {
                r.add("SIGNER_CHANGED");
                sourceReason(a.installer(), r);
                out.add(new Change(Kind.SIGNER_CHANGED, a.packageName(), b, a, CapabilityWatch.Risk.HIGH, Collections.unmodifiableList(new ArrayList<>(r))));
            } else if (b.installer() != a.installer() && a.installer() != CapabilityWatch.Installer.PREINSTALLED) {
                r.add("SOURCE_CHANGED");
                sourceReason(a.installer(), r);
                boolean off = offStore(a.installer());
                out.add(new Change(Kind.INSTALLER_CHANGED, a.packageName(), b, a, power && off ? CapabilityWatch.Risk.HIGH : power || off ? CapabilityWatch.Risk.MEDIUM : CapabilityWatch.Risk.LOW, Collections.unmodifiableList(new ArrayList<>(r))));
            } else if (b.versionCode() != a.versionCode()) {
                // Android refuses ordinary downgrades, so an older version is unusual (debugging tools, or a reinstall).
                boolean down = a.versionCode() < b.versionCode();
                if (down) r.add("DOWNGRADED");
                out.add(new Change(Kind.UPDATED, a.packageName(), b, a, down && power ? CapabilityWatch.Risk.MEDIUM : CapabilityWatch.Risk.LOW, Collections.unmodifiableList(new ArrayList<>(r))));
            }
        }
        for (App b : before.apps().values())
            if (!now.apps().containsKey(b.packageName()) && !b.packageName().equals(ownPackage))
                out.add(new Change(Kind.REMOVED, b.packageName(), b, null, CapabilityWatch.Risk.LOW, Collections.emptyList()));
        out.sort((x, y) -> x.risk() != y.risk() ? y.risk().compareTo(x.risk()) : x.packageName().compareTo(y.packageName()));
        return out;
    }

    /** Changes worth telling the person about: MEDIUM and HIGH. */
    public static List<Change> alerts(List<Change> changes) {
        List<Change> out = new ArrayList<>();
        for (Change c : changes) if (c.risk() != CapabilityWatch.Risk.LOW) out.add(c);
        return out;
    }
}
