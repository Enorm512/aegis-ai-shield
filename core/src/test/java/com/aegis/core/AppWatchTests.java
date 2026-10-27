package com.aegis.core;

import com.aegis.core.AppWatch.*;
import com.aegis.core.CapabilityWatch.Installer;
import com.aegis.core.CapabilityWatch.Risk;
import java.util.*;

/** Host tests for the installed-app watch: snapshot format, diffing and risk. */
public final class AppWatchTests {
    private static int checks;
    private static void check(boolean ok, String message) { checks++; if (!ok) throw new AssertionError(message); }
    private static final String OWN = "com.aegis.aishield";
    private static final String K1 = "a".repeat(64), K2 = "b".repeat(64);
    private static App app(String p, long v, String signer, Installer i) { return new App(p, v, signer, i); }
    private static Change only(List<Change> l, String pkg) { return l.stream().filter(c -> c.packageName().equals(pkg)).findFirst().orElse(null); }

    public static void main(String[] args) {
        // --- Snapshot round trip and robustness
        Snapshot s1 = new Snapshot(Arrays.asList(app("com.store.keyboard", 10, K1, Installer.STORE), app("com.android.talkback", 5, K2 + "+" + K1, Installer.PREINSTALLED), app("com.nosig", 1, "", Installer.UNKNOWN)));
        Snapshot parsed = Snapshot.parse(s1.serialize());
        check(parsed != null && parsed.apps().equals(s1.apps()), "serialize/parse round trip");
        check(Snapshot.parse(null) == null && Snapshot.parse("") == null && Snapshot.parse("AEGIS-CAPS 1\n") == null, "no baseline");
        Snapshot messy = Snapshot.parse("AEGIS-APPS 1\ncom.ok 3 - STORE\ncom.bad x - STORE\ncom.b 1 - NOPE\nbad name 1 - STORE\ncom.sig 1 XYZ STORE\ncom.ok2 4 " + K1 + " SIDELOADED\n\n");
        check(messy.apps().keySet().equals(new TreeSet<>(Arrays.asList("com.ok", "com.ok2"))), "malformed lines skipped: " + messy.apps().keySet());
        check(new Snapshot(Arrays.asList(null, app("com.x", 1, null, Installer.STORE), app("com.y", 1, "", null), app("1bad", 1, "", Installer.STORE))).apps().isEmpty(), "invalid apps dropped");
        List<App> many = new ArrayList<>();
        for (int i = 0; i < 4000; i++) many.add(app("com.p" + i, 1, "", Installer.STORE));
        check(new Snapshot(many).apps().size() == AppWatch.MAX_APPS, "size capped");

        // --- No baseline, no change
        check(AppWatch.diff(null, s1, Set.of(), OWN).isEmpty(), "first look is the baseline");
        check(AppWatch.diff(s1, Snapshot.parse(s1.serialize()), Set.of("com.store.keyboard"), OWN).isEmpty(), "unchanged");

        // --- New apps
        Snapshot base = new Snapshot(List.of(app("com.store.keyboard", 10, K1, Installer.STORE)));
        List<App> now = new ArrayList<>(base.apps().values());
        now.add(app("com.rogue.agent", 1, K2, Installer.SIDELOADED));
        now.add(app("com.store.helper", 1, K2, Installer.STORE));
        now.add(app("com.quiet.sideload", 1, K2, Installer.OTHER_APP));
        now.add(app("com.store.reader", 1, K2, Installer.STORE));
        now.add(app(OWN, 99, K1, Installer.SIDELOADED));
        List<Change> d = AppWatch.diff(base, new Snapshot(now), Set.of("com.rogue.agent", "com.store.helper"), OWN);
        check(only(d, OWN) == null, "own app ignored");
        Change rogue = only(d, "com.rogue.agent");
        check(rogue.kind() == Kind.INSTALLED && rogue.risk() == Risk.HIGH && rogue.reasons().equals(List.of("HOLDS_POWERS", "SIDELOADED")), "sideloaded power holder is HIGH: " + rogue);
        check(only(d, "com.store.helper").risk() == Risk.MEDIUM, "store app with powers is MEDIUM");
        check(only(d, "com.quiet.sideload").risk() == Risk.MEDIUM && only(d, "com.quiet.sideload").reasons().equals(List.of("INSTALLED_BY_OTHER_APP")), "off-store app without powers is MEDIUM");
        check(only(d, "com.store.reader").risk() == Risk.LOW, "ordinary store install is LOW");
        check(d.get(0).packageName().equals("com.rogue.agent"), "most worrying first");
        check(AppWatch.alerts(d).size() == 3 && AppWatch.alerts(d).stream().noneMatch(c -> c.packageName().equals("com.store.reader")), "alerts are MEDIUM and HIGH only");

        // --- Updates, signer and source changes, removals
        Snapshot b2 = new Snapshot(List.of(app("com.a", 10, K1, Installer.STORE), app("com.b", 10, K1, Installer.STORE), app("com.c", 10, K1, Installer.STORE),
            app("com.d", 10, K1, Installer.STORE), app("com.e", 10, "", Installer.STORE), app("com.gone", 1, K1, Installer.STORE), app("com.f", 10, K1, Installer.STORE)));
        Snapshot n2 = new Snapshot(List.of(app("com.a", 11, K1, Installer.STORE), app("com.b", 11, K2, Installer.STORE), app("com.c", 10, K1, Installer.SIDELOADED),
            app("com.d", 9, K1, Installer.STORE), app("com.e", 11, K2, Installer.STORE), app("com.f", 10, K1, Installer.PREINSTALLED)));
        List<Change> d2 = AppWatch.diff(b2, n2, Set.of("com.c", "com.d"), OWN);
        check(only(d2, "com.a").kind() == Kind.UPDATED && only(d2, "com.a").risk() == Risk.LOW, "routine update is LOW");
        check(only(d2, "com.b").kind() == Kind.SIGNER_CHANGED && only(d2, "com.b").risk() == Risk.HIGH, "replaced signer is HIGH");
        check(only(d2, "com.c").kind() == Kind.INSTALLER_CHANGED && only(d2, "com.c").risk() == Risk.HIGH && only(d2, "com.c").reasons().contains("SOURCE_CHANGED"), "power holder now sideloaded is HIGH");
        check(only(d2, "com.d").kind() == Kind.UPDATED && only(d2, "com.d").risk() == Risk.MEDIUM && only(d2, "com.d").reasons().contains("DOWNGRADED"), "downgraded power holder is MEDIUM");
        check(only(d2, "com.e").kind() == Kind.UPDATED, "unknown earlier signer is not reported as a signer change");
        check(only(d2, "com.f") == null, "becoming part of the system image (an OEM update) is not a source change");
        check(only(d2, "com.gone").kind() == Kind.REMOVED && only(d2, "com.gone").risk() == Risk.LOW, "removal is LOW");
        check(AppWatch.diff(b2, n2, null, OWN).size() == d2.size(), "null power set tolerated");

        System.out.println("AppWatchTests passed: " + checks + " checks");
    }
}
