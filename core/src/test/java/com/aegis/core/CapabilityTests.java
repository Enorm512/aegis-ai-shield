package com.aegis.core;

import com.aegis.core.CapabilityWatch.*;
import java.util.*;

/** Host tests for the capability watch: snapshot format, diffing, alerts and per-app risk. */
public final class CapabilityTests {
    private static int checks;
    private static void check(boolean ok, String message) { checks++; if (!ok) throw new AssertionError(message); }
    private static Holder h(Capability c, String p, boolean pre) { return new Holder(c, p, pre); }
    private static final String OWN = "com.aegis.aishield";

    public static void main(String[] args) {
        // --- Android component lists
        check(CapabilityWatch.packagesFromComponentList("com.a/.Svc:com.b/com.b.Other:com.a/.Second").equals(Arrays.asList("com.a", "com.b")), "component list parsed, duplicates merged");
        check(CapabilityWatch.packagesFromComponentList(null).isEmpty() && CapabilityWatch.packagesFromComponentList("").isEmpty(), "empty lists");
        check(CapabilityWatch.packagesFromComponentList("bad pkg/.X:../evil/.Y:com.ok/.Z").equals(Collections.singletonList("com.ok")), "invalid names skipped");
        check(CapabilityWatch.packagesFromComponentList("com.x".repeat(30_000)).isEmpty(), "oversized setting ignored");
        check(CapabilityWatch.validPackage("com.example.app_1") && CapabilityWatch.validPackage("unknown") && !CapabilityWatch.validPackage("1com.x") && !CapabilityWatch.validPackage("com..x") && !CapabilityWatch.validPackage("com.x ") && !CapabilityWatch.validPackage(null), "package name rules");

        // --- Snapshot round trip and robustness
        Snapshot s1 = new Snapshot(Arrays.asList(h(Capability.INPUT_METHOD, "com.google.android.inputmethod.latin", true), h(Capability.DEFAULT_SMS, "com.google.android.apps.messaging", true), h(Capability.ACCESSIBILITY, "com.android.talkback", true)));
        Snapshot parsed = Snapshot.parse(s1.serialize());
        check(parsed != null && parsed.holders().equals(s1.holders()), "serialize/parse round trip");
        check(Snapshot.parse(null) == null && Snapshot.parse("") == null && Snapshot.parse("garbage") == null, "no baseline");
        Snapshot messy = Snapshot.parse("AEGIS-CAPS 1\nACCESSIBILITY com.ok 0\nBOGUS com.x 0\nVPN bad name 1\nVPN com.v 2\nDEVICE_ADMIN com.d 1\n\n");
        check(messy.holders().size() == 2, "malformed lines skipped: " + messy.holders());
        check(new Snapshot(Arrays.asList(null, h(null, "com.x", false), h(Capability.VPN, "not valid!", false))).holders().isEmpty(), "invalid holders dropped");
        List<Holder> many = new ArrayList<>();
        for (int i = 0; i < 3000; i++) many.add(h(Capability.ACCESSIBILITY, "com.p" + i, false));
        check(new Snapshot(many).holders().size() == CapabilityWatch.MAX_HOLDERS, "size capped");
        check(s1.serialize().equals(new Snapshot(new ArrayList<>(s1.holders())).serialize()), "deterministic order");

        // --- Diff and alerts
        check(CapabilityWatch.diff(null, s1).isEmpty(), "first look is the baseline: no alerts");
        check(CapabilityWatch.diff(s1, Snapshot.parse(s1.serialize())).isEmpty(), "no change, no diff");
        List<Holder> now = new ArrayList<>(s1.holders());
        now.add(h(Capability.ACCESSIBILITY, "com.rogue.agent", false));
        now.add(h(Capability.NOTIFICATION_ACCESS, "com.rogue.agent", false));
        now.add(h(Capability.ACCESSIBILITY, OWN, false));
        now.removeIf(x -> x.packageName().equals("com.android.talkback"));
        Snapshot s2 = new Snapshot(now);
        List<Change> d = CapabilityWatch.diff(s1, s2);
        check(d.size() == 4, "3 added, 1 removed: " + d);
        check(d.stream().filter(Change::added).count() == 3 && d.stream().filter(c -> !c.added()).allMatch(c -> c.holder().packageName().equals("com.android.talkback")), "added/removed sides");
        List<Change> alerts = CapabilityWatch.alerts(d, OWN);
        check(alerts.size() == 2 && alerts.stream().allMatch(c -> c.holder().packageName().equals("com.rogue.agent")), "alerts: only new grants, never Aegis itself, never removals");
        List<Holder> flagOnly = new ArrayList<>();
        for (Holder x : s1.holders()) flagOnly.add(h(x.capability(), x.packageName(), !x.preinstalled()));
        check(CapabilityWatch.diff(s1, new Snapshot(flagOnly)).isEmpty(), "a changed preinstalled flag alone is not a change");

        // --- Risk per app
        List<AppSummary> apps = CapabilityWatch.byApp(s2, OWN);
        check(apps.get(0).packageName().equals("com.rogue.agent") && apps.get(0).risk() == Risk.HIGH && apps.get(0).reasons().contains("READ_AND_ACT"), "read-and-act app is first and HIGH: " + apps);
        check(apps.stream().noneMatch(a -> a.packageName().equals(OWN)), "Aegis itself not listed");
        AppSummary kb = apps.stream().filter(a -> a.packageName().endsWith("latin")).findFirst().get();
        check(kb.risk() == Risk.LOW && kb.reasons().equals(Collections.singletonList("KEYBOARD")), "preinstalled keyboard is LOW");
        Risk talkback = CapabilityWatch.byApp(s1, OWN).stream().filter(a -> a.packageName().equals("com.android.talkback")).findFirst().get().risk();
        check(talkback == Risk.MEDIUM, "preinstalled screen reader is capped at MEDIUM");
        Risk sideAcc = CapabilityWatch.byApp(new Snapshot(Collections.singletonList(h(Capability.ACCESSIBILITY, "com.helper", false))), OWN).get(0).risk();
        check(sideAcc == Risk.HIGH, "installed accessibility app is HIGH");
        Risk sideKb = CapabilityWatch.byApp(new Snapshot(Collections.singletonList(h(Capability.INPUT_METHOD, "com.fancy.keys", false))), OWN).get(0).risk();
        check(sideKb == Risk.MEDIUM, "installed keyboard is MEDIUM");
        Risk preReadAct = CapabilityWatch.byApp(new Snapshot(Arrays.asList(h(Capability.ACCESSIBILITY, "com.oem.assistant", true), h(Capability.NOTIFICATION_ACCESS, "com.oem.assistant", true))), OWN).get(0).risk();
        check(preReadAct == Risk.HIGH, "read-and-act stays HIGH even when preinstalled");
        AppSummary mixed = CapabilityWatch.byApp(new Snapshot(Arrays.asList(h(Capability.DEVICE_ADMIN, "com.mix", true), h(Capability.VPN, "com.mix", false))), OWN).get(0);
        check(!mixed.preinstalled() && mixed.reasons().contains("NOT_PREINSTALLED"), "any non-preinstalled record makes the app non-preinstalled");
        check(CapabilityWatch.byApp(new Snapshot(Collections.<Holder>emptyList()), OWN).isEmpty(), "empty phone");

        System.out.println("CapabilityTests: " + checks + " checks passed");
    }
}
