#!/usr/bin/env bash
# CI only: real emulator reboot. Turns DNS protection on the way the person would (consent + "wanted"), reboots, and
# checks that Aegis' boot receiver brought the tunnel back with no one touching the phone.
set -euo pipefail
PKG=com.aegis.aishield.debug
gradle :app:installDebug :app:installDebugAndroidTest
# Stands in for the person tapping OK on the system VPN dialog.
adb shell appops set "$PKG" ACTIVATE_VPN allow
# A launch takes the app out of the "stopped" state, as any real use would; stopped apps get no boot broadcast.
adb shell am start -W -n "$PKG/com.aegis.app.MainActivity"
# Turns protection on through the app's own code path and leaves the choice recorded.
adb shell am instrument -w -e class com.aegis.app.BootRestartSetup -e bootSetup 1 "$PKG.test/androidx.test.runner.AndroidJUnitRunner" | tee /tmp/setup.txt
grep -q "OK (1 test)" /tmp/setup.txt

# Android saves package state (including "this app has been launched") and app-ops a few seconds after a change, and
# `adb reboot` skips the orderly shutdown that would flush them. A failed run (40918864635) logged "Missing permission
# state" for Aegis after boot and Aegis got no BOOT_COMPLETED, consistent with the app still looking never-launched.
# So: give the system time to write first. (A power-manager reboot, `svc power reboot`, left the CI emulator offline.)
sleep 20
adb reboot
# The orderly reboot returns before the device goes down: wait for the old boot to end, then for the device to come
# back, tolerating "device offline" while the emulator restarts.
for _ in $(seq 1 60); do [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ] || break; sleep 2; done
for _ in $(seq 1 60); do adb wait-for-device 2>/dev/null && break; sleep 3; done
for _ in $(seq 1 150); do [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ] && break; sleep 2; done
echo "boot completed; waiting for the tunnel"
# Boot broadcasts can be late on a loaded runner; wait up to 3 minutes.
for _ in $(seq 1 90); do
  if adb shell ip addr 2>/dev/null | grep -q "10.111.222.1"; then
    echo "PASS: DNS tunnel is up after reboot"
    adb shell dumpsys activity services "$PKG" | grep -E "ServiceRecord|isForeground" || true
    exit 0
  fi
  sleep 2
done
echo "FAIL: no Aegis tunnel 180 s after boot"
adb shell dumpsys activity services "$PKG" || true
adb logcat -d > /tmp/logcat.txt || true
echo "--- logcat lines about Aegis, boot broadcasts and VPN"
grep -iE "aegis|BOOT_COMPLETED|LOCKED_BOOT|VpnService|ActivityManager.*(Start proc|Killing|broadcast)|AndroidRuntime" /tmp/logcat.txt | tail -120 || true
exit 1
