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

adb reboot
adb wait-for-device
for _ in $(seq 1 150); do [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ] && break; sleep 2; done
echo "boot completed; waiting for the tunnel"
for _ in $(seq 1 45); do
  if adb shell ip addr 2>/dev/null | grep -q "10.111.222.1"; then
    echo "PASS: DNS tunnel is up after reboot"
    adb shell dumpsys activity services "$PKG" | grep -E "ServiceRecord|isForeground" || true
    exit 0
  fi
  sleep 2
done
echo "FAIL: no Aegis tunnel 90 s after boot"
adb shell dumpsys activity services "$PKG" || true
adb logcat -d > /tmp/logcat.txt || true
exit 1
