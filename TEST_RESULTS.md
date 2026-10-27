# Observed validation — 28 October 2026, build 0.8.1-rc12

Regenerated from what actually ran. Replaces the 25 October 2026 version, which described the 0.2.0 state (permission-free manifest, no services, no APK) and no longer applied. Historical artefacts stay in `reports/` for provenance only.

## Update: first green CI and first emulator run (0.8.2-rc13, commit dbf6fe9)
GitHub Actions run 40545185052 (private repository Enorm512/aegis-ai-shield), both jobs passed:
- **verify** (ubuntu-latest): privacy check, `core/run-tests.sh` (all core and agent-SDK host tests, first time on Linux), icon check, API-26 scans of core and SDK, `:core:check :agent-sdk:check`, debug builds and lint of app, SDK client and sample agent, release lint and build, and `check_release_apk.py` on the unsigned release APK.
- **device-smoke** (Android 15 / API 35 x86_64 emulator, KVM-accelerated): `DashboardSmokeTest`, **7 of 7 passed**:
  - home screen and navigation render
  - a benign link shows a qualified result
  - a malformed link shows "couldn't assess", not "safe"
  - shared text is checked automatically and shows advice
  - sharing during a running check checks the new text
  - the language and theme controls work
  - a waiting agent request shows the banner and can be denied

The first emulator runs found one real bug (shared text was not checked while a check was running; fixed in 0.8.2-rc13), three ambiguous test selectors, and CI setup problems (legacy SDK package, Windows-only dependency checksums, no KVM), all fixed.

Still never run on Android, because no instrumented test covers it:
- the VPN / DNS protection
- the power watch
- tripwire planting
- the agent gateway, broker and tokens with a real second app
- Keystore and `SealedStore`
- the kill switch
- reboot and process-death behaviour
- battery
- real phones and OEM skins

## Environment (local results below)
Windows 11, OpenJDK 17, Gradle 8.11.1 (wrapper), Android Gradle Plugin 8.9.2, Android SDK platform 36 / build-tools 36.0.0. Run from the developer's terminal; no Android device or emulator was used locally.

## Passed
`gradlew :core:check :agent-sdk:check :app:assembleDebug :app:lintDebug :app:assembleDebugAndroidTest :agent-sdk-android:lintDebug :sample-agent:assembleDebug :sample-agent:lintDebug` — BUILD SUCCESSFUL.

| Host test class (module) | Checks |
|---|---|
| CoreTests (core) | 10,075 assertions, incl. 5,000 fixed-seed fuzz cases per analyser |
| ArchiveTests | 325 |
| ThreatIntelTests | 114 |
| AiTests | 7,219 (host measurement: classify ~62 µs/message) |
| DnsTests | 124 (host measurement: blocked-query path ~1.4 µs/query) |
| ManifestTests | 33,975 |
| LookalikeTests | 57 |
| AgentFirewallTests | 4,533 |
| ResultTests | 61 |
| VerdictTests | 63 |
| FirewallReviewTests | 106 |
| SpotTests | 91 |
| DataToolsTests | 46 |
| CapabilityTests | 26 |
| CanaryTests | 2,036 |
| AgentShieldTests | 91 (21 new: denial coalescing, security log, write-skipping revision) |
| BrokerTests | 550 |
| AgentSdkTests (agent-sdk) | 33 |
| TokenTests (agent-sdk) | 50 |

- Lint, 0 errors in every module: app 27 warnings, agent-sdk-android 1, sample-agent 7.
- Static checks: `tools/check_privacy.py` PASS; `tools/check_android_api.py` PASS for core (109 classes) and agent-sdk (13 classes).
- Built but **not executed:** the instrumented-test APK (`assembleDebugAndroidTest`) compiles.
- Release-gate state: the last signed release run (0.8.0-rc11, 2026-10-27) passed `check_release_apk.py` and apksigner. The release build was not repeated for 0.8.1-rc12.

Timing figures are single host-JVM runs on a development PC, not phone measurements.

## Not executed (as of the local run; see the update above for what CI has since covered)
- Android code paths without an instrumented test:
  - the VPN / DNS protection
  - the power watch
  - tripwire planting
  - the agent gateway, broker and approval tokens
  - Keystore keys and `SealedStore`
  - the kill switch
- Reboot, process death, Always-on VPN and Private DNS behaviour.
- Battery, memory, CPU and startup measurements.
- OEM compatibility (including Samsung One UI).
- Packet capture.
- An independent accuracy evaluation or an external security audit.

## Accuracy figures that exist
Only those in AI_EVALUATION.md: on a locked 95-message reviewer set, rules alone 4/41 scam recall with 0/54 false positives; the hybrid with the optional classifier 24/41 with 3/54. These are small, single-author sets, not an independent benchmark.

No production-readiness claim.
