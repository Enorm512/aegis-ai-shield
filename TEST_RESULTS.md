# Observed validation — 29 October 2026, build 0.8.6-rc17

Regenerated from what actually ran. Replaces the 25 October 2026 version, which described the 0.2.0 state (permission-free manifest, no services, no APK) and no longer applied. Historical artefacts stay in `reports/` for provenance only.

## Update: 0.8.6-rc17 cross-step chain rules (commit 95499ce), GitHub Actions run 40943462646, all three jobs passed
- **verify**: as before plus `ChainTests` (53 checks: send after an approved and used sensitive read, the per-host approval after it, refused/unused reads not counting, earlier hijack wording, the content-to-user provenance switch and its 2-minute window, card number and key split across sends to one host, refusals unchanged, the shown chain, bounds, unpairing and kill switch forgetting the session). One `AgentBehaviourTests` case now uses user provenance for its refused request, because the new provenance rule rightly asked on the following call.
- **device-smoke**: 31 tests started, the job passed (1 skipped on purpose, `BootRestartSetup`). New: `AgentGatewayDeviceTest.sendAfterApprovedReadAsksAndShowsTheChain` (over the real Messenger interface: a send to a trusted host is ALLOW; a sensitive read is asked, approved and redeemed; the same send then is ASK_USER with CHAIN_PRIVATE_READ_THEN_SEND, and the waiting approval carries the two earlier steps).
- **boot-restart**: passed.
- Not tested: the approval dialog's new "What this agent did just before" list was not looked at on screen; no false-positive rate for the chain rules.

## Update: 0.8.5-rc16 agent behaviour watch, GitHub Actions run 40924229215, all three jobs passed
- **verify**: as before plus `AgentBehaviourTests` (48 checks: sessions, ratings, debouncing, bounds, the firewall's IS_THIS_YOU pause, the DNS filter's AI-lookup hook). Locally: lint 0 errors, 35 warnings.
- **device-smoke**: **29 of 29 passed** (1 skipped on purpose; first seen in run 40918864635, same code). New: `AgentGatewayDeviceTest.machinePacedAgentIsAskedIsThisYou` (8 quick calls over the real Messenger interface: the first ALLOW, the last ASK_USER with IS_THIS_YOU; after "yes, that was me" the next call is ALLOW again); `AgentWatchDeviceTest` (AI lookups debounced and rated by screen state; 8 quick calls from an agent pause it, the Home item and the "Is this you?" card appear, and confirming in the UI unpauses it).
- **boot-restart**: passed, tunnel up 8 s after boot. Two earlier runs failed (40912636439, 40918864635): BOOT_COMPLETED was delivered but Aegis was never started, and Android logged "Missing permission state" for Aegis. That fits the reboot coming seconds after install and first launch, before Android had saved that the app was launched, so the app still looked never-launched. The job now waits 20 s before `adb reboot`. An orderly `svc power reboot` was tried and left the CI emulator offline. One pass with the wait does not prove the cause.
- Gateway tests of the policy itself switch the behaviour watch off (`AgentWatch.enabled = false`), because their many quick calls would rightly look automated.

## Update: 0.8.4-rc15 screenshot and QR check (commits d5c7e99 and a86d448), GitHub Actions run 40914461674, all three jobs passed
- **verify**: as before plus `ImageCheckTests` (3,051 checks, 3,000 of them fuzz cases); privacy check now also pins the share targets and bans ML Kit/Firebase/Play services. Locally: lint 0 errors (36 warnings, mostly UseKtx/dependency-version notes); release gate's 16 KB alignment check passes for the new Tesseract native libraries (checked on the debug APK).
- **device-smoke** (Android 15 / API 35 x86_64 emulator): **26 of 26 passed** (1 skipped on purpose). New `ImageCheckDeviceTest` (5): Tesseract read the text and ZXing the Telegram sign-in QR from a 1080×1700 screenshot drawn at test time, judged STRONG with QR_DEVICE_LINK and SECRET_REQUEST (0.46 s); a dark-mode screenshot's text and light-on-dark QR were read (0.55 s); a blank picture is "unclear"; file:// and Aegis-own addresses are refused; a PNG inserted into the media store and shared to MainActivity was checked automatically and showed "Strong signs of a scam in this picture" with "Don't scan this QR code" (0.96 s).
- **boot-restart**: passed, tunnel up about 10 s after boot. **The first run of this commit (40912636439) failed this job**: no tunnel within 90 s after reboot and no Aegis service running; no logcat was captured. The script now waits 3 minutes and prints Aegis and boot-broadcast logcat lines on failure. Cause unknown; treat restart-after-reboot as flaky until it is seen again or explained (1 failure in 3 runs so far).

Limits of this evidence: the screenshots were drawn with Android's own sans-serif font at a large size, which is the easy case for OCR; no real-world screenshots, photos of screens, other fonts or languages; no OCR accuracy figure; timings are from the CI emulator, not a phone.

## Update: 0.8.3-rc14 (commit 01463b1), GitHub Actions run 40576139627, all three jobs passed
- **verify**: as below, plus AppWatchTests (22 checks) and CorrelatorTests (32 checks); API-26 scan of core now 119 classes.
- **device-smoke** (Android 15 / API 35 x86_64 emulator): **21 of 21 passed** (1 skipped on purpose: `BootRestartSetup`, which runs only inside the reboot job).
  - `AgentGatewayDeviceTest` (8): over the real Messenger interface, an unpaired caller gets NOT_PAIRED and a pairing request; once paired, policy ALLOW carries a Keystore-signed token that the reference verifier accepts once and rejects as replayed, with the wrong body, wrong audience or expired; a risky type is refused for a non-risky agent; an asked call cannot be redeemed before approval or with a different payload, is redeemed once with a USER_APPROVED token, then refused; the broker returns a one-shot launcher that runs once and is cancelled after, refuses http, and a brokered share waits for the person and reports DENIED_BY_USER; the kill switch removes agents, cancels approved-but-unused approvals, refuses with KILL_SWITCH_ON, persists, and released agents must pair again; the security log is saved encrypted (the package name is not in the file bytes) and its chain verifies; SealedStore rejects a flipped bit and a file copied under another name.
  - `DnsProtectionDeviceTest` (2): with VPN consent granted by `appops` (stands in for the system dialog), the tunnel comes up, a block-listed name gets NXDOMAIN and is counted, a planted tripwire's self-test is caught by the filter, and the tunnel stops cleanly; restore after restart starts protection only when it was wanted and consent exists, and Stop clears the choice.
  - `ThreatSeedDeviceTest`: a bundle signed with the debug test key at test time installs, the link check then reports the listed domain as CONFIRMED_MALICIOUS; the same and an older bundle are refused (NOT_NEWER), an altered one and one from an untrusted key are refused, and the installed database stays.
  - `PowerWatchDeviceTest` (2): the power scan sees the enabled keyboard; the app scan sees Aegis itself with signer digest and version; a refresh on an unchanged phone reports no app changes.
  - `CorrelationDeviceTest`: an install followed by a screen-control grant becomes one HIGH incident, the signals are stored encrypted, and dismissing hides it.
  - `DashboardSmokeTest` (7): unchanged, all passed.
- **boot-restart** (new job): protection turned on through the app, real `adb reboot` of the emulator, the Aegis tunnel (10.111.222.1) was up again about 10 s after boot completed, as a foreground service, with nobody touching the device.

Limits of this evidence: one emulator image and Android version; the agent is Aegis itself in the gateway tests (same process, so no cross-process binder delivery); VPN consent via `appops`, not the dialog; one reboot; no real threat feed (debug key only); no battery, Doze, OEM or real-phone runs.

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
