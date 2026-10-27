# AEGIS AI SHIELD — 0.8.1-rc12 (internal test build, not for public release)

An independently implemented Android security app: link, message and APK checks, a signed threat-database mechanism, an experimental on-device language model, an optional DNS-only VPN filter, and a voluntary AI-agent action firewall. Source, tests, Gradle build and APKs are included.

**Read RELEASE_CHECKLIST.md first.** Everything that depends on Android runtime behaviour (VPN service, foreground service, agent gateway, release/R8 build, the new screens) has been compiled and linted but **never run on a device or emulator**. Detection quality has not been measured on real data. There has been no independent human security review.

## Installable files
`dist/` (next to this folder): a debug APK (application id `.debug`, shows a TEST BUILD banner, trusts a published test key) and a release APK signed with a throwaway **test** key, plus `SHA256SUMS.txt`. Install with `adb install -r <file>` or by opening the file on the phone. A previous build signed with a different key must be uninstalled first.

## What exists (see ARCHITECTURE.md, per-stage notes in CHANGELOG.md)
| Layer | Status |
|---|---|
| Link analysis: strict URL parsing, IDN/mixed-script, brand look-alikes (21 brands), redirect parameters, shorteners | host-tested |
| Message analysis EN/NO: rules + optional experimental text classifier (weak; 9/25 on a 50-message developer-written test; rules alone found 3 of 41 reviewer-written unseen scams, see AI_EVALUATION.md) | host-tested |
| APK review: safe archive checks, SHA-256, signer fingerprints, binary-manifest capability analysis | host-tested; UI compile-verified |
| Signed threat database (ECDSA P-256), rollback protection, import screen, reputation API | host-tested; **no production key or feed exists, so the app ships with an empty database** |
| DNS-only VPN filter (routes only two virtual resolver addresses) | engine host-tested; service never run |
| AI Action Firewall + Messenger gateway + pairing/approvals UI | policy engine host-tested; gateway never run |
| "Who can control or read this phone": apps holding Accessibility, notification access, device admin, default SMS, keyboard, VPN; alerts on new grants; links to system settings | diff/risk logic host-tested; Android reading never run on a device |
| Tripwires: decoy contact/note/file with a unique `.invalid` link; DNS protection answers it locally and alerts; self-test button | token, filter and proxy path host-tested; Android planting never run on a device |
| Agent activity log and waiting approvals kept encrypted across restarts; pairing dialog shows app details, install source and powers; emergency stop for all agents | log/approval persistence, kill switch and pairing advice host-tested; Android side never run on a device |
| Capability broker (Aegis itself opens a link or shares text once allowed/approved), reference agent SDK (`agent-sdk`, `agent-sdk-android`) with harness-side provenance tracking, sample agent app (`sample-agent`); see AGENT_SDK.md | broker and SDK logic host-tested; Android side and sample never run on a device |
| Approval tokens for servers: short-lived ECDSA tokens signed with a per-phone Keystore key; reference verifier and CLI for backends; see APPROVAL_TOKENS.md | format and verifier host-tested; Keystore signing never run on a device |
| Release build: R8, signing config, 16 KB alignment, dependency checksums | built and checked on this PC |

## Verify what is verifiable
```sh
gradlew :core:check :app:assembleDebug :app:assembleRelease :app:lintDebug :app:lintRelease   # run in your own terminal
python tools/check_privacy.py            # exact permission set, DNS-only routing, backup flags
python tools/check_android_api.py <classes-dir> <sdk>/platforms/android-36/data/api-versions.xml 26
python tools/check_release_apk.py app/build/outputs/apk/release/app-release.apk <sdk>/build-tools/36.0.0
```
Without Gradle: `bash core/run-tests.sh` (JDK 17+ and Python). BUILD_INSTRUCTIONS.md has details, including release signing.

## Documents
ARCHITECTURE · THREAT_MODEL · SECURITY_REQUIREMENTS · SECURITY_AUDIT · TEST_PLAN · TEST_RESULTS · KNOWN_LIMITATIONS · DEPENDENCIES · SOURCE_PROVENANCE · THREAT_DB_FORMAT · NETWORK_PROTECTION · AI_EVALUATION · AGENT_FIREWALL · AGENT_SDK · APPROVAL_TOKENS · ACCESSIBILITY · PRIVACY_POLICY (draft) · PLAY_COMPLIANCE · STORE_LISTING (draft) · RELEASE_CHECKLIST · DEVELOPMENT_ROADMAP · CHANGELOG.
