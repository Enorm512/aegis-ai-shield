# Release checklist and readiness verdict

**Verdict: NOT ready for public release. Suitable only for internal testing on your own devices.**
Reason: no feature that depends on Android runtime behaviour has ever run on a device or emulator, detection quality is unmeasured on real data, and there has been no independent security review.

Legend: ✅ done and verified here · 🟡 done, not verified on a device · ❌ not done

## Build and packaging
- ✅ Release build: R8 minified, resources shrunk, not debuggable, target API 36, versionCode 18 / `0.8.1-rc12`
- ✅ Release signing is configured from an untracked `keystore.properties`; without it the release APK is unsigned. Path tested with a throwaway key (v2 signature verifies with `apksigner`)
- ✅ 16 KB native-library alignment (`tools/check_release_apk.py`), `zipalign -P 16`
- ✅ Release trusts no threat-feed key (debug-only test key is not in the release APK)
- ✅ Dependency checksums pinned in `gradle/verification-metadata.xml` (436 components); Gradle refuses changed artifacts
- ✅ JDK-API-vs-minSdk scan, privacy/permission/routing pins (`tools/check_android_api.py`, `tools/check_privacy.py`)
- ❌ Android App Bundle (`bundleRelease`) not built or tested
- ❌ Reproducible-build check, CI run (workflow file exists but has never been executed remotely)
- ❌ **Production signing key**: generate it yourself (`keytool -genkeypair -alias aegis -keyalg RSA -keysize 3072 -validity 9125 -storetype PKCS12 -keystore <offline path>`), back it up in at least two offline places, enrol in Play App Signing, and use an *upload* key for Play. Losing an unmanaged signing key means you can never update the app. Never commit it; put its path and passwords only in `keystore.properties`.

## Testing
- ✅ Host tests (`gradlew :core:check`): core 10,075 · archive 325 · threat intel 114 · AI 7,219 · DNS 124 · manifest 33,975 · look-alike 57 · agent firewall 4,533 · results 61 · verdict 63 · firewall review 106 · spot set 91 · data tools 46 · capability watch 26 · tripwires 2,036 · agent shield 91 · broker 550 checks; agent SDK (`gradlew :agent-sdk:check`) 33 + tokens 50 checks
- ✅ Debug lint 0 errors / 27 warnings (0.8.1-rc12); release lint 0 errors / 27 warnings (last run 0.8.0-rc11); agent-sdk-android lint 0 errors / 1 warning; sample-agent lint 0 errors / 7 warnings
- ❌ Instrumentation tests: compile only; never run
- ❌ Device matrix (API 26, 29, 33, 34, 35/36, Samsung/Pixel): VPN lifecycle, consent, foreground service type, notifications, Wi-Fi↔mobile handover, captive portal, Private DNS, other VPNs, Doze, always-on VPN, process death, rotation
- ❌ R8-shrunk release behaviour on a device (1.1 MB release vs 10 MB debug APK)
- ❌ Battery and performance measurement; startup time; memory on low-end devices
- ❌ Detection accuracy on independent labelled samples (none available); false-positive study on real traffic
- ❌ TalkBack / Switch Access / font-scale / dark-light passes (see ACCESSIBILITY.md)

## Security and privacy
- 🟡 Self-audit plus two automated expert-style review passes (SECURITY_AUDIT.md, REVIEW_SECURITY_EXPERT.md, REVIEW_AI_ENGINEER.md); the top findings were fixed in 0.7.3-rc4, others remain open (KNOWN_LIMITATIONS.md)
- ❌ Independent human security review and penetration test of the IPC surface and parsers
- ❌ Dependency vulnerability scan (e.g. OSV / Dependency-Check) and licence review of every dependency (DEPENDENCIES.md lists them)
- 🟡 Privacy policy drafted; ❌ legal review and public URL
- ❌ Data safety form decision on DNS forwarding (counsel)

## Product and store
- ❌ Real threat feed and production signing key for it (the app ships with none, so all database lookups report "unavailable")
- ❌ Support email, company details, store graphics, screenshots, content rating, category, target audience
- ❌ Play Console declarations: VPN service, foreground service `systemExempted`, data safety, app access
- ❌ Closed/internal testing track runs; staged rollout plan; crash/ANR monitoring decision (currently none, by design)
- ❌ Check current Android developer-verification and Play policy requirements for 2026–27 before submission

## Suggested order
1. Install the TEST-signed release and debug APKs on at least three physical devices; walk the device test plan in NETWORK_PROTECTION.md; record results.
2. Fix what breaks; re-run `gradlew :core:check` and the tools.
3. Create the production upload key; build the AAB; internal testing track.
4. Independent security review; legal review; store assets.
5. Closed test → production.
