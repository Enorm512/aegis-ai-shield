# Dependency inventory

Declared versions are pinned for the alpha, not asserted vulnerability-free or latest. Full resolved transitive inventory and license validation must precede public distribution.

| Dependency | Version | Purpose | Expected license / gate |
|---|---|---|---|
| Android Gradle Plugin | 8.9.2 | Build SDK35 | Apache-2.0; review transitive artifacts |
| Gradle | 8.11.1 | Build | Apache-2.0 with bundled notices |
| Kotlin plugins | 2.1.20 | Kotlin/Compose compiler | Apache-2.0 |
| Compose BOM | 2025.04.01 | Align UI versions | Apache-2.0 |
| AndroidX Activity Compose | 1.10.1 | Activity integration | Apache-2.0 |
| AndroidX lifecycle | 2.8.7 | ViewModel/lifecycle | Apache-2.0 |
| kotlinx.coroutines | 1.10.1 | Background processing | Apache-2.0 |
| Android SDK/build tools | 35 / 35.0.0 | Compilation | Android SDK license; not redistributed |
| Core Java APIs | Platform | Parsing, SHA-256, ZIP | No third-party core runtime library |

App build file is authoritative for any additional test dependencies. CI uses GitHub Actions, Android setup and emulator-runner actions; immutable commit pinning and a software composition audit are pre-release requirements. No API keys, paid services, intelligence feeds or downloaded models. Dependency verification metadata must be generated from trusted resolution and reviewed, not blindly blessed.

## Stage 4
No new libraries. New Android permissions are listed in NETWORK_PROTECTION.md. Build/QA tooling used: javap (JDK) and the Android SDK `api-versions.xml` for tools/check_android_api.py.

## Stage 6
Checksums of all 436 resolved artifacts are pinned in gradle/verification-metadata.xml. Outdated-dependency lint warnings (Compose BOM 2025.04.01 -> 2026.09.00, activity-compose, lifecycle 2.8.7 -> 2.11.0, coroutines, test libs) are deliberately not applied without a re-test on devices.

## 0.8.4-rc15 screenshot and QR check
| Dependency | Version | Purpose | Licence / gate |
|---|---|---|---|
| Tesseract4Android (`cz.adaptech.tesseract4android:tesseract4android`) | 4.9.0 (Tesseract 5.5.1, Leptonica 1.85.0, libjpeg 9f, libpng 1.6.48) | On-device text recognition | Apache-2.0 wrapper; bundled libraries under their own licences (Tesseract Apache-2.0, Leptonica BSD-2, libjpeg IJG, libpng libpng licence). From JitPack only, enforced by `exclusiveContent` in settings.gradle.kts. |
| ZXing core (`com.google.zxing:core`) | 3.5.3 | QR decoding | Apache-2.0, pure Java, no network code |
| tessdata_fast `eng`, `nor` | tag 4.1.0 | Trained models in `app/src/main/assets/tessdata/` | Apache-2.0 (github.com/tesseract-ocr/tessdata_fast) |
Google ML Kit was considered and not used: its terms let it send usage and performance metrics, which the privacy policy rules out. `tools/check_privacy.py` fails the build check if ML Kit, Firebase, Play services or data-transport libraries are resolved.
