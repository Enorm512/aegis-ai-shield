# Observed validation — 25 October 2026

## Passed in this session
- `bash core/run-tests.sh`: 10,075 core assertions, including 5,000 fixed-seed fuzz cases for each of URL and message analysis.
- Same runner: 325 archive checks, including 300 seeded malformed-byte mutation cases. Archive rejections are allowed; uncaught failures are not.
- `python3 tools/check_privacy.py`: permission-free manifest, backup/cleartext disabled, no service, XML parsing and 20 Norwegian finding-code mappings.
- Host CLI compiled and executed: https://bankid.no/login -> NO_KNOWN_WARNING_SIGNS; synthetic Norwegian BankID/password urgency request -> STRONG_INDICATORS.
- Gradle wrapper generation succeeded from official Gradle8.11.1 distribution. Distribution SHA256 matched the official checksum.

Compiler: `java -m jdk.compiler/com.sun.tools.javac.Main`, OpenJDK17.0.20. Raw successful suite output is in reports/host-tests.txt and reports/privacy-static.txt.

## Failed/blocked
- Full Gradle project configuration: com.android.application8.9.2 could not be resolved from configured repositories. An offline assembleDebug attempt also failed because this plugin was not cached; see reports/android-build-attempt.txt.
- Isolated Gradle core check: host JDK lacks javac launcher; Gradle reports no JAVA_COMPILER capability. Direct compiler-module tests above succeeded and are not a Gradle build pass.
- SDK Manager installation skipped platform35/build-tools35/platform-tools because licence was not accepted. Authorization requested before accepting licence and installing.

## Not executed
Android Kotlin compilation, lint, APK generation/signing, six instrumentation tests, emulator/physical device runs, UI rendering/screenshot verification, real APK parser integration, packet capture, battery tests, independent accuracy assessment, external audit and remote CI. **No installable APK is included.**

No measured recall, precision or false-positive rate is available. Synthetic cases were written during implementation and are not an independent holdout. No production-readiness claim.
