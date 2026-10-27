# Changelog

## 0.2.0-stage1-alpha — 2026-10-25
Rebuilt UI/application foundation in Kotlin/Compose; separated portable security core; replaced numeric score presentation with evidence categories; added message analysis, hostile archive guards and selected APK/device adapters; removed QUERY_ALL_PACKAGES; introduced automated host regression/fuzz tests, instrumentation tests and CI; preserved starting specification reports. Actual validation in TEST_RESULTS.md.

## 0.1.0 — supplied prototype
Java Activity and URL heuristic helper; no supplied tests or compiled binary.

## 0.2.0 build verification (2026-10-25)
- compileSdk raised 35 -> 36 (only API 36/37 platforms were installed locally); android.suppressUnsupportedCompileSdk=36 added.
- Verified: gradlew :core:check :app:assembleDebug -> BUILD SUCCESSFUL (3m23s); core 10075 assertions + 325 archive checks pass under Gradle.
- Debug APK produced: app/build/outputs/apk/debug/app-debug.apk, 10140308 bytes, SHA-256 E6E84ABF0F0172F246DB0E2B573E0D72B8649CF49A861EEA4915B55CDB6D335D.
- NOT verified: lint, instrumentation tests (6 written, unrun), on-device behaviour, detection accuracy.

## 0.3.0-stage2-alpha (in progress, 2026-10-25)
- Added signed threat database (THREAT_DB_FORMAT.md): ThreatBundleVerifier (ECDSA P-256), ThreatDatabase, ThreatStore (rollback protection, tamper re-verification, previous-version rollback), ReputationProvider abstraction (local + composite), ThreatChecks (listings only raise verdicts), ThreatBundleTool (publisher keygen/sign).
- App: URL checks and APK hash/signer checks consult the local database; empty database is reported as "could not be checked", never as clear. Norwegian strings added.
- Tests: core/src/test/.../ThreatIntelTests.java (90 checks incl. exhaustive single-bit mutation of a bundle); IntelBenchmark.
- Verified 2026-10-25: `gradlew :core:check :app:assembleDebug` BUILD SUCCESSFUL; ThreatIntelTests 90 checks, CoreTests 10075, ArchiveTests 325 pass. Debug APK 10193867 bytes, SHA-256 52D8C5138807EF59D129C477B03B1BC7452DD97D03600F1DD289D7927BFE1CC7. Not verified: lint, instrumentation tests, on-device behaviour.
- Host benchmark (JVM 21, 8 cpus, avg of 5 runs incl. warm-up): 10k entries/0.67 MB verify+parse 106 ms; 100k/6.8 MB 304 ms; 150k/10.2 MB 464 ms; domain lookup 224-462 ns. Cap of 16 MiB allows roughly 230k entries of this shape.
- Device tab: threat database status line (version, indicators, issued/expires, stale/failed-verification/no-key warnings, EN/NO), "Import signed threat bundle" (disabled unless the build trusts a key), "Restore previous database". Debug build only trusts tools/debug-test-key (public test key, sample v1/v2 bundles, README). Release builds trust no key.
- Hardened ThreatBundleVerifier: signature base64 must be canonical. Found because ThreatIntelTests failed intermittently under Gradle (a flipped padding bit in the signature decoded identically); 60/60 runs pass after the fix. Cause inferred from the mechanism, the failing run was not captured.
- Rebuilt: BUILD SUCCESSFUL; debug APK 10204542 bytes, SHA-256 27FF62BB7F4160C523CD4AC2E512C464CCDD942888631A1CBC5BDFE4E5950FBA. The import UI has NOT been run on a device or emulator.

## 0.4.0-stage3-alpha (2026-10-25)
- Added TextNormalizer, TextClassifier (hashed logistic regression, windowed scoring, checksummed model file), MessageAi (hybrid; can only raise to SUSPICIOUS), ModelTrainer + ml/ corpus and model, AI status + OFF-by-default switch in the app, AI_EVALUATION.md.
- Tests: AiTests 7,219 checks (normaliser, model-file rejection, invariance, fuzz, injection, privacy source scan). tools/check_privacy.py now also covers ThreatChecks/MessageAi finding codes and caught two untranslated codes (added).
- Measured on 50 developer-written held-out messages: recall 9/25, false positives 1/25. Not a detection rate. Padding evasion: 5/9 flagged scams still escape.
- Verified: `gradlew :core:check :app:assembleDebug` BUILD SUCCESSFUL; debug APK 10239530 bytes, SHA-256 39F5C2BE458BDE3FAD79EC02097227370EFB454A3A6E134C75BCBF42E82A5AD0. Not run on a device; no on-device latency or battery measurement.

## 0.5.0-stage4-preview (2026-10-25)
- Added DNS protection engine in `core` (IpPacket, DnsMessage, DnsFilter + user allow/block lists, DnsUpstream with TCP retry and failover, DnsProxy with bounded queue/event log) and the Android `AegisVpnService` (DNS-only tunnel, routes just two virtual resolver addresses), consent flow, foreground notice, Device-tab controls (start/stop, counters, recent blocks, allow/block lists). See NETWORK_PROTECTION.md.
- New permissions: INTERNET, ACCESS_NETWORK_STATE, FOREGROUND_SERVICE, FOREGROUND_SERVICE_SYSTEM_EXEMPTED, POST_NOTIFICATIONS. UI claims updated ("no network permissions" no longer true); tools/check_privacy.py now pins the exact permission set and the DNS-only routing.
- DnsTests: 121 checks (protocol rejection cases, independent checksum verification, fuzz, failover, TCP retry, overload shedding, privacy source scan). Host measurement: blocked-query path ~1.2-1.7 us/query.
- First `lintDebug` run found real bugs, now fixed: `InputStream.readNBytes` (API 33) in model loading and bundle import would have failed/crashed on Android 8-12 (replaced by `BoundedRead`).
- New tools/check_android_api.py (javap + SDK api-versions.xml) found 8 more JDK calls newer than minSdk 26 in `core` that lint cannot see (List.of, Set.of, Map.of, Map.entry, List.copyOf, Optional.isEmpty, String.isBlank, Path.of; API 30-34) which would have thrown NoSuchMethodError on older phones, including at ThreatDatabase class load. Replaced; scan now passes (50 classes, minSdk 26).
- Service now calls startForeground after establish(); if the system refuses the systemExempted type the service stops (fail closed). Lint's ForegroundServicePermission error is suppressed deliberately (docs list VPN apps as qualifying); this must be confirmed on a device.
- Verified 2026-10-25: `gradlew :core:check :app:assembleDebug :app:lintDebug` BUILD SUCCESSFUL, lint 0 errors / 11 warnings (dependency updates, targetSdk, allowBackup note). Debug APK 10334626 bytes, SHA-256 EECFA0B12B92134320D53F5A168C297BD7E75EFBE00DE1DC4A5CA9381F07B0E0.
- NOT verified: anything on a device or emulator (none available: no AVD, no adb device). The VpnService, consent flow, notification, network callback, protect() and the foreground-type assumption are untested.

## 0.6.0-stage5-preview (2026-10-25)
- Enhanced APK inspection: `AxmlParser` (bounded Android binary XML reader) + `ManifestAnalyzer` read the manifest directly and flag capability combinations (accessibility service + overlay/SMS/installer, SMS + network + screen access, no launcher, old target API, debuggable, cleartext, exported components). Permissions alone cap at SUSPICIOUS; an accessibility service alone is not flagged. Tested on real aapt2-generated manifests (`core/src/test/fixtures/manifests`, manifest-only, nothing executable) plus ~40,000 mutated manifests (no unchecked exception escaped). Wired into the APK review screen; Norwegian strings added.
- Advanced scam detection: `LookalikeDetector` (homoglyph/digit/hyphen/rn-m skeleton match and single-edit typos against 21 brands incl. BankID, Vipps, DNB, Nordea, Posten, Skatteetaten) and redirect-parameter detection in `UrlAnalyzer`. On a hand-written list of 104 unrelated popular hosts: 0 flagged; 19 of 19 constructed impersonations caught. Known false-positive class: legitimate sites one edit from a brand (e.g. paypay.com). One existing expectation changed: a Cyrillic-homoglyph "paypal" host is now STRONG_INDICATORS (was SUSPICIOUS).
- Agent Action Firewall prototype: `AgentFirewall`, `SensitiveData`, `InjectionIndicators` (4,522 checks incl. fuzz, ReDoS-style inputs, hash-chained audit tamper tests) and an Android Messenger gateway + pairing/approval screens (AGENT_FIREWALL.md). Preview, never run on a device.
- QR-code phishing, image/OCR analysis, DNS-over-HTTPS and a second-generation model are NOT implemented.
- Verified 2026-10-25: `gradlew :core:check :app:assembleDebug :app:lintDebug` BUILD SUCCESSFUL (lint 0 errors, 14 warnings); `check_android_api.py` and `check_privacy.py` pass. Debug APK 10435642 bytes, SHA-256 5364CE2955FB96AAF47B53E433AEFA86A21C3019797B18DE5F9A713DAA361089.
- NOT verified: any on-device behaviour (APK review with the new analysis, DNS service, agent gateway), real-world malware/phishing detection rates, QR handling.

## 0.7.0-rc1 (Stage 6 commercial-readiness work, 2026-10-26) - NOT a production release
- Release build: R8 + resource shrinking, not debuggable, target API 36, versionCode 7. Release APK 1.16 MB vs debug 10.4 MB. Signing from untracked `keystore.properties`; tested with a throwaway key (APK v2 signature verifies). Without that file the release APK is unsigned.
- 16 KB page-size: both ABIs' native libraries have `p_align=16384`, `zipalign -P 16` passes (tools/check_release_apk.py). The release APK ships no trusted threat-feed key.
- Dependency checksums pinned in gradle/verification-metadata.xml (436 components); the final build ran with verification enforced.
- Data-extraction rules added (all backup/transfer domains excluded). Accessibility fixes (ACCESSIBILITY.md). In-app VPN disclosure dialog before the Android consent prompt.
- Independent reviewer pass (fresh AI reviewer, read-only): 15 findings, all fixed, 14 with regression tests (SECURITY_AUDIT.md). Highlights: binary-XML memory blowup and namespace-shadowing bypass in the manifest parser; approval-hash delimiter forgery; store lock stalling DNS; trailing-text blind spot in injection scan; clock-skew and crash-window bugs in the threat store.
- New documents: PRIVACY_POLICY.md (draft), PLAY_COMPLIANCE.md, STORE_LISTING.md, ACCESSIBILITY.md, SECURITY_AUDIT.md, RELEASE_CHECKLIST.md.
- Verified: `gradlew :core:check :app:assembleDebug :app:assembleRelease :app:lintDebug :app:lintRelease :app:assembleDebugAndroidTest` BUILD SUCCESSFUL; lint 0 errors / 13 warnings (debug and release). Host suites: core 10,075 - archive 325 - threat intel 100 - AI 7,219 - DNS 121 - manifest ~31,000 - look-alike 57 - agent firewall 4,533.
- NOT verified: anything on a device (see RELEASE_CHECKLIST.md). Instrumentation tests compile but have never run.

## 0.7.1-rc2 UX redesign (2026-10-26)
- New structure: bottom navigation (Home, Check, Protection, More); Home status screen with a "needs attention" card and one status row per feature; one Check box for links and messages with auto-detection (`InputKind`) and Link/Message override, Paste button, shared text checked automatically; new result card (level badge + words, top-3 "Why", numbered "What to do", expandable details) driven by core `ResultSummary`; global AI-agent banner, notification and review dialog (Deny is the prominent button). See DESIGN.md.
- Quick fixes: allow/block field keeps focus, shows validation errors; Unpair asks for confirmation; "English / Norsk" language chips; release build hides the unusable import button; developer numbers moved to a technical line; live counters tick only on visible screens; result survives language change; result scrolls into view.
- Core: `InputKind`, `ResultSummary` (+ `combine`), ResultTests (61 checks). `norwegianFinding`/`agentReason` moved to Texts.kt.
- Found and fixed while testing: my earlier "linear" HTML-comment scan for injection markers was still quadratic (unbounded search for the closing marker): 1.8-3 s on a 100 KB hostile input, now ~0.1-0.2 s. The timing test is now warmed up and uses a 2 s bound.
- DashboardSmokeTest rewritten for the new screens (7 tests, compile-checked only, never run). Behaviour change: shared text is now analysed immediately instead of waiting for a tap.
- NOT verified: how any screen actually looks or behaves on a device (layout, clipping, contrast, animation, keyboard/IME, TalkBack).

## 0.7.2-rc3 visual identity (2026-10-26)
- New logo: a two-tone mint shield with a lens and tick ("check"), as an adaptive launcher icon (foreground, background, **monochrome themed-icon layer**), in-app mark, and a white status-bar icon. Replaces the placeholder "A" square.
- Icon set of 21 consistent line icons (home, check, shield, more, link, message, file/APK, globe, agent, database, phone, sparkle, lock, info, alert, warn, cross, help, chevron, paste, power) generated from geometric helpers (`tools/gen_icons.py`) as VectorDrawables; used in navigation, status rows, section titles, buttons, chips, the result badge (replaces text glyphs, so no dependence on font coverage) and the agent dialog.
- `tools/IconPreview.java`: host renderer for the vector drawables (preview sheet, store graphics) and a strict `check` mode that fails on malformed path data or out-of-canvas paths (28 vector drawables / 74 paths pass). I looked at the rendered sheet and logo masks (circle, squircle, rounded square, monochrome) before shipping.
- Store assets generated from the same artwork: `store-assets/play-icon-512.png` and a DRAFT 1024x500 feature graphic.
- Motion (all subtle, none looping except one): screen cross-fade with a small horizontal slide; result card fades and rises in; the level badge pops in once and, for "known threat" and "strong warning", one soft ring expands and fades; the agent banner slides down/up; status icon colours change smoothly; the DNS-protection icon "breathes" slowly while protection is running (the only continuous animation, drawn only while visible). When the system's animation scale is 0 ("Remove animations") every animation snaps.
- Splash/launcher: adaptive icon used on all supported API levels (minSdk 26).
- Version 0.7.2-rc3 (versionCode 9).
- NOT verified: how any of this looks or animates on a real device (launcher masks, themed icons, motion smoothness, jank).

## 0.7.3-rc4 review fixes (2026-10-26)
Fixes for the top findings of REVIEW_SECURITY_EXPERT.md and REVIEW_AI_ENGINEER.md. Version 0.7.3-rc4 (versionCode 10).
- Verdict logic: "no known warning signs" never lists reasons; named dangerous APK capability patterns force at least SUSPICIOUS; brand look-alike now matches brand tokens inside any label of the host plus phishy words, not only four hard-coded brands.
- Text: normaliser folds look-alike letters after lowercasing and the scam rules now run on the normalised text (rules precompiled, negation window for secret requests, a "verify your account" rule, bare-domain detection); term-list explanations removed.
- Agent firewall: two quadratic regexes replaced by linear scans plus a 2-second scan deadline that fails closed; provenance can no longer turn an ASK into an ALLOW; exact-host trust; per-agent grants (risky actions opt-in at pairing); secrets in summary and destination are scanned; length-prefixed request hash.
- Approvals: dialog shows the payload/command (control and bidi characters made visible), real host, kinds of data, and is pinned to the request it opened with; overlay-tap protection (`filterTouchesWhenObscured`).
- Debug-key fencing: debug application id `.debug`, persistent TEST BUILD banner, release gate checks by key id.
- Threat feed: per-key sequence floors (rotation cannot lock out a new key), maximum sequence jump 100,000, maximum validity 100 days, protected domains cannot be listed or blocked, canonical base64 signatures, signature checked before parsing.
- VPN service: answers every startForegroundService call; no database is not a reason to refuse starting; Private DNS (Automatic) caveat in disclosure and docs; "fail closed" wording corrected (stopping the service is fail-open for filtering).
- Docs corrected: INTERNET permission, stale architecture text, limitations list (now includes the review items NOT fixed), version drift, stale checksum file.
- Verified: host tests (see RELEASE_CHECKLIST.md) and the Gradle build/lint on the developer PC. NOT verified: anything on a device.

## 0.7.4-rc5 remaining-review fixes (2026-10-26)
Version 0.7.4-rc5 (versionCode 11).
- Threat store: a correctly signed but older `current.bundle` is refused at startup (floor enforced on reload); deliberate rollback leaves a marker so it survives restart. 3 new tests.
- DNS: upstream sockets bound to the preferred network and only its resolvers used; shed queries answered with SERVFAIL immediately (test updated).
- Agent firewall: trusted-destinations list in the app (add/remove, plain host names only), `untrustDestination`, `isTrustableHost`; 17 new checks.
- CI: all third-party actions pinned to commit SHAs resolved with the GitHub API.
- Not changed: TCP DNS, Private DNS, always-on VPN, key-rotation drill, UTS46, dependency signature verification/CVE scan, classifier padding. See KNOWN_LIMITATIONS.md.
- NOT verified: the network-binding and trusted-host UI code has never run on a device.

## 0.7.5-rc6 spot-test fixes (2026-10-27)
Version 0.7.5-rc6 (versionCode 12).
- Links: Norwegian phishing words (sikkerhet, verifiser, innlogging, betal, toll, pakke...) in the look-alike word list; accents folded when comparing hosts with brands (and one-edit matches for internationalized labels); brand glued to a phishy word (appleid); new brands bring, postnord, dhl; SUSPICIOUS_TLD weak signal.
- Messages: PARCEL_FEE (needs a link or time pressure), FAMILY_IMPERSONATION, GIFTCARD_REQUEST, INVESTMENT_LURE, unpaid-bill and authority-plus-payment threats. Norwegian wording added for the new finding codes.
- Tests: `SpotTests` (91 checks) over `ml/data/spot-set.txt` plus targeted cases for the new rules and for look-alike notices that must stay clear. Existing suites unchanged and passing.
- Held-out reviewer set: rules 3/41 -> 4/41 scams, 0/54 false positives (hybrid 24/41, 3/54). The big gains are on the tuned spot sets only.
- NOT verified: anything on a device.

## Data tooling (2026-10-27, no app behaviour change)
- `FeedBuilder` publisher tool: licence-gated manifest of local domain lists, format parsing (plain/hosts/adblock/URL), the verifier's domain rules, protected-domain and allowlist filtering, duplicate merging, strongest-first size cap, attribution file with input checksums. Round trip to a signed bundle tested.
- `DatasetImporter` developer tool for the UCI SMS Spam Collection and CSV datasets such as Mishra and Soni's SMS phishing set (both CC BY 4.0); spam skipped by default.
- Leakage guard: `ml/data/LOCKED`; `ModelTrainer` refuses overlapping training data. `DataToolsTests` 46 checks.
- DATA_SOURCES.md: researched feeds and datasets with licence verdicts. No third-party data downloaded or bundled yet.

## External SMS data experiment (2026-10-27, model unchanged)
- Downloaded the Mishra and Soni SMS phishing dataset (Mendeley, CC BY 4.0; checksum matched) and the UCI SMS Spam Collection (CC BY 4.0) into `ml/external/` with attribution and checksums; imported with `DatasetImporter`.
- Retrained on 5,550 messages. Locked reviewer set, classifier alone: 23/41 -> 19/41 recall, 3/54 -> 2/54 false positives (English 10/20 -> 4/20). Failed the pre-set acceptance rule; the shipped model is unchanged. Details in AI_EVALUATION.md.
- `ModelEval` takes an optional model path for candidate comparisons.

## Class-balanced retrain (2026-10-27, model unchanged)
- `ModelTrainer --class-weight=auto`: scam-example weight chosen by cross-validation on training data only (default off; weight 1 reproduces the shipped model byte for byte).
- On the 5,550-message combined data it chose weight 9.71. Locked reviewer set, classifier alone: 30/41 recall but 9/54 false positives (17%), above the 3/54 acceptance limit: rejected. Details in AI_EVALUATION.md.

## 0.7.6-rc7 capability watch (2026-10-27)
Version 0.7.6-rc7 (versionCode 13). First item from REVIEW_AGENT_SHIELD.md: protection that does not depend on an agent cooperating.
- Core `CapabilityWatch`: snapshot format, diff (first look = baseline, removals never alert, Aegis itself excluded), per-app risk (READ_AND_ACT for Accessibility plus notification access; preinstalled holders capped at MEDIUM unless read-and-act), Android component-list parsing. `CapabilityTests` 26 checks.
- App `PowerWatch`: reads Accessibility services (secure setting + AccessibilityManager), notification listeners, device admins, default SMS app, enabled keyboards (secure setting + InputMethodManager), and a non-Aegis active VPN. Baseline in app-private storage; "I recognise these" marks reviewed.
- UI: "Who can control or read this phone" card at the top of Protection, Home status row and attention item, deep links to the relevant system settings page and to app info.
- Background re-check every 30 minutes while DNS protection runs; one generic notification per new grant.
- Manifest: `<queries>` for six service/receiver intent actions (no new permissions, no QUERY_ALL_PACKAGES); `check_privacy.py` pins that set. Privacy policy and Play-compliance drafts updated.
- Verified: host tests, Gradle debug/release build, lint 0 errors (19 warnings, 3 new style hints), release/privacy/API gates. NOT verified: anything on a device.

## 0.7.7-rc8 tripwires (2026-10-27)
Version 0.7.7-rc8 (versionCode 14). Item 3.1 from REVIEW_AGENT_SHIELD.md.
- Core `CanaryTokens`: 100-bit base32 tokens, host names under the reserved `aegis-canary.invalid` zone, registry (max 20, label-boundary matching, persist/load), plausible decoy note/file/contact content. `DnsFilter`: tripwire check runs before the allowlist, blocks with `Reason.CANARY`, calls a listener whose exceptions are contained. `CanaryTests` 2,036 checks (incl. 2,000-token uniqueness, proxy NXDOMAIN without forwarding).
- App `Tripwires` + `TripwireCard` on Protection: plant a decoy contact (Contacts insert intent, no contacts permission), note (share sheet) or file (document picker, no storage permission); list, remove, self-test; trip history; high-priority notification; Home attention item; DNS event list marks tripwire hits.
- Verified: host tests, Gradle debug/release build, lint 0 errors (20 warnings), release/privacy/API gates. NOT verified: anything on a device.

## 0.7.8-rc9 agent log, pairing dialog, kill switch (2026-10-27)
Version 0.7.8-rc9 (versionCode 15). Item 4 from REVIEW_AGENT_SHIELD.md.
- Core `AgentFirewall`: audit `Event`s (decision, user approved/denied, redeemed, redeem refused with reason, paired, pairing rejected, unpaired, kill switch on/off, log damaged); fields reduced to fixed character sets; `exportAudit`/`parseAudit`/`restoreAudit` (damaged or edited logs are not trusted and restart with `LOG_DAMAGED`); `exportPending`/`restorePending`/`openApprovals`; `killSwitch`/`releaseKillSwitch`/`restoreLockdown` (every request and redemption refused with `KILL_SWITCH_ON`). `CapabilityWatch.installerOf` and `pairingAdvice`. New `AgentShieldTests`, 70 checks.
- App: `SealedStore` (AES-256-GCM, Android Keystore key, atomic writes); `AgentGateway` saves the log and waiting approvals after every change and restores them at start-up; gateway service refuses everything while the kill switch is on. New `AgentUi.kt`: pairing dialog with label, icon, install source, overlay request, held powers, risk and an extra confirmation for apps with Accessibility or device admin; approval warning when the agent can tap the screen; dialogs hidden from non-tool accessibility services on Android 14+; Emergency stop card with links to Accessibility and notification-access settings; Agent activity log card with fingerprint and export. Home shows when the emergency stop is on or the saved log was damaged.
- Verified: host tests, Gradle debug/release build, lint 0 errors, release/privacy/API gates. NOT verified: anything on a device.

## 0.7.9-rc10 capability broker, agent SDK, sample agent (2026-10-27)
Version 0.7.9-rc10 (versionCode 16). Items 2.1 and 2.3 from REVIEW_AGENT_SHIELD.md.
- Core `CapabilityBroker` (OPEN_URL: https only, printable ASCII, no userinfo, port 443; SHARE_TEXT up to 10,000 characters; single-use in-memory tickets). `AgentFirewall.evaluateBrokered`/`redeemBrokered`: brokered approvals cannot be redeemed by agents (`BROKERED_ACTION`) and are not saved; audit events `BROKER_PERFORMED`/`BROKER_FAILED`. Fix: removing an agent now drops its waiting and approved-but-unused approvals, and redeeming requires the agent to still be paired. New `BrokerTests`, 549 checks (500 are id-uniqueness).
- App: gateway `MSG_BROKER`; links pass Aegis' own link check first (suspicious or worse refused); ALLOW returns an immutable one-shot launcher for a non-exported `BrokerActivity`; ASK_USER shows "Approve and open/share" and Aegis carries it out on approval, reporting `MSG_BROKER_DONE`. Replies echo `requestId`. Protocol constants shared from the SDK. `check_privacy.py` now pins the activity set.
- New modules: `agent-sdk` (pure Java: `AegisProtocol`, `ActionSpec`, `TaintTracker` with context-level taint, memory labels and plan confirmation; `AgentSdkTests` 33 checks, incl. agreement with Aegis' enums), `agent-sdk-android` (`AegisClient`), `sample-agent` (demo harness, no AI model). AGENT_SDK.md.
- Verified: host tests, Gradle builds of Aegis (debug, release) and the sample agent (debug), lint 0 errors in all three Android modules, release/privacy/API gates. NOT verified: anything on a device.

## 0.8.0-rc11 approval tokens for servers (2026-10-27)
Version 0.8.0-rc11 (versionCode 17). Item 2.2 from REVIEW_AGENT_SHIELD.md.
- Agent SDK `ApprovalToken`: canonical, signed token format (`AT1.`; kid, jti, iat, exp, agent, aud, type, dest, body hash, amount, currency, grant), issuing with a pluggable signer, reference `Verifier` (signature first, then lifetime ≤ 120 s, ±30 s skew, audience, body hash, optional destination/agent/type, single use via `ReplayCache`), PEM key helpers, `TokenVerifierCli`. `TokenTests` 50 checks (incl. 2,000 mutated tokens, none verify; non-canonical payloads refused).
- Aegis: per-phone EC P-256 signing key in the Android Keystore (`ApprovalSigner`); tokens on ALLOW (`POLICY_ALLOW`) and on granted redemption (`USER_APPROVED`) when the call has a destination host; audit event `TOKEN_ISSUED`. Protection → Proof for servers: key fingerprint, export public key (PEM), replace key.
- SDK client: `Result.token`; `redeem()` now returns `Redeemed(granted, token)`. Sample agent 0.2.0-demo shows the token.
- APPROVAL_TOKENS.md. Verified: host tests, Gradle builds, lint 0 errors in all Android modules, release/privacy/API gates. NOT verified: anything on a device.

## 0.8.1-rc12 stage 1 security foundation (2026-10-28)
Version 0.8.1-rc12 (versionCode 18). From the 2026-10-27 security audit, stage 1.
- Project put under git (baseline commit = the audited 0.8.0-rc11 tree). `.gitattributes` keeps LF endings and marks signed fixtures and images binary; third-party datasets and experimental models are not tracked.
- Fix (audit P1-1, log eviction): `AgentFirewall` logs at most 5 denials per agent per minute and summarises the rest (`DENIALS_SUMMARISED`); new separate, hash-chained **security log** (`securityLog`, `exportSecurityLog`, `restoreLogs`) for pairings, the person's answers, kill switch, log damage and throttled `RATE_LIMIT_HIT`; both logs saved encrypted and shown in the activity-log card; export contains both.
- Fix (audit P1-2, write amplification): `AgentFirewall.revision()`; `AgentGateway.persist` skips the write when nothing changed and `persistSoon` coalesces gateway saves to one per 2 s; `AgentGatewayService` drops callers above 120 messages/min per UID before any lookup.
- CI and `core/run-tests.sh` now run the agent-SDK host tests, build and lint the SDK client and sample agent, and API-scan the SDK classes.
- TEST_RESULTS.md and ARCHITECTURE.md regenerated from the current tree and today's results.
- AgentShieldTests 91 checks (21 new). Verified: host tests, Gradle debug builds, lint 0 errors, privacy and API checks. NOT verified: anything on a device; CI has not run (no remote).

## 0.8.2-rc13 first emulator run fixes (2026-10-28)
Version 0.8.2-rc13 (versionCode 19). Found by the first instrumented run on an Android 15 emulator in CI (7 tests: 3 passed, 4 failed; no crash or ANR).
- Fix: text shared into Aegis while a check was still running was shown but never checked (`analyze()` returned early while busy, and the earlier result was discarded as stale). `AegisViewModel.shared()` now cancels the running check or APK inspection and starts a new one.
- Tests: three `DashboardSmokeTest` selectors were ambiguous ("Check" matched both the bottom-bar tab and the Check button; "Review" matched both the agent banner and the Home attention item). They now pick the Check button by its button role, and the first "Review" (both open the same dialog).

## 0.8.3-rc14 protection after restart, device tests (2026-10-27)
Version 0.8.3-rc14 (versionCode 20).
- New: DNS protection comes back by itself after a phone restart or an app update when the person had it on and Android still holds the VPN consent (`BootReceiver`, not exported; new permission RECEIVE_BOOT_COMPLETED, used for nothing else). Without consent it is never started silently: a notice asks the person to turn it on. Stop and a revoked VPN clear the choice. The service is now sticky while protection is wanted, so Android restarts it if it kills the process.
- Tests: emulator tests for the agent gateway over its Messenger interface (pairing, verdicts, approvals bound to the exact request, single-use redemption), signed tokens checked with the reference verifier, the capability broker (one-shot launcher, brokered approvals not redeemable by the agent), the kill switch, the encrypted log store (tampering and swapped files rejected), the DNS VPN (block list answered NXDOMAIN, tripwire caught) and the restore-after-restart logic. A new CI job reboots the emulator and checks the tunnel comes back.
