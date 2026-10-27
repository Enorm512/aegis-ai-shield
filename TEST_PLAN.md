# Test plan and gates

| Suite | Method | Current status |
|---|---|---|
| URL/message regression | EN/NB synthetic benign/adversarial input, unsupported syntax, IDN, IPv4/v6, secret/payment combinations | Executed; see results |
| Fuzz smoke | Fixed seed, 5,000 inputs per analyzer; no crash and valid result invariant | Executed, not coverage-guided fuzzing |
| Hash | SHA256 known vector, bounded stream, exact fake-fixture match/no match | Executed; fixtures are not malware |
| Archive | Synthetic ZIPs, CRC/bounds/header/path/overlap failures, bombs, interruption, 300 mutations | Executed; no APK payload executed |
| Privacy/static | Zero manifest permissions, backup/cleartext disabled, no services, XML, current finding translations | Executed; not packet capture |
| Android instrumentation | Dashboard, benign URL, malformed URL, shared text no auto scan, stale-result race, theme/language | Authored, not run |
| APK integration | Android parser on independently signed benign APK, corrupt signing blocks, large files, provider failures | Pending device build |
| False-positive/negative evaluation | Licensed independently labeled time-separated EN/NB holdout; subgroup error and abstention | Pending; no rates claimed |
| Accessibility | TalkBack, font scale200%, contrast, narrow devices, landscape, RTL | Pending physical/emulator review |
| Battery/performance | Repeated scans on low/mid/high devices; idle A/B and memory measurements | Pending; no battery claim |
| Network | Offline packet capture now; future VPN IPv4/v6, QUIC/DoH, captive portals, handover, lockdown and competing VPN | Pending; VPN absent |
| Supply-chain/security | Resolved SBOM/licences/digests, vulnerability scan, external MASVS/MASTG assessment | Pending |

Do not use untrusted real malware on a personal phone. Hash fixtures are harmless synthetic bytes. Device matrix minimum: Android26,28,35 and current supported releases; Pixel/Samsung/Motorola; API changes reviewed before releases. A passing unit suite is not a detection accuracy measurement or security audit.

## Stage 2
`core/run-tests.sh` and `gradlew :core:check` also run ThreatIntelTests: valid bundle, wrong/unknown key, tamper of every field, exhaustive single-bit mutation, random bytes, truncation, appended data, CRLF/non-ASCII, size cap, replay/rollback, expiry, future dating, hostile-but-signed entries (TLDs, public suffixes, IPs, wildcards, injection text), store install/rollback/reopen/tamper-at-rest, reputation semantics, verdict integration. `IntelBenchmark <entries>` prints host timings. These verify correctness only; detection accuracy against labelled samples is not measured.

## Stage 4
`DnsTests` (host, in `core:check`): DNS/IP parsing and rejection, response checksums verified by independent code, filter precedence, upstream failover/TCP retry/protector, proxy end-to-end, overload, fuzz, privacy scan. `tools/check_android_api.py <classes> <api-versions.xml> 26` guards against JDK APIs newer than minSdk. `tools/check_privacy.py` pins permissions and DNS-only routing. Device/battery/network-reliability testing: planned in NETWORK_PROTECTION.md, NOT done.

## Stage 5
`ManifestTests` (real aapt2 fixtures, truncation/bit-mutation/random sweeps), `LookalikeTests` (impersonation set, 104-host benign list, edit-distance helper, analyzer integration), `AgentFirewallTests` (policy matrix, approval binding/expiry/single-use, rate limit, pending cap, audit chain tamper tests, detector validity checks, regex-blowup guard, 5,000-case fuzz). All in `core:check`. Fixtures were created with `aapt2 link --manifest <x>.xml -I android.jar -o <x>.apk` (sources alongside).

## Stage 6
Release gates: `tools/check_release_apk.py <apk> <build-tools>` (16 KB alignment, no trusted feed key, zipalign), `apksigner verify`, release lint (abortOnError), enforced dependency verification. Review-regression tests: ManifestTests (hostile binary XML built by hand, 128 MB heap), ThreatIntelTests (clock skew, crash recovery, concurrent installs, reads during large install, unsigned junk), AgentFirewallTests (hash framing, pending caps, tail scan, regex timing). Still required: the device matrix in RELEASE_CHECKLIST.md.

## UX redesign
ResultTests (core): input-kind detection incl. fuzz, level mapping, ranking, advice per level/subject, APK evidence combination. Instrumentation: DashboardSmokeTest (7 tests: home, benign link, malformed link, auto-checked share, share-during-analysis, language/theme, agent banner approve/deny) - compiled, never executed. Manual: walk every screen in light/dark, EN/NO, 100%/200% fonts, TalkBack on.

## Visual assets
`java tools/IconPreview.java check app/src/main/res` (strict path parsing, bounds). Manual: view launcher icon in circle/squircle/themed modes, light/dark theme, notification shade, at 200% font scale; check motion with and without 'Remove animations'.
