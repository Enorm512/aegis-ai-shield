# Aegis AI Shield — GitHub Source Audit and Integration Plan

**Date:** 25 October 2026  
**Scope:** Rethink DNS + Firewall, Hypatia, App Manager  
**Method:** Shallow clone of default branches, inspection of actual Gradle, manifest, license and source files; review of official Android/Google Play policies. **No build, instrumentation, dependency vulnerability scan, penetration test or formal legal opinion was performed.**

## Executive decision

**Recommend a clean Aegis Kotlin application with three carefully separated engines:** (1) explainable link/scam checker written specifically for Aegis; (2) optional VPN/domain filtering designed around a minimal subset of ideas or suitably licensed components from Rethink; (3) an opt-in APK inspection module modeled on App Manager's read-only architecture. Use Hypatia's signature/Bloom-filter design *as a concept*, not its 2024 implementation.

Do not fork/merge the three apps wholesale. That would inherit broad Android permissions, unrelated features, substantial maintenance burden and conflicting copyleft obligations. The first Aegis version should contain no background accessibility capture, full-storage access, root/ADB service or unsolicited APK upload.

## Snapshot evidence

| Project | Checked-out commit | Commit date | SDK min/target (source) | Primary licensing | Summary |
|---|---|---|---|---|---|
| [Rethink DNS + Firewall](https://github.com/celzero/rethink-app/tree/07fe5373f8aec3b68344db98223a145c404ed386) | `07fe537` | 2026-10-25 | 23 / 37 | Apache-2.0 (check transitive dependencies and go/native subcomponents) | Current, complex network-engine reference |
| [Hypatia](https://github.com/Divested-Mobile/Hypatia/tree/2223a4d) | `2223a4d` | 2024-11-30 | 16 / 32; compile 33 | AGPL-3.0-or-later | Valuable old scanner architecture; modernization required |
| [App Manager](https://github.com/MuntashirAkon/AppManager/tree/15d835d) | `15d835d` | 2026-10-18 | 21 / 36 | Main scanner GPL-3.0-or-later; other source has mixed SPDX and LICENSES | Strong read-only APK inspection reference, heavy whole-app footprint |

These are **single observed commit timestamps**, not a verified complete maintenance trend; no conclusions about historical release quality are implied.

## 1 — Rethink DNS + Firewall: source-level findings

### Valuable specific modules

| Path within source | Observed function | Aegis decision |
|---|---|---|
| `app/src/main/java/com/celzero/bravedns/service/BraveVPNService.kt` | Android VpnService, connection lifecycle, network monitor | **Study and prototype**, but do not wholesale import |
| `.../service/VpnController.kt` | Start/stop, pause/resume, state reporting, resolver/proxy refresh | Adapt state-machine concepts |
| `.../service/VpnBuilderPolicy.kt` | Restart and connection-monitor policy choices | Reference connection resiliency design |
| `.../service/TunFirewallManager.kt` and `FirewallManager.kt` | Tunnel/firewall integration | Defer until Stage 3, isolate behind an interface |
| `.../service/FirewallRuleset.kt` | Enumerated allow/block/reason semantics | Recreate narrow reason-coded policy model |
| `.../service/RethinkBlocklistManager.kt` | Blocklist management | Evaluate separately from network engine |
| `.../download/BlocklistDownloadHelper.kt` | Update checks and blocklist storage lifecycle | Adopt ideas; require signed manifest and rollback |
| `.../database/DnsLog*` | Local DNS-log persistence and querying | Build opt-in, short-retention equivalent |
| `.../net/go/GoVpnAdapter.kt` | Kotlin/native-Go boundary | **Major integration cost** and cross-language security boundary |

The app includes native transport/routing and a broad feature set (DNS modes, WireGuard, app firewall). Treat the build as **multi-language**, not a simple Kotlin library drop-in.

### Manifest and platform risk

Rethink requests `BIND_VPN_SERVICE`, `QUERY_ALL_PACKAGES`, location-related permissions, network permissions and multiple foreground-service types. Its manifest also sets `gwpAsanMode="never"`, `memtagMode="off"` and `largeHeap="true"`. Those are **review flags for a hardened Aegis integration**, not evidence of a vulnerability in Rethink; hardware/memory compatibility can be a reason for opting out. Aegis should evaluate safe memory-hardening defaults on target devices rather than copy the manifest wholesale.

The relevant service declares always-on/lockdown support. If Aegis does the same, it must actually handle startup, reboot, network loss, captive portals, mobile/Wi-Fi transitions and fail-closed configurations without unacceptable connectivity failures.

### Technical recommendation

- Short-term: keep VPN out of the alpha; produce a `DomainDecisionEngine` interface with `allow/block/unknown` and auditable reason codes.
- Research prototype: separate package/flavor for local VPN + DNS resolver; no cloud tunnel needed initially.
- Validate battery and IPv6, DNS-over-HTTPS/QUIC, Private DNS, multiple VPN conflict, background restrictions, lockdown mode and broken-network recovery.
- Use Rethink as the strongest candidate for Apache-licensed implementation patterns. Review its *full* dependency tree before importing code.

**Estimate:** 2–3 weeks to map architecture/prototype a narrowed network engine; 6–10 additional weeks for a reliable, tested user-facing real-time network shield. The latter is an engineering estimate, contingent on supported device coverage.

## 2 — Hypatia: source-level findings

### Valuable specific modules

| Path | Observed function | Aegis decision |
|---|---|---|
| `.../MalwareScanner.java` | MD5, SHA-1, SHA-256 calculation, `BloomFilter.mightContain()` signature matching | **Reimplement** with modern APIs and SHA-256-first rules |
| `.../Database.java` | Separate Bloom filters for hash types and domain indicators; serialized signature database loading | Reimplement with signed versioned feeds |
| `.../SignatureDatabase.java` | Simple feed descriptor | Create stronger schema: source, version, timestamp, hash, signature |
| `.../MalwareScannerService.java` | Background scan operation | Use explicit selected-document scanning first; later WorkManager as appropriate |
| `.../LinkScannerService.java` | AccessibilityService reads other apps' view text recursively, checks domains | **Reject** for Aegis due to privacy/policy/broad-capture concerns |
| `scripts/0genbloom.sh` and `scripts/Main.java` | Signature feed conversion/generation | Inform own signed feed build pipeline, with provenance and tests |

The inspected signature scanner hashes the same content using MD5, SHA-1 and SHA-256 and tests Bloom-filter membership. Bloom filters **can return false positives**. A positive `mightContain()` should trigger a confirmatory lookup, not an automatic malware conclusion or deletion. MD5/SHA-1 may still be used for matching legacy supplied indicators but must not be relied on as modern cryptographic integrity guarantees.

### Modernization and policy risks

The checked-out build targets SDK 32, requests `MANAGE_EXTERNAL_STORAGE`, legacy storage permissions and `QUERY_ALL_PACKAGES`, and implements an accessibility-based link scanner. These choices are unsuitable defaults for a contemporary minimum-permission Play Store app. The observed latest commit was November 2024, so update-feed health and current Android compatibility need independent verification.

Its AGPL license has significant source-availability implications if code is combined into a redistributed product. We should implement the general technique independently, or choose AGPL-compliant licensing deliberately and obtain legal review.

**Estimate:** 1 week to create a fresh selected-APK/file SHA-256 scanner with signed updates, plus 2–4 weeks for signature provenance, data format migration, performance tests and false-positive handling. This does **not** imply antivirus-grade detection coverage.

## 3 — App Manager: source-level findings

### Valuable specific modules

| Path | Observed function | Aegis decision |
|---|---|---|
| `app/src/main/java/io/github/muntashirakon/AppManager/apk/parser/ManifestParser.java` | Decodes APK manifest/components | **Study**, define narrow read-only APK metadata parser |
| `.../compat/PackageManagerCompat.java` | Package-manager compatibility layers | Avoid privileged paths; use public SDK where possible |
| `.../scanner/ScannerViewModel.java` | APK file/URI selection, hashing, verification, class and tracker inspection | Main blueprint for opt-in APK review UI |
| `.../scanner/SignatureInfo.java` | Structured signature finding | Recreate typed evidence records |
| `.../scanner/vt/VtScanCoordinator.java` | Consent-aware external scan attempts | Privacy architecture reference, not direct copy |
| `.../scanner/vt/VtScanRepository.java` | VirusTotal-related scan workflow | No automatic upload; separate opt-in and license assessment |
| `.../details/manifest/ManifestViewerViewModel.java` | Manifest display | Recreate a simplified human-friendly view |

The `ScannerViewModel.java` implementation calls out an explicit consent-required path before an external scan upload and uses Aho–Corasick matching to find tracker/library class signatures. These are useful patterns for an explainable inspection screen.

### Integration risks

App Manager is intentionally broad: its manifest requests `QUERY_ALL_PACKAGES`, `MANAGE_EXTERNAL_STORAGE`, `REQUEST_INSTALL_PACKAGES`, and contains an Accessibility service; other components use hidden Android APIs, root or ADB-backed privileges. **None should be imported into Aegis's initial permission set.** The app itself targets SDK 36 and has a substantial multi-module Java/native codebase. The inspected main scanner file uses GPL-3.0-or-later; `app/build.gradle` declares a compound Apache-2.0 and GPL-3.0-or-later SPDX expression. Legal scoping requires source-by-source and dependency review.

**Estimate:** 2–3 weeks to implement public-API-only APK document picker, signature/manifest analysis and risk explanations; 2–4 weeks for robust file-format parsing, fuzz tests and safe handling of malformed APKs.

## 4 — Comparative integration scorecard

Scores are engineering judgments (5 = most favorable), **not security certifications**.

| Dimension | Rethink | Hypatia | App Manager |
|---|---:|---:|---:|
| Relevance to Aegis | 5 | 4 | 5 |
| Recent source activity | 5 | 1 | 5 |
| Straightforward narrowed reuse | 2 | 3 | 2 |
| Permission minimization ease | 2 | 1 | 1 |
| Commercial license flexibility | 4* | 1 | 1–2 |
| Value as architecture reference | 5 | 4 | 5 |

\* Rethink's top-level Apache license is comparatively permissive, but bundled native code, dependencies, threat lists and commercial services must be reviewed independently.

## 5 — Recommended Aegis target architecture

```text
Android UI (Kotlin + Compose)
  |
  +-- User-shared link/text/image/QR analysis [P0]
  |     +-- robust URL canonicalization
  |     +-- local phishing/scam classifier
  |     +-- licensed reputation evidence
  |
  +-- User-selected APK analysis [P1]
  |     +-- parser sandbox / defensive file processing
  |     +-- manifest, signatures, permission findings
  |     +-- SHA-256 feed lookup (signed updates)
  |
  +-- Android posture checker [P0]
  |     +-- current public-API visibility only
  |     +-- system security and Play Protect guidance
  |
  +-- Optional DNS/VPN service [P2]
        +-- signed local deny lists + allow overrides
        +-- full IPv4/IPv6 network testing
        +-- local logs off by default
```

Separate **deterministic enforcement** from any GenAI explanation. A model's answer must never cause an automatic package removal, credential transmission or silent security bypass.

## 6 — Engineering backlog and costs

| Workstream | Estimated effort | Gate |
|---|---:|---|
| Build reproducible baseline and modern Kotlin UI, CI, dependency inventory | 50–90 h | Signed test build works on real phones |
| Robust URL intake, IDN tests, QR/OCR/share UX | 70–120 h | Low false-positive rate, privacy test |
| Signed threat feeds, provenance, rollback, reputation integration | 80–150 h | Offline/stale-feed tests pass |
| APK read-only parser and risk presentation | 90–160 h | Malformed APK fuzzing + device compatibility |
| Device posture checks and permissions UX | 40–70 h | Play policy review |
| Test dataset, evaluation, localized scam-classifier pipeline | 120–220 h | Independently measured metrics |
| Security QA, OWASP MASVS test suite, privacy review, external validation | 120–220 h | No unresolved critical/high issues |
| Optional production VPN/DNS filtering **additional** | 240–450 h | Network reliability/battery tests |

**Core commercial beta:** ~570–1,030 engineering/test hours. **With real-time VPN:** ~810–1,480 hours. These are planning estimates, excluding large-scale data labeling, major platform regressions, legal costs and long-term incident response. At an illustrative NOK 900–1,400/hour: ~NOK 513k–1.44m core labor; ~NOK 729k–2.07m with VPN, plus external expenses. No fee quotes were obtained.

## 7 — Licensing decision (must precede implementation)

1. **Preferred commercially flexible path:** clean Aegis code, reusing permitted Apache-2.0 components with copyright notices and license compliance, while checking dependency licenses and separate blocklist rights.
2. **Copyleft path:** knowingly release relevant Aegis combined work under GPL/AGPL terms where required, with corresponding source provision and compliance workflow.
3. **Avoid:** copying GPL/AGPL source into closed commercial modules while assuming attribution alone is sufficient. Do not assume an open-source threat list grants rights for resale or incorporation.
4. **Services:** VirusTotal and reputation feeds have their own API usage, disclosure, licensing and upload/data-sharing constraints. Use commercially licensed services where needed. Google's Safe Browsing APIs are non-commercial only; commercial solutions should assess Web Risk or alternatives.

This is a technical risk assessment, not a lawyer's legal determination.

## 8 — Pre-release security test matrix

- APK fuzzing: malformed ZIP, oversized decompression, truncated signatures, duplicate/ambiguous manifest entries, path traversal, encrypted/packed content.
- URL adversarial suite: Unicode homographs, IPv6, userinfo `@`, percent-encoded authority/path, redirect loops, IP literal variants, mixed-case and unusual schemes, punycode.
- VPN: IPv6 connectivity, private DNS, DoH, QUIC, captive portals, airplane mode, sleep/reboot, mobile-to-Wi-Fi switch, other VPN installed, lockdown and bad DNS response behavior.
- Mobile: background restrictions and notification permission on Samsung, Pixel, Motorola; battery benchmark; low RAM.
- Safety: false positives and false negatives sampled against time-separated independent ground truth; no automatic destructive remediation.
- Supply chain: dependency inventory/SBOM, source verification, signed update manifest and rotation, CI secret controls, binary reproducibility where possible.
- Privacy: network capture demonstrating no undeclared upload, no indefinite history, explicit revoke controls, no accessibility capture.

## 9 — Concrete implementation sequence

**Week 1–2:** Create read-only prototypes from Aegis's existing source; write robust tests; remove broad package visibility until justified; run Aegis through MobSF and basic Android lint.

**Week 3–5:** Build APK/URL analysis core, signed feed proof of concept, local findings UI. Inspect only user-selected files. Do not incorporate Hypatia or App Manager code without a license decision.

**Week 6–8:** Norwegian scam evaluation, adversarial content tests, device QA, internal signed APK. Establish effectiveness relative to Android's built-in protections.

**Week 9–12:** Limited consented beta, external security/privacy audit. Decide whether detection quality and user adoption justify continued investment.

**Following stage:** Add optional Rethink-inspired DNS filtering as a separate, deeply tested feature. Defer generic cross-app AI agent supervision—Android cannot grant a normal security app universal authority over other agents.

## 10 — Source and reproducibility appendix

Local source snapshot names in this audit: `audit_rethink`, `audit_hypatia`, `audit_appmanager` (not deliverables; not bundled). All snapshots were taken as shallow clones of default branches on 25 October 2026. They were **read only**. To reproduce findings, checkout the exact commits above; inspect the cited path names and app manifests/build files.

Official constraints:
- [Android VpnService](https://developer.android.com/develop/connectivity/vpn)
- [Android package visibility](https://developer.android.com/training/package-visibility/declaring)
- [Google Play sensitive permission policy](https://support.google.com/googleplay/android-developer/answer/16558241)
- [Google Play SMS/call log and VPN policy](https://support.google.com/googleplay/android-developer/answer/18258653)
- [Google Play AccessibilityService policy](https://support.google.com/googleplay/android-developer/answer/10964491)
- [OWASP MASVS](https://mas.owasp.org/MASVS/) and [MASTG](https://mas.owasp.org/MASTG/)
- [Google Safe Browsing appropriate usage](https://developers.google.com/safe-browsing/reference/Appropriate.Usage)

## Final recommendation

**Green-light a narrow 8–12 week validation build.** Use Rethink's networking implementation as the primary technical reference, App Manager's scanner architecture as the APK-analysis reference, and Hypatia only as a legacy signature-scanning reference. Do not ship copied scanning/network code before legal, security and compatibility reviews. The current Aegis v0.1 source is only a prototype and not a benchmark for effectiveness.
