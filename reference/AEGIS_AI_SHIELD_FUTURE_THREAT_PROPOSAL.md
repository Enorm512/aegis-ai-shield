# Aegis AI Shield 2.0 — Future-Threat Security Architecture & Development Proposal

**Date:** 25 October 2026  
**Audience:** Product owner, Android developers, security engineers, independent testers  
**Status:** Research-backed proposal, updated with independent-implementation policy; not a security certification or implemented feature list

## Executive decision

Build **Aegis as a privacy-first anti-scam, malicious-link, and Android exposure-management product**, with a narrowly scoped experimental **AI-agent safety layer**. Do **not** market it as an app that can stop all AI viruses or protect every other AI app. Android's process isolation and third-party app permissions make those claims unsupportable.

The strategic opportunity is an explainable, localized security assistant for Norwegian and English users, using **independent evidence first, machine learning second, generative AI only as an optional explainer**. Google, Norton, Bitdefender and Malwarebytes already provide major parts of conventional Android security. Our differentiation must be usability, privacy, low false-positive rates, fraud-specific guidance, and accountable security engineering.

**Decision gate:** Fund a 10–12-week pilot only if it demonstrates meaningful detection gains against independent baselines and meets usability/privacy targets. Scale to network protection and agent integrations only after evidence and Play-policy review.

## 1. Threat horizons: 2026–2030

Likelihood and impact are **engineering judgments**, not quantified forecasts.

| Threat | Horizon | Likelihood | Impact | Aegis opportunity | Feasibility |
|---|---|---|---|---|---|
| AI-written phishing, fake bank/BankID/parcel messages, multilingual fraud | Now–2028 | High | High | Local text/URL risk scoring, scam playbooks | High for user-shared content |
| Malicious newly registered domains, QR phishing, URL shorteners, redirect chains | Now–2028 | High | High | Reputation, safe redirect resolution, user-consented QR/image scans | High for submitted URLs; medium for ambient traffic |
| AI voice cloning and family/authority impersonation | Now–2030 | High | High | Challenge-response guidance, verified callback workflows | High for guidance; low for universal live-call detection |
| Android app abuse: sideloaded malware, overlays, accessibility, screen-sharing tricks | Now–2029 | High | High | Posture review, permission education, Play Protect integration | Medium; no full cross-app monitoring |
| Malicious AI agents with excessive permissions acting on money/messages/files | 2027–2030 | Medium–High | Critical | Aegis-controlled approval gate for *integrated* agents | High for integrated agents; very low universally |
| Prompt injection from websites, PDFs, messages hijacking an assistant | Now–2030 | High | High | Protect Aegis's own AI pipelines; optional content labeling | High within Aegis, limited across other apps |
| Agent memory poisoning / malicious tools / supply-chain plugins | 2027–2030 | Medium | High | Signed policy, provenance, allowlists for integrations | Medium within supported integrations |
| Synthetic identities and realistic deepfake video/audio | Now–2030 | High | High | Provenance checks where available; contextual fraud warnings | Medium; detection is not definitive |
| Compromised AI-model or threat-intelligence update | Now–2030 | Medium | Critical | Signed updates, rollback, verified provenance | High for Aegis itself |
| OS/firmware zero-day, kernel-level spyware, baseband compromise | Now–2030 | Lower frequency | Critical | Patch posture, referral, incident advice | **Not reliably detectable or preventable** by ordinary app |

### Key distinction

An **AI-enabled attack** uses AI to create scams or malware; an **attack against AI** manipulates assistants, models, tools, or their memory. Aegis needs two separate detection paths and should never treat text-model output as evidence that executable software is benign.

OWASP's 2025 LLM risks include prompt injection, supply-chain compromise, poisoning and excessive agency. Its 2026 agentic guidance adds tool misuse, privilege abuse, memory poisoning and human-agent trust exploitation. See sources [1–3].

## 2. Product boundaries and proposed modules

### P0 — Launch-critical

**A. Scam Check**
- User shares text, image, QR code, or link into Aegis, or pastes it.
- Local extraction and language detection for Norwegian Bokmål, Nynorsk and English (initial priority Bokmål + English; validate Nynorsk later).
- Rules for impersonation, urgency, fake verification, BankID-like brand spoofing, crypto/investment and romance manipulation.
- URL canonicalization + homograph checks + reputable domain reputation feed. Show exact domain, evidence, and uncertainty.
- Results: `Known malicious`, `Strong scam indicators`, `Suspicious / verify independently`, `No known warning`, or `Unable to assess`. **Never label a URL 'safe' because no flags were found.**
- User education: don't use link-provided numbers; verify using a separately obtained bank/organization contact.

**B. Android Safety Audit**
- Android version and security patch recency; Play Protect status where supported; install-source and permission inspection under approved visibility rules.
- Highlight risky *combinations*, such as unknown installer + SMS/accessibility-related capability; don't declare ordinary permissions malware.
- Launch official device settings and uninstall confirmation flows; no silent removal or bypass.
- Support Play Integrity environment verdict only if API access/eligibility, latency and server-side verification fit architecture. It is not a replacement for malware scanning.

**C. Privacy and evidence UX**
- No registration by default; local analysis and local history off by default.
- Explain which evidence triggered each warning and how stale a reputation result may be.
- Clear consent for any external URL lookup; hash-prefix protocol where supported and appropriate.
- Accessibility, large-text and TalkBack support.

### P1 — Evidence-dependent premium value

**D. Real-time domain defense**
- Opt-in DNS/traffic filtering using a carefully implemented Android VpnService or another compliant, platform-supported route.
- Domain-level blocking using signed local reputation lists, with exact reason and temporary override.
- Handle IPv4/IPv6, DNS caching, private DNS/DoH, QUIC, captive portals, roaming, battery and competing VPNs explicitly.
- HTTPS encryption means URL path, message content and page body are not generally visible. **Do not install a root CA or silently MITM TLS.**
- Network feature must never start before consent; failures must not silently disconnect the user's connectivity.

**E. Downloaded APK analysis**
- Scan an APK the user explicitly selects through the system file picker.
- Validate signing certificate, package metadata, permissions, manifest components and known file hashes; optionally inspect non-executing static indicators.
- No code execution of the inspected APK. Avoid arbitrary file-system access.
- Partner with a reputable licensed threat-intelligence vendor before marketing antivirus-grade detection.

**F. Optional notification protection**
- Only with explicit notification-listener authorization and a high-trust privacy design.
- Process on-device, minimize retained content, support app-by-app exclusion.
- Do not depend on OTP or other protected notification content; Android may withhold it.
- Review Play policy and user consent before implementation. Avoid broad accessibility capture.

### P2 — Future agent-defense platform

**G. AI Action Firewall (integrations only)**
- Offer an Android SDK / documented Intent API that *cooperating* AI agents can invoke before high-risk actions.
- Policy decision engine: money movement, credential release, new app installation, file sharing, new contact, unknown domain, bulk messages.
- Require explicit user confirmation for irreversible/high-impact actions; show origin, data involved, destination and capability used.
- Signed policy configuration and tamper-evident local audit trail.
- No claim that Aegis can intercept, supervise or veto arbitrary third-party agent actions.

**H. Prompt-injection and provenance defense for Aegis**
- Treat web pages, OCR, notifications and threat feeds as untrusted **data**, never system instructions.
- Strict structured extraction, deterministic policy checks, typed tool calls, no assistant access to payment or messaging actions.
- Separate model from privileged operations, require user confirmation, never take remediation actions from an LLM response alone.
- Model/update signing, rollback, SBOM, reproducible training/evaluation provenance where practical.
- Content-provenance support (e.g. standards-based attestations) can inform, but not conclusively prove, authenticity.

## 3. Recommended architecture

```text
User share / picker / optional notification / optional VPN DNS
                          |
                   Consent & minimization
                          |
          Normalization / QR / OCR / metadata
                          |
     +--------------------+-------------------+
     |                    |                   |
 Reputation engine   Rules + tiny ML    Device posture
     |                    |                   |
     +--------------------+-------------------+
                          |
             Deterministic policy engine
                          |
           Explainable risk & user actions
                          |
       Optional AI explanations (sandboxed)
```

**Client:** Kotlin, Jetpack Compose/Material 3, coroutines/Flow, Room (encrypted storage only where needed), WorkManager for bounded signature refreshes, dependency injection, min SDK chosen after device test matrix. No `QUERY_ALL_PACKAGES` assumption until policy approval.

**Detection core:** URL canonicalizer, signed domain lists, independent phishing reputation, controlled classifier (LiteRT) and explicit evidence aggregation. Treat model confidence as a calibration metric, not probability of maliciousness without validated calibration.

**On-device GenAI:** ML Kit / Gemini Nano when available; fallback to compact local text classifier and static explanations. Device capability check is mandatory; never make the app unusable when AICore is unavailable.

**Backend (optional):** Minimal threat-feed service, license-aware commercial reputation provider, signed update distribution, rate limiting, abuse controls. No plaintext user messages sent without separate opt-in consent. Avoid using shared links to train AI by default.

**Security boundaries:** Every network response, feed entry, OCR result and AI output is untrusted; validate lengths, types, encoding and redirect targets. Store signing keys outside app/backend build systems; key rotation and emergency revocation. No remotely delivered executable code.

## 4. Critical Android and Play Store constraints

1. **Package inventory:** `QUERY_ALL_PACKAGES` is tightly reviewed; security/antivirus can be a legitimate category, but minimum visibility and policy justification are required. Previous Aegis v0.1 requests this permission; **remove or scope it before Play submission unless approved**. [4]
2. **SMS/call logs:** Permissions generally require the app to be the default handler or a qualifying exception. Use user sharing rather than promising surveillance of all incoming SMS. [5]
3. **Accessibility:** Don't use accessibility APIs as a shortcut to reading other apps or controlling their interfaces. Non-accessibility products face disclosure and usage restrictions. [6]
4. **Notifications:** NotificationListenerService requires explicit user authorization; sensitive content can be withheld. [7]
5. **VPN:** VpnService needs Android consent, Play declarations, good networking behavior and prominent privacy disclosure. Existing user VPNs will conflict with some approaches. [8]
6. **Play Integrity:** Supports device/Play Protect related verdicts under its defined requirements; not a magic system-wide scanner. [9]
7. **Compliance:** Apply Norwegian/EU GDPR principles: minimization, legal basis, transparent retention, processor contracts where needed, and DPIA screening before broader message/traffic processing.

## 5. Model and detection evaluation

Build a consented or appropriately licensed, provenance-tracked test corpus:

- Genuine Norwegian/English bank, delivery, government and marketplace messages (privacy-safe samples).
- Current phishing and known malware URLs sampled from licensed feeds, with time-separated train/test splits.
- Benign legitimate sites and legitimate but unfamiliar domains (to measure false alarms).
- Brand spoofing, Unicode/IDN, QR, redirects, URL shorteners and newly registered domains.
- Adversarial prompt injection in OCR, HTML and shared messages aimed at making Aegis suppress warnings or exfiltrate content.
- 20+ Android models/versions across Samsung, Pixel, Motorola and other major vendors; include budget devices and no-AICore devices.

**Pilot exit targets (proposed, not demonstrated):**

| Measurement | Acceptance target | Test design |
|---|---:|---|
| Known malicious URL recall | >= 95% | Independent time-separated labeled set |
| Benign URL false-positive rate | <= 0.5% | Representative legitimate traffic corpus |
| Scam-message recall | >= 85% | Norwegian/English adversarial holdout |
| Scam-message precision | >= 90% | Same realistic-prevalence evaluation |
| Median local text scan time | < 500 ms | Mid-range devices, offline |
| Cold app launch | < 2 s | Representative Android hardware |
| Incremental idle battery impact | < 2% per day | Controlled A/B measurements |
| Privacy regression | Zero undisclosed transfers | Packet capture and consent tests |
| Critical/high findings before public launch | Zero unresolved | Independent MASVS/MASTG assessment |

Measure model calibration and detection by language, device class and threat family. Track overrides, not just warning count. Avoid optimizing solely for raw accuracy on imbalanced data.

## 6. Development stages and release gates

| Stage | Duration estimate | Deliverables | Release decision |
|---|---:|---|---|
| 0. Product/security discovery | 2 weeks | Threat model, policies, data flows, vendor/license selection, test plan | Approve actual permission scope |
| 1. Rebuild the MVP | 4–6 weeks | Kotlin/Compose app, share/paste/OCR/QR, robust URL parser, local rule engine, audit dashboard, CI | Internal alpha on physical devices |
| 2. Evidence-backed detection | 4–6 weeks | Licensed reputation feed, compact local classifier, locale-specific tests, explainability | Meet pilot detection and FP gates |
| 3. Security hardening / public beta | 4–6 weeks | Independent review, MASVS tests, crash/battery tests, policy declarations, privacy documentation | Limited Play beta |
| 4. Real-time shield (optional) | 6–10 weeks | VPN/DNS prototype, reliability, network failover, extensive testing | Ship only if network safety and policy gates pass |
| 5. AI Action Firewall R&D | 8–12 weeks | SDK/prototype, developer integration, prompt-injection red team | Separate experimental release |

Durations are **engineering estimates**, not commitments. Parallel tasks and external reviews affect schedule.

### Indicative budget in NOK (planning assumptions, not vendor quotations)

| Approach | One-time effort | External cost allowance | What it buys |
|---|---:|---:|---|
| Solo + AI-assisted prototype | 200–450 developer hours | NOK 10k–50k | Demonstration and device pilot; not commercial-grade protection |
| Focused commercial beta | 650–1,100 multidisciplinary hours | NOK 80k–250k | Validation, policies, UX, threat feeds and independent review |
| Hardened real-time product | 1,500–2,800+ hours | NOK 200k–700k+ | VPN reliability, mature detection, security program and release engineering |

At an **illustrative blended rate of NOK 900–1,400/hour**, the focused beta's labor would be roughly NOK 585k–1.54m, in addition to external costs; the hardened product would be roughly NOK 1.35m–3.92m+ in labor. Costs can be lower if owner-developed but the engineering and validation effort remains. Recurring licensed feeds, infrastructure, security maintenance, customer support and incident handling require a separate operational budget.

## 7. Security-by-design non-negotiables

- Explicit threat and capability claims; no “100% protection.”
- No false green shield from a heuristic-only scan.
- External scan data minimized and opt-in; never monetize installed-app inventory or message contents.
- Signed reputation/model releases, rollback and an incident process.
- No financial or device actions based solely on AI-generated text.
- Strict separation of information gathering, deterministic policy enforcement and AI explanation.
- Local history deletion and short retention defaults; measurable no-network mode.
- Dependency vulnerability scanning, code review, static analysis, fuzzing and reproducible build procedures.
- Independent testing aligned to OWASP MASVS and MASTG before marketing antivirus-grade protection. [10]

## 7A. Independent implementation and source-provenance policy (approved development direction)

**Aegis will be original software, not a fork or source-code merge of Rethink DNS, Hypatia, App Manager or other products.** Existing applications may be studied as references for public functionality, interoperability, usability and performance. Aegis developers must implement code based on independently written requirements and tests. This reduces license entanglement but **does not eliminate all license obligations**: Android SDKs, third-party libraries, datasets, model weights and threat feeds each retain their applicable rights and conditions.

### Clean-room workflow

1. **Reference research:** A research reviewer examines publicly available documentation and lawful software behavior. Record source URL/version, observed inputs and outputs, platform requirements, performance constraints and high-level algorithms. Clearly distinguish directly observed behavior from inferred behavior.
2. **Independent functional specification:** Create platform-neutral, original requirements and black-box tests. Exclude source snippets, decompiled code, copied UI art, proprietary signature tables and distinctive protected implementation details. For sensitive modules, use a separate implementer who receives only the sanitized specification and test fixtures.
3. **Original implementation:** Aegis engineers use documented Android public APIs and independently selected algorithms. Avoid translating source code line by line, syntactic rewrites, AI-assisted paraphrasing of source files, and reproduction of protected assets.
4. **Provenance ledger:** For each module, record author, design sources, third-party dependencies, generated code disclosures, license metadata, approved datasets, test fixtures and code-review sign-off. Keep source/reference research separate from implementation PRs.
5. **Verification:** Run similarity checks where justified, peer review, software composition analysis, SBOM generation, and dependency/license policy checks. Test black-box behavior against original requirements, not copied source output snapshots containing protected content.
6. **Release clearance:** Product owner, security reviewer and license/compliance reviewer approve every component. Independent implementation alone does not remove patent, trademark, contract, trade-secret, data-protection or license considerations.

### Reference-to-original mapping

| Aegis workstream | Reference for research | Original Aegis deliverable | Avoid |
|---|---|---|---|
| DNS/VPN filtering | Rethink DNS, Android VpnService docs | Independently implemented state machine, DNS parser, blocking policy and update mechanism | Copying `BraveVPNService`, routing engine or manifest verbatim |
| Malware signature matching | Hypatia, open algorithm literature | SHA-256-first indicator store with exact-match confirmation, signed feeds and benchmark tests | Copying AGPL code, unrestricted storage/accessibility scanning |
| APK inspector | App Manager, Android PackageManager and APK signing docs | Read-only user-selected APK parser, signer/manifest viewer and risk explanation | Copying GPL scanner classes or privileged/root functionality |
| AI scam detection | OWASP / published threat taxonomies and independently licensed datasets | Original locale-aware feature pipeline, small model and deterministic evidence aggregator | Training on unauthorized private messages or redistributing restricted datasets |
| Agent safety | OWASP Agentic Top 10 and Android public integration APIs | Cooperative high-risk-action authorization API | Claiming interception/control over all other apps and AI assistants |

### Third-party component intake gate

For any external code, model or data package—even a permissively licensed dependency—require: license ID and notice check; provenance and repository owner; maintenance and vulnerability assessment; version pinning and artifact digest; supply-chain risk assessment; privacy/data flow; reproducible tests; and a documented replace/remove path. Treat threat-intelligence terms, commercial API terms and model-weight licenses as separate from code licensing.

### Definition of done for every module

- Original design/specification and test plan approved before implementation.
- No protected external code/artwork copied or paraphrased into Aegis without explicit permission and compliance review.
- SBOM, dependency licenses and third-party data rights recorded.
- Automated behavior tests, fuzz/property tests for parsers, and independent reviewer sign-off.
- Security claims limited to demonstrated behavior; no assertion of universal protection.

### Specific legal boundary

Norwegian Copyright Act § 41 permits an authorized user to observe, study and test operation to determine underlying ideas/principles; § 42 permits certain decompilation for interoperability subject to conditions and use limitations. Directive 2009/24/EC Article 1(2) distinguishes underlying ideas/principles from protected program expression, and CJEU case C-406/10 distinguishes software functionality from protectable implementation. These principles support independent development but are **not blanket permission** to copy code or reverse engineer for any purpose. Obtain a qualified Norwegian/EU legal review before commercial launch.

Primary legal references: https://lovdata.no/lov/2018-06-15-40/%C2%A741 ; https://lovdata.no/lov/2018-06-15-40/%C2%A742 ; https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32009L0024 ; https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:62010CJ0406 .

## 8. Product and business recommendation

**Target:** Norway-first consumers and families who want understandable security advice without uploading private conversations. Differentiation should be proven with comparative testing—not assumed.

**Free:** Manual link/message checks, QR scan, device safety checklist, incident response instructions.

**Paid only after efficacy evidence:** Realtime domain blocking, signed intelligence updates, configurable protection profiles, family education and advanced reports. Keep core safety guidance free; avoid fear-based upselling.

**Do not build initially:** Universal call audio monitoring, hidden screen capture, automatic app uninstall, TLS interception, root-dependent device scanners, arbitrary third-party AI agent control, or unvalidated deepfake “certainty” labels.

## 9. Immediate backlog: next 30 days

1. Refactor Aegis v0.1 to modern Kotlin and unit-test URL normalization (IDN, IPv6, encoded URLs, redirect handling, malformed input).
2. Change risk labels to evidence-based advisory findings; eliminate simplistic numeric score as primary product message.
3. Replace indiscriminate package inventory unless release policy and core-function necessity are demonstrated.
4. Add Android Sharesheet text, QR/image picker, offline OCR and permissionless local scanning.
5. Introduce signed feed format and threat-reputation abstraction with no live feed dependencies hardcoded into UI.
6. Define Norway-focused scam dataset; consent/provenance, personal-data redaction and holdout strategy.
7. Build automated tests, lint, software composition analysis, test APK pipeline and documented device matrix.
8. Prepare privacy notices, Play policy mapping, incident response and independent security testing plan.
9. Establish a clean-room research/specification directory with reviewer roles, source-provenance template and black-box acceptance tests; restrict transfer of reference implementation snippets into product source.
10. Add automated dependency license inventory/SBOM and third-party dataset/model intake checks to continuous integration.

## 10. Source register (primary documentation; accessed 25 October 2026)

1. OWASP, **2025 LLM Top 10** — https://genai.owasp.org/llm-top-10/
2. OWASP, **2026 Top 10 for Agentic Applications** — https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
3. OWASP, **AI Agent Security Cheat Sheet** — https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html
4. Google Play, **Sensitive permissions and package inventory** — https://support.google.com/googleplay/android-developer/answer/16558241
5. Google Play, **SMS and call log policy** — https://support.google.com/googleplay/android-developer/answer/18258653
6. Google Play, **Accessibility API use** — https://support.google.com/googleplay/android-developer/answer/10964491
7. Android, **NotificationListenerService** — https://developer.android.com/reference/android/service/notification/NotificationListenerService
8. Android, **VpnService documentation** — https://developer.android.com/develop/connectivity/vpn
9. Android, **Play Integrity overview** — https://developer.android.com/google/play/integrity/overview
10. OWASP, **MASVS / MASTG** — https://mas.owasp.org/MASVS/ and https://mas.owasp.org/MASTG/
11. Android, **Gemini Nano** — https://developer.android.com/ai/gemini-nano
12. Android, **LiteRT on Android** — https://developer.android.com/ai/custom
13. Google, **Android's next-gen enclave for on-device AI (AISeal), October 2026** — https://blog.google/security/enabling-the-next-gen-enclave-architecture-for-on-device-ai-on-android/
14. Google, **New Android mobile-scam protections, October 2026** — https://blog.google/security/new-android-scam-protections/
15. Google, **Android security and privacy 2026** — https://blog.google/security/whats-new-in-android-security-privacy-2026/
16. Google Safe Browsing, **non-commercial restrictions** — https://developers.google.com/safe-browsing/reference/Appropriate.Usage
17. Malwarebytes, **Scam Guard** — https://help.malwarebytes.com/hc/en-us/articles/52365424317339-Using-Scam-Guard-to-detect-threats-on-iOS-and-Android
18. Norton, **Mobile Security Android** — https://no.norton.com/products/mobile-security-for-android
19. Bitdefender, **Mobile Security Android** — https://www.bitdefender.com/consumer/support/answer/2503/

## Final recommendation

**Proceed with a staged pilot, not immediate full-suite development.** Win trust through demonstrably useful scam detection and excellent local privacy behavior, then earn the right to deploy real-time network protection. Build the future-facing AI Action Firewall only as a cooperative integration platform with hard authorization boundaries; a standalone Android app cannot impose a global security policy on all other agents.
