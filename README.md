# Aegis AI Shield

**A guard between AI agents and your Android phone.** AI assistants that integrate with Aegis ask it before they send data, share files, read private data, install apps, run commands or pay. Aegis allows, refuses or asks you, shows you what the agent did just before, and needs your fingerprint, face or PIN for the risky ones.

> **Preview. Not real protection yet.** Version 0.8.10-rc21. Tested on an Android 15 emulator in CI, never on a real phone, and never reviewed by an independent security expert. Read KNOWN_LIMITATIONS.md before relying on any of it.

## What it does
**AI agent guard** (the main part):
- Agents pair once. You approve each app, and its signing certificate is pinned.
- Every request is checked. Secrets, card numbers and personal data, hijack wording in content, unknown destinations and risky actions lead to a question or a refusal.
- Approvals are bound to the exact request and can be used once.
- Chain rules catch sequences that look fine step by step: reading private data and then sending, acting after hijack wording, a sudden "the person asked for this", and a secret sent in pieces.
- Your controls: an emergency stop for all agents, a stop per kind of action, read-only mode per agent, and "Is this you?" when activity looks like it happened without you.
- Approving anything sensitive, or loosening a limit, needs Android's own screen-lock check.
- Approval tokens let a server check that you really approved (APPROVAL_TOKENS.md). A reference agent SDK and a sample agent are included (AGENT_SDK.md).

**Other checks** (weaker; established apps do these better, see below):
- Links, messages and screenshots or QR codes, checked on the phone (English and Norwegian rules, an experimental small text classifier, Tesseract OCR).
- APK files you choose: archive safety, signer and the permissions they ask for.
- An optional DNS-only filter, and a list of apps that hold strong powers such as Accessibility.
- Tripwires: decoy data that alerts you if something uses it.

Nothing leaves the phone. There are no accounts, ads or tracking, and only the permissions in PRIVACY_POLICY.md.

## What it does not do
- **It only sees agents that choose to ask it.** An agent that acts on its own, or controls the phone through Accessibility, is not stopped. No agent integrates with Aegis today.
- **Scam detection is weak.** The rules found 3 of 41 unseen scam messages in a reviewer's test, and the threat database ships empty. For scam texts and calls, use Google's built-in Scam Detection or an established security app.
- **For DNS and network blocking, use RethinkDNS, TrackerControl or NetGuard.**

## Status
| | |
|---|---|
| Host tests | Core and SDK suites (`bash core/run-tests.sh`) pass in CI |
| Emulator tests | 39 tests on Android 15 (API 35) in CI, including the real gateway over Messenger and the main screens |
| Real phones | **Never run** |
| Fingerprint/PIN prompt | **Never run** (the CI emulator has no screen lock) |
| Independent security review | **None** |

TEST_RESULTS.md lists what each CI run covered and what it did not.

## Build
```sh
bash core/run-tests.sh                                   # core and SDK tests, JDK 17+ only
gradlew :core:check :app:assembleDebug :app:lintDebug    # full build
python tools/check_privacy.py                            # exact permission set, DNS-only routing, backup flags
```
BUILD_INSTRUCTIONS.md covers the rest, including release signing. The debug build shows a TEST BUILD banner and trusts a test key that is published on purpose. The release build trusts no key and ships an empty threat database.

## Documents
- **Agent guard:** AGENT_FIREWALL · AGENT_SDK · APPROVAL_TOKENS
- **Design:** ARCHITECTURE · THREAT_MODEL · SECURITY_REQUIREMENTS · NETWORK_PROTECTION · THREAT_DB_FORMAT · AI_EVALUATION
- **Testing and limits:** TEST_PLAN · TEST_RESULTS · KNOWN_LIMITATIONS · SECURITY_AUDIT
- **Project:** CHANGELOG · DEVELOPMENT_ROADMAP · DEPENDENCIES · DATA_SOURCES · SOURCE_PROVENANCE · PRIVACY_POLICY (draft) · PLAY_COMPLIANCE · STORE_LISTING (draft) · RELEASE_CHECKLIST · ACCESSIBILITY
- **Reviews kept for the record:** REVIEW_* and `reference/`

## How it was made
Written with heavy help from AI coding assistants, from the owner's requirements, with no code copied from other projects (SOURCE_PROVENANCE.md). Every claim in the documents is meant to match what was actually run; if you find one that does not, please open an issue.

## Contributing and security
See CONTRIBUTING.md. Report vulnerabilities privately as described in SECURITY.md.

## Licence
Apache License 2.0 (LICENSE). Third-party parts keep their own licences (NOTICE, DEPENDENCIES.md).
