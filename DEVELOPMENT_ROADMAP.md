# Controlled development roadmap

## Stage 0 — foundation
Two-module repository, Gradle configuration, independent core tests, CI specification, threat model and dependency/provenance ledger. Verification status is in TEST_RESULTS.md. CI definition is not evidence of CI execution.

## Stage 1 — manual security alpha
URL/message rules, sharing, APK selection and static inspection, device posture, English/Norwegian UI. Exit requires Android build/lint, emulator tests and physical device smoke testing; no efficacy claims without an independent corpus. OCR/QR image decoding and persistent history deferred.

## Stage 2 — intelligence (library, store and app lookup done; update transport, import UI, signing key and feed pending)
Choose legally usable commercial feeds; immutable typed indicator schema; pinned verification key; signed exact bytes; monotonic versions, expiry, size limits; atomic active/last-good snapshots; authorized rollback without opening downgrade attacks; rotation/revocation; benign hash fixtures; benchmark. Do not trust unsigned bundled sample indicators as real intelligence.

## Stage 3 — local AI  (classifier, hybrid analysis, tests and app wiring done; real dataset, LiteRT/Gemini Nano, signed models pending)
Evaluate LiteRT vs deterministic baseline on consented EN/NB time-separated labeled samples. License model weights and training data; calibrate abstention; device capability fallback; adversarial tests. Do not label model scores probabilities without calibration.

## Stage 4 — networking  (engine host-tested, service compile-verified; NO device testing yet)
Separate opt-in VpnService research build. IPv4/IPv6, DoH/QUIC/Private DNS limitations, captive portals, VPN conflicts, recovery/lockdown, battery and long-running device matrix. Release blocked until network reliability demonstrated.

## Stage 5 — advanced  (manifest analysis, look-alike detection, agent firewall built and tested on host; Android parts unverified)
Sandboxed APK parser, verified APK signing schemes, richer static metadata; cooperative agent decision interface with caller identity and transaction-bound one-use approvals. No universal interception claims.

## Stage 6 — commercial  (hardening and drafts done; NOT production-ready - see RELEASE_CHECKLIST.md)
Independent audit, labeled accuracy evaluation, supply-chain/SBOM/license review, accessibility, privacy/legal review, current Play target/policy review, release signing and store assets. Current SDK35 is an alpha baseline, not a claim of October 2026 Play submission compliance.

## Stage 6 status  (hardening and drafts done; NOT production-ready - see RELEASE_CHECKLIST.md)
Build hardening, release gates, self-audit, drafts of policy and store material done. Production readiness is NOT reached; see RELEASE_CHECKLIST.md for the blocking items (device testing, production key, independent review, legal, store assets, real threat feed).
