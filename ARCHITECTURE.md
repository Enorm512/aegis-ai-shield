# Architecture — 0.7.3-rc4 (internal test build)

Two modules: `app` is Kotlin/Compose and Android adapters; `core` is Java 17 source with no external dependencies and Android-compatible API usage. Java is deliberate for portable host verification, not an abandoned Kotlin migration; UI and lifecycle code use Kotlin.

Data flow: explicit paste/share -> bounded input -> pure deterministic analysis -> typed verdict and findings -> localized presentation. APK: document picker -> private bounded temporary copy -> archive preflight -> SHA-256 -> Android metadata -> certificate digest and requested-permission explanation -> finally delete temporary file. No APK code runs. The check screens make no network requests and keep no persistent scan history (retention of the current screen is memory only). The only network traffic is the optional DNS-only VPN service forwarding lookups to the upstream resolver.

Trust boundaries: exported text-sharing activity; untrusted document provider; hostile archive; Android package parser; future intelligence provider. Rejection is insufficient evidence, never confirmation of malware. Metadata or a certificate fingerprint alone is not cryptographic APK integrity verification or publisher trust.

The detector cannot infer whether text was AI-generated.

Components added since 0.2.0 (all in `core` unless noted): signed threat-bundle verifier and atomic store with per-key sequence floors (THREAT_DB_FORMAT.md); text normaliser, rule-based `ScamAnalyzer`, look-alike detector, manifest analyser, `ResultSummary` (levels, reasons, advice); an experimental, off-by-default hashed logistic-regression text classifier (AI_EVALUATION.md); DNS filter and packet handling used by the optional consented VPN service in `app` (NETWORK_PROTECTION.md); a voluntary AI-agent action firewall reached through a pinned Messenger gateway in `app` (AGENT_FIREWALL.md). There is still no global agent interception and no production threat feed; no production signing key exists. Future interfaces must not expose unrestricted actions to a model.

Public platform sources: https://developer.android.com/reference/android/content/pm/PackageManager ; https://developer.android.com/training/data-storage/shared/documents-files ; https://developer.android.com/build/releases/agp-8-9-0-release-notes .
