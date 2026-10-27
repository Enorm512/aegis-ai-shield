# Security self-audit (Stage 6)

**This is not an independent audit.** It is (a) the development team's own review against OWASP MASVS v2 categories, plus (b) one review pass by a separate AI reviewer instance that was given the security-critical files and no conclusions, and asked to find concrete defects. No human third-party review, penetration test, dynamic analysis on a device, or dependency-vulnerability scan has been done. Do not describe the app as "audited".

## Reviewer pass: 15 findings and what happened
Severity as stated by the reviewer; "confirmed" means the reviewer reproduced it by running code.

| # | Finding | Status |
|---|---|---|
| 1 | Binary-XML string pool could expand a ~400 KB file into huge memory (OutOfMemoryError → app crash) — high, confirmed | Fixed: cumulative decoded-size cap; regression test runs under a 128 MB heap |
| 2 | Attributes from a foreign XML namespace could shadow `android:name`/`permission`/`exported`, hiding capabilities — high, confirmed | Fixed: only the android namespace (and namespace-less `package`) is read; duplicates rejected; regression tests built with a hand-written XML writer |
| 3 | `startForegroundService` path without `startForeground` when `establish()` fails → crash — medium | Fixed in code (foreground entered on every path). Not device-verified |
| 4 | Approval hash joined fields with `\|`, so a request with shifted delimiter text could redeem another's approval — medium, confirmed | Fixed: length-prefixed fields; regression test |
| 5 | Approval screen omitted amount/currency/payload facts and could show a misleading host — medium | Fixed: real host via URI parsing, amount, currency, sensitive-data kinds and payload size shown. Compile-verified only |
| 6 | Threat store held a lock during verification, stalling DNS lookups during an import — medium-low | Fixed: verification outside the lock, lock-free reads; test shows reads stay fast during a 60,000-entry install |
| 7 | One paired agent could exhaust all approval slots; refused approvals kept their slot — medium-low | Fixed: expiry before counting, per-agent cap of 5, refusals free slots; tests |
| 8 | Injection scan silently ignored the last ~2000 characters of a full-size request — medium-low, confirmed | Fixed: summary and payload scanned separately; test with trailing phrase |
| 9 | One regex was super-linear (700 ms on 100 KB) and ran under a global lock — low, confirmed | Fixed: linear pattern; scans moved outside the lock; timing test |
| 10 | Crash between file moves could leave the database silently empty; floor write failure mishandled — low | Fixed: previous is copied, current replaced by atomic rename after fsync, missing current falls back to previous with a warning, floor re-derived on start; tests |
| 11 | A device clock more than 24 h behind discarded a valid database — low | Fixed: future-dating is enforced on install only; test |
| 12 | Late worker thread could tear down a newer VPN session — low-medium | Fixed in code (session identity check). Not device-verified |
| 13 | Bundle text was split into millions of strings before the signature was checked — low | Fixed: signature verified over raw bytes first; unsigned 4 MB junk rejected quickly (tested) |
| 14 | Trailing dot in domain lists could not be removed — low | Fixed |
| 15 | Comment claimed events hold no allowed names although warn-only names are recorded — low (privacy wording) | Fixed: comment and privacy text corrected |

The reviewer found no defect in DNS/IP parsing, upstream validation, signature and rollback logic, `SensitiveData`, or caller authentication design. Absence of findings in a single automated pass is not evidence of absence.

## MASVS v2 self-assessment
| Group | Assessment |
|---|---|
| STORAGE | Only user lists, pairings, threat database in private storage; backups and device transfer excluded; no secrets stored. Temp APK copies deleted after review. Not verified on a device (file-system inspection) |
| CRYPTO | Only ECDSA P-256/SHA-256 signature verification and SHA-256 hashing through platform providers; no custom crypto; no keys stored. Trust anchors are public keys |
| AUTH | No accounts. Agent callers identified by Binder UID and pinned signing-certificate digest; approvals single-use and request-bound |
| NETWORK | Cleartext disabled; no TLS client; the only network use is plain DNS forwarding to the network's resolver (unauthenticated by nature; ID/question checks only). No DoH/DoT |
| PLATFORM | Exported components: VPN service (bind permission), agent gateway (authenticates in code), launcher/share activity. No WebViews, no deep links, no content providers. Never exercised on a device |
| CODE | Release build minified (R8) and resource-shrunk, not debuggable; target API 36; JDK API usage checked against minSdk; dependency checksums pinned (see below). No dependency CVE scan |
| RESILIENCE | None claimed (no obfuscation goals, root/tamper detection, or anti-debugging) |
| PRIVACY | No analytics/ads/crash SDKs; data minimisation by design; see PRIVACY_POLICY.md (draft) |

## Residual risks (highest first)
1. Nothing in the VPN, foreground-service, gateway or approval UI has run on a device.
2. Detection quality is unmeasured against real labelled data; the language model is weak and optional.
3. The agent firewall relies on the integrating agent's honesty about provenance.
4. No third-party review; the same team wrote the code and the tests.
5. R8-shrunk release behaviour is untested (a 1 MB release APK from a 10 MB debug build means shrinking removed a lot; missing-class issues would only show at run time).
