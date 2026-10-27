# Aegis AI Action Firewall (prototype) and future-threat mapping

**Status: policy engine host-tested (4,533 + 106 + 70 + 549 checks). The Android Messenger service, pairing and approval screens compile and pass lint but have never run on a device.** Revised after the 2026-10-26 expert reviews (REVIEW_SECURITY_EXPERT.md, REVIEW_AI_ENGINEER.md).

## What it is and is not
A voluntary gate. An AI assistant that integrates calls Aegis *before* a consequential action and receives ALLOW, ASK_USER or DENY. Aegis cannot see, intercept or control assistants that do not call it, and a compromised or non-cooperating assistant can ignore the answer. It is a policy *decision* point with no *enforcement* point: real teeth would need Aegis to sit in the data path as a capability broker (the agent only gets credentials/tools through Aegis). It reduces risk for assistants that opt in; it is not an antivirus for AI.

**0.7.9: capability broker.** For opening a link and sharing text, an agent can now ask Aegis to *carry the action out* instead of asking permission: Aegis performs exactly what was allowed or approved, from the content it holds, so for those two actions Aegis is the enforcement point. A reference SDK computes provenance in the harness (context-level taint tracking), not in the model. See AGENT_SDK.md.

**0.8.0: approval tokens.** ALLOW results and granted redemptions carry a short-lived token signed with a per-phone Android Keystore key. A backend that enrols the phone's public key can refuse any agent call without a valid token for that exact host, body and agent. See APPROVAL_TOKENS.md.

## Request model
`AgentFirewall.Request(agentId, type, destination, summary, payload, provenance, amountMinor, currency)`. `summary`, `payload` and `destination` are untrusted agent-supplied text. **Provenance** says whether the instruction came from the user (`USER_DIRECT`, `USER_CONFIRMED_PLAN`) or from `EXTERNAL_CONTENT`, `AGENT_TO_AGENT` or `UNKNOWN`.

**Provenance is self-reported and cannot be verified by Aegis.** It is only meaningful if the *harness* (not the language model) computes it by taint tracking: anything influenced by external content must be labelled `EXTERNAL_CONTENT`, and the most-untrusted label wins. If the model chooses the label, a compromised agent simply claims `USER_DIRECT`. Therefore provenance is used so that it can turn a **DENY into a question to the person**, but it **never turns a question into a silent ALLOW**.

## Policy (all fail-closed)
| Situation | Decision |
|---|---|
| unknown agent, action not granted to that agent, malformed/oversize request, engine error, scan time budget exceeded, rate > 30/min | DENY |
| execute, install, pay, use credential, change settings, **not** from the user | DENY |
| same actions, from the user | ASK_USER (every time, any amount) |
| secret (private key, cloud/API token, JWT, password assignment, DB URL with password, Basic auth...) in outbound data - payload, summary or destination - to an untrusted destination | DENY, even if the user asked |
| secret to a trusted destination | ASK_USER |
| card number, IBAN, Norwegian national id to an untrusted destination | ASK_USER if user-driven, otherwise DENY |
| outbound data or file to a destination not on the trusted list | ASK_USER whatever the provenance |
| sensitive read | ASK_USER whatever the provenance |
| injection wording in untrusted text together with outbound/risky action and no user provenance | DENY; otherwise ASK_USER |
| trusted exact host, nothing flagged | ALLOW |

Trusted destinations are **exact hosts** (trusting `api.example.org` does not trust `evil.api.example.org`; never add multi-tenant suffixes such as `github.io`). In the app, trusted hosts are managed under Protect → AI agent guard → Trusted destinations (plain host names only, at most 50; IP addresses, URLs, wildcards and punycode names are refused). Until the person adds one, every outbound request asks. Trust never overrides secret, personal-data or injection checks.

**Per-agent grants:** pairing grants only `SEND_DATA`, `SHARE_FILE`, `MESSAGE_AGENT`, `READ_SENSITIVE`. Commands, installs, payments, credential use and settings changes require the person to tick "also let it ask for risky actions" in the pairing dialog.

**Revocation:** removing an agent (or the kill switch) also drops its waiting and approved-but-unused approvals; a redemption by an agent that is no longer paired is refused (`AGENT_NOT_PAIRED`). Before 0.7.9 an approval granted before removal could still be redeemed.

**Approvals:** bound to a hash of the exact request (length-prefixed fields), single use, 5-minute expiry, at most 20 open (5 per agent); refusals free their slot. The approval dialog shows the real host (URI-parsed), the destination as written, amount and currency, the kinds of sensitive data found, and **the payload or command itself** (control, bidi and zero-width characters shown as `<U+...>`, clipped to 300 characters, 800 for commands). It is pinned to the request it opened with: if a newer one arrives it closes instead of letting a tap land on something unread. Deny/Reject is the prominent button. On Android 14+ the dialog's window is marked accessibility-data-sensitive, so only accessibility *tools* (such as TalkBack) can read or press its buttons; when the asking agent itself holds Accessibility, the dialog warns that it can tap the screen.

**Persistence (0.7.8):** open and approved-but-unused approvals survive the app being stopped, within their original 5 minutes (`exportPending`/`restorePending`; on restore, expired or refused approvals, approvals of agents no longer paired or no longer granted that action, and expiries more than 5 minutes ahead are dropped). Stored with the dialog's display data in an AES-256-GCM file whose key is in the Android Keystore (`SealedStore`), in app-private storage; app backups are off.

**Flood resistance (0.8.1):** denials are logged one by one only up to 5 per agent per minute; the rest are counted and written as one `DENIALS_SUMMARISED` entry, and the first rate-limit hit per agent per 10 minutes goes to a separate **security log** (300 entries: pairings, the person's answers, kill switch, log damage, rate-limit hits) that request traffic cannot rotate. The app writes its files only when this state changed, at most once per 2 s for gateway traffic, and the gateway drops callers above 120 messages per minute per UID before any lookup or crypto. Before 0.8.1 a paired agent could rotate the log with a burst of rate-limited requests, and every message (even refused or unpaired ones) caused an encrypted write.

**Audit log:** bounded (500), SHA-256 hash-chained, stored in the same encrypted way and continued across restarts. It records decisions, the person's approve/deny, redemptions and refused redemptions (with reason), pairing, rejected pairing, removal and the kill switch, as agent id, action type, destination *host* and reason codes; never payloads or summaries. Every field is reduced to a fixed character set, so agent-supplied text cannot forge lines. A saved log that fails its chain check or cannot be decrypted is not trusted: a new log starts from a hash of the damaged text, its first entry is `LOG_DAMAGED`, and Home shows a warning. Protection → Agent activity log shows the entries, a 16-hex-digit fingerprint of the head hash and an Export (plain text with anchor and head, verifiable with `AgentFirewall.verifyChain`). Not externally anchored: someone who can run code as Aegis could rewrite the whole log consistently; only an older export or a noted fingerprint would show that.

**Pairing dialog (0.7.8):** shows the app's label and icon (marked as chosen by the app) next to its package name, install source (app store, came with phone, sideloaded, installed by another app, unknown; from `getInstallSourceInfo`), whether it asks to draw over other apps, and the powers it already holds from the capability watch (Accessibility, notification access, device admin, default SMS, keyboard). `CapabilityWatch.pairingAdvice` gives a risk level and reasons. An app with Accessibility (it could tap Allow/Approve in Aegis itself) or device admin, or one Aegis cannot read details about, needs an extra "I know this app has strong powers" tick before Allow works.

**Kill switch (0.7.8):** Protection → Emergency stop for AI agents. One confirmed tap unpairs every agent, removes risky grants, cancels waiting and approved-but-unused approvals, drops pending pairing requests and refuses every request (`KILL_SWITCH_ON`), before the caller is even identified, so no pairing prompt can be raised either. The state is saved before anything else and restored at start-up. While on, the card lists apps holding Accessibility or notification access with buttons to the system pages where the person can switch them off; Aegis cannot revoke those itself. Turning it off (also confirmed) does not restore removed agents; they must ask to pair again. Trusted destinations are kept.

## Detectors
- `SensitiveData`: private-key headers (incl. PGP), AWS keys and secret-key assignments, Google `AIza`, Stripe, GitHub/Slack/`sk-` tokens, JWT (linear-time scanner), bearer and Basic tokens, URLs with embedded passwords, `password/secret/api_key/client_secret/...` assignments (quoted, prefixed, JSON; placeholders like `********`, `${VAR}`, `os.environ[...]`, "required" ignored), Luhn-valid card numbers (15-19 digits, plausible first digit), IBAN (mod 97), Norwegian fødselsnummer/D-number. Kinds only; values never kept. Not detected: seed phrases, WIF keys, base64-wrapped or split secrets, custom formats.
- `InjectionIndicators`: English/Norwegian/German/Spanish/French override phrases, role reassignment, fake system lines (linear scan), secrecy from the user, exfiltration of credentials, command patterns, prompt-extraction, hidden text (zero-width, bidi, Unicode tag characters, HTML comments mentioning instructions). Phrase rules run on the original and on normalised text (look-alikes, leetspeak, spacing). Heuristic and bypassable by paraphrase; generic English phrases can still fire on benign text, which is why the agent's own summary of a user-driven action is not scanned.
- **Time budget:** every scan runs under a 2-second wall-clock budget (`Deadline`); exceeding it denies the request (`SCAN_TIMEOUT`). Two quadratic patterns found by the security review were replaced by linear code.

## Integration interface (Android, preview)
Bound `Messenger` service, action `com.aegis.app.AGENT_FIREWALL`; message formats in `AgentGatewayService.kt`. The caller is identified by the system-supplied sending UID; its signing certificate is pinned at pairing; a changed certificate is refused (there is no re-pair path after legitimate certificate rotation: remove and pair again). Unpaired callers only produce a rate-limited, capped pairing prompt and a generic notification. Android's package-visibility documentation lists apps that bind to your service as automatically visible, so resolving the caller should work on API 30+ without `QUERY_ALL_PACKAGES`; that documentation does not name `getPackagesForUid` explicitly, so this is **unverified on a device** (if it fails, callers are refused as unidentified). The service also parses the caller's Bundle before authenticating (platform behaviour).

## Mapping to the Layer E threat list
| Threat | Control | Gap |
|---|---|---|
| Prompt injection / manipulated external content | provenance gating (if harness-computed), indicator scan, secret/exfil denial | semantic and paraphrased attacks, images/audio, a lying harness |
| Agent goal hijacking, excessive agency, tool misuse | risky actions need user provenance and per-request approval; per-agent grants | agent may lie about provenance or bypass Aegis; approval fatigue |
| Unauthorized data transmission, credential exposure | secret/PII scan of payload, summary and destination; exact-host trust | custom secret formats, encoded/split data |
| Unauthorized financial actions | every financial action asks; no auto-approval | amount/payee verification left to the person |
| AI memory poisoning, malicious plugins, multi-step attacks | not addressed | no enforcement point |
| Malicious agent-to-agent instructions | `AGENT_TO_AGENT` treated as untrusted | depends on the integrating agent labelling it |

OWASP LLM / agentic-AI framing is from the developers' background knowledge and the AI reviewer's recollection, not freshly verified; re-check sources before external use.

## Required before any release
Device tests of pairing (label, icon, installer and overlay detection under package visibility), certificate pinning, rate limits, process death during pending approvals, Keystore availability and the encrypted store, the accessibility-data-sensitive flag on dialogs, the kill switch, notification delivery, accessibility of the approval dialog, a reference SDK that does taint tracking, and independent human review of the IPC surface.
