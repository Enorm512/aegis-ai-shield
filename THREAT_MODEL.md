# Threat model

Assets: user messages, selected APK bytes, truthful findings, app availability, future feed trust anchors. Adversaries: message sender, crafted APK publisher, hostile content provider, compromised dependency/feed provider. A compromised OS/root attacker is beyond this alpha's protection boundary.

| Boundary | Attack | Implemented mitigation / residual risk |
|---|---|---|
| Shared text | Huge input, control characters, deceptive authority | Length caps and strict URL parsing; no automatic link navigation |
| URL/message | Rules evasion, benign phrases triggering alarms | Evidence labels; no probability/safety guarantee; real-world accuracy unmeasured |
| Document provider | Misleading filename/length, endless stream | Byte cap, cache-only random file, background work; blocking provider interruption remains device-test item |
| ZIP | Traversal, duplicate names, bombs, corrupt CRC | Read-only bounded preflight; never extract or execute; native/platform metadata parser still shares app process |
| Permission evidence | Ordinary app mislabeled malware | Requested permissions are contextual information, not malware proof |
| Local data | Logs, backups, screenshots | No scan logs or persistent history, backup disabled; screenshots/keyboard behavior require privacy testing |
| Supply chain | Dependency compromise | Pinned declared versions, no copied antivirus code; dependency verification/SBOM independent review pending |
| Future updates | Poisoning/replay | No updater enabled; authenticated updates required before activation |

No root CA, accessibility service, SMS reader, package installer or destructive remediation. A separate isolated parsing process is a pre-beta hardening priority; bounded ZIP inspection is not a security sandbox.

## Stage 4 additions (DNS protection)
- Hostile DNS packets/queries: strict parsing, drop on doubt, bounded queue (shed load), no state per query. Hostile upstream answers: ID and question must match; oversize answers truncated.
- Poisoned or mistaken threat feed: signature + rollback protection (Stage 2), plus a protected-names list and fail-open behaviour; user allowlist overrides everything.
- Tunnel scope creep: build-time check forbids default routes and per-app lists; the tunnel carries only two host addresses.
- Residual: another app on the device can send DNS to the virtual address (answers only reflect public resolver data); a malicious app can bypass system DNS entirely.

## Stage 5 additions
- Malicious manifest/archive input: AxmlParser validates every offset and size, caps strings/elements/depth/attributes, and throws a single checked exception; display strings are sanitised.
- Agent gateway: any app can bind, so every call must pass UID identification, certificate pinning and pairing; unpaired callers can only trigger a capped, rate-limited prompt. Risks left: pairing-prompt fatigue, an agent lying about provenance, approval spam inside the 20-item cap, loss of pending approvals on process death.
- Untrusted text shown to the person (agent summaries) is control-character-stripped, clipped and always labelled as the agent's claim.
