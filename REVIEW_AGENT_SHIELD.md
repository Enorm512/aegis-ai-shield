# Review: Aegis as a shield against rogue AI agents (0.7.5-rc6, 2026-10-27)

Reviewed against the product's stated core purpose. Based on the code (AgentFirewall, InjectionIndicators, SensitiveData, AgentGateway, AgentGatewayService, AgentNotifier: about 720 lines) and its tests. **Nothing in the agent path has run on a device.** Android API statements below come from background knowledge of public platform APIs and must be checked on a device before building on them.

> **Status update (0.7.6-rc7):** item 1 (capability watch) is built: `CapabilityWatch` (core, 26 host checks) and `PowerWatch`/`PowersCard` (app). It lists holders, marks new grants since the last review, rates risk per app (Accessibility plus notification access in one app is the top pattern), links to the system settings pages, and re-checks every 30 minutes while DNS protection runs. Never run on a device. Items 2-5 are still open.
>
> **Status update (0.7.7-rc8):** item 3.1 (canary tokens) is built (see below for 0.7.8): `CanaryTokens` (core) and `Tripwires`/`TripwireCard` (app). Decoy contact (via the Contacts app's own insert screen), note (share sheet) or file (document picker), each with a random 100-bit token under `aegis-canary.invalid`; the DNS filter checks tripwire names before every other rule, answers them locally with NXDOMAIN, never forwards them, records a CANARY event and raises a high-priority notification; a Test button verifies detection end to end. 2,036 host checks (filter precedence, listener failure, proxy path). Never run on a device.

## Verdict
Against **rogue** agents the app gives almost no protection today. What exists is a careful *permission-request service for cooperative agents*: an agent that chooses to ask Aegis gets ALLOW / ASK / DENY, and a person approves risky steps. A rogue agent (a malicious app, a compromised assistant, or a hijacked agent whose harness lies) simply does not ask, ignores the answer, or reports `USER_DIRECT` provenance. Even after an approval, Aegis only replies `granted: true`; the agent then performs the action itself, so nothing ties what was approved to what is done.

So the honest positioning today is: "helps well-behaved assistants avoid being tricked by prompt injection." It is not yet "protects you from rogue agents". The second needs controls the agent cannot opt out of.

## Threat-by-threat
| Rogue-agent threat on a phone | What Aegis does now | Effective? |
|---|---|---|
| Malicious app driving the phone through an Accessibility service (reading screens, tapping "confirm") | Nothing | No |
| Agent reading notifications (OTP codes, messages) via a notification listener | Nothing | No |
| Agent exfiltrating data to its server | DNS filter can block *known* bad domains only; agent firewall only if the agent asks | Weak |
| Prompt-injected but honest assistant (integrated with Aegis) | Provenance gating, secret/PII scan, injection indicators, per-request approval | Partial (if the harness labels provenance correctly) |
| Agent tricking the person into approving (approval fatigue, misleading summary) | Payload shown with hidden characters made visible, real host shown, Deny is prominent, dialog pinned to its request | Reasonable |
| Overlay/tapjacking of Aegis' own approval dialog | `filterTouchesWhenObscured` | Reasonable (unverified on device) |
| Agent impersonating a paired agent | UID + signing-certificate pinning | Good design (unverified on API 30+) |
| Agent-to-agent instruction chains, memory poisoning, malicious tools/plugins | Label `AGENT_TO_AGENT` treated as untrusted | Only if labelled |
| Silent installation of other apps, device-admin takeover, default-SMS takeover | Not monitored (the APK check is manual) | No |

> **Status update (0.8.0-rc11):** item 2.2 is built: signed, short-lived approval tokens a backend can verify (APPROVAL_TOKENS.md). With a backend that requires them, an agent call the person did not approve, or that Aegis did not allow, is refused at the server, even if the agent never asked Aegis. Not run on a device.
>
> **Status update (0.7.9-rc10):** item 2.1 (capability broker for open-link and share-text) and 2.3 (reference SDK with harness-side provenance, sample agent) are built; see AGENT_SDK.md. Item 2.2 (signed redemption tokens for servers) is not. Weaknesses 1-3 below are reduced for those two actions only; nothing has run on a device or with a real assistant.
>
> **Status update (0.7.8-rc9):** item 4's persistent approvals and audit log, better pairing dialog and kill switch are built (see AGENT_FIREWALL.md). Weaknesses 4 and 5 below are addressed in code, not yet on a device. Daily automatic anchoring of the log was not built (export and a shown fingerprint instead). Pairing an app with Accessibility needs an extra confirmation rather than being refused outright.

## Specific weaknesses in the current agent path
1. **No enforcement point.** Approvals return a boolean; the agent acts. Fix direction: Aegis performs (or brokers) the action itself (see 2.1).
2. **Self-reported provenance** decides between DENY and ASK. Correct only if a harness computes it; there is no reference harness or SDK.
3. **No integrating agents exist.** The Messenger protocol is undocumented outside the source, has no client library, and has never been called by a real assistant.
4. **Approvals live in memory**: lost on process death; no persistent audit; the hash-chained log is not anchored anywhere.
5. **Pairing UX is the trust root** and only shows a package name and certificate digest; a person cannot judge that. No app label, installer source, or capability summary is shown.
6. **Detectors are heuristics** (secrets, PII, injection phrases): bypassable by paraphrase, encoding or splitting across requests. No per-agent rate of data volume, no cumulative "this agent has sent 40 messages today" view.
7. **Package visibility on API 30+** for caller identification is still unverified on a device.

## Improvements that make it a real shield (prioritised)

### 1. Watch the powers a rogue agent needs (works without any agent's cooperation)
Rogue agents on Android need one of a few high-power capabilities. Aegis can list them and alert when they change:
- enabled **Accessibility services** (screen reading and automated taps: the main route for phone-controlling agents),
- enabled **notification listeners** (OTP and message reading),
- **device administrators**, the **default SMS app**, enabled **input methods** (keyloggers), active **VPN** apps, and apps allowed to **install unknown apps**.

Public APIs exist for most of these (AccessibilityManager enabled-services list, enabled notification-listener packages, DevicePolicyManager active admins, default SMS package, InputMethodManager enabled list), mostly without special permissions. *To verify on device:* exact data available under package visibility, and which checks need QUERY_ALL_PACKAGES (avoid it). Show a "Who can control or read this phone" screen, a daily or on-open diff ("NEW: app X can now read your screen and tap for you"), and a one-tap deep link to the system page where the person can switch it off. Aegis must not and cannot revoke these itself; it makes them visible. **This is the single most valuable addition** and is something competitors' anti-scam features rarely show clearly.

### 2. Turn the firewall from advice into enforcement where Android allows
2.1 **Capability broker for integrated agents:** instead of "may I send?", the agent asks Aegis to *do* the action: Aegis composes the share/email/SMS intent or HTTP request itself from the approved payload, so what was approved is exactly what happens. The agent never holds the credential or performs the send. Start with "share text to app X" and "open URL" (no new permissions).
2.2 **Hash-bound redemption already exists:** extend it so redemption returns a short-lived signed token the receiving service (your own backend or an MCP gateway) can verify, so a server can refuse un-approved agent calls.
2.3 **Reference client SDK** (Kotlin) that computes provenance by taint tracking in the harness, not by the model, plus a sample assistant app. Without at least one real integration the firewall is untestable.

### 3. Detect rogue behaviour you cannot prevent
3.1 **Canary tokens:** plant decoy data (a fake contact with an email at a unique Aegis canary domain, an optional decoy "password" note). If anything ever resolves that canary domain, the DNS filter sees it: strong evidence that something read private data and tried to use it. Very low false-positive rate; uses the DNS filter Aegis already has.
3.2 **Per-app DNS anomaly view is not possible** (Android resolves DNS on apps' behalf), but Aegis can flag lookups of newly registered or never-seen domains right after a canary trigger or right after a new Accessibility service appears.
3.3 **Agent activity summary:** for integrated agents, persistent per-agent counters (requests, denials, data volume, destinations) with an "unusual today" alert.

### 4. Harden what exists
- Persist pending approvals and the audit log (encrypted, app-private), and anchor the log hash daily in a notification or export so tampering is noticeable.
- Pairing dialog: app label and icon, installer (Play / sideloaded), and the item-1 capabilities that app holds ("this app can also read your screen"): refuse pairing by default if it holds Accessibility plus overlay.
- Rate limits on data volume per agent, not only requests per minute.
- Injection scanning: add a "content check before giving it to your assistant" share target, so a person can screen a web page or email for injection text before an agent reads it.
- Kill switch: one button that unpairs all agents, revokes grants, and opens the system pages for any Accessibility/notification access found.

### 5. Product framing
Rename the promise from "AI firewall" to something true: "**See and control which apps can act for you**", with the cooperative-agent firewall as one part. Document the threat model in the app: what is caught, what is only made visible, what cannot be stopped.

## Suggested order
1. Capability watch screen and change alerts (item 1). Biggest protection gain, no agent cooperation, few or no new permissions.
2. Canary tokens with DNS-based tripwire (3.1).
3. Persistent approvals/audit, better pairing dialog, kill switch (item 4).
4. Capability broker + reference SDK + sample agent (item 2).
All of these need device testing; items 1 and 3.1 can be host-tested in their core logic (diffing, canary matching) like the rest of `core`.
