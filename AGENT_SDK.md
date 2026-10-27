# Aegis agent SDK, capability broker and sample agent (preview)

**Status: protocol, provenance tracking and broker logic host-tested (BrokerTests, AgentSdkTests). The Android client, the broker inside Aegis and the sample agent compile and pass lint but have never run on a device, and no real AI assistant uses them yet.**

## Why
Aegis' agent firewall is voluntary and was advice-only: an agent asked "may I?", got an answer, then acted by itself. Two weaknesses followed (REVIEW_AGENT_SHIELD.md): nothing made the agent do exactly what was approved, and the provenance label that decides between "refuse" and "ask" was chosen by the agent, so a hijacked model could simply claim the user asked. This release adds:

1. **Capability broker:** for actions Aegis can perform, the agent asks Aegis to *do* them. Aegis checks the request, and once it is allowed or the person approves, Aegis starts the action itself from the content it holds. The agent never receives an approval it could reuse.
2. **Reference SDK:** a small library for agent apps: the wire protocol, a Messenger client, and **harness-side provenance tracking** so the label comes from code, not from the model.
3. **Sample agent:** a demo app (no AI model) that exercises all of it.

## Modules
| Module | What | Tested |
|---|---|---|
| `agent-sdk` (pure Java 17, no dependencies) | `AegisProtocol` (message codes and keys, shared with Aegis' gateway), `ActionSpec` (an action and its fingerprint), `TaintTracker` (provenance) | `AgentSdkTests`, 33 checks, incl. agreement with Aegis' own enums and an end-to-end policy check |
| `agent-sdk-android` (Android library) | `AegisClient`: finds Aegis (release, then debug package), binds the gateway, request ids, timeouts, `evaluate`, `redeem`, `broker`, `launch`, `onBrokerDone`. Adds the needed `<queries>` entry | compiles and lints; never run on a device |
| `sample-agent` (app `com.aegis.sampleagent`) | Demo harness | compiles and lints; never run on a device |
| `core` `CapabilityBroker` | Action validation, request mapping, single-use tickets | `BrokerTests` |

## Capability broker
Actions (no new permission for Aegis or the agent):
- `OPEN_URL`: Aegis opens the link in the browser. Only `https`, printable ASCII (look-alike Unicode must come as punycode), no `user:password@`, port 443 only, at most 2,048 characters. Aegis' own link check runs first: anything it rates *suspicious* or worse is refused (`LINK_CHECK_*`).
- `SHARE_TEXT`: Aegis opens Android's share menu with the text (at most 10,000 characters); the person picks the app. There is no known destination, so it is always asked about.

Both go through the firewall as `SEND_DATA` (a link carries its query string to the site), so secrets, personal data and injection wording are checked as for any outbound data.

Flow:
- **DENY:** nothing happens; the agent gets reason codes.
- **ALLOW** (for example a link to a host the person trusts, with nothing flagged): the agent receives a one-shot, immutable launcher (`PendingIntent`) bound to a ticket that Aegis holds for 60 seconds. The agent starts it from its own visible screen (`AegisClient.launch`). Aegis' invisible, non-exported `BrokerActivity` takes the ticket, re-checks the kill switch and that the agent is still paired, and starts the action from the ticket's content. The agent cannot change what the launcher does.
- **ASK_USER:** the request appears in Aegis' approval dialog, which says that Aegis will do it itself and shows the exact link or text. "Approve and open" / "Approve and share" makes Aegis carry it out right then, while Aegis is on screen. The agent learns the outcome through `MSG_BROKER_DONE` (`performed`, `reason`: `DENIED_BY_USER`, `EXPIRED`, `NO_APP_TO_HANDLE`, `KILL_SWITCH_ON`, `AGENT_REMOVED` ...).

Brokered approvals are marked in the firewall: an agent trying to `redeem` one for its own use is refused (`BROKERED_ACTION`), and Aegis' broker cannot use an ordinary approval (`NOT_A_BROKERED_APPROVAL`). Tickets live only in memory (at most 20, at most 5 minutes); brokered approvals are therefore not saved across restarts. The audit log records `BROKER_PERFORMED` / `BROKER_FAILED` with host and reason only.

## Provenance: computed by the harness
`TaintTracker` is fed by the agent's harness code wherever content enters the model's context:

```java
TaintTracker t = new TaintTracker();
t.userMessage();            // the person typed or said something
t.externalContent();        // web page, email, file, search result, tool output
t.agentMessage();           // another AI agent
t.memoryRecall(savedLabel); // a memory saved earlier with t.labelForNewMemory()
Label p = t.provenanceFor(action);  // send this to Aegis
t.clearContext();           // new conversation
```

Rule: **context-level taint.** Once anything not written by the person is in the context, every proposed action gets the least-trusted label present (`EXTERNAL_CONTENT` > `AGENT_TO_AGENT`; `UNKNOWN` is worst), because nobody can tell which part of the context the model followed. Labels never go down within a context. An empty context gives `UNKNOWN`. Memories keep the label they were written under, so a poisoned memory stays tainted when it is recalled later.

The only way to get a user label back without clearing the context is **plan confirmation**: the harness shows the person the exact action (kind, destination, content) and they confirm. Then `confirmPlan` lets that exact action, matched by SHA-256 fingerprint, be sent once as `USER_CONFIRMED_PLAN` within at most 10 minutes. Any change to destination or content makes it a different action.

This is deliberately conservative. Aegis will ask more often for assistants that read the web, which is the intended trade. It is only as good as the harness: a harness that does not report a web page to the tracker produces wrong labels. It does not attribute *which* content influenced an output.

## Integrating (Kotlin)
```kotlin
val aegis = AegisClient(context).apply { onBrokerDone = { d -> /* d.performed, d.reason */ } }
if (!aegis.connect()) return            // Aegis not installed
val spec = ActionSpec.openUrl(url)
val r = aegis.broker(spec, "Open the article you asked for", tracker.provenanceFor(spec))
when (r.verdict) {
    "ALLOW" -> aegis.launch(activity, r.launch!!)
    "ASK_USER" -> showWaitingForAegis()    // Aegis does it after approval
    "NOT_PAIRED" -> askPersonToOpenAegis() // first contact: the person pairs the app in Aegis
    else -> giveUp(r.reasons)
}
```
For actions Aegis cannot perform, use `evaluate` and, after approval, `redeem(approvalId)`. The client repeats the identical request, because Aegis binds approvals to it.

Depend on `:agent-sdk-android` (in this repository) or copy the two modules; there is no published artifact.

## Sample agent
Install the debug APK of Aegis and `AegisSampleAgent-...-debug-TEST-ONLY.apk`, then:
1. Tap **Connect**, then **Ask Aegis to open the link**. You get `NOT_PAIRED`; open Aegis and pair "Aegis Sample Agent" (the pairing dialog shows its details).
2. Tap **Your message**, then ask Aegis to open the link. Provenance is `USER_DIRECT`; Aegis asks you, because `example.org` is not trusted. Approve in Aegis and Aegis opens it. Add `example.org` as a trusted destination in Aegis and try again: the sample receives a launcher and the page opens without asking.
3. Tap **Read a web page** (simulated, with injection text), then **Ask Aegis before sending**. Provenance becomes `EXTERNAL_CONTENT`, and Aegis refuses outbound personal data and asks about the rest.
4. Tick **Show me each action first**: the confirmed action goes out as `USER_CONFIRMED_PLAN`.

The demo never sends data anywhere itself. Its "send" path only shows what Aegis decided.

## Limits
- Nothing here has run on a device, including binding, package visibility, `PendingIntent` launch rules on Android 14+ (the client passes `MODE_BACKGROUND_ACTIVITY_START_ALLOWED`) and the broker's activity starts.
- Only two brokered actions. Sending email, SMS, HTTP requests or files through Aegis would need more design, and for some actions new permissions; not done.
- An opened link can still lead somewhere else after the first page (redirects, page scripts). Aegis checks only the link it is given.
- The broker only helps with agents that use it. An agent with its own network access or Accessibility can still act directly; Aegis' capability watch, tripwires and kill switch are the answer there.
- Signed approval tokens for servers were added in 0.8.0 (APPROVAL_TOKENS.md): `Result.token` and `redeem()` returning `Redeemed(granted, token)`.
