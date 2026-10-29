# Known limitations — 0.8.5-rc16 (internal test build)

- **Never run on a real phone.** Since 0.8.2-rc13 the debug build runs instrumented tests on an Android 15 (API 35) x86_64 emulator in CI; see TEST_RESULTS.md for exactly what they cover. Still unverified: real phones and OEM skins (Samsung One UI etc.), other Android versions, battery and Doze, the release/R8 build at runtime, and every flow that needs a person in a system dialog (VPN consent, Contacts, share sheet, file picker). Older sections below that say "never run on a device" predate the emulator tests; where an emulator test now covers the behaviour, TEST_RESULTS.md says so.
- No production threat feed or signing key, no signed updater or reputation backend, no redirect fetching, global AI control, app inventory or permanent detection history. An experimental text classifier (off by default), a consented DNS-only VPN filter and a voluntary agent firewall exist but are unverified on devices.
- Review items fixed in 0.7.4-rc5 (host-tested or compiled, not device-tested): replayed older feed file refused at startup; upstream DNS sockets bound to the chosen network and only that network's resolvers used; overload answered with SERVFAIL; trusted-destinations UI; CI actions pinned to commit SHAs.
- Remaining items from the 2026-10-26 expert reviews that are **not fixed**: no TCP DNS service and DNS worker pool is shared (heavy bursts still lose queries); Private DNS (Automatic/strict) interplay and unencrypted passed-on lookups; always-on/lockdown VPN blackout behaviour; caller identification by package on API 30+ rests on documentation (bound callers are visible) and is unverified on a device; no signature-key rotation or compromise drill has been rehearsed; IDNA2003 vs UTS46 differences in host handling; dependency `verify-signatures=false` (checksums only) and no CVE scan; threat-feed floors are reset by clearing app data (inherent); rules-only recall on unseen scam wording is very low (3 of 41 in the reviewer's set) and classifier evaluation data is small, partly translation-paired and about 13 independent scam templates; padding evasion of the classifier is not truly fixed.
- URL parsing is conservative Java URI/IDN processing, not a browser-equivalent WHATWG/UTS46 implementation. Unsupported inputs yield insufficient evidence. Mixed-script checks are not comprehensive homograph detection; brand list is tiny and informational. Legitimate brand affiliates can be flagged. IDN/provider behavior needs Android regression tests.
- Scam rules are limited EN/NB patterns. Negation, quotations, unseen tactics, link obfuscation and complex romance/investment fraud can evade or falsely trigger them. They do not identify AI authorship.
- APK UI accepts at most100MiB, core guard128MiB; max10,000 entries, 64MiB per entry, 4MiB manifest, 256MiB actual total and compression-ratio limits. Large or unusually compressed benign APKs can be rejected. ZIP64, encrypted and split archives rejected. An archive passing checks is not proof of safe APK content.
- APK platform parser is in app process, not isolated. Reported signer fingerprints are not full independent v1/v2/v3/v4 signature validation or publisher trust. No class/code/behavioral malware analysis.
- A hostile document provider can block inside read() and delay cancellation despite byte and coroutine checks. Process death can leave private temporary files until next cold start. Cache deletion can fail; device testing required.
- UI localizes labels/explanations, but technical details/underlying parser evidence can remain English. No automated visual/TalkBack review yet.
- SDK35 baseline is not a current Play compliance assertion. No release key, signed production APK, legal review, fully resolved SBOM or independent security certification.

## Agent behaviour watch (0.8.5-rc16)
- The ratings come from fixed, untuned rules (2 calls or 3 AI lookups while locked; 8+ calls averaging under 4 s; 10+ calls with a coefficient of variation under 0.25). No false-positive or detection rate has been measured; scheduled agents the person set up themselves are rated "on its own" by design and need one "yes, that was me" per session.
- "Person present" means screen on and unlocked. An agent driving the phone through Accessibility while the person holds it, or a person using a computer that drives the phone, looks like the person.
- AI-API lookups cannot be tied to an app on Android, are hidden by DNS caching, and are not seen at all when an app uses its own encrypted DNS, a VPN other than Aegis runs, or DNS protection is off. Only programmatic API hosts are listed; agents behind other proxies or self-hosted models are invisible, and an ordinary app calling an AI API in the background can trigger the question.
- Agents that never call the Aegis gateway cannot be paused; for them Aegis can only ask and point at apps with screen control or notification access.
- History is in memory only (24 hours, 3,000 events) and is lost when Android stops the app; an answered "yes" applies to that session only.

## Screenshot and QR check (0.8.4-rc15)
- Tesseract with the fast models reads clean screenshots; photos of screens, small or stylised text, handwriting, low contrast and non-Latin scripts are read poorly or not at all. Only English and Norwegian models are shipped. Misread words can hide a warning sign or invent one; the text read is shown so the person can see it. No accuracy figure for text recognition on real screenshots exists.
- QR decoding covers QR codes only (no other barcodes) and can miss small, damaged, skewed or artistic codes. A QR code split across two screenshots is not read.
- Device-link detection knows the WhatsApp, Telegram, Signal and Discord formats as written in their public clients; formats change, and other services' sign-in QR codes are not recognised. Bare crypto addresses are matched by shape (Bitcoin, Ethereum, Tron) and can match other strings of that shape.
- Images, logos, fake sender names and the look of a fake page are not judged; only text and QR contents are. A clean result says nothing about the picture's source.
- OCR is stopped after 25 seconds; on slow phones a very long screenshot can time out and is then reported as "text could not be read". Speed and memory use have only been seen on the CI emulator.
- Tesseract4Android comes from JitPack, which builds from the project's GitHub source; checksums are pinned, but the build itself is not reproducible by us.

## Restart, feed pipeline, app watch and correlation (0.8.3-rc14)
- **Restart:** protection comes back after a reboot or app update only if the person had it on and Android still holds the VPN consent; this was checked with one real emulator reboot in CI, not on phones (OEM battery managers can delay or block boot broadcasts). Before the first unlock after a reboot (Direct Boot) protection is off: the receiver runs only after unlock. If another VPN took over, Aegis posts a notice and does not ask on its own.
- **Threat feed:** the build-and-sign pipeline (`tools/build_feed.sh`, `tools/feed-sources.txt`) and the bundled-seed loader exist and were exercised with the debug test key only. **No production key exists yet, so release builds still have no threat data.** The lists must be downloaded by hand after reading their terms; both start warn-only. A seed shipped in an APK expires after 30 days, so an old APK installs no data. No automatic download.
- **App watch:** sees only apps Android makes visible to Aegis without QUERY_ALL_PACKAGES (mainly apps offering accessibility, notification-listener, keyboard, device-admin, SMS or VPN services). Ordinary apps are invisible, so an app is noticed only once it offers or holds such a power. Checks run when Aegis is opened and every 30 minutes while DNS protection is on; changes are detected late, not at install time. A signer change can also be a legitimate developer key rotation.
- **Correlation:** five fixed rules over a 7-day local signal log; untuned thresholds, no false-positive measurement. DNS lookups cannot be tied to an app on Android, so lookup rules name candidates, never a culprit. Signals carry detection time, not the time of the grant or install. It only links what the other watches see, so it inherits all their blind spots.

## Stage 2 threat intelligence
- No production signing key and no threat feed exist. `trusted_threat_keys.txt` is empty, so the shipped app can accept no bundle and every lookup reports "database unavailable".
- No download/update transport and no import UI yet: the verifier/store are tested at library level only. Update scheduling (WorkManager) is not implemented.
- Online reputation providers (e.g. Safe Browsing) are only an interface; none is implemented and each would need a privacy and licence review.
- Message analysis does not yet look up embedded links in the database; only the single-URL and APK paths do.
- ECDSA P-256 chosen because Ed25519 is not in the JCA on Android 8-12. Key rotation/revocation beyond adding or removing anchors in an app release is not designed.
- Signer-certificate lookup uses the certificates Android's parser reports, which is not full APK signature verification.
- Benchmarks are JVM-on-host numbers only; no on-device or battery measurements yet.
- Import screen is compile-verified only; no UI test or device run. The debug build trusts a published test key, so a debug APK must never be used as a protection build.

- The 0.7.5-rc6 Norwegian rules were tuned on two small spot sets; on the independent reviewer set they added one catch (3/41 to 4/41). Message-rule recall on unseen wording remains low.

## App powers check (0.7.6-rc7)
- Never run on a device. What Android lets Aegis see is unverified: the Accessibility and keyboard lists come from public secure settings and should include hidden apps, but labels and the "came with the phone" flag need package visibility (the `<queries>` block); notification-listener and device-admin lists may depend on the Android version.
- The owner of another active VPN cannot be identified by a normal app; it is shown as "a VPN app".
- Not covered: apps allowed to install other apps, draw over other apps, or use usage access (these need per-app AppOps checks or broad package visibility); work-profile apps; root or ADB-granted powers.
- Background checks run only while DNS protection is on (no scheduler dependency was added); otherwise changes show when Aegis is opened. A removed grant silently updates the baseline.
- The risk rating is a fixed rule set (host-tested), not a measurement of how dangerous a given app is.

## Gateway flood resistance (0.8.1-rc12)
- A sustained flood of allowed requests (up to the 30/min rate limit) still rotates the 500-entry main log after roughly a quarter of an hour; the security log keeps pairings, the person's answers, the kill switch, log damage and rate-limit hits. Unknown agents share one denial budget beyond 64 distinct ids.
- Debounced saving means up to about 2 seconds of gateway events can be lost if the process dies; the person's own actions are saved at once.
- The per-UID message budget is held in memory and resets when the gateway process restarts. Never run on a device.

## Approval tokens for servers (0.8.0-rc11)
- Never run on a device: Keystore key creation and signing, key export, and token delivery to an agent are unverified.
- A token proves that Aegis on an enrolled phone allowed the call, not that the phone is uncompromised: code running as Aegis or with root could use the key. No Android key attestation.
- Needs a roughly correct phone clock (±30 s), a byte-identical request body, and a destination host. Enrolment is manual; revocation means replacing the key on the phone and removing the old one on the server.
- The reference replay cache is per process; clustered servers need a shared store.

## Capability broker, agent SDK and sample agent (0.7.9-rc10)
- Never run on a device: binding from another app, package visibility for finding Aegis, the one-shot launcher under Android 14+ background-start rules, the broker's activity starts, and the sample agent. No real AI assistant uses the SDK.
- Only two brokered actions (open an https link, open the share menu with text). An opened page can redirect or run scripts; only the link given is checked.
- Brokered actions waiting for approval are kept in memory only and are lost if Aegis is stopped.
- Provenance tracking is only as good as the harness that feeds it; it is context-level (conservative) and cannot tell which content influenced an output.
- An agent that does not use the broker, or that has its own network access or Accessibility, can still act directly.

## Agent log, pairing dialog and kill switch (0.7.8-rc9)
- Never run on a device: the Keystore-backed encrypted store, restoring approvals after the app is stopped, the pairing dialog's app details, and the kill switch are unverified on a phone.
- The audit log is tamper-evident, not tamper-proof: code running as Aegis (or root) could rewrite the whole log consistently. Only an earlier export or a noted fingerprint reveals that. There is no automatic daily anchor.
- If the Keystore key is lost (for example after restoring the app to another phone) the saved log reads as damaged and a new one starts; waiting approvals are lost.
- Install source and "draws over other apps" come from what Android reports: an app can be installed by a store-like package, and the overlay check only sees that the app *asks* for the permission, not whether it was granted.
- Hiding dialogs from accessibility apps needs Android 14+; on older versions, and against gesture injection at screen coordinates, an app with Accessibility can still tap Aegis' buttons. That is why such apps need an extra confirmation to pair and why approvals warn about them.
- The kill switch only stops agents that ask Aegis. It cannot stop an app that never integrated, and it cannot switch off Accessibility or notification access; it links to the system pages.

## Tripwires (0.7.7-rc8)
- Never run on a device: the Contacts insert screen, share sheet and document picker flows, and whether the self-test lookup from Aegis' own process reaches its DNS filter, are unverified.
- Detection only while DNS protection runs, and only for lookups made on this phone through its normal DNS. Not detected: data copied off the phone and used elsewhere (an attacker's server opening the link), apps with their own DNS-over-HTTPS or hard-coded resolvers, an attacker who reads the decoy and recognises it.
- The `.invalid` zone keeps tokens from leaking to anyone, but a careful attacker can spot it; a production version could use a registered zone the project controls (still answered locally).
- Decoys must be removed in their own apps by the person; Aegis cannot delete them. Opening the decoy link yourself triggers an alert (the UI says so).

## Stage 3 on-device AI
- The model is trained on 136 developer-written messages and weak (about one third recall on unseen wording); it is experimental, OFF by default, and only raises messages to "suspicious". No independently labelled data, no real-message evaluation.
- Bag-of-words scoring can be diluted by padding (5 of 9 flagged test scams still escape after appending harmless text), is blind to paraphrase beyond its vocabulary, and handles only English and Norwegian.
- Model file has a checksum, no signature; it ships inside the APK. Model updates must not be downloadable until signed like threat bundles.
- LiteRT, ML Kit and Gemini Nano/AICore are evaluated on paper only (AI_EVALUATION.md); no supported-device probing for them exists because none is integrated. No AI-generated explanations: explanations are per-term contributions from the linear model.
- Links in messages are scored by rules only; the model sees them as a single token.

## Stage 4 DNS protection
- Never run on a device or emulator. All Android-side behaviour (VpnService lifecycle, consent, foreground type, NetworkCallback resolver discovery, socket protection, Doze/battery, handover, captive portals, Private DNS, other VPNs, always-on VPN) is unverified. Not releasable until the device test plan in NETWORK_PROTECTION.md is executed.
- Name-based DNS blocking only; DoH/DoT in apps, hard-coded IPs, CNAME cloaking and answers over ~1232 bytes are not handled. No DoT/DoH upstream, no connection monitoring beyond DNS, no persistent security log (by design, memory only).
- The debug build still trusts the published test key (see Stage 2 notes); only matters if the DNS service is run with the sample bundles.
- Lint warnings remain (outdated dependency versions, targetSdk 35 vs 36, allowBackup/dataExtractionRules note). Instrumentation tests are still not run.

## Stage 5 advanced security
- Manifest analysis reads declared capabilities only. No dex/native code analysis, no certificate or signing-scheme verification, no behavioural analysis. No labelled malware corpus exists here, so detection rate is unmeasured; the only samples are synthetic manifests.
- Look-alike detection covers a fixed list of 21 brands, only second-level labels, and a partial two-level suffix list. It is bypassable by any brand not on the list and flags some legitimate near-names.
- QR codes and text in pictures are read since 0.8.4-rc15 (see that section); there is still no image analysis beyond that, no live redirect following and no message-attachment scanning.
- The agent firewall is voluntary and trusts the caller's provenance claim; approvals and the audit log are now saved encrypted (0.7.8) but the log is not externally anchored; only two actions can be brokered (0.7.9); the gateway is unverified on a device, including whether Android lets it resolve binder callers' packages on API 30+. Injection and secret detection are heuristic and bypassable by paraphrase or encoding.
- Future-threat items not addressed: AI memory poisoning, malicious AI plugins/tool manifests, multi-step attacks across sessions.

## Stage 6
- The release build has never been run. R8 shrinks the app from 10 MB to ~1 MB, so a missing-class or reflection problem could only appear at runtime.
- The `systemExempted` foreground-service type is suppressed in lint on the strength of Android's documentation that lists VPN apps as qualifying; unproven on devices.
- Dependency checksum pinning stops silent artifact changes but is not a vulnerability scan. No licence review of dependencies has been done by a lawyer.
- The privacy policy and store text are drafts. No store graphics or screenshots exist.
- The "independent review" was a separate AI reviewer instance, not a human third party.

## UX redesign
- Never seen rendered. Navigation icons are hand-drawn paths and may need tuning; glyphs ("✕", "!", "?", "i") depend on font coverage.
- Home status says "Nothing needs your attention" only about what Aegis knows; it deliberately does not claim the phone is protected.
- Link/message auto-detection is a heuristic (a bare "file.pdf" is treated as a link); the person can override it.
- Next-step advice is general guidance written by the developers (bank contact via official channels, report to the impersonated company, politi.no in Norway); it has not been reviewed by a fraud expert or checked with the authorities.
- Agent notifications need the notification permission and show only generic text.
