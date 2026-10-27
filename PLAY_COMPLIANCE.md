# Google Play compliance review (self-assessment)

Written from the developer's knowledge of Play policy as of this session; **policy details change and were not re-verified online here.** Re-check each row in Play Console / the current Developer Policy Center before submitting. Status: ✅ done and verified · 🟡 done but unverified · ❌ not done.

| Area | Requirement (as understood) | Status |
|---|---|---|
| Target API | New apps/updates must target a recent API level (36 expected by late 2026) | ✅ `targetSdk = 36`, compiles and lints clean; behaviour changes for 36 not tested on a device |
| 16 KB page size | Native libs must support 16 KB pages (apps targeting Android 15+) | ✅ `tools/check_release_apk.py`: both ABIs `p_align=16384`, `zipalign -P 16` passes |
| App bundle | Play requires AAB for new apps | ❌ only APKs built; run `bundleRelease` and test (not done) |
| Signing | Enrol in Play App Signing; keep an upload key offline | ❌ no production key exists (by design); see RELEASE_CHECKLIST.md |
| VpnService | VPN apps must have VPN as core functionality, declare it in Play Console, give a prominent in-app disclosure before enabling, not collect device/user data beyond what is needed, and not manipulate traffic for ads/monetisation | 🟡 DNS-only design, no data leaves; in-app disclosure dialog before consent added; Console declaration ❌; **service never run on a device** |
| Foreground service type | `systemExempted` needs a Play Console declaration and is only valid for qualifying uses (VPN apps are listed) | 🟡 declared; lint flags it; must be proven on devices |
| Package visibility | A `<queries>` block for six intent actions (accessibility, notification listener, input method, device admin, SMS deliver, VPN service) so the app-powers list can show app names; no `QUERY_ALL_PACKAGES` | 🟡 declared; Play's package-visibility policy should be checked for this use (core purpose: security) |
| Sensitive permissions | No SMS, call log, accessibility, `QUERY_ALL_PACKAGES`, `MANAGE_EXTERNAL_STORAGE`, location | ✅ none requested (checked by `check_privacy.py`) |
| Data safety form | Accurate declaration of collection/sharing | 🟡 developer collects nothing; whether forwarding DNS to the user's own resolver counts as "sharing" needs a decision with counsel |
| Privacy policy | Public URL, consistent with the app | 🟡 draft in PRIVACY_POLICY.md; needs legal review and hosting |
| Deceptive claims | Security apps may not overstate protection | 🟡 in-app and listing texts avoid guarantees; review again before each release |
| Malware/unwanted software | App must not be or enable harmful behaviour | ✅ no hidden behaviour; open question: the APK-inspection feature only reads files the user selects |
| Intent/exported components | Exported components need protection | 🟡 VPN service guarded by `BIND_VPN_SERVICE`; agent gateway open to bind but authenticates every caller (never run on a device) |
| Backup | Sensitive state excluded | ✅ `allowBackup=false` and data-extraction rules exclude everything |
| Target audience / content rating | Questionnaire; not directed to children | ❌ to be completed in Console |
| Developer account | Verified identity; testing requirements for new personal accounts (closed test with testers over a period, per policy at the time of writing) | ❌ not applicable yet |
| Android developer verification | Google has announced developer verification for apps on certified devices, phased in from 2026 | ❌ not checked; confirm current rollout and requirements |
| Accessibility | Not a Play requirement, but quality expectation | 🟡 see ACCESSIBILITY.md |
| Localisation | Store listing in EN and NO | 🟡 drafted in STORE_LISTING.md |

## Verdict
Not submittable. Blocking items: device testing of every feature (especially VPN and foreground-service behaviour), production signing key and Play App Signing, Console declarations, legal review of the privacy policy, store graphics, and an independent security review.

## Visual assets (update)
Adaptive launcher icon with monochrome layer is in place; `store-assets/play-icon-512.png` exists. The 1024x500 feature graphic is a draft. Phone screenshots are still missing (need a device). No trademarked marks are used; the shield-with-lens mark has not been checked against existing trademarks.
