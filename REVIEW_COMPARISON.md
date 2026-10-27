# Spot test and comparison with similar apps (0.7.4-rc5, 2026-10-27)

**What this is:** a small spot test of the host-side engine on 30 fresh inputs, plus a qualitative comparison with similar apps based on a few web searches (vendor pages and forum posts, so treat them as claims, not measurements). **Nothing here was run on a phone, and no competitor app was run at all.** No detection-rate comparison with other products exists.

## Spot test (host engine, same result path as the app)
Inputs written for this test and not used to tune the rules. Set: `spot.txt` logic reproduced below.

| Group | Result |
|---|---|
| 12 benign links/messages (dnb.no, vipps.no, posten.no, GitHub, NRK, coffee invite, dentist reminder, own-bank payment notice, login code...) | 0 flagged (0/12 false positives) |
| 9 bad links | 7 flagged, 2 missed |
| 8 bad messages (EN/NO: customs fee, "new phone" family scam, account limited, prize fee, BankID request, unpaid power bill, fake IRS gift cards, crypto signals) | 3 flagged, 5 missed |

Small samples: 95% intervals are very wide (messages 3/8 is roughly 14-69%). The numbers show where the weak spots are, not a detection rate.

**Missed links**
- `dnb-sikkerhet-verifiser.com/login`: the brand check noticed "dnb" outside its domain, but the app level stayed CLEAR (short brand name without a phishy English word; Norwegian words like *sikkerhet*, *verifiser* are not in the list). A clear-cut Norwegian phishing pattern.
- `xn--vipps-9ra.no` (an accented look-alike of vipps): only an "internationalized host" note, level CLEAR.
- `posten-pakke-toll.top/betal`: nothing fires (no brand match for Posten, no use of the suspicious-TLD signal).

**Missed messages:** the Norwegian customs-fee text, the "hi mum, new phone" money request, the unpaid-bill utility scam, the fake-IRS gift-card text, and the investment-group lure. These are common Norwegian and English scam types; the rules know too few phrasings. (The classifier, off by default, would catch more, at roughly 6% false positives on the reviewer set.)

## After the fixes (0.7.5-rc6)
Norwegian phishing words, accent-folded brand look-alikes, an abuse-heavy-TLD weight (adds 1 point, never flags alone), brands bring/postnord/dhl, glued brand+word hosts (appleid), and five new message rules (parcel fee, family impersonation, gift-card demand, investment lure, unpaid-bill threats, authority-plus-payment threats).
- The original 29 spot inputs: all 17 bad ones now flagged, 0/12 benign flagged. **This is not a fair test any more** because the rules were tuned on it.
- A second fresh set of 36 (21 benign, 15 bad) written afterwards: first run 12 of 15 bad caught, 0 of 21 benign flagged; I then fixed the three misses (appleid-style hosts, a missing brand, compound fee words), so that set is tuned too. Both sets are kept as regression tests (`ml/data/spot-set.txt`, `SpotTests`), not as evidence of detection rates.
- Independent check: on the held-out reviewer set the rules went from 3/41 to 4/41 scams with 0/54 false positives. Honest reading: the message rules still generalise poorly; each new rule covers a known pattern.

## How it compares (qualitative)
| Capability | Aegis AI Shield | Typical commercial mobile security / scam checkers (Malwarebytes, Bitdefender, Norton, Scamio...) | Local-VPN DNS blockers (Blokada, RethinkDNS) / NextDNS | Google built-ins (Play Protect, Pixel/Messages scam detection) |
|---|---|---|---|---|
| Scam text check | Local rules, EN/NO, weak recall; experimental local classifier | Vendor cloud/AI services; Malwarebytes and Bitdefender both advertise message/link checking. Quality unmeasured here | none | On-device AI scam detection exists on supported Pixel/Messages setups (Google describes it as on-device, opt-in, limited regions/devices) |
| Link check | Offline: URL structure, 21 brands, look-alikes, signed domain list (empty: no feed exists) | Reputation databases updated continuously: a large advantage over an empty offline list | Block lists maintained by community or vendor | Safe Browsing in Chrome/Play Protect |
| Known-malware detection | None beyond hash/signer lookup in the (empty) signed feed and manifest capability analysis | Signature + behavioural engines, cloud lookups | none | Play Protect scans installed apps, including after install |
| DNS filtering | Consented DNS-only VPN, two /32 routes, local decisions, no logs; never run on a device | NextDNS-style or built-in web protection (vendor-specific) | This is their core feature, mature, community tested; known limits: one VPN slot, no per-app attribution, Private DNS conflicts | Private DNS setting only |
| Privacy | No analytics, no accounts, no cloud lookup; offline by design | Cloud lookups send links/messages to the vendor (varies; read each policy) | Local (Blokada/Rethink) or provider-side (NextDNS) | Mostly on-device AI, some cloud |
| Unique feature | Voluntary AI-agent action firewall (policy engine, approvals) | none known | none | none known |
| Maturity | 0 devices, 0 users, no production feed, no independent review | Years of field data, large threat-intel teams, independent lab tests (e.g. AV-Comparatives mobile reviews) | Years of field use | Platform-level |

## Honest assessment
- **Where Aegis is differentiated:** local-only and privacy-first design; no account or network need for checks; honest result language (never "safe"); the AI-agent firewall idea, which none of the other categories offer; open, testable code with a documented threat model.
- **Where it is clearly behind:** threat intelligence (there is no feed, so link and file reputation, the main thing commercial products sell, is absent), scam-text recall on unseen wording, no device validation, no independent review, no QR/OCR/redirect resolution, no call or SMS integration.
- **Realistic position today:** a careful prototype of a privacy-first checker, not a replacement for Play Protect plus a maintained DNS filter. As a *second opinion* tool it is plausible; as a main defence it is not. Its value rises sharply only after (1) a real signed threat feed and (2) device testing.
- **Cheap improvements the spot test points to:** Norwegian phishing words in the look-alike list (sikkerhet, verifiser, bekreft, innlogging, betal, toll, pakke), flagging accented look-alikes of known brands, use of suspicious-TLD signals, and more Norwegian scam phrasings (customs/parcel fee, family-impersonation money requests, utility-bill threats).

## Sources consulted (searches on 2026-10-27; vendor-run or forum material)
- Malwarebytes comparison pages (vendor): https://www.malwarebytes.com/solutions/best-mobile-security-apps-software , https://www.malwarebytes.com/solutions/best-scam-detection-tools
- RethinkDNS / Blokada / NextDNS discussions: https://discuss.techlore.tech/t/what-are-your-opinions-on-rethinkdns/5471 , https://www.bgr.com/2154382/block-malicious-ads-dns-service-android/
- Google on-device scam detection and Play Protect live threat detection (2024-25 coverage): https://thehackernews.com/2025/05/google-rolls-out-on-device-ai.html , https://www.helpnetsecurity.com/2024/11/14/android-scam-detection/
- No source gave comparable detection rates; no Norton Genie result was found.
