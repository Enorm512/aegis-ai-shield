# External data sources: what could close the gap, and what we may use

Researched 2026-10-27 from the providers' own pages where possible. **Licence notes are a developer's reading, not legal advice; get a licence review before shipping any third-party data.** Update 2026-10-27: the Mishra and Soni and UCI datasets were downloaded into `ml/external/` and tried; adding them made the classifier worse on the locked reviewer set, so the shipped model does not use them (AI_EVALUATION.md).

## Threat-feed (domain) sources
| Source | Licence / terms (as read) | Verdict for Aegis |
|---|---|---|
| Phishing.Database (github.com/Phishing-Database/Phishing.Database) | MIT (GitHub licence metadata) | **Candidate.** Attribution required. It aggregates other feeds, so check its own sources' terms and expect false positives; FeedBuilder drops protected/allowlisted names. |
| The Block List Project (github.com/blocklistproject/Lists) phishing/scam/malware lists | Unlicense (GitHub metadata) | **Candidate.** Broad lists, likely noisy: start at SUSPICIOUS confidence. |
| Maltrail static trails (github.com/stamparm/maltrail) | MIT (GitHub metadata) | **Candidate** for malware infrastructure domains; check the per-trail origin notes. |
| HaGeZi DNS blocklists | GPL-3.0 | **Not without review**: copyleft terms on bundled data are unclear. |
| OpenPhish | Terms forbid commercial use and redistribution without written consent | **No** (unless licensed). |
| abuse.ch URLhaus / MalwareBazaar / ThreatFox | Commercial use may need a paid Spamhaus subscription; AI training needs prior written consent; copying the platforms needs consent | **No** without a Spamhaus agreement. (Feodo Tracker / SSL Blacklist are stated as CC0 but are botnet-C2 data, little use for phishing.) |
| PhishTank (Cisco) | Free feed with registration; terms are Cisco's EULA, not reviewed | **Not without review.** |
| phishunt.io | Says CC0 for its outputs, but ingests OpenPhish/PhishTank, whose terms may not flow through | **Not without review.** |
| Norwegian sources (NSM, Nkom, Økokrim, banks, Posten) | None found as open data | **Best long-term option:** ask for a data-sharing agreement; a Norwegian scam-domain list would be the clearest edge over global vendors. |

## Message (SMS) training and evaluation data
| Dataset | Size and labels | Licence | Verdict |
|---|---|---|---|
| Mishra and Soni, "SMS Phishing Dataset for Machine Learning and Pattern Recognition", Mendeley Data, doi 10.17632/f45bkkt8pr.1 | 5,971 English SMS: 4,844 ham, 489 spam, 638 smishing | CC BY 4.0 (Mendeley page) | **Best candidate.** Real smishing labels. Import with `DatasetImporter csv` (spam skipped by default). |
| UCI SMS Spam Collection (Almeida and Hidalgo), archive.ics.uci.edu/dataset/228 | 5,574 English SMS: ham / spam | CC BY 4.0 (UCI page) | **Useful for ordinary messages (ham)** as negatives; its "spam" is mostly marketing, not scams, so it is skipped by default. |
| Smishtank dataset (smishtank.com, arXiv 2402.18430) | 1,062 smishing messages | No dataset licence found (CC BY-NC-SA shown is the paper's) | **Not without permission.** |
| NCSU SMS gateway study (~68k phishing messages) | Research data | Availability unclear | **Ask the authors.** |
| Norwegian scam SMS | No public dataset found | - | **Must be collected**: opt-in reports from users, or a partnership with a Norwegian bank, telco or authority. Translations of English data are a stopgap only and leak across splits (see AI_EVALUATION.md). |

## Tooling added (this project)
- `FeedBuilder` (core, publisher tool, no network): reads a manifest of local list files with declared licences, refuses licences that are not on its allowed list, accepts plain/hosts/adblock/URL formats, drops IPs, wildcards, public suffixes, protected domains (banks, government, platforms, connectivity checks) and an optional allowlist, merges duplicates keeping the strongest listing, caps size (strongest first) and writes entries plus an attribution file with input checksums. Output signs with `ThreatBundleTool sign` and loads in the app (round-trip tested). Example manifest: `tools/feed-sources.example.txt`.
- `DatasetImporter` (developer tool): converts the UCI and Mendeley formats to `label|lang|text`, de-duplicates, writes a provenance note.
- Leakage guard: `ml/data/LOCKED` lists evaluation files; `ModelTrainer` refuses to train when a training message also occurs (after normalisation) in the test file or a locked file. `DataToolsTests` (46 checks) also verifies the shipped training data does not overlap the locked sets.

## Suggested next steps
1. Read the Mendeley and UCI licence pages yourself, download both (each well under 1 MB), import them, retrain, and re-run `ModelEval`. Keep `reviewer-novel.txt` locked as the independent test.
2. Pick one or two MIT/Unlicense domain lists, run FeedBuilder at SUSPICIOUS confidence, inspect the drop counts and a sample of entries for false positives, then sign with a **new production key** (none exists yet) and ship the public key in the app.
3. Start a Norwegian data effort (opt-in reporting in the app, outreach to Nkom/NSM/banks): this is where a small local app can be better than global competitors.
