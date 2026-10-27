# Stage 3 — on-device AI evaluation

## What was built
`TextNormalizer` → `TextClassifier` (hashed word, bigram and character-trigram features, logistic regression, 65,536 buckets) → `MessageAi` (hybrid with the rule-based `ScamAnalyzer`). Pure Java, no new dependencies, no I/O, no network. The model is a 66 KB text file (`ml/model/message_model.txt`, bundled as an asset) with an integrity checksum. It is **not signed**: a signature is required before models can ever be downloaded.

Hybrid rules: the model can raise a message to SUSPICIOUS at most, never lowers a verdict, never confirms, and a low score produces no statement. It is OFF by default (Message tab switch).

## Technology evaluation (design analysis, not measured here)
| Option | Decision |
|---|---|
| Hashed linear model (built) | Deterministic, ~66 KB, no dependency, works on every supported Android version, explainable (per-term contributions). Weak on paraphrase and long, padded text. |
| LiteRT | Appropriate once a validated dataset justifies a neural model. Needs a new dependency plus licence/model-provenance review. Not integrated. |
| ML Kit | Its on-device APIs (e.g. language ID, entity extraction) are not scam classifiers; no fit identified yet. Not integrated. |
| Gemini Nano / AICore | Availability depends on device, OS and region; generative output must not decide verdicts. Possible later for optional plain-language explanations only. Not integrated. |

## Data and results (read the caveats)
Training data: 136 messages and test data: 50 messages, **all written by the developer of this prototype** (English and Norwegian, `ml/data/`). No real-world messages, no independent labelling, no population sampling. The test file was used only for reporting; the decision threshold came from 5-fold cross-validation on the training file.

Observed with `ModelTrainer` (threshold 0.825):

| Set | n | scam recall | false-positive rate |
|---|---|---|---|
| Cross-validation, train only | 136 | 32/66 | 1/70 |
| Held-out test (all) | 50 | 9/25 = 36% | 1/25 = 4% |
| Held-out test, English | 24 | 4/12 | 1/12 |
| Held-out test, Norwegian | 26 | 5/13 | 0/13 |
| Train (resubstitution, optimistic) | 136 | 66/66 | 0/70 |

These are small-sample figures with wide uncertainty. They show the pipeline works and the model is weak: it misses roughly two thirds of unseen scam wording. **They must not be quoted as detection rates.** Real evaluation needs a large, independently labelled corpus of real messages.

## Rules vs classifier vs hybrid (0.7.3-rc4, `ModelEval`)
Output of `ModelEval` (Wilson 95% intervals). "Flagged" = SUSPICIOUS or stronger. The reviewer set (41 scams, 54 ordinary, written by the AI-engineer reviewer instance) was not used for training or for choosing the threshold; the 25-scam developer test set was written by the developers and has been looked at while tuning. These are tiny samples and must not be quoted as detection rates.

| Set | Rules only (default product) | Classifier alone | Hybrid (classifier off by default) |
|---|---|---|---|
| train (66 scam / 70 ordinary) | 21/66 recall, 0/70 FP | 66/66, 0/70 (memorised: not evidence) | 66/66, 0/70 |
| developer test (25 / 25) | 5/25 (20%, CI 9-39%), 0/25 FP | 9/25 (36%, CI 20-55%), 1/25 FP | 12/25 (48%, CI 30-67%), 1/25 FP |
| reviewer-novel (41 / 54) | 4/41 (10%, CI 4-23%), 0/54 FP | 23/41 (56%, CI 41-70%), 3/54 FP (6%, CI 2-15%) | 24/41 (59%, CI 43-72%), 3/54 FP |

These are the numbers after the 0.7.5-rc6 Norwegian rule additions (parcel-fee, family-impersonation, gift-card, investment-lure, unpaid-bill threats). On the held-out reviewer set the rules improved only from 3/41 to 4/41, so the new rules mostly help on message types the spot test covered, not on the reviewer's wording. A parcel-fee rule that first also flagged two genuine customs notices from that set (a false-positive jump from 0/54 to 2/54) was narrowed to require a link or time pressure.

Reading: out of the box (classifier off) the product catches very little unseen scam wording; the optional classifier roughly triples that on the held-out set at the price of about 6% of ordinary messages flagged as suspicious.

Caveats the reviewers raised and that still stand: the corpus has translation pairs, so cross-validation leaks between folds and must be grouped; about 13 independent scam templates sit behind the scam examples; the evaluation sets were written by the people who built the rules; padding evasion is only partly mitigated (windowed scoring); "text classifier" is the accurate name (it is a hashed logistic regression, not a language model). The earlier term-list explanation feature was removed because per-term contributions were misleading; the message result now says only that wording resembled known scam messages. The normaliser now folds look-alike letters after lowercasing and the scam rules run on the normalised text.

## External-data experiment (2026-10-27): NOT shipped
Question: does adding the public CC BY 4.0 datasets (Mishra and Soni smishing set, UCI SMS Spam Collection ham; see ml/external/README.md) improve the classifier?
Acceptance rule fixed **before** looking at results: ship only if classifier recall on the locked reviewer set rises and its false positives stay at or below 3/54.

Training data 136 -> 5,550 messages (518 scam, 5,032 ordinary); same features, trainer and threshold procedure (cross-validation on training data only); leakage guard passed.

| Classifier alone | Current model (136 msgs) | Candidate (5,550 msgs) |
|---|---|---|
| Reviewer set, all (41 scam / 54 ordinary) | 23/41 recall, 3/54 FP | 19/41 recall, 2/54 FP |
| Reviewer set, English (20 / 27) | 10/20, 0/27 | 4/20, 0/27 |
| Reviewer set, Norwegian (21 / 27) | 13/21, 3/27 | 15/21, 2/27 |
| Developer test (25 / 25) | 9/25, 1/25 | 5/25, 1/25 |
| Hybrid on reviewer set | 24/41, 3/54 | 20/41, 2/54 |

Result: **rejected** (recall fell). Model file also grew from 66 KB to 663 KB. Likely reasons: the public data is 2010s Singapore/UK/India SMS whose scams (premium-rate, prize texts) look little like modern bank, parcel and crypto scams; the 10:1 ordinary-to-scam ratio and a threshold picked for very low false positives make the model conservative. The small Norwegian gain is not significant. Lessons: public English corpora are not a shortcut for this product; recent, Norwegian, consented data is what is missing. Possible next experiments (each judged once on the locked set): using only the smishing rows plus the project's own ordinary messages, or per-language thresholds.

### Follow-up: class-balanced retrain (2026-10-27): NOT shipped
Procedure fixed before running: scam-example loss weight chosen from {1, 2, 4, 8, ordinary/scam ratio} by 5-fold cross-validation on the 5,550-message training file only (highest out-of-fold recall under the usual 2% false-positive threshold rule, ties to the smaller weight), then one judgement on the locked reviewer set with the same acceptance rule.

Cross-validation (training data only): weight 1 -> 415/518 recall, 2 -> 430, 4 -> 439, 8 -> 450, 9.71 -> 454 (out-of-fold false positives 1-2 of 5,032). Chosen: 9.71, threshold 0.80.

| Classifier alone | Current model | Unweighted candidate | Balanced candidate |
|---|---|---|---|
| Reviewer set, all | 23/41, 3/54 FP | 19/41, 2/54 | **30/41, 9/54** |
| Reviewer set, English | 10/20, 0/27 | 4/20, 0/27 | 10/20, 3/27 |
| Reviewer set, Norwegian | 13/21, 3/27 | 15/21, 2/27 | 20/21, 6/27 |
| Developer test | 9/25, 1/25 | 5/25, 1/25 | 12/25, 1/25 |

Result: **rejected**: false positives rose to 9/54 (17%, 95% CI 9-29%), above the 3/54 limit. Cross-validation promised about 0.04% false positives; the held-out set gave 17%. The old English corpus does not represent modern or Norwegian ordinary messages, so a threshold tuned on it does not transfer. This is the clearest evidence so far that representative ordinary messages, not just more scam examples, are what the classifier needs. No further variants were tried on the locked set, to keep it usable as an independent test. The trainer keeps the option (`--class-weight=auto`, off by default; with weight 1 it reproduces the shipped model byte for byte).

## Adversarial and privacy tests (AiTests, 7,219 checks)
Passing: zero-width characters, bidi/soft-hyphen, case, extra whitespace and Cyrillic/Greek homoglyph substitution leave the score exactly unchanged (the normaliser removes them); leetspeak and spaced-out letters are folded; prompt-injection text is only tokenised, cannot change code paths, and cannot lower a verdict; random-Unicode fuzzing never throws or yields a non-finite score; corrupted or hostile model files (bit flips, wrong bucket count, infinite weights with a valid checksum, oversized bias, unsafe names) are rejected; the classifier sources contain no I/O, network, logging or reflection references.

Measured weakness: appending ~25 harmless words made 9/9 flagged scams fall below the threshold with whole-text scoring; with 32-token window scoring, **5 of 9 still escape**. Paraphrase, other languages, and image/QR content are not handled at all. Rules are unaffected by padding, which is why the model is only a secondary signal.

## Performance
Host JVM (not a phone): about 40–50 µs per short message; model load measured on-device is shown in the app's Device tab. No battery or on-device latency testing has been done.
