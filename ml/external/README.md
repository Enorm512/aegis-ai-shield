# External training data (third-party, CC BY 4.0)

Downloaded 2026-10-27. Used for experiments only; **not** used by the shipped model (see AI_EVALUATION.md, "External-data experiment").

| File | Source | Licence | SHA-256 |
|---|---|---|---|
| raw/mendeley/Dataset_5971.csv | Sandhya Mishra and Devpriya Soni, "SMS Phishing Dataset for Machine Learning and Pattern Recognition", Mendeley Data, V1, doi:10.17632/f45bkkt8pr.1 (zip SHA-256 9bbf3188...b233cc3 matched the value Mendeley publishes) | CC BY 4.0 | 649844f1c62a6b27e145eaf17a65f7010c56c390e11a794ea8329993a05ba71e |
| raw/uci/SMSSpamCollection, raw/uci/readme | Tiago A. Almeida and José María Gómez Hidalgo, "SMS Spam Collection", UCI Machine Learning Repository, doi:10.24432/C5CC84 | CC BY 4.0 (UCI page); readme: free use, copyright retained by the authors, cite their paper | 7d039a24a6083ed9ef0f806ebad56bbb976e3aeb8de05669173bfdc4996c239d |

Processed with `DatasetImporter` (smishing -> 1, ham -> 0, spam skipped):
- processed/mendeley.txt: 5,279 messages (452 scam, 4,827 ordinary) after removing 202 duplicates.
- processed/uci-ham.txt: 4,501 ordinary messages after removing 321 duplicates.
- processed/train-combined.txt: project train.txt + both, de-duplicated across sets: 5,550 (518 scam, 5,032 ordinary), 0 label conflicts, no overlap with the locked evaluation sets.
- processed/candidate_model_2026-10-27_NOT_SHIPPED.txt and candidate_model_weighted_2026-10-27_NOT_SHIPPED.txt: the unweighted and class-balanced models trained on it. Both failed the acceptance rule and are kept only for reproducibility.

Some Mendeley messages contain U+FFFD replacement characters already present in the published file. All messages are English and mostly 2010s Singapore/UK/India SMS. If any of this data is ever used in a shipped model, add the attributions above to the app's licence screen.
