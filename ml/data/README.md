# ml/data

- train.txt / test.txt: written by the project developer (AI-assisted, partly EN/NO translation pairs of each other; see AI_EVALUATION.md for why this limits what the numbers mean).
- reviewer-novel.txt: 95 messages (41 scam, 54 ordinary, EN+NO) written by the independent AI-engineer reviewer instance, not used for training or threshold choice. Same line format: label|lang|text.
- None of this is real-world traffic. Do not quote rates from it as detection rates.
