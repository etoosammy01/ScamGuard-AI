# Synthetic detection evaluation

## Scope and procedure

Dataset: [`synthetic.json`](../backend/internal/evaluation/testdata/synthetic.json), 67 synthetic
examples with no customer information. The labels describe intended risk-review behavior, not
proof that a real URL/site is malicious or safe. No submitted URLs were fetched. Domains ending
in `.invalid` and documentation-only IP addresses are used except named official domains used
as lexical benign controls; those domains were not contacted.

Class distribution: **38 positive, 25 benign, 4 ambiguous**. Ambiguous cases are scored and
reported but excluded from the binary confusion matrix and precision/recall/F1 denominator.
There are 54 messages and 13 URLs. Group composition:

- benign: 15
- bank: 4
- credentials: 5
- prize: 3
- advance-fee: 4
- investment: 3
- jobs: 3
- delivery: 3
- social-engineering: 3
- multilingual: 7
- ambiguous: 4
- benign-url: 7
- suspicious-url: 6

The corpus includes bank impersonation, password/OTP/BVN/NIN requests, prizes, advance fees,
investments, jobs, deliveries, social engineering, suspicious URLs, benign structural URL
signals, Nigerian Pidgin, Yoruba, French, Spanish, and ordinary ambiguous requests.

Run `cd backend && go run ./cmd/evaluate`. A score **>=25** predicts positive, using the
existing low/moderate boundary. No weights or score thresholds were changed for this phase.
Risk consistency checks the score-to-level mapping for every case. This is a versioned
regression corpus, not a held-out representative validation set; changes informed by its
examples cannot demonstrate generalization. Precision/recall vary with thresholds and prevalence.

The unchanged Phase 6 commit `7ca5127` was exported to a temporary directory. The same evaluator
and dataset were copied into it, then executed for the baseline. Hardened results were measured
with the sentence-scoped credential/payment and deterministic brand-link changes. The raw
identifier/score results are in [`detection-evaluation-results.json`](detection-evaluation-results.json).

## Measured rules-only results

| Metric | Phase 6 baseline | Hardened |
| --- | ---: | ---: |
| True positives | 31 | 34 |
| False positives | 1 | 0 |
| True negatives | 24 | 25 |
| False negatives | 7 | 4 |
| Precision TP/(TP+FP) | 0.96875 | 1.00000 |
| Recall TP/(TP+FN) | 0.81579 | 0.89474 |
| F1 | 0.88571 | 0.94444 |
| Risk-level consistency | 67/67 | 67/67 |

Confusion matrix (hardened, ambiguous excluded):

| Expected / predicted | Positive | Negative |
| --- | ---: | ---: |
| Positive | 34 | 4 |
| Benign | 0 | 25 |

**Zero false positives here is not a claim of perfect real-world precision.** The corpus is
small, synthetic and reviewed by the implementer. No statistically validated accuracy claim
is made. Class/category precision was not separately validated.

## Misclassification review

Baseline false positive `benign-09`: “Do not send money to strangers claiming you won a lottery.”
The payment matcher treated negated advice as a payment request. Payment advice is now evaluated
per clause, so an explicit request in another sentence remains detectable. A regression test
covers both the benign advice and advice followed by a separate fee demand.

Baseline misses `bank-03`, `credentials-03`, `credentials-04` involved a BVN/NIN request and
credential requests preceded by a safety notice. Sensitive identity-request vocabulary now
includes BVN/NIN; a disclaimer elsewhere no longer globally suppresses a request. Initial
hardening introduced a Pidgin false positive (`multilingual-07`, “Abeg no share your OTP…”).
The local negation pattern was corrected and retested. No score adjustment was used.

Remaining false negatives:

- `delivery-01` and `delivery-02`: explicit delivery payment scams score 20, below the unchanged
  binary threshold. Their delivery indicator/category remains explainable. Increasing every
  delivery score without broader benign controls would risk false positives; this is deferred.
- `multilingual-03` and `multilingual-04`: French/Spanish credential requests score 0. English
  patterns and limited Pidgin examples do not provide general multilingual support. Yoruba
  benign classification is not evidence of Yoruba scam coverage.

## AI-assisted evaluation (separate)

No paid or live AI calls were made. A neutral deterministic mock was applied to every case:
**67/67 preserved the rules score**. Separate provider mocks verify fixed instructions/model,
no tools, redaction, strict schema handling, rejection of redirects/oversized/trailing JSON,
retry budget, and error fallback. High-risk rules cannot be downgraded by a low mock AI score.

These are integration/safety contract checks, **not AI detection precision, recall or F1**.
A real-model evaluation remains unmeasured and requires an explicitly approved privacy-safe
corpus, provider/model/version record, budget and human-reviewed labeling protocol. Prompt
injection cannot cause application tools/configuration changes because no tools or untrusted
configuration are exposed; semantic correctness of free-form model explanations is not proven
by these mocks. Trusted prompts reduce risk but do not guarantee model compliance.

## Future work and readiness

Keep held-out paraphrases, independent annotators, negative advice/news examples, threat-family
coverage, and multilingual expertise separate from development fixtures. Agree operational
quality targets before release; do not optimize this corpus to a predetermined accuracy number.
Retain current advisory labels and avoid presenting low scores as guarantees. Consider
calibration only after gathering representative authorized data; no external target scanning
or private customer collection was performed.
