# Robustness: evasive variants vs accepted detectors

Generated 2026-11-01T05:34:19.017738+00:00. Reviewed evasive variants (low-and-slow, distributed, low-rate) run on the live lab against each accepted/retired detector version. Detection rate with Wilson 95% CI; attacks still achieve their effect (that is the point of an evasive variant).

| variant | base scenario | effect rate | v1 v1-baseline | v3 candidate-p3 | v4 candidate-p8 |
|---|---|---|---|---|---|
| auth-slow-guessing | auth-password-guessing | 1.00 | 0/12 = 0.00 [0.00, 0.24] | 3/12 = 0.25 [0.09, 0.53] | 3/12 = 0.25 [0.09, 0.53] |
| auth-distributed-guessing | auth-password-guessing | 1.00 | 0/12 = 0.00 [0.00, 0.24] | 0/12 = 0.00 [0.00, 0.24] | 0/12 = 0.00 [0.00, 0.24] |
| app-low-rate-flood | app-request-flood | 1.00 | 0/12 = 0.00 [0.00, 0.24] | 0/12 = 0.00 [0.00, 0.24] | 9/12 = 0.75 [0.47, 0.91] |

Interpretation: where an accepted version detected the *non-evasive* scenario well but detects the evasive variant poorly, the accepted threshold/model is evadable by that technique. This is a limitation of behavioural per-source thresholds, reported honestly rather than hidden.