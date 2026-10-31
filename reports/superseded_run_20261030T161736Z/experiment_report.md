# SAGE-IDS — Experiment Report

Generated 2026-10-30T16:36:54.813534+00:00 from actual execution recorded in `experiment_20261030T161736Z.db`. Every number below is read from that run's records; nothing is estimated or hand-entered.

## 1. Scope and environment

- **lab**: loopback services + application-level sensor + synthetic benign generator
- **threat_intel**: synthetic fixtures (SYNTH- IDs) drive the cases
- **operator**: scripted (operator:demo-script); candidate order fixed in advance
- **trials_per_phase**: 30
- **benign_rounds_per_phase**: 6
- **benign_users**: 8
- **window_seconds**: 5.0
- **python**: 3.12.7
- **platform**: Windows-11-10.0.26200-SP0
- **sklearn**: 1.9.1
- **numpy**: 2.5.4
- **pandas**: 3.1.0
- **cpu_count**: 16
- **config_hash**: 3cbb671937a5c07294a59f253fca022b0c6cc06a5cecae4efc07b9f154973ec5
- **base_seed**: 20261030

## 2. Execution log

- bootstrap v1 (120s)
- case 1: baseline -> remediation_proposed (91s)
- case 1: candidate from proposal 2 (Maximum-sensitivity rule on n_auth_fail (>= 1)) -> remediation_proposed (182s)
- case 1: candidate from proposal 3 (Calibrated rule + lab service hardening (login_lockout_threshold=5)) -> remediation_proposed (273s)
- case 1: candidate from proposal 1 (Calibrated threshold rule on n_auth_fail (>= 3)) -> acceptance_pending (367s)
- case 2: baseline -> remediation_proposed (88s)
- case 2: candidate from proposal 8 (Retrain Random Forest with verified labels from executed baseline trials) -> acceptance_pending (170s)
- case 6: baseline -> remediation_proposed (108s)
- case 6: candidate from proposal 9 (Calibrated threshold rule on n_distinct_dst_ports (>= 3)) -> remediation_proposed (220s)
- case 6: candidate from proposal 11 (Retrain Random Forest with verified labels from executed baseline trials) -> remediation_proposed (335s)
- rollback: active v5 -> v4
- final test (166s)

## 3. Closed-loop case outcomes

| case | finding | scenario | final state | adaptation cycles |
|---|---|---|---|---|
| 1 | `finding:nvd:SYNTH-2026-0001` | auth-password-guessing | `accepted` | 3 |
| 2 | `finding:nvd:SYNTH-2026-0002` | app-request-flood | `accepted` | 1 |
| 3 | `finding:nvd:SYNTH-2025-0107` | auth-password-guessing | `scenario_pending_review` | 0 |
| 4 | `finding:nvd:SYNTH-2026-0003` | — | `not_relevant` | 0 |
| 5 | `finding:nvd:SYNTH-2026-0004` | auth-password-guessing | `rejected` | 0 |
| 6 | `finding:mitre_attack:T1046` | recon-tcp-probe | `remediation_proposed` | 2 |
| 7 | `finding:mitre_attack:T1110.001` | auth-password-guessing | `scenario_pending_review` | 0 |
| 8 | `finding:mitre_attack:T1499.002` | app-request-flood | `scenario_pending_review` | 0 |

**A_password_guessing** (case 1, 367.3 s): final `accepted`, accepted version v4
  - proposal 2 *Maximum-sensitivity rule on n_auth_fail (>= 1)* → `remediation_proposed`
  - proposal 3 *Calibrated rule + lab service hardening (login_lockout_threshold=5)* → `remediation_proposed`
  - proposal 1 *Calibrated threshold rule on n_auth_fail (>= 3)* → `acceptance_pending`
**B_request_flood** (case 2, 169.7 s): final `accepted`, accepted version v5
  - proposal 8 *Retrain Random Forest with verified labels from executed baseline trials* → `acceptance_pending`
**C_recon** (case 6, 334.9 s): final `remediation_proposed`
  - proposal 9 *Calibrated threshold rule on n_distinct_dst_ports (>= 3)* → `remediation_proposed`
  - proposal 11 *Retrain Random Forest with verified labels from executed baseline trials* → `remediation_proposed`

## 4. Baseline measurements (accepted version at the time; Wilson 95% CI)

| case | scenario | executed | security effect | detected | benign windows alerting | regression set |
|---|---|---|---|---|---|---|
| 1 | auth-password-guessing | 30/30 | 30/30 = 1.00 [0.89, 1.00] | 0/30 = 0.00 [0.00, 0.11] | 0/65 = 0.00 [0.00, 0.06] | recon-tcp-probe |
| 2 | app-request-flood | 30/30 | 30/30 = 1.00 [0.89, 1.00] | 0/30 = 0.00 [0.00, 0.11] | 0/64 = 0.00 [0.00, 0.06] | recon-tcp-probe |
| 6 | recon-tcp-probe | 30/30 | 21/30 = 0.70 [0.52, 0.83] | 30/30 = 1.00 [0.89, 1.00] | 0/53 = 0.00 [0.00, 0.07] | auth-password-guessing, app-request-flood |

## 5. Candidate evaluations against frozen criteria (fresh-seed retests)

**evaluation 1** — case 1, candidate v2: **FAILED**

| criterion | measured | required | result |
|---|---|---|---|
| trigger_detection_gain | 0.9333 | >= 0.3 | pass |
| trigger_mcnemar_p | 0.0000 | < 0.05 | pass |
| trigger_detection_rate_lcb | 0.7868 | >= 0.7 | pass |
| effect_rate_not_increased | 1.0000 | <= 1.000 + 0.1 | pass |
| regression:recon-tcp-probe | 1.0000 | >= 1.000 - 0.1 | pass |
| benign_fpr | 0.2615 | <= 0.02 | **FAIL** |
| benign_denied_rate | 0.0000 | <= 0.01 | pass |
| service_health | {'login': True, 'test_app': True} | all healthy | pass |

**evaluation 2** — case 1, candidate v3: **FAILED**

| criterion | measured | required | result |
|---|---|---|---|
| trigger_detection_gain | 0.8000 | >= 0.3 | pass |
| trigger_mcnemar_p | 0.0000 | < 0.05 | pass |
| trigger_detection_rate_lcb | 0.6269 | >= 0.7 | **FAIL** |
| effect_rate_not_increased | 0.2333 | <= 1.000 + 0.1 | pass |
| regression:recon-tcp-probe | 0.9333 | >= 0.933 - 0.1 | pass |
| benign_fpr | 0.0000 | <= 0.02 | pass |
| benign_denied_rate | 0.0000 | <= 0.01 | pass |
| service_health | {'login': True, 'test_app': True} | all healthy | pass |

**evaluation 3** — case 1, candidate v4: **PASSED**

| criterion | measured | required | result |
|---|---|---|---|
| trigger_detection_gain | 0.9667 | >= 0.3 | pass |
| trigger_mcnemar_p | 0.0000 | < 0.05 | pass |
| trigger_detection_rate_lcb | 0.8333 | >= 0.7 | pass |
| effect_rate_not_increased | 1.0000 | <= 1.000 + 0.1 | pass |
| regression:recon-tcp-probe | 1.0000 | >= 1.000 - 0.1 | pass |
| benign_fpr | 0.0000 | <= 0.02 | pass |
| benign_denied_rate | 0.0000 | <= 0.01 | pass |
| service_health | {'login': True, 'test_app': True} | all healthy | pass |

**evaluation 4** — case 2, candidate v5: **PASSED**

| criterion | measured | required | result |
|---|---|---|---|
| trigger_detection_gain | 1.0000 | >= 0.3 | pass |
| trigger_mcnemar_p | 0.0000 | < 0.05 | pass |
| trigger_detection_rate_lcb | 0.8865 | >= 0.7 | pass |
| effect_rate_not_increased | 1.0000 | <= 1.000 + 0.1 | pass |
| regression:recon-tcp-probe | 1.0000 | >= 1.000 - 0.1 | pass |
| benign_fpr | 0.0000 | <= 0.02 | pass |
| benign_denied_rate | 0.0000 | <= 0.01 | pass |
| service_health | {'login': True, 'test_app': True} | all healthy | pass |

**evaluation 5** — case 6, candidate v6: **FAILED**

| criterion | measured | required | result |
|---|---|---|---|
| trigger_detection_gain | 0.0000 | >= 0.3 | **FAIL** |
| trigger_mcnemar_p | 1.0000 | < 0.05 | **FAIL** |
| trigger_detection_rate_lcb | 0.8865 | >= 0.7 | pass |
| effect_rate_not_increased | 0.8333 | <= 0.700 + 0.1 | **FAIL** |
| regression:auth-password-guessing | 0.9333 | >= 0.933 - 0.1 | pass |
| regression:app-request-flood | 1.0000 | >= 1.000 - 0.1 | pass |
| benign_fpr | 0.0000 | <= 0.02 | pass |
| benign_denied_rate | 0.0000 | <= 0.01 | pass |
| service_health | {'login': True, 'test_app': True} | all healthy | pass |

**evaluation 6** — case 6, candidate v7: **FAILED**

| criterion | measured | required | result |
|---|---|---|---|
| trigger_detection_gain | 0.0000 | >= 0.3 | **FAIL** |
| trigger_mcnemar_p | 1.0000 | < 0.05 | **FAIL** |
| trigger_detection_rate_lcb | 0.8333 | >= 0.7 | pass |
| effect_rate_not_increased | 0.6333 | <= 0.700 + 0.1 | pass |
| regression:auth-password-guessing | 0.8000 | >= 0.800 - 0.1 | pass |
| regression:app-request-flood | 1.0000 | >= 1.000 - 0.1 | pass |
| benign_fpr | 0.0000 | <= 0.02 | pass |
| benign_denied_rate | 0.0000 | <= 0.01 | pass |
| service_health | {'login': True, 'test_app': True} | all healthy | pass |

## 6. Versions

| id | name | status | active | rules | lab config | label counts |
|---|---|---|---|---|---|---|
| 1 | v1-baseline | accepted |  | RECON-PORTSCAN n_distinct_dst_ports>=5 | {'login_lockout_seconds': 60} | {'benign': 105, 'recon': 22} |
| 2 | candidate-p2 | rejected |  | RECON-PORTSCAN n_distinct_dst_ports>=5; SAGE-BRUTEFORCE-1-S n_auth_fail>=1.0 | {'login_lockout_seconds': 60} | {'benign': 105, 'recon': 22} |
| 3 | candidate-p3 | rejected |  | RECON-PORTSCAN n_distinct_dst_ports>=5; SAGE-BRUTEFORCE-1 n_auth_fail>=3.0 | {'login_lockout_threshold': 5, 'login_lockout_seconds': 300} | {'benign': 105, 'recon': 22} |
| 4 | candidate-p1 | retired |  | RECON-PORTSCAN n_distinct_dst_ports>=5; SAGE-BRUTEFORCE-1 n_auth_fail>=3.0 | {'login_lockout_seconds': 60} | {'benign': 105, 'recon': 22} |
| 5 | candidate-p8 | accepted | yes | RECON-PORTSCAN n_distinct_dst_ports>=5; SAGE-BRUTEFORCE-1 n_auth_fail>=3.0 | {'login_lockout_seconds': 60} | {'benign': 105, 'flood': 31, 'recon': 22} |
| 6 | candidate-p9 | rejected |  | RECON-PORTSCAN n_distinct_dst_ports>=5; SAGE-BRUTEFORCE-1 n_auth_fail>=3.0; SAGE-RECON-6 n_distinct_dst_ports>=3.0 | {'login_lockout_seconds': 60} | {'benign': 105, 'flood': 31, 'recon': 22} |
| 7 | candidate-p11 | rejected |  | RECON-PORTSCAN n_distinct_dst_ports>=5; SAGE-BRUTEFORCE-1 n_auth_fail>=3.0 | {'login_lockout_seconds': 60} | {'benign': 105, 'recon': 58, 'flood': 31} |
| 8 | ABL-iforest-alerting | ablation |  | RECON-PORTSCAN n_distinct_dst_ports>=5 | {'login_lockout_seconds': 60} | {'benign': 105, 'recon': 22} |
| 9 | ABL-self-training | ablation |  | RECON-PORTSCAN n_distinct_dst_ports>=5 | {'login_lockout_seconds': 60} | {'benign': 168, 'recon': 22} |
| 10 | ABL-verified-retrain-all | ablation |  | RECON-PORTSCAN n_distinct_dst_ports>=5 | {'login_lockout_seconds': 60} | {'benign': 105, 'bruteforce': 32, 'flood': 31, 'recon': 22} |

Rollback demonstration: {'from': 5, 'to': 4, 'restored_to': 5}

## 7. Held-out final test (fresh seeds; identical traffic for every version)

Events: 8169; labelled windows: 197 {'benign': 97, 'recon': 38, 'bruteforce': 32, 'flood': 30}. All versions are evaluated under the v1 lab configuration so that detectors see identical traffic; preventive effects of hardening are reported in Section 5.

### 7.1 Window-level binary detection (attack vs benign)

| version | precision | recall | F1 | FPR [95% CI] | TP/FP/TN/FN | ms/window |
|---|---|---|---|---|---|---|
| v1 v1-baseline (accepted) | 1.000 | 0.380 | 0.551 | 0.0000 [0.000, 0.038] | 38/0/97/62 | 0.73 |
| v2 candidate-p2 (rejected) | 0.753 | 0.700 | 0.725 | 0.2371 [0.164, 0.331] | 70/23/74/30 | 1.30 |
| v3 candidate-p3 (rejected) | 1.000 | 0.670 | 0.802 | 0.0000 [0.000, 0.038] | 67/0/97/33 | 1.25 |
| v4 candidate-p1 (retired) | 1.000 | 0.670 | 0.802 | 0.0000 [0.000, 0.038] | 67/0/97/33 | 1.24 |
| v5 candidate-p8 (accepted) | 1.000 | 0.970 | 0.985 | 0.0000 [0.000, 0.038] | 97/0/97/3 | 1.26 |
| v6 candidate-p9 (rejected) | 1.000 | 0.970 | 0.985 | 0.0000 [0.000, 0.038] | 97/0/97/3 | 1.79 |
| v7 candidate-p11 (rejected) | 1.000 | 0.970 | 0.985 | 0.0000 [0.000, 0.038] | 97/0/97/3 | 1.27 |
| v8 ABL-iforest-alerting (ablation) | 0.990 | 0.980 | 0.985 | 0.0103 [0.002, 0.056] | 98/1/96/2 | 0.73 |
| v9 ABL-self-training (ablation) | 1.000 | 0.380 | 0.551 | 0.0000 [0.000, 0.038] | 38/0/97/62 | 1.05 |
| v10 ABL-verified-retrain-all (ablation) | 1.000 | 1.000 | 1.000 | 0.0000 [0.000, 0.038] | 100/0/97/0 | 1.04 |

### 7.2 Per-trial detection rate by scenario (Wilson 95% CI) and median detection latency

| version | app-request-flood | auth-password-guessing | recon-tcp-probe |
|---|---|---|---|
| v1 v1-baseline | 0/30 = 0.00 [0.00, 0.11]; lat — s | 0/30 = 0.00 [0.00, 0.11]; lat — s | 30/30 = 1.00 [0.89, 1.00]; lat 1.98 s |
| v2 candidate-p2 | 0/30 = 0.00 [0.00, 0.11]; lat — s | 30/30 = 1.00 [0.89, 1.00]; lat 0.00 s | 30/30 = 1.00 [0.89, 1.00]; lat 1.98 s |
| v3 candidate-p3 | 0/30 = 0.00 [0.00, 0.11]; lat — s | 27/30 = 0.90 [0.74, 0.97]; lat 0.06 s | 30/30 = 1.00 [0.89, 1.00]; lat 1.98 s |
| v4 candidate-p1 | 0/30 = 0.00 [0.00, 0.11]; lat — s | 27/30 = 0.90 [0.74, 0.97]; lat 0.06 s | 30/30 = 1.00 [0.89, 1.00]; lat 1.98 s |
| v5 candidate-p8 | 30/30 = 1.00 [0.89, 1.00]; lat 2.55 s | 27/30 = 0.90 [0.74, 0.97]; lat 0.06 s | 30/30 = 1.00 [0.89, 1.00]; lat 1.98 s |
| v6 candidate-p9 | 30/30 = 1.00 [0.89, 1.00]; lat 2.55 s | 27/30 = 0.90 [0.74, 0.97]; lat 0.06 s | 30/30 = 1.00 [0.89, 1.00]; lat 1.12 s |
| v7 candidate-p11 | 30/30 = 1.00 [0.89, 1.00]; lat 2.55 s | 27/30 = 0.90 [0.74, 0.97]; lat 0.06 s | 30/30 = 1.00 [0.89, 1.00]; lat 1.98 s |
| v8 ABL-iforest-alerting | 30/30 = 1.00 [0.89, 1.00]; lat 2.55 s | 28/30 = 0.93 [0.79, 0.98]; lat 3.05 s | 30/30 = 1.00 [0.89, 1.00]; lat 1.98 s |
| v9 ABL-self-training | 0/30 = 0.00 [0.00, 0.11]; lat — s | 0/30 = 0.00 [0.00, 0.11]; lat — s | 30/30 = 1.00 [0.89, 1.00]; lat 1.98 s |
| v10 ABL-verified-retrain-all | 30/30 = 1.00 [0.89, 1.00]; lat 2.55 s | 30/30 = 1.00 [0.89, 1.00]; lat 3.08 s | 30/30 = 1.00 [0.89, 1.00]; lat 1.98 s |

### 7.3 Paired exact McNemar tests vs v1 on identical final-test trials (two-sided)

| scenario | version | candidate-only detections | v1-only detections | p-value |
|---|---|---|---|---|
| app-request-flood | v2 candidate-p2 | 0 | 0 | 1.00e+00 |
| app-request-flood | v3 candidate-p3 | 0 | 0 | 1.00e+00 |
| app-request-flood | v4 candidate-p1 | 0 | 0 | 1.00e+00 |
| app-request-flood | v5 candidate-p8 | 30 | 0 | 1.86e-09 |
| app-request-flood | v6 candidate-p9 | 30 | 0 | 1.86e-09 |
| app-request-flood | v7 candidate-p11 | 30 | 0 | 1.86e-09 |
| app-request-flood | v8 ABL-iforest-alerting | 30 | 0 | 1.86e-09 |
| app-request-flood | v9 ABL-self-training | 0 | 0 | 1.00e+00 |
| app-request-flood | v10 ABL-verified-retrain-all | 30 | 0 | 1.86e-09 |
| auth-password-guessing | v2 candidate-p2 | 30 | 0 | 1.86e-09 |
| auth-password-guessing | v3 candidate-p3 | 27 | 0 | 1.49e-08 |
| auth-password-guessing | v4 candidate-p1 | 27 | 0 | 1.49e-08 |
| auth-password-guessing | v5 candidate-p8 | 27 | 0 | 1.49e-08 |
| auth-password-guessing | v6 candidate-p9 | 27 | 0 | 1.49e-08 |
| auth-password-guessing | v7 candidate-p11 | 27 | 0 | 1.49e-08 |
| auth-password-guessing | v8 ABL-iforest-alerting | 28 | 0 | 7.45e-09 |
| auth-password-guessing | v9 ABL-self-training | 0 | 0 | 1.00e+00 |
| auth-password-guessing | v10 ABL-verified-retrain-all | 30 | 0 | 1.86e-09 |
| recon-tcp-probe | v2 candidate-p2 | 0 | 0 | 1.00e+00 |
| recon-tcp-probe | v3 candidate-p3 | 0 | 0 | 1.00e+00 |
| recon-tcp-probe | v4 candidate-p1 | 0 | 0 | 1.00e+00 |
| recon-tcp-probe | v5 candidate-p8 | 0 | 0 | 1.00e+00 |
| recon-tcp-probe | v6 candidate-p9 | 0 | 0 | 1.00e+00 |
| recon-tcp-probe | v7 candidate-p11 | 0 | 0 | 1.00e+00 |
| recon-tcp-probe | v8 ABL-iforest-alerting | 0 | 0 | 1.00e+00 |
| recon-tcp-probe | v9 ABL-self-training | 0 | 0 | 1.00e+00 |
| recon-tcp-probe | v10 ABL-verified-retrain-all | 0 | 0 | 1.00e+00 |

### 7.4 Per-class metrics and confusion matrices

**v1 v1-baseline**

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| benign | 0.610 | 1.000 | 0.758 | 97 |
| bruteforce | 0.000 | 0.000 | 0.000 | 32 |
| flood | 0.000 | 0.000 | 0.000 | 30 |
| recon | 1.000 | 1.000 | 1.000 | 38 |

| true \ predicted | benign | bruteforce | flood | recon |
|---|---|---|---|---|
| benign | 97 | 0 | 0 | 0 |
| bruteforce | 32 | 0 | 0 | 0 |
| flood | 30 | 0 | 0 | 0 |
| recon | 0 | 0 | 0 | 38 |

**v4 candidate-p1**

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| benign | 0.746 | 1.000 | 0.855 | 97 |
| bruteforce | 1.000 | 0.906 | 0.951 | 32 |
| flood | 0.000 | 0.000 | 0.000 | 30 |
| recon | 1.000 | 1.000 | 1.000 | 38 |

| true \ predicted | benign | bruteforce | flood | recon |
|---|---|---|---|---|
| benign | 97 | 0 | 0 | 0 |
| bruteforce | 3 | 29 | 0 | 0 |
| flood | 30 | 0 | 0 | 0 |
| recon | 0 | 0 | 0 | 38 |

**v5 candidate-p8**

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| benign | 0.970 | 1.000 | 0.985 | 97 |
| bruteforce | 1.000 | 0.906 | 0.951 | 32 |
| flood | 1.000 | 1.000 | 1.000 | 30 |
| recon | 1.000 | 1.000 | 1.000 | 38 |

| true \ predicted | benign | bruteforce | flood | recon |
|---|---|---|---|---|
| benign | 97 | 0 | 0 | 0 |
| bruteforce | 3 | 29 | 0 | 0 |
| flood | 0 | 0 | 30 | 0 |
| recon | 0 | 0 | 0 | 38 |

## 8. Safety verification

| attempted target | decision | detail |
|---|---|---|
| `8.8.8.8:18081` | DENIED | target '8.8.8.8' resolves to non-allowlisted address(es) ['8.8.8.8'] |
| `10.0.0.5:18081` | DENIED | target '10.0.0.5' resolves to non-allowlisted address(es) ['10.0.0.5'] |
| `192.168.1.1:18082` | DENIED | target '192.168.1.1' resolves to non-allowlisted address(es) ['192.168.1.1'] |
| `127.0.0.2:18081` | DENIED | target '127.0.0.2' resolves to non-allowlisted address(es) ['127.0.0.2'] |
| `example.com:18082` | DENIED | target 'example.com' resolves to non-allowlisted address(es) ['104.20.23.154', '172.66.147.243', '2606:4700:90c5:72db:f264:26:ef6b:ff98'] |
| `localhost:18081` | DENIED | target 'localhost' resolves to non-allowlisted address(es) ['::1'] |
| `127.0.0.1:22` | DENIED | port 22 not in laboratory port allowlist |
| `127.0.0.1;rm -rf /:18081` | DENIED | malformed target '127.0.0.1;rm -rf /' |
| `127.0.0.1:18081` | ALLOWED | 127.0.0.1 |
| `scenario->8.8.8.8 (active=True)` | DENIED before any connection | TargetNotAllowed: target '8.8.8.8' resolves to non-allowlisted address(es) ['8.8.8.8'] |
| `scenario->127.0.0.1 (active=False)` | DENIED before any connection | ActiveLabDisabled: active laboratory scenarios are disabled (opt-in: SAGE_ENABLE_ACTIVE_LAB=1) |

- Audit hash chain: valid=True, entries checked=116.
- Tamper test on a copy: modified entry 58 → valid=False, broken at id 58.

## 9. Resource use

- wall_s: 1158.6
- cpu_user_s: 47.6
- cpu_system_s: 35.1
- rss_mb: 254.2
- RSS during final test: 249.9 MB

## 10. Threats to validity and limitations

- **Laboratory realism.** Targets are loopback services; telemetry comes from an application-level sensor, not packet capture; benign traffic is synthetic. Absolute rates do not transfer to production networks.
- **Scenario scope.** Three reviewed, bounded scenarios with parameters randomised inside reviewed bounds. No adaptive or evasive attacker is modelled; a candidate that passes here may fail against one.
- **Sample size.** Trials per phase are finite; use the reported confidence intervals, not point estimates.
- **Scripted operator.** Approvals and the order in which candidates were tried were fixed in advance by the experiment script; they are not independent human judgements.
- **Threat-intel fixtures.** Unless run with live intelligence, findings are synthetic fixtures (SYNTH- IDs) used to exercise the mapping logic; matches are weakness-class/technique matches, not product matches.
- **Detection ≠ prevention.** Alerts show detection only; prevention is measured by the separately recorded security-effect outcome.
- **Benchmark separation.** CICIDS2017 results (if run) come from a separate model and schema and are not comparable to laboratory numbers.
