# SAGE-IDS — Experiment Report

Generated 2026-11-01T06:44:11.687805+00:00 from actual execution recorded in `experiment_20261101T061725Z.db`. Every number below is read from that run's records; nothing is estimated or hand-entered.

**Timing integrity WARNING:** possible host suspend or stall — long runs [{'run_id': 349, 'phase': 'baseline', 'seconds': 159.3}, {'run_id': 353, 'phase': 'baseline', 'seconds': 317.3}], gaps []. Measurements of the affected phases should not be relied on.

## Summary (computed from the records below)

- A_password_guessing: `accepted` after 2 candidate(s); accepted v3
- B_request_flood: `accepted` after 1 candidate(s); accepted v4
- C_recon: `rejected` after 2 candidate(s)
- Candidate evaluations: 5 total, 3 rejected by the frozen criteria.

Held-out final test, initial v1 vs final active v4 (identical traffic):

| metric | v1 | v4 |
|---|---|---|
| window precision | 1.000 | 1.000 |
| window recall | 0.366 | 0.970 |
| window f1 | 0.536 | 0.985 |
| window fpr | 0.000 | 0.000 |
| app-request-flood detection | 0/30 | 30/30 |
| auth-password-guessing detection | 0/30 | 27/30 |
| recon-tcp-probe detection | 30/30 | 30/30 |

Label-provenance ablation (same base model, same observations):

| scenario | self-training (pseudo-labels) | verified-label retraining |
|---|---|---|
| app-request-flood | 0/30 | 30/30 |
| auth-password-guessing | 0/30 | 30/30 |
| recon-tcp-probe | 30/30 | 30/30 |

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
- **config_hash**: f233704eefb24164debf25f06d3ef7129c832c2329ee50019ea70d93b635cc5a
- **base_seed**: 20261102

## 2. Execution log

- bootstrap v1 (123s)
- case 1: baseline -> remediation_proposed (99s)
- case 1: candidate from proposal 2 (Maximum-sensitivity rule on n_auth_fail (>= 1)) -> remediation_proposed (199s)
- case 1: candidate from proposal 3 (Calibrated rule + lab service hardening (login_lockout_threshold=5)) -> acceptance_pending (300s)
- case 2: baseline -> remediation_proposed (98s)
- case 2: candidate from proposal 8 (Retrain Random Forest with verified labels from executed baseline trials) -> acceptance_pending (191s)
- case 6: baseline -> remediation_proposed (588s)
- case 6: candidate from proposal 9 (Calibrated threshold rule on n_distinct_dst_ports (>= 3)) -> remediation_proposed (707s)
- case 6: candidate from proposal 11 (Retrain Random Forest with verified labels from executed baseline trials) -> remediation_proposed (826s)
- case 6: rejected (candidate order exhausted)
- rollback: active v4 -> v3
- final test (164s)

## 3. Closed-loop case outcomes

| case | finding | scenario | final state | adaptation cycles |
|---|---|---|---|---|
| 1 | `finding:nvd:SYNTH-2026-0001` | auth-password-guessing | `accepted` | 2 |
| 2 | `finding:nvd:SYNTH-2026-0002` | app-request-flood | `accepted` | 1 |
| 3 | `finding:nvd:SYNTH-2025-0107` | auth-password-guessing | `scenario_pending_review` | 0 |
| 4 | `finding:nvd:SYNTH-2026-0003` | — | `not_relevant` | 0 |
| 5 | `finding:nvd:SYNTH-2026-0004` | auth-password-guessing | `rejected` | 0 |
| 6 | `finding:mitre_attack:T1046` | recon-tcp-probe | `rejected` | 2 |
| 7 | `finding:mitre_attack:T1110.001` | auth-password-guessing | `scenario_pending_review` | 0 |
| 8 | `finding:mitre_attack:T1499.002` | app-request-flood | `scenario_pending_review` | 0 |

**A_password_guessing** (case 1, 300.5 s): final `accepted`, accepted version v3
  - proposal 2 *Maximum-sensitivity rule on n_auth_fail (>= 1)* → `remediation_proposed`
  - proposal 3 *Calibrated rule + lab service hardening (login_lockout_threshold=5)* → `acceptance_pending`
**B_request_flood** (case 2, 191.0 s): final `accepted`, accepted version v4
  - proposal 8 *Retrain Random Forest with verified labels from executed baseline trials* → `acceptance_pending`
**C_recon** (case 6, 826.4 s): final `rejected`
  - proposal 9 *Calibrated threshold rule on n_distinct_dst_ports (>= 3)* → `remediation_proposed`
  - proposal 11 *Retrain Random Forest with verified labels from executed baseline trials* → `remediation_proposed`

## 4. Baseline measurements (accepted version at the time; Wilson 95% CI)

| case | scenario | executed | security effect | detected | benign windows alerting | regression set |
|---|---|---|---|---|---|---|
| 1 | auth-password-guessing | 30/30 | 30/30 = 1.00 [0.89, 1.00] | 0/30 = 0.00 [0.00, 0.11] | 0/60 = 0.00 [0.00, 0.06] | recon-tcp-probe |
| 2 | app-request-flood | 30/30 | 30/30 = 1.00 [0.89, 1.00] | 0/30 = 0.00 [0.00, 0.11] | 0/66 = 0.00 [0.00, 0.06] | recon-tcp-probe, auth-password-guessing |
| 6 | recon-tcp-probe | 30/30 | 24/30 = 0.80 [0.63, 0.90] | 30/30 = 1.00 [0.89, 1.00] | 0/63 = 0.00 [0.00, 0.06] | auth-password-guessing, app-request-flood |

## 5. Candidate evaluations against frozen criteria (fresh-seed retests)

**evaluation 1** — case 1, candidate v2: **FAILED**

| criterion | measured | required | result |
|---|---|---|---|
| trigger_detection_gain | 0.9667 | >= 0.3 | pass |
| trigger_mcnemar_p | 0.0000 | < 0.05 | pass |
| trigger_detection_rate_lcb | 0.8333 | >= 0.7 | pass |
| effect_rate_not_increased | 1.0000 | <= 1.000 + 0.1 | pass |
| regression:recon-tcp-probe | 0.9333 | >= 0.933 - 0.1 | pass |
| benign_fpr | 0.2419 | <= 0.02 | **FAIL** |
| benign_denied_rate | 0.0000 | <= 0.01 | pass |
| service_health | {'login': True, 'test_app': True} | all healthy | pass |

**evaluation 2** — case 1, candidate v3: **PASSED**

| criterion | measured | required | result |
|---|---|---|---|
| trigger_detection_gain | 0.9000 | >= 0.3 | pass |
| trigger_mcnemar_p | 0.0000 | < 0.05 | pass |
| trigger_detection_rate_lcb | 0.7438 | >= 0.7 | pass |
| effect_rate_not_increased | 0.2333 | <= 1.000 + 0.1 | pass |
| regression:recon-tcp-probe | 0.9333 | >= 0.933 - 0.1 | pass |
| benign_fpr | 0.0000 | <= 0.02 | pass |
| benign_denied_rate | 0.0000 | <= 0.01 | pass |
| service_health | {'login': True, 'test_app': True} | all healthy | pass |

**evaluation 3** — case 2, candidate v4: **PASSED**

| criterion | measured | required | result |
|---|---|---|---|
| trigger_detection_gain | 1.0000 | >= 0.3 | pass |
| trigger_mcnemar_p | 0.0000 | < 0.05 | pass |
| trigger_detection_rate_lcb | 0.8865 | >= 0.7 | pass |
| effect_rate_not_increased | 1.0000 | <= 1.000 + 0.1 | pass |
| regression:recon-tcp-probe | 0.9333 | >= 0.933 - 0.1 | pass |
| regression:auth-password-guessing | 0.7333 | >= 0.733 - 0.1 | pass |
| benign_fpr | 0.0000 | <= 0.02 | pass |
| benign_denied_rate | 0.0000 | <= 0.01 | pass |
| service_health | {'login': True, 'test_app': True} | all healthy | pass |

**evaluation 4** — case 6, candidate v5: **FAILED**

| criterion | measured | required | result |
|---|---|---|---|
| effect_rate_reduction | 0.1667 | >= 0.3 | **FAIL** |
| effect_fisher_p | 0.1258 | < 0.05 | **FAIL** |
| trigger_detection_noninferior | 0.9667 | >= 0.967 - 0.1 | pass |
| regression:auth-password-guessing | 0.6667 | >= 0.667 - 0.1 | pass |
| regression:app-request-flood | 1.0000 | >= 1.000 - 0.1 | pass |
| benign_fpr | 0.0000 | <= 0.02 | pass |
| benign_denied_rate | 0.0000 | <= 0.01 | pass |
| service_health | {'login': True, 'test_app': True} | all healthy | pass |

**evaluation 5** — case 6, candidate v6: **FAILED**

| criterion | measured | required | result |
|---|---|---|---|
| effect_rate_reduction | 0.1667 | >= 0.3 | **FAIL** |
| effect_fisher_p | 0.1258 | < 0.05 | **FAIL** |
| trigger_detection_noninferior | 0.9667 | >= 0.967 - 0.1 | pass |
| regression:auth-password-guessing | 0.6667 | >= 0.667 - 0.1 | pass |
| regression:app-request-flood | 1.0000 | >= 1.000 - 0.1 | pass |
| benign_fpr | 0.0000 | <= 0.02 | pass |
| benign_denied_rate | 0.0000 | <= 0.01 | pass |
| service_health | {'login': True, 'test_app': True} | all healthy | pass |

## 6. Versions

| id | name | status | active | rules | lab config | label counts |
|---|---|---|---|---|---|---|
| 1 | v1-baseline | accepted |  | RECON-PORTSCAN n_distinct_dst_ports>=5 | {'login_lockout_seconds': 60} | {'benign': 97, 'recon': 25} |
| 2 | candidate-p2 | rejected |  | RECON-PORTSCAN n_distinct_dst_ports>=5; SAGE-BRUTEFORCE-1-S n_auth_fail>=1.0 | {'login_lockout_seconds': 60} | {'benign': 97, 'recon': 25} |
| 3 | candidate-p3 | retired |  | RECON-PORTSCAN n_distinct_dst_ports>=5; SAGE-BRUTEFORCE-1 n_auth_fail>=3.0 | {'login_lockout_threshold': 5, 'login_lockout_seconds': 300} | {'benign': 97, 'recon': 25} |
| 4 | candidate-p8 | accepted | yes | RECON-PORTSCAN n_distinct_dst_ports>=5; SAGE-BRUTEFORCE-1 n_auth_fail>=3.0 | {'login_lockout_threshold': 5, 'login_lockout_seconds': 300} | {'benign': 97, 'flood': 31, 'recon': 25} |
| 5 | candidate-p9 | rejected |  | RECON-PORTSCAN n_distinct_dst_ports>=5; SAGE-BRUTEFORCE-1 n_auth_fail>=3.0; SAGE-RECON-6 n_distinct_dst_ports>=3.0 | {'login_lockout_threshold': 5, 'login_lockout_seconds': 300} | {'benign': 97, 'flood': 31, 'recon': 25} |
| 6 | candidate-p11 | rejected |  | RECON-PORTSCAN n_distinct_dst_ports>=5; SAGE-BRUTEFORCE-1 n_auth_fail>=3.0 | {'login_lockout_threshold': 5, 'login_lockout_seconds': 300} | {'benign': 97, 'recon': 61, 'flood': 31} |
| 7 | ABL-iforest-alerting | ablation |  | RECON-PORTSCAN n_distinct_dst_ports>=5 | {'login_lockout_seconds': 60} | {'benign': 97, 'recon': 25} |
| 8 | ABL-self-training | ablation |  | RECON-PORTSCAN n_distinct_dst_ports>=5 | {'login_lockout_seconds': 60} | {'benign': 162, 'recon': 25} |
| 9 | ABL-verified-retrain-all | ablation |  | RECON-PORTSCAN n_distinct_dst_ports>=5 | {'login_lockout_seconds': 60} | {'benign': 97, 'bruteforce': 34, 'flood': 31, 'recon': 25} |

Rollback demonstration: {'from': 4, 'to': 3, 'restored_to': 4}

## 7. Held-out final test (fresh seeds; identical traffic for every version)

Events: 8173; labelled windows: 201 {'benign': 100, 'recon': 37, 'bruteforce': 34, 'flood': 30}. All versions are evaluated under the v1 lab configuration so that detectors see identical traffic; preventive effects of hardening are reported in Section 5.

### 7.1 Window-level binary detection (attack vs benign)

| version | precision | recall | F1 | FPR [95% CI] | TP/FP/TN/FN | ms/window |
|---|---|---|---|---|---|---|
| v1 v1-baseline (accepted) | 1.000 | 0.366 | 0.536 | 0.0000 [0.000, 0.037] | 37/0/100/64 | 0.71 |
| v2 candidate-p2 (rejected) | 0.812 | 0.683 | 0.742 | 0.1600 [0.101, 0.244] | 69/16/84/32 | 1.22 |
| v3 candidate-p3 (retired) | 1.000 | 0.673 | 0.805 | 0.0000 [0.000, 0.037] | 68/0/100/33 | 1.21 |
| v4 candidate-p8 (accepted) | 1.000 | 0.970 | 0.985 | 0.0000 [0.000, 0.037] | 98/0/100/3 | 1.22 |
| v5 candidate-p9 (rejected) | 1.000 | 0.970 | 0.985 | 0.0000 [0.000, 0.037] | 98/0/100/3 | 1.75 |
| v6 candidate-p11 (rejected) | 1.000 | 0.970 | 0.985 | 0.0000 [0.000, 0.037] | 98/0/100/3 | 1.23 |
| v7 ABL-iforest-alerting (ablation) | 0.986 | 0.673 | 0.800 | 0.0100 [0.002, 0.054] | 68/1/99/33 | 0.71 |
| v8 ABL-self-training (ablation) | 1.000 | 0.366 | 0.536 | 0.0000 [0.000, 0.037] | 37/0/100/64 | 1.03 |
| v9 ABL-verified-retrain-all (ablation) | 0.990 | 1.000 | 0.995 | 0.0100 [0.002, 0.054] | 101/1/99/0 | 1.39 |

### 7.2 Per-trial detection rate by scenario (Wilson 95% CI) and median detection latency

| version | app-request-flood | auth-password-guessing | recon-tcp-probe |
|---|---|---|---|
| v1 v1-baseline | 0/30 = 0.00 [0.00, 0.11]; lat — s | 0/30 = 0.00 [0.00, 0.11]; lat — s | 30/30 = 1.00 [0.89, 1.00]; lat 2.11 s |
| v2 candidate-p2 | 0/30 = 0.00 [0.00, 0.11]; lat — s | 28/30 = 0.93 [0.79, 0.98]; lat 0.02 s | 30/30 = 1.00 [0.89, 1.00]; lat 2.11 s |
| v3 candidate-p3 | 0/30 = 0.00 [0.00, 0.11]; lat — s | 27/30 = 0.90 [0.74, 0.97]; lat 0.12 s | 30/30 = 1.00 [0.89, 1.00]; lat 2.11 s |
| v4 candidate-p8 | 30/30 = 1.00 [0.89, 1.00]; lat 2.61 s | 27/30 = 0.90 [0.74, 0.97]; lat 0.12 s | 30/30 = 1.00 [0.89, 1.00]; lat 2.11 s |
| v5 candidate-p9 | 30/30 = 1.00 [0.89, 1.00]; lat 2.61 s | 27/30 = 0.90 [0.74, 0.97]; lat 0.12 s | 30/30 = 1.00 [0.89, 1.00]; lat 1.22 s |
| v6 candidate-p11 | 30/30 = 1.00 [0.89, 1.00]; lat 2.61 s | 27/30 = 0.90 [0.74, 0.97]; lat 0.12 s | 30/30 = 1.00 [0.89, 1.00]; lat 2.11 s |
| v7 ABL-iforest-alerting | 0/30 = 0.00 [0.00, 0.11]; lat — s | 28/30 = 0.93 [0.79, 0.98]; lat 2.01 s | 30/30 = 1.00 [0.89, 1.00]; lat 2.11 s |
| v8 ABL-self-training | 0/30 = 0.00 [0.00, 0.11]; lat — s | 0/30 = 0.00 [0.00, 0.11]; lat — s | 30/30 = 1.00 [0.89, 1.00]; lat 2.11 s |
| v9 ABL-verified-retrain-all | 30/30 = 1.00 [0.89, 1.00]; lat 2.61 s | 30/30 = 1.00 [0.89, 1.00]; lat 1.96 s | 30/30 = 1.00 [0.89, 1.00]; lat 2.11 s |

### 7.3 Paired exact McNemar tests vs v1 on identical final-test trials (two-sided)

| scenario | version | candidate-only detections | v1-only detections | p-value |
|---|---|---|---|---|
| app-request-flood | v2 candidate-p2 | 0 | 0 | 1.00e+00 |
| app-request-flood | v3 candidate-p3 | 0 | 0 | 1.00e+00 |
| app-request-flood | v4 candidate-p8 | 30 | 0 | 1.86e-09 |
| app-request-flood | v5 candidate-p9 | 30 | 0 | 1.86e-09 |
| app-request-flood | v6 candidate-p11 | 30 | 0 | 1.86e-09 |
| app-request-flood | v7 ABL-iforest-alerting | 0 | 0 | 1.00e+00 |
| app-request-flood | v8 ABL-self-training | 0 | 0 | 1.00e+00 |
| app-request-flood | v9 ABL-verified-retrain-all | 30 | 0 | 1.86e-09 |
| auth-password-guessing | v2 candidate-p2 | 28 | 0 | 7.45e-09 |
| auth-password-guessing | v3 candidate-p3 | 27 | 0 | 1.49e-08 |
| auth-password-guessing | v4 candidate-p8 | 27 | 0 | 1.49e-08 |
| auth-password-guessing | v5 candidate-p9 | 27 | 0 | 1.49e-08 |
| auth-password-guessing | v6 candidate-p11 | 27 | 0 | 1.49e-08 |
| auth-password-guessing | v7 ABL-iforest-alerting | 28 | 0 | 7.45e-09 |
| auth-password-guessing | v8 ABL-self-training | 0 | 0 | 1.00e+00 |
| auth-password-guessing | v9 ABL-verified-retrain-all | 30 | 0 | 1.86e-09 |
| recon-tcp-probe | v2 candidate-p2 | 0 | 0 | 1.00e+00 |
| recon-tcp-probe | v3 candidate-p3 | 0 | 0 | 1.00e+00 |
| recon-tcp-probe | v4 candidate-p8 | 0 | 0 | 1.00e+00 |
| recon-tcp-probe | v5 candidate-p9 | 0 | 0 | 1.00e+00 |
| recon-tcp-probe | v6 candidate-p11 | 0 | 0 | 1.00e+00 |
| recon-tcp-probe | v7 ABL-iforest-alerting | 0 | 0 | 1.00e+00 |
| recon-tcp-probe | v8 ABL-self-training | 0 | 0 | 1.00e+00 |
| recon-tcp-probe | v9 ABL-verified-retrain-all | 0 | 0 | 1.00e+00 |

### 7.4 Per-class metrics and confusion matrices

**v1 v1-baseline**

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| benign | 0.610 | 1.000 | 0.758 | 100 |
| bruteforce | 0.000 | 0.000 | 0.000 | 34 |
| flood | 0.000 | 0.000 | 0.000 | 30 |
| recon | 1.000 | 1.000 | 1.000 | 37 |

| true \ predicted | benign | bruteforce | flood | recon |
|---|---|---|---|---|
| benign | 100 | 0 | 0 | 0 |
| bruteforce | 34 | 0 | 0 | 0 |
| flood | 30 | 0 | 0 | 0 |
| recon | 0 | 0 | 0 | 37 |

**v3 candidate-p3**

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| benign | 0.752 | 1.000 | 0.858 | 100 |
| bruteforce | 1.000 | 0.912 | 0.954 | 34 |
| flood | 0.000 | 0.000 | 0.000 | 30 |
| recon | 1.000 | 1.000 | 1.000 | 37 |

| true \ predicted | benign | bruteforce | flood | recon |
|---|---|---|---|---|
| benign | 100 | 0 | 0 | 0 |
| bruteforce | 3 | 31 | 0 | 0 |
| flood | 30 | 0 | 0 | 0 |
| recon | 0 | 0 | 0 | 37 |

**v4 candidate-p8**

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| benign | 0.971 | 1.000 | 0.985 | 100 |
| bruteforce | 1.000 | 0.912 | 0.954 | 34 |
| flood | 1.000 | 1.000 | 1.000 | 30 |
| recon | 1.000 | 1.000 | 1.000 | 37 |

| true \ predicted | benign | bruteforce | flood | recon |
|---|---|---|---|---|
| benign | 100 | 0 | 0 | 0 |
| bruteforce | 3 | 31 | 0 | 0 |
| flood | 0 | 0 | 30 | 0 |
| recon | 0 | 0 | 0 | 37 |

## 8. Safety verification

| attempted target | decision | detail |
|---|---|---|
| `8.8.8.8:18081` | DENIED | target '8.8.8.8' resolves to non-allowlisted address(es) ['8.8.8.8'] |
| `10.0.0.5:18081` | DENIED | target '10.0.0.5' resolves to non-allowlisted address(es) ['10.0.0.5'] |
| `192.168.1.1:18082` | DENIED | target '192.168.1.1' resolves to non-allowlisted address(es) ['192.168.1.1'] |
| `127.0.0.2:18081` | DENIED | target '127.0.0.2' resolves to non-allowlisted address(es) ['127.0.0.2'] |
| `example.com:18082` | DENIED | target 'example.com' resolves to non-allowlisted address(es) ['104.20.23.154', '172.66.147.243', '2606:4700:90c5:72db:f2ef:33:ef6b:ff98'] |
| `localhost:18081` | DENIED | target 'localhost' resolves to non-allowlisted address(es) ['::1'] |
| `127.0.0.1:22` | DENIED | port 22 not in laboratory port allowlist |
| `127.0.0.1;rm -rf /:18081` | DENIED | malformed target '127.0.0.1;rm -rf /' |
| `127.0.0.1:18081` | ALLOWED | 127.0.0.1 |
| `scenario->8.8.8.8 (active=True)` | DENIED before any connection | TargetNotAllowed: target '8.8.8.8' resolves to non-allowlisted address(es) ['8.8.8.8'] |
| `scenario->127.0.0.1 (active=False)` | DENIED before any connection | ActiveLabDisabled: active laboratory scenarios are disabled (opt-in: SAGE_ENABLE_ACTIVE_LAB=1) |

- Audit hash chain: valid=True, entries checked=111.
- Tamper test on a copy: modified entry 55 → valid=False, broken at id 55.

## 9. Resource use

- wall_s: 1606.3
- cpu_user_s: 51.5
- cpu_system_s: 43.0
- rss_mb: 259.9
- RSS during final test: 257.2 MB

## 10. Threats to validity and limitations

- **Laboratory realism.** Targets are loopback services; telemetry comes from an application-level sensor, not packet capture; benign traffic is synthetic. Absolute rates do not transfer to production networks.
- **Scenario scope.** Three reviewed, bounded scenarios with parameters randomised inside reviewed bounds. No adaptive or evasive attacker is modelled; a candidate that passes here may fail against one.
- **Sample size.** Trials per phase are finite; use the reported confidence intervals, not point estimates.
- **Behaviourally undetectable trials.** Password guessing that succeeds within the first ~2 attempts is indistinguishable from benign typos; such trials cap achievable detection for that scenario.
- **Single realisation.** One run with one base seed; repeat with other `base_seed` values for run-to-run variance.
- **Scripted operator.** Approvals and the order in which candidates were tried were fixed in advance by the experiment script; they are not independent human judgements.
- **Threat-intel fixtures.** Unless run with live intelligence, findings are synthetic fixtures (SYNTH- IDs) used to exercise the mapping logic; matches are weakness-class/technique matches, not product matches.
- **Detection ≠ prevention.** Alerts show detection only; prevention is measured by the separately recorded security-effect outcome.
- **Benchmark separation.** CICIDS2017 results (if run) come from a separate model and schema and are not comparable to laboratory numbers.
