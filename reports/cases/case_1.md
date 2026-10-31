# SAGE-IDS case report — case 1

*Generated 2026-10-31T14:59:20Z by the deterministic Explanation Agent. Tags: [OBS] recorded observation, [INF] rule-based inference, [UNC] uncertainty/limitation.*

**Final/current state:** `accepted`

## 1. Source finding
- [OBS] Source `nvd` record `SYNTH-2026-0001` — SYNTH-2026-0001 (data origin: **synthetic_fixture**).
- [OBS] Published: 2026-10-21 04:45:00; first retrieved: 2026-10-31 14:54:53.836240; newly published (≤30 d): True; newly retrieved: True.
- [OBS] Weakness classes: CWE-307; techniques: T1110, T1110.001; CVSS: 7.5.
- [OBS] Provenance: `fixture://nvd_fixture.json` sha256 `d0899b0b3d09569c…`; retrieved content was handled as untrusted data and never executed.

## 2. Applicable laboratory asset
- [INF] Asset `lab-login-service` matched by cwe_class=CWE-307; attack_technique=T1110,T1110.001; candidate scenarios: auth-password-guessing.
- [UNC] lab assets are analogues; a CWE/technique match is not a product vulnerability match.

## 3. Scenario and approval
- [OBS] Scenario `auth-password-guessing` on asset `lab-login-service`.
- [OBS] Approved by `operator:demo-script` at 2026-10-31 14:54:53.871596 (transition:16).

## 4. Baseline test (accepted version v1)
- [OBS] Trials: 30; executed: 30 (runs 31–60).
- [OBS] Security effect achieved: 30/30 = 1.000 [95% CI 0.886-1.000].
- [OBS] IDS detection: 0/30 = 0.000 [95% CI 0.000-0.114]; latency n/a (no detections).
- [OBS] Benign windows: 67, alerting: 0; benign requests denied: 0/551.
- [OBS] Previously passed scenarios (regression set): recon-tcp-probe.
- [OBS] Service health after phase: {'login': True, 'test_app': True}.

- [INF] Decision `remediation_proposed`: detection and prevention weakness confirmed by baseline evidence; acceptance objective: detection — evidence {'detection_gap': 1.0, 'effect_rate': 1.0, 'n_executed': 30, 'detection_weakness': True, 'prevention_weakness': True, 'objective': 'detection'} (transition:19).

## 5. Frozen acceptance criteria
- [OBS] Derived from the measured baseline and hash-committed before any candidate was evaluated: `dd4b16654bcfc171a49e40a9131dc86909cbc07b1600d6cae445d3d2e380ba2a`.
- [OBS] trigger gain ≥ 0.3, McNemar p < 0.05, detection Wilson LCB ≥ 0.7; regression margin 0.1; benign FPR ≤ 0.0200; benign denied ≤ 0.0100; effect may not increase (+0.1); service health required.

## 6. Remediation proposals
- [OBS] Proposal 1 — **Calibrated threshold rule on n_auth_fail (>= 3)** — status `proposed`.
  - Rationale [INF]: Baseline test confirmed a detection gap for auth-password-guessing. Threshold = max sliding-window n_auth_fail over the verified benign calibration traffic (2; 108 windows) plus margin. Pre-check (calibration data, not acceptance data): benign FPR 0.000, coverage of baseline attack windows 0.818.
  - Rollback: remove rule SAGE-BRUTEFORCE-1 (re-activate parent version 1)
- [OBS] Proposal 2 — **Maximum-sensitivity rule on n_auth_fail (>= 1)** — status `rejected`, candidate version 2.
  - Rationale [INF]: Sensitivity-first alternative. Pre-check predicts benign FPR 0.167 on calibration windows; it is expected to fail the benign FPR criterion and is included so the gate is exercised on a plausible but unsuitable fix.
  - Rollback: remove rule SAGE-BRUTEFORCE-1-S
- [OBS] Proposal 3 — **Calibrated rule + lab service hardening (login_lockout_threshold=5)** — status `accepted`, candidate version 3.
  - Rationale [INF]: Detection alone does not prevent the effect. Adds bounded lab service hardening; lockout after 5 failures per account for 300 s.
  - Rollback: remove rule SAGE-BRUTEFORCE-1; restore login_lockout_threshold to parent value None
- [OBS] Proposal 4 — **Retrain Random Forest with verified labels from executed baseline trials** — status `proposed`.
  - Rationale [INF]: Adds 33 verified 'bruteforce' windows from 30 executed baseline trials (ground truth by construction) to the parent's verified training set. Retest uses fresh seeds.
  - Rollback: re-activate parent version 1 (previous model artifact retained)

## 7.1 Retest of candidate v2 (evaluation:1) — **FAILED**
- [OBS] Fresh-seed trials: 30, executed 30; effect 30/30 = 1.000 [95% CI 0.886-1.000].
- [OBS] Detection on identical retest telemetry — baseline v1: 0/30 = 0.000 [95% CI 0.000-0.114]; candidate v2: 30/30 = 1.000 [95% CI 0.886-1.000]; candidate latency median 0.00 s (min 0.00, max 0.02, n=30).

| criterion | measured | required | result |
|---|---|---|---|
| trigger_detection_gain | 1.0000 | >= 0.3 | pass |
| trigger_mcnemar_p | 0.0000 | < 0.05 | pass |
| trigger_detection_rate_lcb | 0.8865 | >= 0.7 | pass |
| effect_rate_not_increased | 1.0000 | <= 1.000 + 0.1 | pass |
| regression:recon-tcp-probe | 1.0000 | >= 1.000 - 0.1 | pass |
| benign_fpr | 0.1667 | <= 0.02 | FAIL |
| benign_denied_rate | 0.0000 | <= 0.01 | pass |
| service_health | {'login': True, 'test_app': True} | all healthy | pass |

## 7.2 Retest of candidate v3 (evaluation:2) — **PASSED**
- [OBS] Fresh-seed trials: 30, executed 30; effect 5/30 = 0.167 [95% CI 0.073-0.336].
- [OBS] Detection on identical retest telemetry — baseline v1: 0/30 = 0.000 [95% CI 0.000-0.114]; candidate v3: 28/30 = 0.933 [95% CI 0.787-0.982]; candidate latency median 0.08 s (min 0.00, max 0.14, n=28).

| criterion | measured | required | result |
|---|---|---|---|
| trigger_detection_gain | 0.9333 | >= 0.3 | pass |
| trigger_mcnemar_p | 0.0000 | < 0.05 | pass |
| trigger_detection_rate_lcb | 0.7868 | >= 0.7 | pass |
| effect_rate_not_increased | 0.1667 | <= 1.000 + 0.1 | pass |
| regression:recon-tcp-probe | 1.0000 | >= 1.000 - 0.1 | pass |
| benign_fpr | 0.0000 | <= 0.02 | pass |
| benign_denied_rate | 0.0000 | <= 0.01 | pass |
| service_health | {'login': True, 'test_app': True} | all healthy | pass |

## 8. Outcome
- [OBS] Last transition: `acceptance_pending` → `accepted` by `operator:demo-script` — operator accepted validated candidate (transition:26, audit hash `e15095bc30ff6e7e…`).
- [OBS] Version v3 (`40c43bf96a352dbc…`) activated by `operator:demo-script`; the previous accepted version remains available for rollback.
- [INF] The accepted change improved detection of the triggering scenario under the tested lab conditions without violating the frozen regression, benign-traffic and health criteria.

## 9. Uncertainty and limitations
- [UNC] An alert demonstrates detection, not prevention; prevention is assessed only through the separately recorded security-effect outcome.
- [UNC] Laboratory = loopback services with an application-level sensor and a synthetic benign generator; results do not transfer to production networks without re-validation.
- [UNC] Confidence intervals reflect the number of trials only; they do not cover adaptive attackers or behaviours outside the reviewed scenario parameters.
