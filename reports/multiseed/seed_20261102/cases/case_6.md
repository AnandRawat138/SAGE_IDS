# SAGE-IDS case report — case 6

*Generated 2026-11-01T06:41:26Z by the deterministic Explanation Agent. Tags: [OBS] recorded observation, [INF] rule-based inference, [UNC] uncertainty/limitation.*

**Final/current state:** `rejected`

## 1. Source finding
- [OBS] Source `mitre_attack` record `T1046` — Network Service Discovery (data origin: **synthetic_fixture**).
- [OBS] Published: 2020-01-01 00:00:00; first retrieved: 2026-11-01 06:19:28.759481; newly published (≤30 d): False; newly retrieved: True.
- [OBS] Weakness classes: —; techniques: T1046; CVSS: —.
- [OBS] Provenance: `fixture://attack_fixture.json` sha256 `8ef3a8190c6f85fd…`; retrieved content was handled as untrusted data and never executed.

## 2. Applicable laboratory asset
- [INF] Asset `lab-decoy-host` matched by attack_technique=T1046; candidate scenarios: recon-tcp-probe.
- [UNC] lab assets are analogues; a CWE/technique match is not a product vulnerability match.

## 3. Scenario and approval
- [OBS] Scenario `recon-tcp-probe` on asset `lab-decoy-host`.
- [OBS] Approved by `operator:demo-script` at 2026-11-01 06:27:40.249068 (transition:35).

## 4. Baseline test (accepted version v4)
- [OBS] Trials: 30; executed: 30 (runs 331–360).
- [OBS] Security effect achieved: 24/30 = 0.800 [95% CI 0.627-0.905].
- [OBS] IDS detection: 30/30 = 1.000 [95% CI 0.886-1.000]; latency median 2.56 s (min 0.49, max 5.60, n=30).
- [OBS] Benign windows: 63, alerting: 0; benign requests denied: 0/502.
- [OBS] Previously passed scenarios (regression set): auth-password-guessing, app-request-flood.
- [OBS] Service health after phase: {'login': True, 'test_app': True}.

- [INF] Decision `remediation_proposed`: prevention weakness confirmed by baseline evidence; acceptance objective: prevention — evidence {'detection_gap': 0.0, 'effect_rate': 0.8, 'n_executed': 30, 'detection_weakness': False, 'prevention_weakness': True, 'objective': 'prevention'} (transition:38).

## 5. Frozen acceptance criteria
- [OBS] Derived from the measured baseline and hash-committed before any candidate was evaluated: `ec337db5da8459d063cd1e38b01d67fbd3a83893b34122e4c37d96b4bff38f70`.
- [OBS] trigger gain ≥ 0.3, McNemar p < 0.05, detection Wilson LCB ≥ 0.7; regression margin 0.1; benign FPR ≤ 0.0200; benign denied ≤ 0.0100; effect may not increase (+0.1); service health required.

## 6. Remediation proposals
- [OBS] Proposal 9 — **Calibrated threshold rule on n_distinct_dst_ports (>= 3)** — status `rejected`, candidate version 5.
  - Rationale [INF]: Baseline test confirmed a detection gap for recon-tcp-probe. Threshold = max sliding-window n_distinct_dst_ports over the verified benign calibration traffic (2; 97 windows) plus margin. Pre-check (calibration data, not acceptance data): benign FPR 0.000, coverage of baseline attack windows 0.694.
  - Rollback: remove rule SAGE-RECON-6 (re-activate parent version 4)
- [OBS] Proposal 10 — **Maximum-sensitivity rule on n_distinct_dst_ports (>= 1)** — status `proposed`.
  - Rationale [INF]: Sensitivity-first alternative. Pre-check predicts benign FPR 1.000 on calibration windows; it is expected to fail the benign FPR criterion and is included so the gate is exercised on a plausible but unsuitable fix.
  - Rollback: remove rule SAGE-RECON-6-S
- [OBS] Proposal 11 — **Retrain Random Forest with verified labels from executed baseline trials** — status `rejected`, candidate version 6.
  - Rationale [INF]: Adds 36 verified 'recon' windows from 30 executed baseline trials (ground truth by construction) to the parent's verified training set. Retest uses fresh seeds.
  - Rollback: re-activate parent version 4 (previous model artifact retained)

## 7.4 Retest of candidate v5 (evaluation:4) — **FAILED**
- [OBS] Fresh-seed trials: 30, executed 30; effect 19/30 = 0.633 [95% CI 0.455-0.781].
- [OBS] Detection on identical retest telemetry — baseline v4: 29/30 = 0.967 [95% CI 0.833-0.994]; candidate v5: 29/30 = 0.967 [95% CI 0.833-0.994]; candidate latency median 1.37 s (min 0.02, max 5.20, n=29).

| criterion | measured | required | result |
|---|---|---|---|
| effect_rate_reduction | 0.1667 | >= 0.3 | FAIL |
| effect_fisher_p | 0.1258 | < 0.05 | FAIL |
| trigger_detection_noninferior | 0.9667 | >= 0.967 - 0.1 | pass |
| regression:auth-password-guessing | 0.6667 | >= 0.667 - 0.1 | pass |
| regression:app-request-flood | 1.0000 | >= 1.000 - 0.1 | pass |
| benign_fpr | 0.0000 | <= 0.02 | pass |
| benign_denied_rate | 0.0000 | <= 0.01 | pass |
| service_health | {'login': True, 'test_app': True} | all healthy | pass |

## 7.5 Retest of candidate v6 (evaluation:5) — **FAILED**
- [OBS] Fresh-seed trials: 30, executed 30; effect 19/30 = 0.633 [95% CI 0.455-0.781].
- [OBS] Detection on identical retest telemetry — baseline v4: 29/30 = 0.967 [95% CI 0.833-0.994]; candidate v6: 29/30 = 0.967 [95% CI 0.833-0.994]; candidate latency median 2.34 s (min 0.41, max 5.77, n=29).

| criterion | measured | required | result |
|---|---|---|---|
| effect_rate_reduction | 0.1667 | >= 0.3 | FAIL |
| effect_fisher_p | 0.1258 | < 0.05 | FAIL |
| trigger_detection_noninferior | 0.9667 | >= 0.967 - 0.1 | pass |
| regression:auth-password-guessing | 0.6667 | >= 0.667 - 0.1 | pass |
| regression:app-request-flood | 1.0000 | >= 1.000 - 0.1 | pass |
| benign_fpr | 0.0000 | <= 0.02 | pass |
| benign_denied_rate | 0.0000 | <= 0.01 | pass |
| service_health | {'login': True, 'test_app': True} | all healthy | pass |

## 8. Outcome
- [OBS] Last transition: `remediation_proposed` → `rejected` by `operator:demo-script` — no remaining proposal in the pre-declared candidate order (transition:45, audit hash `d2da4dafcb5f60ed…`).

## 9. Uncertainty and limitations
- [UNC] An alert demonstrates detection, not prevention; prevention is assessed only through the separately recorded security-effect outcome.
- [UNC] Laboratory = loopback services with an application-level sensor and a synthetic benign generator; results do not transfer to production networks without re-validation.
- [UNC] Confidence intervals reflect the number of trials only; they do not cover adaptive attackers or behaviours outside the reviewed scenario parameters.
