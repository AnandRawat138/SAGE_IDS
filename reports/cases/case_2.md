# SAGE-IDS case report — case 2

*Generated 2026-10-31T15:02:08Z by the deterministic Explanation Agent. Tags: [OBS] recorded observation, [INF] rule-based inference, [UNC] uncertainty/limitation.*

**Final/current state:** `accepted`

## 1. Source finding
- [OBS] Source `nvd` record `SYNTH-2026-0002` — SYNTH-2026-0002 (data origin: **synthetic_fixture**).
- [OBS] Published: 2026-10-18 03:30:00; first retrieved: 2026-10-31 14:54:53.839241; newly published (≤30 d): True; newly retrieved: True.
- [OBS] Weakness classes: CWE-770; techniques: T1499, T1499.002; CVSS: 6.5.
- [OBS] Provenance: `fixture://nvd_fixture.json` sha256 `d0899b0b3d09569c…`; retrieved content was handled as untrusted data and never executed.

## 2. Applicable laboratory asset
- [INF] Asset `lab-test-app` matched by cwe_class=CWE-770; attack_technique=T1499,T1499.002; candidate scenarios: app-request-flood.
- [UNC] lab assets are analogues; a CWE/technique match is not a product vulnerability match.

## 3. Scenario and approval
- [OBS] Scenario `app-request-flood` on asset `lab-test-app`.
- [OBS] Approved by `operator:demo-script` at 2026-10-31 14:59:20.720634 (transition:27).

## 4. Baseline test (accepted version v3)
- [OBS] Trials: 30; executed: 30 (runs 199–228).
- [OBS] Security effect achieved: 30/30 = 1.000 [95% CI 0.886-1.000].
- [OBS] IDS detection: 0/30 = 0.000 [95% CI 0.000-0.114]; latency n/a (no detections).
- [OBS] Benign windows: 64, alerting: 0; benign requests denied: 0/514.
- [OBS] Previously passed scenarios (regression set): recon-tcp-probe.
- [OBS] Service health after phase: {'login': True, 'test_app': True}.

- [INF] Decision `remediation_proposed`: detection and prevention weakness confirmed by baseline evidence; acceptance objective: detection — evidence {'detection_gap': 1.0, 'effect_rate': 1.0, 'n_executed': 30, 'detection_weakness': True, 'prevention_weakness': True, 'objective': 'detection'} (transition:30).

## 5. Frozen acceptance criteria
- [OBS] Derived from the measured baseline and hash-committed before any candidate was evaluated: `7504ec9b76885234a4e00724a9a1b8a17ee64feacee472eca81c6e3ff54ab65c`.
- [OBS] trigger gain ≥ 0.3, McNemar p < 0.05, detection Wilson LCB ≥ 0.7; regression margin 0.1; benign FPR ≤ 0.0200; benign denied ≤ 0.0100; effect may not increase (+0.1); service health required.

## 6. Remediation proposals
- [OBS] Proposal 5 — **Calibrated threshold rule on req_rate (>= 29.93)** — status `proposed`.
  - Rationale [INF]: Baseline test confirmed a detection gap for app-request-flood. Threshold = max sliding-window req_rate over the verified benign calibration traffic (23.1476; 108 windows) plus margin. Pre-check (calibration data, not acceptance data): benign FPR 0.000, coverage of baseline attack windows 1.000.
  - Rollback: remove rule SAGE-FLOOD-2 (re-activate parent version 3)
- [OBS] Proposal 6 — **Maximum-sensitivity rule on req_rate (>= 1)** — status `proposed`.
  - Rationale [INF]: Sensitivity-first alternative. Pre-check predicts benign FPR 1.000 on calibration windows; it is expected to fail the benign FPR criterion and is included so the gate is exercised on a plausible but unsuitable fix.
  - Rollback: remove rule SAGE-FLOOD-2-S
- [OBS] Proposal 7 — **Calibrated rule + lab service hardening (app_rate_limit_rps=29)** — status `proposed`.
  - Rationale [INF]: Detection alone does not prevent the effect. Adds bounded lab service hardening; per-source rate limit at 1.5x the peak benign per-second request count (29 rps).
  - Rollback: remove rule SAGE-FLOOD-2; restore app_rate_limit_rps to parent value None
- [OBS] Proposal 8 — **Retrain Random Forest with verified labels from executed baseline trials** — status `accepted`, candidate version 4.
  - Rationale [INF]: Adds 30 verified 'flood' windows from 30 executed baseline trials (ground truth by construction) to the parent's verified training set. Retest uses fresh seeds.
  - Rollback: re-activate parent version 3 (previous model artifact retained)

## 7.3 Retest of candidate v4 (evaluation:3) — **PASSED**
- [OBS] Fresh-seed trials: 30, executed 30; effect 30/30 = 1.000 [95% CI 0.886-1.000].
- [OBS] Detection on identical retest telemetry — baseline v3: 0/30 = 0.000 [95% CI 0.000-0.114]; candidate v4: 30/30 = 1.000 [95% CI 0.886-1.000]; candidate latency median 2.27 s (min 0.10, max 4.94, n=30).

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

## 8. Outcome
- [OBS] Last transition: `acceptance_pending` → `accepted` by `operator:demo-script` — operator accepted validated candidate (transition:34, audit hash `05e88bf46bd33d24…`).
- [OBS] Version v4 (`ebd629ad91d46787…`) activated by `operator:demo-script`; the previous accepted version remains available for rollback.
- [INF] The accepted change improved detection of the triggering scenario under the tested lab conditions without violating the frozen regression, benign-traffic and health criteria.

## 9. Uncertainty and limitations
- [UNC] An alert demonstrates detection, not prevention; prevention is assessed only through the separately recorded security-effect outcome.
- [UNC] Laboratory = loopback services with an application-level sensor and a synthetic benign generator; results do not transfer to production networks without re-validation.
- [UNC] Confidence intervals reflect the number of trials only; they do not cover adaptive attackers or behaviours outside the reviewed scenario parameters.
