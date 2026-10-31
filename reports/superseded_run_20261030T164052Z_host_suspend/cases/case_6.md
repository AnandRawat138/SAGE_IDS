# SAGE-IDS case report — case 6

*Generated 2026-10-31T14:44:19Z by the deterministic Explanation Agent. Tags: [OBS] recorded observation, [INF] rule-based inference, [UNC] uncertainty/limitation.*

**Final/current state:** `rejected`

## 1. Source finding
- [OBS] Source `mitre_attack` record `T1046` — Network Service Discovery (data origin: **synthetic_fixture**).
- [OBS] Published: 2020-01-01 00:00:00; first retrieved: 2026-10-30 16:42:52.052823; newly published (≤30 d): False; newly retrieved: True.
- [OBS] Weakness classes: —; techniques: T1046; CVSS: —.
- [OBS] Provenance: `fixture://attack_fixture.json` sha256 `8ef3a8190c6f85fd…`; retrieved content was handled as untrusted data and never executed.

## 2. Applicable laboratory asset
- [INF] Asset `lab-decoy-host` matched by attack_technique=T1046; candidate scenarios: recon-tcp-probe.
- [UNC] lab assets are analogues; a CWE/technique match is not a product vulnerability match.

## 3. Scenario and approval
- [OBS] Scenario `recon-tcp-probe` on asset `lab-decoy-host`.
- [OBS] Approved by `operator:demo-script` at 2026-10-31 14:38:33.342820 (transition:35).

## 4. Baseline test (accepted version v4)
- [OBS] Trials: 30; executed: 30 (runs 316–345).
- [OBS] Security effect achieved: 21/30 = 0.700 [95% CI 0.521-0.833].
- [OBS] IDS detection: 30/30 = 1.000 [95% CI 0.886-1.000]; latency median 2.06 s (min 0.22, max 5.12, n=30).
- [OBS] Benign windows: 63, alerting: 0; benign requests denied: 0/474.
- [OBS] Previously passed scenarios (regression set): auth-password-guessing, app-request-flood.
- [OBS] Service health after phase: {'login': True, 'test_app': True}.

- [INF] Decision `remediation_proposed`: prevention weakness confirmed by baseline evidence; acceptance objective: prevention — evidence {'detection_gap': 0.0, 'effect_rate': 0.7, 'n_executed': 30, 'detection_weakness': False, 'prevention_weakness': True, 'objective': 'prevention'} (transition:38).

## 5. Frozen acceptance criteria
- [OBS] Derived from the measured baseline and hash-committed before any candidate was evaluated: `fec0626892d7fb96d169ea7332861ae594af4156e16a874756873102e91cdb1c`.
- [OBS] trigger gain ≥ 0.3, McNemar p < 0.05, detection Wilson LCB ≥ 0.7; regression margin 0.1; benign FPR ≤ 0.0200; benign denied ≤ 0.0100; effect may not increase (+0.1); service health required.

## 6. Remediation proposals
- [OBS] Proposal 9 — **Calibrated threshold rule on n_distinct_dst_ports (>= 3)** — status `rejected`, candidate version 5.
  - Rationale [INF]: Baseline test confirmed a detection gap for recon-tcp-probe. Threshold = max sliding-window n_distinct_dst_ports over the verified benign calibration traffic (2; 94 windows) plus margin. Pre-check (calibration data, not acceptance data): benign FPR 0.000, coverage of baseline attack windows 0.647.
  - Rollback: remove rule SAGE-RECON-6 (re-activate parent version 4)
- [OBS] Proposal 10 — **Maximum-sensitivity rule on n_distinct_dst_ports (>= 1)** — status `proposed`.
  - Rationale [INF]: Sensitivity-first alternative. Pre-check predicts benign FPR 1.000 on calibration windows; it is expected to fail the benign FPR criterion and is included so the gate is exercised on a plausible but unsuitable fix.
  - Rollback: remove rule SAGE-RECON-6-S
- [OBS] Proposal 11 — **Retrain Random Forest with verified labels from executed baseline trials** — status `rejected`, candidate version 6.
  - Rationale [INF]: Adds 34 verified 'recon' windows from 30 executed baseline trials (ground truth by construction) to the parent's verified training set. Retest uses fresh seeds.
  - Rollback: re-activate parent version 4 (previous model artifact retained)

## 7.4 Retest of candidate v5 (evaluation:4) — **FAILED**
- [OBS] Fresh-seed trials: 30, executed 30; effect 21/30 = 0.700 [95% CI 0.521-0.833].
- [OBS] Detection on identical retest telemetry — baseline v4: 27/30 = 0.900 [95% CI 0.744-0.965]; candidate v5: 27/30 = 0.900 [95% CI 0.744-0.965]; candidate latency median 1.06 s (min 0.03, max 4.40, n=27).

| criterion | measured | required | result |
|---|---|---|---|
| effect_rate_reduction | 0.0000 | >= 0.3 | FAIL |
| effect_fisher_p | 0.6106 | < 0.05 | FAIL |
| trigger_detection_noninferior | 0.9000 | >= 0.900 - 0.1 | pass |
| regression:auth-password-guessing | 1.0000 | >= 1.000 - 0.1 | pass |
| regression:app-request-flood | 1.0000 | >= 1.000 - 0.1 | pass |
| benign_fpr | 0.0000 | <= 0.02 | pass |
| benign_denied_rate | 0.0000 | <= 0.01 | pass |
| service_health | {'login': True, 'test_app': True} | all healthy | pass |

## 7.5 Retest of candidate v6 (evaluation:5) — **FAILED**
- [OBS] Fresh-seed trials: 30, executed 30; effect 21/30 = 0.700 [95% CI 0.521-0.833].
- [OBS] Detection on identical retest telemetry — baseline v4: 27/30 = 0.900 [95% CI 0.744-0.965]; candidate v6: 27/30 = 0.900 [95% CI 0.744-0.965]; candidate latency median 2.47 s (min 0.05, max 5.81, n=27).

| criterion | measured | required | result |
|---|---|---|---|
| effect_rate_reduction | 0.0000 | >= 0.3 | FAIL |
| effect_fisher_p | 0.6106 | < 0.05 | FAIL |
| trigger_detection_noninferior | 0.9000 | >= 0.900 - 0.1 | pass |
| regression:auth-password-guessing | 1.0000 | >= 1.000 - 0.1 | pass |
| regression:app-request-flood | 1.0000 | >= 1.000 - 0.1 | pass |
| benign_fpr | 0.0000 | <= 0.02 | pass |
| benign_denied_rate | 0.0000 | <= 0.01 | pass |
| service_health | {'login': True, 'test_app': True} | all healthy | pass |

## 8. Outcome
- [OBS] Last transition: `remediation_proposed` → `rejected` by `operator:demo-script` — no remaining proposal in the pre-declared candidate order (transition:45, audit hash `12ff9146d65fb103…`).

## 9. Uncertainty and limitations
- [UNC] An alert demonstrates detection, not prevention; prevention is assessed only through the separately recorded security-effect outcome.
- [UNC] Laboratory = loopback services with an application-level sensor and a synthetic benign generator; results do not transfer to production networks without re-validation.
- [UNC] Confidence intervals reflect the number of trials only; they do not cover adaptive attackers or behaviours outside the reviewed scenario parameters.
