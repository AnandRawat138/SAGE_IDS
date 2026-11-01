# Development notes: decisions made during implementation

This file records design changes made **after** observing smoke-test behaviour and **before** the
measured experiment, so that readers can judge whether any of them tuned the experiment toward a
desired outcome. All smoke-test databases were discarded. The measured report comes from a fresh run.

| # | Observation in smoke test | Change | Rationale (outcome-independent) |
|---|---|---|---|
| 1 | Attack telemetry missing from windows | `start_phase()` drains the sensor once per phase, not once per sub-batch | bug: telemetry captured before benign rounds was being discarded |
| 2 | With 8 trials per phase, the Wilson lower bound can never reach the 0.70 policy (8/8 → LCB 0.68) | default trials per phase raised to 30 | sample-size requirement implied by the a-priori policy; the policy itself was not changed |
| 3 | Short attacks split across 5 s tumbling-window boundaries | threshold rules evaluated on a per-source **sliding** window using identical feature definitions; remediation calibrates thresholds on sliding-window benign maxima | standard streaming-IDS practice; also gives a meaningful online latency |
| 4 | Benign generator sent "monitoring checks" to decoy ports, so benign windows looked like reconnaissance | benign health checks now call the application's `/health` endpoint | deception-lab convention: decoys receive no legitimate traffic by definition |
| 5 | Isolation Forest was not trained when the calibration had < 20 benign windows | bootstrap uses `benign_windows_per_phase + 4` calibration rounds | the IF needs a minimum benign sample; the threshold rule (99th percentile of benign scores) is unchanged |
| 6 | Tamper check failed on Windows (file lock), and `shutil.copy` is not WAL-safe | SQLite backup API plus engine disposal | correctness |
| 7 | Active-lab refusal moved a case to `failed` | the opt-in check happens before claiming the case | a refused run should not consume the case |
| 8 | The reconnaissance case (C) confirmed a weakness, but the script had no candidate order for it, so it stopped at `remediation_proposed` | added the order `[calibrated rule, retrain]` for case C | the script must drive every confirmed weakness to a decision; the order mirrors case A without the deliberately unsuitable candidate |

## Changes made after the first full measured run (`experiment_20261030T161736Z`)

That run is kept, unedited, in `reports/superseded_run_20261030T161736Z/`. It revealed two protocol flaws.
Both were fixed, and the whole experiment was re-run from scratch.

| # | Observation | Change | Rationale |
|---|---|---|---|
| 9 | Recon case: v1 already detected 30/30 probes, but the probe's effect occurred in 21/30, so the weakness was *preventive*. The frozen criteria still required a ≥0.30 detection gain, which no candidate can satisfy. The case also stalled because the script had no rule for an exhausted candidate order | criteria now carry an `objective` derived from the confirmed weakness type: **detection** (the previous criteria, unchanged) or **prevention** (effect-rate reduction ≥0.30, one-sided Fisher p<0.05, detection non-inferior). The scripted operator rejects a case when its pre-declared candidate order is exhausted | the old criteria were unsatisfiable by construction for preventive weaknesses; the detection-objective thresholds are unchanged |
| 10 | Each candidate of a case was retested on different seeds (seed depended on the adaptation cycle). Candidate 2 of case A happened to draw six trials with ≤3 attempts (undetectable by any behavioural rule) versus one for candidate 3, so the comparison between candidates was confounded by sampling | all candidates of a case are retested on the **same** retest seeds (common random numbers) | standard variance reduction for comparing alternatives; no candidate is built from retest data, and selection bias is checked on the disjoint held-out final test |

## Environmental issue in the second full run (`experiment_20261030T164052Z`)

| # | Observation | Change | Rationale |
|---|---|---|---|
| 11 | The host suspended during case 1's first retest (one benign round lasted 431 s; gaps of 45 min and 21 h) | added an automatic **timing-integrity check** to the report: it flags runs longer than 3× their budget, and gaps over 120 s between runs. The run was archived (`reports/superseded_run_20261030T164052Z_host_suspend/`) and re-run on an awake host with identical code | measurements taken across a suspend are unreliable; the check makes this visible in any future report |

## Benchmark pipeline (first run on the real CICIDS2017 files)

| # | Observation | Change | Rationale |
|---|---|---|---|
| 12 | With 2.4 GB of free RAM, the full dataset could not be held through cleaning and splitting | features loaded as float32, single-mask cleaning, plus a documented uniform subsample of 150,000 rows per CSV (`--max-rows`, recorded in the results). Once enough memory was free, the **full dataset** was run and is now the primary result; the subsample results are kept in `reports/benchmark_subsample_150k/` | memory constraint of the build machine at the time |
| 13 | The leakage guard aborted the run: 2 "identical" rows in train and validation | root cause: `DataFrame.round(9)` on float32 columns corrupts large values (32036248 → 32036246), so distinct rows hashed equal. The row hash now uses exact values (float64-widened, -0.0 folded); regression test added | the guard over-reported and never missed a real leak; deduplication itself was correct |
| 14 | Web-attack labels kept the mis-encoded dash (`ï¿½`) | label normalisation regex fixed; the stratified run was repeated with the same seeds | cosmetic: the labels were consistent across splits, so the metrics are identical |

The acceptance policy (`configs/acceptance_policy.yaml`), the scenario catalogue, the parameter
bounds, the detection-objective thresholds and the candidate orders for cases A and B were **not**
changed after observing results (see rows 8–10).
