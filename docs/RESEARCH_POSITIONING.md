# Research positioning: claimed contributions and what a journal submission still needs

This note separates what the prototype **implements and measures** from what a reviewer at an
IEEE Transactions venue (for example TIFS, TDSC or TNSM) would additionally expect. A strong system
cannot guarantee acceptance. The goal here is to make the claims defensible.

## Candidate contributions (implemented)

1. **Evidence-gated self-evolution.** IDS adaptation is a bounded, persistent state machine in which
   every change must pass criteria that are derived from a measured baseline, then **frozen and
   SHA-256 committed before any candidate is evaluated**. This is a form of experimental
   pre-registration enforced in code. Criteria include a paired McNemar test on identical retest
   traffic, a Wilson lower bound, non-inferiority on previously passed scenarios, a benign-FPR bound,
   a service-impact bound and a security-effect bound. Operator acceptance is still required.
2. **Tri-outcome validation ledger.** Each adversarial trial records *executed*, *security effect
   achieved* and *detected* separately. This lets the evaluation distinguish prevention (effect
   suppressed by hardening) from detection (alert raised). The two are routinely conflated in IDS
   evaluations.
3. **Ground-truth-by-construction labelling with a measured poisoning counterfactual.** Only windows
   attributable to an executed scenario run or the benign generator can be used for retraining.
   The held-out test compares this against *naive self-training*, which uses pseudo-labels from the
   current model. That variant cannot learn attacks the current model misses (confirmation bias).
4. **Untrusted-intelligence isolation.** NVD and ATT&CK content is treated as data. Mapping to
   actions is deterministic (CWE → technique → reviewed scenario). An LLM, if enabled, can only
   choose IDs from a closed set, and the allowlist is enforced on every socket connect.
5. **Honest dual-model design.** The benchmark model (CICIDS2017 schema) and the laboratory model
   (runtime-reproducible lab-v1 schema) are kept separate. Schema incompatibility is detected and
   reported, never silently patched.

Novelty claims must be checked against the related-work literature by the team: automated
adversary emulation (e.g. MITRE CALDERA), adversarial/continual learning for NIDS, LLM-based
security agents, and closed-loop "purple teaming". The defensible angle is the **validation
protocol and its guarantees**, not "an agent that attacks and patches".

## Evidence the prototype produces

* `reports/experiment_report.md`: one full run of the protocol on the loopback lab. It covers
  baseline gaps, rejected and accepted candidates with every criterion, the held-out test of all
  versions and ablations (window P/R/F1/FPR with CIs, per-scenario detection, latency,
  confusion matrices, McNemar tests), safety checks and audit-tamper detection.
* `sage-ids benchmark`: CICIDS2017 with dedup-before-split, train-only preprocessing,
  validation-selected thresholds, cross-split leakage assertions and multiple seeds. **This was not
  run in the build environment because the dataset was not downloaded.**

## Gaps a journal reviewer will raise (and how to close them)

| Gap | Why it matters | How to close |
|---|---|---|
| Loopback lab with an app-level sensor | external validity | run the Docker/VM lab with Zeek + Suricata on real services (e.g. OpenSSH, nginx, a real web app) |
| Synthetic benign traffic | FPR realism | replay benign traffic from CICIDS2017 Monday or a real capture through the lab; report FPR on it |
| Three scenarios, no adaptive attacker | generality, robustness | add more catalogue scenarios plus an evasion study (slow guessing, distributed sources) against accepted versions |
| One experiment realisation | variance | run `sage-ids experiment` with ≥5 `base_seed` values; report mean ± CI across runs |
| Scripted operator | human factors | small user study, or at least report operator decision time and disagreement |
| No comparison to prior systems | positioning | compare against static Suricata rules, threshold tuning by grid search, and naive retraining (partly done via ablations) |
| CICIDS2017 known label issues | dataset validity | also report on the corrected CICIDS2017 relabelling (Engelen et al., 2021) or CIC-IDS2018 / UNSW-NB15 |
| LLM role untested | claim scope | either evaluate the LLM-assisted mapping against the deterministic map, or describe it as optional |

## Reproducibility checklist (already supported)
Seeds, config hash, library versions, dataset file SHA-256 manifests, model cards, label-set digests,
bundle hashes, criteria hashes and the full audit chain are recorded. Each report is generated from
stored records (`sage-ids experiment-report`).
