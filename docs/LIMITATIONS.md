# Limitations (what this prototype does **not** show)

## Laboratory realism
* Targets are loopback services written for this project, not real products. Threat findings are
  mapped to them by **weakness class (CWE)** or **ATT&CK technique**, not by vendor/product.
* The default sensor is application-level: it sees requests and accepted connections, but not packets.
  Probes to closed ports are invisible to it. Zeek and Suricata adapters exist and are tested on fixtures,
  but the packet-capture lab (`docker/`) was not run in the build environment because Docker was unavailable.
* Benign traffic is synthetic: a handful of simulated users with log-in typos, browsing and health checks.
  False-positive rates measured on it are not production false-positive rates.
* All lab traffic shares one host, so timing and rates reflect loopback performance.

## Scenario and attacker scope
* Three reviewed, bounded scenarios: TCP service discovery, password guessing and request flood.
  Their parameters are randomised within reviewed bounds.
* The main experiment uses **non-evasive** attacks. A dedicated robustness evaluation (`sage-ids evasion`,
  `reports/evasion_report.md`) runs reviewed low-and-slow, distributed and low-rate variants against the
  accepted detectors and shows they are **evadable**: the accepted password-guessing detector drops from
  27/30 on the normal attack to 3/12 (slow) and 0/12 (distributed), and the flood detector catches only
  9/12 of a low-rate flood. The accepted fixes are genuine improvements against the tested threat, not
  robust defences. Password guessing that succeeds within the first one or two attempts is inherently
  hard to detect behaviourally, and the reported detection rates include those trials.
* Failure to reproduce a scenario's effect is recorded as `weakness_not_confirmed`, never as "secure".

## Statistics
* Rates are reported with Wilson 95% intervals and paired exact McNemar tests. Trial counts per phase
  are finite (30 by default), so small differences are not resolvable.
* The experiment script acts as the operator, and the order in which candidates are tried is fixed in
  advance. This is not an independent human evaluation.
* Multi-seed: 3 independent seeds give identical accept/reject decisions and tight detection intervals
  (`reports/multiseed/`). One seed had two over-long recon baseline trials from host CPU contention
  (flagged by the timing-integrity check; outcomes unaffected). More seeds would tighten the intervals further.

## Learning
* The laboratory model (RF, plus IF in shadow mode) uses 14 window features. The CICIDS2017 benchmark
  uses a separate 78-feature model. They are not interchangeable, and no claim is made that the
  benchmark model runs on lab telemetry.
* Retraining is batch-only and uses verified labels. There is no online learning.
* Remediation is limited to the threshold-rule template, three bounded lab-service settings and
  verified retraining. There is no source-code patching.

## Engineering
* SQLite and a single process. Background jobs are in-memory threads, so after a restart, running
  phases are timed out rather than resumed.
* The audit chain is tamper-evident, not externally anchored.
* The LLM integration is optional and not exercised by the measured experiment (deterministic mode).
