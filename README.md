# SAGE-IDS

**Self-Evolving Cyber Defense through Closed-Loop Multi-Agent Adversarial Validation and Adaptive Intrusion Detection**

Undergraduate major project **28_CS_4E_04** · Department of CSE, Section CS3E
Team: Anand Rawat (2401640100165) · Anandi Singh (2401640100167) · Ananya Agarwal (2401640100171)
Mentor: Mr Ashutosh Pandey, Assistant Professor · Domains: Agentic AI; Cryptography and Network Security

> Research prototype. "Self-evolving" here means **controlled, versioned improvement based on
> verified feedback**. It does not mean autonomous exploitation, internet code execution or deployment
> to production. Active scenarios are opt-in and run only against allowlisted laboratory targets. Every
> change needs operator acceptance after evidence-gated validation.

## What it does

```
threat finding (NVD / ATT&CK)  ──►  relevance vs lab asset inventory  ──►  reviewed scenario (operator approves)
        ──►  baseline test: executed? · security effect? · detected?  (separately recorded)
        ──►  weakness confirmed  ──►  bounded remediation proposals (rule template / lab config / verified retrain)
        ──►  candidate version  ──►  fresh-seed retest + regression + benign traffic + service health
        ──►  frozen, hash-committed acceptance criteria  ──►  operator accept / reject  ──►  rollback available
        ──►  deterministic evidence report (observation / inference / uncertainty)
```

Five agents (Monitoring, Threat Research, Adversarial Validation, Remediation, Explanation) are driven
by a persistent, bounded state-machine coordinator. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
for diagrams and [docs/RESEARCH_POSITIONING.md](docs/RESEARCH_POSITIONING.md) for the claimed
contributions and the gaps that remain before a journal submission.

## Quick start

```bash
python -m venv .venv
```

```bash
.venv/Scripts/python -m pip install -r requirements.txt
```

```bash
.venv/Scripts/python -m pip install -e .
```

Run the tests:

```bash
.venv/Scripts/python -m pytest -q
```

Offline demo (fixtures only, no active lab, no LLM):

```bash
.venv/Scripts/python -m sage_ids.cli offline-demo
```

Full closed-loop experiment on the loopback lab (opt-in; writes `reports/experiment_report.md`):

```bash
.venv/Scripts/python -m sage_ids.cli experiment --out reports
```

API and dashboard (see [docs/SETUP.md](docs/SETUP.md) for keys and the active-lab flag):

```bash
.venv/Scripts/python -m uvicorn sage_ids.api.main:app --host 127.0.0.1 --port 8000
```

```bash
.venv/Scripts/python -m streamlit run sage_ids/dashboard/app.py --server.address 127.0.0.1
```

CICIDS2017 benchmark (after downloading the dataset; it is not bundled):

```bash
.venv/Scripts/python -m sage_ids.cli benchmark --dataset cicids2017 --data-dir data/datasets/cicids2017 --seeds 0 1 2 3 4
```

## Repository layout

| Path | Contents |
|---|---|
| `sage_ids/agents/` | `monitoring.py`, `threat_research.py`, `adversarial.py`, `remediation.py`, `explanation.py` |
| `sage_ids/coordinator/` | state machine (`state_machine.py`) and coordinator (`coordinator.py`) |
| `sage_ids/detection/` | lab-v1 features, sliding-window rule engine, RF/IF bundle, detector runtime, version registry |
| `sage_ids/lab/` | loopback lab services, approved scenario executors, benign generator |
| `sage_ids/telemetry/` | Zeek conn/http, Suricata EVE and canonical replay adapters |
| `sage_ids/data/` | CICIDS2017 / UNSW-NB15 loaders, leakage controls, benchmark pipeline |
| `sage_ids/evaluation/` | statistics, acceptance gate, experiment runner, report writer |
| `sage_ids/security/` | target allowlist, secret redaction |
| `sage_ids/llm/` | provider interface (deterministic default; optional Ollama / Anthropic) |
| `sage_ids/api/`, `sage_ids/dashboard/` | FastAPI backend, Streamlit dashboard |
| `configs/` | main config, asset inventory, scenario catalogue, mappings, acceptance policy, baseline rules |
| `fixtures/` | **synthetic** threat-intel, Zeek and Suricata fixtures (see `fixtures/README.md`) |
| `docker/` | Dockerfile, compose template with an isolated Zeek/Suricata lab (not executed here) |
| `tests/` | pytest suite |
| `reports/` | generated experiment report, per-case reports, offline-demo report |
| `docs/` | architecture, setup, API, threat model, limitations, research positioning |

## Data labels

Every record carries a `data_origin`. Values are `live_lab` (generated in the loopback lab during this run),
`replay`, `synthetic_fixture`, `live_internet` and `benchmark_dataset`. The dashboard shows a badge
for each value.

## Results (one measured run, `data/experiment_20261031T145253Z.db`)

All numbers come from [reports/experiment_report.md](reports/experiment_report.md), which is generated from the
recorded run (30 trials per phase, Wilson 95% CIs, paired exact McNemar tests; timing integrity: clean).

| case | baseline (v1) | outcome |
|---|---|---|
| Password guessing | effect 30/30, detected 0/30 | maximum-sensitivity rule **rejected** (benign FPR 0.167 vs frozen bound 0.02); calibrated rule + account lockout **accepted**: retest detection 0.93 gain, effect rate 1.00 → 0.17 |
| Request flood | effect 30/30, detected 0/30 | RF retrained on verified labels **accepted** (retest detection LCB 0.89) |
| Reconnaissance | detected 30/30, effect 21/30 (preventive weakness) | rule and retrain candidates **rejected**: neither reduces the effect; no preventive template exists for probing |
| Instruction-injected finding | — | flagged as untrusted; operator denied the scenario |

Held-out final test (fresh seeds, identical traffic for every version): window F1 went from 0.540 (v1) to
0.974 (final active version) at 0/102 benign false positives. Per-trial detection: flood 0/30 → 30/30,
password guessing 0/30 → 27/30. All three misses ended within ≤3 attempts, which is behaviourally
indistinguishable from typos. Naive self-training on the model's own pseudo-labels detected 0/30 of both
attacks; retraining on verified labels detected 30/30 of each. Enabling the Isolation Forest on v1 would have
reached F1 0.776 at FPR 0.010 with no adaptation; this is reported as a stronger static baseline.

These are laboratory results: loopback services, an application-level sensor and synthetic benign traffic.
See [docs/LIMITATIONS.md](docs/LIMITATIONS.md). Earlier runs, kept unedited in `reports/superseded_run_*`, led to the
protocol fixes in [docs/DEVELOPMENT_NOTES.md](docs/DEVELOPMENT_NOTES.md). The second run reached the same
decisions but was invalidated by a host suspend. **The CICIDS2017 benchmark has not been run yet**: the
dataset download requires a personal registration form.

## Status

* Implemented and tested: all five agents, the coordinator, the API, the dashboard, the loopback lab, the Zeek/Suricata adapters,
  live NVD retrieval (one live query verified), the offline demo, and the benchmark pipeline (on synthetic data only).
* Not executed here: the Docker/Zeek/Suricata lab (Docker unavailable), the live ATT&CK bundle download, the CICIDS2017
  and UNSW-NB15 benchmarks (datasets not present), and the optional LLM providers.
