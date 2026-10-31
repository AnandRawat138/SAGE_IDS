# Setup and run guide

Tested on Windows 11 with Python 3.12.7. Linux/macOS work the same way, with `.venv/bin/` in place of `.venv/Scripts/`.

## 1. Install

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt
.venv/Scripts/python -m pip install -e .
cp .env.example .env
```

> Windows note: if `py -3.11` fails with `UnicodeDecodeError … site-packages *.pth`, a third-party
> `.pth` file in that interpreter is not UTF-8. Use another interpreter (3.11+), or set `PYTHONUTF8=1`.

## 2. Tests

```bash
.venv/Scripts/python -m pytest -q
```

## 3. Offline demo (no active lab, no LLM, fixtures only)

```bash
.venv/Scripts/python -m sage_ids.cli offline-demo
```

The demo retrieves fixture findings, maps them to the asset inventory, replays the Zeek and Suricata
fixtures through the monitoring agent, refuses an active scenario because the lab is disabled, checks
the target allowlist, writes a deterministic report to `reports/offline_demo_case_report.md`, and
verifies the audit chain.

## 4. Full closed-loop experiment (active loopback lab, opt-in)

```bash
.venv/Scripts/python -m sage_ids.cli experiment --out reports
```

This command enables the loopback lab **for its own run only**. It binds services to `127.0.0.1:18081`,
`127.0.0.1:18082` and `127.0.0.1:18100-18105`, and uses source aliases `127.0.1.x` (benign) and `127.0.2.x` (attacker). It writes:

* `data/experiment_<UTC>.db` — every run, window, prediction, transition and audit entry
* `artifacts/experiment_<UTC>/models/` — model bundles + model cards
* `reports/experiment_report.md`, `reports/experiment_results.json`, `reports/cases/case_<n>.md`

To regenerate the report from a database: `sage-ids experiment-report --experiment-db data/experiment_<UTC>.db`.

## 5. Interactive use (API + dashboard)

Set `SAGE_OPERATOR_KEY` (a long random value) and `SAGE_OPERATOR_NAME` in `.env`, or export them in the shell.

```bash
.venv/Scripts/python -m uvicorn sage_ids.api.main:app --host 127.0.0.1 --port 8000
```

```bash
.venv/Scripts/python -m streamlit run sage_ids/dashboard/app.py --server.address 127.0.0.1
```

To browse a finished experiment, start the API with `SAGE_DATABASE_URL=sqlite:///data/experiment_<UTC>.db`.
To run scenarios from the dashboard, start the API with `SAGE_ENABLE_ACTIVE_LAB=1`, then:

1. Bootstrap: `POST /bootstrap`, or `sage-ids bootstrap --operator <name>` with `SAGE_ENABLE_ACTIVE_LAB=1`.
2. Threat findings → *Retrieve*.
3. Scenarios & approval queue → *Approve* → *Run baseline*.
4. Remediation proposals → *Prepare candidate* → *Run retest*.
5. Baseline vs candidate → *Accept* / *Reject*.
6. Versions & rollback → *Roll back*.

The CLI equivalents are `sage-ids research | cases | approve | baseline | proposals | prepare | retest | accept | reject | cancel | rollback | versions | report | verify-audit | recover`.

## 6. Live threat intelligence

```bash
.venv/Scripts/python -m sage_ids.cli research --mode live
```

This queries the NVD CVE API 2.0 (by CWE, last 110 days, rate-limited to one request every 6.5 s) and
the MITRE ATT&CK enterprise STIX bundle (about 40 MB, cached for 24 h in `data/cache/threat_intel`).
Only these two HTTPS hosts are permitted.

## 7. Benchmark datasets (not bundled)

* **CICIDS2017** (primary): download `MachineLearningCSV.zip` from
  <https://www.unb.ca/cic/datasets/ids-2017.html> and extract the 8 CSVs to `data/datasets/cicids2017/`.
* **UNSW-NB15** (optional): place `UNSW_NB15_training-set.csv` and `UNSW_NB15_testing-set.csv` in
  `data/datasets/unsw-nb15/` (from <https://research.unsw.edu.au/projects/unsw-nb15-dataset>).

```bash
.venv/Scripts/python -m sage_ids.cli benchmark --dataset cicids2017 --data-dir data/datasets/cicids2017 --split stratified --seeds 0 1 2 3 4
```

```bash
.venv/Scripts/python -m sage_ids.cli benchmark --dataset cicids2017 --data-dir data/datasets/cicids2017 --split day
```

```bash
.venv/Scripts/python -m sage_ids.cli benchmark --dataset unsw-nb15 --data-dir data/datasets/unsw-nb15
```

Reports go to `reports/benchmark_<dataset>_<split>.{md,json}` and artifacts go to `artifacts/benchmark/…`.
If you need a subsample for memory reasons, pass `--max-rows N`; the cap is recorded in the result.

## 8. Docker laboratory (template — not executed in the build environment)

`docker/docker-compose.yml` defines:

* the API and dashboard (published on 127.0.0.1 only);
* an internal bridge network `labnet` (`internal: true`, no upstream route) with the lab services;
* passive Zeek and Suricata capture on the lab bridge, writing to `data/lab_logs/`;
* an opt-in `attacker` container (`--profile active`) whose allowlist is the lab subnet only (`configs/sage.docker.yaml`).

```bash
docker compose -f docker/docker-compose.yml up -d api dashboard lab-targets zeek suricata
```

```bash
.venv/Scripts/python -m sage_ids.cli replay --zeek-conn data/lab_logs/zeek/conn.log --zeek-http data/lab_logs/zeek/http.log --suricata-eve data/lab_logs/suricata/eve.json
```

In a VM-based lab, use a host-only network with no NAT, then set `allowed_target_cidrs` to the
target VM's address only.
