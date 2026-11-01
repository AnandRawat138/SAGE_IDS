"""SAGE-IDS command-line interface.  Run `sage-ids --help` (or `python -m sage_ids.cli --help`)."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sqlalchemy import select

from .config import load_settings
from .security.redaction import configure_logging


def _coord(args):
    from .coordinator.coordinator import Coordinator
    from .db import Database
    s = load_settings(args.config)
    if getattr(args, "db", None):
        s.database_url = args.db
    return Coordinator(s, Database(s.database_url))


def main(argv: list[str] | None = None) -> int:
    configure_logging()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    p = argparse.ArgumentParser(prog="sage-ids", description=__doc__)
    p.add_argument("--config", default=None, help="path to sage.yaml")
    p.add_argument("--db", default=None, help="override database URL")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("bootstrap", help="collect verified calibration traffic and register v1 (needs active lab)") \
        .add_argument("--operator", required=True)
    r = sub.add_parser("research", help="retrieve threat findings and create cases")
    r.add_argument("--mode", choices=["fixture", "live"], default="fixture")
    sub.add_parser("cases", help="list cases")
    for name in ("approve", "deny"):
        a = sub.add_parser(name)
        a.add_argument("case_id", type=int)
        a.add_argument("--operator", required=True)
    sub.add_parser("baseline").add_argument("case_id", type=int)
    sub.add_parser("proposals").add_argument("case_id", type=int)
    pr = sub.add_parser("prepare")
    pr.add_argument("case_id", type=int)
    pr.add_argument("proposal_id", type=int)
    pr.add_argument("--operator", required=True)
    sub.add_parser("retest").add_argument("case_id", type=int)
    for name in ("accept", "cancel"):
        a = sub.add_parser(name)
        a.add_argument("case_id", type=int)
        a.add_argument("--operator", required=True)
    rj = sub.add_parser("reject")
    rj.add_argument("case_id", type=int)
    rj.add_argument("--operator", required=True)
    rj.add_argument("--reason", default="operator rejected")
    rb = sub.add_parser("rollback")
    rb.add_argument("--operator", required=True)
    rb.add_argument("--to", type=int, default=None)
    sub.add_parser("versions")
    sub.add_parser("recover", help="time out stale running cases after a restart")
    rp = sub.add_parser("report")
    rp.add_argument("case_id", type=int)
    sub.add_parser("verify-audit")
    rz = sub.add_parser("replay", help="ingest Zeek / Suricata / canonical replay telemetry (read-only monitoring)")
    rz.add_argument("--zeek-conn")
    rz.add_argument("--zeek-http")
    rz.add_argument("--suricata-eve")
    rz.add_argument("--events", help="canonical CSV/JSONL")
    rz.add_argument("--origin", default="replay", choices=["replay", "synthetic_fixture"])
    ex = sub.add_parser("experiment", help="run the full closed-loop experiment on the loopback lab")
    ex.add_argument("--out", default="reports")
    ex.add_argument("--live-intel", action="store_true")
    ex.add_argument("--trials", type=int, default=None)
    ex.add_argument("--benign-rounds", type=int, default=None)
    er = sub.add_parser("experiment-report", help="re-generate the experiment report from an experiment database")
    er.add_argument("--experiment-db", required=True)
    er.add_argument("--out", default="reports")
    evs = sub.add_parser("evasion", help="run reviewed evasive variants against accepted detectors (needs active lab)")
    evs.add_argument("--experiment-db", required=True)
    evs.add_argument("--out", default="reports")
    evs.add_argument("--trials", type=int, default=12)
    le = sub.add_parser("llm-eval", help="measure the configured LLM against the deterministic scenario mapper")
    le.add_argument("--mode", choices=["fixture", "live"], default="fixture")
    le.add_argument("--out", default="reports")
    le.add_argument("--max-findings", type=int, default=40)
    bm = sub.add_parser("benchmark", help="CICIDS2017 / UNSW-NB15 benchmark (separate model and schema)")
    bm.add_argument("--dataset", choices=["cicids2017", "unsw-nb15"], default="cicids2017")
    bm.add_argument("--data-dir", required=True)
    bm.add_argument("--split", choices=["stratified", "day"], default="stratified")
    bm.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2, 3, 4])
    bm.add_argument("--max-rows", type=int, default=None, help="optional per-file row cap (documented subsample)")
    bm.add_argument("--out", default="reports")
    sub.add_parser("offline-demo", help="reproducible demo with labelled fixtures; no active lab")
    args = p.parse_args(argv)

    if args.cmd == "experiment":
        from .evaluation.experiment import run_experiment
        s = load_settings(args.config)
        if args.trials:
            s.experiment.baseline_trials = s.experiment.retest_trials = args.trials
        if args.benign_rounds:
            s.experiment.benign_windows_per_phase = args.benign_rounds
        res = run_experiment(s, s.path(args.out), live_intel=args.live_intel)
        print(json.dumps({"cases": res["cases"], "report": str(s.path(args.out) / "experiment_report.md")}, indent=2))
        return 0
    if args.cmd == "experiment-report":
        from .db import Database
        from .evaluation.experiment import collect_results
        s = load_settings(args.config)
        path = Path(args.experiment_db).resolve()
        s.database_url = f"sqlite:///{path.as_posix()}"
        extra = {"log": []}
        prev = s.path(args.out) / "experiment_results.json"
        if prev.exists():                      # reuse run-time records (log, case history, resources) of the same DB
            old = json.loads(prev.read_text(encoding="utf-8"))
            if Path(old.get("database", "")).resolve() == path:
                extra = {k: old[k] for k in ("log", "cases", "rollback", "ablation_version_ids", "resources") if k in old}
        extra.setdefault("log", []).append("report regenerated from the database by `sage-ids experiment-report`")
        res = collect_results(s, Database(s.database_url), path, s.path(args.out), extra)
        print(f"wrote {s.path(args.out) / 'experiment_report.md'} (audit valid: {res['audit_chain']['valid']})")
        return 0
    if args.cmd == "evasion":
        import shutil, sqlite3, tempfile, uuid
        from .evaluation.evasion import run_evasion
        s = load_settings(args.config)
        src = Path(args.experiment_db).resolve()
        work = Path(tempfile.gettempdir()) / f"sage_evasion_{uuid.uuid4().hex}.db"
        con = sqlite3.connect(src); dst = sqlite3.connect(work); con.backup(dst); con.close(); dst.close()
        res = run_evasion(s, work, s.path(args.out))
        print(json.dumps({"versions": res["versions"], "report": str(s.path(args.out) / "evasion_report.md")}, indent=2))
        return 0
    if args.cmd == "llm-eval":
        from .evaluation.llm_eval import run_llm_eval
        import tempfile, uuid
        s = load_settings(args.config)
        s.database_url = f"sqlite:///{Path(tempfile.gettempdir()) / ('sage_llmeval_' + uuid.uuid4().hex + '.db')}".replace("\\", "/")
        res = run_llm_eval(s, s.path(args.out), args.mode, args.max_findings)
        print(json.dumps({k: res[k] for k in ("provider", "model", "n_findings_evaluated", "valid_rate",
                                              "agreement_rate", "mean_latency_s", "never_exceeded_closed_set")}, indent=2))
        return 0
    if args.cmd == "benchmark":
        from .data.benchmark import run_benchmark
        s = load_settings(args.config)
        res = run_benchmark(args.dataset, Path(args.data_dir), args.split, args.seeds, s.path(args.out),
                            max_rows=args.max_rows)
        print(json.dumps(res["summary"], indent=2, default=str))
        return 0
    if args.cmd == "offline-demo":
        from .demo import offline_demo
        print(offline_demo(load_settings(args.config)))
        return 0

    c = _coord(args)
    from .db import Case, DetectorVersion, RemediationProposal, Report
    if args.cmd == "bootstrap":
        print(f"active version: v{c.bootstrap(args.operator)}")
    elif args.cmd == "research":
        print(f"cases created: {c.ingest_findings(args.mode)}")
    elif args.cmd == "cases":
        with c.db.session() as s:
            for k in s.execute(select(Case).order_by(Case.id)).scalars():
                print(f"{k.id:>3}  {k.state:<24} {k.scenario_id or '-':<24} {k.idempotency_key}")
    elif args.cmd in ("approve", "deny"):
        c.approve_scenario(args.case_id, args.operator, approve=args.cmd == "approve")
    elif args.cmd == "baseline":
        print(c.run_baseline(args.case_id))
    elif args.cmd == "proposals":
        with c.db.session() as s:
            for pr_ in s.execute(select(RemediationProposal).where(RemediationProposal.case_id == args.case_id)).scalars():
                print(f"{pr_.id:>3} [{pr_.status}] {pr_.title}\n     {pr_.rationale}")
    elif args.cmd == "prepare":
        print(f"candidate version v{c.prepare_candidate(args.case_id, args.proposal_id, args.operator)}")
    elif args.cmd == "retest":
        print(c.run_retest(args.case_id))
    elif args.cmd == "accept":
        print(f"activated v{c.accept(args.case_id, args.operator)}")
    elif args.cmd == "reject":
        c.reject(args.case_id, args.operator, args.reason)
    elif args.cmd == "cancel":
        print(c.cancel(args.case_id, args.operator))
    elif args.cmd == "rollback":
        print(f"active version now v{c.rollback(args.operator, args.to)}")
    elif args.cmd == "versions":
        with c.db.session() as s:
            for v in s.execute(select(DetectorVersion).order_by(DetectorVersion.id)).scalars():
                print(f"v{v.id:<3} {v.status:<9} {'ACTIVE' if v.is_active else '':<6} {v.name}  {v.bundle_hash[:12]}")
    elif args.cmd == "recover":
        print(f"timed out: {c.recover()}")
    elif args.cmd == "report":
        rid = c.report(args.case_id)
        with c.db.session() as s:
            print(s.get(Report, rid).content_md)
    elif args.cmd == "verify-audit":
        from . import audit
        with c.db.session() as s:
            res = audit.verify(s)
        print(json.dumps(res))
        return 0 if res["valid"] else 2
    elif args.cmd == "replay":
        from .demo import replay_into
        print(json.dumps(replay_into(c, args), indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
