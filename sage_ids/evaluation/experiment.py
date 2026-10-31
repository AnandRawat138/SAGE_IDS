"""End-to-end experiment: runs the full closed-loop protocol on the live loopback laboratory and writes
a report generated ONLY from recorded results.

Protocol (scripted operator decisions are fixed in advance and labelled as such in the report):
  1. Bootstrap v1 from verified calibration traffic.
  2. Retrieve findings (fixtures by default; --live for NVD/ATT&CK) and create cases.
  3. Case A (password guessing): approve -> baseline -> proposals -> candidates tried in the fixed order
     [maximum-sensitivity rule, rule+hardening, calibrated rule, verified retrain] until one passes -> accept.
  4. Case B (request flood): approve -> baseline -> candidates tried in order [verified retrain,
     rule+hardening, calibrated rule] -> accept; then demonstrate rollback.
  5. Case C (recon): approve -> baseline -> if a weakness is confirmed, candidates [calibrated rule, retrain].
  6. Case with instruction-like retrieved text: operator denies the scenario.
  7. Held-out final test (fresh seeds, never used for candidate creation/acceptance): every version and
     ablation evaluated on identical traffic -> window metrics, per-scenario detection, latency, cost.
  8. Safety checks: unauthorized targets, disabled active lab, audit-chain tamper detection.
"""
from __future__ import annotations

import json
import platform
import shutil
import sqlite3
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import psutil
import sklearn
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from sqlalchemy import select

from .. import audit
from ..config import Settings
from ..coordinator.coordinator import Coordinator
from ..db import (Case, Database, DetectorVersion, Evaluation, ExperimentRun, FeatureWindow, Prediction,
                  RemediationProposal, Report, ThreatFinding)
from ..detection import versions
from ..detection.engine import DetectorRuntime
from ..detection.features import FEATURES
from ..detection.models import save_bundle, train_bundle
from ..lab.scenarios import ExecContext, execute_trial, load_catalogue
from ..security.allowlist import ActiveLabDisabled, Allowlist, TargetNotAllowed
from .stats import bootstrap_ci, mcnemar_exact, wilson

OPERATOR = "operator:demo-script"
ORDER_A = ["Maximum-sensitivity", "Calibrated rule + lab service hardening", "Calibrated threshold", "Retrain"]
ORDER_B = ["Retrain", "Calibrated rule + lab service hardening", "Calibrated threshold"]
ORDER_C = ["Calibrated threshold", "Retrain"]


def _case_by_finding(s, source_id: str) -> Case:
    f = s.execute(select(ThreatFinding).where(ThreatFinding.source_id == source_id)).scalar_one()
    return s.execute(select(Case).where(Case.finding_id == f.id)).scalar_one()


def _run_case(coord: Coordinator, case_id: int, order: list[str], log: list) -> dict:
    t0 = time.time()
    coord.approve_scenario(case_id, OPERATOR)
    state = coord.run_baseline(case_id)
    log.append(f"case {case_id}: baseline -> {state} ({time.time() - t0:.0f}s)")
    tried = []
    while state == "remediation_proposed":
        with coord.db.session() as s:
            props = s.execute(select(RemediationProposal).where(RemediationProposal.case_id == case_id,
                                                                RemediationProposal.status == "proposed")).scalars().all()
            nxt = next((p for key in order for p in props if p.title.startswith(key)), None)
            if nxt is None:
                break
            pid, title = nxt.id, nxt.title
        coord.prepare_candidate(case_id, pid, OPERATOR)
        state = coord.run_retest(case_id)
        tried.append({"proposal_id": pid, "title": title, "result_state": state})
        log.append(f"case {case_id}: candidate from proposal {pid} ({title}) -> {state} ({time.time() - t0:.0f}s)")
    accepted_version = None
    if state == "remediation_proposed":      # pre-declared candidate order exhausted -> explicit decision
        coord.reject(case_id, OPERATOR, "no remaining proposal in the pre-declared candidate order")
        state = "rejected"
        log.append(f"case {case_id}: rejected (candidate order exhausted)")
    if state == "acceptance_pending":
        accepted_version = coord.accept(case_id, OPERATOR)
        state = "accepted"
    return {"case_id": case_id, "final_state": state, "tried": tried, "accepted_version": accepted_version,
            "wall_s": round(time.time() - t0, 1)}


def safety_checks(settings: Settings) -> list[dict]:
    allow = Allowlist.from_settings(settings.lab)
    out = []
    for host, port in [("8.8.8.8", 18081), ("10.0.0.5", 18081), ("192.168.1.1", 18082), ("127.0.0.2", 18081),
                       ("example.com", 18082), ("localhost", 18081), ("127.0.0.1", 22), ("127.0.0.1;rm -rf /", 18081),
                       ("127.0.0.1", 18081)]:
        try:
            ip = allow.check_target(host, port)
            out.append({"target": f"{host}:{port}", "decision": "ALLOWED", "detail": ip})
        except TargetNotAllowed as e:
            out.append({"target": f"{host}:{port}", "decision": "DENIED", "detail": str(e)[:160]})
    spec = load_catalogue()["auth-password-guessing"]
    for host, active in (("8.8.8.8", True), ("127.0.0.1", False)):
        ctx = ExecContext(allowlist=allow, active_enabled=active, target_host=host,
                          ports={"login": settings.lab.login_service_port, "test_app": settings.lab.test_app_port,
                                 "decoy": settings.lab.decoy_ports[0]})
        try:
            execute_trial(spec, {}, "127.0.2.200", ctx, seed=1)
            out.append({"target": f"scenario->{host} (active={active})", "decision": "EXECUTED", "detail": ""})
        except (TargetNotAllowed, ActiveLabDisabled) as e:
            out.append({"target": f"scenario->{host} (active={active})", "decision": "DENIED before any connection",
                        "detail": f"{type(e).__name__}: {str(e)[:120]}"})
    return out


def tamper_check(db_path: Path, work: Path) -> dict:
    """Snapshot the DB (sqlite backup API: WAL-safe), modify one audit entry, verify the chain breaks."""
    copy = work / "tamper_copy.db"
    copy.unlink(missing_ok=True)
    src, dst = sqlite3.connect(db_path), sqlite3.connect(copy)
    src.backup(dst)
    src.close()
    mid = dst.execute("select max(id)/2 from audit_entries").fetchone()[0]
    dst.execute("update audit_entries set payload = json_set(payload, '$.tampered', 1) where id = ?", (mid,))
    dst.commit()
    dst.close()
    tdb = Database(f"sqlite:///{copy.as_posix()}")
    with tdb.session() as s:
        res = audit.verify(s)
    tdb.engine.dispose()
    copy.unlink(missing_ok=True)
    return {"modified_entry": mid, **res}


def timing_integrity(s, settings: Settings) -> dict:
    """Detect host suspend / stalls: runs much longer than their budget, or long gaps between consecutive runs."""
    runs = s.execute(select(ExperimentRun).order_by(ExperimentRun.id)).scalars().all()
    limit = max(settings.lab.max_trial_seconds, 30.0) * 3
    long_runs = [{"run_id": r.id, "phase": r.phase, "seconds": round(r.ended_at - r.started_at, 1)}
                 for r in runs if r.ended_at - r.started_at > limit]
    gaps = [{"after_run": a.id, "before_run": b.id, "phase": b.phase, "gap_s": round(b.started_at - a.ended_at, 1)}
            for a, b in zip(runs, runs[1:]) if b.started_at - a.ended_at > 120]
    return {"clean": not long_runs and not gaps, "long_runs": long_runs, "gaps": gaps}


# ------------------------------------------------------------------------------------- final test
def _make_ablation(s, settings: Settings, name: str, parent: DetectorVersion, *, policy: dict | None = None,
                   train_rows: list[FeatureWindow] | None = None, labels: list[str] | None = None,
                   note: str = "") -> DetectorVersion:
    model_path, sha, label_set = parent.model_path, parent.model_sha256, parent.label_set
    if train_rows is not None:
        X = pd.DataFrame([r.features for r in train_rows])[FEATURES]
        bundle = train_bundle(X, pd.Series(labels), seed=settings.experiment.base_seed,
                              window_ids=[r.id for r in train_rows])
        path = settings.path(settings.artifacts_dir) / "models" / f"ablation_{name}.joblib"
        sha = save_bundle(bundle, path)
        model_path = str(path)
        label_set = {"window_ids": [r.id for r in train_rows], "label_counts": bundle.card["label_counts"],
                     "policy": note}
    v = versions.create_version(s, name=name, parent_id=parent.id, ruleset=parent.ruleset,
                                lab_config=parent.lab_config, detector_policy=policy or parent.detector_policy,
                                model_path=model_path, model_sha256=sha, label_set=label_set, notes=note,
                                actor="experiment")
    v.status = "ablation"           # never activatable
    return v


def build_ablations(coord: Coordinator, case_ids: list[int]) -> list[int]:
    settings = coord.settings
    with coord.db.session() as s:
        v1 = s.execute(select(DetectorVersion).where(DetectorVersion.name == "v1-baseline")).scalar_one()
        base_rows = s.execute(select(FeatureWindow).where(FeatureWindow.id.in_(v1.label_set["window_ids"]))).scalars().all()
        run_ids = [r.id for r in s.execute(select(ExperimentRun).where(ExperimentRun.case_id.in_(case_ids),
                                                                       ExperimentRun.phase == "baseline")).scalars()]
        new_rows = s.execute(select(FeatureWindow).where(FeatureWindow.run_id.in_(run_ids))).scalars().all()
        out = [_make_ablation(s, settings, "ABL-iforest-alerting", v1, policy={"rf": True, "iforest": True},
                              note="v1 with Isolation Forest alerting enabled (benign 99th-percentile threshold)").id]
        # naive self-training: pseudo-labels from v1's own predictions on unverified observations
        win = pd.DataFrame([{**r.features, "src_ip": r.src_ip, "window_start": r.window_start,
                             "window_end": r.window_end, "event_ids": r.event_ids} for r in new_rows])
        preds = DetectorRuntime(v1).evaluate(win) if len(win) else []
        pseudo = [p["predicted_label"] if p["is_alert"] else "benign" for p in preds]
        out.append(_make_ablation(s, settings, "ABL-self-training", v1, train_rows=base_rows + list(new_rows),
                                  labels=[r.label for r in base_rows] + pseudo,
                                  note="naive self-training: v1 pseudo-labels on observed windows (no ground truth)").id)
        ver = [r for r in new_rows if r.label_verified and r.label is not None]
        out.append(_make_ablation(s, settings, "ABL-verified-retrain-all", v1, train_rows=base_rows + ver,
                                  labels=[r.label for r in base_rows] + [r.label for r in ver],
                                  note="RF retrained with verified labels from all case baselines").id)
        return out


def final_test_execute(coord: Coordinator, trials: int, benign_rounds: int) -> None:
    """Generate held-out traffic (fresh seeds) under the v1 lab configuration and store labelled windows."""
    settings, adv, mon = coord.settings, coord.adversarial, coord.monitoring
    seed = settings.experiment.base_seed + 9_000_000
    with coord.db.session() as s:
        v1 = s.execute(select(DetectorVersion).where(DetectorVersion.name == "v1-baseline")).scalar_one()
        lab_cfg = dict(v1.lab_config)
        adv.start_phase(lab_cfg)
        runs = []
        for i, sid in enumerate(adv.catalogue):
            runs += adv.run_trials(s, case_id=None, scenario_id=sid, phase="final-test", n_trials=trials,
                                   seed_base=seed + 1000 * i, lab_config=lab_cfg, version_id=None)
            s.commit()
        runs += adv.run_benign(s, case_id=None, phase="final-test-benign", rounds=benign_rounds,
                               seed_base=seed + 5000, lab_config=lab_cfg, version_id=None)
        ev = mon.store_events(s, adv.drain_telemetry(), "live_lab")
        mon.build_windows(s, ev, runs, "live_lab")


def final_test_evaluate(db: Database, version_ids: list[int]) -> dict:
    """Evaluate every version on the stored held-out windows/events (re-runnable from the database)."""
    from ..db import TelemetryEvent
    with db.session() as s:
        v1 = s.execute(select(DetectorVersion).where(DetectorVersion.name == "v1-baseline")).scalar_one()
        runs = s.execute(select(ExperimentRun).where(ExperimentRun.phase.in_(["final-test", "final-test-benign"]))
                         ).scalars().all()
        rows = s.execute(select(FeatureWindow).where(FeatureWindow.run_id.in_([r.id for r in runs]))).scalars().all()
        lab = pd.DataFrame([{**r.features, "window_id": r.id, "src_ip": r.src_ip, "window_start": r.window_start,
                             "window_end": r.window_end, "event_ids": r.event_ids, "label": r.label,
                             "run_id": r.run_id} for r in rows if r.label is not None])
        ids = [i for e in lab["event_ids"] for i in e]
        ev = pd.DataFrame([{"id": e.id, "ts": e.ts, "src_ip": e.src_ip, "dst_port": e.dst_port, "service": e.service,
                            "status": e.status, "bytes_in": e.bytes_in, "bytes_out": e.bytes_out,
                            "duration": e.duration} for e in
                           s.execute(select(TelemetryEvent).where(TelemetryEvent.id.in_(ids))).scalars()])
        catalogue = sorted({r.scenario_id for r in runs if r.scenario_id != "benign-traffic"})
        result = {"n_events": int(len(ev)), "n_windows_labelled": int(len(lab)),
                  "label_counts": lab["label"].value_counts().to_dict(), "versions": {}}
        attack_runs = [r for r in runs if r.scenario_id != "benign-traffic" and r.executed]
        rss = psutil.Process().memory_info().rss
        per_trial: dict = {}
        for vid in version_ids:
            v = s.get(DetectorVersion, vid)
            t0 = time.perf_counter()
            res = DetectorRuntime(v).evaluate(lab, ev)
            dt = time.perf_counter() - t0
            y_true = (lab["label"] != "benign").astype(int).to_numpy()
            y_pred = np.array([int(r["is_alert"]) for r in res])
            p, rcl, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
            tn = int(((y_true == 0) & (y_pred == 0)).sum())
            fp = int(((y_true == 0) & (y_pred == 1)).sum())
            cls_labels = ["benign", "bruteforce", "flood", "recon"]
            pred_lbl = [r["predicted_label"] if r["is_alert"] else "benign" for r in res]
            cm = confusion_matrix(lab["label"], pred_lbl, labels=cls_labels)
            pc, rc, fc, sc = precision_recall_fscore_support(lab["label"], pred_lbl, labels=cls_labels, zero_division=0)
            # per-trial detection (any alerting window of the run)
            by_run: dict[int, list] = {}
            for w, r in zip(lab.to_dict("records"), res):
                if w.get("run_id") is not None:
                    by_run.setdefault(int(w["run_id"]), []).append(r)
            scen = {}
            for sid in catalogue:
                rr = [r for r in attack_runs if r.scenario_id == sid]
                det = [any(x["is_alert"] for x in by_run.get(r.id, [])) for r in rr]
                lat = []
                for r in rr:
                    ts = [x["alert_ts"] for x in by_run.get(r.id, []) if x["is_alert"] and x["alert_ts"] is not None]
                    if ts:
                        lat.append(max(0.0, min(ts) - r.started_at))
                k, n = sum(det), len(det)
                pt, lo, hi = wilson(k, n)
                per_trial.setdefault(sid, {})[vid] = det
                scen[sid] = {"detected": k, "n": n, "rate": pt, "ci95": [lo, hi],
                             "latency_median_s": float(np.median(lat)) if lat else None,
                             "latency_p95_s": float(np.quantile(lat, 0.95)) if lat else None}
            result["versions"][str(vid)] = {
                "name": v.name, "status": v.status,
                "window_binary": {"precision": p, "recall": rcl, "f1": f1, "fpr": fp / (fp + tn) if fp + tn else None,
                                  "fpr_ci95": list(wilson(fp, fp + tn)[1:]), "tp_fp_tn_fn": [
                                      int(((y_true == 1) & (y_pred == 1)).sum()), fp, tn,
                                      int(((y_true == 1) & (y_pred == 0)).sum())]},
                "per_class": {c: {"precision": float(pc[i]), "recall": float(rc[i]), "f1": float(fc[i]),
                                  "support": int(sc[i])} for i, c in enumerate(cls_labels)},
                "confusion_matrix": {"labels": cls_labels, "matrix": cm.tolist()},
                "per_scenario": scen,
                "cost": {"eval_seconds_total": dt, "ms_per_window": 1000 * dt / max(len(lab), 1)}}
        result["rss_mb"] = rss / 2**20
        v1id = str(v1.id)
        result["mcnemar_vs_v1"] = {sid: {str(vid): mcnemar_exact(d[v1.id], d[vid], "two-sided")
                                         for vid in version_ids if vid != v1.id}
                                   for sid, d in per_trial.items() if v1.id in d}
        result["v1_id"] = v1id
        return result


# ------------------------------------------------------------------------------------- driver
def run_experiment(settings: Settings, out_dir: Path, live_intel: bool = False) -> dict:
    t_start = time.time()
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    db_path = settings.path("data") / f"experiment_{stamp}.db"
    settings.database_url = f"sqlite:///{db_path.as_posix()}"
    settings.artifacts_dir = f"artifacts/experiment_{stamp}"     # model artifacts are per-experiment
    settings.lab.active_scenarios_enabled = True
    db = Database(settings.database_url)
    coord = Coordinator(settings, db)
    log: list[str] = []
    proc = psutil.Process()
    cpu0 = proc.cpu_times()

    v1 = coord.bootstrap(OPERATOR, calibration_trials=20)
    log.append(f"bootstrap v{v1} ({time.time() - t_start:.0f}s)")
    coord.ingest_findings("fixture")          # closed-loop cases are driven by the labelled fixtures
    if live_intel:                              # live retrieval is recorded additionally (cases stay pending)
        try:
            coord.ingest_findings("live")
            log.append("live threat intelligence retrieved")
        except Exception as e:  # noqa: BLE001
            log.append(f"live threat intelligence FAILED: {type(e).__name__}: {e}")
    with db.session() as s:
        cA = _case_by_finding(s, "SYNTH-2026-0001").id
        cB = _case_by_finding(s, "SYNTH-2026-0002").id
        cC = _case_by_finding(s, "T1046").id
        cD = _case_by_finding(s, "SYNTH-2026-0004").id
    cases = {"A_password_guessing": _run_case(coord, cA, ORDER_A, log),
             "B_request_flood": _run_case(coord, cB, ORDER_B, log),
             "C_recon": _run_case(coord, cC, ORDER_C, log)}
    coord.approve_scenario(cD, OPERATOR, approve=False,
                           reason="retrieved text contains instruction-like content; duplicate of an approved case")
    coord.report(cD)
    # rollback demonstration
    with db.session() as s:
        before = versions.get_active(s).id
    rolled = None
    if before != v1:
        rolled = coord.rollback(OPERATOR)
        with db.session() as s:
            after = versions.get_active(s).id
        log.append(f"rollback: active v{before} -> v{after}")
        rollback_info = {"from": before, "to": after}
        coord.rollback(OPERATOR, to_version_id=before)  # restore the latest accepted state
        with db.session() as s:
            rollback_info["restored_to"] = versions.get_active(s).id
    else:
        rollback_info = {"note": "no accepted candidate; rollback not exercised"}
    # held-out final test
    ablations = build_ablations(coord, [cA, cB])
    with db.session() as s:
        vids = [v.id for v in s.execute(select(DetectorVersion).order_by(DetectorVersion.id)).scalars()]
    t_ft = time.time()
    final_test_execute(coord, trials=settings.experiment.retest_trials,
                       benign_rounds=settings.experiment.benign_windows_per_phase + 4)
    ft = final_test_evaluate(db, vids)
    log.append(f"final test ({time.time() - t_ft:.0f}s)")
    cpu1 = proc.cpu_times()
    extra = {"log": log, "cases": cases, "rollback": rollback_info, "ablation_version_ids": ablations,
             "resources": {"wall_s": round(time.time() - t_start, 1), "cpu_user_s": cpu1.user - cpu0.user,
                           "cpu_system_s": cpu1.system - cpu0.system, "rss_mb": proc.memory_info().rss / 2**20},
             "final_test": ft}
    results = collect_results(settings, db, db_path, out_dir, extra, live_intel)
    return results


def collect_results(settings: Settings, db: Database, db_path: Path, out_dir: Path, extra: dict,
                    live_intel: bool = False) -> dict:
    """Assemble results from the experiment database (re-runnable), write JSON + Markdown reports."""
    out_dir.mkdir(parents=True, exist_ok=True)
    if "final_test" not in extra:
        with db.session() as s:
            vids = [v.id for v in s.execute(select(DetectorVersion).order_by(DetectorVersion.id)).scalars()]
        extra["final_test"] = final_test_evaluate(db, vids)
    safety = safety_checks(settings)
    with db.session() as s:
        chain = audit.verify(s)
        integrity = timing_integrity(s, settings)
    tamper = tamper_check(db_path, settings.path("data"))
    case_dir = out_dir / "cases"
    case_dir.mkdir(exist_ok=True)
    with db.session() as s:
        for case in s.execute(select(Case)).scalars():
            rep = s.execute(select(Report).where(Report.case_id == case.id).order_by(Report.id.desc())).scalars().first()
            if rep:
                (case_dir / f"case_{case.id}.md").write_text(rep.content_md, encoding="utf-8")
        case_rows = [{"id": c.id, "finding": c.idempotency_key, "scenario": c.scenario_id, "state": c.state,
                      "cycles": c.adaptation_cycles} for c in s.execute(select(Case)).scalars()]
        evals = [{"id": e.id, "case_id": e.case_id, "candidate": e.candidate_version_id, "passed": e.passed,
                  "inconclusive": e.inconclusive, "checks": e.results["checks"],
                  "objective": (s.get(Case, e.case_id).criteria or {}).get("objective", "detection")}
                 for e in s.execute(select(Evaluation)).scalars()]
        baselines = {}
        for c in s.execute(select(Case)).scalars():
            if c.baseline_summary:
                b = dict(c.baseline_summary)
                b["benign"] = {k: v for k, v in b["benign"].items() if k != "false_positives"}
                baselines[c.id] = b
        ver_rows = [{"id": v.id, "name": v.name, "status": v.status, "active": v.is_active, "parent": v.parent_id,
                     "bundle_hash": v.bundle_hash,
                     "rules": [r["id"] + f" {r['feature']}>={r['threshold']}" for r in v.ruleset],
                     "lab_config": v.lab_config, "policy": v.detector_policy,
                     "label_counts": v.label_set.get("label_counts")} for v in
                    s.execute(select(DetectorVersion).order_by(DetectorVersion.id)).scalars()]
    results = {
        "generated_at": datetime.now(timezone.utc).isoformat(), "database": str(db_path),
        "environment": {"python": sys.version.split()[0], "platform": platform.platform(),
                        "sklearn": sklearn.__version__, "numpy": np.__version__, "pandas": pd.__version__,
                        "cpu_count": psutil.cpu_count(), "config_hash": settings.config_hash(),
                        "base_seed": settings.experiment.base_seed},
        "scope": {"lab": "loopback services + application-level sensor + synthetic benign generator",
                  "threat_intel": "synthetic fixtures (SYNTH- IDs) drive the cases"
                                  + ("; live NVD/ATT&CK also retrieved" if live_intel else ""),
                  "operator": f"scripted ({OPERATOR}); candidate order fixed in advance",
                  "trials_per_phase": settings.experiment.baseline_trials,
                  "benign_rounds_per_phase": settings.experiment.benign_windows_per_phase,
                  "benign_users": settings.experiment.benign_users,
                  "window_seconds": settings.monitoring.window_seconds},
        "log": extra.get("log", []), "cases": extra.get("cases", {}), "case_states": case_rows, "evaluations": evals,
        "baselines": baselines, "versions": ver_rows, "rollback": extra.get("rollback", {}),
        "ablation_version_ids": extra.get("ablation_version_ids", []), "final_test": extra["final_test"],
        "safety_checks": safety, "audit_chain": chain, "timing_integrity": integrity, "audit_tamper_test": tamper,
        "resources": extra.get("resources", {})}
    (out_dir / "experiment_results.json").write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    from .report import write_report
    write_report(results, out_dir / "experiment_report.md")
    return results
