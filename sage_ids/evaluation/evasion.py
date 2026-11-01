"""Robustness evaluation: run reviewed evasive variants against ACCEPTED detector versions.

For each evasive variant and each version under test, trials are executed on the live lab, telemetry
is turned into windows, and detection is measured per trial (paired on identical trials across versions).
This quantifies how much of an accepted improvement survives low-and-slow / distributed attacks — a
limitation the main experiment cannot show because its scenarios are not evasive.
"""
from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select

from ..agents.adversarial import AdversarialAgent
from ..agents.monitoring import MonitoringAgent
from ..config import Settings, load_yaml
from ..db import Database, DetectorVersion, ExperimentRun
from ..schemas import ScenarioSpec
from ..evaluation.stats import wilson


def load_evasion_catalogue() -> dict[str, ScenarioSpec]:
    return {d["id"]: ScenarioSpec.model_validate(d) for d in load_yaml("evasion_scenarios.yaml")}


# which baseline (non-evasive) scenario each evasive variant corresponds to, for the comparison
BASE_OF = {"auth-slow-guessing": "auth-password-guessing", "auth-distributed-guessing": "auth-password-guessing",
           "app-low-rate-flood": "app-request-flood"}


def run_evasion(settings: Settings, db_path: Path, out_dir: Path, trials: int = 12) -> dict:
    settings.database_url = f"sqlite:///{db_path.as_posix()}"
    settings.lab.active_scenarios_enabled = True
    db = Database(settings.database_url)
    adv = AdversarialAgent(settings)
    mon = MonitoringAgent(settings)
    cat = load_evasion_catalogue()
    adv.catalogue = {**adv.catalogue, **cat}            # allow the evasive IDs through the approved check
    with db.session() as s:
        versions = s.execute(select(DetectorVersion).where(DetectorVersion.status.in_(["accepted", "retired"]))
                             .order_by(DetectorVersion.id)).scalars().all()
        vids = [v.id for v in versions]
        vmap = {v.id: v.name for v in versions}
    seed0 = settings.experiment.base_seed + 7_000_000
    results = {"generated_at": datetime.now(timezone.utc).isoformat(), "versions": vmap, "variants": {}}
    with db.session() as s:
        for vi, sid in enumerate(cat):
            spec = cat[sid]
            adv.start_phase({})
            runs = adv.run_trials(s, case_id=None, scenario_id=sid, phase=f"evasion:{sid}", n_trials=trials,
                                  seed_base=seed0 + 1000 * vi, lab_config={}, version_id=None)
            s.commit()
            ev = mon.store_events(s, adv.drain_telemetry(), "live_lab")
            win, _ = mon.build_windows(s, ev, runs, "live_lab")
            per_version = {}
            for v in versions:
                res = mon.detect(s, v, win, ev, "live_lab", store=False)
                rds = mon.run_detections(s, v, win, res, runs)
                det = [rds[r.id].detected for r in runs if r.executed]
                k, n = sum(det), len(det)
                p, lo, hi = wilson(k, n)
                per_version[v.id] = {"detected": k, "n": n, "rate": p, "ci95": [lo, hi]}
            executed = [r for r in runs if r.executed]
            results["variants"][sid] = {
                "base_scenario": BASE_OF[sid], "executor": spec.executor, "n_trials": len(runs),
                "n_executed": len(executed),
                "effect_rate": sum(bool(r.effect_occurred) for r in executed) / max(len(executed), 1),
                "detection_by_version": per_version}
            s.commit()
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "evasion_results.json").write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    _md(results, out_dir / "evasion_report.md")
    return results


def _md(r: dict, path: Path) -> None:
    vids = list(r["versions"])
    L = [f"# Robustness: evasive variants vs accepted detectors", "",
         f"Generated {r['generated_at']}. Reviewed evasive variants (low-and-slow, distributed, low-rate) run on the "
         "live lab against each accepted/retired detector version. Detection rate with Wilson 95% CI; attacks still "
         "achieve their effect (that is the point of an evasive variant).", "",
         "| variant | base scenario | effect rate | " + " | ".join(f"v{v} {r['versions'][v]}" for v in vids) + " |",
         "|---|---|---|" + "---|" * len(vids)]
    for sid, d in r["variants"].items():
        cells = []
        for v in vids:
            pv = d["detection_by_version"].get(str(v)) or d["detection_by_version"].get(v)
            cells.append(f"{pv['detected']}/{pv['n']} = {pv['rate']:.2f} [{pv['ci95'][0]:.2f}, {pv['ci95'][1]:.2f}]"
                         if pv else "—")
        L.append(f"| {sid} | {d['base_scenario']} | {d['effect_rate']:.2f} | " + " | ".join(cells) + " |")
    L += ["", "Interpretation: where an accepted version detected the *non-evasive* scenario well but detects the "
          "evasive variant poorly, the accepted threshold/model is evadable by that technique. This is a limitation "
          "of behavioural per-source thresholds, reported honestly rather than hidden."]
    path.write_text("\n".join(L), encoding="utf-8")
