"""Run the full closed-loop experiment under several base seeds and aggregate the results.

Each seed is an independent realisation (different attacker parameters, trial order, benign traffic,
model seeds). We report, across seeds: the acceptance decision per case, and the held-out final-test
detection metrics of each case's accepted version, with mean and spread. This answers the
single-realisation limitation of one run.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .experiment import run_experiment
from .stats import bootstrap_ci
from ..config import Settings


def run_multiseed(settings: Settings, out_dir: Path, seeds: list[int]) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    per_seed = []
    for sd in seeds:
        s = settings.model_copy(deep=True)
        s.experiment.base_seed = sd
        res = run_experiment(s, out_dir / f"seed_{sd}", live_intel=False)
        per_seed.append({"seed": sd, "database": res["database"], "timing_clean": res["timing_integrity"]["clean"],
                         "cases": {k: {"final_state": v["final_state"], "accepted_version": v["accepted_version"]}
                                   for k, v in res["cases"].items()},
                         "final_test": res["final_test"]})
    agg = _aggregate(per_seed)
    out = {"generated_at": datetime.now(timezone.utc).isoformat(), "seeds": seeds, "per_seed": per_seed,
           "aggregate": agg}
    (out_dir / "multiseed_results.json").write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
    _md(out, out_dir / "multiseed_report.md")
    return out


def _accepted_final(seed_entry: dict) -> dict:
    """Per-scenario detection of each seed's final active version on its own held-out test."""
    ft = seed_entry["final_test"]
    active = next((v for v, d in ft["versions"].items() if d["status"] == "accepted" and
                   seed_entry["cases"]), None)
    # the active version is the last accepted; find it via case outcomes
    acc_versions = {d["accepted_version"] for d in seed_entry["cases"].values() if d["accepted_version"]}
    out = {}
    for v, d in ft["versions"].items():
        if int(v) in acc_versions:
            for sid, p in d["per_scenario"].items():
                out.setdefault(sid, []).append(p["rate"])
    return out


def _aggregate(per_seed: list[dict]) -> dict:
    # case decision stability
    decisions: dict[str, list[str]] = {}
    for e in per_seed:
        for case, d in e["cases"].items():
            decisions.setdefault(case, []).append(d["final_state"])
    # final-test per-scenario detection of v1 (baseline) and best accepted, across seeds
    v1_by_scenario: dict[str, list[float]] = {}
    acc_by_scenario: dict[str, list[float]] = {}
    for e in per_seed:
        ft = e["final_test"]
        v1 = ft.get("v1_id")
        if v1 and v1 in ft["versions"]:
            for sid, p in ft["versions"][v1]["per_scenario"].items():
                v1_by_scenario.setdefault(sid, []).append(p["rate"])
        acc_versions = {d["accepted_version"] for d in e["cases"].values() if d["accepted_version"]}
        best: dict[str, float] = {}
        for v, d in ft["versions"].items():
            if int(v) in acc_versions:
                for sid, p in d["per_scenario"].items():
                    best[sid] = max(best.get(sid, 0.0), p["rate"])
        for sid, r in best.items():
            acc_by_scenario.setdefault(sid, []).append(r)

    def summ(d):
        out = {}
        for sid, xs in d.items():
            m, lo, hi = bootstrap_ci(xs) if len(xs) > 1 else (xs[0], xs[0], xs[0])
            out[sid] = {"mean": m, "ci95": [lo, hi], "values": xs}
        return out
    return {"case_decisions": decisions, "v1_detection_by_scenario": summ(v1_by_scenario),
            "accepted_detection_by_scenario": summ(acc_by_scenario),
            "timing_clean_all": all(e["timing_clean"] for e in per_seed)}


def _md(o: dict, path: Path) -> None:
    a = o["aggregate"]
    L = [f"# Multi-seed experiment ({len(o['seeds'])} realisations)", "",
         f"Generated {o['generated_at']}. Seeds: {o['seeds']}. Timing clean on all seeds: {a['timing_clean_all']}.", "",
         "## Case decision stability across seeds", "", "| case | final states across seeds |", "|---|---|"]
    for case, states in a["case_decisions"].items():
        L.append(f"| {case} | {', '.join(states)} |")
    L += ["", "## Held-out detection rate by scenario across seeds (mean [95% bootstrap CI])", "",
          "| scenario | initial v1 | accepted version |", "|---|---|---|"]
    for sid in sorted(set(a["v1_detection_by_scenario"]) | set(a["accepted_detection_by_scenario"])):
        v1 = a["v1_detection_by_scenario"].get(sid)
        ac = a["accepted_detection_by_scenario"].get(sid)
        f = lambda x: f"{x['mean']:.2f} [{x['ci95'][0]:.2f}, {x['ci95'][1]:.2f}]" if x else "—"
        L.append(f"| {sid} | {f(v1)} | {f(ac)} |")
    L += ["", "Each seed is an independent run (attacker parameters, trial order, benign traffic and model seeds all "
          "vary). Stable decisions and tight intervals indicate the protocol's outcomes are not an artifact of one "
          "random draw."]
    path.write_text("\n".join(L), encoding="utf-8")
