"""Reproducible OFFLINE demo (no active laboratory, no LLM) and telemetry replay helpers."""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
from sqlalchemy import select

from . import audit
from .config import PROJECT_ROOT, Settings, load_yaml
from .db import Case, Database, DetectorVersion, Report
from .detection import versions

FIX = PROJECT_ROOT / "fixtures"
OFFLINE_RULES = load_yaml("baseline_rules.yaml") + [
    {"id": "OFFLINE-AUTH-FAIL", "template": "threshold", "feature": "n_auth_fail", "op": ">=", "threshold": 5,
     "severity": "high", "label": "bruteforce", "description": "demo rule for the offline fixture replay"}]


def _ensure_rules_version(s, operator: str = "operator:offline-demo") -> DetectorVersion:
    v = versions.get_active(s)
    if v:
        return v
    v = versions.create_version(s, name="offline-rules-only", parent_id=None, ruleset=OFFLINE_RULES, lab_config={},
                                detector_policy={"rf": False, "iforest": False}, model_path=None, model_sha256=None,
                                label_set={}, notes="rules-only version for offline replay (no ML model)",
                                actor=operator)
    return versions.accept(s, v.id, operator, None, bootstrap=True)


def replay_into(coord, args) -> dict:  # noqa: ANN001
    """Read-only monitoring of replayed telemetry with the ACTIVE version."""
    from .telemetry.adapters import replay_events, suricata_alerts, zeek_to_events
    mon = coord.monitoring
    out: dict = {"data_origin": args.origin}
    with coord.db.session() as s:
        v = versions.get_active(s) or _ensure_rules_version(s)
        frames = []
        if args.zeek_conn:
            ports = {coord.settings.lab.login_service_port: "login", coord.settings.lab.test_app_port: "test_app"}
            frames.append(zeek_to_events(args.zeek_conn, args.zeek_http, ports, args.origin))
        if args.events:
            frames.append(replay_events(args.events, args.origin))
        if frames:
            ev = mon.store_events(s, pd.concat(frames, ignore_index=True), args.origin)
            win, _ = mon.build_windows(s, ev, [], args.origin)
            res = mon.detect(s, v, win, ev, args.origin)
            out.update(version=v.id, events=int(len(ev)), windows=int(len(win)),
                       alerts=[{"src_ip": w["src_ip"], "window_start": w["window_start"], "detectors": r["detectors"],
                                "label": r["predicted_label"]} for w, r in zip(win.to_dict("records"), res) if r["is_alert"]])
        if args.suricata_eve:
            out["suricata_alerts_ingested"] = mon.ingest_suricata(s, suricata_alerts(args.suricata_eve, args.origin))
    return out


def offline_demo(settings: Settings) -> str:
    from .coordinator.coordinator import Coordinator
    from .evaluation.experiment import safety_checks
    db_path = settings.path("data") / "offline_demo.db"
    for suffix in ("", "-wal", "-shm"):
        Path(str(db_path) + suffix).unlink(missing_ok=True)
    settings.database_url = f"sqlite:///{db_path.as_posix()}"
    settings.lab.active_scenarios_enabled = False
    settings.llm.provider = "none"
    coord = Coordinator(settings, Database(settings.database_url))
    lines = ["SAGE-IDS offline demo — all inputs are SYNTHETIC FIXTURES; active lab disabled; LLM disabled.", ""]
    case_ids = coord.ingest_findings("fixture")
    with coord.db.session() as s:
        for c in s.execute(select(Case).where(Case.id.in_(case_ids))).scalars():
            lines.append(f"  case {c.id}: {c.idempotency_key:<34} -> {c.state:<24} scenario={c.scenario_id}")
    class A:  # replay arguments
        zeek_conn, zeek_http, suricata_eve = str(FIX / "zeek/conn.log"), str(FIX / "zeek/http.log"), str(FIX / "suricata/eve.json")
        events, origin = None, "synthetic_fixture"
    rep = replay_into(coord, A)
    lines += ["", f"Monitoring replay (rules-only version v{rep['version']}): {rep['events']} events, "
                  f"{rep['windows']} windows, {len(rep['alerts'])} alerting windows, "
                  f"{rep.get('suricata_alerts_ingested', 0)} Suricata alerts ingested"]
    for a in rep["alerts"]:
        lines.append(f"  ALERT {a['src_ip']:<12} {a['label']:<11} {a['detectors']}")
    lines += ["", "Active-scenario attempt with the lab disabled:"]
    try:
        coord.approve_scenario(case_ids[0], "operator:offline-demo")
        coord.run_baseline(case_ids[0])
    except Exception as e:  # noqa: BLE001
        lines.append(f"  refused: {type(e).__name__}: {e}")
    with coord.db.session() as s:
        lines.append(f"  case {case_ids[0]} state unchanged: {s.get(Case, case_ids[0]).state}")
    lines += ["", "Target allowlist checks:"]
    for c in safety_checks(settings):
        lines.append(f"  {c['target']:<36} {c['decision']}")
    rid = coord.report(case_ids[0])
    with coord.db.session() as s:
        md = s.get(Report, rid).content_md
        chain = audit.verify(s)
    out = settings.path(settings.reports_dir) / "offline_demo_case_report.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md, encoding="utf-8")
    lines += ["", f"Deterministic report written (no LLM): {out}", f"Audit chain: {json.dumps(chain)}"]
    return "\n".join(lines)
