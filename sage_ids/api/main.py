"""SAGE-IDS REST API (FastAPI). Binds to 127.0.0.1 by default.

Privilege separation:
  * viewer   -- read-only endpoints (header `X-API-Key: $SAGE_VIEWER_KEY`; open on localhost if unset)
  * operator -- privileged laboratory/coordinator actions (header `X-API-Key: $SAGE_OPERATOR_KEY` and
                `X-Operator: <name>`). If SAGE_OPERATOR_KEY is unset, privileged endpoints are DISABLED.
Run: uvicorn sage_ids.api.main:app --host 127.0.0.1 --port 8000
"""
from __future__ import annotations

import hmac
from contextlib import asynccontextmanager
import os
import threading
import uuid
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from .. import audit
from ..config import load_settings
from ..coordinator.coordinator import Coordinator
from ..coordinator.state_machine import ALL_STATES, TransitionError
from ..db import (Asset, AuditEntry, Case, Database, DetectorVersion, Evaluation, ExperimentRun, FeatureWindow,
                  Prediction, RemediationProposal, Report, RunDetection, TelemetryEvent, ThreatFinding, Transition,
                  row_to_dict)
from ..detection.versions import VersionError, get_active
from ..lab.scenarios import load_catalogue
from ..security.allowlist import ActiveLabDisabled
from ..security.redaction import configure_logging

configure_logging()
settings = load_settings()
db = Database(settings.database_url)
coord = Coordinator(settings, db)


@asynccontextmanager
async def lifespan(_app):  # noqa: ANN001
    coord.recover()          # stale running cases from a previous process are timed out, never resumed
    yield


app = FastAPI(title="SAGE-IDS API", version="0.1.0", lifespan=lifespan,
              description="Self-Evolving Cyber Defense through Closed-Loop Multi-Agent Adversarial Validation "
                          "(research prototype; project 28_CS_4E_04)")
JOBS: dict[str, dict] = {}

PROJECT = {"id": "28_CS_4E_04", "title": "SAGE-IDS: Self-Evolving Cyber Defense through Closed-Loop Multi-Agent "
           "Adversarial Validation and Adaptive Intrusion Detection",
           "team": [{"name": "Anand Rawat", "roll": "2401640100165"}, {"name": "Anandi Singh", "roll": "2401640100167"},
                    {"name": "Ananya Agarwal", "roll": "2401640100171"}],
           "department": "CSE", "section": "CS3E", "mentor": "Mr Ashutosh Pandey, Assistant Professor",
           "domains": ["Agentic AI", "Cryptography and Network Security"]}


def _eq(a: str | None, b: str | None) -> bool:
    return bool(a) and bool(b) and hmac.compare_digest(a.encode(), b.encode())


def viewer(x_api_key: str | None = Header(default=None)) -> str:
    vk, ok = os.environ.get("SAGE_VIEWER_KEY"), os.environ.get("SAGE_OPERATOR_KEY")
    if vk is None or _eq(x_api_key, vk) or _eq(x_api_key, ok):
        return "viewer"
    raise HTTPException(401, "viewer API key required")


def operator(x_api_key: str | None = Header(default=None), x_operator: str | None = Header(default=None)) -> str:
    ok = os.environ.get("SAGE_OPERATOR_KEY")
    if not ok:
        raise HTTPException(403, "privileged actions disabled: SAGE_OPERATOR_KEY is not configured")
    if not _eq(x_api_key, ok):
        raise HTTPException(401, "operator API key required")
    name = (x_operator or "").strip()
    if not name or len(name) > 64 or not name.replace("-", "").replace("_", "").replace(".", "").isalnum():
        raise HTTPException(400, "X-Operator header with a simple operator name is required")
    return f"operator:{name}"


def _rows(objs) -> list[dict]:
    return [row_to_dict(o) for o in objs]


def _guard(fn, *a, **kw) -> Any:
    try:
        return fn(*a, **kw)
    except (TransitionError, VersionError) as e:
        raise HTTPException(409, str(e)) from e
    except ActiveLabDisabled as e:
        raise HTTPException(403, str(e)) from e


def _background(kind: str, fn, *args) -> dict:
    job = {"id": uuid.uuid4().hex[:12], "kind": kind, "status": "running", "result": None, "error": None}
    JOBS[job["id"]] = job

    def run():
        try:
            job["result"], job["status"] = fn(*args), "completed"
        except Exception as e:  # noqa: BLE001
            job["status"], job["error"] = "failed", f"{type(e).__name__}: {e}"
    threading.Thread(target=run, daemon=True).start()
    return job


# ------------------------------------------------------------------------- read-only
@app.get("/health")
def health(_: str = Depends(viewer)) -> dict:
    with db.session() as s:
        act = get_active(s)
        chain = audit.verify(s)
        counts = {name: s.execute(select(func.count(m.id))).scalar_one() for name, m in
                  (("findings", ThreatFinding), ("cases", Case), ("runs", ExperimentRun), ("events", TelemetryEvent),
                   ("alerts", Prediction), ("versions", DetectorVersion), ("reports", Report))}
        states = dict(s.execute(select(Case.state, func.count(Case.id)).group_by(Case.state)).all())
    from ..lab import runtime
    return {"database": settings.database_url.split("///")[-1], "active_version": act.id if act else None,
            "active_version_name": act.name if act else None,
            "lab": {"active_scenarios_enabled": settings.lab.active_scenarios_enabled,
                    "services_running": runtime._lab is not None,
                    "service_health": runtime._lab.health() if runtime._lab else None},
            "llm_provider": settings.llm.provider, "audit_chain": chain, "counts": counts, "case_states": states,
            "privileged_actions_enabled": bool(os.environ.get("SAGE_OPERATOR_KEY")), "jobs": list(JOBS.values())[-10:]}


@app.get("/about")
def about() -> dict:
    return PROJECT


@app.get("/states")
def states(_: str = Depends(viewer)) -> list[str]:
    return ALL_STATES


@app.get("/findings")
def findings(_: str = Depends(viewer)) -> list[dict]:
    with db.session() as s:
        return _rows(s.execute(select(ThreatFinding).order_by(ThreatFinding.id.desc())).scalars())


@app.get("/assets")
def assets(_: str = Depends(viewer)) -> list[dict]:
    with db.session() as s:
        if not s.execute(select(Asset)).first():
            coord.research.sync_assets(s)
        return _rows(s.execute(select(Asset)).scalars())


@app.get("/scenarios")
def scenarios(_: str = Depends(viewer)) -> list[dict]:
    return [sp.model_dump() for sp in load_catalogue().values()]


@app.get("/cases")
def cases(state: str | None = None, _: str = Depends(viewer)) -> list[dict]:
    with db.session() as s:
        q = select(Case).order_by(Case.id)
        if state:
            q = q.where(Case.state == state)
        return [{k: v for k, v in row_to_dict(c).items() if k != "baseline_summary"} for c in s.execute(q).scalars()]


@app.get("/cases/{case_id}")
def case_detail(case_id: int, _: str = Depends(viewer)) -> dict:
    with db.session() as s:
        c = s.get(Case, case_id)
        if not c:
            raise HTTPException(404, "case not found")
        return {"case": row_to_dict(c),
                "transitions": _rows(s.execute(select(Transition).where(Transition.case_id == case_id)
                                               .order_by(Transition.id)).scalars()),
                "proposals": _rows(s.execute(select(RemediationProposal).where(
                    RemediationProposal.case_id == case_id)).scalars()),
                "evaluations": _rows(s.execute(select(Evaluation).where(Evaluation.case_id == case_id)).scalars())}


@app.get("/cases/{case_id}/report")
def case_report(case_id: int, regenerate: bool = False, _: str = Depends(viewer)) -> dict:
    with db.session() as s:
        if not s.get(Case, case_id):
            raise HTTPException(404, "case not found")
        rep = s.execute(select(Report).where(Report.case_id == case_id).order_by(Report.id.desc())).scalars().first()
    if rep is None or regenerate:
        coord.report(case_id)
        with db.session() as s:
            rep = s.execute(select(Report).where(Report.case_id == case_id).order_by(Report.id.desc())).scalars().first()
    return row_to_dict(rep)


@app.get("/runs")
def runs(case_id: int | None = None, phase: str | None = None, limit: int = Query(500, le=5000),
         _: str = Depends(viewer)) -> list[dict]:
    with db.session() as s:
        q = select(ExperimentRun).order_by(ExperimentRun.id.desc()).limit(limit)
        if case_id is not None:
            q = q.where(ExperimentRun.case_id == case_id)
        if phase:
            q = q.where(ExperimentRun.phase == phase)
        out = _rows(s.execute(q).scalars())
        dets = s.execute(select(RunDetection).where(RunDetection.run_id.in_([r["id"] for r in out]))).scalars().all()
        by = {}
        for d in dets:
            by.setdefault(d.run_id, []).append(row_to_dict(d))
        for r in out:
            r["detections"] = by.get(r["id"], [])
        return out


@app.get("/alerts")
def alerts(limit: int = Query(200, le=5000), data_origin: str | None = None, _: str = Depends(viewer)) -> list[dict]:
    with db.session() as s:
        q = select(Prediction).where(Prediction.is_alert.is_(True)).order_by(Prediction.id.desc()).limit(limit)
        if data_origin:
            q = q.where(Prediction.data_origin == data_origin)
        return _rows(s.execute(q).scalars())


@app.get("/events")
def events(limit: int = Query(200, le=5000), _: str = Depends(viewer)) -> list[dict]:
    with db.session() as s:
        return _rows(s.execute(select(TelemetryEvent).order_by(TelemetryEvent.id.desc()).limit(limit)).scalars())


@app.get("/windows")
def windows(limit: int = Query(200, le=5000), _: str = Depends(viewer)) -> list[dict]:
    with db.session() as s:
        return _rows(s.execute(select(FeatureWindow).order_by(FeatureWindow.id.desc()).limit(limit)).scalars())


@app.get("/versions")
def list_versions(_: str = Depends(viewer)) -> list[dict]:
    with db.session() as s:
        return _rows(s.execute(select(DetectorVersion).order_by(DetectorVersion.id)).scalars())


@app.get("/audit")
def audit_log(limit: int = Query(200, le=5000), _: str = Depends(viewer)) -> list[dict]:
    with db.session() as s:
        return _rows(s.execute(select(AuditEntry).order_by(AuditEntry.id.desc()).limit(limit)).scalars())


@app.get("/audit/verify")
def audit_verify(_: str = Depends(viewer)) -> dict:
    with db.session() as s:
        return audit.verify(s)


@app.get("/jobs/{job_id}")
def job(job_id: str, _: str = Depends(viewer)) -> dict:
    if job_id not in JOBS:
        raise HTTPException(404, "unknown job")
    return JOBS[job_id]


# ------------------------------------------------------------------------- privileged (operator)
class ResearchReq(BaseModel):
    mode: str = Field("fixture", pattern="^(fixture|live)$")


class PrepareReq(BaseModel):
    proposal_id: int


class ReasonReq(BaseModel):
    reason: str = Field("operator decision", max_length=500)


class RollbackReq(BaseModel):
    to_version_id: int | None = None


@app.post("/research")
def research(req: ResearchReq, op: str = Depends(operator)) -> dict:
    return {"cases": _guard(coord.ingest_findings, req.mode), "by": op}


@app.post("/bootstrap")
def bootstrap(op: str = Depends(operator)) -> dict:
    if not settings.lab.active_scenarios_enabled:
        raise HTTPException(403, "active laboratory disabled")
    return _background("bootstrap", coord.bootstrap, op)


@app.post("/cases/{case_id}/approve")
def approve(case_id: int, op: str = Depends(operator)) -> dict:
    _guard(coord.approve_scenario, case_id, op, True)
    return {"ok": True}


@app.post("/cases/{case_id}/deny")
def deny(case_id: int, req: ReasonReq, op: str = Depends(operator)) -> dict:
    _guard(coord.approve_scenario, case_id, op, False, req.reason)
    return {"ok": True}


@app.post("/cases/{case_id}/baseline")
def baseline(case_id: int, op: str = Depends(operator)) -> dict:
    if not settings.lab.active_scenarios_enabled:
        raise HTTPException(403, "active laboratory disabled")
    return _background(f"baseline:{case_id}", coord.run_baseline, case_id)


@app.post("/cases/{case_id}/prepare")
def prepare(case_id: int, req: PrepareReq, op: str = Depends(operator)) -> dict:
    return {"candidate_version_id": _guard(coord.prepare_candidate, case_id, req.proposal_id, op)}


@app.post("/cases/{case_id}/retest")
def retest(case_id: int, op: str = Depends(operator)) -> dict:
    if not settings.lab.active_scenarios_enabled:
        raise HTTPException(403, "active laboratory disabled")
    return _background(f"retest:{case_id}", coord.run_retest, case_id)


@app.post("/cases/{case_id}/accept")
def accept(case_id: int, op: str = Depends(operator)) -> dict:
    return {"activated_version_id": _guard(coord.accept, case_id, op)}


@app.post("/cases/{case_id}/reject")
def reject(case_id: int, req: ReasonReq, op: str = Depends(operator)) -> dict:
    _guard(coord.reject, case_id, op, req.reason)
    return {"ok": True}


@app.post("/cases/{case_id}/cancel")
def cancel(case_id: int, op: str = Depends(operator)) -> dict:
    return {"result": _guard(coord.cancel, case_id, op)}


@app.post("/versions/rollback")
def rollback(req: RollbackReq, op: str = Depends(operator)) -> dict:
    return {"active_version_id": _guard(coord.rollback, op, req.to_version_id)}
