"""Persistent storage (SQLAlchemy 2.0 + SQLite)."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from sqlalchemy import (JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text,
                        UniqueConstraint, create_engine, event)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class AuditEntry(Base):
    """Hash-chained, append-only audit ledger (see sage_ids/audit.py)."""
    __tablename__ = "audit_entries"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    entity_type: Mapped[str] = mapped_column(String(64))
    entity_id: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64), unique=True)


class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    host: Mapped[str] = mapped_column(String(64))
    environment: Mapped[str] = mapped_column(String(32), default="lab")
    services: Mapped[list] = mapped_column(JSON, default=list)
    products: Mapped[list] = mapped_column(JSON, default=list)
    cwe_exposure: Mapped[list] = mapped_column(JSON, default=list)
    techniques: Mapped[list] = mapped_column(JSON, default=list)


class ThreatFinding(Base):
    __tablename__ = "threat_findings"
    __table_args__ = (UniqueConstraint("source", "source_id", name="uq_finding_source"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(32))          # nvd | mitre_attack | advisory
    source_id: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(256))
    description: Mapped[str] = mapped_column(Text)            # sanitised, untrusted data
    url: Mapped[str] = mapped_column(String(512), default="")
    published_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_modified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    first_retrieved_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_retrieved_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    content_hash: Mapped[str] = mapped_column(String(64))
    cwe_ids: Mapped[list] = mapped_column(JSON, default=list)
    cpes: Mapped[list] = mapped_column(JSON, default=list)
    techniques: Mapped[list] = mapped_column(JSON, default=list)
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    newly_published: Mapped[bool] = mapped_column(Boolean, default=False)
    newly_retrieved: Mapped[bool] = mapped_column(Boolean, default=True)
    relevance: Mapped[dict] = mapped_column(JSON, default=dict)
    provenance: Mapped[dict] = mapped_column(JSON, default=dict)
    data_origin: Mapped[str] = mapped_column(String(32))     # live_internet | synthetic_fixture


class Case(Base):
    """One closed-loop validation workflow (coordinator state machine instance)."""
    __tablename__ = "cases"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    idempotency_key: Mapped[str] = mapped_column(String(128), unique=True)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("threat_findings.id"), nullable=True)
    asset_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    scenario_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    state: Mapped[str] = mapped_column(String(48))
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    adaptation_cycles: Mapped[int] = mapped_column(Integer, default=0)
    baseline_version_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    candidate_version_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    criteria: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    criteria_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    baseline_summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    lock_token: Mapped[str | None] = mapped_column(String(64), nullable=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Transition(Base):
    __tablename__ = "transitions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"))
    from_state: Mapped[str] = mapped_column(String(48))
    to_state: Mapped[str] = mapped_column(String(48))
    actor: Mapped[str] = mapped_column(String(64))
    role: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    audit_hash: Mapped[str] = mapped_column(String(64), default="")


class DetectorVersion(Base):
    """Versioned bundle: rules + model + lab config + feature schema + label set."""
    __tablename__ = "detector_versions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64))
    parent_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(16))           # candidate|accepted|rejected|retired
    is_active: Mapped[bool] = mapped_column(Boolean, default=False)
    ruleset: Mapped[list] = mapped_column(JSON, default=list)
    lab_config: Mapped[dict] = mapped_column(JSON, default=dict)
    detector_policy: Mapped[dict] = mapped_column(JSON, default=dict)   # which detectors may alert
    model_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    model_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    feature_schema: Mapped[str] = mapped_column(String(32))
    feature_schema_hash: Mapped[str] = mapped_column(String(64))
    label_set: Mapped[dict] = mapped_column(JSON, default=dict)
    bundle_hash: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    accepted_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    notes: Mapped[str] = mapped_column(Text, default="")


class RemediationProposal(Base):
    __tablename__ = "remediation_proposals"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"))
    title: Mapped[str] = mapped_column(String(256))
    changes: Mapped[list] = mapped_column(JSON, default=list)
    rationale: Mapped[str] = mapped_column(Text)
    affected_artifacts: Mapped[list] = mapped_column(JSON, default=list)
    expected_effect: Mapped[str] = mapped_column(Text)
    validation_steps: Mapped[list] = mapped_column(JSON, default=list)
    rollback: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="proposed")  # proposed|prepared|accepted|rejected
    candidate_version_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    generated_by: Mapped[str] = mapped_column(String(32), default="deterministic")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ExperimentRun(Base):
    __tablename__ = "experiment_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    phase: Mapped[str] = mapped_column(String(32))            # calibration|baseline|retest|regression|benign
    scenario_id: Mapped[str] = mapped_column(String(64))
    trial_index: Mapped[int] = mapped_column(Integer, default=0)
    seed: Mapped[int] = mapped_column(Integer)
    src_ip: Mapped[str] = mapped_column(String(64))
    lab_config: Mapped[dict] = mapped_column(JSON, default=dict)
    version_id: Mapped[int | None] = mapped_column(Integer, nullable=True)  # lab config in force
    started_at: Mapped[float] = mapped_column(Float)
    ended_at: Mapped[float] = mapped_column(Float)
    executed: Mapped[bool] = mapped_column(Boolean)
    execution_error: Mapped[str] = mapped_column(Text, default="")
    effect_occurred: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    effect_evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    stop_reason: Mapped[str] = mapped_column(String(64), default="")
    data_origin: Mapped[str] = mapped_column(String(32), default="live_lab")


class RunDetection(Base):
    """Detection outcome of one detector version on the telemetry of one run (paired design)."""
    __tablename__ = "run_detections"
    __table_args__ = (UniqueConstraint("run_id", "version_id", name="uq_run_version"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("experiment_runs.id"))
    version_id: Mapped[int] = mapped_column(Integer)
    detected: Mapped[bool] = mapped_column(Boolean)
    latency_s: Mapped[float | None] = mapped_column(Float, nullable=True)
    detectors: Mapped[list] = mapped_column(JSON, default=list)
    n_windows: Mapped[int] = mapped_column(Integer, default=0)
    n_alert_windows: Mapped[int] = mapped_column(Integer, default=0)


class TelemetryEvent(Base):
    __tablename__ = "telemetry_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    ts: Mapped[float] = mapped_column(Float, index=True)
    src_ip: Mapped[str] = mapped_column(String(64), index=True)
    src_port: Mapped[int] = mapped_column(Integer, default=0)
    dst_ip: Mapped[str] = mapped_column(String(64))
    dst_port: Mapped[int] = mapped_column(Integer)
    proto: Mapped[str] = mapped_column(String(8), default="tcp")
    service: Mapped[str] = mapped_column(String(32), default="")
    status: Mapped[str] = mapped_column(String(16), default="")
    bytes_in: Mapped[int] = mapped_column(Integer, default=0)
    bytes_out: Mapped[int] = mapped_column(Integer, default=0)
    duration: Mapped[float] = mapped_column(Float, default=0.0)
    sensor: Mapped[str] = mapped_column(String(32))           # lab_sensor | zeek | suricata
    data_origin: Mapped[str] = mapped_column(String(32))      # live_lab | replay | synthetic_fixture


class FeatureWindow(Base):
    __tablename__ = "feature_windows"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    src_ip: Mapped[str] = mapped_column(String(64))
    window_start: Mapped[float] = mapped_column(Float)
    window_end: Mapped[float] = mapped_column(Float)
    schema_version: Mapped[str] = mapped_column(String(32))
    features: Mapped[dict] = mapped_column(JSON)
    event_ids: Mapped[list] = mapped_column(JSON, default=list)
    label: Mapped[str | None] = mapped_column(String(32), nullable=True)
    label_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    label_source: Mapped[str] = mapped_column(String(64), default="")
    data_origin: Mapped[str] = mapped_column(String(32))


class Prediction(Base):
    __tablename__ = "predictions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[float] = mapped_column(Float)
    window_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    version_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    detector: Mapped[str] = mapped_column(String(64))         # rule:<id> | rf | iforest | suricata:<sid>
    src_ip: Mapped[str] = mapped_column(String(64))
    is_alert: Mapped[bool] = mapped_column(Boolean)
    predicted_label: Mapped[str] = mapped_column(String(32))
    score: Mapped[float | None] = mapped_column(Float, nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    data_origin: Mapped[str] = mapped_column(String(32))


class Evaluation(Base):
    __tablename__ = "evaluations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"))
    baseline_version_id: Mapped[int] = mapped_column(Integer)
    candidate_version_id: Mapped[int] = mapped_column(Integer)
    criteria_hash: Mapped[str] = mapped_column(String(64))
    results: Mapped[dict] = mapped_column(JSON)
    passed: Mapped[bool] = mapped_column(Boolean)
    inconclusive: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    kind: Mapped[str] = mapped_column(String(32))
    content_md: Mapped[str] = mapped_column(Text)
    generated_by: Mapped[str] = mapped_column(String(32))
    evidence_refs: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Database:
    def __init__(self, url: str):
        if url.startswith("sqlite:///") and not url.startswith("sqlite:///:memory:"):
            Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(url, connect_args={"check_same_thread": False, "timeout": 30}
                                    if url.startswith("sqlite") else {})
        if url.startswith("sqlite"):
            @event.listens_for(self.engine, "connect")
            def _pragmas(dbapi_conn, _):  # noqa: ANN001
                cur = dbapi_conn.cursor()
                cur.execute("PRAGMA journal_mode=WAL")
                cur.execute("PRAGMA foreign_keys=ON")
                cur.close()
        self.SessionLocal = sessionmaker(bind=self.engine, expire_on_commit=False)
        Base.metadata.create_all(self.engine)

    @contextmanager
    def session(self) -> Iterator[Session]:
        s = self.SessionLocal()
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()


def row_to_dict(obj: Any) -> dict:
    out = {}
    for c in obj.__table__.columns:
        v = getattr(obj, c.name)
        out[c.name] = v.isoformat() if isinstance(v, datetime) else v
    return out
