"""Versioned detector bundles: proposed (candidate) vs accepted changes, activation and rollback."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..audit import canonical, sha256_hex
from ..db import DetectorVersion, utcnow
from .features import SCHEMA_HASH, SCHEMA_VERSION


class VersionError(RuntimeError):
    pass


def bundle_hash(v: DetectorVersion) -> str:
    return sha256_hex(canonical({"ruleset": v.ruleset, "lab_config": v.lab_config, "policy": v.detector_policy,
                                 "model_sha256": v.model_sha256, "schema": v.feature_schema_hash,
                                 "label_set": v.label_set}))


def create_version(s: Session, *, name: str, parent_id: int | None, ruleset: list, lab_config: dict,
                   detector_policy: dict, model_path: str | None, model_sha256: str | None,
                   label_set: dict, notes: str = "", actor: str = "remediation") -> DetectorVersion:
    v = DetectorVersion(name=name, parent_id=parent_id, status="candidate", is_active=False, ruleset=ruleset,
                        lab_config=lab_config, detector_policy=detector_policy, model_path=model_path,
                        model_sha256=model_sha256, feature_schema=SCHEMA_VERSION,
                        feature_schema_hash=SCHEMA_HASH, label_set=label_set, notes=notes)
    v.bundle_hash = bundle_hash(v)
    s.add(v)
    s.flush()
    audit.append(s, actor, "version_created", "detector_version", v.id,
                 {"name": name, "parent_id": parent_id, "bundle_hash": v.bundle_hash})
    return v


def get_active(s: Session) -> DetectorVersion | None:
    return s.execute(select(DetectorVersion).where(DetectorVersion.is_active.is_(True))).scalar_one_or_none()


def _activate(s: Session, v: DetectorVersion) -> None:
    for other in s.execute(select(DetectorVersion).where(DetectorVersion.is_active.is_(True))).scalars():
        other.is_active = False
    v.is_active = True


def accept(s: Session, version_id: int, operator: str, evaluation_passed: bool | None,
           bootstrap: bool = False) -> DetectorVersion:
    """Activate a candidate. Requires an operator identity and a passed evaluation,
    except for the documented one-time bootstrap of the initial baseline."""
    v = s.get(DetectorVersion, version_id)
    if v is None or v.status != "candidate":
        raise VersionError(f"version {version_id} is not a candidate")
    if not operator or operator.startswith(("agent:", "llm")):
        raise VersionError("activation requires a human operator identity")
    if not bootstrap and evaluation_passed is not True:
        raise VersionError("candidate has not passed the frozen acceptance criteria")
    if bundle_hash(v) != v.bundle_hash:
        raise VersionError("candidate bundle changed after creation")
    v.status, v.accepted_at, v.accepted_by = "accepted", utcnow(), operator
    _activate(s, v)
    audit.append(s, operator, "version_accepted", "detector_version", v.id,
                 {"bundle_hash": v.bundle_hash, "bootstrap": bootstrap})
    return v


def reject(s: Session, version_id: int, actor: str, reason: str) -> DetectorVersion:
    v = s.get(DetectorVersion, version_id)
    if v is None or v.status != "candidate":
        raise VersionError(f"version {version_id} is not a candidate")
    v.status = "rejected"
    audit.append(s, actor, "version_rejected", "detector_version", v.id, {"reason": reason})
    return v


def rollback(s: Session, operator: str, to_version_id: int | None = None) -> DetectorVersion:
    """Re-activate a previously accepted version (default: the most recent accepted before the active one)."""
    cur = get_active(s)
    if to_version_id is None:
        q = select(DetectorVersion).where(DetectorVersion.status.in_(["accepted", "retired"]))
        if cur:
            q = q.where(DetectorVersion.id < cur.id)
        target = s.execute(q.order_by(DetectorVersion.id.desc()).limit(1)).scalar_one_or_none()
    else:
        target = s.get(DetectorVersion, to_version_id)
    if target is None or target.status not in ("accepted", "retired"):
        raise VersionError("no previously accepted version to roll back to")
    if cur and cur.id == target.id:
        raise VersionError("target version is already active")
    if cur:
        cur.status = "retired"
    target.status = "accepted"
    _activate(s, target)
    audit.append(s, operator, "version_rollback", "detector_version", target.id,
                 {"from_version": cur.id if cur else None, "to_version": target.id})
    return target
