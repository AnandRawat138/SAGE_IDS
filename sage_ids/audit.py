"""Tamper-evident, hash-chained audit ledger.

Each entry commits to the previous entry's hash:
    h_i = SHA-256( h_{i-1} || canonical_json(actor, action, entity_type, entity_id, payload, ts) )
Any edit, deletion or reordering of an earlier entry breaks verification of every later entry.
This is integrity *evidence*, not a substitute for access control or external anchoring.
"""
from __future__ import annotations

import hashlib
import json
import threading
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import AuditEntry, utcnow
from .security.redaction import redact

GENESIS = "0" * 64
_lock = threading.Lock()


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def _entry_digest(prev_hash: str, actor: str, action: str, entity_type: str, entity_id: str,
                  payload: dict, ts_iso: str) -> str:
    body = canonical({"actor": actor, "action": action, "entity_type": entity_type,
                      "entity_id": entity_id, "payload": payload, "ts": ts_iso})
    return sha256_hex(prev_hash + body)


def append(session: Session, actor: str, action: str, entity_type: str, entity_id: Any,
           payload: dict | None = None) -> AuditEntry:
    payload = json.loads(canonical(redact(payload or {})))
    with _lock:
        last = session.execute(select(AuditEntry).order_by(AuditEntry.id.desc()).limit(1)).scalar_one_or_none()
        prev = last.hash if last else GENESIS
        now = utcnow()
        ts = now.replace(microsecond=(now.microsecond // 1000) * 1000)
        h = _entry_digest(prev, actor, action, entity_type, str(entity_id), payload, ts.isoformat())
        entry = AuditEntry(ts=ts, actor=actor, action=action, entity_type=entity_type,
                           entity_id=str(entity_id), payload=payload, prev_hash=prev, hash=h)
        session.add(entry)
        session.flush()
    return entry


def verify(session: Session) -> dict:
    prev = GENESIS
    n = 0
    for e in session.execute(select(AuditEntry).order_by(AuditEntry.id)).scalars():
        expected = _entry_digest(prev, e.actor, e.action, e.entity_type, e.entity_id, e.payload,
                                 e.ts.isoformat())
        if e.prev_hash != prev or e.hash != expected:
            return {"valid": False, "entries_checked": n, "broken_at_id": e.id}
        prev = e.hash
        n += 1
    return {"valid": True, "entries_checked": n, "head": prev}
