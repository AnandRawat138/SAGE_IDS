"""Telemetry ingestion adapters -> canonical flow events (lab-v1 input schema).

Canonical event fields: ts, src_ip, src_port, dst_ip, dst_port, proto, service, status,
bytes_in, bytes_out, duration, sensor, data_origin.

* Zeek: conn.log + http.log (TSV with #fields header, or JSON-lines). HTTP transactions replace
  their underlying conn record (joined on uid) so a request is not counted twice.
* Suricata: eve.json `alert` events -> external rule alerts (stored as predictions).
* Replay: CSV/JSONL already in canonical form.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pandas as pd

from ..detection.features import REQUIRED_EVENT_FIELDS, SchemaIncompatible

CANONICAL = ["ts", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "service", "status",
             "bytes_in", "bytes_out", "duration", "sensor", "data_origin"]
REFUSED_STATES = {"REJ", "S0", "RSTOS0", "RSTRH", "SH", "SHR", "OTH"}


def _read_zeek(path: Path) -> pd.DataFrame:
    text = path.read_text(encoding="utf-8").splitlines()
    first = next((ln for ln in text if ln.strip()), "")
    if first.startswith("{"):
        return pd.DataFrame([json.loads(ln) for ln in text if ln.strip()])
    fields = None
    rows = []
    for ln in text:
        if ln.startswith("#fields"):
            fields = ln.split("\t")[1:]
        elif ln.startswith("#") or not ln.strip():
            continue
        else:
            if fields is None:
                raise SchemaIncompatible(f"{path}: Zeek TSV without #fields header")
            rows.append(dict(zip(fields, ln.split("\t"))))
    return pd.DataFrame(rows)


def _num(s: pd.Series, default: float = 0.0) -> pd.Series:
    return pd.to_numeric(s.replace({"-": None, "(empty)": None}), errors="coerce").fillna(default)


def zeek_to_events(conn_log: str | Path, http_log: str | Path | None = None,
                   service_ports: dict[int, str] | None = None, data_origin: str = "replay") -> pd.DataFrame:
    service_ports = service_ports or {}
    conn = _read_zeek(Path(conn_log))
    need = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "conn_state"]
    missing = [c for c in need if c not in conn.columns]
    if missing:
        raise SchemaIncompatible(f"Zeek conn.log missing fields {missing}")
    http_uids: set = set()
    frames = []
    if http_log:
        http = _read_zeek(Path(http_log))
        hneed = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "uri", "status_code"]
        hmiss = [c for c in hneed if c not in http.columns]
        if hmiss:
            raise SchemaIncompatible(f"Zeek http.log missing fields {hmiss}")
        http_uids = set(http["uid"])
        dur = conn.set_index("uid")["duration"] if "duration" in conn.columns else pd.Series(dtype=float)
        frames.append(pd.DataFrame({
            "ts": _num(http["ts"]), "src_ip": http["id.orig_h"], "src_port": _num(http["id.orig_p"]).astype(int),
            "dst_ip": http["id.resp_h"], "dst_port": _num(http["id.resp_p"]).astype(int), "proto": "tcp",
            "service": http["uri"].astype(str).map(lambda u: "login" if u.startswith("/login") else "http"),
            "status": _num(http["status_code"]).astype(int).astype(str),
            "bytes_in": _num(http.get("request_body_len", pd.Series(0, index=http.index))).astype(int),
            "bytes_out": _num(http.get("response_body_len", pd.Series(0, index=http.index))).astype(int),
            "duration": _num(http["uid"].map(dur)) if len(dur) else 0.0,
        }))
    c = conn[~conn["uid"].isin(http_uids)]
    refused = c["conn_state"].isin(REFUSED_STATES)
    frames.append(pd.DataFrame({
        "ts": _num(c["ts"]), "src_ip": c["id.orig_h"], "src_port": _num(c["id.orig_p"]).astype(int),
        "dst_ip": c["id.resp_h"], "dst_port": _num(c["id.resp_p"]).astype(int), "proto": c["proto"],
        "service": _num(c["id.resp_p"]).astype(int).map(lambda p: service_ports.get(p, "tcp")),
        "status": "conn",
        "bytes_in": _num(c.get("orig_bytes", pd.Series(0, index=c.index))).astype(int),
        "bytes_out": _num(c.get("resp_bytes", pd.Series(0, index=c.index))).astype(int).where(~refused, 0),
        "duration": _num(c.get("duration", pd.Series(0, index=c.index))),
    }))
    out = pd.concat(frames, ignore_index=True).sort_values("ts", ignore_index=True)
    out["sensor"], out["data_origin"] = "zeek", data_origin
    return out[CANONICAL]


def suricata_alerts(eve_json: str | Path, data_origin: str = "replay") -> list[dict]:
    alerts = []
    for ln in Path(eve_json).read_text(encoding="utf-8").splitlines():
        if not ln.strip():
            continue
        e = json.loads(ln)
        if e.get("event_type") != "alert":
            continue
        a = e.get("alert") or {}
        if "signature_id" not in a or "src_ip" not in e:
            raise SchemaIncompatible("Suricata alert missing signature_id/src_ip")
        ts = datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")).timestamp()
        alerts.append({"ts": ts, "src_ip": e["src_ip"], "dst_ip": e.get("dest_ip", ""),
                       "dst_port": int(e.get("dest_port", 0)), "sid": int(a["signature_id"]),
                       "signature": str(a.get("signature", ""))[:256], "severity": int(a.get("severity", 3)),
                       "category": str(a.get("category", ""))[:128], "data_origin": data_origin})
    return alerts


def replay_events(path: str | Path, data_origin: str = "replay") -> pd.DataFrame:
    path = Path(path)
    df = pd.read_json(path, lines=True) if path.suffix in (".jsonl", ".json") else pd.read_csv(path)
    missing = [c for c in REQUIRED_EVENT_FIELDS if c not in df.columns]
    if missing:
        raise SchemaIncompatible(f"replay file {path.name} missing required fields {missing}")
    for col, default in (("src_port", 0), ("dst_ip", ""), ("proto", "tcp")):
        if col not in df.columns:
            df[col] = default
    df["status"] = df["status"].astype(str)
    df["sensor"] = df.get("sensor", "replay")
    df["data_origin"] = data_origin
    return df[CANONICAL]
