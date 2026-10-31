"""Laboratory feature schema (lab-v1): per-source tumbling-window aggregates of canonical flow events.

The same extraction runs on lab-sensor events, Zeek-derived events and replayed CSVs, so the
laboratory model has a reproducible runtime feature path. The CICIDS2017 benchmark model uses a
*different* schema (sage_ids/data/cicids2017.py) and the two are never mixed.
"""
from __future__ import annotations

import hashlib
import math

import numpy as np
import pandas as pd

SCHEMA_VERSION = "lab-v1"
REQUIRED_EVENT_FIELDS = ["ts", "src_ip", "dst_port", "service", "status", "bytes_in", "bytes_out", "duration"]
FEATURES = ["n_events", "n_distinct_dst_ports", "n_http", "n_auth", "n_auth_fail", "n_auth_success",
            "n_http_429", "n_http_4xx", "req_rate", "frac_auth_fail", "n_conn_refused_like",
            "mean_bytes_in", "mean_bytes_out", "mean_duration"]
SCHEMA_HASH = hashlib.sha256((SCHEMA_VERSION + "|" + ",".join(FEATURES)).encode()).hexdigest()


class SchemaIncompatible(ValueError):
    """Raised instead of silently substituting missing features."""


def check_event_schema(df: pd.DataFrame) -> None:
    missing = [c for c in REQUIRED_EVENT_FIELDS if c not in df.columns]
    if missing:
        raise SchemaIncompatible(f"telemetry missing required fields {missing} for schema {SCHEMA_VERSION}")
    bad_ts = df["ts"].isna() | ~np.isfinite(pd.to_numeric(df["ts"], errors="coerce").astype(float))
    if bad_ts.any():
        raise SchemaIncompatible(f"{int(bad_ts.sum())} events with invalid timestamps")


def check_feature_schema(columns, schema_version: str, schema_hash: str) -> None:
    if schema_version != SCHEMA_VERSION or schema_hash != SCHEMA_HASH:
        raise SchemaIncompatible(f"model expects schema {schema_version}/{schema_hash[:12]} but runtime "
                                 f"extractor provides {SCHEMA_VERSION}/{SCHEMA_HASH[:12]}")
    missing = [f for f in FEATURES if f not in columns]
    if missing:
        raise SchemaIncompatible(f"feature matrix missing {missing}")


def _aggregate(g: pd.DataFrame) -> dict:
    status = g["status"].astype(str)
    is_http = status.str.fullmatch(r"\d{3}")
    code = pd.to_numeric(status.where(is_http), errors="coerce")
    is_auth = g["service"].eq("login") & is_http
    n_http = int(is_http.sum())
    span = float(g["ts"].max() - g["ts"].min()) if len(g) > 1 else 0.0
    n_auth = int(is_auth.sum())
    n_auth_fail = int((is_auth & code.isin([401, 423])).sum())
    return {
        "n_events": len(g),
        "n_distinct_dst_ports": int(g["dst_port"].nunique()),
        "n_http": n_http,
        "n_auth": n_auth,
        "n_auth_fail": n_auth_fail,
        "n_auth_success": int((is_auth & code.eq(200)).sum()),
        "n_http_429": int(code.eq(429).sum()),
        "n_http_4xx": int(code.between(400, 499).sum()),
        "req_rate": n_http / max(span, 1.0),
        "frac_auth_fail": n_auth_fail / n_auth if n_auth else 0.0,
        "n_conn_refused_like": int((status.eq("conn") & g["bytes_out"].eq(0)).sum()),
        "mean_bytes_in": float(g["bytes_in"].mean()),
        "mean_bytes_out": float(g["bytes_out"].mean()),
        "mean_duration": float(g["duration"].mean()),
    }


def extract_windows(events: pd.DataFrame, window_seconds: float) -> pd.DataFrame:
    """Return one row per (src_ip, window) with FEATURES plus window_start/window_end/event_ids."""
    if events.empty:
        return pd.DataFrame(columns=["src_ip", "window_start", "window_end", "event_ids", *FEATURES])
    check_event_schema(events)
    df = events.copy()
    df["ts"] = df["ts"].astype(float)
    df["window_start"] = (df["ts"] // window_seconds) * window_seconds
    if "id" not in df.columns:
        df["id"] = range(len(df))
    rows = []
    for (src, ws), g in df.sort_values("ts").groupby(["src_ip", "window_start"], sort=True):
        r = _aggregate(g)
        r.update(src_ip=src, window_start=float(ws), window_end=float(ws) + window_seconds,
                 event_ids=[int(x) for x in g["id"].tolist()], first_ts=float(g["ts"].min()))
        rows.append(r)
    out = pd.DataFrame(rows)
    for f in FEATURES:
        if not out[f].map(lambda v: isinstance(v, (int, float)) and math.isfinite(v)).all():
            raise SchemaIncompatible(f"non-finite values in feature {f}")
    return out


def feature_matrix(windows: pd.DataFrame) -> np.ndarray:
    return windows[FEATURES].to_numpy(dtype=float)
