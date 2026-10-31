"""Network Monitoring Agent: ingest telemetry, build lab-v1 windows, attach verified labels, detect.

Read-only with respect to the laboratory: it never starts scenarios or changes configuration.
"""
from __future__ import annotations

import ipaddress
from typing import Iterable

import pandas as pd
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..config import Settings, load_yaml
from ..db import (DetectorVersion, ExperimentRun, FeatureWindow, Prediction, RunDetection,
                  TelemetryEvent)
from ..detection.engine import DetectorRuntime
from ..detection.features import SCHEMA_VERSION, extract_windows
from ..telemetry.adapters import CANONICAL

BENIGN_LABEL = "benign"


class MonitoringAgent:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.window_s = settings.monitoring.window_seconds
        self.benign_net = ipaddress.ip_network(settings.lab.benign_source_cidr)
        self.scenario_labels = load_yaml("mappings.yaml")["scenario_labels"]

    # ------------------------------------------------------------------ ingestion
    def store_events(self, s: Session, events: Iterable[dict] | pd.DataFrame, data_origin: str) -> pd.DataFrame:
        df = events if isinstance(events, pd.DataFrame) else pd.DataFrame(list(events))
        if df.empty:
            return pd.DataFrame(columns=["id", *CANONICAL])
        df = df.copy()
        df["data_origin"] = data_origin
        for col, default in (("src_port", 0), ("dst_ip", ""), ("proto", "tcp"), ("sensor", "lab_sensor")):
            if col not in df.columns:
                df[col] = default
        rows = [TelemetryEvent(**{k: r[k] for k in CANONICAL}) for r in df[CANONICAL].to_dict("records")]
        s.add_all(rows)
        s.flush()
        df["id"] = [r.id for r in rows]
        return df

    # ------------------------------------------------------------------ labelling
    def _label(self, w: dict, runs: list[ExperimentRun]) -> tuple[str | None, bool, str, int | None]:
        """Ground truth by construction: attacker windows belong to the run that used that source
        address during the window; benign-generator sources are benign. Everything else is unlabelled."""
        for r in runs:
            if r.scenario_id == "benign-traffic":
                continue
            if w["src_ip"] == r.src_ip and w["window_start"] <= r.ended_at + 1.0 and w["window_end"] >= r.started_at:
                label = self.scenario_labels.get(r.scenario_id)
                return label, bool(r.executed), f"run:{r.id}" + ("" if r.executed else " (not executed)"), r.id
        try:
            if ipaddress.ip_address(w["src_ip"]) in self.benign_net:
                benign_run = next((r for r in runs if r.scenario_id == "benign-traffic"
                                   and w["window_start"] <= r.ended_at + 1.0 and w["window_end"] >= r.started_at), None)
                return BENIGN_LABEL, True, "benign_generator" + (f" run:{benign_run.id}" if benign_run else ""), \
                    benign_run.id if benign_run else None
        except ValueError:
            pass
        return None, False, "unverified", None

    def build_windows(self, s: Session, events: pd.DataFrame, runs: list[ExperimentRun], data_origin: str
                      ) -> tuple[pd.DataFrame, list[FeatureWindow]]:
        win = extract_windows(events, self.window_s)
        rows = []
        for w in win.to_dict("records"):
            label, verified, src, run_id = self._label(w, runs)
            feats = {k: w[k] for k in win.columns if k not in ("src_ip", "window_start", "window_end", "event_ids", "first_ts")}
            rows.append(FeatureWindow(run_id=run_id, src_ip=w["src_ip"], window_start=w["window_start"],
                                      window_end=w["window_end"], schema_version=SCHEMA_VERSION, features=feats,
                                      event_ids=w["event_ids"], label=label, label_verified=verified,
                                      label_source=src, data_origin=data_origin))
        s.add_all(rows)
        s.flush()
        if len(win):
            win["window_id"] = [r.id for r in rows]
            win["label"] = [r.label for r in rows]
            win["run_id"] = [r.run_id for r in rows]
        return win, rows

    # ------------------------------------------------------------------ detection
    def detect(self, s: Session, version: DetectorVersion, windows: pd.DataFrame, events: pd.DataFrame,
               data_origin: str, store: bool = True) -> list[dict]:
        results = DetectorRuntime(version).evaluate(windows, events)
        if store:
            preds = []
            for w, r in zip(windows.to_dict("records"), results):
                preds.append(Prediction(ts=r["alert_ts"] or w["window_end"], window_id=w.get("window_id"),
                                        version_id=version.id, detector=",".join(r["detectors"]) or "none",
                                        src_ip=w["src_ip"], is_alert=r["is_alert"],
                                        predicted_label=r["predicted_label"], score=r["score"],
                                        confidence=r["confidence"],
                                        evidence={**r["evidence"], "event_ids": w["event_ids"][:50],
                                                  "window_id": w.get("window_id")},
                                        data_origin=data_origin))
            s.add_all(preds)
            s.flush()
        return results

    def run_detections(self, s: Session, version: DetectorVersion, windows: pd.DataFrame, results: list[dict],
                       runs: list[ExperimentRun]) -> dict[int, RunDetection]:
        out = {}
        recs = windows.to_dict("records") if len(windows) else []
        for run in runs:
            if run.scenario_id == "benign-traffic":
                continue
            idx = [i for i, w in enumerate(recs) if w.get("run_id") == run.id]
            alerts = [results[i] for i in idx if results[i]["is_alert"]]
            t_alert = min((a["alert_ts"] for a in alerts if a["alert_ts"] is not None), default=None)
            existing = s.execute(select(RunDetection).where(RunDetection.run_id == run.id,
                                                            RunDetection.version_id == version.id)).scalar_one_or_none()
            rd = existing or RunDetection(run_id=run.id, version_id=version.id)
            rd.detected = bool(alerts)
            rd.latency_s = max(0.0, t_alert - run.started_at) if t_alert is not None else None
            rd.detectors = sorted({d for a in alerts for d in a["detectors"]})
            rd.n_windows, rd.n_alert_windows = len(idx), len(alerts)
            s.add(rd)
            out[run.id] = rd
        s.flush()
        return out

    def benign_alerts(self, windows: pd.DataFrame, results: list[dict]) -> tuple[int, int, list[dict]]:
        recs = windows.to_dict("records") if len(windows) else []
        idx = [i for i, w in enumerate(recs) if w.get("label") == BENIGN_LABEL]
        fps = [{"window_id": recs[i].get("window_id"), "src_ip": recs[i]["src_ip"],
                "detectors": results[i]["detectors"]} for i in idx if results[i]["is_alert"]]
        return len(idx), len(fps), fps

    # ------------------------------------------------------------------ external alerts
    def ingest_suricata(self, s: Session, alerts: list[dict]) -> int:
        for a in alerts:
            s.add(Prediction(ts=a["ts"], window_id=None, version_id=None, detector=f"suricata:{a['sid']}",
                             src_ip=a["src_ip"], is_alert=True, predicted_label=a["category"] or "suricata_alert",
                             score=None, confidence=None,
                             evidence={"signature": a["signature"], "severity": a["severity"],
                                       "dst": f"{a['dst_ip']}:{a['dst_port']}"}, data_origin=a["data_origin"]))
        s.flush()
        audit.append(s, "agent:monitoring", "suricata_alerts_ingested", "predictions", "-", {"count": len(alerts)})
        return len(alerts)
