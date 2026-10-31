"""Detector runtime: applies one detector version (rules + RF + optional IF) to feature windows."""
from __future__ import annotations

from functools import lru_cache

import pandas as pd

from ..db import DetectorVersion
from .models import LabModelBundle, load_bundle
from .rules import load_rules, rule_fires, sliding_crossings


@lru_cache(maxsize=32)
def _cached_bundle(path: str, sha: str) -> LabModelBundle:
    return load_bundle(path, expected_sha256=sha)


class DetectorRuntime:
    def __init__(self, version: DetectorVersion):
        self.version_id = version.id
        self.rules = load_rules(version.ruleset)
        self.policy = dict(version.detector_policy or {})
        self.bundle = _cached_bundle(version.model_path, version.model_sha256) if version.model_path else None

    def _rule_crossings(self, events: pd.DataFrame | None, window_s: float) -> dict:
        """(rule_id, src_ip) -> sorted crossing timestamps on sliding windows."""
        out: dict = {}
        if events is None or events.empty or not self.rules:
            return out
        for src, g in events.groupby("src_ip"):
            for r in self.rules:
                out[(r.id, src)] = sliding_crossings(r, g, window_s)
        return out

    def evaluate(self, windows: pd.DataFrame, events: pd.DataFrame | None = None) -> list[dict]:
        """One result per (tumbling) window: alert flag, firing detectors, scores and online alert time.
        Rules fire for a window if a sliding-window crossing for that source falls inside it; without
        raw events, rules fall back to the window's aggregate features."""
        if windows.empty:
            return []
        ml = self.bundle.predict(windows) if self.bundle is not None else None
        ws = float(windows["window_end"].iloc[0] - windows["window_start"].iloc[0])
        crossings = self._rule_crossings(events, ws)
        results = []
        for i, w in enumerate(windows.to_dict("records")):
            dets, alert_times, evidence = [], [], {}
            for r in self.rules:
                if crossings:
                    hits = [t for t in crossings.get((r.id, w["src_ip"]), []) if w["window_start"] <= t < w["window_end"]]
                    fired, t_alert = bool(hits), (hits[0] if hits else None)
                else:
                    fired, t_alert = rule_fires(r, w), w["window_end"]
                if not fired:
                    continue
                dets.append(f"rule:{r.id}")
                alert_times.append(t_alert)
                evidence[f"rule:{r.id}"] = {"feature": r.feature, "window_value": w[r.feature],
                                            "threshold": r.threshold, "label": r.label,
                                            "evaluation": "sliding" if crossings else "tumbling"}
            label, conf, score = "benign", None, None
            if ml is not None:
                m = ml.iloc[i]
                label, conf, score = m.rf_label, float(m.rf_conf), float(m.rf_attack_score)
                evidence["rf"] = {"label": label, "confidence": conf}
                if self.policy.get("rf", True) and label != "benign":
                    dets.append("rf")
                    alert_times.append(w["window_end"])
                evidence["iforest"] = {"score": float(m.if_score), "would_alert": bool(m.if_alert),
                                       "alerting_enabled": bool(self.policy.get("iforest", False))}
                if self.policy.get("iforest", False) and bool(m.if_alert):
                    dets.append("iforest")
                    alert_times.append(w["window_end"])
            rule_labels = [evidence[d]["label"] for d in dets if d.startswith("rule:")]
            results.append({"is_alert": bool(dets), "detectors": dets,
                            "alert_ts": min(alert_times) if alert_times else None,
                            "predicted_label": rule_labels[0] if rule_labels and label == "benign" else label,
                            "confidence": conf, "score": score, "evidence": evidence,
                            "if_would_alert": evidence.get("iforest", {}).get("would_alert", False)})
        return results
