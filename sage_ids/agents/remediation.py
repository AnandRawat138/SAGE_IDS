"""Remediation Agent: bounded, structured defensive proposals and candidate-version preparation.

Supported change types (validated by `ProposalSpec`): approved threshold-rule template, bounded
laboratory service configuration keys, and batch retraining on VERIFIED labels only. Proposals
are separate from accepted changes; activation requires the operator and passed criteria.
No source code is ever patched.
"""
from __future__ import annotations

import math

import numpy as np
import pandas as pd
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..config import Settings, load_yaml
from ..db import Case, DetectorVersion, ExperimentRun, FeatureWindow, RemediationProposal, TelemetryEvent
from ..detection import versions
from ..detection.features import FEATURES
from ..detection.models import save_bundle, train_bundle
from ..detection.rules import sliding_crossings, sliding_max
from ..schemas import ProposalSpec, RuleSpec

# scenario label -> (feature for the threshold template, hardening key)
TEMPLATE_FOR_LABEL = {"bruteforce": ("n_auth_fail", "login_lockout_threshold"),
                      "flood": ("req_rate", "app_rate_limit_rps"),
                      "recon": ("n_distinct_dst_ports", None)}


class RemediationAgent:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.labels = load_yaml("mappings.yaml")["scenario_labels"]

    # ------------------------------------------------------------------ evidence helpers
    @staticmethod
    def _windows(s: Session, ids: list[int] | None = None, run_ids: list[int] | None = None) -> pd.DataFrame:
        q = select(FeatureWindow)
        if ids is not None:
            q = q.where(FeatureWindow.id.in_(ids))
        if run_ids is not None:
            q = q.where(FeatureWindow.run_id.in_(run_ids))
        rows = s.execute(q).scalars().all()
        return pd.DataFrame([{"window_id": r.id, "label": r.label, "verified": r.label_verified,
                              "src_ip": r.src_ip, "window_start": r.window_start, "window_end": r.window_end,
                              "event_ids": r.event_ids, **r.features} for r in rows])

    @staticmethod
    def _events(s: Session, windows: pd.DataFrame) -> pd.DataFrame:
        ids = [i for ev in windows.get("event_ids", []) for i in ev]
        rows = s.execute(select(TelemetryEvent).where(TelemetryEvent.id.in_(ids))).scalars().all() if ids else []
        return pd.DataFrame([{"id": e.id, "ts": e.ts, "src_ip": e.src_ip, "dst_port": e.dst_port, "service": e.service,
                              "status": e.status, "bytes_in": e.bytes_in, "bytes_out": e.bytes_out,
                              "duration": e.duration} for e in rows])

    def _window_hit_rate(self, rule: RuleSpec, windows: pd.DataFrame, events: pd.DataFrame) -> float:
        """Fraction of windows in which the rule would fire on sliding windows (same logic as runtime)."""
        if not len(windows) or events.empty:
            return float("nan")
        W = self.settings.monitoring.window_seconds
        cross = {src: sliding_crossings(rule, g, W) for src, g in events.groupby("src_ip")}
        hits = [any(w["window_start"] <= t < w["window_end"] for t in cross.get(w["src_ip"], []))
                for w in windows.to_dict("records")]
        return float(np.mean(hits))

    def _calibration_benign(self, s: Session, parent: DetectorVersion) -> pd.DataFrame:
        w = self._windows(s, ids=parent.label_set.get("window_ids", []))
        return w[(w["label"] == "benign") & w["verified"]] if len(w) else w

    def _benign_peak_rps(self, s: Session, parent: DetectorVersion) -> int:
        w = self._calibration_benign(s, parent)
        ids = [i for r in s.execute(select(FeatureWindow).where(FeatureWindow.id.in_(w["window_id"].tolist()))).scalars()
               for i in r.event_ids]
        ts = [e.ts for e in s.execute(select(TelemetryEvent).where(TelemetryEvent.id.in_(ids),
                                                                   TelemetryEvent.service == "test_app")).scalars()]
        srcs = [e.src_ip for e in s.execute(select(TelemetryEvent).where(TelemetryEvent.id.in_(ids),
                                                                         TelemetryEvent.service == "test_app")).scalars()]
        if not ts:
            return 20
        df = pd.DataFrame({"src": srcs, "sec": np.floor(ts)})
        return int(df.groupby(["src", "sec"]).size().max())

    # ------------------------------------------------------------------ proposals
    def propose(self, s: Session, case: Case, parent: DetectorVersion) -> list[RemediationProposal]:
        label = self.labels[case.scenario_id]
        feature, hard_key = TEMPLATE_FOR_LABEL[label]
        benign = self._calibration_benign(s, parent)
        base_runs = s.execute(select(ExperimentRun).where(ExperimentRun.case_id == case.id,
                                                          ExperimentRun.phase == "baseline",
                                                          ExperimentRun.scenario_id == case.scenario_id)).scalars().all()
        executed_ids = [r.id for r in base_runs if r.executed]
        attack = self._windows(s, run_ids=executed_ids)
        attack = attack[attack["label"] == label] if len(attack) else attack
        benign_ev = self._events(s, benign) if len(benign) else pd.DataFrame()
        attack_ev = self._events(s, attack) if len(attack) else pd.DataFrame()
        W = self.settings.monitoring.window_seconds
        peaks = sliding_max(feature, benign_ev, W) if not benign_ev.empty else {}
        bmax = float(max(peaks.values(), default=0.0))
        thr = math.floor(bmax) + 1 if feature != "req_rate" else round(bmax * 1.25 + 1.0, 2)

        def predicted(th: float) -> dict:
            r = RuleSpec(id="TMP", feature=feature, threshold=th, label=label)
            return {"calibration_benign_fpr": self._window_hit_rate(r, benign, benign_ev),
                    "baseline_attack_window_coverage": self._window_hit_rate(r, attack, attack_ev),
                    "n_benign_windows": int(len(benign)), "n_attack_windows": int(len(attack))}

        rid = f"SAGE-{label.upper()}-{case.id}"
        specs: list[ProposalSpec] = []
        p_cal = predicted(thr)
        specs.append(ProposalSpec(
            title=f"Calibrated threshold rule on {feature} (>= {thr})",
            changes=[{"kind": "rule", "action": "add",
                      "rule": {"id": rid, "feature": feature, "threshold": thr, "severity": "high", "label": label,
                               "description": f"{label}: {feature} above max verified benign calibration value {bmax}"}}],
            rationale=(f"Baseline test confirmed a detection gap for {case.scenario_id}. Threshold = max sliding-window {feature} "
                       f"over the verified benign calibration traffic ({bmax:g}; {p_cal['n_benign_windows']} windows) plus margin. "
                       f"Pre-check (calibration data, not acceptance data): benign FPR {p_cal['calibration_benign_fpr']:.3f}, "
                       f"coverage of baseline attack windows {p_cal['baseline_attack_window_coverage']:.3f}."),
            affected_artifacts=["detector ruleset"], expected_effect="raise alerts on the triggering behaviour without "
            "alerting on benign behaviour observed during calibration",
            validation_steps=["repeat triggering scenario on fresh seeds", "re-run previously passed scenarios",
                              "measure benign FPR and service health", "paired comparison with baseline version"],
            rollback=f"remove rule {rid} (re-activate parent version {parent.id})"))
        p_sens = predicted(1.0)
        specs.append(ProposalSpec(
            title=f"Maximum-sensitivity rule on {feature} (>= 1)",
            changes=[{"kind": "rule", "action": "add",
                      "rule": {"id": rid + "-S", "feature": feature, "threshold": 1.0, "severity": "medium",
                               "label": label, "description": f"{label}: any occurrence of {feature}"}}],
            rationale=("Sensitivity-first alternative. Pre-check predicts benign FPR "
                       f"{p_sens['calibration_benign_fpr']:.3f} on calibration windows; it is expected to fail the "
                       "benign FPR criterion and is included so the gate is exercised on a plausible but unsuitable fix."),
            affected_artifacts=["detector ruleset"], expected_effect="maximum recall, likely high false-positive rate",
            validation_steps=["same as calibrated rule"], rollback=f"remove rule {rid}-S"))
        if hard_key:
            val = 5 if hard_key == "login_lockout_threshold" else max(5, math.ceil(self._benign_peak_rps(s, parent) * 1.5))
            changes = [{"kind": "lab_config", "key": hard_key, "value": val}]
            if hard_key == "login_lockout_threshold":
                changes.append({"kind": "lab_config", "key": "login_lockout_seconds", "value": 300})
            specs.append(ProposalSpec(
                title=f"Calibrated rule + lab service hardening ({hard_key}={val})",
                changes=specs[0].model_dump()["changes"] + changes,
                rationale=("Detection alone does not prevent the effect. Adds bounded lab service hardening; "
                           + ("lockout after 5 failures per account for 300 s." if hard_key == "login_lockout_threshold"
                              else f"per-source rate limit at 1.5x the peak benign per-second request count ({val} rps).")),
                affected_artifacts=["detector ruleset", f"lab service config: {hard_key}"],
                expected_effect="detect the behaviour and reduce the rate at which the security effect is achieved",
                validation_steps=["as above", "verify benign requests are not denied", "verify service health"],
                rollback=f"remove rule {rid}; restore {hard_key} to parent value {parent.lab_config.get(hard_key)}"))
        specs.append(ProposalSpec(
            title="Retrain Random Forest with verified labels from executed baseline trials",
            changes=[{"kind": "retrain", "label_policy": "verified_only", "add_run_ids": executed_ids}],
            rationale=(f"Adds {len(attack)} verified '{label}' windows from {len(executed_ids)} executed baseline trials "
                       "(ground truth by construction) to the parent's verified training set. Retest uses fresh seeds."),
            affected_artifacts=["lab RF/IF model bundle", "label set"],
            expected_effect="supervised detector learns the triggering behaviour",
            validation_steps=["as above", "check per-class behaviour on benign windows"],
            rollback=f"re-activate parent version {parent.id} (previous model artifact retained)"))
        out = []
        for sp in specs:
            p = RemediationProposal(case_id=case.id, title=sp.title, changes=[c.model_dump() for c in sp.changes],
                                    rationale=sp.rationale, affected_artifacts=sp.affected_artifacts,
                                    expected_effect=sp.expected_effect, validation_steps=sp.validation_steps,
                                    rollback=sp.rollback, generated_by="deterministic")
            s.add(p)
            out.append(p)
        s.flush()
        audit.append(s, "agent:remediation", "proposals_generated", "case", case.id, {"proposal_ids": [p.id for p in out]})
        return out

    # ------------------------------------------------------------------ candidate preparation
    def prepare_candidate(self, s: Session, proposal: RemediationProposal, parent: DetectorVersion,
                          seed: int) -> DetectorVersion:
        spec = ProposalSpec.model_validate({"title": proposal.title, "changes": proposal.changes,
                                            "rationale": proposal.rationale,
                                            "affected_artifacts": proposal.affected_artifacts,
                                            "expected_effect": proposal.expected_effect,
                                            "validation_steps": proposal.validation_steps, "rollback": proposal.rollback})
        rules = {r["id"]: r for r in parent.ruleset}
        lab_cfg = dict(parent.lab_config)
        model_path, model_sha, label_set = parent.model_path, parent.model_sha256, dict(parent.label_set)
        for ch in spec.changes:
            if ch.kind == "rule":
                if ch.action == "remove":
                    rules.pop(ch.rule.id, None)
                else:
                    rules[ch.rule.id] = ch.rule.model_dump()
            elif ch.kind == "lab_config":
                lab_cfg[ch.key] = ch.value
            elif ch.kind == "retrain":
                model_path, model_sha, label_set = self._retrain(s, parent, ch.add_run_ids, seed, proposal.id)
        v = versions.create_version(s, name=f"candidate-p{proposal.id}", parent_id=parent.id,
                                    ruleset=list(rules.values()), lab_config=lab_cfg,
                                    detector_policy=dict(parent.detector_policy), model_path=model_path,
                                    model_sha256=model_sha, label_set=label_set,
                                    notes=f"from proposal {proposal.id}: {proposal.title}")
        proposal.status, proposal.candidate_version_id = "prepared", v.id
        return v

    def _retrain(self, s: Session, parent: DetectorVersion, run_ids: list[int], seed: int, pid: int):
        ids = list(parent.label_set.get("window_ids", []))
        new = s.execute(select(FeatureWindow).where(FeatureWindow.run_id.in_(run_ids),
                                                    FeatureWindow.label_verified.is_(True),
                                                    FeatureWindow.label.is_not(None))).scalars().all()
        ids = sorted(set(ids) | {w.id for w in new})
        rows = s.execute(select(FeatureWindow).where(FeatureWindow.id.in_(ids))).scalars().all()
        rows = [r for r in rows if r.label_verified and r.label is not None]   # unverified never enter training
        X = pd.DataFrame([r.features for r in rows])[FEATURES]
        y = pd.Series([r.label for r in rows])
        bundle = train_bundle(X, y, seed=seed, window_ids=[r.id for r in rows])
        path = self.settings.path(self.settings.artifacts_dir) / "models" / f"lab_rf_p{pid}.joblib"
        sha = save_bundle(bundle, path)
        return str(path), sha, {"window_ids": [r.id for r in rows], "digest": bundle.card["label_set_digest"],
                                "label_counts": bundle.card["label_counts"], "policy": "verified_only"}
