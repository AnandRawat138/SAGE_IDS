"""Coordinator: persistent, bounded state machine driving the five agents through a closed loop.

finding_received -> relevance_checked -> scenario_pending_review -> scenario_approved ->
baseline_test_running -> baseline_test_completed -> remediation_proposed -> candidate_prepared ->
retest_running -> acceptance_pending -> accepted | rejected | inconclusive
(+ not_relevant, weakness_not_confirmed, failed, cancelled, timed_out)

* every transition is validated (state + role), recorded with evidence, and hash-chained in the audit log
* running phases are claimed with an atomic compare-and-set -> no duplicate execution
* retries and adaptation cycles are bounded; cancellation is cooperative; stale runs time out on recovery
"""
from __future__ import annotations

import logging
import threading
import uuid
from datetime import timedelta

import pandas as pd
from sqlalchemy import select, update

from .. import audit
from ..agents.adversarial import AdversarialAgent
from ..agents.explanation import ExplanationAgent
from ..agents.monitoring import MonitoringAgent
from ..agents.remediation import RemediationAgent
from ..agents.threat_research import ThreatResearchAgent
from ..config import Settings, load_yaml
from ..db import (Case, Database, DetectorVersion, Evaluation, ExperimentRun, RemediationProposal, RunDetection,
                  Transition, utcnow)
from ..detection import versions
from ..detection.features import FEATURES
from ..detection.models import save_bundle, train_bundle
from ..evaluation.acceptance import (criteria_hash, derive_criteria, evaluate_candidate, load_policy,
                                     weakness_profile)
from ..schemas import AcceptanceCriteria
from ..security.allowlist import ActiveLabDisabled
from .state_machine import OPERATOR, RUNNING, SYSTEM, TERMINAL, TransitionError, check

log = logging.getLogger(__name__)


class Coordinator:
    def __init__(self, settings: Settings, db: Database):
        self.settings, self.db = settings, db
        self.monitoring = MonitoringAgent(settings)
        self.research = ThreatResearchAgent(settings)
        self.adversarial = AdversarialAgent(settings)
        self.remediation = RemediationAgent(settings)
        self.explanation = ExplanationAgent(settings)
        self.policy = load_policy()
        self._cancel_events: dict[int, threading.Event] = {}

    # ================================================================== transitions
    def _transition(self, s, case: Case, to: str, actor: str, role: str, reason: str = "",
                    evidence: dict | None = None) -> Transition:
        if role == OPERATOR and (not actor or actor.startswith(("agent:", "llm"))):
            raise TransitionError("operator transitions require a human operator identity")
        check(case.state, to, role)
        frm = case.state
        case.state, case.updated_at = to, utcnow()
        entry = audit.append(s, actor, "case_transition", "case", case.id,
                             {"from": frm, "to": to, "reason": reason, "evidence": evidence or {}})
        t = Transition(case_id=case.id, from_state=frm, to_state=to, actor=actor, role=role, reason=reason,
                       evidence=evidence or {}, audit_hash=entry.hash)
        s.add(t)
        s.flush()
        return t

    def _claim(self, case_id: int, frm: str, to: str) -> str | None:
        """Atomic compare-and-set; only one caller can move a case into a running state."""
        check(frm, to, SYSTEM)
        token = uuid.uuid4().hex
        with self.db.session() as s:
            res = s.execute(update(Case).where(Case.id == case_id, Case.state == frm)
                            .values(state=to, lock_token=token, heartbeat_at=utcnow(), updated_at=utcnow(),
                                    attempts=Case.attempts + 1))
            if res.rowcount != 1:
                return None
            entry = audit.append(s, "coordinator", "case_transition", "case", case_id,
                                 {"from": frm, "to": to, "reason": "claimed for execution", "lock": token})
            s.add(Transition(case_id=case_id, from_state=frm, to_state=to, actor="coordinator", role=SYSTEM,
                             reason="claimed for execution", evidence={"lock": token}, audit_hash=entry.hash))
        return token

    # ================================================================== findings -> cases
    def ingest_findings(self, mode: str = "fixture") -> list[int]:
        case_ids = []
        with self.db.session() as s:
            self.research.sync_assets(s)
            findings = self.research.retrieve(s, mode)
            for f in findings:
                key = f"finding:{f.source}:{f.source_id}"
                case = s.execute(select(Case).where(Case.idempotency_key == key)).scalar_one_or_none()
                if case is not None:
                    continue                              # dedup: one case per finding
                case = Case(idempotency_key=key, finding_id=f.id, state="finding_received")
                s.add(case)
                s.flush()
                audit.append(s, "coordinator", "case_created", "case", case.id, {"finding": key})
                rel = self.research.assess_relevance(s, f)
                cands = [(m["asset_id"], sc) for m in rel["matches"] for sc in m["scenarios"]]
                if not cands:
                    self._transition(s, case, "not_relevant", "agent:threat_research", SYSTEM,
                                     "no lab asset / approved scenario matches", {"relevance": rel})
                else:
                    case.asset_id, case.scenario_id = cands[0]
                    self._transition(s, case, "relevance_checked", "agent:threat_research", SYSTEM,
                                     "matched lab inventory", {"relevance": rel, "candidates": cands})
                    self._transition(s, case, "scenario_pending_review", "coordinator", SYSTEM,
                                     f"scenario request {case.scenario_id} on {case.asset_id} awaits operator review")
                case_ids.append(case.id)
        return case_ids

    def approve_scenario(self, case_id: int, operator: str, approve: bool = True, reason: str = "") -> None:
        with self.db.session() as s:
            case = s.get(Case, case_id)
            spec = self.adversarial.catalogue.get(case.scenario_id or "")
            if approve and spec is None:
                raise TransitionError("scenario is not in the approved catalogue")
            self._transition(s, case, "scenario_approved" if approve else "rejected", operator, OPERATOR,
                             reason or ("operator approved reviewed scenario" if approve else "operator denied scenario"),
                             {"scenario": spec.model_dump() if spec else None})

    # ================================================================== seeds
    def _seed(self, case_id: int, phase: str) -> int:
        """Baseline and retest use disjoint seed ranges. All candidates of a case are retested on the SAME
        retest seeds (common random numbers): candidates are compared on identical trial parameters, and
        none of them is built from retest data. The held-out final test uses a third, disjoint range."""
        off = {"calibration": 0, "baseline": 10_000, "retest": 20_000}[phase]
        return self.settings.experiment.base_seed + case_id * 100_000 + off

    # ================================================================== bootstrap
    def bootstrap(self, operator: str, calibration_trials: int = 15, benign_rounds: int | None = None) -> int:
        """Collect verified calibration data and register v1 (rules + RF trained on benign+recon)."""
        with self.db.session() as s:
            if versions.get_active(s):
                return versions.get_active(s).id
        benign_rounds = benign_rounds or self.settings.experiment.benign_windows_per_phase + 4
        seed = self.settings.experiment.base_seed
        with self.db.session() as s:
            self.adversarial.start_phase({})
            runs = self.adversarial.run_trials(s, case_id=None, scenario_id="recon-tcp-probe", phase="calibration",
                                               n_trials=calibration_trials, seed_base=seed, lab_config={}, version_id=None)
            runs += self.adversarial.run_benign(s, case_id=None, phase="calibration", rounds=benign_rounds,
                                                seed_base=seed + 5_000, lab_config={}, version_id=None)
            ev = self.monitoring.store_events(s, self.adversarial.drain_telemetry(), "live_lab")
            win, rows = self.monitoring.build_windows(s, ev, runs, "live_lab")
            train = [r for r in rows if r.label_verified and r.label is not None]
            X = pd.DataFrame([r.features for r in train])[FEATURES]
            y = pd.Series([r.label for r in train])
            bundle = train_bundle(X, y, seed=seed, window_ids=[r.id for r in train])
            path = self.settings.path(self.settings.artifacts_dir) / "models" / "lab_rf_v1.joblib"
            sha = save_bundle(bundle, path)
            v = versions.create_version(
                s, name="v1-baseline", parent_id=None, ruleset=load_yaml("baseline_rules.yaml"),
                lab_config={"login_lockout_threshold": None, "login_lockout_seconds": 60, "app_rate_limit_rps": None},
                detector_policy={"rf": True, "iforest": False}, model_path=str(path), model_sha256=sha,
                label_set={"window_ids": [r.id for r in train], "digest": bundle.card["label_set_digest"],
                           "label_counts": bundle.card["label_counts"], "policy": "verified_only"},
                notes="bootstrap baseline: initial rules + RF on verified calibration windows (benign + recon). "
                      "Isolation Forest is scored in shadow mode (alerting disabled).", actor=operator)
            versions.accept(s, v.id, operator, None, bootstrap=True)
            return v.id

    # ================================================================== phase execution
    def _heartbeat(self, s, case: Case, cancel: threading.Event):
        def beat():
            s.refresh(case)
            if case.cancel_requested:
                cancel.set()
            case.heartbeat_at = utcnow()
            s.commit()
        return beat

    def _run_phase(self, s, case: Case, phase: str, seed: int, lab_config: dict, eval_versions: list[DetectorVersion],
                   regression: list[str], cancel: threading.Event, n_trials: int) -> dict:
        beat = self._heartbeat(s, case, cancel)
        exp = self.settings.experiment
        self.adversarial.start_phase(lab_config)
        trig = self.adversarial.run_trials(s, case_id=case.id, scenario_id=case.scenario_id, phase=phase,
                                           n_trials=n_trials, seed_base=seed, lab_config=lab_config,
                                           version_id=eval_versions[-1].id, cancel=cancel, heartbeat=beat)
        reg_runs: dict[str, list[ExperimentRun]] = {}
        n_reg = max(8, n_trials // 2)
        for i, sid in enumerate(regression):
            reg_runs[sid] = self.adversarial.run_trials(
                s, case_id=case.id, scenario_id=sid, phase=f"{phase}-regression", n_trials=n_reg,
                seed_base=seed + 500 + 100 * i, lab_config=lab_config, version_id=eval_versions[-1].id,
                cancel=cancel, heartbeat=beat)
        benign = self.adversarial.run_benign(s, case_id=case.id, phase=f"{phase}-benign", rounds=exp.benign_windows_per_phase,
                                             seed_base=seed + 900, lab_config=lab_config,
                                             version_id=eval_versions[-1].id, heartbeat=beat)
        health = self.adversarial.health()
        if cancel.is_set():
            raise InterruptedError("cancellation requested")
        all_runs = trig + [r for v in reg_runs.values() for r in v] + benign
        ev = self.monitoring.store_events(s, self.adversarial.drain_telemetry(), "live_lab")
        win, _ = self.monitoring.build_windows(s, ev, all_runs, "live_lab")
        summary = {"trigger": {"scenario_id": case.scenario_id, "n_trials": len(trig),
                               "n_executed": sum(r.executed for r in trig),
                               "n_effect": sum(bool(r.effect_occurred) for r in trig if r.executed),
                               "run_ids": [r.id for r in trig], "detected": {}, "latency_s": {}},
                   "regression": {sid: {"n_executed": sum(r.executed for r in rr), "run_ids": [r.id for r in rr],
                                        "detected": {}} for sid, rr in reg_runs.items()},
                   "benign": {"n_windows": 0, "alert_windows": {}, "false_positives": {},
                              "requests": sum(r.effect_evidence.get("requests", 0) for r in benign),
                              "denied": sum(r.effect_evidence.get("denied", 0) for r in benign),
                              "run_ids": [r.id for r in benign]},
                   "health": health, "lab_config": lab_config, "n_events": int(len(ev)), "n_windows": int(len(win))}
        for v in eval_versions:
            res = self.monitoring.detect(s, v, win, ev, "live_lab", store=(v is eval_versions[-1]))
            rds = self.monitoring.run_detections(s, v, win, res, all_runs)
            vid = str(v.id)
            summary["trigger"]["detected"][vid] = [rds[r.id].detected for r in trig if r.executed]
            summary["trigger"]["latency_s"][vid] = [rds[r.id].latency_s for r in trig if r.executed and rds[r.id].detected]
            for sid, rr in reg_runs.items():
                summary["regression"][sid]["detected"][vid] = [rds[r.id].detected for r in rr if r.executed]
            n_b, n_fp, fps = self.monitoring.benign_alerts(win, res)
            summary["benign"]["n_windows"] = n_b
            summary["benign"]["alert_windows"][vid] = n_fp
            summary["benign"]["false_positives"][vid] = fps[:20]
        s.commit()
        return summary

    def _fail_or_retry(self, case_id: int, running: str, retry_to: str, err: Exception) -> None:
        with self.db.session() as s:
            case = s.get(Case, case_id)
            if case.state != running:
                return
            retryable = not isinstance(err, (ActiveLabDisabled, PermissionError, InterruptedError))
            if isinstance(err, InterruptedError):
                self._transition(s, case, "cancelled", "coordinator", SYSTEM,
                                 "operator cancellation honoured between trials")
            elif retryable and case.attempts <= self.settings.coordinator.max_retries:
                self._transition(s, case, retry_to, "coordinator", SYSTEM, f"retry after error: {err}",
                                 {"attempts": case.attempts})
            else:
                self._transition(s, case, "failed", "coordinator", SYSTEM, f"{type(err).__name__}: {err}",
                                 {"attempts": case.attempts})

    # ================================================================== baseline test
    def run_baseline(self, case_id: int) -> str:
        if not self.settings.lab.active_scenarios_enabled:   # refuse before claiming; state unchanged
            raise ActiveLabDisabled("active laboratory scenarios are disabled (opt-in: SAGE_ENABLE_ACTIVE_LAB=1)")
        if not self._claim(case_id, "scenario_approved", "baseline_test_running"):
            raise TransitionError("case is not in scenario_approved (or already claimed): duplicate execution prevented")
        cancel = self._cancel_events.setdefault(case_id, threading.Event())
        try:
            with self.db.session() as s:
                case = s.get(Case, case_id)
                active = versions.get_active(s)
                others = [sid for sid in self.adversarial.catalogue if sid != case.scenario_id]
                summary = self._run_phase(s, case, "baseline", self._seed(case_id, "baseline"), active.lab_config,
                                          [active], others, cancel, self.settings.experiment.baseline_trials)
                vid = str(active.id)
                thr = self.policy["regression_pass_threshold"]
                summary["regression_set"] = [sid for sid, r in summary["regression"].items()
                                             if r["detected"].get(vid) and
                                             sum(r["detected"][vid]) / len(r["detected"][vid]) >= thr]
                case.baseline_version_id, case.baseline_summary = active.id, summary
                criteria = derive_criteria(summary, active.id, self.policy)
                case.criteria, case.criteria_hash = criteria.model_dump(), criteria_hash(criteria)
                audit.append(s, "coordinator", "criteria_frozen", "case", case.id,
                             {"criteria_hash": case.criteria_hash, "criteria": case.criteria})
                self._transition(s, case, "baseline_test_completed", "agent:adversarial", SYSTEM,
                                 "baseline measurement complete", self._evidence(summary, vid))
                self._decide_weakness(s, case, summary, active)
                state = case.state
        except Exception as e:  # noqa: BLE001
            log.warning("baseline test failed: %s", e, exc_info=not isinstance(e, PermissionError))
            self._fail_or_retry(case_id, "baseline_test_running", "scenario_approved", e)
            raise
        if state in TERMINAL:
            self.report(case_id)
        return state

    @staticmethod
    def _evidence(summary: dict, vid: str) -> dict:
        t = summary["trigger"]
        det = t["detected"].get(vid, [])
        return {"trials": t["n_trials"], "executed": t["n_executed"], "effect": t["n_effect"],
                "detected": sum(det), "run_ids": t["run_ids"], "benign_windows": summary["benign"]["n_windows"],
                "benign_alert_windows": summary["benign"]["alert_windows"].get(vid), "health": summary["health"]}

    def _decide_weakness(self, s, case: Case, summary: dict, active: DetectorVersion) -> None:
        t = summary["trigger"]
        if t["n_trials"] == 0 or 1 - t["n_executed"] / t["n_trials"] > self.policy["max_execution_failure_rate"]:
            self._transition(s, case, "inconclusive", "coordinator", SYSTEM,
                             "too many trials failed to execute; no conclusion about the asset is drawn")
            return
        ev = weakness_profile(summary, active.id, self.policy)
        if ev["detection_weakness"] or ev["prevention_weakness"]:
            kind = " and ".join(k for k, f in (("detection", ev["detection_weakness"]),
                                               ("prevention", ev["prevention_weakness"])) if f)
            self._transition(s, case, "remediation_proposed", "agent:remediation", SYSTEM,
                             f"{kind} weakness confirmed by baseline evidence; acceptance objective: {ev['objective']}", ev)
            self.remediation.propose(s, case, active)
        else:
            self._transition(s, case, "weakness_not_confirmed", "coordinator", SYSTEM,
                             "no weakness reproduced under the tested conditions (this is NOT proof of security)", ev)

    # ================================================================== candidate & retest
    def prepare_candidate(self, case_id: int, proposal_id: int, operator: str) -> int:
        with self.db.session() as s:
            case = s.get(Case, case_id)
            if case.adaptation_cycles >= self.settings.coordinator.max_adaptation_cycles:
                raise TransitionError("adaptation cycle budget exhausted")
            p = s.get(RemediationProposal, proposal_id)
            if p is None or p.case_id != case_id or p.status != "proposed":
                raise TransitionError("proposal is not an open proposal of this case")
            parent = s.get(DetectorVersion, case.baseline_version_id)
            v = self.remediation.prepare_candidate(s, p, parent, seed=self.settings.experiment.base_seed + case_id)
            case.candidate_version_id = v.id
            case.adaptation_cycles += 1
            case.attempts = 0
            self._transition(s, case, "candidate_prepared", operator, OPERATOR, f"prepare proposal {p.id}",
                             {"proposal_id": p.id, "candidate_version_id": v.id, "bundle_hash": v.bundle_hash})
            return v.id

    def run_retest(self, case_id: int) -> str:
        if not self.settings.lab.active_scenarios_enabled:   # refuse before claiming; state unchanged
            raise ActiveLabDisabled("active laboratory scenarios are disabled (opt-in: SAGE_ENABLE_ACTIVE_LAB=1)")
        if not self._claim(case_id, "candidate_prepared", "retest_running"):
            raise TransitionError("case is not in candidate_prepared (or already claimed): duplicate execution prevented")
        cancel = self._cancel_events.setdefault(case_id, threading.Event())
        try:
            with self.db.session() as s:
                case = s.get(Case, case_id)
                base = s.get(DetectorVersion, case.baseline_version_id)
                cand = s.get(DetectorVersion, case.candidate_version_id)
                reg = case.baseline_summary.get("regression_set", [])
                summary = self._run_phase(s, case, "retest", self._seed(case_id, "retest"),
                                          cand.lab_config, [base, cand], reg, cancel,
                                          self.settings.experiment.retest_trials)
                criteria = AcceptanceCriteria.model_validate(case.criteria)
                result = evaluate_candidate(criteria, case.criteria_hash, case.baseline_summary, summary,
                                            base.id, cand.id, reg)
                result["retest_summary"] = summary
                ev = Evaluation(case_id=case.id, baseline_version_id=base.id, candidate_version_id=cand.id,
                                criteria_hash=case.criteria_hash, results=result, passed=result["passed"],
                                inconclusive=result["inconclusive"])
                s.add(ev)
                s.flush()
                prop = s.execute(select(RemediationProposal).where(
                    RemediationProposal.candidate_version_id == cand.id)).scalar_one()
                brief = {"evaluation_id": ev.id, "passed": result["passed"], "inconclusive": result["inconclusive"],
                         "failed_checks": [c["name"] for c in result["checks"] if not c["passed"]]}
                if result["inconclusive"]:
                    versions.reject(s, cand.id, "coordinator", "retest inconclusive")
                    prop.status = "rejected"
                    self._transition(s, case, "inconclusive", "coordinator", SYSTEM, "retest inconclusive", brief)
                elif result["passed"]:
                    self._transition(s, case, "acceptance_pending", "coordinator", SYSTEM,
                                     "all frozen criteria satisfied; operator decision required", brief)
                else:
                    versions.reject(s, cand.id, "coordinator", f"failed criteria {brief['failed_checks']}")
                    prop.status = "rejected"
                    if case.adaptation_cycles < self.settings.coordinator.max_adaptation_cycles:
                        self._transition(s, case, "remediation_proposed", "coordinator", SYSTEM,
                                         "candidate failed frozen criteria; other proposals remain", brief)
                    else:
                        self._transition(s, case, "rejected", "coordinator", SYSTEM,
                                         "candidate failed and adaptation budget exhausted", brief)
                state = case.state
        except Exception as e:  # noqa: BLE001
            log.warning("retest failed: %s", e, exc_info=not isinstance(e, PermissionError))
            self._fail_or_retry(case_id, "retest_running", "candidate_prepared", e)
            raise
        if state in TERMINAL:
            self.report(case_id)
        return state

    # ================================================================== operator decisions
    def accept(self, case_id: int, operator: str) -> int:
        with self.db.session() as s:
            case = s.get(Case, case_id)
            ev = s.execute(select(Evaluation).where(Evaluation.case_id == case_id,
                                                    Evaluation.candidate_version_id == case.candidate_version_id)
                           .order_by(Evaluation.id.desc())).scalars().first()
            if case.state != "acceptance_pending" or ev is None or not ev.passed:
                raise TransitionError("acceptance requires state acceptance_pending and a passed evaluation")
            versions.accept(s, case.candidate_version_id, operator, ev.passed)
            prop = s.execute(select(RemediationProposal).where(
                RemediationProposal.candidate_version_id == case.candidate_version_id)).scalar_one()
            prop.status = "accepted"
            self._transition(s, case, "accepted", operator, OPERATOR, "operator accepted validated candidate",
                             {"evaluation_id": ev.id, "version_id": case.candidate_version_id})
            vid = case.candidate_version_id
        self.report(case_id)
        return vid

    def reject(self, case_id: int, operator: str, reason: str) -> None:
        with self.db.session() as s:
            case = s.get(Case, case_id)
            if case.state == "acceptance_pending":
                versions.reject(s, case.candidate_version_id, operator, reason)
                p = s.execute(select(RemediationProposal).where(
                    RemediationProposal.candidate_version_id == case.candidate_version_id)).scalar_one()
                p.status = "rejected"
            self._transition(s, case, "rejected", operator, OPERATOR, reason)
        self.report(case_id)

    def cancel(self, case_id: int, operator: str) -> str:
        with self.db.session() as s:
            case = s.get(Case, case_id)
            if case.state in RUNNING:
                case.cancel_requested = True
                self._cancel_events.setdefault(case_id, threading.Event()).set()
                audit.append(s, operator, "cancel_requested", "case", case_id, {})
                return "cancellation requested"
            self._transition(s, case, "cancelled", operator, OPERATOR, "operator cancelled")
            return "cancelled"

    def rollback(self, operator: str, to_version_id: int | None = None) -> int:
        with self.db.session() as s:
            return versions.rollback(s, operator, to_version_id).id

    # ================================================================== recovery
    def recover(self) -> list[int]:
        """After a restart: running cases whose heartbeat is stale are timed out (never silently resumed)."""
        out = []
        limit = utcnow() - timedelta(seconds=self.settings.coordinator.running_timeout_s)
        with self.db.session() as s:
            for case in s.execute(select(Case).where(Case.state.in_(RUNNING))).scalars():
                if case.heartbeat_at is None or case.heartbeat_at < limit or case.cancel_requested:
                    self._transition(s, case, "timed_out", "coordinator", SYSTEM,
                                     "recovered after restart: running phase had no live heartbeat",
                                     {"last_heartbeat": str(case.heartbeat_at)})
                    out.append(case.id)
        return out

    # ================================================================== reports
    def report(self, case_id: int) -> int:
        with self.db.session() as s:
            return self.explanation.case_report(s, case_id).id

    def run_detections_for(self, s, run_ids: list[int]) -> list[RunDetection]:
        return s.execute(select(RunDetection).where(RunDetection.run_id.in_(run_ids))).scalars().all()
