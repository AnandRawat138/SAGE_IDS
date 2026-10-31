"""Adversarial Validation Agent: runs ONLY approved catalogue scenarios against allowlisted lab targets.

Records, per trial and separately: (a) executed?  (b) intended security effect?  Detection (c) is
determined afterwards by the Monitoring Agent on the captured telemetry.
"""
from __future__ import annotations

import ipaddress
import random
import threading
import time

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit
from ..config import Settings
from ..db import ExperimentRun
from ..lab.benign import run_benign_round
from ..lab.runtime import get_lab
from ..lab.scenarios import default_context, execute_trial, load_catalogue, sample_params
from ..security.allowlist import ActiveLabDisabled, Allowlist


class ScenarioNotApproved(PermissionError):
    pass


class AdversarialAgent:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.catalogue = load_catalogue()
        self.allow = Allowlist.from_settings(settings.lab)
        self._attacker_hosts = [str(h) for h in ipaddress.ip_network(settings.lab.attacker_source_cidr).hosts()][9:250]

    def _next_src(self, s: Session) -> str:
        n = s.execute(select(func.count(ExperimentRun.id))).scalar_one()
        return self._attacker_hosts[n % len(self._attacker_hosts)]

    def ensure_lab(self, lab_config: dict):
        if not self.settings.lab.active_scenarios_enabled:
            raise ActiveLabDisabled("active laboratory scenarios are disabled (opt-in: SAGE_ENABLE_ACTIVE_LAB=1)")
        lab = get_lab(self.settings)
        lab.config.apply(lab_config or {})
        lab.reset_state()
        return lab

    def start_phase(self, lab_config: dict) -> None:
        """Apply the lab config in force and discard telemetry captured before this phase."""
        self.ensure_lab(lab_config).sensor.drain()

    def run_trials(self, s: Session, *, case_id: int | None, scenario_id: str, phase: str, n_trials: int,
                   seed_base: int, lab_config: dict, version_id: int | None,
                   cancel: threading.Event | None = None, heartbeat=None) -> list[ExperimentRun]:  # noqa: ANN001
        spec = self.catalogue.get(scenario_id)
        if spec is None:
            raise ScenarioNotApproved(f"scenario {scenario_id!r} is not in the approved catalogue")
        lab = self.ensure_lab(lab_config)
        ctx = default_context(self.settings, cancel)
        runs = []
        for i in range(n_trials):
            if ctx.cancel.is_set():
                break
            seed = seed_base + i
            src = self._next_src(s)
            params = sample_params(spec, random.Random(seed * 7919))
            out = execute_trial(spec, params, src, ctx, seed=seed, trial_index=i)
            lab.reset_state()  # cleanup between trials
            run = ExperimentRun(case_id=case_id, phase=phase, scenario_id=scenario_id, trial_index=i, seed=seed,
                                src_ip=src, lab_config=lab.config.as_dict(), version_id=version_id,
                                started_at=out.started_at, ended_at=out.ended_at, executed=out.executed,
                                execution_error=out.execution_error, effect_occurred=out.effect_occurred,
                                effect_evidence=out.effect_evidence, stop_reason=out.stop_reason,
                                data_origin="live_lab")
            s.add(run)
            s.flush()
            runs.append(run)
            if heartbeat:
                heartbeat()
            time.sleep(0.05)
        audit.append(s, "agent:adversarial", "trials_executed", "case", case_id or "-",
                     {"scenario": scenario_id, "phase": phase, "trials": len(runs),
                      "executed": sum(r.executed for r in runs), "lab_config": lab.config.as_dict()})
        return runs

    def run_benign(self, s: Session, *, case_id: int | None, phase: str, rounds: int, seed_base: int,
                   lab_config: dict, version_id: int | None, heartbeat=None) -> list[ExperimentRun]:  # noqa: ANN001
        lab = self.ensure_lab(lab_config)
        ports = {"login": self.settings.lab.login_service_port, "test_app": self.settings.lab.test_app_port,
                 "decoy": self.settings.lab.decoy_ports[0]}
        prefix = self.settings.lab.benign_source_cidr.rsplit(".", 1)[0] + "."
        runs = []
        for k in range(rounds):
            st = run_benign_round(self.allow, ports, self.settings.experiment.benign_users, seed_base + k, prefix)
            run = ExperimentRun(case_id=case_id, phase=phase, scenario_id="benign-traffic", trial_index=k,
                                seed=seed_base + k, src_ip=prefix + "*", lab_config=lab.config.as_dict(),
                                version_id=version_id, started_at=st["started_at"], ended_at=st["ended_at"],
                                executed=st["requests"] > 0, effect_occurred=None,
                                effect_evidence={"requests": st["requests"], "denied": st["denied"],
                                                 "errors": st["errors"], "sources": st["sources"]},
                                stop_reason="round complete", data_origin="live_lab")
            s.add(run)
            s.flush()
            runs.append(run)
            if heartbeat:
                heartbeat()
            time.sleep(self.settings.monitoring.window_seconds)  # keep rounds in separate windows
        return runs

    def drain_telemetry(self) -> list[dict]:
        lab = get_lab(self.settings)
        return [e for e in lab.sensor.drain() if e["src_ip"] != "127.0.0.1"]  # drop lab health probes

    def health(self) -> dict:
        return get_lab(self.settings).health()
