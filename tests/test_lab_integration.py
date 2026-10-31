"""Miniature closed loop on a real loopback lab (separate port range). Takes ~1-2 minutes.
Skip with:  pytest -m "not lab"
"""
import pytest
from sqlalchemy import select

from sage_ids import audit
from sage_ids.agents.adversarial import ScenarioNotApproved
from sage_ids.coordinator.coordinator import Coordinator
from sage_ids.coordinator.state_machine import TransitionError
from sage_ids.db import Case, Database, ExperimentRun, RemediationProposal, Report, RunDetection
from sage_ids.lab.runtime import stop_lab

from .conftest import make_settings

pytestmark = pytest.mark.lab


def test_closed_loop_on_live_lab(tmp_path):
    st = make_settings(tmp_path, active=True)
    st.experiment.baseline_trials = st.experiment.retest_trials = 4
    st.experiment.benign_windows_per_phase = 1
    st.monitoring.window_seconds = 2.0
    db = Database(st.database_url)
    coord = Coordinator(st, db)
    try:
        v1 = coord.bootstrap("operator:test", calibration_trials=4, benign_rounds=3)
        coord.ingest_findings("fixture")
        with db.session() as s:
            cid = s.execute(select(Case).where(Case.idempotency_key == "finding:nvd:SYNTH-2026-0001")).scalar_one().id
        coord.approve_scenario(cid, "operator:test")
        state = coord.run_baseline(cid)
        assert state in {"remediation_proposed", "weakness_not_confirmed", "inconclusive"}
        with pytest.raises(TransitionError, match="duplicate"):
            coord.run_baseline(cid)                       # already claimed/completed
        with db.session() as s:
            runs = s.execute(select(ExperimentRun).where(ExperimentRun.case_id == cid)).scalars().all()
            assert runs and all(r.data_origin == "live_lab" for r in runs)
            trig = [r for r in runs if r.phase == "baseline"]
            assert all(r.executed for r in trig)            # three outcomes recorded separately
            assert all(r.effect_occurred is not None for r in trig)
            assert s.execute(select(RunDetection).where(RunDetection.run_id == trig[0].id)).scalar_one().version_id == v1
            case = s.get(Case, cid)
            assert case.criteria_hash and case.baseline_summary["trigger"]["n_trials"] == 4
        if state == "remediation_proposed":
            with db.session() as s:
                pid = s.execute(select(RemediationProposal).where(RemediationProposal.case_id == cid)
                                .order_by(RemediationProposal.id)).scalars().first().id
            coord.prepare_candidate(cid, pid, "operator:test")
            state = coord.run_retest(cid)
            assert state in {"acceptance_pending", "remediation_proposed", "rejected", "inconclusive"}
            if state == "acceptance_pending":
                coord.accept(cid, "operator:test")
                assert coord.rollback("operator:test") == v1
        with db.session() as s:
            assert s.execute(select(Report).where(Report.case_id == cid)).scalars().first() is not None \
                or coord.report(cid)
            assert audit.verify(s)["valid"]
        with pytest.raises(ScenarioNotApproved):
            with db.session() as s:
                coord.adversarial.run_trials(s, case_id=None, scenario_id="downloaded-exploit", phase="x",
                                             n_trials=1, seed_base=1, lab_config={}, version_id=None)
    finally:
        stop_lab()
