from datetime import timedelta

import pytest
from sqlalchemy import select

from sage_ids import audit
from sage_ids.coordinator.coordinator import Coordinator
from sage_ids.coordinator.state_machine import (OPERATOR, SYSTEM, TERMINAL, TRANSITIONS, TransitionError, check)
from sage_ids.db import Case, Transition, utcnow
from sage_ids.security.allowlist import ActiveLabDisabled


def _case(db, state="scenario_approved", **kw):
    with db.session() as s:
        c = Case(idempotency_key=f"k-{state}-{utcnow().timestamp()}", state=state,
                 scenario_id="auth-password-guessing", **kw)
        s.add(c)
        s.flush()
        return c.id


def test_valid_and_invalid_transitions():
    check("finding_received", "relevance_checked", SYSTEM)
    with pytest.raises(TransitionError):
        check("finding_received", "accepted", SYSTEM)            # skipping the loop is impossible
    with pytest.raises(TransitionError):
        check("baseline_test_completed", "accepted", OPERATOR)


def test_role_enforcement():
    with pytest.raises(TransitionError):
        check("scenario_pending_review", "scenario_approved", SYSTEM)   # agents cannot self-approve
    with pytest.raises(TransitionError):
        check("acceptance_pending", "accepted", SYSTEM)                 # acceptance is operator-only
    check("acceptance_pending", "accepted", OPERATOR)


def test_terminal_states_have_no_exit():
    for (frm, _to) in TRANSITIONS:
        assert frm not in TERMINAL


def test_operator_identity_cannot_be_agent(settings, db):
    coord = Coordinator(settings, db)
    cid = _case(db, "scenario_pending_review")
    with pytest.raises(TransitionError):
        coord.approve_scenario(cid, "agent:remediation")
    with pytest.raises(TransitionError):
        coord.approve_scenario(cid, "")


def test_transitions_are_recorded_and_hash_chained(settings, db):
    coord = Coordinator(settings, db)
    cid = _case(db, "scenario_pending_review")
    coord.approve_scenario(cid, "operator:alice")
    with db.session() as s:
        t = s.execute(select(Transition).where(Transition.case_id == cid)).scalar_one()
        assert (t.from_state, t.to_state, t.actor) == ("scenario_pending_review", "scenario_approved", "operator:alice")
        assert t.evidence["scenario"]["id"] == "auth-password-guessing"
        assert len(t.audit_hash) == 64
        assert audit.verify(s)["valid"]


def test_duplicate_execution_prevented(settings, db):
    coord = Coordinator(settings, db)
    cid = _case(db)
    assert coord._claim(cid, "scenario_approved", "baseline_test_running") is not None
    assert coord._claim(cid, "scenario_approved", "baseline_test_running") is None


def test_run_refused_without_opt_in_leaves_state(settings, db):
    coord = Coordinator(settings, db)          # active lab disabled
    cid = _case(db)
    with pytest.raises(ActiveLabDisabled):
        coord.run_baseline(cid)
    with db.session() as s:
        assert s.get(Case, cid).state == "scenario_approved"


def test_recovery_times_out_stale_running_case(settings, db):
    coord = Coordinator(settings, db)
    cid = _case(db, "baseline_test_running", heartbeat_at=utcnow() - timedelta(hours=2))
    fresh = _case(db, "retest_running", heartbeat_at=utcnow())
    assert coord.recover() == [cid]
    with db.session() as s:
        assert s.get(Case, cid).state == "timed_out"
        assert s.get(Case, fresh).state == "retest_running"


def test_cancel_pending_and_running(settings, db):
    coord = Coordinator(settings, db)
    pend = _case(db, "scenario_pending_review")
    assert coord.cancel(pend, "operator:alice") == "cancelled"
    run = _case(db, "baseline_test_running", heartbeat_at=utcnow())
    assert coord.cancel(run, "operator:alice") == "cancellation requested"
    with db.session() as s:
        assert s.get(Case, run).cancel_requested


def test_bounded_retries_then_failed(settings, db):
    coord = Coordinator(settings, db)
    cid = _case(db, "baseline_test_running", attempts=settings.coordinator.max_retries + 1)
    coord._fail_or_retry(cid, "baseline_test_running", "scenario_approved", RuntimeError("boom"))
    with db.session() as s:
        assert s.get(Case, cid).state == "failed"
    cid2 = _case(db, "baseline_test_running", attempts=1)
    coord._fail_or_retry(cid2, "baseline_test_running", "scenario_approved", RuntimeError("transient"))
    with db.session() as s:
        assert s.get(Case, cid2).state == "scenario_approved"


def test_adaptation_cycles_bounded(settings, db):
    coord = Coordinator(settings, db)
    cid = _case(db, "remediation_proposed", adaptation_cycles=settings.coordinator.max_adaptation_cycles)
    with pytest.raises(TransitionError, match="budget"):
        coord.prepare_candidate(cid, 1, "operator:alice")


def test_accept_requires_passed_evaluation(settings, db):
    coord = Coordinator(settings, db)
    cid = _case(db, "acceptance_pending", candidate_version_id=99)
    with pytest.raises(TransitionError):
        coord.accept(cid, "operator:alice")
