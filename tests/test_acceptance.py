import copy

import pytest

from sage_ids.detection import versions
from sage_ids.detection.versions import VersionError
from sage_ids.evaluation.acceptance import criteria_hash, derive_criteria, evaluate_candidate
from sage_ids.evaluation.stats import mcnemar_exact, wilson


def summary(det_b, det_c=None, effect=20, fp_b=1, fp_c=None, n_ben=50, denied=0, health=True, n_trials=20,
            executed=20, reg=None):
    det = {"1": det_b}
    if det_c is not None:
        det["2"] = det_c
    alerts = {"1": fp_b}
    if fp_c is not None:
        alerts["2"] = fp_c
    return {"trigger": {"scenario_id": "auth-password-guessing", "n_trials": n_trials, "n_executed": executed,
                        "n_effect": effect, "detected": det},
            "regression": reg or {}, "benign": {"n_windows": n_ben, "alert_windows": alerts, "requests": 500,
                                                "denied": denied},
            "health": {"login": health, "test_app": True}}


BASE = summary([False] * 20)
CRIT = derive_criteria(BASE, 1)
H = criteria_hash(CRIT)
REG = {"recon-tcp-probe": {"n_executed": 10, "detected": {"1": [True] * 10, "2": [True] * 10}}}


def test_criteria_derived_from_baseline_and_frozen():
    assert CRIT.benign_fpr_max == pytest.approx(1 / 50 + 0.02)
    tampered = copy.deepcopy(CRIT)
    tampered.benign_fpr_max = 0.9
    with pytest.raises(ValueError, match="frozen"):
        evaluate_candidate(tampered, H, BASE, summary([False] * 20, [True] * 20, fp_c=1), 1, 2, [])


def test_good_candidate_passes():
    r = evaluate_candidate(CRIT, H, BASE, summary([False] * 20, [True] * 20, effect=5, fp_c=1, reg=REG), 1, 2,
                           ["recon-tcp-probe"])
    assert r["passed"] and not r["inconclusive"]


def test_high_false_positive_candidate_rejected():
    r = evaluate_candidate(CRIT, H, BASE, summary([False] * 20, [True] * 20, fp_c=15), 1, 2, [])
    assert not r["passed"]
    assert [c["name"] for c in r["checks"] if not c["passed"]] == ["benign_fpr"]


def test_regression_failure_rejected():
    reg = {"recon-tcp-probe": {"n_executed": 10, "detected": {"1": [True] * 10, "2": [False] * 10}}}
    r = evaluate_candidate(CRIT, H, BASE, summary([False] * 20, [True] * 20, fp_c=1, reg=reg), 1, 2, ["recon-tcp-probe"])
    assert not r["passed"]


def test_too_many_execution_failures_inconclusive():
    r = evaluate_candidate(CRIT, H, BASE, summary([False] * 10, [True] * 10, fp_c=0, executed=10), 1, 2, [])
    assert r["inconclusive"] and not r["passed"]


def test_unhealthy_service_and_increased_effect_rejected():
    base = summary([False] * 20, effect=2)
    c = derive_criteria(base, 1)
    r = evaluate_candidate(c, criteria_hash(c), base, summary([False] * 20, [True] * 20, effect=20, fp_c=1,
                                                              health=False), 1, 2, [])
    failed = {x["name"] for x in r["checks"] if not x["passed"]}
    assert {"effect_rate_not_increased", "service_health"} <= failed


def test_stats():
    p, lo, hi = wilson(20, 20)
    assert p == 1 and lo == pytest.approx(0.8389, abs=1e-3)
    m = mcnemar_exact([False] * 10, [True] * 10)
    assert m["b_candidate_only"] == 10 and m["p_value"] == pytest.approx(0.5 ** 10)


# ----------------------------------------------------------------- versions: accept / reject / rollback
def _v(s, name, parent=None):
    return versions.create_version(s, name=name, parent_id=parent, ruleset=[], lab_config={}, detector_policy={},
                                   model_path=None, model_sha256=None, label_set={})


def test_accept_requires_operator_and_passed_criteria(db):
    with db.session() as s:
        v1 = _v(s, "v1")
        versions.accept(s, v1.id, "operator:alice", None, bootstrap=True)
        v2 = _v(s, "v2", v1.id)
        with pytest.raises(VersionError):
            versions.accept(s, v2.id, "operator:alice", evaluation_passed=False)
        with pytest.raises(VersionError):
            versions.accept(s, v2.id, "agent:remediation", evaluation_passed=True)
        assert versions.get_active(s).id == v1.id            # proposal never auto-activated


def test_candidate_bundle_tamper_blocks_acceptance(db):
    with db.session() as s:
        v = _v(s, "v")
        v.ruleset = [{"id": "EVIL"}]
        with pytest.raises(VersionError, match="changed"):
            versions.accept(s, v.id, "operator:alice", True)


def test_rollback_restores_previous_accepted(db):
    with db.session() as s:
        v1 = _v(s, "v1")
        versions.accept(s, v1.id, "operator:alice", None, bootstrap=True)
        with pytest.raises(VersionError):
            versions.rollback(s, "operator:alice")             # nothing earlier to roll back to
        v2 = _v(s, "v2", v1.id)
        versions.accept(s, v2.id, "operator:alice", True)
        rej = _v(s, "v3", v2.id)
        versions.reject(s, rej.id, "coordinator", "failed criteria")
        with pytest.raises(VersionError):
            versions.rollback(s, "operator:alice", rej.id)     # rejected versions can never be activated
        assert versions.rollback(s, "operator:alice").id == v1.id
        assert versions.get_active(s).id == v1.id
        assert versions.rollback(s, "operator:alice", v2.id).id == v2.id


def test_prevention_objective_when_detection_already_adequate():
    base = summary([True] * 20, effect=20)                    # detected, but the effect still happens
    c = derive_criteria(base, 1)
    assert c.objective == "prevention"
    h = criteria_hash(c)
    good = evaluate_candidate(c, h, base, summary([True] * 20, [True] * 20, effect=3, fp_c=1), 1, 2, [])
    assert good["passed"], [x for x in good["checks"] if not x["passed"]]
    detect_only = evaluate_candidate(c, h, base, summary([True] * 20, [True] * 20, effect=19, fp_c=1), 1, 2, [])
    assert {x["name"] for x in detect_only["checks"] if not x["passed"]} == {"effect_rate_reduction", "effect_fisher_p"}
