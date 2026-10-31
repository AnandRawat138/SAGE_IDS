"""Evidence-gated acceptance: derive criteria from the measured baseline, freeze (hash-commit), evaluate.

Phase summaries have the shape produced by `Coordinator._phase_summary`:
{"trigger": {"scenario_id", "n_trials", "n_executed", "n_effect", "detected": {vid: [bool,...]}},
 "regression": {sid: {"n_executed", "detected": {vid: [bool,...]}}},
 "benign": {"n_windows", "alert_windows": {vid: int}, "requests", "denied"},
 "health": {service: bool}}
"""
from __future__ import annotations

from ..audit import canonical, sha256_hex
from ..config import load_yaml
from ..schemas import AcceptanceCriteria
from .stats import fisher_greater, mcnemar_exact, wilson


def load_policy() -> dict:
    return load_yaml("acceptance_policy.yaml")


def _rate(k: int, n: int) -> float:
    return k / n if n else 0.0


def weakness_profile(baseline: dict, baseline_vid: int, policy: dict) -> dict:
    t = baseline["trigger"]
    n = t["n_executed"]
    det = t["detected"].get(str(baseline_vid), [])
    gap = 1 - sum(det) / n if n else 0.0
    eff = t["n_effect"] / n if n else 0.0
    detection_weak = gap >= policy["weakness_min_detection_gap"]
    prevention_weak = eff >= policy["weakness_min_effect_rate"]
    return {"detection_gap": gap, "effect_rate": eff, "n_executed": n, "detection_weakness": detection_weak,
            "prevention_weakness": prevention_weak,
            "objective": "detection" if detection_weak else "prevention"}


def derive_criteria(baseline: dict, baseline_vid: int, policy: dict | None = None) -> AcceptanceCriteria:
    policy = policy or load_policy()
    prof = weakness_profile(baseline, baseline_vid, policy)
    b = baseline["benign"]
    fpr = _rate(b["alert_windows"].get(str(baseline_vid), 0), b["n_windows"])
    denied = _rate(b["denied"], b["requests"])
    return AcceptanceCriteria(
        objective=prof["objective"],
        prevention_min_effect_reduction=policy["prevention_min_effect_reduction"],
        prevention_fisher_alpha=policy["prevention_fisher_alpha"],
        trigger_min_detection_gain=policy["trigger_min_detection_gain"],
        trigger_mcnemar_alpha=policy["trigger_mcnemar_alpha"],
        trigger_min_detection_rate_lcb=policy["trigger_min_detection_rate_lcb"],
        regression_noninferiority_margin=policy["regression_noninferiority_margin"],
        benign_fpr_max=round(fpr + policy["benign_fpr_margin"], 6),
        benign_denied_rate_max=round(denied + policy["benign_denied_margin"], 6),
        effect_must_not_increase=policy["effect_must_not_increase"],
        effect_tolerance=policy["effect_tolerance"],
        require_service_health=policy["require_service_health"],
        max_execution_failure_rate=policy["max_execution_failure_rate"],
        derived_from={"baseline_version_id": baseline_vid, "baseline_benign_fpr": fpr,
                      "baseline_benign_windows": b["n_windows"], "baseline_denied_rate": denied,
                      "baseline_effect_rate": _rate(baseline["trigger"]["n_effect"], baseline["trigger"]["n_executed"]),
                      "weakness_profile": prof, "policy": policy})


def criteria_hash(c: AcceptanceCriteria) -> str:
    return sha256_hex(canonical(c.model_dump()))


def evaluate_candidate(criteria: AcceptanceCriteria, frozen_hash: str, baseline_phase: dict, retest: dict,
                       baseline_vid: int, candidate_vid: int, regression_set: list[str]) -> dict:
    if criteria_hash(criteria) != frozen_hash:
        raise ValueError("acceptance criteria do not match the frozen commitment")
    bv, cv = str(baseline_vid), str(candidate_vid)
    checks: list[dict] = []
    t = retest["trigger"]
    fail_rate = 1 - _rate(t["n_executed"], t["n_trials"])
    inconclusive = t["n_trials"] == 0 or fail_rate > criteria.max_execution_failure_rate

    det_b, det_c = t["detected"].get(bv, []), t["detected"].get(cv, [])
    n = len(det_c)
    p_c, lcb, ucb = wilson(sum(det_c), n)
    p_b = _rate(sum(det_b), len(det_b))
    bt = baseline_phase["trigger"]
    eff_base = _rate(bt["n_effect"], bt["n_executed"])
    eff_new = _rate(t["n_effect"], t["n_executed"])
    if criteria.objective == "detection":
        # 1. detection objective: paired comparison on identical retest telemetry
        mc = mcnemar_exact(det_b, det_c, "greater") if n else {"p_value": 1.0}
        checks.append({"name": "trigger_detection_gain", "value": p_c - p_b,
                       "required": f">= {criteria.trigger_min_detection_gain}",
                       "passed": n > 0 and (p_c - p_b) >= criteria.trigger_min_detection_gain})
        checks.append({"name": "trigger_mcnemar_p", "value": mc["p_value"], "required": f"< {criteria.trigger_mcnemar_alpha}",
                       "passed": mc["p_value"] < criteria.trigger_mcnemar_alpha, "detail": mc})
        checks.append({"name": "trigger_detection_rate_lcb", "value": lcb,
                       "required": f">= {criteria.trigger_min_detection_rate_lcb}",
                       "passed": n > 0 and lcb >= criteria.trigger_min_detection_rate_lcb,
                       "detail": {"rate": p_c, "ci": [lcb, ucb], "baseline_rate_same_trials": p_b}})
        # 2. security effect must not increase relative to the baseline test
        if criteria.effect_must_not_increase:
            checks.append({"name": "effect_rate_not_increased", "value": eff_new,
                           "required": f"<= {eff_base:.3f} + {criteria.effect_tolerance}",
                           "passed": eff_new <= eff_base + criteria.effect_tolerance,
                           "detail": {"baseline_effect_rate": eff_base}})
    else:
        # 1'. prevention objective: the security effect must drop; detection must not get worse
        fp = fisher_greater(bt["n_effect"], bt["n_executed"], t["n_effect"], t["n_executed"])
        checks.append({"name": "effect_rate_reduction", "value": eff_base - eff_new,
                       "required": f">= {criteria.prevention_min_effect_reduction}",
                       "passed": t["n_executed"] > 0 and eff_base - eff_new >= criteria.prevention_min_effect_reduction,
                       "detail": {"baseline_effect_rate": eff_base, "candidate_effect_rate": eff_new}})
        checks.append({"name": "effect_fisher_p", "value": fp, "required": f"< {criteria.prevention_fisher_alpha}",
                       "passed": fp < criteria.prevention_fisher_alpha})
        checks.append({"name": "trigger_detection_noninferior", "value": p_c,
                       "required": f">= {p_b:.3f} - {criteria.regression_noninferiority_margin}",
                       "passed": n > 0 and p_c >= p_b - criteria.regression_noninferiority_margin,
                       "detail": {"baseline_rate_same_trials": p_b}})

    # 3. regression: previously passed scenarios (paired on retest regression trials)
    for sid in regression_set:
        r = retest["regression"].get(sid)
        if not r or not r["detected"].get(cv):
            checks.append({"name": f"regression:{sid}", "value": None, "required": "measured", "passed": False})
            inconclusive = inconclusive or r is None
            continue
        rb = _rate(sum(r["detected"][bv]), len(r["detected"][bv]))
        rc = _rate(sum(r["detected"][cv]), len(r["detected"][cv]))
        checks.append({"name": f"regression:{sid}", "value": rc,
                       "required": f">= {rb:.3f} - {criteria.regression_noninferiority_margin}",
                       "passed": rc >= rb - criteria.regression_noninferiority_margin,
                       "detail": {"baseline_rate_same_trials": rb, "n": len(r["detected"][cv])}})

    # 4. benign traffic: false positives and service impact
    b = retest["benign"]
    fpr = _rate(b["alert_windows"].get(cv, 0), b["n_windows"])
    checks.append({"name": "benign_fpr", "value": fpr, "required": f"<= {criteria.benign_fpr_max}",
                   "passed": b["n_windows"] > 0 and fpr <= criteria.benign_fpr_max,
                   "detail": {"windows": b["n_windows"], "alert_windows": b["alert_windows"].get(cv, 0),
                              "baseline_version_fpr_same_windows": _rate(b["alert_windows"].get(bv, 0), b["n_windows"])}})
    denied = _rate(b["denied"], b["requests"])
    checks.append({"name": "benign_denied_rate", "value": denied, "required": f"<= {criteria.benign_denied_rate_max}",
                   "passed": denied <= criteria.benign_denied_rate_max})
    if criteria.require_service_health:
        checks.append({"name": "service_health", "value": retest["health"], "required": "all healthy",
                       "passed": bool(retest["health"]) and all(retest["health"].values())})
    passed = (not inconclusive) and all(c["passed"] for c in checks)
    return {"passed": passed, "inconclusive": inconclusive, "execution_failure_rate": fail_rate,
            "checks": checks, "criteria_hash": frozen_hash}
