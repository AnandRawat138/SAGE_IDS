"""Coordinator state machine definition: states, allowed transitions and required roles."""
from __future__ import annotations

SYSTEM, OPERATOR = "system", "operator"

TERMINAL = {"not_relevant", "weakness_not_confirmed", "accepted", "rejected", "inconclusive",
            "failed", "cancelled", "timed_out"}
RUNNING = {"baseline_test_running", "retest_running"}

# (from, to) -> roles allowed to perform it
TRANSITIONS: dict[tuple[str, str], set[str]] = {
    ("finding_received", "relevance_checked"): {SYSTEM},
    ("finding_received", "not_relevant"): {SYSTEM},
    ("relevance_checked", "scenario_pending_review"): {SYSTEM},
    ("scenario_pending_review", "scenario_approved"): {OPERATOR},
    ("scenario_pending_review", "rejected"): {OPERATOR},
    ("scenario_approved", "baseline_test_running"): {SYSTEM},
    ("baseline_test_running", "baseline_test_completed"): {SYSTEM},
    ("baseline_test_running", "scenario_approved"): {SYSTEM},          # bounded retry
    ("baseline_test_completed", "remediation_proposed"): {SYSTEM},
    ("baseline_test_completed", "weakness_not_confirmed"): {SYSTEM},
    ("baseline_test_completed", "inconclusive"): {SYSTEM},
    ("remediation_proposed", "candidate_prepared"): {OPERATOR},
    ("remediation_proposed", "rejected"): {OPERATOR},
    ("candidate_prepared", "retest_running"): {SYSTEM},
    ("retest_running", "acceptance_pending"): {SYSTEM},
    ("retest_running", "remediation_proposed"): {SYSTEM},              # criteria failed, cycles remain
    ("retest_running", "rejected"): {SYSTEM},                          # criteria failed, no cycles left
    ("retest_running", "inconclusive"): {SYSTEM},
    ("retest_running", "candidate_prepared"): {SYSTEM},                # bounded retry
    ("acceptance_pending", "accepted"): {OPERATOR},
    ("acceptance_pending", "rejected"): {OPERATOR},
    ("acceptance_pending", "remediation_proposed"): {OPERATOR},        # ask for another candidate
}
NON_TERMINAL = {f for f, _ in TRANSITIONS} | {t for _, t in TRANSITIONS if t not in TERMINAL}
for _st in NON_TERMINAL:
    TRANSITIONS.setdefault((_st, "cancelled"), {OPERATOR})
    TRANSITIONS.setdefault((_st, "failed"), {SYSTEM})
for _st in RUNNING:
    TRANSITIONS[(_st, "timed_out")] = {SYSTEM}
    TRANSITIONS[(_st, "cancelled")] = {OPERATOR, SYSTEM}   # system honours an operator's cancel request

ALL_STATES = sorted({s for pair in TRANSITIONS for s in pair})


class TransitionError(RuntimeError):
    pass


def check(from_state: str, to_state: str, role: str) -> None:
    roles = TRANSITIONS.get((from_state, to_state))
    if roles is None:
        raise TransitionError(f"transition {from_state} -> {to_state} is not allowed")
    if role not in roles:
        raise TransitionError(f"role {role!r} may not perform {from_state} -> {to_state} (requires {sorted(roles)})")
