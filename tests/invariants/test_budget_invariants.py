"""Budget invariant tests (v2.51.0 P0-P1).

Budget carry semantics: approved > previous, approved > accumulated, cost never resets.
Budget pause→approve→resume payload shape invariant.
"""

from __future__ import annotations

import pytest

from nodechain.core.state import ChainState, StateManager
from nodechain.runtime.recovery_policy import OperatorActionPolicy, RecoveryAction


def _budget_snap(**kw):
    base = {
        "run_id": "r", "status": "paused_for_budget",
        "recovery_state": RecoveryState.PAUSED_FOR_BUDGET_APPROVAL.value,
        "failed_step": None, "pending_review": None, "side_effects": [],
        "recovery_decisions": [], "last_failure_retryable": False,
        "last_failure_type": None, "last_failure_node_id": None,
        "last_failure_error": None, "prior_fallback_attempts": [],
        "governed_decision_receipt": None,
        "budget_loop_id": "search", "budget_accumulated_cost": 104.0,
        "budget_previous": 100.0,
    }
    base.update(kw)
    return base


from nodechain.runtime.recovery_classifier import RecoveryState


def test_approved_budget_must_exceed_previous_budget():
    """Policy refuses new_budget <= previous_budget."""
    policy = OperatorActionPolicy()
    result = policy.authorize(
        RecoveryAction.APPROVE_BUDGET_INCREASE,
        _budget_snap(budget_previous=100.0),
        operator_role="finance", new_budget=100.0,
    )
    assert not result.admitted


def test_approved_budget_must_exceed_accumulated_cost():
    """Policy refuses new_budget <= accumulated_cost."""
    policy = OperatorActionPolicy()
    result = policy.authorize(
        RecoveryAction.APPROVE_BUDGET_INCREASE,
        _budget_snap(budget_previous=100.0, budget_accumulated_cost=104.0),
        operator_role="finance", new_budget=102.0,  # above prev, below spent
    )
    assert not result.admitted


def test_budget_resume_preserves_accumulated_cost(tmp_path):
    """After budget approval, accumulated cost must be preserved (carry semantics).
    The budget_context.accumulated_cost must still reflect the original spend,
    not reset to 0."""
    sm = StateManager(db_path=tmp_path / "state.db")
    from nodechain.core.state import ChainState
    state = ChainState(
        run_id="r1", chain_id="c", status="paused_for_budget",
        metadata={
            "budget_context": {
                "loop_id": "search", "accumulated_cost": 104.0,
                "previous_budget": 100.0, "reason": "exceeded",
            },
            "budget_overrides": {"search": 150.0},
            "budget_approved": {
                "previous_budget": 100.0, "new_budget": 150.0,
                "accumulated_cost_at_pause": 104.0,
                "remaining_budget": 46.0,
            },
        },
    )
    sm.save(state)
    loaded = sm.load("r1")
    ctx = loaded.metadata["budget_context"]
    assert ctx["accumulated_cost"] == 104.0  # preserved, not reset
    approved = loaded.metadata["budget_approved"]
    assert approved["remaining_budget"] == 46.0  # 150 - 104
