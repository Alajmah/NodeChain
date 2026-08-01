"""Authorization invariant tests (v2.51.0 P0-P1).

Executes contracts: invalid roles always fail closed, budget never admitted for
operator, non-retryable retry never without admin+override. Parametrized over
roles × actions where useful.
"""

from __future__ import annotations

import pytest

from nodechain.runtime.recovery_classifier import RecoveryState
from nodechain.runtime.recovery_policy import OperatorActionPolicy, RecoveryAction


def _snap(state=RecoveryState.PAUSED_FOR_BUDGET_APPROVAL, **kw):
    base = {
        "run_id": "r", "status": "paused_for_budget", "recovery_state": state.value,
        "failed_step": 4, "pending_review": None, "side_effects": [],
        "recovery_decisions": [], "last_failure_retryable": True,
        "last_failure_type": "search_api_unavailable", "last_failure_node_id": "n",
        "last_failure_error": "e", "prior_fallback_attempts": [],
        "governed_decision_receipt": None,
        "budget_loop_id": "search", "budget_accumulated_cost": 104.0,
        "budget_previous": 100.0,
    }
    base.update(kw)
    return base


# --- invalid roles always fail closed ----------------------------------------

@pytest.mark.parametrize("role", ["viewer", "superuser", "guest", "root", ""])
def test_invalid_roles_fail_closed_for_all_recovery_actions(role):
    """Every recovery action must refuse an invalid role."""
    policy = OperatorActionPolicy()
    for action in RecoveryAction:
        result = policy.authorize(action, _snap(), operator_role=role)
        assert not result.admitted, f"{action.value} should reject role '{role}'"
        assert result.denial_type == "invalid_role"


# --- budget never admitted for operator --------------------------------------

def test_operator_can_never_increase_budget():
    """operator role can never approve a budget increase, regardless of state."""
    policy = OperatorActionPolicy()
    result = policy.authorize(
        RecoveryAction.APPROVE_BUDGET_INCREASE,
        _snap(), operator_role="operator", new_budget=999.0,
    )
    assert not result.admitted
    assert result.denial_type == "rbac"


# --- non-retryable retry requires admin + override ---------------------------

@pytest.mark.parametrize("role,override,should_admit", [
    ("operator", True, False),
    ("finance", True, False),
    ("admin", False, False),
    ("admin", True, True),
])
def test_non_retryable_retry_requires_admin_and_override(role, override, should_admit):
    """Two-key rule: non-retryable retry admitted ONLY with admin+override."""
    policy = OperatorActionPolicy()
    result = policy.authorize(
        RecoveryAction.RETRY_STEP,
        _snap(state=RecoveryState.FAILED_NON_RETRYABLE, status="failed",
              last_failure_type="model_timeout"),
        operator_role=role, operator_override=override, target_step_id=4,
    )
    if should_admit:
        assert result.admitted, f"{role}+override={override} should admit"
    else:
        assert not result.admitted, f"{role}+override={override} should deny"
        assert result.denial_type in ("override_required", "policy")
