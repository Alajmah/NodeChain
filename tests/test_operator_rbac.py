"""Tests for operator RBAC — role-based action authorization (v2.49.0).

The OperatorActionPolicy now checks WHO the operator is (role) before checking
WHAT the action+state allows. Authorization order:
  1. Parse/validate role (invalid → deny)
  2. RBAC matrix check (role not in action's allowed roles → deny)
  3. Override requirements (non-retryable retry needs admin + override env)
  4. Existing action + recovery-state policy
  5. Audit decision for both allow and deny

denial_type distinguishes: rbac, policy, invalid_role, override_required.
"""

from __future__ import annotations

import pytest

from nodechain.runtime.recovery_classifier import RecoveryState
from nodechain.runtime.recovery_policy import (
    AuthorizationResult,
    OperatorActionPolicy,
    RecoveryAction,
)


def _snapshot(
    *, recovery_state=RecoveryState.PAUSED_FOR_BUDGET_APPROVAL,
    status="paused_for_budget", failed_step=4,
    failure_type="search_api_unavailable",
) -> dict:
    return {
        "run_id": "r", "status": status, "recovery_state": recovery_state.value,
        "failed_step": failed_step, "pending_review": None,
        "side_effects": [], "recovery_decisions": [],
        "last_failure_retryable": True,
        "last_failure_type": failure_type,
        "last_failure_node_id": "n", "last_failure_error": "e",
        "prior_fallback_attempts": [], "governed_decision_receipt": None,
        "budget_loop_id": "search", "budget_accumulated_cost": 104.0,
        "budget_previous": 100.0,
    }


@pytest.fixture()
def policy() -> OperatorActionPolicy:
    return OperatorActionPolicy()


# --- role validation ---------------------------------------------------------

def test_invalid_role_denied(policy) -> None:
    """An unrecognized role fails closed — denied with denial_type=invalid_role."""
    result = policy.authorize(
        RecoveryAction.EXPORT_REPORT, _snapshot(),
        operator_role="superuser",
    )
    assert not result.admitted
    assert result.denial_type == "invalid_role"


def test_valid_roles_accepted(policy) -> None:
    """operator, finance, admin are all valid roles."""
    for role in ("operator", "finance", "admin"):
        result = policy.authorize(
            RecoveryAction.EXPORT_REPORT, _snapshot(),
            operator_role=role,
        )
        assert result.admitted, f"role {role} should be valid"


# --- RBAC matrix: budget increase restricted --------------------------------

def test_operator_denied_budget_increase(policy) -> None:
    """operator role cannot approve budget increases."""
    result = policy.authorize(
        RecoveryAction.APPROVE_BUDGET_INCREASE, _snapshot(),
        operator_role="operator", new_budget=150.0,
    )
    assert not result.admitted
    assert result.denial_type == "rbac"
    assert "finance" in result.rejection_reason.lower() or "admin" in result.rejection_reason.lower()


def test_finance_allowed_budget_increase(policy) -> None:
    """finance role can approve budget increases."""
    result = policy.authorize(
        RecoveryAction.APPROVE_BUDGET_INCREASE, _snapshot(),
        operator_role="finance", new_budget=150.0,
    )
    assert result.admitted


def test_admin_allowed_budget_increase(policy) -> None:
    result = policy.authorize(
        RecoveryAction.APPROVE_BUDGET_INCREASE, _snapshot(),
        operator_role="admin", new_budget=150.0,
    )
    assert result.admitted


# --- RBAC matrix: all other actions operator-accessible ---------------------

def test_operator_allowed_cancel(policy) -> None:
    """operator can cancel/fail/resume/retry/review actions."""
    snap = _snapshot(recovery_state=RecoveryState.FAILED_RETRYABLE, status="failed")
    result = policy.authorize(
        RecoveryAction.CANCEL_RUN, snap,
        operator_role="operator",
    )
    assert result.admitted


def test_operator_allowed_retry(policy) -> None:
    snap = _snapshot(recovery_state=RecoveryState.FAILED_RETRYABLE, status="failed")
    result = policy.authorize(
        RecoveryAction.RETRY_STEP, snap,
        operator_role="operator", target_step_id=4,
    )
    assert result.admitted


# --- two-key override: admin + override env ----------------------------------

def test_operator_with_override_denied_for_non_retryable(policy) -> None:
    """operator + override=true is NOT enough for non-retryable retry.
    Override requires admin role too."""
    snap = _snapshot(
        recovery_state=RecoveryState.FAILED_NON_RETRYABLE, status="failed",
        failure_type="model_timeout",
    )
    result = policy.authorize(
        RecoveryAction.RETRY_STEP, snap,
        operator_role="operator", target_step_id=4, operator_override=True,
    )
    assert not result.admitted
    assert result.denial_type == "override_required"


def test_finance_with_override_denied_for_non_retryable(policy) -> None:
    """finance + override=true is NOT enough for non-retryable retry."""
    snap = _snapshot(
        recovery_state=RecoveryState.FAILED_NON_RETRYABLE, status="failed",
        failure_type="model_timeout",
    )
    result = policy.authorize(
        RecoveryAction.RETRY_STEP, snap,
        operator_role="finance", target_step_id=4, operator_override=True,
    )
    assert not result.admitted
    assert result.denial_type == "override_required"


def test_admin_without_override_denied_for_non_retryable(policy) -> None:
    """admin + override=false is NOT enough for non-retryable retry."""
    snap = _snapshot(
        recovery_state=RecoveryState.FAILED_NON_RETRYABLE, status="failed",
        failure_type="model_timeout",
    )
    result = policy.authorize(
        RecoveryAction.RETRY_STEP, snap,
        operator_role="admin", target_step_id=4, operator_override=False,
    )
    assert not result.admitted
    assert result.denial_type == "override_required"


def test_admin_with_override_allowed_for_non_retryable(policy) -> None:
    """admin + override=true admits non-retryable retry (if state policy agrees)."""
    snap = _snapshot(
        recovery_state=RecoveryState.FAILED_NON_RETRYABLE, status="failed",
        failure_type="model_timeout",
    )
    result = policy.authorize(
        RecoveryAction.RETRY_STEP, snap,
        operator_role="admin", target_step_id=4, operator_override=True,
    )
    assert result.admitted


# --- denial_type for existing policy refusals --------------------------------

def test_policy_denial_has_policy_denial_type(policy) -> None:
    """When RBAC passes but action+state policy refuses, denial_type=policy."""
    result = policy.authorize(
        RecoveryAction.RESUME,
        _snapshot(recovery_state=RecoveryState.COMPLETED, status="completed"),
        operator_role="operator",
    )
    assert not result.admitted
    assert result.denial_type == "policy"


# --- default role is operator ------------------------------------------------

def test_default_role_is_operator(policy, monkeypatch) -> None:
    """Without --role or NODECHAIN_OPERATOR_ROLE, the role defaults to operator.
    This means budget increase is denied by default."""
    monkeypatch.delenv("NODECHAIN_OPERATOR_ROLE", raising=False)
    result = policy.authorize(
        RecoveryAction.APPROVE_BUDGET_INCREASE, _snapshot(),
        new_budget=150.0,
    )
    assert not result.admitted
    assert result.denial_type == "rbac"
