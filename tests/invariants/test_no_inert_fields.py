"""Invariant tests proving no governance field is decorative (v2.53.0 #4).

Every field in GovernanceProfile must either affect behavior or be marked
reserved. These tests exercise each field with a value that should change
the authorization outcome.
"""

from __future__ import annotations

import pytest

from nodechain.runtime.governance_profiles import (
    GovernanceProfile, RolePolicy, ActionGovernance, BudgetGovernance,
    BatchGovernance, AuditGovernance, OverrideGovernance, ALL_ROLES, ALL_ACTIONS,
)
from nodechain.runtime.recovery_classifier import RecoveryState
from nodechain.runtime.recovery_policy import OperatorActionPolicy, RecoveryAction


def _snap(**kw):
    base = {
        "run_id": "r", "status": "paused_for_budget",
        "recovery_state": RecoveryState.PAUSED_FOR_BUDGET_APPROVAL.value,
        "failed_step": 4, "pending_review": None, "side_effects": [],
        "recovery_decisions": [], "last_failure_retryable": False,
        "last_failure_type": None, "last_failure_node_id": None,
        "last_failure_error": None, "prior_fallback_attempts": [],
        "governed_decision_receipt": None,
        "budget_loop_id": "search", "budget_accumulated_cost": 104.0,
        "budget_previous": 100.0,
    }
    base.update(kw)
    return base


def _profile(**overrides):
    """Build a custom profile for testing, defaulting to team-default shape."""
    defaults = dict(
        id="test", display_name="Test", description="",
        roles=RolePolicy(allowed_roles=ALL_ROLES, default_role="operator"),
        actions={a: ActionGovernance(allowed_roles=ALL_ROLES) for a in ALL_ACTIONS},
        budget=BudgetGovernance(approve_roles=["finance", "admin"]),
        batch=BatchGovernance(),
        audit=AuditGovernance(),
        override=OverrideGovernance(),
    )
    defaults.update(overrides)
    return GovernanceProfile(**defaults)


@pytest.fixture()
def policy():
    return OperatorActionPolicy()


# --- require_override is enforced --------------------------------------------

def test_require_override_blocks_without_override(policy):
    p = _profile(actions={
        "cancel_run": ActionGovernance(allowed_roles=ALL_ROLES, require_override=True),
        **{a: ActionGovernance(allowed_roles=ALL_ROLES) for a in ALL_ACTIONS if a != "cancel_run"}
    })
    result = policy.authorize(
        RecoveryAction.CANCEL_RUN,
        _snap(recovery_state=RecoveryState.FAILED_RETRYABLE, status="failed"),
        operator_role="operator", governance_profile=p, reason="x",
        operator_override=False,
    )
    assert not result.admitted
    assert result.denial_type == "profile_constraint"
    assert "override" in result.rejection_reason.lower()


def test_require_override_allows_with_override(policy):
    p = _profile(actions={
        "cancel_run": ActionGovernance(allowed_roles=ALL_ROLES, require_override=True),
        **{a: ActionGovernance(allowed_roles=ALL_ROLES) for a in ALL_ACTIONS if a != "cancel_run"}
    })
    result = policy.authorize(
        RecoveryAction.CANCEL_RUN,
        _snap(recovery_state=RecoveryState.FAILED_RETRYABLE, status="failed"),
        operator_role="operator", governance_profile=p, reason="x",
        operator_override=True,
    )
    assert result.admitted


# --- budget.approve_roles enforced beyond global RBAC ------------------------

def test_budget_approve_roles_restricts_finance(policy):
    """Profile with approve_roles=['admin'] blocks finance."""
    p = _profile(budget=BudgetGovernance(approve_roles=["admin"]))
    result = policy.authorize(
        RecoveryAction.APPROVE_BUDGET_INCREASE,
        _snap(), operator_role="finance", governance_profile=p,
        new_budget=150.0, reason="x",
    )
    assert not result.admitted
    assert "not allowed" in result.rejection_reason.lower() or "budget" in result.rejection_reason.lower()


# --- budget.max_new_budget_usd enforced --------------------------------------

def test_budget_max_new_budget_cap_enforced(policy):
    p = _profile(budget=BudgetGovernance(approve_roles=["finance"], max_new_budget_usd=120.0))
    result = policy.authorize(
        RecoveryAction.APPROVE_BUDGET_INCREASE,
        _snap(), operator_role="finance", governance_profile=p,
        new_budget=150.0, reason="x",
    )
    assert not result.admitted
    assert "cap" in result.rejection_reason.lower() or "120" in result.rejection_reason


# --- budget.max_increase_multiplier enforced ---------------------------------

def test_budget_max_increase_multiplier_enforced(policy):
    p = _profile(budget=BudgetGovernance(approve_roles=["finance"], max_increase_multiplier=1.2))
    # 150 > 100 * 1.2 = 120
    result = policy.authorize(
        RecoveryAction.APPROVE_BUDGET_INCREASE,
        _snap(), operator_role="finance", governance_profile=p,
        new_budget=150.0, reason="x",
    )
    assert not result.admitted
    assert "multiplier" in result.rejection_reason.lower()


# --- audit.require_reason_for_mutations enforced -----------------------------

def test_require_reason_for_mutations_enforced(policy):
    p = _profile(audit=AuditGovernance(require_reason_for_mutations=True))
    result = policy.authorize(
        RecoveryAction.CANCEL_RUN,
        _snap(recovery_state=RecoveryState.FAILED_RETRYABLE, status="failed"),
        operator_role="operator", governance_profile=p, reason=None,
    )
    assert not result.admitted
    assert "reason" in result.rejection_reason.lower()
