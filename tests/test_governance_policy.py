"""Tests for profile-aware OperatorActionPolicy (v2.52.0 #23)."""

from __future__ import annotations

import pytest

from nodechain.runtime.recovery_classifier import RecoveryState
from nodechain.runtime.recovery_policy import OperatorActionPolicy, RecoveryAction
from nodechain.runtime.governance_profiles import get_builtin_profile


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


@pytest.fixture()
def policy():
    return OperatorActionPolicy()


def test_team_default_preserves_v251_behavior(policy):
    """team-default should admit exactly what v2.51.0 did — no stricter."""
    p = get_builtin_profile("team-default")
    result = policy.authorize(
        RecoveryAction.CANCEL_RUN,
        _snap(recovery_state=RecoveryState.FAILED_RETRYABLE, status="failed"),
        operator_role="operator", governance_profile=p, reason="test",
    )
    assert result.admitted


def test_regulated_requires_reason_for_cancel(policy):
    """regulated profile requires reason for all mutating actions."""
    p = get_builtin_profile("regulated")
    result = policy.authorize(
        RecoveryAction.CANCEL_RUN,
        _snap(recovery_state=RecoveryState.FAILED_RETRYABLE, status="failed"),
        operator_role="operator", governance_profile=p, reason=None,
    )
    assert not result.admitted
    assert result.denial_type == "profile_constraint"
    assert "reason" in result.rejection_reason.lower()


def test_regulated_admits_cancel_with_reason(policy, monkeypatch):
    monkeypatch.setenv("NODECHAIN_OPERATOR_IDENTITY", "alice@example")
    p = get_builtin_profile("regulated")
    result = policy.authorize(
        RecoveryAction.CANCEL_RUN,
        _snap(recovery_state=RecoveryState.FAILED_RETRYABLE, status="failed"),
        operator_role="operator", governance_profile=p, reason="cleanup",
    )
    assert result.admitted


def test_break_glass_admin_only(policy):
    """break-glass: only admin role can use mutating actions."""
    p = get_builtin_profile("break-glass")
    result = policy.authorize(
        RecoveryAction.CANCEL_RUN,
        _snap(recovery_state=RecoveryState.FAILED_RETRYABLE, status="failed"),
        operator_role="operator", governance_profile=p, reason="test",
    )
    assert not result.admitted
    assert result.denial_type == "profile_constraint"


def test_break_glass_admin_admitted(policy, monkeypatch):
    monkeypatch.setenv("NODECHAIN_OPERATOR_IDENTITY", "admin@example")
    monkeypatch.setenv("NODECHAIN_OPERATOR_OVERRIDE", "true")
    p = get_builtin_profile("break-glass")
    result = policy.authorize(
        RecoveryAction.CANCEL_RUN,
        _snap(recovery_state=RecoveryState.FAILED_RETRYABLE, status="failed"),
        operator_role="admin", governance_profile=p, reason="emergency",
        operator_override=True,
    )
    assert result.admitted


def test_operator_cannot_approve_budget_in_any_profile(policy):
    """Hard floor: operator can never approve budget, regardless of profile."""
    for name in ("team-default", "solo-dev", "regulated", "break-glass"):
        p = get_builtin_profile(name)
        result = policy.authorize(
            RecoveryAction.APPROVE_BUDGET_INCREASE,
            _snap(), operator_role="operator",
            governance_profile=p, new_budget=200.0, reason="test",
        )
        assert not result.admitted, f"operator should not approve budget under {name}"


def test_profile_metadata_in_result(policy):
    """AuthorizationResult carries profile id + digest when a profile is used."""
    p = get_builtin_profile("regulated")
    result = policy.authorize(
        RecoveryAction.CANCEL_RUN,
        _snap(recovery_state=RecoveryState.FAILED_RETRYABLE, status="failed"),
        operator_role="operator", governance_profile=p, reason=None,
    )
    assert result.governance_profile_id == "regulated"
    assert result.governance_profile_digest is not None
    assert result.governance_profile_digest.startswith("sha256:")
