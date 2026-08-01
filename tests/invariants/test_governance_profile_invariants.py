"""Governance profile invariant tests (v2.52.0 #8).

Proves profiles cannot weaken hard floors across all built-in profiles.
"""

from __future__ import annotations

import pytest

from nodechain.runtime.governance_profiles import BUILTIN_PROFILES, validate_profile_hard_floors
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


# --- all built-ins pass hard floor validation --------------------------------

def test_all_builtins_pass_hard_floor_validation():
    for name, p in BUILTIN_PROFILES.items():
        validate_profile_hard_floors(p)  # should not raise


# --- operator cannot approve budget under any profile ------------------------

@pytest.mark.parametrize("profile_name", list(BUILTIN_PROFILES.keys()))
def test_operator_cannot_approve_budget_in_any_profile(profile_name):
    policy = OperatorActionPolicy()
    p = BUILTIN_PROFILES[profile_name]
    result = policy.authorize(
        RecoveryAction.APPROVE_BUDGET_INCREASE,
        _snap(), operator_role="operator",
        governance_profile=p, new_budget=200.0, reason="test",
    )
    assert not result.admitted


# --- non-retryable retry requires admin+override under any profile ------------

@pytest.mark.parametrize("profile_name", ["team-default", "solo-dev", "regulated"])
def test_non_retryable_retry_requires_admin_and_override_in_any_profile(profile_name):
    policy = OperatorActionPolicy()
    p = BUILTIN_PROFILES[profile_name]
    result = policy.authorize(
        RecoveryAction.RETRY_STEP,
        _snap(recovery_state=RecoveryState.FAILED_NON_RETRYABLE, status="failed",
              last_failure_type="model_timeout"),
        operator_role="operator", operator_override=True,
        governance_profile=p, target_step_id=4, reason="test",
    )
    assert not result.admitted


# --- terminal states refuse mutation under any profile -----------------------

@pytest.mark.parametrize("profile_name", ["team-default", "solo-dev", "regulated"])
def test_terminal_states_refuse_mutation_under_any_profile(profile_name):
    policy = OperatorActionPolicy()
    p = BUILTIN_PROFILES[profile_name]
    result = policy.authorize(
        RecoveryAction.CANCEL_RUN,
        _snap(recovery_state=RecoveryState.COMPLETED, status="completed"),
        operator_role="admin", governance_profile=p, reason="test",
    )
    assert not result.admitted


# --- batch dry-run never mutates state under any profile ---------------------

@pytest.mark.parametrize("profile_name", ["team-default", "solo-dev"])
def test_batch_dry_run_never_mutates_under_profile(profile_name, tmp_path):
    from nodechain.core.state import ChainState, StateManager
    from nodechain.runtime.batch_recovery import BatchAction, BatchExecutor, BatchSpec
    from nodechain.runtime.recovery_service import RecoveryService

    sm = StateManager(db_path=tmp_path / "state.db")
    td = tmp_path / "traces"
    td.mkdir()
    sm.save(ChainState(run_id="r1", chain_id="c", status="running"))
    service = RecoveryService(state_manager=sm, trace_dir=str(td))

    spec = BatchSpec(
        actions=[BatchAction(action=RecoveryAction.CANCEL_RUN, run_id="r1", reason="x")],
        governance_profile=profile_name,
    )
    executor = BatchExecutor(service)
    executor.execute(spec, dry_run=True)
    assert sm.load("r1").status == "running"
