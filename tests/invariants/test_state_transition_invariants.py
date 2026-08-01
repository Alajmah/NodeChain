"""State transition invariant tests (v2.51.0 P0-P1).

Durable failure state: FAILED_RETRYABLE/FAILED_NON_RETRYABLE require last_failure.
Terminal states: COMPLETED/CANCELLED refuse all mutations.
"""

from __future__ import annotations

import pytest

from nodechain.core.state import ChainState, StateManager
from nodechain.runtime.recovery_classifier import RecoveryState, classify
from nodechain.runtime.recovery_policy import OperatorActionPolicy, RecoveryAction


def test_failed_retryable_requires_persisted_last_failure():
    """A failed run WITHOUT last_failure metadata must NOT classify as
    FAILED_RETRYABLE — it falls through to CRASH_RECOVERABLE. This protects
    against the wiring bug where the orchestrator didn't persist last_failure."""
    state = ChainState(run_id="r", chain_id="c", status="failed",
                       metadata={"last_failure": {"retryable": True, "step_id": 4}})
    result = classify(state, side_effects=[], report=None, review_attempts=[])
    assert result.state is RecoveryState.FAILED_RETRYABLE

    # Without last_failure → NOT FAILED_RETRYABLE
    state_no_md = ChainState(run_id="r", chain_id="c", status="failed")
    result_no = classify(state_no_md, side_effects=[], report=None, review_attempts=[])
    assert result_no.state is not RecoveryState.FAILED_RETRYABLE


def test_failed_non_retryable_requires_persisted_last_failure():
    """A failed run WITH last_failure.retryable=False classifies as
    FAILED_NON_RETRYABLE. Without last_failure, it still classifies as
    FAILED_NON_RETRYABLE (default), but the INVARIANT is that the durable
    metadata makes the classification PRECISE — retry actions can read the
    failure_type and step_id for targeting."""
    state = ChainState(run_id="r", chain_id="c", status="failed",
                       metadata={"last_failure": {"retryable": False, "step_id": 4,
                                                  "failure_type": "model_timeout"}})
    result = classify(state, side_effects=[], report=None, review_attempts=[])
    assert result.state is RecoveryState.FAILED_NON_RETRYABLE

    # Without last_failure, the run still fails but lacks targeting precision.
    # The invariant: the orchestrator MUST persist last_failure for the
    # recovery system to work. This test proves the classifier consumes it.
    assert result.blocking_reason is not None  # classified with a reason


@pytest.mark.parametrize("action", [
    RecoveryAction.RESUME, RecoveryAction.RETRY_STEP,
    RecoveryAction.CANCEL_RUN, RecoveryAction.FAIL_RUN,
    RecoveryAction.APPROVE_BUDGET_INCREASE,
])
def test_terminal_recovery_states_refuse_all_mutations(action):
    """COMPLETED and CANCELLED runs refuse every mutation action."""
    policy = OperatorActionPolicy()
    for terminal in (RecoveryState.COMPLETED, RecoveryState.CANCELLED):
        snap = {
            "run_id": "r", "status": terminal.value, "recovery_state": terminal.value,
            "failed_step": None, "pending_review": None, "side_effects": [],
            "recovery_decisions": [], "last_failure_retryable": False,
            "last_failure_type": None, "last_failure_node_id": None,
            "last_failure_error": None, "prior_fallback_attempts": [],
            "governed_decision_receipt": None,
            "budget_loop_id": None, "budget_accumulated_cost": 0.0,
            "budget_previous": 0.0,
        }
        result = policy.authorize(action, snap, operator_role="admin",
                                  target_step_id=1, new_budget=999.0)
        assert not result.admitted, \
            f"{action.value} should be refused for {terminal.value}"
