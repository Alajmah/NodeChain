"""Tests for recovery_classifier — derives recovery_state from durable facts (v2.46.0 Phase 1.3).

The classifier is a pure function. recovery_state is NEVER stored on ChainState;
it is re-derived every snapshot from status + side-effect ledger + reconciler
report + review attempts + loop state. These tests pin each branch of the
priority decision tree.
"""

from __future__ import annotations

from nodechain.core.state import ChainState, LoopState
from nodechain.runtime.recovery_classifier import RecoveryState, classify
from nodechain.runtime.trace_reconciler import ReconciliationIssue, ReconciliationReport


def _state(
    *, status: str = "running", step: int = 0, node: str = "",
    completed: dict[int, str] | None = None,
    loops: dict[str, LoopState] | None = None,
    metadata: dict | None = None,
) -> ChainState:
    return ChainState(
        status=status, step=step, current_node=node,
        completed_steps=completed or {},
        loop_state=loops or {},
        metadata=metadata or {},
    )


def _issue(severity: str = "error") -> ReconciliationReport:
    return ReconciliationReport(
        run_id="r",
        issues=[ReconciliationIssue(check="x", severity=severity,
                                    expected="a", actual="b")],
    )


# --- terminal states ---------------------------------------------------------

def test_completed_run_classifies_as_completed() -> None:
    result = classify(_state(status="completed"), side_effects=[], report=None,
                      review_attempts=[])
    assert result.state is RecoveryState.COMPLETED


def test_cancelled_run_classifies_as_cancelled() -> None:
    result = classify(_state(status="cancelled"), side_effects=[], report=None,
                      review_attempts=[])
    assert result.state is RecoveryState.CANCELLED


# --- review pause ------------------------------------------------------------

def test_waiting_for_review_with_pending_request_is_paused_for_human_review() -> None:
    """A run whose status is waiting_for_review and that carries an unresolved
    governed review request is operator-approvable."""
    state = _state(
        status="waiting_for_review", step=3, node="review_node",
        metadata={"governed_review_request": {"request_id": "req-1",
                                              "step_id": 3}},
    )
    result = classify(state, side_effects=[], report=None, review_attempts=[])
    assert result.state is RecoveryState.PAUSED_FOR_HUMAN_REVIEW
    assert "review" in result.blocking_reason.lower()


def test_waiting_for_review_without_pending_request_is_not_paused_for_review() -> None:
    """If the governed request is missing (data drift), we do NOT pretend it is
    a clean human-review pause — it falls through to a recovery-needing state."""
    state = _state(status="waiting_for_review")
    result = classify(state, side_effects=[], report=None, review_attempts=[])
    assert result.state is not RecoveryState.PAUSED_FOR_HUMAN_REVIEW


def test_policy_subject_review_classifies_as_paused_for_policy_approval() -> None:
    """A governed review request whose subject is policy is a policy-approval
    pause, not a human-review pause — they are different operator actions."""
    state = _state(
        status="waiting_for_review", step=2, node="policy_node",
        metadata={"governed_review_request": {
            "request_id": "req-1", "step_id": 2, "subject_type": "policy",
        }},
    )
    result = classify(state, side_effects=[], report=None, review_attempts=[])
    assert result.state is RecoveryState.PAUSED_FOR_POLICY_APPROVAL
    assert "policy" in result.blocking_reason.lower()


def test_non_policy_subject_review_classifies_as_paused_for_human_review() -> None:
    """A governed review request whose subject is not policy (e.g. a node
    output) is a normal human-review pause."""
    state = _state(
        status="waiting_for_review", step=2, node="node_a",
        metadata={"governed_review_request": {
            "request_id": "req-1", "step_id": 2, "subject_type": "node",
        }},
    )
    result = classify(state, side_effects=[], report=None, review_attempts=[])
    assert result.state is RecoveryState.PAUSED_FOR_HUMAN_REVIEW


# --- side-effect / crash states ----------------------------------------------

def test_unknown_side_effect_without_recovery_decision_is_crash_needs_operator() -> None:
    """An unknown side effect the runtime cannot classify autonomously requires
    an operator decision before it can be retried."""
    result = classify(
        _state(status="running"),
        side_effects=[{"status": "unknown", "retryable": True}],
        report=None, review_attempts=[],
    )
    assert result.state is RecoveryState.CRASH_NEEDS_OPERATOR


def test_unknown_side_effect_with_recovery_decision_is_crash_recoverable() -> None:
    """If a recovery decision exists (e.g. safe_to_retry), the run is autonomously
    recoverable but still paused for the runtime to act."""
    result = classify(
        _state(status="running"),
        side_effects=[{"status": "unknown", "retryable": True}],
        report=None,
        recovery_decisions=[{"decision": "safe_to_retry"}],
        review_attempts=[],
    )
    assert result.state is RecoveryState.CRASH_RECOVERABLE


# --- trace health ------------------------------------------------------------

def test_reconciler_errors_make_trace_incomplete() -> None:
    """When trace vs ledger reconciliation raises errors, the run is blocked on
    trace integrity before any recovery action is meaningful."""
    result = classify(
        _state(status="running"), side_effects=[], report=_issue("error"),
        review_attempts=[],
    )
    assert result.state is RecoveryState.TRACE_INCOMPLETE


def test_reconciler_warnings_alone_do_not_block() -> None:
    """Warnings are surfaced but do not by themselves force TRACE_INCOMPLETE."""
    result = classify(
        _state(status="completed"), side_effects=[], report=_issue("warning"),
        review_attempts=[],
    )
    assert result.state is RecoveryState.COMPLETED


# --- loop exhaustion ---------------------------------------------------------

def test_exhausted_loop_classifies_as_loop_exhausted() -> None:
    """A loop that hit its max iterations is blocked on loop policy, not retry."""
    state = _state(
        status="failed",
        loops={"search": LoopState(iteration=5, reason="max_iterations_reached")},
        metadata={"loop_exhausted": "search"},
    )
    result = classify(state, side_effects=[], report=None, review_attempts=[])
    assert result.state is RecoveryState.LOOP_EXHAUSTED


# --- failure retryability ----------------------------------------------------

def test_retryable_failure_is_failed_retryable() -> None:
    """A failed run whose last failure is retryable can be retried."""
    result = classify(
        _state(status="failed", metadata={"last_failure": {"retryable": True}}),
        side_effects=[], report=None, review_attempts=[],
    )
    assert result.state is RecoveryState.FAILED_RETRYABLE


def test_non_retryable_failure_is_failed_non_retryable() -> None:
    """A non-retryable failure cannot be retried without an explicit override."""
    result = classify(
        _state(status="failed", metadata={"last_failure": {"retryable": False}}),
        side_effects=[], report=None, review_attempts=[],
    )
    assert result.state is RecoveryState.FAILED_NON_RETRYABLE


# --- fallback ----------------------------------------------------------------

def test_paused_run_without_signal_is_crash_recoverable_fallback() -> None:
    """A generic pause with no specific signal falls through to the recoverable
    fallback so the operator at least sees the run, rather than it disappearing."""
    result = classify(_state(status="paused"), side_effects=[], report=None,
                      review_attempts=[])
    assert result.state is RecoveryState.CRASH_RECOVERABLE


def test_blocking_reason_is_always_set_when_state_is_not_clean() -> None:
    """Every non-terminal/non-clean state must explain itself — an operator
    should never see a blocking run with a None reason."""
    for kwargs in [
        dict(side_effects=[{"status": "unknown"}], report=None),
        dict(side_effects=[], report=_issue("error")),
    ]:
        result = classify(_state(status="running"), review_attempts=[], **kwargs)
        assert result.blocking_reason, (
            f"missing blocking_reason for {result.state}")
