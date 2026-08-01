"""Tests for OperatorActionPolicy — fail-closed authorization (v2.46.0 Phase 3.1).

Recovery is a high-authority surface: an operator can resume, retry, approve,
cancel, or fail a run. Every action must be explicitly authorized against the
run's recovery state and durable facts before it is admitted. Fail-closed:
when no rule matches, the action is REFUSED.

Carry-forward constraint from Phase 2 review: before authorizing resume/retry
after crash recovery, EACH unresolved unknown side-effect row must have its own
recovery decision (matched by idempotency_key). A recovery decision on the run
as a whole is NOT sufficient — that was the classifier's coarse view.
"""

from __future__ import annotations

import pytest

from nodechain.core.state import ChainState
from nodechain.runtime.recovery_classifier import RecoveryState
from nodechain.runtime.recovery_policy import (
    AuthorizationResult,
    OperatorActionPolicy,
    RecoveryAction,
)


def _snapshot(
    *, recovery_state: RecoveryState, run_id: str = "r", status: str = "running",
    failed_step: int | None = None, pending_review: dict | None = None,
    side_effects: list[dict] | None = None,
    recovery_decisions: list[dict] | None = None,
    last_failure_retryable: bool | None = None,
    governed_decision_receipt: dict | None = None,
) -> dict:
    """A minimal snapshot-like dict the policy consumes (decoupled from the
    Pydantic model so tests are not brittle to unrelated field changes)."""
    return {
        "run_id": run_id,
        "status": status,
        "recovery_state": recovery_state.value,
        "failed_step": failed_step,
        "pending_review": pending_review,
        "side_effects": side_effects or [],
        "recovery_decisions": recovery_decisions or [],
        "last_failure_retryable": last_failure_retryable,
        "governed_decision_receipt": governed_decision_receipt,
    }


@pytest.fixture()
def policy() -> OperatorActionPolicy:
    return OperatorActionPolicy()


# --- enum -------------------------------------------------------------------

def test_recovery_action_enum_has_twelve_values() -> None:
    assert {a.value for a in RecoveryAction} == {
        "resume", "retry_step", "approve_review", "reject_review",
        "request_revision", "route_fallback", "cancel_run", "fail_run",
        "export_report", "approve_budget_increase", "resolve_side_effect",
        "execute_retry_authorized",  # v3.5.0
    }


# --- export_report is always admitted (read-only) ----------------------------

def test_export_report_always_admitted_regardless_of_state(policy) -> None:
    for state in RecoveryState:
        result = policy.authorize(RecoveryAction.EXPORT_REPORT, _snapshot(recovery_state=state))
        assert result.admitted, f"export_report must be admitted for {state}"


# --- terminal runs refuse mutations -----------------------------------------

def test_completed_run_refuses_resume(policy) -> None:
    result = policy.authorize(
        RecoveryAction.RESUME,
        _snapshot(recovery_state=RecoveryState.COMPLETED, status="completed"),
    )
    assert not result.admitted
    assert result.rejection_reason


def test_cancelled_run_refuses_cancel_again(policy) -> None:
    result = policy.authorize(
        RecoveryAction.CANCEL_RUN,
        _snapshot(recovery_state=RecoveryState.CANCELLED, status="cancelled"),
    )
    assert not result.admitted


# --- review actions ---------------------------------------------------------

def test_approve_admitted_for_pending_human_review(policy) -> None:
    result = policy.authorize(
        RecoveryAction.APPROVE_REVIEW,
        _snapshot(
            recovery_state=RecoveryState.PAUSED_FOR_HUMAN_REVIEW,
            pending_review={"request_id": "req-1", "step_id": 3},
        ),
    )
    assert result.admitted


def test_approve_refused_when_no_pending_review(policy) -> None:
    """Cannot approve a review that doesn't exist — prevents fabricating a
    decision out of thin air."""
    result = policy.authorize(
        RecoveryAction.APPROVE_REVIEW,
        _snapshot(recovery_state=RecoveryState.PAUSED_FOR_HUMAN_REVIEW,
                  pending_review=None),
    )
    assert not result.admitted


def test_approve_refused_for_already_decided_review(policy) -> None:
    """A review with a committed receipt cannot be approved again — double
    decision is refused (protects against replay). The committed receipt lives
    in state.metadata['governed_decision_receipt'], not on the pending_review
    dict (the existing review system stores it there)."""
    result = policy.authorize(
        RecoveryAction.APPROVE_REVIEW,
        _snapshot(
            recovery_state=RecoveryState.PAUSED_FOR_HUMAN_REVIEW,
            pending_review={"request_id": "req-1", "step_id": 3},
            governed_decision_receipt={"receipt_id": "rc-1", "decision": "approve"},
        ),
    )
    assert not result.admitted
    assert "already" in result.rejection_reason.lower() or "committed" in result.rejection_reason.lower() or "receipt" in result.rejection_reason.lower()


def test_approve_admitted_when_no_committed_receipt(policy) -> None:
    """A pending review with NO committed receipt on metadata is approvable."""
    result = policy.authorize(
        RecoveryAction.APPROVE_REVIEW,
        _snapshot(
            recovery_state=RecoveryState.PAUSED_FOR_HUMAN_REVIEW,
            pending_review={"request_id": "req-1", "step_id": 3},
            governed_decision_receipt=None,
        ),
    )
    assert result.admitted


def test_reject_and_revise_mirror_approve_gating(policy) -> None:
    """Reject and request_revision follow the same pending-review gating."""
    snap = _snapshot(recovery_state=RecoveryState.PAUSED_FOR_HUMAN_REVIEW,
                     pending_review={"request_id": "r", "step_id": 1})
    assert policy.authorize(RecoveryAction.REJECT_REVIEW, snap).admitted
    assert policy.authorize(RecoveryAction.REQUEST_REVISION, snap).admitted


# --- retry ------------------------------------------------------------------

def test_retry_admitted_for_retryable_failure(policy) -> None:
    result = policy.authorize(
        RecoveryAction.RETRY_STEP,
        _snapshot(
            recovery_state=RecoveryState.FAILED_RETRYABLE, failed_step=4,
            last_failure_retryable=True,
        ),
        target_step_id=4,
    )
    assert result.admitted


def test_retry_non_retryable_refused_without_override(policy) -> None:
    """A non-retryable failure cannot be retried unless an explicit override
    policy admits it (NODECHAIN_OPERATOR_OVERRIDE)."""
    result = policy.authorize(
        RecoveryAction.RETRY_STEP,
        _snapshot(
            recovery_state=RecoveryState.FAILED_NON_RETRYABLE, failed_step=4,
            last_failure_retryable=False,
        ),
        target_step_id=4,
    )
    assert not result.admitted
    assert "override" in result.rejection_reason.lower() or "non-retryable" in result.rejection_reason.lower()


def test_retry_non_retryable_admitted_with_override(policy) -> None:
    """With the explicit override, a non-retryable failure can be retried —
    the override is the operator's acknowledged escalation path."""
    result = policy.authorize(
        RecoveryAction.RETRY_STEP,
        _snapshot(
            recovery_state=RecoveryState.FAILED_NON_RETRYABLE, failed_step=4,
            last_failure_retryable=False,
        ),
        target_step_id=4,
        operator_override=True,
        operator_role="admin",  # v2.49.0: override requires admin role
    )
    assert result.admitted


def test_retry_must_target_a_step(policy) -> None:
    """Retry without a target step_id is refused — protects the looped-node
    case (retry must be step/invocation-precise, never node_id-only)."""
    result = policy.authorize(
        RecoveryAction.RETRY_STEP,
        _snapshot(recovery_state=RecoveryState.FAILED_RETRYABLE, failed_step=4,
                  last_failure_retryable=True),
        target_step_id=None,
    )
    assert not result.admitted
    assert "step" in result.rejection_reason.lower()


# --- CARRY-FORWARD: per-effect matching for resume/retry after crash ---------

def test_resume_after_crash_refused_when_unknown_effect_has_no_decision(policy) -> None:
    """Carry-forward constraint: an unresolved unknown side-effect WITHOUT its
    own recovery decision blocks resume. A decision elsewhere on the run does
    NOT cover it — matching is per idempotency_key."""
    result = policy.authorize(
        RecoveryAction.RESUME,
        _snapshot(
            recovery_state=RecoveryState.CRASH_RECOVERABLE,
            side_effects=[
                {"idempotency_key": "k-A", "status": "unknown"},
            ],
            recovery_decisions=[
                # A decision for a DIFFERENT effect — must not cover k-A.
                {"idempotency_key": "k-B", "decision": "safe_to_retry"},
            ],
        ),
    )
    assert not result.admitted
    assert "k-A" in result.rejection_reason or "unresolved" in result.rejection_reason.lower()


def test_resume_after_crash_admitted_when_every_unknown_effect_is_decided(policy) -> None:
    """Resume is admitted only when EACH unknown effect has a matching decision
    on its own idempotency_key."""
    result = policy.authorize(
        RecoveryAction.RESUME,
        _snapshot(
            recovery_state=RecoveryState.CRASH_RECOVERABLE,
            side_effects=[
                {"idempotency_key": "k-A", "status": "unknown"},
                {"idempotency_key": "k-B", "status": "unknown"},
            ],
            recovery_decisions=[
                {"idempotency_key": "k-A", "decision": "safe_to_retry"},
                {"idempotency_key": "k-B", "decision": "compensated"},
            ],
        ),
    )
    assert result.admitted


def test_resume_after_crash_refused_if_any_unknown_effect_undecided(policy) -> None:
    """Even one undecided unknown effect blocks resume — partial coverage is
    not acceptable for a high-authority resume."""
    result = policy.authorize(
        RecoveryAction.RESUME,
        _snapshot(
            recovery_state=RecoveryState.CRASH_RECOVERABLE,
            side_effects=[
                {"idempotency_key": "k-A", "status": "unknown"},
                {"idempotency_key": "k-B", "status": "unknown"},
            ],
            recovery_decisions=[
                {"idempotency_key": "k-A", "decision": "safe_to_retry"},
                # k-B has no decision
            ],
        ),
    )
    assert not result.admitted
    assert "k-B" in result.rejection_reason


# --- fail-closed default ----------------------------------------------------

def test_unknown_state_action_combination_refused(policy) -> None:
    """Fail-closed: any (state, action) pair not explicitly allowed is refused.
    E.g. resume on a loop-exhausted run makes no sense and must be refused."""
    result = policy.authorize(
        RecoveryAction.RESUME,
        _snapshot(recovery_state=RecoveryState.LOOP_EXHAUSTED),
    )
    assert not result.admitted


def test_route_fallback_refused_without_failure_type(policy) -> None:
    """ROUTE_FALLBACK without a durable failure_type is refused — the policy
    does not classify free-text errors. (#13: was previously refused as
    'not implemented'; now implemented for fallback-capable types only.)"""
    result = policy.authorize(
        RecoveryAction.ROUTE_FALLBACK,
        _snapshot(recovery_state=RecoveryState.FAILED_RETRYABLE,
                  last_failure_retryable=True),
        target_step_id=4,
    )
    assert not result.admitted
    assert "failure_type" in result.rejection_reason.lower()


# --- non-terminal cancel/fail -----------------------------------------------

def test_cancel_admitted_for_non_terminal_run(policy) -> None:
    result = policy.authorize(
        RecoveryAction.CANCEL_RUN,
        _snapshot(recovery_state=RecoveryState.FAILED_RETRYABLE, status="failed"),
    )
    assert result.admitted


def test_fail_admitted_for_non_terminal_run(policy) -> None:
    result = policy.authorize(
        RecoveryAction.FAIL_RUN,
        _snapshot(recovery_state=RecoveryState.PAUSED_FOR_HUMAN_REVIEW,
                  status="waiting_for_review"),
    )
    assert result.admitted
