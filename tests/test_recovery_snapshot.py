"""Tests for RecoverySnapshot — the read-only operator view of a run.

Phase 1, step 1 of v2.46.0 Operator Recovery Console.

RecoverySnapshot is a pure data model: derived from durable state, never
mutated by the operator, and never persisted as the source of truth (the
Chain Trace remains authoritative). These tests pin its shape.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from nodechain.runtime.recovery_snapshot import RecoverySnapshot


def test_snapshot_has_required_operator_facing_fields() -> None:
    """A snapshot carries exactly the fields an operator needs to understand
    why a run stopped and what they can do about it."""
    snapshot = RecoverySnapshot(
        run_id="run-1",
        chain_id="chain-1",
        status="waiting_for_review",
        recovery_state="PAUSED_FOR_HUMAN_REVIEW",
        current_node="review_node",
        current_step=3,
        last_successful_step=2,
        failed_step=None,
        blocking_reason="human review required",
        available_actions=["approve_review", "reject_review", "request_revision"],
        loop_counters={},
        retry_counters={},
        pending_review={"step_id": 3},
        pending_policy_decision=None,
        trace_complete=True,
        trace_warnings=[],
        state_revision=5,
        last_update_time="2026-06-27T00:00:00+00:00",
    )

    assert snapshot.run_id == "run-1"
    assert snapshot.recovery_state == "PAUSED_FOR_HUMAN_REVIEW"
    assert snapshot.blocking_reason == "human review required"
    assert snapshot.available_actions == [
        "approve_review", "reject_review", "request_revision",
    ]
    assert snapshot.last_update_time == "2026-06-27T00:00:00+00:00"


def test_snapshot_defaults_are_empty_not_none() -> None:
    """Optional collections default to empty containers, not None, so renderers
    can iterate without None-checks. Nullable scalars stay None."""
    snapshot = RecoverySnapshot(
        run_id="run-1",
        chain_id="chain-1",
        status="running",
        recovery_state="CRASH_RECOVERABLE",
    )

    assert snapshot.current_node is None
    assert snapshot.current_step is None
    assert snapshot.last_successful_step is None
    assert snapshot.failed_step is None
    assert snapshot.blocking_reason is None
    assert snapshot.available_actions == []
    assert snapshot.loop_counters == {}
    assert snapshot.retry_counters == {}
    assert snapshot.pending_review is None
    assert snapshot.pending_policy_decision is None
    assert snapshot.trace_complete is True  # optimistic default
    assert snapshot.trace_warnings == []
    assert snapshot.state_revision == 0


def test_snapshot_rejects_unknown_fields() -> None:
    """RecoverySnapshot follows the project's extra='forbid' discipline so a
    drift in the model is caught rather than silently swallowed."""
    with pytest.raises(ValidationError):
        RecoverySnapshot(  # type: ignore[call-arg]
            run_id="run-1",
            chain_id="chain-1",
            status="running",
            recovery_state="CRASH_RECOVERABLE",
            surprise_field="should not be allowed",
        )


def test_snapshot_is_json_serializable_for_report_export() -> None:
    """The export-report action serializes a snapshot to JSON. The model must
    round-trip through model_dump_json / model_validate_json without loss."""
    snapshot = RecoverySnapshot(
        run_id="run-1",
        chain_id="chain-1",
        status="failed",
        recovery_state="FAILED_RETRYABLE",
        current_node="flaky_node",
        current_step=4,
        last_successful_step=3,
        failed_step=4,
        blocking_reason="node raised RetryableError",
        available_actions=["retry_step", "cancel_run"],
        loop_counters={"search": 2},
        retry_counters={"flaky_node": 1},
        trace_complete=False,
        trace_warnings=["missing NODE_COMPLETED for step 4"],
        state_revision=7,
        last_update_time="2026-06-27T01:00:00+00:00",
    )

    blob = snapshot.model_dump_json()
    restored = RecoverySnapshot.model_validate_json(blob)

    assert restored == snapshot


def test_snapshot_is_frozen() -> None:
    """RecoverySnapshot is a derived view; mutating it after assembly would
    let the operator (or a bug) silently rewrite the operator-facing picture.
    Frozen=True makes assignment raise."""
    snapshot = RecoverySnapshot(
        run_id="run-1", chain_id="chain-1", status="running",
        recovery_state="CRASH_RECOVERABLE",
    )
    with pytest.raises(ValidationError):
        snapshot.status = "completed"  # type: ignore[misc]
