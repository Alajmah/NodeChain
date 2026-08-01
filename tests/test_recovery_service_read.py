"""Tests for RecoveryService read half (v2.46.0 Phase 1.4).

RecoveryService is the runtime-safe action layer. These tests pin its read-only
methods — list_runs, build_snapshot, build_trace_health — which assemble a
RecoverySnapshot from durable state without mutating anything. The snapshot
must never touch state revision.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nodechain.core.state import ChainState, StateManager
from nodechain.runtime.recovery_classifier import RecoveryState
from nodechain.runtime.recovery_service import RecoveryService
from nodechain.runtime.recovery_snapshot import RecoverySnapshot


@pytest.fixture()
def sm(tmp_path) -> StateManager:
    return StateManager(db_path=tmp_path / "state.db")


@pytest.fixture()
def trace_dir(tmp_path) -> Path:
    d = tmp_path / "traces"
    d.mkdir()
    return d


@pytest.fixture()
def service(sm: StateManager, trace_dir: Path) -> RecoveryService:
    return RecoveryService(state_manager=sm, trace_dir=str(trace_dir))


def _save_run(sm: StateManager, run_id: str, **kw) -> ChainState:
    state = ChainState(run_id=run_id, chain_id="c", **kw)
    sm.save(state)
    return state


def _write_trace(trace_dir: Path, run_id: str, *, events: list | None = None,
                 chain_id: str = "c", run_status: str = "completed") -> None:
    """Write a minimal valid trace JSON for a run."""
    payload = {
        "chain_id": chain_id,
        "run_id": run_id,
        "started_at": "2026-06-27T00:00:00+00:00",
        "completed_at": "2026-06-27T00:01:00+00:00",
        "status": run_status,
        "events": events or [],
    }
    (trace_dir / f"{run_id}.json").write_text(json.dumps(payload))


# --- list_runs ---------------------------------------------------------------

def test_list_runs_delegates_to_state_manager(service: RecoveryService,
                                              sm: StateManager) -> None:
    _save_run(sm, "run-1", status="completed")
    _save_run(sm, "run-2", status="failed")

    summaries = service.list_runs()

    assert {s.run_id for s in summaries} == {"run-1", "run-2"}


# --- build_snapshot ----------------------------------------------------------

def test_build_snapshot_returns_none_for_unknown_run(service: RecoveryService) -> None:
    assert service.build_snapshot("does-not-exist") is None


def test_build_snapshot_assembles_durable_facts_into_classification(
    service: RecoveryService, sm: StateManager,
) -> None:
    """A completed run with a clean trace assembles into a COMPLETED snapshot."""
    _save_run(sm, "run-1", status="completed", step=2, current_node="end")
    _write_trace(__import__("pathlib").Path(service.trace_dir), "run-1")

    snapshot = service.build_snapshot("run-1")

    assert snapshot is not None
    assert snapshot.run_id == "run-1"
    assert snapshot.status == "completed"
    assert snapshot.recovery_state == RecoveryState.COMPLETED.value
    assert snapshot.current_step == 2
    assert snapshot.current_node == "end"
    assert snapshot.state_revision >= 1
    assert snapshot.last_update_time  # populated from chain_states.updated_at


def test_snapshot_last_update_time_is_db_persistence_timestamp(
    service: RecoveryService, sm: StateManager,
) -> None:
    """last_update_time must be the chain_states.updated_at DB field (when the
    state was last persisted), NOT a lifecycle time like started_at/completed_at.

    These diverge when a run is saved multiple times: the lifecycle started_at
    stays fixed, but updated_at advances on each save. Pinning to the DB field
    guarantees the operator sees true persistence freshness."""
    import time
    _save_run(sm, "run-1", status="running", started_at="2020-01-01T00:00:00+00:00")
    first = service.build_snapshot("run-1").last_update_time
    # Save again later — updated_at must advance, started_at must not.
    time.sleep(1.05)
    state = sm.load("run-1")
    state.status = "paused"
    sm.save(state)
    second = service.build_snapshot("run-1").last_update_time

    assert first != second  # DB timestamp advanced on re-save
    assert second != "2020-01-01T00:00:00+00:00"  # not the stale lifecycle time
    # And it must equal what list_all_runs reports (the canonical DB read).
    [summary] = service.list_runs()
    assert summary.updated_at == service.build_snapshot("run-1").last_update_time


def test_build_snapshot_is_read_only(
    service: RecoveryService, sm: StateManager,
) -> None:
    """Building a snapshot must not change state revision — the console is a
    read surface, not a write surface."""
    _save_run(sm, "run-1", status="completed")
    _write_trace(__import__("pathlib").Path(service.trace_dir), "run-1")
    before = sm.load("run-1").revision

    service.build_snapshot("run-1")

    after = sm.load("run-1").revision
    assert before == after


def test_build_snapshot_records_unknown_side_effects_as_crash(
    service: RecoveryService, sm: StateManager,
) -> None:
    """An unknown side effect flows through the classifier into the snapshot's
    recovery_state and blocking_reason."""
    import sqlite3
    _save_run(sm, "run-1", status="running")
    with sqlite3.connect(sm.db_path) as conn:
        conn.execute(
            "INSERT INTO side_effect_ledger "
            "(run_id, step_id, node_id, branch_name, side_effect_type, "
            " idempotency_key, status, request_hash, response_hash, "
            " external_reference, retryable, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("run-1", 1, "n", None, "http", "k-1", "unknown", "rh", "rh",
             None, 1, "2026-06-27T00:00:00+00:00"),
        )

    snapshot = service.build_snapshot("run-1")

    assert snapshot is not None
    assert snapshot.recovery_state == RecoveryState.CRASH_NEEDS_OPERATOR.value
    assert snapshot.blocking_reason


def test_build_snapshot_pending_review_request_surfaces_in_snapshot(
    service: RecoveryService, sm: StateManager,
) -> None:
    """A waiting_for_review run carries the pending governed request into the
    snapshot so the operator can see what to approve."""
    _save_run(
        sm, "run-1", status="waiting_for_review", step=3, current_node="rev",
        metadata={"governed_review_request": {"request_id": "req-1", "step_id": 3}},
    )
    _write_trace(__import__("pathlib").Path(service.trace_dir), "run-1")

    snapshot = service.build_snapshot("run-1")

    assert snapshot is not None
    assert snapshot.recovery_state == RecoveryState.PAUSED_FOR_HUMAN_REVIEW.value
    assert snapshot.pending_review == {"request_id": "req-1", "step_id": 3}


# --- build_trace_health ------------------------------------------------------

def test_build_trace_health_returns_report_for_run_with_trace(
    service: RecoveryService, sm: StateManager, trace_dir: Path,
) -> None:
    _save_run(sm, "run-1", status="completed")
    _write_trace(trace_dir, "run-1")

    report = service.build_trace_health("run-1")

    assert report.run_id == "run-1"
    assert report.is_clean  # no ledger facts to contradict


def test_build_trace_health_missing_trace_is_degraded(
    service: RecoveryService, sm: StateManager,
) -> None:
    """A crashed run may have no trace file. The service surfaces this as a
    degraded report (with a warning), not an exception."""
    _save_run(sm, "run-1", status="running")

    report = service.build_trace_health("run-1")

    assert report.run_id == "run-1"
    assert report.warnings  # missing trace flagged as a warning
    assert any("trace" in w.check.lower() or "trace" in w.actual.lower()
               for w in report.issues)


def test_snapshot_trace_complete_is_false_when_trace_missing(
    service: RecoveryService, sm: StateManager,
) -> None:
    """trace_complete must reflect "no errors AND no warnings". A missing trace
    produces a warning, so trace_complete must be False — is_clean alone is not
    enough because is_clean means "no errors", not "complete"."""
    _save_run(sm, "run-1", status="running")  # no trace file

    snapshot = service.build_snapshot("run-1")

    assert snapshot is not None
    assert snapshot.trace_complete is False
    assert snapshot.trace_warnings  # the reason it is not complete


def test_build_trace_health_corrupt_event_does_not_crash(
    service: RecoveryService, sm: StateManager, trace_dir: Path,
) -> None:
    """A trace file whose events fail TraceEvent validation (bad enum value,
    invalid structure) must not crash snapshot generation. The service returns
    a degraded warning report instead of raising."""
    _save_run(sm, "run-1", status="running")
    _write_trace(trace_dir, "run-1", events=[
        {"event_type": "NOT_A_REAL_EVENT_TYPE", "actor": "node", "run_id": "run-1"},
    ])

    report = service.build_trace_health("run-1")

    assert report.run_id == "run-1"
    assert report.warnings  # corrupt parse flagged, not raised
    assert any("trace" in w.check.lower() or "parse" in w.actual.lower()
               or "invalid" in w.actual.lower()
               for w in report.issues)


def test_build_snapshot_with_corrupt_trace_does_not_crash(
    service: RecoveryService, sm: StateManager, trace_dir: Path,
) -> None:
    """The snapshot path must also survive a corrupt trace — it flows through
    build_trace_health, so the same resilience applies end-to-end."""
    _save_run(sm, "run-1", status="running")
    _write_trace(trace_dir, "run-1", events=[
        {"event_type": "BOGUS", "actor": "node", "run_id": "run-1"},
    ])

    snapshot = service.build_snapshot("run-1")

    assert snapshot is not None
    assert snapshot.trace_complete is False  # corrupt trace is not complete
    assert snapshot.trace_warnings  # surfaced as warnings


# --- available_actions derivation --------------------------------------------

def test_snapshot_available_actions_for_completed_run_excludes_mutations(
    service: RecoveryService, sm: StateManager, trace_dir: Path,
) -> None:
    """A completed run offers no mutation actions — only the read-only report."""
    _save_run(sm, "run-1", status="completed")
    _write_trace(trace_dir, "run-1")

    snapshot = service.build_snapshot("run-1")

    assert snapshot is not None
    # Completed runs expose export_report but not resume/retry/approve/cancel.
    assert "export_report" in snapshot.available_actions
    for blocked in ("resume", "retry_step", "approve_review", "reject_review"):
        assert blocked not in snapshot.available_actions


def test_snapshot_available_actions_for_review_pause_includes_approve_reject(
    service: RecoveryService, sm: StateManager, trace_dir: Path,
) -> None:
    _save_run(
        sm, "run-1", status="waiting_for_review", step=3, current_node="rev",
        metadata={"governed_review_request": {"request_id": "req-1", "step_id": 3}},
    )
    _write_trace(trace_dir, "run-1", run_status="waiting_for_review")

    snapshot = service.build_snapshot("run-1")

    assert snapshot is not None
    assert "approve_review" in snapshot.available_actions
    assert "reject_review" in snapshot.available_actions
    assert "request_revision" in snapshot.available_actions
