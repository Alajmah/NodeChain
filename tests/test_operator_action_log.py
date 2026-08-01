"""Tests for the operator_action_log admission ledger (v2.46.0 Phase 2.2/2.3).

The operator_action_log records each operator recovery action's ADMISSION, not
its execution. It stores intent, authorization result, action params, resulting
status, and the trace_event_id that binds it to the authoritative Chain Trace.
It is NOT a competing execution record — the Chain Trace remains authoritative.

Both admitted AND blocked actions are recorded, so the audit trail shows every
attempted intervention and why it was allowed or refused.
"""

from __future__ import annotations

import pytest

from nodechain.core.state import StateManager


@pytest.fixture()
def sm(tmp_path) -> StateManager:
    return StateManager(db_path=tmp_path / "state.db")


def _admitted_action(**overrides) -> dict:
    base = {
        "action_id": "act-1",
        "run_id": "run-1",
        "action": "resume",
        "actor_identity": "operator@example",
        "requested_at": "2026-06-27T00:00:00+00:00",
        "admitted": True,
        "rejection_reason": None,
        "target_step_id": None,
        "target_node_id": None,
        "resulting_state": "running",
        "trace_event_id": "tev-1",
        "metadata": {"source": "console"},
    }
    base.update(overrides)
    return base


# --- round-trip: admitted action --------------------------------------------

def test_record_and_get_admitted_action_round_trips(sm: StateManager) -> None:
    """An admitted action is persisted and retrievable with all its fields."""
    sm.record_operator_action(_admitted_action())

    [row] = sm.get_operator_actions(run_id="run-1")

    assert row["action_id"] == "act-1"
    assert row["run_id"] == "run-1"
    assert row["action"] == "resume"
    assert row["actor_identity"] == "operator@example"
    assert row["admitted"] is True
    assert row["rejection_reason"] in (None, "")  # null for admitted
    assert row["resulting_state"] == "running"
    assert row["trace_event_id"] == "tev-1"
    assert row["metadata"] == {"source": "console"}


# --- blocked actions are recorded too ---------------------------------------

def test_blocked_action_is_recorded_with_rejection_reason(sm: StateManager) -> None:
    """A REFUSED action is still persisted — the audit trail must show every
    attempted intervention and why it was blocked. This is what makes the
    fail-closed operator policy inspectable after the fact."""
    blocked = _admitted_action(
        action_id="act-2", action="retry_step", admitted=False,
        rejection_reason="non-retryable failure without override",
        trace_event_id="tev-blocked",
    )
    sm.record_operator_action(blocked)

    [row] = sm.get_operator_actions(run_id="run-1")

    assert row["admitted"] is False
    assert row["rejection_reason"] == "non-retryable failure without override"
    assert row["trace_event_id"] == "tev-blocked"


# --- filtering ---------------------------------------------------------------

def test_get_operator_actions_filters_by_admitted(sm: StateManager) -> None:
    """Operators can list only admitted or only blocked attempts."""
    sm.record_operator_action(_admitted_action(action_id="a1", admitted=True))
    sm.record_operator_action(_admitted_action(action_id="a2", admitted=False,
                                               rejection_reason="no"))

    admitted = sm.get_operator_actions(run_id="run-1", admitted=True)
    blocked = sm.get_operator_actions(run_id="run-1", admitted=False)

    assert {r["action_id"] for r in admitted} == {"a1"}
    assert {r["action_id"] for r in blocked} == {"a2"}


def test_get_operator_actions_scoped_to_one_run(sm: StateManager) -> None:
    """The query is run-scoped so one run's ledger never leaks into another."""
    sm.record_operator_action(_admitted_action(action_id="a1", run_id="run-1"))
    sm.record_operator_action(_admitted_action(action_id="a2", run_id="run-2"))

    rows = sm.get_operator_actions(run_id="run-2")
    assert {r["action_id"] for r in rows} == {"a2"}


def test_get_operator_actions_orders_newest_first(sm: StateManager) -> None:
    """Most recent admission attempts first — matches the rest of the console."""
    sm.record_operator_action(_admitted_action(
        action_id="old", requested_at="2026-06-27T00:00:00+00:00"))
    sm.record_operator_action(_admitted_action(
        action_id="new", requested_at="2026-06-27T12:00:00+00:00"))

    rows = sm.get_operator_actions(run_id="run-1")
    assert [r["action_id"] for r in rows] == ["new", "old"]


def test_get_operator_actions_empty_returns_list(sm: StateManager) -> None:
    """A run with no operator actions returns [], not None."""
    assert sm.get_operator_actions(run_id="run-none") == []


# --- ledger is admission-only, not execution --------------------------------

def test_ledger_carries_step_and_node_target_for_retry_precision(
    sm: StateManager,
) -> None:
    """A retry action records its target step_id + node_id so the ledger can be
    cross-checked against the invocation ledger (step/invocation precision is a
    hard constraint — retry must never be ambiguous for looped nodes)."""
    sm.record_operator_action(_admitted_action(
        action="retry_step", target_step_id=4, target_node_id="flaky_node",
    ))

    [row] = sm.get_operator_actions(run_id="run-1")
    assert row["target_step_id"] == 4
    assert row["target_node_id"] == "flaky_node"


def test_record_operator_action_replaces_on_same_action_id(sm: StateManager) -> None:
    """Re-recording the same action_id updates the row (idempotent admit) rather
    than duplicating — an action has exactly one admission outcome."""
    sm.record_operator_action(_admitted_action(action_id="act-1", admitted=False,
                                              rejection_reason="first"))
    sm.record_operator_action(_admitted_action(action_id="act-1", admitted=True,
                                              rejection_reason=None,
                                              resulting_state="running"))

    rows = sm.get_operator_actions(run_id="run-1")
    assert len(rows) == 1
    assert rows[0]["admitted"] is True
    assert rows[0]["resulting_state"] == "running"
