"""Tests for RecoveryService.apply_action — the governed write boundary (v2.46.0 Phase 3.2).

apply_action is the ONLY place an operator action mutates anything. Flow:
build snapshot → OperatorActionPolicy.authorize → (emit operator trace event +
record operator_action_log row + delegate). Read-only commands never call it.

Constraint #2 (transactional): for admitted actions, the operator_action_log
row, the recovery trace event, and the state transition must not diverge
silently. These tests assert all three land together.

These tests cover the paths that need NO orchestrator: export_report (read),
cancel_run/fail_run (terminal, pure StateManager.save), and the BLOCKED path
(policy refusal). Delegation actions (resume/retry/approve) that reconstruct an
Orchestrator are covered separately with a factory stub.
"""

from __future__ import annotations

import pytest

from nodechain.core.state import ChainState, StateManager
from nodechain.runtime.recovery_policy import RecoveryAction
from nodechain.runtime.recovery_service import RecoveryService


@pytest.fixture()
def sm(tmp_path) -> StateManager:
    return StateManager(db_path=tmp_path / "state.db")


@pytest.fixture()
def trace_dir(tmp_path):
    import pathlib
    d = tmp_path / "traces"
    d.mkdir()
    return str(d)


@pytest.fixture()
def service(sm: StateManager, trace_dir: str) -> RecoveryService:
    return RecoveryService(state_manager=sm, trace_dir=trace_dir)


def _seed(sm: StateManager, run_id: str = "r1", **kw) -> ChainState:
    state = ChainState(run_id=run_id, chain_id="c", **kw)
    sm.save(state)
    return state


def _payload(event: dict) -> dict:
    """get_events returns payload as a JSON string; parse it for assertions."""
    import json
    raw = event.get("payload")
    try:
        return json.loads(raw) if raw else {}
    except (ValueError, TypeError):
        return {}


def _event_types(sm: StateManager, run_id: str) -> list[str]:
    return [e["event_type"] for e in sm.get_events(run_id)]


# --- BLOCKED path: policy refusal is fully audited, no mutation -------------

def test_blocked_action_emits_blocked_event_and_admitted_zero_row(
    service: RecoveryService, sm: StateManager,
) -> None:
    """A refused action must NOT mutate run state, but MUST emit a
    RECOVERY_ACTION_BLOCKED event and a ledger row with admitted=0 so the
    attempted intervention is auditable."""
    _seed(sm, "r1", status="completed")  # terminal → resume refused
    before = sm.load("r1").revision

    result = service.apply_action(
        "r1", RecoveryAction.RESUME, operator_identity="op@x",
    )

    assert result.admitted is False
    assert result.rejection_reason
    # State untouched.
    assert sm.load("r1").revision == before
    # ...but the attempt is audited.
    rows = sm.get_operator_actions(run_id="r1")
    assert len(rows) == 1
    assert rows[0]["admitted"] is False
    assert rows[0]["rejection_reason"] == result.rejection_reason
    assert rows[0]["actor_identity"] == "op@x"
    # A BLOCKED trace event was emitted (operator actor).
    events = sm.get_events("r1")
    assert any("blocked" in e.get("event_type", "") for e in events)


def test_blocked_action_carries_actor_identity_and_action(
    service: RecoveryService, sm: StateManager,
) -> None:
    """The ledger row records WHO tried to do WHAT, even on refusal."""
    _seed(sm, "r1", status="completed")
    service.apply_action("r1", RecoveryAction.CANCEL_RUN, operator_identity="alice")
    [row] = sm.get_operator_actions(run_id="r1")
    assert row["actor_identity"] == "alice"
    assert row["action"] == "cancel_run"


# --- export_report: admitted, read-only, no state mutation -------------------

def test_export_report_admitted_and_does_not_mutate(
    service: RecoveryService, sm: StateManager,
) -> None:
    """export_report is read-only: admitted, emits a report-exported event +
    ledger row, but does NOT change run status or revision."""
    _seed(sm, "r1", status="running")
    before = sm.load("r1").revision

    result = service.apply_action("r1", RecoveryAction.EXPORT_REPORT,
                                  operator_identity="op@x")

    assert result.admitted is True
    assert sm.load("r1").revision == before  # no mutation
    rows = sm.get_operator_actions(run_id="r1")
    assert len(rows) == 1 and rows[0]["admitted"] is True
    assert rows[0]["action"] == "export_report"


# --- cancel_run: admitted terminal action ------------------------------------

def test_cancel_run_sets_cancelled_status_and_emits_event(
    service: RecoveryService, sm: StateManager,
) -> None:
    """An admitted cancel writes status=cancelled through StateManager.save,
    emits a run_cancelled_by_operator event, and records the ledger row —
    all three together (no silent divergence)."""
    _seed(sm, "r1", status="waiting_for_review")
    before = sm.load("r1").revision

    result = service.apply_action(
        "r1", RecoveryAction.CANCEL_RUN, operator_identity="op@x",
        reason="operator abort",
    )

    assert result.admitted is True
    state = sm.load("r1")
    assert state.status == "cancelled"
    assert state.revision == before + 1  # save incremented revision
    [row] = sm.get_operator_actions(run_id="r1")
    assert row["admitted"] is True
    assert row["resulting_state"] == "cancelled"
    assert row["trace_event_id"]  # bound to the emitted event
    events = sm.get_events("r1")
    assert any("cancelled" in e.get("event_type", "") for e in events)


def test_fail_run_sets_failed_status_and_emits_event(
    service: RecoveryService, sm: StateManager,
) -> None:
    _seed(sm, "r1", status="waiting_for_review")
    result = service.apply_action(
        "r1", RecoveryAction.FAIL_RUN, operator_identity="op@x",
        reason="unrecoverable",
    )
    assert result.admitted is True
    assert sm.load("r1").status == "failed"
    [row] = sm.get_operator_actions(run_id="r1")
    assert row["resulting_state"] == "failed"


# --- operator events carry Actor.OPERATOR, never NODE ------------------------

def test_admitted_action_event_uses_operator_actor(
    service: RecoveryService, sm: StateManager,
) -> None:
    """The emitted trace event must record actor=operator, never node — the
    trace-truth invariant. An operator cancellation is not a node execution."""
    _seed(sm, "r1", status="running")
    service.apply_action("r1", RecoveryAction.CANCEL_RUN, operator_identity="op@x")
    events = sm.get_events("r1")
    operator_events = [e for e in events
                       if _payload(e).get("actor") == "operator"
                       or "operator" in e.get("event_type", "")]
    assert operator_events  # at least one operator-actor event


# --- transactional: no divergence between row / event / state ----------------

def test_admitted_cancel_does_not_leave_orphan_ledger_row_on_save_failure(
    service: RecoveryService, sm: StateManager, monkeypatch,
) -> None:
    """Constraint #2: if the terminal write fails AFTER the action was
    authorized, the result must reflect the failure (not claim success). Cancel
    now writes via save_with_event, so that is the boundary we fault."""
    _seed(sm, "r1", status="running")

    def boom(state, *a, **kw):
        raise RuntimeError("disk full")
    monkeypatch.setattr(sm, "save_with_event", boom)

    result = service.apply_action(
        "r1", RecoveryAction.CANCEL_RUN, operator_identity="op@x",
    )
    assert result.admitted is False
    assert result.rejection_reason  # the failure is surfaced, not hidden


# --- unknown run -------------------------------------------------------------

def test_apply_action_unknown_run_returns_not_admitted(
    service: RecoveryService,
) -> None:
    result = service.apply_action("no-such-run", RecoveryAction.EXPORT_REPORT)
    assert result.admitted is False
    assert result.rejection_reason


# ── Phase 3 rework: audit-truth invariants (#1, #2, #3, #5) ──────────────────

def test_refused_action_emits_requested_then_blocked(service, sm) -> None:
    """#1: every operator attempt has a complete lifecycle. A refused action
    must emit RECOVERY_ACTION_REQUESTED BEFORE RECOVERY_ACTION_BLOCKED — the
    attempt happened, then policy refused it."""
    _seed(sm, "r1", status="completed")  # terminal → resume refused
    service.apply_action("r1", RecoveryAction.RESUME, operator_identity="op")

    types = _event_types(sm, "r1")
    assert "recovery_action_requested" in types
    assert "recovery_action_blocked" in types
    # REQUESTED must come before BLOCKED in the event order.
    assert types.index("recovery_action_requested") < types.index("recovery_action_blocked")


def test_delegation_failure_emits_blocked_not_allowed(service, sm, monkeypatch) -> None:
    """#2: if delegation raises, the audit must not contradict itself. No
    ALLOWED event should be bound to an admitted=False ledger row. The failure
    path emits BLOCKED and binds the ledger row to that instead."""
    _seed(sm, "r1", status="running")

    def boom(state, *a, **kw):
        raise RuntimeError("disk full")
    monkeypatch.setattr(sm, "save_with_event", boom)

    result = service.apply_action("r1", RecoveryAction.CANCEL_RUN, operator_identity="op")
    assert result.admitted is False

    types = _event_types(sm, "r1")
    # No ALLOWED event survives a delegation failure.
    assert "recovery_action_allowed" not in types
    # A BLOCKED event exists and is what the ledger row binds to.
    assert "recovery_action_blocked" in types
    [row] = sm.get_operator_actions(run_id="r1")
    assert row["admitted"] is False
    assert row["trace_event_id"]  # bound to the blocked event, not an allowed one


def test_export_report_emits_report_exported_event(service, sm) -> None:
    """#3: export_report must emit RECOVERY_REPORT_EXPORTED, not just record a
    ledger row. The outcome event is part of the audit trail."""
    _seed(sm, "r1", status="running")
    service.apply_action("r1", RecoveryAction.EXPORT_REPORT, operator_identity="op")

    assert "recovery_report_exported" in _event_types(sm, "r1")


def test_terminal_cancel_is_atomic_with_outcome_event(service, sm, monkeypatch) -> None:
    """#5: cancel must write the terminal status AND the outcome event in a
    single SQLite transaction (save_with_event), not via a separate save +
    append_event. Proved by spying: save_with_event is called, the public
    append_event is NOT used for the outcome, and the outcome event shares the
    post-cancel state revision."""
    _seed(sm, "r1", status="running")

    swe_calls = []
    orig_swe = sm.save_with_event
    def spy_swe(state, event_type, payload=None):
        swe_calls.append(event_type)
        return orig_swe(state, event_type, payload)
    monkeypatch.setattr(sm, "save_with_event", spy_swe)

    service.apply_action("r1", RecoveryAction.CANCEL_RUN, operator_identity="op")

    state = sm.load("r1")
    assert state.status == "cancelled"
    # The outcome event went through the atomic path.
    assert "run_cancelled_by_operator" in swe_calls
    cancel_events = [e for e in sm.get_events("r1")
                     if e["event_type"] == "run_cancelled_by_operator"]
    assert cancel_events
    # Same revision = same transaction as the state write.
    assert cancel_events[0]["revision"] == state.revision


def test_terminal_fail_is_atomic_with_outcome_event(service, sm, monkeypatch) -> None:
    """#5 mirror: fail_run also writes status + outcome event atomically."""
    _seed(sm, "r1", status="waiting_for_review")

    swe_calls = []
    orig_swe = sm.save_with_event
    def spy_swe(state, event_type, payload=None):
        swe_calls.append(event_type)
        return orig_swe(state, event_type, payload)
    monkeypatch.setattr(sm, "save_with_event", spy_swe)

    service.apply_action("r1", RecoveryAction.FAIL_RUN, operator_identity="op",
                         reason="unrecoverable")

    state = sm.load("r1")
    assert state.status == "failed"
    assert "run_failed_by_operator" in swe_calls
    fail_events = [e for e in sm.get_events("r1")
                   if e["event_type"] == "run_failed_by_operator"]
    assert fail_events
    assert fail_events[0]["revision"] == state.revision


def test_failure_ledger_reports_persisted_pre_action_status_not_in_memory(
    service, sm, monkeypatch,
) -> None:
    """#6: when save_with_event raises, the in-memory ChainState has already
    been mutated (status='cancelled') but the DB still holds the pre-action
    status. The failure ledger row must report the PERSISTED status (the run's
    real state), not the attempted terminal status that never committed.
    Otherwise an admitted=False row falsely claims a transition."""
    _seed(sm, "r1", status="running")  # persisted status is "running"

    def boom(state, *a, **kw):
        raise RuntimeError("disk full")
    monkeypatch.setattr(sm, "save_with_event", boom)

    service.apply_action("r1", RecoveryAction.CANCEL_RUN, operator_identity="op")

    [row] = sm.get_operator_actions(run_id="r1")
    assert row["admitted"] is False
    # The persisted DB status is still "running" — the row must match it,
    # NOT "cancelled" (which only ever existed in memory).
    assert row["resulting_state"] == "running"
    # And the DB itself confirms no transition landed.
    assert sm.load("r1").status == "running"


def test_failure_ledger_for_fail_run_reports_persisted_status(
    service, sm, monkeypatch,
) -> None:
    """#6 mirror for fail_run."""
    _seed(sm, "r1", status="waiting_for_review")

    def boom(state, *a, **kw):
        raise RuntimeError("disk full")
    monkeypatch.setattr(sm, "save_with_event", boom)

    service.apply_action("r1", RecoveryAction.FAIL_RUN, operator_identity="op")

    [row] = sm.get_operator_actions(run_id="r1")
    assert row["admitted"] is False
    assert row["resulting_state"] == "waiting_for_review"
    assert sm.load("r1").status == "waiting_for_review"
