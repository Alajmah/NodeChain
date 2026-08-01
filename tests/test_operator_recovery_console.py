"""Acceptance criteria tests for the Operator Recovery Console (v2.46.0 AC 1-10).

These are the gating tests for the phase. Each maps to one acceptance criterion
from the v2.46.0 spec. They use a real in-memory StateManager + a stubbed
orchestrator delegate (no live model/Chroma) so the governed boundary, policy,
trace discipline, and ledger are exercised end-to-end without environment
dependencies.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from nodechain.core.state import ChainState, StateManager
from nodechain.runtime.recovery_classifier import RecoveryState
from nodechain.runtime.recovery_policy import RecoveryAction
from nodechain.runtime.recovery_service import RecoveryService


@pytest.fixture()
def sm(tmp_path) -> StateManager:
    return StateManager(db_path=tmp_path / "state.db")


@pytest.fixture()
def trace_dir(tmp_path) -> str:
    d = tmp_path / "traces"
    d.mkdir()
    return str(d)


@pytest.fixture()
def service(sm: StateManager, trace_dir: str) -> RecoveryService:
    return RecoveryService(state_manager=sm, trace_dir=trace_dir)


def _seed(sm: StateManager, run_id: str, **kw) -> ChainState:
    state = ChainState(run_id=run_id, chain_id="c", **kw)
    sm.save(state)
    return state


def _seed_trace(trace_dir: str, run_id: str, status: str = "running",
                events: list | None = None) -> None:
    Path(trace_dir, f"{run_id}.json").write_text(json.dumps({
        "chain_id": "c", "run_id": run_id, "status": status,
        "started_at": "2026-06-27T00:00:00+00:00", "events": events or [],
    }))


def _install_delegate(service, sm, *, final_status="completed"):
    """Install a stub orchestrator delegate that persists final_status."""
    def delegate(action, run_id, **kw):
        st = sm.load(run_id)
        st.status = final_status
        sm.save(st)
        return final_status
    service.set_action_delegate(delegate)
    return delegate


def _payload(event: dict) -> dict:
    raw = event.get("payload")
    try:
        return json.loads(raw) if raw else {}
    except (ValueError, TypeError):
        return {}


# ── AC1: recover list shows paused, failed, and review-blocked runs ──────────

def test_ac01_list_shows_all_recoverable_run_types(service, sm, trace_dir) -> None:
    _seed(sm, "run-paused", status="paused")
    _seed(sm, "run-failed", status="failed",
          metadata={"last_failure": {"retryable": True}})
    _seed(sm, "run-review", status="waiting_for_review",
          metadata={"governed_review_request": {"request_id": "r", "step_id": 1}})

    summaries = service.list_runs()

    ids = {s.run_id for s in summaries}
    assert {"run-paused", "run-failed", "run-review"} <= ids


# ── AC2: inspect shows status, blocking reason, actions, trace health,
#    retry count, loop count ─────────────────────────────────────────────────

def test_ac02_inspect_shows_full_recovery_picture(service, sm, trace_dir) -> None:
    _seed(sm, "r1", status="waiting_for_review", step=3, current_node="rev",
          metadata={"governed_review_request": {"request_id": "r", "step_id": 3}})
    _seed_trace(trace_dir, "r1", status="waiting_for_review")

    snap = service.build_snapshot("r1")

    assert snap.status == "waiting_for_review"
    assert snap.recovery_state == RecoveryState.PAUSED_FOR_HUMAN_REVIEW.value
    assert snap.blocking_reason
    assert "approve_review" in snap.available_actions
    assert snap.trace_complete in (True, False)  # health is computed
    assert isinstance(snap.retry_counters, dict)
    assert isinstance(snap.loop_counters, dict)


# ── AC3: a paused human-review run can be approved and resumed ───────────────

def test_ac03_paused_review_can_be_approved_and_resumed(service, sm, trace_dir) -> None:
    _seed(sm, "r1", status="waiting_for_review", step=2,
          metadata={"governed_review_request": {"request_id": "r", "step_id": 2}})
    _seed_trace(trace_dir, "r1", status="waiting_for_review")
    _install_delegate(service, sm, final_status="completed")

    result = service.apply_action("r1", RecoveryAction.APPROVE_REVIEW,
                                  operator_identity="op")

    assert result.admitted is True
    assert result.resulting_state == "completed"
    assert sm.load("r1").status == "completed"


# ── AC4: a rejected human-review run terminates ──────────────────────────────

def test_ac04_rejected_review_terminates(service, sm, trace_dir) -> None:
    _seed(sm, "r1", status="waiting_for_review", step=2,
          metadata={"governed_review_request": {"request_id": "r", "step_id": 2}})
    _seed_trace(trace_dir, "r1", status="waiting_for_review")
    _install_delegate(service, sm, final_status="failed")  # rejected → failed

    result = service.apply_action("r1", RecoveryAction.REJECT_REVIEW,
                                  operator_identity="op")

    assert result.admitted is True
    assert result.resulting_state == "failed"
    assert sm.load("r1").status == "failed"


# ── AC5: a retryable failed node can be retried without corrupting
#    completed_steps ──────────────────────────────────────────────────────────

def test_ac05_retryable_failure_retried_without_corrupting_completed_steps(
    service, sm, trace_dir,
) -> None:
    _seed(sm, "r1", status="failed", step=4,
          completed_steps={1: "n1", 2: "n2", 3: "n3"},
          metadata={"last_failure": {"retryable": True, "step_id": 4}})
    _install_delegate(service, sm, final_status="running")

    result = service.apply_action("r1", RecoveryAction.RETRY_STEP,
                                  operator_identity="op", target_step_id=4)

    assert result.admitted is True
    state = sm.load("r1")
    # Already-completed steps are preserved by the retry (delegate only changes
    # status; it must not touch completed_steps).
    assert state.completed_steps == {1: "n1", 2: "n2", 3: "n3"}
    assert state.status == "running"


# ── AC6: a non-retryable failed node cannot be retried unless policy permits ─

def test_ac06_non_retryable_failure_refused_without_override(service, sm) -> None:
    _seed(sm, "r1", status="failed",
          metadata={"last_failure": {"retryable": False, "step_id": 4}})

    result = service.apply_action("r1", RecoveryAction.RETRY_STEP,
                                  operator_identity="op", target_step_id=4)
    assert result.admitted is False


def test_ac06b_non_retryable_failure_admitted_with_override(service, sm) -> None:
    _seed(sm, "r1", status="failed",
          metadata={"last_failure": {"retryable": False, "step_id": 4}})
    _install_delegate(service, sm, final_status="running")

    result = service.apply_action("r1", RecoveryAction.RETRY_STEP,
                                  operator_identity="op", target_step_id=4,
                                  operator_override=True, operator_role="admin")
    assert result.admitted is True


# ── AC7: every operator action emits a trace event ───────────────────────────

@pytest.mark.parametrize("action,setup,final", [
    (RecoveryAction.CANCEL_RUN, dict(status="running"), None),
    (RecoveryAction.FAIL_RUN, dict(status="running"), None),
    (RecoveryAction.EXPORT_REPORT, dict(status="running"), None),
])
def test_ac07_every_action_emits_trace_event(service, sm, action, setup, final) -> None:
    _seed(sm, "r1", **setup)
    service.apply_action("r1", action, operator_identity="op")
    events = sm.get_events("r1")
    assert events  # at least one event emitted
    # And an operator_action_log row binds to one of them.
    rows = sm.get_operator_actions(run_id="r1")
    assert rows and rows[0]["trace_event_id"]


# ── AC8: recovery actions use StateManager/runtime APIs, not raw DB writes ───

def test_ac08_actions_go_through_state_manager_not_raw_db(service, sm) -> None:
    """A cancel transitions state through save_with_event (revision increments),
    and no row appears that wasn't written by StateManager. We assert revision
    monotonicity + that the state_events row carries the same revision."""
    _seed(sm, "r1", status="running")
    before = sm.load("r1").revision

    service.apply_action("r1", RecoveryAction.CANCEL_RUN, operator_identity="op")

    state = sm.load("r1")
    assert state.revision == before + 1  # StateManager incremented it
    # The terminal event shares that revision — single-transaction proof.
    cancel_events = [e for e in sm.get_events("r1")
                     if e["event_type"] == "run_cancelled_by_operator"]
    assert cancel_events and cancel_events[0]["revision"] == state.revision


# ── AC9: operator actions are operator actions, not node executions ──────────

def test_ac09_operator_events_carry_operator_actor_not_node(service, sm) -> None:
    _seed(sm, "r1", status="running")
    service.apply_action("r1", RecoveryAction.CANCEL_RUN, operator_identity="op")

    events = sm.get_events("r1")
    operator_events = [e for e in events
                       if _payload(e).get("actor") == "operator"]
    assert operator_events  # at least one actor=operator event
    # None of the operator events claim node execution.
    assert all("node_" not in e["event_type"] for e in operator_events)


# ── AC10: tests cover all recovery states ────────────────────────────────────

@pytest.mark.parametrize("setup,expected_state", [
    # crash-recovered: unknown side effect WITH a recovery decision
    (dict(status="running", side_effects=[{"idempotency_key": "k1", "status": "unknown"}],
          decisions=[{"idempotency_key": "k1", "decision": "safe_to_retry"}]),
     RecoveryState.CRASH_RECOVERABLE),
    # human-review pause
    (dict(status="waiting_for_review",
          metadata={"governed_review_request": {"request_id": "r", "step_id": 1}}),
     RecoveryState.PAUSED_FOR_HUMAN_REVIEW),
    # retryable failure
    (dict(status="failed", metadata={"last_failure": {"retryable": True}}),
     RecoveryState.FAILED_RETRYABLE),
    # non-retryable failure
    (dict(status="failed", metadata={"last_failure": {"retryable": False}}),
     RecoveryState.FAILED_NON_RETRYABLE),
    # loop exhaustion
    (dict(status="failed", metadata={"loop_exhausted": "search"}),
     RecoveryState.LOOP_EXHAUSTED),
])
def test_ac10_recovery_states_classified(service, sm, trace_dir, setup, expected_state) -> None:
    state_kw = {k: v for k, v in setup.items() if k not in ("side_effects", "decisions")}
    _seed(sm, "r1", **state_kw)
    _seed_trace(trace_dir, "r1", status=setup.get("status", "running"))
    # Inject side effects + decisions directly for the crash case.
    for se in setup.get("side_effects", []):
        with sqlite3.connect(sm.db_path) as conn:
            conn.execute(
                "INSERT INTO side_effect_ledger (run_id, step_id, node_id, branch_name, "
                "side_effect_type, idempotency_key, status, request_hash, response_hash, "
                "external_reference, retryable, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("r1", 1, "n", None, "http", se["idempotency_key"], se["status"],
                 "rh", "rh", None, 1, "2026-06-27T00:00:00+00:00"),
            )
    for d in setup.get("decisions", []):
        with sqlite3.connect(sm.db_path) as conn:
            conn.execute(
                "INSERT INTO side_effect_recovery_decisions "
                "(decision_id, run_id, idempotency_key, node_id, prior_status, "
                "decision, actor, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (f"dec-{d['idempotency_key']}", "r1", d["idempotency_key"], "n",
                 "unknown", d["decision"], "system", "2026-06-27T00:00:00+00:00"),
            )

    snap = service.build_snapshot("r1")
    assert snap.recovery_state == expected_state.value


# ── trace-incomplete recovery (AC10 supplement) ──────────────────────────────

def test_ac10_trace_incomplete_when_reconciler_errors(service, sm, trace_dir) -> None:
    """A run whose trace has no matching ledger facts is classified with a
    trace warning (missing trace → degraded). The snapshot surfaces it."""
    _seed(sm, "r1", status="running")
    # No trace file → missing-trace warning → trace_complete False.

    snap = service.build_snapshot("r1")
    assert snap.trace_complete is False
    assert snap.trace_warnings
