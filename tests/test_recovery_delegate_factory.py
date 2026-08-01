"""Tests for the RecoveryService action delegate factory (v2.46.0 Phase 4.1).

RecoveryService owns no execution loop. resume/retry/approve/reject/revise
require reconstructing the Orchestrator (heavy: blueprint + model adapter +
Chroma + nodes), which is a CLI/environment concern. So RecoveryService accepts
a pluggable delegate callable that the CLI installs; without it these actions
raise NotImplementedError (honest stub, established in Phase 3).

This keeps RecoveryService testable without a live orchestrator and keeps the
runtime authority model intact: the delegate calls the SAME Orchestrator.resume
/ ReviewManager.resolve_resume_review path the normal resume CLI uses.
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
def trace_dir(tmp_path) -> str:
    return str(tmp_path / "traces")


@pytest.fixture()
def service(sm: StateManager, trace_dir: str) -> RecoveryService:
    d = __import__("pathlib").Path(trace_dir)
    d.mkdir(parents=True, exist_ok=True)
    return RecoveryService(state_manager=sm, trace_dir=trace_dir)


def _seed(sm: StateManager, run_id: str, **kw) -> ChainState:
    state = ChainState(run_id=run_id, chain_id="c", **kw)
    sm.save(state)
    return state


# --- without a delegate, delegation actions raise honestly -------------------

def test_resume_without_delegate_is_not_implemented(service, sm) -> None:
    """A crash-recoverable run with no unknown effects CAN be authorized for
    resume, but without a delegate installed (CLI hasn't wired the
    orchestrator), apply_action surfaces a delegation failure rather than
    silently no-op'ing."""
    _seed(sm, "r1", status="paused")
    result = service.apply_action("r1", RecoveryAction.RESUME, operator_identity="op")
    assert result.admitted is False
    assert "delegate" in result.rejection_reason.lower() or \
           "not implemented" in result.rejection_reason.lower()


# --- with a delegate, the action flows through and the result binds -----------

def test_installed_delegate_is_invoked_for_resume(service, sm) -> None:
    """When the CLI installs a delegate, resume is authorized, delegated to it,
    and the resulting status flows back into the ledger."""
    _seed(sm, "r1", status="paused")
    invoked = {}

    def delegate(action, run_id, **kw):
        invoked["action"] = action
        invoked["run_id"] = run_id
        return "running"  # the orchestrator resumed and is running

    service.set_action_delegate(delegate)
    result = service.apply_action("r1", RecoveryAction.RESUME, operator_identity="op")

    assert result.admitted is True
    assert result.resulting_state == "running"
    assert invoked["action"] is RecoveryAction.RESUME
    assert invoked["run_id"] == "r1"
    [row] = sm.get_operator_actions(run_id="r1")
    assert row["admitted"] is True
    assert row["resulting_state"] == "running"


def test_delegate_receives_target_step_id_for_retry(service, sm) -> None:
    """Retry passes target_step_id through to the delegate (step/invocation
    precision for looped nodes — the delegate/Orchestrator must retry that
    specific step, not the node by name)."""
    _seed(sm, "r1", status="failed",
          metadata={"last_failure": {"retryable": True, "step_id": 4}})
    received = {}

    def delegate(action, run_id, **kw):
        received.update(kw)
        return "running"

    service.set_action_delegate(delegate)
    result = service.apply_action(
        "r1", RecoveryAction.RETRY_STEP, operator_identity="op", target_step_id=4,
    )
    assert result.admitted is True
    assert received["target_step_id"] == 4


def test_delegate_receives_reason_and_instructions(service, sm) -> None:
    """approve/revise pass reason/instructions so the delegate can set
    review_decision / revision hints before Orchestrator.resume runs."""
    _seed(sm, "r1", status="waiting_for_review",
          metadata={"governed_review_request": {"request_id": "r", "step_id": 2}})
    received = {}

    def delegate(action, run_id, **kw):
        received.update(kw)
        return "running"

    service.set_action_delegate(delegate)
    service.apply_action(
        "r1", RecoveryAction.APPROVE_REVIEW, operator_identity="op",
        reason="looks good", instructions=None,
    )
    assert received["reason"] == "looks good"


def test_delegate_failure_surfaces_as_not_admitted(service, sm) -> None:
    """If the delegate raises (orchestrator resume blew up), apply_action
    records admitted=False with the persisted pre-action status and emits
    BLOCKED — no ALLOWED event leaks."""
    _seed(sm, "r1", status="paused")

    def boom(action, run_id, **kw):
        raise RuntimeError("orchestrator exploded")

    service.set_action_delegate(boom)
    result = service.apply_action("r1", RecoveryAction.RESUME, operator_identity="op")
    assert result.admitted is False
    assert "orchestrator exploded" in result.rejection_reason
    [row] = sm.get_operator_actions(run_id="r1")
    assert row["admitted"] is False
    assert row["resulting_state"] == "paused"  # persisted pre-action status


def test_delegate_returned_status_must_differ_for_terminal_delegate_actions(
    service, sm,
) -> None:
    """A reject_review delegate returns 'failed' (the run terminates rejected);
    that resulting_state lands in the ledger."""
    _seed(sm, "r1", status="waiting_for_review",
          metadata={"governed_review_request": {"request_id": "r", "step_id": 2}})

    def delegate(action, run_id, **kw):
        return "failed"  # rejected → terminal

    service.set_action_delegate(delegate)
    result = service.apply_action(
        "r1", RecoveryAction.REJECT_REVIEW, operator_identity="op",
    )
    assert result.admitted is True
    assert result.resulting_state == "failed"
    [row] = sm.get_operator_actions(run_id="r1")
    assert row["resulting_state"] == "failed"


# --- terminal + read-only actions do NOT call the delegate -------------------

def test_cancel_does_not_invoke_delegate(service, sm) -> None:
    """cancel/fail are handled in-process (atomic save_with_event); the delegate
    is never called for them."""
    _seed(sm, "r1", status="running")
    invoked = []

    def delegate(action, run_id, **kw):
        invoked.append(action)
        return "cancelled"

    service.set_action_delegate(delegate)
    service.apply_action("r1", RecoveryAction.CANCEL_RUN, operator_identity="op")
    assert invoked == []  # delegate not used
    assert sm.load("r1").status == "cancelled"


def test_export_report_does_not_invoke_delegate(service, sm) -> None:
    _seed(sm, "r1", status="running")
    invoked = []

    def delegate(action, run_id, **kw):
        invoked.append(action)
        return "running"

    service.set_action_delegate(delegate)
    service.apply_action("r1", RecoveryAction.EXPORT_REPORT, operator_identity="op")
    assert invoked == []
