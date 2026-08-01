"""Batch execution invariant tests (v2.51.0 P0-P1).

Dry-run never mutates state. Fail-fast skips after first denial.
Result count == total actions including skipped.
"""

from __future__ import annotations

import pytest

from nodechain.core.state import ChainState, StateManager
from nodechain.runtime.batch_recovery import BatchAction, BatchExecutor, BatchSpec
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
def service(sm, trace_dir) -> RecoveryService:
    return RecoveryService(state_manager=sm, trace_dir=trace_dir)


def _seed(sm, run_id, **kw):
    sm.save(ChainState(run_id=run_id, chain_id="c", **kw))


def test_batch_dry_run_does_not_mutate_recovery_state(service, sm):
    """Batch dry-run must not change any run's status."""
    _seed(sm, "r1", status="running")
    _seed(sm, "r2", status="running")
    spec = BatchSpec(
        actions=[
            BatchAction(action=RecoveryAction.CANCEL_RUN, run_id="r1", reason="x"),
            BatchAction(action=RecoveryAction.FAIL_RUN, run_id="r2", reason="y"),
        ],
        operator_role="operator",
    )
    executor = BatchExecutor(service)
    executor.execute(spec, dry_run=True)

    assert sm.load("r1").status == "running"
    assert sm.load("r2").status == "running"


def test_batch_fail_fast_skips_after_first_denial(service, sm):
    """Fail-fast: actions after the first denial are marked skipped."""
    _seed(sm, "r1", status="running")
    _seed(sm, "r2", status="paused_for_budget",
          metadata={"budget_context": {"loop_id": "s", "previous_budget": 100.0,
                                       "accumulated_cost": 104.0}})
    _seed(sm, "r3", status="running")
    spec = BatchSpec(
        actions=[
            BatchAction(action=RecoveryAction.CANCEL_RUN, run_id="r1", reason="ok"),
            BatchAction(action=RecoveryAction.APPROVE_BUDGET_INCREASE,
                        run_id="r2", reason="budget", new_budget=150.0),
            BatchAction(action=RecoveryAction.CANCEL_RUN, run_id="r3", reason="skip me"),
        ],
        operator_role="operator",
    )
    executor = BatchExecutor(service)
    summary = executor.execute(spec, dry_run=True, fail_fast=True)

    statuses = [r.status for r in summary.results]
    assert "skipped" in statuses
    # r3 must be skipped
    assert summary.results[2].status == "skipped"


def test_batch_result_count_equals_total_actions(service, sm):
    """Every action (including skipped) must have a result row."""
    _seed(sm, "r1", status="running")
    _seed(sm, "r2", status="paused_for_budget",
          metadata={"budget_context": {"loop_id": "s", "previous_budget": 100.0,
                                       "accumulated_cost": 104.0}})
    _seed(sm, "r3", status="running")
    spec = BatchSpec(
        actions=[
            BatchAction(action=RecoveryAction.CANCEL_RUN, run_id="r1", reason="ok"),
            BatchAction(action=RecoveryAction.APPROVE_BUDGET_INCREASE,
                        run_id="r2", reason="budget", new_budget=150.0),
            BatchAction(action=RecoveryAction.CANCEL_RUN, run_id="r3", reason="ok"),
        ],
        operator_role="operator",
    )
    executor = BatchExecutor(service)
    summary = executor.execute(spec, dry_run=True, fail_fast=True)

    assert len(summary.results) == summary.total_actions
