"""Tests for batch recovery schema/parser + validation (v2.50.0 steps 1-2).

Batch recovery allows multiple recovery actions submitted as one explicit,
auditable YAML batch. Each action inside the batch is authorized independently
— a batch is not authorized as a unit.
"""

from __future__ import annotations

import pytest

from nodechain.runtime.batch_recovery import BatchAction, BatchSpec, parse_batch_file


def _write_yaml(tmp_path, content: str):
    p = tmp_path / "batch.yaml"
    p.write_text(content)
    return str(p)


# --- valid batch accepted ----------------------------------------------------

def test_valid_batch_parsed(tmp_path) -> None:
    """A well-formed batch YAML parses into a BatchSpec."""
    path = _write_yaml(tmp_path, """
batch_id: recovery-001
operator_identity: console
operator_role: admin
dry_run: true
actions:
  - action: retry_step
    run_id: run_001
    step_id: 4
    reason: "Transient failure"
  - action: cancel_run
    run_id: run_002
    reason: "Duplicate"
""")
    spec = parse_batch_file(path)
    assert isinstance(spec, BatchSpec)
    assert spec.batch_id == "recovery-001"
    assert spec.operator_role == "admin"
    assert spec.dry_run is True
    assert len(spec.actions) == 2
    assert spec.actions[0].action == "retry_step"
    assert spec.actions[0].step_id == 4
    assert spec.actions[1].action == "cancel_run"


def test_batch_id_auto_generated_when_missing(tmp_path) -> None:
    """batch_id is optional; auto-generated if missing."""
    path = _write_yaml(tmp_path, """
actions:
  - action: cancel_run
    run_id: run_001
    reason: "test"
""")
    spec = parse_batch_file(path)
    assert spec.batch_id  # auto-generated, non-empty
    assert spec.batch_id.startswith("batch-")


# --- missing/empty actions rejected -----------------------------------------

def test_missing_actions_rejected(tmp_path) -> None:
    path = _write_yaml(tmp_path, """
batch_id: bad
operator_role: admin
""")
    with pytest.raises((ValueError, KeyError)):
        parse_batch_file(path)


def test_empty_actions_rejected(tmp_path) -> None:
    path = _write_yaml(tmp_path, """
actions: []
""")
    with pytest.raises(ValueError, match="empty|non-empty|required"):
        parse_batch_file(path)


# --- unknown action rejected -------------------------------------------------

def test_unknown_action_rejected(tmp_path) -> None:
    path = _write_yaml(tmp_path, """
actions:
  - action: destroy_everything
    run_id: run_001
    reason: "oops"
""")
    with pytest.raises((ValueError, KeyError), match="unknown|invalid"):
        parse_batch_file(path)


# --- missing run_id / reason rejected ----------------------------------------

def test_missing_run_id_rejected(tmp_path) -> None:
    path = _write_yaml(tmp_path, """
actions:
  - action: cancel_run
    reason: "no run"
""")
    with pytest.raises((ValueError, KeyError), match="run_id|required"):
        parse_batch_file(path)


def test_missing_reason_rejected(tmp_path) -> None:
    path = _write_yaml(tmp_path, """
actions:
  - action: cancel_run
    run_id: run_001
""")
    with pytest.raises((ValueError, KeyError), match="reason|required"):
        parse_batch_file(path)


# --- batch over 50 rejected --------------------------------------------------

def test_batch_over_50_rejected(tmp_path) -> None:
    actions = "\n".join(
        f'  - action: cancel_run\n    run_id: run_{i:03d}\n    reason: "bulk"'
        for i in range(101)
    )
    path = _write_yaml(tmp_path, f"actions:\n{actions}")
    with pytest.raises(ValueError, match="100|max|limit|too many"):
        parse_batch_file(path)


# --- dry-run tests -----------------------------------------------------------

@pytest.fixture()
def sm(tmp_path):
    from nodechain.core.state import StateManager
    return StateManager(db_path=tmp_path / "state.db")


@pytest.fixture()
def trace_dir(tmp_path):
    import pathlib
    d = tmp_path / "traces"
    d.mkdir(parents=True, exist_ok=True)
    return str(d)


@pytest.fixture()
def service(sm, trace_dir):
    from nodechain.runtime.recovery_service import RecoveryService
    return RecoveryService(state_manager=sm, trace_dir=trace_dir)


def _seed(sm, run_id, **kw):
    from nodechain.core.state import ChainState
    sm.save(ChainState(run_id=run_id, chain_id="c", **kw))


def test_dry_run_does_not_mutate_state(service, sm) -> None:
    """Dry-run authorizes but does not apply actions."""
    from nodechain.runtime.batch_recovery import BatchExecutor
    _seed(sm, "r1", status="running")
    spec = BatchSpec(
        actions=[BatchAction(
            action=__import__("nodechain.runtime.recovery_policy", fromlist=["RecoveryAction"]).RecoveryAction.CANCEL_RUN,
            run_id="r1", reason="test",
        )],
        operator_role="operator",
    )
    executor = BatchExecutor(service)
    summary = executor.execute(spec, dry_run=True)

    assert summary.mode == "dry_run"
    assert sm.load("r1").status == "running"  # NOT cancelled
    assert summary.results[0].status == "admitted"


def test_dry_run_reports_rbac_denial(service, sm) -> None:
    """Dry-run reports RBAC denial for operator attempting budget increase."""
    from nodechain.runtime.batch_recovery import BatchExecutor
    from nodechain.runtime.recovery_policy import RecoveryAction
    _seed(sm, "r1", status="paused_for_budget",
          metadata={"budget_context": {"loop_id": "search", "previous_budget": 100.0,
                                       "accumulated_cost": 104.0}})
    spec = BatchSpec(
        actions=[BatchAction(
            action=RecoveryAction.APPROVE_BUDGET_INCREASE,
            run_id="r1", reason="test", new_budget=150.0,
        )],
        operator_role="operator",
    )
    executor = BatchExecutor(service)
    summary = executor.execute(spec, dry_run=True)

    assert summary.mode == "dry_run"
    assert summary.results[0].admitted is False
    assert summary.results[0].denial_type == "rbac"
    assert summary.overall_status == "dry_run_denied"


def test_dry_run_admitted_for_finance_budget(service, sm) -> None:
    """finance role passes RBAC for budget increase in dry-run."""
    from nodechain.runtime.batch_recovery import BatchExecutor
    from nodechain.runtime.recovery_policy import RecoveryAction
    _seed(sm, "r1", status="paused_for_budget",
          metadata={"budget_context": {"loop_id": "search", "previous_budget": 100.0,
                                       "accumulated_cost": 104.0}})
    spec = BatchSpec(
        actions=[BatchAction(
            action=RecoveryAction.APPROVE_BUDGET_INCREASE,
            run_id="r1", reason="approved", new_budget=150.0,
        )],
        operator_role="finance",
    )
    executor = BatchExecutor(service)
    summary = executor.execute(spec, dry_run=True)

    assert summary.results[0].admitted is True
    assert summary.overall_status == "dry_run_passed"


# --- fail-fast execution -----------------------------------------------------

def test_fail_fast_stops_after_first_denial(service, sm) -> None:
    """Default fail-fast: first denial stops, remaining actions skipped."""
    from nodechain.runtime.batch_recovery import BatchExecutor
    from nodechain.runtime.recovery_policy import RecoveryAction
    _seed(sm, "r1", status="running")
    _seed(sm, "r2", status="running")
    _seed(sm, "r3", status="paused_for_budget",
          metadata={"budget_context": {"loop_id": "s", "previous_budget": 100.0,
                                       "accumulated_cost": 104.0}})
    spec = BatchSpec(
        actions=[
            BatchAction(action=RecoveryAction.CANCEL_RUN, run_id="r1", reason="ok"),
            BatchAction(action=RecoveryAction.APPROVE_BUDGET_INCREASE,
                        run_id="r3", reason="budget", new_budget=150.0),  # denied (operator)
            BatchAction(action=RecoveryAction.CANCEL_RUN, run_id="r2", reason="should skip"),
        ],
        operator_role="operator",
    )
    executor = BatchExecutor(service)
    summary = executor.execute(spec, dry_run=True, fail_fast=True)

    # r1 admitted, r3 denied (RBAC), r2 skipped
    assert summary.results[0].status == "admitted"
    assert summary.results[1].status == "denied"
    assert summary.results[2].status == "skipped"
    assert summary.skipped_count == 1


# --- continue-on-error -------------------------------------------------------

def test_continue_on_error_processes_later_actions(service, sm) -> None:
    """continue-on-error: denied action recorded, later actions still processed."""
    from nodechain.runtime.batch_recovery import BatchExecutor
    from nodechain.runtime.recovery_policy import RecoveryAction
    _seed(sm, "r1", status="running")
    _seed(sm, "r2", status="paused_for_budget",
          metadata={"budget_context": {"loop_id": "s", "previous_budget": 100.0,
                                       "accumulated_cost": 104.0}})
    _seed(sm, "r3", status="running")
    spec = BatchSpec(
        actions=[
            BatchAction(action=RecoveryAction.CANCEL_RUN, run_id="r1", reason="ok"),
            BatchAction(action=RecoveryAction.APPROVE_BUDGET_INCREASE,
                        run_id="r2", reason="budget", new_budget=150.0),  # denied (operator)
            BatchAction(action=RecoveryAction.CANCEL_RUN, run_id="r3", reason="still runs"),
        ],
        operator_role="operator",
    )
    executor = BatchExecutor(service)
    summary = executor.execute(spec, dry_run=True, continue_on_error=True)

    # All three processed
    assert summary.results[0].status == "admitted"
    assert summary.results[1].status == "denied"
    assert summary.results[2].status == "admitted"
    assert summary.skipped_count == 0


# --- execution (non-dry-run) -------------------------------------------------

def test_execute_batch_mutates_state(service, sm) -> None:
    """Non-dry-run execution actually applies actions."""
    from nodechain.runtime.batch_recovery import BatchExecutor
    from nodechain.runtime.recovery_policy import RecoveryAction
    _seed(sm, "r1", status="running")
    spec = BatchSpec(
        actions=[BatchAction(action=RecoveryAction.CANCEL_RUN, run_id="r1", reason="cancel")],
        operator_role="operator",
    )
    executor = BatchExecutor(service)
    summary = executor.execute(spec, dry_run=False)

    assert summary.mode == "execute"
    assert summary.results[0].status == "executed"
    assert sm.load("r1").status == "cancelled"
    assert summary.overall_status == "completed"


# --- batch summary counts ----------------------------------------------------

def test_batch_summary_counts_correct(service, sm) -> None:
    """Mixed admitted/denied batch reports correct counts."""
    from nodechain.runtime.batch_recovery import BatchExecutor
    from nodechain.runtime.recovery_policy import RecoveryAction
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
    summary = executor.execute(spec, dry_run=True, continue_on_error=True)

    assert summary.total_actions == 3
    assert summary.admitted_count == 2
    assert summary.denied_count == 1
    assert summary.skipped_count == 0
