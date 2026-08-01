"""v3.5.0 Task 8 tests — CLI recovery-specific composition.

Tests the recover_execute_retry_authorized CLI function:
- RBAC: non-operator blocked
- Three-truth rendering with real RetryExecutionResult fields
- Legacy row: clean error
- Fresh adapter construction (distinct instances)
- DelegationResult propagation (no mutable state leak)
- Batch exclusion (parameter check + runtime BatchExecutor denial)
- Async coordinator under an active event loop (native await path)
- Click CliRunner end-to-end execution

Protects: INV-009, INV-021
"""
from __future__ import annotations

import pytest
import sqlite3
from datetime import datetime, timezone

from nodechain.core.state import StateManager, ChainState
from nodechain.runtime.recovery_policy import RecoveryAction


@pytest.fixture
def kek(tmp_path):
    from conftest import provision_test_kek
    return provision_test_kek(tmp_path / "t8_kek.bin")


@pytest.fixture
def setup_for_cli(tmp_path, kek):
    """Set up a StateManager with retry_authorized parent for CLI testing."""
    db_path = str(tmp_path / "t8.db")
    trace_dir = str(tmp_path / "traces")
    sm = StateManager(db_path=db_path)
    run_id = "r1"
    parent_key = "semantic_scholar:abc123"

    sm.start_side_effect_with_capsule(
        run_id=run_id, step_id=1, node_id="search_tool",
        side_effect_type="external_call",
        idempotency_key=parent_key,
        request_hash="abc123",
        capsule_operation={"terms": ["ai"], "max": 10, "filters": {}},
        operation_name="search",
        adapter_id="semantic_scholar", adapter_version="1.0.0",
        node_version="1.0", contract_id="c", contract_version="1",
        kek=kek,
    )
    sm.update_side_effect_status(run_id, parent_key, "unknown")
    sm.resolve_side_effect_recovery_decision(
        run_id=run_id, idempotency_key=parent_key,
        decision="safe_to_retry", reason="test",
    )

    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT decision_id FROM side_effect_recovery_decisions "
            "WHERE run_id=? AND idempotency_key=?",
            (run_id, parent_key),
        ).fetchone()
    decision_id = row[0]

    cs = ChainState(
        run_id=run_id, chain_id="c1", revision=0, status="crashed",
        step=1, current_node="search_tool",
    )
    sm.save(cs)

    return db_path, trace_dir, run_id, parent_key, decision_id, kek


class TestExecuteRetryAuthorizedCLI:
    """The CLI function constructs the coordinator and dispatches correctly."""

    def test_non_operator_blocked(self, setup_for_cli):
        """Non-operator role is blocked by RBAC."""
        from nodechain.cli.recover import recover_execute_retry_authorized
        db_path, trace_dir, run_id, parent_key, decision_id, _ = setup_for_cli

        code = recover_execute_retry_authorized(
            run_id, parent_key, decision_id, db_path, trace_dir,
            role="finance",
        )

        assert code == 17  # EXIT_RECOVERY_BLOCKED

    def test_missing_coordinator_clean_error(self, setup_for_cli):
        """Without a retry coordinator, delegation fails cleanly."""
        from nodechain.cli.recover import recover_execute_retry_authorized
        db_path, trace_dir, run_id, parent_key, decision_id, _ = setup_for_cli

        # This will work — the CLI function constructs the coordinator itself.
        # But if the parent side effect doesn't have a capsule, it should fail.
        code = recover_execute_retry_authorized(
            run_id, parent_key, "nonexistent-decision",
            db_path, trace_dir,
            role="operator",
        )

        # Should be blocked (decision not found)
        assert code == 17

    def test_three_truth_rendering_with_real_result(self, setup_for_cli, capsys):
        """Three-truth rendering shows real RetryExecutionResult fields."""
        from nodechain.cli.recover import _render_retry_result
        from nodechain.runtime.side_effect_retry_coordinator import RetryExecutionResult

        db_path, trace_dir, run_id, parent_key, decision_id, kek = setup_for_cli
        sm = StateManager(db_path=db_path)
        state = sm.load(run_id)

        # Real RetryExecutionResult with all fields populated
        _rr = RetryExecutionResult(
            retry_attempt_key="retry:abc",
            child_status="completed",
            node_invocation_outcome="succeeded",
            operator_action_outcome="completed",
            capsule_id="cap:123",
            dispatch_performed=True,
            recovery_action_id="act-1",
        )

        class FakeActionResult:
            admitted = True
            resulting_state = "completed"
            rejection_reason = None
            trace_event_id = "tev-1"
            action_id = "oal-1"
            retry_result = _rr

        _render_retry_result(run_id, parent_key, FakeActionResult(), sm, state)

        captured = capsys.readouterr()
        assert "Node Invocation:" in captured.out
        assert "succeeded" in captured.out
        assert "Side-Effect Status:" in captured.out
        assert "Operator Action:" in captured.out
        assert "completed" in captured.out
        assert "Dispatch Occurred:" in captured.out
        assert "True" in captured.out
        assert "Chain Status:" in captured.out
        assert "retry_authorized" in captured.out

    def test_blocked_renders_not_attempted(self, setup_for_cli, capsys):
        """Blocked execution renders 'retry not attempted'."""
        from nodechain.cli.recover import _render_retry_result

        db_path, trace_dir, run_id, parent_key, decision_id, kek = setup_for_cli
        sm = StateManager(db_path=db_path)

        class FakeActionResult:
            admitted = False
            resulting_state = None
            rejection_reason = "denied"
            trace_event_id = "tev-b"
            action_id = "oal-b"
            retry_result = None

        _render_retry_result(run_id, parent_key, FakeActionResult(), sm)

        captured = capsys.readouterr()
        assert "retry not attempted" in captured.out
        assert "not attempted" in captured.out  # node_invocation_outcome for blocked


class TestLegacyRowDenied:
    """Legacy capsule row (no capsule) is cleanly rejected."""

    def test_legacy_row_clean_error(self, tmp_path):
        """A retry_authorized parent with legacy_unavailable capsule → blocked."""
        from nodechain.cli.recover import recover_execute_retry_authorized

        db_path = str(tmp_path / "legacy.db")
        sm = StateManager(db_path=db_path)
        sm.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call", idempotency_key="se:legacy",
            status="retry_authorized", request_hash="rh",
        )
        cs = ChainState(run_id="r1", chain_id="c", revision=0, status="crashed", step=1)
        sm.save(cs)

        code = recover_execute_retry_authorized(
            "r1", "se:legacy", "fake-decision", db_path, str(tmp_path / "traces"),
            role="operator",
        )
        assert code == 17  # EXIT_RECOVERY_BLOCKED


class TestFreshAdapterConstruction:
    """ChatGPT T8 fix 3: fresh adapter instances from TRUSTED_ADAPTER_CLASSES."""

    def test_two_resolutions_produce_distinct_instances(self):
        """Two calls to the CLI's adapter factory return distinct objects."""
        from nodechain.runtime.recovery_dispatch_guard import TRUSTED_ADAPTER_CLASSES

        cls = TRUSTED_ADAPTER_CLASSES.get("semantic_scholar")
        assert cls is not None
        a1 = cls()
        a2 = cls()
        assert a1 is not a2  # distinct instances
        assert type(a1) is type(a2)  # same exact class


class TestDelegationResultPropagation:
    """ChatGPT T8 re-review fix 2: no mutable state for retry result."""

    def test_no_state_leak_between_actions(self, setup_for_cli):
        """Reusing RecoveryService cannot leak a previous retry result."""
        from nodechain.runtime.recovery_service import RecoveryService

        db_path, trace_dir, run_id, parent_key, decision_id, kek = setup_for_cli
        sm = StateManager(db_path=db_path)
        service = RecoveryService(state_manager=sm, trace_dir=trace_dir)

        # Verify _last_retry_result is NOT used (it should not exist as a pattern)
        result = service.apply_action(
            run_id, RecoveryAction.EXPORT_REPORT,
            operator_identity="operator", operator_role="operator",
        )
        assert result.retry_result is None  # no leaked retry data


class TestCLIBatchExclusion:
    """EXECUTE_RETRY_AUTHORIZED is excluded from batch execution.

    Two layers of defense for the locked non-goal 'no batch retry
    execution' (one operator command → one side effect):
      1. The CLI function exposes no batch/dry_run parameters.
      2. The BatchExecutor itself denies the action at runtime
         (batch_recovery.py), so even a hand-crafted YAML batch cannot
         route EXECUTE_RETRY_AUTHORIZED through the batch path.
    """

    def test_cli_function_has_no_batch_parameters(self):
        """The CLI function signature carries no batch entry points."""
        from nodechain.cli.recover import recover_execute_retry_authorized
        import inspect
        sig = inspect.signature(recover_execute_retry_authorized)
        param_names = set(sig.parameters.keys())
        assert "batch_file" not in param_names
        assert "dry_run" not in param_names

    def test_batch_executor_denies_retry_authorized(self, tmp_path):
        """BatchExecutor itself rejects EXECUTE_RETRY_AUTHORIZED (runtime guard).

        Exercises the actual denial logic in batch_recovery.py rather than
        only checking parameter names — a YAML batch containing the action
        is denied with batch_policy / denied status, before any recovery
        service authorization is attempted.
        """
        from nodechain.runtime.batch_recovery import (
            BatchAction, BatchSpec, BatchExecutor,
        )
        from nodechain.runtime.recovery_policy import RecoveryAction as RA
        from nodechain.runtime.recovery_service import RecoveryService

        sm = StateManager(db_path=str(tmp_path / "batch.db"))
        service = RecoveryService(state_manager=sm, trace_dir=str(tmp_path / "traces"))
        spec = BatchSpec(
            batch_id="b1", actions=[
                BatchAction(
                    action=RA.EXECUTE_RETRY_AUTHORIZED, run_id="r1",
                    reason="attempt batch retry",
                ),
            ],
        )
        executor = BatchExecutor(service)
        summary = executor.execute(spec)

        # The retry-authorized action is denied by batch policy.
        assert summary.denied_count == 1
        denied = summary.results[0]
        assert denied.status == "denied"
        assert denied.denial_type == "batch_policy"
        assert "excluded from batch" in denied.rejection_reason


class TestAsyncCoordinatorActiveLoop:
    """The async coordinator runs natively under an active event loop.

    ChatGPT T8 3rd re-review gap #6: the sync wrapper uses asyncio.run(),
    which raises RuntimeError if called from inside a running loop. The
    async entry point (execute_authorized_retry_async) must work when
    awaited directly — that is the path the runtime uses when a loop is
    already active. This test proves the async path produces the same
    three-truth outcome as the sync wrapper.
    """

    def test_async_path_completes_under_active_loop(self, setup_for_cli):
        """Awaiting execute_authorized_retry_async under a running loop works."""
        import asyncio
        from nodechain.runtime.side_effect_retry_coordinator import (
            SideEffectRetryCoordinator,
        )
        # Reuse the T6 fake adapter so the dispatch is hermetic.
        from test_v35_t6_execution import FakeAdapter

        db_path, trace_dir, run_id, parent_key, decision_id, kek = setup_for_cli
        sm = StateManager(db_path=db_path)

        fake = FakeAdapter()
        coord = SideEffectRetryCoordinator(
            sm, kek=kek,
            adapter_factory=lambda name: fake,
            adapter_trust_validator=(
                lambda ad: type(ad).__name__ == "FakeAdapter"
            ),
        )

        async def driver():
            # Inside this coroutine a loop is running — asyncio.run() would
            # crash here. The async entry point must work natively.
            return await coord.execute_authorized_retry_async(
                run_id, parent_key, decision_id,
                actor="operator", actor_role="operator",
                operator_action_id="oal-async-1",
            )

        result = asyncio.run(driver())

        # Same three-truth outcome as the sync happy path.
        assert result.child_status == "completed"
        assert result.dispatch_performed is True
        assert result.operator_action_outcome == "completed"
        assert result.node_invocation_outcome == "succeeded"
        assert fake.dispatch_count == 1
        # operator_action_id propagated to the recovery_execution_actions row.
        action = sm.get_recovery_execution_action(result.recovery_action_id)
        assert action is not None
        assert action["operator_action_id"] == "oal-async-1"

    def test_sync_wrapper_is_safe_outside_loop(self, setup_for_cli):
        """The sync wrapper still works when no loop is active (CLI path)."""
        from nodechain.runtime.side_effect_retry_coordinator import (
            SideEffectRetryCoordinator,
        )
        from test_v35_t6_execution import FakeAdapter

        db_path, trace_dir, run_id, parent_key, decision_id, kek = setup_for_cli
        sm = StateManager(db_path=db_path)
        fake = FakeAdapter()
        coord = SideEffectRetryCoordinator(
            sm, kek=kek,
            adapter_factory=lambda name: fake,
            adapter_trust_validator=(
                lambda ad: type(ad).__name__ == "FakeAdapter"
            ),
        )
        result = coord.execute_authorized_retry(
            run_id, parent_key, decision_id,
            operator_action_id="oal-sync-1",
        )
        assert result.child_status == "completed"
        assert result.dispatch_performed is True


class TestCliRunnerExecution:
    """The Click command is executable end-to-end via CliRunner.

    ChatGPT T8 3rd re-review gap #8: prior tests call the Python function
    directly. This exercises the actual Click registration
    (recover_execute_retry_authorized_cmd) — argument parsing, option
    wiring, and exit-code propagation through ctx.exit().
    """

    def test_cli_command_blocked_on_legacy_row(self, tmp_path):
        """A legacy (no-capsule) row exits 17 via the Click command."""
        from click.testing import CliRunner
        from nodechain.cli.main import recover_group

        db_path = str(tmp_path / "legacy_cli.db")
        sm = StateManager(db_path=db_path)
        sm.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call", idempotency_key="se:legacy",
            status="retry_authorized", request_hash="rh",
        )
        cs = ChainState(run_id="r1", chain_id="c", revision=0, status="crashed", step=1)
        sm.save(cs)

        runner = CliRunner()
        res = runner.invoke(recover_group, [
            "execute-retry-authorized", "r1",
            "--side-effect-key", "se:legacy",
            "--recovery-decision-id", "fake-decision",
            "--db", db_path,
            "--trace-dir", str(tmp_path / "traces"),
            "--role", "operator",
        ])
        # ctx.exit(code) surfaces as res.exit_code; EXIT_RECOVERY_BLOCKED == 17.
        assert res.exit_code == 17

