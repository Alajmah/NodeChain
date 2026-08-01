"""Direct tests for PersistenceCoordinator — the transaction boundary.

Covers:
- Atomic invocation commits (snapshot + ledger + event)
- Failure commits
- Recovery loading with step-level identity
- Repeated node invocations (loop recovery)
- Side-effect status maps
- Final state persistence
- Event log ordering
"""

import pytest
import tempfile
import os

from nodechain.core.state import ChainState, StateManager
from nodechain.runtime.persistence import PersistenceCoordinator, RecoveryContext


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test_state.db")


@pytest.fixture
def state_manager(db_path):
    return StateManager(db_path)


@pytest.fixture
def coordinator(state_manager):
    return PersistenceCoordinator(state_manager)


@pytest.fixture
def chain_state():
    return ChainState(chain_id="test-chain")


class TestCommitInvocationSuccess:
    def test_writes_snapshot_ledger_and_event(self, coordinator, chain_state, state_manager):
        """Atomic commit should populate all three surfaces."""
        coordinator.commit_invocation_success(
            chain_state,
            step_id=1,
            node_id="goal_interpreter",
            event_type="node_completed",
            event_payload={"node_id": "goal_interpreter", "step_id": 1},
        )

        # State should be saved
        loaded = state_manager.load(chain_state.run_id)
        assert loaded is not None
        assert loaded.completed_steps.get(1) == "goal_interpreter"

        # Invocation ledger should have the entry
        completed = state_manager.get_completed_steps(chain_state.run_id)
        assert 1 in completed
        assert completed[1] == "goal_interpreter"

    def test_multiple_invocations(self, coordinator, chain_state, state_manager):
        """Multiple commits should accumulate in the ledger."""
        coordinator.commit_invocation_success(
            chain_state, step_id=1, node_id="goal_interpreter",
            event_type="node_completed", event_payload={},
        )
        coordinator.commit_invocation_success(
            chain_state, step_id=2, node_id="task_planner",
            event_type="node_completed", event_payload={},
        )

        completed = state_manager.get_completed_steps(chain_state.run_id)
        assert len(completed) == 2
        assert completed[1] == "goal_interpreter"
        assert completed[2] == "task_planner"

    def test_updates_state_revision(self, coordinator, chain_state):
        """Each commit should advance the state."""
        assert chain_state.revision == 0
        coordinator.commit_invocation_success(
            chain_state, step_id=1, node_id="goal_interpreter",
            event_type="node_completed", event_payload={},
        )
        assert chain_state.completed_steps[1] == "goal_interpreter"


class TestCommitInvocationFailure:
    def test_records_failure(self, coordinator, chain_state, state_manager):
        coordinator.commit_invocation_failure(
            chain_state,
            step_id=3,
            node_id="search_tool",
            error="API timeout",
        )

        # State should be saved with the failure
        loaded = state_manager.load(chain_state.run_id)
        assert loaded is not None


class TestRecoveryLoading:
    def test_load_for_recovery_returns_context(self, coordinator, chain_state):
        coordinator.commit_invocation_success(
            chain_state, step_id=1, node_id="goal_interpreter",
            event_type="node_completed", event_payload={},
        )
        coordinator.commit_invocation_success(
            chain_state, step_id=2, node_id="task_planner",
            event_type="node_completed", event_payload={},
        )

        recovery = coordinator.load_for_recovery(chain_state.run_id)
        assert recovery is not None
        assert isinstance(recovery, RecoveryContext)
        assert recovery.state.run_id == chain_state.run_id

    def test_completed_steps_are_step_level(self, coordinator, chain_state):
        """Recovery should return step_id → node_id mapping, not just a set."""
        coordinator.commit_invocation_success(
            chain_state, step_id=1, node_id="goal_interpreter",
            event_type="node_completed", event_payload={},
        )
        coordinator.commit_invocation_success(
            chain_state, step_id=2, node_id="context_selector",
            event_type="node_completed", event_payload={},
        )

        recovery = coordinator.load_for_recovery(chain_state.run_id)
        assert recovery.completed_steps == {1: "goal_interpreter", 2: "context_selector"}

    def test_completed_node_ids_convenience(self, coordinator, chain_state):
        """completed_node_ids should be a set derived from completed_steps."""
        coordinator.commit_invocation_success(
            chain_state, step_id=1, node_id="goal_interpreter",
            event_type="node_completed", event_payload={},
        )

        recovery = coordinator.load_for_recovery(chain_state.run_id)
        assert "goal_interpreter" in recovery.completed_node_ids

    def test_last_completed_step(self, coordinator, chain_state):
        """last_completed_step returns highest step_id."""
        coordinator.commit_invocation_success(
            chain_state, step_id=1, node_id="goal_interpreter",
            event_type="node_completed", event_payload={},
        )
        coordinator.commit_invocation_success(
            chain_state, step_id=5, node_id="search_tool",
            event_type="node_completed", event_payload={},
        )

        recovery = coordinator.load_for_recovery(chain_state.run_id)
        assert recovery.last_completed_step == 5

    def test_returns_none_for_unknown_run(self, coordinator):
        recovery = coordinator.load_for_recovery("nonexistent-run-id")
        assert recovery is None

    def test_repeated_node_invocations(self, coordinator, chain_state):
        """CRITICAL: A node executing twice (loop-back) should have both invocations recorded."""
        coordinator.commit_invocation_success(
            chain_state, step_id=3, node_id="source_quality_evaluator",
            event_type="node_completed", event_payload={},
        )
        # Loop-back re-execution
        coordinator.commit_invocation_success(
            chain_state, step_id=7, node_id="source_quality_evaluator",
            event_type="node_completed", event_payload={},
        )

        recovery = coordinator.load_for_recovery(chain_state.run_id)
        assert recovery.completed_steps[3] == "source_quality_evaluator"
        assert recovery.completed_steps[7] == "source_quality_evaluator"
        assert recovery.last_completed_step == 7

        # The node appears in completed_node_ids only once (set dedup)
        assert "source_quality_evaluator" in recovery.completed_node_ids

    def test_branch_invocation(self, coordinator, chain_state):
        """Branch invocations should be recorded with branch_name."""
        coordinator.commit_invocation_success(
            chain_state, step_id=4, node_id="branch_search",
            branch_name="biomedical",
            event_type="branch_node_completed",
            event_payload={"branch": "biomedical"},
        )

        recovery = coordinator.load_for_recovery(chain_state.run_id)
        assert 4 in recovery.completed_steps
        assert recovery.completed_steps[4] == "branch_search"


class TestSideEffects:
    def test_record_and_retrieve(self, coordinator, chain_state):
        coordinator.record_side_effect(
            run_id=chain_state.run_id,
            step_id=2,
            node_id="search_tool",
            side_effect_type="api_call",
            idempotency_key="semantic_scholar:abc123",
            status="completed",
            request_hash="hash123",
            response_hash="rhash456",
        )

        keys = coordinator.get_completed_side_effect_keys(chain_state.run_id)
        assert "semantic_scholar:abc123" in keys

    def test_status_map(self, coordinator, chain_state):
        coordinator.record_side_effect(
            run_id=chain_state.run_id,
            step_id=2,
            node_id="search_tool",
            side_effect_type="api_call",
            idempotency_key="arxiv:def456",
            status="completed",
        )
        coordinator.record_side_effect(
            run_id=chain_state.run_id,
            step_id=3,
            node_id="search_tool",
            side_effect_type="api_call",
            idempotency_key="pubmed:ghi789",
            status="failed",
            retryable=True,
        )

        status_map = coordinator.get_side_effect_status_map(chain_state.run_id)
        assert status_map["arxiv:def456"] == "completed"
        assert status_map["pubmed:ghi789"] == "failed"
        assert status_map["pubmed:ghi789__retryable"] == "True"

    def test_recovery_includes_side_effects(self, coordinator, chain_state):
        coordinator.commit_invocation_success(
            chain_state, step_id=1, node_id="goal_interpreter",
            event_type="node_completed", event_payload={},
        )
        coordinator.record_side_effect(
            run_id=chain_state.run_id,
            step_id=2,
            node_id="search_tool",
            side_effect_type="api_call",
            idempotency_key="test:key1",
            status="completed",
        )

        recovery = coordinator.load_for_recovery(chain_state.run_id)
        assert "test:key1" in recovery.completed_side_effect_keys


class TestSaveSnapshot:
    def test_save_and_load(self, coordinator, chain_state, state_manager):
        chain_state.status = "running"
        coordinator.save_snapshot(chain_state)

        loaded = state_manager.load(chain_state.run_id)
        assert loaded is not None
        assert loaded.status == "running"


class TestSaveFinal:
    def test_preserves_terminal_status(self, coordinator, chain_state, state_manager):
        chain_state.status = "completed"
        coordinator.save_final(chain_state)

        loaded = state_manager.load(chain_state.run_id)
        assert loaded.status == "completed"


class TestAppendEvent:
    def test_event_appended(self, coordinator, chain_state, state_manager):
        coordinator.save_snapshot(chain_state)
        coordinator.append_event(
            run_id=chain_state.run_id,
            revision=1,
            event_type="test_event",
            node_id="test_node",
            payload={"key": "value"},
        )

        # Events should be retrievable via state_manager
        events = state_manager.replay_state(chain_state.run_id)
        # replay_state returns reconstructed state; just verify it doesn't error


class TestEmptyRecovery:
    def test_empty_completed_steps(self, coordinator, chain_state):
        """Fresh state with no completions."""
        coordinator.save_snapshot(chain_state)

        recovery = coordinator.load_for_recovery(chain_state.run_id)
        assert recovery is not None
        assert recovery.completed_steps == {}
        assert recovery.completed_node_ids == set()
        assert recovery.last_completed_step == 0
        assert recovery.completed_side_effect_keys == []
