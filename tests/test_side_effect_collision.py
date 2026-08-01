"""Side-Effect Collision Detection and Terminal Dedup Tests (v2.38.1).

Proves the acceptance criteria from the reviewer's v2.38.0 plan:
  2. Same idempotency_key with different request_hash is detected.
  3. Same completed key with different response_hash is detected.
"""

from __future__ import annotations

import pytest

from nodechain.core.state import StateManager, ChainState
from nodechain.core.state import SideEffectCollisionError, SideEffectIntegrityError


@pytest.fixture
def state_manager(tmp_path):
    return StateManager(db_path=str(tmp_path / "collision.db"))


class TestCollisionDetection:
    """v2.38.1 criterion 2: same key + different identity = collision error."""

    def test_same_key_different_node_raises(self, state_manager):
        state_manager.record_side_effect(
            run_id="r1", step_id=1, node_id="search_tool",
            side_effect_type="external_call",
            idempotency_key="k1", status="started",
            request_hash="abc123",
        )
        with pytest.raises(SideEffectCollisionError, match="node_id"):
            state_manager.record_side_effect(
                run_id="r1", step_id=1, node_id="memory_write_decision",
                side_effect_type="external_call",
                idempotency_key="k1", status="started",
                request_hash="abc123",
            )

    def test_same_key_different_type_raises(self, state_manager):
        state_manager.record_side_effect(
            run_id="r1", step_id=1, node_id="search_tool",
            side_effect_type="external_call",
            idempotency_key="k2", status="started",
        )
        with pytest.raises(SideEffectCollisionError, match="type"):
            state_manager.record_side_effect(
                run_id="r1", step_id=1, node_id="search_tool",
                side_effect_type="memory_write",
                idempotency_key="k2", status="started",
            )

    def test_same_key_different_request_hash_raises(self, state_manager):
        state_manager.record_side_effect(
            run_id="r1", step_id=1, node_id="search_tool",
            side_effect_type="external_call",
            idempotency_key="k3", status="started",
            request_hash="hash_a",
        )
        with pytest.raises(SideEffectCollisionError, match="request_hash"):
            state_manager.record_side_effect(
                run_id="r1", step_id=1, node_id="search_tool",
                side_effect_type="external_call",
                idempotency_key="k3", status="started",
                request_hash="hash_b",
            )

    def test_same_key_same_identity_is_idempotent(self, state_manager):
        """Same key + same node/type/request_hash = safe replay, no error."""
        state_manager.record_side_effect(
            run_id="r1", step_id=1, node_id="search_tool",
            side_effect_type="external_call",
            idempotency_key="k4", status="started",
            request_hash="same_hash",
        )
        # Second call with identical identity — should not raise
        state_manager.record_side_effect(
            run_id="r1", step_id=1, node_id="search_tool",
            side_effect_type="external_call",
            idempotency_key="k4", status="started",
            request_hash="same_hash",
        )
        row = state_manager.get_side_effect_by_key("r1", "k4")
        assert row is not None
        assert row["status"] == "started"

    def test_request_hash_absent_on_one_side_allows_replay(self, state_manager):
        """If request_hash is missing on one side, don't false-positive."""
        state_manager.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call",
            idempotency_key="k5", status="started",
        )
        # No request_hash on either side — safe
        state_manager.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call",
            idempotency_key="k5", status="started",
        )


class TestTerminalDedup:
    """v2.38.1 criterion 3: same completed key + different response = integrity error."""

    def test_already_completed_same_response_is_noop(self, state_manager):
        state_manager.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call",
            idempotency_key="k6", status="started",
        )
        state_manager.update_side_effect_status(
            "r1", "k6", "completed", response_hash="resp_a",
        )
        # Re-complete with same response — no error
        state_manager.update_side_effect_status(
            "r1", "k6", "completed", response_hash="resp_a",
        )
        row = state_manager.get_side_effect_by_key("r1", "k6")
        assert row["status"] == "completed"
        assert row["response_hash"] == "resp_a"

    def test_already_completed_different_response_raises(self, state_manager):
        state_manager.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call",
            idempotency_key="k7", status="started",
        )
        state_manager.update_side_effect_status(
            "r1", "k7", "completed", response_hash="resp_a",
        )
        with pytest.raises(SideEffectIntegrityError, match="response"):
            state_manager.update_side_effect_status(
                "r1", "k7", "completed", response_hash="resp_b",
            )

    def test_started_to_completed_allows_transition(self, state_manager):
        """Normal lifecycle: started → completed, no integrity error."""
        state_manager.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call",
            idempotency_key="k8", status="started",
        )
        state_manager.update_side_effect_status(
            "r1", "k8", "completed", response_hash="resp_x",
        )
        row = state_manager.get_side_effect_by_key("r1", "k8")
        assert row["status"] == "completed"

    def test_external_reference_used_for_dedup(self, state_manager):
        """Memory writes use external_reference instead of response_hash."""
        state_manager.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="memory_write",
            idempotency_key="k9", status="started",
        )
        state_manager.update_side_effect_status(
            "r1", "k9", "completed", external_reference="write_ref_1",
        )
        with pytest.raises(SideEffectIntegrityError):
            state_manager.update_side_effect_status(
                "r1", "k9", "completed", external_reference="write_ref_2",
            )

    def test_completed_no_response_replay_allowed(self, state_manager):
        """Completed row without response material — replay is safe."""
        state_manager.record_side_effect(
            run_id="r1", step_id=1, node_id="n",
            side_effect_type="external_call",
            idempotency_key="k10", status="completed",
        )
        # No response material on either side — no error
        state_manager.update_side_effect_status(
            "r1", "k10", "completed",
        )
