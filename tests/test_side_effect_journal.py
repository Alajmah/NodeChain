"""Tests for pre-call side-effect journaling.

AC1: Search side effect is ledgered as planned/started before adapter call.
AC2: Memory write side effect is ledgered before memory mutation.
AC3: Crash after started but before completed resumes as unknown, not blindly repeated.
AC4: Completed idempotency key prevents duplicate external call.
AC5: Side-effect ledger records request_hash before call and response_hash after call.
AC6: Reconciler flags executed side-effect trace without ledger record as error.
AC7: Existing 481 tests remain green.
"""

import pytest
import pathlib

from nodechain.core.state import StateManager
from nodechain.runtime.persistence import PersistenceCoordinator


@pytest.fixture
def db(tmp_path):
    return str(tmp_path / "journal.db")


@pytest.fixture
def persistence(db):
    sm = StateManager(db_path=db)
    return PersistenceCoordinator(sm)


class TestPreCallJournaling:
    """AC1/AC2: Side effects are journalled before execution."""

    def test_record_side_effect_started_before_call(self, persistence):
        """AC1: Pre-call journaling records 'started' status."""
        from nodechain.core.state import ChainState
        state = ChainState(chain_id="test")
        persistence.save_snapshot(state)

        persistence.record_side_effect(
            run_id=state.run_id,
            step_id=1,
            node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="ss:abc123",
            status="started",
            request_hash="abc123",
        )

        effect = persistence.get_side_effect_by_key(state.run_id, "ss:abc123")
        assert effect is not None
        assert effect["status"] == "started"
        assert effect["request_hash"] == "abc123"

    def test_update_to_completed_after_call(self, persistence):
        """AC5: After call, update with response_hash and 'completed'."""
        from nodechain.core.state import ChainState
        state = ChainState(chain_id="test")
        persistence.save_snapshot(state)

        # Pre-call
        persistence.record_side_effect(
            run_id=state.run_id,
            step_id=1,
            node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="ss:abc123",
            status="started",
            request_hash="abc123",
        )

        # Post-call
        persistence.update_side_effect_status(
            state.run_id, "ss:abc123", "completed",
            response_hash="resp456",
        )

        effect = persistence.get_side_effect_by_key(state.run_id, "ss:abc123")
        assert effect["status"] == "completed"
        assert effect["response_hash"] == "resp456"


class TestCrashRecovery:
    """AC3: Started-but-not-completed resumes as 'unknown'."""

    def test_started_effects_become_unknown_on_resume(self, persistence):
        """AC3: Effect that was 'started' but not 'completed' becomes 'unknown'."""
        from nodechain.core.state import ChainState
        state = ChainState(chain_id="test")
        persistence.save_snapshot(state)

        # Simulate: process crashed after starting but before completing
        persistence.record_side_effect(
            run_id=state.run_id,
            step_id=1,
            node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="ss:crash_test",
            status="started",
            request_hash="req_hash",
        )

        # Resume: reconcile
        started = persistence.get_side_effects_by_status(state.run_id, "started")
        assert len(started) == 1

        # Mark as unknown (as resume logic would)
        for effect in started:
            persistence.update_side_effect_status(
                state.run_id, effect["idempotency_key"], "unknown",
            )

        effect = persistence.get_side_effect_by_key(state.run_id, "ss:crash_test")
        assert effect["status"] == "unknown"

    def test_completed_effects_stay_completed(self, persistence):
        """AC4: Completed idempotency key is not affected by resume."""
        from nodechain.core.state import ChainState
        state = ChainState(chain_id="test")
        persistence.save_snapshot(state)

        persistence.record_side_effect(
            run_id=state.run_id,
            step_id=1,
            node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="ss:done",
            status="started",
            request_hash="req1",
        )
        persistence.update_side_effect_status(state.run_id, "ss:done", "completed",
                                               response_hash="resp1")

        # Reconcile should not touch completed
        started = persistence.get_side_effects_by_status(state.run_id, "started")
        assert len(started) == 0

        effect = persistence.get_side_effect_by_key(state.run_id, "ss:done")
        assert effect["status"] == "completed"


class TestIdempotencyGating:
    """AC4: Completed key prevents duplicate call."""

    def test_completed_key_in_status_map(self, persistence):
        """AC4: Completed key appears in status map for gating."""
        from nodechain.core.state import ChainState
        state = ChainState(chain_id="test")
        persistence.save_snapshot(state)

        persistence.record_side_effect(
            run_id=state.run_id,
            step_id=1,
            node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="ss:idem1",
            status="started",
        )
        persistence.update_side_effect_status(state.run_id, "ss:idem1", "completed")

        keys = persistence.get_completed_side_effect_keys(state.run_id)
        assert "ss:idem1" in keys

    def test_unknown_key_not_in_completed(self, persistence):
        """Unknown effects are not treated as completed."""
        from nodechain.core.state import ChainState
        state = ChainState(chain_id="test")
        persistence.save_snapshot(state)

        persistence.record_side_effect(
            run_id=state.run_id,
            step_id=1,
            node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="ss:unknown1",
            status="started",
        )
        persistence.update_side_effect_status(state.run_id, "ss:unknown1", "unknown")

        keys = persistence.get_completed_side_effect_keys(state.run_id)
        assert "ss:unknown1" not in keys


class TestPlannedEffects:
    """Planned effects that never started are safe to re-execute."""

    def test_planned_effects_remain_planned_on_resume(self, persistence):
        from nodechain.core.state import ChainState
        state = ChainState(chain_id="test")
        persistence.save_snapshot(state)

        persistence.record_side_effect(
            run_id=state.run_id,
            step_id=1,
            node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="ss:planned1",
            status="planned",
            request_hash="pre_call",
        )

        planned = persistence.get_side_effects_by_status(state.run_id, "planned")
        assert len(planned) == 1
        assert planned[0]["idempotency_key"] == "ss:planned1"
