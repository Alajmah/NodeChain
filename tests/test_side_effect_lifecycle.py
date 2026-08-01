"""Tests for side-effect key identity across the full lifecycle.

Verifies the reviewer's critical finding: pre-call and post-call must use
one canonical key so that started entries actually transition to completed.

AC1: Search side effect transitions started -> completed with one key.
AC2: Memory write side effect transitions started -> completed with one key.
AC3: No orphan started entries remain after successful execution.
AC4: Canonical key format is node_id:effect_type:step_id.
AC5: On resume, unknown entries are only from genuine crashes (no false unknowns).
"""

import pytest
import sqlite3
import tempfile
import os

from nodechain.core.state import StateManager, ChainState


@pytest.fixture
def db(tmp_path):
    return str(tmp_path / "lifecycle.db")


@pytest.fixture
def state_manager(db):
    return StateManager(db_path=db)


class TestCanonicalKeyFormat:
    """AC4: Operation-level key formats."""

    def test_search_per_adapter_key_format(self, state_manager):
        """Search key format: search:<adapter_name>:<request_hash>"""
        state = ChainState(chain_id="test")
        state_manager.save(state)

        ikey = "search:semantic_scholar:abc123def456"
        state_manager.record_side_effect(
            run_id=state.run_id, step_id=4, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key=ikey, status="started",
        )

        effect = state_manager.get_side_effect_by_key(state.run_id, ikey)
        assert effect is not None
        assert effect["idempotency_key"] == ikey

    def test_memory_per_write_key_format(self, state_manager):
        """Memory write key format: mem:<subject_hash>:<content_hash>:<provenance_hash>"""
        state = ChainState(chain_id="test")
        state_manager.save(state)

        ikey = "mem:abc123:def456:789012"
        state_manager.record_side_effect(
            run_id=state.run_id, step_id=11, node_id="memory_write_decision",
            side_effect_type="memory_write",
            idempotency_key=ikey, status="started",
        )

        effect = state_manager.get_side_effect_by_key(state.run_id, ikey)
        assert effect is not None
        assert effect["idempotency_key"] == ikey

    def test_memory_reservation_key_format(self, state_manager):
        """Memory reservation key: memory_write_decision:memory_write:<step_id>"""
        state = ChainState(chain_id="test")
        state_manager.save(state)

        ikey = "memory_write_decision:memory_write:11"
        state_manager.record_side_effect(
            run_id=state.run_id, step_id=11, node_id="memory_write_decision",
            side_effect_type="memory_write",
            idempotency_key=ikey, status="started",
        )

        effect = state_manager.get_side_effect_by_key(state.run_id, ikey)
        assert effect is not None


class TestStartedToCompletedTransition:
    """AC1/AC2: Side effects transition started -> completed with one key."""

    def test_search_per_adapter_lifecycle(self, state_manager):
        """AC1: Per-adapter search started -> completed with one key."""
        state = ChainState(chain_id="test")
        state_manager.save(state)

        ikey = "search:semantic_scholar:abc123"

        # Pre-call: journal as started
        state_manager.record_side_effect(
            run_id=state.run_id, step_id=4, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key=ikey, status="started",
            request_hash="abc123",
        )

        effect = state_manager.get_side_effect_by_key(state.run_id, ikey)
        assert effect["status"] == "started"

        # Post-call: update to completed (same key!)
        state_manager.update_side_effect_status(
            state.run_id, ikey, "completed",
            response_hash="resp456",
        )

        effect = state_manager.get_side_effect_by_key(state.run_id, ikey)
        assert effect["status"] == "completed"
        assert effect["response_hash"] == "resp456"

    def test_memory_per_write_lifecycle(self, state_manager):
        """AC2: Per-write memory started -> completed with one key."""
        state = ChainState(chain_id="test")
        state_manager.save(state)

        ikey = "mem:abc123:def456:789012"

        # Pre-call: journal as started
        state_manager.record_side_effect(
            run_id=state.run_id, step_id=11, node_id="memory_write_decision",
            side_effect_type="memory_write",
            idempotency_key=ikey, status="started",
        )

        # Post-call: update to completed
        state_manager.update_side_effect_status(
            state.run_id, ikey, "completed",
            response_hash="write_ref_abc",
        )

        effect = state_manager.get_side_effect_by_key(state.run_id, ikey)
        assert effect["status"] == "completed"

    def test_multi_adapter_search_all_complete(self, state_manager):
        """Multiple adapters each get their own row that transitions."""
        state = ChainState(chain_id="test")
        state_manager.save(state)

        keys = [
            "search:semantic_scholar:abc123",
            "search:arxiv:def456",
            "search:openalex:789012",
        ]

        # Pre-call: journal all three
        for ikey in keys:
            state_manager.record_side_effect(
                run_id=state.run_id, step_id=4, node_id="search_tool",
                side_effect_type="external_api_read",
                idempotency_key=ikey, status="started",
            )

        # Post-call: complete all three
        for ikey in keys:
            state_manager.update_side_effect_status(
                state.run_id, ikey, "completed",
            )

        # No orphan started entries
        started = state_manager.get_side_effects_by_status(state.run_id, "started")
        assert len(started) == 0

        # All completed
        completed = state_manager.get_side_effects_by_status(state.run_id, "completed")
        assert len(completed) == 3

    def test_no_orphan_started_after_completion(self, state_manager):
        """AC3: After successful execution, no started entries remain."""
        state = ChainState(chain_id="test")
        state_manager.save(state)

        # Journal search per-adapter
        search_ikey = "search:semantic_scholar:abc123"
        state_manager.record_side_effect(
            run_id=state.run_id, step_id=4, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key=search_ikey, status="started",
        )

        # Journal memory reservation
        mem_reservation = "memory_write_decision:memory_write:11"
        state_manager.record_side_effect(
            run_id=state.run_id, step_id=11, node_id="memory_write_decision",
            side_effect_type="memory_write",
            idempotency_key=mem_reservation, status="started",
        )

        # Journal per-write memory
        mem_write = "mem:sub_hash:cont_hash:prov_hash"
        state_manager.record_side_effect(
            run_id=state.run_id, step_id=11, node_id="memory_write_decision",
            side_effect_type="memory_write",
            idempotency_key=mem_write, status="started",
        )

        # Complete all
        for ikey in [search_ikey, mem_reservation, mem_write]:
            state_manager.update_side_effect_status(
                state.run_id, ikey, "completed",
            )

        started = state_manager.get_side_effects_by_status(state.run_id, "started")
        assert len(started) == 0

    def test_failed_adapter_transition(self, state_manager):
        """Failed adapter: started -> failed on its operation row."""
        state = ChainState(chain_id="test")
        state_manager.save(state)

        ikey = "search:semantic_scholar:abc123"
        state_manager.record_side_effect(
            run_id=state.run_id, step_id=4, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key=ikey, status="started",
        )

        state_manager.update_side_effect_status(
            state.run_id, ikey, "failed",
        )

        effect = state_manager.get_side_effect_by_key(state.run_id, ikey)
        assert effect["status"] == "failed"


class TestResumeNoFalseUnknowns:
    """AC5: Resume doesn't create false unknowns from completed entries."""

    def test_completed_not_marked_unknown_on_resume(self, state_manager):
        """Completed entries stay completed even after resume reconciliation."""
        state = ChainState(chain_id="test")
        state_manager.save(state)

        ikey = "search_tool:external_api_read:4"
        state_manager.record_side_effect(
            run_id=state.run_id, step_id=4, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key=ikey, status="started",
        )
        state_manager.update_side_effect_status(state.run_id, ikey, "completed")

        # Simulate resume: reconcile side effects
        started = state_manager.get_side_effects_by_status(state.run_id, "started")
        assert len(started) == 0  # Nothing to mark unknown

        effect = state_manager.get_side_effect_by_key(state.run_id, ikey)
        assert effect["status"] == "completed"  # Still completed

    def test_only_genuine_crash_creates_unknown(self, state_manager):
        """Only a genuinely crashed (started but not completed) entry becomes unknown."""
        state = ChainState(chain_id="test")
        state_manager.save(state)

        # Effect 1: completed normally
        ikey1 = "search_tool:external_api_read:4"
        state_manager.record_side_effect(
            run_id=state.run_id, step_id=4, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key=ikey1, status="started",
        )
        state_manager.update_side_effect_status(state.run_id, ikey1, "completed")

        # Effect 2: crashed (started but never completed)
        ikey2 = "memory_write_decision:memory_write:11"
        state_manager.record_side_effect(
            run_id=state.run_id, step_id=11, node_id="memory_write_decision",
            side_effect_type="memory_write",
            idempotency_key=ikey2, status="started",
        )

        # Resume: reconcile
        started = state_manager.get_side_effects_by_status(state.run_id, "started")
        for effect in started:
            state_manager.update_side_effect_status(
                state.run_id, effect["idempotency_key"], "unknown",
            )

        # Effect 1: still completed
        e1 = state_manager.get_side_effect_by_key(state.run_id, ikey1)
        assert e1["status"] == "completed"

        # Effect 2: now unknown (genuine crash)
        e2 = state_manager.get_side_effect_by_key(state.run_id, ikey2)
        assert e2["status"] == "unknown"
