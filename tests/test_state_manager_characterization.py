"""v2.81 — StateManager Characterization Harness.

Freezes the persistence surface BEFORE any future store extraction. These tests
assert observable persistence behavior (table presence, write/read contracts,
ledger semantics, resume/recovery paths) — NOT private implementation details.

The goal: if a future StateManager extraction changes any table name, column,
write contract, or read path, these tests fail. That makes store extraction
safe without audit drift.

Test style: temp SQLite databases via tmp_path. No :memory: (StateManager opens
a fresh connection per call, so :memory: creates a new private DB each time).
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from nodechain.core.state import StateManager, ChainState
from nodechain.runtime.persistence import PersistenceCoordinator


# ─── Fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture
def db_path(tmp_path) -> str:
    return str(tmp_path / "test_characterization.db")


@pytest.fixture
def sm(db_path) -> StateManager:
    return StateManager(db_path=db_path)


@pytest.fixture
def coord(sm) -> PersistenceCoordinator:
    return PersistenceCoordinator(sm)


@pytest.fixture
def state() -> ChainState:
    return ChainState(chain_id="test-chain", run_id="test-run-001")


# ─── 1. Table presence / schema initialization ─────────────────────────────

class TestSchemaInitialization:
    """StateManager must create all required tables on initialization."""

    REQUIRED_TABLES = [
        "chain_states",
        "state_events",
        "invocation_ledger",
        "side_effect_ledger",
        "review_decision_attempts",
        "operator_action_log",
        "memory_decisions",
        "side_effect_blocked_attempts",
        "side_effect_recovery_decisions",
        "memory_read_decisions",
        "tool_access_decisions",
        "adapter_access_decisions",
        "package_trust_decisions",
        "registry_admission_decisions",
    ]

    def test_state_manager_creates_all_required_tables(self, db_path):
        """Construction must create all 14 tables."""
        StateManager(db_path=db_path)
        conn = sqlite3.connect(db_path)
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        table_names = {r[0] for r in rows}
        conn.close()
        for table in self.REQUIRED_TABLES:
            assert table in table_names, f"missing required table: {table}"

    def test_chain_states_has_required_columns(self, db_path):
        StateManager(db_path=db_path)
        conn = sqlite3.connect(db_path)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(chain_states)")}
        conn.close()
        assert {"run_id", "state_json", "revision", "updated_at"} <= cols

    def test_invocation_ledger_has_required_columns(self, db_path):
        StateManager(db_path=db_path)
        conn = sqlite3.connect(db_path)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(invocation_ledger)")}
        conn.close()
        assert {"run_id", "step_id", "node_id", "status", "cost_usd", "timestamp"} <= cols

    def test_side_effect_ledger_has_required_columns(self, db_path):
        StateManager(db_path=db_path)
        conn = sqlite3.connect(db_path)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(side_effect_ledger)")}
        conn.close()
        required = {
            "run_id", "step_id", "node_id", "side_effect_type",
            "idempotency_key", "status", "request_hash", "response_hash",
            "retryable", "timestamp",
        }
        assert required <= cols


# ─── 2. Chain state lifecycle writes ───────────────────────────────────────

class TestChainStateLifecycle:
    """save/load must round-trip ChainState with revision increment."""

    def test_save_persists_state_loadable_by_run_id(self, sm, state):
        sm.save(state)
        loaded = sm.load("test-run-001")
        assert loaded is not None
        assert loaded.run_id == "test-run-001"
        assert loaded.chain_id == "test-chain"

    def test_save_increments_revision(self, sm, state):
        assert state.revision == 0
        sm.save(state)
        assert state.revision == 1
        sm.save(state)
        assert state.revision == 2

    def test_load_nonexistent_run_returns_none(self, sm):
        assert sm.load("nonexistent-run") is None


# ─── 3. Invocation ledger ──────────────────────────────────────────────────

class TestInvocationLedger:
    """Invocation ledger records node execution identity."""

    def test_save_with_invocation_records_step_and_node(self, sm, state):
        sm.save_with_invocation(
            state, step_id=1, node_id="test_node",
            invocation_status="completed",
        )
        steps = sm.get_completed_steps("test-run-001")
        assert 1 in steps
        assert steps[1] == "test_node"

    def test_is_step_completed_after_save(self, sm, state):
        sm.save_with_invocation(state, step_id=1, node_id="node_a")
        assert sm.is_step_completed("test-run-001", 1)
        assert not sm.is_step_completed("test-run-001", 2)

    def test_invocation_ledger_records_cost(self, sm, state):
        sm.save_with_invocation(
            state, step_id=1, node_id="model_node", cost_usd=0.05,
        )
        cost = sm.get_invocation_cost("test-run-001")
        assert cost == pytest.approx(0.05)


# ─── 4. Side-effect ledger ─────────────────────────────────────────────────

class TestSideEffectLedger:
    """Side-effect ledger records declared → started → completed lifecycle."""

    def test_record_side_effect_default_status_planned(self, sm):
        sm.record_side_effect(
            run_id="test-run-001", step_id=1, node_id="search_node",
            side_effect_type="external_api_read",
            idempotency_key="search:test:abc123",
        )
        se = sm.get_side_effect_by_key("test-run-001", "search:test:abc123")
        assert se is not None
        assert se["status"] == "planned"

    def test_update_side_effect_to_started(self, sm):
        sm.record_side_effect(
            run_id="test-run-001", step_id=1, node_id="search_node",
            side_effect_type="external_api_read",
            idempotency_key="search:test:abc123",
        )
        sm.update_side_effect_status(
            "test-run-001", "search:test:abc123", "started",
        )
        se = sm.get_side_effect_by_key("test-run-001", "search:test:abc123")
        assert se["status"] == "started"

    def test_update_side_effect_to_completed(self, sm):
        sm.record_side_effect(
            run_id="test-run-001", step_id=1, node_id="search_node",
            side_effect_type="external_api_read",
            idempotency_key="search:test:abc123",
            status="started",
        )
        sm.update_side_effect_status(
            "test-run-001", "search:test:abc123", "completed",
            response_hash="hash123",
        )
        se = sm.get_side_effect_by_key("test-run-001", "search:test:abc123")
        assert se["status"] == "completed"
        assert se["response_hash"] == "hash123"

    def test_side_effect_idempotent_same_key_no_duplicate(self, sm):
        """Recording the same (run_id, idempotency_key) twice is idempotent."""
        for _ in range(2):
            sm.record_side_effect(
                run_id="test-run-001", step_id=1, node_id="search_node",
                side_effect_type="external_api_read",
                idempotency_key="search:test:abc123",
            )
        ses = sm.get_side_effects("test-run-001")
        assert len(ses) == 1


# ─── 5. Side-effect recovery (resume path) ─────────────────────────────────

class TestSideEffectRecovery:
    """Started-but-not-completed side effects are recoverable on resume."""

    def test_started_side_effects_visible_by_status(self, sm):
        sm.record_side_effect(
            run_id="test-run-001", step_id=1, node_id="node_a",
            side_effect_type="external_call",
            idempotency_key="key1", status="started",
        )
        started = sm.get_side_effects_by_status("test-run-001", "started")
        assert len(started) == 1
        assert started[0]["idempotency_key"] == "key1"

    def test_planned_side_effects_safe_to_reexecute(self, sm):
        sm.record_side_effect(
            run_id="test-run-001", step_id=1, node_id="node_a",
            side_effect_type="external_call",
            idempotency_key="key1", status="planned",
        )
        planned = sm.get_side_effects_by_status("test-run-001", "planned")
        assert len(planned) == 1


# ─── 6. Decision durability ────────────────────────────────────────────────

class TestDecisionDurability:
    """Policy/tool/adapter/memory/operator decisions are durable."""

    def test_operator_action_durable(self, sm):
        sm.record_operator_action({
            "action_id": "act-1", "run_id": "test-run-001",
            "action": "pause", "actor_identity": "operator@example.com",
            "requested_at": "2026-01-01T00:00:00Z", "admitted": True,
        })
        actions = sm.get_operator_actions(run_id="test-run-001")
        assert len(actions) == 1
        assert actions[0]["action"] == "pause"
        assert actions[0]["admitted"] is True

    def test_review_attempt_durable(self, sm):
        sm.record_review_attempt({
            "review_attempt_id": "rev-1", "run_id": "test-run-001",
            "chain_id": "test-chain", "step_id": 1, "request_id": "req-1",
            "request_digest": "abc", "subject_type": "memory_write",
            "subject_id": "sub-1", "attempted_decision_type": "allow",
            "attempted_outcome": "admitted", "reviewer_identity": "reviewer",
            "required_reviewer_role": "operator", "admitted": True,
            "policy_digest": "pol-1", "graph_digest": "graph-1",
            "created_at": "2026-01-01T00:00:00Z",
        })
        attempts = sm.get_review_attempts(run_id="test-run-001")
        assert len(attempts) == 1
        assert attempts[0]["review_attempt_id"] == "rev-1"

    def test_memory_decision_durable(self, sm):
        sm.record_memory_decision({
            "memory_decision_id": "mem-1", "run_id": "test-run-001",
            "chain_id": "test-chain", "step_id": 1, "node_id": "memory_write",
            "candidate_id": "cand-1", "subject": "test", "subject_digest": "d1",
            "candidate_digest": "d2", "confidence": 0.8, "sensitivity": "low",
            "policy_id": "pol-1", "rule_id": "rule-1", "decision": "allow",
            "reason_code": "low_sensitivity", "write_ref": "ref-1",
            "created_at": "2026-01-01T00:00:00Z",
        })
        decisions = sm.get_memory_decisions(run_id="test-run-001")
        assert len(decisions) == 1
        assert decisions[0]["decision"] == "allow"

    def test_tool_access_decision_durable(self, sm):
        sm.record_tool_access_decision({
            "decision_id": "tool-1", "run_id": "test-run-001",
            "step_id": 1, "node_id": "tool_node", "tool_name": "web_search",
            "policy_id": "pol-1", "rule_id": "rule-1", "decision": "allow",
            "reason": "permitted", "created_at": "2026-01-01T00:00:00Z",
        })
        decisions = sm.get_tool_access_decisions(run_id="test-run-001")
        assert len(decisions) == 1
        assert decisions[0]["tool_name"] == "web_search"


# ─── 7. Resume reads latest materialized state ─────────────────────────────

class TestResumeReadsMaterializedState:
    """load_for_recovery reads the latest snapshot + completed steps + side effects."""

    def test_load_for_recovery_returns_context(self, sm, coord, state):
        sm.save_with_invocation(
            state, step_id=1, node_id="node_a",
            invocation_status="completed",
        )
        sm.record_side_effect(
            run_id="test-run-001", step_id=1, node_id="node_a",
            side_effect_type="external_call",
            idempotency_key="se-1", status="completed",
        )
        ctx = coord.load_for_recovery("test-run-001")
        assert ctx is not None
        assert ctx.state.run_id == "test-run-001"
        assert 1 in ctx.completed_steps
        assert ctx.completed_steps[1] == "node_a"
        assert "se-1" in ctx.completed_side_effect_keys

    def test_load_for_recovery_returns_none_for_unknown_run(self, coord):
        assert coord.load_for_recovery("nonexistent") is None


# ─── 8. Event log durability ───────────────────────────────────────────────

class TestEventLog:
    """State events are appended and readable for replay."""

    def test_append_event_and_get_events(self, sm, state):
        sm.save(state)
        sm.append_event(
            run_id="test-run-001", revision=1, event_type="node_completed",
            node_id="node_a", step_id=1, payload={"output": "done"},
        )
        events = sm.get_events("test-run-001")
        assert len(events) >= 1
        assert any(e["event_type"] == "node_completed" for e in events)

    def test_events_ordered_by_seq(self, sm, state):
        sm.save(state)
        for i in range(3):
            sm.append_event(
                run_id="test-run-001", revision=i + 1,
                event_type="test_event", step_id=i,
            )
        events = sm.get_events("test-run-001")
        seqs = [e["seq"] for e in events]
        assert seqs == sorted(seqs)
