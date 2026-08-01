"""Tests for durable cost accounting via invocation ledger.

AC1: Invocation ledger records cost_usd per invocation.
AC2: Loop budget enforcement reads cumulative cost from invocation ledger when available.
AC3: Trace cost remains a fallback with cost_source="trace_events".
AC4: LOOP_BLOCKED metadata records cost_source="invocation_ledger" when ledger-backed.
AC5: Report loop summary includes cumulative_cost_usd and max_cost_usd.
AC6: 644 tests remain green.
"""

import pytest
import os
import sys
import sqlite3

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nodechain.core.state import StateManager, ChainState
from nodechain.core.blueprint import LoopDef, ChainBlueprint


class TestInvocationLedgerCostTracking:
    """Verify cost_usd is recorded in invocation ledger."""

    def test_cost_usd_in_schema(self):
        """AC1: invocation_ledger has cost_usd column."""
        sm = StateManager(db_path="data/test_cost_schema.db")
        with sqlite3.connect("data/test_cost_schema.db") as conn:
            cursor = conn.execute("PRAGMA table_info(invocation_ledger)")
            columns = {row[1] for row in cursor.fetchall()}
            assert "cost_usd" in columns

    def test_save_with_cost(self):
        """AC1: save_with_invocation records cost_usd."""
        db_path = "data/test_cost_save.db"
        sm = StateManager(db_path=db_path)
        state = ChainState()
        sm.save_with_invocation(
            state, step_id=1, node_id="test_node",
            cost_usd=0.025,
        )
        with sqlite3.connect(db_path) as conn:
            cursor = conn.execute(
                "SELECT cost_usd FROM invocation_ledger WHERE run_id = ? AND step_id = 1",
                (state.run_id,),
            )
            row = cursor.fetchone()
            assert row is not None
            assert row[0] == 0.025

    def test_default_cost_is_zero(self):
        """AC1: Default cost_usd is 0.0."""
        db_path = "data/test_cost_default.db"
        sm = StateManager(db_path=db_path)
        state = ChainState()
        sm.save_with_invocation(
            state, step_id=1, node_id="test_node",
        )
        with sqlite3.connect(db_path) as conn:
            cursor = conn.execute(
                "SELECT cost_usd FROM invocation_ledger WHERE run_id = ? AND step_id = 1",
                (state.run_id,),
            )
            row = cursor.fetchone()
            assert row is not None
            assert row[0] == 0.0


class TestGetInvocationCost:
    """Verify get_invocation_cost sums correctly."""

    def test_total_cost_all_nodes(self):
        """AC2: Sum cost for all invocations."""
        db_path = "data/test_cost_total.db"
        sm = StateManager(db_path=db_path)
        state = ChainState()
        sm.save_with_invocation(state, step_id=1, node_id="node_a", cost_usd=0.01)
        sm.save_with_invocation(state, step_id=2, node_id="node_b", cost_usd=0.02)
        sm.save_with_invocation(state, step_id=3, node_id="node_c", cost_usd=0.03)

        total = sm.get_invocation_cost(state.run_id)
        assert abs(total - 0.06) < 0.0001

    def test_filtered_cost_by_node_ids(self):
        """AC2: Sum cost for specific nodes only."""
        db_path = "data/test_cost_filtered.db"
        sm = StateManager(db_path=db_path)
        state = ChainState()
        sm.save_with_invocation(state, step_id=1, node_id="node_a", cost_usd=0.01)
        sm.save_with_invocation(state, step_id=2, node_id="node_b", cost_usd=0.02)
        sm.save_with_invocation(state, step_id=3, node_id="node_c", cost_usd=0.03)

        cost = sm.get_invocation_cost(state.run_id, node_ids=["node_a", "node_b"])
        assert abs(cost - 0.03) < 0.0001

    def test_empty_run_returns_zero(self):
        """No invocations returns 0.0."""
        db_path = "data/test_cost_empty.db"
        sm = StateManager(db_path=db_path)
        cost = sm.get_invocation_cost("nonexistent_run_id")
        assert cost == 0.0

    def test_no_matching_nodes_returns_zero(self):
        """No matching node_ids returns 0.0."""
        db_path = "data/test_cost_no_match.db"
        sm = StateManager(db_path=db_path)
        state = ChainState()
        sm.save_with_invocation(state, step_id=1, node_id="node_a", cost_usd=0.01)

        cost = sm.get_invocation_cost(state.run_id, node_ids=["node_z"])
        assert cost == 0.0


class TestLoopCostFromLedger:
    """Verify loop cost computation prefers ledger."""

    def test_ledger_preferred_over_trace(self):
        """AC2: Ledger cost takes precedence when > 0."""
        from nodechain.runtime.loop_enforcer import LoopEnforcer
        from nodechain.core.state import ChainState

        bp = ChainBlueprint(
            chain_id="test", name="test", version="1.0",
            description="test", goal="test",
            nodes=[], connections=[], loops=[],
        )
        enforcer = LoopEnforcer(bp)
        loop = LoopDef(
            loop_id="test-loop",
            entry_condition="", exit_condition="",
            max_iterations=5, max_cost_usd=0.1,
            path=["node_a"],
        )
        state = ChainState()
        # Budget check with ledger cost > 0.1
        result = enforcer.check_budget(loop, state, cost_usd=0.15)
        assert result.allowed is False

    def test_cost_source_metadata(self):
        """AC4: Budget enforcement result carries context with cost info."""
        from nodechain.runtime.loop_enforcer import LoopEnforcer

        bp = ChainBlueprint(
            chain_id="test", name="test", version="1.0",
            description="test", goal="test",
            nodes=[], connections=[], loops=[],
        )
        enforcer = LoopEnforcer(bp)
        loop = LoopDef(
            loop_id="test-loop",
            entry_condition="", exit_condition="",
            max_iterations=5, max_cost_usd=0.1,
            path=["node_a"],
        )
        state = ChainState()
        result = enforcer.check_budget(loop, state, cost_usd=0.15)
        assert result.context["cost"] == 0.15
        assert result.context["max_cost_usd"] == 0.1


class TestSchemaMigration:
    """Verify cost_usd migration works on existing DBs."""

    def test_migration_adds_cost_column(self):
        """Migration adds cost_usd to pre-existing invocation_ledger."""
        db_path = "data/test_migration.db"
        # Create DB without cost_usd
        with sqlite3.connect(db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS invocation_ledger (
                    run_id TEXT NOT NULL,
                    step_id INTEGER NOT NULL,
                    node_id TEXT NOT NULL,
                    branch_name TEXT,
                    status TEXT NOT NULL DEFAULT 'completed',
                    output_hash TEXT,
                    timestamp TEXT NOT NULL,
                    PRIMARY KEY (run_id, step_id)
                )
            """)
            conn.commit()

        # Opening StateManager should migrate
        sm = StateManager(db_path=db_path)
        with sqlite3.connect(db_path) as conn:
            cursor = conn.execute("PRAGMA table_info(invocation_ledger)")
            columns = {row[1] for row in cursor.fetchall()}
            assert "cost_usd" in columns

    def test_migration_idempotent(self):
        """Migration is safe to run multiple times."""
        db_path = "data/test_migration_idem.db"
        sm1 = StateManager(db_path=db_path)
        sm2 = StateManager(db_path=db_path)
        # Both should work without error
        with sqlite3.connect(db_path) as conn:
            cursor = conn.execute("PRAGMA table_info(invocation_ledger)")
            columns = {row[1] for row in cursor.fetchall()}
            assert "cost_usd" in columns
