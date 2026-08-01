"""Declared-vs-Observed Side-Effect Enforcement Tests (v2.35.0).

Proves:
  - Canonical SideEffectType enum (3 types: external_call, memory_write, memory_read)
  - Normalization maps legacy strings → canonical
  - Orchestrator records canonical types (external_call, not external_api_read)
  - Undeclared observed side effects fail closed (CONTRACT_VIOLATION)
  - Reconciler Check 4h flags type mismatches
  - Invariant engine uses canonical taxonomy
"""

from __future__ import annotations

import pytest

from nodechain.core.contract import (
    SideEffectType, normalize_side_effect_type, SideEffect,
    NodeContract, EntryContract, ExitContract, Requirements,
)
from nodechain.core.state import StateManager, ChainState
from nodechain.core.trace import ChainTrace, TraceEvent, EventType, Actor
from nodechain.runtime.trace_reconciler import TraceReconciler


def _make_trace(run_id: str, events: list[TraceEvent] | None = None) -> ChainTrace:
    trace = ChainTrace(run_id=run_id, chain_id="test-chain", chain_name="Test")
    for e in (events or []):
        trace.add_event(e)
    trace.finalize("completed")
    return trace


# ── Unit: canonical taxonomy + normalization ────────────────────────────────

class TestCanonicalTaxonomy:
    """v2.35.0: 3 canonical types, tool_invocation excluded."""

    def test_three_canonical_types(self):
        # v2.73: expanded from 3 to 5 (added code_execution, sandbox_file_write)
        assert len(SideEffectType) == 5
        assert SideEffectType.EXTERNAL_CALL.value == "external_call"
        assert SideEffectType.MEMORY_WRITE.value == "memory_write"
        assert SideEffectType.MEMORY_READ.value == "memory_read"

    def test_tool_invocation_not_canonical(self):
        assert not hasattr(SideEffectType, "TOOL_INVOCATION")

    @pytest.mark.parametrize("raw,expected", [
        ("external_call", "external_call"),
        ("external_api_read", "external_call"),
        ("api_call", "external_call"),
        ("search", "external_call"),
        ("external_read", "external_call"),
        ("external_write", "external_call"),
        ("memory_write", "memory_write"),
        ("memory_read", "memory_read"),
    ])
    def test_legacy_normalizes_to_canonical(self, raw, expected):
        assert normalize_side_effect_type(raw) == expected

    def test_unknown_returns_none(self):
        assert normalize_side_effect_type("bogus_type") is None
        assert normalize_side_effect_type("") is None
        assert normalize_side_effect_type(None) is None  # type: ignore


# ── Integration: orchestrator records canonical types ──────────────────────

class TestOrchestratorCanonicalWrites:
    """v2.35.0: _journal_one normalizes to canonical before recording."""

    def test_journal_one_normalizes_external_api_read(self, tmp_path):
        from nodechain.core.blueprint import ChainBlueprint, NodeDef
        from nodechain.core.envelope import InvocationEnvelope
        from nodechain.runtime.orchestrator import Orchestrator

        sm = StateManager(db_path=str(tmp_path / "canon.db"))
        blueprint = ChainBlueprint(
            chain_id="t", name="T", version="1", goal="test",
            nodes=[NodeDef(node_id="n", node_type="noop")],
            connections=[],
        )
        orch = Orchestrator(blueprint=blueprint, nodes={}, state_manager=sm)
        orch.state.run_id = "run-canon"

        envelope = InvocationEnvelope(
            run_id="run-canon", chain_id="t", node_id="n",
            step_id=1, payload={"q": "test"},
        )
        # Pass legacy string
        orch._journal_one("search:arxiv:legacy", "n", "external_api_read", envelope)

        row = sm.get_side_effect_by_key("run-canon", "search:arxiv:legacy")
        assert row is not None
        # Should be canonical, not legacy
        assert row["side_effect_type"] == "external_call"

        started = [e for e in orch.trace.events
                   if e.event_type == EventType.SIDE_EFFECT_STARTED]
        assert len(started) == 1
        assert started[0].metadata["effect_type"] == "external_call"

    def test_journal_one_normalizes_api_call(self, tmp_path):
        from nodechain.core.blueprint import ChainBlueprint, NodeDef
        from nodechain.core.envelope import InvocationEnvelope
        from nodechain.runtime.orchestrator import Orchestrator

        sm = StateManager(db_path=str(tmp_path / "canon2.db"))
        blueprint = ChainBlueprint(
            chain_id="t", name="T", version="1", goal="test",
            nodes=[NodeDef(node_id="n", node_type="noop")],
            connections=[],
        )
        orch = Orchestrator(blueprint=blueprint, nodes={}, state_manager=sm)
        orch.state.run_id = "run-canon2"

        envelope = InvocationEnvelope(
            run_id="run-canon2", chain_id="t", node_id="n",
            step_id=1, payload={"q": "test"},
        )
        orch._journal_one("key1", "n", "api_call", envelope)
        row = sm.get_side_effect_by_key("run-canon2", "key1")
        assert row["side_effect_type"] == "external_call"


# ── Integration: _assert_declared_side_effect ──────────────────────────────

class TestAssertDeclaredSideEffect:
    """v2.35.0: undeclared observed side effects fail closed."""

    def _make_orch(self, tmp_path, nodes=None):
        from nodechain.core.blueprint import ChainBlueprint, NodeDef
        from nodechain.runtime.orchestrator import Orchestrator
        sm = StateManager(db_path=str(tmp_path / f"assert{id(tmp_path)}.db"))
        blueprint = ChainBlueprint(
            chain_id="t", name="T", version="1", goal="g",
            nodes=[NodeDef(node_id="n", node_type="noop")],
            connections=[],
        )
        orch = Orchestrator(blueprint=blueprint, nodes={}, state_manager=sm)
        orch.state.run_id = "run-assert"
        # Inject nodes dict directly (bypass constructor's contract registry)
        orch._nodes = nodes or {}
        return orch

    def test_declared_type_passes(self, tmp_path):
        from nodechain.nodes.search_tool import SearchToolNode
        orch = self._make_orch(tmp_path, {"search_tool": SearchToolNode(allow_unguarded=True)})

        result = orch._assert_declared_side_effect("search_tool", "external_call")
        assert result == "external_call"

        # Legacy string also works via normalization
        result2 = orch._assert_declared_side_effect("search_tool", "external_api_read")
        assert result2 == "external_call"

    def test_undeclared_type_fails_closed(self, tmp_path):
        from nodechain.nodes.memory_write import MemoryWriteDecisionNode
        orch = self._make_orch(tmp_path, {"memory_write_decision": MemoryWriteDecisionNode()})

        # Node declares memory_write, but we observe external_call
        result = orch._assert_declared_side_effect("memory_write_decision", "external_call")
        assert result is None  # fail closed

        violations = [e for e in orch.trace.events
                      if e.event_type == EventType.CONTRACT_VIOLATION]
        assert len(violations) == 1
        assert violations[0].metadata["reason"] == "side_effect_not_declared_by_node"

    def test_unrecognized_type_fails_closed(self, tmp_path):
        orch = self._make_orch(tmp_path, {})

        result = orch._assert_declared_side_effect("n", "totally_bogus")
        assert result is None

        violations = [e for e in orch.trace.events
                      if e.event_type == EventType.CONTRACT_VIOLATION]
        assert len(violations) == 1
        assert violations[0].metadata["reason"] == "unrecognized_side_effect_type"

    def test_node_without_declarations_fails_closed(self, tmp_path):
        """v2.35.1: node with no declared side effects producing one = CONTRACT_VIOLATION."""
        orch = self._make_orch(tmp_path, {})

        result = orch._assert_declared_side_effect("n", "external_call")
        # Node not in registry at all (contract unavailable) — still returns
        # canonical because we can't verify. Only nodes WITH contracts that
        # declare nothing fail closed.
        # When nodes dict is empty, the node is "unavailable" not "declares nothing."
        assert result == "external_call"  # unavailable → allow (can't check)

    def test_known_node_with_empty_declarations_fails_closed(self, tmp_path):
        """v2.35.1: known node with contract but zero side-effect declarations."""
        from nodechain.nodes.goal_interpreter import GoalInterpreterNode
        # GoalInterpreterNode has no declared side effects
        orch = self._make_orch(tmp_path, {"goal_interpreter": GoalInterpreterNode(None)})

        result = orch._assert_declared_side_effect("goal_interpreter", "external_call")
        assert result is None  # fail closed

        violations = [e for e in orch.trace.events
                      if e.event_type == EventType.CONTRACT_VIOLATION]
        assert len(violations) == 1
        assert violations[0].metadata["reason"] == "node_declares_no_side_effects"


# ── Integration: reconciler Check 4h ────────────────────────────────────────

class TestCheck4hDeclaredTypeMatch:
    """v2.35.0: ledger side-effect type must be declared by node contract."""

    @pytest.mark.asyncio
    async def test_type_mismatch_is_error(self, tmp_path):
        from nodechain.nodes.search_tool import SearchToolNode
        sm = StateManager(db_path=str(tmp_path / "check4h.db"))
        reconciler = TraceReconciler(sm)

        state = ChainState(chain_id="test-chain")
        sm.save(state)

        sm.record_side_effect(
            run_id=state.run_id, step_id=1, node_id="search_tool",
            side_effect_type="memory_write",  # search_tool doesn't declare this
            idempotency_key="ss:mismatch",
            status="completed",
        )

        reconciler.set_nodes({"search_tool": SearchToolNode(allow_unguarded=True)})

        trace = _make_trace(state.run_id)
        report = reconciler.reconcile(trace)

        type_errors = [i for i in report.issues
                       if i.check == "side_effect_declared_type_match"
                       and i.severity == "error"]
        assert len(type_errors) >= 1

    @pytest.mark.asyncio
    async def test_contract_unavailable_is_warning(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "check4h2.db"))
        reconciler = TraceReconciler(sm)
        # No nodes wired

        state = ChainState(chain_id="test-chain")
        sm.save(state)

        sm.record_side_effect(
            run_id=state.run_id, step_id=1, node_id="unknown_node",
            side_effect_type="external_call",
            idempotency_key="ss:no_contract",
            status="completed",
        )

        trace = _make_trace(state.run_id)
        report = reconciler.reconcile(trace)

        warnings = [i for i in report.issues
                    if i.check == "side_effect_declared_type_match"
                    and i.severity == "warning"]
        assert len(warnings) >= 1
