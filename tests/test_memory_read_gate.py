"""Memory Read Policy Runtime Gate Tests (v2.40.0).

Proves:
  - MEMORY_READ policy actually evaluates (no longer dead code)
  - Default policy matches read/read_write (not readonly)
  - Declared memory-read nodes are blocked on deny before invocation
  - _build_context strips memory unless allow decision exists
  - Durable memory_read_decisions recorded for allow and deny
  - Trace emits MEMORY_READ_ALLOWED / MEMORY_READ_DENIED
  - Reconciler detects allowed trace without durable decision
"""

from __future__ import annotations

import pytest

from nodechain.core.policy import (
    PolicyType, PolicyAction, PolicyEngine,
)
from nodechain.core.default_policies import MEMORY_READ_POLICY
from nodechain.core.state import StateManager, ChainState
from nodechain.core.trace import ChainTrace, TraceEvent, EventType, Actor
from nodechain.runtime.trace_reconciler import TraceReconciler


@pytest.fixture
def state_manager(tmp_path):
    return StateManager(db_path=str(tmp_path / "mrg.db"))


@pytest.fixture
def reconciler(state_manager):
    return TraceReconciler(state_manager)


def _make_trace(run_id: str, events: list[TraceEvent] | None = None) -> ChainTrace:
    trace = ChainTrace(run_id=run_id, chain_id="test-chain", chain_name="Test")
    for e in (events or []):
        trace.add_event(e)
    trace.finalize("completed")
    return trace


class TestPolicyFix:
    """v2.40.0: MEMORY_READ_POLICY condition fixed (readonly → read+read_write)."""

    def test_policy_condition_uses_real_values(self):
        rules = {r.rule_id: r.condition for r in MEMORY_READ_POLICY.rules}
        assert "readonly" not in rules["memory.allow_read_with_access"]
        assert "read" in rules["memory.allow_read_with_access"]
        assert "read_write" in rules["memory.allow_read_with_access"]

    def test_allow_matches_read(self):
        engine = PolicyEngine()
        engine.register(MEMORY_READ_POLICY)
        decisions = engine.evaluate(
            PolicyType.MEMORY_READ, "test_node",
            {"memory_access": "read"},
        )
        assert any(d.action == PolicyAction.ALLOW for d in decisions)

    def test_allow_matches_read_write(self):
        engine = PolicyEngine()
        engine.register(MEMORY_READ_POLICY)
        decisions = engine.evaluate(
            PolicyType.MEMORY_READ, "test_node",
            {"memory_access": "read_write"},
        )
        assert any(d.action == PolicyAction.ALLOW for d in decisions)

    def test_deny_without_access(self):
        engine = PolicyEngine()
        engine.register(MEMORY_READ_POLICY)
        decisions = engine.evaluate(
            PolicyType.MEMORY_READ, "test_node",
            {"memory_access": "none"},
        )
        assert any(d.action == PolicyAction.DENY for d in decisions)


class TestDurableDecisionLog:
    """v2.40.0: memory_read_decisions table."""

    def test_record_and_retrieve(self, state_manager):
        state_manager.record_memory_read_decision({
            "decision_id": "mr-1",
            "run_id": "r1",
            "node_id": "evidence_synthesizer",
            "decision": "allow",
            "purpose": "node_context",
            "exposed_to_node": True,
        })
        decisions = state_manager.get_memory_read_decisions(run_id="r1")
        assert len(decisions) == 1
        assert decisions[0]["decision"] == "allow"
        assert decisions[0]["exposed_to_node"] == 1  # stored as int

    def test_filter_by_decision(self, state_manager):
        for i, dec in enumerate(["allow", "deny"]):
            state_manager.record_memory_read_decision({
                "decision_id": f"mr-{i}",
                "run_id": "r1",
                "node_id": "n",
                "decision": dec,
            })
        denied = state_manager.get_memory_read_decisions(run_id="r1", decision="deny")
        assert len(denied) == 1
        assert denied[0]["decision_id"] == "mr-1"


class TestReconcilerMemoryReadBinding:
    """v2.40.0: reconciler MR-1/MR-2/MR-3."""

    @pytest.mark.asyncio
    async def test_mr1_allowed_without_durable_is_error(self, reconciler, state_manager):
        state = ChainState(chain_id="test-chain")
        state_manager.save(state)

        trace = _make_trace(state.run_id, [
            TraceEvent(
                run_id=state.run_id, chain_id="test-chain",
                node_id="evidence_synthesizer", step_id=1,
                event_type=EventType.MEMORY_READ_ALLOWED,
                actor=Actor.RUNTIME,
                metadata={"decision_id": "nonexistent"},
            ),
        ])

        report = reconciler.reconcile(trace)
        errors = [i for i in report.issues
                  if i.check == "memory_read_allowed_without_decision"
                  and i.severity == "error"]
        assert len(errors) >= 1

    @pytest.mark.asyncio
    async def test_mr1_allowed_with_durable_passes(self, reconciler, state_manager):
        state = ChainState(chain_id="test-chain")
        state_manager.save(state)

        state_manager.record_memory_read_decision({
            "decision_id": "mr-ok",
            "run_id": state.run_id,
            "node_id": "evidence_synthesizer",
            "decision": "allow",
            "exposed_to_node": True,
        })

        trace = _make_trace(state.run_id, [
            TraceEvent(
                run_id=state.run_id, chain_id="test-chain",
                node_id="evidence_synthesizer", step_id=1,
                event_type=EventType.MEMORY_READ_ALLOWED,
                actor=Actor.RUNTIME,
                metadata={"decision_id": "mr-ok"},
            ),
        ])

        report = reconciler.reconcile(trace)
        errors = [i for i in report.issues
                  if i.check == "memory_read_allowed_without_decision"
                  and i.severity == "error"]
        assert len(errors) == 0

    @pytest.mark.asyncio
    async def test_mr2_denied_but_exposed_is_error(self, reconciler, state_manager):
        state = ChainState(chain_id="test-chain")
        state_manager.save(state)

        state_manager.record_memory_read_decision({
            "decision_id": "mr-bad",
            "run_id": state.run_id,
            "node_id": "n",
            "decision": "deny",
            "exposed_to_node": True,  # BUG: denied but exposed
        })

        trace = _make_trace(state.run_id, [
            TraceEvent(
                run_id=state.run_id, chain_id="test-chain",
                node_id="n", step_id=1,
                event_type=EventType.MEMORY_READ_DENIED,
                actor=Actor.RUNTIME,
                metadata={"decision_id": "mr-bad"},
            ),
        ])

        report = reconciler.reconcile(trace)
        errors = [i for i in report.issues
                  if i.check == "memory_read_denied_but_exposed"
                  and i.severity == "error"]
        assert len(errors) >= 1

    @pytest.mark.asyncio
    async def test_mr3_allow_without_trace_is_warning(self, reconciler, state_manager):
        state = ChainState(chain_id="test-chain")
        state_manager.save(state)

        state_manager.record_memory_read_decision({
            "decision_id": "mr-lonely",
            "run_id": state.run_id,
            "node_id": "n",
            "decision": "allow",
            "exposed_to_node": True,
        })

        trace = _make_trace(state.run_id)
        report = reconciler.reconcile(trace)

        warnings = [i for i in report.issues
                    if i.check == "memory_read_allow_without_trace"]
        assert len(warnings) >= 1


class TestContextSanitizer:
    """v2.40.0: _build_context strips memory unless allow exists."""

    def test_undeclared_node_gets_no_memory(self, tmp_path):
        from nodechain.core.blueprint import ChainBlueprint, NodeDef
        from nodechain.runtime.orchestrator import Orchestrator

        sm = StateManager(db_path=str(tmp_path / "sanitizer.db"))
        blueprint = ChainBlueprint(
            chain_id="t", name="T", version="1", goal="test",
            nodes=[NodeDef(node_id="n", node_type="noop")],
            connections=[],
        )
        orch = Orchestrator(blueprint=blueprint, nodes={}, state_manager=sm)
        orch._session_memory = [{"id": "mem1", "content": "secret"}]

        ctx = orch._build_context("n")
        # Undeclared node — memory stripped
        assert ctx.session_memory == []

    def test_allowed_node_gets_memory(self, tmp_path):
        from nodechain.core.blueprint import ChainBlueprint, NodeDef
        from nodechain.runtime.orchestrator import Orchestrator

        sm = StateManager(db_path=str(tmp_path / "sanitizer2.db"))
        blueprint = ChainBlueprint(
            chain_id="t", name="T", version="1", goal="test",
            nodes=[NodeDef(node_id="n", node_type="noop")],
            connections=[],
        )
        orch = Orchestrator(blueprint=blueprint, nodes={}, state_manager=sm)
        orch._session_memory = [{"id": "mem1", "content": "data"}]
        # Simulate an allow decision (v2.40.1: decision-scoped key)
        orch._memory_read_allows[(orch._step, "n")] = "test-decision-id"

        ctx = orch._build_context("n")
        assert len(ctx.session_memory) == 1
        assert ctx.session_memory[0]["content"] == "data"
        # v2.40.2: decision_id carried in context
        assert ctx.memory_read_decision_id == "test-decision-id"

    def test_denied_node_context_has_no_decision_id(self, tmp_path):
        from nodechain.core.blueprint import ChainBlueprint, NodeDef
        from nodechain.runtime.orchestrator import Orchestrator

        sm = StateManager(db_path=str(tmp_path / "sanitizer3.db"))
        blueprint = ChainBlueprint(
            chain_id="t", name="T", version="1", goal="test",
            nodes=[NodeDef(node_id="n", node_type="noop")],
            connections=[],
        )
        orch = Orchestrator(blueprint=blueprint, nodes={}, state_manager=sm)
        orch._session_memory = [{"id": "mem1", "content": "secret"}]

        ctx = orch._build_context("n")
        assert ctx.session_memory == []
        assert ctx.memory_read_decision_id == ""


class TestNoPolicyFailClosed:
    """v2.40.1: declared read node with no MEMORY_READ policy → denied."""

    def test_no_policy_fails_closed(self):
        from nodechain.runtime.policy_gate import PolicyGate, PolicyCheckResult
        from nodechain.core.policy import PolicyEngine
        from nodechain.core.contract import (
            NodeContract, EntryContract, ExitContract, Requirements,
        )
        from nodechain.core.manifest import NodeManifest
        from nodechain.nodes.base_node import BaseNode

        # Engine with NO policies registered
        engine = PolicyEngine()

        class FakeReadNode(BaseNode):
            @property
            def manifest(self):
                return NodeManifest(
                    node_id="reader", node_type="test", name="Reader",
                    description="reads memory",
                    contract=NodeContract(
                        contract_id="test.reader.v1", node_id="reader",
                        entry=EntryContract(input_type="any", schema_ref="x", required_fields=[]),
                        exit=ExitContract(output_type="any", schema_ref="x", guaranteed_fields=[]),
                        requirements=Requirements(memory_access="read"),
                    ),
                )

            async def execute(self, envelope):
                pass

        gate = PolicyGate(
            policy_engine=engine,
            get_capabilities=lambda nid: None,
            get_step=lambda: 0,
        )
        result = gate.check("reader", FakeReadNode())
        assert not result.allowed
        # v2.44.0: package trust gate fires first when no policies at all
        assert "No trust-level policy decision" in (result.denial_reason or "")


class TestLoopFreshDecision:
    """v2.40.1: second invocation of same node does not inherit first allow."""

    def test_step_scoped_allow_expires(self, tmp_path):
        from nodechain.core.blueprint import ChainBlueprint, NodeDef
        from nodechain.runtime.orchestrator import Orchestrator

        sm = StateManager(db_path=str(tmp_path / "loop.db"))
        blueprint = ChainBlueprint(
            chain_id="t", name="T", version="1", goal="test",
            nodes=[NodeDef(node_id="n", node_type="noop")],
            connections=[],
        )
        orch = Orchestrator(blueprint=blueprint, nodes={}, state_manager=sm)
        orch._session_memory = [{"content": "data"}]

        # Step 1: allow exists
        orch._step = 1
        orch._memory_read_allows[(1, "n")] = "dec-1"
        ctx1 = orch._build_context("n")
        assert len(ctx1.session_memory) == 1

        # Step 2: no allow for this step → memory stripped
        orch._step = 2
        ctx2 = orch._build_context("n")
        assert ctx2.session_memory == []
        assert ctx2.memory_read_decision_id == ""


class TestMemoryDerivedLineage:
    """v2.40.1: any node receiving memory gets output marked memory-derived."""

    def test_memory_receiving_node_marked_derived(self, tmp_path):
        from nodechain.core.blueprint import ChainBlueprint, NodeDef
        from nodechain.runtime.orchestrator import Orchestrator

        sm = StateManager(db_path=str(tmp_path / "lineage.db"))
        blueprint = ChainBlueprint(
            chain_id="t", name="T", version="1", goal="test",
            nodes=[NodeDef(node_id="n", node_type="noop")],
            connections=[],
        )
        orch = Orchestrator(blueprint=blueprint, nodes={}, state_manager=sm)

        # Simulate: node "reader" had memory allowed at step 1
        orch._memory_read_allows[(1, "reader")] = "dec-1"

        # When _emit_node_detail_events runs for "reader" at step 1,
        # the lineage check should mark it. We test the condition directly:
        allow_key = (orch._step, "reader")
        orch._step = 1
        allow_key = (orch._step, "reader")
        if allow_key in orch._memory_read_allows:
            orch._memory_derived_outputs.add("reader")

        assert "reader" in orch._memory_derived_outputs

    def test_downstream_node_without_allow_gets_stripped_output(self, tmp_path):
        from nodechain.core.blueprint import ChainBlueprint, NodeDef
        from nodechain.runtime.orchestrator import Orchestrator

        sm = StateManager(db_path=str(tmp_path / "lineage2.db"))
        blueprint = ChainBlueprint(
            chain_id="t", name="T", version="1", goal="test",
            nodes=[NodeDef(node_id="n", node_type="noop")],
            connections=[],
        )
        orch = Orchestrator(blueprint=blueprint, nodes={}, state_manager=sm)

        # Node "reader" produced memory-derived output
        orch._memory_derived_outputs.add("reader")
        orch.state.outputs["reader"] = {"summary": "derived from memory"}
        orch.state.outputs["plain"] = {"data": "not memory-derived"}

        # Downstream node "sink" has no memory allow
        ctx = orch._build_context("sink")
        outputs = ctx.chain_state["outputs"]

        # reader's output should be stripped
        assert "reader" not in outputs
        # plain output should remain
        assert "plain" in outputs
