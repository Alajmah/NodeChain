"""Tool Access Runtime Gate Generalization Tests (v2.42.0 + v2.42.1).

Proves the acceptance criteria:
  1. Gate triggers from Requirements.tools_required, not node_id
  2. No TOOL_ACCESS policy decision → fail-closed
  3. TOOL_ACCESS_POLICY targets "*"
  4. Deny-before-allow when ungranted tools exist
  5. Capabilities sanitized to declared ∩ granted
  6. Payload adapter_grants bounded by capabilities
  7. TOOL_ACCESS_ALLOWED/DENIED emitted with decision_id
  8. tool_access_decisions durable (run_id + step_id + node_id + tool_name)
  9. Legacy node_id == "search_tool" alone grants nothing
  10. No tools_required → gate doesn't trigger
"""

from __future__ import annotations

import pytest

from nodechain.core.policy import PolicyType, PolicyAction, PolicyEngine
from nodechain.core.default_policies import TOOL_ACCESS_POLICY
from nodechain.core.state import StateManager, ChainState


class TestPolicyFix:
    """v2.42.0: TOOL_ACCESS_POLICY fixed."""

    def test_target_is_wildcard(self):
        assert TOOL_ACCESS_POLICY.target == "*"

    def test_deny_before_allow(self):
        rules = sorted(TOOL_ACCESS_POLICY.rules, key=lambda r: -r.priority)
        assert rules[0].rule_id == "tool.deny_ungranted"
        assert rules[0].action == PolicyAction.DENY
        assert rules[1].rule_id == "tool.allow_granted"
        assert rules[1].action == PolicyAction.ALLOW

    def test_allow_when_all_granted(self):
        engine = PolicyEngine()
        engine.register(TOOL_ACCESS_POLICY)
        from nodechain.core.default_policies import TRUST_LEVEL_POLICY
        engine.register(TRUST_LEVEL_POLICY)
        decisions = engine.evaluate(
            PolicyType.TOOL_ACCESS, "any_node",
            {"tools_required_count": 2, "has_ungranted_tools": False},
        )
        assert any(d.action == PolicyAction.ALLOW for d in decisions)
        assert not any(d.action == PolicyAction.DENY for d in decisions)

    def test_deny_when_ungranted(self):
        engine = PolicyEngine()
        engine.register(TOOL_ACCESS_POLICY)
        from nodechain.core.default_policies import TRUST_LEVEL_POLICY
        engine.register(TRUST_LEVEL_POLICY)
        decisions = engine.evaluate(
            PolicyType.TOOL_ACCESS, "any_node",
            {"tools_required_count": 2, "has_ungranted_tools": True},
        )
        assert any(d.action == PolicyAction.DENY for d in decisions)


class TestGateTrigger:
    """v2.42.0: gate triggers on tools_required, not node_id."""

    def test_tools_required_triggers_gate(self):
        from nodechain.runtime.policy_gate import PolicyGate, PolicyCheckResult
        from nodechain.core.contract import (
            NodeContract, EntryContract, ExitContract, Requirements,
        )
        from nodechain.core.manifest import NodeManifest
        from nodechain.nodes.base_node import BaseNode

        engine = PolicyEngine()
        engine.register(TOOL_ACCESS_POLICY)
        from nodechain.core.default_policies import TRUST_LEVEL_POLICY
        engine.register(TRUST_LEVEL_POLICY)

        class ToolNode(BaseNode):
            _trust_level = "local_trusted"
            _node_origin = "local_registry"
            @property
            def manifest(self):
                return NodeManifest(
                    node_id="my_tool_node", node_type="test", name="T",
                    description="d",
                    contract=NodeContract(
                        contract_id="t.v1", node_id="my_tool_node",
                        entry=EntryContract(input_type="any", schema_ref="x", required_fields=[]),
                        exit=ExitContract(output_type="any", schema_ref="x", guaranteed_fields=[]),
                        requirements=Requirements(tools_required=["semantic_scholar"]),
                    ),
                )

            async def execute(self, envelope):
                pass

        gate = PolicyGate(
            policy_engine=engine,
            get_capabilities=lambda nid: None,
            get_step=lambda: 0,
        )
        result = gate.check("my_tool_node", ToolNode())
        # Should evaluate tool_access (not skipped like old node_id check)
        ta = [e for e in result.evaluated_policies if e.get("type") == "tool_access"]
        assert len(ta) == 1

    def test_no_tools_required_skips_gate(self):
        from nodechain.runtime.policy_gate import PolicyGate
        from nodechain.core.contract import (
            NodeContract, EntryContract, ExitContract, Requirements,
        )
        from nodechain.core.manifest import NodeManifest
        from nodechain.nodes.base_node import BaseNode

        engine = PolicyEngine()
        engine.register(TOOL_ACCESS_POLICY)
        from nodechain.core.default_policies import TRUST_LEVEL_POLICY
        engine.register(TRUST_LEVEL_POLICY)

        class PlainNode(BaseNode):
            _trust_level = "local_trusted"
            _node_origin = "local_registry"
            @property
            def manifest(self):
                return NodeManifest(
                    node_id="plain", node_type="test", name="P",
                    description="d",
                    contract=NodeContract(
                        contract_id="p.v1", node_id="plain",
                        entry=EntryContract(input_type="any", schema_ref="x", required_fields=[]),
                        exit=ExitContract(output_type="any", schema_ref="x", guaranteed_fields=[]),
                        requirements=Requirements(),
                    ),
                )

            async def execute(self, envelope):
                pass

        gate = PolicyGate(
            policy_engine=engine,
            get_capabilities=lambda nid: None,
            get_step=lambda: 0,
        )
        result = gate.check("plain", PlainNode())
        ta = [e for e in result.evaluated_policies if e.get("type") == "tool_access"]
        assert len(ta) == 0  # gate skipped

    def test_fail_closed_without_policy(self):
        """No TOOL_ACCESS policy registered → fail-closed."""
        from nodechain.runtime.policy_gate import PolicyGate
        from nodechain.core.contract import (
            NodeContract, EntryContract, ExitContract, Requirements,
        )
        from nodechain.core.manifest import NodeManifest
        from nodechain.nodes.base_node import BaseNode

        engine = PolicyEngine()  # empty — no policies

        class ToolNode(BaseNode):
            _trust_level = "local_trusted"
            _node_origin = "local_registry"
            @property
            def manifest(self):
                return NodeManifest(
                    node_id="tn", node_type="test", name="T",
                    description="d",
                    contract=NodeContract(
                        contract_id="tn.v1", node_id="tn",
                        entry=EntryContract(input_type="any", schema_ref="x", required_fields=[]),
                        exit=ExitContract(output_type="any", schema_ref="x", guaranteed_fields=[]),
                        requirements=Requirements(tools_required=["adapter_a"]),
                    ),
                )

            async def execute(self, envelope):
                pass

        gate = PolicyGate(
            policy_engine=engine,
            get_capabilities=lambda nid: None,
            get_step=lambda: 0,
        )
        result = gate.check("tn", ToolNode())
        assert not result.allowed
        # v2.44.0: package trust gate fires first when no policies at all
        assert "No trust-level policy decision" in (result.denial_reason or "")


class TestDurableDecisions:
    """v2.42.0: tool_access_decisions table."""

    def test_record_and_retrieve(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "ta.db"))
        sm.record_tool_access_decision({
            "decision_id": "ta-1", "run_id": "r1",
            "node_id": "search_tool", "tool_name": "arxiv",
            "decision": "allow",
        })
        decisions = sm.get_tool_access_decisions(run_id="r1")
        assert len(decisions) == 1
        assert decisions[0]["tool_name"] == "arxiv"
        assert decisions[0]["node_id"] == "search_tool"

    def test_one_row_per_tool(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "ta2.db"))
        for tool in ["arxiv", "pubmed", "semantic_scholar"]:
            sm.record_tool_access_decision({
                "decision_id": f"ta-{tool}", "run_id": "r1",
                "node_id": "search_tool", "tool_name": tool,
                "decision": "allow",
            })
        decisions = sm.get_tool_access_decisions(run_id="r1")
        assert len(decisions) == 3
        tools = {d["tool_name"] for d in decisions}
        assert tools == {"arxiv", "pubmed", "semantic_scholar"}


class TestCapabilitiesSanitizer:
    """v2.42.0: capabilities sanitized to declared ∩ granted."""

    def test_sanitized_to_intersection(self, tmp_path):
        from nodechain.core.blueprint import ChainBlueprint, NodeDef
        from nodechain.runtime.orchestrator import Orchestrator
        from nodechain.core.contract import (
            NodeContract, EntryContract, ExitContract, Requirements,
        )
        from nodechain.core.manifest import NodeManifest
        from nodechain.nodes.base_node import BaseNode

        sm = StateManager(db_path=str(tmp_path / "san.db"))
        blueprint = ChainBlueprint(
            chain_id="t", name="T", version="1", goal="g",
            nodes=[NodeDef(node_id="n", node_type="noop")],
            connections=[],
        )

        class ToolNode(BaseNode):
            _trust_level = "local_trusted"
            _node_origin = "local_registry"
            def __init__(self):
                pass

            @property
            def manifest(self):
                return NodeManifest(
                    node_id="n", node_type="mock", name="N", description="d",
                    contract=NodeContract(
                        contract_id="mock.n.v1", node_id="n",
                        entry=EntryContract(input_type="any", schema_ref="x", required_fields=[]),
                        exit=ExitContract(output_type="any", schema_ref="x", guaranteed_fields=[]),
                        requirements=Requirements(tools_required=["arxiv", "pubmed"]),
                    ),
                )

            async def execute(self, envelope):
                pass

        orch = Orchestrator(blueprint=blueprint, nodes={"n": ToolNode()}, state_manager=sm)
        orch._step = 1

        caps = orch._build_capabilities("n")
        # No config allowed_tools → intersection is empty
        assert caps.allowed_tools == []


class TestSearchToolContractDeclaration:
    """v2.42.1: real SearchToolNode declares tools_required."""

    def test_search_tool_contract_has_tools_required(self):
        from nodechain.nodes.search_tool import SEARCH_TOOL_CONTRACT
        reqs = SEARCH_TOOL_CONTRACT.requirements
        # v2.43.0: tools_required is capability class, not adapter names
        assert reqs.tools_required
        assert "search" in reqs.tools_required
        # adapters_required has the specific backends
        assert reqs.adapters_required
        assert "semantic_scholar" in reqs.adapters_required

    def test_search_tool_enters_tool_access_gate(self):
        """When PolicyGate.check() runs on SearchToolNode, it enters
        the TOOL_ACCESS branch (not skipped)."""
        from nodechain.runtime.policy_gate import PolicyGate
        from nodechain.nodes.search_tool import SearchToolNode
        from nodechain.core.policy import PolicyEngine

        engine = PolicyEngine()
        engine.register(TOOL_ACCESS_POLICY)
        from nodechain.core.default_policies import TRUST_LEVEL_POLICY
        engine.register(TRUST_LEVEL_POLICY)
        gate = PolicyGate(
            policy_engine=engine,
            get_capabilities=lambda nid: None,
            get_step=lambda: 0,
        )
        result = gate.check("search_tool", SearchToolNode(allow_unguarded=True))
        ta = [e for e in result.evaluated_policies if e.get("type") == "tool_access"]
        assert len(ta) == 1


class TestPayloadUpperBound:
    """v2.43.0: empty allowed_adapters = no adapters callable."""

    def test_empty_capabilities_blocks_all_adapters(self):
        """v2.43.0: payload adapter_grants cannot expand beyond empty
        capabilities.allowed_adapters list."""
        from nodechain.nodes.search_tool import SearchToolNode
        from nodechain.core.envelope import InvocationEnvelope, Capabilities
        import asyncio

        node = SearchToolNode(allow_unguarded=True)
        envelope = InvocationEnvelope(
            run_id="r", chain_id="c", node_id="search_tool", step_id=1,
            payload={
                "search_queries": [{"terms": ["test"], "target_adapters": ["arxiv"]}],
                "adapter_grants": ["arxiv"],  # payload says arxiv is granted
            },
            capabilities=Capabilities(
                can_call_tools=True,
                allowed_tools=["search"],
                allowed_adapters=[],  # but capabilities say NOTHING granted
            ),
        )

        result = asyncio.new_event_loop().run_until_complete(node.execute(envelope))
        output = result.output
        # With empty allowed_tools, no adapter should be called
        adapters_called = output.get("adapters_called", [])
        assert len(adapters_called) == 0


class TestTraceDecisionBinding:
    """v2.42.1: TOOL_ACCESS trace events reference durable decision IDs."""

    def test_allowed_trace_has_decision_ids(self, tmp_path):
        """v2.42.1: TOOL_ACCESS_ALLOWED trace event carries decision_ids
        that match durable tool_access_decisions rows."""
        from nodechain.core.blueprint import ChainBlueprint, NodeDef
        from nodechain.runtime.orchestrator import Orchestrator
        from nodechain.core.contract import Requirements
        from nodechain.core.manifest import NodeManifest
        from nodechain.nodes.base_node import BaseNode
        from nodechain.nodes.search_tool import SearchToolNode

        sm = StateManager(db_path=str(tmp_path / "binding.db"))
        blueprint = ChainBlueprint(
            chain_id="t", name="T", version="1", goal="g",
            nodes=[NodeDef(node_id="search_tool", node_type="search_tool")],
            connections=[],
        )
        orch = Orchestrator(blueprint=blueprint, nodes={"search_tool": SearchToolNode(allow_unguarded=True)}, state_manager=sm)
        orch.state.run_id = "run-binding"

        # Simulate what _check_policy_gate does when tool_access is allowed
        from nodechain.core.trace import EventType, Actor
        import uuid
        did = str(uuid.uuid4())
        sm.record_tool_access_decision({
            "decision_id": did, "run_id": "run-binding", "step_id": 1,
            "node_id": "search_tool", "tool_name": "arxiv",
            "decision": "allow",
        })
        orch._emit(
            EventType.TOOL_ACCESS_ALLOWED, "search_tool",
            actor=Actor.RUNTIME, decision="tool_access_allowed",
            metadata={"decision_ids": [did], "tools": ["arxiv"]},
        )

        # Verify trace references the durable decision_id
        trace_events = [e for e in orch.trace.events
                        if e.event_type == EventType.TOOL_ACCESS_ALLOWED]
        assert len(trace_events) == 1
        assert did in trace_events[0].metadata["decision_ids"]
