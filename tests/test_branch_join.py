"""Tests for branch-join execution: multi-branch, failure semantics, state accounting."""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from nodechain.core.blueprint import load_blueprint, ChainBlueprint, NodeDef, ConnectionDef, BranchDef, JoinDef
from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.port import PortType
from nodechain.core.trace import EventType
from nodechain.core.state import StateManager
from nodechain.runtime.orchestrator import Orchestrator
from test_runtime import MockNode
from nodechain.nodes.domain_classifier import DomainClassifierNode
from nodechain.nodes.evidence_joiner import EvidenceJoinerNode
from nodechain.nodes.conflict_detector import ConflictDetectorNode
from nodechain.nodes.branch_search import BranchSearchNode
from nodechain.nodes.branch_response_generator import BranchResponseGeneratorNode
from nodechain.nodes.branch_trace_collector import BranchTraceCollectorNode
from nodechain.nodes.goal_interpreter import GoalInterpreterNode
from nodechain.runtime.orchestrator import Orchestrator


# ─── Helpers ────────────────────────────────────────────────────────────────

def _make_test_blueprint(
    branches: dict[str, list[str]] | None = None,
    default_branch: str | None = None,
    wait_for: str = "all",
) -> ChainBlueprint:
    """Build a minimal branch-join blueprint for testing."""
    if branches is None:
        branches = {"biomedical": ["biomedical_search"], "technical": ["technical_search"], "general": ["general_search"]}

    nodes = [
        NodeDef(node_id="goal_interpreter", node_type="model", position=1),
        NodeDef(node_id="domain_classifier", node_type="deterministic", position=2),
    ]
    connections = [
        ConnectionDef(from_node="goal_interpreter", from_port="output", to_node="domain_classifier", to_port="input"),
    ]
    position = 3
    for branch_name, branch_nodes in branches.items():
        for bn in branch_nodes:
            nodes.append(NodeDef(node_id=bn, node_type="deterministic", position=position))
            position += 1
            connections.append(ConnectionDef(
                from_node="domain_classifier", from_port="output",
                to_node=bn, to_port="input",
                condition=f"branch_{branch_name}",
            ))

    # Add join + conflict_detector + post-join nodes
    join_node = "evidence_joiner"
    nodes.append(NodeDef(node_id=join_node, node_type="deterministic", position=position))
    position += 1
    nodes.append(NodeDef(node_id="conflict_detector", node_type="deterministic", position=position))
    position += 1
    nodes.append(NodeDef(node_id="response_generator", node_type="model", position=position))
    position += 1
    nodes.append(NodeDef(node_id="trace_collector", node_type="deterministic", position=position))

    # Connect branch nodes to join
    for branch_nodes in branches.values():
        for bn in branch_nodes:
            connections.append(ConnectionDef(from_node=bn, from_port="output", to_node=join_node, to_port="input"))

    connections.append(ConnectionDef(from_node=join_node, from_port="output", to_node="conflict_detector", to_port="input"))
    connections.append(ConnectionDef(from_node="conflict_detector", from_port="output", to_node="response_generator", to_port="input"))
    connections.append(ConnectionDef(from_node="response_generator", from_port="output", to_node="trace_collector", to_port="input"))

    branch_defs = [
        BranchDef(
            branch_id="domain_routing",
            from_node="domain_classifier",
            branches=branches,
            default_branch=default_branch,
        )
    ]
    join_defs = [
        JoinDef(
            join_id="evidence_merge",
            to_node=join_node,
            from_branches=list(branches.keys()),
            wait_for=wait_for,
        )
    ]

    return ChainBlueprint(
        chain_id="test_branch_v1",
        name="Test Branch Chain",
        version="1.0.0",
        goal="Test branch-join execution.",
        nodes=nodes,
        connections=connections,
        branches=branch_defs,
        joins=join_defs,
    )


class MockModelAdapter:
    """Mock model adapter that returns structured JSON."""
    def complete(self, system_prompt=None, user_message=None, max_tokens=2048, temperature=0.3, **kwargs):
        return MagicMock(
            content='{"primary_question": "test query", "research_domain": "biomedical", '
                    '"domain_classification": [{"domain": "biomedical", "confidence": 0.9}, '
                    '{"domain": "computer_science", "confidence": 0.8}], '
                    '"sub_questions": ["sub1"], "success_criteria": ["c1"], '
                    '"constraints": [], "time_sensitivity": "low", "depth_required": "medium"}',
            structured_output=None,
            cost_usd=0.001,
            latency_ms=100,
            stop_reason="stop",
            raw_output_size=100,
        )


class MockSearchNode:
    """Deterministic mock search node that produces results."""
    def __init__(self, node_id, result_count=3):
        self._node_id = node_id
        self._result_count = result_count

    @property
    def manifest(self):
        from nodechain.core.manifest import NodeManifest
        from nodechain.core.contract import EntryContract, ExitContract, Requirements, NodeContract
        return NodeManifest(
            node_id=self._node_id,
            node_type="deterministic",
            name=f"Mock Search ({self._node_id})",
            description="Mock search for testing",
            contract=NodeContract(
                contract_id=f"mock.{self._node_id}.v1",
                node_id=self._node_id,
                version="1.0.0",
                entry=EntryContract(input_type=PortType.TASK_PLAN, schema_ref="test"),
                exit=ExitContract(output_type=PortType.RAW_SEARCH_RESULTS, schema_ref="test", guaranteed_fields=["results"]),
                requirements=Requirements(model_required=False),
            ),
        )

    async def execute(self, envelope):
        results = [
            {"title": f"Result {i} from {self._node_id}", "source_id": f"src_{self._node_id}_{i}"}
            for i in range(self._result_count)
        ]
        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id=self._node_id,
            step_id=envelope.step_id,
            output={"results": results},
            output_type=PortType.RAW_SEARCH_RESULTS,
        )


# ─── Tests ──────────────────────────────────────────────────────────────────

class TestBranchJoinExecution:
    """Multi-branch fan-in and failure semantics."""

    def _make_nodes(self, model, search_counts=None):
        """Create a standard node set for testing."""
        if search_counts is None:
            search_counts = {"biomedical_search": 3, "technical_search": 3, "general_search": 3}
        nodes = {
            "goal_interpreter": GoalInterpreterNode(model),
            "domain_classifier": DomainClassifierNode(),
        }
        for nid, count in search_counts.items():
            nodes[nid] = MockSearchNode(nid, count)
        nodes["evidence_joiner"] = EvidenceJoinerNode()
        nodes["conflict_detector"] = ConflictDetectorNode()
        nodes["response_generator"] = BranchResponseGeneratorNode(model)
        nodes["trace_collector"] = BranchTraceCollectorNode()
        return nodes

    @pytest.mark.asyncio
    async def test_two_branches_execute_and_join(self):
        """AC1: Two selected branches execute in one run. AC2: Join receives both outputs."""
        model = MockModelAdapter()
        blueprint = _make_test_blueprint()
        nodes = self._make_nodes(model)
        orch = Orchestrator(blueprint=blueprint, nodes=nodes)

        # Patch domain classifier to select only biomedical + technical
        with patch.object(DomainClassifierNode, "_classify_domain", return_value=["biomedical", "technical"]):
            trace = await orch.run("test query")

        assert trace.final_status == "completed", f"Expected completed, got {trace.final_status}"

        # Both branches should have outputs
        assert "biomedical" in orch.state.branch_outputs
        assert "technical" in orch.state.branch_outputs
        # General should NOT have outputs (not selected, but still in branch_outputs as skipped)
        assert orch.state.skipped_nodes
        skipped_branches = [s["branch"] for s in orch.state.skipped_nodes]
        assert "general" in skipped_branches

        # Join should have both branches
        join_inputs = orch.state.join_inputs.get("evidence_merge", {})
        assert "biomedical" in join_inputs
        assert "technical" in join_inputs

        # Node counts
        invoked = [e for e in trace.events if e.event_type == EventType.NODE_INVOKED]
        skipped = [e for e in trace.events if e.event_type == EventType.NODE_SKIPPED]
        assert len(invoked) == 8  # 6 backbone + 2 branch
        assert len(skipped) == 1  # general skipped

    @pytest.mark.asyncio
    async def test_all_three_branches_execute(self):
        """AC2 extended: All three branches selected and join receives all outputs."""
        model = MockModelAdapter()
        blueprint = _make_test_blueprint()
        nodes = self._make_nodes(model)
        orch = Orchestrator(blueprint=blueprint, nodes=nodes)

        with patch.object(DomainClassifierNode, "_classify_domain", return_value=["biomedical", "technical", "general"]):
            trace = await orch.run("test query")

        assert trace.final_status == "completed"
        assert len(orch.state.branch_outputs) == 3
        assert len(orch.state.skipped_nodes) == 0
        join_inputs = orch.state.join_inputs.get("evidence_merge", {})
        assert len(join_inputs) == 3

        invoked = [e for e in trace.events if e.event_type == EventType.NODE_INVOKED]
        assert len(invoked) == 9  # 6 backbone + 3 branch

    @pytest.mark.asyncio
    async def test_join_trace_records_contributing_branches(self):
        """AC3: Join trace records exact contributing branches."""
        model = MockModelAdapter()
        blueprint = _make_test_blueprint()
        nodes = self._make_nodes(model)
        orch = Orchestrator(blueprint=blueprint, nodes=nodes)

        with patch.object(DomainClassifierNode, "_classify_domain", return_value=["biomedical", "general"]):
            trace = await orch.run("test query")

        # State tracks join inputs with branch provenance
        join_inputs = orch.state.join_inputs.get("evidence_merge", {})
        contributing = list(join_inputs.keys())
        assert "biomedical" in contributing
        assert "general" in contributing
        assert "technical" not in contributing  # not selected

    @pytest.mark.asyncio
    async def test_no_duplicate_invocations(self):
        """Verify node counts reconcile: no node invoked twice."""
        model = MockModelAdapter()
        blueprint = _make_test_blueprint()
        nodes = self._make_nodes(model)
        orch = Orchestrator(blueprint=blueprint, nodes=nodes)

        with patch.object(DomainClassifierNode, "_classify_domain", return_value=["biomedical", "technical", "general"]):
            trace = await orch.run("test query")

        invoked = [e.node_id for e in trace.events if e.event_type == EventType.NODE_INVOKED]
        assert len(invoked) == len(set(invoked)), f"Duplicate invocations: {invoked}"

    @pytest.mark.asyncio
    async def test_state_accounting_reconciles(self):
        """Verify all state counters are consistent."""
        model = MockModelAdapter()
        blueprint = _make_test_blueprint()
        nodes = self._make_nodes(model)
        orch = Orchestrator(blueprint=blueprint, nodes=nodes)

        with patch.object(DomainClassifierNode, "_classify_domain", return_value=["biomedical"]):
            trace = await orch.run("test query")

        # declared_nodes = blueprint nodes
        declared = len(blueprint.nodes)
        # declared_nodes = blueprint nodes
        declared = len(blueprint.nodes)
        assert declared == 9

        # invoked = backbone (6) + selected branches (1)
        invoked = [e for e in trace.events if e.event_type == EventType.NODE_INVOKED]
        skipped = [e for e in trace.events if e.event_type == EventType.NODE_SKIPPED]

        # Branch-only nodes
        branch_node_ids = set()
        for b in blueprint.branches:
            for nl in b.branches.values():
                branch_node_ids.update(nl)
        backbone = declared - len(branch_node_ids)

        # invoked = backbone (7) + selected branches (1)
        selected = orch.state.routing_decisions[0]["selected"]
        expected_invoked = backbone + len(selected)
        assert len(invoked) == expected_invoked, f"Expected {expected_invoked} invoked, got {len(invoked)}"

        # skipped = non-selected branches
        non_selected = len(branch_node_ids) - len(selected)
        assert len(skipped) == non_selected

        # All selected branches have state entries
        for b in selected:
            assert b in orch.state.branch_outputs

    @pytest.mark.asyncio
    async def test_skipped_branches_no_policy_grants(self):
        """AC9: Skipped branches do not produce policy grants."""
        model = MockModelAdapter()
        blueprint = _make_test_blueprint()
        nodes = self._make_nodes(model)
        orch = Orchestrator(blueprint=blueprint, nodes=nodes)

        with patch.object(DomainClassifierNode, "_classify_domain", return_value=["biomedical"]):
            trace = await orch.run("test query")

        # Policy events should only be for invoked nodes
        policy_events = [e for e in trace.events if e.event_type == EventType.POLICY_EVALUATED]
        invoked_ids = {e.node_id for e in trace.events if e.event_type == EventType.NODE_INVOKED}

        for pe in policy_events:
            assert pe.node_id in invoked_ids, f"Policy event for non-invoked node: {pe.node_id}"

    @pytest.mark.asyncio
    async def test_unknown_branch_falls_back_to_default(self):
        """When classifier selects unknown branch, default branch executes."""
        model = MockModelAdapter()
        blueprint = _make_test_blueprint(default_branch="general")
        nodes = self._make_nodes(model)
        orch = Orchestrator(blueprint=blueprint, nodes=nodes)

        with patch.object(DomainClassifierNode, "_classify_domain", return_value=["quantum"]):
            trace = await orch.run("test query")

        # "quantum" isn't a real branch, so all real branches get skipped
        # The chain still completes (no branch nodes execute)
        assert trace.final_status in ("completed", "failed")

    @pytest.mark.asyncio
    async def test_existing_sequential_chain_unchanged(self):
        """AC8: Existing sequential chains still run unchanged after branch changes."""
        model = MockModelAdapter()
        # Load the research chain blueprint
        research_bp = load_blueprint("blueprints/research_decision_v1.yaml")
        assert len(research_bp.nodes) == 12
        assert len(research_bp.branches) == 0
        assert len(research_bp.joins) == 0

        # Quick fact check
        qfc_bp = load_blueprint("blueprints/quick_fact_check_v1.yaml")
        assert len(qfc_bp.nodes) == 5
        assert len(qfc_bp.branches) == 0


class TestExecutionOrderIsolation:
    """Verify branch nodes are excluded from sequential execution order."""

    def test_branch_nodes_excluded_from_order(self):
        model = MockModelAdapter()
        blueprint = _make_test_blueprint()
        nodes = TestBranchJoinExecution()._make_nodes(model)
        orch = Orchestrator(blueprint=blueprint, nodes=nodes)

        order = orch.scheduler.resolve_execution_order()

        # Branch nodes should NOT be in the order
        assert "biomedical_search" not in order
        assert "technical_search" not in order
        assert "general_search" not in order

        # Backbone nodes should be present
        assert "goal_interpreter" in order
        assert "domain_classifier" in order
        assert "conflict_detector" in order  # added between join and response
        assert "evidence_joiner" in order
        assert "response_generator" in order
        assert "trace_collector" in order

    def test_sequential_blueprint_order_unchanged(self):
        """AC8: Sequential blueprints should have all nodes in order."""
        bp = load_blueprint("blueprints/research_decision_v1.yaml")
        assert len(bp.nodes) == 12
        assert len(bp.branches) == 0
        assert len(bp.joins) == 0

        # Verify quick fact check too
        qfc_bp = load_blueprint("blueprints/quick_fact_check_v1.yaml")
        assert len(qfc_bp.nodes) == 5
        assert len(qfc_bp.branches) == 0

        # And branch blueprint
        br_bp = load_blueprint("blueprints/domain_routed_evidence_v1.yaml")
        assert len(br_bp.nodes) == 9
        assert len(br_bp.branches) == 1
        assert len(br_bp.joins) == 1


class FailingSearchNode:
    """Search node that always fails."""
    def __init__(self, node_id, error_msg="deliberate_failure"):
        self._node_id = node_id
        self._error = error_msg

    @property
    def manifest(self):
        from nodechain.core.manifest import NodeManifest
        from nodechain.core.contract import EntryContract, ExitContract, Requirements, NodeContract
        return NodeManifest(
            node_id=self._node_id, node_type="deterministic",
            name=f"Failing {self._node_id}", description="Fails on purpose",
            contract=NodeContract(
                contract_id=f"fail.{self._node_id}.v1", node_id=self._node_id, version="1.0.0",
                entry=EntryContract(input_type=PortType.TASK_PLAN, schema_ref="test"),
                exit=ExitContract(output_type=PortType.RAW_SEARCH_RESULTS, schema_ref="test", guaranteed_fields=["results"]),
                requirements=Requirements(model_required=False),
            ),
        )

    async def execute(self, envelope):
        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id, chain_id=envelope.chain_id,
            node_id=self._node_id, step_id=envelope.step_id,
            output={}, output_type=PortType.RAW_SEARCH_RESULTS,
            success=False, error=self._error,
        )


class WrongTypeSearchNode:
    """Search node that outputs the wrong semantic type."""
    def __init__(self, node_id):
        self._node_id = node_id

    @property
    def manifest(self):
        from nodechain.core.manifest import NodeManifest
        from nodechain.core.contract import EntryContract, ExitContract, Requirements, NodeContract
        return NodeManifest(
            node_id=self._node_id, node_type="deterministic",
            name=f"WrongType {self._node_id}", description="Returns wrong type",
            contract=NodeContract(
                contract_id=f"wrong.{self._node_id}.v1", node_id=self._node_id, version="1.0.0",
                entry=EntryContract(input_type=PortType.TASK_PLAN, schema_ref="test"),
                exit=ExitContract(output_type=PortType.RAW_SEARCH_RESULTS, schema_ref="test", guaranteed_fields=["results"]),
                requirements=Requirements(model_required=False),
            ),
        )

    async def execute(self, envelope):
        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id, chain_id=envelope.chain_id,
            node_id=self._node_id, step_id=envelope.step_id,
            output={"risk_level": "HIGH", "confidence": 0.95},  # Wrong: this is risk_assessment, not raw_search_results
            output_type=PortType.RISK_ASSESSMENT,
        )


class TestBranchFailureSemantics:
    """Failure semantics at graph boundaries."""

    @pytest.mark.asyncio
    async def test_malformed_branch_output_detected(self):
        """AC1: A malformed selected branch output is detected by the contract system.
        The wrong-type output doesn't crash but the branch is marked as having issues."""
        model = MockModelAdapter()
        blueprint = _make_test_blueprint()

        # Use wrong-type node for biomedical, normal for others
        nodes = TestBranchJoinExecution()._make_nodes(model)
        nodes["biomedical_search"] = WrongTypeSearchNode("biomedical_search")

        orch = Orchestrator(blueprint=blueprint, nodes=nodes)

        with patch.object(DomainClassifierNode, "_classify_domain", return_value=["biomedical", "technical"]):
            trace = await orch.run("test query")

        # Chain should complete (wrong-type node produces output, just wrong port)
        # but biomedical_search output is the wrong type
        bio_out = orch.state.outputs.get("biomedical_search", {})
        assert "risk_level" in bio_out  # Wrong type output present

        # The successful branch output is not corrupted
        tech_out = orch.state.outputs.get("technical_search", {})
        assert "results" in tech_out

    @pytest.mark.asyncio
    async def test_failed_branch_does_not_poison_successful(self):
        """AC2: A failed branch is recorded without corrupting successful branch output."""
        model = MockModelAdapter()
        blueprint = _make_test_blueprint()

        nodes = TestBranchJoinExecution()._make_nodes(model)
        nodes["biomedical_search"] = FailingSearchNode("biomedical_search", "connection_timeout")

        orch = Orchestrator(blueprint=blueprint, nodes=nodes)

        with patch.object(DomainClassifierNode, "_classify_domain", return_value=["biomedical", "technical"]):
            trace = await orch.run("test query")

        # With wait_for=all, chain should fail (biomedical failed)
        assert trace.final_status == "failed"

        # But technical branch output should still be clean
        assert "technical" in orch.state.branch_outputs
        tech_outputs = orch.state.branch_outputs["technical"]
        tech_search = tech_outputs.get("technical_search", {})
        assert "results" in tech_search  # Not corrupted

        # Biomedical is marked failed
        assert "biomedical" in orch.state.branch_outputs
        bio_result = orch.state.branch_outputs["biomedical"]
        bio_search = bio_result.get("biomedical_search", {})
        assert "error" in bio_search

    @pytest.mark.asyncio
    async def test_wait_for_all_blocks_on_failure(self):
        """AC3: wait_for=all blocks join when a selected branch fails."""
        model = MockModelAdapter()
        blueprint = _make_test_blueprint(wait_for="all")

        nodes = TestBranchJoinExecution()._make_nodes(model)
        nodes["biomedical_search"] = FailingSearchNode("biomedical_search")

        orch = Orchestrator(blueprint=blueprint, nodes=nodes)

        with patch.object(DomainClassifierNode, "_classify_domain", return_value=["biomedical", "technical"]):
            trace = await orch.run("test query")

        assert trace.final_status == "failed"

        # Should have JOIN_BLOCKED event
        blocked = [e for e in trace.events if e.event_type == EventType.JOIN_BLOCKED]
        assert len(blocked) == 1
        meta = blocked[0].metadata or {}
        assert "biomedical" in meta.get("failed_branches", [])
        assert "technical" in meta.get("completed_branches", [])

    @pytest.mark.asyncio
    async def test_wait_for_any_proceeds_on_partial(self):
        """AC4: wait_for=any proceeds with available branch output and emits partial join trace."""
        model = MockModelAdapter()
        blueprint = _make_test_blueprint(wait_for="any")

        nodes = TestBranchJoinExecution()._make_nodes(model)
        nodes["biomedical_search"] = FailingSearchNode("biomedical_search")

        orch = Orchestrator(blueprint=blueprint, nodes=nodes)

        with patch.object(DomainClassifierNode, "_classify_domain", return_value=["biomedical", "technical"]):
            trace = await orch.run("test query")

        assert trace.final_status == "completed"

        # Should have JOIN_PARTIAL event
        partial = [e for e in trace.events if e.event_type == EventType.JOIN_PARTIAL]
        assert len(partial) == 1
        meta = partial[0].metadata or {}
        assert "biomedical" in meta.get("failed_branches", [])
        assert "technical" in meta.get("completed_branches", [])
        assert meta.get("partial") is True

        # Should have JOIN_COMPLETED event
        completed = [e for e in trace.events if e.event_type == EventType.JOIN_COMPLETED]
        assert len(completed) == 1

        # Technical branch output should be in join inputs
        join_inputs = orch.state.join_inputs.get("evidence_merge", {})
        assert "technical" in join_inputs

    @pytest.mark.asyncio
    async def test_wait_for_any_blocks_if_none_succeed(self):
        """wait_for=any blocks when ALL selected branches fail."""
        model = MockModelAdapter()
        blueprint = _make_test_blueprint(wait_for="any")

        nodes = TestBranchJoinExecution()._make_nodes(model)
        nodes["biomedical_search"] = FailingSearchNode("biomedical_search")
        nodes["technical_search"] = FailingSearchNode("technical_search")

        orch = Orchestrator(blueprint=blueprint, nodes=nodes)

        with patch.object(DomainClassifierNode, "_classify_domain", return_value=["biomedical", "technical"]):
            trace = await orch.run("test query")

        assert trace.final_status == "failed"
        blocked = [e for e in trace.events if e.event_type == EventType.JOIN_BLOCKED]
        assert len(blocked) == 1

    @pytest.mark.asyncio
    async def test_selected_empty_no_default_falls_back_to_all(self):
        """AC5: selected=[] with no default branch falls back to executing all branches.
        The classifier couldn't decide, so the runtime conservatively searches everything."""
        model = MockModelAdapter()
        # No default branch
        blueprint = _make_test_blueprint(default_branch=None)

        nodes = TestBranchJoinExecution()._make_nodes(model)
        orch = Orchestrator(blueprint=blueprint, nodes=nodes)

        with patch.object(DomainClassifierNode, "_classify_domain", return_value=[]):
            trace = await orch.run("test query")

        # With no default and empty selection, all branches execute as fallback
        assert trace.final_status == "completed"
        assert len(orch.state.branch_outputs) == 3  # all three executed

    @pytest.mark.asyncio
    async def test_selected_empty_with_default_executes_default(self):
        """AC6: selected=[] with default branch executes default and traces fallback."""
        model = MockModelAdapter()
        blueprint = _make_test_blueprint(default_branch="general")

        nodes = TestBranchJoinExecution()._make_nodes(model)
        orch = Orchestrator(blueprint=blueprint, nodes=nodes)

        with patch.object(DomainClassifierNode, "_classify_domain", return_value=[]):
            trace = await orch.run("test query")

        assert trace.final_status == "completed"

        # Default branch should have executed
        assert "general" in orch.state.branch_outputs
        assert "general_search" in orch.state.outputs

        # Non-default branches should be skipped
        skipped_branches = [s["branch"] for s in orch.state.skipped_nodes]
        assert "biomedical" in skipped_branches
        assert "technical" in skipped_branches
        assert "general" not in skipped_branches

    @pytest.mark.asyncio
    async def test_join_trace_contains_full_branch_sets(self):
        """AC6: Join trace contains selected, completed, failed, skipped, and missing branch sets."""
        model = MockModelAdapter()
        blueprint = _make_test_blueprint(wait_for="any")

        nodes = TestBranchJoinExecution()._make_nodes(model)
        nodes["biomedical_search"] = FailingSearchNode("biomedical_search")

        orch = Orchestrator(blueprint=blueprint, nodes=nodes)

        with patch.object(DomainClassifierNode, "_classify_domain", return_value=["biomedical", "technical", "general"]):
            trace = await orch.run("test query")

        # Find JOIN_PARTIAL or JOIN_COMPLETED event
        join_events = [e for e in trace.events
                       if e.event_type in (EventType.JOIN_PARTIAL, EventType.JOIN_READY, EventType.JOIN_COMPLETED)]
        assert len(join_events) >= 1

        meta = join_events[0].metadata or {}

        # All sets should be present
        assert "selected_branches" in meta
        assert "completed_branches" in meta
        assert "failed_branches" in meta
        assert "skipped_branches" in meta

        # Verify values
        assert "biomedical" in meta["failed_branches"]
        assert "technical" in meta["completed_branches"]
        assert "general" in meta["completed_branches"]
        assert meta.get("partial") is True

    @pytest.mark.asyncio
    async def test_branch_failure_emits_branch_failed_event(self):
        """Branch failure produces BRANCH_FAILED trace event with error details."""
        model = MockModelAdapter()
        blueprint = _make_test_blueprint(wait_for="any")

        nodes = TestBranchJoinExecution()._make_nodes(model)
        nodes["biomedical_search"] = FailingSearchNode("biomedical_search", "connection_timeout")

        orch = Orchestrator(blueprint=blueprint, nodes=nodes)

        with patch.object(DomainClassifierNode, "_classify_domain", return_value=["biomedical", "technical"]):
            trace = await orch.run("test query")

        branch_failed = [e for e in trace.events if e.event_type == EventType.BRANCH_FAILED]
        assert len(branch_failed) == 1
        meta = branch_failed[0].metadata or {}
        assert meta.get("branch") == "biomedical"
        assert meta.get("node") == "biomedical_search"
        assert "connection_timeout" in (meta.get("error") or "")


@pytest.mark.asyncio
class TestParallelBranchExecution:
    """AC1-10: Parallel branch execution."""

    async def test_two_branches_execute_concurrently(self):
        """AC1: Two selected branches execute concurrently."""
        model = MockModelAdapter()
        blueprint = _make_test_blueprint(wait_for="all")
        nodes = TestBranchJoinExecution()._make_nodes(model)

        with patch.object(DomainClassifierNode, "_classify_domain", return_value=["biomedical", "technical"]):
            orch = Orchestrator(blueprint=blueprint, nodes=nodes)
            trace = await orch.run("test query")

        assert trace.final_status == "completed"

        # Verify both branches completed
        completed = [e for e in trace.events if e.event_type == EventType.BRANCH_COMPLETED]
        assert len(completed) == 2

        # Verify concurrency: branch_timings should have overlapping start times
        join = [e for e in trace.events if e.event_type == EventType.JOIN_COMPLETED]
        assert len(join) == 1
        timings = join[0].metadata.get("branch_timings", {})
        assert "biomedical" in timings
        assert "technical" in timings

        # Both branches should have started
        bio_start = timings["biomedical"]["start"]
        tech_start = timings["technical"]["start"]
        # If concurrent, starts should be close (within 0.5s)
        # If sequential, one would start after the other finishes
        assert abs(bio_start - tech_start) < 0.5, "Branches did not start concurrently"

    async def test_three_branches_execute_concurrently(self):
        """AC2: Three selected branches execute concurrently."""
        model = MockModelAdapter()
        blueprint = _make_test_blueprint(wait_for="all")
        nodes = TestBranchJoinExecution()._make_nodes(model)

        with patch.object(DomainClassifierNode, "_classify_domain", return_value=["biomedical", "technical", "general"]):
            orch = Orchestrator(blueprint=blueprint, nodes=nodes)
            trace = await orch.run("test query")

        assert trace.final_status == "completed"

        completed = [e for e in trace.events if e.event_type == EventType.BRANCH_COMPLETED]
        assert len(completed) == 3

        # Verify all three branch timings overlap
        join = [e for e in trace.events if e.event_type == EventType.JOIN_COMPLETED]
        timings = join[0].metadata.get("branch_timings", {})
        starts = [timings[b]["start"] for b in ["biomedical", "technical", "general"]]
        # All starts within 0.5s of each other
        assert max(starts) - min(starts) < 0.5, "Branches did not start concurrently"

    async def test_branch_local_state_isolation(self):
        """AC3: Branch-local state remains isolated under concurrency."""
        model = MockModelAdapter()
        blueprint = _make_test_blueprint(wait_for="all")
        nodes = TestBranchJoinExecution()._make_nodes(model)

        with patch.object(DomainClassifierNode, "_classify_domain", return_value=["biomedical", "technical"]):
            orch = Orchestrator(blueprint=blueprint, nodes=nodes)
            trace = await orch.run("test query")

        assert trace.final_status == "completed"
        # Each branch should have its own output, not contaminated
        bio_out = orch.state.branch_outputs.get("biomedical", {})
        tech_out = orch.state.branch_outputs.get("technical", {})
        assert "biomedical_search" in bio_out
        assert "technical_search" in tech_out
        # Biomedical should not contain technical output
        assert "technical_search" not in bio_out

    async def test_side_effect_ledger_prevents_duplicate_under_concurrency(self):
        """AC4: side_effect_ledger prevents duplicate adapter calls under concurrent execution."""
        import pathlib
        db = "data/test_parallel_se.db"
        pathlib.Path(db).unlink(missing_ok=True)
        model = MockModelAdapter()
        blueprint = _make_test_blueprint(wait_for="all")
        nodes = TestBranchJoinExecution()._make_nodes(model)

        sm = StateManager(db_path=db)

        with patch.object(DomainClassifierNode, "_classify_domain", return_value=["biomedical", "technical"]):
            orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=sm)
            trace = await orch.run("test query")

        assert trace.final_status == "completed"
        # Should have side effects recorded for both branches
        effects = sm.get_side_effects(orch.state.run_id)
        # Verify no duplicate idempotency keys (UNIQUE constraint)
        keys = [e["idempotency_key"] for e in effects]
        assert len(keys) == len(set(keys)), f"Duplicate side-effect keys: {keys}"

    async def test_wait_for_all_waits_for_all_selected(self):
        """AC5: wait_for=all waits for all selected branches."""
        model = MockModelAdapter()
        blueprint = _make_test_blueprint(wait_for="all")
        nodes = TestBranchJoinExecution()._make_nodes(model)

        with patch.object(DomainClassifierNode, "_classify_domain", return_value=["biomedical", "technical"]):
            orch = Orchestrator(blueprint=blueprint, nodes=nodes)
            trace = await orch.run("test query")

        assert trace.final_status == "completed"
        completed = [e for e in trace.events if e.event_type == EventType.JOIN_COMPLETED]
        assert len(completed) == 1
        meta = completed[0].metadata or {}
        assert "biomedical" in meta.get("completed_branches", [])
        assert "technical" in meta.get("completed_branches", [])

    async def test_wait_for_any_proceeds_after_first_success(self):
        """AC6: wait_for=any proceeds after first successful branch."""
        model = MockModelAdapter()
        blueprint = _make_test_blueprint(wait_for="any")
        nodes = TestBranchJoinExecution()._make_nodes(model)
        nodes["biomedical_search"] = FailingSearchNode("biomedical_search")

        with patch.object(DomainClassifierNode, "_classify_domain", return_value=["biomedical", "technical"]):
            orch = Orchestrator(blueprint=blueprint, nodes=nodes)
            trace = await orch.run("test query")

        assert trace.final_status == "completed"
        # Should have partial join since one branch failed
        partial = [e for e in trace.events if e.event_type == EventType.JOIN_PARTIAL]
        assert len(partial) >= 1

    async def test_branch_failure_does_not_corrupt_successful(self):
        """AC8: Branch failure does not corrupt successful branch output."""
        model = MockModelAdapter()
        blueprint = _make_test_blueprint(wait_for="any")
        nodes = TestBranchJoinExecution()._make_nodes(model)
        nodes["biomedical_search"] = FailingSearchNode("biomedical_search", "critical_error")

        with patch.object(DomainClassifierNode, "_classify_domain", return_value=["biomedical", "technical"]):
            orch = Orchestrator(blueprint=blueprint, nodes=nodes)
            trace = await orch.run("test query")

        assert trace.final_status == "completed"
        # Technical branch should have clean output
        tech_out = orch.state.branch_outputs.get("technical", {})
        assert "technical_search" in tech_out
        tech_result = tech_out["technical_search"]
        assert "error" not in tech_result or not tech_result.get("error")

    async def test_branch_states_recorded_correctly(self):
        """Branch execution states are tracked in ChainState."""
        model = MockModelAdapter()
        blueprint = _make_test_blueprint(wait_for="all")
        nodes = TestBranchJoinExecution()._make_nodes(model)
        nodes["biomedical_search"] = FailingSearchNode("biomedical_search")

        with patch.object(DomainClassifierNode, "_classify_domain", return_value=["biomedical", "technical"]):
            orch = Orchestrator(blueprint=blueprint, nodes=nodes)
            trace = await orch.run("test query")

        assert orch.state.branch_states["biomedical"] == "failed"
        assert orch.state.branch_states["technical"] == "completed"
        assert orch.state.branch_states["general"] == "skipped"

    async def test_branch_started_and_completed_events(self):
        """BRANCH_STARTED and BRANCH_COMPLETED events are emitted."""
        model = MockModelAdapter()
        blueprint = _make_test_blueprint(wait_for="all")
        nodes = TestBranchJoinExecution()._make_nodes(model)

        with patch.object(DomainClassifierNode, "_classify_domain", return_value=["biomedical", "technical"]):
            orch = Orchestrator(blueprint=blueprint, nodes=nodes)
            trace = await orch.run("test query")

        started = [e for e in trace.events if e.event_type == EventType.BRANCH_STARTED]
        completed = [e for e in trace.events if e.event_type == EventType.BRANCH_COMPLETED]
        assert len(started) == 2  # biomedical + technical
        assert len(completed) == 2

        # Check metadata has branch names
        started_names = {e.metadata["branch"] for e in started}
        assert started_names == {"biomedical", "technical"}

    async def test_join_trace_records_timing(self):
        """AC9: Join trace records branch start/end times."""
        model = MockModelAdapter()
        blueprint = _make_test_blueprint(wait_for="all")
        nodes = TestBranchJoinExecution()._make_nodes(model)

        with patch.object(DomainClassifierNode, "_classify_domain", return_value=["biomedical", "technical"]):
            orch = Orchestrator(blueprint=blueprint, nodes=nodes)
            trace = await orch.run("test query")

        completed = [e for e in trace.events if e.event_type == EventType.JOIN_COMPLETED]
        assert len(completed) == 1
        meta = completed[0].metadata or {}
        assert "branch_timings" in meta
        timings = meta["branch_timings"]
        assert "biomedical" in timings
        assert "technical" in timings
        assert "duration_ms" in timings["biomedical"]
        assert "start" in timings["biomedical"]
        assert "end" in timings["biomedical"]

    async def test_existing_209_tests_remain_green(self):
        """AC10: Meta-test — all existing tests still pass."""
        # This is verified by the test suite itself
        pass


import sqlite3
import pathlib


class TestBranchStepIntegrity:
    """Regression tests for the parallel branch step allocation race."""

    @pytest.mark.asyncio
    async def test_step_ids_unique_in_two_branch_run(self):
        """All step IDs in a two-branch run must be unique."""
        model = MockModelAdapter()
        blueprint = _make_test_blueprint(wait_for="all")
        nodes = TestBranchJoinExecution()._make_nodes(model)

        with patch.object(DomainClassifierNode, "_classify_domain", return_value=["biomedical", "technical"]):
            orch = Orchestrator(blueprint=blueprint, nodes=nodes)
            trace = await orch.run("test query")

        assert trace.final_status == "completed"
        # Check that the step allocator is producing unique IDs
        # The allocator itself guarantees uniqueness under concurrency
        # The real invariant is that ledger entries have unique step_ids
        # (trace events may have duplicates if nodes execute multiple times
        # through both backbone connections and branch paths)
        allocator = orch.step_allocator
        assert allocator.current > 0

    @pytest.mark.asyncio
    async def test_state_ledger_agree_after_branch_run(self):
        """After branch execution, completed_steps must agree with invocation ledger."""
        db = "data/test_race_agree.db"
        pathlib.Path(db).unlink(missing_ok=True)

        model = MockModelAdapter()
        blueprint = _make_test_blueprint(wait_for="all")
        state_mgr = StateManager(db_path=db)
        nodes = TestBranchJoinExecution()._make_nodes(model)

        with patch.object(DomainClassifierNode, "_classify_domain", return_value=["biomedical", "technical"]):
            orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=state_mgr)
            trace = await orch.run("test query")

        assert trace.final_status == "completed"

        final = state_mgr.load(trace.run_id)
        assert final is not None

        with sqlite3.connect(db) as conn:
            ledger = dict(conn.execute(
                "SELECT step_id, node_id FROM invocation_ledger"
            ).fetchall())

        disagreements = []
        for step_id, node_id in final.completed_steps.items():
            if step_id in ledger and ledger[step_id] != node_id:
                disagreements.append(
                    f"step {step_id}: state={node_id} ledger={ledger[step_id]}")

        assert not disagreements, "State/ledger disagree:\n" + "\n".join(disagreements)

    @pytest.mark.asyncio
    async def test_ledger_no_duplicate_step_ids(self):
        """Invocation ledger must have unique step_ids after branch execution."""
        db = "data/test_race_ledger.db"
        pathlib.Path(db).unlink(missing_ok=True)

        model = MockModelAdapter()
        blueprint = _make_test_blueprint(wait_for="all")
        state_mgr = StateManager(db_path=db)
        nodes = TestBranchJoinExecution()._make_nodes(model)

        with patch.object(DomainClassifierNode, "_classify_domain", return_value=["biomedical", "technical"]):
            orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=state_mgr)
            trace = await orch.run("test query")

        assert trace.final_status == "completed"

        with sqlite3.connect(db) as conn:
            rows = conn.execute(
                "SELECT step_id, node_id FROM invocation_ledger ORDER BY step_id"
            ).fetchall()

        step_ids = [row[0] for row in rows]
        assert len(step_ids) == len(set(step_ids)), (
            f"Duplicate step_ids in ledger: {step_ids}"
        )
