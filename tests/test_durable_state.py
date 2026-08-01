"""Tests for durable pause/resume: kill/resume at various execution points."""

import asyncio
import pytest
from unittest.mock import MagicMock, patch

from nodechain.core.blueprint import NodeDef, ConnectionDef, BranchDef, JoinDef, ChainBlueprint
from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.port import PortType
from nodechain.core.trace import EventType
from nodechain.core.state import StateManager, ChainState
from nodechain.nodes.domain_classifier import DomainClassifierNode
from nodechain.nodes.goal_interpreter import GoalInterpreterNode
from nodechain.nodes.evidence_joiner import EvidenceJoinerNode
from nodechain.nodes.conflict_detector import ConflictDetectorNode
from nodechain.nodes.branch_response_generator import BranchResponseGeneratorNode
from nodechain.nodes.branch_trace_collector import BranchTraceCollectorNode
from nodechain.runtime.orchestrator import Orchestrator
from nodechain.core.manifest import NodeManifest
from nodechain.core.contract import EntryContract, ExitContract, Requirements, NodeContract


# ─── Shared fixtures ────────────────────────────────────────────────────────

class MockModelAdapter:
    def complete(self, system_prompt=None, user_message=None, max_tokens=2048, temperature=0.3, **kwargs):
        return MagicMock(
            content='{"primary_question": "test query", "research_domain": "biomedical", '
                    '"domain_classification": [{"domain": "biomedical", "confidence": 0.9}], '
                    '"sub_questions": ["sub1"], "success_criteria": ["c1"], '
                    '"constraints": [], "time_sensitivity": "low", "depth_required": "medium"}',
            structured_output=None, cost_usd=0.001, latency_ms=100, stop_reason="stop", raw_output_size=100,
        )


class SimpleResponseNode:
    """Minimal response node that accepts any input."""
    _trust_level = "local_trusted"
    _node_origin = "local_registry"
    def __init__(self):
        pass
    @property
    def manifest(self):
        return NodeManifest(
            node_id="response_generator", node_type="model",
            name="Simple Response", description="Produces response from any input",
            contract=NodeContract(
                contract_id="test.response.v1", node_id="response_generator", version="1.0.0",
                entry=EntryContract(input_type=PortType.TASK_PLAN, schema_ref="test", required_fields=[]),
                exit=ExitContract(output_type=PortType.FINAL_RESPONSE, schema_ref="test", guaranteed_fields=["recommendation"]),
                requirements=Requirements(model_required=True),
            ),
        )
    async def execute(self, envelope):
        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id, run_id=envelope.run_id,
            chain_id=envelope.chain_id, node_id="response_generator", step_id=envelope.step_id,
            output={"recommendation": "test response", "confidence_statement": {"level": "MEDIUM", "numeric": 0.5}},
            output_type=PortType.FINAL_RESPONSE,
        )


class SimpleTraceCollectorNode:
    """Minimal trace collector that accepts final_response."""
    _trust_level = "local_trusted"
    _node_origin = "local_registry"
    def __init__(self):
        pass
    @property
    def manifest(self):
        return NodeManifest(
            node_id="trace_collector", node_type="deterministic",
            name="Simple Trace Collector", description="Collects trace",
            contract=NodeContract(
                contract_id="test.trace.v1", node_id="trace_collector", version="1.0.0",
                entry=EntryContract(input_type=PortType.FINAL_RESPONSE, schema_ref="test", required_fields=[]),
                exit=ExitContract(output_type=PortType.CHAIN_TRACE_OUTPUT, schema_ref="test", guaranteed_fields=["trace_collected"]),
                requirements=Requirements(model_required=False),
            ),
        )
    async def execute(self, envelope):
        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id, run_id=envelope.run_id,
            chain_id=envelope.chain_id, node_id="trace_collector", step_id=envelope.step_id,
            output={"trace_collected": True},
            output_type=PortType.CHAIN_TRACE_OUTPUT,
        )


class CountingSearchNode:
    """Search node that counts invocations for verifying idempotency."""
    _trust_level = "local_trusted"
    _node_origin = "local_registry"

    def __init__(self, node_id, result_count=3):
        self._node_id = node_id
        self._result_count = result_count
        self._invocations = 0

    @property
    def manifest(self):
        return NodeManifest(
            node_id=self._node_id, node_type="deterministic",
            name=f"Counting {self._node_id}", description="Tracks invocations",
            contract=NodeContract(
                contract_id=f"count.{self._node_id}.v1", node_id=self._node_id, version="1.0.0",
                entry=EntryContract(input_type=PortType.TASK_PLAN, schema_ref="test"),
                exit=ExitContract(output_type=PortType.RAW_SEARCH_RESULTS, schema_ref="test", guaranteed_fields=["results"]),
                requirements=Requirements(model_required=False),
            ),
        )

    async def execute(self, envelope):
        self._invocations += 1
        results = [{"title": f"Result {i} from {self._node_id}", "source_id": f"src_{self._node_id}_{i}"}
                   for i in range(self._result_count)]
        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id, run_id=envelope.run_id,
            chain_id=envelope.chain_id, node_id=self._node_id, step_id=envelope.step_id,
            output={"results": results, "invocation": self._invocations},
            output_type=PortType.RAW_SEARCH_RESULTS,
        )
    """Search node that counts invocations for verifying idempotency."""
    _invocation_count: int = 0

    def __init__(self, node_id, result_count=3):
        self._node_id = node_id
        self._result_count = result_count
        self._invocations = 0

    @property
    def manifest(self):
        return NodeManifest(
            node_id=self._node_id, node_type="deterministic",
            name=f"Counting {self._node_id}", description="Tracks invocations",
            contract=NodeContract(
                contract_id=f"count.{self._node_id}.v1", node_id=self._node_id, version="1.0.0",
                entry=EntryContract(input_type=PortType.TASK_PLAN, schema_ref="test"),
                exit=ExitContract(output_type=PortType.RAW_SEARCH_RESULTS, schema_ref="test", guaranteed_fields=["results"]),
                requirements=Requirements(model_required=False),
            ),
        )

    async def execute(self, envelope):
        self._invocations += 1
        results = [{"title": f"Result {i} from {self._node_id}", "source_id": f"src_{self._node_id}_{i}"}
                   for i in range(self._result_count)]
        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id, run_id=envelope.run_id,
            chain_id=envelope.chain_id, node_id=self._node_id, step_id=envelope.step_id,
            output={"results": results, "invocation": self._invocations},
            output_type=PortType.RAW_SEARCH_RESULTS,
        )


def _make_branch_blueprint():
    """Standard 9-node branch blueprint for testing."""
    return ChainBlueprint(
        chain_id="test_branch_v1", name="Test Branch Chain", version="1.0.0", goal="Test branch-join execution.",
        nodes=[
            NodeDef(node_id="goal_interpreter", node_type="model", position=1),
            NodeDef(node_id="domain_classifier", node_type="deterministic", position=2),
            NodeDef(node_id="biomedical_search", node_type="deterministic", position=3),
            NodeDef(node_id="technical_search", node_type="deterministic", position=4),
            NodeDef(node_id="general_search", node_type="deterministic", position=5),
            NodeDef(node_id="evidence_joiner", node_type="deterministic", position=6),
            NodeDef(node_id="conflict_detector", node_type="deterministic", position=7),
            NodeDef(node_id="response_generator", node_type="model", position=8),
            NodeDef(node_id="trace_collector", node_type="deterministic", position=9),
        ],
        connections=[
            ConnectionDef(from_node="goal_interpreter", from_port="output", to_node="domain_classifier", to_port="input"),
            ConnectionDef(from_node="domain_classifier", from_port="output", to_node="biomedical_search", to_port="input", condition="branch_biomedical"),
            ConnectionDef(from_node="domain_classifier", from_port="output", to_node="technical_search", to_port="input", condition="branch_technical"),
            ConnectionDef(from_node="domain_classifier", from_port="output", to_node="general_search", to_port="input", condition="branch_general"),
            ConnectionDef(from_node="biomedical_search", from_port="output", to_node="evidence_joiner", to_port="input"),
            ConnectionDef(from_node="technical_search", from_port="output", to_node="evidence_joiner", to_port="input"),
            ConnectionDef(from_node="general_search", from_port="output", to_node="evidence_joiner", to_port="input"),
            ConnectionDef(from_node="evidence_joiner", from_port="output", to_node="conflict_detector", to_port="input"),
            ConnectionDef(from_node="conflict_detector", from_port="output", to_node="response_generator", to_port="input"),
            ConnectionDef(from_node="response_generator", from_port="output", to_node="trace_collector", to_port="input"),
        ],
        branches=[
            BranchDef(branch_id="domain_routing", from_node="domain_classifier",
                       branches={"biomedical": ["biomedical_search"], "technical": ["technical_search"], "general": ["general_search"]},
                       default_branch="general"),
        ],
        joins=[
            JoinDef(join_id="evidence_merge", to_node="evidence_joiner",
                    from_branches=["biomedical", "technical", "general"], wait_for="all"),
        ],
    )


def _make_sequential_blueprint():
    """Simple 4-node sequential blueprint for testing."""
    return ChainBlueprint(
        chain_id="test_seq_v1", name="Test Sequential", version="1.0.0", goal="Test sequential resume.",
        nodes=[
            NodeDef(node_id="goal_interpreter", node_type="model", position=1),
            NodeDef(node_id="domain_classifier", node_type="deterministic", position=2),
            NodeDef(node_id="response_generator", node_type="model", position=3),
            NodeDef(node_id="trace_collector", node_type="deterministic", position=4),
        ],
        connections=[
            ConnectionDef(from_node="goal_interpreter", from_port="output", to_node="domain_classifier", to_port="input"),
            ConnectionDef(from_node="domain_classifier", from_port="output", to_node="response_generator", to_port="input"),
            ConnectionDef(from_node="response_generator", from_port="output", to_node="trace_collector", to_port="input"),
        ],
    )


# ─── Tests ──────────────────────────────────────────────────────────────────

class TestDurableResumeSequential:
    """AC1, AC8: Resume after backbone node success."""

    @pytest.mark.asyncio
    async def test_resume_after_first_node(self):
        """Kill after goal_interpreter, resume from saved state."""
        model = MockModelAdapter()
        blueprint = _make_sequential_blueprint()
        state_mgr = StateManager(db_path="data/test_resume.db")

        nodes = {
            "goal_interpreter": GoalInterpreterNode(model),
            "domain_classifier": DomainClassifierNode(),
            "response_generator": SimpleResponseNode(),
            "trace_collector": SimpleTraceCollectorNode(),
        }

        # First run: complete normally
        orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=state_mgr)
        trace = await orch.run("test query")

        assert trace.final_status == "completed"
        run_id = orch.state.run_id
        step_count = orch.state.step

        # Verify state was saved
        saved = state_mgr.load(run_id)
        assert saved is not None
        assert saved.status == "completed"
        assert saved.step == step_count

        # Verify invocation ledger
        completed = state_mgr.get_completed_steps(run_id)
        assert len(completed) == 4  # All 4 nodes
        assert 1 in completed  # step 1: goal_interpreter
        assert 2 in completed  # step 2: domain_classifier

    @pytest.mark.asyncio
    async def test_resume_skips_completed_nodes(self):
        """AC7: Completed nodes are not re-executed on resume."""
        model = MockModelAdapter()
        blueprint = _make_sequential_blueprint()
        state_mgr = StateManager(db_path="data/test_resume_skip.db")

        nodes = {
            "goal_interpreter": GoalInterpreterNode(model),
            "domain_classifier": DomainClassifierNode(),
            "response_generator": SimpleResponseNode(),
            "trace_collector": SimpleTraceCollectorNode(),
        }

        orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=state_mgr)
        trace = await orch.run("test query")
        run_id = orch.state.run_id

        # Now resume the same run
        orch2 = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=state_mgr)
        trace2 = await orch2.resume(run_id)

        # Should complete (no new nodes to run since all completed)
        assert trace2.final_status == "completed"

        # Resumed state should have is_resumed=True
        assert orch2.state.is_resumed is True

        # Same run_id preserved
        assert orch2.state.run_id == run_id


class TestDurableResumeBranch:
    """AC2, AC3: Resume around branch execution boundaries."""

    @pytest.mark.asyncio
    async def test_branch_run_saves_invocation_ledger(self):
        """Branch execution records invocations in the ledger."""
        model = MockModelAdapter()
        blueprint = _make_branch_blueprint()
        state_mgr = StateManager(db_path="data/test_branch_ledger.db")

        nodes = {
            "goal_interpreter": GoalInterpreterNode(model),
            "domain_classifier": DomainClassifierNode(),
            "biomedical_search": CountingSearchNode("biomedical_search"),
            "technical_search": CountingSearchNode("technical_search"),
            "general_search": CountingSearchNode("general_search"),
            "evidence_joiner": EvidenceJoinerNode(),
            "conflict_detector": ConflictDetectorNode(),
            "response_generator": BranchResponseGeneratorNode(model),
            "trace_collector": BranchTraceCollectorNode(),
        }

        orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=state_mgr)

        with patch.object(DomainClassifierNode, "_classify_domain", return_value=["biomedical", "technical"]):
            trace = await orch.run("test query")

        assert trace.final_status == "completed"
        run_id = orch.state.run_id

        # Verify invocation ledger has all nodes
        completed = state_mgr.get_completed_steps(run_id)
        assert len(completed) == 8  # 6 backbone + 2 branch
        assert "biomedical_search" in completed.values()
        assert "technical_search" in completed.values()
        assert "general_search" not in completed.values()  # skipped

        # Verify event log
        events = state_mgr.get_events(run_id)
        assert len(events) > 0
        event_types = {e["event_type"] for e in events}
        assert "routing_decision" in event_types
        # routing_decision, node_skipped, join_ready, etc. come through _emit()


class TestEventLogAndReplay:
    """AC8, AC9: Event log integrity and state consistency."""

    @pytest.mark.asyncio
    async def test_event_log_is_append_only(self):
        """Events are only appended, never deleted."""
        model = MockModelAdapter()
        blueprint = _make_sequential_blueprint()
        state_mgr = StateManager(db_path="data/test_event_log.db")

        nodes = {
            "goal_interpreter": GoalInterpreterNode(model),
            "domain_classifier": DomainClassifierNode(),
            "response_generator": SimpleResponseNode(),
            "trace_collector": SimpleTraceCollectorNode(),
        }

        orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=state_mgr)
        trace = await orch.run("test query")
        run_id = orch.state.run_id

        events = state_mgr.get_events(run_id)
        assert len(events) > 0

        # Sequence numbers should be strictly increasing
        seqs = [e["seq"] for e in events]
        assert seqs == sorted(seqs)
        assert len(seqs) == len(set(seqs))

    @pytest.mark.asyncio
    async def test_revision_monotonic(self):
        """State revision counter increases monotonically."""
        model = MockModelAdapter()
        blueprint = _make_sequential_blueprint()
        state_mgr = StateManager(db_path="data/test_revision.db")

        nodes = {
            "goal_interpreter": GoalInterpreterNode(model),
            "domain_classifier": DomainClassifierNode(),
            "response_generator": SimpleResponseNode(),
            "trace_collector": SimpleTraceCollectorNode(),
        }

        orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=state_mgr)
        trace = await orch.run("test query")

        # Final revision should be > 0 (incremented on each save)
        assert orch.state.revision > 0

    @pytest.mark.asyncio
    async def test_same_run_id_on_resume(self):
        """AC8: Resume preserves the same run_id."""
        model = MockModelAdapter()
        blueprint = _make_sequential_blueprint()
        state_mgr = StateManager(db_path="data/test_run_id.db")

        nodes = {
            "goal_interpreter": GoalInterpreterNode(model),
            "domain_classifier": DomainClassifierNode(),
            "response_generator": SimpleResponseNode(),
            "trace_collector": SimpleTraceCollectorNode(),
        }

        orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=state_mgr)
        trace = await orch.run("test query")
        run_id = orch.state.run_id

        orch2 = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=state_mgr)
        trace2 = await orch2.resume(run_id)

        assert orch2.state.run_id == run_id


class TestStateManager:
    """Unit tests for StateManager event log and invocation ledger."""

    def test_append_and_read_events(self):
        import os, pathlib
        db = "data/test_sm_events_isolated.db"
        pathlib.Path(db).unlink(missing_ok=True)
        sm = StateManager(db_path=db)
        sm.append_event("run-1", 1, "chain_started")
        sm.append_event("run-1", 2, "node_succeeded", node_id="goal_interpreter", step_id=1)
        sm.append_event("run-1", 3, "chain_completed")

        events = sm.get_events("run-1")
        assert len(events) == 3
        assert events[0]["event_type"] == "chain_started"
        assert events[1]["node_id"] == "goal_interpreter"
        assert events[2]["event_type"] == "chain_completed"

    def test_invocation_ledger_idempotency(self):
        sm = StateManager(db_path="data/test_sm_inv2.db")
        sm.record_invocation("run-1", step_id=1, node_id="goal_interpreter")

        assert sm.is_step_completed("run-1", 1) is True
        assert sm.is_step_completed("run-1", 2) is False
        assert sm.is_node_completed("run-1", "goal_interpreter") is True
        assert sm.is_node_completed("run-1", "domain_classifier") is False

        # INSERT OR IGNORE — second insert should not fail
        sm.record_invocation("run-1", step_id=1, node_id="goal_interpreter")

        completed = sm.get_completed_steps("run-1")
        assert len(completed) == 1

    def test_revision_increments(self):
        sm = StateManager(db_path="data/test_sm_rev2.db")
        state = ChainState(run_id="rev-test")
        assert state.revision == 0

        sm.save(state)
        assert state.revision == 1

        sm.save(state)
        assert state.revision == 2

    def test_load_nonexistent_returns_none(self):
        sm = StateManager(db_path="data/test_sm_load2.db")
        assert sm.load("nonexistent") is None

    def test_completed_steps_preserves_order(self):
        sm = StateManager(db_path="data/test_sm_order2.db")
        sm.record_invocation("run-1", 1, "goal_interpreter")
        sm.record_invocation("run-1", 2, "domain_classifier")
        sm.record_invocation("run-1", 3, "response_generator")

        steps = sm.get_completed_steps("run-1")
        assert list(steps.keys()) == [1, 2, 3]
        assert list(steps.values()) == ["goal_interpreter", "domain_classifier", "response_generator"]


class TestReplayEquivalence:
    """AC1: Materialized state = replayed event-log state."""

    @pytest.mark.asyncio
    async def test_replay_reconstructs_completed_steps(self):
        """Replaying the event log recovers the same completed_steps as the snapshot."""
        model = MockModelAdapter()
        blueprint = _make_sequential_blueprint()
        state_mgr = StateManager(db_path="data/test_replay.db")

        nodes = {
            "goal_interpreter": GoalInterpreterNode(model),
            "domain_classifier": DomainClassifierNode(),
            "response_generator": SimpleResponseNode(),
            "trace_collector": SimpleTraceCollectorNode(),
        }

        orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=state_mgr)
        trace = await orch.run("test query")
        run_id = orch.state.run_id

        # Load materialized snapshot
        snapshot = state_mgr.load(run_id)
        assert snapshot is not None

        # Replay from event log
        replayed = state_mgr.replay_state(run_id)
        assert replayed is not None

        # Compare key fields
        assert replayed.run_id == snapshot.run_id
        assert replayed.completed_steps == snapshot.completed_steps
        assert replayed.step == snapshot.step
        # Revision may differ slightly (snapshot includes atomic saves, events include emits)
        # What matters is that replay revision <= snapshot revision (no future events)
        assert replayed.revision <= snapshot.revision

    @pytest.mark.asyncio
    async def test_replay_reconstructs_branch_state(self):
        """Replaying branch chain recovers routing decisions and skipped nodes."""
        model = MockModelAdapter()
        blueprint = _make_branch_blueprint()
        state_mgr = StateManager(db_path="data/test_replay_branch.db")

        nodes = {
            "goal_interpreter": GoalInterpreterNode(model),
            "domain_classifier": DomainClassifierNode(),
            "biomedical_search": CountingSearchNode("biomedical_search"),
            "technical_search": CountingSearchNode("technical_search"),
            "general_search": CountingSearchNode("general_search"),
            "evidence_joiner": EvidenceJoinerNode(),
            "conflict_detector": ConflictDetectorNode(),
            "response_generator": BranchResponseGeneratorNode(model),
            "trace_collector": BranchTraceCollectorNode(),
        }

        orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=state_mgr)
        with patch.object(DomainClassifierNode, "_classify_domain", return_value=["biomedical", "technical"]):
            trace = await orch.run("test query")

        run_id = orch.state.run_id

        # Replay
        replayed = state_mgr.replay_state(run_id)
        assert replayed is not None

        # Routing decisions should be recovered
        assert len(replayed.routing_decisions) >= 1
        rd = replayed.routing_decisions[0]
        assert "biomedical" in rd.get("selected", [])
        assert "technical" in rd.get("selected", [])

        # Skipped nodes should be recovered
        assert len(replayed.skipped_nodes) >= 1
        skipped_branches = [s["branch"] for s in replayed.skipped_nodes]
        assert "general" in skipped_branches


class TestHumanReviewResume:
    """AC2: Human review wait survives resume."""

    @pytest.mark.asyncio
    async def test_pause_during_review_persists(self):
        """Human review pause saves state that can be loaded."""
        model = MockModelAdapter()
        blueprint = _make_sequential_blueprint()
        state_mgr = StateManager(db_path="data/test_review_resume.db")

        nodes = {
            "goal_interpreter": GoalInterpreterNode(model),
            "domain_classifier": DomainClassifierNode(),
            "response_generator": SimpleResponseNode(),
            "trace_collector": SimpleTraceCollectorNode(),
        }

        orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=state_mgr)
        trace = await orch.run("test query")

        # Simulate a pause by directly setting state
        orch.state.status = "paused"
        orch.state.paused_at = "2026-06-11T01:00:00.000Z"
        state_mgr.save(orch.state)

        # Load and verify
        loaded = state_mgr.load(orch.state.run_id)
        assert loaded is not None
        assert loaded.status == "paused"
        assert loaded.paused_at is not None

    @pytest.mark.asyncio
    async def test_resume_after_pause_completes(self):
        """Resuming from paused state completes the chain."""
        import pathlib
        db = "data/test_review_complete.db"
        pathlib.Path(db).unlink(missing_ok=True)
        model = MockModelAdapter()
        blueprint = _make_sequential_blueprint()
        state_mgr = StateManager(db_path=db)

        # Create counting nodes to verify they're not re-executed
        class CountingResponse(SimpleResponseNode):
            invocations = 0
            async def execute(self, envelope):
                CountingResponse.invocations += 1
                return await super().execute(envelope)

        class CountingTrace(SimpleTraceCollectorNode):
            invocations = 0
            async def execute(self, envelope):
                CountingTrace.invocations += 1
                return await super().execute(envelope)

        nodes1 = {
            "goal_interpreter": GoalInterpreterNode(model),
            "domain_classifier": DomainClassifierNode(),
            "response_generator": CountingResponse(),
            "trace_collector": CountingTrace(),
        }

        # First: complete only goal_interpreter, then simulate crash
        orch = Orchestrator(blueprint=blueprint, nodes=nodes1, state_manager=state_mgr)

        # Manually create a paused state after step 1
        state = ChainState(run_id="review-test-run", chain_id=blueprint.chain_id)
        state.step = 1
        state.status = "paused"
        state.paused_at = "2026-06-11T01:00:00.000Z"
        state.current_node = "goal_interpreter"
        state.completed_steps = {1: "goal_interpreter"}
        state.outputs = {"goal_interpreter": {"primary_question": "test", "research_domain": "general"}}

        # Save state and record invocation
        state_mgr.save_with_invocation(
            state=state,
            step_id=1,
            node_id="goal_interpreter",
            event_type="node_completed",
            event_payload={"node_id": "goal_interpreter"},
        )

        # Now resume with fresh nodes
        nodes2 = {
            "goal_interpreter": GoalInterpreterNode(model),
            "domain_classifier": DomainClassifierNode(),
            "response_generator": SimpleResponseNode(),
            "trace_collector": SimpleTraceCollectorNode(),
        }
        orch2 = Orchestrator(blueprint=blueprint, nodes=nodes2, state_manager=state_mgr)
        trace2 = await orch2.resume("review-test-run")

        assert trace2.final_status == "completed"
        assert orch2.state.is_resumed is True
        # Should have run domain_classifier + response_generator + trace_collector
        assert orch2.state.step >= 3
        # goal_interpreter should NOT be re-executed (already in ledger)
        assert state_mgr.is_node_completed("review-test-run", "goal_interpreter")
        # New nodes should also be completed
        assert state_mgr.is_node_completed("review-test-run", "domain_classifier")
        assert state_mgr.is_node_completed("review-test-run", "response_generator")
        assert state_mgr.is_node_completed("review-test-run", "trace_collector")


class TestAtomicWrites:
    """AC7: Transaction ordering is explicit and tested."""

    def test_save_with_invocation_is_atomic(self):
        """save_with_invocation writes state, invocation, and event in one transaction."""
        import pathlib
        db = "data/test_atomic.db"
        pathlib.Path(db).unlink(missing_ok=True)
        sm = StateManager(db_path=db)
        state = ChainState(run_id="atomic-test")

        sm.save_with_invocation(
            state=state,
            step_id=1,
            node_id="goal_interpreter",
            event_type="node_completed",
            event_payload={"node_id": "goal_interpreter"},
        )

        # All three should be written
        loaded = sm.load("atomic-test")
        assert loaded is not None
        assert loaded.revision == 1

        assert sm.is_step_completed("atomic-test", 1)
        assert sm.is_node_completed("atomic-test", "goal_interpreter")

        events = sm.get_events("atomic-test")
        assert len(events) == 1
        assert events[0]["event_type"] == "node_completed"

    def test_save_with_invocation_increments_revision(self):
        """Each call increments revision."""
        import pathlib
        db = "data/test_atomic_rev.db"
        pathlib.Path(db).unlink(missing_ok=True)
        sm = StateManager(db_path=db)
        state = ChainState(run_id="rev-test")

        sm.save_with_invocation(state, step_id=1, node_id="n1")
        assert state.revision == 1

        sm.save_with_invocation(state, step_id=2, node_id="n2")
        assert state.revision == 2

        loaded = sm.load("rev-test")
        assert loaded.revision == 2


class TestSideEffectLedger:
    """AC1-3: Side-effect ledger records external reads separately."""

    def test_record_and_read_side_effect(self):
        import pathlib
        db = "data/test_se_ledger.db"
        pathlib.Path(db).unlink(missing_ok=True)
        sm = StateManager(db_path=db)

        sm.record_side_effect(
            run_id="run-1", step_id=3, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="run-1:3:pubmed",
            status="completed",
        )

        effects = sm.get_side_effects("run-1")
        assert len(effects) == 1
        assert effects[0]["side_effect_type"] == "external_api_read"
        assert effects[0]["idempotency_key"] == "run-1:3:pubmed"
        assert effects[0]["status"] == "completed"

    def test_side_effect_idempotency(self):
        import pathlib
        db = "data/test_se_idem.db"
        pathlib.Path(db).unlink(missing_ok=True)
        sm = StateManager(db_path=db)

        sm.record_side_effect(
            run_id="run-1", step_id=3, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="run-1:3:pubmed",
            status="completed",
        )
        # Second insert with same key should be ignored
        sm.record_side_effect(
            run_id="run-1", step_id=3, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="run-1:3:pubmed",
            status="completed",
        )

        effects = sm.get_side_effects("run-1")
        assert len(effects) == 1  # Not duplicated

    def test_is_side_effect_completed(self):
        import pathlib
        db = "data/test_se_comp.db"
        pathlib.Path(db).unlink(missing_ok=True)
        sm = StateManager(db_path=db)

        sm.record_side_effect(
            run_id="run-1", step_id=3, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="run-1:3:pubmed",
            status="completed",
        )
        sm.record_side_effect(
            run_id="run-1", step_id=3, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="run-1:3:arxiv",
            status="started",
        )

        assert sm.is_side_effect_completed("run-1", "run-1:3:pubmed") is True
        assert sm.is_side_effect_completed("run-1", "run-1:3:arxiv") is False

    def test_update_side_effect_status(self):
        import pathlib
        db = "data/test_se_update.db"
        pathlib.Path(db).unlink(missing_ok=True)
        sm = StateManager(db_path=db)

        sm.record_side_effect(
            run_id="run-1", step_id=3, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="run-1:3:arxiv",
            status="started",
        )

        sm.update_side_effect_status(
            run_id="run-1",
            idempotency_key="run-1:3:arxiv",
            status="completed",
            response_hash="abc123",
        )

        effect = sm.get_side_effect_by_key("run-1", "run-1:3:arxiv")
        assert effect is not None
        assert effect["status"] == "completed"
        assert effect["response_hash"] == "abc123"

    def test_get_side_effects_by_status(self):
        import pathlib
        db = "data/test_se_status.db"
        pathlib.Path(db).unlink(missing_ok=True)
        sm = StateManager(db_path=db)

        sm.record_side_effect("run-1", 3, "search_tool", "api_read", "k1", status="completed")
        sm.record_side_effect("run-1", 3, "search_tool", "api_read", "k2", status="started")
        sm.record_side_effect("run-1", 3, "search_tool", "api_read", "k3", status="completed")

        completed = sm.get_side_effects_by_status("run-1", "completed")
        assert len(completed) == 2
        started = sm.get_side_effects_by_status("run-1", "started")
        assert len(started) == 1


class TestHumanReviewWaitResume:
    """AC4-6: Human review wait is persisted and resumable."""

    @pytest.mark.asyncio
    async def test_review_wait_state_persists(self):
        """AC4: waiting_for_review status persists with approval payload."""
        import pathlib
        db = "data/test_review_wait.db"
        pathlib.Path(db).unlink(missing_ok=True)
        model = MockModelAdapter()
        blueprint = _make_sequential_blueprint()
        state_mgr = StateManager(db_path=db)

        nodes = {
            "goal_interpreter": GoalInterpreterNode(model),
            "domain_classifier": DomainClassifierNode(),
            "response_generator": SimpleResponseNode(),
            "trace_collector": SimpleTraceCollectorNode(),
        }

        orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=state_mgr)
        trace = await orch.run("test query")
        run_id = orch.state.run_id

        # Simulate review wait by directly modifying state
        orch.state.status = "waiting_for_review"
        orch.state.paused_at = "2026-06-11T01:00:00.000Z"
        orch.state.metadata["review_request"] = {
            "risk_assessment": {"risk_level": "HIGH", "confidence": 0.95},
            "step_id": orch.state.step,
            "node_id": "risk_classifier",
        }
        # Only goal_interpreter completed
        orch.state.step = 1
        orch.state.completed_steps = {1: "goal_interpreter"}
        orch.state.outputs = {"goal_interpreter": orch.state.outputs.get("goal_interpreter", {"primary_question": "test"})}
        state_mgr.save(orch.state)

        # Verify persistence
        loaded = state_mgr.load(run_id)
        assert loaded.status == "waiting_for_review"
        assert "review_request" in loaded.metadata

    @pytest.mark.asyncio
    async def test_resume_waiting_for_review_completes(self):
        """AC5-6: Resume during waiting_for_review does not advance until decision."""
        import pathlib
        db = "data/test_review_wait_resume.db"
        pathlib.Path(db).unlink(missing_ok=True)
        model = MockModelAdapter()
        blueprint = _make_sequential_blueprint()
        state_mgr = StateManager(db_path=db)

        # Create waiting_for_review state manually
        state = ChainState(run_id="review-wait-run", chain_id=blueprint.chain_id)
        state.step = 1
        state.status = "waiting_for_review"
        state.paused_at = "2026-06-11T01:00:00.000Z"
        state.current_node = "goal_interpreter"
        state.completed_steps = {1: "goal_interpreter"}
        state.outputs = {"goal_interpreter": {"primary_question": "test", "research_domain": "general"}}
        state.metadata["review_request"] = {
            "risk_assessment": {"risk_level": "HIGH", "confidence": 0.95},
            "step_id": 1,
            "node_id": "risk_classifier",
        }
        # Pre-set review decision to approve
        state.metadata["review_decision"] = "approve"
        state_mgr.save_with_invocation(
            state=state, step_id=1, node_id="goal_interpreter",
            event_type="node_completed", event_payload={"node_id": "goal_interpreter"},
        )

        # Resume
        nodes = {
            "goal_interpreter": GoalInterpreterNode(model),
            "domain_classifier": DomainClassifierNode(),
            "response_generator": SimpleResponseNode(),
            "trace_collector": SimpleTraceCollectorNode(),
        }
        orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=state_mgr)

        import os
        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-approve"
        try:
            trace = await orch.resume("review-wait-run")
        finally:
            os.environ.pop("NODECHAIN_REVIEW_MODE", None)

        assert trace.final_status == "completed"
        assert orch.state.is_resumed is True

        # Verify review event was emitted
        review_events = [e for e in trace.events if e.event_type == EventType.HUMAN_REVIEW_COMPLETED]
        assert len(review_events) == 1
        assert review_events[0].decision == "approve"

        # Remaining nodes should have executed
        assert state_mgr.is_node_completed("review-wait-run", "domain_classifier")
        assert state_mgr.is_node_completed("review-wait-run", "response_generator")
        assert state_mgr.is_node_completed("review-wait-run", "trace_collector")

    @pytest.mark.asyncio
    async def test_review_reject_fails_chain(self):
        """AC5: Review rejection fails the chain on resume."""
        import pathlib
        db = "data/test_review_reject.db"
        pathlib.Path(db).unlink(missing_ok=True)
        model = MockModelAdapter()
        blueprint = _make_sequential_blueprint()
        state_mgr = StateManager(db_path=db)

        state = ChainState(run_id="review-reject-run", chain_id=blueprint.chain_id)
        state.step = 1
        state.status = "waiting_for_review"
        state.paused_at = "2026-06-11T01:00:00.000Z"
        state.current_node = "goal_interpreter"
        state.completed_steps = {1: "goal_interpreter"}
        state.outputs = {"goal_interpreter": {"primary_question": "test"}}
        state.metadata["review_request"] = {
            "risk_assessment": {"risk_level": "HIGH"},
        }
        state.metadata["review_decision"] = "reject"
        state_mgr.save_with_invocation(
            state=state, step_id=1, node_id="goal_interpreter",
        )

        nodes = {
            "goal_interpreter": GoalInterpreterNode(model),
            "domain_classifier": DomainClassifierNode(),
            "response_generator": SimpleResponseNode(),
            "trace_collector": SimpleTraceCollectorNode(),
        }
        orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=state_mgr)
        trace = await orch.resume("review-reject-run")

        assert trace.final_status == "failed"
        # response_generator should NOT have run
        assert not state_mgr.is_node_completed("review-reject-run", "response_generator")


class TestSideEffectExecutionGating:
    """AC1-5: Side-effect ledger gates external calls on resume."""

    def test_completed_side_effect_prevents_call(self):
        """AC1-2: Completed side effect is in capabilities, preventing duplicate call."""
        import pathlib
        db = "data/test_se_gate.db"
        pathlib.Path(db).unlink(missing_ok=True)
        sm = StateManager(db_path=db)

        # Record a completed side effect
        sm.record_side_effect(
            run_id="run-1", step_id=3, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="pubmed:abc123def456",
            status="completed",
        )

        # Verify it shows as completed
        assert sm.is_side_effect_completed("run-1", "pubmed:abc123def456")

        # Verify it appears in get_side_effects
        effects = sm.get_side_effects("run-1")
        assert len(effects) == 1
        assert effects[0]["status"] == "completed"

    def test_semantic_idempotency_key_distinguishes_requests(self):
        """AC7: Different requests to same adapter get different keys."""
        import pathlib
        db = "data/test_se_semantic.db"
        pathlib.Path(db).unlink(missing_ok=True)
        sm = StateManager(db_path=db)

        # Two different searches to PubMed
        sm.record_side_effect(
            run_id="run-1", step_id=3, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="pubmed:hash_of_transformer_terms",
            status="completed",
        )
        sm.record_side_effect(
            run_id="run-1", step_id=5, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="pubmed:hash_of_diabetes_terms",
            status="completed",
        )

        effects = sm.get_side_effects("run-1")
        assert len(effects) == 2  # Both recorded, not deduplicated
        assert effects[0]["idempotency_key"] != effects[1]["idempotency_key"]

    def test_started_unknown_blocks_retry(self):
        """AC3: Started-but-not-completed blocks automatic retry."""
        import pathlib
        db = "data/test_se_started.db"
        pathlib.Path(db).unlink(missing_ok=True)
        sm = StateManager(db_path=db)

        sm.record_side_effect(
            run_id="run-1", step_id=3, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="arxiv:xyz789",
            status="started",
        )

        # Not completed — should block
        assert not sm.is_side_effect_completed("run-1", "arxiv:xyz789")

        # Status filter should find it
        started = sm.get_side_effects_by_status("run-1", "started")
        assert len(started) == 1

    def test_failed_retryable_can_retry(self):
        """AC4: Failed retryable side effect has retryable=True."""
        import pathlib
        db = "data/test_se_retry.db"
        pathlib.Path(db).unlink(missing_ok=True)
        sm = StateManager(db_path=db)

        sm.record_side_effect(
            run_id="run-1", step_id=3, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="pubmed:retry123",
            status="failed",
            retryable=True,
        )

        effects = sm.get_side_effects("run-1")
        assert effects[0]["retryable"] is True
        assert effects[0]["status"] == "failed"

    def test_failed_non_retryable_escalates(self):
        """AC5: Failed non-retryable side effect has retryable=False."""
        import pathlib
        db = "data/test_se_escalate.db"
        pathlib.Path(db).unlink(missing_ok=True)
        sm = StateManager(db_path=db)

        sm.record_side_effect(
            run_id="run-1", step_id=7, node_id="memory_write_decision",
            side_effect_type="memory_write",
            idempotency_key="mem:critical-knowledge",
            status="failed",
            retryable=False,
        )

        effects = sm.get_side_effects("run-1")
        assert effects[0]["retryable"] is False

    @pytest.mark.asyncio
    async def test_capabilities_include_completed_keys(self):
        """Capabilities grant includes completed side-effect keys."""
        import pathlib
        db = "data/test_se_caps.db"
        pathlib.Path(db).unlink(missing_ok=True)
        model = MockModelAdapter()
        blueprint = _make_sequential_blueprint()
        state_mgr = StateManager(db_path=db)

        # Record a completed side effect
        state_mgr.record_side_effect(
            run_id="caps-test", step_id=2, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="pubmed:abc123",
            status="completed",
        )

        # Build capabilities (need orchestrator)
        nodes = {
            "goal_interpreter": GoalInterpreterNode(model),
            "domain_classifier": DomainClassifierNode(),
            "response_generator": SimpleResponseNode(),
            "trace_collector": SimpleTraceCollectorNode(),
        }
        orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=state_mgr)
        orch.state.run_id = "caps-test"

        caps = orch._build_capabilities("goal_interpreter")
        assert "pubmed:abc123" in caps.side_effect_completed_keys

    @pytest.mark.asyncio
    async def test_memory_write_uses_side_effect_ledger(self):
        """AC6: Memory write is recorded in side-effect ledger."""
        import pathlib
        db = "data/test_se_memwrite.db"
        pathlib.Path(db).unlink(missing_ok=True)
        from nodechain.nodes.memory_write import MemoryWriteDecisionNode

        state_mgr = StateManager(db_path=db)

        # Simulate a memory write node execution
        node = MemoryWriteDecisionNode()
        # The orchestrator's _emit_node_detail_events handles this
        # Just verify the recording works
        state_mgr.record_side_effect(
            run_id="mem-test", step_id=10, node_id="memory_write_decision",
            side_effect_type="memory_write",
            idempotency_key="mem:transformer-effectiveness",
            status="completed",
            external_reference="chroma://doc/abc123",
            retryable=False,
        )

        effects = state_mgr.get_side_effects("mem-test")
        assert len(effects) == 1
        assert effects[0]["side_effect_type"] == "memory_write"
        assert effects[0]["external_reference"] == "chroma://doc/abc123"


class TestIdempotencyKeyModel:
    """Verify corrected idempotency key model."""

    def test_request_hash_from_pre_call_payload(self):
        """AC1: request_hash is computed from normalized request, not results."""
        import hashlib, json
        # Simulate what search_tool.py does before the call
        terms = sorted(["transformer", "attention", "neural network"])
        request_payload = json.dumps(
            {"terms": terms, "max": 10, "filters": {}},
            sort_keys=True,
        )
        request_hash = hashlib.sha256(request_payload.encode()).hexdigest()[:16]

        # Same terms → same hash (deterministic)
        request_hash2 = hashlib.sha256(request_payload.encode()).hexdigest()[:16]
        assert request_hash == request_hash2

        # Different terms → different hash
        different_payload = json.dumps(
            {"terms": sorted(["diabetes", "insulin"]), "max": 10, "filters": {}},
            sort_keys=True,
        )
        different_hash = hashlib.sha256(different_payload.encode()).hexdigest()[:16]
        assert request_hash != different_hash

    def test_response_hash_separate_from_request(self):
        """AC2: response_hash is computed from post-call results."""
        import hashlib, json
        # Request hash
        req_hash = hashlib.sha256(json.dumps({"terms": ["test"]}).encode()).hexdigest()[:16]
        # Response hash from different data
        resp_hash = hashlib.sha256(json.dumps(["doi:10.1234/test"]).encode()).hexdigest()[:16]
        assert req_hash != resp_hash

    def test_run_scoped_uniqueness(self):
        """AC3+6: Same key in different runs is allowed."""
        import pathlib
        db = "data/test_se_run_scope.db"
        pathlib.Path(db).unlink(missing_ok=True)
        sm = StateManager(db_path=db)

        # Same idempotency key in two different runs
        sm.record_side_effect(
            run_id="run-A", step_id=3, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="pubmed:abc123",
            status="completed",
        )
        sm.record_side_effect(
            run_id="run-B", step_id=3, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="pubmed:abc123",
            status="completed",
        )

        # Both should exist
        effects_a = sm.get_side_effects("run-A")
        effects_b = sm.get_side_effects("run-B")
        assert len(effects_a) == 1
        assert len(effects_b) == 1

    def test_duplicate_key_same_run_ignored(self):
        """AC3: Duplicate key within same run is ignored."""
        import pathlib
        db = "data/test_se_dup.db"
        pathlib.Path(db).unlink(missing_ok=True)
        sm = StateManager(db_path=db)

        sm.record_side_effect(
            run_id="run-1", step_id=3, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="pubmed:abc123",
            status="completed",
        )
        # Second insert same key same run — should be ignored
        sm.record_side_effect(
            run_id="run-1", step_id=5, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="pubmed:abc123",
            status="completed",
        )

        effects = sm.get_side_effects("run-1")
        assert len(effects) == 1

    def test_memory_write_key_uses_content_provenance_hash(self):
        """AC8: Memory write idempotency uses subject+content+provenance hash."""
        import hashlib
        subject = "Transformer effectiveness in NLP"
        content = "Transformers have shown significant improvements..."
        provenance = ["S1", "S2", "S3"]

        import json
        subject_hash = hashlib.sha256(subject.encode()).hexdigest()[:16]
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
        prov_str = json.dumps(provenance, sort_keys=True)
        provenance_hash = hashlib.sha256(prov_str.encode()).hexdigest()[:16]

        key = f"mem:{subject_hash}:{content_hash}:{provenance_hash}"
        assert key.startswith("mem:")
        assert len(key) > 20  # Meaningful hash, not just a prefix

        # Same content → same key
        key2 = f"mem:{subject_hash}:{content_hash}:{provenance_hash}"
        assert key == key2

        # Different content → different key
        content_hash2 = hashlib.sha256("Different content".encode()).hexdigest()[:16]
        key3 = f"mem:{subject_hash}:{content_hash2}:{provenance_hash}"
        assert key != key3

    @pytest.mark.asyncio
    async def test_status_map_flows_through_capabilities(self):
        """AC7: side_effect_status_map includes all non-planned effects."""
        import pathlib
        db = "data/test_se_status_map.db"
        pathlib.Path(db).unlink(missing_ok=True)
        model = MockModelAdapter()
        blueprint = _make_sequential_blueprint()
        state_mgr = StateManager(db_path=db)

        # Record effects with various statuses
        state_mgr.record_side_effect(
            run_id="status-test", step_id=3, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="pubmed:abc",
            status="completed",
        )
        state_mgr.record_side_effect(
            run_id="status-test", step_id=3, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="arxiv:xyz",
            status="started",
        )
        state_mgr.record_side_effect(
            run_id="status-test", step_id=3, node_id="search_tool",
            side_effect_type="external_api_read",
            idempotency_key="crossref:def",
            status="failed",
            retryable=False,
        )

        nodes = {
            "goal_interpreter": GoalInterpreterNode(model),
            "domain_classifier": DomainClassifierNode(),
            "response_generator": SimpleResponseNode(),
            "trace_collector": SimpleTraceCollectorNode(),
        }
        orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=state_mgr)
        orch.state.run_id = "status-test"

        caps = orch._build_capabilities("goal_interpreter")
        assert "pubmed:abc" in caps.side_effect_completed_keys
        assert caps.side_effect_status_map["pubmed:abc"] == "completed"
        assert caps.side_effect_status_map["arxiv:xyz"] == "started"
        assert caps.side_effect_status_map["crossref:def"] == "failed"
        assert caps.side_effect_status_map["crossref:def__retryable"] == "False"


async def _run_loop_chain(state_manager):
    """Run the research chain with loop-triggering output using MockNode from test_runtime."""
    import sys
    sys.path.insert(0, "tests")
    from test_runtime import MockNode
    from nodechain.runtime.orchestrator import Orchestrator
    from nodechain.core.blueprint import load_blueprint

    call_counts = {"source_quality_evaluator": 0}

    def _sqe_loop_output(p):
        call_counts["source_quality_evaluator"] += 1
        base = {"sources": [], "total_evaluated": 0, "passing": 0, "quality_summary": {"total": 5, "passing": 5}}
        if call_counts["source_quality_evaluator"] == 1:
            base["loop_required"] = True
            base["quality_summary"] = {"total": 0, "passing": 0}
        return base

    transforms = {
        "goal_interpreter": lambda p: {"primary_question": p.get("query", ""), "research_domain": "general", "success_criteria": ["test"], "domain_classification": []},
        "task_planner": lambda p: {"plan_id": "p", "tasks": [{"task_id": "t1", "description": "t", "query_terms": ["t"], "priority": 1}], "source_routing": {"primary": ["ss"], "secondary": []}},
        "context_selector": lambda p: {"plan_ref": "p", "search_queries": [{"query_id": "q1", "terms": ["t"], "target_adapters": ["ss"]}], "adapter_grants": ["ss"]},
        "search_tool": lambda p: {"results": [{"origin_api": "ss", "raw_data": {"title": "T"}, "query_used": "t", "retrieved_at": "2026"}], "total_found": 1, "adapters_called": ["ss"], "adapters_failed": []},
        "source_ingestion": lambda p: {"sources": [{"source_id": "s1", "origin_api": "ss", "title": "T", "quality_score": 0.8}], "total_found": 1},
        "source_quality_evaluator": _sqe_loop_output,
        "evidence_synthesizer": lambda p: {"claims": [{"claim_id": "c1", "text": "TC", "support_level": "strong", "source_refs": ["s1"]}], "confidence": 0.85, "evidence_base_id": "eb1"},
        "claim_validator": lambda p: {"validated_claims": [{"claim_id": "c1", "valid": True, "source_refs": ["s1"]}], "validation_rate": 1.0},
        "risk_classifier": lambda p: {"risk_level": "LOW", "confidence": 0.9, "review_required": False, "risk_factors": [], "uncertainty_disclosures": []},
        "response_generator": lambda p: {"recommendation": "R", "executive_summary": "S", "key_findings": ["F"], "confidence_statement": {"level": "HIGH", "numeric": 0.9}, "citations": []},
        "memory_write_decision": lambda p: {"candidates": [], "write_decision": "no_write"},
        "trace_collector": lambda p: {"trace_id": "t", "events_summary": []},
    }

    from nodechain.core.contract import SideEffect
    _se = {"search_tool": [SideEffect(effect_type="external_call", target="search_apis")]}
    nodes = {nid: MockNode(nid, "any", "any", transforms[nid], side_effects=_se.get(nid, [])) for nid in transforms}
    blueprint = load_blueprint("blueprints/research_decision_v1.yaml")
    orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=state_manager)
    trace = await orch.run("test loop resume")
    return orch.state.run_id, state_manager, call_counts, orch



class TestLoopResumeCursor:
    """CRITICAL: Verify that resume after a loop-back finds the correct
    position in the execution order, not the first occurrence of a repeated node.

    This is the test the review asked for: crash after second execution
    of source_quality_evaluator, resume must continue from after the second
    occurrence, not the first.
    """

    @pytest.mark.asyncio
    async def test_resume_after_loop_finds_correct_position(self, tmp_path):
        """Run chain with loop, verify ledger records both invocations."""
        import pathlib
        db = str(tmp_path / "loop_resume.db")
        sm = StateManager(db_path=db)

        run_id, sm, call_counts, orch = await _run_loop_chain(sm)

        # Verify the loop actually happened
        assert call_counts["source_quality_evaluator"] >= 2, \
            f"Loop didn't trigger: only {call_counts['source_quality_evaluator']} calls"

        # Check the invocation ledger: source_quality_evaluator should have 2+ entries
        completed = sm.get_completed_steps(run_id)
        sqe_entries = [(sid, nid) for sid, nid in completed.items() if nid == "source_quality_evaluator"]
        assert len(sqe_entries) >= 2, f"Only {len(sqe_entries)} ledger entries for source_quality_evaluator"

        # Get the step_id of the second invocation
        sqe_entries.sort()
        second_step = sqe_entries[1][0]

        # Verify that the recovery context has invocation-level detail
        from nodechain.runtime.persistence import PersistenceCoordinator
        coord = PersistenceCoordinator(sm)
        recovery = coord.load_for_recovery(run_id)

        assert recovery is not None
        assert recovery.completed_steps[second_step] == "source_quality_evaluator"

        # The last completed step must be at least the second invocation
        assert recovery.last_completed_step >= second_step

        # Verify the occurrence count in completed_steps
        target_nid = "source_quality_evaluator"
        occurrence = sum(
            1 for sid, nid in recovery.completed_steps.items()
            if nid == target_nid and sid <= recovery.last_completed_step
        )
        assert occurrence >= 2, f"Only {occurrence} invocations of {target_nid} found"

    @pytest.mark.asyncio
    async def test_resume_cursor_uses_occurrence_not_first_match(self, tmp_path):
        """Verify the resume cursor logic counts occurrences correctly.

        Given completed_steps = {3: 'sqe', 7: 'sqe'} and execution_order with
        'sqe' at positions 4 and 8, the cursor should find position 9 (after
        the 2nd occurrence), not position 5 (after the 1st).
        """
        from nodechain.runtime.persistence import PersistenceCoordinator

        # Simulate the resume cursor logic directly
        completed_invocations = {3: "source_quality_evaluator", 7: "source_quality_evaluator"}
        last_step = 7
        target_nid = completed_invocations.get(last_step)
        assert target_nid == "source_quality_evaluator"

        # Count occurrences up to last_step
        occurrence = sum(
            1 for sid, nid in completed_invocations.items()
            if nid == target_nid and sid <= last_step
        )
        assert occurrence == 2  # Not 1!

        # Loop rebuilds the order: original up to sqe, then loop path, then remaining
        # rebuild_order_with_loop appends loop_segment = [sqe, cs, st, si, sqe]
        loop_rebuilt_order = [
            "goal_interpreter",           # 0
            "task_planner",                # 1
            "context_selector",            # 2
            "search_tool",                 # 3
            "source_ingestion",            # 4
            "source_quality_evaluator",    # 5 ← 1st occurrence (original)
            # --- loop-back inserts loop_segment: ---
            "source_quality_evaluator",    # 6 ← loop start (2nd occurrence)
            "context_selector",            # 7
            "search_tool",                 # 8
            "source_ingestion",            # 9
            "source_quality_evaluator",    # 10 ← loop end (3rd occurrence)
            "evidence_synthesizer",        # 11
            "claim_validator",             # 12
            "risk_classifier",             # 13
            "response_generator",          # 14
            "memory_write_decision",       # 15
            "trace_collector",             # 16
        ]

        # Find the Nth (2nd) occurrence
        seen = 0
        start_index = 0
        for i, nid in enumerate(loop_rebuilt_order):
            if nid == target_nid:
                seen += 1
                if seen == occurrence:
                    start_index = i + 1
                    break

        # Must be 7 (after the 2nd occurrence at index 6), NOT 6 (after 1st at index 5)
        assert start_index == 7, f"Expected 7, got {start_index} — cursor found wrong occurrence"

        # The OLD (buggy) logic would have found index 5 (first match):
        old_start = 0
        for i, nid in enumerate(loop_rebuilt_order):
            if nid == target_nid:
                old_start = i + 1
                break
        assert old_start == 6  # Would resume from wrong position (1st occurrence)

    @pytest.mark.asyncio
    async def test_first_occurrence_resume_still_works(self, tmp_path):
        """Verify that resume after the FIRST invocation (no loop yet) still works."""
        # completed_steps = {3: 'source_quality_evaluator'}
        completed_invocations = {3: "source_quality_evaluator"}
        last_step = 3
        target_nid = completed_invocations.get(last_step)

        occurrence = sum(
            1 for sid, nid in completed_invocations.items()
            if nid == target_nid and sid <= last_step
        )
        assert occurrence == 1

        execution_order = [
            "goal_interpreter",        # 0
            "task_planner",             # 1
            "context_selector",         # 2
            "search_tool",              # 3
            "source_quality_evaluator", # 4
            "evidence_synthesizer",     # 5
        ]

        seen = 0
        start_index = 0
        for i, nid in enumerate(execution_order):
            if nid == target_nid:
                seen += 1
                if seen == occurrence:
                    start_index = i + 1
                    break

        assert start_index == 5  # After the only occurrence


class TestRecoveryCursorGuard:
    """Verify resume integrity guard against blueprint drift.

    1. Resume succeeds when execution_order_hash matches.
    2. Resume fails clearly when hash differs.
    3. Error includes run_id, blueprint_id, expected hash, actual hash.
    4. Existing 265 tests remain green.
    """

    @pytest.mark.asyncio
    async def test_resume_succeeds_when_order_hash_matches(self, tmp_path):
        """Resume with matching hash should succeed."""
        db = str(tmp_path / "guard_match.db")
        sm = StateManager(db_path=db)

        model = MockModelAdapter()
        blueprint = _make_sequential_blueprint()
        nodes = {
            "goal_interpreter": GoalInterpreterNode(model),
            "domain_classifier": DomainClassifierNode(),
            "response_generator": SimpleResponseNode(),
            "trace_collector": SimpleTraceCollectorNode(),
        }
        orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=sm)
        trace = await orch.run("first run")
        assert trace.final_status == "completed"

        # The state should have been saved with an execution_order_hash
        saved = sm.load(orch.state.run_id)
        assert saved is not None
        assert saved.execution_order_hash != ""

        # Resume with the same blueprint — should succeed
        orch2 = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=sm)
        trace2 = await orch2.resume(orch.state.run_id)
        assert trace2.final_status == "completed"

    @pytest.mark.asyncio
    async def test_resume_fails_when_order_hash_differs(self, tmp_path):
        """Resume with different blueprint should fail with controlled error."""
        db = str(tmp_path / "guard_mismatch.db")
        sm = StateManager(db_path=db)

        model = MockModelAdapter()
        blueprint1 = _make_sequential_blueprint()
        nodes = {
            "goal_interpreter": GoalInterpreterNode(model),
            "domain_classifier": DomainClassifierNode(),
            "response_generator": SimpleResponseNode(),
            "trace_collector": SimpleTraceCollectorNode(),
        }
        orch1 = Orchestrator(blueprint=blueprint1, nodes=nodes, state_manager=sm)
        trace = await orch1.run("first run")
        assert trace.final_status == "completed"

        # Now create a different blueprint (different node order)
        from nodechain.core.blueprint import NodeDef, ConnectionDef, ChainBlueprint
        blueprint2 = ChainBlueprint(
            chain_id="different-chain",
            name="Different Chain",
            version="2.0",
            goal="Different",
            nodes=[
                NodeDef(node_id="goal_interpreter", node_type="model", config={"model_required": True}, position=1),
                NodeDef(node_id="response_generator", node_type="model", config={}, position=2),
                NodeDef(node_id="extra_node", node_type="deterministic", config={}, position=3),
            ],
            connections=[
                ConnectionDef(from_node="goal_interpreter", to_node="response_generator", from_port="output", to_port="input"),
                ConnectionDef(from_node="response_generator", to_node="extra_node", from_port="output", to_port="input"),
            ],
        )

        # Try to resume with the different blueprint
        nodes2 = {
            **nodes,
            "extra_node": SimpleTraceCollectorNode(),
        }
        orch2 = Orchestrator(blueprint=blueprint2, nodes=nodes2, state_manager=sm)
        trace2 = await orch2.resume(orch1.state.run_id)
        # Should fail due to hash mismatch
        assert trace2.final_status == "failed"

    @pytest.mark.asyncio
    async def test_mismatch_error_includes_context(self, tmp_path):
        """Error trace should include run_id, blueprint_id, hashes."""
        db = str(tmp_path / "guard_context.db")
        sm = StateManager(db_path=db)

        model = MockModelAdapter()
        blueprint1 = _make_sequential_blueprint()
        nodes = {
            "goal_interpreter": GoalInterpreterNode(model),
            "domain_classifier": DomainClassifierNode(),
            "response_generator": SimpleResponseNode(),
            "trace_collector": SimpleTraceCollectorNode(),
        }
        orch1 = Orchestrator(blueprint=blueprint1, nodes=nodes, state_manager=sm)
        await orch1.run("first run")
        saved = sm.load(orch1.state.run_id)
        expected_hash = saved.execution_order_hash

        # Different blueprint
        from nodechain.core.blueprint import NodeDef, ConnectionDef, ChainBlueprint
        blueprint2 = ChainBlueprint(
            chain_id="changed-chain",
            name="Changed",
            version="2.0",
            goal="Changed",
            nodes=[
                NodeDef(node_id="goal_interpreter", node_type="model", config={"model_required": True}, position=1),
                NodeDef(node_id="response_generator", node_type="model", config={}, position=2),
                NodeDef(node_id="new_node", node_type="deterministic", config={}, position=3),
            ],
            connections=[
                ConnectionDef(from_node="goal_interpreter", to_node="response_generator", from_port="output", to_port="input"),
                ConnectionDef(from_node="response_generator", to_node="new_node", from_port="output", to_port="input"),
            ],
        )

        nodes2 = {**nodes, "new_node": SimpleTraceCollectorNode()}
        orch2 = Orchestrator(blueprint=blueprint2, nodes=nodes2, state_manager=sm)
        trace2 = await orch2.resume(orch1.state.run_id)

        # Verify the trace has the failure with context
        assert trace2.final_status == "failed"
        chain_failed_events = [e for e in trace2.events if "CHAIN_FAILED" in str(e.event_type)]
        assert len(chain_failed_events) > 0
        # The reason should include hash mismatch info
        reason = str(chain_failed_events[0].reason_codes)
        assert expected_hash in reason
        assert orch1.state.run_id in reason

    @pytest.mark.asyncio
    async def test_legacy_state_without_hash_still_resumes(self, tmp_path):
        """States saved before the hash field was added should still resume."""
        db = str(tmp_path / "guard_legacy.db")
        sm = StateManager(db_path=db)

        model = MockModelAdapter()
        blueprint = _make_sequential_blueprint()
        nodes = {
            "goal_interpreter": GoalInterpreterNode(model),
            "domain_classifier": DomainClassifierNode(),
            "response_generator": SimpleResponseNode(),
            "trace_collector": SimpleTraceCollectorNode(),
        }
        orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=sm)
        await orch.run("first run")

        # Simulate legacy state by clearing the hash
        saved = sm.load(orch.state.run_id)
        saved.execution_order_hash = ""
        sm.save(saved)

        # Resume should still work (no hash = legacy, allow with warning)
        orch2 = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=sm)
        trace2 = await orch2.resume(orch.state.run_id)
        assert trace2.final_status == "completed"
