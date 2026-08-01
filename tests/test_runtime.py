"""Tests for the chain runtime orchestrator."""

import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock

from nodechain.core.blueprint import load_blueprint
from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.nodes.base_node import BaseNode
from nodechain.core.manifest import NodeManifest
from nodechain.core.contract import (
    NodeContract, EntryContract, ExitContract, Requirements,
)
from nodechain.core.port import PortType
from nodechain.runtime.orchestrator import Orchestrator


class MockNode(BaseNode):
    """A mock node for testing that passes through its payload."""

    def __init__(
        self,
        node_id: str,
        input_type: str,
        output_type: str,
        output_transform=None,
        side_effects=None,
        tools_required=None,
        adapters_required=None,
        model_required=False,
    ):
        self._node_id = node_id
        self._input_type = input_type
        self._output_type = output_type
        self._output_transform = output_transform
        self._side_effects = side_effects or []
        self._tools_required = tools_required or []
        self._adapters_required = adapters_required or []
        self._model_required = model_required
        # v2.44.4: explicit test-node trust marker so mock nodes aren't
        # denied by the built-in provenance boundary check
        self._trust_level = "local_trusted"
        self._node_origin = "local_registry"

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id=self._node_id,
            node_type="mock",
            name=f"Mock {self._node_id}",
            description="Test mock node",
            contract=NodeContract(
                contract_id=f"mock.{self._node_id}.v1",
                node_id=self._node_id,
                entry=EntryContract(
                    input_type=self._input_type,
                    schema_ref=f"mock://{self._input_type}",
                    required_fields=[],
                ),
                exit=ExitContract(
                    output_type=self._output_type,
                    schema_ref=f"mock://{self._output_type}",
                    guaranteed_fields=[],
                ),
                side_effects=self._side_effects,
                requirements=Requirements(
                    tools_required=self._tools_required,
                    adapters_required=self._adapters_required,
                    model_required=self._model_required,
                ) if (self._tools_required or self._adapters_required or self._model_required) else Requirements(),
            ),
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        output = envelope.payload
        if self._output_transform:
            output = self._output_transform(output)

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id=self._node_id,
            step_id=envelope.step_id,
            output=output,
            output_type=self._output_type,
        )


def _mock_search_completion_records():
    """v3.4.0: build the canonical mock's side_effect_records completion report.

    The request_hash must match what SideEffectJournalMixin._journal_search_operations
    derives from the context_selector's query (terms=["test"], target_adapters=
    ["semantic_scholar"], max_results=10, filters={}). Both use
    compute_side_effect_request_hash with the same operation dict.
    """
    from nodechain.core.side_effect_utils import (
        compute_side_effect_request_hash, compute_side_effect_response_hash, make_canonical_search_key,
    )
    req_hash = compute_side_effect_request_hash(
        "external_call", "search_tool", "",
        operation={"terms": ["test"], "max": 10, "filters": {}},
    )
    key = make_canonical_search_key("semantic_scholar", req_hash)
    response_hash = compute_side_effect_response_hash(
        results=[{"raw_data": {"title": "Test Paper", "paperId": "123"}}],
    )
    return [{
        "side_effect_key": key,
        "side_effect_type": "external_call",
        "status": "completed",
        "observed_by": "node",
        "observed_at": "2026-07-08T00:00:00Z",
        "response_hash": response_hash,
        "evidence": {"adapter": "semantic_scholar", "result_count": 1},
    }]


def _create_mock_nodes():
    """Create 12 mock nodes matching the chain blueprint."""
    transforms = {
        "goal_interpreter": lambda p: {
            "primary_question": p.get("query", ""),
            "research_domain": "general",
            "success_criteria": ["test"],
            "domain_classification": [],
            "depth_required": "moderate",
        },
        "task_planner": lambda p: {
            "plan_id": "test-plan",
            "tasks": [{
                "task_id": "t1",
                "description": "test task",
                "query_terms": ["test"],
                "priority": 1,
            }],
            "source_routing": {
                "primary": ["semantic_scholar"],
                "secondary": ["crossref"],
            },
        },
        "context_selector": lambda p: {
            "plan_ref": "test-plan",
            "search_queries": [{
                "query_id": "q1",
                "terms": ["test"],
                "target_adapters": ["semantic_scholar"],
            }],
            "adapter_grants": ["semantic_scholar"],
        },
        "search_tool": lambda p: {
            "results": [{
                "origin_api": "semantic_scholar",
                "raw_data": {"title": "Test Paper", "paperId": "123"},
                "query_used": "test",
                "retrieved_at": "2026-01-01T00:00:00Z",
            }],
            "total_found": 1,
            "adapters_called": ["semantic_scholar"],
            "adapters_failed": [],
            # v3.4.0: observed side-effect completion report (Model C). The
            # canonical mock now reports completion for the semantic_scholar
            # external_call. The side_effect_key matches the ledger key derived
            # by _journal_search_operations for terms=["test"], adapter=
            # "semantic_scholar". This closes the v2.97-characterized gap.
            "side_effect_records": _mock_search_completion_records(),
        },
        "source_ingestion": lambda p: {
            "sources": [{
                "source_id": "src-1",
                "origin_api": "semantic_scholar",
                "title": "Test Paper",
                "authors": ["Author A"],
                "citation_count": 10,
                "peer_reviewed": True,
                "source_type": "journal_article",
                "venue": "Test Journal",
                "subject_areas": ["CS"],
                "open_access": True,
                "pdf_url": "",
                "credibility_signals": {},
                "provenance": {
                    "adapter": "semantic_scholar",
                    "query": "test",
                    "retrieval_timestamp": "2026-01-01T00:00:00Z",
                },
            }],
            "ingestion_stats": {"total_raw": 1, "total_normalized": 1},
        },
        "source_quality_evaluator": lambda p: {
            "qualified_sources": [{
                "source_ref": "src-1",
                "quality_score": 0.8,
                "signals": {"peer_reviewed": True},
                "included": True,
            }],
            "quality_summary": {
                "total_evaluated": 1,
                "total_passed": 1,
                "average_score": 0.8,
                "domain_coverage": "strong",
            },
            "loop_required": False,
        },
        "evidence_synthesizer": lambda p: {
            "claims": [{
                "claim_id": "c1",
                "statement": "Test claim",
                "supporting_sources": ["src-1"],
                "confidence": 0.8,
            }],
            "synthesis": {
                "summary": "Test synthesis",
                "key_findings": ["finding 1"],
                "areas_of_agreement": [],
                "areas_of_disagreement": [],
            },
            "source_count": 1,
        },
        "claim_validator": lambda p: {
            "validated_claims": [{
                "claim_id": "c1",
                "statement": "Test claim",
                "status": "confirmed",
                "structural_validation": {"passed": True},
                "consistency_validation": {"passed": True, "internal_consistency": 0.9},
                "adjusted_confidence": 0.8,
            }],
            "validation_summary": {"total_claims": 1, "confirmed": 1},
        },
        "risk_classifier": lambda p: {
            "risk_level": "LOW",
            "confidence": 0.8,
            "review_required": False,
            "uncertainty_disclosures": [],
            "risk_factors": [],
            "confidence_factors": {},
        },
        "response_generator": lambda p: {
            "recommendation": "Test recommendation based on research",
            "executive_summary": "Test summary",
            "key_findings": ["finding 1"],
            "confidence_statement": {
                "level": "HIGH",
                "numeric": 0.8,
                "explanation": "Strong evidence",
            },
            "citations": [],
            "uncertainty_disclosures": [],
            "human_review_decision": "not_required",
        },
        "memory_write_decision": lambda p: {
            "candidates": [{
                "memory_id": "mem-1",
                "scope": "task_memory",
                "subject": "Test",
                "content": "Test content",
                "confidence": 0.8,
                "sensitivity": "LOW",
                "write_result": {"committed": True, "write_ref": "ref-1"},
            }],
        },
        "trace_collector": lambda p: {
            "trace_file_path": "data/traces/test.json",
            "trace_id": "trace-1",
            "run_id": "run-1",
            "complete": True,
            "event_count": 10,
            "truth_rule_verified": True,
        },
    }

    # Create nodes with correct port types for the chain
    type_chain = [
        ("goal_interpreter", PortType.RAW_QUERY, PortType.RESEARCH_GOAL),
        ("task_planner", PortType.RESEARCH_GOAL, PortType.TASK_PLAN),
        ("context_selector", PortType.TASK_PLAN, PortType.CONTEXT_BUNDLE),
        ("search_tool", PortType.CONTEXT_BUNDLE, PortType.RAW_SEARCH_RESULTS),
        ("source_ingestion", PortType.RAW_SEARCH_RESULTS, PortType.SOURCE_SET),
        ("source_quality_evaluator", PortType.SOURCE_SET, PortType.QUALIFIED_SOURCE_SET),
        ("evidence_synthesizer", PortType.QUALIFIED_SOURCE_SET, PortType.EVIDENCE_BASE),
        ("claim_validator", PortType.EVIDENCE_BASE, PortType.VALIDATED_EVIDENCE),
        ("risk_classifier", PortType.VALIDATED_EVIDENCE, PortType.RISK_ASSESSMENT),
        ("response_generator", PortType.RISK_ASSESSMENT, PortType.FINAL_RESPONSE),
        ("memory_write_decision", PortType.FINAL_RESPONSE, PortType.MEMORY_WRITE_DECISION),
        ("trace_collector", PortType.MEMORY_WRITE_DECISION, PortType.CHAIN_TRACE_OUTPUT),
    ]

    # v2.35.4: mock nodes that produce side-effect markers must declare them
    # v2.42.1: search_tool also declares tools_required for TOOL_ACCESS gate
    from nodechain.core.contract import SideEffect, Requirements
    se_map = {
        "search_tool": [SideEffect(effect_type="external_call", target="search_apis")],
        "memory_write_decision": [SideEffect(effect_type="memory_write", target="memory_store")],
    }
    tr_map = {
        "search_tool": Requirements(
            tools_required=["search"], adapters_required=["semantic_scholar", "arxiv", "openalex", "crossref", "pubmed"],
        ),
    }

    nodes = {}
    for node_id, in_type, out_type in type_chain:
        nodes[node_id] = MockNode(
            node_id=node_id,
            input_type=in_type,
            output_type=out_type,
            output_transform=transforms.get(node_id),
            side_effects=se_map.get(node_id, []),
            tools_required=(tr_map.get(node_id).tools_required if node_id in tr_map else []),
            adapters_required=(tr_map.get(node_id).adapters_required if node_id in tr_map else []),
        )

    return nodes


class TestOrchestrator:
    """Test the chain orchestrator."""

    @pytest.mark.asyncio
    async def test_contract_validation_passes(self):
        """All contracts in the blueprint should be valid."""
        blueprint = load_blueprint("blueprints/research_decision_v1.yaml")
        nodes = _create_mock_nodes()
        orchestrator = Orchestrator(blueprint=blueprint, nodes=nodes)

        issues = orchestrator.validate_contracts()
        assert len(issues) == 0, f"Contract issues: {issues}"

    @pytest.mark.asyncio
    async def test_full_chain_run(self):
        """Full chain should execute all 12 nodes and produce a trace."""
        blueprint = load_blueprint("blueprints/research_decision_v1.yaml")
        nodes = _create_mock_nodes()
        orchestrator = Orchestrator(blueprint=blueprint, nodes=nodes)

        trace = await orchestrator.run("What is the impact of AI on healthcare?")

        # Chain should complete
        assert trace.final_status == "completed"

        # All 12 nodes should have succeeded
        from nodechain.core.trace import EventType
        succeeded = [e for e in trace.events if e.event_type == EventType.NODE_SUCCEEDED]
        assert len(succeeded) == 12, f"Expected 12 node successes, got {len(succeeded)}"

        # Trace should have chain_started and chain_completed
        event_types = {e.event_type for e in trace.events}
        assert EventType.CHAIN_STARTED in event_types
        assert EventType.CHAIN_COMPLETED in event_types

        # Trace should be complete
        assert trace.summary.trace_complete is True

    @pytest.mark.asyncio
    async def test_execution_order(self):
        """Nodes should execute in topological order."""
        blueprint = load_blueprint("blueprints/research_decision_v1.yaml")
        nodes = _create_mock_nodes()
        orchestrator = Orchestrator(blueprint=blueprint, nodes=nodes)

        order = orchestrator.scheduler.resolve_execution_order()
        assert order[0] == "goal_interpreter"
        assert order[-1] == "trace_collector"
        assert order.index("goal_interpreter") < order.index("task_planner")
        assert order.index("search_tool") < order.index("source_ingestion")

    @pytest.mark.asyncio
    async def test_trace_cost_tracking(self):
        """Trace should track accumulated cost."""
        blueprint = load_blueprint("blueprints/research_decision_v1.yaml")
        nodes = _create_mock_nodes()
        orchestrator = Orchestrator(blueprint=blueprint, nodes=nodes)

        trace = await orchestrator.run("test query")
        # Mock nodes don't incur cost
        assert trace.total_cost_usd >= 0


class TestSchedulerLoopCorrectness:
    """Verify the scheduler loop correctly re-executes nodes on loop-back."""

    @pytest.mark.asyncio
    async def test_loop_back_actually_re_executes_nodes(self):
        """Loop-back must re-execute target nodes, not just emit events.

        Regression test for the mutable-list-in-for-loop bug.
        The old code used `for node_id in execution_order:` which ignores
        list mutation. The scheduler loop uses index-based iteration
        which correctly follows list mutations.
        """
        from nodechain.core.state import StateManager
        import pathlib

        db = "data/test_scheduler_loop.db"
        pathlib.Path(db).unlink(missing_ok=True)
        sm = StateManager(db_path=db)

        # Create nodes with loop-triggering output on first call
        call_counts = {"source_quality_evaluator": 0}
        original_fn = None

        # Patch the mock output generator for source_quality_evaluator
        transforms = {
            "goal_interpreter": lambda p: {
                "primary_question": p.get("query", ""),
                "research_domain": "general",
                "success_criteria": ["test"],
                "domain_classification": [],
            },
            "task_planner": lambda p: {
                "plan_id": "test-plan",
                "tasks": [{"task_id": "t1", "description": "test", "query_terms": ["test"], "priority": 1}],
                "source_routing": {"primary": ["semantic_scholar"], "secondary": ["crossref"]},
            },
            "context_selector": lambda p: {
                "plan_ref": "test-plan",
                "search_queries": [{"query_id": "q1", "terms": ["test"], "target_adapters": ["semantic_scholar"]}],
                "adapter_grants": ["semantic_scholar"],
            },
            "search_tool": lambda p: {
                "results": [{"origin_api": "semantic_scholar", "raw_data": {"title": "Test"}, "query_used": "test", "retrieved_at": "2026-01-01"}],
                "total_found": 1, "adapters_called": ["semantic_scholar"], "adapters_failed": [],
            },
            "source_ingestion": lambda p: {
                "sources": [{"source_id": "src-1", "origin_api": "semantic_scholar", "title": "Test", "quality_score": 0.8}],
                "total_found": 1,
            },
            "source_quality_evaluator": lambda p: _sqe_output(p, call_counts),
            "evidence_synthesizer": lambda p: {
                "claims": [{"claim_id": "c1", "text": "Test claim", "support_level": "strong", "source_refs": ["src-1"]}],
                "confidence": 0.85, "evidence_base_id": "eb-1",
            },
            "claim_validator": lambda p: {
                "validated_claims": [{"claim_id": "c1", "valid": True, "source_refs": ["src-1"]}],
                "validation_rate": 1.0,
            },
            "risk_classifier": lambda p: {
                "risk_level": "LOW", "confidence": 0.9, "review_required": False,
                "risk_factors": [], "uncertainty_disclosures": [],
            },
            "response_generator": lambda p: {
                "recommendation": "Test recommendation",
                "executive_summary": "Test summary",
                "key_findings": ["Finding 1"],
                "confidence_statement": {"level": "HIGH", "numeric": 0.9},
                "citations": [],
            },
            "memory_write_decision": lambda p: {
                "candidates": [],
                "write_decision": "no_write",
            },
            "trace_collector": lambda p: {
                "trace_id": "test-trace",
                "events_summary": [],
            },
        }

        def _sqe_output(p, counts):
            counts["source_quality_evaluator"] += 1
            base = {
                "sources": [],
                "total_evaluated": 0,
                "passing": 0,
                "quality_summary": {"total": 5, "passing": 5},
            }
            if counts["source_quality_evaluator"] == 1:
                base["loop_required"] = True
                base["quality_summary"] = {"total": 0, "passing": 0}
            return base

        from nodechain.core.contract import SideEffect
        _se = {
            "search_tool": [SideEffect(effect_type="external_call", target="search_apis")],
            "memory_write_decision": [SideEffect(effect_type="memory_write", target="memory_store")],
        }
        from nodechain.core.contract import Requirements as _Req
        _tr = {"search_tool": _Req(tools_required=["search"], adapters_required=["semantic_scholar", "arxiv", "openalex", "crossref", "pubmed"])}
        nodes = {nid: MockNode(nid, "any", "any", transforms[nid], side_effects=_se.get(nid, []), tools_required=(_tr[nid].tools_required if nid in _tr else []), adapters_required=(_tr[nid].adapters_required if nid in _tr else [])) for nid in transforms}

        blueprint = load_blueprint("blueprints/research_decision_v1.yaml")
        orch = Orchestrator(blueprint=blueprint, nodes=nodes, state_manager=sm)
        trace = await orch.run("test scheduler loop")

        assert trace.final_status == "completed", f"Chain failed: {trace.final_status}"

        # Key assertion: source_quality_evaluator must be executed at least twice
        assert call_counts["source_quality_evaluator"] >= 2, (
            f"source_quality_evaluator only executed {call_counts['source_quality_evaluator']} time(s). "
            f"Scheduler loop did not re-execute nodes."
        )

        # The invocation ledger should also show it was invoked twice
        steps = sm.get_completed_steps(orch.state.run_id)
        sqe_steps = [s for s, n in steps.items() if n == "source_quality_evaluator"]
        assert len(sqe_steps) >= 2, f"Only {len(sqe_steps)} invocation ledger entries for source_quality_evaluator"
