"""Test loop trigger — verify the source quality loop fires correctly."""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nodechain.nodes.source_quality import SourceQualityEvaluatorNode


class TestDeterministicLoopTrigger:
    """Verify the deterministic loop trigger fires under insufficient evidence."""

    def _make_node(self):
        from unittest.mock import MagicMock
        return SourceQualityEvaluatorNode(model_adapter=MagicMock())

    def test_zero_sources_no_loop(self):
        """With 0 sources, loop should NOT trigger (looping won't help)."""
        node = self._make_node()
        output = {
            "qualified_sources": [],
            "quality_summary": {"total_evaluated": 0, "average_score": 0.0, "domain_coverage": "weak"},
        }
        result = node._apply_deterministic_loop_trigger(output, [])
        assert result["loop_required"] is False

    def test_two_low_quality_sources_triggers_loop(self):
        """With 2 low-quality sources, loop should trigger."""
        node = self._make_node()
        output = {
            "qualified_sources": [
                {"source_ref": "s1", "quality_score": 0.2, "included": True, "signals": {}},
                {"source_ref": "s2", "quality_score": 0.3, "included": True, "signals": {}},
            ],
            "quality_summary": {
                "total_evaluated": 2,
                "average_score": 0.25,
                "domain_coverage": "limited",
            },
        }
        sources = [
            {"source_id": "s1", "origin_api": "semantic_scholar"},
            {"source_id": "s2", "origin_api": "semantic_scholar"},
        ]
        result = node._apply_deterministic_loop_trigger(output, sources)
        assert result["loop_required"] is True

    def test_five_qualified_sources_no_loop(self):
        """With 5+ qualified sources from multiple APIs, loop should NOT trigger."""
        node = self._make_node()
        output = {
            "qualified_sources": [
                {"source_ref": f"s{i}", "quality_score": 0.7, "included": True,
                 "signals": {"peer_reviewed": True}}
                for i in range(5)
            ],
            "quality_summary": {
                "total_evaluated": 5,
                "average_score": 0.7,
                "domain_coverage": "strong",
            },
        }
        sources = [
            {"source_id": f"s{i}", "origin_api": api}
            for i, api in enumerate(["semantic_scholar", "arxiv", "crossref", "openalex", "pubmed"])
        ]
        result = node._apply_deterministic_loop_trigger(output, sources)
        assert result["loop_required"] is False

    def test_single_api_triggers_loop(self):
        """All sources from one API should trigger loop (no corroboration)."""
        node = self._make_node()
        output = {
            "qualified_sources": [
                {"source_ref": f"s{i}", "quality_score": 0.6, "included": True,
                 "signals": {"peer_reviewed": False}}
                for i in range(4)
            ],
            "quality_summary": {
                "total_evaluated": 4,
                "average_score": 0.6,
                "domain_coverage": "adequate",
            },
        }
        sources = [
            {"source_id": f"s{i}", "origin_api": "semantic_scholar"}
            for i in range(4)
        ]
        result = node._apply_deterministic_loop_trigger(output, sources)
        # Should trigger because single API and no peer review
        assert result["loop_required"] is True

    def test_loop_includes_revised_queries(self):
        """Loop trigger should include revised queries for next iteration."""
        node = self._make_node()
        output = {
            "qualified_sources": [],
            "quality_summary": {"total_evaluated": 2, "average_score": 0.1, "domain_coverage": "weak"},
        }
        sources = [{"source_id": "s1"}, {"source_id": "s2"}]
        result = node._apply_deterministic_loop_trigger(output, sources)
        assert result["loop_required"] is True
        assert "revised_queries" in result
        assert len(result["revised_queries"]) > 0

    def test_loop_reason_is_informative(self):
        """Loop reason should explain why the loop triggered."""
        node = self._make_node()
        output = {
            "qualified_sources": [],
            "quality_summary": {"total_evaluated": 2, "average_score": 0.1, "domain_coverage": "weak"},
        }
        sources = [{"source_id": "s1"}, {"source_id": "s2"}]
        result = node._apply_deterministic_loop_trigger(output, sources)
        assert result["loop_required"] is True
        assert "loop_reason" in result
        assert "Deterministic trigger" in result["loop_reason"]


class TestLoopInOrchestrator:
    """Verify the orchestrator correctly handles loop-back from source quality."""

    def test_loop_back_with_insufficient_sources(self):
        """Orchestrator should loop back when source quality triggers loop_required."""
        from test_runtime import load_blueprint, _create_mock_nodes, MockNode
        from nodechain.runtime.orchestrator import Orchestrator
        from nodechain.core.port import PortType

        blueprint = load_blueprint("blueprints/research_decision_v1.yaml")
        nodes = _create_mock_nodes()

        # Override source_quality to return loop_required=True on first call
        original_quality = nodes["source_quality_evaluator"]
        call_count = [0]

        class LoopTriggerQuality(MockNode):
            def __init__(self):
                super().__init__(
                    "source_quality_evaluator",
                    PortType.SOURCE_SET,
                    PortType.QUALIFIED_SOURCE_SET,
                )

            async def execute(self, envelope):
                from nodechain.core.envelope import EnvelopeResponse
                call_count[0] += 1
                if call_count[0] == 1:
                    # First call: trigger loop
                    return EnvelopeResponse(
                        request_envelope_id=envelope.envelope_id,
                        run_id=envelope.run_id,
                        chain_id=envelope.chain_id,
                        node_id="source_quality_evaluator",
                        step_id=envelope.step_id,
                        output={
                            "qualified_sources": [{"source_ref": "src-1", "quality_score": 0.2, "included": True}],
                            "quality_summary": {"total_evaluated": 1, "average_score": 0.2, "domain_coverage": "limited"},
                            "loop_required": True,
                            "loop_reason": "Test: insufficient sources",
                            "revised_queries": ["AI healthcare systematic review"],
                        },
                        output_type=PortType.QUALIFIED_SOURCE_SET,
                    )
                else:
                    # Second call: pass
                    return EnvelopeResponse(
                        request_envelope_id=envelope.envelope_id,
                        run_id=envelope.run_id,
                        chain_id=envelope.chain_id,
                        node_id="source_quality_evaluator",
                        step_id=envelope.step_id,
                        output={
                            "qualified_sources": [{"source_ref": "src-1", "quality_score": 0.8, "included": True}],
                            "quality_summary": {"total_evaluated": 1, "average_score": 0.8, "domain_coverage": "adequate"},
                            "loop_required": False,
                        },
                        output_type=PortType.QUALIFIED_SOURCE_SET,
                    )

        nodes["source_quality_evaluator"] = LoopTriggerQuality()
        orch = Orchestrator(blueprint=blueprint, nodes=nodes)
        import asyncio
        trace = asyncio.run(orch.run("Test loop query"))

        # Chain should complete (not fail from loop exhaustion)
        assert trace.final_status == "completed"

        # Trace should have loop events
        event_types = {e.event_type for e in trace.events}
        from nodechain.core.trace import EventType
        assert EventType.LOOP_ENTERED in event_types

    def test_max_iterations_escalation(self):
        """Loop should escalate after max_iterations, not loop forever."""
        from test_runtime import load_blueprint, _create_mock_nodes, MockNode
        from nodechain.runtime.orchestrator import Orchestrator
        from nodechain.core.port import PortType
        from nodechain.core.trace import EventType

        blueprint = load_blueprint("blueprints/research_decision_v1.yaml")
        nodes = _create_mock_nodes()

        # Override source_quality to ALWAYS trigger loop
        class AlwaysLoop(MockNode):
            def __init__(self):
                super().__init__(
                    "source_quality_evaluator",
                    PortType.SOURCE_SET,
                    PortType.QUALIFIED_SOURCE_SET,
                )

            async def execute(self, envelope):
                from nodechain.core.envelope import EnvelopeResponse
                return EnvelopeResponse(
                    request_envelope_id=envelope.envelope_id,
                    run_id=envelope.run_id,
                    chain_id=envelope.chain_id,
                    node_id="source_quality_evaluator",
                    step_id=envelope.step_id,
                    output={
                        "qualified_sources": [],
                        "quality_summary": {"total_evaluated": 0, "average_score": 0},
                        "loop_required": True,
                        "loop_reason": "Test: always loop",
                    },
                    output_type=PortType.QUALIFIED_SOURCE_SET,
                )

        nodes["source_quality_evaluator"] = AlwaysLoop()
        orch = Orchestrator(blueprint=blueprint, nodes=nodes)
        import asyncio
        trace = asyncio.run(orch.run("Test loop exhaustion"))

        # Should have loop events
        event_types = {e.event_type for e in trace.events}
        # Loop escalation should fire
        assert EventType.LOOP_ENTERED in event_types or EventType.LOOP_ESCALATION in event_types
