"""Test trace completeness — verify all expected event types are emitted."""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nodechain.core.trace import EventType, ChainTrace, TraceEvent, Actor


def _make_trace_with_events(event_types: list[EventType]) -> ChainTrace:
    """Create a trace with the given event types."""
    trace = ChainTrace(run_id="test-run", chain_id="test-chain")
    for i, et in enumerate(event_types):
        trace.add_event(TraceEvent(
            run_id="test-run",
            chain_id="test-chain",
            node_id="test_node",
            step_id=i + 1,
            event_type=et,
            actor=Actor.RUNTIME,
        ))
    return trace


class TestTraceCompleteness:
    """Verify that chain traces contain the expected event types."""

    def test_complete_trace_has_chain_lifecycle(self):
        """A complete trace must have CHAIN_STARTED and CHAIN_COMPLETED."""
        trace = _make_trace_with_events([
            EventType.CHAIN_STARTED,
            EventType.NODE_SUCCEEDED,
            EventType.CHAIN_COMPLETED,
        ])
        trace.finalize("completed")

        event_types = {e.event_type for e in trace.events}
        assert EventType.CHAIN_STARTED in event_types
        assert EventType.CHAIN_COMPLETED in event_types

    def test_failed_trace_has_chain_failed(self):
        """A failed trace must have CHAIN_STARTED and CHAIN_FAILED."""
        trace = _make_trace_with_events([
            EventType.CHAIN_STARTED,
            EventType.NODE_FAILED,
            EventType.CHAIN_FAILED,
        ])
        trace.finalize("failed")

        event_types = {e.event_type for e in trace.events}
        assert EventType.CHAIN_STARTED in event_types
        assert EventType.CHAIN_FAILED in event_types

    def test_trace_truth_rule_complete(self):
        """Trace with CHAIN_STARTED + CHAIN_COMPLETED satisfies truth rule."""
        trace = _make_trace_with_events([
            EventType.CHAIN_STARTED,
            EventType.CHAIN_COMPLETED,
        ])
        trace.finalize("completed")
        assert trace.summary.trace_complete is True

    def test_trace_truth_rule_incomplete(self):
        """Trace missing CHAIN_STARTED violates truth rule."""
        trace = _make_trace_with_events([
            EventType.NODE_SUCCEEDED,
            EventType.CHAIN_COMPLETED,
        ])
        trace.finalize("completed")
        assert trace.summary.trace_complete is False

    def test_trace_truth_rule_no_terminus(self):
        """Trace missing CHAIN_COMPLETED/FAILED violates truth rule."""
        trace = _make_trace_with_events([
            EventType.CHAIN_STARTED,
            EventType.NODE_SUCCEEDED,
        ])
        trace.finalize("running")
        assert trace.summary.trace_complete is False

    def test_full_chain_trace_event_coverage(self):
        """Verify a simulated full chain trace has all expected event categories."""
        from test_runtime import load_blueprint, _create_mock_nodes
        from nodechain.runtime.orchestrator import Orchestrator

        async def _run():
            blueprint = load_blueprint("blueprints/research_decision_v1.yaml")
            nodes = _create_mock_nodes()
            orch = Orchestrator(blueprint=blueprint, nodes=nodes)
            trace = await orch.run("Test query")
            return trace

        import asyncio
        trace = asyncio.run(_run())

        event_types = {e.event_type for e in trace.events}

        # Must have lifecycle events
        assert EventType.CHAIN_STARTED in event_types, "Missing CHAIN_STARTED"
        assert EventType.CHAIN_COMPLETED in event_types, "Missing CHAIN_COMPLETED"

        # Must have per-node events
        assert EventType.NODE_INVOKED in event_types, "Missing NODE_INVOKED"
        assert EventType.NODE_SUCCEEDED in event_types, "Missing NODE_SUCCEEDED"

        # Must have contract validation
        assert EventType.CONTRACT_VALIDATED in event_types, "Missing CONTRACT_VALIDATED"

        # Must have validation events
        has_validation = EventType.VALIDATION_PASSED in event_types or EventType.VALIDATION_FAILED in event_types
        assert has_validation, "Missing VALIDATION_PASSED or VALIDATION_FAILED"

        # Must have routing decisions for source quality and risk
        assert EventType.ROUTING_DECISION in event_types, "Missing ROUTING_DECISION"

        # Must have model call events (most nodes are model-backed)
        assert EventType.MODEL_CALLED in event_types, "Missing MODEL_CALLED"

        # Count distinct event types
        print(f"Event types in trace: {len(event_types)}")
        print(f"Event types: {sorted(e.value for e in event_types)}")

        # A complete chain trace should have at least 8 distinct event types
        assert len(event_types) >= 8, f"Only {len(event_types)} event types, expected >= 8"

    def test_trace_timestamps_monotonic(self):
        """Trace event timestamps should be non-decreasing."""
        from test_runtime import load_blueprint, _create_mock_nodes
        from nodechain.runtime.orchestrator import Orchestrator

        async def _run():
            blueprint = load_blueprint("blueprints/research_decision_v1.yaml")
            nodes = _create_mock_nodes()
            orch = Orchestrator(blueprint=blueprint, nodes=nodes)
            return await orch.run("Test query")

        import asyncio
        trace = asyncio.run(_run())

        timestamps = [e.timestamp for e in trace.events]
        # ISO timestamps should be non-decreasing when sorted
        assert timestamps == sorted(timestamps), "Timestamps are not monotonically increasing"

    def test_trace_no_events_for_nonexistent_nodes(self):
        """Trace truth rule: no events for nodes that didn't execute."""
        from test_runtime import load_blueprint, _create_mock_nodes
        from nodechain.runtime.orchestrator import Orchestrator

        async def _run():
            blueprint = load_blueprint("blueprints/research_decision_v1.yaml")
            nodes = _create_mock_nodes()
            orch = Orchestrator(blueprint=blueprint, nodes=nodes)
            return await orch.run("Test query")

        import asyncio
        trace = asyncio.run(_run())

        # Get all node_ids that have events
        node_ids_with_events = {e.node_id for e in trace.events}
        # Remove 'runtime' (orchestrator events)
        node_ids_with_events.discard("runtime")

        # Get registered nodes from the test helper
        from test_runtime import load_blueprint, _create_mock_nodes
        blueprint = load_blueprint("blueprints/research_decision_v1.yaml")
        registered_nodes = set(_create_mock_nodes().keys())
        for nid in node_ids_with_events:
            assert nid in registered_nodes, f"Event for unregistered node: {nid}"
