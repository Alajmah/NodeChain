"""Test for Shared Trace Collector node."""
import asyncio
from nodechain.core.envelope import InvocationEnvelope
from nodes.shared_trace_collector.implementation import SharedTraceCollectorNode


def test_trace_collection():
    node = SharedTraceCollectorNode()
    env = InvocationEnvelope(
        envelope_id="t1", run_id="run-123", chain_id="test-chain", step_id=1, node_id="shared_trace_collector",
        payload={
            "run_id": "run-123",
            "chain_id": "test-chain",
            "nodes_executed": ["node_a", "node_b", "node_c"],
            "total_cost": 0.05,
            "total_duration_ms": 1200,
            "final_status": "completed",
            "errors": [],
        },
    )
    result = asyncio.run(node.execute(env))
    assert result.output["trace_id"].startswith("trace-")
    assert result.output["run_id"] == "run-123"
    assert result.output["node_count"] == 3
    assert result.output["trace_complete"] is True


def test_domain_neutral():
    """Same trace collector works for different chain types."""
    node = SharedTraceCollectorNode()
    for chain_type in ["research", "incident_response", "security_audit"]:
        env = InvocationEnvelope(
            envelope_id=f"t-{chain_type}", run_id="r", chain_id=chain_type, step_id=1, node_id="shared_trace_collector",
            payload={
                "run_id": "r",
                "chain_id": chain_type,
                "nodes_executed": ["a"],
                "total_cost": 0,
                "total_duration_ms": 0,
                "final_status": "completed",
                "errors": [],
            },
        )
        result = asyncio.run(node.execute(env))
        assert result.output["chain_id"] == chain_type
        assert result.output["trace_complete"] is True
