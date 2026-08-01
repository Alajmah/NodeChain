"""Shared Trace Collector — domain-neutral reusable node (v2.61.0).

Accepts TRACE_INPUT (chain execution summary) and produces
CHAIN_TRACE_OUTPUT (final trace record). Reusable across all chains.

Build a node once. Govern it forever. Reuse it everywhere.
"""

from __future__ import annotations

import uuid
from typing import Any

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import (
    EntryContract, ExitContract, NodeContract, Requirements,
)
from nodechain.core.manifest import NodeManifest
from nodechain.core.port import PortType
from nodechain.nodes.base_node import BaseNode


SHARED_TRACE_COLLECTOR_CONTRACT = NodeContract(
    contract_id="shared.trace-collector.v1",
    node_id="shared_trace_collector",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.TRACE_INPUT,
        schema_ref="nodechain://schemas/semantic_types/trace_input",
        required_fields=["run_id"],
    ),
    exit=ExitContract(
        output_type=PortType.CHAIN_TRACE_OUTPUT,
        schema_ref="nodechain://schemas/semantic_types/chain_trace_output",
        guaranteed_fields=["trace_id", "run_id", "nodes_executed"],
    ),
    requirements=Requirements(
        model_required=False,
    ),
)


class SharedTraceCollectorNode(BaseNode):
    """Domain-neutral trace collector.

    Collects execution summary from any chain and produces a final
    trace record with node count, cost, duration, and status.
    """

    def __init__(self, model_adapter: Any = None) -> None:
        self._model = model_adapter

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="shared_trace_collector",
            node_type="deterministic",
            name="Shared Trace Collector",
            description="Domain-neutral trace collector. Reusable across chains.",
            contract=SHARED_TRACE_COLLECTOR_CONTRACT,
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        ctx = envelope.payload

        run_id = ctx.get("run_id", "")
        chain_id = ctx.get("chain_id", "")
        nodes_executed = ctx.get("nodes_executed", [])
        total_cost = ctx.get("total_cost", 0.0)
        total_duration_ms = ctx.get("total_duration_ms", 0)
        final_status = ctx.get("final_status", "unknown")
        errors = ctx.get("errors", [])

        output = {
            "trace_id": f"trace-{uuid.uuid4().hex[:12]}",
            "run_id": run_id,
            "chain_id": chain_id,
            "nodes_executed": nodes_executed,
            "node_count": len(nodes_executed),
            "total_cost_usd": round(total_cost, 6),
            "total_duration_ms": total_duration_ms,
            "final_status": final_status,
            "errors": errors,
            "error_count": len(errors),
            "trace_complete": final_status in ("completed", "cancelled", "failed"),
        }

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="shared_trace_collector",
            step_id=envelope.step_id,
            output=output,
            output_type=PortType.CHAIN_TRACE_OUTPUT,
        )
