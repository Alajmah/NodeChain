"""Branch Trace Collector — simplified trace collector for branch chains."""

from __future__ import annotations

from typing import Any

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.manifest import NodeManifest
from nodechain.core.port import PortType
from nodechain.core.contract import (
    EntryContract, ExitContract, Requirements, NodeContract,
)
from nodechain.nodes.base_node import BaseNode

BRANCH_TRACE_CONTRACT = NodeContract(
    contract_id="branch.trace-collector.v1",
    node_id="trace_collector",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.FINAL_RESPONSE,
        schema_ref="nodechain://schemas/semantic_types/final_response",
        required_fields=["recommendation"],
    ),
    exit=ExitContract(
        output_type=PortType.CHAIN_TRACE_OUTPUT,
        schema_ref="nodechain://schemas/chain_trace",
        guaranteed_fields=["trace_collected"],
    ),
    requirements=Requirements(model_required=False),
)


class BranchTraceCollectorNode(BaseNode):
    """Simplified trace collector for branch chains."""

    def __init__(self) -> None:
        pass

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="trace_collector",
            node_type="deterministic",
            name="Branch Trace Collector",
            description="Finalizes branch chain trace.",
            contract=BRANCH_TRACE_CONTRACT,
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="trace_collector",
            step_id=envelope.step_id,
            output={"trace_collected": True},
            output_type=PortType.CHAIN_TRACE_OUTPUT,
        )
