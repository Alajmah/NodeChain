"""Reverse Node implementation."""

from __future__ import annotations
from typing import Any

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import NodeContract, EntryContract, ExitContract, Requirements
from nodechain.core.manifest import NodeManifest
from nodechain.core.port import PortType
from nodechain.nodes.base_node import BaseNode

REVERSE_CONTRACT = NodeContract(
    contract_id="transforms.reverse.v1",
    node_id="reverse_node",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.RAW_QUERY,
        schema_ref="nodechain://schemas/semantic_types/raw_user_query",
        required_fields=["query"],
    ),
    exit=ExitContract(
        output_type=PortType.RAW_QUERY,
        schema_ref="nodechain://schemas/semantic_types/raw_user_query",
        guaranteed_fields=["query", "transformed"],
    ),
    requirements=Requirements(model_required=False),
)


class ReverseNode(BaseNode):
    """Reverses the input string."""

    def __init__(self, **kwargs: Any) -> None:
        pass

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="reverse_node", node_type="deterministic",
            name="Reverse Node",
            description="Reverses the input query string.",
            contract=REVERSE_CONTRACT,
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        query = envelope.payload.get("query", "")
        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id, chain_id=envelope.chain_id,
            node_id="reverse_node", step_id=envelope.step_id,
            output={"query": query, "transformed": query[::-1]},
            output_type=PortType.RAW_QUERY,
            cost_usd=0.0, latency_ms=0,
        )
