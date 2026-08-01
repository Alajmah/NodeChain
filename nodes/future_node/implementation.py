"""Future Node implementation."""

from __future__ import annotations

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import (
    NodeContract, EntryContract, ExitContract, Requirements,
)
from nodechain.core.manifest import NodeManifest
from nodechain.core.port import PortType
from nodechain.nodes.base_node import BaseNode


FUTURE_NODE_CONTRACT = NodeContract(
    contract_id="test.future.v1",
    node_id="future_node",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.RAW_QUERY,
        schema_ref="nodechain://schemas/semantic_types/raw_user_query",
        required_fields=["query"],
    ),
    exit=ExitContract(
        output_type=PortType.RAW_QUERY,
        schema_ref="nodechain://schemas/semantic_types/raw_user_query",
        guaranteed_fields=["query"],
    ),
    side_effects=[],
    requirements=Requirements(),
)


class FutureNode(BaseNode):
    """A node that requires a future runtime version."""

    manifest = NodeManifest(
        node_id="future_node",
        node_type="deterministic",
        name="Future Node",
        description="A node that requires a future runtime version.",
        version="1.0.0",
        contract=FUTURE_NODE_CONTRACT,
    )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        return EnvelopeResponse(
            output={"query": envelope.payload.get("query", ""), "result": "future"},
        )
