"""Echo Node implementation — a simple example Harness Node."""

from __future__ import annotations

from typing import Any

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import (
    NodeContract, EntryContract, ExitContract, Requirements,
)
from nodechain.core.manifest import NodeManifest
from nodechain.core.port import PortType
from nodechain.nodes.base_node import BaseNode


ECHO_NODE_CONTRACT = NodeContract(
    contract_id="utility.echo.v1",
    node_id="echo_node",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.RAW_QUERY,
        schema_ref="nodechain://schemas/semantic_types/raw_user_query",
        required_fields=["query"],
        optional_fields=["transform"],
    ),
    exit=ExitContract(
        output_type=PortType.RAW_QUERY,
        schema_ref="nodechain://schemas/semantic_types/raw_user_query",
        guaranteed_fields=["query", "transformed"],
    ),
    requirements=Requirements(
        model_required=False,
        memory_access="none",
        trust_level="trusted",
    ),
)


class EchoNode(BaseNode):
    """
    Echo Node — passes through input with optional transformation.

    Supported transforms:
      - uppercase: Convert query to uppercase
      - lowercase: Convert query to lowercase
      - reverse: Reverse the query string
      - none (default): Pass through unchanged
    """

    def __init__(self, **kwargs: Any) -> None:
        pass  # No dependencies needed

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="echo_node",
            node_type="deterministic",
            name="Echo Node",
            description="Passes through input with optional transformation.",
            contract=ECHO_NODE_CONTRACT,
            tags=["example", "utility", "passthrough"],
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        query = envelope.payload.get("query", "")
        transform = envelope.payload.get("transform", "none")

        if transform == "uppercase":
            transformed = query.upper()
        elif transform == "lowercase":
            transformed = query.lower()
        elif transform == "reverse":
            transformed = query[::-1]
        else:
            transformed = query

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="echo_node",
            step_id=envelope.step_id,
            output={
                "query": query,
                "transformed": transformed,
                "transform_applied": transform,
            },
            output_type=PortType.RAW_QUERY,
            cost_usd=0.0,
            latency_ms=0,
        )
