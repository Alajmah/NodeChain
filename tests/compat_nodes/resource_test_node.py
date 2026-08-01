"""Resource test node — reads a data file from the package directory.

Tests that data files packaged alongside implementation.py are
accessible under chroot (via the /package bind mount).
"""
from __future__ import annotations
from typing import Any
from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import NodeContract, EntryContract, ExitContract, Requirements
from nodechain.core.manifest import NodeManifest
from nodechain.core.port import PortType
from nodechain.nodes.base_node import BaseNode
import os

_RESOURCE_CONTRACT = NodeContract(
    contract_id="compat.resource.v1",
    node_id="resource_test_node",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.RAW_QUERY,
        schema_ref="nodechain://schemas/semantic_types/raw_user_query",
        required_fields=["query"],
    ),
    exit=ExitContract(
        output_type=PortType.FINAL_RESPONSE,
        schema_ref="nodechain://schemas/semantic_types/final_response",
        guaranteed_fields=["resource_read"],
    ),
    requirements=Requirements(model_required=False, memory_access="none", trust_level="trusted"),
)


class ResourceTestNode(BaseNode):
    def __init__(self, **kwargs: Any) -> None:
        pass

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="resource_test_node",
            node_type="deterministic",
            name="Resource Test Node",
            description="Reads a data file from the package directory.",
            contract=_RESOURCE_CONTRACT,
            tags=["test", "chroot", "compat"],
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        # Try to read resource_data.txt from the same directory as this module.
        # Under chroot, this file should be at /package/resource_data.txt
        # (bind-mounted from the real package directory).
        resource_path = os.path.join(os.path.dirname(__file__), "resource_data.txt")
        # Under chroot, __file__ is /package/resource_test.py
        # so resource_data.txt would be at /package/resource_data.txt
        resource_read = False
        resource_content = ""
        error_msg = ""
        try:
            with open(resource_path, "r") as f:
                resource_content = f.read().strip()
                resource_read = True
        except (FileNotFoundError, PermissionError, OSError) as e:
            error_msg = str(e)

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="resource_test_node",
            step_id=envelope.step_id,
            output={
                "resource_read": resource_read,
                "resource_preview": resource_content[:50],
                "error": error_msg,
            },
            output_type=PortType.FINAL_RESPONSE,
            cost_usd=0.0,
            latency_ms=0,
        )
