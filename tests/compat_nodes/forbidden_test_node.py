"""Forbidden import test node — attempts to import a dangerous module.

Tests that import enforcement blocks forbidden modules under chroot.
This node tries to import `ctypes`, which is in the _PRELOADED_DENYLIST.
"""
from __future__ import annotations
from typing import Any
from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import NodeContract, EntryContract, ExitContract, Requirements
from nodechain.core.manifest import NodeManifest
from nodechain.core.port import PortType
from nodechain.nodes.base_node import BaseNode

_FORBIDDEN_CONTRACT = NodeContract(
    contract_id="compat.forbidden.v1",
    node_id="forbidden_test_node",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.RAW_QUERY,
        schema_ref="nodechain://schemas/semantic_types/raw_user_query",
        required_fields=["query"],
    ),
    exit=ExitContract(
        output_type=PortType.FINAL_RESPONSE,
        schema_ref="nodechain://schemas/semantic_types/final_response",
        guaranteed_fields=["ctypes_blocked"],
    ),
    requirements=Requirements(model_required=False, memory_access="none", trust_level="trusted"),
)


class ForbiddenTestNode(BaseNode):
    def __init__(self, **kwargs: Any) -> None:
        pass

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="forbidden_test_node",
            node_type="deterministic",
            name="Forbidden Import Test Node",
            description="Attempts to import ctypes (should be blocked).",
            contract=_FORBIDDEN_CONTRACT,
            tags=["test", "chroot", "compat", "security"],
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        ctypes_blocked = False
        ctypes_error = ""
        try:
            import ctypes  # noqa: F401
            ctypes_blocked = False  # Not blocked — security issue
        except (ImportError, PermissionError, Exception) as e:
            ctypes_blocked = True  # Correctly blocked
            ctypes_error = str(e)

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="forbidden_test_node",
            step_id=envelope.step_id,
            output={
                "ctypes_blocked": ctypes_blocked,
                "ctypes_error": ctypes_error,
            },
            output_type=PortType.FINAL_RESPONSE,
            cost_usd=0.0,
            latency_ms=0,
        )
