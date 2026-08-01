"""Test node with declared dependency import.

Used by mount confinement tests to verify that a node importing
from nodechain.core still works under chroot (because the SDK
modules are pre-imported before chroot).
"""
from __future__ import annotations

from typing import Any

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import (
    NodeContract, EntryContract, ExitContract, Requirements,
)
from nodechain.core.manifest import NodeManifest
from nodechain.core.port import PortType
from nodechain.nodes.base_node import BaseNode


CHROOT_TEST_CONTRACT = NodeContract(
    contract_id="test.chroot.v1",
    node_id="chroot_test_node",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.RAW_QUERY,
        schema_ref="nodechain://schemas/semantic_types/raw_user_query",
        required_fields=["query"],
    ),
    exit=ExitContract(
        output_type=PortType.FINAL_RESPONSE,
        schema_ref="nodechain://schemas/semantic_types/final_response",
        guaranteed_fields=["result"],
    ),
    requirements=Requirements(
        model_required=False,
        memory_access="none",
        trust_level="trusted",
    ),
)


class ChrootTestNode(BaseNode):
    """Node that imports a dependency and checks filesystem access."""

    def __init__(self, **kwargs: Any) -> None:
        pass

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="chroot_test_node",
            node_type="deterministic",
            name="Chroot Test Node",
            description="Tests dependency import and host path blocking under chroot.",
            contract=CHROOT_TEST_CONTRACT,
            tags=["test", "chroot"],
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        # Verify PortType import worked (declared dependency)
        port_ok = PortType.RAW_QUERY is not None

        # Try to read a host path that should be blocked under chroot
        host_blocked = False
        try:
            with open("/etc/passwd", "r") as f:
                f.read(1)
        except (FileNotFoundError, PermissionError, OSError):
            host_blocked = True

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="chroot_test_node",
            step_id=envelope.step_id,
            output_type=PortType.FINAL_RESPONSE,
            output={
                "result": f"port_ok={port_ok} host_blocked={host_blocked}",
                "port_type_imported": port_ok,
                "host_path_blocked": host_blocked,
            },
        )
