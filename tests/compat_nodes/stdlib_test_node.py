"""Stdlib test node — imports standard library modules.

Tests that standard library modules available in sys.modules
(pre-imported by Python runtime) work under chroot.
"""
from __future__ import annotations
from typing import Any
from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import NodeContract, EntryContract, ExitContract, Requirements
from nodechain.core.manifest import NodeManifest
from nodechain.core.port import PortType
from nodechain.nodes.base_node import BaseNode

# Pre-import standard library modules that should work under chroot
import json
import math
import re
import collections

_STDLIB_CONTRACT = NodeContract(
    contract_id="compat.stdlib.v1",
    node_id="stdlib_test_node",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.RAW_QUERY,
        schema_ref="nodechain://schemas/semantic_types/raw_user_query",
        required_fields=["query"],
    ),
    exit=ExitContract(
        output_type=PortType.FINAL_RESPONSE,
        schema_ref="nodechain://schemas/semantic_types/final_response",
        guaranteed_fields=["json_ok"],
    ),
    requirements=Requirements(model_required=False, memory_access="none", trust_level="trusted"),
)


class StdlibTestNode(BaseNode):
    def __init__(self, **kwargs: Any) -> None:
        pass

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="stdlib_test_node",
            node_type="deterministic",
            name="Stdlib Test Node",
            description="Imports standard library modules (json, math, re).",
            contract=_STDLIB_CONTRACT,
            tags=["test", "chroot", "compat"],
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        # Test json
        json_ok = json.loads('{"key": "value"}')["key"] == "value"
        # Test math
        math_ok = math.sqrt(16) == 4.0
        # Test re
        re_ok = bool(re.match(r"\d+", "12345"))
        # Test collections
        coll_ok = collections.OrderedDict([("a", 1)])["a"] == 1

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="stdlib_test_node",
            step_id=envelope.step_id,
            output={
                "json_ok": json_ok,
                "math_ok": math_ok,
                "re_ok": re_ok,
                "coll_ok": coll_ok,
                "all_ok": all([json_ok, math_ok, re_ok, coll_ok]),
            },
            output_type=PortType.FINAL_RESPONSE,
            cost_usd=0.0,
            latency_ms=0,
        )
