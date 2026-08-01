"""Sandbox test node — attempts all four blocked boundaries.

This node tries import, filesystem, subprocess, and network operations
that should all be blocked for restricted trust levels.
"""

from __future__ import annotations

from nodechain.nodes.base_node import BaseNode
from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse


class SandboxTestNode(BaseNode):
    """Attempts all four sandbox boundaries and reports which were blocked."""

    def manifest(self):
        from nodechain.core.manifest import NodeManifest
        return NodeManifest(
            node_id="sandbox_test_node",
            node_type="deterministic",
            name="Sandbox Test Node",
            description="Demo node testing all four sandbox boundaries",
            version="1.0.0",
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        results = {
            "import_blocked": False,
            "filesystem_blocked": False,
            "subprocess_blocked": False,
            "network_blocked": False,
            "details": {},
        }

        # Test 1: Import a restricted module
        try:
            import subprocess  # noqa: F401 — testing import policy
            results["import_blocked"] = False
        except Exception:
            results["import_blocked"] = True
        results["details"]["import"] = "attempted"

        # Test 1b: importlib.import_module bypass attempt (FINDING-002 regression)
        try:
            import importlib
            importlib.import_module("subprocess")
            results["importlib_blocked"] = False
        except Exception:
            results["importlib_blocked"] = True
        results["details"]["importlib"] = "attempted"

        # Test 2: Filesystem write
        try:
            with open("sandbox_test_output.txt", "w") as f:
                f.write("test")
            results["filesystem_blocked"] = False
        except Exception:
            results["filesystem_blocked"] = True
        results["details"]["filesystem"] = "attempted"

        # Test 3: Subprocess execution
        try:
            import subprocess as sp
            sp.run(["echo", "sandbox_test"], capture_output=True)
            results["subprocess_blocked"] = False
        except Exception:
            results["subprocess_blocked"] = True
        results["details"]["subprocess"] = "attempted"

        # Test 4: Network access
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.close()
            results["network_blocked"] = False
        except Exception:
            results["network_blocked"] = True
        results["details"]["network"] = "attempted"

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="sandbox_test_node",
            step_id=envelope.step_id,
            output=results,
            output_type="dict",
        )
