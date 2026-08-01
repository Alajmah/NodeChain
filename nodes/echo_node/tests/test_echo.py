"""Tests for the Echo Node package."""

import asyncio
import importlib.util
from pathlib import Path

import pytest

from nodechain.core.envelope import InvocationEnvelope

# Load implementation from the package directory
_impl_path = Path(__file__).parent.parent / "implementation.py"
_spec = importlib.util.spec_from_file_location("implementation", _impl_path)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
EchoNode = _mod.EchoNode


def _make_envelope(payload: dict) -> InvocationEnvelope:
    return InvocationEnvelope(
        envelope_id="test-env-1",
        run_id="test-run",
        chain_id="test-chain",
        node_id="echo_node",
        step_id=1,
        payload=payload,
    )


async def _execute(node, payload):
    env = _make_envelope(payload)
    return await node.execute(env)


class TestEchoNode:
    def test_passthrough(self):
        node = EchoNode()
        result = asyncio.get_event_loop().run_until_complete(
            _execute(node, {"query": "Hello World"})
        )
        assert result.output["query"] == "Hello World"
        assert result.output["transformed"] == "Hello World"

    def test_uppercase(self):
        node = EchoNode()
        result = asyncio.get_event_loop().run_until_complete(
            _execute(node, {"query": "hello", "transform": "uppercase"})
        )
        assert result.output["transformed"] == "HELLO"

    def test_lowercase(self):
        node = EchoNode()
        result = asyncio.get_event_loop().run_until_complete(
            _execute(node, {"query": "HELLO", "transform": "lowercase"})
        )
        assert result.output["transformed"] == "hello"

    def test_reverse(self):
        node = EchoNode()
        result = asyncio.get_event_loop().run_until_complete(
            _execute(node, {"query": "abc", "transform": "reverse"})
        )
        assert result.output["transformed"] == "cba"

    def test_manifest(self):
        node = EchoNode()
        m = node.manifest
        assert m.node_id == "echo_node"
        assert m.node_type == "deterministic"

    def test_zero_cost(self):
        node = EchoNode()
        result = asyncio.get_event_loop().run_until_complete(
            _execute(node, {"query": "test"})
        )
        assert result.cost_usd == 0.0
