"""T3.0 production-caller propagation tests.

Verifies that the T3.0 fence refusal propagates correctly through
NodeInvoker.invoke() for both untrusted trust levels.
"""
from __future__ import annotations

import os
from pathlib import Path
from unittest import mock

import pytest

from nodechain.core.envelope import InvocationEnvelope


def _make_module(tmp_path: Path) -> Path:
    module = tmp_path / "caller_node.py"
    module.write_text(
        "MODULE_IMPORTED = True\n"
        "from nodechain.core.envelope import EnvelopeResponse\n"
        "class TestNode:\n"
        "    async def execute(self, envelope):\n"
        "        return EnvelopeResponse(\n"
        "            request_envelope_id=envelope.envelope_id, run_id=envelope.run_id,\n"
        "            chain_id=envelope.chain_id, node_id=envelope.node_id,\n"
        "            step_id=envelope.step_id,\n"
        '            output={"module_imported": MODULE_IMPORTED, "execute_called": True},\n'
        '            output_type="result",\n'
        "        )\n"
    )
    return module


def _make_envelope() -> InvocationEnvelope:
    return InvocationEnvelope(
        run_id="caller-test", chain_id="caller-chain",
        node_id="caller_node", step_id=1, payload={"query": "test"},
    )


def _make_refusal_result(trust_level: str) -> dict:
    return {
        "success": False,
        "error": (
            "supervised_backend_required: POSIX untrusted execution "
            f"({trust_level}) is disabled on the legacy SubprocessRunner "
            "path until supervised routing (T3) is available"
        ),
        "exit_code": 126,
        "isolation_mode": "subprocess",
        "duration_ms": 0,
        "child_policy_enforced": False,
        "child_cwd": "",
        "temp_dir_isolated": False,
    }


@pytest.mark.skipif(os.name == "nt", reason="POSIX fence propagation only")
class TestProductionCallerPropagation:
    """NodeInvoker must propagate the T3.0 fence refusal correctly."""

    @pytest.mark.parametrize("trust_level", ["local_untrusted", "remote_untrusted"])
    async def test_refusal_propagates_through_invoker(self, tmp_path, trust_level):
        """Refusal -> failed EnvelopeResponse; zero node execution; zero retry."""
        from nodechain.runtime.node_invoker import NodeInvoker

        module = _make_module(tmp_path)
        invoker = NodeInvoker()
        isolation_config = {
            "module_path": str(module),
            "class_name": "TestNode",
            "package_root": str(tmp_path),
        }

        node = mock.Mock()
        node.execute = mock.AsyncMock()

        with mock.patch(
            "nodechain.runtime.subprocess_runner.get_subprocess_runner"
        ) as mock_get_runner:
            runner = mock_get_runner.return_value
            runner.should_use_subprocess.return_value = True
            runner.run_isolated = mock.AsyncMock(
                return_value=_make_refusal_result(trust_level)
            )

            response, elapsed = await invoker.invoke(
                node, _make_envelope(),
                trust_level=trust_level,
                isolation_config=isolation_config,
            )

        assert response.success is False, "Invoker returned success for refused untrusted"
        assert response.output_type == "error"
        assert "supervised_backend_required" in (response.error or "")
        assert response.output == {}

        meta = response.metadata or {}
        assert meta.get("exit_code") == 126, f"exit_code={meta.get('exit_code')}"

        runner.run_isolated.assert_awaited_once()
        node.execute.assert_not_awaited()

    @pytest.mark.parametrize("trust_level", ["local_untrusted", "remote_untrusted"])
    async def test_no_unsafe_fallback(self, tmp_path, trust_level):
        """The invoker must not fall through to direct execution on refusal."""
        from nodechain.runtime.node_invoker import NodeInvoker

        module = _make_module(tmp_path)
        invoker = NodeInvoker()
        isolation_config = {
            "module_path": str(module),
            "class_name": "TestNode",
            "package_root": str(tmp_path),
        }

        node = mock.Mock()
        node.execute = mock.AsyncMock()

        with mock.patch(
            "nodechain.runtime.subprocess_runner.get_subprocess_runner"
        ) as mock_get_runner:
            runner = mock_get_runner.return_value
            runner.should_use_subprocess.return_value = True
            runner.run_isolated = mock.AsyncMock(
                return_value=_make_refusal_result(trust_level)
            )

            response, elapsed = await invoker.invoke(
                node, _make_envelope(),
                trust_level=trust_level,
                isolation_config=isolation_config,
            )

        assert not response.success
        node.execute.assert_not_awaited()
        runner.run_isolated.assert_awaited_once()
