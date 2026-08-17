"""T3 production-caller propagation tests (H0.2 activation).

Verifies that the supervised route's fail-closed refusal propagates
correctly through NodeInvoker.invoke() for both untrusted trust levels:
failed EnvelopeResponse, zero direct node execution, zero retry, and the
trusted supervised evidence projection preserved on the failure path.
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
    """A supervised fail-closed refusal in the established result shape —
    what the T3 adapter returns when the supervised topology cannot start
    (e.g. unprivileged host) or a requested control is unavailable."""
    return {
        "success": False,
        "error": (
            "supervised execution failed before workload start "
            f"(unshare_failed: unshare_clone_newpid_failed: errno=1) [{trust_level}]"
        ),
        "exit_code": 126,
        "isolation_mode": "subprocess",
        "duration_ms": 3,
        "child_policy_enforced": False,
        "child_cwd": "/tmp/x",
        "temp_dir_isolated": True,
        "supervised_execution": {
            "backend": "native_os_sandbox",
            "process_started": False,
            "process_timed_out": False,
            "output_truncated": False,
            "exit_code_interpretation": "error",
            "reason": "unshare_failed: unshare_clone_newpid_failed: errno=1",
            "process_exit_code": None,
            "sandbox_metadata": {},
        },
    }


@pytest.mark.skipif(os.name == "nt", reason="POSIX supervised propagation only")
class TestProductionCallerPropagation:
    """NodeInvoker must propagate the supervised refusal correctly."""

    @pytest.mark.parametrize("trust_level", ["local_untrusted", "remote_untrusted"])
    async def test_refusal_propagates_through_invoker(self, tmp_path, trust_level):
        """Refusal -> failed EnvelopeResponse; zero node execution; zero retry;
        supervised evidence projection preserved on the failure path."""
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
        assert "supervised execution failed before workload start" in (response.error or "")
        assert response.output == {}

        meta = response.metadata or {}
        assert meta.get("exit_code") == 126, f"exit_code={meta.get('exit_code')}"
        # T3 evidence projection survives the failure path.
        assert meta.get("supervised_execution", {}).get("process_started") is False

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
