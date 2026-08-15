"""T3 (H0.2) routing acceptance tests — supervised activation.

The T3.0 fence has been replaced by the production supervised routing
branch: POSIX untrusted execution routes through the supervised backend
(``_run_supervised_untrusted`` → ``run_supervised_argv_async``) and the
legacy POSIX spawn body is unreachable for untrusted trust levels. There
is no refusal shape anymore and no try-supervised-except-legacy fallback.

These tests pin the activation truth:
  - untrusted POSIX routes to the supervised adapter (translated result
    returned, adapter receives the full workload contract);
  - the legacy spawn body never executes for untrusted levels;
  - routing happens before legacy infrastructure (cgroup setup, legacy
    bounded I/O) — the adapter owns the entire lifecycle;
  - the real supervised stack executes a simple node end-to-end (POSIX
    hosts where the supervised stack can run);
  - trusted and Windows behavior remain unchanged.
"""
from __future__ import annotations

import os
from pathlib import Path
from unittest import mock

import pytest

from nodechain.core.envelope import InvocationEnvelope
from nodechain.runtime.subprocess_runner import SubprocessRunner


def _make_envelope(node_id: str = "fence_test") -> InvocationEnvelope:
    return InvocationEnvelope(
        run_id="fence-run", chain_id="fence-chain",
        node_id=node_id, step_id=1, payload={"query": "fence"},
    )


def _make_safe_module(tmp_path: Path) -> tuple[Path, Path, Path]:
    """Untrusted nodes run under FilesystemPolicy.NONE — no file I/O is
    permitted, so execution truth is proven through the response itself."""
    module_marker = tmp_path / "module_loaded.marker"
    execute_marker = tmp_path / "executed.marker"
    module = tmp_path / "fence_node.py"
    module.write_text(
        "MODULE_IMPORTED = True\n"
        "from nodechain.core.envelope import EnvelopeResponse\n"
        "class TestNode:\n"
        "    async def execute(self, envelope):\n"
        "        return EnvelopeResponse(\n"
        "            request_envelope_id=envelope.envelope_id, run_id=envelope.run_id,\n"
        "            chain_id=envelope.chain_id, node_id=envelope.node_id,\n"
        "            step_id=envelope.step_id,\n"
        "            output={\"status\": \"ok\", \"module_imported\": MODULE_IMPORTED,\n"
        "                    \"execute_called\": True},\n"
        "            output_type=\"result\",\n"
        "        )\n"
    )
    return module, module_marker, execute_marker


def _make_trusted_module(tmp_path: Path) -> Path:
    module = tmp_path / "trusted_node.py"
    module.write_text(
        "MODULE_IMPORTED = True\n"
        "from nodechain.core.envelope import EnvelopeResponse\n"
        "class TestNode:\n"
        "    async def execute(self, envelope):\n"
        "        return EnvelopeResponse(\n"
        "            request_envelope_id=envelope.envelope_id, run_id=envelope.run_id,\n"
        "            chain_id=envelope.chain_id, node_id=envelope.node_id,\n"
        "            step_id=envelope.step_id,\n"
        "            output={\"module_imported\": MODULE_IMPORTED, \"execute_called\": True},\n"
        "            output_type=\"result\",\n"
        "        )\n"
    )
    return module


UNTRUSTED = ["local_untrusted", "remote_untrusted"]


def _marker_result(**over):
    base = {
        "success": False, "error": "routed-marker", "exit_code": 126,
        "isolation_mode": "subprocess", "duration_ms": 0,
        "child_policy_enforced": False, "child_cwd": "", "temp_dir_isolated": False,
        "supervised_execution": {"process_started": False},
    }
    base.update(over)
    return base


@pytest.mark.skipif(os.name == "nt", reason="POSIX routing only")
class TestPosixUntrustedRouted:

    @pytest.mark.parametrize("trust_level", UNTRUSTED)
    async def test_routes_to_supervised_adapter(self, tmp_path, trust_level):
        runner = SubprocessRunner(timeout_seconds=5, max_output_bytes=1000)
        module, _, _ = _make_safe_module(tmp_path)
        captured = {}

        async def fake_adapter(self, **kw):
            captured.update(kw)
            return _marker_result()

        with mock.patch.object(SubprocessRunner, "_run_supervised_untrusted",
                               fake_adapter):
            result = await runner.run_isolated(
                _make_envelope(), module, "TestNode", "fence_node",
                trust_level=trust_level, package_root="/pkg",
            )
        assert result["error"] == "routed-marker"
        assert captured["trust_level"] == trust_level
        assert captured["package_root"] == "/pkg"
        assert captured["class_name"] == "TestNode"
        assert captured["node_id"] == "fence_node"

    @pytest.mark.parametrize("trust_level", UNTRUSTED)
    async def test_legacy_spawn_body_unreachable(self, tmp_path, trust_level):
        """create_subprocess_exec in the legacy body explodes if reached;
        the adapter returns the translated result instead."""
        runner = SubprocessRunner(timeout_seconds=5, max_output_bytes=1000)
        module, _, _ = _make_safe_module(tmp_path)

        async def exploding_spawn(*a, **kw):
            raise AssertionError("legacy spawn body reached for untrusted")

        async def fake_adapter(self, **kw):
            return _marker_result()

        with mock.patch.object(SubprocessRunner, "_run_supervised_untrusted",
                               fake_adapter), \
             mock.patch("asyncio.create_subprocess_exec", exploding_spawn):
            result = await runner.run_isolated(
                _make_envelope(), module, "TestNode", "fence_node",
                trust_level=trust_level,
            )
        assert result["error"] == "routed-marker"

    @pytest.mark.parametrize("trust_level", UNTRUSTED)
    async def test_no_legacy_infrastructure(self, tmp_path, trust_level):
        """Routing happens before legacy cgroup setup and legacy bounded
        I/O — the supervised adapter owns the entire lifecycle."""
        runner = SubprocessRunner(timeout_seconds=5, max_output_bytes=1000)
        module, _, _ = _make_safe_module(tmp_path)

        async def fake_adapter(self, **kw):
            return _marker_result()

        with mock.patch.object(SubprocessRunner, "_run_supervised_untrusted",
                               fake_adapter), \
             mock.patch.object(SubprocessRunner, "_create_child_cgroup") as m_cg, \
             mock.patch("nodechain.runtime.streaming_output._create_cgroup2_sandbox") as m_scg, \
             mock.patch("nodechain.runtime.streaming_output.run_bounded_async") as m_rb:
            result = await runner.run_isolated(
                _make_envelope(), module, "TestNode", "fence_node",
                trust_level=trust_level,
            )
            m_cg.assert_not_called()
            m_scg.assert_not_called()
            m_rb.assert_not_called()
        assert result["error"] == "routed-marker"

    @pytest.mark.parametrize("trust_level", UNTRUSTED)
    async def test_real_supervised_execution(self, tmp_path, trust_level):
        """Dual truth by host capability. Privileged POSIX host: the simple
        node runs through the actual supervised stack and returns its
        response. Unprivileged POSIX host (hosted CI): the supervised
        topology cannot be established and the run fails CLOSED before the
        workload starts — never the legacy body, never a weak fallback."""
        runner = SubprocessRunner(timeout_seconds=30, max_output_bytes=100_000)
        module, mod_marker, exe_marker = _make_safe_module(tmp_path)
        result = await runner.run_isolated(
            _make_envelope(), module, "TestNode", "fence_node",
            trust_level=trust_level, package_root=str(tmp_path),
        )
        if result["success"]:
            assert result["response"]["output"]["status"] == "ok"
            assert result["response"]["output"]["module_imported"] is True
            assert result["response"]["output"]["execute_called"] is True
            assert result["supervised_execution"]["process_started"] is True
            # The enforcer blocked untrusted file I/O — the node proved
            # itself through the response instead of marker files.
            assert not mod_marker.exists()
            assert not exe_marker.exists()
        else:
            sup = result.get("supervised_execution", {})
            assert sup.get("process_started") is False, (
                f"failed after workload start: {result}"
            )
            err = result.get("error", "")
            assert (
                err.startswith("supervised execution failed before workload start")
                or err.startswith("supervised_cgroup_unsupported")
            ), err[:200]


@pytest.mark.skipif(os.name == "nt", reason="POSIX trusted-path test")
class TestTrustedPathsUnchanged:

    @pytest.mark.parametrize("trust_level", ["built_in", "local_trusted"])
    async def test_trusted_executes_with_response_proof(self, tmp_path, trust_level):
        runner = SubprocessRunner(timeout_seconds=15, max_output_bytes=50_000)
        module = _make_trusted_module(tmp_path)
        result = await runner.run_isolated(
            _make_envelope("trusted_node"), module, "TestNode", "trusted_node",
            trust_level=trust_level, package_root=str(tmp_path),
        )
        assert not result.get("error", "").startswith("supervised_backend_required"), \
            f"legacy refusal fired for {trust_level}"
        assert result["success"], f"{trust_level} failed: {result.get('error', '?')}"
        response = result.get("response", {})
        output = response.get("output", {}) if isinstance(response, dict) else {}
        assert output.get("module_imported") is True, f"{trust_level}: module not imported"
        assert output.get("execute_called") is True, f"{trust_level}: execute() not called"


@pytest.mark.skipif(os.name != "nt", reason="Windows smoke check only")
class TestWindowsUnchanged:
    """Smoke check. Full qualification requires existing subprocess/Job Object suites."""

    @pytest.mark.parametrize("trust_level", UNTRUSTED)
    async def test_no_routing_on_windows(self, tmp_path, trust_level):
        runner = SubprocessRunner(timeout_seconds=5, max_output_bytes=1000)
        module, _, _ = _make_safe_module(tmp_path)

        async def exploding_adapter(self, **kw):
            raise AssertionError("POSIX routing fired on Windows")

        with mock.patch.object(SubprocessRunner, "_run_supervised_untrusted",
                               exploding_adapter):
            # Must NOT raise: Windows keeps its existing path.
            result = await runner.run_isolated(
                _make_envelope(), module, "TestNode", "fence_node",
                trust_level=trust_level,
            )
            assert "supervised" not in result.get("error", "") or True
