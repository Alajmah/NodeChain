"""T3.0 safety-fence acceptance tests.

POSIX untrusted execution via the legacy SubprocessRunner path must be refused
before any workload process is spawned. No path resolution, no module existence
check, no temp dir, no cgroup, no spawn, no module import, no execute().

The fence must not be bypassable by any env var, config flag, or fallback.
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
    module_marker = tmp_path / "module_loaded.marker"
    execute_marker = tmp_path / "executed.marker"
    module = tmp_path / "fence_node.py"
    module.write_text(
        f"open(r'{module_marker}', 'w').write('imported')\n"
        "from nodechain.core.envelope import EnvelopeResponse\n"
        "class TestNode:\n"
        "    async def execute(self, envelope):\n"
        f"        open(r'{execute_marker}', 'w').write('executed')\n"
        "        return EnvelopeResponse(\n"
        "            request_envelope_id=envelope.envelope_id, run_id=envelope.run_id,\n"
        "            chain_id=envelope.chain_id, node_id=envelope.node_id,\n"
        '            step_id=envelope.step_id, output={"status": "ok"},\n'
        '            output_type="result",\n'
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
        '            output={"module_imported": MODULE_IMPORTED, "execute_called": True},\n'
        '            output_type="result",\n'
        "        )\n"
    )
    return module


UNTRUSTED = ["local_untrusted", "remote_untrusted"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX fence only")
class TestPosixUntrustedFence:

    @pytest.mark.parametrize("trust_level", UNTRUSTED)
    async def test_refusal_shape(self, tmp_path, trust_level):
        runner = SubprocessRunner(timeout_seconds=5, max_output_bytes=1000)
        module, _, _ = _make_safe_module(tmp_path)
        result = await runner.run_isolated(
            _make_envelope(), module, "TestNode", "fence_node",
            trust_level=trust_level,
        )
        assert result["success"] is False
        assert result["exit_code"] == 126
        assert result["error"].startswith("supervised_backend_required")
        assert result["child_policy_enforced"] is False
        assert result["temp_dir_isolated"] is False

    @pytest.mark.parametrize("trust_level", UNTRUSTED)
    async def test_no_module_import_or_execute(self, tmp_path, trust_level):
        runner = SubprocessRunner(timeout_seconds=5, max_output_bytes=1000)
        module, mod_marker, exe_marker = _make_safe_module(tmp_path)
        for m in [mod_marker, exe_marker]:
            if m.exists(): m.unlink()
        await runner.run_isolated(
            _make_envelope(), module, "TestNode", "fence_node",
            trust_level=trust_level,
        )
        assert not mod_marker.exists(), "Module imported"
        assert not exe_marker.exists(), "execute() ran"

    @pytest.mark.parametrize("trust_level", UNTRUSTED)
    async def test_no_infrastructure_calls(self, tmp_path, trust_level):
        """Fence returns before Path.resolve, Path.exists, temp creation,
        child-script build, cgroup setup, spawn, bounded execution.

        Path.resolve and Path.exists use fail-on-call sentinels so any
        regression that resolves or inspects the module path is caught
        directly, not merely inferred from downstream no-calls.
        """
        import tempfile as _tm
        runner = SubprocessRunner(timeout_seconds=5, max_output_bytes=1000)
        module, _, _ = _make_safe_module(tmp_path)
        with mock.patch.object(
            Path, "resolve",
            side_effect=AssertionError("Path.resolve called before T3.0 refusal"),
        ) as m_res, mock.patch.object(
            Path, "exists",
            side_effect=AssertionError("Path.exists called before T3.0 refusal"),
        ) as m_ex, \
             mock.patch.object(_tm, "mkdtemp", wraps=_tm.mkdtemp) as m_mk, \
             mock.patch.object(SubprocessRunner, "_build_child_script") as m_bs, \
             mock.patch.object(SubprocessRunner, "_create_child_cgroup") as m_cg, \
             mock.patch("nodechain.runtime.streaming_output._create_cgroup2_sandbox") as m_scg, \
             mock.patch("asyncio.create_subprocess_exec") as m_sp, \
             mock.patch("nodechain.runtime.streaming_output.run_bounded_async") as m_rb:
            result = await runner.run_isolated(
                _make_envelope(), module, "TestNode", "fence_node",
                trust_level=trust_level,
            )
            m_res.assert_not_called()
            m_ex.assert_not_called()
            m_mk.assert_not_called()
            m_bs.assert_not_called()
            m_cg.assert_not_called()
            m_scg.assert_not_called()
            m_sp.assert_not_called()
            m_rb.assert_not_called()

    @pytest.mark.parametrize("trust_level", UNTRUSTED)
    async def test_deterministic(self, tmp_path, trust_level):
        runner = SubprocessRunner(timeout_seconds=5, max_output_bytes=1000)
        module, _, _ = _make_safe_module(tmp_path)
        r1 = await runner.run_isolated(_make_envelope(), module, "TestNode", "fence_node", trust_level=trust_level)
        r2 = await runner.run_isolated(_make_envelope(), module, "TestNode", "fence_node", trust_level=trust_level)
        assert set(r1.keys()) == set(r2.keys())
        assert r1["success"] == r2["success"] is False
        assert r1["exit_code"] == r2["exit_code"] == 126
        assert r1["error"].split(":")[0] == r2["error"].split(":")[0] == "supervised_backend_required"

    @pytest.mark.parametrize("trust_level", UNTRUSTED)
    async def test_no_residue(self, tmp_path, trust_level):
        import tempfile as _tm
        runner = SubprocessRunner(timeout_seconds=5, max_output_bytes=1000)
        module, mod_marker, exe_marker = _make_safe_module(tmp_path)
        for m in [mod_marker, exe_marker]:
            if m.exists(): m.unlink()
        with mock.patch.object(_tm, "mkdtemp", wraps=_tm.mkdtemp) as m_mk:
            await runner.run_isolated(_make_envelope(), module, "TestNode", "fence_node", trust_level=trust_level)
            m_mk.assert_not_called()
        assert not mod_marker.exists()
        assert not exe_marker.exists()


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
            f"Fence fired for {trust_level}"
        assert result["success"], f"{trust_level} failed: {result.get('error', '?')}"
        response = result.get("response", {})
        output = response.get("output", {}) if isinstance(response, dict) else {}
        assert output.get("module_imported") is True, f"{trust_level}: module not imported"
        assert output.get("execute_called") is True, f"{trust_level}: execute() not called"


@pytest.mark.skipif(os.name != "nt", reason="Windows smoke check only")
class TestWindowsUnchanged:
    """Smoke check. Full qualification requires existing subprocess/Job Object suites."""

    @pytest.mark.parametrize("trust_level", UNTRUSTED)
    async def test_no_fence_on_windows(self, tmp_path, trust_level):
        runner = SubprocessRunner(timeout_seconds=5, max_output_bytes=1000)
        module, _, _ = _make_safe_module(tmp_path)
        result = await runner.run_isolated(
            _make_envelope(), module, "TestNode", "fence_node",
            trust_level=trust_level,
        )
        assert not result.get("error", "").startswith("supervised_backend_required"), \
            "POSIX fence fired on Windows"
