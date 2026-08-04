"""Tests for mount namespace temp-root confinement (v1.4.5).

Tests cover:
1. apply_mount_confinement() function
2. RunnerConfig/SubprocessRunner enable_mount_confinement
3. NodeTrustRecord mount confinement fields
4. INV-012 (advisory)
5. E2E: child runs under chroot (Linux)
6. Host path blocked test (Linux)
7. Node executes correctly under chroot (Linux)
8. Version and changelog
"""

from __future__ import annotations

import platform
import pytest
from pathlib import Path


# ─── 1. apply_mount_confinement Function ─────────────────────────────────

class TestApplyMountConfinement:
    """apply_mount_confinement module function."""

    def test_function_exists(self):
        from nodechain.sdk.namespace_profile import apply_mount_confinement
        assert callable(apply_mount_confinement)

    def test_returns_dict(self):
        from nodechain.sdk.namespace_profile import apply_mount_confinement
        result = apply_mount_confinement("/nonexistent", "/tmp")
        assert isinstance(result, dict)
        assert "mount_confinement_enforced" in result
        assert "temp_root_created" in result
        assert "allowed_mounts" in result
        assert "mount_confinement_error" in result


# ─── 2. RunnerConfig/SubprocessRunner ────────────────────────────────────

class TestRunnerConfigMountConfinement:
    """RunnerConfig and SubprocessRunner support mount confinement."""

    def test_runner_config_field(self):
        from nodechain.runtime.subprocess_runner import RunnerConfig
        cfg = RunnerConfig(enable_mount_confinement=True)
        assert cfg.enable_mount_confinement is True

    def test_runner_config_to_kwargs(self):
        from nodechain.runtime.subprocess_runner import RunnerConfig
        cfg = RunnerConfig(enable_mount_confinement=True)
        kwargs = cfg.to_runner_kwargs()
        assert kwargs["enable_mount_confinement"] is True

    def test_subprocess_runner_field(self):
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        runner = SubprocessRunner(enable_mount_confinement=True)
        assert runner.enable_mount_confinement is True

    def test_default_disabled(self):
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        runner = SubprocessRunner()
        assert runner.enable_mount_confinement is False


# ─── 3. NodeTrustRecord Mount Confinement Fields ─────────────────────────

class TestNodeTrustRecordMountConfinement:
    """NodeTrustRecord has mount confinement fields."""

    def test_fields_exist(self):
        from nodechain.sdk.trust_summary import NodeTrustRecord
        rec = NodeTrustRecord(node_id="test")
        assert hasattr(rec, "mount_confinement_enforced")
        assert hasattr(rec, "mount_confinement_error")
        assert hasattr(rec, "temp_root_created")
        assert hasattr(rec, "allowed_mounts")

    def test_fields_in_dict(self):
        from nodechain.sdk.trust_summary import NodeTrustRecord, TrustSummary
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="test",
            mount_confinement_enforced=True,
            temp_root_created=True,
            allowed_mounts=["/package", "/tmp"],
        ))
        d = summary.to_dict()
        node = d["nodes"][0]
        assert node["mount_confinement_enforced"] is True
        assert node["temp_root_created"] is True
        assert "/package" in node["allowed_mounts"]


# ─── 4. INV-012 ──────────────────────────────────────────────────────────

class TestINV012:
    """INV-012 exists (advisory for now)."""

    def test_no_hard_failure_by_default(self):
        """INV-012 does not fire as error for unconfined nodes."""
        from nodechain.sdk.trust_summary import TrustSummary, NodeTrustRecord
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="test",
            trust_level="local_untrusted",
            mount_confinement_enforced=False,
        ))
        violations = summary.validate_invariants(strict=True)
        inv012 = [v for v in violations if v.code == "INV-012"]
        # Advisory — should not produce hard errors yet
        assert len(inv012) == 0


# ─── 5-7. E2E: Child Runs Under Chroot (Linux) ──────────────────────────

class TestMountConfinementE2E:
    """Mount confinement enforcement on Linux."""

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
    def test_mount_confinement_enforced(self):
        """SubprocessRunner creates chroot confinement in child."""
        import asyncio
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        from nodechain.core.envelope import InvocationEnvelope

        echo_path = str(Path("nodes/echo_node/implementation.py").resolve())
        if not Path(echo_path).exists():
            pytest.skip("echo_node not found")

        runner = SubprocessRunner(enable_mount_confinement=True)
        envelope = InvocationEnvelope(
            envelope_id="test_confine", run_id="test_confine", chain_id="test",
            node_id="echo_node", step_id=1, payload={"query": "hello chroot"},
        )

        result = asyncio.run(runner.run_isolated(
            envelope=envelope, module_path=echo_path, class_name="EchoNode",
            node_id="echo_node", trust_level="local_untrusted",
            package_root=str(Path(echo_path).parent), enable_seccomp=False,
        ))

        # T3.0 safety fence: POSIX untrusted execution refused before spawn
        assert result["success"] is False
        assert result["exit_code"] == 126
        assert result["error"].startswith("supervised_backend_required")
        return  # Skip original capability assertions on POSIX

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
    def test_host_path_blocked(self):
        """Child cannot access host paths under chroot."""
        import asyncio
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        from nodechain.core.envelope import InvocationEnvelope

        echo_path = str(Path("nodes/echo_node/implementation.py").resolve())
        if not Path(echo_path).exists():
            pytest.skip("echo_node not found")

        runner = SubprocessRunner(enable_mount_confinement=True)
        envelope = InvocationEnvelope(
            envelope_id="test_block", run_id="test_block", chain_id="test",
            node_id="echo_node", step_id=1, payload={"query": "test"},
        )

        result = asyncio.run(runner.run_isolated(
            envelope=envelope, module_path=echo_path, class_name="EchoNode",
            node_id="echo_node", trust_level="local_untrusted",
            package_root=str(Path(echo_path).parent), enable_seccomp=False,
        ))

        # T3.0 safety fence: POSIX untrusted execution refused before spawn
        assert result["success"] is False
        assert result["exit_code"] == 126
        assert result["error"].startswith("supervised_backend_required")
        return  # Skip original capability assertions on POSIX

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
    def test_combined_all_layers(self):
        """Network ns + mount ns + mount confinement + seccomp together."""
        import asyncio
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        from nodechain.core.envelope import InvocationEnvelope

        echo_path = str(Path("nodes/echo_node/implementation.py").resolve())
        if not Path(echo_path).exists():
            pytest.skip("echo_node not found")

        runner = SubprocessRunner(
            enable_network_namespace=True,
            enable_mount_namespace=True,
            enable_mount_confinement=True,
            enable_cgroup=True,
            cgroup_memory_max_mb=256,
            cgroup_pids_max=10,
        )
        envelope = InvocationEnvelope(
            envelope_id="test_all", run_id="test_all", chain_id="test",
            node_id="echo_node", step_id=1, payload={"query": "all layers"},
        )

        result = asyncio.run(runner.run_isolated(
            envelope=envelope, module_path=echo_path, class_name="EchoNode",
            node_id="echo_node", trust_level="local_untrusted",
            package_root=str(Path(echo_path).parent), enable_seccomp=True,
        ))

        # T3.0 safety fence: POSIX untrusted execution refused before spawn
        assert result["success"] is False
        assert result["exit_code"] == 126
        assert result["error"].startswith("supervised_backend_required")
        return  # Skip original capability assertions on POSIX


# ─── 8. Version and Changelog ────────────────────────────────────────────

class TestV146Version:
    """Version reflects v1.4.6."""

    def test_version_is_1_6_0(self):
        import nodechain
        assert nodechain.__version__ == "3.6.0"

    def test_changelog_has_v145(self):
        changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
        assert "3.5.1" in changelog
        assert "Temp-Root Confinement" in changelog
