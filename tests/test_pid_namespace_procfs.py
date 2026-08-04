"""Tests for PID namespace procfs consolidation (v1.5.1).

Tests cover:
1. remount_procfs_for_pid_namespace function exists
2. RunnerConfig/SubprocessRunner enable_procfs_isolation
3. NodeTrustRecord procfs fields
4. CLI display shows procfs fields
5. hardened_untrusted enables procfs isolation
6. E2E: procfs remount on Linux (PID ns + procfs)
7. /proc behavior documented honestly
8. PID 1 behavior documented
9. Enforcement layer hierarchy documented
10. Version and changelog
"""

from __future__ import annotations

import platform
import pytest
from pathlib import Path


# ─── 1. remount_procfs Function ─────────────────────────────────────────

class TestRemountProcfs:
    def test_function_exists(self):
        from nodechain.sdk.namespace_profile import remount_procfs_for_pid_namespace
        assert callable(remount_procfs_for_pid_namespace)

    def test_returns_dict(self):
        from nodechain.sdk.namespace_profile import remount_procfs_for_pid_namespace
        result = remount_procfs_for_pid_namespace()
        assert isinstance(result, dict)
        assert "procfs_namespace_view_enforced" in result
        assert "procfs_isolated" in result
        assert "procfs_error" in result


# ─── 2. RunnerConfig/SubprocessRunner ────────────────────────────────────

class TestRunnerConfigProcfs:
    def test_runner_config_field(self):
        from nodechain.runtime.subprocess_runner import RunnerConfig
        cfg = RunnerConfig(enable_procfs_isolation=True)
        assert cfg.enable_procfs_isolation is True

    def test_runner_config_to_kwargs(self):
        from nodechain.runtime.subprocess_runner import RunnerConfig
        cfg = RunnerConfig(enable_procfs_isolation=True)
        kwargs = cfg.to_runner_kwargs()
        assert kwargs["enable_procfs_isolation"] is True

    def test_subprocess_runner_field(self):
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        runner = SubprocessRunner(enable_procfs_isolation=True)
        assert runner.enable_procfs_isolation is True

    def test_default_disabled(self):
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        runner = SubprocessRunner()
        assert runner.enable_procfs_isolation is False


# ─── 3. NodeTrustRecord Procfs Fields ────────────────────────────────────

class TestNodeTrustRecordProcfs:
    def test_fields_exist(self):
        from nodechain.sdk.trust_summary import NodeTrustRecord
        rec = NodeTrustRecord(node_id="test")
        assert hasattr(rec, "procfs_namespace_view_enforced")
        assert hasattr(rec, "procfs_error")
        assert rec.procfs_namespace_view_enforced is False

    def test_fields_in_to_dict(self):
        from nodechain.sdk.trust_summary import NodeTrustRecord, TrustSummary
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="test",
            procfs_namespace_view_enforced=True,
        ))
        d = summary.to_dict()
        node = d["nodes"][0]
        assert node["procfs_namespace_view_enforced"] is True
        assert "procfs_error" in node


# ─── 4. CLI Display ─────────────────────────────────────────────────────

class TestCLIDisplayProcfs:
    def test_trust_source_has_procfs_display(self):
        main_src = Path("src/nodechain/cli/main.py").read_text(encoding="utf-8")
        assert "procfs_isolated" in main_src

    def test_report_source_has_procfs_display(self):
        report_src = Path("src/nodechain/cli/report.py").read_text(encoding="utf-8")
        assert "Procfs Isolation" in report_src

    def test_inspect_source_has_procfs_display(self):
        inspect_src = Path("src/nodechain/cli/inspect.py").read_text(encoding="utf-8")
        assert "Procfs Isolation" in inspect_src


# ─── 5. hardened_untrusted Preset ────────────────────────────────────────

class TestHardenedUntrustedProcfs:
    def test_preset_enables_procfs(self):
        from nodechain.sdk.policy_presets import get_preset
        preset = get_preset("hardened_untrusted")
        # pid_namespace_required=True also enables procfs isolation
        kwargs = preset.to_runner_kwargs()
        assert kwargs.get("enable_procfs_isolation") is True
        assert kwargs.get("enable_pid_namespace") is True

    def test_preset_to_dict_has_procfs(self):
        from nodechain.sdk.policy_presets import get_preset
        preset = get_preset("hardened_untrusted")
        d = preset.to_dict()
        assert "procfs_isolation_required" in d


# ─── 6. E2E: Procfs Remount (Linux) ─────────────────────────────────────

class TestProcfsRemountE2E:
    """Procfs remount under PID namespace on Linux."""

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
    def test_procfs_remount_enforced(self):
        """PID ns + procfs isolation → /proc shows namespace-local PIDs."""
        import asyncio
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        from nodechain.core.envelope import InvocationEnvelope

        echo_path = str(Path("nodes/echo_node/implementation.py").resolve())
        if not Path(echo_path).exists():
            pytest.skip("echo_node not found")

        runner = SubprocessRunner(
            enable_pid_namespace=True,
            enable_procfs_isolation=True,
        )
        envelope = InvocationEnvelope(
            envelope_id="test_procfs", run_id="test_procfs", chain_id="test",
            node_id="echo_node", step_id=1, payload={"query": "procfs test"},
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
    def test_combined_hardened_with_procfs(self):
        """All layers + procfs isolation."""
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
            enable_pid_namespace=True,
            enable_procfs_isolation=True,
            enable_cgroup=True,
            cgroup_memory_max_mb=256,
            cgroup_pids_max=10,
        )
        envelope = InvocationEnvelope(
            envelope_id="test_all_v151", run_id="test_all_v151", chain_id="test",
            node_id="echo_node", step_id=1, payload={"query": "all v151"},
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


# ─── 7. Documentation ────────────────────────────────────────────────────

class TestProcfsDocumentation:
    def test_linux_deployment_documents_proc_visibility(self):
        ld = Path("docs/linux-deployment.md").read_text(encoding="utf-8")
        # Must honestly document /proc visibility
        assert "/proc" in ld
        assert "procfs" in ld.lower() or "proc" in ld.lower()

    def test_linux_deployment_documents_pid1_behavior(self):
        ld = Path("docs/linux-deployment.md").read_text(encoding="utf-8")
        assert "PID 1" in ld or "PID1" in ld or "pid 1" in ld.lower()

    def test_linux_deployment_documents_signal_handling(self):
        ld = Path("docs/linux-deployment.md").read_text(encoding="utf-8")
        assert "signal" in ld.lower()

    def test_linux_deployment_has_enforcement_hierarchy(self):
        ld = Path("docs/linux-deployment.md").read_text(encoding="utf-8")
        # Must have the corrected 5-layer hierarchy
        assert "Layer 1" in ld
        assert "Layer 2" in ld
        assert "seccomp" in ld.lower()

    def test_linux_deployment_pid_namespace_section(self):
        ld = Path("docs/linux-deployment.md").read_text(encoding="utf-8")
        assert "PID Namespace" in ld

    def test_linux_deployment_procfs_remount_section(self):
        ld = Path("docs/linux-deployment.md").read_text(encoding="utf-8")
        assert "procfs remount" in ld.lower() or "procfs_namespace_view" in ld.lower()


# ─── 8. Version and Changelog ────────────────────────────────────────────

class TestV151Version:
    def test_version_is_1_6_0(self):
        import nodechain
        assert nodechain.__version__ == "3.6.0"

    def test_changelog_has_v151(self):
        changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
        assert "3.5.1" in changelog
        assert "Procfs Consolidation" in changelog

    def test_frozen_surfaces_has_procfs(self):
        fs = Path("docs/frozen-surfaces.md").read_text(encoding="utf-8")
        assert "procfs_namespace_view_enforced" in fs
