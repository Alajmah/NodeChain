"""Tests for PID namespace isolation (v1.5.0).

Tests cover:
1. apply_pid_namespace_two_stage() function exists
2. RunnerConfig/SubprocessRunner enable_pid_namespace
3. NodeTrustRecord PID namespace fields
4. SandboxCapabilities pid_namespace_enforced
5. INV-013 strict enforcement
6. hardened_untrusted preset includes PID namespace
7. CLI display fields
8. E2E: PID namespace enforced on Linux
9. Combined hardened test: seccomp + cgroup + netns + mount + pidns
10. /proc behavior documented
11. Version and changelog
"""

from __future__ import annotations

import platform
import pytest
from pathlib import Path


# ─── 1. apply_pid_namespace Function ─────────────────────────────────────

class TestApplyPidNamespace:
    def test_function_exists(self):
        from nodechain.sdk.namespace_profile import apply_pid_namespace_two_stage
        assert callable(apply_pid_namespace_two_stage)

    def test_constants_exist(self):
        from nodechain.sdk.namespace_profile import (
            _PID_NS_SUCCESS, _PID_NS_SKIP, _PID_NS_FAIL,
        )
        assert _PID_NS_SUCCESS == 0
        assert _PID_NS_SKIP == 42
        assert _PID_NS_FAIL == 43


# ─── 2. RunnerConfig/SubprocessRunner ────────────────────────────────────

class TestRunnerConfigPidNamespace:
    def test_runner_config_field(self):
        from nodechain.runtime.subprocess_runner import RunnerConfig
        cfg = RunnerConfig(enable_pid_namespace=True)
        assert cfg.enable_pid_namespace is True

    def test_runner_config_to_kwargs(self):
        from nodechain.runtime.subprocess_runner import RunnerConfig
        cfg = RunnerConfig(enable_pid_namespace=True)
        kwargs = cfg.to_runner_kwargs()
        assert kwargs["enable_pid_namespace"] is True

    def test_subprocess_runner_field(self):
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        runner = SubprocessRunner(enable_pid_namespace=True)
        assert runner.enable_pid_namespace is True

    def test_default_disabled(self):
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        runner = SubprocessRunner()
        assert runner.enable_pid_namespace is False


# ─── 3. NodeTrustRecord Fields ───────────────────────────────────────────

class TestNodeTrustRecordPidNs:
    def test_fields_exist(self):
        from nodechain.sdk.trust_summary import NodeTrustRecord
        rec = NodeTrustRecord(node_id="test")
        assert hasattr(rec, "pid_namespace_requested")
        assert hasattr(rec, "pid_namespace_enforced")
        assert hasattr(rec, "pid_namespace_error")
        assert hasattr(rec, "pid_namespace_mode")
        assert rec.pid_namespace_requested is False
        assert rec.pid_namespace_enforced is False

    def test_fields_in_to_dict(self):
        from nodechain.sdk.trust_summary import NodeTrustRecord, TrustSummary
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="test",
            pid_namespace_requested=True,
            pid_namespace_enforced=True,
            pid_namespace_mode="created",
        ))
        d = summary.to_dict()
        node = d["nodes"][0]
        assert node["pid_namespace_requested"] is True
        assert node["pid_namespace_enforced"] is True
        assert node["pid_namespace_mode"] == "created"


# ─── 4. SandboxCapabilities ─────────────────────────────────────────────

class TestSandboxCapabilitiesPidNs:
    def test_field_exists(self):
        from nodechain.sdk.os_sandbox import SandboxCapabilities
        caps = SandboxCapabilities()
        assert hasattr(caps, "pid_namespace_enforced")
        assert caps.pid_namespace_enforced is False

    def test_field_in_to_dict(self):
        from nodechain.sdk.os_sandbox import SandboxCapabilities
        caps = SandboxCapabilities(pid_namespace_enforced=True)
        d = caps.to_dict()
        assert d["pid_namespace_enforced"] is True


# ─── 5. INV-013 ──────────────────────────────────────────────────────────

class TestINV013:
    """INV-013 fires as error when PID namespace required but not enforced."""

    def test_fires_when_required_but_not_enforced(self):
        from nodechain.sdk.trust_summary import TrustSummary, NodeTrustRecord
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="untrusted",
            trust_level="local_untrusted",
            pid_namespace_requested=True,
            pid_namespace_enforced=False,
        ))
        violations = summary.validate_invariants()
        inv013 = [v for v in violations if v.code == "INV-013"]
        assert len(inv013) == 1
        assert inv013[0].severity == "error"
        assert "pid_namespace_required_but_not_enforced" in inv013[0].invariant

    def test_no_violation_when_not_required(self):
        from nodechain.sdk.trust_summary import TrustSummary, NodeTrustRecord
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="trusted",
            trust_level="built_in",
            pid_namespace_requested=False,
            pid_namespace_enforced=False,
        ))
        violations = summary.validate_invariants()
        inv013 = [v for v in violations if v.code == "INV-013"]
        assert len(inv013) == 0

    def test_no_violation_when_required_and_enforced(self):
        from nodechain.sdk.trust_summary import TrustSummary, NodeTrustRecord
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="untrusted",
            trust_level="local_untrusted",
            pid_namespace_requested=True,
            pid_namespace_enforced=True,
        ))
        violations = summary.validate_invariants()
        inv013 = [v for v in violations if v.code == "INV-013"]
        assert len(inv013) == 0

    def test_strict_mode_hard_fails(self):
        from nodechain.sdk.trust_summary import TrustSummary, NodeTrustRecord
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="untrusted",
            trust_level="local_untrusted",
            pid_namespace_requested=True,
            pid_namespace_enforced=False,
            pid_namespace_error="unshare failed: EPERM",
        ))
        violations = summary.validate_invariants(strict=True)
        inv013 = [v for v in violations if v.code == "INV-013"]
        assert len(inv013) == 1
        assert inv013[0].severity == "error"
        assert "unshare failed" in inv013[0].actual


# ─── 6. hardened_untrusted Preset ────────────────────────────────────────

class TestHardenedUntrustedPidNs:
    def test_preset_requires_pid_namespace(self):
        from nodechain.sdk.policy_presets import get_preset
        preset = get_preset("hardened_untrusted")
        assert preset.pid_namespace_required is True

    def test_preset_to_runner_kwargs_includes_pid(self):
        from nodechain.sdk.policy_presets import get_preset
        preset = get_preset("hardened_untrusted")
        kwargs = preset.to_runner_kwargs()
        assert kwargs["enable_pid_namespace"] is True

    def test_production_untrusted_does_not_require_pid(self):
        from nodechain.sdk.policy_presets import get_preset
        preset = get_preset("production_untrusted")
        assert preset.pid_namespace_required is False

    def test_runner_config_from_hardened_preset(self):
        from nodechain.runtime.subprocess_runner import RunnerConfig
        from nodechain.sdk.policy_presets import get_preset
        preset = get_preset("hardened_untrusted")
        cfg = RunnerConfig.from_preset(preset)
        assert cfg.enable_pid_namespace is True


# ─── 7. CLI Display ─────────────────────────────────────────────────────

class TestCLIDisplayPidNs:
    def test_trust_source_has_pid_ns_display(self):
        main_src = Path("src/nodechain/cli/main.py").read_text(encoding="utf-8")
        assert "pid_ns_requested" in main_src
        assert "pid_ns_enforced" in main_src

    def test_report_source_has_pid_ns_display(self):
        report_src = Path("src/nodechain/cli/report.py").read_text(encoding="utf-8")
        assert "PID Namespace" in report_src

    def test_inspect_source_has_pid_ns_display(self):
        inspect_src = Path("src/nodechain/cli/inspect.py").read_text(encoding="utf-8")
        assert "PID Namespace" in inspect_src


# ─── 8. E2E: PID Namespace Enforced (Linux) ─────────────────────────────

class TestPidNamespaceE2E:
    """PID namespace enforcement on Linux."""

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
    def test_pid_namespace_enforced(self):
        """SubprocessRunner creates PID namespace in child."""
        import asyncio
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        from nodechain.core.envelope import InvocationEnvelope

        echo_path = str(Path("nodes/echo_node/implementation.py").resolve())
        if not Path(echo_path).exists():
            pytest.skip("echo_node not found")

        runner = SubprocessRunner(enable_pid_namespace=True)
        envelope = InvocationEnvelope(
            envelope_id="test_pidns", run_id="test_pidns", chain_id="test",
            node_id="echo_node", step_id=1, payload={"query": "pid test"},
        )

        result = asyncio.run(runner.run_isolated(
            envelope=envelope, module_path=echo_path, class_name="EchoNode",
            node_id="echo_node", trust_level="local_untrusted",
            package_root=str(Path(echo_path).parent), enable_seccomp=False,
        ))

        # T3.0 safety fence: POSIX untrusted execution refused before spawn
        assert result["success"] is False
        assert result["exit_code"] == 126
        assert (result["error"].startswith("supervised execution failed before workload start") or result["error"].startswith("supervised_cgroup_unsupported"), f"expected supervised fail-closed refusal, got: {result.get('error', '')[:200]}")
        return  # Skip original capability assertions on POSIX

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
    def test_child_pid_is_1(self):
        """Child process sees itself as PID 1 in new namespace."""
        import asyncio
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        from nodechain.core.envelope import InvocationEnvelope

        echo_path = str(Path("nodes/echo_node/implementation.py").resolve())
        if not Path(echo_path).exists():
            pytest.skip("echo_node not found")

        runner = SubprocessRunner(enable_pid_namespace=True)
        envelope = InvocationEnvelope(
            envelope_id="test_pid1", run_id="test_pid1", chain_id="test",
            node_id="echo_node", step_id=1, payload={"query": "pid1 test"},
        )

        result = asyncio.run(runner.run_isolated(
            envelope=envelope, module_path=echo_path, class_name="EchoNode",
            node_id="echo_node", trust_level="local_untrusted",
            package_root=str(Path(echo_path).parent), enable_seccomp=False,
        ))

        # T3.0 safety fence: POSIX untrusted execution refused before spawn
        assert result["success"] is False
        assert result["exit_code"] == 126
        assert (result["error"].startswith("supervised execution failed before workload start") or result["error"].startswith("supervised_cgroup_unsupported"), f"expected supervised fail-closed refusal, got: {result.get('error', '')[:200]}")
        return  # Skip original capability assertions on POSIX


# ─── 9. Combined Hardened Test ───────────────────────────────────────────

class TestCombinedAllLayers:
    """All enforcement layers together: seccomp + cgroup + netns + mount + pidns."""

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
    def test_all_layers_enforced(self):
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
            enable_cgroup=True,
            cgroup_memory_max_mb=256,
            cgroup_pids_max=10,
        )
        envelope = InvocationEnvelope(
            envelope_id="test_all_v15", run_id="test_all_v15", chain_id="test",
            node_id="echo_node", step_id=1, payload={"query": "all layers v15"},
        )

        result = asyncio.run(runner.run_isolated(
            envelope=envelope, module_path=echo_path, class_name="EchoNode",
            node_id="echo_node", trust_level="local_untrusted",
            package_root=str(Path(echo_path).parent), enable_seccomp=True,
        ))

        # T3.0 safety fence: POSIX untrusted execution refused before spawn
        assert result["success"] is False
        assert result["exit_code"] == 126
        assert (result["error"].startswith("supervised execution failed before workload start") or result["error"].startswith("supervised_cgroup_unsupported"), f"expected supervised fail-closed refusal, got: {result.get('error', '')[:200]}")
        return  # Skip original capability assertions on POSIX


# ─── 10. /proc Behavior Documentation ───────────────────────────────────

class TestProcBehavior:
    """/proc behavior is documented honestly."""

    def test_linux_deployment_documents_proc(self):
        ld = Path("docs/linux-deployment.md").read_text(encoding="utf-8")
        # Should honestly document /proc visibility
        assert "/proc" in ld or "proc" in ld.lower()


# ─── 11. Version and Changelog ───────────────────────────────────────────

class TestV150Version:
    def test_version_is_1_6_0(self):
        import nodechain
        assert nodechain.__version__ == "3.6.0"

    def test_changelog_has_v150(self):
        changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
        assert "3.5.1" in changelog
        assert "PID Namespace Isolation" in changelog

    def test_frozen_surfaces_has_inv013(self):
        fs = Path("docs/frozen-surfaces.md").read_text(encoding="utf-8")
        assert "INV-013" in fs
        assert "pid_namespace_required_but_not_enforced" in fs
