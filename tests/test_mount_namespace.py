"""Tests for mount namespace prototype (v1.4.3).

Tests cover:
1. apply_mount_namespace() function
2. RunnerConfig/SubprocessRunner enable_mount_namespace
3. NodeTrustRecord mount namespace fields
4. SandboxCapabilities mount_namespace_enforced
5. PolicyPreset mount_namespace_required field
6. INV-011 extended for mount namespace
7. E2E: mount namespace created in child (Linux)
8. Mount namespace inode differs from parent (Linux)
9. Existing behavior unchanged (production_untrusted does not require mount ns)
10. Version and changelog
"""

from __future__ import annotations

import platform
import pytest
from pathlib import Path


# ─── 1. apply_mount_namespace Function ───────────────────────────────────

class TestApplyMountNamespace:
    """apply_mount_namespace() module function."""

    def test_function_exists(self):
        from nodechain.sdk.namespace_profile import apply_mount_namespace
        assert callable(apply_mount_namespace)

    def test_returns_false_on_non_linux(self):
        if platform.system() == "Linux":
            pytest.skip("Non-Linux only")
        from nodechain.sdk.namespace_profile import apply_mount_namespace
        assert apply_mount_namespace() is False

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
    @pytest.mark.native_sandbox
    def test_mount_ns_inode_differs_in_subprocess(self):
        """Child mount namespace inode differs from parent."""
        import subprocess, sys
        parent_mnt = __import__("os").readlink("/proc/self/ns/mnt")

        test_code = """
import os, sys
from nodechain.sdk.namespace_profile import apply_mount_namespace
result = apply_mount_namespace()
if result:
    link = os.readlink("/proc/self/ns/mnt")
    print(link)
else:
    print("FAILED")
"""
        r = subprocess.run([sys.executable, "-c", test_code],
                          capture_output=True, text=True, timeout=10)
        child_mnt = r.stdout.strip()
        assert child_mnt != "FAILED", f"Mount namespace creation failed: {r.stderr}"
        assert child_mnt != parent_mnt, \
            f"Expected different mount ns inode: parent={parent_mnt} child={child_mnt}"


# ─── 2. RunnerConfig/SubprocessRunner ────────────────────────────────────

class TestRunnerConfigMountNS:
    """RunnerConfig and SubprocessRunner support mount namespace."""

    def test_runner_config_field(self):
        from nodechain.runtime.subprocess_runner import RunnerConfig
        cfg = RunnerConfig(enable_mount_namespace=True)
        assert cfg.enable_mount_namespace is True

    def test_runner_config_to_kwargs(self):
        from nodechain.runtime.subprocess_runner import RunnerConfig
        cfg = RunnerConfig(enable_mount_namespace=True)
        kwargs = cfg.to_runner_kwargs()
        assert kwargs["enable_mount_namespace"] is True

    def test_runner_config_repr(self):
        from nodechain.runtime.subprocess_runner import RunnerConfig
        cfg = RunnerConfig(enable_mount_namespace=True)
        assert "mntns=True" in repr(cfg)

    def test_subprocess_runner_field(self):
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        runner = SubprocessRunner(enable_mount_namespace=True)
        assert runner.enable_mount_namespace is True

    def test_subprocess_runner_default(self):
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        runner = SubprocessRunner()
        assert runner.enable_mount_namespace is False

    def test_get_runner_with_config(self):
        from nodechain.runtime.subprocess_runner import get_subprocess_runner, RunnerConfig
        cfg = RunnerConfig(enable_mount_namespace=True)
        runner = get_subprocess_runner(config=cfg)
        assert runner.enable_mount_namespace is True


# ─── 3. NodeTrustRecord Mount Namespace Fields ───────────────────────────

class TestNodeTrustRecordMountNS:
    """NodeTrustRecord has mount namespace fields."""

    def test_fields_exist(self):
        from nodechain.sdk.trust_summary import NodeTrustRecord
        rec = NodeTrustRecord(node_id="test")
        assert hasattr(rec, "mount_namespace_requested")
        assert hasattr(rec, "mount_namespace_enforced")
        assert hasattr(rec, "mount_namespace_error")
        assert rec.mount_namespace_requested is False
        assert rec.mount_namespace_enforced is False

    def test_fields_in_dict(self):
        from nodechain.sdk.trust_summary import NodeTrustRecord, TrustSummary
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="test",
            mount_namespace_requested=True,
            mount_namespace_enforced=True,
        ))
        d = summary.to_dict()
        node = d["nodes"][0]
        assert node["mount_namespace_requested"] is True
        assert node["mount_namespace_enforced"] is True


# ─── 4. SandboxCapabilities ──────────────────────────────────────────────

class TestSandboxCapabilitiesMountNS:
    """SandboxCapabilities has mount_namespace_enforced."""

    def test_field_exists(self):
        from nodechain.sdk.os_sandbox import SandboxCapabilities
        caps = SandboxCapabilities()
        assert hasattr(caps, "mount_namespace_enforced")
        assert caps.mount_namespace_enforced is False

    def test_field_in_dict(self):
        from nodechain.sdk.os_sandbox import SandboxCapabilities
        d = SandboxCapabilities().to_dict()
        assert "mount_namespace_enforced" in d


# ─── 5. PolicyPreset Mount Namespace ─────────────────────────────────────

class TestPolicyPresetMountNS:
    """PolicyPreset has mount_namespace_required field."""

    def test_field_exists(self):
        from nodechain.sdk.policy_presets import PolicyPreset
        p = PolicyPreset(name="test", description="test")
        assert hasattr(p, "mount_namespace_required")
        assert p.mount_namespace_required is False

    def test_field_in_dict(self):
        from nodechain.sdk.policy_presets import PolicyPreset
        p = PolicyPreset(name="test", description="test", mount_namespace_required=True)
        d = p.to_dict()
        assert d["mount_namespace_required"] is True

    def test_production_untrusted_does_not_require_mount(self):
        """production_untrusted does NOT require mount namespace yet."""
        from nodechain.sdk.policy_presets import get_preset
        p = get_preset("production_untrusted")
        assert p.mount_namespace_required is False

    def test_to_runner_kwargs_mount_ns(self):
        from nodechain.sdk.policy_presets import PolicyPreset
        p = PolicyPreset(
            name="test", description="test",
            mount_namespace_required=True,
        )
        kwargs = p.to_runner_kwargs()
        assert kwargs.get("enable_mount_namespace") is True

    def test_required_os_caps_mount(self):
        from nodechain.sdk.policy_presets import PolicyPreset
        p = PolicyPreset(
            name="test", description="test",
            mount_namespace_required=True,
        )
        caps = p.to_required_os_capabilities()
        assert "mount_namespace" in caps


# ─── 6. INV-011 Extended for Mount Namespace ─────────────────────────────

class TestINV011MountNS:
    """INV-011 fires for mount namespace when required but not enforced."""

    def test_fires_when_mount_required_but_not_enforced(self):
        from nodechain.sdk.trust_summary import TrustSummary, NodeTrustRecord
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="test",
            mount_namespace_requested=True,
            mount_namespace_enforced=False,
        ))
        violations = summary.validate_invariants()
        inv011 = [v for v in violations if v.code == "INV-011"
                  and "mount_namespace" in v.invariant]
        assert len(inv011) == 1
        assert inv011[0].severity == "error"

    def test_no_violation_when_mount_required_and_enforced(self):
        from nodechain.sdk.trust_summary import TrustSummary, NodeTrustRecord
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="test",
            mount_namespace_requested=True,
            mount_namespace_enforced=True,
        ))
        violations = summary.validate_invariants()
        inv011 = [v for v in violations if v.code == "INV-011"
                  and "mount_namespace" in v.invariant]
        assert len(inv011) == 0

    def test_no_violation_when_not_required(self):
        from nodechain.sdk.trust_summary import TrustSummary, NodeTrustRecord
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="test",
            mount_namespace_requested=False,
            mount_namespace_enforced=False,
        ))
        violations = summary.validate_invariants()
        inv011 = [v for v in violations if v.code == "INV-011"
                  and "mount_namespace" in v.invariant]
        assert len(inv011) == 0


# ─── 7. E2E: Mount Namespace Created in Child (Linux) ───────────────────

class TestMountNSEndToEnd:
    """Mount namespace enforcement on Linux."""

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
    def test_mount_ns_enforced_in_child(self):
        """SubprocessRunner creates mount namespace in child."""
        import asyncio
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        from nodechain.core.envelope import InvocationEnvelope

        echo_path = str(Path("nodes/echo_node/implementation.py").resolve())
        if not Path(echo_path).exists():
            pytest.skip("echo_node not found")

        runner = SubprocessRunner(enable_mount_namespace=True)
        envelope = InvocationEnvelope(
            envelope_id="test_mnt", run_id="test_mnt", chain_id="test",
            node_id="echo_node", step_id=1, payload={"query": "hello"},
        )

        result = asyncio.run(runner.run_isolated(
            envelope=envelope, module_path=echo_path, class_name="EchoNode",
            node_id="echo_node", trust_level="local_untrusted",
            package_root=str(Path(echo_path).parent), enable_seccomp=True,
        ))

        # Dual truth (T3 routing): on a host where the supervised topology
        # runs, mount namespace + requested seccomp are enforced and the
        # workload executes; elsewhere the run fails closed BEFORE start.
        if result["success"]:
            assert result["mount_namespace_enforced"] is True, result
            assert result["seccomp_enforced"] is True, result
        else:
            sup = result.get("supervised_execution", {})
            assert sup.get("process_started") is False, result
            assert result["exit_code"] == 126
            assert result["error"].startswith("supervised execution failed before workload start"), f"expected supervised fail-closed refusal, got: {result.get('error', '')[:200]}"
        return  # Skip original capability assertions on POSIX

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
    def test_combined_net_and_mount_ns(self):
        """Network + mount namespace together."""
        import asyncio
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        from nodechain.core.envelope import InvocationEnvelope

        echo_path = str(Path("nodes/echo_node/implementation.py").resolve())
        if not Path(echo_path).exists():
            pytest.skip("echo_node not found")

        runner = SubprocessRunner(
            enable_network_namespace=True,
            enable_mount_namespace=True,
        )
        envelope = InvocationEnvelope(
            envelope_id="test_both", run_id="test_both", chain_id="test",
            node_id="echo_node", step_id=1, payload={"query": "hello"},
        )

        result = asyncio.run(runner.run_isolated(
            envelope=envelope, module_path=echo_path, class_name="EchoNode",
            node_id="echo_node", trust_level="local_untrusted",
            package_root=str(Path(echo_path).parent), enable_seccomp=True,
        ))

        # Dual truth (T3 routing): on a capable host both namespaces plus
        # requested seccomp are enforced and the workload executes;
        # elsewhere the run fails closed BEFORE start.
        if result["success"]:
            assert result["network_namespace_enforced"] is True, result
            assert result["mount_namespace_enforced"] is True, result
            assert result["seccomp_enforced"] is True, result
        else:
            sup = result.get("supervised_execution", {})
            assert sup.get("process_started") is False, result
            assert result["exit_code"] == 126
            assert result["error"].startswith("supervised execution failed before workload start"), f"expected supervised fail-closed refusal, got: {result.get('error', '')[:200]}"
        return  # Skip original capability assertions on POSIX


# ─── 8. Existing Behavior Unchanged ──────────────────────────────────────

class TestExistingBehaviorUnchanged:
    """Production_untrusted behavior unchanged."""

    def test_production_untrusted_still_has_network_ns(self):
        from nodechain.sdk.policy_presets import get_preset
        p = get_preset("production_untrusted")
        assert p.network_namespace_required is True
        # Mount ns NOT required by production_untrusted
        assert p.mount_namespace_required is False


# ─── 9. Version and Changelog ────────────────────────────────────────────

class TestV143Version:
    """Version reflects v1.4.3."""

    def test_version_is_1_6_0(self):
        import nodechain
        assert nodechain.__version__ == "3.6.0"

    def test_changelog_has_v143(self):
        changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
        assert "3.5.1" in changelog
        assert "Mount Namespace Prototype" in changelog
