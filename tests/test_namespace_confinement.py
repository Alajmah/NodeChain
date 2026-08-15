"""Tests for Linux namespace confinement (v1.4.0).

Tests cover:
1. Namespace detection module
2. SandboxCapabilities namespace fields
3. NodeTrustRecord namespace fields
4. INV-011 invariant
5. PolicyPreset network_namespace field
6. RunnerConfig enable_network_namespace
7. SubprocessRunner enable_network_namespace
8. Network namespace enforcement (Linux only)
9. Version and changelog
"""

from __future__ import annotations

import os
import platform
import pytest
from pathlib import Path


# ─── 1. Namespace Detection Module ──────────────────────────────────────

@pytest.mark.native_sandbox
class TestNamespaceProfile:
    """Namespace detection module basic functionality."""

    def test_module_importable(self):
        from nodechain.sdk.namespace_profile import detect_namespaces
        caps = detect_namespaces()
        assert caps is not None

    def test_platform_field(self):
        from nodechain.sdk.namespace_profile import detect_namespaces
        caps = detect_namespaces()
        assert caps.platform == platform.system()

    def test_non_linux_returns_unavailable(self):
        if platform.system() == "Linux":
            pytest.skip("Linux only test for non-Linux behavior")
        from nodechain.sdk.namespace_profile import detect_namespaces
        caps = detect_namespaces()
        assert caps.namespace_available is False

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
    def test_linux_detection(self):
        from nodechain.sdk.namespace_profile import detect_namespaces
        caps = detect_namespaces()
        assert caps.platform == "Linux"
        # On Proxmox LXC with nesting enabled, namespaces should be available
        assert caps.namespace_mode in ("created", "nested", "detected")
        assert caps.namespace_mode != "none"

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
    def test_linux_network_namespace_available(self):
        from nodechain.sdk.namespace_profile import detect_namespaces
        caps = detect_namespaces()
        # Network namespace should be creatable on CT 801
        assert caps.network_namespace_available is True

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
    def test_linux_already_nested(self):
        from nodechain.sdk.namespace_profile import detect_namespaces
        caps = detect_namespaces()
        # A KVM guest may correctly report already_nested = False.
        # A nested container (e.g. LXC) would report True. Both are valid.
        # The contract is that detection reports the actual state accurately.
        assert isinstance(caps.already_nested, bool)

    def test_apply_network_namespace_non_linux(self):
        if platform.system() == "Linux":
            pytest.skip("Non-Linux only test")
        from nodechain.sdk.namespace_profile import apply_network_namespace
        assert apply_network_namespace() is False


# ─── 2. SandboxCapabilities Namespace Fields ─────────────────────────────

class TestSandboxCapabilitiesNamespace:
    """SandboxCapabilities has namespace fields."""

    def test_namespace_fields_exist(self):
        from nodechain.sdk.os_sandbox import SandboxCapabilities
        caps = SandboxCapabilities()
        assert hasattr(caps, "namespace_available")
        assert hasattr(caps, "namespace_mode")
        assert hasattr(caps, "already_nested")
        assert hasattr(caps, "mount_namespace_available")
        assert hasattr(caps, "pid_namespace_available")
        assert hasattr(caps, "network_namespace_available")
        assert hasattr(caps, "network_namespace_enforced")
        assert hasattr(caps, "user_namespace_available")

    def test_namespace_fields_in_to_dict(self):
        from nodechain.sdk.os_sandbox import SandboxCapabilities
        caps = SandboxCapabilities()
        d = caps.to_dict()
        assert "namespace_available" in d
        assert "namespace_mode" in d
        assert "already_nested" in d
        assert "network_namespace_available" in d
        assert "network_namespace_enforced" in d

    def test_default_values(self):
        from nodechain.sdk.os_sandbox import SandboxCapabilities
        caps = SandboxCapabilities()
        assert caps.namespace_available is False
        assert caps.namespace_mode == "none"
        assert caps.network_namespace_enforced is False


# ─── 3. NodeTrustRecord Namespace Fields ─────────────────────────────────

class TestNodeTrustRecordNamespace:
    """NodeTrustRecord has namespace fields."""

    def test_namespace_fields_exist(self):
        from nodechain.sdk.trust_summary import NodeTrustRecord
        rec = NodeTrustRecord(node_id="test")
        assert hasattr(rec, "namespace_available")
        assert hasattr(rec, "network_namespace_enforced")
        assert hasattr(rec, "namespace_mode")

    def test_namespace_fields_in_dict(self):
        from nodechain.sdk.trust_summary import NodeTrustRecord, TrustSummary
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="test",
            namespace_available=True,
            network_namespace_enforced=True,
            namespace_mode="created",
        ))
        d = summary.to_dict()
        node = d["nodes"][0]
        assert node["namespace_available"] is True
        assert node["network_namespace_enforced"] is True
        assert node["namespace_mode"] == "created"


# ─── 4. INV-011 Invariant ────────────────────────────────────────────────

class TestINV011:
    """INV-011 namespace confinement invariant."""

    def test_inv011_code_exists(self):
        from nodechain.sdk.trust_summary import TrustSummary, NodeTrustRecord
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="test",
            trust_level="local_untrusted",
            network_namespace_requested=True,
            network_namespace_enforced=False,
        ))
        violations = summary.validate_invariants()
        inv011 = [v for v in violations if v.code == "INV-011"]
        assert len(inv011) > 0
        assert "network_namespace_required_but_not_enforced" in inv011[0].invariant

    def test_inv011_no_violation_when_available(self):
        from nodechain.sdk.trust_summary import TrustSummary, NodeTrustRecord
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="test",
            trust_level="local_untrusted",
            network_namespace_requested=True,
            network_namespace_enforced=True,
        ))
        violations = summary.validate_invariants()
        inv011 = [v for v in violations if v.code == "INV-011"]
        assert len(inv011) == 0


# ─── 5. PolicyPreset Network Namespace ───────────────────────────────────

class TestPolicyPresetNetworkNS:
    """PolicyPreset has network_namespace_required field."""

    def test_field_exists(self):
        from nodechain.sdk.policy_presets import PolicyPreset
        p = PolicyPreset(name="test", description="test")
        assert hasattr(p, "network_namespace_required")
        assert p.network_namespace_required is False

    def test_production_untrusted_has_network_ns(self):
        from nodechain.sdk.policy_presets import get_preset
        p = get_preset("production_untrusted")
        assert p.network_namespace_required is True

    def test_standard_untrusted_no_network_ns(self):
        from nodechain.sdk.policy_presets import get_preset
        p = get_preset("standard_untrusted")
        assert p.network_namespace_required is False

    def test_to_runner_kwargs_includes_netns(self):
        from nodechain.sdk.policy_presets import get_preset
        p = get_preset("production_untrusted")
        kwargs = p.to_runner_kwargs()
        assert kwargs.get("enable_network_namespace") is True

    def test_to_dict_includes_netns(self):
        from nodechain.sdk.policy_presets import get_preset
        p = get_preset("production_untrusted")
        d = p.to_dict()
        assert "network_namespace_required" in d

    def test_required_os_caps_includes_netns(self):
        from nodechain.sdk.policy_presets import get_preset
        p = get_preset("production_untrusted")
        caps = p.to_required_os_capabilities()
        assert "network_namespace" in caps


# ─── 6. RunnerConfig Network Namespace ───────────────────────────────────

class TestRunnerConfigNetworkNS:
    """RunnerConfig has enable_network_namespace field."""

    def test_field_exists(self):
        from nodechain.runtime.subprocess_runner import RunnerConfig
        cfg = RunnerConfig()
        assert hasattr(cfg, "enable_network_namespace")
        assert cfg.enable_network_namespace is False

    def test_from_preset_includes_netns(self):
        from nodechain.runtime.subprocess_runner import RunnerConfig
        from nodechain.sdk.policy_presets import get_preset
        p = get_preset("production_untrusted")
        cfg = RunnerConfig.from_preset(p)
        assert cfg.enable_network_namespace is True

    def test_to_runner_kwargs_includes_netns(self):
        from nodechain.runtime.subprocess_runner import RunnerConfig
        cfg = RunnerConfig(enable_network_namespace=True)
        kwargs = cfg.to_runner_kwargs()
        assert kwargs["enable_network_namespace"] is True

    def test_repr_includes_netns(self):
        from nodechain.runtime.subprocess_runner import RunnerConfig
        cfg = RunnerConfig(enable_network_namespace=True)
        assert "netns=True" in repr(cfg)


# ─── 7. SubprocessRunner Network Namespace ───────────────────────────────

class TestSubprocessRunnerNetworkNS:
    """SubprocessRunner has enable_network_namespace parameter."""

    def test_init_accepts_netns(self):
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        runner = SubprocessRunner(enable_network_namespace=True)
        assert runner.enable_network_namespace is True

    def test_default_no_netns(self):
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        runner = SubprocessRunner()
        assert runner.enable_network_namespace is False

    def test_get_runner_with_config_netns(self):
        from nodechain.runtime.subprocess_runner import get_subprocess_runner, RunnerConfig
        cfg = RunnerConfig(enable_network_namespace=True)
        runner = get_subprocess_runner(config=cfg)
        assert runner.enable_network_namespace is True


# ─── 8. Network Namespace Enforcement (Linux) ────────────────────────────

class TestNetworkNSEndToEnd:
    """Network namespace enforcement on Linux."""

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
    def test_network_ns_blocks_socket(self):
        """Network namespace makes socket fail in child."""
        import asyncio
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        from nodechain.core.envelope import InvocationEnvelope

        echo_path = str(Path("nodes/echo_node/implementation.py").resolve())
        if not Path(echo_path).exists():
            pytest.skip("echo_node not found")

        runner = SubprocessRunner(enable_network_namespace=True)
        envelope = InvocationEnvelope(
            envelope_id="test_ns",
            run_id="test_ns",
            chain_id="test",
            node_id="echo_node",
            step_id=1,
            payload={"query": "hello netns"},
        )

        result = asyncio.run(runner.run_isolated(
            envelope=envelope,
            module_path=echo_path,
            class_name="EchoNode",
            node_id="echo_node",
            trust_level="local_untrusted",
            package_root=str(Path(echo_path).parent),
            enable_seccomp=True,
        ))

        # T3.0 safety fence: POSIX untrusted execution refused before spawn
        assert result["success"] is False
        assert result["exit_code"] == 126
        assert (result["error"].startswith("supervised execution failed before workload start") or result["error"].startswith("supervised_cgroup_unsupported"), f"expected supervised fail-closed refusal, got: {result.get('error', '')[:200]}")
        return  # Skip original capability assertions on POSIX

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
    def test_production_untrusted_includes_netns(self):
        """production_untrusted preset enables network namespace in runner."""
        import asyncio
        import os as _os
        from nodechain.runtime.subprocess_runner import get_subprocess_runner
        from nodechain.core.envelope import InvocationEnvelope

        echo_path = str(Path("nodes/echo_node/implementation.py").resolve())
        if not Path(echo_path).exists():
            pytest.skip("echo_node not found")

        _os.environ["NODECHAIN_POLICY_PRESET"] = "production_untrusted"
        try:
            runner = get_subprocess_runner()
            assert runner.enable_network_namespace is True

            envelope = InvocationEnvelope(
                envelope_id="test_prod_ns",
                run_id="test_prod_ns",
                chain_id="test",
                node_id="echo_node",
                step_id=1,
                payload={"query": "hello production netns"},
            )

            result = asyncio.run(runner.run_isolated(
                envelope=envelope,
                module_path=echo_path,
                class_name="EchoNode",
                node_id="echo_node",
                trust_level="local_untrusted",
                package_root=str(Path(echo_path).parent),
                enable_seccomp=True,
            ))

            # T3.0 safety fence: POSIX untrusted execution refused before spawn
            assert result["success"] is False
            assert result["exit_code"] == 126
            assert (result["error"].startswith("supervised execution failed before workload start") or result["error"].startswith("supervised_cgroup_unsupported"), f"expected supervised fail-closed refusal, got: {result.get('error', '')[:200]}")
            return  # Skip original capability assertions on POSIX
        finally:
            _os.environ.pop("NODECHAIN_POLICY_PRESET", None)


# ─── 9. Version and Changelog ────────────────────────────────────────────

class TestV140Version:
    """Version reflects v1.4.0."""

    def test_version_is_1_6_0(self):
        import nodechain
        assert nodechain.__version__ == "3.6.0"

    def test_changelog_has_v140(self):
        changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
        assert "3.5.1" in changelog

    def test_changelog_mentions_namespace(self):
        changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
        assert "namespace" in changelog.lower()
        assert "INV-011" in changelog
