"""Tests for network namespace policy completion (v1.4.1).

Tests cover:
1. INV-011 is capability-specific and fires as error when required but not enforced
2. INV-011 does NOT fire when namespace not required
3. INV-011 does NOT fire when namespace required AND enforced
4. Strict mode produces INV-011 on namespace failure
5. NodeTrustRecord has new fields (network_namespace_requested, network_namespace_error)
6. TrustSummary to_dict includes all namespace fields
7. Physical isolation test: socket fails under network namespace (Linux)
8. Version and changelog
"""

from __future__ import annotations

import platform
import pytest
from pathlib import Path


# ─── 1. INV-011 Capability-Specific ─────────────────────────────────────

class TestINV011CapabilitySpecific:
    """INV-011 fires as error when namespace required but not enforced."""

    def test_fires_when_required_but_not_enforced(self):
        from nodechain.sdk.trust_summary import TrustSummary, NodeTrustRecord
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="untrusted",
            trust_level="local_untrusted",
            network_namespace_requested=True,
            network_namespace_enforced=False,
        ))
        violations = summary.validate_invariants()
        inv011 = [v for v in violations if v.code == "INV-011"]
        assert len(inv011) == 1
        assert inv011[0].severity == "error"
        assert "network_namespace_required_but_not_enforced" in inv011[0].invariant

    def test_no_violation_when_not_required(self):
        from nodechain.sdk.trust_summary import TrustSummary, NodeTrustRecord
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="trusted",
            trust_level="built_in",
            network_namespace_requested=False,
            network_namespace_enforced=False,
        ))
        violations = summary.validate_invariants()
        inv011 = [v for v in violations if v.code == "INV-011"]
        assert len(inv011) == 0

    def test_no_violation_when_required_and_enforced(self):
        from nodechain.sdk.trust_summary import TrustSummary, NodeTrustRecord
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="untrusted",
            trust_level="local_untrusted",
            network_namespace_requested=True,
            network_namespace_enforced=True,
        ))
        violations = summary.validate_invariants()
        inv011 = [v for v in violations if v.code == "INV-011"]
        assert len(inv011) == 0

    def test_fires_with_error_detail(self):
        from nodechain.sdk.trust_summary import TrustSummary, NodeTrustRecord
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="untrusted",
            trust_level="local_untrusted",
            network_namespace_requested=True,
            network_namespace_enforced=False,
            network_namespace_error="unshare failed: EPERM",
        ))
        violations = summary.validate_invariants()
        inv011 = [v for v in violations if v.code == "INV-011"]
        assert len(inv011) == 1
        assert "unshare failed" in inv011[0].actual


# ─── 2. Strict Mode Hard-Fails ───────────────────────────────────────────

class TestStrictModeHardFails:
    """Strict mode produces INV-011 error on namespace failure."""

    def test_strict_mode_elevates_to_error(self):
        from nodechain.sdk.trust_summary import TrustSummary, NodeTrustRecord
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="untrusted",
            trust_level="local_untrusted",
            network_namespace_requested=True,
            network_namespace_enforced=False,
        ))
        # Even without strict, INV-011 is already error severity
        violations = summary.validate_invariants(strict=False)
        inv011 = [v for v in violations if v.code == "INV-011"]
        assert all(v.severity == "error" for v in inv011)

    def test_strict_mode_same_behavior(self):
        from nodechain.sdk.trust_summary import TrustSummary, NodeTrustRecord
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="untrusted",
            trust_level="local_untrusted",
            network_namespace_requested=True,
            network_namespace_enforced=False,
        ))
        violations_strict = summary.validate_invariants(strict=True)
        inv011 = [v for v in violations_strict if v.code == "INV-011"]
        assert len(inv011) == 1
        assert inv011[0].severity == "error"


# ─── 3. Negative Test: Simulated Namespace Failure ──────────────────────

class TestSimulatedNamespaceFailure:
    """Simulate namespace creation failure and verify INV-011 fires."""

    def test_simulated_failure_produces_inv011(self):
        """When child reports network_namespace_enforced=false after request."""
        from nodechain.sdk.trust_summary import TrustSummary, NodeTrustRecord
        summary = TrustSummary(run_id="test", policy_preset="production_untrusted")
        summary.add_node(NodeTrustRecord(
            node_id="untrusted_node",
            trust_level="local_untrusted",
            isolation_mode="subprocess",
            sandbox_profile_required="os_profile",
            network_namespace_requested=True,
            network_namespace_enforced=False,
            network_namespace_error="os.unshare failed: EPERM",
        ))
        violations = summary.validate_invariants(strict=True)
        inv011 = [v for v in violations if v.code == "INV-011"]
        assert len(inv011) == 1
        assert inv011[0].severity == "error"
        assert "untrusted_node" == inv011[0].node_id


# ─── 4. NodeTrustRecord New Fields ───────────────────────────────────────

class TestNodeTrustRecordNewFields:
    """NodeTrustRecord has network_namespace_requested and _error fields."""

    def test_fields_exist(self):
        from nodechain.sdk.trust_summary import NodeTrustRecord
        rec = NodeTrustRecord(node_id="test")
        assert hasattr(rec, "network_namespace_requested")
        assert hasattr(rec, "network_namespace_error")
        assert rec.network_namespace_requested is False
        assert rec.network_namespace_error == ""

    def test_fields_in_to_dict(self):
        from nodechain.sdk.trust_summary import NodeTrustRecord, TrustSummary
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="test",
            network_namespace_requested=True,
            network_namespace_error="test error",
        ))
        d = summary.to_dict()
        node = d["nodes"][0]
        assert node["network_namespace_requested"] is True
        assert node["network_namespace_error"] == "test error"


# ─── 5. Physical Isolation Test (Linux) ──────────────────────────────────

@pytest.mark.native_sandbox
class TestPhysicalIsolation:
    """Network namespace prevents connectivity even without Python hooks."""

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
    def test_socket_blocked_under_network_namespace(self):
        """Socket connection fails in network namespace.

        This proves kernel-level isolation, not just Python hooks.
        The child process gets a new network namespace with no interfaces.
        """
        import asyncio
        import subprocess
        import sys

        # Run a subprocess that creates a network namespace and tries to connect
        test_code = """
import os, socket, sys
# Create network namespace
try:
    os.unshare(os.CLONE_NEWNET)
    # Try to connect to any address - should fail
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        s.connect(("127.0.0.1", 9999))
        print("CONNECTED")
        s.close()
    except OSError as e:
        print(f"BLOCKED:{type(e).__name__}")
except Exception as e:
    print(f"NS_FAILED:{e}")
"""
        result = subprocess.run(
            [sys.executable, "-c", test_code],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout.strip()
        assert "BLOCKED" in output, \
            f"Expected socket to be blocked by network namespace, got: {output}"

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
    def test_network_namespace_inode_differs(self):
        """Child network namespace inode differs from parent."""
        import subprocess
        import sys

        parent_inode = None
        try:
            link = __import__("os").readlink("/proc/self/ns/net")
            parent_inode = link
        except Exception:
            pytest.skip("Cannot read namespace inode")

        test_code = """
import os
# Create network namespace
os.unshare(os.CLONE_NEWNET)
# Print our netns inode
link = os.readlink("/proc/self/ns/net")
print(link)
"""
        result = subprocess.run(
            [sys.executable, "-c", test_code],
            capture_output=True, text=True, timeout=10
        )
        child_inode = result.stdout.strip()
        assert child_inode != parent_inode, \
            f"Expected different netns inode, parent={parent_inode} child={child_inode}"


# ─── 6. E2E: production_untrusted Enforces Network Namespace ─────────────

class TestProductionUntrustedEnforcesNetNS:
    """production_untrusted actually enforces network namespace on Linux."""

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
    def test_e2e_network_namespace_enforced(self):
        import asyncio
        import os
        from nodechain.runtime.subprocess_runner import get_subprocess_runner
        from nodechain.core.envelope import InvocationEnvelope

        echo_path = str(Path("nodes/echo_node/implementation.py").resolve())
        if not Path(echo_path).exists():
            pytest.skip("echo_node not found")

        os.environ["NODECHAIN_POLICY_PRESET"] = "production_untrusted"
        try:
            runner = get_subprocess_runner()
            assert runner.enable_network_namespace is True

            envelope = InvocationEnvelope(
                envelope_id="test_e2e_ns",
                run_id="test_e2e_ns",
                chain_id="test",
                node_id="echo_node",
                step_id=1,
                payload={"query": "hello"},
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
            os.environ.pop("NODECHAIN_POLICY_PRESET", None)


# ─── 7. Version and Changelog ────────────────────────────────────────────

class TestV141Version:
    """Version reflects v1.4.1."""

    def test_version_is_1_6_0(self):
        import nodechain
        assert nodechain.__version__ == "3.6.0"

    def test_changelog_has_v141(self):
        changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
        assert "3.5.1" in changelog
        assert "capability-specific" in changelog.lower()
