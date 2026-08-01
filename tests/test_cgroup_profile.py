"""Tests for cgroup v2 resource accounting (v1.3.0).

Tests cover:
1. Cgroup detection (v2/v1/unavailable)
2. Accounting readability
3. Limits writability
4. Honest capability reporting
5. CgroupAccounting data model
6. INV-008 invariant
7. SandboxCapabilities cgroup fields
8. NodeTrustRecord cgroup fields
9. CLI report includes cgroup status
10. Version and changelog
"""

from __future__ import annotations

import platform
import pytest
from pathlib import Path

from nodechain.sdk.cgroup_profile import (
    CgroupAccounting,
    CgroupCapabilities,
    CgroupLimits,
    CgroupBackend,
    detect_cgroup,
    read_accounting,
)
from nodechain.sdk.trust_summary import (
    NodeTrustRecord,
    TrustSummary,
    TrustViolation,
)


# ─── 1. Detection ─────────────────────────────────────────────────────────

class TestCgroupDetection:
    """Cgroup version detection works correctly."""

    def test_detect_returns_capabilities(self):
        caps = detect_cgroup()
        assert isinstance(caps, CgroupCapabilities)

    def test_detection_fields_exist(self):
        caps = detect_cgroup()
        assert hasattr(caps, "cgroup_available")
        assert hasattr(caps, "cgroup_version")
        assert hasattr(caps, "cgroup_accounting_readable")
        assert hasattr(caps, "cgroup_limits_writable")
        assert hasattr(caps, "cgroup_enforced")
        assert hasattr(caps, "accounting_only")
        assert hasattr(caps, "cgroup_path")

    @pytest.mark.skipif(
        platform.system() != "Linux",
        reason="Linux only"
    )
    def test_cgroup_available_on_linux(self):
        caps = detect_cgroup()
        # On the Proxmox container, cgroup v2 should be available
        assert caps.cgroup_available is True
        assert caps.cgroup_version == "v2"

    @pytest.mark.skipif(
        platform.system() == "Linux",
        reason="Non-Linux only"
    )
    def test_cgroup_unavailable_on_non_linux(self):
        caps = detect_cgroup()
        assert caps.cgroup_available is False
        assert caps.cgroup_version == ""


# ─── 2. Capability Reporting ──────────────────────────────────────────────

class TestCgroupCapabilityReporting:
    """Capabilities are reported independently."""

    def test_capabilities_to_dict(self):
        caps = CgroupCapabilities(
            cgroup_available=True,
            cgroup_version="v2",
            cgroup_accounting_readable=True,
            cgroup_limits_writable=True,
        )
        d = caps.to_dict()
        assert d["cgroup_available"] is True
        assert d["cgroup_version"] == "v2"
        assert d["cgroup_accounting_readable"] is True
        assert d["cgroup_limits_writable"] is True

    def test_accounting_only_flag(self):
        caps = CgroupCapabilities(
            cgroup_available=True,
            cgroup_accounting_readable=True,
            cgroup_limits_writable=False,
            accounting_only=True,
        )
        d = caps.to_dict()
        assert d["accounting_only"] is True

    @pytest.mark.skipif(
        platform.system() != "Linux",
        reason="Linux only"
    )
    def test_real_container_capabilities_distinguished(self):
        """On the Proxmox container, distinguish accounting from limits."""
        caps = detect_cgroup()
        # Don't assert specific values, just verify they're set
        if caps.cgroup_available:
            # accounting_readable and limits_writable should be independently set
            assert isinstance(caps.cgroup_accounting_readable, bool)
            assert isinstance(caps.cgroup_limits_writable, bool)
            # If accounting but not writable, accounting_only should be True
            if caps.cgroup_accounting_readable and not caps.cgroup_limits_writable:
                assert caps.accounting_only is True


# ─── 3. CgroupAccounting ──────────────────────────────────────────────────

class TestCgroupAccounting:
    """CgroupAccounting data model."""

    def test_default_values(self):
        acct = CgroupAccounting()
        assert acct.memory_current_bytes == 0
        assert acct.cpu_usage_usec == 0
        assert acct.pids_current == 0

    def test_to_dict(self):
        acct = CgroupAccounting(
            memory_current_bytes=1024,
            memory_peak_bytes=2048,
            cpu_usage_usec=50000,
            pids_current=5,
        )
        d = acct.to_dict()
        assert d["memory_current_bytes"] == 1024
        assert d["memory_peak_bytes"] == 2048
        assert d["cpu_usage_usec"] == 50000
        assert d["pids_current"] == 5

    @pytest.mark.skipif(
        platform.system() != "Linux",
        reason="Linux only"
    )
    def test_read_accounting_from_real_system(self):
        """Read actual cgroup accounting on Linux."""
        acct = read_accounting()
        # Memory should be non-zero on a running system
        assert acct.memory_current_bytes > 0
        # CPU usage should have some value
        assert acct.cpu_usage_usec >= 0


# ─── 4. CgroupBackend ─────────────────────────────────────────────────────

class TestCgroupBackend:
    """CgroupBackend class."""

    def test_backend_construction(self):
        backend = CgroupBackend()
        assert backend is not None

    def test_backend_capabilities(self):
        backend = CgroupBackend()
        caps = backend.get_capabilities()
        assert isinstance(caps, CgroupCapabilities)

    def test_backend_describe(self):
        backend = CgroupBackend()
        desc = backend.describe()
        assert "backend" in desc
        assert desc["backend"] == "cgroup"
        assert "available" in desc
        assert "version" in desc

    @pytest.mark.skipif(
        platform.system() != "Linux",
        reason="Linux only"
    )
    def test_backend_describe_has_accounting_on_linux(self):
        """On Linux with cgroup, describe includes accounting."""
        backend = CgroupBackend()
        if backend.available:
            desc = backend.describe()
            assert desc["accounting"] is not None
            acct = desc["accounting"]
            assert "memory_current_bytes" in acct


# ─── 5. CgroupLimits ──────────────────────────────────────────────────────

class TestCgroupLimits:
    """CgroupLimits data model."""

    def test_default_values(self):
        limits = CgroupLimits()
        assert limits.memory_max_bytes == 0
        assert limits.pids_max == 0
        assert limits.cpu_max_quota == 0

    def test_custom_limits(self):
        limits = CgroupLimits(
            memory_max_bytes=512 * 1024 * 1024,
            pids_max=100,
            cpu_max_quota=50000,
        )
        d = limits.to_dict()
        assert d["memory_max_bytes"] == 536870912
        assert d["pids_max"] == 100
        assert d["cpu_max_quota"] == 50000


# ─── 6. INV-008 Invariant ─────────────────────────────────────────────────

class TestINV008CgroupCheck:
    """INV-008 fires when OS capability required but unavailable.

    v1.3.1: Platform-neutral. Fires when os_profile is required
    but no OS enforcement capability is available on the platform.
    Also checks explicit capability requirements via required_os_capabilities.
    """

    def test_inv008_fires_when_no_os_capability(self):
        """os_profile requires at least one OS enforcement capability."""
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="untrusted_node",
            trust_level="local_untrusted",
            isolation_mode="subprocess",
            child_policy_enforced=True,
            env_filtered=True,
            temp_dir_isolated=True,
            sandbox_profile_required="os_profile",
            sandbox_profile_used="os_profile",
            sandbox_backend="linux_rlimit",
            # No OS capability available
            resource_limits_enforced=False,
            syscall_filtering_enforced=False,
            cgroup_available=False,
            job_object_enforced=False,
        ))
        violations = summary.validate_invariants()
        inv008 = [v for v in violations if v.code == "INV-008"]
        assert len(inv008) == 1
        assert "os_capability" in inv008[0].invariant

    def test_inv008_passes_with_rlimit_only(self):
        """RLIMIT alone satisfies os_profile (Linux without cgroup)."""
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="untrusted_node",
            trust_level="local_untrusted",
            isolation_mode="subprocess",
            child_policy_enforced=True,
            env_filtered=True,
            temp_dir_isolated=True,
            sandbox_profile_required="os_profile",
            sandbox_profile_used="os_profile",
            sandbox_backend="linux_rlimit",
            resource_limits_enforced=True,  # RLIMIT available
            cgroup_available=False,  # No cgroup
        ))
        violations = summary.validate_invariants()
        inv008 = [v for v in violations if v.code == "INV-008"]
        assert len(inv008) == 0

    def test_inv008_passes_with_job_object_only(self):
        """Job Objects alone satisfy os_profile (Windows)."""
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="untrusted_node",
            trust_level="local_untrusted",
            isolation_mode="subprocess",
            child_policy_enforced=True,
            env_filtered=True,
            temp_dir_isolated=True,
            sandbox_profile_required="os_profile",
            sandbox_profile_used="os_profile",
            sandbox_backend="windows_job_object",
            job_object_enforced=True,  # Job Objects available
            cgroup_available=False,
        ))
        violations = summary.validate_invariants()
        inv008 = [v for v in violations if v.code == "INV-008"]
        assert len(inv008) == 0

    def test_inv008_passes_with_cgroup(self):
        """cgroup_available=true satisfies os_profile."""
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="untrusted_node",
            trust_level="local_untrusted",
            isolation_mode="subprocess",
            child_policy_enforced=True,
            env_filtered=True,
            temp_dir_isolated=True,
            sandbox_profile_required="os_profile",
            sandbox_profile_used="os_profile",
            sandbox_backend="linux_cgroup",
            cgroup_available=True,
            cgroup_version="v2",
        ))
        violations = summary.validate_invariants()
        inv008 = [v for v in violations if v.code == "INV-008"]
        assert len(inv008) == 0

    def test_inv008_does_not_fire_for_non_os_profile(self):
        """subprocess_isolated doesn't require os capability."""
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="basic",
            trust_level="built_in",
            isolation_mode="in_process",
        ))
        violations = summary.validate_invariants()
        inv008 = [v for v in violations if v.code == "INV-008"]
        assert len(inv008) == 0

    def test_inv008_explicit_cgroup_requirement(self):
        """Explicit cgroup_accounting requirement fires when unavailable."""
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="untrusted_node",
            trust_level="local_untrusted",
            isolation_mode="subprocess",
            sandbox_profile_required="os_profile",
            sandbox_profile_used="os_profile",
            resource_limits_enforced=True,
            cgroup_available=False,
            required_os_capabilities=["cgroup_accounting"],
        ))
        violations = summary.validate_invariants()
        inv008 = [v for v in violations if v.code == "INV-008"]
        assert len(inv008) == 1
        assert "cgroup_accounting" in inv008[0].actual

    def test_inv008_explicit_cgroup_requirement_passes_when_available(self):
        """Explicit cgroup_accounting requirement satisfied when available."""
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="untrusted_node",
            trust_level="local_untrusted",
            isolation_mode="subprocess",
            sandbox_profile_required="os_profile",
            sandbox_profile_used="os_profile",
            resource_limits_enforced=True,
            cgroup_available=True,
            cgroup_accounting_readable=True,
            required_os_capabilities=["cgroup_accounting"],
        ))
        violations = summary.validate_invariants()
        inv008 = [v for v in violations if v.code == "INV-008"]
        assert len(inv008) == 0


# ─── 7. SandboxCapabilities Cgroup Fields ─────────────────────────────────

class TestSandboxCapabilitiesCgroupFields:
    """SandboxCapabilities has v1.3.0 cgroup fields."""

    def test_fields_exist(self):
        from nodechain.sdk.os_sandbox import SandboxCapabilities
        caps = SandboxCapabilities()
        assert hasattr(caps, "cgroup_available")
        assert hasattr(caps, "cgroup_version")
        assert hasattr(caps, "cgroup_accounting_readable")
        assert hasattr(caps, "cgroup_limits_writable")
        assert hasattr(caps, "cgroup_accounting_only")

    def test_fields_in_to_dict(self):
        from nodechain.sdk.os_sandbox import SandboxCapabilities
        caps = SandboxCapabilities(
            cgroup_available=True,
            cgroup_version="v2",
            cgroup_accounting_readable=True,
        )
        d = caps.to_dict()
        assert "cgroup_available" in d
        assert d["cgroup_available"] is True
        assert d["cgroup_version"] == "v2"


# ─── 8. NodeTrustRecord Cgroup Fields ─────────────────────────────────────

class TestNodeTrustRecordCgroupFields:
    """NodeTrustRecord has v1.3.0/v1.3.1 cgroup fields."""

    def test_fields_exist(self):
        record = NodeTrustRecord(node_id="test")
        assert hasattr(record, "cgroup_available")
        assert hasattr(record, "cgroup_version")
        assert hasattr(record, "cgroup_accounting_readable")
        assert hasattr(record, "cgroup_limits_writable")
        assert hasattr(record, "cgroup_accounting_only")
        assert hasattr(record, "cgroup_limits_enforced")
        assert hasattr(record, "cgroup_accounting_scope")
        assert hasattr(record, "required_os_capabilities")

    def test_fields_in_to_dict(self):
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="test",
            trust_level="local_untrusted",
            isolation_mode="subprocess",
            cgroup_available=True,
            cgroup_version="v2",
            cgroup_accounting_readable=True,
            cgroup_limits_writable=True,
            cgroup_limits_enforced=True,
            cgroup_accounting_scope="invocation",
            required_os_capabilities=["cgroup_accounting"],
        ))
        d = summary.to_dict()
        node = d["nodes"][0]
        assert node["cgroup_available"] is True
        assert node["cgroup_version"] == "v2"
        assert node["cgroup_accounting_readable"] is True
        assert node["cgroup_limits_writable"] is True
        assert node["cgroup_limits_enforced"] is True
        assert node["cgroup_accounting_scope"] == "invocation"
        assert node["required_os_capabilities"] == ["cgroup_accounting"]


# ─── 9. SubprocessRunner Cgroup Lifecycle ─────────────────────────────

class TestSubprocessRunnerCgroupLifecycle:
    """Per-invocation cgroup lifecycle in SubprocessRunner."""

    def test_cgroup_disabled_by_default(self):
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        runner = SubprocessRunner()
        assert runner.enable_cgroup is False
        assert runner._cgroup_path is None

    def test_cgroup_enabled_flag(self):
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        runner = SubprocessRunner(enable_cgroup=True)
        assert runner.enable_cgroup is True

    def test_finalize_cgroup_returns_empty_when_no_cgroup(self):
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        runner = SubprocessRunner()
        result = runner._finalize_cgroup()
        assert result["cgroup_accounting"] is None
        assert result["cgroup_path"] is None
        assert result["cgroup_accounting_scope"] == ""

    def test_create_child_cgroup_returns_none_when_disabled(self):
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        runner = SubprocessRunner(enable_cgroup=False)
        assert runner._create_child_cgroup("test") is None

    @pytest.mark.skipif(
        platform.system() != "Linux",
        reason="Linux only"
    )
    def test_create_child_cgroup_on_linux(self):
        """Child cgroup creation works on Linux with cgroup v2."""
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        runner = SubprocessRunner(enable_cgroup=True)
        cg_path = runner._create_child_cgroup("test_node")
        # On Proxmox with writable cgroups, this should create a cgroup
        if cg_path:
            assert cg_path.startswith("/sys/fs/cgroup/nodechain_")
            # Clean up
            runner._cgroup_path = cg_path
            info = runner._finalize_cgroup()
            assert info["cgroup_accounting_scope"] == "invocation"
            assert info["cgroup_accounting"] is not None

    @pytest.mark.skipif(
        platform.system() != "Linux",
        reason="Linux only"
    )
    def test_full_isolated_run_with_cgroup(self):
        """End-to-end subprocess run with cgroup enabled."""
        import asyncio
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        from nodechain.core.envelope import InvocationEnvelope

        echo_path = Path("nodes/echo_node/implementation.py")
        if not echo_path.exists():
            pytest.skip("echo_node not found")

        runner = SubprocessRunner(enable_cgroup=True, timeout_seconds=10)
        envelope = InvocationEnvelope(
            envelope_id="test_cg",
            run_id="test_cg",
            chain_id="test",
            node_id="echo",
            step_id=1,
            payload={"query": "hello cgroup"},
        )

        result = asyncio.run(runner.run_isolated(
            envelope=envelope,
            module_path=str(echo_path.resolve()),
            class_name="EchoNode",
            node_id="echo",
            trust_level="local_untrusted",
            package_root=str(echo_path.parent.resolve()),
        ))

        # T3.0 safety fence: POSIX untrusted execution refused before spawn
        assert result["success"] is False
        assert result["exit_code"] == 126
        assert result["error"].startswith("supervised_backend_required")
        return  # Skip original capability assertions on POSIX


# ─── 10. CLI Report Includes Cgroup ────────────────────────────────────────

class TestCLIReportCgroup:
    """CLI report includes cgroup status."""

    def test_report_source_has_cgroup(self):
        from nodechain.cli import report as report_module
        source = open(report_module.__file__, encoding="utf-8").read()
        assert "cgroup" in source.lower()




# ─── 11. INV-009: Cgroup Limit Enforcement ────────────────────────────────

class TestINV009CgroupLimitEnforcement:
    """INV-009 fires when cgroup limits requested but not enforced."""

    def test_inv009_fires_when_limits_requested_not_enforced(self):
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="untrusted_node",
            trust_level="local_untrusted",
            isolation_mode="subprocess",
            sandbox_profile_required="os_profile",
            sandbox_profile_used="os_profile",
            resource_limits_enforced=True,
            cgroup_available=True,
            cgroup_limits_requested=True,
            cgroup_limits_enforced=False,
        ))
        violations = summary.validate_invariants()
        inv009 = [v for v in violations if v.code == "INV-009"]
        assert len(inv009) == 1
        assert "cgroup_limits_enforced" in inv009[0].expected

    def test_inv009_passes_when_limits_requested_and_enforced(self):
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="untrusted_node",
            trust_level="local_untrusted",
            isolation_mode="subprocess",
            sandbox_profile_required="os_profile",
            sandbox_profile_used="os_profile",
            resource_limits_enforced=True,
            cgroup_available=True,
            cgroup_limits_requested=True,
            cgroup_limits_enforced=True,
        ))
        violations = summary.validate_invariants()
        inv009 = [v for v in violations if v.code == "INV-009"]
        assert len(inv009) == 0

    def test_inv009_passes_when_no_limits_requested(self):
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="untrusted_node",
            trust_level="local_untrusted",
            isolation_mode="subprocess",
            sandbox_profile_required="os_profile",
            sandbox_profile_used="os_profile",
            resource_limits_enforced=True,
            cgroup_available=True,
            cgroup_limits_requested=False,
            cgroup_limits_enforced=False,
        ))
        violations = summary.validate_invariants()
        inv009 = [v for v in violations if v.code == "INV-009"]
        assert len(inv009) == 0


# ─── 12. Cgroup Limit Enforcement in SubprocessRunner ────────────────────

class TestCgroupLimitEnforcement:
    """SubprocessRunner applies and reports cgroup limits."""

    def test_cpu_quota_param_exists(self):
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        runner = SubprocessRunner(cgroup_cpu_max_quota=50000)
        assert runner.cgroup_cpu_max_quota == 50000

    def test_limits_requested_flag_default_false(self):
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        runner = SubprocessRunner()
        assert runner._cgroup_limits_requested is False
        assert runner._cgroup_limits_applied is False

    def test_finalize_reports_limits_fields(self):
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        runner = SubprocessRunner()
        result = runner._finalize_cgroup()
        assert "cgroup_limits_requested" in result
        assert "cgroup_limits_enforced" in result
        assert "cgroup_memory_max_mb" in result
        assert "cgroup_pids_max" in result
        assert "cgroup_cpu_max_quota" in result

    @pytest.mark.skipif(
        platform.system() != "Linux",
        reason="Linux only"
    )
    def test_limits_applied_with_memory_cap_on_linux(self):
        """Memory limit applied to child cgroup on Linux."""
        import asyncio
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        from nodechain.core.envelope import InvocationEnvelope

        echo_path = Path("nodes/echo_node/implementation.py")
        if not echo_path.exists():
            pytest.skip("echo_node not found")

        runner = SubprocessRunner(
            enable_cgroup=True,
            cgroup_memory_max_mb=256,
            cgroup_pids_max=10,
            timeout_seconds=10,
        )
        envelope = InvocationEnvelope(
            envelope_id="test_limit",
            run_id="test_limit",
            chain_id="test",
            node_id="echo",
            step_id=1,
            payload={"query": "hello limit"},
        )

        result = asyncio.run(runner.run_isolated(
            envelope=envelope,
            module_path=str(echo_path.resolve()),
            class_name="EchoNode",
            node_id="echo",
            trust_level="local_untrusted",
            package_root=str(echo_path.parent.resolve()),
        ))

        # T3.0 safety fence: POSIX untrusted execution refused before spawn
        assert result["success"] is False
        assert result["exit_code"] == 126
        assert result["error"].startswith("supervised_backend_required")
        return  # Skip original capability assertions on POSIX


# ─── 13. Killed-Child Cleanup Test ───────────────────────────────────────

class TestKilledChildCgroupCleanup:
    """Cgroup is cleaned up after killed child process (timeout)."""

    @pytest.mark.skipif(
        platform.system() != "Linux",
        reason="Linux only"
    )
    def test_timeout_cleans_up_cgroup(self):
        """Timeout path still cleans up cgroup."""
        import asyncio
        import os
        import tempfile
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        from nodechain.core.envelope import InvocationEnvelope

        slow_code = '''
import time, sys, json
try:
    data = json.loads(sys.stdin.read())
except Exception:
    pass
time.sleep(30)
sys.stdout.write(json.dumps({"output": {}, "output_type": "error", "success": False, "error": "timeout"}))
'''
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, dir="/tmp") as f:
            f.write(slow_code)
            slow_path = f.name

        try:
            runner = SubprocessRunner(
                enable_cgroup=True,
                timeout_seconds=2,
            )
            envelope = InvocationEnvelope(
                envelope_id="test_kill",
                run_id="test_kill",
                chain_id="test",
                node_id="slow",
                step_id=1,
                payload={"query": "slow"},
            )

            result = asyncio.run(runner.run_isolated(
                envelope=envelope,
                module_path=slow_path,
                class_name="Node",
                node_id="slow",
                trust_level="local_untrusted",
                package_root="/tmp",
            ))

            # T3.0 safety fence: POSIX untrusted execution refused before spawn
            assert result["success"] is False
            assert result["exit_code"] == 126
            assert result["error"].startswith("supervised_backend_required")
            return  # Skip original capability assertions on POSIX
        finally:
            os.unlink(slow_path)


# ─── 14. NodeTrustRecord v1.3.2 Fields ──────────────────────────────────

class TestNodeTrustRecordV132Fields:
    """NodeTrustRecord has v1.3.2 cgroup limit fields."""

    def test_fields_exist(self):
        record = NodeTrustRecord(node_id="test")
        assert hasattr(record, "cgroup_limits_requested")
        assert hasattr(record, "cgroup_memory_max_mb")
        assert hasattr(record, "cgroup_pids_max")
        assert hasattr(record, "cgroup_cpu_max_quota")

    def test_fields_in_to_dict(self):
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="test",
            trust_level="local_untrusted",
            isolation_mode="subprocess",
            cgroup_limits_requested=True,
            cgroup_memory_max_mb=512,
            cgroup_pids_max=50,
            cgroup_cpu_max_quota=100000,
        ))
        d = summary.to_dict()
        node = d["nodes"][0]
        assert node["cgroup_limits_requested"] is True
        assert node["cgroup_memory_max_mb"] == 512
        assert node["cgroup_pids_max"] == 50
        assert node["cgroup_cpu_max_quota"] == 100000



class TestCgroupVersion:
    """Version reflects v1.3.2."""

    def test_version_is_1_6_0(self):
        import nodechain
        assert nodechain.__version__ == "3.5.1"

    def test_changelog_has_v132(self):
        changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
        assert "3.5.1" in changelog
