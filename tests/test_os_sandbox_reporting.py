"""Tests for OS profile reporting hardening — v1.1.1.

AC1: Report differentiates resource_limits_enforced from syscall_filtering_enforced.
AC2: Strict mode can require specific OS features.
AC3: macOS reports capability_detection_only explicitly.
AC4: Windows reports job_object_enforced=true/false.
AC5: Reconciler checks requested OS features, not just os_profile=true.
"""

import pytest
import sys

from nodechain.sdk.os_sandbox import (
    SandboxProfile,
    SandboxCapabilities,
    SandboxProfileResolver,
    LinuxBackend,
    WindowsJobObjectBackend,
    MacOSBackend,
    OSBackend,
    detect_backend,
    SandboxResult,
    ResourceLimits,
)


# ── 1. Granular Capability Reporting ──────────────────────────────

class TestGranularCapabilities:
    """AC1: resource_limits vs syscall_filtering are separate fields."""

    def test_capabilities_dataclass_fields(self):
        caps = SandboxCapabilities()
        assert hasattr(caps, "resource_limits_enforced")
        assert hasattr(caps, "syscall_filtering_enforced")
        assert hasattr(caps, "namespace_enforced")
        assert hasattr(caps, "cgroup_enforced")
        assert hasattr(caps, "job_object_enforced")
        assert hasattr(caps, "detection_only")

    def test_capabilities_to_dict(self):
        caps = SandboxCapabilities(
            resource_limits_enforced=True,
            syscall_filtering_enforced=False,
            backend_name="linux_rlimit",
            platform="linux",
        )
        d = caps.to_dict()
        assert d["resource_limits_enforced"] is True
        assert d["syscall_filtering_enforced"] is False
        assert d["backend_name"] == "linux_rlimit"
        assert d["platform"] == "linux"

    def test_resource_limits_and_syscall_filtering_independent(self):
        """resource_limits can be True while syscall_filtering is False."""
        caps = SandboxCapabilities(
            resource_limits_enforced=True,
            syscall_filtering_enforced=False,
        )
        assert caps.resource_limits_enforced is True
        assert caps.syscall_filtering_enforced is False


# ── 2. Linux Backend Capabilities ─────────────────────────────────

class TestLinuxCapabilities:

    def test_linux_reports_resource_limits(self):
        backend = LinuxBackend()
        caps = backend.get_capabilities()
        if backend.available:
            assert caps.resource_limits_enforced is True

    def test_linux_does_not_claim_seccomp(self):
        """Linux does NOT claim syscall filtering in v1.1.x."""
        backend = LinuxBackend()
        caps = backend.get_capabilities()
        assert caps.syscall_filtering_enforced is False

    def test_linux_does_not_claim_namespaces(self):
        """Linux does NOT claim namespace enforcement in v1.1.x."""
        backend = LinuxBackend()
        caps = backend.get_capabilities()
        assert caps.namespace_enforced is False

    def test_linux_cgroup_reporting_honest(self):
        """Linux reports cgroup capabilities honestly (v1.3.0)."""
        backend = LinuxBackend()
        caps = backend.get_capabilities()
        assert hasattr(caps, "cgroup_enforced")
        assert isinstance(caps.cgroup_enforced, bool)

    def test_linux_backend_name(self):
        backend = LinuxBackend()
        caps = backend.get_capabilities()
        assert caps.backend_name == "linux_rlimit"


# ── 3. Windows Backend Capabilities ───────────────────────────────

class TestWindowsCapabilities:
    """AC4: Windows reports job_object_enforced."""

    def test_windows_reports_job_object(self):
        backend = WindowsJobObjectBackend()
        caps = backend.get_capabilities()
        if backend.available:
            assert caps.job_object_enforced is True

    def test_windows_does_not_claim_seccomp(self):
        backend = WindowsJobObjectBackend()
        caps = backend.get_capabilities()
        assert caps.syscall_filtering_enforced is False

    def test_windows_does_not_claim_namespaces(self):
        backend = WindowsJobObjectBackend()
        caps = backend.get_capabilities()
        assert caps.namespace_enforced is False

    def test_windows_reports_resource_limits(self):
        """Windows Job Objects provide resource limits."""
        backend = WindowsJobObjectBackend()
        caps = backend.get_capabilities()
        if backend.available:
            assert caps.resource_limits_enforced is True

    def test_windows_backend_name(self):
        backend = WindowsJobObjectBackend()
        caps = backend.get_capabilities()
        assert caps.backend_name == "windows_job_object"


# ── 4. macOS Backend Capabilities ─────────────────────────────────

class TestMacOSCapabilities:
    """AC3: macOS reports capability_detection_only."""

    def test_macos_is_detection_only(self):
        backend = MacOSBackend()
        caps = backend.get_capabilities()
        assert caps.detection_only is True

    def test_macos_does_not_claim_enforcement(self):
        backend = MacOSBackend()
        caps = backend.get_capabilities()
        assert caps.resource_limits_enforced is False
        assert caps.syscall_filtering_enforced is False
        assert caps.namespace_enforced is False
        assert caps.job_object_enforced is False

    def test_macos_backend_name(self):
        backend = MacOSBackend()
        caps = backend.get_capabilities()
        assert caps.backend_name == "macos_sandbox_exec"


# ── 5. Resolver Includes Capabilities ─────────────────────────────

class TestResolverCapabilities:

    def test_os_profile_result_has_capabilities(self):
        backend = OSBackend(platform="test", available=True, backend_name="test")
        resolver = SandboxProfileResolver(backend=backend)
        result = resolver.resolve(SandboxProfile.OS_PROFILE, "local_untrusted")
        assert result.capabilities is not None
        assert isinstance(result.capabilities, SandboxCapabilities)

    def test_fallback_result_has_capabilities(self):
        backend = OSBackend(platform="test", available=False, backend_name="none")
        resolver = SandboxProfileResolver(backend=backend, allow_fallback=True)
        result = resolver.resolve(SandboxProfile.OS_PROFILE, "local_untrusted")
        assert result.capabilities is not None
        assert result.capabilities.detection_only is True

    def test_passthrough_result_has_capabilities(self):
        backend = OSBackend(platform="test", available=True, backend_name="test")
        resolver = SandboxProfileResolver(backend=backend)
        result = resolver.resolve(SandboxProfile.PYTHON_HOOKS, "local_trusted")
        assert result.capabilities is not None


# ── 6. Backend describe() Includes Granular Capabilities ──────────

class TestBackendDescribe:

    def test_describe_includes_granular_capabilities(self):
        backend = detect_backend()
        desc = backend.describe()
        assert "granular_capabilities" in desc
        granular = desc["granular_capabilities"]
        assert "resource_limits_enforced" in granular
        assert "syscall_filtering_enforced" in granular
        assert "detection_only" in granular

    def test_describe_matches_get_capabilities(self):
        backend = detect_backend()
        desc = backend.describe()
        caps = backend.get_capabilities()
        assert desc["granular_capabilities"] == caps.to_dict()


# ── 7. Honest Backend Description Per Platform ────────────────────

class TestHonestPlatformDescription:

    def test_current_platform_honest_about_seccomp(self):
        """Whatever platform we're on, it must NOT claim seccomp in v1.1.x."""
        backend = detect_backend()
        caps = backend.get_capabilities()
        assert caps.syscall_filtering_enforced is False, \
            f"{backend.backend_name} should not claim syscall filtering in v1.1.x"

    def test_current_platform_honest_about_namespaces(self):
        backend = detect_backend()
        caps = backend.get_capabilities()
        assert caps.namespace_enforced is False, \
            f"{backend.backend_name} should not claim namespace enforcement in v1.1.x"

    def test_current_platform_honest_about_cgroups(self):
        """Every platform reports cgroup honestly (v1.3.0)."""
        backend = detect_backend()
        caps = backend.get_capabilities()
        assert hasattr(caps, "cgroup_enforced")
        assert isinstance(caps.cgroup_enforced, bool)

    def test_detection_only_flag_is_set_correctly(self):
        backend = detect_backend()
        caps = backend.get_capabilities()
        if not backend.available:
            assert caps.detection_only is True


# ── 8. Strict Mode Feature Requirements ───────────────────────────

class TestStrictModeFeatures:
    """AC2: Strict mode can require specific features."""

    def test_strict_resolver_still_works(self):
        backend = OSBackend(platform="test", available=False, backend_name="none")
        resolver = SandboxProfileResolver(backend=backend, strict=True)
        result = resolver.resolve(SandboxProfile.OS_PROFILE, "local_untrusted")
        assert result.fallback_used is True
        assert result.error is not None

    def test_capabilities_are_available_even_on_fallback(self):
        """Even on fallback, capabilities should be reported."""
        backend = OSBackend(platform="test", available=False, backend_name="none")
        resolver = SandboxProfileResolver(backend=backend, strict=True)
        result = resolver.resolve(SandboxProfile.OS_PROFILE, "local_untrusted")
        assert result.capabilities is not None
        assert result.capabilities.detection_only is True


# ── 9. Capability Report in Trust Summary ─────────────────────────

class TestTrustSummaryCapabilityFields:

    def test_sandbox_backend_field_exists(self):
        from nodechain.sdk.trust_summary import NodeTrustRecord
        record = NodeTrustRecord(
            node_id="test",
            sandbox_backend="windows_job_object",
        )
        assert record.sandbox_backend == "windows_job_object"

    def test_sandbox_fields_backward_compat(self):
        from nodechain.sdk.trust_summary import NodeTrustRecord
        record = NodeTrustRecord(node_id="old")
        assert record.sandbox_backend == ""
        assert record.sandbox_profile_required == ""
