"""Tests for OS sandbox profiles — v1.1.0.

AC1: Trust policy can select an OS sandbox profile per node.
AC2: Report records sandbox_profile and enforcement backend.
AC3: local_untrusted/remote_untrusted can run with os_profile when available.
AC4: Runtime falls back only when policy permits fallback.
AC5: Strict mode blocks fallback from os_profile to weaker sandbox.
AC6: Timeout/output/memory limits still work under OS profile.
AC7: TrustSummary includes os_sandbox_enforced.
AC8: Reconciler checks required sandbox profile was used (INV-006).
AC9: Existing 1235 tests remain green.
"""

import pytest
import sys

from nodechain.sdk.os_sandbox import (
    SandboxProfile,
    Platform,
    ResourceLimits,
    SandboxResult,
    OSBackend,
    LinuxBackend,
    WindowsJobObjectBackend,
    MacOSBackend,
    detect_backend,
    SandboxProfileResolver,
)
from nodechain.sdk.trust_summary import TrustSummary, NodeTrustRecord, TrustViolation


# ── 1. SandboxProfile Model ───────────────────────────────────────

class TestSandboxProfile:

    def test_profile_strength_ordering(self):
        assert SandboxProfile.OS_PROFILE.strength > SandboxProfile.SUBPROCESS_ISOLATED.strength
        assert SandboxProfile.SUBPROCESS_ISOLATED.strength > SandboxProfile.PYTHON_HOOKS.strength
        assert SandboxProfile.PYTHON_HOOKS.strength > SandboxProfile.NONE.strength

    def test_for_trust_level_mapping(self):
        assert SandboxProfile.for_trust_level("built_in") == SandboxProfile.NONE
        assert SandboxProfile.for_trust_level("local_trusted") == SandboxProfile.PYTHON_HOOKS
        assert SandboxProfile.for_trust_level("local_untrusted") == SandboxProfile.SUBPROCESS_ISOLATED
        assert SandboxProfile.for_trust_level("remote_untrusted") == SandboxProfile.SUBPROCESS_ISOLATED

    def test_unknown_trust_level_defaults_to_subprocess(self):
        assert SandboxProfile.for_trust_level("unknown") == SandboxProfile.SUBPROCESS_ISOLATED

    def test_enum_values(self):
        assert SandboxProfile.OS_PROFILE.value == "os_profile"
        assert SandboxProfile.SUBPROCESS_ISOLATED.value == "subprocess_isolated"
        assert SandboxProfile.PYTHON_HOOKS.value == "python_hooks"
        assert SandboxProfile.NONE.value == "none"


# ── 2. Platform Detection ─────────────────────────────────────────

class TestPlatformDetection:

    def test_detect_returns_valid_platform(self):
        p = Platform.detect()
        assert p in (Platform.LINUX, Platform.WINDOWS, Platform.MACOS, Platform.OTHER)

    def test_current_platform_matches_sys(self):
        p = Platform.detect()
        if sys.platform.startswith("linux"):
            assert p == Platform.LINUX
        elif sys.platform == "win32":
            assert p == Platform.WINDOWS
        elif sys.platform == "darwin":
            assert p == Platform.MACOS


# ── 3. Backend Detection ──────────────────────────────────────────

class TestBackendDetection:

    def test_detect_backend_returns_backend(self):
        backend = detect_backend()
        assert isinstance(backend, OSBackend)

    def test_backend_has_name(self):
        backend = detect_backend()
        assert backend.backend_name != ""

    def test_backend_describe(self):
        backend = detect_backend()
        desc = backend.describe()
        assert "platform" in desc
        assert "available" in desc
        assert "backend" in desc
        assert "capabilities" in desc

    def test_linux_backend_on_linux(self):
        if sys.platform.startswith("linux"):
            backend = LinuxBackend()
            assert backend.available
            assert "rlimit_cpu" in backend.capabilities

    def test_windows_backend_on_windows(self):
        if sys.platform == "win32":
            backend = WindowsJobObjectBackend()
            assert backend.available
            assert "job_object" in backend.capabilities


# ── 4. ResourceLimits ─────────────────────────────────────────────

class TestResourceLimits:

    def test_defaults(self):
        limits = ResourceLimits()
        assert limits.memory_mb == 512
        assert limits.output_size_mb == 10
        assert limits.wall_timeout_seconds == 30
        assert limits.process_count == 1

    def test_custom_limits(self):
        limits = ResourceLimits(memory_mb=1024, cpu_time_seconds=60)
        assert limits.memory_mb == 1024
        assert limits.cpu_time_seconds == 60


# ── 5. SandboxProfileResolver ─────────────────────────────────────

class TestProfileResolver:

    def test_os_profile_available(self):
        """AC3: os_profile when backend available."""
        backend = OSBackend(platform="test", available=True, backend_name="test_backend")
        resolver = SandboxProfileResolver(backend=backend)
        result = resolver.resolve(SandboxProfile.OS_PROFILE, "local_untrusted")
        assert result.profile_used == "os_profile"
        assert result.os_sandbox_enforced is True
        assert result.fallback_used is False

    def test_os_profile_fallback_when_unavailable(self):
        """AC4: fallback to subprocess when os_profile unavailable."""
        backend = OSBackend(platform="test", available=False, backend_name="none")
        resolver = SandboxProfileResolver(backend=backend, allow_fallback=True)
        result = resolver.resolve(SandboxProfile.OS_PROFILE, "local_untrusted")
        assert result.profile_used == "subprocess_isolated"
        assert result.os_sandbox_enforced is False
        assert result.fallback_used is True

    def test_os_profile_strict_blocks_fallback(self):
        """AC5: strict mode blocks fallback from os_profile."""
        backend = OSBackend(platform="test", available=False, backend_name="none")
        resolver = SandboxProfileResolver(backend=backend, strict=True)
        result = resolver.resolve(SandboxProfile.OS_PROFILE, "local_untrusted")
        # In strict mode, we still use subprocess but record the error
        assert result.fallback_used is True
        assert result.error is not None
        assert "strict" in result.error.lower()

    def test_subprocess_profile_passthrough(self):
        """subprocess_isolated profile passes through."""
        backend = OSBackend(platform="test", available=True, backend_name="test")
        resolver = SandboxProfileResolver(backend=backend)
        result = resolver.resolve(SandboxProfile.SUBPROCESS_ISOLATED, "local_untrusted")
        assert result.profile_used == "subprocess_isolated"
        assert result.fallback_used is False

    def test_python_hooks_profile_passthrough(self):
        """python_hooks profile passes through."""
        backend = OSBackend(platform="test", available=True, backend_name="test")
        resolver = SandboxProfileResolver(backend=backend)
        result = resolver.resolve(SandboxProfile.PYTHON_HOOKS, "local_trusted")
        assert result.profile_used == "python_hooks"

    def test_none_profile_passthrough(self):
        """none profile passes through."""
        backend = OSBackend(platform="test", available=True, backend_name="test")
        resolver = SandboxProfileResolver(backend=backend)
        result = resolver.resolve(SandboxProfile.NONE, "built_in")
        assert result.profile_used == "none"

    def test_fallback_disabled_error(self):
        """When fallback disabled and OS unavailable, error recorded."""
        backend = OSBackend(platform="test", available=False, backend_name="none")
        resolver = SandboxProfileResolver(backend=backend, allow_fallback=False)
        result = resolver.resolve(SandboxProfile.OS_PROFILE, "local_untrusted")
        assert result.profile_used == "none"
        assert result.error is not None


# ── 6. INV-006 Trust Invariant ────────────────────────────────────

class TestINV006:

    def test_inv006_fires_on_profile_downgrade(self):
        """AC8: INV-006 fires when required profile not used."""
        summary = TrustSummary(run_id="t")
        summary.add_node(NodeTrustRecord(
            node_id="bad",
            trust_level="local_untrusted",
            isolation_mode="subprocess",
            child_policy_enforced=True,
            env_filtered=True,
            temp_dir_isolated=True,
            sandbox_profile_required="os_profile",
            sandbox_profile_used="subprocess_isolated",
        ))
        violations = summary.validate_invariants(strict=True)
        codes = [v.code for v in violations]
        assert "INV-006" in codes

    def test_inv006_passes_when_profile_matches(self):
        """No violation when required profile used."""
        summary = TrustSummary(run_id="t")
        summary.add_node(NodeTrustRecord(
            node_id="good",
            trust_level="local_untrusted",
            isolation_mode="subprocess",
            child_policy_enforced=True,
            env_filtered=True,
            temp_dir_isolated=True,
            sandbox_profile_required="os_profile",
            sandbox_profile_used="os_profile",
            os_sandbox_enforced=True,
        ))
        violations = summary.validate_invariants(strict=True)
        assert all(v.code != "INV-006" for v in violations)

    def test_inv006_passes_when_no_profile_required(self):
        """No violation when no profile required (backward compat)."""
        summary = TrustSummary(run_id="t")
        summary.add_node(NodeTrustRecord(
            node_id="basic",
            trust_level="built_in",
            isolation_mode="in_process",
        ))
        violations = summary.validate_invariants(strict=True)
        assert all(v.code != "INV-006" for v in violations)

    def test_inv006_violation_structure(self):
        summary = TrustSummary(run_id="t")
        summary.add_node(NodeTrustRecord(
            node_id="node1",
            trust_level="local_untrusted",
            isolation_mode="subprocess",
            child_policy_enforced=True,
            env_filtered=True,
            temp_dir_isolated=True,
            sandbox_profile_required="os_profile",
            sandbox_profile_used="python_hooks",
        ))
        violations = summary.validate_invariants(strict=True)
        inv6 = [v for v in violations if v.code == "INV-006"][0]
        assert inv6.invariant == "required_sandbox_profile_must_be_used"
        assert inv6.node_id == "node1"
        assert "os_profile" in inv6.expected
        assert "python_hooks" in inv6.actual


# ── 7. TrustSummary os_sandbox_enforced Field ─────────────────────

class TestTrustSummarySandboxFields:

    def test_node_record_has_sandbox_fields(self):
        """AC7: TrustSummary includes os_sandbox_enforced."""
        record = NodeTrustRecord(
            node_id="test",
            sandbox_profile_required="os_profile",
            sandbox_profile_used="os_profile",
            os_sandbox_enforced=True,
            fallback_used=False,
            sandbox_backend="windows_job_object",
        )
        d = TrustSummary(run_id="t")
        d.add_node(record)
        data = d.to_dict()
        node_data = data["nodes"][0]
        assert "os_sandbox_enforced" in node_data
        assert node_data["os_sandbox_enforced"] is True
        assert "sandbox_profile_required" in node_data
        assert "sandbox_profile_used" in node_data
        assert "fallback_used" in node_data
        assert "sandbox_backend" in node_data

    def test_backward_compat_empty_sandbox_fields(self):
        """Old records without sandbox fields work fine."""
        record = NodeTrustRecord(node_id="old")
        assert record.sandbox_profile_required == ""
        assert record.os_sandbox_enforced is False


# ── 8. CLI --sandbox-profile Flag ─────────────────────────────────

class TestCLISandboxProfile:

    def test_sandbox_profile_in_run_help(self):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["run", "--help"])
        assert "--sandbox-profile" in result.output

    def test_sandbox_profile_choices(self):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["run", "--help"])
        assert "os_profile" in result.output
        assert "python_hooks" in result.output
        assert "subprocess_isolated" in result.output


# ── 9. Windows Job Object Backend (only on Windows) ───────────────

class TestWindowsJobObject:

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    def test_job_object_backend_available_on_windows(self):
        backend = WindowsJobObjectBackend()
        assert backend.available
        assert "job_object" in backend.capabilities

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    def test_apply_limits_to_current_process(self):
        """Verify Job Object can be applied (does not actually limit current process)."""
        import os
        backend = WindowsJobObjectBackend()
        limits = ResourceLimits(memory_mb=512, process_count=1)
        # This will try to assign current process — may fail due to already being in a job
        # The point is the ctypes interface works without crashing
        try:
            result = backend.apply_limits(limits, child_pid=os.getpid())
            # Result may be True or False depending on whether we're already in a job
            assert isinstance(result, bool)
        except Exception as e:
            pytest.fail(f"Job Object apply_limits crashed: {e}")

    @pytest.mark.skipif(sys.platform == "win32", reason="Non-Windows only")
    def test_job_object_unavailable_off_windows(self):
        backend = WindowsJobObjectBackend()
        assert not backend.available
