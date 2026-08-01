"""Tests for Linux seccomp profile — v1.2.0.

AC1: SeccompProfile model exists with deny list.
AC2: SeccompBackend detects availability correctly.
AC3: seccomp_available/seccomp_enforced/seccomp_profile_name in capabilities.
AC4: SeccompBackend.apply_profile returns False when unavailable.
AC5: INV-007 fires when capability claimed but not enforced.
AC6: Seccomp tests skip cleanly on non-Linux.
AC7: Default deny list includes dangerous syscalls.
AC8: Existing 1294 tests remain green.
"""

import sys
import pytest

from nodechain.sdk.seccomp_profile import (
    SeccompProfile,
    SeccompBackend,
    detect_seccomp,
    DEFAULT_DENY_SYSCALLS,
)
from nodechain.sdk.os_sandbox import SandboxCapabilities
from nodechain.sdk.trust_summary import (
    TrustSummary,
    NodeTrustRecord,
)


# ── 1. SeccompProfile Model ───────────────────────────────────────

class TestSeccompProfile:

    def test_default_profile_name(self):
        p = SeccompProfile()
        assert p.name == "nodechain_default"

    def test_default_deny_list_has_dangerous_syscalls(self):
        """AC7: Default deny list includes dangerous syscalls."""
        p = SeccompProfile()
        assert "fork" in p.deny_syscalls
        assert "clone" in p.deny_syscalls
        assert "ptrace" in p.deny_syscalls
        assert "mount" in p.deny_syscalls
        assert "reboot" in p.deny_syscalls
        assert "kexec_load" in p.deny_syscalls
        assert "init_module" in p.deny_syscalls
        assert "unshare" in p.deny_syscalls
        assert "bpf" in p.deny_syscalls

    def test_custom_profile(self):
        p = SeccompProfile(
            name="strict",
            deny_syscalls=["fork", "execve"],
            deny_action="ERRNO",
        )
        assert p.name == "strict"
        assert "execve" in p.deny_syscalls
        assert p.deny_action == "ERRNO"

    def test_to_dict(self):
        p = SeccompProfile(name="custom")
        d = p.to_dict()
        assert d["name"] == "custom"
        assert "deny_syscalls" in d
        assert "default_action" in d
        assert "deny_action" in d

    def test_default_deny_list_is_immutable_copy(self):
        """Each profile gets its own copy of the deny list."""
        p1 = SeccompProfile()
        p2 = SeccompProfile()
        p1.deny_syscalls.append("custom_syscall")
        assert "custom_syscall" not in p2.deny_syscalls


# ── 2. SeccompBackend Detection ───────────────────────────────────

class TestSeccompBackend:
    """AC2: SeccompBackend detects availability correctly."""

    def test_backend_returns_bool_for_available(self):
        backend = SeccompBackend()
        assert isinstance(backend.available, bool)

    def test_backend_platform(self):
        backend = SeccompBackend()
        if sys.platform.startswith("linux"):
            assert backend.platform == "linux"
        else:
            assert backend.platform != "linux"

    def test_detect_seccomp_returns_backend(self):
        backend = detect_seccomp()
        assert isinstance(backend, SeccompBackend)

    def test_unavailable_on_windows(self):
        """AC6: Seccomp reports unavailable on non-Linux."""
        if sys.platform == "win32":
            backend = SeccompBackend()
            assert backend.available is False

    def test_get_capabilities_structure(self):
        backend = SeccompBackend()
        caps = backend.get_capabilities()
        assert "seccomp_available" in caps
        assert "seccomp_platform" in caps


# ── 3. SeccompBackend Apply Profile ───────────────────────────────

class TestSeccompApply:
    """AC4: apply_profile returns False when unavailable."""

    def test_apply_returns_false_when_unavailable(self):
        backend = SeccompBackend()
        if not backend.available:
            profile = SeccompProfile()
            assert backend.apply_profile(profile) is False

    def test_describe_structure(self):
        backend = SeccompBackend()
        desc = backend.describe()
        assert desc["backend"] == "seccomp"
        assert "available" in desc
        assert "capabilities" in desc


# ── 4. SandboxCapabilities Seccomp Fields ─────────────────────────

class TestSandboxCapabilitiesSeccomp:
    """AC3: seccomp fields in capabilities."""

    def test_capabilities_has_seccomp_available(self):
        caps = SandboxCapabilities()
        assert hasattr(caps, "seccomp_available")
        assert caps.seccomp_available is False  # Default

    def test_capabilities_has_seccomp_enforced(self):
        caps = SandboxCapabilities()
        assert hasattr(caps, "seccomp_enforced")
        assert caps.seccomp_enforced is False  # Default

    def test_capabilities_has_seccomp_profile_name(self):
        caps = SandboxCapabilities()
        assert hasattr(caps, "seccomp_profile_name")
        assert caps.seccomp_profile_name == ""  # Default

    def test_to_dict_includes_seccomp_fields(self):
        caps = SandboxCapabilities(
            seccomp_available=True,
            seccomp_enforced=True,
            seccomp_profile_name="nodechain_default",
        )
        d = caps.to_dict()
        assert d["seccomp_available"] is True
        assert d["seccomp_enforced"] is True
        assert d["seccomp_profile_name"] == "nodechain_default"


# ── 5. INV-007 Trust Invariant ────────────────────────────────────

class TestINV007:
    """AC5: INV-007 fires when capability claimed but not enforced."""

    def test_inv007_fires_on_empty_backend(self):
        """OS profile claimed but sandbox_backend is empty."""
        summary = TrustSummary(run_id="t")
        summary.add_node(NodeTrustRecord(
            node_id="bad",
            trust_level="local_untrusted",
            isolation_mode="subprocess",
            child_policy_enforced=True,
            env_filtered=True,
            temp_dir_isolated=True,
            sandbox_profile_required="os_profile",
            sandbox_profile_used="os_profile",
            os_sandbox_enforced=True,
            sandbox_backend="",  # Empty backend — claim without evidence
        ))
        violations = summary.validate_invariants(strict=True)
        codes = [v.code for v in violations]
        assert "INV-007" in codes

    def test_inv007_fires_on_none_backend(self):
        """OS profile claimed but sandbox_backend is 'none'."""
        summary = TrustSummary(run_id="t")
        summary.add_node(NodeTrustRecord(
            node_id="bad",
            trust_level="local_untrusted",
            isolation_mode="subprocess",
            child_policy_enforced=True,
            env_filtered=True,
            temp_dir_isolated=True,
            sandbox_profile_required="os_profile",
            sandbox_profile_used="os_profile",
            os_sandbox_enforced=True,
            sandbox_backend="none",
        ))
        violations = summary.validate_invariants(strict=True)
        codes = [v.code for v in violations]
        assert "INV-007" in codes

    def test_inv007_passes_with_real_backend(self):
        """No violation when backend is set to a real name."""
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
            sandbox_backend="linux_rlimit",
            syscall_filtering_enforced=True,  # v1.2.3: required for os_profile on Linux
        ))
        violations = summary.validate_invariants(strict=True)
        inv007 = [v for v in violations if v.code == "INV-007"]
        assert len(inv007) == 0

    def test_inv007_passes_without_os_profile(self):
        """No INV-007 when not using os_profile."""
        summary = TrustSummary(run_id="t")
        summary.add_node(NodeTrustRecord(
            node_id="basic",
            trust_level="built_in",
            isolation_mode="in_process",
        ))
        violations = summary.validate_invariants(strict=True)
        assert all(v.code != "INV-007" for v in violations)

    def test_inv007_violation_structure(self):
        summary = TrustSummary(run_id="t")
        summary.add_node(NodeTrustRecord(
            node_id="node1",
            trust_level="local_untrusted",
            isolation_mode="subprocess",
            child_policy_enforced=True,
            env_filtered=True,
            temp_dir_isolated=True,
            sandbox_profile_used="os_profile",
            os_sandbox_enforced=True,
            sandbox_backend="",
        ))
        violations = summary.validate_invariants(strict=True)
        inv7 = [v for v in violations if v.code == "INV-007"][0]
        assert inv7.invariant == "required_sandbox_capability_must_be_enforced"
        assert inv7.node_id == "node1"


# ── 6. Platform-Specific Behavior ─────────────────────────────────

class TestPlatformBehavior:
    """AC6: Clean behavior on all platforms."""

    def test_seccomp_backend_does_not_crash(self):
        """SeccompBackend constructor never crashes on any platform."""
        backend = SeccompBackend()
        # Just constructing it should work
        assert backend is not None

    def test_apply_does_not_crash(self):
        """apply_profile never crashes on any platform.

        On Linux where seccomp is available, we apply in a subprocess
        because seccomp filters are irrevocable — applying to the test
        process would kill it when later tests use fork/clone.
        """
        backend = SeccompBackend()
        profile = SeccompProfile()

        if backend.available:
            # Apply in a subprocess to protect the test process
            import subprocess as _sp
            import sys as _sys
            code = (
                "from nodechain.sdk.seccomp_profile import SeccompBackend, SeccompProfile; "
                "b = SeccompBackend(); p = SeccompProfile(); "
                "import sys; sys.exit(0 if b.apply_profile(p) else 1)"
            )
            result = _sp.run([_sys.executable, "-c", code], capture_output=True)
            assert result.returncode in (0, 1)  # 0=applied, 1=returned False
        else:
            result = backend.apply_profile(profile)
            assert isinstance(result, bool)

    @pytest.mark.skipif(
        not sys.platform.startswith("linux"),
        reason="Linux only"
    )
    def test_linux_detects_seccomp_correctly(self):
        """On Linux, seccomp is either available or not, but detection works."""
        backend = SeccompBackend()
        # The test doesn't assert availability — just that detection works
        caps = backend.get_capabilities()
        assert caps["seccomp_available"] == backend.available


# ── 7. Default Deny List Completeness ─────────────────────────────

class TestDenyListCompleteness:

    def test_deny_list_includes_process_creation(self):
        assert "fork" in DEFAULT_DENY_SYSCALLS
        assert "clone" in DEFAULT_DENY_SYSCALLS
        assert "vfork" in DEFAULT_DENY_SYSCALLS

    def test_deny_list_includes_namespace_syscalls(self):
        assert "unshare" in DEFAULT_DENY_SYSCALLS
        assert "setns" in DEFAULT_DENY_SYSCALLS

    def test_deny_list_includes_kernel_module_syscalls(self):
        assert "init_module" in DEFAULT_DENY_SYSCALLS
        assert "finit_module" in DEFAULT_DENY_SYSCALLS
        assert "delete_module" in DEFAULT_DENY_SYSCALLS

    def test_deny_list_includes_debugging(self):
        assert "ptrace" in DEFAULT_DENY_SYSCALLS

    def test_deny_list_includes_ebpf(self):
        assert "bpf" in DEFAULT_DENY_SYSCALLS

    def test_deny_list_includes_mount(self):
        assert "mount" in DEFAULT_DENY_SYSCALLS
        assert "umount2" in DEFAULT_DENY_SYSCALLS
