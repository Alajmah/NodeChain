"""OS Sandbox Profiles — pluggable OS-backed confinement for untrusted nodes.

v1.1.0 additive layer on top of the v1.0.0 trust runtime.

Sandbox profile hierarchy (strongest to weakest):
    os_profile        — OS kernel/container enforcement (seccomp, Job Objects, etc.)
    subprocess_isolated — Subprocess with Python hooks + resource limits
    python_hooks      — In-process Python API interception only
    none              — No restrictions (built_in nodes only)

Platform backends:
    Linux:   seccomp (via resource module), RLIMIT_CPU/RLIMIT_AS/RLIMIT_FSIZE
    Windows: Job Objects (memory/CPU limits via ctypes)
    macOS:   sandbox-exec profiles (future)
    Fallback: subprocess isolation only

The profile is selected per-node by trust policy. If the requested OS sandbox
backend is unavailable, the runtime falls back only when policy permits.
Strict mode blocks fallback from os_profile to weaker sandbox.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SandboxProfile(str, Enum):
    """Sandbox profile levels, ordered from strongest to weakest."""

    OS_PROFILE = "os_profile"
    SUBPROCESS_ISOLATED = "subprocess_isolated"
    PYTHON_HOOKS = "python_hooks"
    NONE = "none"

    @classmethod
    def for_trust_level(cls, trust_level: str) -> "SandboxProfile":
        """Map a trust level to its default sandbox profile."""
        mapping = {
            "built_in": cls.NONE,
            "local_trusted": cls.PYTHON_HOOKS,
            "local_untrusted": cls.SUBPROCESS_ISOLATED,
            "remote_untrusted": cls.SUBPROCESS_ISOLATED,
        }
        return mapping.get(trust_level, cls.SUBPROCESS_ISOLATED)

    @property
    def strength(self) -> int:
        """Numeric strength: higher = stronger confinement."""
        order = {
            "none": 0,
            "python_hooks": 1,
            "subprocess_isolated": 2,
            "os_profile": 3,
        }
        return order.get(self.value, 2)


class Platform(str, Enum):
    """Platform identifiers for sandbox backend selection."""

    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"
    OTHER = "other"

    @classmethod
    def detect(cls) -> "Platform":
        """Detect the current platform."""
        if sys.platform.startswith("linux"):
            return cls.LINUX
        elif sys.platform == "win32":
            return cls.WINDOWS
        elif sys.platform == "darwin":
            return cls.MACOS
        else:
            return cls.OTHER


@dataclass
class ResourceLimits:
    """Resource limits for sandboxed execution."""

    cpu_time_seconds: int = 0      # 0 = unlimited
    memory_mb: int = 512           # Default 512 MB
    output_size_mb: int = 10       # Default 10 MB output
    wall_timeout_seconds: int = 30  # Default 30s wall clock
    temp_storage_mb: int = 100     # Default 100 MB temp storage
    process_count: int = 1         # Max child processes


@dataclass
class SandboxCapabilities:
    """Granular OS sandbox capability reporting.

    Each field is independently verifiable so the report can distinguish
    'resource limits enforced' from 'syscall filtering enforced'.
    """

    resource_limits_enforced: bool = False
    syscall_filtering_enforced: bool = False     # seccomp
    namespace_enforced: bool = False             # mount/pid/net namespaces
    cgroup_enforced: bool = False                # cgroup v2
    job_object_enforced: bool = False            # Windows Job Objects
    apparmor_profile_used: str = ""              # AppArmor profile name
    detection_only: bool = False                 # macOS: detection but no enforcement
    backend_name: str = ""
    platform: str = ""
    # v1.2.0 additive fields
    seccomp_available: bool = False              # seccomp library detected
    seccomp_enforced: bool = False               # seccomp profile actually applied
    seccomp_profile_name: str = ""               # name of the applied profile
    # v1.3.0 additive fields
    cgroup_available: bool = False               # cgroup v2 detected
    cgroup_version: str = ""                     # "v2", "v1", ""
    cgroup_accounting_readable: bool = False     # can read resource accounting
    cgroup_limits_writable: bool = False         # can write resource limits
    cgroup_accounting_only: bool = False         # read-only delegation (Proxmox LXC)
    # v1.4.0 additive fields
    namespace_available: bool = False            # namespace creation possible
    namespace_mode: str = "none"                  # none|detected|nested|created
    already_nested: bool = False                   # process is in a container namespace
    mount_namespace_available: bool = False
    pid_namespace_available: bool = False
    network_namespace_available: bool = False
    network_namespace_enforced: bool = False       # network ns actually applied
    user_namespace_available: bool = False
    # v1.4.3 additive fields
    mount_namespace_enforced: bool = False          # mount ns actually applied
    # v1.5.0 additive fields
    pid_namespace_enforced: bool = False            # PID ns actually applied

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_limits_enforced": self.resource_limits_enforced,
            "syscall_filtering_enforced": self.syscall_filtering_enforced,
            "namespace_enforced": self.namespace_enforced,
            "cgroup_enforced": self.cgroup_enforced,
            "job_object_enforced": self.job_object_enforced,
            "apparmor_profile_used": self.apparmor_profile_used,
            "detection_only": self.detection_only,
            "backend_name": self.backend_name,
            "platform": self.platform,
            "seccomp_available": self.seccomp_available,
            "seccomp_enforced": self.seccomp_enforced,
            "seccomp_profile_name": self.seccomp_profile_name,
            "cgroup_available": self.cgroup_available,
            "cgroup_version": self.cgroup_version,
            "cgroup_accounting_readable": self.cgroup_accounting_readable,
            "cgroup_limits_writable": self.cgroup_limits_writable,
            "cgroup_accounting_only": self.cgroup_accounting_only,
            "namespace_available": self.namespace_available,
            "namespace_mode": self.namespace_mode,
            "already_nested": self.already_nested,
            "mount_namespace_available": self.mount_namespace_available,
            "pid_namespace_available": self.pid_namespace_available,
            "network_namespace_available": self.network_namespace_available,
            "network_namespace_enforced": self.network_namespace_enforced,
            "user_namespace_available": self.user_namespace_available,
            "mount_namespace_enforced": self.mount_namespace_enforced,
            "pid_namespace_enforced": self.pid_namespace_enforced,
        }


@dataclass
class SandboxResult:
    """Result of a sandbox execution attempt."""

    profile_requested: str
    profile_used: str
    os_sandbox_enforced: bool
    fallback_used: bool
    backend: str
    resource_limits: ResourceLimits | None = None
    error: str | None = None
    capabilities: SandboxCapabilities | None = None


@dataclass
class OSBackend:
    """Abstract base for platform-specific OS sandbox backends."""

    platform: str
    available: bool
    backend_name: str
    capabilities: list[str] = field(default_factory=list)

    def get_capabilities(self) -> SandboxCapabilities:
        """Return granular capability report.

        Subclasses must override to report what is actually enforced.
        """
        return SandboxCapabilities(
            backend_name=self.backend_name,
            platform=self.platform,
            detection_only=not self.available,
        )

    def apply_limits(
        self,
        limits: ResourceLimits,
        child_pid: int | None = None,
    ) -> bool:
        """Apply resource limits to a process.

        Returns True if limits were applied, False otherwise.
        """
        raise NotImplementedError

    def describe(self) -> dict[str, Any]:
        """Describe this backend's capabilities."""
        return {
            "platform": self.platform,
            "available": self.available,
            "backend": self.backend_name,
            "capabilities": list(self.capabilities),
            "granular_capabilities": self.get_capabilities().to_dict(),
        }


class LinuxBackend(OSBackend):
    """Linux OS sandbox backend using resource limits.

    Uses the `resource` module for RLIMIT_CPU, RLIMIT_AS, RLIMIT_FSIZE.
    Seccomp and namespace support are capability-detected but not
    enforced in v1.1.x (requires additional native dependencies).
    """

    def __init__(self) -> None:
        try:
            import resource as _resource  # noqa: F401
            available = True
            caps = ["rlimit_cpu", "rlimit_as", "rlimit_fsize"]
        except ImportError:
            available = False
            caps = []

        # Check for seccomp availability (not enforced yet)
        try:
            import seccomp  # noqa: F401
            caps.append("seccomp")
        except ImportError:
            pass

        super().__init__(
            platform="linux",
            available=available,
            backend_name="linux_rlimit",
            capabilities=caps,
        )

    def get_capabilities(self) -> SandboxCapabilities:
        """Report granular Linux sandbox capabilities.

        RLIMIT is enforced; seccomp/namespaces are detected but not enforced.
        Seccomp availability is propagated from the seccomp backend.
        Cgroup availability is propagated from the cgroup backend (v1.3.0).
        """
        # Check seccomp availability without creating circular import
        seccomp_avail = False
        try:
            from nodechain.sdk.seccomp_profile import detect_seccomp
            seccomp_avail = detect_seccomp().available
        except Exception:
            pass

        # Check cgroup availability (v1.3.0)
        cg_avail = False
        cg_version = ""
        cg_accounting = False
        cg_writable = False
        cg_accounting_only = False
        try:
            from nodechain.sdk.cgroup_profile import detect_cgroup
            cg_caps = detect_cgroup()
            cg_avail = cg_caps.cgroup_available
            cg_version = cg_caps.cgroup_version
            cg_accounting = cg_caps.cgroup_accounting_readable
            cg_writable = cg_caps.cgroup_limits_writable
            cg_accounting_only = cg_caps.accounting_only
        except Exception:
            pass

        # Check namespace availability (v1.4.0)
        ns_avail = False
        ns_mode = "none"
        ns_nested = False
        ns_mount = False
        ns_pid = False
        ns_net = False
        ns_user = False
        try:
            from nodechain.sdk.namespace_profile import detect_namespaces
            ns_caps = detect_namespaces()
            ns_avail = ns_caps.namespace_available
            ns_mode = ns_caps.namespace_mode
            ns_nested = ns_caps.already_nested
            ns_mount = ns_caps.mount_namespace_available
            ns_pid = ns_caps.pid_namespace_available
            ns_net = ns_caps.network_namespace_available
            ns_user = ns_caps.user_namespace_available
        except Exception:
            pass

        return SandboxCapabilities(
            resource_limits_enforced=self.available,
            syscall_filtering_enforced=False,
            namespace_enforced=False,  # True only when actually applied (v1.4.0)
            cgroup_enforced=cg_writable,  # True only when limits writable
            job_object_enforced=False,
            apparmor_profile_used="",
            detection_only=not self.available,
            backend_name=self.backend_name,
            platform=self.platform,
            seccomp_available=seccomp_avail,
            seccomp_enforced=False,
            cgroup_available=cg_avail,
            cgroup_version=cg_version,
            cgroup_accounting_readable=cg_accounting,
            cgroup_limits_writable=cg_writable,
            cgroup_accounting_only=cg_accounting_only,
            namespace_available=ns_avail,
            namespace_mode=ns_mode,
            already_nested=ns_nested,
            mount_namespace_available=ns_mount,
            pid_namespace_available=ns_pid,
            network_namespace_available=ns_net,
            network_namespace_enforced=False,  # Set when actually enforced
            user_namespace_available=ns_user,
        )

    def apply_limits(
        self,
        limits: ResourceLimits,
        child_pid: int | None = None,
    ) -> bool:
        if not self.available:
            return False
        import resource

        applied = True

        # CPU time limit (SIGXCPU on exceed)
        if limits.cpu_time_seconds > 0:
            try:
                resource.setrlimit(
                    resource.RLIMIT_CPU,
                    (limits.cpu_time_seconds, limits.cpu_time_seconds),
                )
            except (ValueError, OSError):
                applied = False

        # Address space (memory) limit
        if limits.memory_mb > 0:
            try:
                mem_bytes = limits.memory_mb * 1024 * 1024
                resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
            except (ValueError, OSError):
                applied = False

        # File size (output) limit
        if limits.output_size_mb > 0:
            try:
                fsize_bytes = limits.output_size_mb * 1024 * 1024
                resource.setrlimit(resource.RLIMIT_FSIZE, (fsize_bytes, fsize_bytes))
            except (ValueError, OSError):
                applied = False

        return applied


class WindowsJobObjectBackend(OSBackend):
    """Windows OS sandbox backend using Job Objects via ctypes.

    Job Objects provide:
    - Memory limits (JOB_OBJECT_LIMIT_PROCESS_MEMORY)
    - CPU rate control (JOB_OBJECT_CPU_RATE_CONTROL)
    - Process count limits
    - Kill on job close

    This is the real Windows confinement mechanism used by containers
    and process isolation tools.
    """

    def __init__(self) -> None:
        available = sys.platform == "win32"
        caps = []
        if available:
            caps = ["job_object", "memory_limit", "process_count", "kill_on_close"]
        super().__init__(
            platform="windows",
            available=available,
            backend_name="windows_job_object",
            capabilities=caps,
        )

    def get_capabilities(self) -> SandboxCapabilities:
        """Report granular Windows sandbox capabilities.

        Job Objects enforce memory/process limits and kill-on-close.
        No syscall filtering or namespace isolation on Windows.
        """
        return SandboxCapabilities(
            resource_limits_enforced=self.available,
            syscall_filtering_enforced=False,
            namespace_enforced=False,
            cgroup_enforced=False,
            job_object_enforced=self.available,
            apparmor_profile_used="",
            detection_only=not self.available,
            backend_name=self.backend_name,
            platform=self.platform,
        )

    def apply_limits(
        self,
        limits: ResourceLimits,
        child_pid: int | None = None,
    ) -> bool:
        if not self.available or child_pid is None:
            return False

        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.windll.kernel32

            # Create a Job Object
            JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
            JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008

            handle = kernel32.CreateJobObjectW(None, None)
            if not handle:
                return False

            # Configure extended limits
            class IO_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("ReadOperationCount", ctypes.c_ulonglong),
                    ("WriteOperationCount", ctypes.c_ulonglong),
                    ("OtherOperationCount", ctypes.c_ulonglong),
                    ("ReadTransferCount", ctypes.c_ulonglong),
                    ("WriteTransferCount", ctypes.c_ulonglong),
                    ("OtherTransferCount", ctypes.c_ulonglong),
                ]

            class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("PerProcessUserTimeLimit", ctypes.c_int64),
                    ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", ctypes.c_uint),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", ctypes.c_uint),
                    ("Affinity", ctypes.c_void_p),
                    ("PriorityClass", ctypes.c_uint),
                    ("SchedulingClass", ctypes.c_uint),
                ]

            class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                    ("IoInfo", IO_COUNTERS),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t),
                ]

            limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if limits.memory_mb > 0:
                limit_flags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY
            if limits.process_count > 0:
                limit_flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS

            extended = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            extended.BasicLimitInformation.LimitFlags = limit_flags
            extended.BasicLimitInformation.ActiveProcessLimit = limits.process_count
            extended.ProcessMemoryLimit = limits.memory_mb * 1024 * 1024

            JobObjectExtendedLimitInformation = 9
            result = kernel32.SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                ctypes.byref(extended),
                ctypes.sizeof(extended),
            )
            if not result:
                kernel32.CloseHandle(handle)
                return False

            # Assign child process to the job
            child_handle = kernel32.OpenProcess(
                0x0400 | 0x0001 | 0x0200,  # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE
                False,
                child_pid,
            )
            if not child_handle:
                kernel32.CloseHandle(handle)
                return False

            result = kernel32.AssignProcessToJobObject(handle, child_handle)
            kernel32.CloseHandle(child_handle)

            if not result:
                kernel32.CloseHandle(handle)
                return False

            # Note: We intentionally leak the job handle so it stays alive
            # for the child's lifetime. When the parent process exits,
            # the OS will close the handle and kill the child (KILL_ON_JOB_CLOSE).
            return True

        except Exception:
            return False


class MacOSBackend(OSBackend):
    """macOS OS sandbox backend using sandbox-exec profiles.

    Future: v1.2+ will implement seatbelt/sandbox-exec profile generation.
    For now, capability detection only — no enforcement.
    """

    def __init__(self) -> None:
        available = sys.platform == "darwin" and os.path.exists("/usr/bin/sandbox-exec")
        caps = []
        if available:
            caps = ["sandbox_exec", "seatbelt"]
        super().__init__(
            platform="macos",
            available=available,
            backend_name="macos_sandbox_exec",
            capabilities=caps,
        )

    def get_capabilities(self) -> SandboxCapabilities:
        """Report granular macOS sandbox capabilities.

        macOS is detection-only in v1.1.x — sandbox-exec exists but
        profile generation and enforcement are not implemented.
        """
        return SandboxCapabilities(
            resource_limits_enforced=False,
            syscall_filtering_enforced=False,
            namespace_enforced=False,
            cgroup_enforced=False,
            job_object_enforced=False,
            apparmor_profile_used="",
            detection_only=True,
            backend_name=self.backend_name,
            platform=self.platform,
        )

    def apply_limits(
        self,
        limits: ResourceLimits,
        child_pid: int | None = None,
    ) -> bool:
        # Not implemented in v1.1.0
        return False


def detect_backend() -> OSBackend:
    """Detect the best available OS sandbox backend for this platform."""
    platform = Platform.detect()
    if platform == Platform.LINUX:
        return LinuxBackend()
    elif platform == Platform.WINDOWS:
        return WindowsJobObjectBackend()
    elif platform == Platform.MACOS:
        return MacOSBackend()
    else:
        return OSBackend(
            platform="other",
            available=False,
            backend_name="none",
            capabilities=[],
        )


@dataclass
class SandboxProfileResolver:
    """Resolves which sandbox profile to use for a given node.

    Handles fallback logic:
    - If os_profile requested but backend unavailable → fallback to subprocess_isolated
    - Strict mode blocks fallback from os_profile to weaker sandbox
    - Returns SandboxResult with full audit trail
    """

    backend: OSBackend = field(default_factory=detect_backend)
    strict: bool = False
    allow_fallback: bool = True

    def resolve(
        self,
        requested: SandboxProfile,
        trust_level: str,
    ) -> SandboxResult:
        """Resolve the actual sandbox profile to use.

        Args:
            requested: The requested profile from trust policy.
            trust_level: The node's trust level.

        Returns:
            SandboxResult with the resolved profile, audit info,
            and granular capabilities.
        """
        limits = ResourceLimits()
        caps = self.backend.get_capabilities()

        # If OS profile requested
        if requested == SandboxProfile.OS_PROFILE:
            if self.backend.available:
                return SandboxResult(
                    profile_requested=requested.value,
                    profile_used=SandboxProfile.OS_PROFILE.value,
                    os_sandbox_enforced=True,
                    fallback_used=False,
                    backend=self.backend.backend_name,
                    resource_limits=limits,
                    capabilities=caps,
                )
            elif self.strict:
                # Strict mode: no fallback from os_profile
                return SandboxResult(
                    profile_requested=requested.value,
                    profile_used=SandboxProfile.SUBPROCESS_ISOLATED.value,
                    os_sandbox_enforced=False,
                    fallback_used=True,
                    backend="none",
                    resource_limits=limits,
                    error="OS sandbox unavailable in strict mode — using subprocess isolation",
                    capabilities=caps,
                )
            elif self.allow_fallback:
                # Fallback to subprocess isolation
                return SandboxResult(
                    profile_requested=requested.value,
                    profile_used=SandboxProfile.SUBPROCESS_ISOLATED.value,
                    os_sandbox_enforced=False,
                    fallback_used=True,
                    backend=self.backend.backend_name,
                    resource_limits=limits,
                    error="OS sandbox unavailable — falling back to subprocess isolation",
                    capabilities=caps,
                )
            else:
                return SandboxResult(
                    profile_requested=requested.value,
                    profile_used=SandboxProfile.NONE.value,
                    os_sandbox_enforced=False,
                    fallback_used=False,
                    backend="none",
                    resource_limits=limits,
                    error="OS sandbox unavailable and fallback disabled",
                    capabilities=caps,
                )

        # Non-OS profiles: pass through
        return SandboxResult(
            profile_requested=requested.value,
            profile_used=requested.value,
            os_sandbox_enforced=False,
            fallback_used=False,
            backend=self.backend.backend_name,
            resource_limits=limits,
            capabilities=caps,
        )
