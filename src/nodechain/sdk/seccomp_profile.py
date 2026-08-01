"""Seccomp profile support for Linux sandbox — v1.2.0.

Optional syscall filtering for untrusted node execution on Linux.

This module provides:
- SeccompProfile: declarative syscall filter definition
- SeccompBackend: applies the filter via the `seccomp` Python library
- Capability detection: reports whether seccomp is available and enforced

On non-Linux platforms or without the `seccomp` library, all methods
return False and report seccomp_available=False.

Install on Linux:
    pip install seccomp  (or pyseccomp)

Default deny list for untrusted nodes:
    fork, clone (process creation — already Python-level enforced)
    ptrace (debugging)
    mount, umount (filesystem namespace)
    reboot
    kexec_load
    init_module, finit_module, delete_module (kernel modules)
    setns (namespace entry)
    unshare (namespace creation)
    perf_event_open (performance monitoring)
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Any


# Default syscalls denied for untrusted nodes
DEFAULT_DENY_SYSCALLS: list[str] = [
    "fork",
    "vfork",
    "clone",
    "clone3",
    "ptrace",
    "mount",
    "umount2",
    "reboot",
    "kexec_load",
    "kexec_file_load",
    "init_module",
    "finit_module",
    "delete_module",
    "setns",
    "unshare",
    "perf_event_open",
    "bpf",
    "userfaultfd",
    "mbind",
    "migrate_pages",
    "move_pages",
]


@dataclass
class SeccompProfile:
    """Declarative seccomp profile definition.

    Attributes:
        name: Profile name for identification.
        deny_syscalls: List of syscall names to deny.
        allow_syscalls: List of syscall names to explicitly allow.
        default_action: Default action when syscall not in deny list.
        deny_action: Action to take for denied syscalls.
    """

    name: str = "nodechain_default"
    deny_syscalls: list[str] = field(default_factory=lambda: list(DEFAULT_DENY_SYSCALLS))
    allow_syscalls: list[str] = field(default_factory=list)
    default_action: str = "ALLOW"  # ALLOW or KILL
    deny_action: str = "KILL"      # KILL, TRAP, ERRNO

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "deny_syscalls": list(self.deny_syscalls),
            "allow_syscalls": list(self.allow_syscalls),
            "default_action": self.default_action,
            "deny_action": self.deny_action,
        }


class SeccompBackend:
    """Seccomp backend for Linux syscall filtering.

    Detects whether the `seccomp` Python library is available and
    applies seccomp filters when requested.

    On non-Linux platforms or without the library, all operations
    return False and report availability as False.
    """

    def __init__(self) -> None:
        self._available = False
        self._library = None

        if sys.platform.startswith("linux"):
            try:
                import seccomp as _seccomp  # noqa: F401
                self._library = _seccomp
                self._available = True
            except ImportError:
                # Try alternative package name
                try:
                    import pyseccomp as _seccomp  # noqa: F401
                    self._library = _seccomp
                    self._available = True
                except ImportError:
                    self._available = False

    @property
    def available(self) -> bool:
        """Whether seccomp is available on this platform."""
        return self._available

    @property
    def platform(self) -> str:
        return "linux" if sys.platform.startswith("linux") else sys.platform

    def get_capabilities(self) -> dict[str, Any]:
        """Report seccomp capabilities."""
        return {
            "seccomp_available": self._available,
            "seccomp_platform": self.platform,
            "seccomp_library": "seccomp" if self._available else None,
        }

    def apply_profile(
        self,
        profile: SeccompProfile,
        child_pid: int | None = None,
    ) -> bool:
        """Apply a seccomp profile to a process.

        Args:
            profile: The seccomp profile to apply.
            child_pid: If provided, apply to child process.
                       If None, apply to current process.

        Returns:
            True if the profile was applied, False otherwise.

        Note:
            In v1.2.0, this only applies to the current process.
            Applying to a child requires ptrace (which we deny).
        """
        if not self._available or self._library is None:
            return False

        try:
            seccomp = self._library

            # Create a seccomp filter with positional arg
            f = seccomp.SyscallFilter(seccomp.ALLOW)

            # Add deny rules — pyseccomp accepts syscall names as strings
            for syscall_name in profile.deny_syscalls:
                try:
                    if profile.deny_action == "KILL":
                        f.add_rule(seccomp.KILL, syscall_name)
                    elif profile.deny_action == "ERRNO":
                        f.add_rule(seccomp.ERRNO(1), syscall_name)
                    else:
                        f.add_rule(seccomp.KILL, syscall_name)
                except (AttributeError, ValueError, TypeError):
                    # Unknown syscall — skip it
                    pass

            # Apply the filter
            f.load()
            return True

        except Exception:
            return False

    def describe(self) -> dict[str, Any]:
        """Describe this backend's capabilities."""
        return {
            "backend": "seccomp",
            "available": self._available,
            "platform": self.platform,
            "capabilities": self.get_capabilities(),
        }


def detect_seccomp() -> SeccompBackend:
    """Detect and return the seccomp backend."""
    return SeccompBackend()
