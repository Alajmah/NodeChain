"""Cgroup v2 resource accounting and limit reporting.

Detects cgroup v2 on Linux, reads resource accounting files, and
optionally applies resource limits to child cgroups.

Capability levels (honest reporting):
  - detected:          cgroup v2 filesystem exists
  - accounting readable: memory.current, cpu.stat, pids.current readable
  - limits writable:   can create child cgroups and write memory.max etc.
  - limits enforced:   a child cgroup with limits is active

On Proxmox LXC, these may be partial. We report each independently.
"""

from __future__ import annotations

import os
import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CGROUP_FS = "/sys/fs/cgroup"


@dataclass
class CgroupAccounting:
    """Resource accounting snapshot from cgroup v2 files."""

    memory_current_bytes: int = 0
    memory_peak_bytes: int = 0
    memory_max_bytes: int = 0  # 0 = "max" (unlimited)
    cpu_usage_usec: int = 0
    cpu_user_usec: int = 0
    cpu_system_usec: int = 0
    # v1.3.3: throttling stats from cpu.stat
    cpu_nr_periods: int = 0
    cpu_nr_throttled: int = 0
    cpu_throttled_usec: int = 0
    pids_current: int = 0
    pids_peak: int = 0
    pids_max: int = 0  # 0 = "max" (unlimited)
    # v1.3.3: OOM event detection from memory.events
    oom_events: int = 0
    oom_kill_events: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "memory_current_bytes": self.memory_current_bytes,
            "memory_peak_bytes": self.memory_peak_bytes,
            "memory_max_bytes": self.memory_max_bytes,
            "cpu_usage_usec": self.cpu_usage_usec,
            "cpu_user_usec": self.cpu_user_usec,
            "cpu_system_usec": self.cpu_system_usec,
            "cpu_nr_periods": self.cpu_nr_periods,
            "cpu_nr_throttled": self.cpu_nr_throttled,
            "cpu_throttled_usec": self.cpu_throttled_usec,
            "pids_current": self.pids_current,
            "pids_peak": self.pids_peak,
            "pids_max": self.pids_max,
            "oom_events": self.oom_events,
            "oom_kill_events": self.oom_kill_events,
        }


@dataclass
class CgroupCapabilities:
    """Cgroup v2 capability report — each field independently verifiable."""

    cgroup_available: bool = False
    cgroup_version: str = ""  # "v2", "v1", ""
    cgroup_accounting_readable: bool = False
    cgroup_limits_writable: bool = False
    cgroup_enforced: bool = False
    accounting_only: bool = False  # True when read-only (Proxmox LXC delegation)
    cgroup_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "cgroup_available": self.cgroup_available,
            "cgroup_version": self.cgroup_version,
            "cgroup_accounting_readable": self.cgroup_accounting_readable,
            "cgroup_limits_writable": self.cgroup_limits_writable,
            "cgroup_enforced": self.cgroup_enforced,
            "accounting_only": self.accounting_only,
            "cgroup_path": self.cgroup_path,
        }


def detect_cgroup() -> CgroupCapabilities:
    """Detect cgroup version and capabilities.

    Returns CgroupCapabilities with each field independently set.
    """
    caps = CgroupCapabilities()

    if platform.system() != "Linux":
        return caps

    cgroup_path = Path(CGROUP_FS)
    if not cgroup_path.exists():
        return caps

    # Check for cgroup v2 (unified hierarchy)
    controllers_file = cgroup_path / "cgroup.controllers"
    if controllers_file.exists():
        caps.cgroup_available = True
        caps.cgroup_version = "v2"
        # Resolve the process's actual cgroup path, not just the root
        resolved = _resolve_process_cgroup_v2()
        caps.cgroup_path = resolved or str(cgroup_path)
        detect_path = Path(caps.cgroup_path)

        # Check accounting readability
        accounting_files = [
            "memory.current", "memory.peak", "memory.max",
            "cpu.stat", "pids.current", "pids.peak", "pids.max",
        ]
        readable_count = 0
        for f in accounting_files:
            fp = detect_path / f
            if fp.exists() and os.access(fp, os.R_OK):
                readable_count += 1

        if readable_count >= 5:  # At least core accounting files
            caps.cgroup_accounting_readable = True

        # Check if we can create child cgroups (writable)
        caps.cgroup_limits_writable = _check_writable(detect_path)

        # If accounting readable but not writable, it's accounting_only
        if caps.cgroup_accounting_readable and not caps.cgroup_limits_writable:
            caps.accounting_only = True

    else:
        # Check for cgroup v1 (legacy hierarchy)
        v1_dirs = [d for d in cgroup_path.iterdir() if d.is_dir() and not d.name.startswith(".")]
        if v1_dirs:
            caps.cgroup_available = True
            caps.cgroup_version = "v1"
            caps.cgroup_path = str(cgroup_path)

    return caps


def _check_writable(cgroup_path: Path) -> bool:
    """Check if we can create child cgroups."""
    try:
        test_dir = cgroup_path / ".nodechain_write_test"
        test_dir.mkdir(exist_ok=True)
        # Try writing a limit
        memory_max = test_dir / "memory.max"
        if memory_max.exists():
            original = memory_max.read_text().strip()
            memory_max.write_text("1073741824")  # 1 GB
            memory_max.write_text(original)  # Restore
        test_dir.rmdir()
        return True
    except (PermissionError, OSError):
        return False


def _resolve_process_cgroup_v2() -> str | None:
    """Discover the current process's cgroup-v2 path from /proc/self/cgroup.

    Returns the absolute filesystem path under the cgroup v2 mount, or None
    if the process is not on cgroup v2 or the path cannot be determined.
    """
    proc_cgroup = Path("/proc/self/cgroup")
    if not proc_cgroup.exists():
        return None
    for line in proc_cgroup.read_text().splitlines():
        # cgroup v2 format: 0::<relative_path>
        if line.startswith("0::"):
            rel = line[3:].strip()
            if rel:
                return str(Path(CGROUP_FS) / rel.lstrip("/"))
            return CGROUP_FS
    return None


def read_accounting(cgroup_path: str | None = None) -> CgroupAccounting:
    """Read resource accounting from cgroup v2 files.

    Args:
        cgroup_path: Path to the cgroup directory to read from.
            If None, discovers the current process's cgroup-v2 path
            from /proc/self/cgroup. Falls back to CGROUP_FS if discovery
            fails.

    Returns:
        CgroupAccounting with current resource usage.
    """
    accounting = CgroupAccounting()
    if cgroup_path is None:
        cgroup_path = _resolve_process_cgroup_v2() or CGROUP_FS
    path = Path(cgroup_path)

    def _read_file(name: str) -> str | None:
        f = path / name
        if f.exists() and os.access(f, os.R_OK):
            return f.read_text().strip()
        return None

    # Memory
    val = _read_file("memory.current")
    if val and val.isdigit():
        accounting.memory_current_bytes = int(val)

    val = _read_file("memory.peak")
    if val and val.isdigit():
        accounting.memory_peak_bytes = int(val)

    val = _read_file("memory.max")
    if val:
        accounting.memory_max_bytes = 0 if val == "max" else (int(val) if val.isdigit() else 0)

    # CPU
    val = _read_file("cpu.stat")
    if val:
        for line in val.splitlines():
            parts = line.split()
            if len(parts) == 2:
                key, num = parts
                if key == "usage_usec" and num.isdigit():
                    accounting.cpu_usage_usec = int(num)
                elif key == "user_usec" and num.isdigit():
                    accounting.cpu_user_usec = int(num)
                elif key == "system_usec" and num.isdigit():
                    accounting.cpu_system_usec = int(num)
                elif key == "nr_periods" and num.isdigit():
                    accounting.cpu_nr_periods = int(num)
                elif key == "nr_throttled" and num.isdigit():
                    accounting.cpu_nr_throttled = int(num)
                elif key == "throttled_usec" and num.isdigit():
                    accounting.cpu_throttled_usec = int(num)

    # PIDs
    val = _read_file("pids.current")
    if val and val.isdigit():
        accounting.pids_current = int(val)

    val = _read_file("pids.peak")
    if val and val.isdigit():
        accounting.pids_peak = int(val)

    val = _read_file("pids.max")
    if val:
        accounting.pids_max = 0 if val == "max" else (int(val) if val.isdigit() else 0)

    # v1.3.3: OOM events from memory.events
    val = _read_file("memory.events")
    if val:
        for line in val.splitlines():
            parts = line.split()
            if len(parts) == 2:
                key, num = parts
                if key == "oom" and num.isdigit():
                    accounting.oom_events = int(num)
                elif key == "oom_kill" and num.isdigit():
                    accounting.oom_kill_events = int(num)

    return accounting


@dataclass
class CgroupLimits:
    """Resource limits to apply to a child cgroup."""

    memory_max_bytes: int = 0  # 0 = don't set (inherit)
    pids_max: int = 0  # 0 = don't set
    cpu_max_quota: int = 0  # 0 = don't set (microseconds per period)
    cpu_max_period: int = 100000  # default period

    def to_dict(self) -> dict[str, Any]:
        return {
            "memory_max_bytes": self.memory_max_bytes,
            "pids_max": self.pids_max,
            "cpu_max_quota": self.cpu_max_quota,
            "cpu_max_period": self.cpu_max_period,
        }


class CgroupBackend:
    """Cgroup v2 backend for resource accounting and limits."""

    def __init__(self) -> None:
        self._caps = detect_cgroup()

    @property
    def available(self) -> bool:
        return self._caps.cgroup_available

    @property
    def version(self) -> str:
        return self._caps.cgroup_version

    @property
    def capabilities(self) -> CgroupCapabilities:
        return self._caps

    def get_capabilities(self) -> CgroupCapabilities:
        """Get cgroup capabilities for sandbox reporting."""
        return self._caps

    def read_accounting(self, cgroup_path: str = "") -> CgroupAccounting:
        """Read resource accounting from a cgroup path.

        When cgroup_path is empty, auto-discovers the process's real
        cgroup-v2 path rather than defaulting to the cgroup root.
        """
        if cgroup_path:
            return read_accounting(cgroup_path)
        # Try the process's actual cgroup first, then fall back to stored path
        resolved = _resolve_process_cgroup_v2()
        return read_accounting(resolved or self._caps.cgroup_path or CGROUP_FS)

    def create_child_cgroup(
        self, name: str, limits: CgroupLimits | None = None
    ) -> str | None:
        """Create a child cgroup with optional limits.

        Returns the path to the child cgroup, or None if creation failed.
        """
        if not self._caps.cgroup_available or not self._caps.cgroup_limits_writable:
            return None

        parent = Path(self._caps.cgroup_path or CGROUP_FS)
        child = parent / name

        try:
            child.mkdir(exist_ok=True)

            if limits:
                # Enable controllers for the child
                subtree = parent / "cgroup.subtree_control"
                if subtree.exists() and os.access(subtree, os.W_OK):
                    current = subtree.read_text().strip()
                    needed_controllers = []
                    if limits.memory_max_bytes > 0:
                        needed_controllers.append("+memory")
                    if limits.pids_max > 0:
                        needed_controllers.append("+pids")
                    if limits.cpu_max_quota > 0:
                        needed_controllers.append("+cpu")
                    for ctrl in needed_controllers:
                        if ctrl not in current:
                            try:
                                subtree.write_text(ctrl)
                            except (PermissionError, OSError):
                                pass

                # Apply limits
                if limits.memory_max_bytes > 0:
                    f = child / "memory.max"
                    if f.exists() and os.access(f, os.W_OK):
                        f.write_text(str(limits.memory_max_bytes))

                if limits.pids_max > 0:
                    f = child / "pids.max"
                    if f.exists() and os.access(f, os.W_OK):
                        f.write_text(str(limits.pids_max))

                if limits.cpu_max_quota > 0:
                    f = child / "cpu.max"
                    if f.exists() and os.access(f, os.W_OK):
                        f.write_text(f"{limits.cpu_max_quota} {limits.cpu_max_period}")

            return str(child)
        except (PermissionError, OSError):
            return None

    def move_process_to_cgroup(self, pid: int, cgroup_path: str) -> bool:
        """Move a process to a cgroup.

        Returns True if successful.
        """
        procs_file = Path(cgroup_path) / "cgroup.procs"
        if not procs_file.exists() or not os.access(procs_file, os.W_OK):
            return False
        try:
            procs_file.write_text(str(pid))
            return True
        except (PermissionError, OSError):
            return False

    def remove_child_cgroup(self, cgroup_path: str) -> bool:
        """Remove a child cgroup (cleanup)."""
        try:
            Path(cgroup_path).rmdir()
            return True
        except (PermissionError, OSError):
            return False

    def describe(self) -> dict[str, Any]:
        """Full description for reporting."""
        caps = self._caps
        accounting = self.read_accounting() if caps.cgroup_accounting_readable else None
        return {
            "backend": "cgroup",
            "available": caps.cgroup_available,
            "version": caps.cgroup_version,
            "accounting_readable": caps.cgroup_accounting_readable,
            "limits_writable": caps.cgroup_limits_writable,
            "enforced": caps.cgroup_enforced,
            "accounting_only": caps.accounting_only,
            "cgroup_path": caps.cgroup_path,
            "accounting": accounting.to_dict() if accounting else None,
        }
