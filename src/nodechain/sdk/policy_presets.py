"""Policy presets for cgroup and sandbox configuration.

Presets declare resource policy requirements. They do not auto-create
limits — strict mode enforces declared requirements.

Available presets:
  - production_untrusted: os_profile + seccomp + cgroup limits + trust-check
  - standard_untrusted: os_profile + seccomp
  - minimal: subprocess isolation only
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PolicyPreset:
    """Declarative resource policy preset."""

    name: str
    description: str
    sandbox_profile: str = "subprocess_isolated"
    seccomp_required: bool = False
    cgroup_limits_requested: bool = False
    cgroup_memory_max_mb: int = 0
    cgroup_pids_max: int = 0
    cgroup_cpu_max_quota: int = 0
    trust_check_required: bool = False
    network_namespace_required: bool = False  # v1.4.0
    mount_namespace_required: bool = False    # v1.4.3 prototype
    mount_confinement_required: bool = False  # v1.4.5 chroot-based
    pid_namespace_required: bool = False      # v1.5.0 PID isolation
    procfs_isolation_required: bool = False   # v1.5.1 procfs remount

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "sandbox_profile": self.sandbox_profile,
            "seccomp_required": self.seccomp_required,
            "cgroup_limits_requested": self.cgroup_limits_requested,
            "cgroup_memory_max_mb": self.cgroup_memory_max_mb,
            "cgroup_pids_max": self.cgroup_pids_max,
            "cgroup_cpu_max_quota": self.cgroup_cpu_max_quota,
            "trust_check_required": self.trust_check_required,
            "network_namespace_required": self.network_namespace_required,
            "mount_namespace_required": self.mount_namespace_required,
            "mount_confinement_required": self.mount_confinement_required,
            "pid_namespace_required": self.pid_namespace_required,
            "procfs_isolation_required": self.procfs_isolation_required,
        }

    def to_runner_kwargs(self) -> dict[str, Any]:
        """Convert preset to SubprocessRunner kwargs."""
        kwargs: dict[str, Any] = {}
        if self.cgroup_limits_requested:
            kwargs["enable_cgroup"] = True
            kwargs["cgroup_memory_max_mb"] = self.cgroup_memory_max_mb
            kwargs["cgroup_pids_max"] = self.cgroup_pids_max
            kwargs["cgroup_cpu_max_quota"] = self.cgroup_cpu_max_quota
        if self.network_namespace_required:
            kwargs["enable_network_namespace"] = True
        if self.mount_namespace_required:
            kwargs["enable_mount_namespace"] = True
        if self.mount_confinement_required:
            kwargs["enable_mount_confinement"] = True
        if self.pid_namespace_required:
            kwargs["enable_pid_namespace"] = True
            kwargs["enable_procfs_isolation"] = True
        return kwargs

    def to_required_os_capabilities(self) -> list[str]:
        """Get the required OS capabilities for this preset."""
        caps: list[str] = []
        if self.seccomp_required:
            caps.append("seccomp")
        if self.cgroup_limits_requested:
            caps.append("cgroup_limits")
            caps.append("cgroup_accounting")
        if self.network_namespace_required:
            caps.append("network_namespace")
        if self.mount_namespace_required:
            caps.append("mount_namespace")
        if self.mount_confinement_required:
            caps.append("mount_confinement")
        if self.pid_namespace_required:
            caps.append("pid_namespace")
        if self.procfs_isolation_required:
            caps.append("procfs_isolation")
        return caps


# ─── Preset Registry ─────────────────────────────────────────────────────

PRESETS: dict[str, PolicyPreset] = {
    "production_untrusted": PolicyPreset(
        name="production_untrusted",
        description="Full production isolation: os_profile + seccomp + cgroup limits + trust-check",
        sandbox_profile="os_profile",
        seccomp_required=True,
        cgroup_limits_requested=True,
        cgroup_memory_max_mb=512,
        cgroup_pids_max=50,
        cgroup_cpu_max_quota=200000,  # 2 cores out of default 100000 period
        trust_check_required=True,
        network_namespace_required=True,  # v1.4.0: network namespace isolation
    ),
    "standard_untrusted": PolicyPreset(
        name="standard_untrusted",
        description="Standard isolation: os_profile + seccomp",
        sandbox_profile="os_profile",
        seccomp_required=True,
    ),
    "hardened_untrusted": PolicyPreset(
        name="hardened_untrusted",
        description="Hardened isolation: production_untrusted + mount confinement (chroot)",
        sandbox_profile="os_profile",
        seccomp_required=True,
        cgroup_limits_requested=True,
        cgroup_memory_max_mb=512,
        cgroup_pids_max=50,
        cgroup_cpu_max_quota=200000,
        trust_check_required=True,
        network_namespace_required=True,
        mount_confinement_required=True,
        pid_namespace_required=True,
    ),
    "minimal": PolicyPreset(
        name="minimal",
        description="Minimal isolation: subprocess only",
        sandbox_profile="subprocess_isolated",
    ),
}


def get_preset(name: str) -> PolicyPreset | None:
    """Get a preset by name."""
    return PRESETS.get(name)


def list_presets() -> list[str]:
    """List available preset names."""
    return list(PRESETS.keys())
