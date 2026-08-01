"""Trust summary — unified view of trust enforcement for a run.

Aggregates trust level, isolation mode, policy enforcement, and
environment controls into a single auditable structure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class NodeTrustRecord:
    """Per-node trust record for the trust summary."""

    node_id: str
    trust_level: str = "built_in"
    isolation_mode: str = "in_process"
    child_policy_enforced: bool = False
    env_filtered: bool = False
    temp_dir_isolated: bool = False
    timeout_limit: int = 0
    output_limit: int = 0
    memory_limit: int = 0
    import_violations: bool = False
    filesystem_violations: bool = False
    subprocess_violations: bool = False
    network_violations: bool = False
    origin: str = "built_in"
    # v1.1.0 additive fields
    sandbox_profile_required: str = ""
    sandbox_profile_used: str = ""
    os_sandbox_enforced: bool = False
    fallback_used: bool = False
    sandbox_backend: str = ""
    # v1.2.3 additive fields
    seccomp_enforced: bool = False
    seccomp_profile_name: str = ""
    syscall_filtering_enforced: bool = False
    # v1.3.0 additive fields
    cgroup_available: bool = False
    cgroup_version: str = ""
    cgroup_accounting_readable: bool = False
    cgroup_limits_writable: bool = False
    cgroup_accounting_only: bool = False
    # v1.3.1 additive fields
    cgroup_limits_enforced: bool = False
    cgroup_accounting_scope: str = ""  # "parent" | "invocation" | ""
    required_os_capabilities: list[str] = field(default_factory=list)
    resource_limits_enforced: bool = False
    job_object_enforced: bool = False
    # v1.3.2 additive fields
    cgroup_limits_requested: bool = False
    cgroup_memory_max_mb: int = 0
    cgroup_pids_max: int = 0
    cgroup_cpu_max_quota: int = 0
    # v1.3.3 additive fields — behavioral observation
    cgroup_oom_kill_observed: bool = False
    cgroup_cpu_throttling_observed: bool = False
    cgroup_pids_limit_observed: bool = False
    # v1.3.4 additive fields — pressure evidence counters
    memory_events_max: int = 0
    memory_events_oom: int = 0
    memory_events_oom_kill: int = 0
    cpu_nr_throttled: int = 0
    cpu_throttled_usec: int = 0
    pids_limit_denied: bool = False
    # v1.4.0 additive fields — namespace confinement
    namespace_available: bool = False
    network_namespace_enforced: bool = False
    network_namespace_requested: bool = False
    network_namespace_error: str = ""
    namespace_mode: str = ""
    # v1.4.3 additive fields — mount namespace prototype
    mount_namespace_requested: bool = False
    mount_namespace_enforced: bool = False
    mount_namespace_error: str = ""
    # v1.4.5 additive fields — mount confinement (chroot-based)
    mount_confinement_enforced: bool = False
    mount_confinement_requested: bool = False
    mount_confinement_error: str = ""
    temp_root_created: bool = False
    allowed_mounts: list[str] = field(default_factory=list)
    # v1.5.0 additive fields — PID namespace isolation
    pid_namespace_requested: bool = False
    pid_namespace_enforced: bool = False
    pid_namespace_error: str = ""
    pid_namespace_mode: str = ""
    # v1.5.1 additive fields — procfs namespace view
    procfs_namespace_view_enforced: bool = False
    procfs_error: str = ""


@dataclass
class TrustSummary:
    """Unified trust summary for a chain run."""

    run_id: str
    nodes: list[NodeTrustRecord] = field(default_factory=list)
    lockfile_verified: bool = False
    locked_mode: bool = False

    # Enforcement surface status
    import_enforced: bool = True
    filesystem_enforced: bool = True
    subprocess_enforced: bool = True
    network_enforced: bool = True
    process_isolation: str = "available"
    # v1.3.5: policy preset
    policy_preset: str = ""  # minimal|standard_untrusted|production_untrusted
    preset_source: str = ""  # cli|blueprint|""

    def add_node(self, record: NodeTrustRecord) -> None:
        self.nodes.append(record)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "lockfile_verified": self.lockfile_verified,
            "locked_mode": self.locked_mode,
            "policy_preset": self.policy_preset,
            "preset_source": self.preset_source,
            "enforcement_surface": {
                "imports": "enforced" if self.import_enforced else "not_enforced",
                "filesystem": "enforced" if self.filesystem_enforced else "not_enforced",
                "subprocess": "enforced" if self.subprocess_enforced else "not_enforced",
                "network": "enforced" if self.network_enforced else "not_enforced",
                "process_isolation": self.process_isolation,
            },
            "nodes": [
                {
                    "node_id": n.node_id,
                    "trust_level": n.trust_level,
                    "isolation_mode": n.isolation_mode,
                    "child_policy_enforced": n.child_policy_enforced,
                    "env_filtered": n.env_filtered,
                    "temp_dir_isolated": n.temp_dir_isolated,
                    "timeout_limit": n.timeout_limit,
                    "output_limit": n.output_limit,
                    "memory_limit": n.memory_limit,
                    "import_violations": n.import_violations,
                    "filesystem_violations": n.filesystem_violations,
                    "subprocess_violations": n.subprocess_violations,
                    "network_violations": n.network_violations,
                    "origin": n.origin,
                    "sandbox_profile_required": n.sandbox_profile_required,
                    "sandbox_profile_used": n.sandbox_profile_used,
                    "os_sandbox_enforced": n.os_sandbox_enforced,
                    "fallback_used": n.fallback_used,
                    "sandbox_backend": n.sandbox_backend,
                    "seccomp_enforced": n.seccomp_enforced,
                    "seccomp_profile_name": n.seccomp_profile_name,
                    "syscall_filtering_enforced": n.syscall_filtering_enforced,
                    "cgroup_available": n.cgroup_available,
                    "cgroup_version": n.cgroup_version,
                    "cgroup_accounting_readable": n.cgroup_accounting_readable,
                    "cgroup_limits_writable": n.cgroup_limits_writable,
                    "cgroup_accounting_only": n.cgroup_accounting_only,
                    "cgroup_limits_enforced": n.cgroup_limits_enforced,
                    "cgroup_accounting_scope": n.cgroup_accounting_scope,
                    "required_os_capabilities": n.required_os_capabilities,
                    "resource_limits_enforced": n.resource_limits_enforced,
                    "job_object_enforced": n.job_object_enforced,
                    "cgroup_limits_requested": n.cgroup_limits_requested,
                    "cgroup_memory_max_mb": n.cgroup_memory_max_mb,
                    "cgroup_pids_max": n.cgroup_pids_max,
                    "cgroup_cpu_max_quota": n.cgroup_cpu_max_quota,
                    "cgroup_oom_kill_observed": n.cgroup_oom_kill_observed,
                    "cgroup_cpu_throttling_observed": n.cgroup_cpu_throttling_observed,
                    "cgroup_pids_limit_observed": n.cgroup_pids_limit_observed,
                    "memory_events_max": n.memory_events_max,
                    "memory_events_oom": n.memory_events_oom,
                    "memory_events_oom_kill": n.memory_events_oom_kill,
                    "cpu_nr_throttled": n.cpu_nr_throttled,
                    "cpu_throttled_usec": n.cpu_throttled_usec,
                    "pids_limit_denied": n.pids_limit_denied,
                    "namespace_available": n.namespace_available,
                    "network_namespace_enforced": n.network_namespace_enforced,
                    "network_namespace_requested": n.network_namespace_requested,
                    "network_namespace_error": n.network_namespace_error,
                    "namespace_mode": n.namespace_mode,
                    "mount_namespace_requested": n.mount_namespace_requested,
                    "mount_namespace_enforced": n.mount_namespace_enforced,
                    "mount_namespace_error": n.mount_namespace_error,
                    "mount_confinement_enforced": n.mount_confinement_enforced,
                    "mount_confinement_requested": n.mount_confinement_requested,
                    "mount_confinement_error": n.mount_confinement_error,
                    "temp_root_created": n.temp_root_created,
                    "allowed_mounts": n.allowed_mounts,
                    "pid_namespace_requested": n.pid_namespace_requested,
                    "pid_namespace_enforced": n.pid_namespace_enforced,
                    "pid_namespace_error": n.pid_namespace_error,
                    "pid_namespace_mode": n.pid_namespace_mode,
                    "procfs_namespace_view_enforced": n.procfs_namespace_view_enforced,
                    "procfs_error": n.procfs_error,
                }
                for n in self.nodes
            ],
        }

    @property
    def is_compliant(self) -> bool:
        """Check if all untrusted nodes have proper isolation."""
        violations = self.validate_invariants(strict=False)
        return len(violations) == 0

    def validate_invariants(
        self, strict: bool = False
    ) -> list["TrustViolation"]:
        """Validate trust invariants and return structured violations.

        In non-strict mode, returns violations but does not raise.
        In strict mode, still returns violations (caller may raise).
        """
        violations: list[TrustViolation] = []

        for node in self.nodes:
            tl = node.trust_level

            # INV-001: untrusted requires subprocess isolation
            if tl in ("local_untrusted", "remote_untrusted"):
                if node.isolation_mode != "subprocess":
                    violations.append(TrustViolation(
                        code="INV-001",
                        severity="error",
                        node_id=node.node_id,
                        invariant="untrusted_requires_subprocess_isolation",
                        expected="isolation_mode=subprocess",
                        actual=f"isolation_mode={node.isolation_mode}",
                    ))

                # INV-002: untrusted requires child_policy_enforced
                if not node.child_policy_enforced:
                    violations.append(TrustViolation(
                        code="INV-002",
                        severity="error",
                        node_id=node.node_id,
                        invariant="untrusted_requires_child_policy",
                        expected="child_policy_enforced=true",
                        actual=f"child_policy_enforced={node.child_policy_enforced}",
                    ))

                # INV-003: subprocess-isolated requires env_filtered
                if node.isolation_mode == "subprocess" and not node.env_filtered:
                    violations.append(TrustViolation(
                        code="INV-003",
                        severity="error",
                        node_id=node.node_id,
                        invariant="subprocess_requires_env_filtered",
                        expected="env_filtered=true",
                        actual=f"env_filtered={node.env_filtered}",
                    ))

                # INV-004: subprocess-isolated requires temp_dir_isolated
                if node.isolation_mode == "subprocess" and not node.temp_dir_isolated:
                    violations.append(TrustViolation(
                        code="INV-004",
                        severity="error",
                        node_id=node.node_id,
                        invariant="subprocess_requires_temp_isolated",
                        expected="temp_dir_isolated=true",
                        actual=f"temp_dir_isolated={node.temp_dir_isolated}",
                    ))

        # INV-005: locked mode requires lockfile_verified
        if self.locked_mode and not self.lockfile_verified:
            violations.append(TrustViolation(
                code="INV-005",
                severity="error",
                node_id="*",
                invariant="locked_requires_lockfile_verified",
                expected="lockfile_verified=true",
                actual="lockfile_verified=false",
            ))

        # INV-006: required sandbox profile must be used (v1.1.0)
        for node in self.nodes:
            if node.sandbox_profile_required and node.sandbox_profile_required != node.sandbox_profile_used:
                # os_profile was requested but a weaker profile was used
                required_strength = {
                    "os_profile": 3,
                    "subprocess_isolated": 2,
                    "python_hooks": 1,
                    "none": 0,
                }.get(node.sandbox_profile_required, 2)
                used_strength = {
                    "os_profile": 3,
                    "subprocess_isolated": 2,
                    "python_hooks": 1,
                    "none": 0,
                }.get(node.sandbox_profile_used, 2)
                if used_strength < required_strength:
                    violations.append(TrustViolation(
                        code="INV-006",
                        severity="error",
                        node_id=node.node_id,
                        invariant="required_sandbox_profile_must_be_used",
                        expected=f"profile={node.sandbox_profile_required}",
                        actual=f"profile={node.sandbox_profile_used}",
                    ))

        # INV-007: required sandbox capability must be enforced (v1.2.0)
        # Capability-level check — fires when a specific capability is
        # required (e.g., syscall_filtering_enforced) but not actually enforced.
        import platform as _platform
        _is_linux = _platform.system() == "Linux"
        for node in self.nodes:
            # Check os_sandbox_enforced flag claims
            if node.os_sandbox_enforced and node.sandbox_profile_used == "os_profile":
                # If claiming OS profile but sandbox_backend is empty/none, that's suspicious
                if not node.sandbox_backend or node.sandbox_backend == "none":
                    violations.append(TrustViolation(
                        code="INV-007",
                        severity="error",
                        node_id=node.node_id,
                        invariant="required_sandbox_capability_must_be_enforced",
                        expected="sandbox_backend set to real backend",
                        actual="sandbox_backend empty or none",
                    ))

            # On Linux, os_profile should have seccomp enforced if available
            if _is_linux and node.sandbox_profile_used == "os_profile":
                if not node.syscall_filtering_enforced:
                    violations.append(TrustViolation(
                        code="INV-007",
                        severity="error",
                        node_id=node.node_id,
                        invariant="required_sandbox_capability_must_be_enforced",
                        expected="syscall_filtering_enforced=true (Linux os_profile)",
                        actual="syscall_filtering_enforced=false",
                    ))

        # INV-008: required OS capability must be available (v1.3.0, fixed v1.3.1)
        # Platform-neutral: checks that at least one OS enforcement mechanism
        # is available when os_profile is required.
        # - Linux: RLIMIT, seccomp, or cgroup
        # - Windows: Job Objects
        # - macOS: detection_only (no enforcement)
        #
        # Also checks explicit capability requirements via required_os_capabilities.
        for node in self.nodes:
            if node.sandbox_profile_required == "os_profile":
                # Check that at least one OS enforcement capability exists
                has_os_capability = (
                    node.resource_limits_enforced
                    or node.syscall_filtering_enforced
                    or node.cgroup_available
                    or node.job_object_enforced
                )
                if not has_os_capability:
                    violations.append(TrustViolation(
                        code="INV-008",
                        severity="error",
                        node_id=node.node_id,
                        invariant="required_os_capability_must_be_available",
                        expected="at least one OS enforcement capability (rlimit/seccomp/cgroup/job_object)",
                        actual="none available",
                    ))

                # Check explicit capability requirements (v1.3.1)
                capability_checks = {
                    "cgroup_accounting": (
                        node.cgroup_available and node.cgroup_accounting_readable,
                        "cgroup_accounting_readable=true",
                    ),
                    "cgroup_limits": (
                        node.cgroup_limits_writable,
                        "cgroup_limits_writable=true",
                    ),
                    "seccomp": (
                        node.syscall_filtering_enforced,
                        "syscall_filtering_enforced=true",
                    ),
                    "job_object": (
                        node.job_object_enforced,
                        "job_object_enforced=true",
                    ),
                    "resource_limits": (
                        node.resource_limits_enforced,
                        "resource_limits_enforced=true",
                    ),
                }
                for req_cap in node.required_os_capabilities:
                    if req_cap in capability_checks:
                        check_result, expected = capability_checks[req_cap]
                        if not check_result:
                            violations.append(TrustViolation(
                                code="INV-008",
                                severity="error",
                                node_id=node.node_id,
                                invariant=f"required_os_capability_must_be_available",
                                expected=expected,
                                actual=f"{req_cap}=false",
                            ))

        # INV-009: required cgroup limits must be enforced (v1.3.2)
        # Fires when cgroup limits are requested but not enforced.
        # This is stricter than INV-008 — it checks actual limit enforcement.
        for node in self.nodes:
            if node.cgroup_limits_requested and not node.cgroup_limits_enforced:
                violations.append(TrustViolation(
                    code="INV-009",
                    severity="error",
                    node_id=node.node_id,
                    invariant="required_cgroup_limits_must_be_enforced",
                    expected="cgroup_limits_enforced=true",
                    actual="cgroup_limits_enforced=false",
                ))

        # INV-010: policy preset requirements must be satisfied (v1.3.5)
        # Preset declares requirements; strict mode enforces them.
        # This invariant checks that the preset's requirements are met
        # by the runtime environment, not that individual nodes met them.
        if self.policy_preset:
            from nodechain.sdk.policy_presets import get_preset
            preset = get_preset(self.policy_preset)
            if preset:
                for node in self.nodes:
                    if preset.seccomp_required and not node.syscall_filtering_enforced:
                        violations.append(TrustViolation(
                            code="INV-010",
                            severity="error",
                            node_id=node.node_id,
                            invariant="preset_seccomp_required",
                            expected=f"seccomp=true (preset={self.policy_preset})",
                            actual="syscall_filtering_enforced=false",
                        ))
                    if preset.cgroup_limits_requested:
                        if not node.cgroup_available:
                            violations.append(TrustViolation(
                                code="INV-010",
                                severity="error",
                                node_id=node.node_id,
                                invariant="preset_cgroup_required",
                                expected=f"cgroup_available=true (preset={self.policy_preset})",
                                actual="cgroup_available=false",
                            ))
                        if not node.cgroup_limits_enforced:
                            violations.append(TrustViolation(
                                code="INV-010",
                                severity="error",
                                node_id=node.node_id,
                                invariant="preset_cgroup_limits_required",
                                expected=f"cgroup_limits_enforced=true (preset={self.policy_preset})",
                                actual="cgroup_limits_enforced=false",
                            ))

        # INV-011: required namespace confinement must be enforced (v1.4.0)
        # v1.4.1: Capability-specific for network namespace.
        # v1.4.3: Extended for mount namespace.
        for node in self.nodes:
            if node.network_namespace_requested:
                if not node.network_namespace_enforced:
                    detail = node.network_namespace_error or "not enforced"
                    violations.append(TrustViolation(
                        code="INV-011",
                        severity="error",
                        node_id=node.node_id,
                        invariant="network_namespace_required_but_not_enforced",
                        expected="network_namespace_enforced=true",
                        actual=f"network_namespace_enforced=false ({detail})",
                    ))
            if node.mount_namespace_requested:
                if not node.mount_namespace_enforced:
                    detail = node.mount_namespace_error or "not enforced"
                    violations.append(TrustViolation(
                        code="INV-011",
                        severity="error",
                        node_id=node.node_id,
                        invariant="mount_namespace_required_but_not_enforced",
                        expected="mount_namespace_enforced=true",
                        actual=f"mount_namespace_enforced=false ({detail})",
                    ))

        # INV-012: required mount confinement must be enforced (v1.4.5/v1.4.6)
        # When mount_confinement is required by policy, the chroot-based
        # confinement must be active. This is separate from
        # mount_namespace_enforced: mount namespace just means separate
        # namespace; mount confinement means restricted filesystem view.
        #
        # v1.4.6: Upgraded from advisory to capability-specific error,
        # matching INV-011 pattern. Fires as error when:
        #   mount_confinement_requested=true AND mount_confinement_enforced=false
        # Strict mode → exit 15.
        for node in self.nodes:
            if node.mount_confinement_requested:
                if not node.mount_confinement_enforced:
                    detail = node.mount_confinement_error or "not enforced"
                    violations.append(TrustViolation(
                        code="INV-012",
                        node_id=node.node_id,
                        severity="error",
                        invariant="mount_confinement_required_but_not_enforced",
                        expected="mount_confinement_enforced=true",
                        actual=f"mount_confinement_enforced=false ({detail})",
                    ))

        # INV-013: required PID namespace must be enforced (v1.5.0)
        # When PID namespace is required by policy, the two-stage fork
        # must succeed and the child must be in a new PID namespace.
        # Fires as error when:
        #   pid_namespace_requested=true AND pid_namespace_enforced=false
        # Strict mode → exit 15.
        for node in self.nodes:
            if node.pid_namespace_requested:
                if not node.pid_namespace_enforced:
                    detail = node.pid_namespace_error or "not enforced"
                    violations.append(TrustViolation(
                        code="INV-013",
                        node_id=node.node_id,
                        severity="error",
                        invariant="pid_namespace_required_but_not_enforced",
                        expected="pid_namespace_enforced=true",
                        actual=f"pid_namespace_enforced=false ({detail})",
                    ))

        # In strict mode, warnings become errors
        if strict:
            for v in violations:
                if v.severity == "warning":
                    v.severity = "error"

        return violations


@dataclass
class TrustViolation:
    """Structured trust invariant violation."""

    code: str
    severity: str  # "error" or "warning"
    node_id: str
    invariant: str
    expected: str
    actual: str

    def to_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "severity": self.severity,
            "node_id": self.node_id,
            "invariant": self.invariant,
            "expected": self.expected,
            "actual": self.actual,
        }
