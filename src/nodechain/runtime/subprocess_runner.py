"""Process-isolated node execution runner.

Runs local_untrusted and remote_untrusted nodes in a separate subprocess
with constrained capabilities, timeout, and output-size limits.

Architecture:
  1. Parent creates isolated temp directory per invocation
  2. Parent serializes config + InvocationEnvelope to JSON
  3. Parent spawns child process (close_fds=True, cwd=package_root/temp)
     with filtered environment (secrets stripped, temp dirs isolated)
  4. Child installs import/filesystem/subprocess/network enforcers
  5. Child imports ONLY the node module, executes it under enforcement
  6. Child returns response on stdout
  7. Child has no access to parent DB, state, or other nodes
  8. Parent cleans up temp directory after execution (success or failure)
  9. Timeout, output-size limits enforced by parent

Child protocol:
  stdin:  JSON {"config": {...}, "envelope": {...}}
  stdout: JSON response (EnvelopeResponse dict)
  stderr: captured for error reporting

Exit codes:
  0: success
  1: execution error
  2: timeout (parent-side)
  3: output size exceeded (parent-side)
  10: import/execution blocked by policy
"""

from __future__ import annotations

import asyncio
import json
import os
import platform
import signal
import subprocess
import sys
import traceback
from pathlib import Path
from typing import Any

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.sdk.trust import TrustLevel

# Limits for subprocess execution
DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_MAX_OUTPUT_BYTES = 10 * 1024 * 1024  # 10 MB
DEFAULT_MAX_MEMORY_MB = 512


# ─── v1.3.9: Explicit runner configuration ──────────────────────────────


class RunnerConfig:
    """Explicit configuration for SubprocessRunner.

    v1.3.9: Replaces hidden env-var coupling with explicit config
    objects passed through the call chain.

    Usage:
        config = RunnerConfig.from_preset(preset)
        runner = get_subprocess_runner(config=config)

    Env vars remain as external override inputs and fallback when
    no explicit config is provided.
    """

    def __init__(
        self,
        enable_cgroup: bool = False,
        cgroup_memory_max_mb: int = 0,
        cgroup_pids_max: int = 0,
        cgroup_cpu_max_quota: int = 0,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
        max_memory_mb: int = DEFAULT_MAX_MEMORY_MB,
        enable_network_namespace: bool = False,
        enable_mount_namespace: bool = False,
        enable_mount_confinement: bool = False,
        enable_pid_namespace: bool = False,
        enable_procfs_isolation: bool = False,
    ):
        self.enable_cgroup = enable_cgroup
        self.cgroup_memory_max_mb = cgroup_memory_max_mb
        self.cgroup_pids_max = cgroup_pids_max
        self.cgroup_cpu_max_quota = cgroup_cpu_max_quota
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes
        self.max_memory_mb = max_memory_mb
        self.enable_network_namespace = enable_network_namespace
        self.enable_mount_namespace = enable_mount_namespace
        self.enable_mount_confinement = enable_mount_confinement
        self.enable_pid_namespace = enable_pid_namespace
        self.enable_procfs_isolation = enable_procfs_isolation

    @classmethod
    def from_preset(cls, preset) -> "RunnerConfig":
        """Create RunnerConfig from a PolicyPreset's to_runner_kwargs()."""
        kwargs = preset.to_runner_kwargs()
        return cls(**kwargs)

    @classmethod
    def from_env(cls) -> "RunnerConfig | None":
        """Create RunnerConfig from NODECHAIN_POLICY_PRESET env var.

        Returns None if no preset is set or preset is unknown.
        """
        preset_name = os.environ.get("NODECHAIN_POLICY_PRESET", "")
        if not preset_name:
            return None
        try:
            from nodechain.sdk.policy_presets import get_preset
            preset = get_preset(preset_name)
            if preset:
                return cls.from_preset(preset)
        except Exception:
            pass
        return None

    def to_runner_kwargs(self) -> dict[str, Any]:
        """Convert to kwargs for SubprocessRunner.__init__."""
        return {
            "enable_cgroup": self.enable_cgroup,
            "cgroup_memory_max_mb": self.cgroup_memory_max_mb,
            "cgroup_pids_max": self.cgroup_pids_max,
            "cgroup_cpu_max_quota": self.cgroup_cpu_max_quota,
            "timeout_seconds": self.timeout_seconds,
            "max_output_bytes": self.max_output_bytes,
            "max_memory_mb": self.max_memory_mb,
            "enable_network_namespace": self.enable_network_namespace,
            "enable_mount_namespace": self.enable_mount_namespace,
            "enable_mount_confinement": self.enable_mount_confinement,
            "enable_pid_namespace": self.enable_pid_namespace,
            "enable_procfs_isolation": self.enable_procfs_isolation,
        }

    def __repr__(self) -> str:
        return (
            f"RunnerConfig(enable_cgroup={self.enable_cgroup}, "
            f"mem={self.cgroup_memory_max_mb}MB, "
            f"pids={self.cgroup_pids_max}, "
            f"cpu={self.cgroup_cpu_max_quota}, "
            f"netns={self.enable_network_namespace}, "
            f"mntns={self.enable_mount_namespace}, "
            f"mntconf={self.enable_mount_confinement}, "
            f"pidns={self.enable_pid_namespace}, "
            f"procfs={self.enable_procfs_isolation})"
        )


class SubprocessRunner:
    """Runs a node in an isolated subprocess."""

    def __init__(
        self,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
        max_memory_mb: int = DEFAULT_MAX_MEMORY_MB,
        enable_cgroup: bool = False,
        cgroup_memory_max_mb: int = 0,
        cgroup_pids_max: int = 0,
        cgroup_cpu_max_quota: int = 0,
        enable_network_namespace: bool = False,
        enable_mount_namespace: bool = False,
        enable_mount_confinement: bool = False,
        enable_pid_namespace: bool = False,
        enable_procfs_isolation: bool = False,
    ):
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes
        self.max_memory_mb = max_memory_mb
        self.enable_cgroup = enable_cgroup
        self.cgroup_memory_max_mb = cgroup_memory_max_mb
        self.cgroup_pids_max = cgroup_pids_max
        self.cgroup_cpu_max_quota = cgroup_cpu_max_quota
        self.enable_network_namespace = enable_network_namespace
        self.enable_mount_namespace = enable_mount_namespace
        self.enable_mount_confinement = enable_mount_confinement
        self.enable_pid_namespace = enable_pid_namespace
        self.enable_procfs_isolation = enable_procfs_isolation
        self._cgroup_path: str | None = None
        self._cgroup_accounting: dict[str, Any] | None = None
        self._cgroup_limits_applied: bool = False
        self._cgroup_limits_requested: bool = False

    # Secret patterns to strip from child environment
    _SECRET_PATTERNS = (
        "API_KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL",
        "AUTH", "PRIVATE", "DATABASE_URL", "DB_PASSWORD",
        "AWS_", "OPENAI_", "ANTHROPIC_", "NODECHAIN_TEST_SECRET",
    )

    def _build_child_env(self, temp_dir: str = "") -> dict[str, str]:
        """Build minimal environment for child process.

        Filters out common secret patterns. Keeps PATH, HOME, and
        other safe environment variables needed for Python to function.
        Sets TEMP/TMP/TMPDIR to isolated temp directory if provided.
        """
        safe_env = {}
        for key, value in os.environ.items():
            key_upper = key.upper()
            # Strip known secret patterns
            if any(pattern in key_upper for pattern in self._SECRET_PATTERNS):
                continue
            safe_env[key] = value

        # Override temp dirs with isolated temp directory
        if temp_dir:
            safe_env["TEMP"] = temp_dir
            safe_env["TMP"] = temp_dir
            safe_env["TMPDIR"] = temp_dir

        return safe_env

    def _build_child_script(
        self,
        module_path: str,
        class_name: str,
        trust_level: str,
        package_root: str = "",
        enable_seccomp: bool = False,
    ) -> str:
        """Build the Python script that runs inside the child process.

        Safe bootstrap ordering (v1.2.4 + v1.4.0):

        Phase 1:  Import trusted NodeChain SDK/runtime only + create event loop
        Phase 1a: Create network namespace (v1.4.0, Linux only, if enabled)
        Phase 1b: Apply seccomp filter (Linux only, if enabled and available)
        Phase 1c: Activate ALL Python enforcement (import/fs/subprocess/network)
        Phase 2:  Import untrusted node module (UNDER all enforcement)
        Phase 3:  Execute node
        Phase 4:  Report + deactivate enforcement

        CRITICAL: The untrusted node module is NOT imported until Phase 2,
        after seccomp AND all Python enforcers are active. Import enforcement
        is active with allow_preloaded=True — modules already loaded by
        trusted bootstrap bypass the policy, but NEW imports of dangerous
        modules (ctypes, etc.) are blocked.
        """
        return f'''
import sys
import os
import json
import traceback
import asyncio
import importlib.util

# Pre-import trusted NodeChain code only
sys.path.insert(0, {repr(str(Path.cwd()))})

# Phase 1: Bootstrap — import trusted SDK types only (NO node module yet)
from nodechain.core.envelope import InvocationEnvelope
from nodechain.sdk.trust import TrustLevel as TL
from nodechain.sdk.import_enforcer import enforce_imports_for_node
from nodechain.sdk.filesystem_enforcer import enforce_filesystem_for_node
from nodechain.sdk.subprocess_enforcer import enforce_subprocess_for_node
from nodechain.sdk.network_enforcer import enforce_network_for_node
# Pre-import core modules that BaseNode subclasses commonly need.
# These MUST be in sys.modules before chroot/mount confinement.
import nodechain.core.port
import nodechain.core.contract
import nodechain.core.manifest
import nodechain.nodes.base_node

def main():
    try:
        # Read config + envelope from stdin
        input_data = json.loads(sys.stdin.read())

        # Phase 0: PID namespace (v1.5.0)
        # Must happen BEFORE seccomp (which blocks fork) and BEFORE
        # any other phase (fork duplicates process state).
        # PID namespace semantics: unshare(CLONE_NEWPID) only affects
        # children created after the call. So we fork: the child is
        # PID 1 in the new namespace.
        pid_ns_report = {{"pid_namespace_enforced": False}}
        if {repr(self.enable_pid_namespace)}:
            try:
                from nodechain.sdk.namespace_profile import (
                    apply_pid_namespace_two_stage,
                    _PID_NS_SUCCESS, _PID_NS_SKIP, _PID_NS_FAIL,
                )
                _pid_result = apply_pid_namespace_two_stage()
                if _pid_result == _PID_NS_SUCCESS:
                    pid_ns_report["pid_namespace_enforced"] = True
                    pid_ns_report["child_pid"] = os.getpid()
                elif _pid_result == _PID_NS_FAIL:
                    pid_ns_report["pid_namespace_error"] = "unshare(CLONE_NEWPID) failed"
                # _PID_NS_SKIP: not enabled, continue normally
            except Exception as pid_err:
                pid_ns_report["pid_namespace_error"] = str(pid_err)

            # Phase 0a: Optional procfs remount for PID namespace (v1.5.1)
            # After PID namespace is active, remount /proc so only
            # namespace-local PIDs are visible. Must happen BEFORE seccomp
            # (which blocks mount/umount syscalls).
            if pid_ns_report.get("pid_namespace_enforced") and {repr(self.enable_procfs_isolation)}:
                try:
                    from nodechain.sdk.namespace_profile import remount_procfs_for_pid_namespace
                    procfs_report = remount_procfs_for_pid_namespace()
                    pid_ns_report.update(procfs_report)
                except Exception as procfs_err:
                    pid_ns_report["procfs_error"] = str(procfs_err)

        config = input_data.get("config", {{}})
        envelope_data = input_data.get("envelope", {{}})

        trust_level = config.get("trust_level", "built_in")
        package_root = config.get("package_root", "")
        node_id = config.get("node_id", "unknown")

        # Build envelope (trusted code, no node module needed)
        envelope = InvocationEnvelope(**envelope_data)

        # Phase 1b: Create event loop BEFORE enforcement (avoids asyncio lazy imports)
        loop = asyncio.new_event_loop()

        # Phase 1a: Create network namespace BEFORE seccomp (v1.4.0)
        # Must happen before any network-related imports or operations
        ns_report = {{"network_namespace_enforced": False}}
        if {repr(self.enable_network_namespace)}:
            try:
                import platform as _plat
                if _plat.system() == "Linux":
                    from nodechain.sdk.namespace_profile import apply_network_namespace
                    ns_ok = apply_network_namespace()
                    ns_report["network_namespace_enforced"] = ns_ok
                    if not ns_ok:
                        ns_report["namespace_error"] = "apply_network_namespace returned False"
            except Exception as ns_err:
                ns_report["namespace_error"] = str(ns_err)

        # Phase 1a: Create mount namespace (v1.4.3)
        mnt_ns_report = {{"mount_namespace_enforced": False}}
        if {repr(self.enable_mount_namespace)}:
            try:
                import platform as _plat2
                if _plat2.system() == "Linux":
                    from nodechain.sdk.namespace_profile import apply_mount_namespace
                    mnt_ok = apply_mount_namespace()
                    mnt_ns_report["mount_namespace_enforced"] = mnt_ok
                    if not mnt_ok:
                        mnt_ns_report["mount_namespace_error"] = "apply_mount_namespace returned False"
            except Exception as mnt_err:
                mnt_ns_report["mount_namespace_error"] = str(mnt_err)

        # Phase 1b: Apply mount confinement with chroot (v1.4.5)
        # This is stronger than mount namespace alone — it restricts
        # the child's filesystem view to only allowed directories.
        # Must happen AFTER all trusted SDK imports (they remain in
        # sys.modules and don't need filesystem access).
        confine_report = {{
            "mount_confinement_enforced": False,
            "temp_root_created": False,
            "allowed_mounts": [],
            "mount_confinement_error": "",
        }}
        _effective_module_path = {repr(str(module_path))}
        if {repr(self.enable_mount_confinement)}:
            try:
                import platform as _plat3
                if _plat3.system() == "Linux":
                    from nodechain.sdk.namespace_profile import apply_mount_confinement
                    _confine = apply_mount_confinement(
                        package_root or os.path.dirname({repr(str(module_path))}),
                        os.environ.get("TEMP", os.environ.get("TMPDIR", "/tmp")),
                    )
                    confine_report["mount_confinement_enforced"] = _confine.get("mount_confinement_enforced", False)
                    confine_report["temp_root_created"] = _confine.get("temp_root_created", False)
                    confine_report["allowed_mounts"] = _confine.get("allowed_mounts", [])
                    confine_report["mount_confinement_error"] = _confine.get("mount_confinement_error", "")
                    if _confine.get("mount_confinement_enforced"):
                        import os as _os2
                        _module_filename = _os2.path.basename({repr(str(module_path))})
                        _effective_module_path = _confine.get("chrooted_module_prefix", "/package") + "/" + _module_filename
            except Exception as confine_err:
                confine_report["mount_confinement_error"] = str(confine_err)

        # Phase 1c: Apply seccomp filter BEFORE node import (Linux only)
        seccomp_report = {{"seccomp_enforced": False, "seccomp_available": False}}
        if {repr(enable_seccomp)}:
            try:
                import platform
                if platform.system() == "Linux":
                    from nodechain.sdk.seccomp_profile import SeccompProfile, SeccompBackend
                    sb = SeccompBackend()
                    seccomp_report["seccomp_available"] = sb.available
                    if sb.available:
                        profile = SeccompProfile()
                        applied = sb.apply_profile(profile)
                        seccomp_report["seccomp_enforced"] = applied
                        seccomp_report["seccomp_profile_name"] = profile.name if applied else ""
                        seccomp_report["syscall_filtering_enforced"] = applied
                        if not applied:
                            seccomp_report["seccomp_error"] = "apply_profile returned False"
            except Exception as seccomp_err:
                seccomp_report["seccomp_error"] = str(seccomp_err)

        # Phase 1c: Activate ALL enforcement BEFORE node import
        # Import enforcer uses allow_preloaded=True so trusted framework
        # dependencies already in sys.modules bypass policy. NEW imports
        # of dangerous modules not in sys.modules are still blocked.
        enforcers = []
        imp = fs = sp = net = None
        if trust_level != "built_in":
            tl = TL(trust_level)
            imp = enforce_imports_for_node(tl, node_id, allow_preloaded=True)
            fs = enforce_filesystem_for_node(tl, node_id, package_root or None)
            sp = enforce_subprocess_for_node(tl, node_id)
            net = enforce_network_for_node(tl, node_id)

            # Activate ALL enforcement before node import
            imp_cm = imp.enforce(); imp_cm.__enter__()
            fs_cm = fs.enforce(); fs_cm.__enter__()
            sp_cm = sp.enforce(); sp_cm.__enter__()
            net_cm = net.enforce(); net_cm.__enter__()
            enforcers = [imp_cm, fs_cm, sp_cm, net_cm]

        # Phase 2: Import untrusted node module
        # (UNDER seccomp + import + fs + subprocess + network enforcement)
        spec = importlib.util.spec_from_file_location(
            "_node_module", _effective_module_path
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        node_cls = getattr(mod, {repr(class_name)})

        # Phase 3: Execute node under all enforcement
        policy_report = {{}}
        try:
            response = loop.run_until_complete(node_cls().execute(envelope))
        finally:
            loop.close()

            # Collect violation reports
            if trust_level != "built_in":
                policy_report = {{
                    "child_policy_enforced": True,
                    "import_violations": imp.had_violations if imp else False,
                    "filesystem_violations": fs.had_violations if fs else False,
                    "subprocess_violations": sp.had_violations if sp else False,
                    "network_violations": net.had_violations if net else False,
                }}

            # Phase 4: Deactivate enforcement
            for cm in reversed(enforcers):
                try:
                    cm.__exit__(None, None, None)
                except Exception:
                    pass

        # Attach policy report to response metadata
        resp_dict = response.model_dump(mode="json")
        if policy_report:
            resp_dict.setdefault("metadata", {{}}).update(policy_report)
        # Always attach seccomp report (v1.2.x)
        resp_dict.setdefault("metadata", {{}}).update(seccomp_report)
        # Attach namespace report (v1.4.0)
        resp_dict.setdefault("metadata", {{}}).update(ns_report)
        # Attach mount namespace report (v1.4.3)
        resp_dict.setdefault("metadata", {{}}).update(mnt_ns_report)
        # Attach mount confinement report (v1.4.5)
        resp_dict.setdefault("metadata", {{}}).update(confine_report)
        # Attach PID namespace report (v1.5.0)
        resp_dict.setdefault("metadata", {{}}).update(pid_ns_report)

        sys.stdout.write(json.dumps(resp_dict))
        sys.stdout.flush()

    except Exception as e:
        sys.stderr.write(traceback.format_exc())
        sys.exit(1)

main()
'''

    async def run_isolated(
        self,
        envelope: InvocationEnvelope,
        module_path: str | Path,
        class_name: str,
        node_id: str,
        trust_level: str = "local_untrusted",
        package_root: str = "",
        enable_seccomp: bool = False,
    ) -> dict[str, Any]:
        """Run a node in an isolated subprocess.

        Returns a dict with:
          success: bool
          response: dict (EnvelopeResponse) if success
          error: str if failure
          exit_code: int
          isolation_mode: "subprocess"
          duration_ms: int
          child_policy_enforced: bool
          child_cwd: str
          temp_dir_isolated: bool
        """
        # ── T3.0 safety fence ────────────────────────────────────────────────
        # POSIX untrusted execution via the legacy SubprocessRunner path is
        # disabled until supervised routing (T3) is implemented. The legacy
        # path cgroup setup may silently return None, execution proceeds
        # without verified containment, and load-bearing cgroup operations
        # suppress failures. Refuse before any workload process is spawned,
        # before temp-env creation, child-script construction, cgroup setup,
        # or subprocess spawn.
        #
        # Does NOT alter: Windows behavior, built_in, local_trusted, direct
        # supervisor APIs, or legacy trusted-utility behavior. No env var,
        # config flag, fallback, or test-only bypass may re-enable it.
        if os.name == "posix" and trust_level in ("local_untrusted", "remote_untrusted"):
            return {
                "success": False,
                "error": (
                    "supervised_backend_required: POSIX untrusted execution "
                    f"({trust_level}) is disabled on the legacy SubprocessRunner "
                    "path until supervised routing (T3) is available"
                ),
                "exit_code": 126,
                "isolation_mode": "subprocess",
                "duration_ms": 0,
                "child_policy_enforced": False,
                "child_cwd": "",
                "temp_dir_isolated": False,
            }

        import time
        import tempfile
        import shutil

        module_path = Path(module_path).resolve()
        if not module_path.exists():
            return {
                "success": False,
                "error": f"Module not found: {module_path}",
                "exit_code": -1,
                "isolation_mode": "subprocess",
                "duration_ms": 0,
                "child_policy_enforced": False,
                "child_cwd": "",
                "temp_dir_isolated": False,
            }

        start = time.monotonic()

        # Create isolated temp directory per invocation
        temp_dir = tempfile.mkdtemp(prefix="nodechain_child_")

        # Determine child cwd: package root if available, else temp dir
        child_cwd = package_root if package_root else temp_dir

        # Build config + envelope payload
        config = {
            "trust_level": trust_level,
            "package_root": package_root,
            "node_id": node_id,
        }
        payload = json.dumps({
            "config": config,
            "envelope": envelope.model_dump(mode="json"),
        })

        child_script = self._build_child_script(
            str(module_path), class_name, trust_level, package_root,
            enable_seccomp=enable_seccomp,
        )

        try:
            # Build minimal environment — filter secrets, set isolated temp
            child_env = self._build_child_env(temp_dir=temp_dir)

            # Create child cgroup for per-invocation accounting (v1.3.1)
            cg_path = self._create_child_cgroup(node_id)
            self._cgroup_path = cg_path

            # v3.5.1 H2 #1: on Windows, use the sync spawn_contained helper
            # via asyncio.to_thread so the async method does not block.
            # run_bounded_subprocess owns the entire lifecycle: suspended
            # creation, Job Object assignment, resume, bounded I/O,
            # termination, and handle cleanup. Exactly one child is launched.
            if os.name == "nt":
                from nodechain.runtime.streaming_output import run_bounded_subprocess
                _result = await asyncio.to_thread(
                    run_bounded_subprocess,
                    [sys.executable, "-c", child_script],
                    cwd=str(child_cwd),
                    env=child_env,
                    timeout_seconds=self.timeout_seconds,
                    max_output_bytes=self.max_output_bytes,
                    stdin_data=payload,
                )
                elapsed = int((time.monotonic() - start) * 1000)

                if not _result["process_started"]:
                    cg_info = self._finalize_cgroup()
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    return {
                        "success": False,
                        "error": _result.get("stderr", "spawn failed")[:500],
                        "exit_code": _result.get("process_exit_code") or 126,
                        "isolation_mode": "subprocess",
                        "duration_ms": elapsed,
                        "child_policy_enforced": False,
                        "child_cwd": child_cwd,
                        "temp_dir_isolated": True,
                        **cg_info,
                    }
                if _result["process_timed_out"]:
                    cg_info = self._finalize_cgroup()
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    return {
                        "success": False,
                        "error": f"Timeout after {self.timeout_seconds}s",
                        "exit_code": 2,
                        "isolation_mode": "subprocess",
                        "duration_ms": elapsed,
                        "child_policy_enforced": False,
                        "child_cwd": child_cwd,
                        "temp_dir_isolated": True,
                        **cg_info,
                    }
                if _result["output_truncated"]:
                    cg_info = self._finalize_cgroup()
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    return {
                        "success": False,
                        "error": f"Output exceeded {self.max_output_bytes} bytes ({_result.get('reason')})",
                        "exit_code": 3,
                        "isolation_mode": "subprocess",
                        "duration_ms": elapsed,
                        "child_policy_enforced": True,
                        "child_cwd": child_cwd,
                        "temp_dir_isolated": True,
                        **cg_info,
                    }
                _rc = _result["process_exit_code"]
                _stdout_data = _result["stdout"]
                _stderr_data = _result["stderr"]
                if _rc != 0:
                    error_msg = _stderr_data[:2000] if _stderr_data else ""
                    cg_info = self._finalize_cgroup()
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    return {
                        "success": False,
                        "error": error_msg,
                        "exit_code": _rc,
                        "isolation_mode": "subprocess",
                        "duration_ms": elapsed,
                        "child_policy_enforced": _rc == 10,
                        "child_cwd": child_cwd,
                        "temp_dir_isolated": True,
                        **cg_info,
                    }
                try:
                    response_data = json.loads(_stdout_data)
                except (json.JSONDecodeError, ValueError) as e:
                    cg_info = self._finalize_cgroup()
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    return {
                        "success": False,
                        "error": f"Invalid JSON response: {e}",
                        "exit_code": _rc or 1,
                        "isolation_mode": "subprocess",
                        "duration_ms": elapsed,
                        "child_policy_enforced": False,
                        "child_cwd": child_cwd,
                        "temp_dir_isolated": True,
                        **cg_info,
                    }
                cg_info = self._finalize_cgroup()
                shutil.rmtree(temp_dir, ignore_errors=True)
                child_policy_enforced = (
                    response_data.get("metadata", {})
                    .get("child_policy_enforced", False)
                )
                return {
                    "success": True,
                    "response": response_data,
                    "exit_code": _rc,
                    "isolation_mode": "subprocess",
                    "duration_ms": elapsed,
                    "child_policy_enforced": child_policy_enforced,
                    "child_cwd": child_cwd,
                    "temp_dir_isolated": True,
                    **cg_info,
                }

            # v3.5.1 H2 #4: create per-invocation cgroup2 BEFORE spawning.
            # On containers, this is the authoritative containment boundary.
            # On bare metal, start_new_session + killpg is sufficient.
            _sandbox_cg = None
            if os.name == "posix":
                from nodechain.runtime.streaming_output import (
                    _create_cgroup2_sandbox, _posix_containment_available,
                )
                # Fail-closed admission: refuse to execute UNTRUSTED nodes when
                # containment cannot be guaranteed. Trusted and built-in nodes
                # may still execute (they are part of the NodeChain trust boundary).
                if trust_level in ("local_untrusted", "remote_untrusted") and not _posix_containment_available():
                    elapsed = int((time.monotonic() - start) * 1000)
                    cg_info = self._finalize_cgroup()
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    return {
                        "success": False,
                        "error": "containment_unavailable: reliable descendant termination cannot be guaranteed in this environment (container without cgroup v2)",
                        "exit_code": 126,
                        "isolation_mode": "subprocess",
                        "duration_ms": elapsed,
                        "child_policy_enforced": False,
                        "child_cwd": child_cwd,
                        "temp_dir_isolated": True,
                        **cg_info,
                    }
                _sandbox_cg = _create_cgroup2_sandbox()

            # POSIX path: async create_subprocess_exec.
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "-c", child_script,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                close_fds=True,
                env=child_env,
                cwd=child_cwd,
                start_new_session=True,  # always create new session
            )

            # Move child process into cgroup after spawn (v1.3.1)
            if cg_path:
                self._move_pid_to_cgroup(proc.pid)

            # v3.5.1 H2 #4: move child into cgroup2 immediately after spawn.
            if _sandbox_cg:
                from nodechain.runtime.streaming_output import _cgroup2_move_pid
                _cgroup2_move_pid(_sandbox_cg, proc.pid)

            # v3.5.1 H2 #2: bounded async streaming (POSIX path).
            # Windows path returns earlier via run_bounded_subprocess.
            from nodechain.runtime.streaming_output import (
                run_bounded_async, _cgroup2_kill, _cgroup2_cleanup,
            )
            try:
                bounded = await run_bounded_async(
                    proc,
                    input_data=payload.encode(),
                    timeout_seconds=self.timeout_seconds,
                    max_output_bytes=self.max_output_bytes,
                    job_handle=None,
                )
            finally:
                if _sandbox_cg:
                    _cgroup2_kill(_sandbox_cg)
                    _cgroup2_cleanup(_sandbox_cg)

            elapsed = int((time.monotonic() - start) * 1000)

            if bounded["timed_out"]:
                cg_info = self._finalize_cgroup()
                shutil.rmtree(temp_dir, ignore_errors=True)
                return {
                    "success": False,
                    "error": f"Timeout after {self.timeout_seconds}s",
                    "exit_code": 2,
                    "isolation_mode": "subprocess",
                    "duration_ms": elapsed,
                    "child_policy_enforced": False,
                    "child_cwd": child_cwd,
                    "temp_dir_isolated": True,
                    **cg_info,
                }

            if bounded["output_truncated"]:
                cg_info = self._finalize_cgroup()
                shutil.rmtree(temp_dir, ignore_errors=True)
                return {
                    "success": False,
                    "error": f"Output exceeded {self.max_output_bytes} bytes ({bounded['reason']})",
                    "exit_code": 3,
                    "isolation_mode": "subprocess",
                    "duration_ms": elapsed,
                    "child_policy_enforced": True,
                    "child_cwd": child_cwd,
                    "temp_dir_isolated": True,
                    **cg_info,
                }

            stdout_data = bounded["stdout"]
            stderr_data = bounded["stderr"]

            if proc.returncode != 0:
                error_msg = stderr_data[:2000] if stderr_data else ""
                cg_info = self._finalize_cgroup()
                shutil.rmtree(temp_dir, ignore_errors=True)
                return {
                    "success": False,
                    "error": error_msg,
                    "exit_code": proc.returncode,
                    "isolation_mode": "subprocess",
                    "duration_ms": elapsed,
                    "child_policy_enforced": proc.returncode == 10,
                    "child_cwd": child_cwd,
                    "temp_dir_isolated": True,
                    **cg_info,
                }

            response_data = json.loads(stdout_data)
            child_policy_enforced = (
                response_data.get("metadata", {})
                .get("child_policy_enforced", False)
            )
            network_ns_enforced = (
                response_data.get("metadata", {})
                .get("network_namespace_enforced", False)
            )
            mount_ns_enforced = (
                response_data.get("metadata", {})
                .get("mount_namespace_enforced", False)
            )
            mount_confine_enforced = (
                response_data.get("metadata", {})
                .get("mount_confinement_enforced", False)
            )
            pid_ns_enforced = (
                response_data.get("metadata", {})
                .get("pid_namespace_enforced", False)
            )
            procfs_isolated = (
                response_data.get("metadata", {})
                .get("procfs_namespace_view_enforced", False)
            )
            cg_info = self._finalize_cgroup()
            shutil.rmtree(temp_dir, ignore_errors=True)
            return {
                "success": True,
                "response": response_data,
                "exit_code": 0,
                "isolation_mode": "subprocess",
                "duration_ms": elapsed,
                "child_policy_enforced": child_policy_enforced,
                "network_namespace_enforced": network_ns_enforced,
                "mount_namespace_enforced": mount_ns_enforced,
                "mount_confinement_enforced": mount_confine_enforced,
                "pid_namespace_enforced": pid_ns_enforced,
                "procfs_namespace_view_enforced": procfs_isolated,
                "child_cwd": child_cwd,
                "temp_dir_isolated": True,
                **cg_info,
            }

        except Exception as e:
            elapsed = int((time.monotonic() - start) * 1000)
            cg_info = self._finalize_cgroup()
            shutil.rmtree(temp_dir, ignore_errors=True)
            return {
                "success": False,
                "error": str(e),
                "exit_code": -1,
                "isolation_mode": "subprocess",
                "duration_ms": elapsed,
                "child_policy_enforced": False,
                "child_cwd": child_cwd,
                "temp_dir_isolated": True,
                **cg_info,
            }

    def should_use_subprocess(self, trust_level: TrustLevel) -> bool:
        """Determine if a node should run in a subprocess based on trust level."""
        return trust_level in (
            TrustLevel.LOCAL_UNTRUSTED,
            TrustLevel.REMOTE_UNTRUSTED,
        )

    def _create_child_cgroup(self, node_id: str) -> str | None:
        """Create a child cgroup for per-invocation resource accounting.

        Returns the cgroup path, or None if cgroup not available/enabled.
        """
        if not self.enable_cgroup:
            return None
        if platform.system() != "Linux":
            return None
        self._cgroup_limits_applied = False
        self._cgroup_limits_requested = False
        try:
            from nodechain.sdk.cgroup_profile import CgroupBackend, CgroupLimits
            backend = CgroupBackend()
            if not backend.available or not backend.capabilities.cgroup_limits_writable:
                return None
            import uuid
            cg_name = f"nodechain_{node_id}_{uuid.uuid4().hex[:8]}"
            limits = CgroupLimits(
                memory_max_bytes=self.cgroup_memory_max_mb * 1024 * 1024 if self.cgroup_memory_max_mb else 0,
                pids_max=self.cgroup_pids_max if self.cgroup_pids_max else 0,
                cpu_max_quota=self.cgroup_cpu_max_quota if self.cgroup_cpu_max_quota else 0,
            )
            has_limits = bool(limits.memory_max_bytes or limits.pids_max or limits.cpu_max_quota)
            self._cgroup_limits_requested = has_limits
            cg_path = backend.create_child_cgroup(cg_name, limits=limits if has_limits else None)
            if cg_path:
                self._cgroup_backend = backend
                self._cgroup_limits_applied = has_limits
            return cg_path
        except Exception:
            return None

    def _move_pid_to_cgroup(self, pid: int, cgroup_path: str) -> bool:
        """Move child process PID into the cgroup."""
        try:
            backend = getattr(self, "_cgroup_backend", None)
            if backend:
                return backend.move_process_to_cgroup(pid, cgroup_path)
        except Exception:
            pass
        return False

    def _read_cgroup_accounting(self, cgroup_path: str) -> dict[str, Any]:
        """Read per-invocation resource accounting from child cgroup."""
        try:
            from nodechain.sdk.cgroup_profile import read_accounting
            acct = read_accounting(cgroup_path)
            return acct.to_dict()
        except Exception:
            return {}

    def _cleanup_cgroup(self, cgroup_path: str) -> None:
        """Remove child cgroup after process exit."""
        try:
            backend = getattr(self, "_cgroup_backend", None)
            if backend:
                backend.remove_child_cgroup(cgroup_path)
        except Exception:
            pass

    def _finalize_cgroup(self) -> dict[str, Any]:
        """Read accounting from active cgroup and clean up.

        Returns dict with cgroup_accounting, cgroup_path, cgroup_accounting_scope,
        cgroup_limits_requested, cgroup_limits_enforced.
        """
        result: dict[str, Any] = {
            "cgroup_accounting": None,
            "cgroup_path": None,
            "cgroup_accounting_scope": "",
            "cgroup_limits_requested": False,
            "cgroup_limits_enforced": False,
            "cgroup_memory_max_mb": 0,
            "cgroup_pids_max": 0,
            "cgroup_cpu_max_quota": 0,
        }
        cg_path = self._cgroup_path
        if cg_path:
            result["cgroup_accounting"] = self._read_cgroup_accounting(cg_path)
            result["cgroup_path"] = cg_path
            result["cgroup_accounting_scope"] = "invocation"
            result["cgroup_limits_requested"] = self._cgroup_limits_requested
            result["cgroup_limits_enforced"] = self._cgroup_limits_applied
            result["cgroup_memory_max_mb"] = self.cgroup_memory_max_mb
            result["cgroup_pids_max"] = self.cgroup_pids_max
            result["cgroup_cpu_max_quota"] = self.cgroup_cpu_max_quota
            self._cleanup_cgroup(cg_path)
            self._cgroup_path = None
        return result


def get_subprocess_runner(config: RunnerConfig | None = None) -> SubprocessRunner:
    """Get a subprocess runner instance.

    v1.3.9: Prefers explicit RunnerConfig. Falls back to env-var
    resolution for backward compatibility.

    Args:
        config: Explicit runner configuration. If provided, used directly.
                If None, falls back to NODECHAIN_POLICY_PRESET env var.
    """
    if config is not None:
        return SubprocessRunner(**config.to_runner_kwargs())

    # Fallback: resolve from env vars (v1.3.6 behavior)
    env_config = RunnerConfig.from_env()
    if env_config is not None:
        return SubprocessRunner(**env_config.to_runner_kwargs())

    return SubprocessRunner()
