"""v2.76/v2.78: Native OS-sandbox isolated command execution (Linux).

Runs an arbitrary command (argv) inside NodeChain's existing native OS sandbox
stack — PID namespace, network namespace, mount namespace, mount confinement
(with optional workspace bind mount), and seccomp. This is the enforcement
path invoked by ``SandboxCommandRunner``'s ``native_os_sandbox`` backend.

## v2.78 redesign — child-applied seccomp + in-place execve

The v2.76/v2.77 model applied seccomp to the *spawner* then called
``subprocess.run`` to launch the workload — incompatible with the deny-list
(fork/vfork/clone/clone3 are denied, but ``subprocess.run`` needs fork).

v2.78 moves seccomp to the *child*, applied after all setup, immediately before
in-place ``os.execve`` into the workload. The filter survives ``execve`` (Linux
guarantee: seccomp filters attach to the process, not the binary), so the
workload runs confined without the spawner needing fork-denied syscalls.

## Model (single-process after execve)

```
parent / native runner (supervisor)
  - spawns ONE child (the bootstrap) via asyncio.create_subprocess_exec
  - creates a metadata pipe; passes the write FD to the child via pass_fds
  - owns stdout/stderr capture (workload output = child's stdout/stderr after exec)
  - owns timeout + final result normalization (exit code, output cap)
  - reads setup metadata from the metadata pipe (NOT stdout)

bootstrap child (Python, spawned by parent)
  1. enters PID/network/mount/chroot/procfs boundary
  2. writes setup metadata to the metadata pipe
  3. applies seccomp to SELF (process-local filter)
  4. writes seccomp_applied metadata to the metadata pipe
  5. closes the metadata pipe
  6. os.execve() workload argv IN PLACE — replaces self with workload

workload (the argv)
  - inherits the seccomp filter (survives execve)
  - emits normal stdout/stderr only
```

Security posture: this module does NOT claim complete hostile-code containment.
It reuses the existing native OS sandbox primitives; enforcement strength is
bounded by kernel namespace/seccomp guarantees. Fail-closed on non-Linux hosts
is handled by the caller (NativeOsSandboxBackend), not here.
"""
from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from nodechain.runtime.exec_supervisor import SupervisorExecutionEvidence


def _build_child_script() -> str:
    """Build the isolated child bootstrap script.

    v2.78: the child does setup + seccomp + in-place execve (terminal).
    It does NOT return. The parent reads setup metadata from a side-channel
    pipe FD and the workload's stdout/stderr/exit from the child process.
    """
    return '''
import sys, os, json, traceback

# v2.77/v2.78 fix: TRUSTED PRE-CHROOT IMPORT PHASE.
# All nodechain.sdk.* imports MUST happen while the filesystem is still fully
# visible (before chroot). Once mounted/confinement is applied, these modules
# stay in sys.modules and don't need filesystem access.
_APPLY_PID_NS_TWO_STAGE = None
_PID_NS_SUCCESS = _PID_NS_SKIP = _PID_NS_FAIL = None
_REMOUNT_PROCFS = None
_APPLY_NETWORK_NS = None
_APPLY_MOUNT_NS = None
_APPLY_MOUNT_CONFINEMENT = None
_SECCOMP_PROFILE_CLS = _SECCOMP_BACKEND = None
try:
    from nodechain.sdk.namespace_profile import (
        apply_pid_namespace_two_stage as _APPLY_PID_NS_TWO_STAGE,
        _PID_NS_SUCCESS, _PID_NS_SKIP, _PID_NS_FAIL,
        remount_procfs_for_pid_namespace as _REMOUNT_PROCFS,
        apply_network_namespace as _APPLY_NETWORK_NS,
        apply_mount_namespace as _APPLY_MOUNT_NS,
        apply_mount_confinement as _APPLY_MOUNT_CONFINEMENT,
    )
    from nodechain.sdk.seccomp_profile import (
        SeccompProfile as _SECCOMP_PROFILE_CLS,
        SeccompBackend as _SECCOMP_BACKEND,
    )
    _NATIVE_IMPORT_ERROR = ""
except Exception as _import_err:
    _NATIVE_IMPORT_ERROR = str(_import_err)


_AUTHORITY_STATES = frozenset({
    "bootstrap_started", "enforcement_verified", "exec_attempted",
    "exec_failed", "bootstrap_failed",
})


def _emit_meta(metadata_fd, obj):
    """Write one NDJSON metadata record to the side-channel pipe.

    v3.5.1 H2 #5: authoritative state transitions (bootstrap_state changes)
    are written in a retry loop and treat write failure as FATAL. Ordinary
    diagnostic metadata (namespaced flags, error strings) remains best-effort.
    """
    is_authority = "bootstrap_state" in obj and obj["bootstrap_state"] in _AUTHORITY_STATES
    data = (json.dumps(obj) + "\\n").encode()
    if is_authority:
        # Strict write: retry until the complete record is written.
        # A failed write of an authoritative state is bootstrap-fatal.
        written = 0
        for _attempt in range(5):
            try:
                n = os.write(metadata_fd, data[written:])
                written += n
                if written >= len(data):
                    return  # success
            except OSError:
                break
        # Write failed — this is a protocol failure. The parent will see
        # missing/stale authority metadata and fail closed.
        # We cannot emit bootstrap_failed here because the pipe itself is
        # broken. Exit non-zero so the parent sees an error exit code.
        sys.stderr.write("native sandbox: FATAL — authority metadata write failed\\n")
        sys.exit(125)
    else:
        # Diagnostic metadata — best-effort, never crashes bootstrap.
        try:
            os.write(metadata_fd, data)
        except Exception:
            pass


def main():
    try:
        cfg = json.loads(sys.stdin.read())
        argv = cfg["argv"]
        cwd = cfg["cwd"]
        workspace_src = cfg.get("workspace_src")
        metadata_fd = cfg["metadata_fd"]
        enable_pid_ns = cfg.get("enable_pid_namespace", False)
        enable_procfs = cfg.get("enable_procfs_isolation", False)
        enable_net_ns = cfg.get("enable_network_namespace", False)
        enable_mount_ns = cfg.get("enable_mount_namespace", False)
        enable_mount_confine = cfg.get("enable_mount_confinement", False)
        enable_seccomp = cfg.get("enable_seccomp", False)

        # v3.5.1 H2 #2: set FD_CLOEXEC on the exec-error pipe so successful
        # execve auto-closes it (parent sees clean EOF = workload started).
        exec_error_fd = cfg.get("exec_error_fd")
        if exec_error_fd is not None:
            try:
                import fcntl as _fcntl
                _flags = _fcntl.fcntl(exec_error_fd, _fcntl.F_GETFD)
                _fcntl.fcntl(exec_error_fd, _fcntl.F_SETFD, _flags | _fcntl.FD_CLOEXEC)
            except (ImportError, OSError):
                pass  # fcntl not available (Windows) — metadata pipe is the fallback

        meta = {"seccomp_requested": enable_seccomp}

        # v3.5.1 H2 #5: explicit local stage variable that tracks the ACTUAL
        # current bootstrap stage, advanced independently from the metadata
        # dictionary. This is used in the except handler to emit the correct
        # authority state (exec_failed vs bootstrap_failed).
        _stage = "init"

        # v3.5.1 H2 #6: explicit bootstrap protocol state. The parent uses this to
        # distinguish bootstrap failure from workload start.
        meta["bootstrap_state"] = "bootstrap_started"
        _stage = "bootstrap_started"
        _emit_meta(metadata_fd, meta)
        if _NATIVE_IMPORT_ERROR:
            meta["native_import_error"] = _NATIVE_IMPORT_ERROR
            _emit_meta(metadata_fd, meta)
            # Cannot proceed without the native modules.
            sys.stderr.write("native sandbox: import error: " + _NATIVE_IMPORT_ERROR)
            sys.exit(127)

        # Phase 0: PID namespace (MUST precede seccomp — fork is denied after)
        # v3.5.1 H2 #5: deterministic primitive-failure injection.
        if cfg.get("_force_pid_namespace_unavailable"):
            meta["pid_namespace_error"] = "injected failure"
        elif enable_pid_ns and _APPLY_PID_NS_TWO_STAGE is not None:
            try:
                import platform as _plat
                if _plat.system() == "Linux":
                    r = _APPLY_PID_NS_TWO_STAGE()
                    if r == _PID_NS_SUCCESS:
                        meta["pid_namespace_enforced"] = True
                        if enable_procfs and _REMOUNT_PROCFS is not None:
                            if cfg.get("_force_procfs_isolation_unavailable"):
                                meta["procfs_error"] = "injected failure"
                            else:
                                meta.update(_REMOUNT_PROCFS())
            except Exception as e:
                meta["pid_namespace_error"] = str(e)

        # Phase 1: Network namespace
        if cfg.get("_force_network_namespace_unavailable"):
            meta["network_namespace_error"] = "injected failure"
        elif enable_net_ns and _APPLY_NETWORK_NS is not None:
            try:
                import platform as _plat
                if _plat.system() == "Linux":
                    meta["network_namespace_enforced"] = _APPLY_NETWORK_NS()
            except Exception as e:
                meta["network_namespace_error"] = str(e)

        # Phase 2: Mount namespace + confinement
        if cfg.get("_force_mount_confinement_unavailable"):
            meta["mount_confinement_error"] = "injected failure"
        elif enable_mount_confine and _APPLY_MOUNT_CONFINEMENT is not None:
            try:
                import platform as _plat
                if _plat.system() == "Linux":
                    # v2.77: bind-mount /usr, /lib, /lib64, venv so argv[0]
                    # (the python interpreter) is reachable inside the chroot.
                    interpreter = argv[0] if argv else "/usr/bin/python3"
                    extra_mounts = []
                    for d in ("/usr", "/lib", "/lib64"):
                        if os.path.isdir(d):
                            extra_mounts.append((d, d))
                    if "/.venv/" in interpreter or "/venv/" in interpreter:
                        parts = interpreter.split("/")
                        if "bin" in parts:
                            venv_root = "/".join(parts[:parts.index("bin")])
                            if venv_root and os.path.isdir(venv_root):
                                extra_mounts.append((venv_root, venv_root))
                    confine = _APPLY_MOUNT_CONFINEMENT(
                        package_root=cfg.get("package_root", "/"),
                        temp_dir=cfg.get("temp_dir", "/tmp"),
                        workspace_src=workspace_src,
                        extra_mounts=extra_mounts,
                    )
                    meta["mount_confinement"] = confine
                    if confine.get("mount_confinement_enforced"):
                        meta["mount_confinement_enforced"] = True
                        meta["allowed_mounts"] = confine.get("allowed_mounts", [])
                        meta["chrooted_workspace_prefix"] = confine.get("chrooted_workspace_prefix", "")
            except Exception as e:
                meta["mount_confinement_error"] = str(e)
        elif enable_mount_ns and _APPLY_MOUNT_NS is not None:
            try:
                import platform as _plat
                if _plat.system() == "Linux":
                    meta["mount_namespace_enforced"] = _APPLY_MOUNT_NS()
            except Exception as e:
                meta["mount_namespace_error"] = str(e)

        # Emit setup metadata (pre-seccomp) to the side channel.
        _emit_meta(metadata_fd, meta)

        # Phase 3: Seccomp — apply to SELF. Filter survives execve.
        # NON-NEGOTIABLE: after this, no fork/clone/Popen. Only os.execve.
        seccomp_meta = {"seccomp_apply_mode": "child_pre_exec"}
        if enable_seccomp and _SECCOMP_BACKEND is not None:
            try:
                import platform as _plat
                if _plat.system() == "Linux":
                    sb = _SECCOMP_BACKEND()
                    # v3.5.1 H2: deterministic test injection — force seccomp unavailable.
                    if cfg.get("_force_seccomp_unavailable"):
                        sb._available = False
                    if sb.available:
                        applied = sb.apply_profile(_SECCOMP_PROFILE_CLS())
                        seccomp_meta["seccomp_applied"] = bool(applied)
                    else:
                        seccomp_meta["seccomp_applied"] = False
                        seccomp_meta["seccomp_unavailable"] = True
                else:
                    seccomp_meta["seccomp_applied"] = False
                    seccomp_meta["seccomp_unavailable"] = True
            except Exception as e:
                seccomp_meta["seccomp_applied"] = False
                seccomp_meta["seccomp_error"] = str(e)
        else:
            seccomp_meta["seccomp_applied"] = False
            if not enable_seccomp:
                seccomp_meta["seccomp_skipped"] = True
            elif _SECCOMP_BACKEND is None:
                seccomp_meta["seccomp_unavailable"] = True

        _emit_meta(metadata_fd, seccomp_meta)

        # v3.5.1 (#1) H2: MANDATORY enforcement-tuple verification. Every
        # requested primitive MUST have reported *_enforced=True. If any
        # required primitive is absent, failed, or errored, ABORT before
        # execve — never run the workload with incomplete enforcement.
        # This is the fail-closed contract: the workload may start ONLY when
        # all requested controls are verified.
        # v3.5.1 H2 #5: procfs isolation is included in the tuple.
        _enforcement_failures = []
        if enable_pid_ns and not meta.get("pid_namespace_enforced"):
            _enforcement_failures.append("pid_namespace")
        if enable_procfs and not meta.get("procfs_namespace_view_enforced"):
            _enforcement_failures.append("procfs_isolation")
        if enable_net_ns and not meta.get("network_namespace_enforced"):
            _enforcement_failures.append("network_namespace")
        if enable_mount_confine and not meta.get("mount_confinement_enforced"):
            _enforcement_failures.append("mount_confinement")
        if enable_mount_ns and not enable_mount_confine and not meta.get("mount_namespace_enforced"):
            _enforcement_failures.append("mount_namespace")
        if enable_seccomp and not seccomp_meta.get("seccomp_applied"):
            _enforcement_failures.append("seccomp")
        if _enforcement_failures:
            _abort_meta = {
                "bootstrap_state": "bootstrap_failed",
                "enforcement_failed": _enforcement_failures,
                "workload_started": False,
            }
            _emit_meta(metadata_fd, _abort_meta)
            try:
                os.close(metadata_fd)
            except Exception:
                pass
            sys.stderr.write(
                "native sandbox: enforcement verification FAILED for: "
                + ", ".join(_enforcement_failures)
                + " — workload NOT started\\n"
            )
            sys.exit(126)

        # v3.5.1 H2 #6: set the metadata FD to close-on-exec. On successful
        # execve, the FD auto-closes (no leak to workload). On FAILED exec,
        # the child can still emit bootstrap_failed before exiting.
        try:
            import fcntl as _fcntl
            _flags = _fcntl.fcntl(metadata_fd, _fcntl.F_GETFD)
            _fcntl.fcntl(metadata_fd, _fcntl.F_SETFD, _flags | _fcntl.FD_CLOEXEC)
        except (ImportError, OSError):
            # fcntl not available (Windows) — fall back to explicit close.
            _emit_meta(metadata_fd, {"bootstrap_state": "enforcement_verified"})
            _stage = "enforcement_verified"
            try:
                os.close(metadata_fd)
            except Exception:
                pass
        else:
            _emit_meta(metadata_fd, {"bootstrap_state": "enforcement_verified"})
            _stage = "enforcement_verified"

        # v3.5.1 (#2) H2: the workload environment is the bootstrap env (which
        # was already filtered by the parent from the allowlist). The bootstrap
        # was spawned with env=_bootstrap_env, so os.environ IS the filtered set.
        # The v3.5.0 code used ``env = dict(os.environ)`` with the FULL parent
        # env — now the bootstrap env is filtered at spawn, so this is correct.
        env = dict(os.environ)

        # v3.5.1 H2 #4: PATH bypass rule. execvpe searches PATH for slash-less
        # argv[0]. Only admit PATH if:
        # (a) argv[0] has no slash (needs PATH lookup); AND
        # (b) PATH is already in the filtered env (caller explicitly allowed it).
        # If argv[0] is an absolute/relative path with a slash, PATH is never
        # needed. If PATH is not in the filtered env and argv[0] needs lookup,
        # use os.execve with an absolute resolution or fail rather than inherit.
        if "/" not in (argv[0] if argv else "") and "PATH" not in env:
            # argv[0] is slash-less but PATH was not allowed. Resolve via
            # shutil.which on the FULL parent PATH (available to the bootstrap
            # Python) to get an absolute path, then use execve (no PATH needed).
            import shutil as _shutil
            _resolved = _shutil.which(argv[0]) if argv else None
            if _resolved:
                argv[0] = _resolved
            else:
                sys.stderr.write(
                    "native sandbox: cannot resolve argv[0] without PATH\\n"
                )
                sys.exit(126)
        # Phase 4: TERMINAL — execve the workload in place.
        # The seccomp filter (if applied) survives this exec; the workload runs confined.
        ws_prefix = meta.get("chrooted_workspace_prefix")
        if ws_prefix:
            env["PYTHONPATH"] = ws_prefix.rstrip("/") + "/src"
            os.chdir(ws_prefix)
        else:
            os.chdir(cwd)

        # v3.5.1 H2 #6: emit exec_attempted before the terminal exec.
        # On successful exec, the FD auto-closes (O_CLOEXEC). On failure, the
        # except block below emits bootstrap_failed.
        _emit_meta(metadata_fd, {"bootstrap_state": "exec_attempted"})
        _stage = "exec_attempted"

        # v3.5.1 H2 #4: the exec-error pipe has CLOEXEC set. On successful
        # execve, the kernel atomically closes the FD — the pipe is empty
        # because the success path never writes to it. On failed execve, the
        # bootstrap writes a failure record to this pipe. If the write fails,
        # the pipe remains empty — but the bootstrap then exits with a
        # bootstrap error code (126), which the parent treats conservatively.
        # The parent NEVER sees the proof byte approach — empty+EOF is the
        # success signal, non-empty is the failure signal.

        # v3.5.1 H2 #4: use execve (not execvpe) when argv[0] is resolved to
        # an absolute path or contains a slash. execvpe would search PATH
        # from the (possibly PATH-less) workload env.
        if "/" in (argv[0] if argv else "") or "PATH" not in env:
            os.execve(argv[0], argv, env)
        else:
            os.execvpe(argv[0], argv, env)
        # NOTREACHED
        sys.stderr.write("native sandbox: execve returned unexpectedly\\n")
        sys.exit(127)

    except Exception:
        # v3.5.1 H2 #4: if we're past exec_attempted, write failure record to
        # the exec-error pipe AFTER the proof byte (0x01) that was already
        # written before execve. The parent sees: proof byte + failure data →
        # exec failed. If this write fails, the parent sees proof byte + clean
        # EOF → which is still ambiguous between success and failed-write-after-
        # proof. BUT: the proof byte proves the bootstrap reached exec boundary,
        # and the metadata pipe's exec_failed state (written below) is the
        # independent corrective channel.
        import traceback as _tb
        _err_msg = str(_tb.format_exc())[:500]
        if _stage == "exec_attempted" and exec_error_fd is not None:
            _err_data = json.dumps({"exec_failed": _err_msg}).encode()
            _written = 0
            _attempts = 0
            while _written < len(_err_data) and _attempts < 20:
                _attempts += 1
                try:
                    n = os.write(exec_error_fd, _err_data[_written:])
                    _written += n
                except InterruptedError:
                    _attempts -= 1
                    continue
                except OSError:
                    break
            try:
                os.close(exec_error_fd)
            except OSError:
                pass
        try:
            if _stage == "exec_attempted":
                _emit_meta(metadata_fd, {"bootstrap_state": "exec_failed"})
            else:
                _emit_meta(metadata_fd, {"bootstrap_state": "bootstrap_failed"})
        except SystemExit:
            raise  # _emit_meta may call sys.exit on authority-write failure
        except Exception:
            pass
        sys.stderr.write("native sandbox bootstrap traceback:\\n")
        sys.stderr.write(traceback.format_exc())
        sys.exit(126)


main()
'''


def _classify_exit(returncode: int | None, timed_out: bool) -> tuple[str, str | None]:
    """Classify exit code into interpretation + optional reason.

    v2.78: detect seccomp SIGSYS kill (the default KILL action). When the
    workload trips a denied syscall, Linux terminates the process with SIGSYS
    (signal 31). The exit code may surface as either:
      - negative returncode (-31), the conventional waitstatus_to_exitcode form, OR
      - positive 128+31 = 159, the shell/POSIX propagation form.
    Both indicate a seccomp kill; classify accordingly.
    """
    if timed_out:
        return "timeout", None
    if returncode is None:
        return "error", "no_exit_code"
    if returncode == 0:
        return "pass", None
    if returncode < 0:
        # Killed by signal -returncode (conventional form).
        if -returncode == signal.SIGSYS:
            return "fail", "seccomp_sigsys_kill"
        return "fail", f"signal_{-returncode}"
    if returncode > 128:
        # Killed by signal (returncode - 128), shell/POSIX propagation form.
        sig = returncode - 128
        if sig == signal.SIGSYS:
            return "fail", "seccomp_sigsys_kill"
        return "fail", f"signal_{sig}"
    return "fail", None


async def _run_child(child_script: str, config: dict[str, Any]) -> dict[str, Any]:
    """Spawn the bootstrap child, capture workload output, read metadata pipe.

    v2.78 model: the child does setup + seccomp + execve (terminal). The parent
    reads the workload's stdout/stderr/exit from the child process, and reads
    setup/seccomp metadata from a side-channel pipe.

    v3.5.1 H2 #2: a SECOND pipe — the exec-error pipe — uses FD_CLOEXEC.
    On successful execve, the kernel auto-closes the FD → parent sees clean
    EOF → workload_started=True. On failed execve, the bootstrap writes an
    error record → workload_started=False. Ambiguous/missing → fail closed.
    """
    # Create the metadata pipe. Pass the write end to the child.
    rfd, wfd = os.pipe()
    config["metadata_fd"] = wfd

    # v3.5.1 H2 #2: create the exec-error pipe. The child sets FD_CLOEXEC
    # on the write end so successful execve auto-closes it.
    exec_rfd, exec_wfd = os.pipe()
    config["exec_error_fd"] = exec_wfd

    try:
        # v3.5.1 H2 #3: filter the BOOTSTRAP environment. The v3.5.0 code
        # spawned the bootstrap with no env= argument, inheriting the complete
        # NodeChain process environment (credentials, tokens, Python control
        # variables). The bootstrap needs only a minimal set to start Python.
        # The WORKLOAD env is separately filtered inside the child script
        # before execvpe (see #2 fix above).
        _allowlist = set(config.get("env_allowlist", []))
        if _allowlist:
            _bootstrap_env = {
                k: v for k, v in os.environ.items() if k in _allowlist
            }
        else:
            _bootstrap_env = {}
        # The bootstrap Python needs SYSTEMROOT on Windows; always admit it.
        if os.name == "nt" and "SYSTEMROOT" in os.environ:
            _bootstrap_env.setdefault("SYSTEMROOT", os.environ["SYSTEMROOT"])

        # v3.5.1 (#3) H2: start_new_session so the process group can be killed
        # on timeout or output-cap exceedance (POSIX).
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-c", child_script,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            pass_fds=(wfd, exec_wfd),
            close_fds=True,
            start_new_session=True,
            env=_bootstrap_env,
        )
    finally:
        # Parent closes its copy of the write ends so EOF is reached when child closes.
        os.close(wfd)
        os.close(exec_wfd)

    input_payload = json.dumps(config).encode()
    # v3.5.1 H2 #1: replace communicate() with bounded async streaming.
    # The native sandbox reads stdout/stderr concurrently with per-stream
    # and combined byte caps; kills the process group when limits are crossed.
    from nodechain.runtime.streaming_output import (
        run_bounded_async, _create_windows_job_object,
        _assign_to_job_object, _close_job_handle,
    )
    max_output = config.get("max_output_bytes", 50_000)
    timeout_s = config.get("timeout_seconds", 120)
    # v3.5.1 H2 #5: create Windows Job Object for descendant termination.
    _native_job = None
    if os.name == "nt":
        _native_job = _create_windows_job_object()
        if _native_job is not None:
            _assign_to_job_object(_native_job, proc)
    try:
        bounded = await run_bounded_async(
            proc,
            input_data=input_payload,
            timeout_seconds=timeout_s,
            max_output_bytes=max_output,
            job_handle=_native_job,
        )
    except Exception:
        # Fallback: if the streaming reader itself fails, kill and report error.
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (OSError, ProcessLookupError):
            proc.kill()
        await proc.wait()
        _close_job_handle(_native_job)
        return {
            "process_started": False,
            "process_exit_code": proc.returncode,
            "process_timed_out": False,
            "stdout": "",
            "stderr": "native sandbox streaming reader error",
            "output_truncated": False,
            "exit_code_interpretation": "error",
            "reason": "streaming_reader_error",
            "backend": "native_os_sandbox",
            "sandbox_metadata": {},
            "sandbox_event_log": [{"event_type": "code_execution_failed", "backend": "native_os_sandbox"}],
        }

    stdout_b = bounded["stdout"]
    stderr_b = bounded["stderr"]
    output_truncated = bounded["output_truncated"]
    timed_out = bounded["timed_out"]

    # v3.5.1 H2 #6: ALWAYS read metadata regardless of termination path (timeout,
    # output-cap, normal, error). The bootstrap protocol state determines whether the
    # workload actually started. Missing/malformed metadata fails closed.
    sandbox_metadata: dict[str, Any] = {}
    try:
        os.set_blocking(rfd, False)
        meta_bytes = b""
        while True:
            try:
                chunk = os.read(rfd, 65536)
            except BlockingIOError:
                break
            if not chunk:
                break
            meta_bytes += chunk
        for line in meta_bytes.decode(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                if isinstance(rec, dict):
                    sandbox_metadata.update(rec)
            except Exception:
                pass
    except Exception:
        pass
    finally:
        try:
            os.close(rfd)
        except OSError:
            pass

    # v3.5.1 H2 #4: read the exec-error pipe.
    # The exec-error pipe has CLOEXEC set. On successful execve, the kernel
    # closes the FD — the pipe is EMPTY (success path never writes to it).
    # On failed execve, the bootstrap writes a failure record before exiting.
    #
    # States:
    #   clean_eof: empty + confirmed EOF → CLOEXEC closure (success)
    #   error_record: any data → exec failed
    #   no_proof_byte: alias for would_block/ambiguous (bootstrap may not have
    #     reached exec, or the pipe was closed by process exit without CLOEXEC)
    #   would_block: pipe still open (ambiguous)
    #   read_error: pipe read failed (ambiguous)
    #
    # process_started=True requires clean_eof.
    # The locked adversarial case (exec fails + error write fails + metadata
    # correction fails) produces empty+EOF from process exit, which is
    # indistinguishable from CLOEXEC success. This is a fundamental limitation
    # of single-FD CLOEXEC protocols. We conservatively accept the risk because:
    # (a) the metadata pipe's exec_failed write is a SECOND independent channel
    #     that would catch the failure if the write succeeds;
    # (b) the bootstrap exits with code 126 on failure, which the parent
    #     treats as a non-workload exit.
    exec_pipe_state = "would_block"  # default: ambiguous
    exec_failed_msg = None
    try:
        os.set_blocking(exec_rfd, False)
        exec_bytes = b""
        eof_observed = False
        while True:
            try:
                chunk = os.read(exec_rfd, 65536)
            except BlockingIOError:
                break
            except OSError:
                exec_pipe_state = "read_error"
                break
            if not chunk:
                eof_observed = True
                break
            exec_bytes += chunk
        if exec_pipe_state != "read_error":
            if eof_observed:
                if len(exec_bytes) == 0:
                    exec_pipe_state = "clean_eof"
                else:
                    exec_pipe_state = "error_record"
                    exec_failed_msg = exec_bytes.decode(errors="replace")[:500]
            # else: would_block — ambiguous
    except Exception:
        exec_pipe_state = "read_error"
    finally:
        try:
            os.close(exec_rfd)
        except OSError:
            pass

    # v3.5.1 H2 #2: STRICT state machine using exec_pipe_state.
    # process_started=True requires clean_eof AND no enforcement_failed
    # AND bootstrap_state == exec_attempted.
    # would_block, read_error, malformed, error_record all fail closed.
    bootstrap_state = sandbox_metadata.get("bootstrap_state")
    enforcement_failed = sandbox_metadata.get("enforcement_failed")

    # v3.5.1 H2 #4: Conservative exec-start authority.
    # process_started=True requires ALL:
    #   exec_pipe_state == "clean_eof" (CLOEXEC closure, empty pipe)
    #   no enforcement_failed
    #   bootstrap_state == "exec_attempted"
    #   exit code is NOT a bootstrap-error code (125, 126, 127)
    #
    # The exit-code check is a CONSERVATIVE guard against the zero-byte
    # false-positive: if execve failed and both correction channels failed,
    # the bootstrap exits with 126. The pipe is empty (clean_eof) and metadata
    # is stale (exec_attempted). The exit code 126 reveals the bootstrap
    # failure. This is conservative: a workload that legitimately exits
    # 125/126/127 would be reported as process_started=False (false negative,
    # not false positive). This is acceptable for a security boundary.
    _exit_code = proc.returncode
    _bootstrap_exit = _exit_code is not None and _exit_code in (125, 126, 127)

    if exec_pipe_state != "clean_eof" or enforcement_failed or bootstrap_state != "exec_attempted" or _bootstrap_exit:
        # Check enforcement_failed FIRST — it aborts before the exec boundary,
        # so the exec-error pipe correctly has no proof byte.
        if enforcement_failed:
            reason = "enforcement_verification_failed"
        elif _bootstrap_exit and exec_pipe_state == "clean_eof":
            reason = "bootstrap_exit_after_exec_attempt"
        elif exec_pipe_state == "error_record":
            reason = "exec_failed"
            sandbox_metadata["exec_failed"] = exec_failed_msg
        elif exec_pipe_state == "no_proof_byte":
            # No proof byte: either bootstrap failed before exec, or proof write failed.
            # If metadata shows enforcement_verified, this is ambiguous — fail closed.
            # If metadata shows bootstrap_failed/exec_failed, use that reason.
            if bootstrap_state == "exec_failed":
                reason = "exec_failed"
            elif bootstrap_state == "bootstrap_failed":
                reason = "bootstrap_failed"
            else:
                reason = "exec_pipe_no_proof_byte"
        elif exec_pipe_state in ("would_block", "read_error"):
            reason = f"exec_pipe_{exec_pipe_state}"
        elif timed_out:
            reason = "bootstrap_timeout"
        elif bootstrap_state == "exec_failed":
            reason = "exec_failed"
        elif bootstrap_state == "bootstrap_failed":
            reason = "bootstrap_failed"
        elif bootstrap_state is None:
            reason = "bootstrap_protocol_error"
        else:
            reason = f"bootstrap_incomplete_{bootstrap_state}"
        event_log = [
            {"event_type": "code_execution_failed", "backend": "native_os_sandbox",
             "metadata": {"reason": reason,
                          "failed_primitives": enforcement_failed or [],
                          "bootstrap_state": bootstrap_state}},
        ]
        return {
            "process_started": False,
            "process_exit_code": proc.returncode,
            "process_timed_out": timed_out,
            "stdout": "",
            "stderr": stderr_b if stderr_b else "",
            "output_truncated": False,
            "exit_code_interpretation": "error",
            "reason": reason,
            "backend": "native_os_sandbox",
            "sandbox_metadata": sandbox_metadata,
            "sandbox_event_log": event_log,
        }

    # Workload started (exec_attempted confirmed). Assemble the result using
    # the bounded reader's classification for output-limit propagation.
    # v3.5.1 H2 #7: propagate the bounded reader's output_limit_exceeded reason.
    bounded_reason = bounded.get("reason")
    if bounded_reason == "output_limit_exceeded":
        interpretation = "fail"
        reason = "output_limit_exceeded"
    elif timed_out:
        interpretation = "timeout"
        reason = "timeout"
    else:
        interpretation, reason = _classify_exit(proc.returncode, timed_out=False)

    stdout_s = bounded["stdout"]
    stderr_s = bounded["stderr"]

    event_log = [{"event_type": "code_execution_started", "backend": "native_os_sandbox"}]
    if interpretation == "pass":
        event_log.append({"event_type": "code_execution_completed", "backend": "native_os_sandbox",
                          "metadata": {"exit_code": proc.returncode}})
    elif interpretation == "timeout":
        event_log.append({"event_type": "code_execution_timed_out", "backend": "native_os_sandbox"})
    else:
        event_log.append({"event_type": "code_execution_failed", "backend": "native_os_sandbox",
                          "metadata": {"exit_code": proc.returncode, "reason": reason}})
    if output_truncated:
        event_log.append({"event_type": "sandbox_output_capped", "backend": "native_os_sandbox"})

    return {
        "process_started": True,
        "process_exit_code": proc.returncode,
        "process_timed_out": False,
        "stdout": stdout_s,
        "stderr": stderr_s,
        "output_truncated": output_truncated,
        "exit_code_interpretation": interpretation,
        "reason": reason,
        "backend": "native_os_sandbox",
        "sandbox_metadata": sandbox_metadata,
        "sandbox_event_log": event_log,
    }


# ---------------------------------------------------------------------------
# v3.5.1 H2 S3: Supervised execution path (exact exec-start authority)
# ---------------------------------------------------------------------------

def map_supervisor_result(
    evidence: SupervisorExecutionEvidence,
    bounded: dict[str, Any] | None,
    *,
    output_task_failure: bool = False,
) -> dict[str, Any]:
    """Pure function: map supervisor evidence + bounded output to result schema.

    Fix #6 (round 3): extracted as a pure function for direct unit testing.
    """
    process_started = evidence.exec_confirmed

    # Fix #2 (round 3): output-task failure → streaming_reader_error.
    if output_task_failure or bounded is None:
        # Fix #4 (round 3): preserve full trusted truth.
        if evidence.workload_signal is not None:
            exit_code = -evidence.workload_signal
        else:
            exit_code = evidence.workload_exit_code
        # Fix #5 (round 4): retain ALL trusted truth in metadata.
        sandbox_metadata = dict(evidence.enforcement_metadata)
        sandbox_metadata["protocol_valid"] = evidence.protocol_valid
        sandbox_metadata["protocol_failure_reason"] = evidence.protocol_failure_reason
        sandbox_metadata["cleanup_succeeded"] = evidence.cleanup_succeeded
        sandbox_metadata["workload_exit_code"] = evidence.workload_exit_code
        sandbox_metadata["workload_signal"] = evidence.workload_signal
        if evidence.supervisor_failure_reason:
            sandbox_metadata["supervisor_failure_reason"] = evidence.supervisor_failure_reason
        event_log = []
        if process_started:
            event_log.append({"event_type": "code_execution_started", "backend": "native_os_sandbox"})
        event_log.append({"event_type": "code_execution_failed", "backend": "native_os_sandbox",
                          "metadata": {"reason": "streaming_reader_error"}})
        return {
            "process_started": process_started,
            "process_exit_code": exit_code,
            "process_timed_out": False,
            "stdout": "", "stderr": "streaming_reader_error",
            "output_truncated": False,
            "exit_code_interpretation": "error",
            "reason": "streaming_reader_error",
            "backend": "native_os_sandbox",
            "sandbox_metadata": sandbox_metadata,
            "sandbox_event_log": event_log,
        }

    stdout_b = bounded.get("stdout", "")
    stderr_b = bounded.get("stderr", "")
    output_truncated = bounded.get("output_truncated", False)
    timed_out = bounded.get("timed_out", False)

    sandbox_metadata = dict(evidence.enforcement_metadata)
    if evidence.supervisor_failure_reason:
        sandbox_metadata["supervisor_failure_reason"] = evidence.supervisor_failure_reason
    if evidence.protocol_failure_reason:
        sandbox_metadata["protocol_failure_reason"] = evidence.protocol_failure_reason

    if not process_started:
        reason = evidence.supervisor_failure_reason or evidence.protocol_failure_reason or "bootstrap_failed"
        if timed_out:
            reason = "bootstrap_timeout"
        return {
            "process_started": False,
            "process_exit_code": evidence.workload_exit_code,
            "process_timed_out": timed_out,
            "stdout": "", "stderr": stderr_b if stderr_b else "",
            "output_truncated": False,
            "exit_code_interpretation": "error",
            "reason": reason,
            "backend": "native_os_sandbox",
            "sandbox_metadata": sandbox_metadata,
            "sandbox_event_log": [
                {"event_type": "code_execution_failed", "backend": "native_os_sandbox",
                 "metadata": {"reason": reason, "protocol_valid": evidence.protocol_valid}},
            ],
        }

    # Fix #1: process_exit_code = workload exit, not supervisor return code.
    if evidence.workload_signal is not None:
        workload_exit_code = -evidence.workload_signal
    elif evidence.workload_exit_code is not None:
        workload_exit_code = evidence.workload_exit_code
    else:
        workload_exit_code = None

    # Fix #3: locked precedence after exec_confirmed.
    overall_failure = False
    bounded_reason = bounded.get("reason")
    if bounded_reason == "output_limit_exceeded":
        interpretation = "fail"
        reason = "output_limit_exceeded"
    elif timed_out:
        interpretation = "timeout"
        reason = "timeout"
    elif evidence.supervisor_failure_reason:
        interpretation = "error"
        reason = evidence.supervisor_failure_reason
        overall_failure = True
    elif evidence.cleanup_succeeded is False:
        interpretation = "error"
        reason = "cleanup_failed"
        overall_failure = True
    elif not evidence.protocol_valid:
        interpretation = "error"
        reason = evidence.protocol_failure_reason or "protocol_invalid"
        overall_failure = True
    elif evidence.workload_signal is not None:
        if evidence.workload_signal == signal.SIGSYS:
            interpretation = "fail"
            reason = "seccomp_sigsys_kill"
        else:
            interpretation = "fail"
            reason = f"signal_{evidence.workload_signal}"
    elif evidence.workload_exit_code is not None:
        interpretation, reason = _classify_exit(evidence.workload_exit_code, timed_out=False)
    else:
        interpretation = "error"
        reason = "supervisor_error_after_exec"
        overall_failure = True

    # Build event log.
    event_log = [{"event_type": "code_execution_started", "backend": "native_os_sandbox"}]
    if not overall_failure and interpretation == "pass":
        event_log.append({"event_type": "code_execution_completed", "backend": "native_os_sandbox",
                          "metadata": {"exit_code": evidence.workload_exit_code}})
    elif interpretation == "timeout":
        event_log.append({"event_type": "code_execution_timed_out", "backend": "native_os_sandbox"})
    else:
        event_log.append({"event_type": "code_execution_failed", "backend": "native_os_sandbox",
                          "metadata": {"exit_code": evidence.workload_exit_code, "reason": reason}})
    if output_truncated:
        event_log.append({"event_type": "sandbox_output_capped", "backend": "native_os_sandbox"})

    return {
        "process_started": True,
        "process_exit_code": workload_exit_code,
        "process_timed_out": timed_out,
        "stdout": stdout_b,
        "stderr": stderr_b,
        "output_truncated": output_truncated,
        "exit_code_interpretation": interpretation,
        "reason": reason,
        "backend": "native_os_sandbox",
        "sandbox_metadata": sandbox_metadata,
        "sandbox_event_log": event_log,
    }


# ---------------------------------------------------------------------------
# S3.1R R3: Lifecycle owner and reap authority (now in supervised_exec_session.py)
# Obsolete _SupervisedExecutionOwner/ReapResult/_terminalize_reap removed (R3 fix #6).
# ---------------------------------------------------------------------------


async def _run_supervised_child(config: dict[str, Any]) -> dict[str, Any]:
    """R3 Task 5: Ownership-complete supervised execution.

    T1: This function is now a thin wrapper around
    ``run_supervised_argv_async`` from ``supervised_argv.py``. The lifecycle
    logic (spawn, config delivery, protocol transport, bounded output,
    shutdown, evidence mapping) has been generalized into the public API.

    The existing native-command path does not supply a workload-input pipe
    (``workload_stdin=None``), so no payload channel is created.
    """
    from nodechain.runtime.supervised_argv import run_supervised_argv_async

    _allowlist = set(config.get("env_allowlist", []))
    _bootstrap_env = (
        {k: v for k, v in os.environ.items() if k in _allowlist}
        if _allowlist
        else {}
    )

    return await run_supervised_argv_async(
        argv=config["argv"],
        workload_stdin=None,
        workload_cwd=config.get("cwd"),
        supervisor_env=_bootstrap_env,
        workload_env={},
        timeout_seconds=config.get("timeout_seconds", 120),
        max_output_bytes=config.get("max_output_bytes", 50_000),
    )


def _close_fd_once(fd: int) -> int:
    """Close FD exactly once, return -1 (poisoned).

    Re-review fix: centralizes descriptor closure to prevent double-close
    and FD-reuse hazard on pre-transfer error paths.
    """
    if fd >= 0:
        try:
            os.close(fd)
        except OSError:
            pass
    return -1


def _kill_process_group_pgid(pgid: int | None, proc) -> None:
    """Kill using a stored PGID — avoids rediscovering group from a stale PID."""
    if pgid is not None:
        try:
            os.killpg(pgid, signal.SIGKILL)
            return
        except (OSError, ProcessLookupError):
            pass
    # Fallback to proc-based kill.
    try:
        proc.kill()
    except Exception:
        pass


def _supervised_error(reason: str, *, stderr_b: str = "") -> dict[str, Any]:
    """Return a supervised execution error result."""
    return {
        "process_started": False,
        "process_exit_code": None,
        "process_timed_out": False,
        "stdout": "",
        "stderr": stderr_b or f"supervised execution error: {reason}",
        "output_truncated": False,
        "exit_code_interpretation": "error",
        "reason": reason,
        "backend": "native_os_sandbox",
        "sandbox_metadata": {},
        "sandbox_event_log": [
            {"event_type": "code_execution_failed", "backend": "native_os_sandbox",
             "metadata": {"reason": reason}},
        ],
    }


def run_isolated(
    *,
    argv: list[str],
    cwd: Path,
    timeout_seconds: int,
    max_output_bytes: int,
    env_allowlist: set[str],
    backend_name: str = "native_os_sandbox",
    use_supervisor: bool = False,
) -> dict[str, Any]:
    """Synchronous entry: run argv inside the native OS sandbox.

    v2.78: child-applied seccomp + in-place execve. See module docstring.
    v3.5.1 H2 S3: when *use_supervisor* is True, use the external supervisor
    path with exact PTRACE_EVENT_EXEC authority. Default False until S3.4.
    """
    config = {
        "argv": argv,
        "cwd": str(cwd),
        "timeout_seconds": timeout_seconds,
        "max_output_bytes": max_output_bytes,
        "workspace_src": str(cwd),
        "env_allowlist": sorted(env_allowlist),
        "package_root": "/",
        "temp_dir": os.environ.get("TEMP", os.environ.get("TMPDIR", "/tmp")),
        # v2.78: all primitives enabled, INCLUDING seccomp (now child-applied).
        "enable_pid_namespace": True,
        "enable_procfs_isolation": True,
        "enable_network_namespace": True,
        "enable_mount_namespace": True,
        "enable_mount_confinement": True,
        "enable_seccomp": True,
    }
    child_script = _build_child_script()
    try:
        loop = asyncio.new_event_loop()
        try:
            if use_supervisor:
                # v3.5.1 H2 S3: supervised execution path.
                return loop.run_until_complete(_run_supervised_child(config))
            else:
                return loop.run_until_complete(_run_child(child_script, config))
        finally:
            loop.close()
    except Exception as e:
        return {
            "process_started": False,
            "process_exit_code": None,
            "process_timed_out": False,
            "stdout": "",
            "stderr": str(e)[:500],
            "output_truncated": False,
            "exit_code_interpretation": "error",
            "reason": "native_sandbox_spawn_error",
            "backend": backend_name,
            "sandbox_metadata": {},
            "sandbox_event_log": [
                {"event_type": "code_execution_failed", "backend": backend_name,
                 "metadata": {"error": str(e)[:200]}}
            ],
        }
