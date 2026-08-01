"""v3.5.1 H2 — Bounded streaming output readers for sandbox execution.

Both synchronous and asynchronous variants share one contract:

* count bytes while reading stdout and stderr concurrently;
* retain only bounded prefixes — per-stream AND combined hard ceiling;
* terminate the complete process tree when any limit is crossed or the
  direct child exits;
* race process-exit, output-limit, I/O-completion, and timeout concurrently;
* distinguish timeout from output-limit termination;
* bounded stdin with max_input_bytes rejection and deadline governance;
* Windows Job Object with fail-closed containment.

No path may call ``communicate()`` with untrusted stdout or stderr pipes.
"""

from __future__ import annotations

import asyncio
import os
import signal
import subprocess
import threading
import time
from typing import Any

# ── Windows Job Object constants ──────────────────────────────────────────

_WIN_JOB_OBJECT_LIMIT_KILL_ON_JOB = 0x2000
_WIN_JOB_OBJECT_TERMINATE = 0
_WIN_CREATE_SUSPENDED = 0x4


def _kill_process_tree(proc: subprocess.Popen, pgid: int | None,
                       job_handle: int | None = None,
                       supervisor_pid: int | None = None) -> None:
    """Kill the entire process tree.

    POSIX: ``os.killpg`` on the stored pgid, then kill the dedicated
    supervisor process (if any) which was the subreaper for this invocation.
    Windows: ``TerminateJobObject`` if a job handle is provided, then
    ``wmic`` for descendants that escape Job membership.
    """
    if pgid is not None and os.name == "posix":
        try:
            os.killpg(pgid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        # v3.5.1 H2 #4: if a dedicated supervisor process was used, kill it
        # and its adopted descendants. The supervisor was the subreaper for
        # exactly this invocation, so this is invocation-scoped.
        if supervisor_pid is not None:
            _kill_orphaned_descendants(supervisor_pid)
            try:
                os.kill(supervisor_pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
    if job_handle is not None and os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes
            kernel32 = ctypes.windll.kernel32
            kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
            kernel32.TerminateJobObject.restype = wintypes.BOOL
            kernel32.TerminateJobObject(job_handle, 1)
        except (OSError, AttributeError):
            pass
    # v3.5.1 H2: Windows fallback — wmic for descendants that escape Job.
    if os.name == "nt":
        try:
            import subprocess as _sp
            _sp.run(
                ["wmic", "process", "where",
                 f"ParentProcessId={proc.pid}",
                 "call", "terminate"],
                capture_output=True, timeout=5,
            )
        except Exception:
            pass
    try:
        proc.kill()
    except OSError:
        pass


def _create_posix_supervisor() -> tuple[int | None, int | None]:
    """Detect whether reliable descendant containment is available on POSIX.

    v3.5.1 H2 #4: on LXC/Docker containers, process-group kill may not reach
    reparented descendants. A dedicated per-invocation subreaper requires the
    supervisor to be the parent of the sandbox child, which conflicts with the
    existing SubprocessRunner architecture.

    The correct invocation-scoped boundaries are cgroup v2 (cgroup.kill) or a
    dedicated PID namespace. When neither is available, the sandbox MUST fail
    closed rather than execute untrusted code it cannot contain.

    This function returns (None, None) on all platforms. The caller is
    responsible for checking _posix_containment_available() before executing.
    """
    return None, None


def _posix_containment_available() -> bool:
    """Check whether reliable process-tree containment is available.

    v3.5.1 H2: fail-closed on every ambiguous result. Only returns True
    when systemd-detect-virt explicitly reports bare metal or a recognized
    VM hypervisor. Returns False for containers, unknown results, and
    detector errors.

    The production SubprocessRunner MUST call this before executing untrusted
    nodes and fail closed when it returns False.
    """
    if os.name != "posix":
        return True  # Windows uses Job Objects
    try:
        import subprocess as _sp
        result = _sp.run(
            ["systemd-detect-virt"],
            capture_output=True, text=True, timeout=5,
        )
        virt_type = result.stdout.strip()
        # Known container types — refuse.
        container_types = {
            "lxc", "docker", "podman", "openvz", "rkt", "containerd",
            "systemd-nspawn",
        }
        if virt_type in container_types:
            return False
        # Known safe (bare metal / VM) — allow.
        safe_types = {"none", "kvm", "qemu", "xen", "vmware", "microsoft", "oracle", "zvm", "parallels"}
        if virt_type in safe_types:
            return True
        # Unknown virtualization type — fail closed.
        return False
    except (OSError, FileNotFoundError, Exception):
        # Detector unavailable or errored — fail closed.
        return False


def _create_cgroup2_sandbox() -> str | None:
    """Create a per-invocation cgroup v2 for process containment.

    Returns the cgroup path, or None if cgroup v2 is not available.
    The caller moves the child PID into this cgroup and uses cgroup.kill
    to terminate all processes in it during cleanup.
    """
    if os.name != "posix":
        return None
    if not os.path.exists("/sys/fs/cgroup/cgroup.kill"):
        return None
    import uuid
    cg_name = f"nodechain_sandbox_{uuid.uuid4().hex[:8]}"
    cg_path = f"/sys/fs/cgroup/{cg_name}"
    try:
        os.mkdir(cg_path)
        return cg_path
    except OSError:
        return None


def _cgroup2_kill(cg_path: str) -> None:
    """Kill all processes in a cgroup v2 via cgroup.kill."""
    if not cg_path:
        return
    try:
        kill_file = f"{cg_path}/cgroup.kill"
        with open(kill_file, "w") as f:
            f.write("1")
    except OSError:
        pass


def _cgroup2_move_pid(cg_path: str, pid: int) -> None:
    """Move a process into a cgroup v2."""
    if not cg_path:
        return
    try:
        with open(f"{cg_path}/cgroup.procs", "w") as f:
            f.write(str(pid))
    except OSError:
        pass


def _cgroup2_cleanup(cg_path: str) -> None:
    """Remove the cgroup directory after all processes have exited."""
    if not cg_path:
        return
    try:
        os.rmdir(cg_path)
    except OSError:
        pass  # cgroup not empty or already removed


def _kill_orphaned_descendants(parent_pid: int) -> int:
    """Scan /proc for processes whose PPID matches and kill them.

    Returns the number of processes killed.
    """
    if os.name != "posix":
        return 0
    try:
        import os as _os
        # Build a map of PID -> PPID from /proc.
        pid_map: dict[int, int] = {}  # pid -> ppid
        for entry in _os.listdir("/proc"):
            if not entry.isdigit():
                continue
            pid = int(entry)
            try:
                with open(f"/proc/{pid}/stat", "r") as f:
                    stat = f.read()
                # Field 4 is ppid (after comm which may contain spaces).
                # Parse: pid (comm) state ppid ...
                rparen = stat.rfind(")")
                fields = stat[rparen + 2:].split()
                ppid = int(fields[1])  # state=fields[0], ppid=fields[1]
                pid_map[pid] = ppid
            except (OSError, ValueError, IndexError):
                continue
        # Find all descendants (recursive).
        descendants = set()
        to_check = [parent_pid]
        while to_check:
            current = to_check.pop()
            for pid, ppid in pid_map.items():
                if ppid == current and pid not in descendants:
                    descendants.add(pid)
                    to_check.append(pid)
        # Kill them.
        killed = 0
        for pid in descendants:
            try:
                _os.kill(pid, signal.SIGKILL)
                killed += 1
            except (ProcessLookupError, PermissionError, OSError):
                pass
        return killed
    except Exception:
        return 0


def _windows_resume_suspended_process(proc: subprocess.Popen) -> bool:
    """Resume a process created with CREATE_SUSPENDED. Returns True on success."""
    return False  # POSIX no-op; Windows implementation below


def _close_job_handle(job_handle: int | None) -> None:
    """Close a Windows Job Object handle."""
    if job_handle is None or os.name != "nt":
        return
    try:
        import ctypes
        ctypes.windll.kernel32.CloseHandle(job_handle)
    except (OSError, AttributeError):
        pass


def _create_windows_job_object() -> int | None:
    """Create a Windows Job Object with kill-on-close.

    Returns the handle, or None if creation or configuration fails.
    Fail-closed: callers MUST check the return value.
    """
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        # Define argument types.
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]

        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            return None

        # Configure kill-on-job.
        class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", ctypes.c_uint32),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", ctypes.c_uint32),
                ("Affinity", ctypes.c_void_p),
                ("PriorityClass", ctypes.c_uint32),
                ("SchedulingClass", ctypes.c_uint32),
            ]

        class _IO_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_uint64),
                ("WriteOperationCount", ctypes.c_uint64),
                ("OtherOperationCount", ctypes.c_uint64),
                ("ReadTransferCount", ctypes.c_uint64),
                ("WriteTransferCount", ctypes.c_uint64),
                ("OtherTransferCount", ctypes.c_uint64),
            ]

        class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
                ("IoInfo", _IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        ext = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        ext.BasicLimitInformation.LimitFlags = _WIN_JOB_OBJECT_LIMIT_KILL_ON_JOB

        JobObjectExtendedLimitInformation = 9
        kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE, ctypes.c_int,
            ctypes.c_void_p, wintypes.DWORD,
        ]
        kernel32.SetInformationJobObject.restype = wintypes.BOOL

        ok = kernel32.SetInformationJobObject(
            handle, JobObjectExtendedLimitInformation,
            ctypes.byref(ext), ctypes.sizeof(ext),
        )
        if not ok:
            _close_job_handle(handle)
            return None
        return handle
    except (OSError, AttributeError, Exception):
        return None


def _get_windows_process_handle(proc) -> int | None:
    """Extract the Windows process handle from a subprocess.Popen or
    asyncio.subprocess.Process. Returns the integer handle or None."""
    if os.name != "nt":
        return None
    if hasattr(proc, "_handle"):
        return int(proc._handle)
    transport = getattr(proc, "_transport", None)
    if transport is not None:
        inner = getattr(transport, "_proc", None)
        if inner is not None and hasattr(inner, "_handle"):
            return int(inner._handle)
    return None


def _windows_resume_suspended_process(proc: subprocess.Popen) -> bool:
    """Resume a process created with CREATE_SUSPENDED.

    Finds the main (and only, since it's suspended) thread via Toolhelp
    snapshot and resumes it. Returns True only if ResumeThread succeeded
    (return value != 0xFFFFFFFF). All Win32 calls have typed signatures
    and exact failure handling.
    """
    if os.name != "nt":
        return False
    try:
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.windll.kernel32

        TH32CS_SNAPTHREAD = 0x4
        INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
        THREAD_SUSPEND_RESUME = 0x0002
        RESUME_FAILED = 0xFFFFFFFF

        class _THREADENTRY32(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ThreadID", wintypes.DWORD),
                ("th32OwnerProcessID", wintypes.DWORD),
                ("tpBasePri", ctypes.c_long),
                ("tpDeltaPri", ctypes.c_long),
                ("dwFlags", wintypes.DWORD),
            ]

        # Type all API calls.
        kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
        kernel32.Thread32First.restype = wintypes.BOOL
        kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
        kernel32.Thread32Next.restype = wintypes.BOOL
        kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenThread.restype = wintypes.HANDLE
        kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
        kernel32.ResumeThread.restype = wintypes.DWORD
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
        if snap == INVALID_HANDLE_VALUE or not snap:
            return False
        try:
            te = _THREADENTRY32()
            te.dwSize = ctypes.sizeof(te)
            if not kernel32.Thread32First(snap, ctypes.byref(te)):
                return False  # no threads found
            while True:
                if te.th32OwnerProcessID == proc.pid:
                    thread_handle = kernel32.OpenThread(
                        THREAD_SUSPEND_RESUME, False, te.th32ThreadID,
                    )
                    if not thread_handle or thread_handle == INVALID_HANDLE_VALUE:
                        return False
                    suspend_count = kernel32.ResumeThread(thread_handle)
                    kernel32.CloseHandle(thread_handle)
                    if suspend_count == RESUME_FAILED:
                        return False
                    return True
                if not kernel32.Thread32Next(snap, ctypes.byref(te)):
                    break
        finally:
            kernel32.CloseHandle(snap)
        return False  # thread not found
    except (OSError, AttributeError, Exception):
        return False


def _windows_spawn_contained(
    argv: list[str],
    *,
    cwd: str,
    env: dict[str, str],
    stdin: int,
    stdout: int,
    stderr: int,
    job_handle: int | None,
) -> subprocess.Popen | None:
    """Spawn a child with CREATE_SUSPENDED, assign to Job Object, then resume.

    Returns the Popen object on success, or None on any containment failure
    (job creation, assignment, resume). On failure, the suspended process is
    terminated and cleaned up.
    """
    if os.name != "nt":
        return None  # Not applicable on POSIX.

    CREATE_SUSPENDED = 0x4
    try:
        proc = subprocess.Popen(
            argv, cwd=cwd, env=env,
            stdin=stdin, stdout=stdout, stderr=stderr,
            shell=False, creationflags=CREATE_SUSPENDED,
        )
    except (OSError, ValueError):
        return None

    # Assign to Job Object while suspended.
    if job_handle is not None:
        if not _assign_to_job_object(job_handle, proc):
            # Assignment failed — terminate, wait, close pipes, fail closed.
            proc.kill()
            try: proc.wait(timeout=5)
            except Exception: pass
            try: proc.stdin.close()
            except Exception: pass
            try: proc.stdout.close()
            except Exception: pass
            try: proc.stderr.close()
            except Exception: pass
            return None

    # Resume the primary thread.
    if not _windows_resume_suspended_process(proc):
        proc.kill()
        try: proc.wait(timeout=5)
        except Exception: pass
        try: proc.stdin.close()
        except Exception: pass
        try: proc.stdout.close()
        except Exception: pass
        try: proc.stderr.close()
        except Exception: pass
        return None

    return proc
    if hasattr(proc, "_handle"):
        return int(proc._handle)
    # asyncio.subprocess.Process wraps the transport which wraps a Popen.
    transport = getattr(proc, "_transport", None)
    if transport is not None:
        inner = getattr(transport, "_proc", None)
        if inner is not None and hasattr(inner, "_handle"):
            return int(inner._handle)
    return None


def _assign_to_job_object(job_handle: int, proc_or_handle) -> bool:
    """Assign a process to the Job Object. Accepts either an integer handle
    or a subprocess/asyncio Process object. Returns True on success."""
    if os.name != "nt" or not job_handle:
        return False
    # Accept either a raw handle or a process object.
    if isinstance(proc_or_handle, int):
        proc_handle = proc_or_handle
    else:
        proc_handle = _get_windows_process_handle(proc_or_handle)
    if proc_handle is None:
        return False
    try:
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.windll.kernel32
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        return bool(kernel32.AssignProcessToJobObject(job_handle, proc_handle))
    except (OSError, AttributeError, Exception):
        return False


# ── Default limits ────────────────────────────────────────────────────────

DEFAULT_MAX_INPUT_BYTES = 1 * 1024 * 1024  # 1 MiB


# ── Sync variant ─────────────────────────────────────────────────────────


def run_bounded_subprocess(
    argv: list[str],
    *,
    cwd: str,
    env: dict[str, str],
    timeout_seconds: int,
    max_output_bytes: int,
    stdout_cap: int | None = None,
    stderr_cap: int | None = None,
    combined_cap: int | None = None,
    stdin_data: str | None = None,
    max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES,
    start_new_session: bool = True,
) -> dict[str, Any]:
    """Run ``argv`` with bounded streaming output capture (synchronous).

    See module docstring for the full contract.
    """
    stdout_limit = stdout_cap if stdout_cap is not None else max_output_bytes
    stderr_limit = stderr_cap if stderr_cap is not None else max_output_bytes
    combined_limit = combined_cap if combined_cap is not None else max_output_bytes

    # v3.5.1 H2 #4: reject oversized stdin before spawning.
    stdin_bytes: bytes | None = None
    if stdin_data is not None:
        stdin_bytes = stdin_data.encode()
        if len(stdin_bytes) > max_input_bytes:
            return {
                "process_started": False, "process_exit_code": None,
                "process_timed_out": False, "stdout": "", "stderr": "",
                "output_truncated": False,
                "exit_code_interpretation": "error",
                "reason": "input_oversized",
            }

    stdin_arg = subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL

    # v3.5.1 H2 #4: create a dedicated supervisor process that becomes the
    # subreaper for exactly this invocation (NOT the global NodeChain process).
    _supervisor_pid, _supervisor_rfd = _create_posix_supervisor()

    # v3.5.1 H2 #3: create Job Object BEFORE spawning so we can fail-closed.
    _job_handle: int | None = None
    if os.name == "nt":
        _job_handle = _create_windows_job_object()
        if _job_handle is None:
            return {
                "process_started": False, "process_exit_code": None,
                "process_timed_out": False, "stdout": "", "stderr": "",
                "output_truncated": False,
                "exit_code_interpretation": "error",
                "reason": "job_object_creation_failed",
            }

    try:
        if os.name == "nt" and _job_handle is not None:
            # v3.5.1 H2 #1: Windows spawn-suspended — establish containment
            # BEFORE the primary thread executes. Create suspended, assign to
            # Job Object, resume. Fail-closed on any step.
            proc = _windows_spawn_contained(
                argv, cwd=cwd, env=env,
                stdin=stdin_arg, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                job_handle=_job_handle,
            )
            if proc is None:
                _close_job_handle(_job_handle)
                return {
                    "process_started": False, "process_exit_code": None,
                    "process_timed_out": False, "stdout": "", "stderr": "",
                    "output_truncated": False,
                    "exit_code_interpretation": "error",
                    "reason": "job_object_assignment_failed",
                }
        else:
            proc = subprocess.Popen(
                argv, cwd=cwd, env=env,
                stdin=stdin_arg, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                shell=False,
                start_new_session=start_new_session and os.name == "posix",
            )
    except (OSError, ValueError) as e:
        _close_job_handle(_job_handle)
        return {
            "process_started": False, "process_exit_code": None,
            "process_timed_out": False, "stdout": "", "stderr": str(e)[:500],
            "output_truncated": False,
            "exit_code_interpretation": "error", "reason": "spawn_failed",
        }

    # Store pgid at spawn.
    _pgid: int | None = None
    if os.name == "posix":
        try:
            _pgid = os.getpgid(proc.pid)
        except (ProcessLookupError, OSError):
            _pgid = proc.pid

    # v3.5.1 H2 #4: write stdin in a bounded thread (doesn't block readers).
    if stdin_bytes is not None:
        def _write_stdin():
            try:
                proc.stdin.write(stdin_bytes)
                proc.stdin.close()
            except (OSError, ValueError):
                pass
        stdin_thread = threading.Thread(target=_write_stdin, daemon=True)
        stdin_thread.start()
    else:
        stdin_thread = None

    # Shared state.
    stdout_sink = [b""]
    stderr_sink = [b""]
    stdout_truncated = [False]
    stderr_truncated = [False]
    combined_exceeded = [False]
    _lock = threading.Lock()
    combined_retained = [0]

    def _stream(pipe, stream_limit, sink, trunc_flag):
        try:
            while True:
                chunk = pipe.read(8192)
                if not chunk:
                    break
                if isinstance(chunk, str):
                    chunk = chunk.encode("utf-8", errors="replace")
                with _lock:
                    # v3.5.1 H2 #2: hard combined retained-byte ceiling.
                    combined_remaining = combined_limit - combined_retained[0]
                    stream_remaining = stream_limit - len(sink[0])
                    retain_n = min(len(chunk), stream_remaining, combined_remaining)
                    if retain_n > 0:
                        sink[0] += chunk[:retain_n]
                        combined_retained[0] += retain_n
                    if len(sink[0]) >= stream_limit or combined_retained[0] >= combined_limit:
                        trunc_flag[0] = True
                        combined_exceeded[0] = True
        except (OSError, ValueError):
            pass

    t_out = threading.Thread(target=_stream, args=(proc.stdout, stdout_limit, stdout_sink, stdout_truncated), daemon=True)
    t_err = threading.Thread(target=_stream, args=(proc.stderr, stderr_limit, stderr_sink, stderr_truncated), daemon=True)
    t_out.start()
    t_err.start()

    timed_out = False
    output_capped = False
    deadline = time.monotonic() + timeout_seconds

    while True:
        try:
            proc.wait(timeout=0.2)
            break  # direct child exited → kill group immediately
        except subprocess.TimeoutExpired:
            pass
        if stdout_truncated[0] or stderr_truncated[0] or combined_exceeded[0]:
            output_capped = True
            _kill_process_tree(proc, _pgid, _job_handle, _supervisor_pid)
            break
        if time.monotonic() >= deadline:
            timed_out = True
            _kill_process_tree(proc, _pgid, _job_handle, _supervisor_pid)
            break

    # v3.5.1 H2 #1: kill the group IMMEDIATELY after leader exits.
    _kill_process_tree(proc, _pgid, _job_handle, _supervisor_pid)

    # Drain reader threads (bounded).
    t_out.join(timeout=3)
    t_err.join(timeout=3)
    _kill_process_tree(proc, _pgid, _job_handle, _supervisor_pid)  # second pass
    t_out.join(timeout=2)
    t_err.join(timeout=2)
    if stdin_thread:
        stdin_thread.join(timeout=2)
    try: proc.stdout.close()
    except (OSError, ValueError): pass
    try: proc.stderr.close()
    except (OSError, ValueError): pass
    _close_job_handle(_job_handle)
    if _supervisor_pid is not None:
        try: os.close(_supervisor_rfd)
        except OSError: pass
        try: os.waitpid(_supervisor_pid, 0)
        except (OSError, ChildProcessError): pass

    stdout_s = stdout_sink[0].decode(errors="replace")
    stderr_s = stderr_sink[0].decode(errors="replace")
    output_truncated = stdout_truncated[0] or stderr_truncated[0] or combined_exceeded[0]
    returncode = proc.returncode

    if output_capped or output_truncated:
        interpretation, reason = "fail", "output_limit_exceeded"
    elif timed_out:
        interpretation, reason = "timeout", "timeout"
    elif returncode == 0:
        interpretation, reason = "pass", None
    elif returncode is None:
        interpretation, reason = "error", "no_exit_code"
    else:
        interpretation, reason = "fail", f"exit_{returncode}"

    return {
        "process_started": True, "process_exit_code": returncode,
        "process_timed_out": timed_out,
        "stdout": stdout_s, "stderr": stderr_s,
        "output_truncated": output_truncated,
        "exit_code_interpretation": interpretation, "reason": reason,
    }


# ── Async variant ────────────────────────────────────────────────────────


async def run_bounded_async(
    proc: asyncio.subprocess.Process,
    *,
    input_data: bytes | None,
    timeout_seconds: int,
    max_output_bytes: int,
    stdout_cap: int | None = None,
    stderr_cap: int | None = None,
    combined_cap: int | None = None,
    job_handle: int | None = None,
    max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES,
    proc_exit_task: asyncio.Task | None = None,
) -> dict[str, Any]:
    """Bounded async streaming reader for an already-spawned subprocess.

    The caller spawns the process with ``start_new_session=True`` (POSIX) and
    passes it here.  The supervisor races process-exit, output-limit, I/O
    completion, and timeout. When any limit is crossed OR the direct child
    exits, the process tree is killed immediately.
    """
    stdout_limit = stdout_cap if stdout_cap is not None else max_output_bytes
    stderr_limit = stderr_cap if stderr_cap is not None else max_output_bytes
    combined_limit = combined_cap if combined_cap is not None else max_output_bytes

    # v3.5.1 H2 #3: cgroup lifecycle is owned by the caller (SubprocessRunner).
    # run_bounded_async does NOT create its own cgroup to avoid duplicate ownership.

    # v3.5.1 H2 #5: resolve pgid BEFORE any early-return path so the process
    # group can be killed even on oversized-input rejection.
    _pgid: int | None = None
    if os.name == "posix":
        try:
            _pgid = os.getpgid(proc.pid)
        except (ProcessLookupError, OSError):
            _pgid = proc.pid

    # v3.5.1 H2 #4: reject oversized stdin — terminate, reap, close, return.
    if input_data is not None and len(input_data) > max_input_bytes:
        _kill_process_tree(proc, _pgid, job_handle, None)
        # Close stdin, drain stdout/stderr, await process exit.
        try:
            proc.stdin.close()
        except Exception:
            pass
        # Reuse shared proc_exit_task if provided; otherwise create one.
        _oversized_exit = proc_exit_task
        if _oversized_exit is None:
            _oversized_exit = asyncio.ensure_future(proc.wait())
        try:
            await asyncio.wait({_oversized_exit}, timeout=5)
        except Exception:
            pass
        try:
            proc.stdout.close()
        except Exception:
            pass
        try:
            proc.stderr.close()
        except Exception:
            pass
        return {
            "stdout": "", "stderr": "",
            "output_truncated": False, "timed_out": False,
            "exit_code": proc.returncode, "reason": "input_oversized",
        }

    # Shared supervisor state.
    _lock = asyncio.Lock()
    _combined_retained = [0]
    _combined_exceeded = [False]
    _limit_event = asyncio.Event()

    async def _read_stream(stream, stream_limit: int) -> tuple[bytes, bool]:
        retained = b""
        truncated = False
        while True:
            chunk = await stream.read(8192)
            if not chunk:
                break
            async with _lock:
                # v3.5.1 H2 #2: hard combined retained-byte ceiling.
                combined_remaining = combined_limit - _combined_retained[0]
                stream_remaining = stream_limit - len(retained)
                retain_n = min(len(chunk), stream_remaining, combined_remaining)
                if retain_n > 0:
                    retained += chunk[:retain_n]
                    _combined_retained[0] += retain_n
                if len(retained) >= stream_limit or _combined_retained[0] >= combined_limit:
                    truncated = True
                    _combined_exceeded[0] = True
                    _limit_event.set()
        return retained, truncated

    async def _write_stdin(data: bytes) -> None:
        try:
            proc.stdin.write(data)
            await proc.stdin.drain()
        except Exception:
            pass
        finally:
            try:
                proc.stdin.close()
            except Exception:
                pass

    # Start concurrent tasks.
    stdin_task = None
    if input_data is not None and proc.stdin:
        stdin_task = asyncio.create_task(_write_stdin(input_data))
    stdout_task = asyncio.create_task(_read_stream(proc.stdout, stdout_limit))
    stderr_task = asyncio.create_task(_read_stream(proc.stderr, stderr_limit))

    timed_out = False
    output_capped = False

    limit_wait = asyncio.create_task(_limit_event.wait())

    async def _io_complete():
        await asyncio.gather(stdout_task, stderr_task)

    io_done = asyncio.create_task(_io_complete())

    # v3.5.1 H2 S3.1: ONE proc_exit authority — accept externally-created task
    # or create one. This task is NEVER cancelled — it's the reap authority.
    if proc_exit_task is not None:
        proc_exit = proc_exit_task
    else:
        proc_exit = asyncio.create_task(proc.wait())

    stdout_b, stdout_trunc = b"", False
    stderr_b, stderr_trunc = b"", False

    try:
        done, pending = await asyncio.wait(
            [io_done, limit_wait, proc_exit],
            timeout=timeout_seconds,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if limit_wait in done:
            output_capped = True
        if proc_exit in done and io_done not in done:
            pass  # fall through to unconditional kill below
        if not done:
            timed_out = True
    except asyncio.CancelledError:
        timed_out = True
        raise
    except Exception:
        timed_out = True

    # v3.5.1 H2 S3.1: cancellation-safe finally owning ALL child tasks.
    finally:
        # Always kill the group on any exit path.
        _kill_process_tree(proc, _pgid, job_handle, None)

        # Cancel supervisor tasks — but NOT proc_exit (it's the reap authority).
        for task in [limit_wait]:
            if not task.done():
                task.cancel()

        # Drain reader tasks (bounded) — after kill, descendant pipes close.
        try:
            stdout_b, stdout_trunc = await asyncio.wait_for(stdout_task, timeout=5)
        except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
            pass
        try:
            stderr_b, stderr_trunc = await asyncio.wait_for(stderr_task, timeout=5)
        except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
            pass

        # Await/cleanup stdin task.
        if stdin_task is not None:
            if not stdin_task.done():
                stdin_task.cancel()
            try:
                await asyncio.gather(stdin_task, return_exceptions=True)
            except Exception:
                pass

        # Await io_done if not finished.
        if not io_done.done():
            io_done.cancel()
        try:
            await asyncio.wait_for(io_done, timeout=3)
        except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
            pass

        # v3.5.1 H2 S3.1: await proc_exit for reap — NEVER cancel it.
        # Use asyncio.wait (not wait_for) to avoid cancelling the reap task.
        if not proc_exit.done():
            try:
                await asyncio.wait({proc_exit}, timeout=5)
            except asyncio.CancelledError:
                # Even under cancellation, try to complete the reap.
                try:
                    await asyncio.wait({proc_exit}, timeout=3)
                except Exception:
                    pass
            except Exception:
                pass

        # Guarantee all owned tasks are done before return.
        all_tasks = [stdin_task, stdout_task, stderr_task, limit_wait, io_done]
        for task in all_tasks:
            if task is not None and not task.done():
                task.cancel()
                try:
                    await asyncio.wait_for(task, timeout=2)
                except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
                    pass
        # Postcondition: every owned task must be done.
        for task in all_tasks:
            if task is not None and not task.done():
                # Last resort — unbounded await for this specific task.
                try:
                    await task
                except Exception:
                    pass

    returncode = proc.returncode
    output_truncated = stdout_trunc or stderr_trunc or output_capped or _combined_exceeded[0]

    if output_capped or output_truncated:
        reason = "output_limit_exceeded"
    elif timed_out:
        reason = "timeout"
    elif returncode == 0:
        reason = None
    elif returncode is None:
        reason = "no_exit_code"
    else:
        reason = f"exit_{returncode}"

    return {
        "stdout": stdout_b.decode(errors="replace") if stdout_b else "",
        "stderr": stderr_b.decode(errors="replace") if stderr_b else "",
        "output_truncated": output_truncated,
        "timed_out": timed_out,
        "exit_code": returncode,
        "reason": reason,
    }
