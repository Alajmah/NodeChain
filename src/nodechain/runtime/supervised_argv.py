"""T1: Public parent-side supervised execution API.

Provides ``run_supervised_argv_async`` — the composition root for spawning
the S3.2 external supervisor (``python -m nodechain.runtime.exec_supervisor``),
delivering configuration + optional workload payload, collecting bounded
output, managing the full lifecycle, and returning evidence + results.

This module generalizes the existing ``_run_supervised_child`` lifecycle
without duplicating it. The workload-input pipe and its event-loop-native
writer are session-owned, ensuring the writer participates in centralized
shutdown alongside config, output, protocol transport, and ``proc_exit_task``.

T1 scope: parent-side API + payload writer + session ownership.
T2 scope: supervisor FD forwarding through S→I→B1→B2.
T3 scope: SubprocessRunner routing and result mapping.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import struct
import sys
import time
from typing import Any, Callable, Mapping, Sequence

# Maximum payload size for the workload-input channel (1 MiB).
MAX_WORKLOAD_INPUT_BYTES = 1_048_576


async def run_supervised_argv_async(
    *,
    argv: Sequence[str],
    workload_stdin: bytes | None,
    workload_cwd: str | None,
    supervisor_env: Mapping[str, str],
    workload_env: Mapping[str, str],
    timeout_seconds: float,
    max_output_bytes: int,
    containment: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Public parent-side supervised execution API.

    Spawns the S3.2 supervisor process, delivers framed configuration over
    the supervisor's stdin (FD 0), optionally delivers a workload payload
    through a dedicated pipe, collects bounded stdout/stderr, manages the
    protocol transport, runs deterministic shutdown, and returns the
    evidence + bounded output.

    Parameters
    ----------
    argv
        Workload command-line arguments. The supervisor will ``execve`` these
        after PID-namespace topology verification and ptrace arming.
    workload_stdin
        Optional payload bytes delivered to the workload through a dedicated
        pipe. If ``None``, no workload-input pipe is created and the workload
        receives ``/dev/null`` on FD 0 (T2: the supervisor forwards the
        payload pipe read-end to FD 0 via dup2, or opens ``/dev/null`` when
        no payload is supplied).
    workload_cwd
        Working directory for the workload. Forwarded in the supervisor
        configuration and applied by B1 via ``chdir()`` before B2 exec.
    supervisor_env
        Minimal safe environment for the supervisor process. Must NOT contain
        arbitrary inherited PYTHONPATH, secrets, PYTHONHOME, etc.
    workload_env
        Secret-filtered environment for the workload. Forwarded in the
        supervisor configuration; applied by B1 at B2 exec.
    timeout_seconds
        Workload execution timeout. The total terminal deadline is computed
        from spawn time and includes startup + timeout + cleanup allowance.
    max_output_bytes
        Maximum bytes to collect per stdout/stderr stream.

    Returns
    -------
    dict
        Result dictionary with keys matching the native sandbox result schema:
        ``process_started``, ``process_exit_code``, ``stdout``, ``stderr``,
        ``exit_code_interpretation``, ``reason``, ``backend``,
        ``sandbox_metadata``, ``sandbox_event_log``.
    """
    # Late imports to keep module load lightweight.
    from nodechain.runtime.exec_supervisor import (
        extract_supervisor_evidence,
        SupervisorExecutionEvidence,
        MAX_CONFIG_BYTES,
        CONFIG_DEADLINE_SECONDS,
    )
    from nodechain.runtime.streaming_output import (
        run_bounded_async,
        _create_windows_job_object,
        _assign_to_job_object,
        _close_job_handle,
    )
    from nodechain.runtime.async_fd_transport import AsyncProtocolTransport
    from nodechain.runtime.supervised_exec_session import (
        SupervisedExecSession,
        ShutdownReason,
    )
    from nodechain.runtime.exec_protocol import MAX_PROTOCOL_STREAM_BYTES

    # --- Payload size validation BEFORE spawn ---
    if workload_stdin is not None and len(workload_stdin) > MAX_WORKLOAD_INPUT_BYTES:
        return _attach_workload_input_metadata(
            _error_result("workload_input_oversized"),
            report=None, session=None, fallback_status="not_created",
        )

    # --- Serialize supervisor configuration ---
    # T1 repair (v7 Blocker 2): list(argv) and dict(workload_env) are inside
    # the serialization error boundary so a failing custom sequence/mapping
    # produces config_serialize_failed rather than escaping ungoverned.
    # T1 repair (v8): catch Exception (not just TypeError/ValueError) because
    # a custom argv.__iter__() or workload_env.keys() can raise RuntimeError,
    # OSError, KeyError, etc. This block contains no await, so catching
    # Exception will not consume task cancellation.
    try:
        supervisor_config: dict[str, Any] = {
            "workload_argv": list(argv),
            "workload_env": dict(workload_env),
        }
        if workload_cwd is not None:
            supervisor_config["workload_cwd"] = workload_cwd
        if workload_stdin is not None:
            supervisor_config["has_workload_input"] = True
        # T3 (H0.2): requested OS containment — forwarded to the trusted
        # bootstrap, applied fail-closed before workload exec.
        if containment is not None:
            supervisor_config["containment"] = dict(containment)
        config_payload = json.dumps(supervisor_config).encode("utf-8")
    except Exception as e:
        return _attach_workload_input_metadata(
            _error_result(f"config_serialize_failed: {e}"),
            report=None, session=None, fallback_status="not_created",
        )
    if len(config_payload) > MAX_CONFIG_BYTES:
        return _attach_workload_input_metadata(
            _error_result("config_oversized"),
            report=None, session=None, fallback_status="not_created",
        )
    framed_config = struct.pack(">I", len(config_payload)) + config_payload

    # --- Resource initialization (defaults before the ownership boundary) ---
    # T1 repair (v5 Blocker 2): all pipe allocation and environment
    # materialization happen INSIDE the try/finally ownership boundary so a
    # failure at any point (EMFILE/ENFILE on the second pipe, or an exception
    # materializing supervisor_env) cannot leak partially-created descriptors.
    protocol_rfd = -1
    protocol_wfd = -1
    workload_input_rfd = -1
    workload_input_wfd = -1
    proc = None
    native_job = None
    supervisor_pgid = None
    session = SupervisedExecSession()
    bounded: dict[str, Any] | None = None
    output_task_failure = False
    sup_env: Mapping[str, str] = {}
    terminal_deadline = 0.0
    # T1 repair (v7 Blocker 2b): set a conservative fallback cleanup deadline
    # immediately so that if a post-setup fault reaches the outer BaseException
    # handler BEFORE the real spawn-time deadline is computed, session.shutdown()
    # does not reject with "deadline not set" and mask the original error.
    # This is overwritten with the real terminal_deadline at spawn time.
    session._cleanup_deadline = time.monotonic() + CONFIG_DEADLINE_SECONDS + timeout_seconds + session.cleanup_budget

    try:
        # T1 repair (v7 Blocker 2): pipe allocation and environment
        # materialization are in SEPARATE try blocks with operation-specific
        # handlers. A dict() that raises OSError is not pipe_creation_failed;
        # a dict() that raises RuntimeError/KeyError does not escape to the
        # outer BaseException handler (which would call session.shutdown()
        # before _cleanup_deadline is initialized, masking the original error).
        workload_input_channel_created = False

        try:
            # --- Create pipes (inside the ownership boundary) ---
            protocol_rfd, protocol_wfd = os.pipe()
            if workload_stdin is not None:
                workload_input_rfd, workload_input_wfd = os.pipe()
                # Transfer write-end ownership to the session immediately.
                session.workload_input_wfd = workload_input_wfd
                workload_input_wfd = -1
                workload_input_channel_created = True
        except OSError as exc:
            # Setup-only: pipe creation failed (e.g. EMFILE/ENFILE). The
            # finally block closes all partially-created descriptors.
            return _attach_workload_input_metadata(
                _error_result(f"pipe_creation_failed: {exc}"),
                report=None, session=session,
                fallback_status="not_started" if workload_input_channel_created else "not_created",
            )

        try:
            # --- Build supervisor environment (separate from pipe errors) ---
            # dict() contains no await, so catching Exception will not
            # consume task cancellation.
            sup_env = dict(supervisor_env)
        except Exception as exc:
            return _attach_workload_input_metadata(
                _error_result(f"supervisor_env_failed: {exc}"),
                report=None, session=session,
                fallback_status="not_started" if workload_input_channel_created else "not_created",
            )

        # --- Compute ONE terminal deadline at spawn time ---
        # spawn_time + config_startup + workload_timeout + cleanup_allowance
        spawn_time = time.monotonic()
        cleanup_allowance = session.cleanup_budget  # 15.0 seconds
        terminal_deadline = spawn_time + CONFIG_DEADLINE_SECONDS + timeout_seconds + cleanup_allowance
        session.execution_deadline = terminal_deadline
        session._cleanup_deadline = terminal_deadline  # T1 amendment: one deadline, set at spawn

        # --- Spawn supervisor ---
        pass_fds_list = [protocol_wfd]
        if workload_input_rfd >= 0:
            pass_fds_list.append(workload_input_rfd)

        # T2: pass workload_input_rfd as an explicit CLI argument — the CLI
        # is the sole descriptor authority (the config JSON carries only
        # has_workload_input as informational).
        supervisor_args = [
            sys.executable, "-m", "nodechain.runtime.exec_supervisor",
            "--protocol-fd", str(protocol_wfd),
        ]
        if workload_input_rfd >= 0:
            supervisor_args += ["--workload-input-fd", str(workload_input_rfd)]

        try:
            proc = await asyncio.create_subprocess_exec(
                *supervisor_args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                pass_fds=tuple(pass_fds_list),
                close_fds=True,
                start_new_session=True,
                env=sup_env,
            )
        except Exception as e:
            # T1 repair (v4): the workload-input pipe was allocated before
            # spawn (line ~142), so a spawn failure with a payload means the
            # channel was created but never started. Use not_started then.
            return _attach_workload_input_metadata(
                _error_result(f"supervisor_spawn_failed: {e}"),
                report=None, session=None,
                fallback_status="not_started" if workload_stdin is not None else "not_created",
            )
        finally:
            # Close parent's copies of inherited FDs immediately after spawn.
            protocol_wfd = _close_fd_once(protocol_wfd)
            # T1 repair (v4 Blocker 3): close the parent's READ endpoint of
            # the workload-input pipe immediately. On successful spawn the
            # supervisor's inherited copy remains valid; the parent's copy
            # serves no purpose and suppressing it means the writer can
            # observe EPIPE on early child exit (channel truth), and a
            # payload larger than the pipe buffer will not block against a
            # false reader.
            workload_input_rfd = _close_fd_once(workload_input_rfd)
            # Workload-input write-end ownership was transferred to the
            # session at pipe-creation time; workload_input_wfd is already
            # -1 here. All closure routes through the session primitive.

        # --- proc_exit_task (sole reap authority) ---
        proc_exit_task = asyncio.ensure_future(proc.wait())
        try:
            supervisor_pgid = os.getpgid(proc.pid)
        except (ProcessLookupError, OSError):
            supervisor_pgid = proc.pid

        session.proc = proc
        session.pgid = supervisor_pgid
        session.proc_exit_task = proc_exit_task
        session._loop = asyncio.get_running_loop()
        session.observe("supervisor_spawned")

        if os.name == "nt":
            native_job = _create_windows_job_object()
            if native_job is not None:
                _assign_to_job_object(native_job, proc)

        # --- Config delivery ---
        config_delivery_failed = False
        config_delivery_reason: str | None = None

        async def _deliver_config():
            nonlocal config_delivery_failed, config_delivery_reason
            try:
                proc.stdin.write(framed_config)
                await proc.stdin.drain()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                config_delivery_failed = True
                config_delivery_reason = f"config_delivery_failed: {e}"
            finally:
                try:
                    proc.stdin.close()
                except Exception:
                    pass

        config_task = asyncio.create_task(_deliver_config())
        session.config_task = config_task

        try:
            await asyncio.wait_for(config_task, timeout=CONFIG_DEADLINE_SECONDS)
        except asyncio.TimeoutError:
            config_delivery_failed = True
            config_delivery_reason = "config_delivery_timeout"
        except asyncio.CancelledError:
            _kill_process_group_pgid(supervisor_pgid, proc)
            raise
        except Exception:
            pass

        if config_delivery_failed:
            report = await session.shutdown(ShutdownReason.FAILURE)
            if native_job is not None:
                _close_job_handle(native_job)
            if not report.cleanup_complete:
                unresolved = "; ".join(report.unresolved) if report.unresolved else "unknown"
                return _attach_workload_input_metadata(
                    _error_result(f"supervisor_cleanup_incomplete: {unresolved}"),
                    report=report, session=session,
                )
            return _attach_workload_input_metadata(
                _error_result(config_delivery_reason or "config_delivery_failed"),
                report=report, session=session,
            )

        # --- Workload-input writer (event-loop-native, no blocking os.write) ---
        # T1 repair (v4): the writer uses the SESSION-owned FD (the parent
        # no longer holds its own copy) and delivers EOF through the
        # session's close-once primitive via close_once.
        if workload_stdin is not None and session.workload_input_wfd is not None and session.workload_input_wfd >= 0:
            writer_fd = session.workload_input_wfd
            writer_task = asyncio.create_task(
                _write_workload_input_nonblocking(
                    writer_fd,
                    workload_stdin,
                    terminal_deadline,
                    close_once=session.close_workload_input_wfd_once,
                )
            )
            session.workload_input_task = writer_task
            session.observe("workload_input_writer_started")

        # --- Protocol transport ---
        transport = AsyncProtocolTransport(
            protocol_rfd,
            loop=session._loop,
            max_bytes=MAX_PROTOCOL_STREAM_BYTES,
        )
        session.transport = transport
        protocol_rfd = -1  # ownership transferred to transport
        protocol_future = transport.start(deadline=terminal_deadline)
        session.observe("protocol_task_started")

        # --- Output task ---
        output_task = asyncio.create_task(
            run_bounded_async(
                proc,
                input_data=None,
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
                job_handle=native_job,
                proc_exit_task=proc_exit_task,
            )
        )
        session.stdout_task = output_task
        session.observe("output_task_started")

        # --- Coordination: wait for output or protocol ---
        # T1 repair (v7 Blocker 1): delegated to the extracted helper so the
        # bounded policy is testable independently of the full lifecycle.
        await _coordinate_protocol_output(
            protocol_future, output_task, terminal_deadline,
        )

        # If the protocol future completed first, the output task may still be
        # pending. Wait for it (capped by the terminal deadline) before
        # collecting its result — calling .result() on a pending task raises
        # InvalidStateError.
        if not output_task.done():
            remaining = terminal_deadline - time.monotonic()
            if remaining > 0:
                await asyncio.wait({output_task}, timeout=remaining)

        # --- Collect results ---
        try:
            bounded = output_task.result()
        except Exception:
            output_task_failure = True
            bounded = None

        protocol_result = None
        if protocol_future.done():
            try:
                protocol_result = protocol_future.result()
            except Exception:
                protocol_result = None

        # T1 repair (v4): nonblocking writer-result inspection. If the writer
        # is already terminal, read its result now so the exception is never
        # left unobserved ("Task exception was never retrieved"). Never awaits
        # a pending writer — the session's bounded shutdown owns that.
        session.consume_workload_input_result()

        # --- Shutdown ---
        reason = ShutdownReason.NORMAL
        if bounded and bounded.get("timed_out"):
            reason = ShutdownReason.TIMEOUT
        report = await session.shutdown(reason)

        # Refresh protocol result after shutdown drain.
        if protocol_future.done():
            try:
                fresh = protocol_future.result()
                if fresh is not None:
                    protocol_result = fresh
            except Exception:
                pass

        if session.transport is not None and not session.transport.closed:
            session.transport.close()
        if native_job is not None:
            _close_job_handle(native_job)

    except asyncio.CancelledError as cancel_err:
        cancel_report = None
        cancel_shutdown_failed = False
        try:
            cancel_report = await session.shutdown(ShutdownReason.CANCELLED)
        except Exception:
            cancel_shutdown_failed = True
        if session.transport is not None and not session.transport.closed:
            session.transport.close()
        if native_job is not None:
            _close_job_handle(native_job)
        if cancel_shutdown_failed or (
            cancel_report is not None and not cancel_report.cleanup_complete
        ):
            unresolved = (
                "; ".join(cancel_report.unresolved)
                if cancel_report and cancel_report.unresolved
                else "unknown"
            )
            raise RuntimeError(
                f"supervisor_cleanup_incomplete during cancellation: {unresolved}"
            ) from cancel_err
        raise

    except BaseException as original_err:
        cleanup_report = None
        cleanup_failed = False
        try:
            cleanup_report = await session.shutdown(ShutdownReason.FAILURE)
        except Exception:
            cleanup_failed = True
        if session.transport is not None and not session.transport.closed:
            session.transport.close()
        if native_job is not None:
            _close_job_handle(native_job)
        if cleanup_failed or (
            cleanup_report is not None and not cleanup_report.cleanup_complete
        ):
            unresolved = (
                "; ".join(cleanup_report.unresolved)
                if cleanup_report and cleanup_report.unresolved
                else "unknown"
            )
            raise RuntimeError(
                f"supervisor_cleanup_incomplete: {unresolved}"
            ) from original_err
        raise

    finally:
        if session.transport is not None and not session.transport.closed:
            session.transport.close()
        protocol_rfd = _close_fd_once(protocol_rfd)
        protocol_wfd = _close_fd_once(protocol_wfd)
        # T1 repair (v4 Amendment 3): route EVERY write-FD closure through
        # the session's close-once primitive — no direct os.close here. This
        # is the catch-all for early returns where shutdown was never called;
        # it records the same close proof and never retries a numeric FD.
        session.close_workload_input_wfd_once()
        # workload_input_rfd was closed in the spawn finally (immediate);
        # _close_fd_once is idempotent (-1 → no-op) so this is safe.
        workload_input_rfd = _close_fd_once(workload_input_rfd)
        if native_job is not None:
            try:
                _close_job_handle(native_job)
            except Exception:
                pass

    # --- Cleanup-incomplete dominance ---
    if not report.cleanup_complete:
        unresolved_str = (
            "; ".join(report.unresolved) if report.unresolved else "unknown"
        )
        if protocol_result is not None:
            evidence = extract_supervisor_evidence(protocol_result)
        else:
            evidence = SupervisorExecutionEvidence(
                protocol_valid=False,
                exec_confirmed=False,
                workload_exit_code=None,
                workload_signal=None,
                supervisor_failure_reason=f"supervisor_cleanup_incomplete: {unresolved_str}",
                cleanup_succeeded=None,
                protocol_failure_reason=f"supervisor_cleanup_incomplete: {unresolved_str}",
            )
        result = _map_result(evidence, bounded, output_task_failure)
        result["reason"] = f"supervisor_cleanup_incomplete: {unresolved_str}"
        result["exit_code_interpretation"] = "error"
        result["sandbox_event_log"] = [
            e
            for e in result["sandbox_event_log"]
            if e.get("event_type") != "code_execution_completed"
        ]
        result["sandbox_event_log"].append(
            {
                "event_type": "code_execution_failed",
                "backend": "native_os_sandbox",
                "metadata": {"reason": result["reason"]},
            }
        )
        return _attach_workload_input_metadata(result, report=report, session=session)

    # --- Map results ---
    if protocol_result is not None:
        evidence = extract_supervisor_evidence(protocol_result)
    else:
        evidence = SupervisorExecutionEvidence(
            protocol_valid=False,
            exec_confirmed=False,
            workload_exit_code=None,
            workload_signal=None,
            supervisor_failure_reason="protocol_read_exception",
            cleanup_succeeded=None,
            protocol_failure_reason="protocol_read_exception",
        )

    return _attach_workload_input_metadata(
        _map_result(evidence, bounded, output_task_failure=output_task_failure),
        report=report, session=session,
    )


# ---------------------------------------------------------------------------
# Coordination policy (extracted for testability)
# ---------------------------------------------------------------------------

async def _coordinate_protocol_output(
    protocol_future: asyncio.Future,
    output_task: asyncio.Task,
    terminal_deadline: float,
) -> None:
    """Bounded coordination: wait for protocol or output completion.

    Checks done-state BEFORE waiting, caps EVERY wait by the absolute
    terminal deadline, and never excludes an already-completed protocol
    future in favor of a pending-only wait set. Returns when either future
    is done or the deadline is exhausted. The caller is responsible for
    post-coordination drain via session shutdown.
    """
    while True:
        if protocol_future.done() or output_task.done():
            return
        remaining = terminal_deadline - time.monotonic()
        if remaining <= 0:
            return
        await asyncio.wait(
            {protocol_future, output_task},
            timeout=min(1.0, remaining),
            return_when=asyncio.FIRST_COMPLETED,
        )
        if protocol_future.done() or output_task.done():
            return


# ---------------------------------------------------------------------------
# Event-loop-native workload-input writer
# ---------------------------------------------------------------------------

async def _write_workload_input_nonblocking(
    wfd: int,
    data: bytes,
    deadline: float,
    *,
    close_once: Callable[[], Any] | None = None,
) -> None:
    """Write workload payload to a pipe FD using event-loop-native I/O.

    Uses ``loop.add_writer`` for readiness notification with non-blocking
    ``os.write``. Never uses ``asyncio.to_thread``. The FD is set
    non-blocking; partial writes are tracked and retried on next readiness.

    The caller (session) owns the task and its cancellation. This function
    does NOT enforce its own internal timeout — the session's one absolute
    terminal deadline is the authoritative bound via task cancellation.
    The ``deadline`` parameter is reserved for future use.

    EOF delivery: if ``close_once`` is provided (the session-owned
    close-once primitive), it is invoked exactly once in a function-level
    ``finally`` after the ENTIRE payload is written or the task exits. This
    guarantees the write FD is closed through the single ownership authority
    and delivers EOF to the reader. The inner per-readiness ``finally`` only
    removes the event-loop writer registration — it must NOT close the FD
    (a partial write would truncate the payload).
    """
    loop = asyncio.get_running_loop()
    written = 0
    total = len(data)

    # T1 repair (v4): wrap fcntl setup AND the write loop in one try/finally
    # so the close guarantee is truly function-wide. If fcntl raises, the FD
    # is still closed exactly once.
    try:
        import fcntl
        flags = fcntl.fcntl(wfd, fcntl.F_GETFL)
        fcntl.fcntl(wfd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        while written < total:
            # Create a fresh future for this write attempt.
            future: asyncio.Future = loop.create_future()

            def _on_writable():
                if future.done():
                    return
                try:
                    n = os.write(wfd, data[written:])
                    if n > 0:
                        if not future.done():
                            future.set_result(n)
                    # n == 0 is unusual but not an error; just retry.
                except BlockingIOError:
                    # Pipe full. Remove writer so we don't busy-loop.
                    # Set future with 0 to signal "retry needed".
                    loop.remove_writer(wfd)
                    if not future.done():
                        future.set_result(0)
                except OSError as e:
                    if not future.done():
                        future.set_exception(e)

            loop.add_writer(wfd, _on_writable)
            try:
                n = await future
                if n > 0:
                    written += n
                else:
                    # Pipe was full (BlockingIOError path). Yield to let the
                    # reader drain some data, then retry.
                    await asyncio.sleep(0.01)
            finally:
                # Inner finally: ONLY remove the writer registration.
                # Do NOT close the FD here — a partial write would truncate.
                try:
                    loop.remove_writer(wfd)
                except Exception:
                    pass
    finally:
        # Function-level finally: deliver EOF through the single close
        # authority, exactly once, after the full payload (or task exit).
        if close_once is not None:
            close_once()
        else:
            # Raw-pipe unit-test path: no session-owned primitive.
            try:
                os.close(wfd)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Helpers (thin wrappers to avoid circular imports)
# ---------------------------------------------------------------------------

def _close_fd_once(fd: int) -> int:
    """Close FD exactly once, return -1 (poisoned)."""
    if fd >= 0:
        try:
            os.close(fd)
        except OSError:
            pass
    return -1


def _kill_process_group_pgid(pgid: int | None, proc) -> None:
    """Kill using a stored PGID."""
    if pgid is not None:
        try:
            os.killpg(pgid, signal.SIGKILL)
            return
        except (OSError, ProcessLookupError):
            pass
    try:
        proc.kill()
    except Exception:
        pass


def _error_result(reason: str) -> dict[str, Any]:
    """Return a supervised execution error result."""
    return {
        "process_started": False,
        "process_exit_code": None,
        "process_timed_out": False,
        "stdout": "",
        "stderr": f"supervised execution error: {reason}",
        "output_truncated": False,
        "exit_code_interpretation": "error",
        "reason": reason,
        "backend": "native_os_sandbox",
        "sandbox_metadata": {},
        "sandbox_event_log": [
            {
                "event_type": "code_execution_failed",
                "backend": "native_os_sandbox",
                "metadata": {"reason": reason},
            }
        ],
    }


def _map_result(
    evidence: Any,
    bounded: dict[str, Any] | None,
    *,
    output_task_failure: bool = False,
) -> dict[str, Any]:
    """Map supervisor evidence + bounded output to result dict.

    Thin wrapper around the existing ``map_supervisor_result`` to avoid
    duplicating the mapping logic.
    """
    from nodechain.runtime.native_sandbox_exec import map_supervisor_result

    return map_supervisor_result(
        evidence, bounded, output_task_failure=output_task_failure
    )


def _attach_workload_input_metadata(
    result: dict[str, Any],
    *,
    report: Any = None,
    session: Any = None,
    fallback_status: str = "not_created",
) -> dict[str, Any]:
    """Project workload-input delivery state into caller-visible result metadata.

    T1 repair (v4): the session disappears when ``run_supervised_argv_async``
    returns, so writer classification must land in ``sandbox_metadata``.

    - When ``report`` is None (early return before any shutdown), use
      ``fallback_status`` — the workload pipe may already have been allocated
      before a spawn failure (``not_started``) or not at all (``not_created``).
    - When ``report`` is present, project the RAW writer signal to its
      caller-visible interpretation: ``epipe`` becomes ``epipe_tolerated``
      only when the process is proven terminal, else ``epipe_unexpected``.
      Other signals pass through unchanged.
    - Unexpected writer errors and unexpected EPIPE surface a distinct
      ``workload_input_delivery_error`` field.

    Robust to a malformed or None ``sandbox_metadata`` slot.
    """
    metadata = result.get("sandbox_metadata")
    if not isinstance(metadata, dict):
        metadata = {}
        result["sandbox_metadata"] = metadata

    if report is None:
        metadata["workload_input_status"] = fallback_status
        metadata["workload_input_writer_signal"] = None
        return result

    raw_signal = getattr(report, "workload_input_writer_signal", None)
    projected_signal = raw_signal
    if raw_signal == "epipe":
        # Interpretation deferred until process terminal proof exists.
        process_proven = getattr(getattr(report, "process_terminal", None), "proven", False)
        projected_signal = "epipe_tolerated" if process_proven else "epipe_unexpected"

    metadata["workload_input_status"] = getattr(report, "workload_input_status", "not_created")
    metadata["workload_input_writer_signal"] = projected_signal

    if projected_signal and (
        projected_signal.startswith("writer_error")
        or projected_signal == "epipe_unexpected"
    ):
        metadata["workload_input_delivery_error"] = projected_signal

    return result
