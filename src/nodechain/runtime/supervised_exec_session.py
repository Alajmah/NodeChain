"""R3 Task 3-4: Supervised execution session — ownership, terminal proof, shutdown.

This module centralizes all lifecycle state for one supervised execution:
  - supervisor process and its one proc_exit_task
  - stored PGID (never rediscovered)
  - protocol transport (event-loop-owned)
  - config/stdout/stderr tasks
  - absolute execution and cleanup deadlines
  - deterministic shutdown state machine

R3-INV-002: One owner per resource.
R3-INV-004: Strict process terminal proof.
R3-INV-005: Cancellation is not cleanup.
R3-INV-006: One absolute cleanup deadline.
R3-INV-007: Natural protocol drain precedes forced stop.
"""

from __future__ import annotations

import asyncio
import errno
import os
import signal
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from nodechain.runtime.async_fd_transport import AsyncProtocolTransport
from nodechain.runtime.exec_protocol import (
    ProtocolReadResult,
    ProtocolAccumulator,
)


# ---------------------------------------------------------------------------
# Terminal proof (R3-INV-004)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ProcessTerminalProof:
    """Strict process terminal validation result (R3-INV-004).

    A process is proven terminal only when ALL conditions hold:
        done() and not cancelled() and exception is None
        and returncode is not None and result matches returncode.
    """
    proven: bool
    returncode: int | None = None
    reason: str | None = None


def validate_terminal_proof(
    proc_exit_task: asyncio.Task,
    proc: Any,
) -> ProcessTerminalProof:
    """Pure validator — does not mutate the task or process.

    R3-INV-004: checks done, cancelled, exception, returncode, result consistency.
    Task.exception() must never be called before the cancelled check.
    """
    if not proc_exit_task.done():
        return ProcessTerminalProof(False, reason="proc_wait_pending")
    if proc_exit_task.cancelled():
        return ProcessTerminalProof(False, reason="proc_wait_cancelled")
    exc = proc_exit_task.exception()
    if exc is not None:
        return ProcessTerminalProof(False, reason="proc_wait_exception")
    if proc.returncode is None:
        return ProcessTerminalProof(False, reason="proc_returncode_missing")
    task_result = proc_exit_task.result()
    if task_result != proc.returncode:
        return ProcessTerminalProof(
            False, proc.returncode, "proc_wait_result_mismatch")
    return ProcessTerminalProof(True, proc.returncode)


# ---------------------------------------------------------------------------
# Shutdown state machine
# ---------------------------------------------------------------------------

class ShutdownState(Enum):
    OPEN = "open"
    NATURAL_DRAIN = "natural_drain"
    TERM_SENT = "term_sent"
    KILL_SENT = "kill_sent"
    TRANSPORT_DETACHED = "transport_detached"
    TASKS_SETTLED = "tasks_settled"
    CLOSED = "closed"


class ShutdownReason(Enum):
    NORMAL = "normal"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    FAILURE = "failure"


@dataclass
class CleanupReport:
    """Result of session shutdown."""
    process_terminal: ProcessTerminalProof
    protocol_terminal: bool
    stdout_complete: bool
    stderr_complete: bool
    config_complete: bool
    owned_tasks_terminal: bool
    owned_fds_closed: bool
    process_group_quiescent: bool
    cleanup_complete: bool
    duration_seconds: float
    unresolved: list[str] = field(default_factory=list)
    # T1: workload-input evidence (computed in _finalize_cleanup, not defaulted).
    workload_input_complete: bool = False
    workload_input_fd_closed: bool = False
    # T1 repair (v4): delivery status separate from resource terminality.
    workload_input_status: str = "not_created"
    workload_input_writer_signal: str | None = None
    # T1 repair (v4): ownership consistency is load-bearing for cleanup_complete
    # (EBADF proves physical closure but also proves an accounting defect —
    # the FD-reuse hazard). Exposed explicitly in the report.
    workload_input_fd_close_consistent: bool = True


# ---------------------------------------------------------------------------
# Supervised execution session
# ---------------------------------------------------------------------------

NATURAL_SHUTDOWN_GRACE = 5.0
TERM_GRACE = 5.0
KILL_GRACE = 5.0


@dataclass
class SupervisedExecSession:
    """R3 Task 3: Centralized supervised execution ownership (R3-INV-002).

    Owns every resource for one execution session. No helper may independently
    cancel, close, reap, or kill an owned resource.
    """
    proc: Any = None  # asyncio.subprocess.Process
    pgid: int | None = None
    proc_exit_task: asyncio.Task | None = None

    transport: AsyncProtocolTransport | None = None
    config_task: asyncio.Task | None = None
    stdout_task: asyncio.Task | None = None
    stderr_task: asyncio.Task | None = None

    # T1: workload-input task and write FD — owned by the session.
    workload_input_task: asyncio.Task | None = None
    workload_input_wfd: int | None = None  # parent-side write end; -1 after close

    execution_deadline: float = 0.0
    cleanup_budget: float = 15.0  # SUPERVISOR_CLEANUP_SECONDS

    _shutdown_state: ShutdownState = ShutdownState.OPEN
    _shutdown_task: asyncio.Task | None = None
    _cleanup_deadline: float = 0.0
    _observer: Callable[[str], None] | None = None
    _loop: asyncio.AbstractEventLoop | None = None
    # T1 repair (v4): cached close proof + raw writer signal (session-private).
    _workload_input_close_proof: tuple[bool, bool] | None = field(
        default=None, init=False, repr=False,
    )
    _workload_input_writer_signal: str | None = field(
        default=None, init=False, repr=False,
    )

    def observe(self, state: str) -> None:
        if self._observer is not None:
            self._observer(state)

    @property
    def shutdown_state(self) -> ShutdownState:
        return self._shutdown_state

    def owned_tasks(self) -> list[asyncio.Task]:
        """Return all owned tasks (excluding proc_exit_task which is shared)."""
        return [t for t in [self.config_task, self.stdout_task, self.stderr_task,
                            self.workload_input_task] if t is not None]

    def all_tasks(self) -> list[asyncio.Task]:
        """Return all tasks including proc_exit_task."""
        return self.owned_tasks() + ([self.proc_exit_task] if self.proc_exit_task else [])

    # ------------------------------------------------------------------
    # T1 repair (v4): single close-once authority + nonblocking inspect
    # ------------------------------------------------------------------

    def close_workload_input_wfd_once(self) -> tuple[bool, bool]:
        """Close the workload-input write FD exactly once.

        Poisons the slot to -1 BEFORE calling ``os.close`` so that a later
        retry sees -1 and skips. Records physical-close proof and returns it;
        all subsequent calls return the cached proof unchanged.

        Returns ``(fd_closed, close_consistent)``:
          * ``(True, True)``   — clean close.
          * ``(True, False)``  — EBADF: physically closed but ownership
                                 accounting was inconsistent (FD-reuse hazard).
          * ``(False, True)``  — non-EBADF OSError: closure could not be proven.

        Edge case: slot ``None``/negative with no recorded proof returns
        ``(True, True)`` — no live FD is owned and there is no failed close.
        """
        proof = self._workload_input_close_proof
        fd = self.workload_input_wfd
        if fd is None or fd < 0:
            return proof if proof is not None else (True, True)
        self.workload_input_wfd = -1  # poison BEFORE close
        try:
            os.close(fd)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                proof = (True, False)   # physically closed, inconsistent
            else:
                proof = (False, True)   # closure not proven
        else:
            proof = (True, True)
        self._workload_input_close_proof = proof
        return proof

    def consume_workload_input_result(self) -> str | None:
        """Nonblocking writer-result classification.

        NEVER awaits the task. Checks ``cancelled()`` BEFORE ``exception()``
        (the same strict terminal-state discipline applied to
        ``proc_exit_task``). Idempotent — caches the result in
        ``_workload_input_writer_signal``.

        Records the RAW observation. At T1 the caller-visible interpretation
        (``epipe_tolerated`` vs ``epipe_unexpected``) is projected only after
        the process terminal proof exists (see ``_attach_workload_input_metadata``).

        Returns ``None`` if the task is ``None`` or not yet done.
        """
        task = self.workload_input_task
        if task is None or not task.done():
            return None
        if self._workload_input_writer_signal is not None:
            return self._workload_input_writer_signal
        if task.cancelled():
            signal = "cancelled"
        else:
            try:
                exc = task.exception()  # cancelled() already checked above
            except asyncio.CancelledError:
                signal = "cancelled"
            else:
                if exc is None:
                    signal = "completed"
                elif isinstance(exc, (BrokenPipeError, ConnectionResetError)):
                    signal = "epipe"     # RAW — interpretation deferred
                elif isinstance(exc, OSError) and exc.errno == errno.EPIPE:
                    signal = "epipe"
                else:
                    signal = f"writer_error: {type(exc).__name__}: {exc}"
        self._workload_input_writer_signal = signal
        return signal

    # ------------------------------------------------------------------
    # Shutdown (Task 4)
    # ------------------------------------------------------------------

    async def shutdown(self, reason: ShutdownReason) -> CleanupReport:
        """R3 Task 4: Deterministic bounded shutdown state machine.

        Phases (R3-INV-006, R3-INV-007):
            A. Natural drain (bounded grace)
            B. SIGTERM (if natural drain incomplete)
            C. SIGKILL (if SIGTERM incomplete)
            D. Final containment (detach, close, settle)

        All phases consume one absolute cleanup deadline.

        R3 fix #3: phase ceilings prevent one phase from consuming the
        entire budget. The natural-drain phase is capped so that TERM
        and KILL phases always retain reserve time.
        R3 re-review fix #1: PGID quiescence is part of early-completion checks.
        R3 re-review fix #3: shutdown is idempotent with a persistent deadline.
        """
        # Re-review fix #3: idempotent with persistent deadline.
        if self._shutdown_state == ShutdownState.CLOSED:
            return self._last_report
        if self._shutdown_task is not None and not self._shutdown_task.done():
            # A shutdown is already in progress — await it.
            return await asyncio.shield(self._shutdown_task)
        # Create one persistent shutdown task.
        self._shutdown_task = asyncio.ensure_future(self._do_shutdown(reason))
        try:
            return await asyncio.shield(self._shutdown_task)
        except asyncio.CancelledError:
            # The shielded task continues; propagate cancellation.
            raise

    async def _do_shutdown(self, reason: ShutdownReason) -> CleanupReport:
        """Actual shutdown implementation with persistent deadline."""
        if self._shutdown_state == ShutdownState.CLOSED:
            return self._last_report

        # T1 amendment: one terminal deadline set at spawn. No fresh
        # deadline is manufactured at shutdown time. A zero deadline
        # means the caller did not set it — that is a programming error.
        if self._cleanup_deadline == 0.0:
            raise RuntimeError(
                "SupervisedExecSession._cleanup_deadline not set: "
                "caller must set it at spawn time"
            )
        cleanup_deadline = self._cleanup_deadline
        shutdown_start = time.monotonic()
        self.observe("cleanup_started")

        # R3 fix #3/#5: compute phase ceilings from reserved intervals.
        if reason == ShutdownReason.NORMAL:
            natural_cap = NATURAL_SHUTDOWN_GRACE
        else:
            natural_cap = 2.0
        term_reserve = min(TERM_GRACE, self.cleanup_budget * 0.3)
        kill_reserve = min(KILL_GRACE, self.cleanup_budget * 0.3)

        # T1 repair (v4): derive each phase ceiling from its ACTUAL entry time
        # using min()-only. No max() clamp — an expired deadline means that
        # phase receives zero time and _drain_naturally returns immediately
        # (it already short-circuits when remaining <= 0). This prevents a
        # cancellation early after spawn from waiting through unused execution
        # allowance, and bounds every phase including SIGKILL. The one absolute
        # terminal ceiling (cleanup_deadline) is set at spawn and never moved.
        natural_start = time.monotonic()
        natural_deadline = min(
            natural_start + natural_cap,
            cleanup_deadline - term_reserve - kill_reserve,
        )

        # Phase A: Natural drain (bounded by natural_cap).
        self._shutdown_state = ShutdownState.NATURAL_DRAIN
        self.observe("natural_shutdown_started")
        await self._drain_naturally(natural_deadline)

        # Re-review fix #1: PGID quiescence part of early-completion.
        proof = self._check_process_terminal()
        transport_terminal = self._check_transport_terminal()
        pgid_quiescent = self._check_pgid_quiescent()
        if proof.proven and self._all_tasks_terminal() and transport_terminal and pgid_quiescent:
            return self._finalize_cleanup(shutdown_start, proof)

        # Phase B: SIGTERM (ceiling from actual TERM entry time).
        if self._shutdown_state != ShutdownState.CLOSED:
            self._shutdown_state = ShutdownState.TERM_SENT
            self._signal_group(signal.SIGTERM)
            term_start = time.monotonic()
            term_deadline = min(
                term_start + TERM_GRACE,
                cleanup_deadline - kill_reserve,
            )
            await self._drain_naturally(term_deadline)

        proof = self._check_process_terminal()
        transport_terminal = self._check_transport_terminal()
        pgid_quiescent = self._check_pgid_quiescent()
        if proof.proven and self._all_tasks_terminal() and transport_terminal and pgid_quiescent:
            return self._finalize_cleanup(shutdown_start, proof)

        # Phase C: SIGKILL (ceiling from actual KILL entry time).
        # Default kill_deadline to the terminal ceiling; the KILL phase
        # refines it from its own entry time if it runs. (The guard is
        # defensive: if reached, state is TERM_SENT, not CLOSED.)
        kill_deadline = cleanup_deadline
        if self._shutdown_state != ShutdownState.CLOSED:
            self._shutdown_state = ShutdownState.KILL_SENT
            self._signal_group(signal.SIGKILL)
            kill_start = time.monotonic()
            kill_deadline = min(kill_start + KILL_GRACE, cleanup_deadline)
            await self._drain_naturally(kill_deadline)

        # Re-review fix #1: bounded PGID poll after SIGKILL.
        pgid_remaining = max(0.0, kill_deadline - time.monotonic())
        if pgid_remaining > 0 and not self._check_pgid_quiescent():
            # Poll for PGID disappearance within remaining budget.
            poll_end = time.monotonic() + min(pgid_remaining, 2.0)
            while time.monotonic() < poll_end:
                await asyncio.sleep(0.1)
                if self._check_pgid_quiescent():
                    break

        # Phase D: Final containment — terminalize transport runner.
        self._shutdown_state = ShutdownState.TRANSPORT_DETACHED
        if self.transport is not None:
            # R3 fix #2: terminalize the transport runner task.
            remaining = max(0.0, kill_deadline - time.monotonic())
            if remaining > 0:
                try:
                    await self.transport.terminate(deadline=kill_deadline)
                except Exception:
                    pass
            if not self.transport.closed:
                self.transport.close()
        await self._settle_tasks(kill_deadline)

        proof = self._check_process_terminal()
        return self._finalize_cleanup(shutdown_start, proof)

    async def _drain_naturally(self, deadline: float):
        """Await all owned resources within remaining cleanup budget."""
        remaining = max(0.0, deadline - time.monotonic())
        if remaining <= 0:
            return

        # Wait for proc_exit_task without cancellation.
        if self.proc_exit_task is not None and not self.proc_exit_task.done():
            done, _ = await asyncio.wait(
                {self.proc_exit_task}, timeout=remaining,
            )

        # Wait for transport future.
        if self.transport is not None:
            future = self.transport._future
            if future is not None and not future.done():
                remaining = max(0.0, deadline - time.monotonic())
                if remaining > 0:
                    done, _ = await asyncio.wait(
                        {future}, timeout=remaining,
                    )

        # Wait for owned tasks.
        for task in self.owned_tasks():
            if not task.done():
                remaining = max(0.0, deadline - time.monotonic())
                if remaining <= 0:
                    break
                done, _ = await asyncio.wait({task}, timeout=remaining)

        # T1 repair (v4): nonblocking — if the writer became terminal during
        # the drain, read its result now so the exception is never left
        # unobserved. Never awaits; returns None if still pending.
        self.consume_workload_input_result()

    async def _settle_tasks(self, deadline: float):
        """Cancel and await remaining tasks within remaining budget."""
        self._shutdown_state = ShutdownState.TASKS_SETTLED
        for task in self.owned_tasks():
            if not task.done():
                task.cancel()
        for task in self.owned_tasks():
            if not task.done():
                remaining = max(0.0, deadline - time.monotonic())
                if remaining > 0:
                    try:
                        await asyncio.wait({task}, timeout=remaining)
                    except Exception:
                        pass

        # T1 repair (v4): after cancellation/settlement, read the writer result
        # so a cancelled task's state is recorded and its exception is observed.
        self.consume_workload_input_result()

    def _signal_group(self, sig: int):
        """Signal the stored process group (R3-INV-007: stable PGID)."""
        if self.pgid is not None:
            try:
                os.killpg(self.pgid, sig)
            except (OSError, ProcessLookupError):
                pass

    def _check_process_terminal(self) -> ProcessTerminalProof:
        """Validate process terminal state (R3-INV-004)."""
        if self.proc_exit_task is None:
            return ProcessTerminalProof(False, reason="proc_wait_missing")
        return validate_terminal_proof(self.proc_exit_task, self.proc)

    def _check_transport_terminal(self) -> bool:
        """R3 fix #2: transport runner must be terminal."""
        if self.transport is None:
            return True
        if not self.transport.runner_done:
            return False
        if self.transport._future is not None and not self.transport._future.done():
            return False
        return True

    def _check_pgid_quiescent(self) -> bool:
        """R3 fix #4: independently prove process-group quiescence.

        After the leader's terminal proof, probe the stored PGID with
        os.killpg(pgid, 0). ESRCH means the group is gone.
        """
        if self.pgid is None:
            return False
        try:
            os.killpg(self.pgid, 0)
            # Group still exists — not quiescent.
            return False
        except ProcessLookupError:
            # ESRCH — group does not exist. Quiescent.
            return True
        except OSError:
            # Permission or other error — conservatively not proven.
            return False

    def _all_tasks_terminal(self) -> bool:
        """Check if all owned tasks are done."""
        return all(t.done() for t in self.all_tasks())

    def _finalize_cleanup(self, start: float, proof: ProcessTerminalProof) -> CleanupReport:
        """Build final cleanup report and close the session."""
        self._shutdown_state = ShutdownState.CLOSED
        self.observe("cleanup_completed")

        # Close transport if not already.
        if self.transport is not None and not self.transport.closed:
            self.transport.close()

        # T1 repair (v4): delivery status is separate from resource
        # terminality. workload_input_complete means the ENTIRE payload was
        # written (completed only); cancellation/epipe/error are terminal but
        # not delivered. Delivery failure must NOT dominate cleanup_complete —
        # cleanup_complete is a resource-terminalization statement.
        if self.workload_input_wfd is None and self.workload_input_task is None:
            workload_input_status = "not_created"
            workload_input_complete = True   # vacuous
        elif self.workload_input_task is None:
            # FD registered but writer never started (pre-writer failure).
            workload_input_status = "not_started"
            workload_input_complete = False  # delivery did not happen
        else:
            raw_signal = self.consume_workload_input_result()
            workload_input_status = raw_signal or "pending"
            workload_input_complete = (raw_signal == "completed")

        # FD closure proof via the SINGLE close-once primitive. Ownership
        # consistency (EBADF) stays load-bearing for cleanup_complete: it
        # proves the numeric descriptor was already closed AND that ownership
        # accounting was wrong — the FD-reuse hazard.
        workload_input_fd_closed, workload_input_fd_close_consistent = (
            self.close_workload_input_wfd_once()
        )

        all_terminal = self._all_tasks_terminal()
        transport_terminal = self._check_transport_terminal()
        pgid_quiescent = self._check_pgid_quiescent()
        duration = time.monotonic() - start

        # R3 fix #2: cleanup_complete requires transport terminality + FD closure.
        # R3 fix #4: process_group_quiescent is independently proven.
        # T1 repair (v4): workload FD close proof + ownership consistency are
        # load-bearing. Delivery (workload_input_complete) is NOT — a missing
        # payload delivery is reported in status, not as cleanup failure.
        cleanup_complete = (
            all_terminal
            and proof.proven
            and transport_terminal
            and pgid_quiescent
            and (self.transport is None or self.transport.fd_closed)
            and workload_input_fd_closed
            and workload_input_fd_close_consistent
        )

        unresolved = []
        if not proof.proven:
            unresolved.append(f"process: {proof.reason}")
        for name, task in [("config", self.config_task), ("stdout", self.stdout_task),
                           ("stderr", self.stderr_task)]:
            if task is not None and not task.done():
                unresolved.append(f"{name}_task_pending")
        if self.workload_input_task is not None and not self.workload_input_task.done():
            unresolved.append("workload_input_task_pending")
        if not workload_input_fd_closed:
            unresolved.append("workload_input_fd_open")
        if not workload_input_fd_close_consistent:
            unresolved.append("workload_input_fd_ownership_inconsistent")
        if self.proc_exit_task is not None and not self.proc_exit_task.done():
            unresolved.append("proc_exit_task_pending")
        if not transport_terminal:
            unresolved.append("protocol_transport_not_terminal")
        if not pgid_quiescent:
            unresolved.append("process_group_not_quiescent")

        report = CleanupReport(
            process_terminal=proof,
            protocol_terminal=transport_terminal,
            stdout_complete=self.stdout_task is None or self.stdout_task.done(),
            stderr_complete=self.stderr_task is None or self.stderr_task.done(),
            config_complete=self.config_task is None or self.config_task.done(),
            workload_input_complete=workload_input_complete,
            workload_input_fd_closed=workload_input_fd_closed,
            workload_input_status=workload_input_status,
            workload_input_writer_signal=self._workload_input_writer_signal,
            workload_input_fd_close_consistent=workload_input_fd_close_consistent,
            owned_tasks_terminal=all_terminal,
            owned_fds_closed=(self.transport is None or self.transport.fd_closed)
                             and workload_input_fd_closed,
            process_group_quiescent=pgid_quiescent,
            cleanup_complete=cleanup_complete,
            duration_seconds=duration,
            unresolved=unresolved,
        )
        self._last_report = report
        return report
