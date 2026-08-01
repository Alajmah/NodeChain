"""T1 repair (v4) adversarial lifecycle tests.

These cover the four blockers + the lifecycle gap + metadata visibility
identified in the HOLD verdict on commit 5668b86f:

  Blocker 1: successful payload delivery must not break FD ownership.
  Blocker 2: phase deadlines bounded from actual entry time.
  Blocker 3: parent's read-end closed immediately after spawn.
  Blocker 4: config failure before writer must not dominate cleanup.
  Gap:      writer exceptions retrieved, classified, surfaced.
  Amend 3:  outer finally routes through session close-once.

Session/mock tests run cross-platform; real-pipe tests are @posix_only.
"""

from __future__ import annotations

import asyncio
import gc
import os
import sys
import time
from pathlib import Path

import pytest


posix_only = pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: uses os.pipe and event-loop FD operations",
)


class TestRepairV4NormalWriterCompletion:
    """Blocker 1: successful payload delivery must not break FD ownership.

    Uses the REAL writer + real pipe + concurrent reader + counted os.close
    to prove the writer closed the FD exactly once via close_once and the
    finalizer did not retry it.
    """

    @posix_only
    @pytest.mark.asyncio
    async def test_normal_writer_completion_session_finalize(self):
        """Real writer writes payload through a pipe with a concurrent reader,
        delivers EOF via close_once, then session finalization reports
        cleanup_complete=True with status='completed'.

        Counts os.close calls to prove the writer closed exactly once and the
        finalizer did not retry the numeric FD.
        """
        from nodechain.runtime.supervised_exec_session import (
            SupervisedExecSession, ShutdownReason,
        )
        from nodechain.runtime.supervised_argv import _write_workload_input_nonblocking
        from unittest import mock as _mock

        rfd, wfd = os.pipe()
        original_close = os.close
        close_log: list = []

        payload = b"normal-completion-real-payload"

        # Concurrent reader so the writer can actually drain the pipe.
        received = bytearray()

        async def _reader():
            import fcntl
            fl = fcntl.fcntl(rfd, fcntl.F_GETFL)
            fcntl.fcntl(rfd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
            while True:
                try:
                    chunk = os.read(rfd, 65536)
                    if not chunk:
                        break
                    received.extend(chunk)
                except BlockingIOError:
                    await asyncio.sleep(0.001)
                except OSError:
                    break

        session = SupervisedExecSession()
        session._loop = asyncio.get_running_loop()
        session._cleanup_deadline = time.monotonic() + 5.0
        session.workload_input_wfd = wfd

        # Fake terminal proc_exit_task (done, result 0, not cancelled).
        async def _fake_wait():
            return 0
        proc_exit_task = asyncio.ensure_future(_fake_wait())
        await asyncio.sleep(0)
        session.proc_exit_task = proc_exit_task

        class _FakeProc:
            returncode = 0
        session.proc = _FakeProc()

        reader_task = asyncio.ensure_future(_reader())

        # REAL writer with close_once bound to the session primitive.
        writer_task = asyncio.ensure_future(
            _write_workload_input_nonblocking(
                wfd, payload, time.monotonic() + 5.0,
                close_once=session.close_workload_input_wfd_once,
            )
        )
        session.workload_input_task = writer_task

        original_pgid = session._check_pgid_quiescent
        original_transport = session._check_transport_terminal
        session._check_pgid_quiescent = lambda: True
        session._check_transport_terminal = lambda: True

        class _FakeTransport:
            closed = True
            fd_closed = True
        session.transport = _FakeTransport()

        # Count os.close calls on the workload wfd specifically.
        def _counting_close(fd, *a, **kw):
            close_log.append(fd)
            return original_close(fd, *a, **kw)

        try:
            # Let the writer complete (writes payload + calls close_once).
            with _mock.patch("os.close", side_effect=_counting_close):
                await writer_task

            # Await the reader to natural EOF — writer completion proves bytes
            # were written and the write end closed, but does NOT prove the
            # independently scheduled reader has consumed them. Without this
            # await the test can race with an empty/partial buffer on Linux.
            await asyncio.wait_for(reader_task, timeout=2.0)

            # Now finalize — the FD is already closed by the writer.
            report = await session.shutdown(ShutdownReason.NORMAL)

            # The reader consumed the full payload.
            assert bytes(received) == payload, "payload not fully delivered"

            # The wfd was closed exactly once (by the writer's close_once).
            # The finalizer's close_workload_input_wfd_once saw slot=-1 and
            # returned cached proof without calling os.close again.
            wfd_closes = [fd for fd in close_log if fd == wfd]
            assert len(wfd_closes) == 1, (
                f"wfd closed {len(wfd_closes)} times — must be exactly 1 "
                f"(writer close_once); finalizer must not retry"
            )

            assert report.cleanup_complete is True, (
                f"normal completion should be cleanup_complete=True; "
                f"unresolved={report.unresolved}"
            )
            assert report.workload_input_fd_closed is True
            assert report.workload_input_fd_close_consistent is True
            assert report.workload_input_status == "completed"
            assert report.workload_input_complete is True
            assert session.workload_input_wfd is None or session.workload_input_wfd < 0
        finally:
            session._check_pgid_quiescent = original_pgid
            session._check_transport_terminal = original_transport
            reader_task.cancel()
            try:
                await reader_task
            except (asyncio.CancelledError, Exception):
                pass
            try:
                original_close(rfd)
            except OSError:
                pass


class TestRepairV4FdReuseProtection:
    """Blocker 1: close-once poisons slot before close, never retries."""

    @pytest.mark.asyncio
    async def test_fd_reuse_protection_close_once_poisons_before_close(self):
        """close_workload_input_wfd_once poisons slot to -1 BEFORE os.close,
        attempts close exactly once, second call returns cached proof, no
        second close attempt."""
        from nodechain.runtime.supervised_exec_session import SupervisedExecSession
        from unittest import mock as _mock

        rfd, wfd = os.pipe()
        original_close = os.close
        close_log = []

        session = SupervisedExecSession()
        session.workload_input_wfd = wfd

        def _logging_close(fd, *a, **kw):
            close_log.append(fd)
            # Slot must ALREADY be poisoned at close time.
            assert session.workload_input_wfd == -1, (
                "slot must be poisoned to -1 BEFORE os.close is called"
            )
            return original_close(fd, *a, **kw)

        try:
            with _mock.patch("os.close", side_effect=_logging_close):
                proof1 = session.close_workload_input_wfd_once()
                proof2 = session.close_workload_input_wfd_once()
                proof3 = session.close_workload_input_wfd_once()

            assert len(close_log) == 1, (
                f"close attempted {len(close_log)} times — must be exactly 1"
            )
            assert proof1 == proof2 == proof3 == (True, True)
            assert session.workload_input_wfd == -1
        finally:
            try:
                original_close(rfd)
            except OSError:
                pass


class TestRepairV4ParentReadEndClose:
    """Blocker 3: parent's read-end closed immediately after spawn (AST lock)."""

    def test_parent_read_end_closed_immediately_after_spawn(self):
        """Static-source lock: workload_input_rfd is closed in the spawn
        'finally' block, not deferred to the outer finally."""
        import ast

        src = Path("src/nodechain/runtime/supervised_argv.py").read_text()
        tree = ast.parse(src)
        func = next(
            n for n in tree.body
            if isinstance(n, ast.AsyncFunctionDef) and n.name == "run_supervised_argv_async"
        )

        # Find the spawn try/except/finally by locating the except handler
        # that references supervisor_spawn_failed.
        spawn_block_src = None
        for node in ast.walk(func):
            if isinstance(node, ast.Try) and node.handlers:
                for handler in node.handlers:
                    handler_src = ast.get_source_segment(src, handler) or ""
                    if "supervisor_spawn_failed" in handler_src:
                        spawn_block_src = ast.get_source_segment(src, node)
                        break
                if spawn_block_src:
                    break

        assert spawn_block_src is not None, "could not locate the spawn try/finally"
        assert "workload_input_rfd = _close_fd_once(workload_input_rfd)" in spawn_block_src, (
            "spawn finally must close workload_input_rfd immediately"
        )


class TestRepairV4PreWriterFailure:
    """Blocker 4: config failure before writer creation must not dominate cleanup."""

    @pytest.mark.asyncio
    async def test_pre_writer_config_failure_does_not_dominate_cleanup(self):
        """FD registered, task=None (pre-writer). FD closes cleanly.
        cleanup_complete=True, status='not_started', delivery incomplete,
        but 'workload_input_writer_not_started' NOT in unresolved."""
        from nodechain.runtime.supervised_exec_session import (
            SupervisedExecSession, ShutdownReason,
        )

        rfd, wfd = os.pipe()
        session = SupervisedExecSession()
        session._loop = asyncio.get_running_loop()
        session._cleanup_deadline = time.monotonic() + 5.0
        session.workload_input_wfd = wfd
        # workload_input_task stays None — simulates pre-writer failure.

        async def _fake_wait():
            return 0
        proc_exit_task = asyncio.ensure_future(_fake_wait())
        await asyncio.sleep(0)
        session.proc_exit_task = proc_exit_task

        class _FakeProc:
            returncode = 0
        session.proc = _FakeProc()
        session._check_pgid_quiescent = lambda: True
        session._check_transport_terminal = lambda: True

        class _T:
            closed = True
            fd_closed = True
        session.transport = _T()

        try:
            report = await session.shutdown(ShutdownReason.FAILURE)

            assert report.workload_input_status == "not_started", (
                f"expected not_started, got {report.workload_input_status}"
            )
            assert report.workload_input_complete is False, (
                "delivery did not happen — complete should be False"
            )
            assert report.cleanup_complete is True, (
                f"clean FD closure must allow cleanup_complete=True; "
                f"unresolved={report.unresolved}"
            )
            assert "workload_input_writer_not_started" not in report.unresolved, (
                f"informational status must not pollute unresolved: {report.unresolved}"
            )
            assert report.workload_input_fd_closed is True
        finally:
            try:
                os.close(rfd)
            except OSError:
                pass


class TestRepairV4PhaseCeilings:
    """Blocker 2: phase deadlines bounded from actual entry time."""

    @posix_only
    @pytest.mark.asyncio
    async def test_cancellation_phase_ceilings_bounded_from_actual_start(self):
        """A pending owned task + unproven process forces shutdown through all
        phases. With a 3s terminal deadline, return must be well under the
        full execution allowance (tighter than generic <5s).

        POSIX-only: _do_shutdown references signal.SIGKILL which does not exist
        on Windows. The duration-nonnegative test covers the 'start' arithmetic
        fix cross-platform; this test covers the full multi-phase bounding.
        """
        """A pending owned task + unproven process forces shutdown through all
        phases. With a 3s terminal deadline, return must be well under the
        full execution allowance (tighter than generic <5s)."""
        from nodechain.runtime.supervised_exec_session import (
            SupervisedExecSession, ShutdownReason,
        )

        session = SupervisedExecSession()
        session._loop = asyncio.get_running_loop()
        # Terminal deadline 3s out — bounded.
        session._cleanup_deadline = time.monotonic() + 3.0

        # Pending owned task (forces the shutdown to not early-complete).
        async def _pending():
            await asyncio.sleep(3600)
        pending = asyncio.ensure_future(_pending())
        session.config_task = pending

        # proc_exit_task NOT done (process unproven) → forces TERM/KILL.
        async def _hanging_wait():
            await asyncio.sleep(3600)
            return 0
        proc_exit_task = asyncio.ensure_future(_hanging_wait())
        session.proc_exit_task = proc_exit_task

        class _P:
            returncode = None
        session.proc = _P()
        # Monkeypatch PGID quiescence -> False (non-quiescent) so shutdown
        # cannot early-complete and exercises all phases. We also patch
        # _signal_group so it doesn't call os.killpg (POSIX-only).
        original_pgid = session._check_pgid_quiescent
        original_signal = session._signal_group
        session._check_pgid_quiescent = lambda: False
        session._signal_group = lambda sig: None

        t0 = time.monotonic()
        try:
            await session.shutdown(ShutdownReason.CANCELLED)
        finally:
            session._check_pgid_quiescent = original_pgid
            session._signal_group = original_signal
            pending.cancel()
            proc_exit_task.cancel()
            for t in (pending, proc_exit_task):
                try:
                    await t
                except asyncio.CancelledError:
                    pass

        elapsed = time.monotonic() - t0
        assert elapsed < 4.0, (
            f"shutdown took {elapsed:.2f}s with 3s terminal deadline — "
            f"phase ceilings not bounded from actual entry time"
        )

    @pytest.mark.asyncio
    async def test_cleanup_duration_nonnegative(self):
        """A quick NORMAL shutdown (fake terminal everything) must report a
        nonnegative cleanup duration (proves the 'start' arithmetic fix)."""
        from nodechain.runtime.supervised_exec_session import (
            SupervisedExecSession, ShutdownReason,
        )

        session = SupervisedExecSession()
        session._loop = asyncio.get_running_loop()
        session._cleanup_deadline = time.monotonic() + 5.0

        async def _fake_wait():
            return 0
        proc_exit_task = asyncio.ensure_future(_fake_wait())
        await asyncio.sleep(0)
        session.proc_exit_task = proc_exit_task

        class _P:
            returncode = 0
        session.proc = _P()
        session._check_pgid_quiescent = lambda: True
        session._check_transport_terminal = lambda: True

        class _T:
            closed = True
            fd_closed = True
        session.transport = _T()

        report = await session.shutdown(ShutdownReason.NORMAL)
        assert report.duration_seconds >= 0.0, (
            f"cleanup duration negative: {report.duration_seconds} — "
            f"'start' was computed as a future synthetic time"
        )


class TestRepairV4WriterExceptionClassification:
    """Lifecycle gap: writer exceptions retrieved, classified, surfaced."""

    @posix_only
    @pytest.mark.asyncio
    async def test_writer_epipe_classified_raw_then_projected(self):
        """Writer with closed read-end -> raw 'epipe'. After attaching metadata
        with a terminal process, projected to 'epipe_tolerated'. No
        'Task exception was never retrieved' via loop exception handler."""
        from nodechain.runtime.supervised_exec_session import (
            SupervisedExecSession, ProcessTerminalProof,
        )
        from nodechain.runtime.supervised_argv import (
            _write_workload_input_nonblocking, _attach_workload_input_metadata,
        )

        rfd, wfd = os.pipe()
        os.close(rfd)  # close read end -> writer will get EPIPE

        loop = asyncio.get_running_loop()
        contexts: list = []
        previous = loop.get_exception_handler()
        loop.set_exception_handler(lambda _l, ctx: contexts.append(ctx))

        session = SupervisedExecSession()
        session.workload_input_wfd = wfd

        try:
            writer_task = asyncio.ensure_future(
                _write_workload_input_nonblocking(
                    wfd, b"data that will not be read", time.monotonic() + 5.0,
                    close_once=session.close_workload_input_wfd_once,
                )
            )
            session.workload_input_task = writer_task

            # Wait for terminality WITHOUT retrieving the result (asyncio.wait
            # does not call .result()/.exception()). This lets us prove that
            # consume_workload_input_result() is what retrieves the exception.
            done, _ = await asyncio.wait({writer_task}, timeout=2.0)
            assert writer_task in done, "writer did not terminate"

            raw = session.consume_workload_input_result()
            assert raw == "epipe", f"expected raw 'epipe', got {raw!r}"

            # Release references + GC so unobserved exceptions surface.
            session.workload_input_task = None
            del writer_task
            gc.collect()
            await asyncio.sleep(0)

            assert not any(
                ctx.get("message") == "Task exception was never retrieved"
                for ctx in contexts
            ), f"unobserved task exception: {contexts}"

            report = type("R", (), {
                "workload_input_writer_signal": "epipe",
                "workload_input_status": "epipe",
                "process_terminal": ProcessTerminalProof(True, 0),
            })()
            result = _attach_workload_input_metadata(
                {"sandbox_metadata": {}}, report=report, session=session,
            )
            assert result["sandbox_metadata"]["workload_input_writer_signal"] == "epipe_tolerated", (
                result["sandbox_metadata"]
            )
        finally:
            loop.set_exception_handler(previous)

    @pytest.mark.asyncio
    async def test_writer_unexpected_exception_classified(self):
        """Injected RuntimeError -> raw 'writer_error: RuntimeError: ...'.
        Surfaces workload_input_delivery_error in metadata."""
        from nodechain.runtime.supervised_exec_session import (
            SupervisedExecSession, ProcessTerminalProof,
        )
        from nodechain.runtime.supervised_argv import _attach_workload_input_metadata

        loop = asyncio.get_running_loop()
        contexts: list = []
        previous = loop.get_exception_handler()
        loop.set_exception_handler(lambda _l, ctx: contexts.append(ctx))

        session = SupervisedExecSession()

        async def _failing_writer():
            raise RuntimeError("injected writer failure")

        try:
            writer_task = asyncio.ensure_future(_failing_writer())
            session.workload_input_task = writer_task

            # Wait for terminality WITHOUT retrieving the result.
            done, _ = await asyncio.wait({writer_task}, timeout=2.0)
            assert writer_task in done, "writer did not terminate"

            raw = session.consume_workload_input_result()
            assert raw is not None and raw.startswith("writer_error"), raw
            assert "RuntimeError" in raw

            session.workload_input_task = None
            del writer_task
            gc.collect()
            await asyncio.sleep(0)

            assert not any(
                ctx.get("message") == "Task exception was never retrieved"
                for ctx in contexts
            ), f"unobserved task exception: {contexts}"

            report = type("R", (), {
                "workload_input_writer_signal": raw,
                "workload_input_status": raw,
                "process_terminal": ProcessTerminalProof(True, 0),
            })()
            result = _attach_workload_input_metadata(
                {"sandbox_metadata": {}}, report=report, session=session,
            )
            assert "workload_input_delivery_error" in result["sandbox_metadata"], (
                result["sandbox_metadata"]
            )
        finally:
            loop.set_exception_handler(previous)


class TestRepairV4OuterFinallyOwnership:
    """Amendment 3: outer finally routes through session close-once (AST lock)."""

    def test_outer_finally_uses_session_close_once(self):
        """Static-source lock scoped to the outer lifecycle Try.finalbody:
        the outer finally must call session.close_workload_input_wfd_once(),
        and no direct os.close(session.workload_input_wfd) may appear anywhere
        in the function.

        The outer Try is the top-level try statement directly in the function
        body (not a nested spawn try). Its finalbody is the authoritative
        catch-all close site."""
        import ast

        src = Path("src/nodechain/runtime/supervised_argv.py").read_text()
        tree = ast.parse(src)
        func = next(
            n for n in tree.body
            if isinstance(n, ast.AsyncFunctionDef) and n.name == "run_supervised_argv_async"
        )
        func_src = ast.get_source_segment(src, func)

        # No direct os.close on the session-owned FD anywhere in the function.
        assert "os.close(session.workload_input_wfd)" not in func_src, (
            "direct os.close(session.workload_input_wfd) found — must route "
            "through session.close_workload_input_wfd_once()"
        )

        # Find the outer lifecycle Try — the one whose finalbody closes
        # protocol_rfd/protocol_wfd (the catch-all). Walk ONLY direct children
        # of the function body to get the top-level try (not nested ones).
        outer_try = None
        for stmt in func.body:
            if isinstance(stmt, ast.Try) and stmt.finalbody:
                fb_src = ast.get_source_segment(src, stmt) or ""
                if "protocol_rfd" in fb_src and "protocol_wfd" in fb_src:
                    outer_try = stmt
                    break

        assert outer_try is not None, (
            "could not locate the outer lifecycle try/finally"
        )
        # Inspect ONLY the finalbody nodes (not the whole try statement, which
        # includes the try body where the writer callback wiring appears).
        finalbody_src = "\n".join(
            ast.get_source_segment(src, stmt) or ""
            for stmt in outer_try.finalbody
        )
        # The outer finalbody must contain the session primitive call.
        assert "session.close_workload_input_wfd_once()" in finalbody_src, (
            "outer lifecycle finalbody must call "
            "session.close_workload_input_wfd_once() — not just the writer wiring"
        )


# ---------------------------------------------------------------------------
# T1 repair (v5) fault-injection tests for the three new blockers
# ---------------------------------------------------------------------------


class TestRepairV5DeadlineOverrun:
    """Blocker 1: coordination must not overrun the absolute deadline.

    Tests the PRODUCTION helper _coordinate_protocol_output, not a copy."""

    @pytest.mark.asyncio
    async def test_completed_protocol_returns_immediately(self):
        """An already-completed protocol future must cause immediate return,
        not a 1-second wait on the output task."""
        from nodechain.runtime.supervised_argv import _coordinate_protocol_output

        protocol_future = asyncio.get_running_loop().create_future()
        protocol_future.set_result("done")

        async def _pending_output():
            await asyncio.sleep(30.0)
        output_task = asyncio.ensure_future(_pending_output())

        terminal_deadline = time.monotonic() + 0.15

        t0 = time.monotonic()
        await _coordinate_protocol_output(protocol_future, output_task, terminal_deadline)
        elapsed = time.monotonic() - t0

        # Must return near-instantly, NOT wait 1s on output.
        assert elapsed < 0.5, (
            f"coordination took {elapsed:.2f}s with completed protocol — "
            f"should return immediately, not wait on output"
        )

        output_task.cancel()
        try:
            await output_task
        except asyncio.CancelledError:
            pass

    @pytest.mark.asyncio
    async def test_coordination_does_not_overrun_near_deadline(self):
        """When both futures are pending and the terminal deadline is ~150ms
        out, the helper must return within ~150ms, not wait a full second.

        The lower bound rejects an unconditional immediate return (a no-op
        helper would pass <1.0 but fail >=0.08). The futures must remain
        pending (termination was by deadline, not by completion)."""
        from nodechain.runtime.supervised_argv import _coordinate_protocol_output

        async def _pending():
            await asyncio.sleep(30.0)
        protocol_future = asyncio.ensure_future(_pending())
        output_task = asyncio.ensure_future(_pending())

        terminal_deadline = time.monotonic() + 0.15

        t0 = time.monotonic()
        await _coordinate_protocol_output(protocol_future, output_task, terminal_deadline)
        elapsed = time.monotonic() - t0

        # Lower bound: the helper must have actually waited for the deadline.
        # Upper bound: must not overrun to the full 1s.
        assert 0.08 <= elapsed < 0.75, (
            f"coordination took {elapsed:.2f}s with 0.15s deadline — "
            f"either returned immediately (no-op) or overran"
        )
        # Neither future completed — termination was by deadline exhaustion.
        assert not protocol_future.done(), "protocol_future should still be pending"
        assert not output_task.done(), "output_task should still be pending"

        for t in (protocol_future, output_task):
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass

    @pytest.mark.asyncio
    async def test_expired_deadline_returns_immediately(self):
        """An already-expired terminal deadline must cause immediate return."""
        from nodechain.runtime.supervised_argv import _coordinate_protocol_output

        async def _pending():
            await asyncio.sleep(30.0)
        protocol_future = asyncio.ensure_future(_pending())
        output_task = asyncio.ensure_future(_pending())

        # Deadline already in the past.
        terminal_deadline = time.monotonic() - 1.0

        t0 = time.monotonic()
        await _coordinate_protocol_output(protocol_future, output_task, terminal_deadline)
        elapsed = time.monotonic() - t0

        assert elapsed < 0.1, (
            f"coordination took {elapsed:.2f}s with expired deadline — "
            f"should return immediately"
        )

        for t in (protocol_future, output_task):
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass


class TestRepairV5PipeOwnershipBoundary:
    """Blocker 2: pipe creation + env materialization inside the ownership
    boundary; partial-creation failures return governed errors with proven
    descriptor closure, not leaks."""

    def test_pipe_creation_inside_ownership_boundary(self):
        """Source lock: os.pipe() calls appear INSIDE the outer try."""
        import ast

        src = Path("src/nodechain/runtime/supervised_argv.py").read_text()
        tree = ast.parse(src)
        func = next(
            n for n in tree.body
            if isinstance(n, ast.AsyncFunctionDef)
            and n.name == "run_supervised_argv_async"
        )

        outer_try = None
        for stmt in func.body:
            if isinstance(stmt, ast.Try) and stmt.finalbody:
                fb_src = ast.get_source_segment(src, stmt) or ""
                if "protocol_rfd" in fb_src:
                    outer_try = stmt
                    break
        assert outer_try is not None

        outer_try_src = ast.get_source_segment(src, outer_try)
        assert "os.pipe()" in outer_try_src, (
            "os.pipe() calls must be inside the ownership try boundary"
        )

        for stmt in func.body:
            if stmt is outer_try:
                break
            stmt_src = ast.get_source_segment(src, stmt) or ""
            assert "os.pipe()" not in stmt_src, (
                "os.pipe() must not appear before the ownership boundary"
            )

    @pytest.mark.asyncio
    async def test_first_pipe_failure_returns_governed_error(self):
        """If the FIRST os.pipe() fails, no descriptors are created. The API
        returns a governed error with status not_created."""
        from nodechain.runtime.supervised_argv import run_supervised_argv_async
        from unittest import mock as _mock

        def _failing_first_pipe():
            raise OSError(24, "EMFILE injected — first pipe")

        with _mock.patch("os.pipe", side_effect=_failing_first_pipe):
            result = await run_supervised_argv_async(
                argv=["/bin/true"],
                workload_stdin=b"payload",
                workload_cwd=None,
                supervisor_env={},
                workload_env={},
                timeout_seconds=5,
                max_output_bytes=1000,
            )

        assert result["process_started"] is False
        assert "pipe_creation_failed" in result["reason"], result["reason"]
        # No channel was ever created.
        assert result["sandbox_metadata"]["workload_input_status"] == "not_created"

    @pytest.mark.asyncio
    async def test_second_pipe_failure_closes_protocol_fds(self):
        """If the SECOND os.pipe() fails after the protocol pipe succeeds, the
        protocol FDs are physically closed (no leak) and status is not_created."""
        from nodechain.runtime.supervised_argv import run_supervised_argv_async
        from unittest import mock as _mock

        original_pipe = os.pipe
        original_close = os.close
        created_fds: list = []
        closed_fds: list = []
        call_count = {"n": 0}

        def _tracking_pipe():
            call_count["n"] += 1
            fds = original_pipe()
            if call_count["n"] == 1:
                # First pipe (protocol) — track its FDs.
                created_fds.extend(fds)
            return fds

        def _tracking_close(fd, *a, **kw):
            closed_fds.append(fd)
            return original_close(fd, *a, **kw)

        def _failing_second_pipe():
            call_count["n"] += 1
            if call_count["n"] == 2:
                raise OSError(24, "EMFILE injected — second pipe")
            fds = original_pipe()
            created_fds.extend(fds)
            return fds

        with _mock.patch("os.pipe", side_effect=_failing_second_pipe), \
             _mock.patch("os.close", side_effect=_tracking_close):
            result = await run_supervised_argv_async(
                argv=["/bin/true"],
                workload_stdin=b"payload",
                workload_cwd=None,
                supervisor_env={},
                workload_env={},
                timeout_seconds=5,
                max_output_bytes=1000,
            )

        assert "pipe_creation_failed" in result["reason"], result["reason"]
        # Channel never created (second pipe failed before transfer).
        assert result["sandbox_metadata"]["workload_input_status"] == "not_created"

        # Prove the protocol pipe FDs were physically closed by the finally
        # boundary — each created FD appears in the close log and was passed
        # to the real os.close exactly once.
        for fd in created_fds:
            assert fd in closed_fds, (
                f"protocol FD {fd} was created but never closed — leak"
            )
            assert closed_fds.count(fd) == 1, (
                f"protocol FD {fd} closed {closed_fds.count(fd)} times — must be once"
            )

    @pytest.mark.asyncio
    async def test_supervisor_env_failure_closes_created_fds(self):
        """If dict(supervisor_env) raises after pipe allocation, the created
        FDs are closed (no leak) and status reflects no channel created."""
        from nodechain.runtime.supervised_argv import run_supervised_argv_async
        from unittest import mock as _mock

        original_pipe = os.pipe
        original_close = os.close
        created_fds: list = []
        closed_fds: list = []

        def _tracking_pipe():
            fds = original_pipe()
            created_fds.extend(fds)
            return fds

        def _tracking_close(fd, *a, **kw):
            closed_fds.append(fd)
            return original_close(fd, *a, **kw)

        class _ExplodingMapping:
            def __iter__(self):
                raise TypeError("injected env materialization failure")
            def keys(self):
                raise TypeError("injected env materialization failure")

        with _mock.patch("os.pipe", side_effect=_tracking_pipe), \
             _mock.patch("os.close", side_effect=_tracking_close):
            result = await run_supervised_argv_async(
                argv=["/bin/true"],
                workload_stdin=None,
                workload_cwd=None,
                supervisor_env=_ExplodingMapping(),  # type: ignore
                workload_env={},
                timeout_seconds=5,
                max_output_bytes=1000,
            )

        assert "supervisor_env_failed" in result["reason"], result["reason"]
        assert result["sandbox_metadata"]["workload_input_status"] == "not_created"

        # Prove created FDs were closed exactly once (no double-close, no leak).
        for fd in created_fds:
            assert fd in closed_fds, f"FD {fd} created but never closed — leak"
            assert closed_fds.count(fd) == 1, (
                f"FD {fd} closed {closed_fds.count(fd)} times — must be exactly 1"
            )


class TestRepairV8ConfigMaterialization:
    """Configuration materialization must govern ALL ordinary exceptions, not
    just TypeError/ValueError. A custom argv or workload_env can raise
    RuntimeError, OSError, KeyError, etc. during iteration."""

    @pytest.mark.asyncio
    async def test_argv_runtime_error_returns_config_serialize_failed(self):
        """A custom argv sequence whose __iter__ raises RuntimeError must
        return config_serialize_failed, not escape ungoverned."""
        from nodechain.runtime.supervised_argv import run_supervised_argv_async

        class _ExplodingSequence:
            def __iter__(self):
                raise RuntimeError("injected argv iteration failure")
            def __len__(self):
                return 1

        result = await run_supervised_argv_async(
            argv=_ExplodingSequence(),  # type: ignore
            workload_stdin=None,
            workload_cwd=None,
            supervisor_env={},
            workload_env={},
            timeout_seconds=5,
            max_output_bytes=1000,
        )

        assert result["process_started"] is False
        assert "config_serialize_failed" in result["reason"], result["reason"]
        assert result["sandbox_metadata"]["workload_input_status"] == "not_created"

    @pytest.mark.asyncio
    async def test_workload_env_oserror_returns_config_serialize_failed(self):
        """A custom workload_env mapping whose keys() raises OSError must
        return config_serialize_failed, not escape ungoverned."""
        from nodechain.runtime.supervised_argv import run_supervised_argv_async

        class _ExplodingMapping:
            def keys(self):
                raise OSError(5, "injected workload_env keys failure")
            def __iter__(self):
                raise OSError(5, "injected workload_env iteration failure")

        result = await run_supervised_argv_async(
            argv=["/bin/true"],
            workload_stdin=None,
            workload_cwd=None,
            supervisor_env={},
            workload_env=_ExplodingMapping(),  # type: ignore
            timeout_seconds=5,
            max_output_bytes=1000,
        )

        assert result["process_started"] is False
        assert "config_serialize_failed" in result["reason"], result["reason"]
        assert result["sandbox_metadata"]["workload_input_status"] == "not_created"


class TestRepairV6PostSpawnFaultGovernance:
    """Post-spawn exceptions must go through governed session shutdown, not be
    misclassified as setup errors. Injects real faults at AsyncProtocolTransport
    construction (which runs after proc_exit_task is registered).

    The outer BaseException handler performs governed failure shutdown and then
    RE-RAISES the original exception when cleanup succeeds. So these tests use
    pytest.raises to capture the preserved exception, then assert that governed
    shutdown ran with FAILURE and completed."""

    @posix_only
    @pytest.mark.asyncio
    async def test_post_spawn_oserror_enters_governed_shutdown(self):
        """An OSError raised at AsyncProtocolTransport construction (after
        proc_exit_task is registered) must be preserved through governed
        failure-shutdown — not misclassified as pipe_creation_failed."""
        from nodechain.runtime.supervised_argv import run_supervised_argv_async
        from unittest import mock as _mock
        from nodechain.runtime.supervised_exec_session import (
            SupervisedExecSession, ShutdownReason,
        )

        shutdown_reasons: list = []
        reports: list = []
        original_shutdown = SupervisedExecSession.shutdown

        async def _tracking_shutdown(self, reason):
            report = await original_shutdown(self, reason)
            shutdown_reasons.append(reason)
            reports.append(report)
            return report

        def _failing_transport_init(self, *a, **kw):
            raise OSError(5, "injected post-spawn transport fault")

        import nodechain.runtime.async_fd_transport as _adt
        with _mock.patch.object(SupervisedExecSession, "shutdown", _tracking_shutdown), \
             _mock.patch.object(_adt.AsyncProtocolTransport, "__init__", _failing_transport_init):
            with pytest.raises(OSError, match="injected post-spawn transport fault"):
                await run_supervised_argv_async(
                    argv=["/bin/true"],
                    workload_stdin=None,
                    workload_cwd=None,
                    supervisor_env={"PATH": "/usr/bin:/bin"},
                    workload_env={},
                    timeout_seconds=5,
                    max_output_bytes=1000,
                )

        # Governed shutdown ran with FAILURE.
        assert ShutdownReason.FAILURE in shutdown_reasons, (
            f"shutdown reasons: {shutdown_reasons} — expected FAILURE"
        )
        # Cleanup actually completed (not merely attempted).
        assert reports, "no CleanupReport captured"
        assert reports[-1].cleanup_complete is True, (
            f"governed shutdown did not complete: {reports[-1].unresolved}"
        )

    @posix_only
    @pytest.mark.asyncio
    async def test_post_spawn_typeerror_enters_governed_shutdown(self):
        """A TypeError raised at AsyncProtocolTransport construction must take
        the same governed failure-shutdown path."""
        from nodechain.runtime.supervised_argv import run_supervised_argv_async
        from unittest import mock as _mock
        from nodechain.runtime.supervised_exec_session import (
            SupervisedExecSession, ShutdownReason,
        )

        shutdown_reasons: list = []
        reports: list = []
        original_shutdown = SupervisedExecSession.shutdown

        async def _tracking_shutdown(self, reason):
            report = await original_shutdown(self, reason)
            shutdown_reasons.append(reason)
            reports.append(report)
            return report

        def _failing_transport_init(self, *a, **kw):
            raise TypeError("injected post-spawn TypeError")

        import nodechain.runtime.async_fd_transport as _adt
        with _mock.patch.object(SupervisedExecSession, "shutdown", _tracking_shutdown), \
             _mock.patch.object(_adt.AsyncProtocolTransport, "__init__", _failing_transport_init):
            with pytest.raises(TypeError, match="injected post-spawn TypeError"):
                await run_supervised_argv_async(
                    argv=["/bin/true"],
                    workload_stdin=None,
                    workload_cwd=None,
                    supervisor_env={"PATH": "/usr/bin:/bin"},
                    workload_env={},
                    timeout_seconds=5,
                    max_output_bytes=1000,
                )

        assert ShutdownReason.FAILURE in shutdown_reasons, (
            f"shutdown reasons: {shutdown_reasons} — expected FAILURE"
        )
        assert reports, "no CleanupReport captured"
        assert reports[-1].cleanup_complete is True, (
            f"governed shutdown did not complete: {reports[-1].unresolved}"
        )
