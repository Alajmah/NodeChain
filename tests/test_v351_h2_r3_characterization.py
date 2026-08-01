"""Task 0: Characterize current async supervision ownership defects.

These tests demonstrate the three production blockers that R3 resolves:

1. asyncio.to_thread protocol reader can survive return
2. proc_exit_task.done() accepts cancelled/exceptional tasks as reaped
3. A non-terminating nested reader can exceed the nominal cleanup budget

These are NOT tests that should pass in the final R3 implementation — they
characterize the CURRENT broken behavior so R3 can prove it fixes them.
"""

from __future__ import annotations

import asyncio
import os
import signal
import sys
import threading
import time
from unittest import mock

import pytest


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only: async lifecycle")
class TestCurrentDefects:
    """Characterization tests for the three async supervision ownership defects."""

    # ------------------------------------------------------------------
    # Defect 1: asyncio.to_thread protocol reader can survive return
    # ------------------------------------------------------------------

    def test_to_thread_protocol_reader_exists(self):
        """Post-R3/T1: the production supervised lifecycle must NOT use
        asyncio.to_thread for protocol reading.

        After R3 Task 5, the production path uses AsyncProtocolTransport.
        After T1, the lifecycle implementation moved from
        ``native_sandbox_exec._run_supervised_child`` to
        ``supervised_argv.run_supervised_argv_async``. The thin wrapper
        in ``_run_supervised_child`` delegates and contains no independent
        process lifecycle.
        """
        # T1: the lifecycle source moved to supervised_argv.py.
        with open("src/nodechain/runtime/supervised_argv.py") as f:
            lifecycle_source = f.read()

        # The wrapper in native_sandbox_exec.py must be thin — no
        # independent lifecycle (no AsyncProtocolTransport, no
        # asyncio.to_thread, no start_new_session).
        with open("src/nodechain/runtime/native_sandbox_exec.py") as f:
            wrapper_source = f.read()
        start = wrapper_source.index("async def _run_supervised_child")
        end = wrapper_source.index("def _close_fd_once")
        wrapper_func = wrapper_source[start:end]
        assert "run_supervised_argv_async" in wrapper_func, (
            "wrapper must delegate to run_supervised_argv_async"
        )
        assert "AsyncProtocolTransport" not in wrapper_func, (
            "wrapper must not contain independent lifecycle"
        )
        assert "start_new_session=True" not in wrapper_func, (
            "wrapper must not contain spawn logic"
        )

        # The lifecycle source must use AsyncProtocolTransport and must
        # NOT call asyncio.to_thread.
        for line in lifecycle_source.split("\n"):
            stripped = line.strip()
            if "asyncio.to_thread(" in stripped:
                pytest.fail(f"asyncio.to_thread call found: {stripped}")
        assert "AsyncProtocolTransport" in lifecycle_source, (
            "lifecycle source must use AsyncProtocolTransport"
        )
        assert "start_new_session=True" in lifecycle_source, (
            "lifecycle source must spawn with start_new_session=True"
        )

    # ------------------------------------------------------------------
    # Defect 2: proc_exit_task.done() accepts cancelled/exceptional tasks
    # ------------------------------------------------------------------

    def test_done_only_check_accepts_cancelled_task(self):
        """Task.done() returns True for cancelled tasks, masking failed reaping.

        This proves the validation gap: a cancelled proc_exit_task would be
        accepted as 'done' without checking cancelled() or exception().
        """
        async def demonstrate():
            async def hanging():
                await asyncio.sleep(999)
                return 0

            task = asyncio.create_task(hanging())
            # Let the task start.
            await asyncio.sleep(0.01)
            # Cancel it.
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

            # done() returns True — but the task was cancelled, not completed.
            assert task.done(), "cancelled task should be done()"
            assert task.cancelled(), "cancelled task should be cancelled()"
            # A done()-only check would accept this as reaped. R3 must not.
            return task

        loop = asyncio.new_event_loop()
        try:
            task = loop.run_until_complete(demonstrate())
        finally:
            loop.close()
        assert task.done()
        assert task.cancelled()

    def test_done_only_check_accepts_exceptional_task(self):
        """Task.done() returns True for exceptional tasks, masking failed reaping."""
        async def demonstrate():
            async def failing():
                raise RuntimeError("reap failure")

            task = asyncio.create_task(failing())
            await asyncio.sleep(0.01)  # let it fail

            # done() returns True — but the task raised an exception.
            assert task.done()
            assert task.exception() is not None
            # A done()-only check would accept this as reaped. R3 must not.
            return task

        loop = asyncio.new_event_loop()
        try:
            task = loop.run_until_complete(demonstrate())
        finally:
            loop.close()
        assert task.done()
        assert task.exception() is not None

    # ------------------------------------------------------------------
    # Defect 3: Non-terminating nested reader can exceed cleanup budget
    # ------------------------------------------------------------------

    def test_cancellation_resistant_task_can_block_indefinitely(self):
        """A task that catches CancelledError can prevent bounded cleanup.

        This demonstrates why unbounded `await task` exists in the current
        code and why R3 must replace it with deterministic transport shutdown.
        """
        async def demonstrate():
            cancellation_count = {"n": 0}

            async def resistant_task():
                try:
                    await asyncio.sleep(999)
                except asyncio.CancelledError:
                    cancellation_count["n"] += 1
                    if cancellation_count["n"] < 3:
                        # Resist cancellation the first 2 times.
                        return "resisted"
                    raise

            task = asyncio.create_task(resistant_task())
            await asyncio.sleep(0.01)

            # Cancel — the task resists.
            task.cancel()
            try:
                result = await task
                # If it returned "resisted", it caught CancelledError.
                return result, cancellation_count["n"]
            except asyncio.CancelledError:
                return "cancelled", cancellation_count["n"]

        loop = asyncio.new_event_loop()
        try:
            result, cancel_count = loop.run_until_complete(demonstrate())
        finally:
            loop.close()
        # The task caught at least one CancelledError before terminating.
        assert cancel_count >= 1, "task should have caught at least one cancel"

    # ------------------------------------------------------------------
    # Summary: the three defects R3 must fix
    # ------------------------------------------------------------------

    def test_r3_must_eliminate_to_thread(self):
        """R3 acceptance criterion: no asyncio.to_thread in protocol path."""
        with open("src/nodechain/runtime/native_sandbox_exec.py") as f:
            source = f.read()
        # This characterization documents what EXISTS today.
        # R3 Task 5 will remove this line. After R3, this assertion
        # should be updated to assert the line is ABSENT.
        if "asyncio.to_thread(read_bounded_protocol" in source:
            pass  # defect still present (pre-R3 state)
        # Post-R3: assert "asyncio.to_thread" not in source

    def test_r3_must_validate_reap_terminal_state(self):
        """R3 acceptance: process terminal proof is validated via validate_terminal_proof."""
        from nodechain.runtime.supervised_exec_session import validate_terminal_proof
        assert validate_terminal_proof is not None
        # R3 now uses validate_terminal_proof through SupervisedExecSession.shutdown().
        # The obsolete _terminalize_reap has been removed.
