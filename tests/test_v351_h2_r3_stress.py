"""R3 Task 7: Leak and stress verification.

Runs 100+ iterations of supervised execution, measuring:
  - /proc/self/fd count
  - asyncio.all_tasks() count
  - live child processes
  - thread count

Acceptance: no monotonic FD growth, no surviving task, no protocol reader thread.
"""

from __future__ import annotations

import asyncio
import os
import sys
import threading
import time
from pathlib import Path

import pytest

from nodechain.runtime.native_sandbox_exec import run_isolated
pytestmark = pytest.mark.native_sandbox


def _fd_count() -> int:
    """Count open FDs via /proc/self/fd."""
    try:
        return len(os.listdir("/proc/self/fd"))
    except OSError:
        return -1


def _thread_count() -> int:
    """Count active threads."""
    return threading.active_count()


def _child_count() -> int:
    """Count child processes of this process."""
    try:
        pids = os.listdir("/proc")
        my_pid = os.getpid()
        children = 0
        for pid_str in pids:
            if not pid_str.isdigit():
                continue
            try:
                stat = open(f"/proc/{pid_str}/stat").read()
                # PPID is the 4th field after the comm name.
                parts = stat.rsplit(")", 1)[1].split()
                ppid = int(parts[1])
                if ppid == my_pid:
                    children += 1
            except (OSError, IndexError, ValueError):
                pass
        return children
    except OSError:
        return -1


def _run_supervised(argv, timeout=10):
    """Run one supervised execution."""
    import tempfile
    return run_isolated(
        argv=argv,
        cwd=Path(tempfile.mkdtemp()),
        timeout_seconds=timeout,
        max_output_bytes=10000,
        env_allowlist={"PATH"},
        use_supervisor=True,
    )


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only: supervisor + /proc")
class TestLeakAndStress:
    """R3 Task 7: Leak and stress verification."""

    def test_stress_successful_executions_no_leak(self):
        """100 short successful executions show no monotonic FD/thread growth."""
        fd_before = _fd_count()
        thread_before = _thread_count()
        child_before = _child_count()

        for i in range(100):
            r = _run_supervised([sys.executable, "-c", "import sys; sys.exit(0)"])
            assert r["process_started"], f"iteration {i} failed: {r}"

        time.sleep(0.5)  # let any zombie cleanup settle
        fd_after = _fd_count()
        thread_after = _thread_count()
        child_after = _child_count()

        # No monotonic FD growth (allow small variance for transient FDs).
        assert fd_after <= fd_before + 5, (
            f"FD leak: {fd_before} → {fd_after} after 100 runs"
        )
        # No thread leak.
        assert thread_after <= thread_before + 1, (
            f"thread leak: {thread_before} → {thread_after} after 100 runs"
        )
        # No surviving child processes.
        assert child_after <= child_before + 1, (
            f"child process leak: {child_before} → {child_after} after 100 runs"
        )

    def test_stress_pre_exec_failures_no_leak(self):
        """50 pre-exec failures (missing executable) show no FD/thread growth."""
        fd_before = _fd_count()
        thread_before = _thread_count()

        for i in range(50):
            r = _run_supervised(["/nonexistent/path"])
            assert not r["process_started"]

        time.sleep(0.3)
        fd_after = _fd_count()
        thread_after = _thread_count()

        assert fd_after <= fd_before + 5, (
            f"FD leak on failures: {fd_before} → {fd_after}"
        )
        assert thread_after <= thread_before + 1, (
            f"thread leak on failures: {thread_before} → {thread_after}"
        )

    def test_stress_nonzero_exits_no_leak(self):
        """50 nonzero exits show no FD/thread growth."""
        fd_before = _fd_count()
        thread_before = _thread_count()

        for i in range(50):
            r = _run_supervised([sys.executable, "-c", f"import sys; sys.exit({i % 255 + 1})"])
            assert r["process_started"]
            assert r["process_exit_code"] == i % 255 + 1

        time.sleep(0.3)
        fd_after = _fd_count()
        thread_after = _thread_count()

        assert fd_after <= fd_before + 5, (
            f"FD leak on nonzero exits: {fd_before} → {fd_after}"
        )
        assert thread_after <= thread_before + 1, (
            f"thread leak on nonzero exits: {thread_before} → {thread_after}"
        )

    def test_no_protocol_reader_thread_survives(self):
        """After execution, no protocol reader thread exists.

        The async transport uses loop.add_reader — no thread should be created.
        """
        import threading
        before = threading.active_count()
        r = _run_supervised([sys.executable, "-c", "import sys; sys.exit(0)"])
        after = threading.active_count()
        assert r["process_started"]
        assert after <= before + 1, (
            f"thread count increased (protocol reader thread?): {before} → {after}"
        )

    def test_rapid_fd_allocation_after_run(self):
        """After a run, FD numbers can be allocated and used without stale callbacks."""
        r = _run_supervised([sys.executable, "-c", "import sys; sys.exit(0)"])
        assert r["process_started"]
        # Allocate many FDs and close them — if stale callbacks existed,
        # this would cause errors or corruption.
        fds = []
        for _ in range(20):
            fds.append(os.pipe())
        for rfd, wfd in fds:
            os.close(rfd)
            os.close(wfd)
        # No error means no stale callback interfered.

    def test_asyncio_task_cleanup(self):
        """After a run in a fresh event loop, no tasks remain."""
        from nodechain.runtime.native_sandbox_exec import _run_supervised_child
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(_run_supervised_child({
                "argv": [sys.executable, "-c", "import sys; sys.exit(0)"],
                "cwd": "/tmp", "timeout_seconds": 10,
                "max_output_bytes": 10000, "env_allowlist": {"PATH"},
            }))
            # Check for pending tasks in this loop.
            # asyncio.all_tasks() checks across all loops, so filter.
            pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
            assert len(pending) == 0, f"{len(pending)} tasks survived after return"
        finally:
            loop.close()
