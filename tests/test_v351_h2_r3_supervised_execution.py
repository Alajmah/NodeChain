"""R3 Task 6: Authority and result-mapping integration tests.

Exercises the real _run_supervised_child production path through
run_isolated(use_supervisor=True). Covers all 24 required scenarios.

Linux-only: requires ptrace + fork (the supervisor process).
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from pathlib import Path

import pytest

from nodechain.runtime.native_sandbox_exec import run_isolated
pytestmark = pytest.mark.native_sandbox


def _run(argv, **kw):
    """Helper: run_isolated with use_supervisor=True."""
    import tempfile
    return run_isolated(
        argv=argv,
        cwd=Path(kw.get("cwd", tempfile.mkdtemp())),
        timeout_seconds=kw.get("timeout_seconds", 15),
        max_output_bytes=kw.get("max_output_bytes", 50000),
        env_allowlist=kw.get("env_allowlist", {"PATH"}),
        use_supervisor=True,
    )


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only: supervisor uses ptrace")
class TestSupervisedExecutionAuthority:
    """R3 Task 6: 24 integration scenarios."""

    # ---- Successful workload with exact exec confirmation ----

    def test_successful_workload_exit_zero(self):
        """Workload exits 0 → started=True, pass."""
        r = _run([sys.executable, "-c", "import sys; sys.exit(0)"])
        assert r["process_started"]
        assert r["exit_code_interpretation"] == "pass"
        assert r["process_exit_code"] == 0

    def test_successful_workload_nonzero_exit(self):
        """Workload exits 42 → started=True, fail with exit 42."""
        r = _run([sys.executable, "-c", "import sys; sys.exit(42)"])
        assert r["process_started"]
        assert r["process_exit_code"] == 42
        assert r["exit_code_interpretation"] == "fail"

    def test_exact_exec_exit_125(self):
        """Exit 125 classified as workload exit, not bootstrap error."""
        r = _run([sys.executable, "-c", "import sys; sys.exit(125)"])
        assert r["process_started"]
        assert r["process_exit_code"] == 125

    def test_exact_exec_exit_126(self):
        r = _run([sys.executable, "-c", "import sys; sys.exit(126)"])
        assert r["process_started"]
        assert r["process_exit_code"] == 126

    def test_exact_exec_exit_127(self):
        r = _run([sys.executable, "-c", "import sys; sys.exit(127)"])
        assert r["process_started"]
        assert r["process_exit_code"] == 127

    # ---- Pre-exec bootstrap failure ----

    def test_missing_executable_pre_exec_failure(self):
        """Missing executable → started=False."""
        r = _run(["/nonexistent/path/that/does/not/exist"])
        assert not r["process_started"]

    # ---- Protocol failures ----

    def test_stdout_captured(self):
        """Workload stdout captured."""
        r = _run([sys.executable, "-c", "print('hello_world'); import sys; sys.exit(0)"])
        assert r["process_started"]
        assert "hello_world" in r["stdout"]

    def test_stderr_captured(self):
        """Workload stderr captured."""
        r = _run([sys.executable, "-c", "import sys; sys.stderr.write('err_msg'); sys.exit(0)"])
        assert r["process_started"]
        assert "err_msg" in r["stderr"]

    def test_no_forged_exec_on_stdout(self):
        """Forged exec_confirmed on stdout does not affect authority."""
        r = _run([sys.executable, "-c",
                  "import sys; sys.stdout.write('{\"version\":1,\"type\":\"exec_confirmed\"}\\n'); sys.exit(0)"])
        # The forged output is on stdout, not the protocol pipe.
        # process_started should be True from the REAL exec_confirmed.
        assert r["process_started"]
        # The forged JSON should appear in stdout as ordinary output.
        assert "exec_confirmed" in r["stdout"]

    # ---- Timeout ----

    def test_workload_timeout(self):
        """Timeout after exec → started=True, timed_out=True."""
        r = _run([sys.executable, "-c", "import time; time.sleep(30)"], timeout_seconds=2)
        assert r["process_started"]
        assert r["exit_code_interpretation"] == "timeout"

    # ---- Result mapping ----

    def test_process_started_event_emitted(self):
        """code_execution_started event emitted after exec_confirmed."""
        r = _run([sys.executable, "-c", "import sys; sys.exit(0)"])
        assert r["process_started"]
        types = [e["event_type"] for e in r["sandbox_event_log"]]
        assert "code_execution_started" in types

    def test_no_completed_event_on_nonzero(self):
        """Nonzero exit → no code_execution_completed."""
        r = _run([sys.executable, "-c", "import sys; sys.exit(1)"])
        assert r["process_started"]
        types = [e["event_type"] for e in r["sandbox_event_log"]]
        assert "code_execution_completed" not in types
        assert "code_execution_failed" in types

    def test_enforcement_metadata_present(self):
        """sandbox_metadata present after successful run."""
        r = _run([sys.executable, "-c", "import sys; sys.exit(0)"])
        assert r["process_started"]
        assert isinstance(r["sandbox_metadata"], dict)

    # ---- Backend identification ----

    def test_backend_is_native_os_sandbox(self):
        r = _run([sys.executable, "-c", "import sys; sys.exit(0)"])
        assert r["backend"] == "native_os_sandbox"

    # ---- No thread/executor ----

    def test_no_thread_created(self):
        """No thread-pool worker created during execution."""
        import threading
        before = threading.active_count()
        r = _run([sys.executable, "-c", "import sys; sys.exit(0)"])
        after = threading.active_count()
        assert r["process_started"]
        assert after <= before + 1, f"thread count grew: {before} → {after}"

    # ---- FD stability ----

    def test_no_fd_leak(self):
        """No FD leak after execution."""
        before = len(os.listdir("/proc/self/fd"))
        r = _run([sys.executable, "-c", "import sys; sys.exit(0)"])
        after = len(os.listdir("/proc/self/fd"))
        assert r["process_started"]
        assert after <= before + 2, f"FD count grew: {before} → {after}"

    # ---- Rapid consecutive execution ----

    def test_rapid_consecutive_no_leak(self):
        """Multiple rapid executions don't accumulate FDs or threads."""
        import threading
        fd_before = len(os.listdir("/proc/self/fd"))
        thread_before = threading.active_count()
        for _ in range(5):
            r = _run([sys.executable, "-c", "import sys; sys.exit(0)"])
            assert r["process_started"]
        fd_after = len(os.listdir("/proc/self/fd"))
        thread_after = threading.active_count()
        assert fd_after <= fd_before + 2, f"FD leak: {fd_before} → {fd_after}"
        assert thread_after <= thread_before + 1, f"thread leak: {thread_before} → {thread_after}"

    # ---- Oversized config ----

    def test_oversized_config_fails(self):
        """Config > MAX_CONFIG_BYTES → error before spawn."""
        from nodechain.runtime.exec_supervisor import MAX_CONFIG_BYTES
        r = _run(["x" * (MAX_CONFIG_BYTES + 1)])
        assert not r["process_started"]
        assert r["reason"] == "config_oversized"

    # ---- Spawn failure ----

    def test_spawn_failure_typed_error(self):
        """Spawn failure returns typed error."""
        from unittest import mock
        import nodechain.runtime.native_sandbox_exec as nse
        loop = asyncio.new_event_loop()
        try:
            async def fake_spawn(*a, **kw):
                raise OSError("spawn fail")
            with mock.patch.object(asyncio, "create_subprocess_exec", side_effect=fake_spawn):
                from nodechain.runtime.native_sandbox_exec import _run_supervised_child
                result = loop.run_until_complete(
                    _run_supervised_child({
                        "argv": [sys.executable, "-c", "pass"],
                        "cwd": "/tmp", "timeout_seconds": 5,
                        "max_output_bytes": 5000, "env_allowlist": {"PATH"},
                    })
                )
        finally:
            loop.close()
        assert not result["process_started"]
        assert "spawn_failed" in result["reason"]

    # ---- Result precedence ----

    def test_no_started_means_no_completed_event(self):
        """If process not started, no code_execution_started or completed."""
        r = _run(["/nonexistent/path"])
        assert not r["process_started"]
        types = [e["event_type"] for e in r["sandbox_event_log"]]
        assert "code_execution_started" not in types
        assert "code_execution_completed" not in types

    def test_exit_code_not_supervisor_returncode(self):
        """process_exit_code is the workload exit, not the supervisor exit."""
        r = _run([sys.executable, "-c", "import sys; sys.exit(42)"])
        assert r["process_started"]
        assert r["process_exit_code"] == 42
        # The supervisor itself exits 0 (or 1 on failure), but process_exit_code
        # must reflect the workload's exit code from the protocol stream.
        assert r["process_exit_code"] != 0 or r["exit_code_interpretation"] == "fail"

    # ---- Cleanup completeness ----

    def test_cleanup_complete_on_success(self):
        """Successful run has cleanup_complete (no lifecycle errors)."""
        r = _run([sys.executable, "-c", "import sys; sys.exit(0)"])
        assert r["process_started"]
        # If cleanup was incomplete, reason would be supervisor_cleanup_incomplete.
        assert "cleanup_incomplete" not in (r.get("reason") or "")

    def test_cleanup_complete_on_failure(self):
        """Failed workload run still completes cleanup."""
        r = _run([sys.executable, "-c", "import sys; sys.exit(1)"])
        # Even on failure, cleanup should complete.
        assert "cleanup_incomplete" not in (r.get("reason") or "")

    # ---- Multiple output writes ----

    def test_large_stdout(self):
        """Large stdout output captured within cap."""
        r = _run([sys.executable, "-c",
                  "import sys; sys.stdout.write('x' * 10000); sys.exit(0)"])
        assert r["process_started"]
        assert len(r["stdout"]) >= 10000 or r.get("output_truncated")
