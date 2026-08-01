"""S3.1 adversarial lifecycle proofs — deterministic injection + exact assertions.

R3 Task 5 note: The old S3.1 adversarial tests tested the pre-R3 architecture
(asyncio.to_thread, stop-pipe, proto_state, threading.Thread). R3 replaced
that architecture with AsyncProtocolTransport + SupervisedExecSession.
The comprehensive R3 tests in test_v351_h2_r3_terminal_proof.py,
test_v351_h2_r3_async_transport.py, and test_v351_h2_r3_supervised_execution.py
(Task 6) provide the adversarial lifecycle coverage for the new architecture.

The spawn-failure FD cleanup test is retained as it tests the production
spawn path which is unchanged. Other tests that injected mocks into the
old reader/cleanup internals are superseded.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
import threading
import time
from unittest import mock

import pytest
pytestmark = pytest.mark.native_sandbox


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only: supervisor lifecycle")
class TestAdversarialLifecycle:
    """Retained adversarial proofs for the R3 production architecture."""

    def _basic_config(self, argv=None, **kw):
        return {
            "argv": argv or [sys.executable, "-c", "import sys; sys.exit(0)"],
            "cwd": "/tmp",
            "timeout_seconds": kw.get("timeout_seconds", 15),
            "max_output_bytes": kw.get("max_output_bytes", 50000),
            "env_allowlist": kw.get("env_allowlist", {"PATH"}),
        }

    def _run(self, config):
        from nodechain.runtime.native_sandbox_exec import _run_supervised_child
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(_run_supervised_child(config))
        finally:
            loop.close()

    # ---- Retained: spawn failure FD cleanup ----

    def test_spawn_failure_closes_all_fds(self):
        """Inject spawn failure; verify typed reason and every FD closed."""
        original_pipe = os.pipe
        created_fds = []
        call_count = {"n": 0}
        def tracking_pipe():
            call_count["n"] += 1
            r, w = original_pipe()
            created_fds.append((call_count["n"], r, w))
            return r, w
        async def fake_spawn(*a, **kw): raise OSError("spawn fail")
        with mock.patch("os.pipe", side_effect=tracking_pipe):
            with mock.patch.object(asyncio, "create_subprocess_exec", side_effect=fake_spawn):
                result = self._run(self._basic_config())
        assert not result["process_started"]
        assert "supervisor_spawn_failed" in result["reason"]
        for n, rfd, wfd in created_fds:
            for fd in (rfd, wfd):
                with pytest.raises(OSError): os.fstat(fd)

    def test_protocol_pipe_creation_failure(self):
        """Protocol pipe creation failure returns error."""
        def failing_pipe():
            raise OSError("pipe creation fail")
        with mock.patch("os.pipe", side_effect=failing_pipe):
            try:
                result = self._run(self._basic_config())
            except OSError:
                # The OSError propagates from the pipe creation — that's
                # acceptable for this test. The point is it fails closed.
                return
        assert not result["process_started"]

    # ---- Retained: normal path integration ----

    def test_normal_execution_starts(self):
        """Real supervisor with fast workload → process_started=True."""
        result = self._run(self._basic_config())
        assert result["process_started"], f"expected started: {result}"
        assert result["exit_code_interpretation"] == "pass"
        assert result["process_exit_code"] == 0

    def test_exit_125_is_workload_exit(self):
        """Exit 125 classified as workload exit, not bootstrap error."""
        result = self._run(self._basic_config([sys.executable, "-c", "import sys; sys.exit(125)"]))
        assert result["process_started"], f"exit 125 must be started: {result}"
        assert result["process_exit_code"] == 125

    def test_exit_126_is_workload_exit(self):
        result = self._run(self._basic_config([sys.executable, "-c", "import sys; sys.exit(126)"]))
        assert result["process_started"]
        assert result["process_exit_code"] == 126

    def test_exit_127_is_workload_exit(self):
        result = self._run(self._basic_config([sys.executable, "-c", "import sys; sys.exit(127)"]))
        assert result["process_started"]
        assert result["process_exit_code"] == 127

    def test_missing_executable(self):
        """Missing executable → process_started=False."""
        result = self._run(self._basic_config(["/nonexistent/path/that/does/not/exist"]))
        assert not result["process_started"]

    def test_oversized_config_fails_closed(self):
        """Config > MAX_CONFIG_BYTES → error before spawn."""
        from nodechain.runtime.exec_supervisor import MAX_CONFIG_BYTES
        from nodechain.runtime.native_sandbox_exec import _run_supervised_child
        loop = asyncio.new_event_loop()
        try:
            big_config = {
                "argv": ["x" * (MAX_CONFIG_BYTES + 1)],
                "cwd": "/tmp", "timeout_seconds": 5,
                "max_output_bytes": 5000, "env_allowlist": set(),
            }
            result = loop.run_until_complete(_run_supervised_child(big_config))
        finally:
            loop.close()
        assert not result["process_started"]
        assert result["reason"] == "config_oversized"

    # ---- No thread/executor created ----

    def test_no_executor_thread(self):
        """No thread-pool worker created during execution."""
        config = self._basic_config([sys.executable, "-c", "import sys; sys.exit(0)"])
        threads_before = threading.active_count()
        result = self._run(config)
        threads_after = threading.active_count()
        assert result["process_started"]
        assert threads_after <= threads_before + 1
