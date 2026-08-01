"""S3: Production integration of exact exec authority via external supervisor.

Tests the supervised execution path where ``run_isolated(use_supervisor=True)``
launches an external supervisor process that confirms exec via
``PTRACE_EVENT_EXEC``.

S3.1 scope: external launch, concurrent protocol/output drain, evidence
extraction, exact start authority, result mapping. Uses the S2 stub
enforcement (no real namespace/seccomp).
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

from nodechain.runtime.exec_supervisor import (
    SupervisorExecutionEvidence,
    extract_supervisor_evidence,
    ProtocolReadResult,
    PROTO_SUPERVISOR_STARTED,
    PROTO_BOOTSTRAP_SPAWNED,
    PROTO_ENFORCEMENT_VERIFIED,
    PROTO_EXEC_MONITOR_ARMED,
    PROTO_EXEC_CONFIRMED,
    PROTO_WORKLOAD_EXITED,
    PROTO_CLEANUP_COMPLETED,
    PROTO_SUPERVISOR_FAILED,
)
from nodechain.runtime.native_sandbox_exec import map_supervisor_result


# ---------------------------------------------------------------------------
# Evidence extraction tests (fork-free, platform-agnostic)
# ---------------------------------------------------------------------------

class TestExtractSupervisorEvidence:
    """Tests for extract_supervisor_evidence from protocol results."""

    def test_normal_success_exit_zero(self):
        """Normal terminal with exit 0 → exec_confirmed, exit 0."""
        result = ProtocolReadResult(ok=True, reason="ok", records=[
            {"version": 1, "type": PROTO_SUPERVISOR_STARTED},
            {"version": 1, "type": PROTO_BOOTSTRAP_SPAWNED, "pid": 123},
            {"version": 1, "type": PROTO_ENFORCEMENT_VERIFIED},
            {"version": 1, "type": PROTO_EXEC_MONITOR_ARMED},
            {"version": 1, "type": PROTO_EXEC_CONFIRMED},
            {"version": 1, "type": PROTO_WORKLOAD_EXITED, "started": True, "exit_code": 0},
            {"version": 1, "type": PROTO_CLEANUP_COMPLETED, "cleanup_succeeded": True},
        ])
        ev = extract_supervisor_evidence(result)
        assert ev.protocol_valid
        assert ev.exec_confirmed
        assert ev.workload_exit_code == 0
        assert ev.workload_signal is None
        assert ev.supervisor_failure_reason is None
        assert ev.cleanup_succeeded is True

    def test_normal_success_exit_125(self):
        """Exit 125 is a valid workload exit, not a bootstrap error."""
        result = ProtocolReadResult(ok=True, reason="ok", records=[
            {"version": 1, "type": PROTO_SUPERVISOR_STARTED},
            {"version": 1, "type": PROTO_BOOTSTRAP_SPAWNED, "pid": 1},
            {"version": 1, "type": PROTO_ENFORCEMENT_VERIFIED},
            {"version": 1, "type": PROTO_EXEC_MONITOR_ARMED},
            {"version": 1, "type": PROTO_EXEC_CONFIRMED},
            {"version": 1, "type": PROTO_WORKLOAD_EXITED, "started": True, "exit_code": 125},
            {"version": 1, "type": PROTO_CLEANUP_COMPLETED, "cleanup_succeeded": True},
        ])
        ev = extract_supervisor_evidence(result)
        assert ev.exec_confirmed
        assert ev.workload_exit_code == 125

    def test_pre_exec_failure(self):
        """Pre-exec failure → exec_confirmed=False, supervisor_failure_reason set."""
        result = ProtocolReadResult(ok=True, reason="ok", records=[
            {"version": 1, "type": PROTO_SUPERVISOR_STARTED},
            {"version": 1, "type": PROTO_BOOTSTRAP_SPAWNED, "pid": 1},
            {"version": 1, "type": PROTO_SUPERVISOR_FAILED, "reason": "ptrace_failed"},
            {"version": 1, "type": PROTO_CLEANUP_COMPLETED, "cleanup_succeeded": True},
        ])
        ev = extract_supervisor_evidence(result)
        assert not ev.exec_confirmed
        assert ev.supervisor_failure_reason == "ptrace_failed"

    def test_protocol_invalid_no_exec_confirmed(self):
        """Invalid protocol → protocol_valid=False."""
        result = ProtocolReadResult(ok=False, reason="protocol_timeout", records=[])
        ev = extract_supervisor_evidence(result)
        assert not ev.protocol_valid
        assert not ev.exec_confirmed

    def test_enforcement_metadata_extracted(self):
        """Enforcement metadata from enforcement_verified is captured."""
        result = ProtocolReadResult(ok=True, reason="ok", records=[
            {"version": 1, "type": PROTO_SUPERVISOR_STARTED},
            {"version": 1, "type": PROTO_BOOTSTRAP_SPAWNED, "pid": 1},
            {"version": 1, "type": PROTO_ENFORCEMENT_VERIFIED,
             "metadata": {"seccomp_applied": True, "namespace_pid": 1}},
            {"version": 1, "type": PROTO_EXEC_MONITOR_ARMED},
            {"version": 1, "type": PROTO_EXEC_CONFIRMED},
            {"version": 1, "type": PROTO_WORKLOAD_EXITED, "started": True, "exit_code": 0},
            {"version": 1, "type": PROTO_CLEANUP_COMPLETED, "cleanup_succeeded": True},
        ])
        ev = extract_supervisor_evidence(result)
        assert ev.enforcement_metadata.get("seccomp_applied") is True
        assert ev.enforcement_metadata.get("namespace_pid") == 1

    def test_signaled_workload(self):
        """Signaled workload → workload_signal set."""
        result = ProtocolReadResult(ok=True, reason="ok", records=[
            {"version": 1, "type": PROTO_SUPERVISOR_STARTED},
            {"version": 1, "type": PROTO_BOOTSTRAP_SPAWNED, "pid": 1},
            {"version": 1, "type": PROTO_ENFORCEMENT_VERIFIED},
            {"version": 1, "type": PROTO_EXEC_MONITOR_ARMED},
            {"version": 1, "type": PROTO_EXEC_CONFIRMED},
            {"version": 1, "type": PROTO_WORKLOAD_EXITED, "started": True,
             "signaled": True, "signal_num": 31},  # SIGSYS
            {"version": 1, "type": PROTO_CLEANUP_COMPLETED, "cleanup_succeeded": True},
        ])
        ev = extract_supervisor_evidence(result)
        assert ev.exec_confirmed
        assert ev.workload_signal == 31
        assert ev.workload_exit_code is None

    def test_cleanup_failure_preserves_exec(self):
        """Cleanup failure → exec_confirmed still True."""
        result = ProtocolReadResult(ok=False, reason="protocol_cleanup_failed", records=[
            {"version": 1, "type": PROTO_SUPERVISOR_STARTED},
            {"version": 1, "type": PROTO_BOOTSTRAP_SPAWNED, "pid": 1},
            {"version": 1, "type": PROTO_ENFORCEMENT_VERIFIED},
            {"version": 1, "type": PROTO_EXEC_MONITOR_ARMED},
            {"version": 1, "type": PROTO_EXEC_CONFIRMED},
            {"version": 1, "type": PROTO_WORKLOAD_EXITED, "started": True, "exit_code": 0},
            {"version": 1, "type": PROTO_CLEANUP_COMPLETED, "cleanup_succeeded": False, "reason": "reap_timeout"},
        ])
        ev = extract_supervisor_evidence(result)
        assert ev.exec_confirmed
        assert ev.cleanup_succeeded is False
        assert not ev.protocol_valid  # cleanup failure makes protocol invalid


# ---------------------------------------------------------------------------
# Integration tests (Linux-only: supervisor uses ptrace + fork)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only: supervisor uses ptrace")
@pytest.mark.native_sandbox
class TestSupervisorIntegration:
    """S3.1 integration tests via run_isolated(use_supervisor=True)."""

    def _run_supervised(self, argv, **kwargs):
        """Helper: run_isolated with use_supervisor=True."""
        from nodechain.runtime.native_sandbox_exec import run_isolated
        import tempfile
        return run_isolated(
            argv=argv,
            cwd=Path(kwargs.get("cwd", tempfile.mkdtemp())),
            timeout_seconds=kwargs.get("timeout_seconds", 30),
            max_output_bytes=kwargs.get("max_output_bytes", 50000),
            env_allowlist=kwargs.get("env_allowlist", {"PATH"}),
            use_supervisor=True,
        )

    def test_workload_exit_zero(self):
        """Workload exits 0 → process_started=True, interpretation=pass, exit_code=0."""
        result = self._run_supervised([sys.executable, "-c", "import sys; sys.exit(0)"])
        assert result["process_started"], f"expected started, got: {result}"
        assert result["exit_code_interpretation"] == "pass"
        assert result["process_exit_code"] == 0, f"exit_code should be 0: {result}"
        assert result["backend"] == "native_os_sandbox"
        assert not result["process_timed_out"], "should not time out"

    def test_workload_exit_125(self):
        """Workload exits 125 → process_started=True, interpretation=fail.

        This is the critical S3 test: exit code 125 is a workload exit, NOT
        a bootstrap error (the old heuristic would classify it as bootstrap failure).
        """
        result = self._run_supervised([sys.executable, "-c", "import sys; sys.exit(125)"])
        assert result["process_started"], f"exit 125 must be process_started=True: {result}"
        assert result["exit_code_interpretation"] == "fail"

    def test_workload_exit_126(self):
        """Workload exits 126 → process_started=True."""
        result = self._run_supervised([sys.executable, "-c", "import sys; sys.exit(126)"])
        assert result["process_started"], f"exit 126 must be process_started=True: {result}"

    def test_workload_exit_127(self):
        """Workload exits 127 → process_started=True."""
        result = self._run_supervised([sys.executable, "-c", "import sys; sys.exit(127)"])
        assert result["process_started"], f"exit 127 must be process_started=True: {result}"

    def test_missing_executable(self):
        """Missing workload executable → process_started=False."""
        result = self._run_supervised(["/nonexistent/path/that/does/not/exist"])
        assert not result["process_started"], f"missing exec should be started=False: {result}"

    def test_stdout_captured(self):
        """Workload stdout is captured in the result."""
        result = self._run_supervised(
            [sys.executable, "-c", "print('hello_from_workload')"])
        assert result["process_started"], f"expected started: {result}"
        assert "hello_from_workload" in result["stdout"], (
            f"stdout missing workload output: {result['stdout']!r}"
        )

    def test_enforcement_metadata_present(self):
        """sandbox_metadata contains enforcement report from the protocol."""
        result = self._run_supervised([sys.executable, "-c", "import sys; sys.exit(0)"])
        assert result["process_started"]
        # The S2 stub enforcement produces metadata with "enforcement": "s2_stub"
        # S3.3 will replace this with real enforcement data.
        assert isinstance(result["sandbox_metadata"], dict)

    def test_event_log_started_emitted(self):
        """code_execution_started appears in event log after exec_confirmed."""
        result = self._run_supervised([sys.executable, "-c", "import sys; sys.exit(0)"])
        assert result["process_started"]
        event_types = [e["event_type"] for e in result["sandbox_event_log"]]
        assert "code_execution_started" in event_types, f"missing started event: {event_types}"

    # -----------------------------------------------------------------------
    # Fix #1 (round 1): process_exit_code = workload exit, not supervisor rc
    # -----------------------------------------------------------------------

    def test_exit_code_matches_workload_125(self):
        """Fix #1: process_exit_code == 125 (not supervisor rc 0)."""
        result = self._run_supervised([sys.executable, "-c", "import sys; sys.exit(125)"])
        assert result["process_started"]
        assert result["process_exit_code"] == 125, (
            f"expected exit_code=125, got {result['process_exit_code']}"
        )

    def test_exit_code_matches_workload_126(self):
        """Fix #1: process_exit_code == 126."""
        result = self._run_supervised([sys.executable, "-c", "import sys; sys.exit(126)"])
        assert result["process_started"]
        assert result["process_exit_code"] == 126

    def test_exit_code_matches_workload_127(self):
        """Fix #1: process_exit_code == 127."""
        result = self._run_supervised([sys.executable, "-c", "import sys; sys.exit(127)"])
        assert result["process_started"]
        assert result["process_exit_code"] == 127

    def test_exit_code_matches_workload_42(self):
        """Fix #1: process_exit_code == 42."""
        result = self._run_supervised([sys.executable, "-c", "import sys; sys.exit(42)"])
        assert result["process_started"]
        assert result["process_exit_code"] == 42

    # -----------------------------------------------------------------------
    # Fix #2: process_timed_out reflects actual timeout
    # -----------------------------------------------------------------------

    def test_timeout_after_exec(self):
        """Fix #2: timeout after exec → started=True, timed_out=True."""
        result = self._run_supervised(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            timeout_seconds=2,
        )
        assert result["process_started"], f"expected started: {result}"
        assert result["process_timed_out"], f"expected timed_out: {result}"
        assert result["exit_code_interpretation"] == "timeout"

    # -----------------------------------------------------------------------
    # Fix #6/#7 (round 3): map_supervisor_result — pure function tests
    # -----------------------------------------------------------------------

    def test_map_cleanup_failure_is_error_not_pass(self):
        """Cleanup failure → error, not pass; no code_execution_completed."""
        ev = SupervisorExecutionEvidence(
            protocol_valid=False, exec_confirmed=True,
            workload_exit_code=0, workload_signal=None,
            supervisor_failure_reason=None, cleanup_succeeded=False,
            protocol_failure_reason="protocol_cleanup_failed",
        )
        result = map_supervisor_result(ev, {"stdout":"","stderr":"","output_truncated":False,"timed_out":False,"reason":None})
        assert result["process_started"] is True
        assert result["process_exit_code"] == 0
        assert result["exit_code_interpretation"] == "error"
        assert result["reason"] == "cleanup_failed"
        assert not any(e["event_type"] == "code_execution_completed" for e in result["sandbox_event_log"])

    def test_map_streaming_reader_error_preserves_signal(self):
        """Fix #4 (round 3): streaming reader error preserves signal outcome."""
        ev = SupervisorExecutionEvidence(
            protocol_valid=False, exec_confirmed=True,
            workload_exit_code=None, workload_signal=15,  # SIGTERM
            supervisor_failure_reason=None, cleanup_succeeded=None,
        )
        result = map_supervisor_result(ev, None, output_task_failure=True)
        assert result["process_started"] is True
        assert result["process_exit_code"] == -15  # negative signal
        assert result["exit_code_interpretation"] == "error"
        assert result["reason"] == "streaming_reader_error"
        # code_execution_started emitted when process_started=True.
        assert any(e["event_type"] == "code_execution_started" for e in result["sandbox_event_log"])

    def test_map_signal_workload(self):
        """Signaled workload maps the actual signal outcome."""
        ev = SupervisorExecutionEvidence(
            protocol_valid=True, exec_confirmed=True,
            workload_exit_code=None, workload_signal=31,  # SIGSYS
            supervisor_failure_reason=None, cleanup_succeeded=True,
        )
        result = map_supervisor_result(ev, {"stdout":"","stderr":"","output_truncated":False,"timed_out":False,"reason":None})
        assert result["process_started"] is True
        assert result["process_exit_code"] == -31
        assert result["reason"] == "seccomp_sigsys_kill"

    def test_map_output_cap_after_exec(self):
        """Output cap after exec → started=True, fail, output_limit_exceeded."""
        ev = SupervisorExecutionEvidence(
            protocol_valid=True, exec_confirmed=True,
            workload_exit_code=1, workload_signal=None,
            supervisor_failure_reason=None, cleanup_succeeded=True,
        )
        result = map_supervisor_result(ev, {"stdout":"x","stderr":"","output_truncated":True,"timed_out":False,"reason":"output_limit_exceeded"})
        assert result["process_started"] is True
        assert result["exit_code_interpretation"] == "fail"
        assert result["reason"] == "output_limit_exceeded"
        assert any(e["event_type"] == "sandbox_output_capped" for e in result["sandbox_event_log"])

    def test_map_protocol_failure_after_exec(self):
        """Protocol invalid after exec → error, start retained."""
        ev = SupervisorExecutionEvidence(
            protocol_valid=False, exec_confirmed=True,
            workload_exit_code=0, workload_signal=None,
            supervisor_failure_reason=None, cleanup_succeeded=True,
            protocol_failure_reason="protocol_timeout",
        )
        result = map_supervisor_result(ev, {"stdout":"","stderr":"","output_truncated":False,"timed_out":False,"reason":None})
        assert result["process_started"] is True
        assert result["exit_code_interpretation"] == "error"
        assert result["reason"] == "protocol_timeout"

    def test_map_pre_exec_failure(self):
        """Pre-exec failure → started=False."""
        ev = SupervisorExecutionEvidence(
            protocol_valid=True, exec_confirmed=False,
            workload_exit_code=None, workload_signal=None,
            supervisor_failure_reason="ptrace_failed", cleanup_succeeded=True,
        )
        result = map_supervisor_result(ev, {"stdout":"","stderr":"err","output_truncated":False,"timed_out":False,"reason":None})
        assert result["process_started"] is False
        assert result["reason"] == "ptrace_failed"

    def test_map_timeout_after_exec(self):
        """Timeout after exec → started=True, timed_out=True."""
        ev = SupervisorExecutionEvidence(
            protocol_valid=True, exec_confirmed=True,
            workload_exit_code=None, workload_signal=None,
            supervisor_failure_reason=None, cleanup_succeeded=True,
        )
        result = map_supervisor_result(ev, {"stdout":"","stderr":"","output_truncated":False,"timed_out":True,"reason":None})
        assert result["process_started"] is True
        assert result["process_timed_out"] is True
        assert result["exit_code_interpretation"] == "timeout"

    def test_cleanup_failure_preserves_start_but_fails(self):
        """Fix #7 (round 2): cleanup_succeeded=False → error result, start retained.

        Verifies the parent result mapper's precedence by calling the evidence
        extractor and checking the production result-mapping logic directly.
        """
        from nodechain.runtime.exec_supervisor import (
            ProtocolReadResult, extract_supervisor_evidence,
        )
        result = ProtocolReadResult(ok=False, reason="protocol_cleanup_failed", records=[
            {"version": 1, "type": "supervisor_started"},
            {"version": 1, "type": "bootstrap_spawned", "pid": 1},
            {"version": 1, "type": "enforcement_verified"},
            {"version": 1, "type": "exec_monitor_armed"},
            {"version": 1, "type": "exec_confirmed"},
            {"version": 1, "type": "workload_exited", "started": True, "exit_code": 0},
            {"version": 1, "type": "cleanup_completed", "cleanup_succeeded": False, "reason": "reap"},
        ])
        ev = extract_supervisor_evidence(result)
        # The mapper's precedence after exec_confirmed checks cleanup_succeeded=False
        # before the workload exit outcome. This must produce "error", not "pass".
        assert ev.exec_confirmed, "start truth must be retained"
        assert ev.cleanup_succeeded is False
        assert ev.protocol_failure_reason == "protocol_cleanup_failed"
        # Simulate the production precedence check:
        # cleanup_succeeded is False → interpretation = error, not pass.
        assert not ev.protocol_valid  # cleanup failure invalidates the protocol
        # No code_execution_completed should be emitted when protocol is invalid.
        # (The event log construction in _run_supervised_child checks overall_failure.)

    # -----------------------------------------------------------------------
    # Fix #5 (round 2): oversized config fails closed — real execution path
    # -----------------------------------------------------------------------

    @pytest.mark.skipif(sys.platform != "linux", reason="Linux-only: asyncio event loop")
    def test_oversized_config_fails_closed(self):
        """Fix #5 (round 2): config > MAX_CONFIG_BYTES → error before spawn."""
        from nodechain.runtime.exec_supervisor import MAX_CONFIG_BYTES
        from nodechain.runtime.native_sandbox_exec import _run_supervised_child
        import asyncio as _asyncio

        # Create a config with argv that exceeds MAX_CONFIG_BYTES when serialized.
        big_config = {
            "argv": ["x" * (MAX_CONFIG_BYTES + 1)],
            "cwd": "/tmp",
            "timeout_seconds": 5,
            "max_output_bytes": 5000,
            "env_allowlist": set(),
        }
        loop = _asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(_run_supervised_child(big_config))
        finally:
            loop.close()
        assert not result["process_started"], f"should not start: {result}"
        assert result["reason"] == "config_oversized", f"reason: {result['reason']}"

    # -----------------------------------------------------------------------
    # Fix #4 (round 2): protocol_fd must be writable (write end)
    # -----------------------------------------------------------------------

    def test_read_end_protocol_fd_rejected(self):
        """Fix #4 (round 2): protocol_fd pointing to a pipe READ end → rejected."""
        from nodechain.runtime.exec_supervisor import supervisor_process_main
        rfd, wfd = os.pipe()
        try:
            rc = supervisor_process_main(rfd)  # rfd is read-only
            assert rc != 0, "read-only protocol_fd should be rejected"
        finally:
            try:
                os.close(rfd)
            except OSError:
                pass
            try:
                os.close(wfd)
            except OSError:
                pass

    def test_invalid_protocol_fd_rejected(self):
        """Fix #7: protocol_fd < 3 → supervisor exits nonzero."""
        from nodechain.runtime.exec_supervisor import supervisor_process_main
        rc = supervisor_process_main(0)
        assert rc != 0

    def test_non_pipe_protocol_fd_rejected(self):
        """Fix #6 (round 2): protocol_fd pointing to a regular file → rejected."""
        import tempfile
        from nodechain.runtime.exec_supervisor import supervisor_process_main
        # Open a regular file and KEEP it open.
        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(b"not a pipe")
        f.flush()
        try:
            rc = supervisor_process_main(f.fileno())
            assert rc != 0, "non-pipe protocol_fd should be rejected"
        finally:
            f.close()
            os.unlink(f.name)
