"""T2: Workload FD forwarding, /dev/null, and workload_cwd end-to-end tests.

All tests are Linux-only: the path requires unshare, PID namespaces, ptrace,
and /proc. They exercise the full Parent → S → I → B1 → B2 → exec(workload)
topology with real workload processes.

T2 objectives proven:
  1. Workload receives exactly the intended payload on FD 0.
  2. When no payload is supplied, FD 0 is deterministically /dev/null.
  3. workload_cwd is applied in the final execution process before exec.
"""

from __future__ import annotations

import os
import sys
import tempfile
from unittest import mock as _mock

import pytest

linux_only = pytest.mark.skipif(
    sys.platform != "linux",
    reason="Linux-only: requires unshare, PID namespaces, ptrace, /proc",
)


def _run_supervised(
    argv=None,
    workload_stdin=None,
    workload_cwd=None,
    timeout_seconds=10,
    max_output_bytes=50_000,
):
    """Invoke run_supervised_argv_async with minimal env."""
    import asyncio
    from nodechain.runtime.supervised_argv import run_supervised_argv_async

    async def _go():
        return await run_supervised_argv_async(
            argv=argv,
            workload_stdin=workload_stdin,
            workload_cwd=workload_cwd,
            supervisor_env={"PATH": "/usr/bin:/bin"},
            workload_env={},
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )

    return asyncio.run(_go())


# ---------------------------------------------------------------------------
# End-to-end tests
# ---------------------------------------------------------------------------

@linux_only
@pytest.mark.native_sandbox
class TestT2PayloadForwarding:
    """Objective 1: workload receives the intended payload on FD 0."""

    def test_payload_delivered_on_fd0(self):
        """Workload reads stdin and echoes it. Exact payload match + completed."""
        payload = b"hello-t2-payload"
        workload = [
            sys.executable, "-c",
            "import sys; data = sys.stdin.buffer.read(); "
            "sys.stdout.buffer.write(data); sys.stdout.flush()",
        ]
        result = _run_supervised(
            argv=workload, workload_stdin=payload,
        )
        assert result["process_started"], f"process not started: {result}"
        assert result["stdout"] == payload.decode(), (
            f"payload mismatch: stdout={result['stdout']!r}"
        )
        assert result["sandbox_metadata"].get("workload_input_status") == "completed", (
            result["sandbox_metadata"]
        )

    def test_large_payload_delivered_on_fd0(self):
        """128 KiB payload (> pipe buffer) delivered exactly + completed."""
        payload = b"A" * 131072  # 128 KiB
        workload = [
            sys.executable, "-c",
            "import sys; data = sys.stdin.buffer.read(); "
            "sys.stdout.write(str(len(data))); sys.stdout.flush()",
        ]
        result = _run_supervised(
            argv=workload, workload_stdin=payload,
        )
        assert result["process_started"]
        assert result["stdout"] == "131072", f"byte count: {result['stdout']}"
        assert result["sandbox_metadata"].get("workload_input_status") == "completed"


@linux_only
@pytest.mark.native_sandbox
class TestT2DevNull:
    """Objective 2: no payload → FD 0 is /dev/null."""

    def test_no_payload_fd0_is_devnull(self):
        """Workload verifies FD 0 is a char device with same st_rdev as
        /dev/null, then reads → immediate EOF."""
        workload = [
            sys.executable, "-c",
            "import os, sys\n"
            "# Verify FD 0 is a character device.\n"
            "st0 = os.fstat(0)\n"
            "if not hasattr(st0, 'st_rdev'):\n"
            "    sys.stdout.write('NO_STAT_RDEV'); sys.exit(1)\n"
            "# Compare with /dev/null.\n"
            "st_null = os.stat('/dev/null')\n"
            "if st0.st_rdev != st_null.st_rdev:\n"
            "    sys.stdout.write(f'RDEV_MISMATCH:{st0.st_rdev}:{st_null.st_rdev}'); sys.exit(1)\n"
            "# Read → immediate EOF.\n"
            "data = os.read(0, 4096)\n"
            "if data != b'':\n"
            "    sys.stdout.write(f'NOT_EOF:{data!r}'); sys.exit(1)\n"
            "sys.stdout.write('DEVNULL_OK'); sys.stdout.flush()\n",
        ]
        result = _run_supervised(argv=workload, workload_stdin=None)
        assert result["process_started"], f"not started: {result}"
        assert result["stdout"] == "DEVNULL_OK", f"stdout: {result['stdout']!r}"
        assert result["process_exit_code"] == 0


@linux_only
@pytest.mark.native_sandbox
class TestT2WorkloadCwd:
    """Objective 3: workload_cwd applied before exec."""

    def test_workload_cwd_applied(self, tmp_path):
        """Workload writes realpath(getcwd()). Assert matches temp dir."""
        workload = [
            sys.executable, "-c",
            "import os, sys; "
            "sys.stdout.write(os.path.realpath(os.getcwd())); sys.stdout.flush()",
        ]
        result = _run_supervised(
            argv=workload, workload_cwd=str(tmp_path),
        )
        assert result["process_started"]
        assert os.path.realpath(result["stdout"]) == os.path.realpath(str(tmp_path)), (
            f"cwd mismatch: got {result['stdout']!r}, expected {str(tmp_path)!r}"
        )

    def test_default_cwd_inherited(self):
        """No workload_cwd → workload inherits the test process's cwd."""
        workload = [
            sys.executable, "-c",
            "import os, sys; "
            "sys.stdout.write(os.path.realpath(os.getcwd())); sys.stdout.flush()",
        ]
        result = _run_supervised(argv=workload, workload_cwd=None)
        assert result["process_started"]
        # The supervisor inherits the parent's cwd. The test process runs
        # from the repo root, so the workload should see the same cwd.
        expected = os.path.realpath(os.getcwd())
        assert os.path.realpath(result["stdout"]) == expected, (
            f"default cwd mismatch: got {result['stdout']!r}, expected {expected!r}"
        )


# ---------------------------------------------------------------------------
# Adversarial tests
# ---------------------------------------------------------------------------

@linux_only
@pytest.mark.native_sandbox
class TestT2NonexistentCwd:
    """workload_cwd pointing to a nonexistent path fails before exec_confirmed."""

    def test_nonexistent_cwd_fails_before_exec(self):
        workload = [
            sys.executable, "-c", "import sys; sys.exit(0)",
        ]
        result = _run_supervised(
            argv=workload, workload_cwd="/nonexistent/path/that/does/not/exist",
        )
        assert result["process_started"] is False, (
            f"process should not start with bad cwd: {result}"
        )
        assert not any(
            event.get("event_type") == "code_execution_completed"
            for event in result["sandbox_event_log"]
        ), "unexpected completed event"
        # The failure should surface in stderr or reason.
        assert (
            "bootstrap" in result.get("reason", "")
            or "metadata" in result.get("reason", "")
            or "cleanup" in result.get("reason", "")
        ), f"unexpected reason: {result['reason']}"
        assert (
            "chdir failed" in result.get("stderr", "")
            or "workload_cwd" in result.get("stderr", "")
        ), f"stderr should mention chdir failure: {result['stderr']!r}"
        # Direct bootstrap stage authority: the failure must be at the
        # workload_cwd stage (not a generic bootstrap failure).
        assert "workload_cwd" in result.get("stderr", "") or \
               "chdir" in result.get("stderr", ""), (
            f"failure must identify the workload_cwd stage: {result['stderr']!r}"
        )


@linux_only
@pytest.mark.native_sandbox
class TestT2ConflictingFdAuthority:
    """Config JSON must not contain workload_input_rfd — CLI is sole authority."""

    def test_conflicting_fd_authority_rejected(self):
        """Invoke supervisor_process_main with a crafted config containing
        workload_input_rfd → rejected."""
        import json
        import struct
        from nodechain.runtime.exec_supervisor import supervisor_process_main

        # Create a protocol pipe and a workload-input pipe.
        proto_r, proto_w = os.pipe()
        wl_r, wl_w = os.pipe()

        # Craft config with both has_workload_input and workload_input_rfd.
        config = {
            "workload_argv": ["/bin/true"],
            "workload_env": {},
            "has_workload_input": True,
            "workload_input_rfd": wl_r,  # conflicting authority
        }
        config_bytes = json.dumps(config).encode("utf-8")
        framed = struct.pack(">I", len(config_bytes)) + config_bytes

        # Write config to a pipe that will be FD 0 for the supervisor.
        cfg_r, cfg_w = os.pipe()
        os.write(cfg_w, framed)
        os.close(cfg_w)

        # dup2 cfg_r onto FD 0.
        saved_0 = os.dup(0)
        os.dup2(cfg_r, 0)
        os.close(cfg_r)

        try:
            rc = supervisor_process_main(proto_w, wl_r)
            assert rc != 0, "supervisor should reject conflicting FD authority"
        finally:
            os.dup2(saved_0, 0)
            os.close(saved_0)
            for fd in (proto_r, proto_w, wl_r, wl_w):
                try:
                    os.close(fd)
                except OSError:
                    pass


@linux_only
@pytest.mark.native_sandbox
class TestT2EarlyReaderExit:
    """Large payload + workload exits without reading → EPIPE classification."""

    def test_early_reader_exit_epipe_classified(self):
        """Send 1 MiB payload; workload closes FD 0 and exits without reading.
        Assert T1 public classification: epipe → epipe_tolerated."""
        from nodechain.runtime.supervised_argv import MAX_WORKLOAD_INPUT_BYTES

        payload = b"X" * MAX_WORKLOAD_INPUT_BYTES
        workload = [
            sys.executable, "-c",
            "import os, time; os.close(0); time.sleep(0.25)",
        ]
        result = _run_supervised(
            argv=workload, workload_stdin=payload,
            timeout_seconds=15,
        )
        metadata = result["sandbox_metadata"]
        assert metadata.get("workload_input_status") == "epipe", (
            f"expected epipe, got {metadata.get('workload_input_status')}"
        )
        assert metadata.get("workload_input_writer_signal") == "epipe_tolerated", (
            f"expected epipe_tolerated, got {metadata.get('workload_input_writer_signal')}"
        )
        assert "workload_input_delivery_error" not in metadata, (
            f"unexpected delivery error: {metadata}"
        )


# ---------------------------------------------------------------------------
# Handoff authority tests (checked-close primitives)
# ---------------------------------------------------------------------------

class TestT2HandoffPrimitive:
    """Tests for SupervisorPipeSet.close_workload_input_after_fork."""

    def test_checked_close_poisons_and_returns_true(self):
        """Successful close poisons the slot and returns True."""
        from nodechain.runtime.exec_supervisor import SupervisorPipeSet

        rfd, wfd = os.pipe()
        os.close(rfd)  # close read end so wfd is the only open one
        pipes = SupervisorPipeSet(workload_input_rfd=wfd)
        ok = pipes.close_workload_input_after_fork()
        assert ok is True
        assert pipes.workload_input_rfd is None
        # wfd is now closed.
        with pytest.raises(OSError):
            os.fstat(wfd)

    def test_checked_close_returns_false_on_failure(self):
        """Close failure returns False; slot still poisoned."""
        from nodechain.runtime.exec_supervisor import SupervisorPipeSet

        pipes = SupervisorPipeSet(workload_input_rfd=99999)  # invalid FD
        ok = pipes.close_workload_input_after_fork()
        assert ok is False
        assert pipes.workload_input_rfd is None  # still poisoned

    def test_checked_close_idempotent_on_none(self):
        """None slot returns True, no close attempted."""
        from nodechain.runtime.exec_supervisor import SupervisorPipeSet

        pipes = SupervisorPipeSet()
        ok = pipes.close_workload_input_after_fork()
        assert ok is True
        assert pipes.workload_input_rfd is None


# ---------------------------------------------------------------------------
# S/I handoff fault-injection tests — REAL behavioral injection
# ---------------------------------------------------------------------------

@linux_only
@pytest.mark.native_sandbox
class TestT2SHandoffInjection:
    """Real S handoff behavioral injection: mock the fork boundary, fail the
    workload-FD close after I fork, stub containment, capture protocol records."""

    def test_s_close_failure_denies_release_and_forces_cleanup_failed(self):
        """S fork succeeds → S tries to close workload_input_fd → fails.
        Assert: release token NOT written, containment runs, cleanup_succeeded=False."""
        import json
        import struct
        import nodechain.runtime.exec_supervisor as _es
        from unittest import mock as _mock

        proto_r, proto_w = os.pipe()
        wl_r, wl_w = os.pipe()

        # Build minimal config for the launcher.
        config = {
            "workload_argv": ["/bin/true"],
            "workload_env": {},
            "has_workload_input": True,
        }

        captured_records = []
        original_emit = _es.emit_protocol

        def _capturing_emit(fd, record):
            import json as _j
            captured_records.append(_j.loads(_j.dumps(record)))
            # Write to the pipe so read_bounded_protocol can consume it.
            original_emit(fd, record)

        contain_called = {"v": False}
        original_close = os.close

        def _injected_close(fd):
            if fd == wl_r:
                raise OSError(9, "injected close failure")
            return original_close(fd)

        with _mock.patch("nodechain.runtime.pid_namespace_topology.unshare_pid_namespace"), \
             _mock.patch("nodechain.runtime.pid_namespace_topology.build_topology_proof", return_value=(999, 888)), \
             _mock.patch.object(_es, "_contain_init_child", side_effect=lambda pid: (contain_called.__setitem__("v", True), True)[-1]), \
             _mock.patch.object(_es, "emit_protocol", side_effect=_capturing_emit), \
             _mock.patch("os.fork", return_value=12345), \
             _mock.patch("os.close", side_effect=_injected_close), \
             _mock.patch.object(_es, "_write_bounded_fd") as _mock_write_gate, \
             _mock.patch("os.kill"), \
             _mock.patch("os.waitpid", return_value=(12345, 0)):
            rc = _es.launch_pid_namespace_supervisor(config, proto_w, wl_r)

        assert rc == 1, f"expected rc=1, got {rc}"
        assert contain_called["v"] is True, "containment not called"
        # Release token was never written — _contain_and_fail closed gate_w
        # without the token, denying release. _write_bounded_fd is also used
        # by emit_protocol (protocol records), so we inspect the calls to
        # verify none wrote the release token.
        for call in _mock_write_gate.call_args_list:
            args, kwargs = call
            if len(args) >= 2:
                data = args[1]
                if isinstance(data, (bytes, bytearray)) and b"RELEASE" in data:
                    pytest.fail(f"release token written after handoff failure: {call}")
        cleanup_records = [r for r in captured_records if r.get("type") == "cleanup_completed"]
        assert len(cleanup_records) == 1, f"expected 1 cleanup record, got {len(cleanup_records)}"
        assert cleanup_records[0]["cleanup_succeeded"] is False
        fail_records = [r for r in captured_records if r.get("type") == "supervisor_failed"]
        assert len(fail_records) >= 1
        assert fail_records[-1]["reason"] == "cleanup_failed", (
            f"expected cleanup_failed, got {fail_records[-1]['reason']}"
        )

        for fd in (proto_r, wl_w):
            try: original_close(fd)
            except OSError: pass


@linux_only
@pytest.mark.native_sandbox
class TestT2IHandoffInjection:
    """Real I handoff behavioral injection: mock the B1 fork, fail the
    checked close, stub cleanup, capture protocol records."""

    def test_i_close_failure_no_bootstrap_spawned_and_cleanup_failed(self):
        """I forks B1 → checked close fails → no bootstrap_spawned emitted,
        cleanup_succeeded=False."""
        import nodechain.runtime.exec_supervisor as _es
        from unittest import mock as _mock

        proto_r, proto_w = os.pipe()

        config = {
            "workload_argv": ["/bin/true"],
            "workload_env": {},
            "workload_cwd": None,
            "expected_pidns_dev": 999,
            "expected_pidns_ino": 888,
        }

        captured_records = []
        original_emit = _es.emit_protocol

        def _capturing_emit(fd, record):
            import json as _j
            captured_records.append(_j.loads(_j.dumps(record)))

        # Create a SupervisorPipeSet with a workload FD that will fail to close.
        wl_r, wl_w = os.pipe()
        os.close(wl_r)  # close read so wl_w is valid
        pipes = _es.SupervisorPipeSet(
            protocol_wfd=proto_w,
            workload_input_rfd=wl_w,
        )

        with _mock.patch.object(_es, "emit_protocol", side_effect=_capturing_emit), \
             _mock.patch.object(_es.SupervisorPipeSet, "close_workload_input_after_fork", return_value=False) as _mock_handoff, \
             _mock.patch.object(_es, "_cleanup_namespace", return_value=True) as _mock_cleanup, \
             _mock.patch("os.fork", return_value=12345) as _mock_fork, \
             _mock.patch.object(_es, "write_bounded_config"):
            rc = _es.supervisor_main(config, proto_w, wl_w)

        assert rc == 1
        _mock_fork.assert_called_once()
        _mock_handoff.assert_called_once()
        _mock_cleanup.assert_called_once()
        record_types = [r["type"] for r in captured_records]
        assert "bootstrap_spawned" not in record_types
        assert record_types == ["supervisor_started", "supervisor_failed", "cleanup_completed"], (
            f"unexpected record sequence: {record_types}"
        )
        assert captured_records[1]["reason"] == "workload_input_handoff_close_failed"
        assert captured_records[2]["cleanup_succeeded"] is False


class TestT2PreforkCloseFailureReason:
    """Verify pre-fork close failure produces caller-visible cleanup_failed."""

    def test_prefork_helper_emits_cleanup_failed_on_close_failure(self):
        """The _prefork_fail_and_cleanup helper must replace the reason with
        'cleanup_failed' when wl_fd_closed is False."""
        import ast
        from pathlib import Path

        src = Path("src/nodechain/runtime/exec_supervisor.py").read_text()
        tree = ast.parse(src)

        launcher = next(
            n for n in tree.body
            if isinstance(n, ast.FunctionDef)
            and n.name == "launch_pid_namespace_supervisor"
        )

        # Find the _prefork_fail_and_cleanup nested function.
        helper = None
        for node in launcher.body:
            if isinstance(node, ast.FunctionDef) and node.name == "_prefork_fail_and_cleanup":
                helper = node
                break
        assert helper is not None, "_prefork_fail_and_cleanup not found"

        helper_src = ast.get_source_segment(src, helper)
        assert "effective_reason" in helper_src, (
            "must compute effective_reason for cleanup_failed masking"
        )
        assert '"cleanup_failed"' in helper_src, (
            "must replace reason with cleanup_failed when close fails"
        )


# ---------------------------------------------------------------------------
# FD-reuse adversarial test — real reuse scenario
# ---------------------------------------------------------------------------

@linux_only
@pytest.mark.native_sandbox
class TestT2FdReuseAdversarial:
    """Real FD-reuse test: substitute a launcher that closes the FD, reuses
    the number, raises, and prove the reused FD survives."""

    def test_recycled_fd_survives_caller_unwind(self):
        """The fake launcher closes FD N, opens a resource until N is reused,
        then raises. After supervisor_process_main unwinds, fstat(N) must
        succeed and identify the new resource."""
        import json
        import struct
        from nodechain.runtime.exec_supervisor import supervisor_process_main

        proto_r, proto_w = os.pipe()
        wl_r, wl_w = os.pipe()

        config = {"workload_argv": ["/bin/true"], "workload_env": {},
                  "has_workload_input": True}
        config_bytes = json.dumps(config).encode("utf-8")
        framed = struct.pack(">I", len(config_bytes)) + config_bytes

        cfg_r, cfg_w = os.pipe()
        os.write(cfg_w, framed)
        os.close(cfg_w)

        saved_0 = os.dup(0)
        os.dup2(cfg_r, 0)
        os.close(cfg_r)

        original_close = os.close

        reused_fd_holder = {"fd": None}

        def _reusing_launcher(config, protocol_fd, workload_input_fd):
            # Close the transferred FD.
            original_close(workload_input_fd)
            # Reopen until the same number is reused.
            for _ in range(100):
                fd = os.open("/dev/null", os.O_RDONLY)
                if fd == workload_input_fd:
                    reused_fd_holder["fd"] = fd
                    break
                else:
                    original_close(fd)
            # Raise unexpectedly.
            raise RuntimeError("injected launcher failure")

        runtime_error_raised = {"v": False}

        try:
            with _mock.patch(
                "nodechain.runtime.exec_supervisor.launch_pid_namespace_supervisor",
                side_effect=_reusing_launcher,
            ):
                try:
                    supervisor_process_main(proto_w, wl_r)
                except RuntimeError:
                    runtime_error_raised["v"] = True

            assert runtime_error_raised["v"] is True, "RuntimeError did not propagate"
            assert reused_fd_holder["fd"] == wl_r, (
                f"FD reuse did not occur: expected {wl_r}, got {reused_fd_holder['fd']}"
            )
            st = os.fstat(wl_r)
            assert st is not None, "recycled FD closed by caller — FD reuse hazard"
        finally:
            os.dup2(saved_0, 0)
            os.close(saved_0)
            if reused_fd_holder["fd"] is not None:
                try: original_close(reused_fd_holder["fd"])
                except OSError: pass
            for fd in (proto_r, proto_w, wl_w):
                try: original_close(fd)
                except OSError: pass

    def test_pretransfer_invalid_protocol_closes_workload_fd_once(self):
        """Invalid protocol_fd (< 3) → early return. Assert exactly one close."""
        from nodechain.runtime.exec_supervisor import supervisor_process_main

        wl_r, wl_w = os.pipe()
        original_close = os.close
        close_log = []

        def _logging_close(fd, *a, **kw):
            close_log.append(fd)
            return original_close(fd, *a, **kw)

        try:
            with _mock.patch("os.close", side_effect=_logging_close):
                rc = supervisor_process_main(0, wl_r)
            assert rc != 0
            wl_closes = [fd for fd in close_log if fd == wl_r]
            assert len(wl_closes) == 1, (
                f"wl_r closed {len(wl_closes)} times — must be exactly 1"
            )
        finally:
            try: original_close(wl_w)
            except OSError: pass

    @pytest.mark.parametrize("scenario", [
        "bad_protocol_fd",
        "conflicting_authority",
        "fd_mismatch",
        "readonly_protocol",
        "config_read_failure",
    ])
    def test_pretransfer_returns_close_workload_fd_once(self, scenario):
        """Each pre-transfer return path closes the workload FD exactly once."""
        import json
        import struct
        from nodechain.runtime.exec_supervisor import supervisor_process_main

        proto_r, proto_w = os.pipe()
        wl_r, wl_w = os.pipe()

        original_close = os.close
        close_log = []

        def _logging_close(fd, *a, **kw):
            close_log.append(fd)
            return original_close(fd, *a, **kw)

        if scenario == "bad_protocol_fd":
            config = {"workload_argv": ["/bin/true"], "workload_env": {},
                      "has_workload_input": True}
            proto_to_use = 1
        elif scenario == "conflicting_authority":
            config = {"workload_argv": ["/bin/true"], "workload_env": {},
                      "has_workload_input": True,
                      "workload_input_rfd": wl_r}
            proto_to_use = proto_w
        elif scenario == "fd_mismatch":
            config = {"workload_argv": ["/bin/true"], "workload_env": {}}
            proto_to_use = proto_w
        elif scenario == "readonly_protocol":
            config = {"workload_argv": ["/bin/true"], "workload_env": {},
                      "has_workload_input": True}
            proto_to_use = proto_r  # read end is read-only
        elif scenario == "config_read_failure":
            config = {"workload_argv": ["/bin/true"], "workload_env": {},
                      "has_workload_input": True}
            proto_to_use = proto_w
        else:
            return

        if scenario == "config_read_failure":
            cfg_r, cfg_w = os.pipe()
            os.write(cfg_w, b"\xff\xff\xff\xff garbage not valid json")
            os.close(cfg_w)
        else:
            config_bytes = json.dumps(config).encode("utf-8")
            framed = struct.pack(">I", len(config_bytes)) + config_bytes
            cfg_r, cfg_w = os.pipe()
            os.write(cfg_w, framed)
            os.close(cfg_w)

        saved_0 = os.dup(0)
        os.dup2(cfg_r, 0)
        os.close(cfg_r)

        try:
            with _mock.patch("os.close", side_effect=_logging_close):
                rc = supervisor_process_main(proto_to_use, wl_r)
            assert rc == 1, f"expected rc=1 for {scenario}, got {rc}"
            wl_closes = [fd for fd in close_log if fd == wl_r]
            assert len(wl_closes) == 1, (
                f"wl_r closed {len(wl_closes)} times for {scenario} — must be 1"
            )
        finally:
            os.dup2(saved_0, 0)
            os.close(saved_0)
            for fd in (proto_r, proto_w, wl_w):
                try: original_close(fd)
                except OSError: pass


# ---------------------------------------------------------------------------
# Bootstrap metadata stage authority for workload_cwd
# ---------------------------------------------------------------------------

@linux_only
@pytest.mark.native_sandbox
class TestT2BootstrapCwdStage:
    """Verify the bootstrap emits bootstrap_failed with stage=workload_cwd
    when chdir fails. Uses a low-level approach: run the full API and
    inspect the metadata/protocol records for the stage."""

    def test_nonexistent_cwd_emits_exact_bootstrap_stage(self):
        """Run the generated bootstrap script directly with a config pipe
        and metadata pipe. Assert the exact metadata record sequence:
        bootstrap_started → bootstrap_failed(stage='workload_cwd').

        The cwd failure occurs before namespace verification, so no
        ptrace/PID-namespace prerequisites are needed."""
        import json as _json
        import struct
        import subprocess
        from nodechain.runtime.exec_supervisor import _build_bootstrap_script

        # Create config + metadata pipes.
        cfg_r, cfg_w = os.pipe()
        meta_r, meta_w = os.pipe()

        # Build config with a nonexistent workload_cwd and no workload-input FD
        # (so the /dev/null path is taken, which succeeds before cwd).
        bootstrap_config = {
            "metadata_fd": meta_w,
            "workload_argv": ["/bin/true"],
            "workload_env": {},
            "workload_input_rfd": None,
            "workload_cwd": "/nonexistent/path/that/does/not/exist",
            "expected_pidns_dev": None,
            "expected_pidns_ino": None,
        }
        config_bytes = _json.dumps(bootstrap_config).encode("utf-8")
        framed = struct.pack(">I", len(config_bytes)) + config_bytes
        os.write(cfg_w, framed)
        os.close(cfg_w)

        # Mark meta_w inheritable across exec.
        os.set_inheritable(meta_w, True)

        # Generate and run the bootstrap script directly.
        script = _build_bootstrap_script()
        proc = subprocess.Popen(
            [sys.executable, "-c", script],
            stdin=cfg_r,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(meta_w,),
            close_fds=True,
        )
        os.close(cfg_r)
        os.close(meta_w)

        stdout, stderr = proc.communicate(timeout=10)

        # Read metadata records from the pipe.
        meta_data = b""
        try:
            while True:
                chunk = os.read(meta_r, 65536)
                if not chunk:
                    break
                meta_data += chunk
        except OSError:
            pass
        os.close(meta_r)

        # Parse NDJSON records.
        records = []
        for line in meta_data.decode("utf-8", errors="replace").strip().split("\n"):
            line = line.strip()
            if line:
                try:
                    records.append(_json.loads(line))
                except _json.JSONDecodeError:
                    pass

        # Assert the exact record sequence.
        assert len(records) >= 2, (
            f"expected at least 2 metadata records, got {len(records)}: {records}"
        )
        assert records[0]["type"] == "bootstrap_started", (
            f"first record should be bootstrap_started: {records[0]}"
        )
        assert records[1]["type"] == "bootstrap_failed", (
            f"second record should be bootstrap_failed: {records[1]}"
        )
        assert records[1].get("stage") == "workload_cwd", (
            f"stage should be workload_cwd: {records[1]}"
        )
        assert records[1].get("reason", "").startswith("chdir_failed"), (
            f"reason should start with chdir_failed: {records[1]}"
        )
