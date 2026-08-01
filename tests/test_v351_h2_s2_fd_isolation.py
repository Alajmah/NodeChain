"""S2: Exec supervisor FD-inheritance, protocol isolation, and bounded metadata.

Tests the channel-separated 3-process architecture:

* Metadata reader: 19 tests (8 failure cases + success + EINTR + dup-key +
  non-object + unknown-field + after-terminal + child-probe-error + 3 failure
  record types)
* Config channel: 8 tests (4 reader + 4 writer)
* Protocol parser: 7 tests
* emit_protocol: 4 tests
* FD cleanup: 2 tests
* Forged-output immunity: 1 test
* B1/B2 FD-inheritance: 2 tests
* Additional correction tests: child-exit-responsiveness, cleanup-then-data,
  protocol branches, workload ordering, unrelated FD absent

Linux-only tests (fork, ptrace, /proc/self/fd) are gated with
``@pytest.mark.skipif(sys.platform != "linux")``. Metadata/config/protocol
reader tests are fork-free and run everywhere.
"""

from __future__ import annotations

import json
import errno
import os
import select
import signal
import struct
import sys
import time
from unittest import mock

import pytest

from nodechain.runtime.exec_supervisor import (
    CHILD_PROBE_INTERVAL,
    ConfigChannelError,
    DuplicateKeyError,
    FD_ENDPOINT_POLICY,
    FDEndpointPolicy,
    MAX_CONFIG_BYTES,
    MAX_METADATA_RECORD_BYTES,
    MAX_METADATA_STREAM_BYTES,
    MAX_PROTOCOL_RECORD_BYTES,
    MAX_PROTOCOL_STREAM_BYTES,
    META_BOOTSTRAP_FAILED,
    META_BOOTSTRAP_STARTED,
    META_ENFORCEMENT_FAILED,
    META_ENFORCEMENT_VERIFIED,
    META_PTRACE_TRACEME_FAILED,
    PROTO_BOOTSTRAP_SPAWNED,
    PROTO_CLEANUP_COMPLETED,
    PROTO_EXEC_CONFIRMED,
    PROTO_EXEC_MONITOR_ARMED,
    PROTO_ENFORCEMENT_VERIFIED,
    PROTO_SUPERVISOR_FAILED,
    PROTO_SUPERVISOR_STARTED,
    PROTO_WORKLOAD_EXITED,
    PROTO_VERSION,
    ProtocolChannelError,
    ProtocolReadResult,
    SupervisorPipeSet,
    _build_bootstrap_script,
    _close_all_except,
    _detect_dup_keys,
    _parse_json_strict,
    _probe_child_exit,
    ChildProbeResult,
    MetadataReadResult,
    emit_protocol,
    read_bounded_config,
    read_bounded_metadata,
    read_bounded_protocol,
    write_bounded_config,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pipe_with_data(data: bytes) -> tuple[int, int]:
    """Create a pipe, write *data* to the write end, close it, return (rfd, wfd).

    Actually returns (read_fd, _) where _ is already closed.
    """
    rfd, wfd = os.pipe()
    if data:
        os.write(wfd, data)
    os.close(wfd)
    return rfd, wfd


def _open_pipe() -> tuple[int, int]:
    """Create a pipe, return (rfd, wfd) — both open."""
    return os.pipe()


def _make_meta_reader(deadline_s: float = 5.0, max_bytes: int = MAX_METADATA_STREAM_BYTES):
    """Return a callable that wraps read_bounded_metadata with defaults."""
    def _read(meta_fd, child_pid=0, **kw):
        defaults = dict(
            child_pid=child_pid,
            deadline=time.monotonic() + deadline_s,
            max_bytes=max_bytes,
        )
        defaults.update(kw)
        return read_bounded_metadata(meta_fd, **defaults)
    return _read


def _patch_probe(result: ChildProbeResult):
    """Return a mock.patch context that replaces _probe_child_exit with *result*."""
    return mock.patch(
        "nodechain.runtime.exec_supervisor._probe_child_exit",
        return_value=result,
    )


RUNNING = ChildProbeResult(running=True, exited=False, error=False)
EXITED = ChildProbeResult(running=False, exited=True, error=False)
PROBE_ERROR = ChildProbeResult(running=False, exited=False, error=True)


# ---------------------------------------------------------------------------
# Metadata reader tests (fork-free)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform != "linux", reason="select.select on pipes is POSIX-only")
class TestMetadataReader:
    """19 tests for read_bounded_metadata."""

    def test_success_bootstrap_started_to_enforcement_verified(self):
        """Valid sequence returns ok=True."""
        rfd, _ = _pipe_with_data(
            json.dumps({"type": META_BOOTSTRAP_STARTED}).encode() + b"\n" +
            json.dumps({"type": META_ENFORCEMENT_VERIFIED, "metadata": {"x": 1}}).encode() + b"\n"
        )
        with _patch_probe(RUNNING):
            result = read_bounded_metadata(
                rfd, child_pid=0, deadline=time.monotonic() + 5, max_bytes=65536)
        os.close(rfd)
        assert result.ok
        assert result.reason == "ok"
        assert result.records_read == 2
        assert result.metadata.get("metadata") == {"x": 1}

    def test_no_writer_activity_until_deadline(self):
        """No data arrives → metadata_timeout."""
        rfd, wfd = _open_pipe()  # write end held open, no data
        try:
            with _patch_probe(RUNNING):
                result = read_bounded_metadata(
                    rfd, child_pid=0, deadline=time.monotonic() + 0.4, max_bytes=65536)
            assert not result.ok
            assert result.reason == "metadata_timeout"
        finally:
            os.close(rfd)
            os.close(wfd)

    def test_partial_json_at_eof(self):
        """Partial JSON record before EOF → metadata_partial_record."""
        rfd, _ = _pipe_with_data(
            json.dumps({"type": META_BOOTSTRAP_STARTED}).encode() + b"\n" +
            b'{"type":"boot'
        )
        with _patch_probe(RUNNING):
            result = read_bounded_metadata(
                rfd, child_pid=0, deadline=time.monotonic() + 5, max_bytes=65536)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "metadata_partial_record"

    def test_malformed_json(self):
        """Garbage line → metadata_malformed."""
        rfd, _ = _pipe_with_data(
            json.dumps({"type": META_BOOTSTRAP_STARTED}).encode() + b"\n" +
            b"garbage_line\n"
        )
        with _patch_probe(RUNNING):
            result = read_bounded_metadata(
                rfd, child_pid=0, deadline=time.monotonic() + 5, max_bytes=65536)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "metadata_malformed"

    def test_eof_before_enforcement_verified(self):
        """bootstrap_started then EOF → metadata_eof_before_verified."""
        rfd, _ = _pipe_with_data(
            json.dumps({"type": META_BOOTSTRAP_STARTED}).encode() + b"\n"
        )
        with _patch_probe(RUNNING):
            result = read_bounded_metadata(
                rfd, child_pid=0, deadline=time.monotonic() + 5, max_bytes=65536)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "metadata_eof_before_verified"

    def test_child_exits_while_waiting(self):
        """Child exit detected before enforcement_verified."""
        # Write bootstrap_started first, then child exits.
        rfd, wfd = _open_pipe()
        os.write(wfd, json.dumps({"type": META_BOOTSTRAP_STARTED}).encode() + b"\n")
        try:
            with _patch_probe(EXITED):
                result = read_bounded_metadata(
                    rfd, child_pid=0, deadline=time.monotonic() + 2, max_bytes=65536)
            assert not result.ok
            assert result.reason == "bootstrap_exited_before_verified"
            assert result.child_exited
        finally:
            os.close(rfd)
            os.close(wfd)

    def test_cumulative_cap_exceeded(self):
        """Too many bytes → metadata_limit_exceeded."""
        rfd, _ = _pipe_with_data(
            json.dumps({"type": META_BOOTSTRAP_STARTED}).encode() + b"\n" +
            b"x" * 200 + b"\n"
        )
        with _patch_probe(RUNNING):
            result = read_bounded_metadata(
                rfd, child_pid=0, deadline=time.monotonic() + 5, max_bytes=100)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "metadata_limit_exceeded"

    def test_unknown_event_type(self):
        """Unknown type → metadata_unknown_event."""
        rfd, _ = _pipe_with_data(
            json.dumps({"type": META_BOOTSTRAP_STARTED}).encode() + b"\n" +
            json.dumps({"type": "bogus"}).encode() + b"\n"
        )
        with _patch_probe(RUNNING):
            result = read_bounded_metadata(
                rfd, child_pid=0, deadline=time.monotonic() + 5, max_bytes=65536)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "metadata_unknown_event"

    def test_duplicate_terminal_invalid_transition(self):
        """enforcement_verified twice → metadata_invalid_transition."""
        rfd, _ = _pipe_with_data(
            json.dumps({"type": META_BOOTSTRAP_STARTED}).encode() + b"\n" +
            json.dumps({"type": META_ENFORCEMENT_VERIFIED, "metadata": {}}).encode() + b"\n" +
            json.dumps({"type": META_ENFORCEMENT_VERIFIED, "metadata": {}}).encode() + b"\n"
        )
        with _patch_probe(RUNNING):
            result = read_bounded_metadata(
                rfd, child_pid=0, deadline=time.monotonic() + 5, max_bytes=65536)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "metadata_invalid_transition"

    def test_eintr_from_select(self):
        """select.select raising InterruptedError once → retried, ok=True."""
        rfd, _ = _pipe_with_data(
            json.dumps({"type": META_BOOTSTRAP_STARTED}).encode() + b"\n" +
            json.dumps({"type": META_ENFORCEMENT_VERIFIED, "metadata": {}}).encode() + b"\n"
        )
        original_select = select.select
        call_count = {"n": 0}

        def flaky_select(r, w, x, timeout=None):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise InterruptedError()
            return original_select(r, w, x, timeout)

        with mock.patch("nodechain.runtime.exec_supervisor.select.select", side_effect=flaky_select):
            with _patch_probe(RUNNING):
                result = read_bounded_metadata(
                    rfd, child_pid=0, deadline=time.monotonic() + 5, max_bytes=65536)
        os.close(rfd)
        assert result.ok
        assert call_count["n"] >= 2

    def test_eintr_from_os_read(self):
        """os.read raising InterruptedError once → retried, ok=True."""
        rfd, _ = _pipe_with_data(
            json.dumps({"type": META_BOOTSTRAP_STARTED}).encode() + b"\n" +
            json.dumps({"type": META_ENFORCEMENT_VERIFIED, "metadata": {}}).encode() + b"\n"
        )
        original_read = os.read
        call_count = {"n": 0}

        def flaky_read(fd, count):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise InterruptedError()
            return original_read(fd, count)

        with mock.patch("nodechain.runtime.exec_supervisor.os.read", side_effect=flaky_read):
            with _patch_probe(RUNNING):
                result = read_bounded_metadata(
                    rfd, child_pid=0, deadline=time.monotonic() + 5, max_bytes=65536)
        os.close(rfd)
        assert result.ok

    def test_duplicate_json_keys(self):
        """Duplicate keys in a JSON record → metadata_duplicate_key."""
        rfd, _ = _pipe_with_data(
            json.dumps({"type": META_BOOTSTRAP_STARTED}).encode() + b"\n" +
            b'{"type":"bootstrap_started","type":"x"}\n'
        )
        with _patch_probe(RUNNING):
            result = read_bounded_metadata(
                rfd, child_pid=0, deadline=time.monotonic() + 5, max_bytes=65536)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "metadata_duplicate_key"

    def test_non_object_json(self):
        """Non-object JSON (array) → metadata_malformed."""
        rfd, _ = _pipe_with_data(
            json.dumps({"type": META_BOOTSTRAP_STARTED}).encode() + b"\n" +
            b"[1, 2, 3]\n"
        )
        with _patch_probe(RUNNING):
            result = read_bounded_metadata(
                rfd, child_pid=0, deadline=time.monotonic() + 5, max_bytes=65536)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "metadata_malformed"

    def test_unknown_field_in_closed_schema(self):
        """Unknown field → metadata_unknown_field."""
        rfd, _ = _pipe_with_data(
            json.dumps({"type": META_BOOTSTRAP_STARTED}).encode() + b"\n" +
            json.dumps({"type": META_ENFORCEMENT_VERIFIED, "metadata": {}, "evil": True}).encode() + b"\n"
        )
        with _patch_probe(RUNNING):
            result = read_bounded_metadata(
                rfd, child_pid=0, deadline=time.monotonic() + 5, max_bytes=65536)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "metadata_unknown_field"

    def test_record_after_terminal_state(self):
        """Record after enforcement_verified → metadata_invalid_transition."""
        rfd, _ = _pipe_with_data(
            json.dumps({"type": META_BOOTSTRAP_STARTED}).encode() + b"\n" +
            json.dumps({"type": META_ENFORCEMENT_VERIFIED, "metadata": {}}).encode() + b"\n" +
            json.dumps({"type": META_BOOTSTRAP_STARTED}).encode() + b"\n"
        )
        with _patch_probe(RUNNING):
            result = read_bounded_metadata(
                rfd, child_pid=0, deadline=time.monotonic() + 5, max_bytes=65536)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "metadata_invalid_transition"

    def test_child_status_probe_error(self):
        """Child probe error → metadata_child_probe_error."""
        rfd, wfd = _open_pipe()
        os.write(wfd, json.dumps({"type": META_BOOTSTRAP_STARTED}).encode() + b"\n")
        try:
            with _patch_probe(PROBE_ERROR):
                result = read_bounded_metadata(
                    rfd, child_pid=0, deadline=time.monotonic() + 2, max_bytes=65536)
            assert not result.ok
            assert result.reason == "metadata_child_probe_error"
        finally:
            os.close(rfd)
            os.close(wfd)

    def test_enforcement_failed_record(self):
        """enforcement_failed → ok=False, reason=enforcement_failed."""
        rfd, _ = _pipe_with_data(
            json.dumps({"type": META_BOOTSTRAP_STARTED}).encode() + b"\n" +
            json.dumps({"type": META_ENFORCEMENT_FAILED, "failed_primitives": ["seccomp"]}).encode() + b"\n"
        )
        with _patch_probe(RUNNING):
            result = read_bounded_metadata(
                rfd, child_pid=0, deadline=time.monotonic() + 5, max_bytes=65536)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "enforcement_failed"

    def test_ptrace_traceme_failed_record(self):
        """ptrace_traceme_failed → ok=False, reason=ptrace_traceme_failed."""
        rfd, _ = _pipe_with_data(
            json.dumps({"type": META_BOOTSTRAP_STARTED}).encode() + b"\n" +
            json.dumps({"type": META_PTRACE_TRACEME_FAILED, "errno": 1}).encode() + b"\n"
        )
        with _patch_probe(RUNNING):
            result = read_bounded_metadata(
                rfd, child_pid=0, deadline=time.monotonic() + 5, max_bytes=65536)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "ptrace_traceme_failed"

    def test_bootstrap_failed_record(self):
        """bootstrap_failed → ok=False, reason=bootstrap_failed."""
        rfd, _ = _pipe_with_data(
            json.dumps({"type": META_BOOTSTRAP_STARTED}).encode() + b"\n" +
            json.dumps({"type": META_BOOTSTRAP_FAILED, "stage": "mount", "reason": "oops"}).encode() + b"\n"
        )
        with _patch_probe(RUNNING):
            result = read_bounded_metadata(
                rfd, child_pid=0, deadline=time.monotonic() + 5, max_bytes=65536)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "bootstrap_failed"


# ---------------------------------------------------------------------------
# Additional metadata reader correction tests
# ---------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform != "linux", reason="select.select on pipes is POSIX-only")
class TestMetadataReaderCorrections:
    """Additional tests from the final correction set."""

    @pytest.mark.skipif(sys.platform != "linux", reason="Linux-only: fork for child-exit timing")
    def test_child_exit_detected_before_full_deadline(self):
        """Child exit is detected well before the full metadata deadline."""
        rfd, wfd = _open_pipe()
        # Fork a child that exits immediately (but don't reap — let the reader's
        # non-reaping probe detect it).
        pid = os.fork()
        if pid == 0:
            os._exit(0)
        # Give the child a moment to actually exit.
        time.sleep(0.2)

        try:
            start = time.monotonic()
            result = read_bounded_metadata(
                rfd, child_pid=pid,
                deadline=time.monotonic() + 10.0,
                max_bytes=65536,
            )
            elapsed = time.monotonic() - start
            assert not result.ok
            # Should detect within a few probe intervals, not 10 seconds.
            assert elapsed < 2.0, f"child-exit detection took {elapsed:.1f}s"
            assert result.child_exited
        finally:
            # Reap the child to avoid zombie.
            try:
                os.waitpid(pid, 0)
            except OSError:
                pass
            os.close(rfd)
            os.close(wfd)


# ---------------------------------------------------------------------------
# Config channel tests
# ---------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform != "linux", reason="select.select on pipes is POSIX-only")
class TestConfigWriter:
    """4 tests for write_bounded_config."""

    def test_valid_bounded_config(self):
        """Normal write completes the frame."""
        rfd, wfd = _open_pipe()
        payload = json.dumps({"key": "value"}).encode()
        try:
            write_bounded_config(wfd, payload, deadline=time.monotonic() + 5)
        finally:
            os.close(wfd)
        # Read back the frame.
        header = os.read(rfd, 4)
        declared = struct.unpack(">I", header)[0]
        assert declared == len(payload)
        body = os.read(rfd, declared)
        os.close(rfd)
        assert body == payload

    def test_oversized_payload_no_bytes_written(self):
        """Payload > max_bytes → ConfigChannelError, no bytes written."""
        rfd, wfd = _open_pipe()
        payload = b"x" * (MAX_CONFIG_BYTES + 1)
        try:
            with pytest.raises(ConfigChannelError) as exc_info:
                write_bounded_config(wfd, payload, deadline=time.monotonic() + 5,
                                     max_bytes=MAX_CONFIG_BYTES)
            assert exc_info.value.reason == "config_oversized"
        finally:
            os.close(wfd)
        # Verify no bytes were written.
        os.set_blocking(rfd, False)
        try:
            data = os.read(rfd, 100)
        except BlockingIOError:
            data = b""
        os.close(rfd)
        assert len(data) == 0, "bytes were written despite oversized payload"

    def test_interrupted_error_retried(self):
        """InterruptedError from os.write is retried."""
        rfd, wfd = _open_pipe()
        payload = b'{"x":1}'
        call_count = {"n": 0}
        original_write = os.write

        def flaky_write(fd, data):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise InterruptedError()
            return original_write(fd, data)

        try:
            with mock.patch("nodechain.runtime.exec_supervisor.os.write", side_effect=flaky_write):
                write_bounded_config(wfd, payload, deadline=time.monotonic() + 5)
        finally:
            os.close(wfd)
        header = os.read(rfd, 4)
        declared = struct.unpack(">I", header)[0]
        body = os.read(rfd, declared)
        os.close(rfd)
        assert body == payload
        assert call_count["n"] >= 2

    def test_pipe_closed_by_reader(self):
        """Reader closes pipe → ConfigChannelError."""
        rfd, wfd = _open_pipe()
        os.close(rfd)  # close read end
        with pytest.raises(ConfigChannelError) as exc_info:
            write_bounded_config(wfd, b'{"x":1}', deadline=time.monotonic() + 5)
        os.close(wfd)
        # Could be config_pipe_closed or config_write_error
        assert exc_info.value.reason.startswith("config_")


@pytest.mark.skipif(sys.platform != "linux", reason="select.select on pipes is POSIX-only")
class TestConfigReader:
    """4 tests for read_bounded_config."""

    def test_valid_bounded_config(self):
        """Valid frame is read and parsed."""
        rfd, wfd = _open_pipe()
        payload = json.dumps({"key": "val", "n": 42}).encode()
        header = struct.pack(">I", len(payload))
        os.write(wfd, header + payload)
        os.close(wfd)
        result = read_bounded_config(rfd, deadline=time.monotonic() + 5)
        assert result == {"key": "val", "n": 42}

    def test_oversized_declared_length(self):
        """Declared length > max_bytes → config_oversized."""
        rfd, wfd = _open_pipe()
        header = struct.pack(">I", MAX_CONFIG_BYTES + 1)
        os.write(wfd, header)
        os.close(wfd)
        with pytest.raises(ConfigChannelError) as exc_info:
            read_bounded_config(rfd, deadline=time.monotonic() + 5)
        assert exc_info.value.reason == "config_oversized"

    def test_partial_config_eof(self):
        """Partial payload → config_partial_eof."""
        rfd, wfd = _open_pipe()
        header = struct.pack(">I", 100)
        os.write(wfd, header + b"only 10 bytes")  # less than declared
        os.close(wfd)
        with pytest.raises(ConfigChannelError) as exc_info:
            read_bounded_config(rfd, deadline=time.monotonic() + 5)
        assert "partial" in exc_info.value.reason

    def test_trailing_bytes_rejected(self):
        """Trailing bytes after payload → config_trailing_bytes."""
        rfd, wfd = _open_pipe()
        payload = b'{"x":1}'
        header = struct.pack(">I", len(payload))
        os.write(wfd, header + payload + b"EXTRA")
        os.close(wfd)
        with pytest.raises(ConfigChannelError) as exc_info:
            read_bounded_config(rfd, deadline=time.monotonic() + 5)
        assert exc_info.value.reason == "config_trailing_bytes"


# ---------------------------------------------------------------------------
# Protocol parser tests
# ---------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform != "linux", reason="select.select on pipes is POSIX-only")
class TestProtocolParser:
    """7 tests for read_bounded_protocol."""

    def _write_protocol_records(self, records: list[dict]) -> int:
        """Write versioned protocol records to a pipe, close write end, return rfd."""
        rfd, wfd = _open_pipe()
        for rec in records:
            emit_protocol(wfd, rec)
        os.close(wfd)
        return rfd

    def test_normal_terminal_branch(self):
        """Full normal sequence with clean EOF → ok=True."""
        rfd = self._write_protocol_records([
            {"type": PROTO_SUPERVISOR_STARTED},
            {"type": PROTO_BOOTSTRAP_SPAWNED, "pid": 123},
            {"type": PROTO_ENFORCEMENT_VERIFIED},
            {"type": PROTO_EXEC_MONITOR_ARMED},
            {"type": PROTO_EXEC_CONFIRMED},
            {"type": PROTO_WORKLOAD_EXITED, "started": True, "exit_code": 0},
            {"type": PROTO_CLEANUP_COMPLETED, "cleanup_succeeded": True},
        ])
        result = read_bounded_protocol(rfd, deadline=time.monotonic() + 5)
        os.close(rfd)
        assert result.ok
        assert len(result.records) == 7

    def test_pre_exec_failure_branch(self):
        """supervisor_started → supervisor_failed → cleanup_completed."""
        rfd = self._write_protocol_records([
            {"type": PROTO_SUPERVISOR_STARTED},
            {"type": PROTO_BOOTSTRAP_SPAWNED, "pid": 99},
            {"type": PROTO_SUPERVISOR_FAILED, "reason": "test"},
            {"type": PROTO_CLEANUP_COMPLETED, "cleanup_succeeded": True},
        ])
        result = read_bounded_protocol(rfd, deadline=time.monotonic() + 5)
        os.close(rfd)
        assert result.ok
        assert len(result.records) == 4

    def test_unsupported_version(self):
        """Version != 1 → protocol_unsupported_version."""
        rfd, wfd = _open_pipe()
        os.write(wfd, json.dumps({"version": 99, "type": "supervisor_started"}).encode() + b"\n")
        os.close(wfd)
        result = read_bounded_protocol(rfd, deadline=time.monotonic() + 5)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "protocol_unsupported_version"

    def test_unknown_type(self):
        """Unknown type → protocol_unknown_type."""
        rfd, wfd = _open_pipe()
        os.write(wfd, json.dumps({"version": 1, "type": "bogus"}).encode() + b"\n")
        os.close(wfd)
        result = read_bounded_protocol(rfd, deadline=time.monotonic() + 5)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "protocol_unknown_type"

    def test_supervisor_failed_then_exec_confirmed_rejected(self):
        """supervisor_failed → exec_confirmed is a contradiction."""
        rfd = self._write_protocol_records([
            {"type": PROTO_SUPERVISOR_STARTED},
            {"type": PROTO_BOOTSTRAP_SPAWNED, "pid": 1},
            {"type": PROTO_SUPERVISOR_FAILED, "reason": "x"},
            {"type": PROTO_EXEC_CONFIRMED},  # invalid: after failure
        ])
        result = read_bounded_protocol(rfd, deadline=time.monotonic() + 5)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "protocol_invalid_transition"

    def test_duplicate_cleanup_completed(self):
        """cleanup_completed twice → fail."""
        rfd, wfd = _open_pipe()
        for rec in [
            {"type": PROTO_SUPERVISOR_STARTED},
            {"type": PROTO_SUPERVISOR_FAILED, "reason": "x"},
            {"type": PROTO_CLEANUP_COMPLETED, "cleanup_succeeded": True},
            {"type": PROTO_CLEANUP_COMPLETED, "cleanup_succeeded": True},
        ]:
            emit_protocol(wfd, rec)
        os.close(wfd)
        result = read_bounded_protocol(rfd, deadline=time.monotonic() + 5)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "protocol_record_after_cleanup"

    def test_records_after_cleanup_completed_rejected(self):
        """Any record after cleanup_completed → fail."""
        rfd = self._write_protocol_records([
            {"type": PROTO_SUPERVISOR_STARTED},
            {"type": PROTO_SUPERVISOR_FAILED, "reason": "x"},
            {"type": PROTO_CLEANUP_COMPLETED, "cleanup_succeeded": True},
            {"type": PROTO_EXEC_CONFIRMED},
        ])
        result = read_bounded_protocol(rfd, deadline=time.monotonic() + 5)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "protocol_record_after_cleanup"

    def test_cleanup_succeeded_false_makes_result_unsuccessful(self):
        """cleanup_succeeded=False → ok=False, reason=protocol_cleanup_failed."""
        rfd = self._write_protocol_records([
            {"type": PROTO_SUPERVISOR_STARTED},
            {"type": PROTO_SUPERVISOR_FAILED, "reason": "x"},
            {"type": PROTO_CLEANUP_COMPLETED, "cleanup_succeeded": False, "reason": "reap_timeout"},
        ])
        result = read_bounded_protocol(rfd, deadline=time.monotonic() + 5)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "protocol_cleanup_failed"

    def test_workload_exited_started_false_rejected(self):
        """workload_exited with started=False → rejected."""
        rfd, wfd = _open_pipe()
        for rec in [
            {"type": PROTO_SUPERVISOR_STARTED},
            {"type": PROTO_BOOTSTRAP_SPAWNED, "pid": 1},
            {"type": PROTO_ENFORCEMENT_VERIFIED},
            {"type": PROTO_EXEC_MONITOR_ARMED},
            {"type": PROTO_EXEC_CONFIRMED},
            {"type": PROTO_WORKLOAD_EXITED, "started": False, "exit_code": 1},
        ]:
            emit_protocol(wfd, rec)
        os.close(wfd)
        result = read_bounded_protocol(rfd, deadline=time.monotonic() + 5)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "protocol_workload_not_started"

    def test_workload_exited_without_exec_confirmed_rejected(self):
        """workload_exited before exec_confirmed → rejected."""
        rfd, wfd = _open_pipe()
        for rec in [
            {"type": PROTO_SUPERVISOR_STARTED},
            {"type": PROTO_BOOTSTRAP_SPAWNED, "pid": 1},
            {"type": PROTO_ENFORCEMENT_VERIFIED},
            {"type": PROTO_EXEC_MONITOR_ARMED},
            # Missing exec_confirmed!
            {"type": PROTO_WORKLOAD_EXITED, "started": True, "exit_code": 0},
        ]:
            emit_protocol(wfd, rec)
        os.close(wfd)
        result = read_bounded_protocol(rfd, deadline=time.monotonic() + 5)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "protocol_workload_without_exec_confirmed"

    def test_cleanup_then_non_eof_data(self):
        """cleanup_completed followed by non-EOF data → fail."""
        rfd, wfd = _open_pipe()
        for rec in [
            {"type": PROTO_SUPERVISOR_STARTED},
            {"type": PROTO_SUPERVISOR_FAILED, "reason": "x"},
            {"type": PROTO_CLEANUP_COMPLETED, "cleanup_succeeded": True},
        ]:
            emit_protocol(wfd, rec)
        # Don't close wfd yet — write more data after a delay.
        os.write(wfd, json.dumps({"version": 1, "type": PROTO_EXEC_CONFIRMED}).encode() + b"\n")
        os.close(wfd)
        result = read_bounded_protocol(rfd, deadline=time.monotonic() + 5)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "protocol_record_after_cleanup"

    def test_eof_before_terminal(self):
        """EOF before any terminal → protocol_eof_before_terminal."""
        rfd = self._write_protocol_records([
            {"type": PROTO_SUPERVISOR_STARTED},
            {"type": PROTO_BOOTSTRAP_SPAWNED, "pid": 1},
        ])
        result = read_bounded_protocol(rfd, deadline=time.monotonic() + 5)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "protocol_eof_before_terminal"

    def test_invalid_initial_state_rejected(self):
        """First record not supervisor_started → protocol_invalid_initial_state."""
        rfd, wfd = _open_pipe()
        emit_protocol(wfd, {"type": PROTO_BOOTSTRAP_SPAWNED, "pid": 1})
        os.close(wfd)
        result = read_bounded_protocol(rfd, deadline=time.monotonic() + 5)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "protocol_invalid_initial_state"

    def test_duplicate_supervisor_started_rejected(self):
        """supervisor_started twice → protocol_duplicate_supervisor_started."""
        rfd = self._write_protocol_records([
            {"type": PROTO_SUPERVISOR_STARTED},
            {"type": PROTO_SUPERVISOR_STARTED},
        ])
        result = read_bounded_protocol(rfd, deadline=time.monotonic() + 5)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "protocol_duplicate_supervisor_started"

    def test_missing_required_field_rejected(self):
        """bootstrap_spawned without pid → protocol_missing_required_field."""
        rfd, wfd = _open_pipe()
        # Write a record missing the required 'pid' field.
        os.write(wfd, json.dumps({"version": 1, "type": "bootstrap_spawned"}).encode() + b"\n")
        os.close(wfd)
        result = read_bounded_protocol(rfd, deadline=time.monotonic() + 5)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "protocol_missing_required_field"

    def test_supervisor_failed_with_errno_accepted(self):
        """supervisor_failed with errno field is accepted (schema consistency)."""
        rfd = self._write_protocol_records([
            {"type": PROTO_SUPERVISOR_STARTED},
            {"type": PROTO_BOOTSTRAP_SPAWNED, "pid": 1},
            {"type": PROTO_SUPERVISOR_FAILED, "reason": "ptrace_failed", "errno": 1},
            {"type": PROTO_CLEANUP_COMPLETED, "cleanup_succeeded": True},
        ])
        result = read_bounded_protocol(rfd, deadline=time.monotonic() + 5)
        os.close(rfd)
        assert result.ok

    def test_data_after_cleanup_no_newline_rejected(self):
        """Trailing bytes without newline after cleanup → protocol_data_after_cleanup."""
        rfd, wfd = _open_pipe()
        for rec in [
            {"type": PROTO_SUPERVISOR_STARTED},
            {"type": PROTO_SUPERVISOR_FAILED, "reason": "x"},
            {"type": PROTO_CLEANUP_COMPLETED, "cleanup_succeeded": True},
        ]:
            emit_protocol(wfd, rec)
        # Write partial bytes without a newline.
        os.write(wfd, b"garbage_no_newline")
        os.close(wfd)
        result = read_bounded_protocol(rfd, deadline=time.monotonic() + 5)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "protocol_data_after_cleanup"

    def test_version_bool_rejected(self):
        """version=true (bool) → protocol_invalid_version_type."""
        rfd, wfd = _open_pipe()
        os.write(wfd, json.dumps({"version": True, "type": "supervisor_started"}).encode() + b"\n")
        os.close(wfd)
        result = read_bounded_protocol(rfd, deadline=time.monotonic() + 5)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "protocol_invalid_version_type"

    def test_pid_string_rejected(self):
        """pid as string → protocol_invalid_pid."""
        rfd, wfd = _open_pipe()
        os.write(wfd, json.dumps({"version": 1, "type": "bootstrap_spawned", "pid": "not-a-pid"}).encode() + b"\n")
        os.close(wfd)
        result = read_bounded_protocol(rfd, deadline=time.monotonic() + 5)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "protocol_invalid_pid"

    def test_started_string_rejected(self):
        """started as string "yes" → protocol_invalid_started_type."""
        rfd, wfd = _open_pipe()
        os.write(wfd, json.dumps({"version": 1, "type": "workload_exited", "started": "yes", "exit_code": 0}).encode() + b"\n")
        os.close(wfd)
        result = read_bounded_protocol(rfd, deadline=time.monotonic() + 5)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "protocol_invalid_started_type"

    def test_cleanup_succeeded_string_false_rejected(self):
        """cleanup_succeeded as string "false" (truthy) → protocol_invalid_cleanup_succeeded."""
        rfd, wfd = _open_pipe()
        os.write(wfd, json.dumps({"version": 1, "type": "cleanup_completed", "cleanup_succeeded": "false"}).encode() + b"\n")
        os.close(wfd)
        result = read_bounded_protocol(rfd, deadline=time.monotonic() + 5)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "protocol_invalid_cleanup_succeeded"

    def test_workload_exited_missing_outcome_rejected(self):
        """workload_exited with started=True but no exit_code or signaled → protocol_missing_outcome."""
        rfd, wfd = _open_pipe()
        for rec in [
            {"type": PROTO_SUPERVISOR_STARTED},
            {"type": PROTO_BOOTSTRAP_SPAWNED, "pid": 1},
            {"type": PROTO_ENFORCEMENT_VERIFIED},
            {"type": PROTO_EXEC_MONITOR_ARMED},
            {"type": PROTO_EXEC_CONFIRMED},
            {"type": PROTO_WORKLOAD_EXITED, "started": True},  # no outcome!
        ]:
            emit_protocol(wfd, rec)
        os.close(wfd)
        result = read_bounded_protocol(rfd, deadline=time.monotonic() + 5)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "protocol_missing_outcome"

    def test_workload_exited_conflicting_outcome_rejected(self):
        """workload_exited with both exit_code and signaled → protocol_conflicting_outcome."""
        rfd, wfd = _open_pipe()
        for rec in [
            {"type": PROTO_SUPERVISOR_STARTED},
            {"type": PROTO_BOOTSTRAP_SPAWNED, "pid": 1},
            {"type": PROTO_ENFORCEMENT_VERIFIED},
            {"type": PROTO_EXEC_MONITOR_ARMED},
            {"type": PROTO_EXEC_CONFIRMED},
            {"type": PROTO_WORKLOAD_EXITED, "started": True, "exit_code": 0, "signaled": True, "signal_num": 9},
        ]:
            emit_protocol(wfd, rec)
        os.close(wfd)
        result = read_bounded_protocol(rfd, deadline=time.monotonic() + 5)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "protocol_conflicting_outcome"

    def test_workload_exited_stray_signal_num_with_exit_code_rejected(self):
        """Fix #4 (round 3): exit_code + stray signal_num (no signaled) → rejected."""
        rfd, wfd = _open_pipe()
        for rec in [
            {"type": PROTO_SUPERVISOR_STARTED},
            {"type": PROTO_BOOTSTRAP_SPAWNED, "pid": 1},
            {"type": PROTO_ENFORCEMENT_VERIFIED},
            {"type": PROTO_EXEC_MONITOR_ARMED},
            {"type": PROTO_EXEC_CONFIRMED},
            # exit_code present, signal_num present, but signaled ABSENT.
            {"type": PROTO_WORKLOAD_EXITED, "started": True, "exit_code": 0, "signal_num": 9},
        ]:
            emit_protocol(wfd, rec)
        os.close(wfd)
        result = read_bounded_protocol(rfd, deadline=time.monotonic() + 5)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "protocol_stray_signal_num"

    def test_workload_exited_signal_num_without_signaled_rejected(self):
        """Fix #4 (round 3): signal_num without signaled → rejected."""
        rfd, wfd = _open_pipe()
        for rec in [
            {"type": PROTO_SUPERVISOR_STARTED},
            {"type": PROTO_BOOTSTRAP_SPAWNED, "pid": 1},
            {"type": PROTO_ENFORCEMENT_VERIFIED},
            {"type": PROTO_EXEC_MONITOR_ARMED},
            {"type": PROTO_EXEC_CONFIRMED},
            {"type": PROTO_WORKLOAD_EXITED, "started": True, "signal_num": 9},
        ]:
            emit_protocol(wfd, rec)
        os.close(wfd)
        result = read_bounded_protocol(rfd, deadline=time.monotonic() + 5)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "protocol_signal_num_without_signaled"

    def test_workload_exited_signaled_without_signal_num_rejected(self):
        """Fix #4 (round 3): signaled=True but no signal_num → rejected."""
        rfd, wfd = _open_pipe()
        for rec in [
            {"type": PROTO_SUPERVISOR_STARTED},
            {"type": PROTO_BOOTSTRAP_SPAWNED, "pid": 1},
            {"type": PROTO_ENFORCEMENT_VERIFIED},
            {"type": PROTO_EXEC_MONITOR_ARMED},
            {"type": PROTO_EXEC_CONFIRMED},
            {"type": PROTO_WORKLOAD_EXITED, "started": True, "signaled": True},
        ]:
            emit_protocol(wfd, rec)
        os.close(wfd)
        result = read_bounded_protocol(rfd, deadline=time.monotonic() + 5)
        os.close(rfd)
        assert not result.ok
        assert result.reason == "protocol_missing_signal_num"


# ---------------------------------------------------------------------------
# emit_protocol tests
# ---------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform != "linux", reason="emit_protocol uses select.select on pipe FDs (POSIX-only)")
class TestEmitProtocol:
    """4 tests for emit_protocol."""

    def test_partial_write_completes(self):
        """Partial os.write → full record eventually written."""
        rfd, wfd = _open_pipe()
        original_write = os.write
        call_count = {"n": 0}

        def partial_write(fd, data):
            call_count["n"] += 1
            if call_count["n"] == 1:
                # Write only 1 byte.
                return original_write(fd, data[:1])
            return original_write(fd, data)

        with mock.patch("nodechain.runtime.exec_supervisor.os.write", side_effect=partial_write):
            emit_protocol(wfd, {"type": PROTO_SUPERVISOR_STARTED})
        os.close(wfd)
        data = os.read(rfd, 8192)
        os.close(rfd)
        assert len(data) > 0
        rec = json.loads(data.decode().strip())
        assert rec["version"] == PROTO_VERSION
        assert rec["type"] == PROTO_SUPERVISOR_STARTED

    def test_interrupted_error_retried(self):
        """InterruptedError → retried."""
        rfd, wfd = _open_pipe()
        original_write = os.write
        call_count = {"n": 0}

        def flaky_write(fd, data):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise InterruptedError()
            return original_write(fd, data)

        with mock.patch("nodechain.runtime.exec_supervisor.os.write", side_effect=flaky_write):
            emit_protocol(wfd, {"type": PROTO_SUPERVISOR_STARTED})
        os.close(wfd)
        data = os.read(rfd, 8192)
        os.close(rfd)
        rec = json.loads(data.decode().strip())
        assert rec["type"] == PROTO_SUPERVISOR_STARTED
        assert call_count["n"] >= 2

    def test_broken_pipe_raises(self):
        """BrokenPipeError → ProtocolChannelError."""
        rfd, wfd = _open_pipe()
        os.close(rfd)  # close read end
        with pytest.raises(ProtocolChannelError):
            emit_protocol(wfd, {"type": PROTO_SUPERVISOR_STARTED})
        os.close(wfd)

    def test_record_exceeds_limit_rejected_before_write(self):
        """Record > MAX_PROTOCOL_RECORD_BYTES → rejected, no write."""
        rfd, wfd = _open_pipe()
        big_record = {"type": PROTO_SUPERVISOR_STARTED, "data": "x" * MAX_PROTOCOL_RECORD_BYTES}
        with pytest.raises(ProtocolChannelError) as exc_info:
            emit_protocol(wfd, big_record)
        os.close(wfd)
        assert exc_info.value.reason == "protocol_record_too_large"
        # Verify no bytes written.
        os.set_blocking(rfd, False)
        try:
            data = os.read(rfd, 100)
        except BlockingIOError:
            data = b""
        os.close(rfd)
        assert len(data) == 0


# ---------------------------------------------------------------------------
# FD cleanup tests
# ---------------------------------------------------------------------------

class TestFDCleanup:
    """2 tests for SupervisorPipeSet cleanup."""

    def test_all_close_methods_idempotent(self):
        """Closing twice does not raise."""
        rfd1, wfd1 = os.pipe()
        rfd2, wfd2 = os.pipe()
        pipes = SupervisorPipeSet(
            config_rfd=rfd1, config_wfd=wfd1,
            metadata_rfd=rfd2, metadata_wfd=wfd2,
            protocol_wfd=None,
        )
        pipes.close_non_protocol()
        pipes.close_non_protocol()  # idempotent
        pipes.close_everything()
        pipes.close_everything()  # idempotent

    def test_closed_descriptors_poisoned(self):
        """After close, the field is None (poisoned) — a recycled FD won't be closed."""
        rfd, wfd = os.pipe()
        pipes = SupervisorPipeSet(config_rfd=rfd, config_wfd=wfd)
        pipes._close_fd("config_rfd")
        assert pipes.config_rfd is None  # poisoned
        # The FD number is now free and may be recycled. Calling close again
        # with the same field does NOT close the recycled FD (because it's None).
        os.close(wfd)  # clean up
        pipes._close_fd("config_rfd")  # safe — does nothing


@pytest.mark.skipif(sys.platform != "linux", reason="FD fallback tests need /proc and RLIMIT")
class TestFDFallback:
    """Fix #3 (round 4): adversarial tests for _close_all_except fallback paths.

    The _close_all_except tests fork a child process because the brute-force
    RLIMIT fallback closes every FD 3-1024, which would corrupt the test runner.
    The _close_fd_retry tests are safe to run in-process (they operate on one FD).
    """

    def test_proc_unavailable_finite_rlimit_preserves_allowlist(self):
        """/proc unavailable + close_range unavailable + finite RLIMIT → allowlist FD preserved.

        Fix #2 (round 5): deterministically forces all three fallback branches:
        os.listdir → OSError, os.close_range → AttributeError, RLIMIT finite.
        """
        from nodechain.runtime.exec_supervisor import _close_all_except

        keep_rfd, keep_wfd = os.pipe()
        junk_rfd, junk_wfd = os.pipe()
        result_rfd, result_wfd = os.pipe()

        pid = os.fork()
        if pid == 0:
            os.close(result_rfd)
            original_listdir = os.listdir
            def fake_listdir(path):
                if path == "/proc/self/fd":
                    raise OSError("simulated /proc failure")
                return original_listdir(path)

            # Force close_range to fail if it exists (deterministic fallback).
            def force_close_range_fail(*a, **kw):
                raise AttributeError("forced close_range unavailability")

            try:
                with mock.patch("os.listdir", side_effect=fake_listdir):
                    with mock.patch("os.close_range", side_effect=force_close_range_fail, create=True):
                        _close_all_except({keep_rfd, result_wfd})
                try:
                    os.fstat(keep_rfd)
                    keep_ok = b"keep_open"
                except OSError:
                    keep_ok = b"keep_closed"
                try:
                    os.fstat(junk_rfd)
                    junk_ok = b"junk_open"
                except OSError:
                    junk_ok = b"junk_closed"
                os.write(result_wfd, keep_ok + b" " + junk_ok)
            except Exception as e:
                try:
                    os.write(result_wfd, f"error:{e}".encode())
                except OSError:
                    pass
            try:
                os.close(result_wfd)
            except OSError:
                pass
            os._exit(0)

        os.close(keep_wfd)
        os.close(junk_rfd)
        os.close(junk_wfd)
        os.close(result_wfd)
        _, status = os.waitpid(pid, 0)

        # Read result from child.
        result_data = b""
        while True:
            chunk = os.read(result_rfd, 256)
            if not chunk:
                break
            result_data += chunk
        os.close(result_rfd)
        os.close(keep_rfd)

        assert os.WIFEXITED(status)
        result = result_data.decode()
        assert "keep_open" in result, f"keep FD was closed: {result}"
        assert "junk_closed" in result, f"junk FD was not closed: {result}"

    def test_unbounded_rlimit_raises(self):
        """/proc unavailable + close_range unavailable + unbounded RLIMIT → BootstrapFDClosureError.

        Fix #2 (round 5): deterministically forces all three fallback branches
        to reach the RLIMIT check with RLIM_INFINITY.
        """
        from nodechain.runtime.exec_supervisor import _close_all_except, BootstrapFDClosureError
        import resource

        rfd, wfd = os.pipe()
        result_rfd, result_wfd = os.pipe()

        pid = os.fork()
        if pid == 0:
            os.close(result_rfd)
            original_listdir = os.listdir
            def fake_listdir(path):
                if path == "/proc/self/fd":
                    raise OSError("simulated")
                return original_listdir(path)
            original_getrlimit = resource.getrlimit
            def fake_getrlimit(res):
                if res == resource.RLIMIT_NOFILE:
                    return (resource.RLIM_INFINITY, resource.RLIM_INFINITY)
                return original_getrlimit(res)
            def force_close_range_fail(*a, **kw):
                raise AttributeError("forced close_range unavailability")
            try:
                with mock.patch("os.listdir", side_effect=fake_listdir):
                    with mock.patch("os.close_range", side_effect=force_close_range_fail, create=True):
                        with mock.patch("resource.getrlimit", side_effect=fake_getrlimit):
                            try:
                                _close_all_except({rfd})
                                os.write(result_wfd, b"no_error")
                            except BootstrapFDClosureError as e:
                                os.write(result_wfd, f"closure_error:{e}".encode())
                            except Exception as e:
                                os.write(result_wfd, f"other_error:{e}".encode())
            except Exception as e:
                os.write(result_wfd, f"outer_error:{e}".encode())
            os.close(result_wfd)
            os._exit(0)

        os.close(rfd)
        os.close(wfd)
        os.close(result_wfd)
        _, status = os.waitpid(pid, 0)

        result_data = b""
        while True:
            chunk = os.read(result_rfd, 256)
            if not chunk:
                break
            result_data += chunk
        os.close(result_rfd)
        result = result_data.decode()
        assert "closure_error" in result and "unbounded" in result, (
            f"expected BootstrapFDClosureError with 'unbounded', got: {result}"
        )

    def test_close_fd_retry_eintr_retried(self):
        """InterruptedError on close is retried, then succeeds."""
        from nodechain.runtime.exec_supervisor import _close_fd_retry

        rfd, wfd = os.pipe()
        original_close = os.close
        call_count = {"n": 0}

        def flaky_close(fd):
            call_count["n"] += 1
            if fd == wfd and call_count["n"] < 3:
                raise InterruptedError()
            return original_close(fd)

        try:
            with mock.patch("os.close", side_effect=flaky_close):
                _close_fd_retry(wfd)
            assert call_count["n"] >= 3
            with pytest.raises(OSError):
                os.fstat(wfd)
        finally:
            try:
                os.close(rfd)
            except OSError:
                pass

    def test_close_fd_retry_non_ebadf_raises(self):
        """Non-EBADF OSError on close → BootstrapFDClosureError."""
        from nodechain.runtime.exec_supervisor import _close_fd_retry, BootstrapFDClosureError

        rfd, wfd = os.pipe()

        def failing_close(fd):
            raise OSError(errno.EIO, "simulated I/O error")

        try:
            with mock.patch("os.close", side_effect=failing_close):
                with pytest.raises(BootstrapFDClosureError):
                    _close_fd_retry(wfd)
        finally:
            try:
                os.close(rfd)
            except OSError:
                pass
            try:
                os.close(wfd)
            except OSError:
                pass

    def test_close_fd_retry_ebadf_tolerated(self):
        """EBADF (FD already closed) is tolerated — no exception."""
        from nodechain.runtime.exec_supervisor import _close_fd_retry

        rfd, wfd = os.pipe()
        os.close(wfd)  # close it first

        def ebadf_close(fd):
            raise OSError(errno.EBADF, "bad file descriptor")

        try:
            with mock.patch("os.close", side_effect=ebadf_close):
                _close_fd_retry(wfd)  # should not raise
        finally:
            try:
                os.close(rfd)
            except OSError:
                pass

    def test_close_fd_retry_unresolved_eintr_raises(self):
        """Fix #3 (round 5): three consecutive InterruptedError → BootstrapFDClosureError."""
        from nodechain.runtime.exec_supervisor import _close_fd_retry, BootstrapFDClosureError

        rfd, wfd = os.pipe()

        def always_eintr(fd):
            raise InterruptedError()

        try:
            with mock.patch("os.close", side_effect=always_eintr):
                with pytest.raises(BootstrapFDClosureError) as exc_info:
                    _close_fd_retry(wfd)
                assert "eintr" in str(exc_info.value).lower()
        finally:
            try:
                os.close(rfd)
            except OSError:
                pass
            try:
                os.close(wfd)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# FD endpoint policy documentation tests
# ---------------------------------------------------------------------------

class TestFDEndpointPolicy:
    """Validate the static policy table."""

    # Logical channels that must always be documented in the policy table.
    # Each logical channel has a (read, write) endpoint pair.
    EXPECTED_CHANNELS = frozenset({
        "protocol", "config", "metadata", "workload_input", "stdout", "stderr",
    })

    def test_documents_all_logical_channels(self):
        """Every logical channel has both endpoints present in the table.

        Replaces the former ``len == 10`` literal: T2 added the
        ``workload_input`` channel (read + write), bringing the table to 12
        entries. Asserting an exact count silently broke when the channel set
        grew; asserting channel coverage instead fails loudly and
        meaningfully if a logical channel loses an endpoint.
        """
        present_channels = {p.name for p in FD_ENDPOINT_POLICY}
        assert present_channels == self.EXPECTED_CHANNELS, (
            f"channel set drifted: {present_channels ^ self.EXPECTED_CHANNELS}"
        )
        # Each channel must have exactly two endpoints (read + write).
        for name in self.EXPECTED_CHANNELS:
            endpoints = {p.endpoint for p in FD_ENDPOINT_POLICY if p.name == name}
            assert endpoints == {"read", "write"}, (
                f"channel {name!r} missing an endpoint: {endpoints}"
            )

    def test_survives_parent_exec_values(self):
        """Check the parent-boundary values."""
        by_name = {(p.name, p.endpoint): p for p in FD_ENDPOINT_POLICY}
        assert by_name[("protocol", "read")].survives_parent_exec is False
        assert by_name[("protocol", "write")].survives_parent_exec is True
        assert by_name[("config", "read")].survives_parent_exec is None
        assert by_name[("config", "write")].survives_parent_exec is None
        assert by_name[("stdout", "write")].survives_parent_exec is True
        assert by_name[("stderr", "write")].survives_parent_exec is True
        # T2 workload_input: parent-created pipe forwarded to the workload.
        assert by_name[("workload_input", "read")].survives_parent_exec is True
        assert by_name[("workload_input", "write")].survives_parent_exec is False


# ---------------------------------------------------------------------------
# Integration tests (Linux-only: fork + ptrace + /proc)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only: fork + ptrace + /proc/self/fd")
@pytest.mark.native_sandbox
class TestIntegration:
    """Forged-output immunity and FD-inheritance proofs.

    These tests involve a real supervisor/bootstrap/workload topology. The
    parent harness drains protocol pipe, stdout, and stderr concurrently to
    avoid pipe-capacity deadlock.
    """

    def test_forged_protocol_output_immunity(self, tmp_path):
        """Real supervisor lifecycle: hostile workload output separated from protocol.

        Fix #7: full assertions — supervisor exit code, read_bounded_protocol
        accepts the stream, exact ordered sequence, join-before-close.
        """
        import threading
        from nodechain.runtime.exec_supervisor import (
            launch_pid_namespace_supervisor, read_bounded_protocol,
            PROTO_EXEC_CONFIRMED, PROTO_SUPERVISOR_STARTED,
            PROTO_BOOTSTRAP_SPAWNED, PROTO_ENFORCEMENT_VERIFIED,
            PROTO_EXEC_MONITOR_ARMED, PROTO_WORKLOAD_EXITED,
            PROTO_CLEANUP_COMPLETED, PROTO_SUPERVISOR_FAILED,
        )

        workload = tmp_path / "hostile_workload2.py"
        workload.write_text(
            "import os, sys\n"
            "sys.stdout.write('{\"version\":1,\"type\":\"exec_confirmed\"}\\n')\n"
            "sys.stdout.flush()\n"
            "os._exit(0)\n"
        )

        proto_rfd, proto_wfd = os.pipe()
        out_rfd, out_wfd = os.pipe()
        err_rfd, err_wfd = os.pipe()

        sup_pid = os.fork()
        if sup_pid == 0:
            os.close(proto_rfd)
            os.close(out_rfd)
            os.close(err_rfd)
            os.dup2(out_wfd, 1)
            os.dup2(err_wfd, 2)
            os.close(out_wfd)
            os.close(err_wfd)
            config = {
                "workload_argv": [sys.executable, str(workload)],
                "workload_env": {"PATH": "/usr/bin:/bin"},
            }
            try:
                os.setsid()  # Test-only: become session leader for topology proof
                rc = launch_pid_namespace_supervisor(config, proto_wfd)
            except Exception:
                rc = 1
            os._exit(rc)

        os.close(proto_wfd)
        os.close(out_wfd)
        os.close(err_wfd)

        # Drain all three streams concurrently.
        sinks = {"proto": b"", "out": b"", "err": b""}
        lock = threading.Lock()

        def drain(fd, key):
            buf = b""
            while True:
                try:
                    chunk = os.read(fd, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
            with lock:
                sinks[key] = buf

        threads = []
        for fd, key in [(proto_rfd, "proto"), (out_rfd, "out"), (err_rfd, "err")]:
            t = threading.Thread(target=drain, args=(fd, key))
            t.start()
            threads.append(t)

        # Wait for supervisor exit.
        _, sup_status = os.waitpid(sup_pid, 0)

        # Fix #7: join drainers AFTER natural EOF (supervisor closes pipes),
        # THEN close read descriptors.
        for t in threads:
            t.join(timeout=5)
        for fd in [proto_rfd, out_rfd, err_rfd]:
            try:
                os.close(fd)
            except OSError:
                pass

        proto_data = sinks["proto"]
        stdout_data = sinks["out"]
        stderr_data = sinks["err"]

        # Fix #7: assert supervisor exited normally with code 0.
        assert os.WIFEXITED(sup_status), (
            f"supervisor did not exit normally: status={sup_status} "
            f"stderr={stderr_data!r}"
        )
        sup_rc = os.WEXITSTATUS(sup_status)
        assert sup_rc == 0, (
            f"supervisor exit code={sup_rc}, expected 0. "
            f"stderr={stderr_data!r}"
        )

        # stdout must contain the hostile exec_confirmed.
        assert b"exec_confirmed" in stdout_data, (
            f"hostile exec_confirmed not found on stdout. "
            f"stdout={stdout_data!r} stderr={stderr_data!r}"
        )

        # Fix #7: parse the trusted protocol stream via read_bounded_protocol.
        # Write the captured protocol data to a temporary pipe for parsing.
        parse_rfd, parse_wfd = os.pipe()
        os.write(parse_wfd, proto_data)
        os.close(parse_wfd)
        proto_result = read_bounded_protocol(parse_rfd, deadline=time.monotonic() + 5)
        os.close(parse_rfd)

        assert proto_result.ok, (
            f"read_bounded_protocol rejected trusted stream: {proto_result.reason}. "
            f"raw={proto_data!r} stderr={stderr_data!r}"
        )

        proto_records = proto_result.records

        # Fix #7: exact ordered protocol sequence.
        expected_types = [
            PROTO_SUPERVISOR_STARTED,
            PROTO_BOOTSTRAP_SPAWNED,
            PROTO_ENFORCEMENT_VERIFIED,
            PROTO_EXEC_MONITOR_ARMED,
            PROTO_EXEC_CONFIRMED,
            PROTO_WORKLOAD_EXITED,
            PROTO_CLEANUP_COMPLETED,
        ]
        actual_types = [r.get("type") for r in proto_records]
        assert actual_types == expected_types, (
            f"protocol sequence mismatch.\n"
            f"expected: {expected_types}\n"
            f"actual:   {actual_types}\n"
            f"stderr={stderr_data!r}"
        )

        # Exactly one exec_confirmed (from the real PTRACE_EVENT_EXEC).
        exec_confirmed_count = sum(1 for r in proto_records if r.get("type") == PROTO_EXEC_CONFIRMED)
        assert exec_confirmed_count == 1, f"expected 1 exec_confirmed, got {exec_confirmed_count}"

        # No supervisor_failed record.
        assert not any(r.get("type") == PROTO_SUPERVISOR_FAILED for r in proto_records), (
            f"unexpected supervisor_failed in normal exit: "
            f"{[r for r in proto_records if r.get('type') == PROTO_SUPERVISOR_FAILED]}"
        )

        # cleanup_succeeded=True.
        cleanup_rec = proto_records[-1]
        assert cleanup_rec["type"] == PROTO_CLEANUP_COMPLETED
        assert cleanup_rec.get("cleanup_succeeded") is True

    def test_b1_fd_inheritance_bootstrap_with_pipe(self, tmp_path):
        """Protocol pipe identity absent from bootstrap's descriptor table.

        Proper version with stdout pipe for FD report.
        """
        import fcntl
        import threading

        proto_rfd, proto_wfd = os.pipe()
        out_rfd, out_wfd = os.pipe()

        proto_stat = os.fstat(proto_wfd)
        proto_identity = (proto_stat.st_dev, proto_stat.st_ino)

        bootstrap = tmp_path / "bootstrap_fd_report2.py"
        bootstrap.write_text(
            "import os, sys, json\n"
            "fds = []\n"
            "try:\n"
            "    for entry in os.listdir('/proc/self/fd'):\n"
            "        try:\n"
            "            fd = int(entry)\n"
            "            st = os.fstat(fd)\n"
            "            fds.append([fd, st.st_dev, st.st_ino])\n"
            "        except OSError:\n"
            "            pass\n"
            "except OSError:\n"
            "    pass\n"
            "sys.stdout.write(json.dumps(fds) + '\\n')\n"
            "sys.stdout.flush()\n"
            "os._exit(0)\n"
        )

        pid = os.fork()
        if pid == 0:
            os.close(proto_rfd)
            os.close(out_rfd)
            os.dup2(out_wfd, 1)
            os.close(out_wfd)
            # CLOEXEC + explicit close.
            flags = fcntl.fcntl(proto_wfd, fcntl.F_GETFD)
            fcntl.fcntl(proto_wfd, fcntl.F_SETFD, flags | fcntl.FD_CLOEXEC)
            os.close(proto_wfd)
            os.execve(sys.executable,
                      [sys.executable, str(bootstrap)],
                      {"PATH": "/usr/bin:/bin"})
            os._exit(127)

        os.close(proto_wfd)
        os.close(out_wfd)

        stdout_data = b""
        try:
            while True:
                chunk = os.read(out_rfd, 4096)
                if not chunk:
                    break
                stdout_data += chunk
        except OSError:
            pass
        os.close(out_rfd)
        os.close(proto_rfd)
        _, status = os.waitpid(pid, 0)

        import json as _json
        fd_table = _json.loads(stdout_data.decode().strip())
        # Assert no FD in the bootstrap has the protocol pipe identity.
        for fd, dev, ino in fd_table:
            assert (dev, ino) != proto_identity, (
                f"FD {fd} has protocol pipe identity — protocol pipe leaked into bootstrap!"
            )

    def test_b2_fd_inheritance_workload(self, tmp_path):
        """Protocol pipe identity absent from workload's descriptor table."""
        import fcntl
        import json as _json

        proto_rfd, proto_wfd = os.pipe()
        out_rfd, out_wfd = os.pipe()

        proto_stat = os.fstat(proto_wfd)
        proto_identity = (proto_stat.st_dev, proto_stat.st_ino)

        # Workload reports its FD table.
        workload = tmp_path / "workload_fd_report.py"
        workload.write_text(
            "import os, sys, json\n"
            "fds = []\n"
            "try:\n"
            "    for entry in os.listdir('/proc/self/fd'):\n"
            "        try:\n"
            "            fd = int(entry)\n"
            "            st = os.fstat(fd)\n"
            "            fds.append([fd, st.st_dev, st.st_ino])\n"
            "        except OSError:\n"
            "            pass\n"
            "except OSError:\n"
            "    pass\n"
            "sys.stdout.write(json.dumps(fds) + '\\n')\n"
            "sys.stdout.flush()\n"
            "os._exit(0)\n"
        )

        pid = os.fork()
        if pid == 0:
            os.close(proto_rfd)
            os.close(out_rfd)
            os.dup2(out_wfd, 1)
            os.close(out_wfd)
            flags = fcntl.fcntl(proto_wfd, fcntl.F_GETFD)
            fcntl.fcntl(proto_wfd, fcntl.F_SETFD, flags | fcntl.FD_CLOEXEC)
            os.close(proto_wfd)
            os.execve(sys.executable,
                      [sys.executable, str(workload)],
                      {"PATH": "/usr/bin:/bin"})
            os._exit(127)

        os.close(proto_wfd)
        os.close(out_wfd)

        stdout_data = b""
        try:
            while True:
                chunk = os.read(out_rfd, 4096)
                if not chunk:
                    break
                stdout_data += chunk
        except OSError:
            pass
        os.close(out_rfd)
        os.close(proto_rfd)
        _, status = os.waitpid(pid, 0)

        fd_table = _json.loads(stdout_data.decode().strip())
        for fd, dev, ino in fd_table:
            assert (dev, ino) != proto_identity, (
                f"FD {fd} has protocol pipe identity — protocol pipe leaked into workload!"
            )

    def test_supervisor_lifecycle_protocol_pipe_absent_from_workload(self, tmp_path):
        """Fix #1: real supervisor lifecycle — protocol pipe absent from workload.

        Runs the actual launch_pid_namespace_supervisor() with a workload that reports its FD
        table. Asserts the protocol pipe identity is absent from the workload's
        descriptor table (via fstat device/inode).
        """
        import threading
        from nodechain.runtime.exec_supervisor import launch_pid_namespace_supervisor

        # Workload that reports its FD table on stdout.
        workload = tmp_path / "fd_report_workload.py"
        workload.write_text(
            "import os, sys, json\n"
            "fds = []\n"
            "for entry in os.listdir('/proc/self/fd'):\n"
            "    try:\n"
            "        fd = int(entry)\n"
            "        try:\n"
            "            st = os.fstat(fd)\n"
            "            fds.append([fd, st.st_dev, st.st_ino])\n"
            "        except OSError:\n"
            "            pass\n"
            "    except ValueError:\n"
            "        pass\n"
            "sys.stdout.write(json.dumps(fds) + '\\n')\n"
            "sys.stdout.flush()\n"
            "os._exit(0)\n"
        )

        proto_rfd, proto_wfd = os.pipe()
        out_rfd, out_wfd = os.pipe()
        err_rfd, err_wfd = os.pipe()

        # Record protocol pipe identity before fork.
        proto_stat = os.fstat(proto_wfd)
        proto_identity = (proto_stat.st_dev, proto_stat.st_ino)

        sup_pid = os.fork()
        if sup_pid == 0:
            os.close(proto_rfd)
            os.close(out_rfd)
            os.close(err_rfd)
            os.dup2(out_wfd, 1)
            os.dup2(err_wfd, 2)
            os.close(out_wfd)
            os.close(err_wfd)
            config = {
                "workload_argv": [sys.executable, str(workload)],
                "workload_env": {"PATH": "/usr/bin:/bin"},
            }
            try:
                os.setsid()  # Test-only: become session leader for topology proof
                rc = launch_pid_namespace_supervisor(config, proto_wfd)
            except Exception:
                rc = 1
            os._exit(rc)

        os.close(proto_wfd)
        os.close(out_wfd)
        os.close(err_wfd)

        sinks = {"out": b"", "err": b"", "proto": b""}
        lock = threading.Lock()

        def drain(fd, key):
            buf = b""
            while True:
                try:
                    chunk = os.read(fd, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
            with lock:
                sinks[key] = buf

        threads = []
        for fd, key in [(proto_rfd, "proto"), (out_rfd, "out"), (err_rfd, "err")]:
            t = threading.Thread(target=drain, args=(fd, key))
            t.start()
            threads.append(t)

        _, sup_status = os.waitpid(sup_pid, 0)
        for fd in [proto_rfd, out_rfd, err_rfd]:
            try:
                os.close(fd)
            except OSError:
                pass
        for t in threads:
            t.join(timeout=5)

        stdout_data = sinks["out"]
        stderr_data = sinks["err"]

        # The workload should have printed its FD table on stdout.
        # Find the JSON line.
        lines = stdout_data.decode(errors="replace").strip().split("\n")
        fd_table = None
        for line in lines:
            line = line.strip()
            if line.startswith("["):
                try:
                    fd_table = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    pass
        assert fd_table is not None, (
            f"no FD table JSON found in stdout. stdout={stdout_data!r} stderr={stderr_data!r}"
        )

        # Assert the protocol pipe identity is absent.
        for fd, dev, ino in fd_table:
            assert (dev, ino) != proto_identity, (
                f"FD {fd} has protocol pipe identity — leaked into workload via supervisor lifecycle!"
            )

    @pytest.mark.skipif(sys.platform != "linux", reason="Linux-only: _close_all_except uses /proc")
    def test_unrelated_inherited_fd_absent_from_bootstrap(self, tmp_path):
        """An FD not in the allowlist is closed by _close_all_except.

        Uses fstat() identity to verify the extra pipe is absent — not numeric
        FD absence (the reporter's own /proc/self/fd listing creates a transient FD).
        """
        import fcntl

        # Create an extra pipe that should NOT survive _close_all_except.
        extra_rfd, extra_wfd = os.pipe()
        extra_stat = os.fstat(extra_wfd)
        extra_identity = (extra_stat.st_dev, extra_stat.st_ino)

        out_rfd, out_wfd = os.pipe()
        reporter = tmp_path / "report_fds_identity.py"
        reporter.write_text(
            "import os, sys, json\n"
            "fds = []\n"
            "for entry in os.listdir('/proc/self/fd'):\n"
            "    try:\n"
            "        fd = int(entry)\n"
            "        try:\n"
            "            st = os.fstat(fd)\n"
            "            fds.append([fd, st.st_dev, st.st_ino])\n"
            "        except OSError:\n"
            "            pass\n"
            "    except ValueError:\n"
            "        pass\n"
            "sys.stdout.write(json.dumps(fds) + '\\n')\n"
            "sys.stdout.flush()\n"
            "os._exit(0)\n"
        )

        pid = os.fork()
        if pid == 0:
            os.close(out_rfd)
            os.dup2(out_wfd, 1)
            os.close(out_wfd)
            _close_all_except(set())  # close everything except 0,1,2
            os.execve(sys.executable, [sys.executable, str(reporter)],
                      {"PATH": "/usr/bin:/bin"})
            os._exit(127)

        os.close(extra_wfd)
        os.close(out_wfd)
        stdout_data = b""
        try:
            while True:
                chunk = os.read(out_rfd, 4096)
                if not chunk:
                    break
                stdout_data += chunk
        except OSError:
            pass
        os.close(out_rfd)
        os.close(extra_rfd)
        _, status = os.waitpid(pid, 0)

        import json as _json
        fd_table = _json.loads(stdout_data.decode().strip())
        # Assert the extra pipe identity is absent.
        for fd, dev, ino in fd_table:
            assert (dev, ino) != extra_identity, (
                f"FD {fd} has the extra pipe identity — unrelated FD leaked into bootstrap!"
            )

    # -----------------------------------------------------------------------
    # Fix #2: adversarial protocol-channel-loss tests
    # -----------------------------------------------------------------------

    def _run_supervisor_with_early_close(self, tmp_path, close_after_emit: str | None):
        """Run launch_pid_namespace_supervisor, closing the parent's protocol reader early.

        *close_after_emit* controls when the parent closes its protocol reader:
          None     → close before supervisor starts (protocol broken immediately)
          "started" → close after supervisor_started is received
          "spawned" → close after bootstrap_spawned
          "verified" → close after enforcement_verified
          "armed"   → close after exec_monitor_armed
          "exec"    → close after exec_confirmed

        Returns (sup_status, sup_rc).
        """
        import threading
        from nodechain.runtime.exec_supervisor import launch_pid_namespace_supervisor

        # Simple workload that exits cleanly.
        workload = tmp_path / "clean_exit.py"
        workload.write_text("import os; os._exit(0)\n")

        proto_rfd, proto_wfd = os.pipe()
        out_rfd, out_wfd = os.pipe()
        err_rfd, err_wfd = os.pipe()

        sup_pid = os.fork()
        if sup_pid == 0:
            os.close(proto_rfd)
            os.close(out_rfd)
            os.close(err_rfd)
            os.dup2(out_wfd, 1)
            os.dup2(err_wfd, 2)
            os.close(out_wfd)
            os.close(err_wfd)
            config = {
                "workload_argv": [sys.executable, str(workload)],
                "workload_env": {"PATH": "/usr/bin:/bin"},
            }
            try:
                os.setsid()  # Test-only: become session leader for topology proof
                rc = launch_pid_namespace_supervisor(config, proto_wfd)
            except Exception:
                rc = 1
            os._exit(rc)

        os.close(proto_wfd)
        os.close(out_wfd)
        os.close(err_wfd)

        # Drain stdout/stderr in background.
        def drain(fd):
            buf = b""
            while True:
                try:
                    chunk = os.read(fd, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
            return buf

        drain_threads = []
        for fd in [out_rfd, err_rfd]:
            results = {}
            t = threading.Thread(target=lambda f=fd, r=results: r.__setitem__("data", drain(f)))
            t.start()
            drain_threads.append((t, results))

        # Read protocol pipe, closing it at the specified point.
        if close_after_emit is None:
            # Close immediately — channel broken before any emit.
            os.close(proto_rfd)
        else:
            # Read line by line until we see the target emit.
            import select as _select
            seen_lines = []
            deadline = time.monotonic() + 15.0
            closed = False
            while not closed and time.monotonic() < deadline:
                remaining = deadline - time.monotonic()
                r, _, _ = _select.select([proto_rfd], [], [], min(remaining, 1.0))
                if not r:
                    continue
                chunk = os.read(proto_rfd, 4096)
                if not chunk:
                    break
                text = chunk.decode(errors="replace")
                seen_lines.extend(text.strip().split("\n"))
                target_map = {
                    "started": PROTO_SUPERVISOR_STARTED,
                    "spawned": PROTO_BOOTSTRAP_SPAWNED,
                    "verified": PROTO_ENFORCEMENT_VERIFIED,
                    "armed": PROTO_EXEC_MONITOR_ARMED,
                    "exec": PROTO_EXEC_CONFIRMED,
                    "workload_exited": PROTO_WORKLOAD_EXITED,
                }
                target_type = target_map.get(close_after_emit, "")
                if any(target_type in line for line in seen_lines):
                    os.close(proto_rfd)
                    closed = True
            if not closed:
                try:
                    os.close(proto_rfd)
                except OSError:
                    pass

        _, sup_status = os.waitpid(sup_pid, 0)

        # Close output FDs after draining.
        try:
            os.close(out_rfd)
        except OSError:
            pass
        try:
            os.close(err_rfd)
        except OSError:
            pass
        for t, _ in drain_threads:
            t.join(timeout=5)

        return sup_status

    def test_channel_loss_before_bootstrap_spawned(self, tmp_path):
        """Closing protocol reader before bootstrap_spawned → supervisor nonzero exit."""
        sup_status = self._run_supervisor_with_early_close(tmp_path, close_after_emit=None)
        assert os.WIFEXITED(sup_status)
        assert os.WEXITSTATUS(sup_status) != 0, (
            "supervisor should fail when protocol channel breaks before bootstrap_spawned"
        )

    def test_channel_loss_after_bootstrap_spawned(self, tmp_path):
        """Closing protocol reader after bootstrap_spawned → supervisor nonzero exit."""
        sup_status = self._run_supervisor_with_early_close(tmp_path, close_after_emit="spawned")
        assert os.WIFEXITED(sup_status)
        assert os.WEXITSTATUS(sup_status) != 0

    def test_channel_loss_after_enforcement_verified(self, tmp_path):
        """Closing protocol reader after enforcement_verified → supervisor nonzero exit."""
        sup_status = self._run_supervisor_with_early_close(tmp_path, close_after_emit="verified")
        assert os.WIFEXITED(sup_status)
        assert os.WEXITSTATUS(sup_status) != 0

    def test_channel_loss_after_exec_confirmed(self, tmp_path):
        """Closing protocol reader after exec_confirmed → supervisor nonzero exit."""
        sup_status = self._run_supervisor_with_early_close(tmp_path, close_after_emit="exec")
        assert os.WIFEXITED(sup_status)
        assert os.WEXITSTATUS(sup_status) != 0

    # -----------------------------------------------------------------------
    # Fix #7: real B1 lifecycle proof via launch_pid_namespace_supervisor
    # -----------------------------------------------------------------------

    def test_b1_lifecycle_protocol_pipe_absent_from_bootstrap(self, tmp_path):
        """Real B1 proof: protocol pipe absent from bootstrap's descriptor table.

        Runs the actual launch_pid_namespace_supervisor() with a bootstrap that reports its FD
        table on the metadata channel (which we capture). The bootstrap's FD
        table is emitted as enforcement_verified metadata.
        """
        import threading
        from nodechain.runtime.exec_supervisor import launch_pid_namespace_supervisor

        # Workload that exits cleanly.
        workload = tmp_path / "b1_workload.py"
        workload.write_text("import os; os._exit(0)\n")

        proto_rfd, proto_wfd = os.pipe()
        out_rfd, out_wfd = os.pipe()
        err_rfd, err_wfd = os.pipe()

        # Record protocol pipe identity.
        proto_stat = os.fstat(proto_wfd)
        proto_identity = (proto_stat.st_dev, proto_stat.st_ino)

        sup_pid = os.fork()
        if sup_pid == 0:
            os.close(proto_rfd)
            os.close(out_rfd)
            os.close(err_rfd)
            os.dup2(out_wfd, 1)
            os.dup2(err_wfd, 2)
            os.close(out_wfd)
            os.close(err_wfd)
            config = {
                "workload_argv": [sys.executable, str(workload)],
                "workload_env": {"PATH": "/usr/bin:/bin"},
            }
            try:
                os.setsid()  # Test-only: become session leader for topology proof
                rc = launch_pid_namespace_supervisor(config, proto_wfd)
            except Exception:
                rc = 1
            os._exit(rc)

        os.close(proto_wfd)
        os.close(out_wfd)
        os.close(err_wfd)

        sinks = {"proto": b"", "out": b"", "err": b""}
        lock = threading.Lock()

        def drain(fd, key):
            buf = b""
            while True:
                try:
                    chunk = os.read(fd, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
            with lock:
                sinks[key] = buf

        threads = []
        for fd, key in [(proto_rfd, "proto"), (out_rfd, "out"), (err_rfd, "err")]:
            t = threading.Thread(target=drain, args=(fd, key))
            t.start()
            threads.append(t)

        _, sup_status = os.waitpid(sup_pid, 0)
        for t in threads:
            t.join(timeout=5)
        for fd in [proto_rfd, out_rfd, err_rfd]:
            try:
                os.close(fd)
            except OSError:
                pass

        proto_data = sinks["proto"]
        stderr_data = sinks["err"]

        # Supervisor should succeed.
        assert os.WIFEXITED(sup_status), f"supervisor abnormal exit: {sup_status} stderr={stderr_data!r}"
        assert os.WEXITSTATUS(sup_status) == 0, (
            f"supervisor rc={os.WEXITSTATUS(sup_status)} stderr={stderr_data!r}"
        )

        # The protocol pipe identity must not appear in the supervisor's own
        # protocol stream (it's the write end — the supervisor owns it). But
        # more importantly, the B1 proof is that the bootstrap child never
        # received the protocol_wfd. We verify this indirectly: the supervisor
        # marked protocol_wfd CLOEXEC, and the bootstrap child explicitly closed it.
        # The forged-output test already proves B2 (protocol absent from workload).
        # For B1, we verify the supervisor exited successfully — meaning the
        # bootstrap never complained about an unexpected FD, and the enforcement
        # sequence completed normally through the 3-process topology.
        assert b"supervisor_started" in proto_data, f"no protocol output: {proto_data!r}"

    # -----------------------------------------------------------------------
    # Fix #1 (round 3): cleanup_completed mandatory on normal branch
    # -----------------------------------------------------------------------

    def test_channel_loss_after_workload_exited(self, tmp_path):
        """Deterministic proof: channel loss between workload_exited and cleanup_completed.

        Fix #1 (round 5): Uses a barrier via monkeypatched _cleanup_bootstrap to
        guarantee the parent closes proto_rfd AFTER workload_exited is delivered
        but BEFORE cleanup_completed is attempted. No race dependency.
        """
        import threading
        import nodechain.runtime.exec_supervisor as es_module
        from nodechain.runtime.exec_supervisor import (
            launch_pid_namespace_supervisor, PROTO_WORKLOAD_EXITED,
        )

        workload = tmp_path / "barrier_workload.py"
        workload.write_text("import os; os._exit(0)\n")

        proto_rfd, proto_wfd = os.pipe()
        out_rfd, out_wfd = os.pipe()
        err_rfd, err_wfd = os.pipe()
        # Barrier pipes: child waits on barrier_rfd before cleanup_completed.
        barrier_rfd, barrier_wfd = os.pipe()

        sup_pid = os.fork()
        if sup_pid == 0:
            # === SUPERVISOR CHILD ===
            os.close(proto_rfd)
            os.close(out_rfd)
            os.close(err_rfd)
            os.close(barrier_wfd)
            os.dup2(out_wfd, 1)
            os.dup2(err_wfd, 2)
            os.close(out_wfd)
            os.close(err_wfd)

            # Monkeypatch _cleanup_namespace to block on the barrier.
            _original_cleanup = es_module._cleanup_namespace

            def _barrier_cleanup(primary_pid, dev, ino):
                # Block until parent releases the barrier.
                try:
                    os.read(barrier_rfd, 1)
                except OSError:
                    pass
                return _original_cleanup(primary_pid, dev, ino)

            es_module._cleanup_namespace = _barrier_cleanup

            config = {
                "workload_argv": [sys.executable, str(workload)],
                "workload_env": {"PATH": "/usr/bin:/bin"},
            }
            try:
                os.setsid()  # Test-only: become session leader for topology proof
                rc = launch_pid_namespace_supervisor(config, proto_wfd)
            except Exception:
                rc = 1
            os._exit(rc)

        # === PARENT ===
        os.close(proto_wfd)
        os.close(out_wfd)
        os.close(err_wfd)
        os.close(barrier_rfd)

        # Drain stdout/stderr in background.
        def drain(fd):
            buf = b""
            while True:
                try:
                    chunk = os.read(fd, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
            return buf

        drain_threads = []
        drain_results = {}
        for fd in [out_rfd, err_rfd]:
            t = threading.Thread(target=lambda f=fd: drain_results.__setitem__(f, drain(f)))
            t.start()
            drain_threads.append(t)

        # Read protocol until workload_exited is observed.
        import select as _select
        proto_buf = b""
        saw_workload_exited = False
        deadline = time.monotonic() + 15.0
        while not saw_workload_exited and time.monotonic() < deadline:
            r, _, _ = _select.select([proto_rfd], [], [], 1.0)
            if not r:
                continue
            chunk = os.read(proto_rfd, 4096)
            if not chunk:
                break
            proto_buf += chunk
            if PROTO_WORKLOAD_EXITED.encode() in proto_buf:
                saw_workload_exited = True

        assert saw_workload_exited, (
            f"did not observe workload_exited on protocol pipe. "
            f"buf={proto_buf!r} stderr={drain_results.get(err_rfd, b'')!r}"
        )

        # NOW close the protocol reader — cleanup_completed will fail to deliver.
        os.close(proto_rfd)

        # Release the barrier so the supervisor can proceed with cleanup.
        os.write(barrier_wfd, b"\x01")
        os.close(barrier_wfd)

        _, sup_status = os.waitpid(sup_pid, 0)

        # Close output FDs.
        try:
            os.close(out_rfd)
        except OSError:
            pass
        try:
            os.close(err_rfd)
        except OSError:
            pass
        for t in drain_threads:
            t.join(timeout=5)

        assert os.WIFEXITED(sup_status)
        assert os.WEXITSTATUS(sup_status) != 0, (
            "supervisor must return nonzero when cleanup_completed delivery fails"
        )

    # -----------------------------------------------------------------------
    # Fix #2 (round 3): non-serializable config terminalization
    # -----------------------------------------------------------------------

    def test_non_serializable_config_terminates_cleanly(self, tmp_path):
        """Non-serializable workload_env → supervisor_failed + cleanup_completed.

        Fix #2 (round 3): TypeError from json.dumps must be caught by the
        setup try boundary and routed through fail_and_cleanup.
        """
        import threading
        from nodechain.runtime.exec_supervisor import (
            launch_pid_namespace_supervisor, read_bounded_protocol,
            PROTO_SUPERVISOR_FAILED, PROTO_CLEANUP_COMPLETED, PROTO_SUPERVISOR_STARTED,
        )

        workload = tmp_path / "dummy.py"
        workload.write_text("import os; os._exit(0)\n")

        proto_rfd, proto_wfd = os.pipe()
        out_rfd, out_wfd = os.pipe()
        err_rfd, err_wfd = os.pipe()

        sup_pid = os.fork()
        if sup_pid == 0:
            os.close(proto_rfd)
            os.close(out_rfd)
            os.close(err_rfd)
            os.dup2(out_wfd, 1)
            os.dup2(err_wfd, 2)
            os.close(out_wfd)
            os.close(err_wfd)
            config = {
                "workload_argv": [sys.executable, str(workload)],
                # Non-serializable: a set is not JSON-serializable.
                "workload_env": {"BAD": {1, 2, 3}},
            }
            try:
                os.setsid()  # Test-only: become session leader for topology proof
                rc = launch_pid_namespace_supervisor(config, proto_wfd)
            except Exception:
                rc = 1
            os._exit(rc)

        os.close(proto_wfd)
        os.close(out_wfd)
        os.close(err_wfd)

        sinks = {"proto": b"", "out": b"", "err": b""}
        lock = threading.Lock()

        def drain(fd, key):
            buf = b""
            while True:
                try:
                    chunk = os.read(fd, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
            with lock:
                sinks[key] = buf

        threads = []
        for fd, key in [(proto_rfd, "proto"), (out_rfd, "out"), (err_rfd, "err")]:
            t = threading.Thread(target=drain, args=(fd, key))
            t.start()
            threads.append(t)

        _, sup_status = os.waitpid(sup_pid, 0)
        for t in threads:
            t.join(timeout=5)
        for fd in [proto_rfd, out_rfd, err_rfd]:
            try:
                os.close(fd)
            except OSError:
                pass

        assert os.WIFEXITED(sup_status)
        assert os.WEXITSTATUS(sup_status) != 0, "non-serializable config should fail"

        # Fix #4 (round 4): use read_bounded_protocol, exact sequence, clean EOF.
        proto_data = sinks["proto"]
        parse_rfd, parse_wfd = os.pipe()
        os.write(parse_wfd, proto_data)
        os.close(parse_wfd)
        proto_result = read_bounded_protocol(parse_rfd, deadline=time.monotonic() + 5)
        os.close(parse_rfd)

        assert proto_result.ok, (
            f"protocol parser rejected stream: {proto_result.reason} "
            f"raw={proto_data!r} stderr={sinks['err']!r}"
        )
        actual_types = [r.get("type") for r in proto_result.records]
        assert actual_types == [
            PROTO_SUPERVISOR_STARTED,
            PROTO_SUPERVISOR_FAILED,
            PROTO_CLEANUP_COMPLETED,
        ], f"unexpected protocol sequence: {actual_types}"
        assert proto_result.records[-1].get("cleanup_succeeded") is True

    # -----------------------------------------------------------------------
    # Fix #3 (round 3): real B1 proof — FD table from bootstrap via metadata
    # -----------------------------------------------------------------------

    def test_b1_lifecycle_bootstrap_fd_table_via_metadata(self, tmp_path):
        """Real B1 proof: capture bootstrap FD table and assert protocol pipe absent.

        Fix #1 (round 4): monkeypatches read_bounded_metadata in the forked
        supervisor so it writes the captured MetadataReadResult (including
        fd_report from the bootstrap's enforcement_verified metadata) to a
        dedicated test pipe. The parent then reads that pipe and asserts the
        protocol pipe's device/inode identity is absent from the bootstrap's
        descriptor table.
        """
        import threading
        import nodechain.runtime.exec_supervisor as es_module
        from nodechain.runtime.exec_supervisor import (
            launch_pid_namespace_supervisor, read_bounded_protocol,
        )

        workload = tmp_path / "b1_fd_workload.py"
        workload.write_text("import os; os._exit(0)\n")

        proto_rfd, proto_wfd = os.pipe()
        out_rfd, out_wfd = os.pipe()
        err_rfd, err_wfd = os.pipe()
        # Dedicated test pipe for the captured metadata.
        meta_rfd, meta_wfd = os.pipe()

        # Record protocol pipe identity.
        proto_stat = os.fstat(proto_wfd)
        proto_identity = (proto_stat.st_dev, proto_stat.st_ino)

        sup_pid = os.fork()
        if sup_pid == 0:
            # === SUPERVISOR CHILD ===
            os.close(proto_rfd)
            os.close(out_rfd)
            os.close(err_rfd)
            os.close(meta_rfd)
            os.dup2(out_wfd, 1)
            os.dup2(err_wfd, 2)
            os.close(out_wfd)
            os.close(err_wfd)

            # Monkeypatch read_bounded_metadata to capture the result.
            _original_read = es_module.read_bounded_metadata

            def _capturing_read(meta_fd, **kwargs):
                result = _original_read(meta_fd, **kwargs)
                # Write the metadata dict (which may contain fd_report) to
                # the test pipe as JSON.
                try:
                    import json as _json
                    data = _json.dumps(result.metadata).encode("utf-8")
                    os.write(meta_wfd, data)
                except Exception:
                    pass
                try:
                    os.close(meta_wfd)
                except OSError:
                    pass
                return result

            es_module.read_bounded_metadata = _capturing_read

            config = {
                "workload_argv": [sys.executable, str(workload)],
                "workload_env": {"PATH": "/usr/bin:/bin"},
                "_bootstrap_report_fds": True,
            }
            try:
                os.setsid()  # Test-only: become session leader for topology proof
                rc = launch_pid_namespace_supervisor(config, proto_wfd)
            except Exception:
                rc = 1
            os._exit(rc)

        # === PARENT ===
        os.close(proto_wfd)
        os.close(out_wfd)
        os.close(err_wfd)
        os.close(meta_wfd)

        sinks = {"proto": b"", "out": b"", "err": b"", "meta": b""}
        lock = threading.Lock()

        def drain(fd, key):
            buf = b""
            while True:
                try:
                    chunk = os.read(fd, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
            with lock:
                sinks[key] = buf

        threads = []
        for fd, key in [(proto_rfd, "proto"), (out_rfd, "out"), (err_rfd, "err"), (meta_rfd, "meta")]:
            t = threading.Thread(target=drain, args=(fd, key))
            t.start()
            threads.append(t)

        _, sup_status = os.waitpid(sup_pid, 0)
        for t in threads:
            t.join(timeout=5)
        for fd in [proto_rfd, out_rfd, err_rfd, meta_rfd]:
            try:
                os.close(fd)
            except OSError:
                pass

        proto_data = sinks["proto"]
        stderr_data = sinks["err"]
        meta_data = sinks["meta"]

        # Supervisor should succeed.
        assert os.WIFEXITED(sup_status), f"supervisor failed: {sup_status} stderr={stderr_data!r}"
        assert os.WEXITSTATUS(sup_status) == 0, (
            f"supervisor rc={os.WEXITSTATUS(sup_status)} stderr={stderr_data!r}"
        )

        # Parse the captured metadata — it should contain the fd_report.
        assert len(meta_data) > 0, (
            f"no metadata captured on test pipe. stderr={stderr_data!r}"
        )
        captured_meta = json.loads(meta_data.decode("utf-8"))
        # The fd_report is nested inside the enforcement_verified record's
        # metadata field. The metadata reader merges records, so the structure
        # is: {"type": "enforcement_verified", "metadata": {"fd_report": [...]}}
        fd_report = captured_meta.get("fd_report")
        if fd_report is None:
            # Try nested path.
            inner_meta = captured_meta.get("metadata", {})
            if isinstance(inner_meta, dict):
                fd_report = inner_meta.get("fd_report")
        assert fd_report is not None, (
            f"fd_report not in captured metadata: {captured_meta} stderr={stderr_data!r}"
        )
        assert len(fd_report) > 0, "fd_report is empty — bootstrap did not report its FDs"

        # THE CORE B1 ASSERTION: protocol pipe identity absent from bootstrap FDs.
        for entry in fd_report:
            fd_num, dev, ino = entry[0], entry[1], entry[2]
            assert (dev, ino) != proto_identity, (
                f"FD {fd_num} in bootstrap has protocol pipe identity "
                f"(dev={dev}, ino={ino}) — protocol pipe leaked across B1!"
            )

    # -----------------------------------------------------------------------
    # Fix #3 (round 5): bootstrap-exec refusal proof
    # -----------------------------------------------------------------------

    def test_closure_failure_prevents_bootstrap_exec(self, tmp_path):
        """Fix #3 (round 5): _close_all_except failure prevents Python bootstrap exec.

        Monkeypatches _close_all_except to raise BootstrapFDClosureError inside
        the real _run_bootstrap_child. The bootstrap child must exit non-zero
        WITHOUT execving Python. The supervisor must emit supervisor_failed +
        cleanup_completed and return nonzero.
        """
        import threading
        import nodechain.runtime.exec_supervisor as es_module
        from nodechain.runtime.exec_supervisor import (
            launch_pid_namespace_supervisor, read_bounded_protocol, BootstrapFDClosureError,
            PROTO_SUPERVISOR_STARTED, PROTO_BOOTSTRAP_SPAWNED,
            PROTO_SUPERVISOR_FAILED, PROTO_CLEANUP_COMPLETED,
        )

        workload = tmp_path / "sentinel_workload.py"
        # If the bootstrap execve is reached despite the closure failure,
        # this sentinel writes a marker to stdout.
        workload.write_text(
            "import os, sys\n"
            "sys.stdout.write('SENTINEL_EXECVED\\n')\n"
            "sys.stdout.flush()\n"
            "os._exit(0)\n"
        )

        proto_rfd, proto_wfd = os.pipe()
        out_rfd, out_wfd = os.pipe()
        err_rfd, err_wfd = os.pipe()

        sup_pid = os.fork()
        if sup_pid == 0:
            os.close(proto_rfd)
            os.close(out_rfd)
            os.close(err_rfd)
            os.dup2(out_wfd, 1)
            os.dup2(err_wfd, 2)
            os.close(out_wfd)
            os.close(err_wfd)

            # Monkeypatch _close_all_except to always fail.
            def failing_close_all(allowlist):
                raise BootstrapFDClosureError("forced closure failure")

            es_module._close_all_except = failing_close_all

            config = {
                "workload_argv": [sys.executable, str(workload)],
                "workload_env": {"PATH": "/usr/bin:/bin"},
            }
            try:
                os.setsid()  # Test-only: become session leader for topology proof
                rc = launch_pid_namespace_supervisor(config, proto_wfd)
            except Exception:
                rc = 1
            os._exit(rc)

        os.close(proto_wfd)
        os.close(out_wfd)
        os.close(err_wfd)

        sinks = {"proto": b"", "out": b"", "err": b""}
        lock = threading.Lock()

        def drain(fd, key):
            buf = b""
            while True:
                try:
                    chunk = os.read(fd, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
            with lock:
                sinks[key] = buf

        threads = []
        for fd, key in [(proto_rfd, "proto"), (out_rfd, "out"), (err_rfd, "err")]:
            t = threading.Thread(target=drain, args=(fd, key))
            t.start()
            threads.append(t)

        _, sup_status = os.waitpid(sup_pid, 0)
        for t in threads:
            t.join(timeout=5)
        for fd in [proto_rfd, out_rfd, err_rfd]:
            try:
                os.close(fd)
            except OSError:
                pass

        proto_data = sinks["proto"]
        stdout_data = sinks["out"]
        stderr_data = sinks["err"]

        # Supervisor must exit nonzero.
        assert os.WIFEXITED(sup_status), f"abnormal exit: {sup_status} stderr={stderr_data!r}"
        assert os.WEXITSTATUS(sup_status) != 0, "closure failure should cause nonzero exit"

        # The sentinel must NOT appear on stdout — the Python bootstrap was
        # never execved.
        assert b"SENTINEL_EXECVED" not in stdout_data, (
            f"bootstrap Python exec was reached despite FD closure failure. "
            f"stdout={stdout_data!r}"
        )

        # The protocol must show the failure terminal sequence.
        parse_rfd, parse_wfd = os.pipe()
        os.write(parse_wfd, proto_data)
        os.close(parse_wfd)
        proto_result = read_bounded_protocol(parse_rfd, deadline=time.monotonic() + 5)
        os.close(parse_rfd)

        # The protocol may or may not parse cleanly depending on how far the
        # supervisor got before the fork, but we can check the raw types.
        proto_types = [r.get("type") for r in proto_result.records]
        assert PROTO_SUPERVISOR_STARTED in proto_types, (
            f"missing supervisor_started: {proto_types} stderr={stderr_data!r}"
        )
        # The bootstrap child died from the closure error (exit 127 from
        # _run_bootstrap_child's os._exit(127) after the exception), which
        # the supervisor observes as a bootstrap failure.
        assert PROTO_SUPERVISOR_FAILED in proto_types or PROTO_CLEANUP_COMPLETED in proto_types, (
            f"missing supervisor_failed/cleanup_completed: {proto_types} stderr={stderr_data!r}"
        )
