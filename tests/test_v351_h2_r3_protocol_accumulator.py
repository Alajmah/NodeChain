"""R3 Task 1: Pure protocol accumulator tests.

Tests the ProtocolAccumulator interface (re-exported from R1's
_ProtocolStreamParser) as a pure state machine with no I/O dependencies.
"""

from __future__ import annotations

import json

import pytest

from nodechain.runtime.exec_protocol import (
    ProtocolAccumulator,
    ProtocolReadResult,
    PROTO_SUPERVISOR_STARTED,
    PROTO_BOOTSTRAP_SPAWNED,
    PROTO_ENFORCEMENT_VERIFIED,
    PROTO_EXEC_MONITOR_ARMED,
    PROTO_EXEC_CONFIRMED,
    PROTO_WORKLOAD_EXITED,
    PROTO_CLEANUP_COMPLETED,
    PROTO_SUPERVISOR_FAILED,
    MAX_PROTOCOL_STREAM_BYTES,
)


def _normal_stream() -> bytes:
    records = [
        {"version": 1, "type": PROTO_SUPERVISOR_STARTED},
        {"version": 1, "type": PROTO_BOOTSTRAP_SPAWNED, "pid": 123},
        {"version": 1, "type": PROTO_ENFORCEMENT_VERIFIED},
        {"version": 1, "type": PROTO_EXEC_MONITOR_ARMED},
        {"version": 1, "type": PROTO_EXEC_CONFIRMED},
        {"version": 1, "type": PROTO_WORKLOAD_EXITED, "started": True, "exit_code": 0},
        {"version": 1, "type": PROTO_CLEANUP_COMPLETED, "cleanup_succeeded": True},
    ]
    return b"".join(json.dumps(r).encode() + b"\n" for r in records)


class TestProtocolAccumulator:
    """Pure protocol accumulator tests (no I/O, no FD, no async)."""

    def test_no_fd_no_async_no_io(self):
        """The accumulator owns no FD, event loop, timeout, or task."""
        acc = ProtocolAccumulator()
        assert not hasattr(acc, "_fd") or getattr(acc, "_fd", None) is None
        assert not hasattr(acc, "_loop")

    def test_feed_returns_none_until_terminal(self):
        """feed() returns None until a terminal result is reached."""
        acc = ProtocolAccumulator()
        data = _normal_stream()
        # Feed all records.
        result = acc.feed(data)
        # After all records including cleanup_completed, feed returns None
        # because the terminal is "seen" but EOF hasn't been processed.
        assert result is None

    def test_feed_eof_returns_terminal_result(self):
        """feed_eof() returns the final ProtocolReadResult."""
        acc = ProtocolAccumulator()
        acc.feed(_normal_stream())
        result = acc.feed_eof()
        assert isinstance(result, ProtocolReadResult)
        assert result.ok
        assert len(result.records) == 7

    def test_byte_cap_enforced(self):
        """Byte-cap violation returns protocol_limit_exceeded."""
        acc = ProtocolAccumulator(max_bytes=50)
        result = acc.feed(b'{"version":1,"type":"supervisor_started"}\n')
        assert result is None  # under limit
        result = acc.feed(b'{"version":1,"type":"bootstrap_spawned","pid":1}\n')
        assert result is not None
        assert result.reason == "protocol_limit_exceeded"

    def test_malformed_json(self):
        """Malformed JSON returns protocol_malformed."""
        acc = ProtocolAccumulator()
        acc.feed(b'{"version":1,"type":"supervisor_started"}\n')
        result = acc.feed(b"garbage\n")
        assert result is not None
        assert result.reason == "protocol_malformed"

    def test_duplicate_keys_rejected(self):
        """Duplicate JSON keys are rejected."""
        acc = ProtocolAccumulator()
        result = acc.feed(b'{"version":1,"type":"supervisor_started","type":"x"}\n')
        assert result is not None
        assert result.reason == "protocol_duplicate_key"

    def test_unknown_type_rejected(self):
        """Unknown record type is rejected."""
        acc = ProtocolAccumulator()
        acc.feed(b'{"version":1,"type":"supervisor_started"}\n')
        result = acc.feed(b'{"version":1,"type":"bogus"}\n')
        assert result.reason == "protocol_unknown_type"

    def test_invalid_transition_rejected(self):
        """Invalid state transition is rejected."""
        acc = ProtocolAccumulator()
        acc.feed(b'{"version":1,"type":"supervisor_started"}\n')
        result = acc.feed(b'{"version":1,"type":"exec_confirmed"}\n')
        assert result.reason == "protocol_invalid_transition"

    def test_failure_terminal_branch(self):
        """Supervisor failure branch reaches terminal correctly."""
        acc = ProtocolAccumulator()
        acc.feed(b'{"version":1,"type":"supervisor_started"}\n')
        acc.feed(b'{"version":1,"type":"supervisor_failed","reason":"test"}\n')
        acc.feed(b'{"version":1,"type":"cleanup_completed","cleanup_succeeded":true}\n')
        result = acc.feed_eof()
        assert result.ok  # well-formed failure branch

    def test_cleanup_failure_at_eof(self):
        """cleanup_succeeded=False → protocol_cleanup_failed at EOF."""
        acc = ProtocolAccumulator()
        acc.feed(b'{"version":1,"type":"supervisor_started"}\n')
        acc.feed(b'{"version":1,"type":"supervisor_failed","reason":"x"}\n')
        acc.feed(b'{"version":1,"type":"cleanup_completed","cleanup_succeeded":false}\n')
        result = acc.feed_eof()
        assert not result.ok
        assert result.reason == "protocol_cleanup_failed"

    def test_data_after_cleanup_rejected(self):
        """Residual bytes after cleanup → protocol_data_after_cleanup."""
        acc = ProtocolAccumulator()
        acc.feed(_normal_stream())
        acc.feed(b"extra_bytes")  # no newline
        result = acc.feed_eof()
        assert not result.ok
        assert result.reason == "protocol_data_after_cleanup"

    def test_eof_before_terminal(self):
        """EOF before cleanup → protocol_eof_before_terminal."""
        acc = ProtocolAccumulator()
        acc.feed(b'{"version":1,"type":"supervisor_started"}\n')
        result = acc.feed_eof()
        assert not result.ok
        assert result.reason == "protocol_eof_before_terminal"

    def test_on_deadline_before_terminal(self):
        """Deadline before terminal → protocol_timeout."""
        acc = ProtocolAccumulator()
        acc.feed(b'{"version":1,"type":"supervisor_started"}\n')
        result = acc.on_deadline()
        assert not result.ok
        assert result.reason == "protocol_timeout"

    def test_on_deadline_after_cleanup(self):
        """Deadline after cleanup → protocol_no_eof_after_cleanup."""
        acc = ProtocolAccumulator()
        acc.feed(_normal_stream())
        result = acc.on_deadline()
        assert not result.ok
        assert result.reason == "protocol_no_eof_after_cleanup"

    def test_on_stop_preserves_records(self):
        """Stop preserves parsed records and byte count."""
        acc = ProtocolAccumulator()
        half = _normal_stream()[:len(_normal_stream()) // 2]
        acc.feed(half)
        result = acc.on_stop()
        assert not result.ok
        assert result.reason == "protocol_stopped"
        assert len(result.records) >= 1

    def test_terminal_seen_property(self):
        """terminal_seen is True after cleanup_completed."""
        acc = ProtocolAccumulator()
        assert not acc.terminal_seen
        acc.feed(_normal_stream())
        assert acc.terminal_seen

    def test_records_property(self):
        """records property returns a copy of the records list."""
        acc = ProtocolAccumulator()
        acc.feed(b'{"version":1,"type":"supervisor_started"}\n')
        records = acc.records
        assert len(records) == 1
        assert records[0]["type"] == "supervisor_started"
        # Mutating the returned list must not affect the accumulator.
        records.clear()
        assert len(acc.records) == 1

    def test_bytes_read_property(self):
        """bytes_read tracks total bytes consumed."""
        acc = ProtocolAccumulator()
        data = b'{"version":1,"type":"supervisor_started"}\n'
        acc.feed(data)
        assert acc.bytes_read == len(data)
