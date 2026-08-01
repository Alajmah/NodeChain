"""R1 direct parser tests for _ProtocolStreamParser.

Tests the pure incremental parser interface directly — not through
read_bounded_protocol's synchronous I/O driver. Proves chunk-boundary
independence, terminal EOF variants, deadline/stop state, and immediate
parser failure with exact reason strings and retained evidence.
"""

from __future__ import annotations

import json

import pytest

from nodechain.runtime.exec_supervisor import (
    _ProtocolStreamParser,
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


def _normal_stream() -> bytes:
    """A valid normal-terminal protocol stream."""
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


def _failure_stream() -> bytes:
    """A valid failure-terminal protocol stream."""
    records = [
        {"version": 1, "type": PROTO_SUPERVISOR_STARTED},
        {"version": 1, "type": PROTO_BOOTSTRAP_SPAWNED, "pid": 1},
        {"version": 1, "type": PROTO_SUPERVISOR_FAILED, "reason": "test"},
        {"version": 1, "type": PROTO_CLEANUP_COMPLETED, "cleanup_succeeded": True},
    ]
    return b"".join(json.dumps(r).encode() + b"\n" for r in records)


class TestProtocolStreamParser:
    """Direct tests for _ProtocolStreamParser (R1 acceptance)."""

    # ------------------------------------------------------------------
    # 1. Incremental valid stream
    # ------------------------------------------------------------------

    def test_incremental_one_byte_at_a_time(self):
        """Feed valid stream one byte at a time; feed() stays nonterminal until EOF."""
        data = _normal_stream()
        parser = _ProtocolStreamParser()
        for i in range(len(data)):
            result = parser.feed(data[i:i + 1])
            assert result is None, (
                f"feed() returned terminal at byte {i}: {result}"
            )
        eof_result = parser.feed_eof()
        assert eof_result.ok, f"expected ok=True, got reason={eof_result.reason}"
        assert len(eof_result.records) == 7
        assert eof_result.bytes_read == len(data)

    def test_incremental_irregular_chunks(self):
        """Feed valid stream in irregular chunk sizes."""
        data = _normal_stream()
        parser = _ProtocolStreamParser()
        chunk_sizes = [1, 5, 3, 10, 2, 7, 1, 1, 20, 4]
        pos = 0
        for size in chunk_sizes:
            chunk = data[pos:pos + size]
            if not chunk:
                break
            result = parser.feed(chunk)
            assert result is None, f"feed() returned terminal: {result}"
            pos += size
        # Feed remaining
        if pos < len(data):
            result = parser.feed(data[pos:])
            assert result is None, f"feed() returned terminal on remainder: {result}"
        result = parser.feed_eof()
        assert result.ok
        assert len(result.records) == 7

    # ------------------------------------------------------------------
    # 2. Chunk-boundary independence — split records and newlines
    # ------------------------------------------------------------------

    def test_chunk_boundary_mid_json(self):
        """Split a JSON record in the middle across two chunks."""
        records = [
            {"version": 1, "type": PROTO_SUPERVISOR_STARTED},
            {"version": 1, "type": PROTO_BOOTSTRAP_SPAWNED, "pid": 1},
            {"version": 1, "type": PROTO_ENFORCEMENT_VERIFIED},
            {"version": 1, "type": PROTO_EXEC_MONITOR_ARMED},
            {"version": 1, "type": PROTO_EXEC_CONFIRMED},
            {"version": 1, "type": PROTO_WORKLOAD_EXITED, "started": True, "exit_code": 0},
            {"version": 1, "type": PROTO_CLEANUP_COMPLETED, "cleanup_succeeded": True},
        ]
        data = b"".join(json.dumps(r).encode() + b"\n" for r in records)
        # Split in the middle of the second record.
        mid = len(json.dumps(records[0]).encode()) + 1 + len(json.dumps(records[1]).encode()) // 2
        parser = _ProtocolStreamParser()
        parser.feed(data[:mid])
        parser.feed(data[mid:])
        result = parser.feed_eof()
        assert result.ok
        assert len(result.records) == 7

    def test_chunk_boundary_at_newline(self):
        """Split exactly at the newline delimiter."""
        data = _normal_stream()
        # Find the first newline.
        nl_idx = data.index(b"\n")
        parser = _ProtocolStreamParser()
        parser.feed(data[:nl_idx])  # first record without newline
        parser.feed(data[nl_idx:])  # newline + rest
        result = parser.feed_eof()
        assert result.ok
        assert len(result.records) == 7

    def test_multiple_records_in_one_chunk(self):
        """Feed all records in a single chunk."""
        data = _normal_stream()
        parser = _ProtocolStreamParser()
        result = parser.feed(data)
        # cleanup_completed makes it terminal_seen, but feed returns None
        # because EOF hasn't been processed yet.
        assert result is None, f"feed should return None before EOF: {result}"
        assert parser.terminal_seen
        result = parser.feed_eof()
        assert result.ok

    # ------------------------------------------------------------------
    # 3. Terminal EOF variants
    # ------------------------------------------------------------------

    def test_eof_residual_after_cleanup(self):
        """Residual bytes after cleanup_completed → protocol_data_after_cleanup at EOF."""
        data = _normal_stream()
        parser = _ProtocolStreamParser()
        parser.feed(data)
        assert parser.terminal_seen
        parser.feed(b"garbage_no_newline")  # added to buffer, no newline to trigger processing
        result = parser.feed_eof()
        assert not result.ok
        assert result.reason == "protocol_data_after_cleanup"

    def test_eof_cleanup_failed(self):
        """Failed cleanup at EOF → protocol_cleanup_failed."""
        records = [
            {"version": 1, "type": PROTO_SUPERVISOR_STARTED},
            {"version": 1, "type": PROTO_SUPERVISOR_FAILED, "reason": "x"},
            {"version": 1, "type": PROTO_CLEANUP_COMPLETED, "cleanup_succeeded": False, "reason": "reap"},
        ]
        data = b"".join(json.dumps(r).encode() + b"\n" for r in records)
        parser = _ProtocolStreamParser()
        parser.feed(data)
        assert parser.terminal_seen
        result = parser.feed_eof()
        assert not result.ok
        assert result.reason == "protocol_cleanup_failed"

    def test_eof_before_terminal(self):
        """EOF before any terminal → protocol_eof_before_terminal."""
        data = (
            json.dumps({"version": 1, "type": PROTO_SUPERVISOR_STARTED}).encode() + b"\n"
        )
        parser = _ProtocolStreamParser()
        parser.feed(data)
        result = parser.feed_eof()
        assert not result.ok
        assert result.reason == "protocol_eof_before_terminal"

    def test_eof_clean_after_terminal(self):
        """Clean EOF after terminal → ok=True."""
        data = _normal_stream()
        parser = _ProtocolStreamParser()
        parser.feed(data)
        result = parser.feed_eof()
        assert result.ok
        assert result.reason == "ok"

    # ------------------------------------------------------------------
    # 4. Deadline and stop state
    # ------------------------------------------------------------------

    def test_on_deadline_before_terminal(self):
        """Deadline before terminal → protocol_timeout."""
        parser = _ProtocolStreamParser()
        parser.feed(json.dumps({"version": 1, "type": PROTO_SUPERVISOR_STARTED}).encode() + b"\n")
        result = parser.on_deadline()
        assert not result.ok
        assert result.reason == "protocol_timeout"
        # Parsed records preserved.
        assert len(result.records) == 1

    def test_on_deadline_after_cleanup(self):
        """Deadline after cleanup but before EOF → protocol_no_eof_after_cleanup."""
        data = _normal_stream()
        parser = _ProtocolStreamParser()
        parser.feed(data)
        assert parser.terminal_seen
        result = parser.on_deadline()
        assert not result.ok
        assert result.reason == "protocol_no_eof_after_cleanup"
        assert len(result.records) == 7

    def test_on_stop_preserves_records(self):
        """Stop preserves already parsed records and byte count."""
        data = _normal_stream()
        half = len(data) // 2
        parser = _ProtocolStreamParser()
        parser.feed(data[:half])
        result = parser.on_stop()
        assert not result.ok
        assert result.reason == "protocol_stopped"
        # Records parsed so far are preserved.
        assert len(result.records) >= 1
        assert result.bytes_read == half

    # ------------------------------------------------------------------
    # 5. Immediate parser failure with exact reason and retained evidence
    # ------------------------------------------------------------------

    def test_malformed_json(self):
        """Malformed JSON returns protocol_malformed."""
        parser = _ProtocolStreamParser()
        result = parser.feed(b'{"version":1,"type":"supervisor_started"}\n')
        assert result is None  # valid first record
        result = parser.feed(b"garbage\n")
        assert result is not None
        assert not result.ok
        assert result.reason == "protocol_malformed"
        # First record preserved.
        assert len(result.records) == 1

    def test_invalid_transition(self):
        """Invalid transition returns protocol_invalid_transition."""
        parser = _ProtocolStreamParser()
        parser.feed(b'{"version":1,"type":"supervisor_started"}\n')
        result = parser.feed(b'{"version":1,"type":"exec_confirmed"}\n')
        assert result is not None
        assert not result.ok
        assert result.reason == "protocol_invalid_transition"

    def test_unknown_type(self):
        """Unknown type returns protocol_unknown_type."""
        parser = _ProtocolStreamParser()
        parser.feed(b'{"version":1,"type":"supervisor_started"}\n')
        result = parser.feed(b'{"version":1,"type":"bogus_type"}\n')
        assert result is not None
        assert not result.ok
        assert result.reason == "protocol_unknown_type"

    def test_byte_limit_exceeded(self):
        """Byte limit exceeded returns protocol_limit_exceeded."""
        parser = _ProtocolStreamParser(max_bytes=50)
        result = parser.feed(b'{"version":1,"type":"supervisor_started"}\n')
        assert result is None  # under limit
        result = parser.feed(b'{"version":1,"type":"bootstrap_spawned","pid":1}\n')
        assert result is not None
        assert not result.ok
        assert result.reason == "protocol_limit_exceeded"

    def test_duplicate_supervisor_started(self):
        """Duplicate supervisor_started returns protocol_duplicate_supervisor_started."""
        parser = _ProtocolStreamParser()
        parser.feed(b'{"version":1,"type":"supervisor_started"}\n')
        result = parser.feed(b'{"version":1,"type":"supervisor_started"}\n')
        assert result is not None
        assert not result.ok
        assert result.reason == "protocol_duplicate_supervisor_started"

    def test_invalid_initial_state(self):
        """First record not supervisor_started → protocol_invalid_initial_state."""
        parser = _ProtocolStreamParser()
        result = parser.feed(b'{"version":1,"type":"bootstrap_spawned","pid":1}\n')
        assert result is not None
        assert not result.ok
        assert result.reason == "protocol_invalid_initial_state"

    def test_failure_stream_preserved(self):
        """Failure-terminal stream records preserved in result."""
        data = _failure_stream()
        parser = _ProtocolStreamParser()
        parser.feed(data)
        result = parser.feed_eof()
        assert result.ok  # well-formed failure branch is valid
        types = [r.get("type") for r in result.records]
        assert types == [
            PROTO_SUPERVISOR_STARTED,
            PROTO_BOOTSTRAP_SPAWNED,
            PROTO_SUPERVISOR_FAILED,
            PROTO_CLEANUP_COMPLETED,
        ]
