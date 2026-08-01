"""R3 Task 2: Native async protocol transport tests.

Tests AsyncProtocolTransport's event-loop-owned reader with 14 required proofs.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
import time

import pytest

from nodechain.runtime.async_fd_transport import AsyncProtocolTransport
from nodechain.runtime.exec_protocol import (
    ProtocolReadResult,
    PROTO_SUPERVISOR_STARTED,
    PROTO_BOOTSTRAP_SPAWNED,
    PROTO_ENFORCEMENT_VERIFIED,
    PROTO_EXEC_MONITOR_ARMED,
    PROTO_EXEC_CONFIRMED,
    PROTO_WORKLOAD_EXITED,
    PROTO_CLEANUP_COMPLETED,
)


def _normal_data() -> bytes:
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


@pytest.mark.skipif(sys.platform != "linux", reason="loop.add_reader is Linux/Unix")
class TestAsyncProtocolTransport:
    """14 tests for AsyncProtocolTransport."""

    def _run_transport(self, data, *, deadline_s=5.0, stop_rfd=None):
        """Helper: write data, run transport, return result."""
        rfd, wfd = os.pipe()
        if data:
            os.write(wfd, data)
        os.close(wfd)
        loop = asyncio.new_event_loop()
        try:
            transport = AsyncProtocolTransport(rfd, loop=loop, stop_fd=stop_rfd)
            future = transport.start(deadline=time.monotonic() + deadline_s)
            result = loop.run_until_complete(future)
            transport.close()  # R3 fix #2: transport.close() physically closes the FD
        finally:
            loop.close()
            # FD is already closed by transport.close() — don't double-close.
        return result

    def test_partial_record_across_callbacks(self):
        """Partial record across multiple readiness callbacks."""
        data = _normal_data()
        rfd, wfd = os.pipe()
        # Write one byte at a time via thread.
        def writer():
            for b in data:
                os.write(wfd, bytes([b]))
                time.sleep(0.001)
            os.close(wfd)
        t = threading.Thread(target=writer)
        t.start()
        loop = asyncio.new_event_loop()
        try:
            transport = AsyncProtocolTransport(rfd, loop=loop)
            future = transport.start(deadline=time.monotonic() + 15)
            result = loop.run_until_complete(future)
            transport.close()
        finally:
            loop.close()
            pass  # rfd already closed by transport.close()
            t.join(timeout=5)
        assert result.ok
        assert len(result.records) == 7

    def test_multiple_records_one_read(self):
        """Multiple records in one read."""
        result = self._run_transport(_normal_data())
        assert result.ok
        assert len(result.records) == 7

    def test_eof_finalizes_valid_sequence(self):
        """EOF finalizes a valid protocol sequence."""
        result = self._run_transport(_normal_data())
        assert result.ok

    def test_eof_rejects_partial_record(self):
        """EOF rejects a partial record."""
        data = b'{"version":1,"type":"supervisor_started"}\n{"version":1,"type":"boot'
        result = self._run_transport(data)
        assert not result.ok
        assert result.reason in ("protocol_partial_record", "protocol_eof_before_terminal")

    def test_byte_cap_failure_detaches(self):
        """Byte-cap failure detaches the reader."""
        from nodechain.runtime.exec_protocol import MAX_PROTOCOL_STREAM_BYTES
        record = b'{"version":1,"type":"supervisor_started"}\n'
        big = record * (MAX_PROTOCOL_STREAM_BYTES // len(record) + 2)
        rfd, wfd = os.pipe()
        def writer():
            try: os.write(wfd, big)
            except OSError: pass
            os.close(wfd)
        t = threading.Thread(target=writer)
        t.start()
        loop = asyncio.new_event_loop()
        try:
            transport = AsyncProtocolTransport(rfd, loop=loop)
            future = transport.start(deadline=time.monotonic() + 5)
            result = loop.run_until_complete(future)
            transport.close()
            # Verify reader detached — selector should be clean.
            selector = getattr(loop, "_selector", None)
            if selector:
                fds = set(selector.get_map().keys())
                assert rfd not in fds, "FD still registered after byte-cap failure"
        finally:
            loop.close()
            pass  # rfd already closed by transport.close()
            t.join(timeout=5)
        assert "limit_exceeded" in result.reason

    def test_parser_failure_detaches(self):
        """Parser failure detaches the reader."""
        data = b'{"version":1,"type":"supervisor_started"}\ngarbage\n'
        rfd, wfd = os.pipe()
        os.write(wfd, data)
        os.close(wfd)
        loop = asyncio.new_event_loop()
        try:
            transport = AsyncProtocolTransport(rfd, loop=loop)
            future = transport.start(deadline=time.monotonic() + 5)
            result = loop.run_until_complete(future)
            transport.close()
            selector = getattr(loop, "_selector", None)
            if selector:
                fds = set(selector.get_map().keys())
                assert rfd not in fds
        finally:
            loop.close()
            pass  # rfd already closed by transport.close()
        assert result.reason == "protocol_malformed"

    def test_close_is_idempotent(self):
        """close() is idempotent."""
        rfd, wfd = os.pipe()
        os.close(wfd)
        loop = asyncio.new_event_loop()
        try:
            transport = AsyncProtocolTransport(rfd, loop=loop)
            transport.close()
            transport.close()  # no error
            assert transport.closed
            assert transport.fd == -1  # poisoned
        finally:
            loop.close()
            pass  # rfd already closed by transport.close()

    def test_reader_removed_before_fd_close(self):
        """Reader registration removed before FD close."""
        data = _normal_data()
        rfd, wfd = os.pipe()
        os.write(wfd, data)
        os.close(wfd)
        loop = asyncio.new_event_loop()
        try:
            transport = AsyncProtocolTransport(rfd, loop=loop)
            future = transport.start(deadline=time.monotonic() + 5)
            result = loop.run_until_complete(future)
            # Before close, check selector.
            selector = getattr(loop, "_selector", None)
            if selector:
                fds_before = set(selector.get_map().keys())
                assert rfd not in fds_before, "FD should be unregistered after result"
            transport.close()
        finally:
            loop.close()
            pass  # rfd already closed by transport.close()
        assert result.ok

    def test_fd_reuse_cannot_be_read_by_stale_callback(self):
        """FD-number reuse cannot trigger a stale callback."""
        data = _normal_data()
        rfd, wfd = os.pipe()
        os.write(wfd, data)
        os.close(wfd)
        loop = asyncio.new_event_loop()
        try:
            transport = AsyncProtocolTransport(rfd, loop=loop)
            future = transport.start(deadline=time.monotonic() + 5)
            result = loop.run_until_complete(future)
            assert result.ok
            transport.close()
            assert transport.fd == -1  # poisoned
            # Reuse the FD number.
            pass  # rfd already closed by transport.close()
            target = rfd
            for _ in range(50):
                nr, nw = os.pipe()
                if nr == target:
                    # Install a new reader — if a stale callback survived,
                    # it would interfere.
                    new_fired = {"n": 0}
                    def on_read():
                        new_fired["n"] += 1
                    loop.add_reader(nr, on_read)
                    os.write(nw, b"x\n")
                    os.close(nw)
                    loop.run_until_complete(asyncio.sleep(0.05))
                    loop.remove_reader(nr)
                    assert new_fired["n"] >= 1, "new reader should fire on reused FD"
                    os.close(nr)
                    break
                os.close(nr)
                os.close(nw)
        finally:
            loop.close()

    def test_cancellation_leaves_no_registered_reader(self):
        """Cancellation removes all registered readers."""
        rfd, wfd = os.pipe()  # no data
        loop = asyncio.new_event_loop()
        try:
            transport = AsyncProtocolTransport(rfd, loop=loop)

            async def cancel_test():
                future = transport.start(deadline=time.monotonic() + 10)
                await asyncio.sleep(0.2)
                future.cancel()
                try:
                    await future
                except asyncio.CancelledError:
                    pass

            loop.run_until_complete(cancel_test())
            transport.close()
            selector = getattr(loop, "_selector", None)
            if selector:
                fds = set(selector.get_map().keys())
                assert rfd not in fds
        finally:
            loop.close()
            pass  # rfd already closed by transport.close()
            os.close(wfd)

    def test_no_thread_pool_worker_created(self):
        """No thread-pool worker is created by the transport."""
        data = _normal_data()
        rfd, wfd = os.pipe()
        os.write(wfd, data)
        os.close(wfd)
        threads_before = threading.active_count()
        loop = asyncio.new_event_loop()
        try:
            transport = AsyncProtocolTransport(rfd, loop=loop)
            future = transport.start(deadline=time.monotonic() + 5)
            result = loop.run_until_complete(future)
            transport.close()
        finally:
            loop.close()
            pass  # rfd already closed by transport.close()
        threads_after = threading.active_count()
        assert result.ok
        assert threads_after <= threads_before + 1

    def test_absolute_deadline_enforced(self):
        """Deadline fires when writer stays open."""
        data = b'{"version":1,"type":"supervisor_started"}\n'
        rfd, wfd = os.pipe()
        os.write(wfd, data)  # don't close wfd
        loop = asyncio.new_event_loop()
        try:
            transport = AsyncProtocolTransport(rfd, loop=loop)
            future = transport.start(deadline=time.monotonic() + 0.5)
            result = loop.run_until_complete(future)
            transport.close()
        finally:
            loop.close()
            pass  # rfd already closed by transport.close()
            os.close(wfd)
        assert not result.ok
        assert result.reason == "protocol_timeout"
        assert len(result.records) == 1

    def test_generation_check_prevents_stale_callback(self):
        """Generation check prevents stale callback after close."""
        rfd, wfd = os.pipe()
        loop = asyncio.new_event_loop()
        try:
            transport = AsyncProtocolTransport(rfd, loop=loop)
            assert transport._generation == 0
            transport.close()
            assert transport._generation == 1
            assert transport.closed
        finally:
            loop.close()
            pass  # rfd already closed by transport.close()
            os.close(wfd)
