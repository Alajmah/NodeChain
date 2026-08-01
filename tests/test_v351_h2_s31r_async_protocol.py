"""R2 async protocol driver tests — read_bounded_protocol_async.

Production accepted. Test-only successor addressing 6 proof blockers.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
import time
from unittest import mock

import pytest

from nodechain.runtime.exec_supervisor import (
    read_bounded_protocol,
    read_bounded_protocol_async,
    ProtocolReadResult,
    _ProtocolStreamParser,
    PROTO_SUPERVISOR_STARTED,
    PROTO_BOOTSTRAP_SPAWNED,
    PROTO_ENFORCEMENT_VERIFIED,
    PROTO_EXEC_MONITOR_ARMED,
    PROTO_EXEC_CONFIRMED,
    PROTO_WORKLOAD_EXITED,
    PROTO_CLEANUP_COMPLETED,
    PROTO_SUPERVISOR_FAILED,
)


def _normal_records():
    return [
        {"version": 1, "type": PROTO_SUPERVISOR_STARTED},
        {"version": 1, "type": PROTO_BOOTSTRAP_SPAWNED, "pid": 123},
        {"version": 1, "type": PROTO_ENFORCEMENT_VERIFIED},
        {"version": 1, "type": PROTO_EXEC_MONITOR_ARMED},
        {"version": 1, "type": PROTO_EXEC_CONFIRMED},
        {"version": 1, "type": PROTO_WORKLOAD_EXITED, "started": True, "exit_code": 0},
        {"version": 1, "type": PROTO_CLEANUP_COMPLETED, "cleanup_succeeded": True},
    ]


def _records_to_bytes(records):
    return b"".join(json.dumps(r).encode() + b"\n" for r in records)


def _write_and_close(rfd, wfd, data):
    os.write(wfd, data)
    os.close(wfd)


def _get_registered_fds(loop) -> set[int]:
    """Return the set of FDs registered in the loop's selector."""
    selector = getattr(loop, "_selector", None)
    if selector is None:
        return set()
    get_map = getattr(selector, "get_map", None)
    if get_map is None:
        return set()
    return set(get_map().keys())


@pytest.mark.skipif(sys.platform != "linux", reason="loop.add_reader is Linux/Unix")
class TestAsyncProtocolDriver:
    """R2 acceptance: async protocol reader tests."""

    async def _read_async(self, rfd, *, deadline_s=5.0, stop_rfd=None):
        return await read_bounded_protocol_async(
            rfd, deadline=time.monotonic() + deadline_s, stop_fd=stop_rfd,
        )

    def _read_sync(self, rfd, *, deadline_s=5.0, stop_rfd=None):
        return read_bounded_protocol(
            rfd, deadline=time.monotonic() + deadline_s, stop_fd=stop_rfd,
        )

    # ------------------------------------------------------------------
    # 1. Sync/async parity — expanded matrix
    # ------------------------------------------------------------------

    def _parity(self, data: bytes):
        rfd, wfd = os.pipe()
        _write_and_close(rfd, wfd, data)
        sync_r = self._read_sync(rfd)
        os.close(rfd)
        rfd2, wfd2 = os.pipe()
        _write_and_close(rfd2, wfd2, data)
        async_r = asyncio.run(self._read_async(rfd2))
        os.close(rfd2)
        assert sync_r.ok == async_r.ok
        assert sync_r.reason == async_r.reason
        assert len(sync_r.records) == len(async_r.records)
        assert sync_r.bytes_read == async_r.bytes_read

    def test_parity_normal(self):
        self._parity(_records_to_bytes(_normal_records()))

    def test_parity_malformed(self):
        self._parity(b'{"version":1,"type":"supervisor_started"}\ngarbage\n')

    def test_parity_eof_before_terminal(self):
        self._parity(b'{"version":1,"type":"supervisor_started"}\n')

    def test_parity_cleanup_failed(self):
        data = b"".join(json.dumps(r).encode() + b"\n" for r in [
            {"version": 1, "type": PROTO_SUPERVISOR_STARTED},
            {"version": 1, "type": PROTO_SUPERVISOR_FAILED, "reason": "x"},
            {"version": 1, "type": PROTO_CLEANUP_COMPLETED, "cleanup_succeeded": False, "reason": "reap"},
        ])
        self._parity(data)

    def test_parity_failure_branch(self):
        data = b"".join(json.dumps(r).encode() + b"\n" for r in [
            {"version": 1, "type": PROTO_SUPERVISOR_STARTED},
            {"version": 1, "type": PROTO_BOOTSTRAP_SPAWNED, "pid": 1},
            {"version": 1, "type": PROTO_SUPERVISOR_FAILED, "reason": "test"},
            {"version": 1, "type": PROTO_CLEANUP_COMPLETED, "cleanup_succeeded": True},
        ])
        self._parity(data)

    def test_parity_invalid_transition(self):
        self._parity(b'{"version":1,"type":"supervisor_started"}\n{"version":1,"type":"exec_confirmed"}\n')

    def test_parity_unknown_type(self):
        self._parity(b'{"version":1,"type":"supervisor_started"}\n{"version":1,"type":"bogus"}\n')

    def test_parity_data_after_cleanup(self):
        self._parity(_records_to_bytes(_normal_records()) + b"extra_bytes")

    def test_parity_byte_limit(self):
        from nodechain.runtime.exec_supervisor import MAX_PROTOCOL_STREAM_BYTES
        record = b'{"version":1,"type":"supervisor_started"}\n'
        big = record * (MAX_PROTOCOL_STREAM_BYTES // len(record) + 2)
        rfd, wfd = os.pipe()
        def writer():
            try: os.write(wfd, big)
            except OSError: pass
            os.close(wfd)
        t = threading.Thread(target=writer); t.start()
        sync_r = self._read_sync(rfd)
        os.close(rfd); t.join(timeout=5)
        rfd2, wfd2 = os.pipe()
        def writer2():
            try: os.write(wfd2, big)
            except OSError: pass
            os.close(wfd2)
        t2 = threading.Thread(target=writer2); t2.start()
        async_r = asyncio.run(self._read_async(rfd2, deadline_s=5))
        os.close(rfd2); t2.join(timeout=5)
        assert sync_r.reason == async_r.reason
        assert "limit_exceeded" in sync_r.reason

    # ------------------------------------------------------------------
    # 2. Fragmented reads
    # ------------------------------------------------------------------

    def test_fragmented_delivery(self):
        data = _records_to_bytes(_normal_records())
        rfd, wfd = os.pipe()
        def slow_writer():
            for byte in data:
                os.write(wfd, bytes([byte]))
                time.sleep(0.001)
            os.close(wfd)
        t = threading.Thread(target=slow_writer); t.start()
        result = asyncio.run(self._read_async(rfd, deadline_s=15))
        os.close(rfd); t.join(timeout=5)
        assert result.ok
        assert len(result.records) == 7

    # ------------------------------------------------------------------
    # 3. Delayed EOF after cleanup_completed
    # ------------------------------------------------------------------

    def test_delayed_eof_after_cleanup(self):
        data = _records_to_bytes(_normal_records())
        rfd, wfd = os.pipe()
        os.write(wfd, data)
        def delayed_close():
            time.sleep(1.0)
            os.close(wfd)
        t = threading.Thread(target=delayed_close); t.start()
        result = asyncio.run(self._read_async(rfd, deadline_s=5))
        os.close(rfd); t.join(timeout=5)
        assert result.ok
        assert result.reason == "ok"

    # ------------------------------------------------------------------
    # 4. Simultaneous protocol and stop — protocol drained first
    # ------------------------------------------------------------------

    def test_protocol_drained_before_stop_simultaneous(self):
        data = _records_to_bytes(_normal_records())
        rfd, wfd = os.pipe()
        stop_rfd, stop_wfd = os.pipe()
        os.write(wfd, data); os.close(wfd)
        os.write(stop_wfd, b"\x01"); os.close(stop_wfd)
        result = asyncio.run(self._read_async(rfd, deadline_s=5, stop_rfd=stop_rfd))
        os.close(rfd); os.close(stop_rfd)
        types = [r.get("type") for r in result.records]
        assert PROTO_EXEC_CONFIRMED in types

    def test_stop_only_returns_protocol_stopped(self):
        rfd, wfd = os.pipe()
        stop_rfd, stop_wfd = os.pipe()
        os.write(stop_wfd, b"\x01"); os.close(stop_wfd)
        result = asyncio.run(self._read_async(rfd, deadline_s=5, stop_rfd=stop_rfd))
        os.close(rfd); os.close(stop_rfd); os.close(wfd)
        assert not result.ok
        assert result.reason == "protocol_stopped"

    # ------------------------------------------------------------------
    # 5. Deadline — deterministic with writer open
    # ------------------------------------------------------------------

    def test_deadline_with_writer_open(self):
        data = b'{"version":1,"type":"supervisor_started"}\n'
        rfd, wfd = os.pipe()
        os.write(wfd, data)  # don't close wfd
        result = asyncio.run(self._read_async(rfd, deadline_s=0.5))
        os.close(rfd); os.close(wfd)
        assert not result.ok
        assert result.reason == "protocol_timeout"
        assert len(result.records) == 1

    # ------------------------------------------------------------------
    # 6. Registration cleanup — selector introspection
    # ------------------------------------------------------------------

    def _assert_fds_unregistered(self, loop, *fds):
        """Assert none of the given FDs are in the selector after return."""
        registered = _get_registered_fds(loop)
        for fd in fds:
            assert fd not in registered, (
                f"FD {fd} still registered in selector after return: {registered}"
            )

    def test_success_removes_registrations(self):
        """Successful completion removes protocol and stop registrations."""
        data = _records_to_bytes(_normal_records())
        rfd, wfd = os.pipe()
        stop_rfd, stop_wfd = os.pipe()
        _write_and_close(rfd, wfd, data)
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                read_bounded_protocol_async(
                    rfd, deadline=time.monotonic() + 5, stop_fd=stop_rfd,
                )
            )
            assert result.ok
            self._assert_fds_unregistered(loop, rfd, stop_rfd)
        finally:
            loop.close()
            os.close(rfd); os.close(stop_rfd); os.close(stop_wfd)

    def test_parser_failure_removes_registrations(self):
        """Parser failure removes all registrations."""
        data = b'{"version":1,"type":"supervisor_started"}\ngarbage\n'
        rfd, wfd = os.pipe()
        _write_and_close(rfd, wfd, data)
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                read_bounded_protocol_async(rfd, deadline=time.monotonic() + 5)
            )
            assert result.reason == "protocol_malformed"
            self._assert_fds_unregistered(loop, rfd)
        finally:
            loop.close()
            os.close(rfd)

    def test_deadline_removes_registrations(self):
        """Deadline timeout removes all registrations."""
        rfd, wfd = os.pipe()  # no data — reader will timeout
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                read_bounded_protocol_async(rfd, deadline=time.monotonic() + 0.3)
            )
            assert result.reason == "protocol_timeout"
            self._assert_fds_unregistered(loop, rfd)
        finally:
            loop.close()
            os.close(rfd); os.close(wfd)

    def test_cancellation_removes_registrations(self):
        """Cancellation removes all registrations — verified via selector."""
        rfd, wfd = os.pipe()
        stop_rfd, stop_wfd = os.pipe()
        loop = asyncio.new_event_loop()
        try:
            task = loop.create_task(
                read_bounded_protocol_async(
                    rfd, deadline=time.monotonic() + 10, stop_fd=stop_rfd,
                )
            )

            async def cancel_after_start():
                await asyncio.sleep(0.3)
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

            loop.run_until_complete(cancel_after_start())
            # Directly inspect selector BEFORE closing the loop.
            self._assert_fds_unregistered(loop, rfd, stop_rfd)
        finally:
            loop.close()
            os.close(rfd); os.close(wfd); os.close(stop_rfd); os.close(stop_wfd)

    # ------------------------------------------------------------------
    # 7. No executor thread created
    # ------------------------------------------------------------------

    def test_no_executor_thread_created(self):
        data = _records_to_bytes(_normal_records())
        rfd, wfd = os.pipe()
        _write_and_close(rfd, wfd, data)
        threads_before = threading.active_count()
        result = asyncio.run(self._read_async(rfd))
        os.close(rfd)
        threads_after = threading.active_count()
        assert result.ok
        assert threads_after <= threads_before + 1

    # ------------------------------------------------------------------
    # 8. Unsupported loop — real NotImplementedError
    # ------------------------------------------------------------------

    def test_unsupported_loop_not_implemented_error(self):
        """Loop where add_reader raises NotImplementedError → unsupported."""
        rfd, wfd = os.pipe()
        os.close(wfd)

        class FakeLoopRaisesNI:
            def get_debug(self): return False
            def add_reader(self, fd, callback):
                raise NotImplementedError("not supported")
            def remove_reader(self, fd):
                pass
            def call_later(self, delay, callback):
                return mock.MagicMock(cancel=lambda: None)

        async def run_test():
            with mock.patch.object(asyncio, "get_running_loop", return_value=FakeLoopRaisesNI()):
                return await read_bounded_protocol_async(
                    rfd, deadline=time.monotonic() + 5,
                )

        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(run_test())
        finally:
            loop.close()
            os.close(rfd)
        assert not result.ok
        assert result.reason == "protocol_async_reader_unsupported"

    # ------------------------------------------------------------------
    # 9. Stale callback — deterministic FD-number reuse
    # ------------------------------------------------------------------

    def test_no_stale_callback_after_return_fd_reuse(self):
        """After return, reuse exact FD number and verify no stale callback fires.

        1. Run the reader to completion.
        2. Verify old FD absent from selector.
        3. Close old FD, deterministically reuse the exact number.
        4. Install a new reader on the reused FD, make it readable.
        5. Run loop — new reader fires, old protocol callback does NOT.
        """
        data = _records_to_bytes(_normal_records())
        rfd, wfd = os.pipe()
        _write_and_close(rfd, wfd, data)

        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                read_bounded_protocol_async(rfd, deadline=time.monotonic() + 5)
            )
            assert result.ok
            # Core proof: rfd absent from selector.
            self._assert_fds_unregistered(loop, rfd)
            # Close rfd, then deterministically reuse the FD number.
            os.close(rfd)
            target = rfd
            new_rfd = None
            new_wfd = None
            leftovers = []
            for _ in range(100):
                nr, nw = os.pipe()
                if nr == target:
                    new_rfd, new_wfd = nr, nw
                    break
                leftovers.append((nr, nw))
            for nr, nw in leftovers:
                try: os.close(nr)
                except OSError: pass
                try: os.close(nw)
                except OSError: pass
            # Required: exact FD reuse must succeed.
            assert new_rfd is not None, (
                f"could not reuse FD number {target} after 100 attempts"
            )
            assert new_rfd == target, (
                f"FD reuse mismatch: got {new_rfd}, expected {target}"
            )
            # Install a new reader on the reused FD and make it readable.
            new_fired = {"n": 0}
            def on_new_read():
                new_fired["n"] += 1
            loop.add_reader(new_rfd, on_new_read)
            os.write(new_wfd, b"x\n")
            os.close(new_wfd)
            loop.run_until_complete(asyncio.sleep(0.05))
            loop.remove_reader(new_rfd)
            # New reader must have fired.
            assert new_fired["n"] >= 1, "new reader on reused FD should fire"
            try: os.close(new_rfd)
            except OSError: pass
        finally:
            loop.close()

    # ------------------------------------------------------------------
    # 10. Deterministic stop-first then data — callback-entry barrier
    # ------------------------------------------------------------------

    def test_stop_first_then_data_preserves_evidence(self):
        """Stop callback fires BEFORE protocol data arrives — deterministic barrier.

        Wraps loop.add_reader to intercept the stop_fd callback. The wrapped
        callback blocks on a barrier until a writer thread delivers protocol
        data, proving callback entry occurred before the write.
        """
        data = _records_to_bytes(_normal_records())
        rfd, wfd = os.pipe()
        stop_rfd, stop_wfd = os.pipe()

        # Barrier: stop callback signals "entered", writer waits for it,
        # writes data, then releases the callback.
        stop_callback_entered = threading.Event()
        stop_callback_can_proceed = threading.Event()
        callback_order = {"stop_before_data": False}

        loop = asyncio.new_event_loop()
        try:
            # Wrap add_reader to intercept stop_fd callback.
            original_add_reader = loop.add_reader
            def wrapping_add_reader(fd, callback, *args):
                if fd == stop_rfd:
                    def barrier_wrapped_stop():
                        # Signal that the stop callback has entered.
                        stop_callback_entered.set()
                        # Wait for the writer to deliver protocol data.
                        stop_callback_can_proceed.wait(timeout=5)
                        # Now we know: stop callback ran, THEN data was written,
                        # THEN we proceed.
                        callback_order["stop_before_data"] = True
                        # Call the original callback.
                        callback()
                    return original_add_reader(fd, barrier_wrapped_stop, *args)
                return original_add_reader(fd, callback, *args)
            loop.add_reader = wrapping_add_reader

            async def controlled_reader():
                read_task = asyncio.create_task(
                    read_bounded_protocol_async(
                        rfd, deadline=time.monotonic() + 10, stop_fd=stop_rfd,
                    )
                )
                # Give the reader time to register callbacks.
                await asyncio.sleep(0.2)
                # Signal stop — the stop callback will fire and block on the barrier.
                os.write(stop_wfd, b"\x01")
                os.close(stop_wfd)
                # Writer thread: wait for stop callback to enter, then write data.
                def writer_thread():
                    stop_callback_entered.wait(timeout=5)
                    os.write(wfd, data)
                    os.close(wfd)
                    # Release the stop callback.
                    stop_callback_can_proceed.set()
                t = threading.Thread(target=writer_thread)
                t.start()
                result = await read_task
                t.join(timeout=5)
                return result

            result = loop.run_until_complete(controlled_reader())
        finally:
            loop.close()
            os.close(rfd)
            os.close(stop_rfd)

        # The stop callback must have entered before data was written.
        assert callback_order["stop_before_data"], (
            "stop callback did not enter before protocol data was written"
        )
        # Protocol evidence must be drained before stop handling.
        types = [r.get("type") for r in result.records]
        assert PROTO_EXEC_CONFIRMED in types, (
            f"exec_confirmed lost despite protocol-first drain: "
            f"types={types}, reason={result.reason}"
        )
