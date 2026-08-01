"""R3 Task 2: Event-loop-owned protocol transport.

AsyncProtocolTransport wraps the accepted R2 read_bounded_protocol_async
into a class with explicit lifecycle management:
  - start() returns a Future[ProtocolReadResult]
  - detach() removes the loop registration before FD close
  - close() is idempotent and poisons the FD

FD-reuse protection: the callback carries an ownership generation check.
A delayed callback after close() cannot read from a newly-allocated FD
that reused the same integer.
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import Any

from nodechain.runtime.exec_protocol import (
    ProtocolAccumulator,
    ProtocolReadResult,
    MAX_PROTOCOL_STREAM_BYTES,
    MAX_PROTOCOL_RECORDS,
    MAX_PROTOCOL_RECORD_BYTES,
)


class AsyncProtocolTransport:
    """Event-loop-owned protocol reader using loop.add_reader().

    No thread, executor, or asyncio.to_thread.
    """

    def __init__(
        self,
        fd: int,
        *,
        loop: asyncio.AbstractEventLoop | None = None,
        max_bytes: int = MAX_PROTOCOL_STREAM_BYTES,
        max_records: int = MAX_PROTOCOL_RECORDS,
        max_record_bytes: int = MAX_PROTOCOL_RECORD_BYTES,
        stop_fd: int | None = None,
    ) -> None:
        self._fd = fd
        self._stop_fd = stop_fd
        self._loop = loop or asyncio.get_event_loop()
        self._max_bytes = max_bytes
        self._max_records = max_records
        self._max_record_bytes = max_record_bytes
        self._closed = False
        self._generation = 0  # increments on close, callbacks check this
        self._future: asyncio.Future[ProtocolReadResult] | None = None
        self._runner_task: asyncio.Task | None = None
        self._accumulator = ProtocolAccumulator(
            max_bytes=max_bytes, max_records=max_records, max_record_bytes=max_record_bytes,
        )
        # Readiness state.
        self._wake_event = asyncio.Event()
        self._protocol_ready = False
        self._stop_ready = False
        self._deadline_ready = False
        self._registered_fds: set[int] = set()
        self._deadline_handle: asyncio.TimerHandle | None = None

    def start(self, *, deadline: float) -> asyncio.Future[ProtocolReadResult]:
        """Start the transport. Returns a Future that resolves to the result."""
        if self._future is not None:
            raise RuntimeError("transport already started")
        self._future = self._loop.create_future()

        # Set nonblocking.
        try:
            os.set_blocking(self._fd, False)
        except OSError:
            pass
        if self._stop_fd is not None:
            try:
                os.set_blocking(self._stop_fd, False)
            except OSError:
                pass

        gen = self._generation

        def _on_protocol_ready():
            if self._closed or gen != self._generation:
                return  # stale callback
            self._protocol_ready = True
            try:
                self._loop.remove_reader(self._fd)
                self._registered_fds.discard(self._fd)
            except Exception:
                pass
            self._wake_event.set()

        def _on_stop_ready():
            if self._closed or gen != self._generation:
                return  # stale callback
            self._stop_ready = True
            try:
                self._loop.remove_reader(self._stop_fd)
                self._registered_fds.discard(self._stop_fd)
            except Exception:
                pass
            self._wake_event.set()

        def _on_deadline():
            if self._closed or gen != self._generation:
                return  # stale callback
            self._deadline_ready = True
            self._wake_event.set()

        self._on_protocol_ready = _on_protocol_ready
        self._on_stop_ready = _on_stop_ready
        self._on_deadline = _on_deadline

        # Register readers.
        try:
            self._loop.add_reader(self._fd, _on_protocol_ready)
            self._registered_fds.add(self._fd)
        except (OSError, NotImplementedError) as e:
            self._future.set_result(ProtocolReadResult(
                False, f"protocol_async_register_failed: {e}", [], 0))
            return self._future

        if self._stop_fd is not None:
            try:
                self._loop.add_reader(self._stop_fd, _on_stop_ready)
                self._registered_fds.add(self._stop_fd)
            except (OSError, NotImplementedError) as e:
                self._loop.remove_reader(self._fd)
                self._registered_fds.discard(self._fd)
                self._future.set_result(ProtocolReadResult(
                    False, f"protocol_async_register_failed: {e}", [], 0))
                return self._future

        # Deadline timer.
        delay = max(0.0, deadline - time.monotonic())
        self._deadline_handle = self._loop.call_later(delay, _on_deadline)

        # Start the coroutine — store the task so it can be terminalized.
        self._runner_task = self._loop.create_task(self._run())

        return self._future

    async def _run(self):
        """Main read loop — drains protocol FD on every wake."""
        try:
            while True:
                self._wake_event.clear()
                await self._wake_event.wait()

                # Clear flags.
                was_protocol = self._protocol_ready
                was_stop = self._stop_ready
                was_deadline = self._deadline_ready
                self._protocol_ready = False
                self._stop_ready = False
                self._deadline_ready = False

                # Unconditional protocol drain (INV-R4).
                result = self._drain_protocol()
                if result is not None:
                    if not self._future.done():
                        self._future.set_result(result)
                    return

                # Re-arm protocol reader (always, until EOF).
                reg_fail = self._rearm_protocol()
                if reg_fail is not None:
                    if not self._future.done():
                        self._future.set_result(reg_fail)
                    return

                # Check deadline.
                if was_deadline:
                    if not self._future.done():
                        self._future.set_result(self._accumulator.on_deadline())
                    return

                # Check stop (after protocol drain).
                if was_stop:
                    if not self._future.done():
                        self._future.set_result(self._accumulator.on_stop())
                    return

        except asyncio.CancelledError:
            if not self._future.done():
                self._future.set_result(ProtocolReadResult(
                    False, "protocol_cancelled", self._accumulator.records,
                    self._accumulator.bytes_read))
            raise
        finally:
            self._cleanup_registrations()

    def _drain_protocol(self) -> ProtocolReadResult | None:
        """Drain protocol FD to EAGAIN/EOF."""
        while True:
            try:
                chunk = os.read(self._fd, 65536)
            except BlockingIOError:
                break
            except InterruptedError:
                continue
            except OSError as e:
                return ProtocolReadResult(
                    False, f"protocol_read_error: {e}",
                    self._accumulator.records, self._accumulator.bytes_read)
            if not chunk:
                return self._accumulator.feed_eof()
            result = self._accumulator.feed(chunk)
            if result is not None:
                return result
        return None

    def _rearm_protocol(self) -> ProtocolReadResult | None:
        """Re-register protocol FD reader."""
        try:
            self._loop.add_reader(self._fd, self._on_protocol_ready)
            self._registered_fds.add(self._fd)
        except (OSError, NotImplementedError) as e:
            return ProtocolReadResult(
                False, f"protocol_async_reregister_failed: {e}",
                self._accumulator.records, self._accumulator.bytes_read)
        return None

    def _cleanup_registrations(self):
        """Remove all reader registrations and cancel timer."""
        for fd in list(self._registered_fds):
            try:
                self._loop.remove_reader(fd)
            except Exception:
                pass
        self._registered_fds.clear()
        try:
            self._loop.remove_reader(self._fd)
        except Exception:
            pass
        if self._stop_fd is not None:
            try:
                self._loop.remove_reader(self._stop_fd)
            except Exception:
                pass
        if self._deadline_handle is not None:
            self._deadline_handle.cancel()
            self._deadline_handle = None

    def detach(self) -> None:
        """Remove loop registration before FD close. Idempotent."""
        self._cleanup_registrations()
        # Cancel the runner task if pending.
        if self._runner_task is not None and not self._runner_task.done():
            self._runner_task.cancel()

    async def terminate(self, *, deadline: float = 0) -> bool:
        """Cancel the runner task and await its termination within deadline.

        R3 fix #1: returns True only if the runner actually terminated.
        Never discards the task reference — retains it for inspection.
        """
        self._cleanup_registrations()
        if self._runner_task is not None and not self._runner_task.done():
            self._runner_task.cancel()
            remaining = max(0.0, deadline - time.monotonic()) if deadline > 0 else 5.0
            if remaining > 0:
                try:
                    await asyncio.wait({self._runner_task}, timeout=remaining)
                except Exception:
                    pass
        # R3 fix #1: do NOT discard the reference. Return whether it's done.
        return self._runner_task is None or self._runner_task.done()

    def close(self) -> None:
        """Detach, poison FD, mark closed. Idempotent.

        Note: close() is synchronous. Use terminate() for async-aware shutdown
        that awaits the runner task.
        """
        if self._closed:
            return
        self._closed = True
        self._generation += 1  # invalidate stale callbacks
        self._cleanup_registrations()
        # Cancel runner task (cannot await synchronously).
        if self._runner_task is not None and not self._runner_task.done():
            self._runner_task.cancel()
        # R3 fix #2: physically close the FD, not just poison the integer.
        if self._fd >= 0:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd_closed = True
        self._fd = -1  # poison
        self._stop_fd = None

    @property
    def runner_done(self) -> bool:
        """True if the runner task is done or absent."""
        return self._runner_task is None or self._runner_task.done()

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def fd_closed(self) -> bool:
        """True if the underlying FD has been physically closed."""
        return getattr(self, "_fd_closed", False) or self._fd < 0

    @property
    def fd(self) -> int:
        return self._fd

    @property
    def accumulator(self) -> ProtocolAccumulator:
        return self._accumulator
