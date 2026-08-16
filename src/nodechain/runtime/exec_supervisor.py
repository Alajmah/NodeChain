"""v3.5.1 H2 S2 — Non-execing supervisor for exact exec-start authority.

The supervisor is a trusted process that owns the bootstrap/workload lifecycle.
It establishes exact exec observation via PTRACE_EVENT_EXEC and reports two
independent truths: workload_started (bool) and workload_outcome.

## Locked five-channel topology (S2)

::

    parent ↔ supervisor:         private trusted protocol FD (never inherited)
    parent/supervisor → bootstrap: dedicated configuration channel (framed, bounded)
    bootstrap → supervisor:      bounded enforcement/status channel (metadata pipe)
    bootstrap/workload stdout:   parent-owned bounded output (untrusted)
    bootstrap/workload stderr:   parent-owned bounded output (untrusted)

Three processes: ``parent → trusted supervisor → bootstrap/workload``.

## Channel ownership

The protocol pipe is created **before** the supervisor is spawned. The parent
keeps ``protocol_rfd``; the supervisor keeps ``protocol_wfd``. The supervisor
marks ``protocol_wfd`` as ``FD_CLOEXEC`` before forking the bootstrap. The
bootstrap child explicitly closes ``protocol_wfd`` and closes every non-allowlisted
descriptor before execving the Python bootstrap.

stdout/stderr are inherited (fd 1, fd 2) from the parent through the supervisor
into the bootstrap and workload. The parent applies its existing bounded output
reader. The supervisor never writes trusted protocol data to either stream.

## Exec boundaries

* **Boundary 1 (supervisor → Python bootstrap):** the trusted post-fork child
  calls ``dup2(config_rfd, 0)``, marks ``metadata_wfd`` inheritable, closes
  ``protocol_wfd`` + all non-allowlisted FDs, then ``execve``s Python.
* **Boundary 2 (Python bootstrap → workload):** the bootstrap sets
  ``FD_CLOEXEC`` on ``metadata_wfd`` then ``execve``s the workload. The kernel
  atomically closes ``metadata_wfd`` on successful exec.

Protocol messages never enter the bootstrap/workload descriptor table.

If the bootstrap dies before ``PTRACE_EVENT_EXEC``, ``workload_started=False``.
"""

from __future__ import annotations

import asyncio
import errno
import json
import os
import select
import signal
import struct
import sys
import time
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROTO_VERSION = 1

# ptrace constants (Linux)
PTRACE_TRACEME = 0
PTRACE_SETOPTIONS = 0x4200
PTRACE_CONT = 7
PTRACE_O_TRACEEXEC = 0x10
PTRACE_EVENT_EXEC = 4

# Child-exit probe interval for the metadata reader.
CHILD_PROBE_INTERVAL = 0.1  # seconds

# Record / stream limits (Correction #5: separate record vs stream limits)
MAX_PROTOCOL_RECORD_BYTES = 8_192
MAX_PROTOCOL_STREAM_BYTES = 64_000
MAX_PROTOCOL_RECORDS = 32

MAX_METADATA_RECORD_BYTES = 16_384
MAX_METADATA_STREAM_BYTES = 65_536
MAX_METADATA_RECORDS = 16

MAX_CONFIG_BYTES = 65_536  # payload only, excluding 4-byte header
CONFIG_DEADLINE_SECONDS = 30.0
METADATA_DEADLINE_SECONDS = 30.0

# Metadata event types (bootstrap → supervisor, typed records)
META_BOOTSTRAP_STARTED = "bootstrap_started"
META_ENFORCEMENT_VERIFIED = "enforcement_verified"
META_ENFORCEMENT_FAILED = "enforcement_failed"
META_PTRACE_TRACEME_FAILED = "ptrace_traceme_failed"
META_BOOTSTRAP_FAILED = "bootstrap_failed"

# Protocol event types (supervisor → parent, versioned records)
PROTO_SUPERVISOR_STARTED = "supervisor_started"
PROTO_BOOTSTRAP_SPAWNED = "bootstrap_spawned"
PROTO_ENFORCEMENT_VERIFIED = "enforcement_verified"
PROTO_EXEC_MONITOR_ARMED = "exec_monitor_armed"
PROTO_EXEC_CONFIRMED = "exec_confirmed"
PROTO_WORKLOAD_EXITED = "workload_exited"
PROTO_SUPERVISOR_FAILED = "supervisor_failed"
PROTO_CLEANUP_COMPLETED = "cleanup_completed"

# Allowed metadata event types (closed schema)
_META_ALLOWED_TYPES = frozenset({
    META_BOOTSTRAP_STARTED,
    META_ENFORCEMENT_VERIFIED,
    META_ENFORCEMENT_FAILED,
    META_PTRACE_TRACEME_FAILED,
    META_BOOTSTRAP_FAILED,
})

# Allowed metadata fields per type (closed schema)
_META_ALLOWED_FIELDS: dict[str, frozenset[str]] = {
    META_BOOTSTRAP_STARTED: frozenset({"type"}),
    META_ENFORCEMENT_VERIFIED: frozenset({"type", "metadata"}),
    META_ENFORCEMENT_FAILED: frozenset({"type", "failed_primitives"}),
    META_PTRACE_TRACEME_FAILED: frozenset({"type", "errno"}),
    META_BOOTSTRAP_FAILED: frozenset({"type", "stage", "reason"}),
}

# Metadata success-terminal types
_META_TERMINAL_TYPES = frozenset({
    META_ENFORCEMENT_VERIFIED,
    META_ENFORCEMENT_FAILED,
    META_PTRACE_TRACEME_FAILED,
    META_BOOTSTRAP_FAILED,
})

# Protocol event types (closed schema for read_bounded_protocol)
_PROTO_ALLOWED_TYPES = frozenset({
    PROTO_SUPERVISOR_STARTED,
    PROTO_BOOTSTRAP_SPAWNED,
    PROTO_ENFORCEMENT_VERIFIED,
    PROTO_EXEC_MONITOR_ARMED,
    PROTO_EXEC_CONFIRMED,
    PROTO_WORKLOAD_EXITED,
    PROTO_SUPERVISOR_FAILED,
    PROTO_CLEANUP_COMPLETED,
})

# Allowed protocol fields per type (closed schema)
_PROTO_ALLOWED_FIELDS: dict[str, frozenset[str]] = {
    PROTO_SUPERVISOR_STARTED: frozenset({"version", "type"}),
    PROTO_BOOTSTRAP_SPAWNED: frozenset({"version", "type", "pid"}),
    PROTO_ENFORCEMENT_VERIFIED: frozenset({"version", "type", "metadata"}),
    PROTO_EXEC_MONITOR_ARMED: frozenset({"version", "type"}),
    PROTO_EXEC_CONFIRMED: frozenset({"version", "type"}),
    PROTO_WORKLOAD_EXITED: frozenset({"version", "type", "started", "exit_code",
                                       "signaled", "signal_num"}),
    PROTO_SUPERVISOR_FAILED: frozenset({"version", "type", "reason", "errno"}),
    PROTO_CLEANUP_COMPLETED: frozenset({"version", "type", "cleanup_succeeded", "reason"}),
}

# Required fields per protocol record type (Fix #4)
_PROTO_REQUIRED_FIELDS: dict[str, frozenset[str]] = {
    PROTO_SUPERVISOR_STARTED: frozenset({"version", "type"}),
    PROTO_BOOTSTRAP_SPAWNED: frozenset({"version", "type", "pid"}),
    PROTO_ENFORCEMENT_VERIFIED: frozenset({"version", "type"}),
    PROTO_EXEC_MONITOR_ARMED: frozenset({"version", "type"}),
    PROTO_EXEC_CONFIRMED: frozenset({"version", "type"}),
    PROTO_WORKLOAD_EXITED: frozenset({"version", "type", "started"}),
    PROTO_SUPERVISOR_FAILED: frozenset({"version", "type", "reason"}),
    PROTO_CLEANUP_COMPLETED: frozenset({"version", "type", "cleanup_succeeded"}),
}


def _is_int_not_bool(v: Any) -> bool:
    """True if *v* is an int but NOT a bool (Python bool is a subclass of int)."""
    return isinstance(v, int) and not isinstance(v, bool)


def _validate_proto_fields(rec_type: str, obj: dict[str, Any]) -> str | None:
    """Validate field types and conditional relationships for a protocol record.

    Returns an error reason string on failure, or None on success.

    Fix #1: strict type validation — version must be int (not bool), pid must
    be a positive int, booleans must be exact bools, workload_exited must have
    exactly one valid outcome variant, reason must be a nonempty bounded string.
    """
    # version: exact integer 1, not bool.
    if not _is_int_not_bool(obj.get("version")):
        return "protocol_invalid_version_type"

    # type: nonempty string.
    if not isinstance(obj.get("type"), str) or not obj["type"]:
        return "protocol_invalid_type_value"

    if rec_type == PROTO_BOOTSTRAP_SPAWNED:
        pid = obj.get("pid")
        if not _is_int_not_bool(pid) or pid <= 0:
            return "protocol_invalid_pid"

    if rec_type == PROTO_WORKLOAD_EXITED:
        started = obj.get("started")
        if not isinstance(started, bool):
            return "protocol_invalid_started_type"
        has_exit = "exit_code" in obj
        has_signal = "signaled" in obj
        has_signal_num = "signal_num" in obj

        # Fix #4 (round 3): exact outcome variant enforcement.
        # Exit variant: started=True, exit_code=int, signaled absent, signal_num absent.
        # Signal variant: started=True, signaled=True, signal_num=int, exit_code absent.
        # Reject all other combinations including cross-variant stray fields.
        if has_exit and has_signal:
            return "protocol_conflicting_outcome"
        if has_exit and has_signal_num:
            # exit_code present but signal_num is a stray cross-variant field.
            return "protocol_stray_signal_num"
        if has_signal and not has_signal_num:
            return "protocol_missing_signal_num"
        if has_signal_num and not has_signal:
            return "protocol_signal_num_without_signaled"

        if has_exit:
            if not _is_int_not_bool(obj.get("exit_code")):
                return "protocol_invalid_exit_code"
            if obj.get("exit_code") < 0 or obj["exit_code"] > 255:
                return "protocol_invalid_exit_code_range"
        if has_signal:
            signaled = obj.get("signaled")
            if not isinstance(signaled, bool) or not signaled:
                return "protocol_invalid_signaled"
            signal_num = obj.get("signal_num")
            if not _is_int_not_bool(signal_num) or signal_num < 1:
                return "protocol_invalid_signal_num"
            # Cap to valid platform signal range.
            if signal_num > 64:
                return "protocol_invalid_signal_num_range"
        # Must have exactly one outcome.
        if not has_exit and not has_signal:
            return "protocol_missing_outcome"

    if rec_type == PROTO_SUPERVISOR_FAILED:
        reason = obj.get("reason")
        if not isinstance(reason, str) or not reason:
            return "protocol_invalid_reason"
        if len(reason) > 500:
            return "protocol_reason_too_long"
        if "errno" in obj:
            if not _is_int_not_bool(obj.get("errno")) or obj["errno"] < 0:
                return "protocol_invalid_errno"

    if rec_type == PROTO_CLEANUP_COMPLETED:
        cs = obj.get("cleanup_succeeded")
        if not isinstance(cs, bool):
            return "protocol_invalid_cleanup_succeeded"
        if "reason" in obj:
            if not isinstance(obj.get("reason"), str) or not obj["reason"]:
                return "protocol_invalid_cleanup_reason"

    return None


# ---------------------------------------------------------------------------
# FD endpoint policy (documentation + validation)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FDEndpointPolicy:
    """Documents the intended lifecycle of one endpoint of a channel.

    ``survives_parent_exec`` is ``None`` for endpoints that do not exist at the
    parent→supervisor boundary (they are created later by the supervisor).
    """

    name: str
    endpoint: str                         # "read" | "write"
    owner: str                            # parent | supervisor | bootstrap | workload
    survives_parent_exec: bool | None
    survives_bootstrap_exec: bool         # B1
    closes_on_workload_exec: bool         # B2
    max_bytes: int | None
    timeout_seconds: float | None


FD_ENDPOINT_POLICY: list[FDEndpointPolicy] = [
    # Parent→supervisor boundary
    FDEndpointPolicy("protocol", "read",  "parent",     False, False, False, 8192, 10),
    FDEndpointPolicy("protocol", "write", "supervisor", True,  False, False, 8192, 10),
    # Supervisor-created (None = not present at parent→supervisor boundary)
    FDEndpointPolicy("config",   "read",  "bootstrap",  None,  True,  True,  65536, 30),
    FDEndpointPolicy("config",   "write", "supervisor", None,  False, False, 65536, 30),
    FDEndpointPolicy("metadata", "read",  "supervisor", None,  False, False, 65536, 30),
    FDEndpointPolicy("metadata", "write", "bootstrap",  None,  True,  True,  65536, 30),
    # T2: workload-input pipe (parent-created).
    # The original numbered read descriptor is closed after dup2 in B1, but
    # the logical endpoint survives into B2 as FD 0 (closes_on_workload_exec
    # = False means the logical channel does not disappear at B2 exec).
    FDEndpointPolicy("workload_input", "read",  "workload", True,  True,  False, 1048576, None),
    FDEndpointPolicy("workload_input", "write", "parent",   False, False, False, 1048576, None),
    # Parent-owned (inherited fd 1/fd 2)
    FDEndpointPolicy("stdout",   "read",  "parent",     False, False, False, 50000, 120),
    FDEndpointPolicy("stdout",   "write", "bootstrap",  True,  True,  False, 50000, 120),
    FDEndpointPolicy("stderr",   "read",  "parent",     False, False, False, 50000, 120),
    FDEndpointPolicy("stderr",   "write", "bootstrap",  True,  True,  False, 50000, 120),
]


# ---------------------------------------------------------------------------
# Runtime FD holder
# ---------------------------------------------------------------------------

@dataclass
class SupervisorPipeSet:
    """Owns **both ends** of every supervisor-created pipe, plus the
    parent-created workload-input read-end FD (T2).

    stdout/stderr are parent-owned (inherited fd 1/fd 2) and deliberately NOT
    held here. The workload-input read-end is parent-created and passed via
    the CLI; it is owned here only between I's ``supervisor_main`` entry and
    the B1 fork handoff.
    """

    config_rfd: int | None = None
    config_wfd: int | None = None
    metadata_rfd: int | None = None
    metadata_wfd: int | None = None
    protocol_wfd: int | None = None   # created by parent, passed in
    workload_input_rfd: int | None = None  # T2: parent-created, passed via CLI

    # After a successful fork, the supervisor closes its unused write/read ends.
    def close_supervisor_unused_after_fork(self) -> None:
        """Close supervisor-side endpoints that only the bootstrap uses."""
        self._close_fd("config_rfd")    # bootstrap reads config
        self._close_fd("metadata_wfd")  # bootstrap writes metadata

    def close_workload_input_after_fork(self) -> bool:
        """T2 checked handoff: poison-before-close, return False on OSError.

        This is the load-bearing I→B1 handoff. A retained read end can
        suppress EPIPE and keep the parent writer blocked, so the caller
        MUST fail-closed if this returns False.
        """
        fd = self.workload_input_rfd
        self.workload_input_rfd = None  # poison before close
        if fd is None:
            return True
        try:
            os.close(fd)
        except OSError:
            return False
        return True

    def close_non_protocol(self) -> None:
        """Close config + metadata pipes (called after metadata read completes).

        Also defensively best-effort closes workload_input_rfd if it was not
        already poisoned by the checked handoff. This is NOT the handoff
        authority — see ``close_workload_input_after_fork``.
        """
        self._close_fd("config_rfd")
        self._close_fd("config_wfd")
        self._close_fd("metadata_rfd")
        self._close_fd("metadata_wfd")
        self._close_fd("workload_input_rfd")

    def close_protocol(self) -> None:
        """Close the protocol pipe. Only call after the terminal record is emitted."""
        self._close_fd("protocol_wfd")

    def close_everything(self) -> None:
        """Close all held descriptors. Idempotent."""
        self._close_fd("config_rfd")
        self._close_fd("config_wfd")
        self._close_fd("metadata_rfd")
        self._close_fd("metadata_wfd")
        self._close_fd("protocol_wfd")
        self._close_fd("workload_input_rfd")

    def _close_fd(self, field_name: str) -> None:
        """Idempotent close with poisoning.

        Sets the field to ``None`` **before** closing so a later cleanup pass
        cannot close an unrelated FD that recycled the same number.
        """
        fd = getattr(self, field_name)
        if fd is None:
            return
        setattr(self, field_name, None)
        try:
            os.close(fd)
        except OSError:
            pass


class BootstrapFDClosureError(OSError):
    """Raised when FD closure cannot be verified."""


def _close_all_except(allowlist: set[int]) -> None:
    """Close every open FD except those in *allowlist* (and 0, 1, 2 implicitly).

    Designed for the trusted post-fork child before execving the Python bootstrap.

    Fix #5 (round 3): fail-closed in ALL fallback paths.
    - RLIMIT_INFINITY is rejected (unbounded range cannot be verified).
    - InterruptedError on close is retried.
    - EBADF is expected (FD already closed); other OSError values raise.
    - The child must never exec Python after an unverifiable close operation.
    """
    allowlist = allowlist | {0, 1, 2}
    sorted_allow = sorted(allowlist)
    try:
        fd_dir = os.listdir("/proc/self/fd")
    except OSError:
        # /proc not available — try close_range in ranges between allowlisted FDs.
        try:
            prev = 2
            for fd in sorted_allow:
                if fd > prev + 1:
                    os.close_range(prev + 1, fd - 1)
                prev = fd
            if sorted_allow:
                os.close_range(sorted_allow[-1] + 1, 1 << 30)
            else:
                os.close_range(3, 1 << 30)
            return
        except (AttributeError, OSError):
            # close_range not available — brute-force the full RLIMIT_NOFILE.
            import resource
            soft_limit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
            if soft_limit in (resource.RLIM_INFINITY, -1):
                raise BootstrapFDClosureError("unbounded_rlimit")
            for fd in range(3, soft_limit):
                if fd in allowlist:
                    continue
                _close_fd_retry(fd)
            return
    for entry in fd_dir:
        try:
            fd = int(entry)
        except ValueError:
            continue
        if fd in allowlist:
            continue
        _close_fd_retry(fd)


def _close_fd_retry(fd: int) -> None:
    """Close one FD with InterruptedError retry and EBADF tolerance.

    Fix #5 (round 3): EBADF (FD already closed) is expected and ignored.
    InterruptedError is retried. Other OSError values raise
    BootstrapFDClosureError.
    """
    for _attempt in range(3):
        try:
            os.close(fd)
            return
        except InterruptedError:
            continue
        except OSError as e:
            if e.errno == errno.EBADF:
                return  # FD was already closed — expected.
            raise BootstrapFDClosureError(f"close_failed_fd_{fd}: {e}")
    raise BootstrapFDClosureError(f"close_eintr_fd_{fd}")


# ---------------------------------------------------------------------------
# JSON helpers
# ---------------------------------------------------------------------------

class DuplicateKeyError(ValueError):
    """Raised when a JSON object contains duplicate keys."""


def _detect_dup_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """``object_pairs_hook`` that rejects duplicate keys."""
    seen: set[str] = set()
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise DuplicateKeyError(f"duplicate key: {key!r}")
        seen.add(key)
        result[key] = value
    return result


def _parse_json_strict(raw: str, *, allowed_fields: frozenset[str] | None = None) -> dict[str, Any]:
    """Parse JSON with duplicate-key rejection and optional closed-schema validation.

    Rejects:
    * malformed JSON
    * non-object top-level values
    * duplicate keys
    * unknown fields (when *allowed_fields* is provided)
    """
    try:
        obj = json.loads(raw, object_pairs_hook=_detect_dup_keys)
    except DuplicateKeyError:
        raise
    except (json.JSONDecodeError, ValueError):
        raise ValueError("malformed JSON")
    if not isinstance(obj, dict):
        raise ValueError("non-object JSON")
    if allowed_fields is not None:
        extra = set(obj.keys()) - allowed_fields
        if extra:
            raise ValueError(f"unknown fields: {extra}")
    return obj


# ---------------------------------------------------------------------------
# Bounded configuration channel (framed)
# ---------------------------------------------------------------------------

class ConfigChannelError(Exception):
    """Typed failure from the bounded configuration channel."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _write_bounded_fd(
    fd: int,
    data: bytes,
    *,
    deadline: float,
    error_cls: type[Exception],
    reason_prefix: str,
) -> None:
    """Write all *data* to *fd* using nonblocking I/O with ``select`` writability.

    Fix #9: the write channel must be deadline-bounded. Sets the FD nonblocking,
    uses ``select.select`` to wait for writability within the remaining deadline,
    writes available bytes, retries EINTR, and fails on deadline expiry.
    """
    # Save original flags, set nonblocking.
    # Fix #6: fail-closed if O_NONBLOCK cannot be established — never write
    # to a blocking pipe that could stall beyond the deadline.
    orig_flags = None
    try:
        import fcntl
        orig_flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, orig_flags | os.O_NONBLOCK)
    except (ImportError, OSError) as e:
        raise error_cls(f"{reason_prefix}_nonblock_setup_failed: {e}")

    written = 0
    try:
        while written < len(data):
            now = time.monotonic()
            if now >= deadline:
                raise error_cls(f"{reason_prefix}_timeout")
            remaining = deadline - now
            try:
                _, writable, _ = select.select([], [fd], [], min(remaining, 1.0))
            except InterruptedError:
                continue
            except OSError as e:
                raise error_cls(f"{reason_prefix}_select_error: {e}")
            if not writable:
                continue
            try:
                n = os.write(fd, data[written:])
            except InterruptedError:
                continue
            except BrokenPipeError:
                raise error_cls(f"{reason_prefix}_pipe_closed")
            except BlockingIOError:
                continue
            except OSError as e:
                raise error_cls(f"{reason_prefix}_write_error: {e}")
            if n <= 0:
                raise error_cls(f"{reason_prefix}_write_zero")
            written += n
    finally:
        # Restore original flags.
        if orig_flags is not None:
            try:
                import fcntl
                fcntl.fcntl(fd, fcntl.F_SETFL, orig_flags)
            except (ImportError, OSError):
                pass


def write_bounded_config(
    config_fd: int,
    payload: bytes,
    *,
    deadline: float,
    max_bytes: int = MAX_CONFIG_BYTES,
) -> None:
    """Write a 4-byte big-endian length header + exact payload to *config_fd*.

    *max_bytes* applies to the payload only (excludes the 4-byte header).

    Raises :class:`ConfigChannelError` on any failure. If the payload exceeds
    *max_bytes*, **no bytes are written**.
    """
    if len(payload) > max_bytes:
        raise ConfigChannelError("config_oversized")
    header = struct.pack(">I", len(payload))
    data = header + payload
    _write_bounded_fd(config_fd, data, deadline=deadline,
                      error_cls=ConfigChannelError, reason_prefix="config")


def read_bounded_config(
    config_fd: int,
    *,
    deadline: float,
    max_bytes: int = MAX_CONFIG_BYTES,
    close_fd: bool = True,
) -> dict[str, Any]:
    """Read a framed bounded configuration from *config_fd*.

    Reads the 4-byte header, rejects declared length > *max_bytes*, reads the
    exact payload, requires clean EOF (no trailing bytes), parses one JSON
    object, then closes the FD (unless *close_fd* is False).

    *max_bytes* applies to the payload only (excludes the 4-byte header).
    """
    try:
        # Read 4-byte header.
        header = _read_exact(config_fd, 4, deadline=deadline, reason_prefix="config_header")
        declared = struct.unpack(">I", header)[0]
        if declared > max_bytes:
            raise ConfigChannelError("config_oversized")
        if declared == 0:
            raise ConfigChannelError("config_empty_payload")

        # Read exact payload.
        payload = _read_exact(config_fd, declared, deadline=deadline, reason_prefix="config_payload")

        # Require clean EOF (no trailing bytes).
        trailing = _read_exact(config_fd, 1, deadline=deadline, reason_prefix="config_eof",
                               allow_eof=True)
        if trailing is not None:
            raise ConfigChannelError("config_trailing_bytes")

        # Parse one JSON object.
        try:
            obj = json.loads(payload.decode("utf-8"), object_pairs_hook=_detect_dup_keys)
        except DuplicateKeyError:
            raise ConfigChannelError("config_duplicate_key")
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            raise ConfigChannelError("config_malformed")
        if not isinstance(obj, dict):
            raise ConfigChannelError("config_non_object")

        return obj
    finally:
        if close_fd:
            try:
                os.close(config_fd)
            except OSError:
                pass


def _read_exact(
    fd: int,
    count: int,
    *,
    deadline: float,
    reason_prefix: str,
    allow_eof: bool = False,
) -> bytes | None:
    """Read exactly *count* bytes from *fd* using ``select`` with deadline.

    Returns ``None`` if *allow_eof* is True and EOF is reached immediately.
    Raises :class:`ConfigChannelError` on partial read / timeout.
    """
    buf = bytearray()
    while len(buf) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ConfigChannelError(f"{reason_prefix}_timeout")
        wait = min(remaining, 1.0)
        try:
            readable, _, _ = select.select([fd], [], [], wait)
        except InterruptedError:
            continue
        except OSError as e:
            raise ConfigChannelError(f"{reason_prefix}_select_error: {e}")
        if not readable:
            continue
        try:
            chunk = os.read(fd, count - len(buf))
        except InterruptedError:
            continue
        except OSError as e:
            raise ConfigChannelError(f"{reason_prefix}_read_error: {e}")
        if not chunk:
            if allow_eof and len(buf) == 0:
                return None
            raise ConfigChannelError(f"{reason_prefix}_partial_eof")
        buf.extend(chunk)
    return bytes(buf)


# ---------------------------------------------------------------------------
# Child-exit probing (non-reaping)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ChildProbeResult:
    """Result of a non-reaping child status probe."""
    running: bool
    exited: bool
    error: bool


def _probe_child_exit(child_pid: int) -> ChildProbeResult:
    """Probe child exit status without reaping (``WNOWAIT``).

    Any probe error — including ``ChildProcessError`` — fails closed
    (``error=True``). The caller must not treat an error as "still running."
    """
    try:
        # os.waitid with WNOWAT keeps the child reapable for the caller.
        result = os.waitid(os.P_PID, child_pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        if result is None:
            return ChildProbeResult(running=True, exited=False, error=False)
        return ChildProbeResult(running=False, exited=True, error=False)
    except ChildProcessError:
        return ChildProbeResult(running=False, exited=False, error=True)
    except OSError:
        return ChildProbeResult(running=False, exited=False, error=True)


# ---------------------------------------------------------------------------
# Bounded metadata reader
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MetadataReadResult:
    """Result of :func:`read_bounded_metadata`."""
    ok: bool
    reason: str
    metadata: dict[str, Any] = field(default_factory=dict)
    bytes_read: int = 0
    records_read: int = 0
    child_exited: bool = False


def read_bounded_metadata(
    meta_fd: int,
    *,
    child_pid: int,
    deadline: float,
    max_bytes: int = MAX_METADATA_STREAM_BYTES,
    max_records: int = MAX_METADATA_RECORDS,
    max_record_bytes: int = MAX_METADATA_RECORD_BYTES,
) -> MetadataReadResult:
    """Read bounded typed metadata records from *meta_fd* until a terminal state.

    Uses ``select.select`` with a bounded probe interval (not spin) so child-exit
    detection is responsive. Retries ``InterruptedError`` from both ``select``
    and ``os.read``. Counts framing bytes and partial-record bytes toward
    *max_bytes*. Does not close *meta_fd*, does not reap *child_pid*.

    Success requires the exact sequence::

        bootstrap_started → enforcement_verified

    Any failure record (``enforcement_failed``, ``ptrace_traceme_failed``,
    ``bootstrap_failed``) returns ``ok=False`` with a stable reason derived
    from the record type.
    """
    # Preserve original blocking mode.
    try:
        import fcntl
        orig_flags = fcntl.fcntl(meta_fd, fcntl.F_GETFL)
        fcntl.fcntl(meta_fd, fcntl.F_SETFL, orig_flags | os.O_NONBLOCK)
    except (ImportError, OSError):
        orig_flags = None

    buffer = bytearray()
    records: list[dict[str, Any]] = []
    bytes_read = 0
    got_bootstrap_started = False
    terminal: str | None = None

    def _finalize(ok: bool, reason: str, exited: bool = False) -> MetadataReadResult:
        _restore_blocking(meta_fd, orig_flags)
        merged: dict[str, Any] = {}
        for rec in records:
            merged.update(rec)
        return MetadataReadResult(
            ok=ok, reason=reason, metadata=merged,
            bytes_read=bytes_read, records_read=len(records),
            child_exited=exited,
        )

    def _process_line(line: str) -> str | None:
        """Parse one metadata line. Returns a reason string on failure, None on success.

        Also updates *records*, *got_bootstrap_started*, and *terminal* via closure.
        """
        nonlocal got_bootstrap_started, terminal

        if len(line.encode("utf-8", errors="replace")) > max_record_bytes:
            return "metadata_record_too_large"

        # Parse with strict JSON + duplicate-key detection.
        try:
            obj = _parse_json_strict(line)
        except DuplicateKeyError:
            return "metadata_duplicate_key"
        except ValueError:
            return "metadata_malformed"

        rec_type = obj.get("type")
        if rec_type not in _META_ALLOWED_TYPES:
            return "metadata_unknown_event"

        # Validate closed schema for this type.
        allowed = _META_ALLOWED_FIELDS.get(rec_type, frozenset({"type"}))
        extra = set(obj.keys()) - allowed
        if extra:
            return "metadata_unknown_field"

        # Validate transition ordering.
        if rec_type == META_BOOTSTRAP_STARTED:
            if got_bootstrap_started:
                return "metadata_invalid_transition"
            if terminal is not None:
                return "metadata_invalid_transition"
            got_bootstrap_started = True
        else:
            if not got_bootstrap_started:
                # Record before bootstrap_started.
                return "metadata_invalid_transition"
            if terminal is not None:
                # Record after a terminal state.
                return "metadata_invalid_transition"

        records.append(obj)
        if rec_type in _META_TERMINAL_TYPES:
            terminal = rec_type
        return None

    try:
        while True:
            now = time.monotonic()
            if now >= deadline:
                if terminal is not None:
                    break
                return _finalize(False, "metadata_timeout")

            # Bounded probe interval for responsive child-exit detection.
            wait = min(deadline - now, CHILD_PROBE_INTERVAL)
            try:
                readable, _, _ = select.select([meta_fd], [], [], wait)
            except InterruptedError:
                continue
            except OSError as e:
                return _finalize(False, f"metadata_select_error: {e}")

            if readable:
                try:
                    chunk = os.read(meta_fd, 65536)
                except InterruptedError:
                    continue
                except BlockingIOError:
                    chunk = b""
                except OSError as e:
                    return _finalize(False, f"metadata_read_error: {e}")

                if chunk:
                    # Byte accounting BEFORE extending buffer.
                    if bytes_read + len(chunk) > max_bytes:
                        return _finalize(False, "metadata_limit_exceeded")
                    buffer.extend(chunk)
                    bytes_read += len(chunk)

                    # Process complete lines.
                    while b"\n" in buffer:
                        idx = buffer.index(b"\n")
                        line = buffer[:idx].decode("utf-8", errors="replace").strip()
                        del buffer[:idx + 1]
                        if not line:
                            continue
                        if len(records) >= max_records:
                            return _finalize(False, "metadata_too_many_records")
                        fail_reason = _process_line(line)
                        if fail_reason is not None:
                            return _finalize(False, fail_reason)

                    # Check if we reached a terminal state.
                    if terminal == META_ENFORCEMENT_VERIFIED:
                        break
                    elif terminal is not None:
                        # Failure terminal — map type to reason.
                        return _finalize(False, terminal)

                elif chunk == b"":
                    # EOF on the metadata pipe.
                    if terminal == META_ENFORCEMENT_VERIFIED:
                        break
                    elif terminal is not None:
                        return _finalize(False, terminal)
                    else:
                        # Partial record remaining?
                        remaining = buffer.decode("utf-8", errors="replace").strip()
                        if remaining:
                            return _finalize(False, "metadata_partial_record")
                        if not got_bootstrap_started:
                            return _finalize(False, "metadata_eof_before_verified")
                        return _finalize(False, "metadata_eof_before_verified")

            # Drain complete: check terminal state first, then probe child.
            if terminal == META_ENFORCEMENT_VERIFIED:
                break
            if terminal is not None:
                return _finalize(False, terminal)

            # Probe child status (non-reaping).
            # The child can die at any time — even before writing bootstrap_started.
            # Probe unconditionally so exit is detected responsively.
            probe = _probe_child_exit(child_pid)
            if probe.error:
                return _finalize(False, "metadata_child_probe_error")
            if probe.exited:
                if got_bootstrap_started:
                    return _finalize(False, "bootstrap_exited_before_verified", exited=True)
                else:
                    return _finalize(False, "bootstrap_exited_before_started", exited=True)

        # Success.
        if terminal == META_ENFORCEMENT_VERIFIED:
            return _finalize(True, "ok")
        return _finalize(False, terminal or "metadata_incomplete")

    finally:
        _restore_blocking(meta_fd, orig_flags)


def _restore_blocking(fd: int, orig_flags: int | None) -> None:
    """Restore original blocking mode on *fd*."""
    if orig_flags is None:
        return
    try:
        import fcntl
        fcntl.fcntl(fd, fcntl.F_SETFL, orig_flags)
    except (ImportError, OSError):
        pass


# ---------------------------------------------------------------------------
# Versioned protocol (supervisor → parent)
# ---------------------------------------------------------------------------

class ProtocolChannelError(Exception):
    """Typed failure from the trusted protocol channel."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def emit_protocol(
    protocol_fd: int,
    record: dict[str, Any],
    *,
    deadline: float | None = None,
) -> None:
    """Write one versioned JSON-line protocol record to the trusted protocol pipe.

    * Only the supervisor calls this.
    * Each record must not exceed :data:`MAX_PROTOCOL_RECORD_BYTES`.
    * Fix #9: uses nonblocking I/O with ``select`` writability, bounded by
      *deadline* (default: now + 10s).
    * Handles partial writes and ``EINTR``.
    * ``BrokenPipeError`` raises :class:`ProtocolChannelError`.
    * A record exceeding the limit is rejected **before** any write.
    """
    if deadline is None:
        deadline = time.monotonic() + 10.0
    record_with_version = {"version": PROTO_VERSION, **record}
    data = (json.dumps(record_with_version, separators=(",", ":")) + "\n").encode("utf-8")
    if len(data) > MAX_PROTOCOL_RECORD_BYTES:
        raise ProtocolChannelError("protocol_record_too_large")
    _write_bounded_fd(protocol_fd, data, deadline=deadline,
                      error_cls=ProtocolChannelError, reason_prefix="protocol")


@dataclass(frozen=True)
class ProtocolReadResult:
    """Result of :func:`read_bounded_protocol`."""
    ok: bool
    reason: str
    records: list[dict[str, Any]] = field(default_factory=list)
    bytes_read: int = 0


# ---------------------------------------------------------------------------
# S3.1R R1: Pure protocol stream parser (INV-R1)
# ---------------------------------------------------------------------------

class _ProtocolStreamParser:
    """Pure incremental protocol stream parser (INV-R1).

    Neither the synchronous nor asynchronous I/O driver may duplicate
    protocol validation logic. Both feed bytes to this parser and
    interpret its terminal results.
    """

    def __init__(
        self,
        *,
        max_bytes: int = MAX_PROTOCOL_STREAM_BYTES,
        max_records: int = MAX_PROTOCOL_RECORDS,
        max_record_bytes: int = MAX_PROTOCOL_RECORD_BYTES,
    ) -> None:
        self._buffer: bytearray = bytearray()
        self._records: list[dict[str, Any]] = []
        self._bytes_read: int = 0
        self._last_type: str | None = None
        self._terminal_seen: bool = False
        self._cleanup_failed: bool = False
        self._max_bytes = max_bytes
        self._max_records = max_records
        self._max_record_bytes = max_record_bytes

    @property
    def records(self) -> list[dict[str, Any]]:
        return list(self._records)

    @property
    def bytes_read(self) -> int:
        return self._bytes_read

    @property
    def terminal_seen(self) -> bool:
        return self._terminal_seen

    def _result(self, ok: bool, reason: str) -> ProtocolReadResult:
        return ProtocolReadResult(ok, reason, list(self._records), self._bytes_read)

    def _process_line(self, line: str) -> ProtocolReadResult | None:
        """Parse and validate one newline-delimited record. Return terminal result or None."""
        if len(self._records) >= self._max_records:
            return self._result(False, "protocol_too_many_records")

        if len(line.encode("utf-8", errors="replace")) > self._max_record_bytes:
            return self._result(False, "protocol_record_too_large")

        try:
            obj = _parse_json_strict(line)
        except DuplicateKeyError:
            return self._result(False, "protocol_duplicate_key")
        except ValueError:
            return self._result(False, "protocol_malformed")

        version = obj.get("version")
        if version != PROTO_VERSION:
            return self._result(False, "protocol_unsupported_version")

        rec_type = obj.get("type")
        if rec_type not in _PROTO_ALLOWED_TYPES:
            return self._result(False, "protocol_unknown_type")

        allowed = _PROTO_ALLOWED_FIELDS.get(rec_type, frozenset())
        extra = set(obj.keys()) - allowed
        if extra:
            return self._result(False, "protocol_unknown_field")

        required = _PROTO_REQUIRED_FIELDS.get(rec_type, frozenset({"version", "type"}))
        missing = required - set(obj.keys())
        if missing:
            return self._result(False, "protocol_missing_required_field")

        type_error = _validate_proto_fields(rec_type, obj)
        if type_error is not None:
            return self._result(False, type_error)

        if self._last_type is None:
            # S3.2 Task 3: the protocol now accepts two valid initial records:
            #   supervisor_started → existing normal protocol sequence
            #   supervisor_failed  → cleanup_completed → EOF (pre-gate failure)
            # No other initial record is permitted. A synthetic supervisor_started
            # is NOT required on the pre-gate failure path.
            if rec_type not in (PROTO_SUPERVISOR_STARTED, PROTO_SUPERVISOR_FAILED):
                return self._result(False, "protocol_invalid_initial_state")
        elif rec_type == PROTO_SUPERVISOR_STARTED:
            return self._result(False, "protocol_duplicate_supervisor_started")

        if self._terminal_seen:
            return self._result(False, "protocol_record_after_cleanup")

        if rec_type == PROTO_WORKLOAD_EXITED:
            if not obj.get("started", False):
                return self._result(False, "protocol_workload_not_started")
            if self._last_type != PROTO_EXEC_CONFIRMED:
                return self._result(False, "protocol_workload_without_exec_confirmed")

        predecessors = _PROTO_PREDECESSORS.get(rec_type, frozenset())
        if self._last_type is not None:
            if self._last_type not in predecessors:
                return self._result(False, "protocol_invalid_transition")

        self._records.append(obj)
        self._last_type = rec_type

        if rec_type == PROTO_CLEANUP_COMPLETED:
            self._terminal_seen = True
            if not obj.get("cleanup_succeeded", True):
                self._cleanup_failed = True

        return None  # non-terminal — continue feeding

    def feed(self, chunk: bytes) -> ProtocolReadResult | None:
        """Consume a chunk of bytes. Return a terminal result or None.

        Performs byte accounting, line extraction, and record validation.
        Returns None if no terminal result has been reached yet.
        """
        if self._bytes_read + len(chunk) > self._max_bytes:
            return self._result(False, "protocol_limit_exceeded")
        self._buffer.extend(chunk)
        self._bytes_read += len(chunk)

        while b"\n" in self._buffer:
            idx = self._buffer.index(b"\n")
            line = self._buffer[:idx].decode("utf-8", errors="replace").strip()
            del self._buffer[:idx + 1]
            if not line:
                continue
            result = self._process_line(line)
            if result is not None:
                return result

        return None  # non-terminal

    def feed_eof(self) -> ProtocolReadResult:
        """Apply exact EOF semantics."""
        if self._terminal_seen:
            if self._buffer.strip():
                return self._result(False, "protocol_data_after_cleanup")
            if self._cleanup_failed:
                return self._result(False, "protocol_cleanup_failed")
            return self._result(True, "ok")
        return self._result(False, "protocol_eof_before_terminal")

    def on_deadline(self) -> ProtocolReadResult:
        """Return the correct timeout reason based on terminal state."""
        if self._terminal_seen:
            return self._result(False, "protocol_no_eof_after_cleanup")
        return self._result(False, "protocol_timeout")

    def on_stop(self) -> ProtocolReadResult:
        """Return protocol_stopped while preserving parsed records."""
        return self._result(False, "protocol_stopped")


# Protocol state machine — legal predecessor states for each event type.
_PROTO_PREDECESSORS: dict[str, frozenset[str]] = {
    PROTO_SUPERVISOR_STARTED: frozenset(),  # initial
    PROTO_BOOTSTRAP_SPAWNED: frozenset({PROTO_SUPERVISOR_STARTED}),
    PROTO_ENFORCEMENT_VERIFIED: frozenset({PROTO_BOOTSTRAP_SPAWNED}),
    PROTO_EXEC_MONITOR_ARMED: frozenset({PROTO_ENFORCEMENT_VERIFIED}),
    PROTO_EXEC_CONFIRMED: frozenset({PROTO_EXEC_MONITOR_ARMED}),
    PROTO_WORKLOAD_EXITED: frozenset({PROTO_EXEC_CONFIRMED}),
    PROTO_SUPERVISOR_FAILED: frozenset({
        # S3.2 Task 3: supervisor_failed may be the INITIAL record when S
        # fails before releasing I (pre-gate failure). The empty string
        # represents the initial state (self._last_type is None at that
        # point, but _PROTO_PREDECESSORS uses type names, not None).
        # We include "" to allow the initial-state transition check to pass.
        "",  # initial state (pre-gate failure)
        PROTO_SUPERVISOR_STARTED, PROTO_BOOTSTRAP_SPAWNED,
        PROTO_ENFORCEMENT_VERIFIED, PROTO_EXEC_MONITOR_ARMED,
        PROTO_EXEC_CONFIRMED,
    }),
    PROTO_CLEANUP_COMPLETED: frozenset({
        PROTO_WORKLOAD_EXITED, PROTO_SUPERVISOR_FAILED,
    }),
}


def read_bounded_protocol(
    protocol_fd: int,
    *,
    deadline: float,
    max_bytes: int = MAX_PROTOCOL_STREAM_BYTES,
    max_records: int = MAX_PROTOCOL_RECORDS,
    max_record_bytes: int = MAX_PROTOCOL_RECORD_BYTES,
    stop_fd: int | None = None,
) -> ProtocolReadResult:
    """Read and validate versioned protocol records from the trusted protocol pipe.

    S3.1R R1: Refactored to use :class:`_ProtocolStreamParser` for all
    validation logic. This synchronous I/O driver remains the S2 compatibility
    path (INV-R2).

    If *stop_fd* is provided, it is included in the reader's ``select`` set.
    When *stop_fd* becomes readable, the reader returns immediately with
    ``ok=False, reason="protocol_stopped"``.
    """
    parser = _ProtocolStreamParser(
        max_bytes=max_bytes, max_records=max_records, max_record_bytes=max_record_bytes,
    )

    try:
        os.set_blocking(protocol_fd, False)
    except OSError:
        pass

    while True:
        now = time.monotonic()
        if now >= deadline:
            return parser.on_deadline()

        remaining = deadline - now
        select_fds = [protocol_fd]
        if stop_fd is not None:
            select_fds.append(stop_fd)
        try:
            readable, _, _ = select.select(select_fds, [], [], min(remaining, 1.0))
        except InterruptedError:
            continue
        except OSError as e:
            return ProtocolReadResult(False, f"protocol_select_error: {e}",
                                      parser.records, parser.bytes_read)

        if not readable:
            continue

        # Check stop signal first — deterministic cancellation.
        if stop_fd is not None and stop_fd in readable:
            return parser.on_stop()

        try:
            chunk = os.read(protocol_fd, 65536)
        except InterruptedError:
            continue
        except BlockingIOError:
            continue
        except OSError as e:
            return ProtocolReadResult(False, f"protocol_read_error: {e}",
                                      parser.records, parser.bytes_read)

        if not chunk:
            # EOF
            return parser.feed_eof()

        # Feed bytes to the shared parser.
        result = parser.feed(chunk)
        if result is not None:
            return result

        # After processing, continue if no terminal result.
        if parser.terminal_seen:
            continue


# ---------------------------------------------------------------------------
# S3.1R R2: Native asynchronous protocol reader (INV-R3)
# ---------------------------------------------------------------------------

async def read_bounded_protocol_async(
    protocol_fd: int,
    *,
    deadline: float,
    max_bytes: int = MAX_PROTOCOL_STREAM_BYTES,
    max_records: int = MAX_PROTOCOL_RECORDS,
    max_record_bytes: int = MAX_PROTOCOL_RECORD_BYTES,
    stop_fd: int | None = None,
) -> ProtocolReadResult:
    """Read and validate protocol records using event-loop-native FD I/O.

    S3.1R R2 (INV-R3): No thread, executor, or ``asyncio.to_thread``.
    Uses ``loop.add_reader()`` for readiness notifications and nonblocking
    ``os.read()`` for data. Protocol data is drained before stop handling
    (INV-R4).

    All reader registrations and timer handles are removed in ``finally``
    on every exit path.
    """
    loop = asyncio.get_running_loop()

    # Verify add_reader support (catch NotImplementedError too).
    def _safe_add_reader(fd, callback):
        loop.add_reader(fd, callback)

    try:
        _safe_add_reader(protocol_fd, lambda: None)
        loop.remove_reader(protocol_fd)
    except (NotImplementedError, AttributeError):
        return ProtocolReadResult(
            False, "protocol_async_reader_unsupported", [], 0)
    except OSError:
        return ProtocolReadResult(
            False, "protocol_async_reader_unsupported", [], 0)

    parser = _ProtocolStreamParser(
        max_bytes=max_bytes, max_records=max_records, max_record_bytes=max_record_bytes,
    )

    # Set nonblocking.
    try:
        os.set_blocking(protocol_fd, False)
    except OSError:
        pass
    if stop_fd is not None:
        try:
            os.set_blocking(stop_fd, False)
        except OSError:
            pass

    # Coroutine-owned readiness state.
    wake_event = asyncio.Event()
    protocol_ready = [False]
    stop_ready = [False]
    deadline_ready = [False]
    registered_fds: set[int] = set()

    def _on_protocol_ready():
        protocol_ready[0] = True
        loop.remove_reader(protocol_fd)
        registered_fds.discard(protocol_fd)
        wake_event.set()

    def _on_stop_ready():
        stop_ready[0] = True
        loop.remove_reader(stop_fd)
        registered_fds.discard(stop_fd)
        wake_event.set()

    def _on_deadline():
        deadline_ready[0] = True
        wake_event.set()

    # Shared drain routine — called on every wake (INV-R4: protocol first).
    def _drain_protocol():
        """Drain protocol_fd to EAGAIN/EOF. Return terminal result or None."""
        while True:
            try:
                chunk = os.read(protocol_fd, 65536)
            except BlockingIOError:
                break
            except InterruptedError:
                continue
            except OSError as e:
                return ProtocolReadResult(
                    False, f"protocol_read_error: {e}",
                    parser.records, parser.bytes_read)
            if not chunk:
                return parser.feed_eof()
            result = parser.feed(chunk)
            if result is not None:
                return result
        return None

    def _rearm_protocol():
        """Re-register protocol_fd reader. Fail-closed on registration error."""
        try:
            loop.add_reader(protocol_fd, _on_protocol_ready)
            registered_fds.add(protocol_fd)
        except (OSError, NotImplementedError) as e:
            return ProtocolReadResult(
                False, f"protocol_async_reregister_failed: {e}",
                parser.records, parser.bytes_read)
        return None

    # Initial registration.
    reg_fail = _rearm_protocol()
    if reg_fail is not None:
        return reg_fail
    if stop_fd is not None:
        try:
            loop.add_reader(stop_fd, _on_stop_ready)
            registered_fds.add(stop_fd)
        except (OSError, NotImplementedError) as e:
            loop.remove_reader(protocol_fd)
            registered_fds.discard(protocol_fd)
            return ProtocolReadResult(
                False, f"protocol_async_register_failed: {e}", [], 0)

    # Deadline timer.
    delay = max(0.0, deadline - time.monotonic())
    deadline_handle = loop.call_later(delay, _on_deadline)

    try:
        while True:
            # Wait for any readiness signal.
            wake_event.clear()
            await wake_event.wait()

            # Clear readiness flags.
            was_protocol = protocol_ready[0]
            was_stop = stop_ready[0]
            was_deadline = deadline_ready[0]
            protocol_ready[0] = False
            stop_ready[0] = False
            deadline_ready[0] = False

            # INV-R4 (fix #2): Unconditionally drain protocol first on every wake.
            drain_result = _drain_protocol()
            if drain_result is not None:
                return drain_result

            # After protocol drain, re-arm protocol reader.
            # Fix #1: Always re-arm (even after terminal_seen) until feed_eof returns.
            reg_result = _rearm_protocol()
            if reg_result is not None:
                return reg_result

            # After protocol drain, check deadline.
            if was_deadline:
                return parser.on_deadline()

            # After protocol drain, check stop (INV-R4: protocol first).
            if was_stop:
                return parser.on_stop()

    except asyncio.CancelledError:
        raise
    finally:
        # Remove all reader registrations.
        for fd in list(registered_fds):
            try:
                loop.remove_reader(fd)
            except Exception:
                pass
        registered_fds.clear()
        try:
            loop.remove_reader(protocol_fd)
        except Exception:
            pass
        if stop_fd is not None:
            try:
                loop.remove_reader(stop_fd)
            except Exception:
                pass
        if deadline_handle is not None:
            deadline_handle.cancel()


# ---------------------------------------------------------------------------
# Bootstrap script template
# ---------------------------------------------------------------------------

def _nodechain_root() -> str:
    """T3 (H0.2): the nodechain package parent directory for B1 imports.

    The bootstrap child (B1) execve's with a minimal PATH-only environment;
    to import the trusted containment primitives (namespace_profile,
    seccomp_profile) it needs the nodechain source root on sys.path. The
    supervisor process itself was launched via ``-m nodechain...`` so the
    package location is resolvable here and embedded into the generated
    bootstrap script.
    """
    try:
        from pathlib import Path as _P
        import nodechain as _nc
        return str(_P(_nc.__file__).resolve().parent.parent)
    except Exception:
        return ""


def _build_bootstrap_script() -> str:
    """Generate the Python bootstrap script.

    The bootstrap:
    1. Reads bounded framed configuration from fd 0, then closes it.
    2. Emits ``bootstrap_started`` to the metadata pipe.
    3. Performs namespace/mount/procfs setup.
    4. Calls ``PTRACE_TRACEME`` (before seccomp — the profile may block ptrace).
    5. Applies and verifies seccomp.
    6. Sets ``FD_CLOEXEC`` on the metadata pipe write end.
    7. Emits ``enforcement_verified``.
    8. Raises ``SIGSTOP``.
    9. ``execve``s the workload.

    On any failure, emits a typed failure record and exits non-zero.
    """
    return f'''\
import json as _json
import os as _os
import signal as _signal
import sys as _sys
import struct as _struct
import time as _time

_PROTO_VERSION = {PROTO_VERSION}
_META_BOOTSTRAP_STARTED = "{META_BOOTSTRAP_STARTED}"
_META_ENFORCEMENT_VERIFIED = "{META_ENFORCEMENT_VERIFIED}"
_META_ENFORCEMENT_FAILED = "{META_ENFORCEMENT_FAILED}"
_META_PTRACE_TRACEME_FAILED = "{META_PTRACE_TRACEME_FAILED}"
_META_BOOTSTRAP_FAILED = "{META_BOOTSTRAP_FAILED}"
_PTRACE_TRACEME = {PTRACE_TRACEME}

_MAX_CONFIG_BYTES = {MAX_CONFIG_BYTES}


def _detect_dup_keys(pairs):
    seen = set()
    for k, _ in pairs:
        if k in seen:
            raise ValueError("duplicate key")
        seen.add(k)
    return dict(pairs)


def _read_bounded_config(config_fd, deadline, max_bytes=_MAX_CONFIG_BYTES):
    """Read framed config: 4-byte header + exact payload + clean EOF."""
    import select as _select

    def _read_exact(count, allow_eof=False):
        buf = bytearray()
        while len(buf) < count:
            remaining = deadline - _time.monotonic()
            if remaining <= 0:
                raise ValueError("config_timeout")
            try:
                r, _, _ = _select.select([config_fd], [], [], min(remaining, 1.0))
            except InterruptedError:
                continue
            if not r:
                continue
            try:
                chunk = _os.read(config_fd, count - len(buf))
            except InterruptedError:
                continue
            except OSError as e:
                raise ValueError(f"config_read_error: {{e}}")
            if not chunk:
                if allow_eof and len(buf) == 0:
                    return None
                raise ValueError("config_partial_eof")
            buf.extend(chunk)
        return bytes(buf)

    header = _read_exact(4)
    declared = _struct.unpack(">I", header)[0]
    if declared > max_bytes:
        raise ValueError("config_oversized")
    if declared == 0:
        raise ValueError("config_empty_payload")
    payload = _read_exact(declared)
    trailing = _read_exact(1, allow_eof=True)
    if trailing is not None:
        raise ValueError("config_trailing_bytes")
    try:
        obj = _json.loads(payload.decode("utf-8"), object_pairs_hook=_detect_dup_keys)
    except Exception:
        raise ValueError("config_malformed")
    if not isinstance(obj, dict):
        raise ValueError("config_non_object")
    return obj


def _emit_meta(metadata_fd, record):
    """Write one JSON-line metadata record."""
    data = (_json.dumps(record) + "\\n").encode("utf-8")
    written = 0
    while written < len(data):
        try:
            n = _os.write(metadata_fd, data[written:])
        except InterruptedError:
            continue
        except OSError:
            return False
        if n <= 0:
            return False
        written += n
    return True


def main():
    config_fd = 0
    metadata_fd = None
    stage = "init"

    try:
        # Read configuration.
        cfg = _read_bounded_config(config_fd, deadline=_time.monotonic() + 30.0)
        _os.close(config_fd)  # close fd 0 before workload exec
        metadata_fd = cfg["metadata_fd"]
        workload_argv = cfg["workload_argv"]
        workload_env = cfg.get("workload_env", {{}})

        # Emit bootstrap_started.
        if not _emit_meta(metadata_fd, {{"type": _META_BOOTSTRAP_STARTED}}):
            _os._exit(125)
        stage = "bootstrap_started"

        # --- T2: Configure workload FD 0 and apply cwd ---
        # These stages occur AFTER bootstrap_started (the metadata parser
        # requires bootstrap_started as the first record) and BEFORE
        # namespace verification/enforcement_verified, so a failure here
        # produces a valid bootstrap_started → bootstrap_failed sequence
        # with the specific stage preserved.

        # T2: FD 0 setup (payload pipe via dup2, or /dev/null).
        stage = "workload_stdin_setup"
        _workload_input_rfd = cfg.get("workload_input_rfd")
        if _workload_input_rfd is not None:
            # Validate before use.
            if type(_workload_input_rfd) is not int or _workload_input_rfd < 3 \
                    or _workload_input_rfd == metadata_fd:
                _emit_meta(metadata_fd, {{"type": _META_BOOTSTRAP_FAILED,
                    "stage": "workload_stdin_setup", "reason": "invalid_workload_input_rfd"}})
                _sys.stderr.write("bootstrap: invalid workload_input_rfd\\n")
                _os._exit(126)
            _os.dup2(_workload_input_rfd, 0, inheritable=True)
            if _workload_input_rfd != 0:
                _os.close(_workload_input_rfd)
        else:
            # No payload: open /dev/null on FD 0, ensure inheritable.
            _dev_null = _os.open("/dev/null", _os.O_RDONLY)
            try:
                if _dev_null != 0:
                    _os.dup2(_dev_null, 0, inheritable=True)
                else:
                    _os.set_inheritable(0, True)
            finally:
                if _dev_null != 0:
                    _os.close(_dev_null)
        _os.set_inheritable(0, True)  # belt-and-suspenders invariant

        # T2: Apply workload_cwd before enforcement_verified.
        stage = "workload_cwd"
        _workload_cwd = cfg.get("workload_cwd")
        if _workload_cwd is not None:
            if not isinstance(_workload_cwd, str) or not _workload_cwd:
                _emit_meta(metadata_fd, {{"type": _META_BOOTSTRAP_FAILED,
                    "stage": "workload_cwd", "reason": "invalid_workload_cwd"}})
                _sys.stderr.write("bootstrap: invalid workload_cwd\\n")
                _os._exit(126)
            try:
                _os.chdir(_workload_cwd)
            except OSError as _cwd_err:
                _emit_meta(metadata_fd, {{"type": _META_BOOTSTRAP_FAILED,
                    "stage": "workload_cwd", "reason": f"chdir_failed: {{_cwd_err}}"}})
                _sys.stderr.write(f"bootstrap: chdir failed: {{_cwd_err}}\\n")
                _os._exit(126)

        # --- S3.2 Task 4: PID-namespace verification (before PTRACE_TRACEME) ---
        # The bootstrap must verify it is running inside the expected PID
        # namespace BEFORE calling PTRACE_TRACEME or emitting
        # enforcement_verified. The expected identity was established by
        # S's topology proof and forwarded through I's config pipe.
        #
        # This replaces the S2 stub. Failures emit bootstrap_failed with
        # a stable reason and exit before PTRACE_TRACEME.
        _exp_dev = cfg.get("expected_pidns_dev")
        _exp_ino = cfg.get("expected_pidns_ino")
        if _exp_dev is not None and _exp_ino is not None:
            # Verify getpid > 1 and getppid == 1 (inside the namespace).
            if _os.getpid() <= 1:
                _emit_meta(metadata_fd, {{"type": _META_BOOTSTRAP_FAILED,
                    "stage": "namespace_verify", "reason": "bootstrap_pid_not_gt_1"}})
                _sys.stderr.write("bootstrap: getpid() <= 1 in namespace\\n")
                _os._exit(126)
            if _os.getppid() != 1:
                _emit_meta(metadata_fd, {{"type": _META_BOOTSTRAP_FAILED,
                    "stage": "namespace_verify", "reason": "bootstrap_ppid_not_1"}})
                _sys.stderr.write("bootstrap: getppid() != 1 in namespace\\n")
                _os._exit(126)
            # Verify /proc/self/ns/pid matches the expected namespace.
            try:
                _ns_st = _os.stat("/proc/self/ns/pid")
            except OSError as _ns_err:
                _emit_meta(metadata_fd, {{"type": _META_BOOTSTRAP_FAILED,
                    "stage": "namespace_verify", "reason": "ns_pid_read_failed"}})
                _sys.stderr.write(f"bootstrap: /proc/self/ns/pid stat failed: {{_ns_err}}\\n")
                _os._exit(126)
            if _ns_st.st_dev != _exp_dev or _ns_st.st_ino != _exp_ino:
                _emit_meta(metadata_fd, {{"type": _META_BOOTSTRAP_FAILED,
                    "stage": "namespace_verify", "reason": "ns_pid_identity_mismatch"}})
                _sys.stderr.write(
                    f"bootstrap: ns/pid mismatch dev={{_ns_st.st_dev}} ino={{_ns_st.st_ino}} "
                    f"expected dev={{_exp_dev}} ino={{_exp_ino}}\\n")
                _os._exit(126)
            enforcement_meta = {{
                "enforcement": "pid_namespace_verified",
                "namespace_pid": _os.getpid(),
                "namespace_parent_pid": _os.getppid(),
                "pidns_dev": _ns_st.st_dev,
                "pidns_ino": _ns_st.st_ino,
            }}
        else:
            # No expected identity — fail closed. In the S3.2 topology the
            # expected identity must always be present (S always builds a
            # topology proof). Its absence means the proof was not forwarded.
            _emit_meta(metadata_fd, {{"type": _META_BOOTSTRAP_FAILED,
                "stage": "namespace_verify", "reason": "expected_identity_absent"}})
            _sys.stderr.write("bootstrap: expected_pidns_dev/ino absent from config\\n")
            _os._exit(126)

        # Fix #3 (round 3): optional B1 FD report for lifecycle testing.
        # When _bootstrap_report_fds is set in config, enumerate /proc/self/fd
        # and include the result in enforcement_verified metadata. This lets
        # the B1 lifecycle test verify protocol pipe identity is absent from
        # the bootstrap's descriptor table after the Python exec.
        if cfg.get("_bootstrap_report_fds"):
            _fd_report = []
            try:
                for _entry in _os.listdir("/proc/self/fd"):
                    try:
                        _fd = int(_entry)
                        _st = _os.fstat(_fd)
                        _fd_report.append([_fd, _st.st_dev, _st.st_ino])
                    except OSError:
                        pass
            except OSError:
                pass
            enforcement_meta["fd_report"] = _fd_report

        # --- PTRACE_TRACEME (before seccomp) ---
        import ctypes as _ctypes
        libc = _ctypes.CDLL(None, use_errno=True)
        libc.ptrace.argtypes = [_ctypes.c_long, _ctypes.c_int,
                                _ctypes.c_void_p, _ctypes.c_void_p]
        libc.ptrace.restype = _ctypes.c_long
        r = libc.ptrace(_PTRACE_TRACEME, 0, None, None)
        if r != 0:
            _errno = _ctypes.get_errno()
            _emit_meta(metadata_fd, {{"type": _META_PTRACE_TRACEME_FAILED, "errno": _errno}})
            _sys.stderr.write(f"bootstrap: PTRACE_TRACEME failed errno={{_errno}}\\n")
            _os._exit(126)

        # --- T3 (H0.2): requested OS containment — fail-closed (S3 slot) ---
        # Every control requested for this invocation is applied HERE, in
        # the trusted bootstrap, BEFORE workload exec. Ordering: namespaces
        # first, confinement next, seccomp LAST (the profile denies
        # unshare/mount). Any requested control that cannot be enforced
        # aborts before the workload can start — never a weak fallback.
        _containment = cfg.get("containment", {{}})
        _enf = {{}}
        _failed = []

        _nc_root = {repr(_nodechain_root())}
        if _nc_root:
            if _nc_root not in _sys.path:
                _sys.path.insert(0, _nc_root)

        if _containment.get("network_namespace"):
            try:
                from nodechain.sdk.namespace_profile import apply_network_namespace as _ann
                if _ann():
                    _enf["network_namespace_enforced"] = True
                else:
                    _failed.append("network_namespace")
            except Exception as _e:
                _enf["network_namespace_error"] = str(_e)
                _failed.append("network_namespace")

        if _containment.get("mount_namespace") and not _containment.get("mount_confinement"):
            try:
                from nodechain.sdk.namespace_profile import apply_mount_namespace as _amn
                if _amn():
                    _enf["mount_namespace_enforced"] = True
                else:
                    _failed.append("mount_namespace")
            except Exception as _e:
                _enf["mount_namespace_error"] = str(_e)
                _failed.append("mount_namespace")

        if _containment.get("mount_confinement"):
            try:
                from nodechain.sdk.namespace_profile import (
                    apply_mount_confinement as _amc,
                )
                _interp = _sys.executable or "/usr/bin/python3"
                _extra = []
                for _d in ("/usr", "/lib", "/lib64"):
                    if _os.path.isdir(_d):
                        _extra.append((_d, _d))
                # T3 privileged-qualification fix: the chroot has no
                # ld.so.cache, so the interpreter's lib dir (e.g.
                # /usr/local/lib on official python images — where
                # libpythonX.Y.so lives) must be bound explicitly; the
                # adapter names it in LD_LIBRARY_PATH for the loader.
                _ilib = _containment.get("interpreter_libdir")
                if isinstance(_ilib, str) and _ilib and _os.path.isdir(_ilib):
                    _pair = (_ilib, _ilib)
                    if _pair not in _extra:
                        _extra.append(_pair)
                if "/.venv/" in _interp or "/venv/" in _interp:
                    _parts = _interp.split("/")
                    if "bin" in _parts:
                        _vr = "/".join(_parts[:_parts.index("bin")])
                        if _vr and _os.path.isdir(_vr):
                            _extra.append((_vr, _vr))
                # T3 read-only containment contract: the package bind and
                # every runtime extra mount are remounted read-only inside
                # the primitive; /tmp stays writable. Any required remount
                # that cannot be established makes the primitive return
                # not-enforced → this block fails confinement (fail closed
                # before workload exec).
                _ro = ["/package"]
                _ro.extend(_t for _s, _t in _extra)
                _cr = _amc(
                    package_root=_containment.get("package_root", "/"),
                    temp_dir=_containment.get("temp_dir", "/tmp"),
                    extra_mounts=_extra,
                    read_only_targets=_ro,
                )
                if isinstance(_cr, dict) and _cr.get("mount_confinement_enforced"):
                    _enf["mount_confinement_enforced"] = True
                    _enf["allowed_mounts"] = _cr.get("allowed_mounts", [])
                    _enf["read_only_mounts"] = _cr.get("read_only_mounts", [])
                else:
                    _failed.append("mount_confinement")
            except Exception as _e:
                _enf["mount_confinement_error"] = str(_e)
                _failed.append("mount_confinement")

        # T3 (H0.2 review fix): confinement chroots into temp_root and
        # chdir("/")s, discarding the earlier workload_cwd. Re-establish the
        # WORKLOAD-VISIBLE cwd before exec authority is crossed. The value
        # comes from the containment config's workload_visible_cwd — the
        # SAME single derivation the adapter reports as child_cwd metadata
        # (explicit package root → /package; temp-cwd case → /tmp; the
        # confinement primitive creates both inside the root). Host paths
        # are never restored inside the chroot; a missing value fails
        # closed rather than guessing. Failures join the containment
        # enforcement_failed family (this block runs in the post-TRACEME
        # region, where bootstrap_failed is structurally forbidden).
        if _containment.get("mount_confinement") and _enf.get("mount_confinement_enforced"):
            _visible_cwd = _containment.get("workload_visible_cwd")
            if not isinstance(_visible_cwd, str) or _visible_cwd not in ("/package", "/tmp"):
                _enf["workload_visible_cwd_error"] = (
                    "workload_visible_cwd_absent_or_invalid"
                )
                _failed.append("workload_visible_cwd")
            else:
                try:
                    _os.chdir(_visible_cwd)
                    _enf["workload_cwd_visible"] = _visible_cwd
                except OSError as _cwd_err:
                    _enf["workload_visible_cwd_error"] = (
                        f"workload_cwd_reestablish_failed: {{_cwd_err}}"
                    )
                    _failed.append("workload_visible_cwd")

        # Procfs isolation runs AFTER mount confinement: confinement
        # creates a fresh mount namespace and chroot, so an earlier procfs
        # remount would be discarded (and the enforced flag would lie).
        # The confinement root does not contain a /proc mountpoint, so it
        # must be created inside the root before the remount helper runs —
        # otherwise the composition fails closed instead of producing the
        # requested verified procfs view.
        if _containment.get("procfs_isolation"):
            if _containment.get("mount_confinement") and _enf.get("mount_confinement_enforced"):
                try:
                    _os.mkdir("/proc", 0o755)
                except FileExistsError:
                    pass
                except OSError as _procdir_err:
                    _enf["procfs_error"] = f"proc_mountpoint_failed: {{_procdir_err}}"
                    _failed.append("procfs_isolation")
            if "procfs_isolation" not in _failed:
                try:
                    from nodechain.sdk.namespace_profile import (
                        remount_procfs_for_pid_namespace as _rproc,
                    )
                    _pr = _rproc()
                    if isinstance(_pr, dict):
                        for _k, _v in _pr.items():
                            _enf[_k] = _v
                        if not _pr.get("procfs_namespace_view_enforced"):
                            _failed.append("procfs_isolation")
                    else:
                        _failed.append("procfs_isolation")
                except Exception as _e:
                    _enf["procfs_error"] = str(_e)
                    _failed.append("procfs_isolation")

        if _containment.get("seccomp"):
            try:
                from nodechain.sdk.seccomp_profile import (
                    SeccompBackend as _SB, SeccompProfile as _SP,
                )
                _sb = _SB()
                if not _sb.available:
                    _failed.append("seccomp")
                    _enf["seccomp_available"] = False
                elif not _sb.apply_profile(_SP()):
                    _failed.append("seccomp")
                    _enf["seccomp_available"] = True
                else:
                    _enf["seccomp_enforced"] = True
                    _enf["seccomp_available"] = True
            except Exception as _e:
                _enf["seccomp_error"] = str(_e)
                _failed.append("seccomp")

        if _failed:
            _emit_meta(metadata_fd, {{
                "type": _META_ENFORCEMENT_FAILED,
                "failed_primitives": _failed,
            }})
            _sys.stderr.write(
                "bootstrap: containment unavailable: " + ", ".join(_failed)
                + " — workload NOT started\\n")
            _os._exit(126)

        enforcement_meta.update(_enf)

        # Set FD_CLOEXEC on metadata_fd so it closes at workload exec (B2).
        # Fix #10: failure to establish the locked B2 inheritance rule MUST
        # abort before enforcement_verified — not silently continue.
        try:
            import fcntl as _fcntl
            _flags = _fcntl.fcntl(metadata_fd, _fcntl.F_GETFD)
            _fcntl.fcntl(metadata_fd, _fcntl.F_SETFD, _flags | _fcntl.FD_CLOEXEC)
        except (ImportError, OSError) as _cloexec_err:
            _emit_meta(metadata_fd, {{
                "type": _META_BOOTSTRAP_FAILED,
                "stage": "cloexec_metadata",
                "reason": str(_cloexec_err),
            }})
            _sys.stderr.write(f"bootstrap: CLOEXEC on metadata_fd failed: {{_cloexec_err}}\\n")
            _os._exit(126)

        # Emit enforcement_verified.
        _emit_meta(metadata_fd, {{
            "type": _META_ENFORCEMENT_VERIFIED,
            "metadata": enforcement_meta,
        }})

        # Stop for the supervisor to arm PTRACE_O_TRACEEXEC.
        _os.kill(_os.getpid(), _signal.SIGSTOP)

        # Exec the workload (B2).
        argv0 = workload_argv[0] if workload_env else ""
        env = dict(workload_env)
        if "/" in (workload_argv[0] if workload_argv else ""):
            _os.execve(workload_argv[0], workload_argv, env)
        else:
            _os.execvpe(workload_argv[0], workload_argv, env)
        # NOTREACHED
        _sys.stderr.write("bootstrap: execve returned unexpectedly\\n")
        _os._exit(127)

    except Exception as e:
        import traceback as _tb
        _err = str(_tb.format_exc())[:500]
        if metadata_fd is not None:
            _emit_meta(metadata_fd, {{
                "type": _META_BOOTSTRAP_FAILED,
                "stage": stage,
                "reason": _err,
            }})
        _sys.stderr.write(f"bootstrap failed at stage {{stage}}: {{_err}}\\n")
        _os._exit(126)


main()
'''


# ---------------------------------------------------------------------------
# Supervisor main
# ---------------------------------------------------------------------------

def supervisor_main(
    config: dict[str, Any],
    protocol_fd: int,
    workload_input_fd: int | None = None,
) -> int:
    """Supervisor entry point.

    T2: ``workload_input_fd`` is the parent-created workload-input read-end.
    I owns it until the B1 fork, where it is checked-closed (handoff to B1
    via the inheritable allowlist + dup2 in the bootstrap).

    Returns an exit code (0 on success, non-zero on any failure).

    Fix #2 (review round 2): mandatory protocol emit failure terminates the
    supervisor — the trusted audit channel must not be silently lost.
    Fix #3 (review round 2): pipe creation, config serialization, and fork
    are wrapped in a try boundary through fail_and_cleanup.
    Fix #4 (review round 2): unexpected wait status / ChildProcessError in
    the tracing loop sets supervisor_error (no incomplete protocol → success).
    """
    pipes = SupervisorPipeSet(protocol_wfd=protocol_fd)
    bootstrap_pid = 0  # 0 = not forked yet

    # S3.2 Task 5: capture the accepted namespace identity for cleanup guard.
    expected_pidns_dev = config.get("expected_pidns_dev")
    expected_pidns_ino = config.get("expected_pidns_ino")

    # Mark protocol_wfd CLOEXEC before bootstrap fork (defense in depth).
    try:
        import fcntl
        flags = fcntl.fcntl(protocol_fd, fcntl.F_GETFD)
        fcntl.fcntl(protocol_fd, fcntl.F_SETFD, flags | fcntl.FD_CLOEXEC)
    except (ImportError, OSError):
        pass

    # Track whether the protocol channel is alive.
    # Fix #2: mandatory emit failure on a live-governed channel terminates.
    protocol_alive = True

    def _emit_mandatory(record: dict[str, Any]) -> bool:
        """Emit a mandatory protocol record. Returns True on success.

        Fix #2: if the trusted channel is lost, this returns False. The caller
        must treat a False return as a supervisor failure: kill the bootstrap,
        emit cleanup_completed best-effort, and return nonzero.
        """
        nonlocal protocol_alive
        if not protocol_alive:
            return False
        try:
            emit_protocol(protocol_fd, record)
            return True
        except ProtocolChannelError as e:
            sys.stderr.write(f"supervisor: mandatory protocol emit failed: {e.reason}\n")
            protocol_alive = False
            return False

    def _fail_and_cleanup(
        reason: str,
        *,
        errno_value: int | None = None,
        force_cleanup_failed: bool = False,
    ) -> int:
        """Single terminalization boundary.

        Fix #6: protocol-delivery failure never bypasses process cleanup.
        Fix #2: if the protocol channel broke, this still attempts cleanup.
        S3.2 Task 5: namespace-wide cleanup runs unconditionally.
        T2 fix (B3): ``force_cleanup_failed`` forces cleanup_succeeded=False
        even when namespace child cleanup succeeds. Used when a workload-input
        FD handoff close failed — a competing reader may remain, so cleanup
        cannot be claimed successful.
        """
        _emit_mandatory({"type": PROTO_SUPERVISOR_FAILED,
                         "reason": reason,
                         **({"errno": errno_value} if errno_value is not None else {})})
        # Task 5: always run namespace-wide cleanup, even if bootstrap_pid == 0.
        cleanup_ok = _cleanup_namespace(
            bootstrap_pid if bootstrap_pid > 0 else None,
            expected_pidns_dev,
            expected_pidns_ino,
        )
        # T2 fix (B3): combine namespace cleanup with forced failure.
        if force_cleanup_failed:
            cleanup_ok = False
        # Best-effort terminal record (only meaningful if channel is alive).
        if protocol_alive:
            try:
                emit_protocol(protocol_fd, {"type": PROTO_CLEANUP_COMPLETED,
                                            "cleanup_succeeded": cleanup_ok})
            except ProtocolChannelError:
                pass
        pipes.close_non_protocol()
        pipes.close_protocol()
        return 1

    # Initial emit — if this fails, no governed execution can proceed.
    # S3.2 Task 5: route through _fail_and_cleanup so namespace cleanup runs.
    if not _emit_mandatory({"type": PROTO_SUPERVISOR_STARTED}):
        sys.stderr.write("supervisor: protocol channel broken at startup\n")
        return _fail_and_cleanup("protocol_channel_broken_at_startup")

    # T2: register the workload-input FD on the pipe set before any setup.
    pipes.workload_input_rfd = workload_input_fd

    # Fix #3 (round 2): wrap pipe creation, config serialization, and fork in try.
    # Fix #2 (round 3): catch TypeError/ValueError too (json.dumps can raise
    # TypeError on non-serializable workload_env).
    try:
        pipes.config_rfd, pipes.config_wfd = os.pipe()
        pipes.metadata_rfd, pipes.metadata_wfd = os.pipe()

        bootstrap_config = {
            "metadata_fd": pipes.metadata_wfd,
            "workload_argv": config.get("workload_argv", [sys.executable, "-c", "pass"]),
            "workload_env": config.get("workload_env", {}),
            "_bootstrap_report_fds": config.get("_bootstrap_report_fds", False),
            # Task 4: expected PID-namespace identity for bootstrap
            # pre-ptrace verification. Injected by namespace_init from
            # the accepted topology proof; absent on non-S3.2 paths.
            "expected_pidns_dev": config.get("expected_pidns_dev"),
            "expected_pidns_ino": config.get("expected_pidns_ino"),
            # T2: forward workload-input FD and cwd into the trusted
            # bootstrap config for B1 → B2.
            "workload_input_rfd": pipes.workload_input_rfd,
            "workload_cwd": config.get("workload_cwd"),
            # T3 (H0.2): requested OS containment — applied fail-closed by
            # the trusted bootstrap before workload exec.
            "containment": config.get("containment", {}),
        }
        config_payload = json.dumps(bootstrap_config).encode("utf-8")

        bootstrap_pid = os.fork()
    except (OSError, TypeError, ValueError) as exc:
        # Lock 3: explicitly checked-close the workload FD before teardown.
        if not pipes.close_workload_input_after_fork():
            return _fail_and_cleanup(
                "workload_input_close_failed",
                force_cleanup_failed=True,
            )
        return _fail_and_cleanup(f"setup_failed: {exc}")

    if bootstrap_pid == 0:
        # ==================== BOOTSTRAP CHILD ====================
        _run_bootstrap_child(pipes)
        os._exit(127)

    # ==================== SUPERVISOR ====================
    # T2 Lock 2: checked I→B1 handoff — MUST happen before bootstrap_spawned,
    # config delivery, metadata waiting, and ptrace. A retained read end
    # would suppress EPIPE and keep the parent writer blocked. If the
    # checked close fails, fail immediately — do not advertise a governed
    # bootstrap while retaining a competing reader.
    # T2 fix (B3): force_cleanup_failed=True so cleanup_succeeded is False
    # even if namespace child cleanup succeeds — a competing reader may remain.
    if not pipes.close_workload_input_after_fork():
        return _fail_and_cleanup(
            "workload_input_handoff_close_failed",
            force_cleanup_failed=True,
        )

    pipes.close_supervisor_unused_after_fork()

    # Fix #2: mandatory emit failure on bootstrap_spawned terminates.
    if not _emit_mandatory({"type": PROTO_BOOTSTRAP_SPAWNED, "pid": bootstrap_pid}):
        return _fail_and_cleanup("protocol_emit_bootstrap_spawned_failed")

    try:
        write_bounded_config(
            pipes.config_wfd, config_payload,
            deadline=time.monotonic() + CONFIG_DEADLINE_SECONDS,
        )
    except ConfigChannelError as e:
        return _fail_and_cleanup(f"config: {e.reason}")

    pipes._close_fd("config_wfd")

    meta_result = read_bounded_metadata(
        pipes.metadata_rfd,
        child_pid=bootstrap_pid,
        deadline=time.monotonic() + METADATA_DEADLINE_SECONDS,
    )
    if not meta_result.ok:
        return _fail_and_cleanup(f"metadata: {meta_result.reason}")

    # T3 (H0.2): forward the trusted containment evidence (namespace/
    # confinement/seccomp enforcement flags) from the bootstrap's
    # enforcement_verified metadata record into the protocol stream — the
    # evidence extractor reads rec["metadata"] and the result mapper
    # projects it into sandbox_metadata for the caller.
    _enf_meta = meta_result.metadata.get("metadata")
    _enf_rec = {"type": PROTO_ENFORCEMENT_VERIFIED}
    if isinstance(_enf_meta, dict):
        _enf_rec["metadata"] = _enf_meta
    if not _emit_mandatory(_enf_rec):
        return _fail_and_cleanup("protocol_emit_enforcement_verified_failed")

    try:
        wpid, status = os.waitpid(bootstrap_pid, 0)
        if not os.WIFSTOPPED(status) or os.WSTOPSIG(status) != signal.SIGSTOP:
            return _fail_and_cleanup("bootstrap_did_not_sigstop")
    except ChildProcessError:
        return _fail_and_cleanup("waitpid_sigstop_failed")

    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
    libc.ptrace.restype = ctypes.c_long

    def _checked_ptrace_cont(pid: int, sig: int = 0) -> bool:
        r = libc.ptrace(PTRACE_CONT, pid, None, sig)
        return r == 0

    result = libc.ptrace(PTRACE_SETOPTIONS, bootstrap_pid, None, PTRACE_O_TRACEEXEC)
    if result != 0:
        return _fail_and_cleanup("ptrace_setoptions_failed",
                                 errno_value=ctypes.get_errno())

    if not _emit_mandatory({"type": PROTO_EXEC_MONITOR_ARMED}):
        return _fail_and_cleanup("protocol_emit_exec_monitor_armed_failed")

    if not _checked_ptrace_cont(bootstrap_pid):
        return _fail_and_cleanup("ptrace_cont_initial_failed",
                                 errno_value=ctypes.get_errno())

    # Wait for exec event or workload exit.
    exec_confirmed = False
    supervisor_error: str | None = None
    workload_exit_code = None
    workload_signaled = False
    workload_signal_num = None
    workload_terminal = False

    while True:
        try:
            wpid, status = os.waitpid(bootstrap_pid, 0)
        except ChildProcessError:
            # Fix #4: ChildProcessError after exec → supervisor error.
            if exec_confirmed:
                supervisor_error = "waitpid_child_lost_after_exec"
            else:
                supervisor_error = "waitpid_child_lost_before_exec"
            break
        except OSError:
            if exec_confirmed:
                supervisor_error = "waitpid_oserror_after_exec"
            else:
                supervisor_error = "waitpid_oserror_before_exec"
            break

        if os.WIFSTOPPED(status):
            stopsig = os.WSTOPSIG(status)
            event = status >> 16

            if stopsig == signal.SIGTRAP and event == PTRACE_EVENT_EXEC:
                exec_confirmed = True
                # Fix #2: exec_confirmed is mandatory — channel loss terminates.
                if not _emit_mandatory({"type": PROTO_EXEC_CONFIRMED}):
                    return _fail_and_cleanup("protocol_emit_exec_confirmed_failed")
                if not _checked_ptrace_cont(bootstrap_pid):
                    supervisor_error = "ptrace_cont_after_exec_failed"
                    break
                continue
            else:
                if not _checked_ptrace_cont(bootstrap_pid, sig=stopsig):
                    supervisor_error = "ptrace_cont_signal_forward_failed"
                    break
                continue
        elif os.WIFEXITED(status):
            workload_exit_code = os.WEXITSTATUS(status)
            workload_terminal = True
            break
        elif os.WIFSIGNALED(status):
            workload_signaled = True
            workload_signal_num = os.WTERMSIG(status)
            workload_terminal = True
            break
        else:
            # Fix #4: unexpected wait status → supervisor error.
            supervisor_error = f"unexpected_wait_status: {status}"
            break

    # Fix #4: if loop exited without a verified workload terminal AND no error
    # was set, that's itself a supervisor error.
    if supervisor_error is None and not workload_terminal:
        supervisor_error = "loop_exit_without_terminal"

    if supervisor_error is not None:
        return _fail_and_cleanup(supervisor_error,
                                 errno_value=ctypes.get_errno())

    # Report workload outcome.
    if exec_confirmed and workload_terminal:
        if workload_signaled:
            if not _emit_mandatory({"type": PROTO_WORKLOAD_EXITED,
                                    "started": True, "signaled": True,
                                    "signal_num": workload_signal_num}):
                return _fail_and_cleanup("protocol_emit_workload_exited_failed")
        else:
            if not _emit_mandatory({"type": PROTO_WORKLOAD_EXITED,
                                    "started": True,
                                    "exit_code": workload_exit_code}):
                return _fail_and_cleanup("protocol_emit_workload_exited_failed")
    elif not exec_confirmed:
        if workload_signaled:
            return _fail_and_cleanup("bootstrap_killed_before_exec")
        else:
            return _fail_and_cleanup(f"bootstrap_exited_before_exec: {workload_exit_code}")

    # Normal cleanup.
    # S3.2 Task 5: namespace-wide cleanup.
    cleanup_ok = _cleanup_namespace(
        bootstrap_pid if bootstrap_pid > 0 else None,
        expected_pidns_dev,
        expected_pidns_ino,
    )
    # Fix #1 (round 3): cleanup_completed is mandatory on the normal branch.
    # If the channel breaks here, success is impossible.
    if not _emit_mandatory({"type": PROTO_CLEANUP_COMPLETED,
                            "cleanup_succeeded": cleanup_ok}):
        # Channel broke — protocol_alive is now False.
        pipes.close_non_protocol()
        pipes.close_protocol()
        return 1
    pipes.close_non_protocol()
    pipes.close_protocol()

    # Fix #4: success requires exec_confirmed AND workload_terminal AND
    # cleanup_succeeded AND no supervisor_error AND protocol_alive
    # (which now includes successful cleanup_completed delivery).
    return 0 if (exec_confirmed and workload_terminal and cleanup_ok
                 and supervisor_error is None and protocol_alive) else 1


def _try_emit(protocol_fd: int, record: dict[str, Any]) -> None:
    """Best-effort protocol emit. Silently ignores broken-pipe errors.

    Fix #6: protocol-delivery failure is recorded locally but never bypasses
    process cleanup. The supervisor logs to stderr if the protocol pipe breaks.
    """
    try:
        emit_protocol(protocol_fd, record)
    except ProtocolChannelError as e:
        sys.stderr.write(f"supervisor: protocol emit failed: {e.reason}\n")


def _run_bootstrap_child(pipes: SupervisorPipeSet) -> None:
    """Bootstrap child setup: configure FDs and exec the Python bootstrap.

    Called from within ``supervisor_main`` after fork — runs in the child
    process and never returns (execves or exits).
    """
    # dup2 config_rfd → fd 0.
    if pipes.config_rfd != 0:
        os.dup2(pipes.config_rfd, 0)

    # Mark metadata_wfd inheritable across B1.
    os.set_inheritable(pipes.metadata_wfd, True)

    # Close protocol_wfd (defense in depth).
    try:
        os.close(pipes.protocol_wfd)
    except (OSError, TypeError):
        pass

    # Close supervisor-side pipe ends.
    try:
        os.close(pipes.config_wfd)
    except (OSError, TypeError):
        pass
    try:
        os.close(pipes.metadata_rfd)
    except (OSError, TypeError):
        pass

    # Close original config_rfd if duped.
    if pipes.config_rfd != 0:
        try:
            os.close(pipes.config_rfd)
        except OSError:
            pass

    # Close every FD except {0, 1, 2, metadata_wfd}.
    # T2: if a workload-input FD is present, mark it inheritable across the
    # B1 execve and add it to the allowlist so it survives _close_all_except.
    if pipes.workload_input_rfd is not None and pipes.workload_input_rfd >= 0:
        os.set_inheritable(pipes.workload_input_rfd, True)
        _close_all_except({pipes.metadata_wfd, pipes.workload_input_rfd})
    else:
        _close_all_except({pipes.metadata_wfd})

    # Exec the Python bootstrap.
    bootstrap_script = _build_bootstrap_script()
    os.execve(sys.executable, [sys.executable, "-c", bootstrap_script],
              {"PATH": "/usr/bin:/bin"})


def _cleanup_namespace(
    primary_pid: int | None,
    expected_pidns_dev: int,
    expected_pidns_ino: int,
) -> bool:
    """S3.2 Task 5: namespace-wide terminal cleanup from namespace-init I.

    Runs inside I (namespace PID 1). Performs a bounded namespace-wide
    kill-and-reap sequence. Returns ``True`` ONLY if ``ECHILD`` is proven
    (``waitpid(-1, WNOHANG)`` raises ``ChildProcessError``).

    Identity guard: before any ``kill(-1, ...)``, requires:
      ``getpid() == 1``, ``getppid() == 0``, and
      ``/proc/self/ns/pid`` identity matches the accepted Task 4 proof.
    If the guard fails, no namespace-wide signal is sent. An optional
    best-effort exact-PID fallback may run, but the result is always
    ``False`` — namespace cleanup proof requires verified-I authority.

    ``primary_pid``: the bootstrap PID (may be ``None`` if fork hasn't
    happened or the bootstrap was already reaped). Used only for the
    optional fallback, never as the authoritative proof.
    """
    TERM_GRACE_SECONDS = 2.5
    KILL_GRACE_SECONDS = 2.5
    DRAIN_GRACE_SECONDS = 0.5

    # Establish all absolute deadlines before draining.
    cleanup_start = time.monotonic()
    drain_deadline = cleanup_start + DRAIN_GRACE_SECONDS
    term_deadline = drain_deadline + TERM_GRACE_SECONDS
    final_deadline = term_deadline + KILL_GRACE_SECONDS

    # --- Identity guard ---
    guard_ok = False
    try:
        if (os.getpid() == 1 and os.getppid() == 0
                and isinstance(expected_pidns_dev, int)
                and not isinstance(expected_pidns_dev, bool)
                and expected_pidns_dev > 0
                and isinstance(expected_pidns_ino, int)
                and not isinstance(expected_pidns_ino, bool)
                and expected_pidns_ino > 0):
            ns_st = os.stat("/proc/self/ns/pid")
            if ns_st.st_dev == expected_pidns_dev and ns_st.st_ino == expected_pidns_ino:
                guard_ok = True
    except (OSError, ValueError):
        guard_ok = False

    if not guard_ok:
        # Guard failed: no kill(-1, ...). Best-effort owned-PID fallback.
        _owned_pid_fallback(primary_pid)
        return False  # Guard failure always returns False.

    # --- Namespace-wide cleanup (guard passed) ---
    wait_error_seen = False

    def _drain_immediately(deadline: float) -> str:
        """Non-blocking drain of immediately reapable children.
        Bounded by the absolute deadline. Returns 'ECHILD_PROVEN',
        'CHILDREN_REMAIN', or 'WAIT_ERROR'."""
        nonlocal wait_error_seen
        while True:
            if time.monotonic() >= deadline:
                return "CHILDREN_REMAIN"
            try:
                wpid, _ = os.waitpid(-1, os.WNOHANG)
            except InterruptedError:
                continue
            except ChildProcessError:
                return "ECHILD_PROVEN"
            except OSError as e:
                if e.errno == errno.EINTR:
                    continue
                if e.errno == errno.ECHILD:
                    return "ECHILD_PROVEN"
                wait_error_seen = True
                return "WAIT_ERROR"
            if wpid > 0:
                continue  # Reaped one child; keep draining.
            if wpid == 0:
                return "CHILDREN_REMAIN"

    def _reap_until(deadline: float) -> str:
        """Poll children until ECHILD, deadline, or wait error.
        Sleeps and retries when waitpid returns 0 (children remain)."""
        nonlocal wait_error_seen
        while True:
            if time.monotonic() >= deadline:
                return "DEADLINE_EXPIRED"
            try:
                wpid, _ = os.waitpid(-1, os.WNOHANG)
            except InterruptedError:
                continue
            except ChildProcessError:
                return "ECHILD_PROVEN"
            except OSError as e:
                if e.errno == errno.EINTR:
                    continue
                if e.errno == errno.ECHILD:
                    return "ECHILD_PROVEN"
                wait_error_seen = True
                return "WAIT_ERROR"
            if wpid > 0:
                continue
            time.sleep(0.02)

    # Step 1: Drain immediately reapable children (bounded by drain_deadline).
    drain_result = _drain_immediately(drain_deadline)
    if drain_result == "ECHILD_PROVEN":
        return not wait_error_seen
    if drain_result == "WAIT_ERROR":
        pass  # Best-effort: continue with signals, but result will be False.

    # Step 3-4: kill(-1, SIGCONT) then kill(-1, SIGTERM).
    _safe_kill_minus_one(signal.SIGCONT)
    _safe_kill_minus_one(signal.SIGTERM)

    # Step 5: Reap until TERM deadline (pre-established).
    term_result = _reap_until(term_deadline)
    if term_result == "ECHILD_PROVEN":
        return not wait_error_seen

    # Step 7-8: kill(-1, SIGCONT) then kill(-1, SIGKILL).
    _safe_kill_minus_one(signal.SIGCONT)
    _safe_kill_minus_one(signal.SIGKILL)

    # Step 9: Reap until final deadline (pre-established).
    final_result = _reap_until(final_deadline)
    if final_result == "ECHILD_PROVEN":
        return not wait_error_seen

    return False


def _safe_kill_minus_one(sig: int) -> None:
    """Send signal to all namespace processes (pid=-1). Best-effort;
    ESRCH or other errors from kill do not prove quiescence."""
    try:
        os.kill(-1, sig)
    except (OSError, ProcessLookupError):
        pass


def _owned_pid_fallback(primary_pid: int | None) -> None:
    """Best-effort exact-PID termination for the guard-failure path.

    First checks ownership via waitpid(primary_pid, WNOHANG):
      returns 0 -> still an owned unreaped child -> exact-PID signal OK
      returns primary_pid -> already reaped -> do not signal
      ECHILD -> ownership lost -> do not signal
      other error -> do not signal

    Never signals a PID that may have been recycled."""
    if primary_pid is None or primary_pid <= 0:
        return
    try:
        wpid, _ = os.waitpid(primary_pid, os.WNOHANG)
    except ChildProcessError:
        return  # Ownership lost; do not signal.
    except OSError:
        return  # Unknown state; do not signal.
    if wpid != 0:
        return  # Already reaped; do not signal.
    # wpid == 0: still an owned unreaped child -- safe to signal.
    try:
        os.kill(primary_pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        pass
    # Best-effort reap.
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        try:
            wpid, _ = os.waitpid(primary_pid, os.WNOHANG)
            if wpid != 0:
                return
        except (ChildProcessError, OSError):
            return
        time.sleep(0.02)


# ---------------------------------------------------------------------------
# S3.2 Task 3: PID-namespace launcher / namespace-init split
# ---------------------------------------------------------------------------
#
# Architecture:
#   supervisor_process_main
#     └── launch_pid_namespace_supervisor        (S — launcher)
#           ├── unshare_pid_namespace()
#           ├── fork I (first child = namespace PID 1)
#           ├── read/validate I private identity (framed, closed-schema)
#           ├── build_topology_proof(S_pid, I_host_pid)
#           ├── close S protocol writer (handoff)
#           ├── send exact release token + close gate
#           └── exact wait for I (no independent timeout)
#                 └── namespace_init_supervisor_main   (I — namespace PID 1)
#                       ├── emit private identity
#                       ├── await exact token + clean EOF
#                       └── supervisor_main()           (UNCHANGED)
#                             └── fork bootstrap        (namespace PID 2)
#
# Normal-path protocol ownership:
#   S is SILENT on the normal path. I emits supervisor_started (inside
#   supervisor_main) and owns all subsequent protocol records. S emits
#   only supervisor_failed + cleanup_completed on pre-gate failures.
#
# Locked corrections (from plan approval):
#   1. Pipe-end ownership: S keeps gate_w + identity_r; I keeps gate_r + identity_w.
#   2. Identity channel: 4-byte framed, closed-schema, 256-byte max.
#   3. Release gate: exact token + immediate clean EOF required.
#   4. Post-handoff failure window: S cannot emit after closing protocol writer.
#   5. Normal-path wait: blocking waitpid, no independent timeout.
#   6. Pre-gate containment: exact reap proof, ECHILD only.
#   7. Bootstrap PID semantics: namespace-local, not host authority.
#   8. Child exit via os._exit.
#   9. L7 characterization replacement is narrow.
#  10. Extended test coverage.

# Identity channel constants.
_IDENTITY_VERSION = 1
_IDENTITY_MAX_PAYLOAD = 256  # Excludes the 4-byte header.
_RELEASE_TOKEN = b"S3.2_RELEASE_V1\n"  # Exact token; clean EOF must follow.

# Identity record allowed fields (closed schema).
_IDENTITY_ALLOWED_FIELDS = frozenset({"version", "type", "pid", "ppid"})


class IdentityChannelError(Exception):
    """Typed failure from the launcher <-> namespace-init identity channel."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _write_identity_frame(fd: int, obj: dict[str, Any], *, deadline: float) -> None:
    """Write a 4-byte-framed identity record to *fd*.

    Uses the same framing pattern as the config channel (big-endian length
    header + payload), with a dedicated 256-byte max.
    """
    payload = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    if len(payload) > _IDENTITY_MAX_PAYLOAD:
        raise IdentityChannelError("identity_oversized")
    header = struct.pack(">I", len(payload))
    _write_bounded_fd(fd, header + payload, deadline=deadline,
                      error_cls=IdentityChannelError, reason_prefix="identity")


def _read_identity_frame(fd: int, *, deadline: float) -> dict[str, Any]:
    """Read and validate a 4-byte-framed identity record from *fd*.

    Requires clean EOF after the frame (no trailing bytes). Parses with
    duplicate-key rejection and closed-schema validation.

    Translates every ``_read_exact()`` ``ConfigChannelError`` (timeout,
    partial EOF, select failure, read failure) into
    ``IdentityChannelError`` so the launcher's ``except IdentityChannelError``
    boundary catches all identity-channel failures uniformly.
    """
    try:
        header = _read_exact(fd, 4, deadline=deadline, reason_prefix="identity_header")
    except ConfigChannelError as e:
        raise IdentityChannelError(f"identity_header_failed: {e.reason}") from e
    declared = struct.unpack(">I", header)[0]
    if declared > _IDENTITY_MAX_PAYLOAD:
        raise IdentityChannelError("identity_oversized")
    if declared == 0:
        raise IdentityChannelError("identity_empty_payload")
    try:
        payload = _read_exact(fd, declared, deadline=deadline, reason_prefix="identity_payload")
    except ConfigChannelError as e:
        raise IdentityChannelError(f"identity_payload_failed: {e.reason}") from e
    # Require clean EOF (no trailing bytes after the frame).
    try:
        trailing = _read_exact(fd, 1, deadline=deadline, reason_prefix="identity_eof",
                               allow_eof=True)
    except ConfigChannelError as e:
        raise IdentityChannelError(f"identity_eof_failed: {e.reason}") from e
    if trailing is not None:
        raise IdentityChannelError("identity_trailing_bytes")
    try:
        obj = json.loads(payload.decode("utf-8"), object_pairs_hook=_detect_dup_keys)
    except DuplicateKeyError:
        raise IdentityChannelError("identity_duplicate_key")
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        raise IdentityChannelError("identity_malformed")
    if not isinstance(obj, dict):
        raise IdentityChannelError("identity_non_object")
    return obj


def _validate_identity(obj: dict[str, Any]) -> tuple[int, int]:
    """Validate the closed-schema identity record.

    Returns ``(pid, ppid)`` on success. Raises :class:`IdentityChannelError`
    on any schema, type, or value violation.

    Required schema (exact):
        {"version": 1, "type": "init_identity", "pid": 1, "ppid": 0}

    Bool values are rejected for int fields (bool is a subclass of int in
    Python, so an explicit isinstance check is needed).
    """
    extra = set(obj.keys()) - _IDENTITY_ALLOWED_FIELDS
    if extra:
        raise IdentityChannelError(f"identity_unknown_fields: {extra}")
    missing = _IDENTITY_ALLOWED_FIELDS - set(obj.keys())
    if missing:
        raise IdentityChannelError(f"identity_missing_fields: {missing}")
    v = obj["version"]
    if isinstance(v, bool) or not isinstance(v, int) or v != _IDENTITY_VERSION:
        raise IdentityChannelError(f"identity_version_invalid: {v!r}")
    if obj["type"] != "init_identity":
        raise IdentityChannelError(f"identity_type_invalid: {obj['type']!r}")
    pid = obj["pid"]
    if isinstance(pid, bool) or not isinstance(pid, int) or pid != 1:
        raise IdentityChannelError(f"identity_pid_invalid: {pid!r}")
    ppid = obj["ppid"]
    if isinstance(ppid, bool) or not isinstance(ppid, int) or ppid != 0:
        raise IdentityChannelError(f"identity_ppid_invalid: {ppid!r}")
    return (pid, ppid)


# Proof record allowed fields (closed schema).
_PROOF_ALLOWED_FIELDS = frozenset({"version", "type", "child_pidns_dev",
                                    "child_pidns_ino", "init_host_pid"})


def _validate_proof_record(obj: dict[str, Any]) -> tuple[int, int]:
    """Validate the closed-schema topology proof record received by I.

    Returns ``(child_pidns_dev, child_pidns_ino)`` on success. Raises
    :class:`IdentityChannelError` on any schema, type, or value violation.

    Schema-only validation (the preferred narrow model): S is the sole
    host-PID binding authority — S explicitly checks
    ``proof.init_host_pid == fork-return init_host_pid`` before writing the
    frame. I validates the exact field set, version, type, positivity, and
    bool rejection, but does NOT perform an independent host-PID comparison
    (I cannot observe its own host PID from inside the namespace).

    Required schema (exact):
        {"version": 1, "type": "topology_proof",
         "child_pidns_dev": <positive int>, "child_pidns_ino": <positive int>,
         "init_host_pid": <positive int>}
    """
    extra = set(obj.keys()) - _PROOF_ALLOWED_FIELDS
    if extra:
        raise IdentityChannelError(f"proof_unknown_fields: {extra}")
    missing = _PROOF_ALLOWED_FIELDS - set(obj.keys())
    if missing:
        raise IdentityChannelError(f"proof_missing_fields: {missing}")
    v = obj["version"]
    if isinstance(v, bool) or not isinstance(v, int) or v != _IDENTITY_VERSION:
        raise IdentityChannelError(f"proof_version_invalid: {v!r}")
    if obj["type"] != "topology_proof":
        raise IdentityChannelError(f"proof_type_invalid: {obj['type']!r}")
    dev = obj["child_pidns_dev"]
    if isinstance(dev, bool) or not isinstance(dev, int) or dev <= 0:
        raise IdentityChannelError(f"proof_dev_invalid: {dev!r}")
    ino = obj["child_pidns_ino"]
    if isinstance(ino, bool) or not isinstance(ino, int) or ino <= 0:
        raise IdentityChannelError(f"proof_ino_invalid: {ino!r}")
    ihpid = obj["init_host_pid"]
    if isinstance(ihpid, bool) or not isinstance(ihpid, int) or ihpid <= 0:
        raise IdentityChannelError(f"proof_init_host_pid_invalid: {ihpid!r}")
    return (dev, ino)


def _read_exact_token(fd: int, expected: bytes, *, deadline: float) -> bool:
    """Read exactly *expected* bytes and require immediate clean EOF.

    Returns True ONLY if the exact token matched AND EOF followed
    immediately. Rejects: partial token, wrong token, extra bytes after
    token, EOF before token, timeout, or read error.
    """
    try:
        data = _read_exact(fd, len(expected), deadline=deadline,
                           reason_prefix="gate_token")
    except ConfigChannelError:
        return False
    if data != expected:
        return False
    try:
        trailing = _read_exact(fd, 1, deadline=deadline, reason_prefix="gate_eof",
                               allow_eof=True)
    except ConfigChannelError:
        return False
    if trailing is not None:
        return False  # Extra bytes after token.
    return True


def _contain_init_child(init_pid: int) -> bool:
    """Bounded containment for the namespace-init child on pre-gate failure.

    Escalates SIGTERM -> bounded reap. If SIGTERM does not produce an exact
    reap within the deadline, escalates to SIGKILL ONLY IF child authority
    has not been lost (i.e., waitpid did not raise ECHILD on the prior
    signal — ECHILD means S has lost proof that the numeric PID still
    denotes its child, and signaling a recycled PID is forbidden).

    Returns True ONLY if BOTH conditions hold:
      1. An exact ``waitpid(init_pid, ...)`` returned ``init_pid``
         (a real recorded reap — NOT ECHILD-before-reap).
      2. ``waitpid(-1, WNOHANG)`` raised ``ChildProcessError`` (ECHILD —
         no waitable child remains).

    Returns False if either condition fails.
    """
    exact_reaped = False
    child_authority_lost = False
    for sig in (signal.SIGTERM, signal.SIGKILL):
        # Correction #3: do NOT signal if child authority was lost on a
        # prior iteration (ECHILD before exact reap). The numeric PID may
        # have been recycled; signaling it risks hitting an unrelated process.
        if child_authority_lost:
            break
        try:
            os.kill(init_pid, sig)
        except (OSError, ProcessLookupError):
            pass
        reap_deadline = time.monotonic() + 2.5
        while time.monotonic() < reap_deadline:
            try:
                wpid, _ = os.waitpid(init_pid, os.WNOHANG)
            except ChildProcessError:
                # ECHILD before exact reap — child authority lost.
                # Do NOT signal this PID again.
                child_authority_lost = True
                break
            except OSError:
                break
            if wpid == init_pid:
                exact_reaped = True
                break
            time.sleep(0.02)
        if exact_reaped:
            break
    # Final proof: waitpid(-1, WNOHANG) must raise ECHILD.
    no_children = False
    try:
        os.waitpid(-1, os.WNOHANG)
        no_children = False  # A child is still waitable.
    except ChildProcessError:
        no_children = True   # ECHILD — no waitable child.
    except OSError:
        no_children = False
    return exact_reaped and no_children


def _decode_wait_status(status: int) -> int:
    """Decode a wait status into a process exit code.

    WIFEXITED -> WEXITSTATUS; WIFSIGNALED -> 128 + WTERMSIG; else -> 1.
    Never returns the raw encoded wait status.
    """
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status)
    return 1


def _contain_and_fail(
    init_pid: int, gate_w: int, protocol_fd: int,
    reason: str,
    *,
    force_cleanup_failed: bool = False,
) -> None:
    """Contain I, then emit supervisor_failed + cleanup_completed.

    Pre-gate failure path (protocol_fd still owned by S). Denies release
    by closing gate_w without the token, escalates TERM/KILL with exact
    reap proof, then emits failure records AFTER containment so S is
    demonstrably the sole remaining protocol writer.

    T2: ``force_cleanup_failed`` forces cleanup_succeeded=False even when
    namespace child cleanup succeeds. Used when a workload-input FD close
    failed — a competing reader may remain, so cleanup cannot be claimed
    successful.
    """
    # Deny release: close gate without token -> I sees EOF -> I exits.
    try: os.close(gate_w)
    except OSError: pass
    # Contain I (bounded). Carry the ACTUAL cleanup result — do not
    # hardcode True. A failed or ambiguous reap reports cleanup_succeeded=False.
    cleanup_ok = _contain_init_child(init_pid)
    # T2: combine namespace cleanup with forced failure.
    if force_cleanup_failed:
        cleanup_ok = False
    # Emit failure records (protocol_fd still ours).
    # Correction #2: when cleanup fails, encode "cleanup_failed" as the
    # supervisor_failed.reason so the frozen result mapper (which does not
    # inspect cleanup_succeeded on the pre-start path) surfaces it
    # correctly to the caller.
    effective_reason = reason if cleanup_ok else "cleanup_failed"
    try:
        emit_protocol(protocol_fd, {"type": PROTO_SUPERVISOR_FAILED,
                                    "reason": effective_reason})
        emit_protocol(protocol_fd, {"type": PROTO_CLEANUP_COMPLETED,
                                    "cleanup_succeeded": cleanup_ok})
    except ProtocolChannelError:
        pass
    try: os.close(protocol_fd)
    except OSError: pass


def launch_pid_namespace_supervisor(
    config: dict[str, Any],
    protocol_fd: int,
    workload_input_fd: int | None = None,
) -> int:
    """S3.2 launcher S: create PID namespace, verify topology, release I.

    This function runs in the external supervisor process (spawned by the
    NodeChain parent with ``start_new_session=True``). It:

      1. Calls ``unshare_pid_namespace()`` (Task 2 primitive).
      2. Forks exactly one child I (namespace-init, PID 1).
      3. Reads I's private identity (framed, closed-schema).
      4. Calls ``build_topology_proof()`` (Task 2 proof).
      5. Closes its protocol-writer copy (handoff to I).
      6. Sends the exact release token + closes the gate.
      7. Waits for I (blocking, no independent timeout).

    T2: ``workload_input_fd`` is the parent-created workload-input read-end.
    S owns it until I is forked, then checked-closes its copy immediately.
    I inherits and carries it through to ``supervisor_main``.

    On any pre-gate failure, S contains and reaps I, then emits
    ``supervisor_failed`` + ``cleanup_completed``.

    On the normal path, S is SILENT -- I emits ``supervisor_started``
    inside ``supervisor_main()`` after release.
    """
    from nodechain.runtime.pid_namespace_topology import (
        PidNamespaceUnsupported,
        PidNamespaceProofError,
        build_topology_proof,
        unshare_pid_namespace,
    )

    s_pid = os.getpid()

    # --- Gate + identity + proof pipes (with failure boundary) ---
    # Task 4: a third pipe (proof_r/proof_w) carries the accepted topology
    # proof from S to I. S writes the child namespace identity after
    # build_topology_proof succeeds; I reads it before entering supervisor_main
    # and passes it through to bootstrap_config.
    gate_r = gate_w = identity_r = identity_w = proof_r = proof_w = None

    def _prefork_fail_and_cleanup(reason: str) -> int:
        """T2: pre-fork failure with checked workload-FD closure.

        Reports cleanup_succeeded based on whether the workload-input FD
        was actually closed, not hardcoded True.
        """
        for fd in (gate_r, gate_w, identity_r, identity_w, proof_r, proof_w):
            if fd is not None:
                try: os.close(fd)
                except OSError: pass
        wl_fd_closed = True
        if workload_input_fd is not None:
            try:
                os.close(workload_input_fd)
            except OSError:
                wl_fd_closed = False
        try:
            # T2: when the workload-FD close failed, replace the reason so
            # map_supervisor_result (which chooses supervisor_failure_reason
            # before cleanup_succeeded on pre-start paths) surfaces the
            # cleanup failure to the caller.
            effective_reason = reason if wl_fd_closed else "cleanup_failed"
            emit_protocol(protocol_fd, {"type": PROTO_SUPERVISOR_FAILED,
                                        "reason": effective_reason})
            emit_protocol(protocol_fd, {"type": PROTO_CLEANUP_COMPLETED,
                                        "cleanup_succeeded": wl_fd_closed})
        except ProtocolChannelError:
            pass
        try: os.close(protocol_fd)
        except OSError: pass
        return 1

    try:
        gate_r, gate_w = os.pipe()
        identity_r, identity_w = os.pipe()
        proof_r, proof_w = os.pipe()
    except OSError as e:
        return _prefork_fail_and_cleanup(f"pipe_failed: {e}")

    # --- 1. unshare(CLONE_NEWPID) ---
    try:
        unshare_pid_namespace()
    except PidNamespaceUnsupported as e:
        return _prefork_fail_and_cleanup(f"unshare_failed: {e.reason}")

    # --- 2. Fork I (first child in new namespace = namespace PID 1) ---
    # Correction #3: fork is wrapped in a failure boundary. On fork failure,
    # no I exists — S closes all Task 3 FDs, emits typed failure, and returns.
    try:
        init_host_pid = os.fork()
    except OSError as e:
        return _prefork_fail_and_cleanup(f"fork_failed: {e}")
        return 1

    if init_host_pid == 0:
        # ==================== I -- namespace-init ====================
        # I keeps: gate_r, identity_w, proof_r. Close the other ends.
        try: os.close(gate_w)
        except OSError: pass
        try: os.close(identity_r)
        except OSError: pass
        try: os.close(proof_w)
        except OSError: pass
        # I keeps proof_r (reads the topology proof from S).
        # CRITICAL: proof_w must be closed in I so that when S also closes
        # its proof_w, the pipe has no remaining writers → I's read gets
        # EOF after the proof frame. If I retains proof_w, the read hangs
        # forever waiting for EOF that never comes (I holds a competing writer).
        # Correction #4 (review round 2): wrap the child call in a
        # BaseException boundary. If namespace_init_supervisor_main or
        # anything it calls raises unexpectedly, the child must NOT unwind
        # through the launcher/supervisor_process_main/module stack —
        # that would permit inherited exception handling, buffering, and
        # shutdown machinery to run in the fork child.
        # T2: I inherits workload_input_fd from S (fork). I owns it now.
        try:
            rc = namespace_init_supervisor_main(
                config, protocol_fd, gate_r, identity_w, proof_r,
                workload_input_fd,
            )
        except BaseException:
            # Best-effort close of child-owned descriptors.
            for fd in (gate_r, identity_w, proof_r, protocol_fd):
                try: os.close(fd)
                except OSError: pass
            if workload_input_fd is not None:
                try: os.close(workload_input_fd)
                except OSError: pass
            os._exit(1)
            return  # Defensive: os._exit should never return, but if mocked
                    # in tests, prevent fall-through to the else branch.
        else:
            # Correction #8: child must os._exit, not return through the stack.
            os._exit(rc if isinstance(rc, int) and 0 <= rc <= 255 else 1)

    # ==================== S -- launcher ====================
    # S keeps: gate_w, identity_r, proof_w. Close the other ends.
    # Each FD closed exactly once; no double-close.
    try: os.close(gate_r)
    except OSError: pass
    try: os.close(identity_w)
    except OSError: pass
    try: os.close(proof_r)
    except OSError: pass

    # T2: S checked-closes its workload_input_fd copy immediately after the
    # I fork succeeds. A retained read end would suppress EPIPE and keep the
    # parent writer blocked. If the close fails, S must deny release, contain
    # I, and fail — never continue with a possibly retained reader.
    # Use _contain_and_fail (the existing authority): it denies release by
    # closing gate_w without the token, performs bounded exact containment,
    # derives the real cleanup result, and only then emits terminal records.
    if workload_input_fd is not None:
        try:
            os.close(workload_input_fd)
        except OSError:
            _contain_and_fail(
                init_host_pid, gate_w, protocol_fd,
                "workload_input_handoff_close_failed",
                force_cleanup_failed=True,
            )
            return 1

    # --- 3. Read I's private identity (bounded, framed, closed-schema) ---
    try:
        identity_obj = _read_identity_frame(
            identity_r, deadline=time.monotonic() + METADATA_DEADLINE_SECONDS
        )
        _validate_identity(identity_obj)
    except (IdentityChannelError, OSError) as e:
        try: os.close(identity_r)
        except OSError: pass
        _contain_and_fail(init_host_pid, gate_w, protocol_fd,
                          f"identity_failed: {e}")
        return 1
    try: os.close(identity_r)
    except OSError: pass

    # --- 4. build_topology_proof(S_pid, I_host_pid) ---
    # Task 4: capture the proof so its child namespace identity can be
    # forwarded to I → bootstrap for pre-ptrace verification.
    try:
        proof = build_topology_proof(s_pid, init_host_pid)
    except PidNamespaceProofError as e:
        try: os.close(proof_w)
        except OSError: pass
        _contain_and_fail(init_host_pid, gate_w, protocol_fd,
                          f"topology_proof_failed: {e.reason}")
        return 1

    # --- 4a. Write proof frame to I (S → I proof channel) ---
    # Task 4: S writes the accepted child namespace identity so I can pass
    # it through to bootstrap_config. The proof is bound to the current
    # I host PID and the accepted child namespace device/inode.
    # Explicitly require the proof's init_host_pid matches the forked I.
    if proof.init_host_pid != init_host_pid:
        try: os.close(proof_w)
        except OSError: pass
        _contain_and_fail(init_host_pid, gate_w, protocol_fd,
                          f"proof_binding_mismatch: proof.init_host_pid="
                          f"{proof.init_host_pid} != fork_pid={init_host_pid}")
        return 1
    try:
        _write_identity_frame(proof_w, {
            "version": _IDENTITY_VERSION,
            "type": "topology_proof",
            "child_pidns_dev": proof.child_pidns_dev,
            "child_pidns_ino": proof.child_pidns_ino,
            "init_host_pid": proof.init_host_pid,
        }, deadline=time.monotonic() + 5.0)
    except (IdentityChannelError, OSError) as e:
        try: os.close(proof_w)
        except OSError: pass
        _contain_and_fail(init_host_pid, gate_w, protocol_fd,
                          f"proof_write_failed: {e}")
        return 1
    try: os.close(proof_w)
    except OSError: pass

    # --- 5. Close S protocol writer (handoff -- I is sole writer after release) ---
    # Correction #4: if the close FAILS, S must NOT release I. A failed
    # handoff close means S may retain a competing protocol writer —
    # releasing I would violate sole-writer ownership.
    protocol_handoff_ok = True
    try:
        os.close(protocol_fd)
    except OSError:
        protocol_handoff_ok = False
    if not protocol_handoff_ok:
        # Ambiguous post-handoff failure: deny release, contain I, return
        # nonzero. S cannot emit a protocol record (the close failed — the
        # FD may or may not still be open). The parent will observe EOF
        # or incomplete protocol and fail closed.
        try: os.close(gate_w)
        except OSError: pass
        _contain_init_child(init_host_pid)
        return 1
    # Protocol FD is now closed and poisoned — no S code path may emit.

    # --- 6. Send exact release token + close gate ---
    try:
        _write_bounded_fd(gate_w, _RELEASE_TOKEN,
                          deadline=time.monotonic() + 5.0,
                          error_cls=IdentityChannelError, reason_prefix="gate")
    except (IdentityChannelError, OSError):
        pass  # I will see EOF and exit without entering core.
    try: os.close(gate_w)
    except OSError: pass

    # --- 7. Wait for I (blocking, no independent timeout) ---
    # Correction #5: the parent's existing session timeout and PGID
    # containment are the outer lifecycle authority. A launcher-level
    # timeout would alter execution semantics.
    while True:
        try:
            waited_pid, status = os.waitpid(init_host_pid, 0)
            break
        except InterruptedError:
            continue
        except ChildProcessError:
            return 1
        except OSError:
            return 1
    if waited_pid != init_host_pid:
        return 1
    return _decode_wait_status(status)


def namespace_init_supervisor_main(
    config: dict[str, Any], protocol_fd: int, gate_r: int, identity_w: int,
    proof_r: int, workload_input_fd: int | None = None,
) -> int:
    """S3.2 namespace-init I: emit identity, await proof + gate, run core.

    Runs as namespace PID 1 (the first child forked by S after
    ``unshare(CLONE_NEWPID)``). Sends a private identity record to S,
    reads the accepted topology proof from S (Task 4, mandatory), blocks
    on the release gate, then -- on exact token + clean EOF -- enters
    ``supervisor_main()`` with the expected namespace identity injected
    into config.

    T2: ``workload_input_fd`` is carried through and passed to
    ``supervisor_main``. I owns it from entry until the B1 fork handoff
    inside ``supervisor_main``. Every pre-core failure branch closes it.

    On any gate, identity, or proof failure — INCLUDING missing proof
    channel or absent proof frame — closes its protocol writer and exits
    nonzero WITHOUT entering ``supervisor_main()``.
    """
    # --- Emit private identity record ---
    identity_record = {
        "version": _IDENTITY_VERSION,
        "type": "init_identity",
        "pid": os.getpid(),    # 1 inside the new namespace
        "ppid": os.getppid(),  # 0 inside the new namespace
    }
    try:
        _write_identity_frame(identity_w, identity_record,
                              deadline=time.monotonic() + 5.0)
    except (IdentityChannelError, OSError):
        for fd in (identity_w, gate_r, proof_r, protocol_fd):
            try: os.close(fd)
            except OSError: pass
        if workload_input_fd is not None:
            try: os.close(workload_input_fd)
            except OSError: pass
        return 1
    try: os.close(identity_w)
    except OSError: pass

    # --- Read topology proof from S (Task 4: S → I proof channel) ---
    # The proof channel is MANDATORY. No proof → no core entry.
    # This is the locked authority chain: S builds the proof, forwards it,
    # I validates it against the closed schema and its own host PID.
    if proof_r < 0:
        # Missing proof channel — deny core entry unconditionally.
        for fd in (gate_r, protocol_fd):
            try: os.close(fd)
            except OSError: pass
        if workload_input_fd is not None:
            try: os.close(workload_input_fd)
            except OSError: pass
        return 1
    try:
        proof_obj = _read_identity_frame(
            proof_r, deadline=time.monotonic() + METADATA_DEADLINE_SECONDS
        )
    except (IdentityChannelError, OSError):
        for fd in (proof_r, gate_r, protocol_fd):
            try: os.close(fd)
            except OSError: pass
        if workload_input_fd is not None:
            try: os.close(workload_input_fd)
            except OSError: pass
        return 1
    try: os.close(proof_r)
    except OSError: pass
    # Strict closed-schema validation.
    try:
        # I's host PID is not directly visible from inside the namespace,
        # but the proof frame carries init_host_pid which S verified.
        # I requires it to be a positive int (schema check); S performed
        # the binding check against the actual fork return.
        expected_pidns_dev, expected_pidns_ino = _validate_proof_record(proof_obj)
    except IdentityChannelError:
        for fd in (gate_r, protocol_fd):
            try: os.close(fd)
            except OSError: pass
        if workload_input_fd is not None:
            try: os.close(workload_input_fd)
            except OSError: pass
        return 1

    # --- Await exact release token + clean EOF ---
    token_ok = _read_exact_token(gate_r, _RELEASE_TOKEN,
                                 deadline=time.monotonic() + 120.0)
    try: os.close(gate_r)
    except OSError: pass
    if not token_ok:
        try: os.close(protocol_fd)
        except OSError: pass
        if workload_input_fd is not None:
            try: os.close(workload_input_fd)
            except OSError: pass
        return 1

    # --- Inject accepted namespace identity into config (Task 4) ---
    # Shallow-copy the config, then STRIP any parent-supplied identity keys
    # (they cannot override the validated proof values), then inject the
    # proof-derived values. This closes the parent-config override path.
    config = dict(config)
    config.pop("expected_pidns_dev", None)
    config.pop("expected_pidns_ino", None)
    config["expected_pidns_dev"] = expected_pidns_dev
    config["expected_pidns_ino"] = expected_pidns_ino

    # --- Enter the existing supervisor core (UNCHANGED) ---
    # supervisor_main emits supervisor_started, forks bootstrap (namespace
    # PID 2), arms PTRACE_O_TRACEEXEC, and recognizes workload start only
    # through the exact SIGTRAP && PTRACE_EVENT_EXEC condition.
    #
    # Correction #7: bootstrap_spawned.pid is the I-visible namespace PID
    # (normally 2), not a host PID. It is authoritative for I's waitpid
    # and ptrace but must not be used by the NodeChain parent for host
    # signaling or containment.
    return supervisor_main(config, protocol_fd, workload_input_fd)


# ---------------------------------------------------------------------------
# S3: External supervisor process entry point
# ---------------------------------------------------------------------------

def supervisor_process_main(
    protocol_fd: int,
    workload_input_fd: int | None = None,
) -> int:
    """Production entry point for the external supervisor process.

    Reads one bounded framed configuration from fd 0 (stdin), closes fd 0,
    then calls :func:`launch_pid_namespace_supervisor`.

    T2: ``workload_input_fd`` is the read-end of the parent-created
    workload-input pipe, passed via the ``--workload-input-fd`` CLI argument.
    It is the sole descriptor authority; the config JSON must not contain
    ``workload_input_rfd``.

    Returns the supervisor exit code.
    """
    # T2 Lock 1: S owns workload_input_fd from function entry. Centralize
    # pre-transfer cleanup so every early return closes it. The `finally`
    # closes only if the FD was NOT transferred into the launcher.
    owned_workload_fd = workload_input_fd
    transferred = False

    try:
        # Fix #7: validate protocol_fd before any work.
        if not isinstance(protocol_fd, int) or protocol_fd < 3:
            sys.stderr.write(f"supervisor: invalid protocol_fd: {protocol_fd!r}\n")
            return 1
        try:
            # Must be open, a pipe, and writable (write end, not read end).
            import stat as _stat
            import fcntl as _fcntl
            st = os.fstat(protocol_fd)
            if not _stat.S_ISFIFO(st.st_mode):
                sys.stderr.write(f"supervisor: protocol_fd {protocol_fd} is not a pipe\n")
                return 1
            # Fix #4 (round 2): verify writability — reject O_RDONLY.
            flags = _fcntl.fcntl(protocol_fd, _fcntl.F_GETFL)
            access_mode = flags & os.O_ACCMODE
            if access_mode == os.O_RDONLY:
                sys.stderr.write(f"supervisor: protocol_fd {protocol_fd} is read-only\n")
                return 1
        except OSError as e:
            sys.stderr.write(f"supervisor: protocol_fd {protocol_fd} not accessible: {e}\n")
            return 1

        try:
            config = read_bounded_config(
                0, deadline=time.monotonic() + CONFIG_DEADLINE_SECONDS,
                close_fd=False,
            )
        except ConfigChannelError as e:
            sys.stderr.write(f"supervisor: startup config failed: {e.reason}\n")
            return 1

        # T2: validate workload_input_fd authority and consistency.
        has_input = config.get("has_workload_input", False)
        if type(has_input) is not bool:
            sys.stderr.write(f"supervisor: invalid has_workload_input: {has_input!r}\n")
            return 1
        if "workload_input_rfd" in config:
            sys.stderr.write("supervisor: conflicting workload_input_fd authority "
                             "(workload_input_rfd in config)\n")
            return 1
        if has_input != (owned_workload_fd is not None):
            sys.stderr.write(
                f"supervisor: workload_input_fd mismatch: "
                f"has_workload_input={has_input} fd={owned_workload_fd}\n")
            return 1
        if owned_workload_fd is not None:
            if type(owned_workload_fd) is not int or owned_workload_fd < 3:
                sys.stderr.write(f"supervisor: invalid workload_input_fd: {owned_workload_fd}\n")
                return 1
            if owned_workload_fd == protocol_fd:
                sys.stderr.write("supervisor: workload_input_fd == protocol_fd\n")
                return 1
            try:
                import stat as _stat2
                import fcntl as _fcntl2
                wst = os.fstat(owned_workload_fd)
                if not _stat2.S_ISFIFO(wst.st_mode):
                    sys.stderr.write(
                        f"supervisor: workload_input_fd {owned_workload_fd} not a pipe\n")
                    return 1
                wflags = _fcntl2.fcntl(owned_workload_fd, _fcntl2.F_GETFL)
                if (wflags & os.O_ACCMODE) != os.O_RDONLY:
                    sys.stderr.write(
                        f"supervisor: workload_input_fd {owned_workload_fd} not read-only\n")
                    return 1
            except OSError as e:
                sys.stderr.write(
                    f"supervisor: workload_input_fd {owned_workload_fd} not accessible: {e}\n")
                return 1

        # Fix #7: close fd 0 and REQUIRE /dev/null reservation to succeed.
        try:
            os.close(0)
        except OSError:
            pass
        try:
            dev_null = os.open("/dev/null", os.O_RDONLY)
            if dev_null != 0:
                os.dup2(dev_null, 0)
                os.close(dev_null)
        except OSError as e:
            # Fix #7: fail-closed — do not continue with fd 0 unreserved.
            sys.stderr.write(f"supervisor: failed to reserve fd 0: {e}\n")
            return 1

        # S3.2 Task 3: delegate to the PID-namespace launcher, which unshares,
        # forks namespace-init I, verifies topology, and releases I into the
        # existing supervisor_main core.
        #
        # T2 fix (B2): poison our ownership BEFORE calling the launcher. The
        # launcher becomes the sole close authority. If the launcher raises
        # after closing FD N (which may be recycled), the finally cannot
        # close a stale numeric descriptor.
        launcher_workload_fd = owned_workload_fd
        owned_workload_fd = None
        transferred = True
        return launch_pid_namespace_supervisor(
            config, protocol_fd, launcher_workload_fd,
        )
    finally:
        # Lock 1: close the workload FD on any pre-transfer return.
        if not transferred and owned_workload_fd is not None:
            try:
                os.close(owned_workload_fd)
            except OSError:
                pass


def _main() -> int:
    """Module entry point: ``python -m nodechain.runtime.exec_supervisor --protocol-fd <fd> [--workload-input-fd <fd>]``."""
    import argparse
    parser = argparse.ArgumentParser(description="NodeChain exec supervisor")
    parser.add_argument("--protocol-fd", type=int, required=True,
                        help="Write end of the trusted protocol pipe")
    parser.add_argument("--workload-input-fd", type=int, default=None,
                        help="Read end of the workload-input pipe (T2, optional)")
    args = parser.parse_args()
    return supervisor_process_main(args.protocol_fd, args.workload_input_fd)


if __name__ == "__main__":
    sys.exit(_main())


# ---------------------------------------------------------------------------
# S3: Parent-side evidence extraction
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SupervisorExecutionEvidence:
    """Evidence extracted from the trusted protocol stream.

    Separates protocol validity (did the stream parse?) from execution truth
    (did the workload actually start and what was its outcome?).
    """
    protocol_valid: bool
    exec_confirmed: bool
    workload_exit_code: int | None
    workload_signal: int | None
    supervisor_failure_reason: str | None
    cleanup_succeeded: bool | None
    protocol_failure_reason: str | None = None
    enforcement_metadata: dict[str, Any] = field(default_factory=dict)


def extract_supervisor_evidence(
    protocol_result: ProtocolReadResult,
) -> SupervisorExecutionEvidence:
    """Extract execution evidence from a parsed protocol stream.

    ``protocol_result.ok`` means the protocol terminated validly (clean EOF
    after ``cleanup_completed``). It does NOT mean the workload succeeded —
    a well-formed failure branch is still a valid protocol.
    """
    exec_confirmed = False
    workload_exit_code: int | None = None
    workload_signal: int | None = None
    supervisor_failure_reason: str | None = None
    cleanup_succeeded: bool | None = None
    enforcement_metadata: dict[str, Any] = {}

    for rec in protocol_result.records:
        rec_type = rec.get("type")
        if rec_type == PROTO_EXEC_CONFIRMED:
            exec_confirmed = True
        elif rec_type == PROTO_WORKLOAD_EXITED:
            if rec.get("signaled"):
                workload_signal = rec.get("signal_num")
            else:
                workload_exit_code = rec.get("exit_code")
        elif rec_type == PROTO_SUPERVISOR_FAILED:
            supervisor_failure_reason = rec.get("reason")
        elif rec_type == PROTO_CLEANUP_COMPLETED:
            cleanup_succeeded = rec.get("cleanup_succeeded")
        elif rec_type == PROTO_ENFORCEMENT_VERIFIED:
            meta = rec.get("metadata", {})
            if isinstance(meta, dict):
                enforcement_metadata = meta

    # Fix #3 (round 1): retain the protocol parser's failure reason.
    protocol_failure_reason = protocol_result.reason if not protocol_result.ok else None

    return SupervisorExecutionEvidence(
        protocol_valid=protocol_result.ok,
        exec_confirmed=exec_confirmed,
        workload_exit_code=workload_exit_code,
        workload_signal=workload_signal,
        supervisor_failure_reason=supervisor_failure_reason,
        cleanup_succeeded=cleanup_succeeded,
        protocol_failure_reason=protocol_failure_reason,
        enforcement_metadata=enforcement_metadata,
    )
