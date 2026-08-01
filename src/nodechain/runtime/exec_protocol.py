"""Pure exec protocol state machine — no I/O, no async, no FD logic.

R3 Task 1: Extract protocol parsing and validation into a pure module.
This module re-exports the accepted R1 _ProtocolStreamParser (which lives
in exec_supervisor.py) and provides the ProtocolAccumulator interface
specified in the R3 plan.

The accumulator owns:
    byte-cap enforcement
    newline framing
    JSON duplicate-key detection
    closed record schemas
    version validation
    state-transition validation
    normal and failure terminal branches
    EOF validation
    final ProtocolReadResult construction

It owns no FD, event loop, timeout, task, or signal behavior.
"""

from __future__ import annotations

from typing import Any

# Re-export the accepted R1 pure parser and its dependencies.
from nodechain.runtime.exec_supervisor import (
    # Parser class (the pure accumulator)
    _ProtocolStreamParser as ProtocolAccumulator,
    # Result type
    ProtocolReadResult,
    # Protocol constants
    PROTO_VERSION,
    PROTO_SUPERVISOR_STARTED,
    PROTO_BOOTSTRAP_SPAWNED,
    PROTO_ENFORCEMENT_VERIFIED,
    PROTO_EXEC_MONITOR_ARMED,
    PROTO_EXEC_CONFIRMED,
    PROTO_WORKLOAD_EXITED,
    PROTO_CLEANUP_COMPLETED,
    PROTO_SUPERVISOR_FAILED,
    # Limits
    MAX_PROTOCOL_RECORD_BYTES,
    MAX_PROTOCOL_STREAM_BYTES,
    MAX_PROTOCOL_RECORDS,
    # Schema tables (for testing)
    _PROTO_ALLOWED_TYPES,
    _PROTO_ALLOWED_FIELDS,
    _PROTO_REQUIRED_FIELDS,
    _PROTO_PREDECESSORS,
    # Validation helpers
    _validate_proto_fields,
    _is_int_not_bool,
    _parse_json_strict,
    _detect_dup_keys,
    DuplicateKeyError,
)

__all__ = [
    "ProtocolAccumulator",
    "ProtocolReadResult",
    "PROTO_VERSION",
    "PROTO_SUPERVISOR_STARTED",
    "PROTO_BOOTSTRAP_SPAWNED",
    "PROTO_ENFORCEMENT_VERIFIED",
    "PROTO_EXEC_MONITOR_ARMED",
    "PROTO_EXEC_CONFIRMED",
    "PROTO_WORKLOAD_EXITED",
    "PROTO_CLEANUP_COMPLETED",
    "PROTO_SUPERVISOR_FAILED",
    "MAX_PROTOCOL_RECORD_BYTES",
    "MAX_PROTOCOL_STREAM_BYTES",
    "MAX_PROTOCOL_RECORDS",
]
