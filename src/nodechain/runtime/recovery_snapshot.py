"""RecoverySnapshot — read-only operator view of a recoverable run (v2.46.0).

RecoverySnapshot is a *derived* view assembled by RecoveryService from durable
state (ChainState, side-effect ledger, invocation ledger, review attempts, and
trace health). It is never mutated by the operator and never persisted as the
source of truth — the Chain Trace remains the authoritative execution record.

The snapshot exists so an operator can understand, at a glance:

* why a run stopped (recovery_state, blocking_reason),
* where it stopped (current_node, current_step, failed_step),
* what the runtime knows about durability (trace_complete, trace_warnings,
  state_revision, last_update_time), and
* which governed recovery actions are available (available_actions).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class RecoverySnapshot(BaseModel):
    """Immutable operator-facing summary of a run's recovery posture.

    Frozen: once assembled by RecoveryService it must not be mutated — the
    snapshot is a derived view and the Chain Trace remains the source of truth.
    All collection fields default to empty containers (not None) so console
    renderers can iterate without None-checks; nullable scalars stay None.
    """

    run_id: str
    chain_id: str
    status: str
    recovery_state: str

    current_node: str | None = None
    current_step: int | None = None
    last_successful_step: int | None = None
    failed_step: int | None = None
    blocking_reason: str | None = None
    available_actions: list[str] = Field(default_factory=list)
    loop_counters: dict[str, int] = Field(default_factory=dict)
    retry_counters: dict[str, int] = Field(default_factory=dict)
    pending_review: dict[str, Any] | None = None
    pending_policy_decision: dict[str, Any] | None = None
    trace_complete: bool = True
    trace_warnings: list[str] = Field(default_factory=list)
    trace_errors: list[str] = Field(default_factory=list)
    state_revision: int = 0
    last_update_time: str | None = None

    model_config = {"extra": "forbid", "frozen": True}
