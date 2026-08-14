"""Persistence Coordinator — transaction boundary for durable state.

Owns:
- Atomic invocation commits (state + ledger + event log)
- State snapshots and recovery loads
- Side-effect recording
- Revision management

Does NOT own:
- Scheduling decisions
- Node invocation
- Policy checks
- Trace emission (uses StateManager events)
- Human review logic
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from nodechain.core.state import ChainState, StateManager
from nodechain.core.trace import TraceEvent

#: Sentinel distinguishing "no output proposal" from an output of None.
_UNSET = object()


@dataclass
class InvocationRecord:
    """A single completed invocation, keyed by step."""
    step_id: int
    node_id: str
    branch_name: str | None = None


@dataclass
class RecoveryContext:
    """Loaded state for resume/review-resume."""

    state: ChainState
    completed_steps: dict[int, str] = field(default_factory=dict)  # step_id → node_id
    side_effects: list[dict[str, Any]] = field(default_factory=list)
    completed_side_effect_keys: list[str] = field(default_factory=list)

    @property
    def completed_node_ids(self) -> set[str]:
        """Convenience: set of node IDs that have been completed at least once."""
        return set(self.completed_steps.values())

    @property
    def last_completed_step(self) -> int:
        """Highest step_id that was completed (0 if none)."""
        return max(self.completed_steps.keys()) if self.completed_steps else 0


class PersistenceCoordinator:
    """Coordinates all persistence operations.

    Enforces the invariant:
    state snapshot + invocation ledger + event log = single SQLite transaction.

    H0.5 accepted-state rule: every authoritative transition constructs a
    candidate copy (``ChainState.transition_candidate()``), commits it, and
    only then adopts the proposals into the caller's live state. A failed
    commit leaves the accepted state untouched — no field, no revision.
    """

    def __init__(self, state_manager: StateManager) -> None:
        self.state_manager = state_manager

    def commit_invocation_success(
        self,
        state: ChainState,
        *,
        step_id: int,
        node_id: str,
        branch_name: str | None = None,
        output: Any = _UNSET,
        cursor: tuple[int, str] | None = None,
        branch_states: dict[str, str] | None = None,
        event_type: str = "node_completed",
        event_payload: dict[str, Any] | None = None,
        cost_usd: float = 0.0,
    ) -> None:
        """H0.5 class 1: candidate/adopt invocation transition.

        Proposals (output, cursor, branch states) and the completed-step
        entry are applied to a candidate copy, committed through the atomic
        ``save_with_invocation`` transaction, and only then adopted into the
        caller's live state. A failed commit leaves the accepted state
        untouched — no output, completed-step, cursor, branch-state, or
        revision change (V2, criterion 4).
        """
        cand = state.transition_candidate()
        cand.completed_steps[step_id] = node_id
        if output is not _UNSET:
            cand.outputs[node_id] = output
        if cursor is not None:
            cand.step, cand.current_node = cursor
        if branch_states:
            cand.branch_states.update(branch_states)
        self.state_manager.save_with_invocation(
            state=cand,
            step_id=step_id,
            node_id=node_id,
            branch_name=branch_name,
            event_type=event_type,
            event_payload=event_payload or {"node_id": node_id, "step_id": step_id},
            cost_usd=cost_usd,
        )
        # Adopt: apply the committed proposals to the accepted live state.
        state.completed_steps[step_id] = node_id
        if output is not _UNSET:
            state.outputs[node_id] = output
        if cursor is not None:
            state.step, state.current_node = cursor
        if branch_states:
            state.branch_states.update(branch_states)
        state.revision = cand.revision

    def commit_lifecycle(
        self,
        state: ChainState,
        *,
        event: TraceEvent,
        status: str | None = None,
        completed_at: str | None = None,
        paused_at: Any = _UNSET,
        is_resumed: bool | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """H0.5 class 2: state-asserting lifecycle transition.

        The candidate status change and the authoritative ``TraceEvent``
        commit in ONE SQLite transaction
        (``StateManager.save_with_trace_event``): the durable trace row and
        the state it asserts land together or not at all. On success the
        caller acknowledges by appending the exact same event object to the
        live trace through the singular authority's already-durable mode.
        A failed commit leaves the accepted state untouched and the event
        non-durable (V3, V4, V5, V7).
        """
        cand = state.transition_candidate()
        if status is not None:
            cand.status = status
        if completed_at is not None:
            cand.completed_at = completed_at
        if paused_at is not _UNSET:
            cand.paused_at = paused_at
        if is_resumed is not None:
            cand.is_resumed = is_resumed
        if metadata:
            cand.metadata = {**(cand.metadata or {}), **metadata}
        self.state_manager.save_with_trace_event(cand, event)
        # Adopt: apply the committed transition to the accepted live state.
        if status is not None:
            state.status = status
        if completed_at is not None:
            state.completed_at = completed_at
        if paused_at is not _UNSET:
            state.paused_at = paused_at
        if is_resumed is not None:
            state.is_resumed = is_resumed
        if metadata:
            state.metadata = {**(state.metadata or {}), **metadata}
        state.revision = cand.revision

    def commit_checkpoint(
        self,
        state: ChainState,
        apply: Any,
    ) -> None:
        """H0.5 class 3: state-only checkpoint (no trace event participates).

        ``apply(candidate)`` proposes mutations on a candidate copy; the
        snapshot-only state write commits it; the same mutations are then
        adopted into the accepted state. A failed commit leaves the accepted
        state untouched and consumes no revision (V1).
        """
        cand = state.transition_candidate()
        apply(cand)
        self.state_manager.save(cand)
        apply(state)
        state.revision = cand.revision

    def commit_invocation_failure(
        self,
        state: ChainState,
        *,
        step_id: int,
        node_id: str,
        error: str,
        branch_name: str | None = None,
    ) -> None:
        """Record a failed invocation in the ledger."""
        self.state_manager.save_with_invocation(
            state=state,
            step_id=step_id,
            node_id=node_id,
            branch_name=branch_name,
            event_type="node_failed",
            event_payload={"node_id": node_id, "step_id": step_id, "error": error},
        )

    def save_snapshot(self, state: ChainState) -> None:
        """Snapshot-only state write, candidate-safe (H0.5).

        Persists the accepted content; the revision increment lands on a
        candidate copy and is adopted only after the write succeeds, so a
        failed snapshot never consumes a revision on the live object (V1).
        """
        cand = state.transition_candidate()
        self.state_manager.save(cand)
        state.revision = cand.revision

    def save_final(self, state: ChainState) -> None:
        """Final snapshot-only save, candidate-safe (H0.5, class 3)."""
        cand = state.transition_candidate()
        self.state_manager.save(cand)
        state.revision = cand.revision

    def load_for_recovery(self, run_id: str) -> RecoveryContext | None:
        """Load state and completed steps for resume/review-resume.

        Returns None if no state found for the run_id.
        """
        state = self.state_manager.load(run_id)
        if state is None:
            return None

        completed_steps = self.state_manager.get_completed_steps(run_id)

        side_effects = self.state_manager.get_side_effects(run_id)
        completed_keys = [
            e["idempotency_key"]
            for e in side_effects
            if e["status"] == "completed"
        ]

        return RecoveryContext(
            state=state,
            completed_steps=completed_steps,
            side_effects=side_effects,
            completed_side_effect_keys=completed_keys,
        )

    def record_side_effect(
        self,
        run_id: str,
        *,
        step_id: int,
        node_id: str,
        side_effect_type: str,
        idempotency_key: str,
        status: str = "completed",
        request_hash: str | None = None,
        response_hash: str | None = None,
        external_reference: str | None = None,
        retryable: bool = True,
        branch_name: str | None = None,
    ) -> None:
        """Record a side effect in the ledger."""
        self.state_manager.record_side_effect(
            run_id=run_id,
            step_id=step_id,
            node_id=node_id,
            side_effect_type=side_effect_type,
            idempotency_key=idempotency_key,
            status=status,
            request_hash=request_hash,
            response_hash=response_hash,
            external_reference=external_reference,
            retryable=retryable,
            branch_name=branch_name,
        )

    def get_completed_side_effect_keys(self, run_id: str) -> list[str]:
        """Get idempotency keys of completed side effects."""
        effects = self.state_manager.get_side_effects(run_id)
        return [
            e["idempotency_key"]
            for e in effects
            if e["status"] == "completed"
        ]

    def get_side_effect_status_map(self, run_id: str) -> dict[str, str]:
        """Get all side-effect statuses for capabilities."""
        effects = self.state_manager.get_side_effects(run_id)
        status_map: dict[str, str] = {}
        for e in effects:
            key = e["idempotency_key"]
            status_map[key] = e["status"]
            if e["status"] == "failed":
                status_map[f"{key}__retryable"] = str(bool(e.get("retryable", True)))
        return status_map

    def get_side_effects_by_status(self, run_id: str, status: str) -> list[dict]:
        """Get side effects filtered by status."""
        return self.state_manager.get_side_effects_by_status(run_id, status)

    def get_side_effect_by_key(self, run_id: str, idempotency_key: str) -> dict | None:
        """Get a specific side effect by its idempotency key."""
        return self.state_manager.get_side_effect_by_key(run_id, idempotency_key)

    def update_side_effect_status(
        self,
        run_id: str,
        idempotency_key: str,
        status: str,
        response_hash: str | None = None,
    ) -> None:
        """Update a side effect's status."""
        self.state_manager.update_side_effect_status(
            run_id, idempotency_key, status, response_hash=response_hash,
        )

    def start_side_effect_with_capsule(
        self, run_id: str, **kwargs,
    ) -> str:
        """v3.5.0: Delegate to StateManager.start_side_effect_with_capsule."""
        return self.state_manager.start_side_effect_with_capsule(
            run_id=run_id, **kwargs,
        )

    def append_event(
        self,
        run_id: str,
        event_type: str,
        payload: dict[str, Any],
        *,
        revision: int | None = None,
        node_id: str | None = None,
        step_id: int | None = None,
    ) -> None:
        """Append an event to the state events log."""
        self.state_manager.append_event(
            run_id=run_id,
            revision=revision or 0,
            event_type=event_type,
            node_id=node_id,
            step_id=step_id,
            payload=payload,
        )

    def append_trace_event(
        self,
        run_id: str,
        revision: int,
        event_type: str,
        node_id: str | None,
        step_id: int | None,
        trace_event_id: str,
        timestamp: str,
        payload: dict[str, Any] | None = None,
    ) -> None:
        """Append an authoritative trace event (H0.4 singular emission authority).

        Delegates to StateManager.append_trace_event. The durable row carries
        a first-class trace_event_id and the event's own timestamp.
        """
        self.state_manager.append_trace_event(
            run_id=run_id,
            revision=revision,
            event_type=event_type,
            node_id=node_id,
            step_id=step_id,
            trace_event_id=trace_event_id,
            timestamp=timestamp,
            payload=payload,
        )
