"""Trace Emitter — structured trace event creation and emission.

Owns:
- Creating well-formed TraceEvent instances
- Appending events to ChainTrace
- Standard event helpers for common lifecycle patterns

Does NOT own:
- Deciding WHEN to emit (caller/orchestrator decides)
- Persistence (StateManager handles durable event log)
- Reconciliation (TraceReconciler handles audit)
"""

from __future__ import annotations

from typing import Any

from nodechain.core.trace import ChainTrace, TraceEvent, EventType, Actor


class TraceEmitter:
    """Creates and records trace events.

    Usage:
        emitter = TraceEmitter(trace=my_trace, run_id="...", chain_id="...")
        emitter.emit(EventType.CHAIN_STARTED, node_id="runtime", decision="chain_init")
        emitter.node_invoked("goal_interpreter", step_id=1)
        emitter.node_succeeded("goal_interpreter", step_id=1, latency_ms=150)
    """

    def __init__(self, trace: ChainTrace, run_id: str, chain_id: str):
        self.trace = trace
        self.run_id = run_id
        self.chain_id = chain_id
        self._step = 0

    def set_step(self, step: int) -> None:
        """Update current step counter."""
        self._step = step

    # ── Core emit ──

    def emit(
        self,
        event_type: EventType,
        node_id: str = "runtime",
        actor: Actor = Actor.RUNTIME,
        decision: str | None = None,
        reason_codes: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        cost_usd: float = 0.0,
        latency_ms: int = 0,
        step_id: int | None = None,
    ) -> None:
        """Emit a trace event with standard fields."""
        self.trace.add_event(TraceEvent(
            run_id=self.run_id,
            chain_id=self.chain_id,
            node_id=node_id,
            step_id=step_id if step_id is not None else self._step,
            event_type=event_type,
            actor=actor,
            decision=decision,
            reason_codes=reason_codes or [],
            metadata=metadata or {},
            cost_usd=cost_usd,
            latency_ms=latency_ms,
        ))

    # ── Chain lifecycle ──

    def chain_started(self, chain_name: str) -> None:
        self.emit(
            EventType.CHAIN_STARTED,
            decision="chain_init",
            metadata={"chain_name": chain_name},
        )

    def chain_completed(self, duration_ms: float, final_status: str) -> None:
        self.emit(
            EventType.CHAIN_COMPLETED,
            decision="chain_done",
            metadata={"duration_ms": duration_ms, "final_status": final_status},
        )

    def chain_failed(self, reason: str, details: dict[str, Any] | None = None) -> None:
        self.emit(
            EventType.CHAIN_FAILED,
            decision="chain_error",
            reason_codes=[reason],
            metadata=details or {},
        )

    # ── Node lifecycle ──

    def node_invoked(self, node_id: str, step_id: int | None = None) -> None:
        self.emit(
            EventType.NODE_INVOKED,
            node_id=node_id,
            decision="node_invoke",
            step_id=step_id,
        )

    def node_succeeded(
        self,
        node_id: str,
        step_id: int | None = None,
        latency_ms: int = 0,
        cost_usd: float = 0.0,
    ) -> None:
        self.emit(
            EventType.NODE_SUCCEEDED,
            node_id=node_id,
            decision="node_success",
            latency_ms=latency_ms,
            cost_usd=cost_usd,
            step_id=step_id,
        )

    def node_failed(
        self,
        node_id: str,
        error: str,
        step_id: int | None = None,
    ) -> None:
        self.emit(
            EventType.NODE_FAILED,
            node_id=node_id,
            decision="node_error",
            reason_codes=[error],
            step_id=step_id,
        )

    def node_skipped(self, node_id: str, reason: str = "") -> None:
        self.emit(
            EventType.NODE_SKIPPED,
            node_id=node_id,
            decision="node_skipped",
            metadata={"reason": reason},
        )

    # ── Policy events ──

    def policy_result(
        self,
        node_id: str,
        policy_type: str,
        allowed: bool,
        reason: str = "",
    ) -> None:
        self.emit(
            EventType.POLICY_EVALUATED,
            node_id=node_id,
            decision="policy_pass" if allowed else "policy_deny",
            metadata={
                "policy_type": policy_type,
                "allowed": allowed,
                "reason": reason,
            },
        )

    # ── Validation events ──

    def validation_passed(self, node_id: str, validation_type: str = "schema") -> None:
        self.emit(
            EventType.VALIDATION_PASSED,
            node_id=node_id,
            decision=f"{validation_type}_valid",
        )

    def validation_failed(
        self,
        node_id: str,
        errors: list[str],
        validation_type: str = "schema",
    ) -> None:
        self.emit(
            EventType.VALIDATION_FAILED,
            node_id=node_id,
            decision=f"{validation_type}_invalid",
            reason_codes=errors,
        )

    # ── Branch/join events ──

    def branch_started(self, node_id: str, branch_name: str, nodes: list[str]) -> None:
        self.emit(
            EventType.BRANCH_STARTED,
            node_id=node_id,
            decision=f"branch_{branch_name}_started",
            metadata={"branch": branch_name, "nodes": nodes},
        )

    def branch_completed(
        self, node_id: str, branch_name: str, duration_ms: float,
    ) -> None:
        self.emit(
            EventType.BRANCH_COMPLETED,
            node_id=node_id,
            decision=f"branch_{branch_name}_completed",
            metadata={"branch": branch_name, "duration_ms": duration_ms},
        )

    def branch_failed(
        self, node_id: str, branch_name: str, error: str, failed_node: str = "",
    ) -> None:
        self.emit(
            EventType.BRANCH_FAILED,
            node_id=node_id,
            decision=f"branch_{branch_name}_failed",
            metadata={"branch": branch_name, "error": error, "node": failed_node},
        )

    def join_ready(self, node_id: str, metadata: dict[str, Any]) -> None:
        self.emit(EventType.JOIN_READY, node_id=node_id, decision="join_ready", metadata=metadata)

    def join_blocked(self, node_id: str, metadata: dict[str, Any]) -> None:
        self.emit(EventType.JOIN_BLOCKED, node_id=node_id, decision="join_blocked", metadata=metadata)

    def join_partial(self, node_id: str, metadata: dict[str, Any]) -> None:
        self.emit(EventType.JOIN_PARTIAL, node_id=node_id, decision="join_partial", metadata=metadata)

    def join_completed(self, node_id: str, metadata: dict[str, Any]) -> None:
        self.emit(EventType.JOIN_COMPLETED, node_id=node_id, decision="join_completed", metadata=metadata)

    # ── Review events ──

    def review_requested(self, node_id: str, gate_id: str) -> None:
        self.emit(
            EventType.HUMAN_REVIEW_REQUESTED,
            node_id=node_id,
            decision="review_pause",
            metadata={"gate_id": gate_id},
        )

    def review_resolved(self, node_id: str, decision: str, gate_id: str = "") -> None:
        self.emit(
            EventType.HUMAN_REVIEW_COMPLETED,
            node_id=node_id,
            decision="review_resume",
            metadata={"gate_id": gate_id, "review_decision": decision},
        )

    # ── Side-effect events ──
    #
    # v2.33.0: these helpers now emit the canonical SIDE_EFFECT_* EventType
    # values (not TOOL_CALLED / TOOL_RESULT_RECEIVED). The reconciler buckets
    # side-effect lifecycle events by the SIDE_EFFECT_* substring, so the
    # previous tool-call aliases were invisible to the side-effect checks
    # (4a/4b/4d). SIDE_EFFECT_FAILED is new — the orchestrator marks a side
    # effect failed in the ledger on adapter failure, and now the trace
    # surface reflects that honestly.

    def side_effect_started(
        self, node_id: str, effect_type: str, key: str,
        request_hash: str = "",
    ) -> None:
        metadata: dict[str, Any] = {
            "effect_type": effect_type,
            "idempotency_key": key,
        }
        if request_hash:
            metadata["request_hash"] = request_hash
        self.emit(
            EventType.SIDE_EFFECT_STARTED,
            node_id=node_id,
            decision="side_effect_begin",
            metadata=metadata,
        )

    def side_effect_completed(
        self, node_id: str, effect_type: str, key: str, duration_ms: float = 0,
        request_hash: str = "",
        response_hash: str = "",
        external_reference: str = "",
    ) -> None:
        metadata: dict[str, Any] = {
            "effect_type": effect_type,
            "idempotency_key": key,
            "duration_ms": duration_ms,
        }
        if request_hash:
            metadata["request_hash"] = request_hash
        if response_hash:
            metadata["response_hash"] = response_hash
        if external_reference:
            metadata["external_reference"] = external_reference
        self.emit(
            EventType.SIDE_EFFECT_COMPLETED,
            node_id=node_id,
            decision="side_effect_done",
            metadata=metadata,
        )

    def side_effect_failed(
        self, node_id: str, effect_type: str, key: str, reason: str = "",
        request_hash: str = "",
    ) -> None:
        """Emit a SIDE_EFFECT_FAILED event for a side effect that genuinely failed."""
        metadata: dict[str, Any] = {
            "effect_type": effect_type,
            "idempotency_key": key,
        }
        if reason:
            metadata["reason"] = reason
        if request_hash:
            metadata["request_hash"] = request_hash
        self.emit(
            EventType.SIDE_EFFECT_FAILED,
            node_id=node_id,
            decision="side_effect_failed",
            metadata=metadata,
        )

    # ── Contracts ──

    def contracts_validated(self, node_ids: list[str]) -> None:
        self.emit(
            EventType.CONTRACT_VALIDATED,
            decision="all_contracts_valid",
            metadata={"validated_nodes": node_ids},
        )
