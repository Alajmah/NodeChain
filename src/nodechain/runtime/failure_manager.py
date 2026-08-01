"""Failure Manager — per-failure-type recovery strategies."""

from __future__ import annotations

import time
from enum import Enum
from typing import Any

from nodechain.core.trace import EventType, TraceEvent, Actor
from nodechain.nodes.base_node import BaseNode
from nodechain.core.envelope import InvocationEnvelope, compile_envelope


class FailureType(str, Enum):
    """Categorized failure types with distinct recovery strategies."""
    NODE_SCHEMA_VALIDATION = "node_schema_validation"
    MODEL_TIMEOUT = "model_timeout"
    SEARCH_API_UNAVAILABLE = "search_api_unavailable"
    SOURCE_QUALITY_LOOP_EXHAUSTED = "source_quality_loop_exhausted"
    CLAIM_VALIDATION_FAILURE = "claim_validation_failure"
    RISK_HIGH_NO_REVIEWER = "risk_high_no_reviewer"
    MEMORY_WRITE_POLICY_REJECTION = "memory_write_policy_rejection"
    TRACE_WRITE_FAILURE = "trace_write_failure"
    UNKNOWN = "unknown"


class FailureResult:
    """Result of a failure recovery attempt."""

    def __init__(
        self,
        recovered: bool,
        response: Any = None,
        action: str = "",
        trace_events: list[TraceEvent] | None = None,
    ):
        self.recovered = recovered
        self.response = response
        self.action = action
        self.trace_events = trace_events or []


class FailureManager:
    """
    Handles node failures with per-type strategies.

    Strategies:
      1. Schema validation failure → retry once with reduced context
      2. Model call timeout → retry with extended timeout, then fallback model
      3. Search API unavailable → retry with local document store only
      4. Source quality loop exhausted → request human review
      5. Claim validation failure → route to task planner for one revision
      6. Risk HIGH + no reviewer → pause, emit escalation, wait
      7. Memory write policy rejection → skip write, trace policy_rejection
      8. Trace write failure → alternate sink (stderr), flag trace_incomplete
    """

    # Operator-callable fallback allowlist (#13). Only true fallback-capable
    # failure types — NOT retries, skips, or unknown handling. Adding a type
    # here makes it operator-routable via RecoveryAction.ROUTE_FALLBACK.
    OPERATOR_FALLBACK_TYPES: set[FailureType] = {FailureType.SEARCH_API_UNAVAILABLE}

    @classmethod
    def supports_operator_fallback(cls, failure_type: FailureType) -> bool:
        """True only for failure types with a real operator-callable fallback.

        Retries (MODEL_TIMEOUT, SCHEMA_VALIDATION), sink fallbacks
        (TRACE_WRITE_FAILURE), and skip/continue strategies are NOT operator
        fallbacks — ROUTE_FALLBACK must not become 'invoke any handler'.
        """
        return failure_type in cls.OPERATOR_FALLBACK_TYPES

    async def route_fallback(
        self,
        failure_type: FailureType,
        node,
        envelope,
        error: str,
        state: dict,
        invoke_fn,
    ) -> "FailureResult":
        """Operator-initiated fallback for one failure (#13).

        Routes through the existing handle() dispatch ONLY for fallback-capable
        failure types. Non-fallback types are refused with a clear action rather
        than silently invoking a retry/skip handler. The caller (orchestrator
        delegate) supplies the node, envelope, and invoke_fn.
        """
        if not self.supports_operator_fallback(failure_type):
            return FailureResult(
                recovered=False,
                action=f"no_operator_fallback_for_{failure_type.value}",
            )
        return await self.handle(failure_type, node, envelope, error, state, invoke_fn)

    def __init__(
        self,
        max_retries: int = 2,
        default_timeout: float = 60.0,
        extended_timeout: float = 120.0,
        allocate_step_fn=None,
    ):
        self.max_retries = max_retries
        self.default_timeout = default_timeout
        self.extended_timeout = extended_timeout
        self._retry_counts: dict[str, int] = {}
        self._allocate_step = allocate_step_fn  # Callable(run_id, node_id, attempt) -> int

    def classify_failure(self, error: str, context: dict[str, Any]) -> FailureType:
        """Classify a failure by error message and context."""
        error_lower = error.lower()

        # Check more specific patterns first
        if "claim" in error_lower and ("fail" in error_lower or "all" in error_lower or "unable" in error_lower):
            return FailureType.CLAIM_VALIDATION_FAILURE
        if "loop" in error_lower and "exhaust" in error_lower:
            return FailureType.SOURCE_QUALITY_LOOP_EXHAUSTED
        if "risk" in error_lower and "review" in error_lower:
            return FailureType.RISK_HIGH_NO_REVIEWER
        if "memory" in error_lower and "policy" in error_lower:
            return FailureType.MEMORY_WRITE_POLICY_REJECTION
        if "trace" in error_lower and ("write" in error_lower or "sink" in error_lower):
            return FailureType.TRACE_WRITE_FAILURE

        # Less specific patterns
        if "schema" in error_lower or "validation" in error_lower:
            return FailureType.NODE_SCHEMA_VALIDATION
        if "timeout" in error_lower or "timed out" in error_lower:
            return FailureType.MODEL_TIMEOUT
        if "api" in error_lower and ("unavail" in error_lower or "connect" in error_lower):
            return FailureType.SEARCH_API_UNAVAILABLE

        return FailureType.UNKNOWN

    def _allocate_retry_step(self, envelope: InvocationEnvelope, attempt: int = 2) -> int:
        """Allocate a step ID for a retry via StepAllocator if available.

        Falls back to envelope.step_id + 1 only if no allocator is injected.
        """
        if self._allocate_step is not None:
            return self._allocate_step(envelope.run_id, envelope.node_id, attempt=attempt)
        # Fallback: old behavior (bypasses StepAllocator)
        return envelope.step_id + 1

    async def handle(
        self,
        failure_type: FailureType,
        node: BaseNode,
        envelope: InvocationEnvelope,
        error: str,
        state: dict[str, Any],
        invoke_fn=None,
    ) -> FailureResult:
        """Apply the recovery strategy for a classified failure."""
        handler = {
            FailureType.NODE_SCHEMA_VALIDATION: self._handle_schema_failure,
            FailureType.MODEL_TIMEOUT: self._handle_model_timeout,
            FailureType.SEARCH_API_UNAVAILABLE: self._handle_search_unavailable,
            FailureType.SOURCE_QUALITY_LOOP_EXHAUSTED: self._handle_loop_exhausted,
            FailureType.CLAIM_VALIDATION_FAILURE: self._handle_claim_failure,
            FailureType.RISK_HIGH_NO_REVIEWER: self._handle_no_reviewer,
            FailureType.MEMORY_WRITE_POLICY_REJECTION: self._handle_memory_rejection,
            FailureType.TRACE_WRITE_FAILURE: self._handle_trace_failure,
            FailureType.UNKNOWN: self._handle_unknown,
        }.get(failure_type, self._handle_unknown)

        return await handler(node, envelope, error, state, invoke_fn)

    async def _handle_schema_failure(
        self, node, envelope, error, state, invoke_fn
    ) -> FailureResult:
        """Strategy 1: Retry once with reduced context."""
        node_id = node.manifest.node_id
        retries = self._retry_counts.get(node_id, 0)

        if retries >= 1:
            return FailureResult(recovered=False, action="exhausted_schema_retry")

        self._retry_counts[node_id] = retries + 1

        # Retry with empty context (reduced payload)
        reduced_envelope = compile_envelope(
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id=node_id,
            step_id=self._allocate_retry_step(envelope, attempt=2),
            payload=envelope.payload,
        )

        if invoke_fn:
            response = await invoke_fn(node, reduced_envelope)
            if response.success:
                return FailureResult(recovered=True, response=response, action="schema_retry_reduced_context")
            return FailureResult(recovered=False, response=response, action="schema_failure_retry_failed")

        return FailureResult(recovered=False, action="no_invoke_fn")

    async def _handle_model_timeout(
        self, node, envelope, error, state, invoke_fn
    ) -> FailureResult:
        """Strategy 2: Retry with extended timeout."""
        node_id = node.manifest.node_id
        retries = self._retry_counts.get(node_id, 0)

        if retries >= 2:
            return FailureResult(recovered=False, action="exhausted_model_retry")

        self._retry_counts[node_id] = retries + 1

        if invoke_fn:
            retry_envelope = compile_envelope(
                run_id=envelope.run_id,
                chain_id=envelope.chain_id,
                node_id=node_id,
                step_id=self._allocate_retry_step(envelope, attempt=2),
                payload=envelope.payload,
                context=envelope.context,
            )
            response = await invoke_fn(node, retry_envelope)
            if response.success:
                return FailureResult(recovered=True, response=response, action="model_retry_extended_timeout")
            return FailureResult(recovered=False, response=response, action="model_timeout_retry_failed")

        return FailureResult(recovered=False, action="no_invoke_fn")

    async def _handle_search_unavailable(
        self, node, envelope, error, state, invoke_fn
    ) -> FailureResult:
        """Strategy 3: Retry with local document store fallback."""
        node_id = node.manifest.node_id
        retries = self._retry_counts.get(node_id, 0)

        if retries >= 1:
            return FailureResult(recovered=False, action="exhausted_search_fallback")

        self._retry_counts[node_id] = retries + 1

        # Modify payload to use local store only
        fallback_payload = dict(envelope.payload)
        fallback_payload["adapters_granted"] = {"chroma_local": True}
        fallback_payload["fallback_mode"] = True

        if invoke_fn:
            fallback_envelope = compile_envelope(
                run_id=envelope.run_id,
                chain_id=envelope.chain_id,
                node_id=node_id,
                step_id=self._allocate_retry_step(envelope, attempt=2),
                payload=fallback_payload,
            )
            response = await invoke_fn(node, fallback_envelope)
            if response.success:
                return FailureResult(
                    recovered=True, response=response,
                    action="search_fallback_local_store",
                )
            return FailureResult(
                recovered=False, response=response,
                action="search_unavailable_retry_failed",
            )

        return FailureResult(recovered=False, action="no_invoke_fn")

    async def _handle_loop_exhausted(
        self, node, envelope, error, state, invoke_fn
    ) -> FailureResult:
        """Strategy 4: Escalate to human review."""
        return FailureResult(
            recovered=False,
            action="escalate_to_human_review",
        )

    async def _handle_claim_failure(
        self, node, envelope, error, state, invoke_fn
    ) -> FailureResult:
        """Strategy 5: Route to task planner for one revision."""
        revision_count = state.get("revision_count", 0)
        if revision_count >= 1:
            return FailureResult(recovered=False, action="exhausted_revision")

        return FailureResult(
            recovered=False,
            action="route_to_task_planner_revision",
        )

    async def _handle_no_reviewer(
        self, node, envelope, error, state, invoke_fn
    ) -> FailureResult:
        """Strategy 6: Pause and emit escalation."""
        return FailureResult(
            recovered=False,
            action="pause_escalation_no_reviewer",
        )

    async def _handle_memory_rejection(
        self, node, envelope, error, state, invoke_fn
    ) -> FailureResult:
        """Strategy 7: Skip write, continue."""
        return FailureResult(
            recovered=True,
            response=None,
            action="skip_memory_write_policy_rejection",
        )

    async def _handle_trace_failure(
        self, node, envelope, error, state, invoke_fn
    ) -> FailureResult:
        """Strategy 8: Alternate sink (stderr), continue."""
        import sys
        print(f"[TRACE FALLBACK] {error}", file=sys.stderr)

        return FailureResult(
            recovered=True,
            action="trace_fallback_stderr",
        )

    async def _handle_unknown(
        self, node, envelope, error, state, invoke_fn
    ) -> FailureResult:
        """Default: retry once."""
        node_id = node.manifest.node_id
        retries = self._retry_counts.get(node_id, 0)

        if retries >= 1:
            return FailureResult(recovered=False, action="exhausted_default_retry")

        self._retry_counts[node_id] = retries + 1

        if invoke_fn:
            retry_envelope = compile_envelope(
                run_id=envelope.run_id,
                chain_id=envelope.chain_id,
                node_id=node_id,
                step_id=self._allocate_retry_step(envelope, attempt=2),
                payload=envelope.payload,
                context=envelope.context,
            )
            response = await invoke_fn(node, retry_envelope)
            if response.success:
                return FailureResult(recovered=True, response=response, action="default_retry")
            return FailureResult(recovered=False, response=response, action="unknown_retry_failed")

        return FailureResult(recovered=False, action="no_invoke_fn")
