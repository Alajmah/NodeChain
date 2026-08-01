"""Trace — the authoritative execution record."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EventType(str, Enum):
    """All defined trace event types. Missing events = incomplete trace."""

    CHAIN_STARTED = "chain_started"
    CHAIN_COMPLETED = "chain_completed"
    CHAIN_FAILED = "chain_failed"
    NODE_INVOKED = "node_invoked"
    NODE_SUCCEEDED = "node_succeeded"
    NODE_FAILED = "node_failed"
    CONTRACT_VALIDATED = "contract_validated"
    POLICY_EVALUATED = "policy_evaluated"
    TOOL_CALLED = "tool_called"
    TOOL_RESULT_RECEIVED = "tool_result_received"
    VALIDATION_STARTED = "validation_started"
    VALIDATION_PASSED = "validation_passed"
    VALIDATION_FAILED = "validation_failed"
    LOOP_ENTERED = "loop_entered"
    LOOP_EXITED = "loop_exited"
    LOOP_BLOCKED = "loop_blocked"
    LOOP_ESCALATION = "loop_escalation"
    ESCALATION_TRIGGERED = "escalation_triggered"
    HUMAN_REVIEW_REQUESTED = "human_review_requested"
    HUMAN_REVIEW_COMPLETED = "human_review_completed"
    HUMAN_REVIEW_TIMEOUT = "human_review_timeout"
    MEMORY_READ_REQUESTED = "memory_read_requested"
    MEMORY_READ_COMPLETED = "memory_read_completed"
    MEMORY_READ_ALLOWED = "memory_read_allowed"  # v2.40.0
    MEMORY_READ_DENIED = "memory_read_denied"    # v2.40.0
    MEMORY_READ_EXPOSED = "memory_read_exposed"  # v2.41.0 — actual exposure (not just authorization)
    TOOL_ACCESS_ALLOWED = "tool_access_allowed"  # v2.42.0
    TOOL_ACCESS_DENIED = "tool_access_denied"    # v2.42.0
    ADAPTER_ACCESS_ALLOWED = "adapter_access_allowed"  # v2.43.0
    ADAPTER_ACCESS_DENIED = "adapter_access_denied"    # v2.43.0
    PACKAGE_TRUST_ALLOWED = "package_trust_allowed"    # v2.44.0
    PACKAGE_TRUST_DENIED = "package_trust_denied"      # v2.44.0
    MEMORY_WRITE_REQUESTED = "memory_write_requested"
    MEMORY_WRITE_ALLOWED = "memory_write_allowed"
    MEMORY_WRITE_BLOCKED = "memory_write_blocked"
    MODEL_CALLED = "model_called"
    MODEL_REQUIREMENTS_EVALUATED = "model_requirements_evaluated"  # v2.68 — explicit model-output floor evaluation
    # v2.72.0 — Code Review patch proposal governance
    PATCH_PROPOSED = "patch_proposed"
    PATCH_VALIDATION_STARTED = "patch_validation_started"
    PATCH_VALIDATION_PASSED = "patch_validation_passed"
    PATCH_VALIDATION_FAILED = "patch_validation_failed"
    PATCH_RISK_CLASSIFIED = "patch_risk_classified"
    REPO_WRITE_BLOCKED = "repo_write_blocked"
    # v2.73.0 — Governed temp-workspace test execution
    SANDBOX_WORKSPACE_REQUESTED = "sandbox_workspace_requested"
    SANDBOX_WORKSPACE_CREATED = "sandbox_workspace_created"
    PATCH_APPLY_STARTED = "patch_apply_started"
    PATCH_APPLY_SUCCEEDED = "patch_apply_succeeded"
    PATCH_APPLY_FAILED = "patch_apply_failed"
    TEST_COMMAND_AUTHORIZED = "test_command_authorized"
    TEST_COMMAND_BLOCKED = "test_command_blocked"
    CODE_EXECUTION_STARTED = "code_execution_started"
    CODE_EXECUTION_COMPLETED = "code_execution_completed"
    CODE_EXECUTION_FAILED = "code_execution_failed"
    CODE_EXECUTION_TIMED_OUT = "code_execution_timed_out"
    SANDBOX_OUTPUT_CAPPED = "sandbox_output_capped"
    SANDBOX_CLEANUP_STARTED = "sandbox_cleanup_started"
    SANDBOX_CLEANUP_SUCCEEDED = "sandbox_cleanup_succeeded"
    SANDBOX_CLEANUP_FAILED = "sandbox_cleanup_failed"
    TEST_RESULT_CLASSIFIED = "test_result_classified"
    TRANSITION_EVALUATED = "transition_evaluated"
    ROUTING_DECISION = "routing_decision"
    NODE_SKIPPED = "node_skipped"  # Branch path not executed
    JOIN_READY = "join_ready"  # All required branches completed
    JOIN_BLOCKED = "join_blocked"  # Required branch failed/missing
    JOIN_PARTIAL = "join_partial"  # Some branches succeeded, some failed
    JOIN_COMPLETED = "join_completed"  # Join finished successfully
    BRANCH_FAILED = "branch_failed"  # Individual branch execution failure
    BRANCH_STARTED = "branch_started"  # Branch execution started (parallel)
    BRANCH_COMPLETED = "branch_completed"  # Branch finished successfully
    BRANCH_CANCELLED = "branch_cancelled"  # Branch cancelled (wait_for=any)
    BRANCH_IGNORED = "branch_ignored"  # Branch allowed to complete but ignored at join
    BRANCH_FIRST_SELECTED = "branch_first_selected"  # First branch selected for wait_for=first join
    SIDE_EFFECT_STARTED = "side_effect_started"  # Pre-call journaling
    SIDE_EFFECT_COMPLETED = "side_effect_completed"  # Post-call confirmation
    SIDE_EFFECT_FAILED = "side_effect_failed"  # Post-call failure
    SIDE_EFFECT_BLOCKED = "side_effect_blocked"  # Policy denied before execution (v2.34.0)
    # v3.5.0 T7: recovery retry lifecycle events (INV-020)
    SIDE_EFFECT_RETRY_REQUEUED = "side_effect_retry_requeued"  # Expired pre-dispatch child requeued
    CONTRACT_VIOLATION = "contract_violation"  # Undeclared observed side effect (v2.35.0)
    SKIPPED = "skipped"
    SIMULATED = "simulated"
    # v2.46.0 — Operator Recovery Console. Every operator intervention is
    # traced with a distinct event type and Actor.OPERATOR, so operator
    # actions are never recorded as node execution. See recovery_service.
    OPERATOR_CONSOLE_OPENED = "operator_console_opened"
    RECOVERY_SNAPSHOT_VIEWED = "recovery_snapshot_viewed"
    RECOVERY_ACTION_REQUESTED = "recovery_action_requested"
    RECOVERY_ACTION_ALLOWED = "recovery_action_allowed"
    RECOVERY_ACTION_BLOCKED = "recovery_action_blocked"
    RUN_RESUMED_BY_OPERATOR = "run_resumed_by_operator"
    STEP_RETRIED_BY_OPERATOR = "step_retried_by_operator"
    HUMAN_REVIEW_APPROVED_BY_OPERATOR = "human_review_approved_by_operator"
    HUMAN_REVIEW_REJECTED_BY_OPERATOR = "human_review_rejected_by_operator"
    REVISION_REQUESTED_BY_OPERATOR = "revision_requested_by_operator"
    RUN_CANCELLED_BY_OPERATOR = "run_cancelled_by_operator"
    RUN_FAILED_BY_OPERATOR = "run_failed_by_operator"
    RECOVERY_REPORT_EXPORTED = "recovery_report_exported"


class Actor(str, Enum):
    NODE = "node"
    RUNTIME = "runtime"
    HUMAN = "human"
    POLICY_ENGINE = "policy_engine"
    OPERATOR = "operator"  # v2.46.0 — console/operating human, distinct from in-band HUMAN review


class TraceEvent(BaseModel):
    """A single trace event — immutable once created."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    run_id: str
    chain_id: str
    node_id: str
    step_id: int
    contract_id: str | None = None
    policy_id: str | None = None
    event_type: EventType
    actor: Actor
    input_reference: str | None = None
    output_reference: str | None = None
    decision: str | None = None
    reason_codes: list[str] = Field(default_factory=list)
    cost_usd: float = 0.0
    latency_ms: int = 0
    risk_level: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "forbid"}


class TraceSummary(BaseModel):
    """Summary statistics for a complete chain trace."""

    nodes_executed: int = 0
    loops_entered: int = 0
    human_reviews: int = 0
    memory_writes_attempted: int = 0
    memory_writes_committed: int = 0
    trace_complete: bool = False


class ChainTrace(BaseModel):
    """Complete chain trace — the authoritative execution record."""

    trace_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    run_id: str
    chain_id: str
    chain_name: str = ""
    started_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    completed_at: str | None = None
    final_status: str | None = None
    events: list[TraceEvent] = Field(default_factory=list)
    total_cost_usd: float = 0.0
    total_duration_ms: int = 0
    summary: TraceSummary = Field(default_factory=TraceSummary)

    model_config = {"extra": "forbid"}

    def add_event(self, event: TraceEvent) -> None:
        """Add an event and update running totals."""
        self.events.append(event)
        self.total_cost_usd += event.cost_usd

    def finalize(self, status: str) -> None:
        """Mark trace as complete with final status."""
        now = datetime.now(timezone.utc).isoformat()
        self.completed_at = now
        self.final_status = status

        # Calculate duration
        if self.events:
            first = self.events[0].timestamp
            # Simple ISO string comparison works for UTC
            self.summary.nodes_executed = sum(
                1 for e in self.events if e.event_type == EventType.NODE_SUCCEEDED
            )
            self.summary.loops_entered = sum(
                1 for e in self.events if e.event_type == EventType.LOOP_ENTERED
            )
            self.summary.human_reviews = sum(
                1
                for e in self.events
                if e.event_type == EventType.HUMAN_REVIEW_REQUESTED
            )
            self.summary.memory_writes_attempted = sum(
                1
                for e in self.events
                if e.event_type == EventType.MEMORY_WRITE_REQUESTED
            )
            self.summary.memory_writes_committed = sum(
                1
                for e in self.events
                if e.event_type == EventType.MEMORY_WRITE_ALLOWED
            )

        # Verify truth rule
        self.summary.trace_complete = self._verify_truth_rule()

    def _verify_truth_rule(self) -> bool:
        """
        Trace Truth Rule: the trace must not claim a step occurred
        unless it was actually executed. This is a structural check.
        """
        # Must have chain_started and chain_completed/failed
        event_types = {e.event_type for e in self.events}
        if EventType.CHAIN_STARTED not in event_types:
            return False
        if not (
            EventType.CHAIN_COMPLETED in event_types
            or EventType.CHAIN_FAILED in event_types
        ):
            return False
        return True

    def to_json(self) -> str:
        """Serialize trace to JSON for file output."""
        return self.model_dump_json(indent=2)
