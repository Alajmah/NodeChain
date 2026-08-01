"""v3.5.0: SideEffectRetryCoordinator — retry-authorized execution mechanics.

The coordinator owns the retry execution workflow per ChatGPT's locked T6
execution protocol:

    1. Validate parent status == retry_authorized
    2. Validate capsule available (not legacy)
    3. Validate decision not already bound (deterministic convergence)
    4. Validate adapter attestation
    5. Allocate deterministic child attempt at planned
    6. Claim dispatch ownership (fencing token via CAS)
    7. Mark dispatch attempted (fenced one-shot CAS)
    8. Dispatch through guarded adapter (exactly once)
    9. Classify outcome (boundary as truth divider)
   10. Terminalize through fenced recovery API
   11. Finalize recovery_execution_actions record

Critical T6 rules (ChatGPT):
- The adapter must NEVER be called unless step 7 succeeds.
- Never terminalize a recovery child through ordinary completion mutation.
- Node success must not imply child completion.
- Any post-boundary outcome whose external truth is uncertain becomes unknown,
  not failed.
- Concurrent/repeated actions converge on one child and at most one dispatch.
- RECOVERY_ACTION_ALLOWED, attempt allocation, boundary crossing, and terminal
  outcome remain distinct facts in the trace.

Protects: INV-001, INV-002, INV-003, INV-005, INV-006, INV-009, INV-011,
         INV-013, INV-014, INV-017, INV-018, INV-019, INV-020
"""
from __future__ import annotations

import asyncio
import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from nodechain.core.side_effect_utils import (
    make_retry_side_effect_key,
    canonicalize_capsule_payload,
    compute_canonical_request_digest,
    ReplayCapsule,
)
from nodechain.core.capsule_crypto import KekManager


class RetryExecutionError(Exception):
    """Raised when retry execution fails validation or execution."""

    def __init__(self, message: str, *, code: str = "RETRY_EXECUTION_FAILED") -> None:
        self.code = code
        super().__init__(message)


class ConfirmedNoEffectError(Exception):
    """Raised by an adapter to signal positive knowledge that no external
    effect occurred (ChatGPT T6 3rd re-review fix 4).

    Unlike timeout or transport errors (which are ambiguous → unknown),
    this signal means the adapter confirmed the external system did not
    execute the operation. The child should be terminalized as 'failed'.
    """
    pass


@dataclass
class RetryExecutionResult:
    """Outcome of a retry execution (three-truth model — INV-009)."""
    retry_attempt_key: str
    child_status: str  # "planned" | "started" | "completed" | "failed" | "unknown"
    node_invocation_outcome: str  # "succeeded" | "failed" | "no_operation" | "rejected" | "pending"
    operator_action_outcome: str  # "completed" | "failed" | "in_progress" | "not_acquired"
    capsule_id: str | None = None
    error: str | None = None
    dispatch_performed: bool = False
    recovery_action_id: str | None = None


@dataclass
class DispatchPreparation:
    """Artifacts prepared BEFORE the dispatch boundary (ChatGPT revised T6 fix 1).

    All validation, envelope construction, constraint derivation, and adapter
    resolution happen here. The boundary CAS is only crossed after this
    succeeds, so a preparation failure leaves dispatch_attempted_at = NULL.
    """
    envelope: Any  # RecoveryEnvelopeV1
    constraints: Any  # ExecutionConstraints
    adapter: Any  # BaseSearchAdapter
    guard: Any  # RecoveryDispatchGuard
    query: Any  # SearchQuery


class SideEffectRetryCoordinator:
    """Coordinates retry-authorized side-effect execution.

    Invoked through RecoveryService._delegate_action for EXECUTE_RETRY_AUTHORIZED.
    The coordinator validates eligibility, allocates the child, claims ownership,
    dispatches through the guarded adapter boundary, classifies the outcome, and
    terminalizes through fenced recovery APIs.

    ChatGPT T6: the adapter must never be called unless the dispatch boundary
    CAS (mark_recovery_dispatch_attempted) succeeds.
    """

    def __init__(
        self,
        state_manager: Any,
        kek: bytes | None = None,
        *,
        adapter_factory: Any = None,
        adapter_trust_validator: Any = None,
        metrics_emitter: Any = None,
    ) -> None:
        """Initialize the coordinator.

        Args:
            state_manager: StateManager instance for all store operations.
            kek: master key for capsule decryption. If None, uses KekManager
                in local-dev mode.
            adapter_factory: callable(adapter_name) -> BaseSearchAdapter that
                produces fresh adapter instances. For T6 testing, inject a
                factory returning a fake adapter. Production CLI wiring lands
                in T8. If None, the coordinator can allocate + converge but
                cannot dispatch (returns child at 'planned' for losing callers
                or raises for dispatch attempts).
            adapter_trust_validator: callable(adapter) -> bool that verifies
                the adapter is a trusted concrete class. Defaults to
                is_trusted_adapter from recovery_dispatch_guard. Tests inject
                a validator that accepts their fake adapter class. No
                adapter-supplied property can bypass this.
            metrics_emitter: RecoveryMetricsEmitter for T9 observability.
                If None, metrics are not emitted (backward-compatible). Must
                use failure_isolated() so a metrics failure never changes
                retry semantics.
        """
        self._sm = state_manager
        self._kek = kek
        self._adapter_factory = adapter_factory
        if adapter_trust_validator is None:
            from nodechain.runtime.recovery_dispatch_guard import is_trusted_adapter
            adapter_trust_validator = is_trusted_adapter
        self._adapter_trust_validator = adapter_trust_validator
        self._metrics = metrics_emitter

    async def execute_authorized_retry_async(
        self,
        run_id: str,
        parent_side_effect_key: str,
        recovery_decision_id: str,
        *,
        actor: str = "operator",
        actor_role: str = "operator",
        operator_action_id: str | None = None,
    ) -> RetryExecutionResult:
        """Execute one authorized retry following the locked T6 protocol.

        Returns RetryExecutionResult with three-truth outcome (INV-009).
        A losing concurrent caller receives child_status of the existing
        child and dispatch_performed=False.

        T9: wraps _execute_authorized_retry_async_impl in a finally block to
        emit retry_command_latency_ms for every path (success, validation
        failure, convergence, exception).
        """
        import time as _time
        _cmd_start = _time.perf_counter()
        try:
            return await self._execute_authorized_retry_async_impl(
                run_id, parent_side_effect_key, recovery_decision_id,
                actor=actor, actor_role=actor_role,
                operator_action_id=operator_action_id,
            )
        finally:
            if self._metrics:
                _cmd_id = operator_action_id or "direct"
                _ms = (_time.perf_counter() - _cmd_start) * 1000.0
                self._metrics.failure_isolated(
                    metric_name="retry_command_latency_ms",
                    value=_ms,
                    run_id=run_id,
                    source_event_key=f"retry:{_cmd_id}:command-latency",
                )

    async def _execute_authorized_retry_async_impl(
        self,
        run_id: str,
        parent_side_effect_key: str,
        recovery_decision_id: str,
        *,
        actor: str = "operator",
        actor_role: str = "operator",
        operator_action_id: str | None = None,
    ) -> RetryExecutionResult:
        """Implementation — see execute_authorized_retry_async for timing wrapper."""
        # ── Step 1: Load parent side-effect, validate status ──
        parent = self._sm.get_side_effect_by_key(run_id, parent_side_effect_key)
        if parent is None:
            raise RetryExecutionError(
                f"Parent side effect not found: {parent_side_effect_key}",
                code="SIDE_EFFECT_NOT_FOUND",
            )
        if parent["status"] != "retry_authorized":
            raise RetryExecutionError(
                f"Parent status is {parent['status']}, not retry_authorized",
                code="SIDE_EFFECT_NOT_RETRY_AUTHORIZED",
            )

        # ── Step 2: Validate capsule available (not legacy) ──
        capsule_status = parent.get("capsule_status", "legacy_unavailable")
        if capsule_status != "available":
            # T9 metrics: material unavailable + legacy ineligible
            if self._metrics:
                _cmd_id = operator_action_id or "direct"
                self._metrics.failure_isolated(
                    metric_name="retry_material_unavailable_total",
                    run_id=run_id,
                    source_event_key=f"retry:{_cmd_id}:material-unavailable",
                )
                if capsule_status == "legacy_unavailable":
                    self._metrics.failure_isolated(
                        metric_name="retry_legacy_ineligible_total",
                        run_id=run_id,
                        source_event_key=f"retry:{_cmd_id}:legacy-ineligible",
                    )
            raise RetryExecutionError(
                f"Parent capsule status is {capsule_status}, not available. "
                f"Legacy rows are categorically ineligible (INV-015).",
                code="REPLAY_MATERIAL_UNAVAILABLE",
            )

        # ── Step 2b: Validate recovery decision binding (ChatGPT T6 5th re-review) ──
        # The recovery_decision_id must correspond to an actual decision record
        # that: exists, belongs to this run, targets this parent side-effect key,
        # is a safe_to_retry decision, was issued from unknown, and is active.
        # Without this check, an operator could supply arbitrary decision IDs
        # to create multiple retry children from one authorization.
        import sqlite3 as _sqlite3
        with _sqlite3.connect(self._sm.db_path) as conn:
            decision_row = conn.execute(
                """SELECT run_id, idempotency_key, decision, prior_status,
                          retention_status
                   FROM side_effect_recovery_decisions
                   WHERE decision_id = ?""",
                (recovery_decision_id,),
            ).fetchone()
        if decision_row is None:
            raise RetryExecutionError(
                f"Recovery decision {recovery_decision_id} not found.",
                code="DECISION_NOT_FOUND",
            )
        d_run, d_key, d_decision, d_prior, d_retention = decision_row
        if d_run != run_id:
            raise RetryExecutionError(
                f"Decision {recovery_decision_id} belongs to run {d_run}, "
                f"not {run_id}.",
                code="DECISION_RUN_MISMATCH",
            )
        if d_key != parent_side_effect_key:
            raise RetryExecutionError(
                f"Decision {recovery_decision_id} targets side effect {d_key}, "
                f"not {parent_side_effect_key}.",
                code="DECISION_TARGET_MISMATCH",
            )
        if d_decision != "safe_to_retry":
            raise RetryExecutionError(
                f"Decision {recovery_decision_id} is '{d_decision}', "
                f"not 'safe_to_retry'.",
                code="DECISION_NOT_SAFE_TO_RETRY",
            )
        if d_prior != "unknown":
            raise RetryExecutionError(
                f"Decision {recovery_decision_id} was issued from "
                f"'{d_prior}', not 'unknown'.",
                code="DECISION_PRIOR_NOT_UNKNOWN",
            )
        if d_retention != "active":
            raise RetryExecutionError(
                f"Decision {recovery_decision_id} retention_status is "
                f"'{d_retention}', not 'active'.",
                code="DECISION_NOT_ACTIVE",
            )

        # ── Step 3: Derive deterministic child key, check convergence ──
        child_key = make_retry_side_effect_key(
            parent_side_effect_key, recovery_decision_id,
        )
        existing_child = self._sm.get_side_effect_by_key(run_id, child_key)
        child_already_allocated = existing_child is not None

        if child_already_allocated and existing_child["status"] != "planned":
            # Terminal or in-flight child — return idempotent result
            return self._handle_existing_child(
                existing_child, child_key, parent, run_id,
            )

        # If child is planned (from initial allocation or requeue after
        # expiry), continue through the claim → prepare → dispatch path.
        # ChatGPT T7 2nd re-review fix 3: a requeued child must be executable.

        # ── Step 4: Extract adapter name ──
        adapter_name = self._extract_adapter_name(parent, parent_side_effect_key)

        action_id = str(uuid.uuid4())
        initial_claim_id = str(uuid.uuid4())

        if not child_already_allocated:
            # ── Step 5: Allocate child at planned + create action row ──
            parent_root = parent.get("root_side_effect_key") or parent_side_effect_key
            parent_ordinal = parent.get("retry_ordinal", 0)
            retry_ordinal = parent_ordinal + 1
        else:
            # ChatGPT T7 3rd re-review fix 1: retry_ordinal from existing child
            parent_root = parent.get("root_side_effect_key") or parent_side_effect_key
            retry_ordinal = existing_child["retry_ordinal"]

        action_id = str(uuid.uuid4())
        initial_claim_id = str(uuid.uuid4())

        if not child_already_allocated:
            # INV-018: child allocation + action row creation in one transaction.
            # Race guard: under concurrent execution, two callers may both see
            # no existing child (TOCTOU between get_side_effect_by_key and the
            # INSERT). The UNIQUE(run_id, recovery_decision_id) constraint
            # prevents duplicate children. The losing caller catches the
            # IntegrityError, re-reads, and converges via _handle_existing_child.
            # The loser must NOT fall through to the claim path — its action_id
            # row was rolled back with the allocation, so the claim CAS would
            # fail with a phantom-action reference.
            _allocation_succeeded = True
            try:
                self._allocate_child_and_action(
                    run_id=run_id,
                    child_key=child_key,
                    parent=parent,
                    parent_side_effect_key=parent_side_effect_key,
                    parent_root=parent_root,
                    retry_ordinal=retry_ordinal,
                    recovery_decision_id=recovery_decision_id,
                    action_id=action_id,
                    operator_action_id=operator_action_id,
                    initial_claim_id=initial_claim_id,
                    actor=actor,
                    actor_role=actor_role,
                )
            except sqlite3.IntegrityError:
                # Race lost — another caller allocated the child (UNIQUE
                # constraint on run_id + recovery_decision_id). Re-read and
                # converge immediately. Do NOT fall through to the claim path:
                # our action_id row was rolled back. Also do NOT emit
                # retry_attempt_created — we did not create the attempt.
                _allocation_succeeded = False
                existing_child = self._sm.get_side_effect_by_key(run_id, child_key)
                if existing_child is not None:
                    return self._handle_existing_child(
                        existing_child, child_key, parent, run_id,
                    )
                # Child vanished (concurrent deletion). Raise — caller handles.
                raise RetryExecutionError(
                    f"Child {child_key} disappeared during allocation race",
                    code="CHILD_ALLOCATION_RACE_LOST",
                )
            # T9 metric: attempt created — only after successful allocation
            if _allocation_succeeded and self._metrics:
                self._metrics.failure_isolated(
                    metric_name="retry_attempt_created",
                    run_id=run_id, retry_attempt_key=child_key,
                    recovery_action_id=action_id,
                    source_event_key=f"retry:{action_id}:attempt-created",
                )
        else:
            # ChatGPT T7 2nd re-review fix 3: child already at planned (from
            # requeue). Create a new action row for this execution attempt
            # but don't re-allocate the child.
            import json as _json
            now = datetime.now(timezone.utc).isoformat()
            metadata = _json.dumps({"actor": actor, "role": actor_role, "requeue": True})
            with __import__("sqlite3").connect(self._sm.db_path) as conn:
                conn.execute(
                    """INSERT INTO recovery_execution_actions
                       (action_id, operator_action_id, run_id, retry_attempt_key,
                        execution_status, execution_claim_id, started_at,
                        finished_at, outcome_code, metadata_json)
                       VALUES (?, ?, ?, ?, 'created', ?, NULL, NULL, NULL, ?)""",
                    (action_id, operator_action_id, run_id, child_key,
                     initial_claim_id, metadata),
                )

        # ── Step 6: Claim dispatch ownership (planned → started) ──
        try:
            fencing_token = self._sm.claim_recovery_attempt(
                run_id, child_key, initial_claim_id, action_id,
            )
        except Exception as e:
            # Someone else claimed it between our allocation and claim.
            # Re-read to converge.
            child_after = self._sm.get_side_effect_by_key(run_id, child_key)
            if child_after is not None:
                self._sm.update_recovery_execution_status(
                    action_id, "not_acquired",
                    outcome_code="claim_contention",
                )
                # T9 metric: claim lost on contention (not boundary CAS)
                if self._metrics:
                    self._metrics.failure_isolated(
                        metric_name="retry_claim_not_acquired",
                        run_id=run_id, retry_attempt_key=child_key,
                        recovery_action_id=action_id,
                        source_event_key=f"retry:{action_id}:claim-not-acquired",
                    )
                return RetryExecutionResult(
                    retry_attempt_key=child_key,
                    child_status=child_after["status"],
                    node_invocation_outcome="pending",
                    operator_action_outcome="not_acquired",
                    recovery_action_id=action_id,
                    error=f"claim contention: {e}",
                )
            raise

        # ChatGPT T7 4th re-review fix 1: action 'claimed' transition is now
        # atomic with the child claim inside claim_recovery_attempt. No
        # separate update needed.

        # T9 metric: claim acquired — immediately after the authoritative claim
        # CAS, NOT after the boundary CAS. A worker that acquires the claim and
        # then fails during preparation is still counted here.
        if self._metrics:
            self._metrics.failure_isolated(
                metric_name="retry_claim_acquired",
                run_id=run_id, retry_attempt_key=child_key,
                recovery_action_id=action_id,
                source_event_key=f"retry:{action_id}:claim-acquired",
            )

        # ── Step 7a: Prepare dispatch (BEFORE boundary) ──
        # ChatGPT revised T6 fix 1: all validation, envelope construction,
        # constraint derivation, and adapter resolution happen BEFORE the
        # boundary CAS. A preparation failure terminalizes as pre-boundary
        # 'failed' with dispatch_attempted_at = NULL.
        try:
            preparation = self._prepare_dispatch(
                run_id, child_key, fencing_token, parent, adapter_name,
                recovery_decision_id, retry_ordinal, action_id,
            )
        except RetryExecutionError as e:
            # Pre-boundary failure — terminalize as failed, no dispatch.
            # ChatGPT T6 re-review fix 5: check the CAS result. If the lease
            # expired during preparation and another worker reclaimed, our
            # fence is stale and fail_recovery_attempt returns False.
            cas_ok = self._sm.fail_recovery_attempt(
                run_id, child_key, fencing_token,
            )
            if not cas_ok:
                # Fence lost — another worker owns the child now.
                # Report as not_acquired, not authoritative failure.
                child_now = self._sm.get_side_effect_by_key(run_id, child_key)
                self._sm.update_recovery_execution_status(
                    action_id, "not_acquired",
                    outcome_code=f"fence_lost_during_prep:{e.code}",
                )
                # T9 metric: claim lost on fence loss during preparation
                # (third authoritative not_acquired path)
                if self._metrics:
                    self._metrics.failure_isolated(
                        metric_name="retry_claim_not_acquired",
                        run_id=run_id, retry_attempt_key=child_key,
                        recovery_action_id=action_id,
                        source_event_key=f"retry:{action_id}:claim-not-acquired",
                    )
                return RetryExecutionResult(
                    retry_attempt_key=child_key,
                    child_status=child_now["status"] if child_now else "unknown",
                    node_invocation_outcome="pending",
                    operator_action_outcome="not_acquired",
                    recovery_action_id=action_id,
                    dispatch_performed=False,
                    error=f"fence lost during preparation: {e}",
                )
            self._sm.finalize_recovery_execution_action(
                action_id, "failed", outcome_code=e.code,
            )
            return RetryExecutionResult(
                retry_attempt_key=child_key,
                child_status="failed",
                node_invocation_outcome="failed",
                operator_action_outcome="completed",
                recovery_action_id=action_id,
                dispatch_performed=False,
                error=str(e),
            )

        # ── Step 7b: Mark dispatch attempted (fenced one-shot CAS) ──
        boundary_crossed = self._sm.mark_recovery_dispatch_attempted(
            run_id, child_key, fencing_token,
        )
        if not boundary_crossed:
            self._sm.update_recovery_execution_status(
                action_id, "not_acquired",
                outcome_code="boundary_cas_rejected",
            )
            # T9 metric: claim lost
            if self._metrics:
                self._metrics.failure_isolated(
                    metric_name="retry_claim_not_acquired",
                    run_id=run_id, retry_attempt_key=child_key,
                    recovery_action_id=action_id,
                    source_event_key=f"retry:{action_id}:claim-not-acquired",
                )
            child_now = self._sm.get_side_effect_by_key(run_id, child_key)
            return RetryExecutionResult(
                retry_attempt_key=child_key,
                child_status=child_now["status"] if child_now else "unknown",
                node_invocation_outcome="pending",
                operator_action_outcome="not_acquired",
                recovery_action_id=action_id,
                error="boundary CAS rejected (lease expired or fence stolen)",
            )

        # T9 metric: boundary crossed (claim_acquired already emitted at the
        # authoritative claim CAS, not here)
        if self._metrics:
            self._metrics.failure_isolated(
                metric_name="retry_dispatch_boundary_crossed_total",
                run_id=run_id, recovery_action_id=action_id,
                source_event_key=f"retry:{action_id}:dispatch-crossed",
            )

        # Update action: dispatch_started
        self._sm.update_recovery_execution_status(action_id, "dispatch_started")

        # ── Step 8: Execute dispatch through guarded adapter ──
        # T9: attempt latency starts AFTER the boundary CAS succeeds and ends
        # after terminalization + final-status reread (authoritative truth).
        import time as _time
        _attempt_start = _time.perf_counter()
        outcome, response_hash, error = await self._execute_dispatch_async(preparation)

        # ── Step 9: Terminalize through fenced recovery API ──
        self._terminalize(
            run_id, child_key, fencing_token, action_id, outcome,
            response_hash, error,
        )

        # ── Step 10: Build three-truth result ──
        child_final = self._sm.get_side_effect_by_key(run_id, child_key)
        final_status = child_final["status"] if child_final else "unknown"

        # T9 metrics: authoritative outcome from final_status (NOT pre-terminal
        # outcome arg — a lost fence can turn nominal completed into unknown).
        # Attempt latency ends here, after the reread.
        if self._metrics:
            _outcome_metric = {
                "completed": "retry_outcome_completed",
                "failed": "retry_outcome_failed",
                "unknown": "retry_unknown_total",
            }.get(final_status, "retry_unknown_total")
            # Include adapter_id on outcome metrics so the dashboard adapter
            # top-20 aggregation has real data from actual retry executions.
            _outcome_labels = {}
            if final_status in ("completed", "failed", "unknown"):
                _outcome_labels["outcome"] = final_status
            if adapter_name:
                _outcome_labels["adapter_id"] = adapter_name
            self._metrics.failure_isolated(
                metric_name=_outcome_metric,
                run_id=run_id, retry_attempt_key=child_key,
                recovery_action_id=action_id,
                source_event_key=f"retry:{action_id}:outcome:{final_status}",
                labels=_outcome_labels if _outcome_labels else None,
            )
            _attempt_ms = (_time.perf_counter() - _attempt_start) * 1000.0
            self._metrics.failure_isolated(
                metric_name="retry_attempt_latency_ms",
                value=_attempt_ms,
                run_id=run_id, retry_attempt_key=child_key,
                recovery_action_id=action_id,
                source_event_key=f"retry:{action_id}:attempt-latency",
            )

        return RetryExecutionResult(
            retry_attempt_key=child_key,
            child_status=final_status,
            node_invocation_outcome=self._outcome_to_node(outcome),
            operator_action_outcome=self._status_to_operator(final_status),
            capsule_id=parent.get("capsule_id"),
            recovery_action_id=action_id,
            dispatch_performed=True,
            error=error,
        )

    # ── Convergence: handle existing child ──────────────────────────────

    def _handle_existing_child(
        self,
        existing_child: dict,
        child_key: str,
        parent: dict,
        run_id: str = "",
    ) -> RetryExecutionResult:
        """Return idempotent result for an already-allocated child.

        ChatGPT T6: a losing caller should receive an explicit result with
        dispatch_performed=False, NOT treat contention as execution failure.
        """
        status = existing_child["status"]
        # T9 metric: convergence no-operation (a losing caller found an
        # already-allocated child — no new dispatch occurred).
        if self._metrics:
            self._metrics.failure_isolated(
                metric_name="retry_no_operation_total",
                run_id=run_id or None, retry_attempt_key=child_key,
                source_event_key=f"retry:{run_id}:{child_key}:no-operation",
            )
        return RetryExecutionResult(
            retry_attempt_key=child_key,
            child_status=status,
            node_invocation_outcome=(
                "succeeded" if status == "completed"
                else "failed" if status == "failed"
                else "pending"
            ),
            operator_action_outcome=(
                "completed" if status in ("completed", "failed", "unknown")
                else "in_progress"
            ),
            capsule_id=parent.get("capsule_id"),
            dispatch_performed=False,
            error=None if status != "unknown" else "prior dispatch outcome uncertain",
        )

    # ── Child allocation (INV-018: atomic child + action) ───────────────

    def _allocate_child_and_action(
        self,
        *,
        run_id: str,
        child_key: str,
        parent: dict,
        parent_side_effect_key: str,
        parent_root: str,
        retry_ordinal: int,
        recovery_decision_id: str,
        action_id: str,
        operator_action_id: str | None,
        initial_claim_id: str,
        actor: str,
        actor_role: str,
    ) -> None:
        """Atomically allocate the child at planned + create the action row.

        INV-018: both must commit or roll back together.
        """
        import sqlite3
        now = datetime.now(timezone.utc).isoformat()
        metadata = json.dumps({"actor": actor, "role": actor_role})

        with sqlite3.connect(self._sm.db_path) as conn:
            # Create child side-effect row at planned
            conn.execute(
                """INSERT INTO side_effect_ledger
                   (run_id, step_id, node_id, side_effect_type, idempotency_key,
                    status, request_hash, retryable, timestamp,
                    parent_side_effect_key, root_side_effect_key,
                    retry_ordinal, recovery_decision_id, capsule_status,
                    capsule_id)
                   VALUES (?, ?, ?, ?, ?, 'planned', ?, 1, ?, ?, ?, ?, ?, 'available', ?)""",
                (run_id, parent["step_id"], parent["node_id"],
                 parent["side_effect_type"], child_key,
                 parent.get("request_hash"), now,
                 parent_side_effect_key, parent_root,
                 retry_ordinal, recovery_decision_id,
                 parent.get("capsule_id")),
            )
            # Create recovery execution action row
            conn.execute(
                """INSERT INTO recovery_execution_actions
                   (action_id, operator_action_id, run_id, retry_attempt_key,
                    execution_status, execution_claim_id, started_at,
                    finished_at, outcome_code, metadata_json)
                   VALUES (?, ?, ?, ?, 'created', ?, NULL, NULL, NULL, ?)""",
                (action_id, operator_action_id, run_id, child_key,
                 initial_claim_id, metadata),
            )

    # ── Step 8: dispatch through guarded adapter ────────────────────────

    def _prepare_dispatch(
        self,
        run_id: str,
        child_key: str,
        fencing_token: str,
        parent: dict,
        adapter_name: str,
        recovery_decision_id: str,
        retry_ordinal: int,
        action_id: str,
    ) -> DispatchPreparation:
        """Prepare all dispatch artifacts BEFORE the boundary CAS.

        ChatGPT revised T6 fix 1: the sequence must be:
            capsule decrypted
            → RecoveryEnvelopeV1 constructed and validated
            → execution constraints derived
            → SearchQuery built
            → adapter resolved
            → [boundary crossed by caller]
            → guarded dispatch

        A preparation failure raises RetryExecutionError. The caller
        terminalizes as pre-boundary 'failed' with dispatch_attempted_at=NULL.

        Raises RetryExecutionError on any validation failure.
        """
        from nodechain.runtime.recovery_dispatch_guard import (
            RecoveryDispatchGuard,
        )
        from nodechain.core.envelope import RecoveryEnvelopeV1, RecoveryEnvelopeError

        # Load capsule — fail closed on decryption/parsing failures
        capsule_data = self._load_capsule_metadata(parent, run_id)
        canonical_operation = capsule_data.get("canonical_operation")
        if canonical_operation is None:
            raise RetryExecutionError(
                "Capsule payload could not be decrypted or parsed. "
                "Cannot prepare dispatch without canonical operation.",
                code="CAPSULE_DECRYPTION_FAILED",
            )

        # ChatGPT revised T6 major 4: use attested values from capsule,
        # not empty-string fallbacks. Cross-check adapter identity.
        caps_adapter_id = capsule_data.get("adapter_id", "")
        if not caps_adapter_id:
            raise RetryExecutionError(
                "Capsule source binding has empty adapter_id.",
                code="INCOMPLETE_CAPSULE_BINDING",
            )
        if caps_adapter_id != adapter_name:
            raise RetryExecutionError(
                f"Adapter identity mismatch: capsule attests '{caps_adapter_id}' "
                f"but key parsing produced '{adapter_name}'.",
                code="ADAPTER_IDENTITY_MISMATCH",
            )

        # Build source binding from attested capsule values (no fallbacks)
        required_binding_fields = [
            "node_id", "node_version", "contract_id", "contract_version",
            "adapter_id", "adapter_version",
        ]
        for field in required_binding_fields:
            if not capsule_data.get(field):
                raise RetryExecutionError(
                    f"Capsule source binding field '{field}' is empty. "
                    f"Recovery dispatch requires complete attested binding.",
                    code="INCOMPLETE_CAPSULE_BINDING",
                )

        source_binding = {f: capsule_data[f] for f in required_binding_fields}

        parent_root = parent.get("root_side_effect_key") or parent.get(
            "idempotency_key", "",
        )

        # Construct and validate RecoveryEnvelopeV1
        try:
            envelope = RecoveryEnvelopeV1.build(
                recovery_action_id=action_id,
                recovery_decision_id=recovery_decision_id,
                original_invocation_id=parent.get("idempotency_key", ""),
                parent_side_effect_key=parent.get("idempotency_key", ""),
                root_side_effect_key=parent_root,
                retry_attempt_key=child_key,
                retry_ordinal=retry_ordinal,
                replay_capsule_id=parent.get("capsule_id", ""),
                replay_capsule_digest=capsule_data.get(
                    "canonical_request_digest", "",
                ),
                replay_capsule_schema_version=capsule_data.get(
                    "capsule_schema_version", 1,
                ),
                canonicalization_version=capsule_data.get(
                    "canonicalization_version", "1",
                ),
                source_binding=source_binding,
                execution_claim_id=fencing_token,
                required_type=parent.get("side_effect_type", "search"),
                required_operation_name=capsule_data.get(
                    "operation_name", "search",
                ),
                required_adapter_id=caps_adapter_id,
                required_adapter_version=capsule_data["adapter_version"],
                required_request_hash=capsule_data.get(
                    "canonical_request_digest", "",
                ),
            )
        except RecoveryEnvelopeError as e:
            raise RetryExecutionError(
                f"Recovery envelope validation failed: {e}",
                code="ENVELOPE_VALIDATION_FAILED",
            ) from e

        # Derive execution constraints from the validated envelope
        constraints = envelope.to_execution_constraints()

        # Resolve adapter
        if self._adapter_factory is None:
            raise RetryExecutionError(
                "No adapter_factory configured — cannot prepare dispatch.",
                code="NO_ADAPTER_FACTORY",
            )
        try:
            adapter = self._adapter_factory(adapter_name)
        except Exception as e:
            raise RetryExecutionError(
                f"Adapter construction failed: {e}",
                code="ADAPTER_CONSTRUCTION_FAILED",
            ) from e

        # ChatGPT fix 1: verify the resolved adapter's identity matches
        # the capsule's attested adapter (prevents factory returning wrong adapter)
        if adapter.adapter_name != caps_adapter_id:
            raise RetryExecutionError(
                f"Resolved adapter '{adapter.adapter_name}' does not match "
                f"capsule-attested adapter '{caps_adapter_id}'.",
                code="ADAPTER_IDENTITY_MISMATCH",
            )

        # ChatGPT T6 re-review fix 3: attest the ACTUAL capsule adapter version
        # (not hardcoded 1.0.0) and verify the resolved adapter is a trusted
        # implementation class (not identity-spoofed).
        from nodechain.runtime.recovery_dispatch_guard import (
            is_adapter_attested, is_trusted_adapter,
        )
        caps_adapter_version = capsule_data["adapter_version"]
        if not is_adapter_attested(caps_adapter_id, caps_adapter_version):
            raise RetryExecutionError(
                f"Adapter {caps_adapter_id} v{caps_adapter_version} is not "
                f"attested for retry execution (INV-019).",
                code="ADAPTER_NOT_ATTESTED",
            )
        # ChatGPT T6 re-review fix 1: trust validation is injected by the
        # composition root, not self-asserted by the adapter. No adapter-
        # supplied property can bypass this.
        if not self._adapter_trust_validator(adapter):
            raise RetryExecutionError(
                f"Adapter {caps_adapter_id} is not a trusted concrete class. "
                f"Identity spoofing prevented.",
                code="UNTRUSTED_ADAPTER",
            )

        # Build guard (boundary callback is noop — caller already crossed)
        guard = RecoveryDispatchGuard(
            target_adapter=adapter,
            constraints=constraints,
            on_dispatch_attempted=lambda: None,
        )

        # Build SearchQuery from canonical operation
        from nodechain.adapters.search.base_search import SearchQuery
        terms = canonical_operation.get("terms", [])
        if isinstance(terms, str):
            terms = [terms]
        query = SearchQuery(
            terms=terms,
            max_results=canonical_operation.get("max", 10),
            filters=canonical_operation.get("filters", {}),
        )

        # ChatGPT T6 re-review fix 2: run preflight validation BEFORE the
        # boundary CAS. This validates adapter ID, version, and request hash
        # without persisting or dispatching. A mismatch raises here, leaving
        # dispatch_attempted_at = NULL.
        from nodechain.runtime.recovery_dispatch_guard import RecoveryDispatchError
        try:
            guard.preflight_validate(query)
        except RecoveryDispatchError as e:
            raise RetryExecutionError(
                f"Preflight dispatch validation failed: {e}",
                code="PREFLIGHT_VALIDATION_FAILED",
            ) from e

        # ChatGPT T6 re-review fix 2: recompute digest from decrypted bytes
        # and verify it matches the stored capsule_digest.
        from nodechain.core.side_effect_utils import (
            canonicalize_capsule_payload, compute_canonical_request_digest,
        )
        recomputed_digest = compute_canonical_request_digest(
            canonicalize_capsule_payload(canonical_operation),
        )
        stored_digest = capsule_data.get("canonical_request_digest", "")
        if stored_digest and recomputed_digest != stored_digest:
            raise RetryExecutionError(
                f"Capsule digest mismatch: stored={stored_digest[:12]}… "
                f"recomputed={recomputed_digest[:12]}…",
                code="CAPSULE_DIGEST_MISMATCH",
            )

        return DispatchPreparation(
            envelope=envelope,
            constraints=constraints,
            adapter=adapter,
            guard=guard,
            query=query,
        )

    async def _execute_dispatch_async(
        self, preparation: DispatchPreparation,
    ) -> tuple[str, str | None, str | None]:
        """Execute the prepared dispatch through the guarded adapter (async).

        ChatGPT T8 fix 1: no asyncio.run() after the boundary. This method
        is natively async — the caller manages the event loop.

        ChatGPT T6 outcome classification (boundary as truth divider):
        - Confirmed completion → "completed"
        - Confirmed no-effect failure → "failed"
        - Timeout/crash/transport ambiguity → "unknown"
        """
        from nodechain.runtime.recovery_dispatch_guard import RecoveryDispatchError

        try:
            results = await preparation.guard.search(preparation.query)
        except RecoveryDispatchError as e:
            return ("failed", None, f"dispatch guard rejected: {e}")
        except ConfirmedNoEffectError as e:
            # ChatGPT T6 3rd re-review fix 4: positive knowledge that no
            # external effect occurred → failed (not unknown).
            return ("failed", None, f"confirmed no-effect: {e}")
        except TimeoutError as e:
            return ("unknown", None, f"adapter timeout: {e}")
        except ConnectionError as e:
            return ("unknown", None, f"transport error: {e}")
        except Exception as e:
            error_name = type(e).__name__
            if "timeout" in str(e).lower() or "timed out" in str(e).lower():
                return ("unknown", None, f"adapter timeout: {e}")
            return ("unknown", None, f"{error_name}: {e}")

        response_hash = self._compute_response_hash(results)
        return ("completed", response_hash, None)

    def _terminalize(
        self,
        run_id: str,
        child_key: str,
        fencing_token: str,
        action_id: str,
        outcome: str,
        response_hash: str | None,
        error: str | None,
    ) -> None:
        """Terminalize the child through fenced recovery API (step 9).

        ChatGPT T6: never terminalize a recovery child through ordinary
        completion mutation.
        """
        if outcome == "completed":
            ok = self._sm.complete_recovery_attempt(
                run_id, child_key, fencing_token, response_hash,
            )
            if ok:
                # We held the fence and completed the child ourselves.
                self._sm.finalize_recovery_execution_action(
                    action_id, "completed",
                    outcome_code="adapter_confirmed_completion",
                )
                return
            # v3.5.1 (#6): fence lost between dispatch and completion. Derive
            # the action result EXCLUSIVELY from authoritative child truth —
            # the stale worker's nominal adapter result must not override the
            # child ledger. The previous code fell through to finalize as
            # completed whenever the child was failed/unknown/missing, which
            # is precisely when a stale worker must never complete.
            child = self._sm.get_side_effect_by_key(run_id, child_key)
            child_status = child["status"] if child else "missing"
            if child_status == "completed":
                # v3.5.1 (#6) B1: status compatibility alone is insufficient.
                # Require the stored and worker response hashes to be nonempty
                # AND equal before idempotent convergence. Two workers can
                # receive different external responses; the stale action must
                # not be recorded as adapter_confirmed_completion unless the
                # outcome is cryptographically identical.
                child_hash = child.get("response_hash") if child else None
                if (child_hash and response_hash
                        and child_hash == response_hash):
                    self._sm.finalize_recovery_execution_action(
                        action_id, "completed",
                        outcome_code="adapter_confirmed_completion",
                    )
                elif not child_hash or not response_hash:
                    self._sm.finalize_recovery_execution_action(
                        action_id, "unknown",
                        outcome_code="stale_fence_completed_hash_unverifiable",
                    )
                else:
                    self._sm.finalize_recovery_execution_action(
                        action_id, "unknown",
                        outcome_code="stale_fence_completed_hash_mismatch",
                    )
            elif child_status == "failed":
                # Authoritative truth says the effect did NOT happen.
                self._sm.finalize_recovery_execution_action(
                    action_id, "unknown",
                    outcome_code="stale_fence_child_failed",
                )
            elif child_status == "unknown":
                self._sm.finalize_recovery_execution_action(
                    action_id, "unknown",
                    outcome_code="stale_fence_child_unknown",
                )
            elif child_status == "missing":
                # Child row vanished — integrity failure. Conservative.
                self._sm.finalize_recovery_execution_action(
                    action_id, "unknown",
                    outcome_code="stale_fence_child_missing_integrity",
                )
            else:
                # planned / started under another claim (in-flight): the
                # effect's terminal outcome is not yet knowable.
                self._sm.update_recovery_execution_status(
                    action_id, "unknown",
                    outcome_code="fence_lost_after_dispatch",
                )
        elif outcome == "failed":
            ok = self._sm.fail_recovery_attempt(
                run_id, child_key, fencing_token,
            )
            if not ok:
                self._sm.update_recovery_execution_status(
                    action_id, "unknown",
                    outcome_code="fence_lost_after_dispatch",
                )
                return
            self._sm.finalize_recovery_execution_action(
                action_id, "failed",
                outcome_code="adapter_confirmed_no_effect",
            )
        else:  # unknown
            # Conservative: mark child as unknown if not already terminal
            child = self._sm.get_side_effect_by_key(run_id, child_key)
            if child and child["status"] == "started":
                # The reclaim path handles boundary-crossed children → unknown
                # But we hold the fence, so attempt a direct transition via
                # complete/fail CAS which will fail if fence lost, then
                # let the reconciler (T7) catch it.
                #
                # Actually: for unknown, we need to transition started→unknown.
                # The fenced recovery API doesn't have a direct unknown method.
                # The reclaim path does it, but requires lease expiry.
                # For correctness: we expire the lease and let reclaim handle it.
                # But we hold a valid lease... So we need a fenced unknown path.
                #
                # Direct approach: use the store's generic update with our fence.
                # This is safe because we're the fence holder.
                import sqlite3
                with sqlite3.connect(self._sm.db_path) as conn:
                    conn.execute(
                        """UPDATE side_effect_ledger
                           SET status = 'unknown'
                           WHERE run_id = ? AND idempotency_key = ?
                           AND status = 'started'
                           AND execution_claim_id = ?""",
                        (run_id, child_key, fencing_token),
                    )
            self._sm.finalize_recovery_execution_action(
                action_id, "unknown",
                outcome_code="post_boundary_uncertain",
            )

    # ── Helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _extract_adapter_name(parent: dict, parent_key: str) -> str:
        """Extract adapter name from side effect key or capsule metadata."""
        # Try capsule source binding first (loaded by caller if needed)
        # Fall back to key parsing
        key_parts = parent_key.split(":")
        if key_parts[0] == "search" and len(key_parts) >= 3:
            return key_parts[1]
        if len(key_parts) >= 2:
            return key_parts[0]
        return parent.get("side_effect_type", "unknown")

    def _load_capsule_metadata(self, parent: dict, run_id: str = "") -> dict:
        """Load and decrypt the capsule to extract canonical operation + metadata.

        The capsule metadata lives in side_effect_replay_capsules.source_binding_json.
        The canonical operation is in the encrypted payload.
        """
        capsule_id = parent.get("capsule_id")
        if not capsule_id:
            return {}

        import sqlite3
        import json as _json
        with sqlite3.connect(self._sm.db_path) as conn:
            row = conn.execute(
                """SELECT source_binding_json, capsule_digest,
                          capsule_schema_version, canonicalization_version,
                          encrypted_payload, nonce, key_version
                   FROM side_effect_replay_capsules WHERE capsule_id = ?""",
                (capsule_id,),
            ).fetchone()

        if row is None:
            return {}

        source_binding_json, digest, schema_ver, canon_ver, \
            encrypted_payload, nonce, key_version = row

        metadata: dict[str, Any] = {
            "canonical_request_digest": digest,
            "capsule_schema_version": schema_ver,
            "canonicalization_version": canon_ver,
        }

        # Parse source binding
        try:
            source_binding = _json.loads(source_binding_json) if source_binding_json else {}
            metadata.update(source_binding)
        except (ValueError, TypeError):
            pass

        # Decrypt payload to get canonical operation
        # ChatGPT revised T6 major 4: fail closed on decryption/parsing errors.
        # Do NOT swallow exceptions and return empty metadata.
        if encrypted_payload and nonce:
            if self._kek is None:
                # v3.5.1 (#8) blocker A: resolve the KEK via the injected
                # composition-root manager on the StateManager. Only fall back
                # to a bare KekManager() (production fail-closed default) when
                # no manager was injected — preserving backward compatibility
                # for direct coordinator construction in tests.
                try:
                    injected = getattr(self._sm, "_kek_manager", None)
                    if injected is not None:
                        self._kek = injected.get_kek()
                    else:
                        self._kek = KekManager().get_kek()
                except Exception as e:
                    raise RetryExecutionError(
                        f"Cannot resolve KEK for capsule decryption: {e}",
                        code="CAPSULE_DECRYPTION_FAILED",
                    ) from e
            try:
                from nodechain.core.stores import RunKeyStore
                from nodechain.core.capsule_crypto import decrypt_capsule_payload
                run_key_store = RunKeyStore(self._sm.db_path)
                dek, _ = run_key_store.get_or_create_run_dek(run_id, self._kek)
                plaintext = decrypt_capsule_payload(
                    dek, encrypted_payload, nonce,
                    run_id=run_id,
                    capsule_id=capsule_id,
                    side_effect_key=parent.get("idempotency_key", ""),
                    capsule_schema_version=schema_ver,
                    canonicalization_version=canon_ver,
                )
                canonical_operation = _json.loads(plaintext)
                metadata["canonical_operation"] = canonical_operation
            except RetryExecutionError:
                raise
            except Exception as e:
                raise RetryExecutionError(
                    f"Capsule decryption or payload parsing failed: {e}",
                    code="CAPSULE_DECRYPTION_FAILED",
                ) from e

        return metadata

    @staticmethod
    def _compute_response_hash(results: list) -> str:
        """Compute a response hash from adapter results."""
        import hashlib
        if not results:
            return hashlib.sha256(b"empty").hexdigest()
        # Normalize SearchAdapterResult objects to dicts for hashing
        if hasattr(results[0], "model_dump"):
            serializable = [r.model_dump() for r in results]
        elif hasattr(results[0], "__dict__"):
            serializable = [vars(r) for r in results]
        else:
            serializable = results
        canonical = canonicalize_capsule_payload(serializable)
        return hashlib.sha256(canonical).hexdigest()

    @staticmethod
    def _outcome_to_node(outcome: str) -> str:
        """Map outcome to node_invocation_outcome."""
        return {
            "completed": "succeeded",
            "failed": "failed",
            "unknown": "pending",
        }.get(outcome, "pending")

    @staticmethod
    def _status_to_operator(status: str) -> str:
        """Map child status to operator_action_outcome."""
        if status in ("completed", "failed", "unknown"):
            return "completed"
        return "in_progress"

    def execute_authorized_retry(
        self,
        run_id: str,
        parent_side_effect_key: str,
        recovery_decision_id: str,
        *,
        actor: str = "operator",
        actor_role: str = "operator",
        operator_action_id: str | None = None,
    ) -> RetryExecutionResult:
        """Synchronous wrapper — single top-level asyncio.run() at the CLI boundary.

        ChatGPT T8 fix 1: the event loop is created HERE, before any recovery
        state mutation. No asyncio.run() occurs after the boundary CAS.
        """
        return asyncio.run(self.execute_authorized_retry_async(
            run_id, parent_side_effect_key, recovery_decision_id,
            actor=actor, actor_role=actor_role,
            operator_action_id=operator_action_id,
        ))
