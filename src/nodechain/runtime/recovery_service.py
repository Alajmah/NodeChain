"""RecoveryService — runtime-safe action layer for the Operator Recovery Console (v2.46.0).

This is the bridge between the console (CLI) and the existing runtime primitives
(StateManager, TraceReconciler, ReviewManager, Orchestrator, FailureManager).
It owns NO execution loop and NO state mutation of its own: reads assemble a
derived snapshot; actions delegate to the existing primitives through their
public APIs and never write to the DB directly.

Phase 1 (this file) implements the read half only:

* ``list_runs()``                  -> cross-run backlog (delegates to StateManager)
* ``build_snapshot(run_id)``       -> derived RecoverySnapshot
* ``build_trace_health(run_id)``   -> TraceReconciler report (or degraded)

The action half (``apply_action``) lands in Phase 3.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from nodechain.core.state import ChainState, RunSummary, StateManager
from nodechain.core.trace import EventType
from nodechain.runtime.recovery_classifier import (
    RecoveryState,
    classify,
)
from nodechain.runtime.recovery_policy import (
    AuthorizationResult,
    OperatorActionPolicy,
    RecoveryAction,
)
from nodechain.runtime.recovery_snapshot import RecoverySnapshot
from nodechain.runtime.trace_reconciler import (
    ReconciliationIssue,
    ReconciliationReport,
    TraceReconciler,
)

DEFAULT_TRACE_DIR = "data/traces"


@dataclass
class DelegationResult:
    """Internal result from _delegate_action — carries resulting_state plus
    optional structured recovery data without mutable service-global state.

    ChatGPT T8 re-review fix 2: replaces self._last_retry_result.
    """
    resulting_state: str
    retry_result: Any = None  # RetryExecutionResult | None


class RecoveryService:
    """Read + (later) action surface over durable run state.

    Constructed with a StateManager and the trace directory the runtime writes
    ChainTrace JSON to. All reads are read-only; ``build_snapshot`` never
    changes ``state.revision``.
    """

    def __init__(
        self,
        state_manager: StateManager,
        trace_dir: str = DEFAULT_TRACE_DIR,
    ) -> None:
        self.state_manager = state_manager
        self.trace_dir = trace_dir
        self._action_delegate: Callable[..., str] | None = None
        self._retry_coordinator: Any = None  # v3.5.0: SideEffectRetryCoordinator
        self._metrics_emitter: Any = None  # v3.5.0 T9: RecoveryMetricsEmitter

    def set_action_delegate(self, delegate: Callable[..., str]) -> None:
        """Install the orchestrator-backed delegate (v2.46.0 Phase 4).

        The delegate is a callable ``(action, run_id, *, target_step_id, reason,
        instructions) -> resulting_status`` that reconstructs the Orchestrator
        and calls the SAME runtime path the normal resume CLI uses
        (Orchestrator.resume / ReviewManager.resolve_resume_review). Installed
        by the CLI; without it, resume/retry/approve/reject/revise raise
        NotImplementedError rather than silently no-op'ing.

        RecoveryService owns no execution loop — this is the seam that keeps
        runtime authority with the Orchestrator while the console stays a thin
        policy/audit layer.
        """
        self._action_delegate = delegate

    def set_retry_coordinator(self, coordinator: Any) -> None:
        """Install the SideEffectRetryCoordinator for v3.5.0 retry execution.

        ChatGPT T6 CLI composition item: the coordinator is injected via a
        dedicated seam, NOT overloading _action_delegate. The orchestrator
        delegate handles flow-control actions (resume/retry/approve); the
        retry coordinator handles side-effect retry execution through the
        recovery dispatch seam (INV-005).

        Without this, EXECUTE_RETRY_AUTHORIZED raises NotImplementedError.
        """
        self._retry_coordinator = coordinator

    def set_metrics_emitter(self, emitter: Any) -> None:
        """Install the T9 metrics emitter for retry observability.

        Emits retry_policy_denied_total + retry_rejected_total when an
        EXECUTE_RETRY_AUTHORIZED action is refused by governance. Uses
        failure_isolated() so metrics never change execution truth.
        """
        self._metrics_emitter = emitter

    # --- read: list --------------------------------------------------------

    def list_runs(self) -> list[RunSummary]:
        """Every persisted run, most-recently-updated first."""
        return self.state_manager.list_all_runs()

    # --- read: snapshot ----------------------------------------------------

    def build_snapshot(self, run_id: str) -> RecoverySnapshot | None:
        """Assemble a derived RecoverySnapshot for one run.

        Returns None if the run is unknown. Never mutates state — building a
        snapshot leaves ``state.revision`` unchanged.
        """
        state = self.state_manager.load(run_id)
        if state is None:
            return None

        # v3.5.1 (#4): build_trace_health is pure — it reports expired children
        # that need repair but does not perform it. We load side_effects after
        # the (read-only) health check so the snapshot reflects current durable
        # facts. An expired child remains 'started' in the snapshot until an
        # explicit `reconcile` repairs it; the snapshot surfaces the need via
        # trace warnings.
        report = self.build_trace_health(run_id)

        side_effects = self.state_manager.get_side_effects(run_id)
        recovery_decisions = self.state_manager.get_recovery_decisions(run_id=run_id)
        review_attempts = self.state_manager.get_review_attempts(run_id=run_id)

        classification = classify(
            state,
            side_effects,
            report,
            review_attempts,
            recovery_decisions=recovery_decisions,
        )

        pending_review = self._pending_review(state)
        loop_counters = self._loop_counters(state)
        retry_counters = self._retry_counters(state, side_effects)
        last_successful_step = self._last_successful_step(state)
        failed_step = self._failed_step(state, side_effects)

        md = state.metadata or {}
        # last_update_time is the DB persistence timestamp (chain_states.updated_at),
        # NOT a lifecycle field — started_at/completed_at stay fixed and would
        # show stale freshness on a re-saved run. Fall back to started_at only
        # if the DB row is somehow missing the column.
        last_update = self.state_manager.get_run_updated_at(run_id) or state.started_at

        return RecoverySnapshot(
            run_id=state.run_id,
            chain_id=state.chain_id,
            status=state.status,
            recovery_state=classification.state.value,
            current_node=state.current_node or None,
            current_step=state.step if state.step is not None else None,
            last_successful_step=last_successful_step,
            failed_step=failed_step,
            blocking_reason=classification.blocking_reason,
            available_actions=self._available_actions(classification.state, state),
            loop_counters=loop_counters,
            retry_counters=retry_counters,
            pending_review=pending_review,
            pending_policy_decision=self._pending_policy_decision(state),
            trace_complete=report.is_clean and not report.warnings,
            trace_warnings=[w.actual or w.check for w in report.warnings],
            trace_errors=[e.actual or e.check for e in report.errors],
            state_revision=state.revision,
            last_update_time=last_update,
        )

    # --- read: trace health -----------------------------------------------

    def build_trace_health(self, run_id: str) -> ReconciliationReport:
        """Run the TraceReconciler over the run's persisted trace.

        If the trace file is missing (e.g. a crash before flush) or cannot be
        parsed into a valid ChainTrace, returns a degraded report with a
        warning rather than raising — the snapshot must still render for the
        operator and a corrupt trace must never crash generation.

        v3.5.1 (#4): this method is PURE. It performs ZERO durable mutation —
        no child-status transitions, no action-row updates, no state_events
        inserts, no metric emissions. Expired recovery children are DETECTED
        via scan_expired_recovery_children and reported as
        ``side_effect_retry_repair_required`` issues so the operator sees that
        an explicit reconciliation is needed, but the read never performs it.
        The explicit mutating owner is ``reconcile_expired_recovery_children``
        (driven by the reconcile command), NOT a snapshot.
        """
        # v3.5.1 (#4): PURE detection — report repair needed, do not perform it.
        repair_issues: list[ReconciliationIssue] = []
        try:
            expired = self.state_manager.scan_expired_recovery_children(run_id)
            for rec in expired:
                child_key = rec.get("child_key", "")
                would = rec.get("would_action", "requeued")
                repair_issues.append(ReconciliationIssue(
                    check="side_effect_retry_repair_required",
                    severity="warning",
                    expected="no expired started recovery children",
                    actual=(
                        f"expired child {child_key} needs explicit reconciliation "
                        f"(would {would}); run `nodechain reconcile` to repair"
                    ),
                ))
        except Exception as e:
            # T9 re-review: the snapshot must remain renderable, but the repair
            # failure must be represented — not silently suppressed.
            repair_issues.append(ReconciliationIssue(
                check="side_effect_retry_repair_failed",
                severity="error",
                expected="expired-child detection completes",
                actual=f"detection raised: {e}",
            ))

        trace, load_error = self._load_trace(run_id)
        if trace is None:
            actual = load_error or "trace could not be loaded"
            return ReconciliationReport(
                run_id=run_id,
                issues=repair_issues + [ReconciliationIssue(
                    check="trace_file_present",
                    severity="warning",
                    expected="a valid persisted trace for the run",
                    actual=actual,
                )],
            )
        reconciler = TraceReconciler(state_manager=self.state_manager)
        # T9: wire the shared metrics emitter so reconciliation requeue events
        # are observable. Without this, retry_requeued is never emitted from
        # the production reconciliation path.
        if self._metrics_emitter is not None:
            reconciler.set_metrics_emitter(self._metrics_emitter)
        # T9 5th re-review: skip the reconciler's own expiry repair — we
        # already ran it above (single-owner per invocation). Without this,
        # a persistent DB failure produces two side_effect_retry_repair_failed
        # errors for one underlying failure.
        report = reconciler.reconcile(trace, repair_expired=False)
        # T9 re-review: if the pre-trace repair failed, surface it here too.
        if repair_issues:
            report.issues.extend(repair_issues)
        return report

    def authorize_action(
        self,
        run_id: str,
        action: RecoveryAction,
        *,
        operator_identity: str = "console",
        target_step_id: int | None = None,
        operator_override: bool | None = None,
        reason: str | None = None,
        instructions: str | None = None,
        new_budget: float | None = None,
        operator_role: str | None = None,
        governance_profile: str | None = None,
        governance_profile_file: str | None = None,
    ) -> AuthorizationResult:
        """Authorize an action WITHOUT executing it (v2.50.0 batch dry-run).

        Runs the same RBAC + policy checks as apply_action but does not emit
        events, record ledger rows, or delegate. Used by batch dry-run planning.
        """
        from nodechain.runtime.recovery_policy import OperatorActionPolicy
        state = self.state_manager.load(run_id)
        if state is None:
            return AuthorizationResult(admitted=False,
                                        rejection_reason=f"unknown run: {run_id}",
                                        denial_type="policy")
        snapshot = self._snapshot_for_policy(run_id, state)
        try:
            resolved_profile = self._resolve_profile(governance_profile, governance_profile_file)
        except Exception as e:
            return AuthorizationResult(
                admitted=False,
                rejection_reason=f"invalid governance profile: {e}",
                denial_type="governance_profile",
            )
        policy = OperatorActionPolicy()
        return policy.authorize(
            action, snapshot,
            target_step_id=target_step_id,
            operator_override=operator_override,
            new_budget=new_budget,
            operator_role=operator_role,
            governance_profile=resolved_profile,
            reason=reason,
            operator_identity=operator_identity,
        )

    def _resolve_profile(self, governance_profile: str | None,
                         governance_profile_file: str | None):
        """Resolve governance profile (v2.52.0). Always returns a profile,
        defaulting to team-default when no explicit profile is given."""
        from nodechain.runtime.governance_profiles import GovernanceProfileResolver
        resolver = GovernanceProfileResolver()
        return resolver.resolve(
            explicit_profile=governance_profile,
            explicit_profile_file=governance_profile_file,
        )

    # --- action: governed write boundary ----------------------------------

    def apply_action(
        self,
        run_id: str,
        action: RecoveryAction,
        *,
        operator_identity: str = "console",
        target_step_id: int | None = None,
        operator_override: bool | None = None,
        reason: str | None = None,
        instructions: str | None = None,
        new_budget: float | None = None,
        operator_role: str | None = None,
        governance_profile: str | None = None,
        governance_profile_file: str | None = None,
        side_effect_key: str | None = None,
        side_effect_decision: str | None = None,
        external_reference: str | None = None,
        response_hash: str | None = None,
        recovery_decision_id: str | None = None,  # v3.5.0
    ) -> "ActionResult":
        """Apply ONE governed operator recovery action (v2.46.0 Phase 3).

        The ONLY place an operator action mutates anything. Flow:

            1. re-read state + build snapshot (never authorize on a stale handle)
            2. emit RECOVERY_ACTION_REQUESTED  (EVERY attempt — even refused)
            3. OperatorActionPolicy.authorize
            4. on refusal      -> emit RECOVERY_ACTION_BLOCKED, bind ledger to it
               on admission    -> delegate, THEN on success emit
                                  RECOVERY_ACTION_ALLOWED and bind ledger to it;
                                  on delegation failure emit RECOVERY_ACTION_BLOCKED
                                  and bind to THAT (never to an allowed event)
            5. record the operator_action_log row (admitted + resulting_state +
               trace_event_id), and the action-specific outcome event

        Audit-truth invariants:
        - Every attempt emits REQUESTED (complete lifecycle).
        - ALLOWED is deferred until after successful delegation, so a failed
          delegation never leaves an ALLOWED event bound to an admitted=False row.
        - Terminal cancel/fail write status + outcome event in a single SQLite
          transaction (StateManager.save_with_event), no crash window.
        - export_report emits RECOVERY_REPORT_EXPORTED.

        Read commands (list/inspect/trace) never call this.
        """
        state = self.state_manager.load(run_id)
        if state is None:
            return ActionResult(admitted=False,
                                rejection_reason=f"unknown run: {run_id}")

        snapshot = self._snapshot_for_policy(run_id, state)
        # v2.53.0: convert profile resolution errors into governed denials.
        try:
            resolved_profile = self._resolve_profile(governance_profile, governance_profile_file)
        except Exception as e:
            self.state_manager.record_operator_action({
                "action_id": f"oal-{uuid.uuid4().hex[:12]}",
                "run_id": run_id,
                "action": action.value,
                "actor_identity": operator_identity,
                "requested_at": datetime.now(timezone.utc).isoformat(),
                "admitted": False,
                "rejection_reason": f"invalid governance profile: {e}",
                "target_step_id": target_step_id,
                "target_node_id": None,
                "resulting_state": state.status if state else "unknown",
                "trace_event_id": None,
                "metadata": {"reason": reason} if reason else {},
            })
            return ActionResult(
                admitted=False, rejection_reason=f"invalid governance profile: {e}",
                denial_type="governance_profile",
            )
        policy = OperatorActionPolicy()
        decision = policy.authorize(
            action, snapshot,
            target_step_id=target_step_id,
            operator_override=operator_override,
            new_budget=new_budget,
            operator_role=operator_role,
            governance_profile=resolved_profile,
            reason=reason,
            operator_identity=operator_identity,
        )
        requested_at = datetime.now(timezone.utc).isoformat()
        action_id = f"oal-{uuid.uuid4().hex[:12]}"

        # v2.52.0: extract profile metadata from decision for trace events.
        _gp_id = decision.governance_profile_id
        _gp_digest = decision.governance_profile_digest

        # Build action-specific metadata for the operator_action_log rows (#4).
        # Budget approvals carry the full audit context; other actions carry reason.
        action_metadata: dict[str, Any] = {"reason": reason} if reason else {}
        # v2.52.0: add governance profile metadata to every action log row.
        if resolved_profile is not None:
            from nodechain.runtime.governance_profiles import compute_profile_digest
            action_metadata = {
                **action_metadata,
                "governance_profile_id": resolved_profile.id,
                "governance_profile_digest": compute_profile_digest(resolved_profile),
            }
            if resolved_profile.id == "break-glass":
                action_metadata["break_glass"] = True
        if action is RecoveryAction.APPROVE_BUDGET_INCREASE and new_budget is not None:
            budget_ctx = (state.metadata or {}).get("budget_context") or {}
            action_metadata = {
                **action_metadata,
                "loop_id": budget_ctx.get("loop_id"),
                "previous_budget": budget_ctx.get("previous_budget"),
                "new_budget": new_budget,
                "accumulated_cost_at_pause": budget_ctx.get("accumulated_cost"),
                "remaining_budget_after_approval": (
                    new_budget - (budget_ctx.get("accumulated_cost") or 0.0)
                ),
            }

        # #1: EVERY attempt emits REQUESTED first — even when policy refuses.
        self._emit_operator_event(
            run_id, state.revision,
            EventType.RECOVERY_ACTION_REQUESTED, action, operator_identity,
            reason=reason, target_step_id=target_step_id,
            governance_profile_id=_gp_id, governance_profile_digest=_gp_digest,
            operator_role=operator_role,
        )

        if not decision.admitted:
            # Refused: emit BLOCKED, bind the ledger row to it, mutate nothing.
            tev_id = self._emit_operator_event(
                run_id, state.revision,
                EventType.RECOVERY_ACTION_BLOCKED, action, operator_identity,
                reason=reason, rejection=decision.rejection_reason,
                target_step_id=target_step_id,
                governance_profile_id=_gp_id, governance_profile_digest=_gp_digest,
                operator_role=operator_role,
            )
            self.state_manager.record_operator_action({
                "action_id": action_id, "run_id": run_id,
                "action": action.value, "actor_identity": operator_identity,
                "requested_at": requested_at, "admitted": False,
                "rejection_reason": decision.rejection_reason,
                "target_step_id": target_step_id, "target_node_id": None,
                "resulting_state": state.status, "trace_event_id": tev_id,
                "metadata": action_metadata,
            })
            # v3.5.0 T9: emit retry denial metrics — ONLY for
            # EXECUTE_RETRY_AUTHORIZED (do not count denials of unrelated
            # recovery actions). Overlapping counters: every denial is a
            # rejected_total; the policy-denied subset is also policy_denied.
            if (self._metrics_emitter is not None
                    and action is RecoveryAction.EXECUTE_RETRY_AUTHORIZED):
                self._metrics_emitter.failure_isolated(
                    metric_name="retry_rejected_total",
                    run_id=run_id, recovery_action_id=action_id,
                    source_event_key=f"retry:{action_id}:rejected",
                )
                self._metrics_emitter.failure_isolated(
                    metric_name="retry_policy_denied_total",
                    run_id=run_id, recovery_action_id=action_id,
                    source_event_key=f"retry:{action_id}:policy-denied",
                )
            return ActionResult(admitted=False,
                                rejection_reason=decision.rejection_reason,
                                action_id=action_id, trace_event_id=tev_id)

        # Admitted: delegate FIRST, then emit ALLOWED only on success.
        # Capture the PERSISTED status before delegation — _delegate_action may
        # mutate the in-memory ChainState (e.g. set status='cancelled') BEFORE
        # the atomic save. If that save raises, the DB still holds the
        # pre-action status, and the failure ledger row must report THAT, not
        # the in-memory terminal status that never committed.
        persisted_status = state.status
        try:
            delegation = self._delegate_action(
                action, state, run_id, target_step_id=target_step_id,
                reason=reason, instructions=instructions, new_budget=new_budget,
                side_effect_key=side_effect_key,
                side_effect_decision=side_effect_decision,
                external_reference=external_reference,
                response_hash=response_hash,
                recovery_decision_id=recovery_decision_id,
                operator_identity=operator_identity,
                operator_role=operator_role,
                operator_action_id=action_id,
            )
            resulting_state = delegation.resulting_state
        except Exception as e:
            # #2: delegation failed — emit BLOCKED (NOT allowed) and bind to it,
            # so the ledger row (admitted=False) never contradicts its bound event.
            tev_id = self._emit_operator_event(
                run_id, state.revision,
                EventType.RECOVERY_ACTION_BLOCKED, action, operator_identity,
                reason=reason, rejection=f"delegation failed: {e}",
                target_step_id=target_step_id,
                governance_profile_id=_gp_id, governance_profile_digest=_gp_digest,
                operator_role=operator_role,
            )
            self.state_manager.record_operator_action({
                "action_id": action_id, "run_id": run_id,
                "action": action.value, "actor_identity": operator_identity,
                "requested_at": requested_at, "admitted": False,
                "rejection_reason": f"delegation failed: {e}",
                "target_step_id": target_step_id, "target_node_id": None,
                # #6: report the persisted pre-action status, not the in-memory
                # terminal status that never committed.
                "resulting_state": persisted_status, "trace_event_id": tev_id,
                "metadata": action_metadata,
            })
            return ActionResult(admitted=False,
                                rejection_reason=f"delegation failed: {e}",
                                action_id=action_id, trace_event_id=tev_id)
        # T9: note — delegation failures for EXECUTE_RETRY_AUTHORIZED do not
        # emit retry_rejected_total here because the coordinator's own hooks
        # cover material/legacy/claim rejections. Delegation exceptions are
        # infrastructure failures, not governed rejections.

        # Success: NOW emit ALLOWED and bind the ledger row to it.
        tev_id = self._emit_operator_event(
            run_id, state.revision,
            EventType.RECOVERY_ACTION_ALLOWED, action, operator_identity,
            reason=reason, target_step_id=target_step_id,
            governance_profile_id=_gp_id, governance_profile_digest=_gp_digest,
            operator_role=operator_role,
        )
        self.state_manager.record_operator_action({
            "action_id": action_id, "run_id": run_id,
            "action": action.value, "actor_identity": operator_identity,
            "requested_at": requested_at, "admitted": True,
            "rejection_reason": None,
            "target_step_id": target_step_id, "target_node_id": None,
            "resulting_state": resulting_state, "trace_event_id": tev_id,
            "metadata": action_metadata,
        })
        # ChatGPT T8 re-review fix 2: use DelegationResult, not mutable state
        return ActionResult(admitted=True, resulting_state=resulting_state,
                            action_id=action_id, trace_event_id=tev_id,
                            retry_result=delegation.retry_result)

    # --- delegation -------------------------------------------------------

    def _delegate_action(
        self, action: RecoveryAction, state: ChainState, run_id: str, *,
        target_step_id: int | None, reason: str | None,
        instructions: str | None, new_budget: float | None = None,
        side_effect_key: str | None = None,
        side_effect_decision: str | None = None,
        external_reference: str | None = None,
        response_hash: str | None = None,
        recovery_decision_id: str | None = None,
        operator_identity: str = "operator",
        operator_role: str | None = None,
        operator_action_id: str | None = None,
    ) -> DelegationResult:
        """Delegate an admitted action to the existing runtime primitive.

        Terminal actions (cancel/fail) write status through StateManager.save.
        export_report is read-only. resume/retry/approve route through a
        pluggable delegate hook (wired to the Orchestrator in Phase 4) so this
        module owns no second execution loop.
        """
        if action is RecoveryAction.EXPORT_REPORT:
            # #3: read-only, but emit the report-exported outcome event so the
            # audit trail records that an operator pulled a recovery report.
            self._emit_outcome_event(
                run_id, state.revision, EventType.RECOVERY_REPORT_EXPORTED,
                run_id, reason=reason,
            )
            return DelegationResult(resulting_state=state.status)  # no transition

        if action is RecoveryAction.CANCEL_RUN:
            # H0.5 (amendment 2): candidate-before-commit — the cancelled
            # status and reason metadata are proposed on a copy; the loaded
            # accepted state stays untouched if the atomic transaction
            # fails. #5 semantics (atomic state + outcome event, no crash
            # window) are preserved unchanged.
            cand = state.transition_candidate()
            cand.status = "cancelled"
            if reason:
                cand.metadata = {**(cand.metadata or {}), "cancel_reason": reason}
            payload: dict[str, Any] = {"actor": Actor_OPERATOR}
            if reason:
                payload["reason"] = reason
            cancel_tev_id = f"tev-{uuid.uuid4().hex[:12]}"
            payload["trace_event_id"] = cancel_tev_id
            self.state_manager.save_with_event(
                cand, EventType.RUN_CANCELLED_BY_OPERATOR.value, payload,
                trace_event_id=cancel_tev_id,
            )
            # Commit succeeded — adopt the committed candidate as the live
            # authoritative state (success half of the accepted-state rule),
            # so subsequent operator events observe the committed revision.
            state.status = cand.status
            state.metadata = cand.metadata
            state.revision = cand.revision
            return DelegationResult(resulting_state=state.status)

        if action is RecoveryAction.FAIL_RUN:
            # H0.5 (amendment 2): candidate-before-commit, as CANCEL_RUN.
            cand = state.transition_candidate()
            cand.status = "failed"
            if reason:
                cand.metadata = {**(cand.metadata or {}), "fail_reason": reason}
            payload = {"actor": Actor_OPERATOR}
            if reason:
                payload["reason"] = reason
            fail_tev_id = f"tev-{uuid.uuid4().hex[:12]}"
            payload["trace_event_id"] = fail_tev_id
            self.state_manager.save_with_event(
                cand, EventType.RUN_FAILED_BY_OPERATOR.value, payload,
                trace_event_id=fail_tev_id,
            )
            # Commit succeeded — adopt the committed candidate (as CANCEL_RUN).
            state.status = cand.status
            state.metadata = cand.metadata
            state.revision = cand.revision
            return DelegationResult(resulting_state=state.status)

        if action is RecoveryAction.RESOLVE_SIDE_EFFECT:
            # v3.3.0: operator resolves an unknown side effect. This is a
            # ledger-layer operation — no orchestrator re-execution. The
            # StateManager facade validates evidence, generates a decision_id,
            # and calls the atomic store method.
            if not side_effect_key or not side_effect_decision:
                raise ValueError(
                    "RESOLVE_SIDE_EFFECT requires side_effect_key and "
                    "side_effect_decision"
                )
            resulting = self.state_manager.resolve_side_effect_recovery_decision(
                run_id=run_id,
                idempotency_key=side_effect_key,
                decision=side_effect_decision,
                reason=reason or "",
                actor="operator",
                response_hash=response_hash or "",
                external_reference=external_reference or "",
            )
            return DelegationResult(resulting_state=resulting)

        if action is RecoveryAction.EXECUTE_RETRY_AUTHORIZED:
            # v3.5.0: execute a retry-authorized side effect through the
            # SideEffectRetryCoordinator. This is a recovery-execution operation,
            # NOT an orchestrator re-execution. The coordinator owns the full
            # T6 execution protocol: allocate child → claim → boundary CAS →
            # guarded dispatch → classify outcome → terminalize → finalize.
            #
            # ChatGPT T6: the retry coordinator is injected via
            # set_retry_coordinator, NOT _action_delegate. This keeps the
            # recovery dispatch seam (INV-005) distinct from the typed-port
            # orchestrator loop.
            if not side_effect_key or not recovery_decision_id:
                raise ValueError(
                    "EXECUTE_RETRY_AUTHORIZED requires side_effect_key "
                    "(parent side-effect key) and recovery_decision_id"
                )
            if self._retry_coordinator is None:
                raise NotImplementedError(
                    "EXECUTE_RETRY_AUTHORIZED requires a retry coordinator, "
                    "which is not installed (CLI must call "
                    "set_retry_coordinator)"
                )
            retry_result = self._retry_coordinator.execute_authorized_retry(
                run_id=run_id,
                parent_side_effect_key=side_effect_key,
                recovery_decision_id=recovery_decision_id,
                actor=operator_identity if operator_identity else "operator",
                actor_role=operator_role or "operator",
                operator_action_id=operator_action_id,
            )
            # ChatGPT T8 re-review fix 2: return structured DelegationResult
            # instead of mutable instance state.
            return DelegationResult(
                resulting_state=retry_result.child_status,
                retry_result=retry_result,
            )

        # resume / retry_step / approve_review / reject_review / request_revision
        # require reconstructing the orchestrator — route through the delegate
        # installed by the CLI. Without it, refuse honestly rather than
        # silently no-op.
        if self._action_delegate is None:
            raise NotImplementedError(
                f"{action.value} requires an orchestrator delegate, which is "
                f"not installed (CLI must call set_action_delegate)"
            )
        delegate_state = self._action_delegate(
            action, run_id, target_step_id=target_step_id,
            reason=reason, instructions=instructions, new_budget=new_budget,
        )
        return DelegationResult(resulting_state=delegate_state)

    # --- operator event emission ------------------------------------------

    def _emit_operator_event(
        self, run_id: str, revision: int, event_type: EventType,
        action: RecoveryAction, operator_identity: str, *,
        reason: str | None = None, rejection: str | None = None,
        target_step_id: int | None = None,
        governance_profile_id: str | None = None,
        governance_profile_digest: str | None = None,
        operator_role: str | None = None,
    ) -> str:
        """Append an operator trace event to the durable state_events log.

        Actor is always 'operator' (the trace-truth invariant: an operator
        action is never recorded as node execution). Returns a stable id that
        the operator_action_log row binds to.
        """
        tev_id = f"tev-{uuid.uuid4().hex[:12]}"
        payload: dict[str, Any] = {
            "actor": Actor_OPERATOR, "action": action.value,
            "operator_identity": operator_identity, "trace_event_id": tev_id,
        }
        # v2.52.0: include profile metadata in trace payloads.
        if governance_profile_id:
            payload["governance_profile_id"] = governance_profile_id
        if governance_profile_digest:
            payload["governance_profile_digest"] = governance_profile_digest
        if operator_role:
            payload["operator_role"] = operator_role
        if reason:
            payload["reason"] = reason
        if rejection:
            payload["rejection_reason"] = rejection
        if target_step_id is not None:
            payload["target_step_id"] = target_step_id
        # H0.4: write through append_trace_event so the first-class
        # trace_event_id SQL column is populated, making operator trace
        # events visible in get_trace_events() — the authoritative projection.
        timestamp = datetime.now(timezone.utc).isoformat()
        self.state_manager.append_trace_event(
            run_id, revision, event_type.value,
            node_id=None, step_id=target_step_id,
            trace_event_id=tev_id, timestamp=timestamp,
            payload=payload,
        )
        return tev_id

    def _emit_outcome_event(
        self, run_id: str, revision: int, event_type: EventType,
        node_id: str, *, reason: str | None = None,
    ) -> None:
        tev_id = f"tev-{uuid.uuid4().hex[:12]}"
        payload: dict[str, Any] = {"actor": Actor_OPERATOR, "trace_event_id": tev_id}
        if reason:
            payload["reason"] = reason
        # H0.4: write through append_trace_event for first-class trace identity.
        timestamp = datetime.now(timezone.utc).isoformat()
        self.state_manager.append_trace_event(
            run_id, revision, event_type.value,
            node_id=node_id, step_id=None,
            trace_event_id=tev_id, timestamp=timestamp,
            payload=payload,
        )

    # --- snapshot-for-policy ----------------------------------------------

    def _snapshot_for_policy(self, run_id: str, state: ChainState) -> dict[str, Any]:
        """Assemble the dict the pure OperatorActionPolicy consumes.

        Re-reads side effects + recovery decisions so the carry-forward
        per-effect matching runs against current durable facts, not a cached
        snapshot.
        """
        snap = self.build_snapshot(run_id)
        side_effects = self.state_manager.get_side_effects(run_id)
        recovery_decisions = self.state_manager.get_recovery_decisions(run_id=run_id)
        md = state.metadata or {}
        last_failure = md.get("last_failure") or {}
        # Prior admitted route_fallback attempts for duplicate protection (#13).
        # Read from the operator_action_log so the bound is durable across
        # process restarts, not the in-memory FailureManager._retry_counts.
        prior_fallback_steps = [
            row["target_step_id"]
            for row in self.state_manager.get_operator_actions(
                run_id=run_id, admitted=True,
            )
            if row.get("action") == "route_fallback"
            and row.get("target_step_id") is not None
        ]
        return {
            "run_id": run_id,
            "status": state.status,
            "recovery_state": snap.recovery_state if snap else RecoveryState.CRASH_RECOVERABLE.value,
            "failed_step": snap.failed_step if snap else None,
            "pending_review": snap.pending_review if snap else None,
            "side_effects": side_effects,
            "recovery_decisions": recovery_decisions,
            "last_failure_retryable": bool(last_failure.get("retryable")),
            "last_failure_type": last_failure.get("failure_type"),
            "last_failure_node_id": last_failure.get("node_id"),
            "last_failure_error": last_failure.get("error"),
            "prior_fallback_attempts": prior_fallback_steps,
            "governed_decision_receipt": md.get("governed_decision_receipt"),
            "budget_loop_id": (md.get("budget_context") or {}).get("loop_id"),
            "budget_accumulated_cost": (md.get("budget_context") or {}).get("accumulated_cost", 0.0),
            "budget_previous": (md.get("budget_context") or {}).get("previous_budget", 0.0),
        }

    # --- snapshot helpers --------------------------------------------------

    def _load_trace(self, run_id: str) -> tuple[Any, str | None]:
        """Load the ChainTrace for a run.

        Returns ``(trace, None)`` on success, or ``(None, reason)`` if no
        usable trace could be produced — missing file, unreadable JSON, or a
        structure that fails TraceEvent/ChainTrace validation (e.g. a corrupt
        event_type enum value). The reason distinguishes "missing" from
        "corrupt" so the degraded report can say which.
        """
        from nodechain.cli.reconcile import _build_trace, _find_trace
        from nodechain.core.trace import ChainTrace

        trace_path = _find_trace(run_id, self.trace_dir)
        if trace_path is None:
            return None, "no trace file found — run may have crashed before flush"
        try:
            with open(trace_path) as f:
                trace_data = json.load(f)
            if hasattr(ChainTrace, "from_dict"):
                return ChainTrace.from_dict(trace_data), None  # type: ignore[attr-defined]
            return _build_trace(trace_data), None
        except (OSError, ValueError) as e:
            return None, f"trace file unreadable or invalid JSON: {e}"
        except Exception as e:
            # TraceEvent/ChainTrace validation failure (bad enum value,
            # invalid structure, ...). Surface as corrupt, not missing.
            return None, f"trace parse failed — invalid trace structure: {type(e).__name__}"

    @staticmethod
    def _pending_review(state: ChainState) -> dict[str, Any] | None:
        md = state.metadata or {}
        if state.status == "waiting_for_review":
            req = md.get("governed_review_request")
            if req:
                return req
        return None

    @staticmethod
    def _pending_policy_decision(state: ChainState) -> dict[str, Any] | None:
        md = state.metadata or {}
        # A governed review request whose outcome is policy approval.
        req = md.get("governed_review_request")
        if req and req.get("subject_type") == "policy":
            return req
        return None

    @staticmethod
    def _loop_counters(state: ChainState) -> dict[str, int]:
        return {name: ls.iteration for name, ls in state.loop_state.items()}

    @staticmethod
    def _retry_counters(state: ChainState, side_effects: list[dict[str, Any]]) -> dict[str, int]:
        """Per-node retry count derived from side-effect ledger attempts.

        There is no dedicated retry counter on ChainState today; the durable
        signal of a retry is a repeated side-effect attempt. We expose a
        best-effort per-node count keyed by node_id.
        """
        counts: dict[str, int] = {}
        md = state.metadata or {}
        explicit = md.get("retry_counters")
        if isinstance(explicit, dict):
            return {k: int(v) for k, v in explicit.items()}
        for se in side_effects:
            node = se.get("node_id") or ""
            if not node:
                continue
            counts[node] = counts.get(node, 0) + 1
        return counts

    @staticmethod
    def _last_successful_step(state: ChainState) -> int | None:
        if state.completed_steps:
            return max(state.completed_steps)
        return None

    @staticmethod
    def _failed_step(state: ChainState, side_effects: list[dict[str, Any]]) -> int | None:
        md = state.metadata or {}
        last_failure = md.get("last_failure") or {}
        if isinstance(last_failure, dict) and last_failure.get("step_id") is not None:
            return last_failure["step_id"]
        failed = [se.get("step_id") for se in side_effects
                  if se.get("status") == "failed" and se.get("step_id") is not None]
        if failed:
            return max(failed)
        if state.status == "failed":
            return state.step or None
        return None

    @staticmethod
    def _available_actions(state: RecoveryState, chain_state: ChainState) -> list[str]:
        """Derive the governed actions an operator may take for this state.

        Read-only report is always available. Mutation actions are gated by the
        recovery state; final authorization happens in OperatorActionPolicy
        (Phase 3), but the snapshot advertises the candidate set so the console
        can render the right controls.
        """
        actions: list[str] = []
        always = "export_report"
        terminal = {RecoveryState.COMPLETED, RecoveryState.CANCELLED}

        # Approve/reject/revise are only meaningful when genuinely paused for review.
        if state is RecoveryState.PAUSED_FOR_HUMAN_REVIEW:
            actions.extend(["approve_review", "reject_review", "request_revision"])

        # Resume is meaningful for recoverable pauses.
        if state in {
            RecoveryState.CRASH_RECOVERABLE,
            RecoveryState.PAUSED_FOR_POLICY_APPROVAL,
        }:
            actions.append("resume")

        # Retry is meaningful for retryable failures.
        if state is RecoveryState.FAILED_RETRYABLE:
            actions.append("retry_step")

        # Operator may always end a non-terminal run.
        if state not in terminal:
            actions.extend(["cancel_run", "fail_run"])

        actions.append(always)
        # Preserve a stable, deduplicated order.
        seen: set[str] = set()
        ordered: list[str] = []
        for a in actions:
            if a not in seen:
                seen.add(a)
                ordered.append(a)
        return ordered


# Actor.OPERATOR spelled as a string for the trace-event payload (kept in sync
# with core.trace.Actor.OPERATOR by test_operator_trace_events).
Actor_OPERATOR = "operator"


@dataclass(frozen=True)
class ActionResult:
    """Outcome of one operator recovery action."""

    admitted: bool
    rejection_reason: str | None = None
    resulting_state: str | None = None
    action_id: str | None = None
    trace_event_id: str | None = None
    denial_type: str | None = None
    # v3.5.0 T8: full retry execution result for three-truth rendering (INV-009)
    retry_result: Any = None
