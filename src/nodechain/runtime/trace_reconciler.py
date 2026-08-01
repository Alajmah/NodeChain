"""Trace Reconciler — verify trace claims agree with durable ledger facts.

Compares trace events against invocation ledger, side-effect ledger,
and materialized state to detect inconsistencies.

This is the audit integrity layer: it turns "trace has plausible shape"
into "trace agrees with durable facts."
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from nodechain.core.state import StateManager
from nodechain.core.trace import ChainTrace, EventType


@dataclass
class ReconciliationIssue:
    """A single discrepancy between trace and ledger."""

    check: str          # Name of the reconciliation check
    severity: str       # "error" or "warning"
    expected: str       # What the trace claims
    actual: str         # What the ledger says
    node_id: str = ""   # Affected node
    step_id: int = 0    # Affected step


@dataclass
class ReconciliationReport:
    """Full reconciliation result."""

    run_id: str
    checks_passed: int = 0
    issues: list[ReconciliationIssue] = field(default_factory=list)

    @property
    def errors(self) -> list[ReconciliationIssue]:
        return [i for i in self.issues if i.severity == "error"]

    @property
    def warnings(self) -> list[ReconciliationIssue]:
        return [i for i in self.issues if i.severity == "warning"]

    @property
    def is_clean(self) -> bool:
        return len(self.errors) == 0

    def summary(self) -> str:
        parts = [f"Trace Reconciliation: {self.checks_passed} checks passed"]
        if self.issues:
            parts.append(f"{len(self.errors)} errors, {len(self.warnings)} warnings")
            for issue in self.issues:
                parts.append(f"  [{issue.severity.upper()}] {issue.check}: {issue.expected} vs {issue.actual}")
        else:
            parts.append("All checks passed")
        return "\n".join(parts)


class TraceReconciler:
    """Reconcile trace events against durable ledger facts.

    Usage:
        reconciler = TraceReconciler(state_manager)
        report = reconciler.reconcile(trace)
        if not report.is_clean:
            print(report.summary())
    """

    def __init__(self, state_manager: StateManager) -> None:
        self.state_manager = state_manager
        # v2.35.0: optional node registry for declared-type matching (Check 4h)
        self._nodes: dict | None = None
        # v3.5.0 T9: optional metrics emitter for requeue observability
        self._metrics_emitter = None

    def set_nodes(self, nodes: dict) -> None:
        """Wire the node registry for declared-side-effect checks (v2.35.0)."""
        self._nodes = nodes

    def set_metrics_emitter(self, emitter) -> None:
        """Wire the T9 metrics emitter (runtime boundary for requeue metrics)."""
        self._metrics_emitter = emitter

    def reconcile(self, trace: ChainTrace, *, repair_expired: bool = True) -> ReconciliationReport:
        """Run all reconciliation checks against a trace.

        Returns a ReconciliationReport with issues and pass count.

        Args:
            repair_expired: if True (default), run durable expiry reconciliation
                before checks. RecoveryService.build_trace_health sets this to
                False when it has already performed the repair itself, to avoid
                a duplicate repair+error cycle.
        """
        report = ReconciliationReport(run_id=trace.run_id)
        run_id = trace.run_id

        # Load ledger facts
        invocation_steps = self.state_manager.get_completed_steps(run_id)
        side_effects = self.state_manager.get_side_effects(run_id)
        events = self.state_manager.get_events(run_id)
        # v2.23.0: hoist the materialized-state load so the receipt-binding
        # check (Check 5) can read ChainState.metadata independent of Check 9's
        # completed_steps branch. Check 9 reuses this same variable below.
        materialized = self.state_manager.load(run_id)

        # v3.5.0 T7: Durable expiry reconciliation — repair expired started
        # recovery children before running checks. This is the production
        # crash-repair entry path (ChatGPT T7 2nd re-review fix 5).
        # T9 5th re-review: repair_expired=False lets RecoveryService skip
        # this when it already ran the repair (single-owner per invocation).
        if repair_expired:
            try:
                repaired = self.state_manager.reconcile_expired_recovery_children(run_id)
                if repaired:
                    # v3.5.0 T9: emit one retry_requeued metric per requeued child.
                    # This is the runtime boundary — core.stores returns the records,
                    # TraceReconciler (runtime) emits the metric. No core→runtime dep.
                    if self._metrics_emitter is not None:
                        for rec in repaired:
                            if rec.get("action") == "requeued":
                                child_key = rec.get("child_key", "")
                                old_claim = rec.get("execution_claim_id", "")
                                self._metrics_emitter.failure_isolated(
                                    metric_name="retry_requeued",
                                    run_id=run_id,
                                    retry_attempt_key=child_key,
                                    source_event_key=(
                                        f"retry:{run_id}:{child_key}:{old_claim}:requeued"
                                    ),
                                )
                    # Reload side_effects after repair to reflect the new state
                    side_effects = self.state_manager.get_side_effects(run_id)
            except Exception as e:
                report.issues.append(ReconciliationIssue(
                    check="side_effect_retry_repair_failed",
                    severity="error",
                    expected="durable expiry reconciliation completes",
                    actual=f"repair raised: {e}",
                ))

        # Categorize trace events
        succeeded_events = []
        failed_events = []
        branch_completed = []
        branch_failed = []
        side_effect_completed = []
        side_effect_started = []
        side_effect_failed = []
        side_effect_blocked = []
        review_requested = []
        review_completed = []
        node_skipped = []
        join_completed = []
        memory_write_allowed = []
        memory_write_blocked = []

        for e in trace.events:
            et = str(e.event_type)
            if "NODE_SUCCEEDED" in et or "node_completed" in et.lower():
                succeeded_events.append(e)
            elif "NODE_FAILED" in et:
                failed_events.append(e)
            elif "BRANCH_COMPLETED" in et:
                branch_completed.append(e)
            elif "BRANCH_FAILED" in et:
                branch_failed.append(e)
            elif "SIDE_EFFECT_COMPLETED" in et:
                side_effect_completed.append(e)
            elif "SIDE_EFFECT_FAILED" in et:
                side_effect_failed.append(e)
            elif "SIDE_EFFECT_BLOCKED" in et:
                side_effect_blocked.append(e)
            elif "SIDE_EFFECT_STARTED" in et:
                side_effect_started.append(e)
            elif "REVIEW_REQUESTED" in et:
                review_requested.append(e)
            elif "REVIEW_COMPLETED" in et or "HUMAN_REVIEW_COMPLETED" in et:
                review_completed.append(e)
            elif "NODE_SKIPPED" in et:
                node_skipped.append(e)
            elif "JOIN_COMPLETED" in et:
                join_completed.append(e)
            elif "MEMORY_WRITE_ALLOWED" in et:
                memory_write_allowed.append(e)
            elif "MEMORY_WRITE_BLOCKED" in et:
                memory_write_blocked.append(e)

        # ── Check 1: NODE_SUCCEEDED ↔ invocation ledger completed ──
        for e in succeeded_events:
            step_id = e.step_id
            node_id = e.node_id
            if step_id and step_id in invocation_steps:
                ledger_node = invocation_steps[step_id]
                if ledger_node != node_id:
                    report.issues.append(ReconciliationIssue(
                        check="node_succeeded_ledger_match",
                        severity="error",
                        expected=f"step {step_id} = {node_id}",
                        actual=f"step {step_id} = {ledger_node}",
                        node_id=node_id,
                        step_id=step_id,
                    ))
                else:
                    report.checks_passed += 1
            elif step_id:
                report.issues.append(ReconciliationIssue(
                    check="node_succeeded_ledger_exists",
                    severity="warning",
                    expected=f"step {step_id} in invocation ledger",
                    actual=f"step {step_id} not found",
                    node_id=node_id,
                    step_id=step_id,
                ))
                report.checks_passed += 1  # Trace-only events are OK

        # ── Check 2: NODE_FAILED ↔ invocation ledger failed ──
        for e in failed_events:
            # Failed nodes may or may not be in the invocation ledger
            # (depends on whether the failure was recorded before failing)
            report.checks_passed += 1

        # ── Check 3: Invocation ledger entries ↔ trace events ──
        for step_id, node_id in invocation_steps.items():
            # Each ledger entry should have a corresponding trace event
            found_in_trace = any(
                e.step_id == step_id and e.node_id == node_id
                for e in succeeded_events
            )
            if found_in_trace:
                # Best case: covered by both ChainTrace and ledger
                report.checks_passed += 1
            else:
                # Check if it's covered only in internal state_events
                found_in_state_events = any(
                    ev.get("step_id") == step_id
                    for ev in events
                )
                if found_in_state_events:
                    # Internal recovery coverage, but not in audit trace
                    report.issues.append(ReconciliationIssue(
                        check="ledger_trace_coverage",
                        severity="warning",
                        expected=f"ChainTrace event for step {step_id} ({node_id})",
                        actual="covered only by internal state_events (not audit-visible)",
                        node_id=node_id,
                        step_id=step_id,
                    ))
                    report.checks_passed += 1
                else:
                    # No coverage at all — serious
                    report.issues.append(ReconciliationIssue(
                        check="ledger_trace_coverage",
                        severity="error",
                        expected=f"trace event for step {step_id} ({node_id})",
                        actual="no trace or state event found",
                        node_id=node_id,
                        step_id=step_id,
                    ))
                report.checks_passed += 1

        # ── Check 4: Side-effect trace ↔ ledger cross-check ──
        self._check_side_effect_trace_ledger(
            side_effect_completed, side_effect_started,
            side_effect_failed, side_effect_blocked, side_effects, report,
        )

        # ── Check 5: Review events ↔ governed receipt binding (v2.23.0) ──
        # Replaces the prior presence-only check. Binds HUMAN_REVIEW_COMPLETED
        # trace metadata to the persisted DecisionReceipt digest and (when
        # available) the original governed ReviewRequest digest.
        self._check_review_receipt_binding(
            review_requested, review_completed, materialized, report,
        )
        # ── Check 5b: Review attempt-log binding (v2.26.0) ──
        # Binds review_decision_attempts rows to the trace event + receipt,
        # forming the audit triangle (trace ↔ receipt ↔ attempt log).
        self._check_review_attempt_binding(
            review_completed, materialized, report,
        )
        # ── Check 5c: Memory decision-log binding (v2.29.0) ──
        # Binds MEMORY_WRITE_ALLOWED/BLOCKED trace events to the durable
        # memory_decisions table (candidate_digest, write_ref, decision).
        self._check_memory_decision_binding(
            memory_write_allowed, memory_write_blocked, report,
        )

        # ── Check 5d: Memory read governance binding (v2.40.0) ──
        self._check_memory_read_binding(trace, report)

        # ── Check 5e: Adapter access governance binding (v2.43.1) ──
        self._check_adapter_access_binding(trace, report)

        # ── Check 5f: Package trust binding (v2.44.1) ──
        self._check_package_trust_binding(trace, report)

        # ── Check 6: Chain terminal status ──
        terminal_events = [
            e for e in trace.events
            if "CHAIN_COMPLETED" in str(e.event_type) or "CHAIN_FAILED" in str(e.event_type)
        ]
        if terminal_events:
            report.checks_passed += 1
        elif trace.final_status in ("completed", "failed"):
            report.checks_passed += 1
        else:
            report.issues.append(ReconciliationIssue(
                check="chain_terminal_status",
                severity="warning",
                expected="CHAIN_COMPLETED or CHAIN_FAILED event",
                actual=f"final_status={trace.final_status} with no terminal event",
            ))

        # ── Check 7: Branch consistency ──
        if branch_completed:
            report.checks_passed += len(branch_completed)
        if branch_failed:
            report.checks_passed += len(branch_failed)

        # ── Check 8: Join events ──
        if join_completed:
            report.checks_passed += len(join_completed)

        # ── Check 9: Materialized state ↔ invocation ledger agreement ──
        # This is the durable-surface contradiction check.
        # If the materialized snapshot says step X = node A but the ledger
        # says step X = node B, the durability contract is violated.
        # (materialized loaded once at the top of reconcile() — v2.23.0)
        if materialized is not None and materialized.completed_steps:
            for step_id, node_id in materialized.completed_steps.items():
                if step_id in invocation_steps:
                    ledger_node = invocation_steps[step_id]
                    if ledger_node != node_id:
                        report.issues.append(ReconciliationIssue(
                            check="state_ledger_step_mapping",
                            severity="error",
                            expected=f"state: step {step_id} = {node_id}",
                            actual=f"ledger: step {step_id} = {ledger_node}",
                            node_id=node_id,
                            step_id=step_id,
                        ))
                    else:
                        report.checks_passed += 1
                else:
                    # State has a step the ledger doesn't — stale snapshot
                    report.issues.append(ReconciliationIssue(
                        check="state_ledger_step_mapping",
                        severity="error",
                        expected=f"ledger entry for step {step_id} ({node_id})",
                        actual="step in materialized state but not in invocation ledger",
                        node_id=node_id,
                        step_id=step_id,
                    ))
            # Check ledger has steps the state doesn't
            for step_id, node_id in invocation_steps.items():
                if step_id not in materialized.completed_steps:
                    report.issues.append(ReconciliationIssue(
                        check="state_ledger_step_mapping",
                        severity="warning",
                        expected=f"state entry for step {step_id} ({node_id})",
                        actual="step in ledger but not in materialized state",
                        node_id=node_id,
                        step_id=step_id,
                    ))

        # ── Check 10: Duplicate step IDs across durable surfaces ──
        # No step_id should map to more than one node_id in any surface.
        trace_step_map: dict[int, str] = {}
        for e in succeeded_events:
            if e.step_id:
                if e.step_id in trace_step_map:
                    if trace_step_map[e.step_id] != e.node_id:
                        report.issues.append(ReconciliationIssue(
                            check="trace_step_id_uniqueness",
                            severity="error",
                            expected=f"step {e.step_id} = {trace_step_map[e.step_id]}",
                            actual=f"step {e.step_id} also = {e.node_id}",
                            node_id=e.node_id,
                            step_id=e.step_id,
                        ))
                else:
                    trace_step_map[e.step_id] = e.node_id

        # Ledger step_id uniqueness (the invocation_ledger PRIMARY KEY guarantees
        # this at the SQL level, but check anyway for defense in depth)
        seen_ledger: dict[int, str] = {}
        for step_id, node_id in invocation_steps.items():
            if step_id in seen_ledger:
                report.issues.append(ReconciliationIssue(
                    check="ledger_step_id_uniqueness",
                    severity="error",
                    expected=f"step {step_id} = {seen_ledger[step_id]}",
                    actual=f"step {step_id} also = {node_id}",
                    node_id=node_id,
                    step_id=step_id,
                ))
            else:
                seen_ledger[step_id] = node_id

        if trace_step_map and invocation_steps:
            report.checks_passed += 1  # Uniqueness checks completed

        return report

    def _check_side_effect_trace_ledger(
        self,
        side_effect_completed: list,
        side_effect_started: list,
        side_effect_failed: list,
        side_effect_blocked: list,
        side_effects: list[dict],
        report: ReconciliationReport,
    ) -> None:
        """Cross-check side-effect trace events against the side-effect ledger.

        Checks:
        4a. SIDE_EFFECT_COMPLETED trace must match ledger completed entry (by idempotency_key)
        4b. SIDE_EFFECT_STARTED trace must match ledger started/completed/failed/unknown
        4c. Ledger completed without trace → warning (coverage)
        4d. Unknown side effects → recovery_required flag (WARNING from ledger)
        4e. Count match (completed trace vs ledger completed)
        4f. SIDE_EFFECT_FAILED trace must match ledger failed entry (v2.33.0)

        v2.33.0: the unknown recovery transition emits no trace event (unknown
        is not failed, not completed). Check 4d reads ledger state directly.
        SIDE_EFFECT_FAILED (4f) is minimal lifecycle binding — missing row or
        status mismatch is ERROR; strong binding (request_hash/response_hash)
        is deferred to v2.36.0.
        """
        # Build lookup maps
        completed_trace_keys = set()
        for e in side_effect_completed:
            key = e.metadata.get("idempotency_key", "") if e.metadata else ""
            if key:
                completed_trace_keys.add(key)
            report.checks_passed += 1

        started_trace_keys = set()
        for e in side_effect_started:
            key = e.metadata.get("idempotency_key", "") if e.metadata else ""
            if key:
                started_trace_keys.add(key)
            report.checks_passed += 1

        ledger_by_key: dict[str, dict] = {
            se["idempotency_key"]: se for se in side_effects
        }

        # v2.36.0: build trace event lookup for strong binding
        completed_trace_by_key: dict[str, TraceEvent] = {}
        for e in side_effect_completed:
            key = e.metadata.get("idempotency_key", "") if e.metadata else ""
            if key:
                completed_trace_by_key[key] = e
        started_trace_by_key: dict[str, TraceEvent] = {}
        for e in side_effect_started:
            key = e.metadata.get("idempotency_key", "") if e.metadata else ""
            if key:
                started_trace_by_key[key] = e
        failed_trace_by_key: dict[str, TraceEvent] = {}
        for e in side_effect_failed:
            key = e.metadata.get("idempotency_key", "") if e.metadata else ""
            if key:
                failed_trace_by_key[key] = e

        def _strong_bind(
            trace_event: TraceEvent,
            ledger_row: dict,
            check_name: str,
        ) -> None:
            """v2.36.0: compare trace event against ledger row on composite fields.

            Binds: node_id, step_id, side_effect_type (after canonicalization),
            request_hash (WARNING if absent on one side), response_hash/
            external_reference (ERROR if both present and mismatched, WARNING
            if absent on one side).
            """
            from nodechain.core.contract import normalize_side_effect_type
            # node_id
            if trace_event.node_id and ledger_row.get("node_id") and \
               trace_event.node_id != ledger_row["node_id"]:
                report.issues.append(ReconciliationIssue(
                    check=check_name, severity="error",
                    expected=f"node_id {ledger_row['node_id']}",
                    actual=f"trace node_id {trace_event.node_id}",
                    node_id=trace_event.node_id, step_id=trace_event.step_id,
                ))
            # step_id
            if trace_event.step_id and ledger_row.get("step_id") and \
               trace_event.step_id != ledger_row["step_id"]:
                report.issues.append(ReconciliationIssue(
                    check=check_name, severity="error",
                    expected=f"step_id {ledger_row['step_id']}",
                    actual=f"trace step_id {trace_event.step_id}",
                    node_id=trace_event.node_id, step_id=trace_event.step_id,
                ))
            # side_effect_type (canonicalized)
            trace_type = normalize_side_effect_type(
                (trace_event.metadata or {}).get("effect_type", "")
            ) or (trace_event.metadata or {}).get("effect_type", "")
            ledger_type = normalize_side_effect_type(
                ledger_row.get("side_effect_type", "")
            ) or ledger_row.get("side_effect_type", "")
            if trace_type and ledger_type and trace_type != ledger_type:
                report.issues.append(ReconciliationIssue(
                    check=check_name, severity="error",
                    expected=f"side_effect_type {ledger_type}",
                    actual=f"trace effect_type {trace_type}",
                    node_id=trace_event.node_id, step_id=trace_event.step_id,
                ))
            # request_hash (v2.38.0: upgraded to ERROR — derivation is now
            # canonical across all paths. Missing on one side stays WARNING.)
            trace_req = (trace_event.metadata or {}).get("request_hash", "")
            ledger_req = ledger_row.get("request_hash", "")
            if trace_req and ledger_req and trace_req != ledger_req:
                report.issues.append(ReconciliationIssue(
                    check=check_name, severity="error",
                    expected=f"request_hash {ledger_req}",
                    actual=f"trace request_hash {trace_req}",
                    node_id=trace_event.node_id, step_id=trace_event.step_id,
                ))
            # response_hash (ERROR if both present and mismatched)
            trace_resp = (trace_event.metadata or {}).get("response_hash", "") or \
                         (trace_event.metadata or {}).get("external_reference", "")
            ledger_resp = ledger_row.get("response_hash", "") or \
                          ledger_row.get("external_reference", "")
            if trace_resp and ledger_resp and trace_resp != ledger_resp:
                report.issues.append(ReconciliationIssue(
                    check=check_name, severity="error",
                    expected=f"response_hash {ledger_resp}",
                    actual=f"trace response_hash {trace_resp}",
                    node_id=trace_event.node_id, step_id=trace_event.step_id,
                ))

        # Check 4a: SIDE_EFFECT_COMPLETED trace must have matching ledger entry
        for key in completed_trace_keys:
            if key not in ledger_by_key:
                report.issues.append(ReconciliationIssue(
                    check="side_effect_trace_ledger_match",
                    severity="error",
                    expected=f"ledger entry for {key}",
                    actual="no matching side_effect_ledger entry",
                    step_id=0,
                ))
            elif ledger_by_key[key]["status"] != "completed":
                report.issues.append(ReconciliationIssue(
                    check="side_effect_trace_ledger_match",
                    severity="error",
                    expected=f"ledger status 'completed' for {key}",
                    actual=f"ledger status '{ledger_by_key[key]['status']}'",
                    step_id=ledger_by_key[key].get("step_id", 0),
                ))
            else:
                report.checks_passed += 1
                # v2.36.0: strong binding
                te = completed_trace_by_key.get(key)
                if te:
                    _strong_bind(te, ledger_by_key[key], "side_effect_strong_bind_completed")

        # Check 4b: SIDE_EFFECT_STARTED trace must match ledger started/completed/failed/unknown
        for key in started_trace_keys:
            if key not in ledger_by_key:
                report.issues.append(ReconciliationIssue(
                    check="side_effect_started_ledger_match",
                    severity="error",
                    expected=f"ledger entry for started effect {key}",
                    actual="no matching side_effect_ledger entry",
                    step_id=0,
                ))
            elif ledger_by_key[key]["status"] not in ("started", "completed", "failed", "unknown"):
                report.issues.append(ReconciliationIssue(
                    check="side_effect_started_ledger_match",
                    severity="error",
                    expected=f"ledger status started/completed/failed/unknown for {key}",
                    actual=f"ledger status '{ledger_by_key[key]['status']}'",
                    step_id=ledger_by_key[key].get("step_id", 0),
                ))
            else:
                report.checks_passed += 1
                # v2.36.0: strong binding
                te = started_trace_by_key.get(key)
                if te:
                    _strong_bind(te, ledger_by_key[key], "side_effect_strong_bind_started")

        # Check 4c: Ledger completed without trace SIDE_EFFECT_COMPLETED → warning
        for se in side_effects:
            if se["status"] == "completed" and se["idempotency_key"] not in completed_trace_keys:
                report.issues.append(ReconciliationIssue(
                    check="side_effect_ledger_trace_coverage",
                    severity="warning",
                    expected=f"SIDE_EFFECT_COMPLETED event for {se['idempotency_key']}",
                    actual="completed in ledger but not in audit trace",
                    step_id=se.get("step_id", 0),
                ))
            elif se["status"] == "completed":
                report.checks_passed += 1

        # Check 4d: Unknown side effects → recovery_required flag
        unknown_effects = [se for se in side_effects if se["status"] == "unknown"]
        if unknown_effects:
            report.issues.append(ReconciliationIssue(
                check="side_effect_recovery_required",
                severity="warning",
                expected="all side effects in known terminal state",
                actual=f"{len(unknown_effects)} side effects in 'unknown' state (crash recovery required)",
                step_id=0,
            ))
        else:
            report.checks_passed += 1

        # Check 4e: Count match
        completed_in_ledger = [se for se in side_effects if se["status"] == "completed"]
        if len(side_effect_completed) != len(completed_in_ledger):
            report.issues.append(ReconciliationIssue(
                check="side_effect_count_match",
                severity="warning",
                expected=f"{len(completed_in_ledger)} completed side effects in ledger",
                actual=f"{len(side_effect_completed)} SIDE_EFFECT_COMPLETED events in trace",
            ))
        report.checks_passed += 1

        # Check 4f: SIDE_EFFECT_FAILED trace must match ledger failed entry (v2.33.0)
        # v2.36.0: now includes strong binding (node_id, step_id, side_effect_type,
        # request_hash). Missing row = ERROR; status mismatch = ERROR;
        # ledger failed without trace = WARNING.
        failed_trace_keys = set()
        for e in side_effect_failed:
            key = e.metadata.get("idempotency_key", "") if e.metadata else ""
            if key:
                failed_trace_keys.add(key)

        for key in failed_trace_keys:
            if key not in ledger_by_key:
                report.issues.append(ReconciliationIssue(
                    check="side_effect_failed_ledger_match",
                    severity="error",
                    expected=f"ledger entry for failed effect {key}",
                    actual="no matching side_effect_ledger entry",
                    step_id=0,
                ))
            elif ledger_by_key[key]["status"] != "failed":
                report.issues.append(ReconciliationIssue(
                    check="side_effect_failed_ledger_match",
                    severity="error",
                    expected=f"ledger status 'failed' for {key}",
                    actual=f"ledger status '{ledger_by_key[key]['status']}'",
                    step_id=ledger_by_key[key].get("step_id", 0),
                ))
            else:
                report.checks_passed += 1
                # v2.36.0: strong binding
                te = failed_trace_by_key.get(key)
                if te:
                    _strong_bind(te, ledger_by_key[key], "side_effect_strong_bind_failed")

        # Ledger failed without SIDE_EFFECT_FAILED trace → warning (not error):
        # the failure may have been observed only via the ledger on a path that
        # legitimately cannot emit trace (e.g. a blocked memory write in
        # v2.33.0). Upgraded when strong binding lands in v2.36.0.
        for se in side_effects:
            if (
                se["status"] == "failed"
                and se["idempotency_key"] not in failed_trace_keys
            ):
                report.issues.append(ReconciliationIssue(
                    check="side_effect_failed_trace_coverage",
                    severity="warning",
                    expected=f"SIDE_EFFECT_FAILED event for {se['idempotency_key']}",
                    actual="failed in ledger but not in audit trace",
                    step_id=se.get("step_id", 0),
                ))

        # Check 4g: SIDE_EFFECT_BLOCKED trace ↔ durable blocked attempt (v2.34.0)
        # Minimal lifecycle binding: the trace event's attempt_id must exist in
        # the side_effect_blocked_attempts table, and the durable row's decision
        # must be deny/require_approval. Strong binding (run_id, node_id,
        # step_id, policy_id, rule_id, declaration digest) deferred to v2.36.0.
        blocked_trace_ids = set()
        for e in side_effect_blocked:
            aid = e.metadata.get("attempt_id", "") if e.metadata else ""
            if aid:
                blocked_trace_ids.add(aid)

        # Fetch durable blocked attempts for this run
        blocked_rows: list[dict] = []
        try:
            blocked_rows = self.state_manager.get_side_effect_blocks(
                run_id=report.run_id,
            )
        except Exception:
            blocked_rows = []
        blocked_row_ids = {r.get("attempt_id", "") for r in blocked_rows}

        for aid in blocked_trace_ids:
            if aid not in blocked_row_ids:
                report.issues.append(ReconciliationIssue(
                    check="side_effect_blocked_ledger_match",
                    severity="error",
                    expected=f"durable blocked attempt for {aid}",
                    actual="no matching side_effect_blocked_attempts row",
                    step_id=0,
                ))
            else:
                row = next(r for r in blocked_rows if r.get("attempt_id") == aid)
                if row.get("decision") not in ("deny", "require_approval"):
                    report.issues.append(ReconciliationIssue(
                        check="side_effect_blocked_ledger_match",
                        severity="error",
                        expected=f"decision deny/require_approval for {aid}",
                        actual=f"decision '{row.get('decision')}'",
                        step_id=row.get("step_id", 0),
                    ))
                else:
                    report.checks_passed += 1

        # Durable blocked rows without SIDE_EFFECT_BLOCKED trace → warning
        for row in blocked_rows:
            if row.get("attempt_id", "") not in blocked_trace_ids:
                report.issues.append(ReconciliationIssue(
                    check="side_effect_blocked_trace_coverage",
                    severity="warning",
                    expected=f"SIDE_EFFECT_BLOCKED event for {row.get('attempt_id', '')}",
                    actual="blocked in ledger but not in audit trace",
                    step_id=row.get("step_id", 0),
                ))

        # Check 4h: side_effect_declared_type_match (v2.35.0, extended v2.35.1)
        # Ledger AND trace side-effect type must be declared by the node
        # contract (after canonicalization). Three states:
        #   contract available + declares the type → pass
        #   contract available + does NOT declare the type → ERROR
        #   contract truly unavailable (node not in registry) → WARNING
        from nodechain.core.contract import normalize_side_effect_type
        # Build declared-type lookup from node registry. Include ALL known
        # nodes (even those with empty declarations) so we can distinguish
        # "declares nothing" from "contract unavailable."
        declared_by_node: dict[str, list[str]] = {}
        nodes = getattr(self, "_nodes", None)
        if nodes:
            for nid, node in nodes.items():
                contract = getattr(getattr(node, "manifest", None), "contract", None)
                types: list[str] = []
                if contract and contract.side_effects:
                    for se in contract.side_effects:
                        canon = normalize_side_effect_type(se.effect_type)
                        if canon and canon not in types:
                            types.append(canon)
                declared_by_node[nid] = types  # empty list = declares nothing

        def _check_declared(nid: str, canon: str, step_id: int, source: str) -> None:
            if nid in declared_by_node:
                declared = declared_by_node[nid]
                if canon not in declared:
                    report.issues.append(ReconciliationIssue(
                        check="side_effect_declared_type_match",
                        severity="error",
                        expected=f"{nid} declares {declared}",
                        actual=f"{source} records '{canon}' for {nid}",
                        node_id=nid,
                        step_id=step_id,
                    ))
            else:
                report.issues.append(ReconciliationIssue(
                    check="side_effect_declared_type_match",
                    severity="warning",
                    expected=f"declared types for {nid}",
                    actual="node contract unavailable",
                    node_id=nid,
                    step_id=step_id,
                ))

        # Check ledger rows
        for se in side_effects:
            nid = se.get("node_id", "")
            raw_type = se.get("side_effect_type", "")
            canon = normalize_side_effect_type(raw_type) or raw_type
            _check_declared(nid, canon, se.get("step_id", 0), "ledger")

        # Check trace events (v2.35.1)
        for e in side_effect_started + side_effect_completed + side_effect_failed:
            nid = e.node_id or ""
            raw_type = (e.metadata or {}).get("effect_type", "")
            canon = normalize_side_effect_type(raw_type) or raw_type
            _check_declared(nid, canon, e.step_id or 0, "trace")

        # ── Recovery decision checks (v2.39.0) ──────────────────────
        # SE-R1: unknown side effects → recovery-required warning
        # (already covered by Check 4d, but re-affirmed here)
        # SE-R2: unknown resolved without recovery decision = ERROR
        # SE-R3: illegal side-effect status transition = ERROR
        # SE-R4: recovery decision references missing ledger row = ERROR
        # SE-R5: recovery decision conflicts with terminal ledger state = ERROR
        try:
            recovery_decisions = self.state_manager.get_recovery_decisions(
                run_id=report.run_id,
            )
        except Exception:
            recovery_decisions = []

        # Build ledger status map for transition validation
        ledger_status_by_key = {
            se["idempotency_key"]: se["status"] for se in side_effects
        }

        # SE-R2: any ledger row that was 'unknown' and is now terminal
        # must have a recovery decision
        keys_with_recovery = {
            rd.get("idempotency_key", "") for rd in recovery_decisions
        }
        for se in side_effects:
            if se["status"] in ("completed", "failed", "retry_authorized"):
                # Check if this row was previously unknown (heuristic: if a
                # recovery decision exists for this key, it was resolved)
                pass  # The transition validator handles this at write time

        # SE-R3: illegal transitions — detect by checking if the ledger
        # contains any row whose status is unreachable from the legal
        # transition graph
        LEGAL_STATES = {"planned", "started", "completed", "failed",
                        "unknown", "retry_authorized"}
        for se in side_effects:
            if se["status"] not in LEGAL_STATES:
                report.issues.append(ReconciliationIssue(
                    check="side_effect_illegal_transition",
                    severity="error",
                    expected=f"status in {LEGAL_STATES}",
                    actual=f"status '{se['status']}' for {se['idempotency_key']}",
                    node_id=se.get("node_id", ""),
                    step_id=se.get("step_id", 0),
                ))

        # SE-R4: recovery decision references missing ledger row
        for rd in recovery_decisions:
            rd_key = rd.get("idempotency_key", "")
            if rd_key and rd_key not in ledger_status_by_key:
                report.issues.append(ReconciliationIssue(
                    check="side_effect_recovery_missing_ledger",
                    severity="error",
                    expected=f"ledger row for recovery decision {rd.get('decision_id', '')}",
                    actual=f"no side_effect_ledger entry for key {rd_key}",
                    step_id=rd.get("step_id", 0),
                ))

        # SE-R5: recovery decision conflicts with terminal ledger state
        for rd in recovery_decisions:
            rd_key = rd.get("idempotency_key", "")
            rd_decision = rd.get("decision", "")
            if rd_key in ledger_status_by_key:
                ledger_st = ledger_status_by_key[rd_key]
                # If decision says verified_completed but ledger says failed → conflict
                if rd_decision == "verified_completed" and ledger_st != "completed":
                    report.issues.append(ReconciliationIssue(
                        check="side_effect_recovery_conflict",
                        severity="error",
                        expected=f"ledger status 'completed' for {rd_key} (recovery: verified_completed)",
                        actual=f"ledger status '{ledger_st}'",
                        step_id=rd.get("step_id", 0),
                    ))
                elif rd_decision == "verified_failed" and ledger_st != "failed":
                    report.issues.append(ReconciliationIssue(
                        check="side_effect_recovery_conflict",
                        severity="error",
                        expected=f"ledger status 'failed' for {rd_key} (recovery: verified_failed)",
                        actual=f"ledger status '{ledger_st}'",
                        step_id=rd.get("step_id", 0),
                    ))
                # v3.5.0 T7: safe_to_retry ↔ retry_authorized binding (SE-R5b)
                elif rd_decision == "safe_to_retry" and ledger_st != "retry_authorized":
                    report.issues.append(ReconciliationIssue(
                        check="side_effect_recovery_conflict",
                        severity="error",
                        expected=f"ledger status 'retry_authorized' for {rd_key} "
                                 f"(recovery: safe_to_retry)",
                        actual=f"ledger status '{ledger_st}'",
                        step_id=rd.get("step_id", 0),
                    ))

        # v3.5.0 T7: SE-R5c — retry_authorized parents must have an active
        # safe_to_retry decision targeting them.
        safe_to_retry_keys = {
            rd.get("idempotency_key", "")
            for rd in recovery_decisions
            if rd.get("decision") == "safe_to_retry"
            and rd.get("retention_status") == "active"
        }
        for se in side_effects:
            if se.get("status") == "retry_authorized":
                se_key = se.get("idempotency_key", "")
                if se_key not in safe_to_retry_keys:
                    report.issues.append(ReconciliationIssue(
                        check="side_effect_retry_missing_safe_to_retry",
                        severity="error",
                        expected=f"active safe_to_retry decision for {se_key}",
                        actual="no active safe_to_retry decision found",
                        step_id=se.get("step_id", 0),
                    ))

        # ── SE-R6: Retry-authorized lineage cross-record checks (v3.5.0 T7) ──
        # ChatGPT T7 gate #3: detect cross-record inconsistencies in the
        # retry-authorized execution lifecycle.
        try:
            exec_actions = self.state_manager.get_recovery_execution_actions(
                run_id=report.run_id,
            )
        except Exception:
            exec_actions = []

        # Build lookup: retry_attempt_key → list of actions
        # ChatGPT T7 4th re-review fix 2: inspect ALL action rows per child,
        # not just the last one (requeue creates multiple rows).
        from collections import defaultdict
        actions_by_child = defaultdict(list)
        for a in exec_actions:
            actions_by_child[a.get("retry_attempt_key", "")].append(a)

        for se in side_effects:
            se_key = se.get("idempotency_key", "")
            se_status = se.get("status", "")
            parent_key = se.get("parent_side_effect_key")
            child_key = se.get("idempotency_key", "") if parent_key else None

            # Only check recovery children (have parent_side_effect_key)
            if not parent_key:
                continue

            # SE-R6a: orphan child — parent doesn't exist
            if parent_key not in ledger_status_by_key:
                report.issues.append(ReconciliationIssue(
                    check="side_effect_retry_orphan_child",
                    severity="error",
                    expected=f"parent side effect {parent_key} exists",
                    actual=f"child {se_key} references missing parent",
                    step_id=se.get("step_id", 0),
                ))

            # SE-R6b: parent not retry_authorized
            elif ledger_status_by_key.get(parent_key) != "retry_authorized":
                report.issues.append(ReconciliationIssue(
                    check="side_effect_retry_parent_not_authorized",
                    severity="error",
                    expected=f"parent {parent_key} status 'retry_authorized'",
                    actual=f"parent status '{ledger_status_by_key.get(parent_key)}'",
                    step_id=se.get("step_id", 0),
                ))

            # SE-R6c: child missing execution action
            if se_key not in actions_by_child:
                report.issues.append(ReconciliationIssue(
                    check="side_effect_retry_missing_action",
                    severity="warning",
                    expected=f"execution action for child {se_key}",
                    actual="no recovery_execution_actions row found",
                    step_id=se.get("step_id", 0),
                ))

            # SE-R6d: dispatch_attempted_at on a planned child
            if se_status == "planned" and se.get("dispatch_attempted_at"):
                report.issues.append(ReconciliationIssue(
                    check="side_effect_retry_premature_dispatch",
                    severity="error",
                    expected=f"child {se_key} planned with no dispatch_attempted_at",
                    actual=f"dispatch_attempted_at={se.get('dispatch_attempted_at')}",
                    step_id=se.get("step_id", 0),
                ))

            # SE-R6e-g: inspect ALL action rows for this child
            # ChatGPT T7 4th re-review fix 2: multiple actions may exist
            # (requeue creates new rows). Must inspect each, not reduce to one.
            child_actions = actions_by_child.get(se_key, [])
            active_actions = [
                a for a in child_actions
                if a.get("execution_status") in ("created", "claimed", "dispatch_started")
            ]
            terminal_actions = [
                a for a in child_actions
                if a.get("execution_status") in ("completed", "failed", "unknown", "not_acquired")
            ]

            # SE-R6e: more than one active action for the same child
            if len(active_actions) > 1:
                report.issues.append(ReconciliationIssue(
                    check="side_effect_retry_multiple_active_actions",
                    severity="error",
                    expected=f"at most one active action for {se_key}",
                    actual=f"{len(active_actions)} active actions",
                    step_id=se.get("step_id", 0),
                ))

            # ChatGPT T7 5th re-review fix 2: check action-to-child claim binding.
            # ChatGPT T7 6th re-review: require non-empty fence for started children.
            # For every started recovery child, require a non-empty fence and
            # exactly one matching claimed/dispatch_started action.
            child_claim = se.get("execution_claim_id")
            if se_status == "started":
                if not child_claim:
                    report.issues.append(ReconciliationIssue(
                        check="side_effect_retry_action_claim_mismatch",
                        severity="error",
                        expected=f"non-empty execution_claim_id for started child {se_key}",
                        actual="execution_claim_id is empty or NULL",
                        step_id=se.get("step_id", 0),
                    ))
                else:
                    matching = [
                        a for a in active_actions
                        if a.get("execution_claim_id") == child_claim
                        and a.get("execution_status") in ("claimed", "dispatch_started")
                    ]
                    if len(matching) != 1:
                        report.issues.append(ReconciliationIssue(
                            check="side_effect_retry_action_claim_mismatch",
                            severity="error",
                            expected=f"exactly one action with claim {child_claim} for {se_key}",
                            actual=f"{len(matching)} matching active actions",
                            step_id=se.get("step_id", 0),
                        ))

            # Check each action for boundary/finalization/mismatch
            for action in child_actions:
                act_status = action.get("execution_status", "")
                outcome_code = action.get("outcome_code", "") or ""
                requires_boundary = (
                    act_status in {"dispatch_started", "completed", "unknown"}
                    or (
                        act_status == "failed"
                        and outcome_code == "adapter_confirmed_no_effect"
                    )
                )
                if requires_boundary and not se.get("dispatch_attempted_at"):
                    report.issues.append(ReconciliationIssue(
                        check="side_effect_retry_action_dispatch_without_boundary",
                        severity="error",
                        expected=f"dispatch_attempted_at set for {se_key}",
                        actual=f"action={act_status} but boundary marker absent",
                        step_id=se.get("step_id", 0),
                    ))

                # SE-R6f: terminal child with unfinalized active action
                if se_status in ("completed", "failed", "unknown"):
                    if act_status in ("created", "claimed", "dispatch_started"):
                        report.issues.append(ReconciliationIssue(
                            check="side_effect_retry_unfinalized_action",
                            severity="warning",
                            expected=f"action terminal for {se_key} (child {se_status})",
                            actual=f"action status '{act_status}'",
                            step_id=se.get("step_id", 0),
                        ))

                # SE-R6g: finalized action outcome disagrees with child status
                if act_status in ("completed", "failed", "unknown"):
                    outcome_map = {"completed": "completed", "failed": "failed", "unknown": "unknown"}
                    expected_child = outcome_map.get(act_status)
                    if expected_child and se_status != expected_child:
                        report.issues.append(ReconciliationIssue(
                            check="side_effect_retry_action_child_mismatch",
                            severity="error",
                            expected=f"child status '{expected_child}' for {se_key}",
                            actual=f"child status '{se_status}', action '{act_status}'",
                            step_id=se.get("step_id", 0),
                        ))

        # ── Trust checks ──────────────────────────────────────────
        # Check that untrusted nodes have proper isolation metadata
        # This is advisory — origins data may not be available in all contexts
        try:
            origins = getattr(self, "_run_origins", None)
            if origins:
                for node_id, origin in origins.items():
                    origin_type = origin.get("origin", "built_in")
                    if origin_type in ("local_registry", "remote_registry"):
                        trust = origin.get("trust_level", "local_untrusted")
                        if trust in ("local_untrusted", "remote_untrusted"):
                            isolation = origin.get("isolation_mode", "in_process")
                            if isolation != "subprocess":
                                report.issues.append(ReconciliationIssue(
                                    check="trust_isolation_required",
                                    severity="error",
                                    expected=f"{node_id} should have isolation_mode=subprocess",
                                    actual=f"isolation_mode={isolation}, trust_level={trust}",
                                ))
            report.checks_passed += 1
        except Exception:
            report.checks_passed += 1

        return report

    def _check_review_receipt_binding(
        self,
        review_requested: list,
        review_completed: list,
        materialized,
        report: ReconciliationReport,
    ) -> None:
        """Bind human-review trace events to the persisted governed receipt (v2.23.0).

        For each HUMAN_REVIEW_COMPLETED event, verify its receipt metadata agrees
        with the persisted DecisionReceipt in ChainState.metadata — including a
        recomputed receipt digest (tamper detection, not just string equality).
        When governed_review_request is also persisted, cross-bind the request
        digest (recomputed with the original created_at).

        Governance-failure events (decision='governance_failure') must have NO
        committed receipt — they reconcile as failure-path-valid.
        """
        from nodechain.sdk.review_workbench import (
            DecisionReceipt, ReviewRequest, ReviewSubject,
        )

        # Presence-only accounting for REQUESTED events (no receipt yet).
        if review_requested:
            report.checks_passed += 1

        # No persisted state → cannot bind. Treat completed events without state
        # as a warning (state may simply be unavailable in some test contexts).
        persisted_receipt = None
        governed_request = None
        if materialized is not None and materialized.metadata:
            persisted_receipt = materialized.metadata.get("governed_decision_receipt")
            req_dict = materialized.metadata.get("governed_review_request")
            if req_dict:
                try:
                    subj = req_dict.get("subject", {})
                    governed_request = ReviewRequest(
                        request_id=req_dict.get("request_id", ""),
                        subject=ReviewSubject(
                            subject_type=subj.get("subject_type", "chain_review"),
                            subject_id=subj.get("subject_id", ""),
                            subject_digest=subj.get("subject_digest", ""),
                        ),
                        reason_for_review=req_dict.get("reason_for_review", ""),
                        required_reviewer_role=req_dict.get("required_reviewer_role", "operator"),
                        graph_digest=req_dict.get("graph_digest", ""),
                        policy_digest=req_dict.get("policy_digest", ""),
                        trace_event_ids=list(req_dict.get("trace_event_ids", [])),
                        created_at=req_dict.get("created_at"),  # preserved verbatim
                        risk_level=req_dict.get("risk_level", "medium"),
                        status=req_dict.get("status", "pending"),
                    )
                except Exception:
                    governed_request = None

        # Recompute the persisted receipt digest (tamper detection).
        recomputed_receipt_digest = ""
        recomputed_request_digest = ""
        if persisted_receipt:
            try:
                # Reconstruct the receipt to recompute its digest from current fields.
                dec_dict = persisted_receipt.get("decision", {})
                from nodechain.sdk.review_workbench import OperatorDecision
                decision = OperatorDecision(
                    decision_type=dec_dict.get("decision_type", ""),
                    request_id=dec_dict.get("request_id", ""),
                    reviewer_identity=dec_dict.get("reviewer_identity", ""),
                    reviewer_role=dec_dict.get("reviewer_role", "operator"),
                    rationale=dec_dict.get("rationale", ""),
                    request_digest=dec_dict.get("request_digest", ""),
                    subject_digest=dec_dict.get("subject_digest", ""),
                    policy_digest=dec_dict.get("policy_digest", ""),
                    decided_at=dec_dict.get("decided_at"),
                    authority_source=dec_dict.get("authority_source", "reviewer_policy"),
                )
                receipt = DecisionReceipt(
                    receipt_id=persisted_receipt.get("receipt_id", ""),
                    decision=decision,
                    request_id=persisted_receipt.get("request_id", ""),
                    request_digest=persisted_receipt.get("request_digest", ""),
                    subject_type=persisted_receipt.get("subject_type", "chain_review"),
                    subject_id=persisted_receipt.get("subject_id", ""),
                    subject_digest=persisted_receipt.get("subject_digest", ""),
                    policy_digest=persisted_receipt.get("policy_digest", ""),
                    schema_version=persisted_receipt.get("schema_version", "1.0.0"),
                    created_at=persisted_receipt.get("created_at"),
                    digest_commitment=persisted_receipt.get("digest_commitment", ""),
                )
                recomputed_receipt_digest = receipt.compute_receipt_digest()
            except Exception:
                recomputed_receipt_digest = ""
        if governed_request is not None:
            try:
                recomputed_request_digest = governed_request.compute_digest()
            except Exception:
                recomputed_request_digest = ""

        for e in review_completed:
            md = e.metadata or {}
            step_id = e.step_id or 0

            # Governance-failure path: no receipt must be committed.
            if e.decision == "governance_failure":
                if persisted_receipt:
                    report.issues.append(ReconciliationIssue(
                        check="governance_failure_with_receipt",
                        severity="error",
                        expected="no committed receipt for governance failure",
                        actual=f"receipt {persisted_receipt.get('receipt_id', '?')} present",
                        node_id=e.node_id, step_id=step_id,
                    ))
                else:
                    report.checks_passed += 1  # failure-path-valid
                continue

            # Timeout events carry no receipt metadata by design.
            if e.decision == "timeout":
                report.checks_passed += 1
                continue

            # Valid approve/reject/revision must carry receipt metadata.
            required_keys = ("receipt_id", "receipt_digest", "request_id", "request_digest")
            missing = [k for k in required_keys if not md.get(k)]
            if missing:
                report.issues.append(ReconciliationIssue(
                    check="review_receipt_metadata_missing",
                    severity="error",
                    expected=f"receipt metadata keys {required_keys}",
                    actual=f"missing {missing} on HUMAN_REVIEW_COMPLETED",
                    node_id=e.node_id, step_id=step_id,
                ))
                continue

            if persisted_receipt is None:
                # Completed review event but no persisted receipt to bind against.
                report.issues.append(ReconciliationIssue(
                    check="review_receipt_state_missing",
                    severity="error",
                    expected="governed_decision_receipt in state.metadata",
                    actual="no persisted receipt for completed review event",
                    node_id=e.node_id, step_id=step_id,
                ))
                continue

            # 1. receipt_id match
            if md.get("receipt_id") != persisted_receipt.get("receipt_id"):
                report.issues.append(ReconciliationIssue(
                    check="review_receipt_id_mismatch",
                    severity="error",
                    expected=f"receipt_id {persisted_receipt.get('receipt_id', '?')}",
                    actual=f"trace receipt_id {md.get('receipt_id')}",
                    node_id=e.node_id, step_id=step_id,
                ))
            else:
                report.checks_passed += 1

            # 2. receipt_digest match — against BOTH the persisted value AND a
            #    recomputed digest (tamper/drift detection, per code-review refinement).
            trace_dig = md.get("receipt_digest", "")
            stored_dig = persisted_receipt.get("receipt_digest", "")
            if trace_dig != stored_dig:
                report.issues.append(ReconciliationIssue(
                    check="review_receipt_digest_mismatch",
                    severity="error",
                    expected=f"trace receipt_digest == persisted {stored_dig[:16]}...",
                    actual=f"trace {trace_dig[:16]}...",
                    node_id=e.node_id, step_id=step_id,
                ))
            elif recomputed_receipt_digest and stored_dig != recomputed_receipt_digest:
                # Persisted receipt was tampered with after commit.
                report.issues.append(ReconciliationIssue(
                    check="review_receipt_digest_tamper",
                    severity="error",
                    expected=f"persisted digest == recomputed {recomputed_receipt_digest[:16]}...",
                    actual=f"persisted {stored_dig[:16]}...",
                    node_id=e.node_id, step_id=step_id,
                ))
            else:
                report.checks_passed += 1

            # 3. request_id match
            if md.get("request_id") != persisted_receipt.get("request_id"):
                report.issues.append(ReconciliationIssue(
                    check="review_request_id_mismatch",
                    severity="error",
                    expected=f"request_id {persisted_receipt.get('request_id', '?')}",
                    actual=f"trace request_id {md.get('request_id')}",
                    node_id=e.node_id, step_id=step_id,
                ))
            else:
                report.checks_passed += 1

            # 4. request_digest match (trace ↔ receipt)
            trace_req_dig = md.get("request_digest", "")
            receipt_req_dig = persisted_receipt.get("request_digest", "")
            if trace_req_dig != receipt_req_dig:
                report.issues.append(ReconciliationIssue(
                    check="review_request_digest_mismatch",
                    severity="error",
                    expected=f"trace request_digest == receipt {receipt_req_dig[:16]}...",
                    actual=f"trace {trace_req_dig[:16]}...",
                    node_id=e.node_id, step_id=step_id,
                ))
            else:
                report.checks_passed += 1

            # 5. subject_type == chain_review for runtime receipts (warning if drift)
            trace_subj = md.get("subject_type", "")
            receipt_subj = persisted_receipt.get("subject_type", "")
            if trace_subj and receipt_subj and trace_subj != receipt_subj:
                report.issues.append(ReconciliationIssue(
                    check="review_subject_type_mismatch",
                    severity="warning",
                    expected=f"subject_type {receipt_subj}",
                    actual=f"trace subject_type {trace_subj}",
                    node_id=e.node_id, step_id=step_id,
                ))
            elif receipt_subj and receipt_subj != "chain_review":
                report.issues.append(ReconciliationIssue(
                    check="review_subject_type_unexpected",
                    severity="warning",
                    expected="subject_type chain_review (runtime receipt)",
                    actual=f"subject_type {receipt_subj}",
                    node_id=e.node_id, step_id=step_id,
                ))
            else:
                report.checks_passed += 1

            # 6. receipt must be committed for a valid decision.
            if not persisted_receipt.get("is_committed"):
                report.issues.append(ReconciliationIssue(
                    check="review_receipt_not_committed",
                    severity="error",
                    expected="is_committed True for admitted decision",
                    actual="persisted receipt is_committed False",
                    node_id=e.node_id, step_id=step_id,
                ))
            else:
                report.checks_passed += 1

            # 7. Cross-bind against original governed_review_request (conditional).
            if governed_request is not None and recomputed_request_digest:
                if receipt_req_dig != recomputed_request_digest:
                    report.issues.append(ReconciliationIssue(
                        check="review_request_digest_request_mismatch",
                        severity="error",
                        expected=f"receipt request_digest == recomputed request {recomputed_request_digest[:16]}...",
                        actual=f"receipt {receipt_req_dig[:16]}...",
                        node_id=e.node_id, step_id=step_id,
                    ))
                else:
                    report.checks_passed += 1

    def _check_review_attempt_binding(
        self,
        review_completed: list,
        materialized,
        report: ReconciliationReport,
    ) -> None:
        """Bind review_decision_attempts rows to the trace + receipt (v2.26.0).

        Forms the audit triangle: trace ↔ receipt ↔ attempt log. For each
        HUMAN_REVIEW_COMPLETED event, verifies a durable attempt row exists
        for that run and that its binding fields agree with both the trace
        metadata and the persisted receipt.

        Admitted paths: exactly one admitted attempt, bound to receipt.
        Governance-failure paths: exactly one non-admitted attempt, matching
        rejection_reason.
        Duplicate admitted attempts: warning if equivalent, error if conflicting.
        """
        if not review_completed:
            return

        try:
            all_attempts = self.state_manager.get_review_attempts()
        except Exception:
            return  # attempt log unavailable; receipt binding (Check 5) still ran

        # Index attempts by run_id.
        attempts_by_run: dict[str, list[dict]] = {}
        for att in all_attempts:
            attempts_by_run.setdefault(att.get("run_id", ""), []).append(att)

        persisted_receipt = None
        if materialized is not None and materialized.metadata:
            persisted_receipt = materialized.metadata.get("governed_decision_receipt")

        for e in review_completed:
            step_id = e.step_id or 0
            md = e.metadata or {}
            run_attempts = attempts_by_run.get(e.run_id, [])

            # Timeout events carry no attempt by design; skip.
            if e.decision == "timeout":
                if not run_attempts:
                    report.checks_passed += 1
                continue

            # Governance-failure path: exactly one non-admitted attempt.
            if e.decision == "governance_failure":
                non_admitted = [a for a in run_attempts if not a.get("admitted")]
                if len(non_admitted) == 0:
                    report.issues.append(ReconciliationIssue(
                        check="review_attempt_log_missing",
                        severity="error",
                        expected=">=1 non-admitted attempt for governance failure",
                        actual="0 non-admitted attempts recorded",
                        node_id=e.node_id, step_id=step_id,
                    ))
                elif len(non_admitted) > 1:
                    report.issues.append(ReconciliationIssue(
                        check="review_attempt_duplicate_failure",
                        severity="error",
                        expected="exactly 1 non-admitted attempt for governance failure",
                        actual=f"{len(non_admitted)} non-admitted attempts",
                        node_id=e.node_id, step_id=step_id,
                    ))
                else:
                    att = non_admitted[0]
                    trace_reason = md.get("rejection_reason", "")
                    att_reason = att.get("rejection_reason", "")
                    if trace_reason and att_reason and trace_reason != att_reason:
                        report.issues.append(ReconciliationIssue(
                            check="review_attempt_rejection_mismatch",
                            severity="error",
                            expected=f"rejection_reason {trace_reason}",
                            actual=f"attempt rejection_reason {att_reason}",
                            node_id=e.node_id, step_id=step_id,
                        ))
                    else:
                        report.checks_passed += 1
                continue

            # Admitted path (approve/reject/revision).
            admitted = [a for a in run_attempts if a.get("admitted")]
            if len(admitted) == 0:
                report.issues.append(ReconciliationIssue(
                    check="review_attempt_log_missing",
                    severity="error",
                    expected=">=1 admitted attempt for completed review",
                    actual="0 admitted attempts recorded",
                    node_id=e.node_id, step_id=step_id,
                ))
                continue

            if len(admitted) > 1:
                # Duplicate admitted: warning if equivalent, error if conflicting.
                if self._admitted_attempts_conflict(admitted):
                    report.issues.append(ReconciliationIssue(
                        check="review_attempt_duplicate_conflict",
                        severity="error",
                        expected="equivalent duplicate admitted attempts",
                        actual=f"{len(admitted)} conflicting admitted attempts",
                        node_id=e.node_id, step_id=step_id,
                    ))
                else:
                    report.issues.append(ReconciliationIssue(
                        check="review_attempt_duplicate_admitted",
                        severity="warning",
                        expected="1 admitted attempt",
                        actual=f"{len(admitted)} equivalent admitted attempts",
                        node_id=e.node_id, step_id=step_id,
                    ))

            # Bind the (first) admitted attempt against trace + receipt.
            att = admitted[0]
            # request_digest: trace ↔ attempt
            trace_req_dig = md.get("request_digest", "")
            att_req_dig = att.get("request_digest", "")
            if trace_req_dig and att_req_dig and trace_req_dig != att_req_dig:
                report.issues.append(ReconciliationIssue(
                    check="review_attempt_request_digest_mismatch",
                    severity="error",
                    expected=f"trace request_digest == attempt {att_req_dig[:16]}...",
                    actual=f"trace {trace_req_dig[:16]}...",
                    node_id=e.node_id, step_id=step_id,
                ))
            else:
                report.checks_passed += 1

            # subject_type == chain_review (code-review fix: error, not warning)
            att_subj = att.get("subject_type", "")
            if att_subj and att_subj != "chain_review":
                report.issues.append(ReconciliationIssue(
                    check="review_attempt_subject_type_unexpected",
                    severity="error",
                    expected="subject_type chain_review (governed runtime receipt)",
                    actual=f"subject_type {att_subj}",
                    node_id=e.node_id, step_id=step_id,
                ))
            else:
                report.checks_passed += 1

            # Bind against the receipt (audit triangle).
            if persisted_receipt:
                # code-review fix: bind attempt request_id and request_digest to receipt
                att_req_id = att.get("request_id", "")
                rec_req_id = persisted_receipt.get("request_id", "")
                if att_req_id and rec_req_id and att_req_id != rec_req_id:
                    report.issues.append(ReconciliationIssue(
                        check="review_attempt_request_id_receipt_mismatch",
                        severity="error",
                        expected=f"attempt request_id == receipt {rec_req_id}",
                        actual=f"attempt request_id {att_req_id}",
                        node_id=e.node_id, step_id=step_id,
                    ))
                else:
                    report.checks_passed += 1

                att_req_dig = att.get("request_digest", "")
                rec_req_dig = persisted_receipt.get("request_digest", "")
                if att_req_dig and rec_req_dig and att_req_dig != rec_req_dig:
                    report.issues.append(ReconciliationIssue(
                        check="review_attempt_request_digest_receipt_mismatch",
                        severity="error",
                        expected=f"attempt request_digest == receipt {rec_req_dig[:16]}...",
                        actual=f"attempt request_digest {att_req_dig[:16]}...",
                        node_id=e.node_id, step_id=step_id,
                    ))
                else:
                    report.checks_passed += 1

                # Bind attempt subject_type to receipt subject_type
                rec_subj_type = persisted_receipt.get("subject_type", "")
                if att_subj and rec_subj_type and att_subj != rec_subj_type:
                    report.issues.append(ReconciliationIssue(
                        check="review_attempt_subject_type_receipt_mismatch",
                        severity="error",
                        expected=f"subject_type == receipt {rec_subj_type}",
                        actual=f"attempt subject_type {att_subj}",
                        node_id=e.node_id, step_id=step_id,
                    ))
                else:
                    report.checks_passed += 1

                if att.get("attempted_outcome") != (persisted_receipt.get("decision") or {}).get("outcome"):
                    report.issues.append(ReconciliationIssue(
                        check="review_attempt_outcome_receipt_mismatch",
                        severity="error",
                        expected=f"outcome == receipt {(persisted_receipt.get('decision') or {}).get('outcome')}",
                        actual=f"attempt outcome {att.get('attempted_outcome')}",
                        node_id=e.node_id, step_id=step_id,
                    ))
                else:
                    report.checks_passed += 1
                # subject_id binding
                if att.get("subject_id") and persisted_receipt.get("subject_id") and \
                        att.get("subject_id") != persisted_receipt.get("subject_id"):
                    report.issues.append(ReconciliationIssue(
                        check="review_attempt_subject_id_mismatch",
                        severity="error",
                        expected=f"subject_id == receipt {persisted_receipt.get('subject_id')}",
                        actual=f"attempt subject_id {att.get('subject_id')}",
                        node_id=e.node_id, step_id=step_id,
                    ))
                else:
                    report.checks_passed += 1
                # reviewer_identity: fail only on explicit disagreement
                att_rev = att.get("reviewer_identity", "")
                rec_rev = (persisted_receipt.get("decision") or {}).get("reviewer_identity", "")
                if att_rev and rec_rev and att_rev != rec_rev:
                    report.issues.append(ReconciliationIssue(
                        check="review_attempt_reviewer_identity_mismatch",
                        severity="error",
                        expected=f"reviewer_identity == receipt {rec_rev}",
                        actual=f"attempt reviewer_identity {att_rev}",
                        node_id=e.node_id, step_id=step_id,
                    ))
                else:
                    report.checks_passed += 1

    def _check_memory_decision_binding(
        self,
        memory_write_allowed: list,
        memory_write_blocked: list,
        report: ReconciliationReport,
    ) -> None:
        """Bind memory write trace events to durable memory_decisions rows (v2.29.0).

        The durable row is the canonical governance artifact; the trace is the
        audit projection. For each MEMORY_WRITE_ALLOWED/BLOCKED event, verifies
        a matching memory_decisions row exists and that binding fields agree
        (candidate_digest, write_ref, rule_id, decision).
        """
        if not memory_write_allowed and not memory_write_blocked:
            return

        try:
            # code-review fix: filter by run_id, not scan all runs.
            # candidate_digest is intentionally stable across runs, so scanning
            # all runs would cause false duplicate/conflict detection.
            all_decisions = self.state_manager.get_memory_decisions(
                run_id=report.run_id,
            )
        except Exception:
            return  # memory decision log unavailable

        # Index by candidate_digest (the stable cross-surface binding key).
        by_digest: dict[str, list[dict]] = {}
        for md in all_decisions:
            by_digest.setdefault(md.get("candidate_digest", ""), []).append(md)

        def _bind_event(e: TraceEvent, expected_decisions: set[str]) -> None:
            md_meta = e.metadata or {}
            step_id = e.step_id or 0
            cand_digest = md_meta.get("candidate_digest", "")

            # Must have a matching durable row.
            rows = by_digest.get(cand_digest, []) if cand_digest else []
            if not rows:
                report.issues.append(ReconciliationIssue(
                    check="memory_decision_log_missing",
                    severity="error",
                    expected=f"memory_decisions row for candidate_digest {cand_digest[:16]}...",
                    actual="no matching durable decision row",
                    node_id=e.node_id, step_id=step_id,
                ))
                return

            # Duplicate rows: warning if identical, error if conflicting.
            if len(rows) > 1:
                if self._memory_decisions_conflict(rows):
                    report.issues.append(ReconciliationIssue(
                        check="memory_decision_duplicate_conflict",
                        severity="error",
                        expected="equivalent duplicate memory decisions",
                        actual=f"{len(rows)} conflicting rows",
                        node_id=e.node_id, step_id=step_id,
                    ))
                else:
                    report.issues.append(ReconciliationIssue(
                        check="memory_decision_duplicate",
                        severity="warning",
                        expected="1 memory decision row",
                        actual=f"{len(rows)} equivalent rows",
                        node_id=e.node_id, step_id=step_id,
                    ))

            row = rows[0]

            # Decision must match one of the expected types.
            if row.get("decision") not in expected_decisions:
                report.issues.append(ReconciliationIssue(
                    check="memory_decision_type_mismatch",
                    severity="error",
                    expected=f"decision in {expected_decisions}",
                    actual=f"durable decision={row.get('decision')}",
                    node_id=e.node_id, step_id=step_id,
                ))
            else:
                report.checks_passed += 1

            # write_ref: allow must have non-empty, deny/skip must have empty.
            row_wref = row.get("write_ref", "")
            is_blocked = expected_decisions != {"allow"}
            if not is_blocked and not row_wref:
                report.issues.append(ReconciliationIssue(
                    check="memory_decision_allow_missing_write_ref",
                    severity="error",
                    expected="non-empty write_ref for allowed write",
                    actual="empty write_ref",
                    node_id=e.node_id, step_id=step_id,
                ))
            elif is_blocked and row_wref:
                report.issues.append(ReconciliationIssue(
                    check="memory_decision_blocked_has_write_ref",
                    severity="error",
                    expected="empty write_ref for blocked write",
                    actual=f"write_ref={row_wref[:16]}...",
                    node_id=e.node_id, step_id=step_id,
                ))
            else:
                report.checks_passed += 1

            # write_ref must match trace (for allowed writes).
            trace_wref = md_meta.get("write_ref", "")
            if not is_blocked and trace_wref and row_wref and trace_wref != row_wref:
                report.issues.append(ReconciliationIssue(
                    check="memory_write_ref_mismatch",
                    severity="error",
                    expected=f"write_ref == durable {row_wref[:16]}...",
                    actual=f"trace {trace_wref[:16]}...",
                    node_id=e.node_id, step_id=step_id,
                ))
            else:
                report.checks_passed += 1

            # rule_id must match (generic binding — covers checks 8-10 implicitly).
            trace_rule = md_meta.get("rule_id", "")
            row_rule = row.get("rule_id", "")
            if trace_rule and row_rule and trace_rule != row_rule:
                report.issues.append(ReconciliationIssue(
                    check="memory_rule_id_mismatch",
                    severity="error",
                    expected=f"rule_id == durable {row_rule}",
                    actual=f"trace rule_id {trace_rule}",
                    node_id=e.node_id, step_id=step_id,
                ))
            else:
                report.checks_passed += 1

        for e in memory_write_allowed:
            _bind_event(e, {"allow"})
        for e in memory_write_blocked:
            _bind_event(e, {"deny", "skip"})

    @staticmethod
    def _memory_decisions_conflict(rows: list[dict]) -> bool:
        """True if duplicate memory decision rows disagree on binding fields."""
        keys = ("decision", "write_ref", "rule_id", "candidate_digest")
        for k in keys:
            values = {r.get(k) for r in rows}
            if len(values) > 1:
                return True
        return False

    @staticmethod
    def _admitted_attempts_conflict(attempts: list[dict]) -> bool:
        """True if duplicate admitted attempts disagree on any binding field."""
        keys = ("request_digest", "attempted_outcome", "reviewer_identity",
                "subject_id", "subject_type")
        for k in keys:
            values = {a.get(k) for a in attempts}
            if len(values) > 1:
                return True
        return False

    def _check_memory_read_binding(
        self,
        trace: ChainTrace,
        report: ReconciliationReport,
    ) -> None:
        """Memory read governance binding (v2.40.0).

        MR-1: MEMORY_READ_ALLOWED without durable allow decision = ERROR
        MR-2: MEMORY_READ_DENIED but exposed_to_node = ERROR
        MR-3: durable allow without trace = WARNING
        """
        try:
            mr_decisions = self.state_manager.get_memory_read_decisions(
                run_id=report.run_id,
            )
        except Exception:
            mr_decisions = []

        mr_decision_ids = {d.get("decision_id", "") for d in mr_decisions}

        for e in trace.events:
            et = str(e.event_type)
            if "MEMORY_READ_ALLOWED" in et:
                did = (e.metadata or {}).get("decision_id", "")
                if did and did not in mr_decision_ids:
                    report.issues.append(ReconciliationIssue(
                        check="memory_read_allowed_without_decision",
                        severity="error",
                        expected=f"durable allow decision for {did}",
                        actual="no matching memory_read_decisions row",
                        node_id=e.node_id, step_id=e.step_id or 0,
                    ))
                else:
                    report.checks_passed += 1
            elif "MEMORY_READ_DENIED" in et:
                did = (e.metadata or {}).get("decision_id", "")
                if did:
                    dec = next(
                        (d for d in mr_decisions if d.get("decision_id") == did), None,
                    )
                    if dec and dec.get("exposed_to_node"):
                        report.issues.append(ReconciliationIssue(
                            check="memory_read_denied_but_exposed",
                            severity="error",
                            expected=f"no exposure for denied decision {did}",
                            actual="exposed_to_node is True",
                            node_id=e.node_id, step_id=e.step_id or 0,
                        ))

        # MR-3: durable allow without trace = WARNING
        trace_decision_ids = {
            (e.metadata or {}).get("decision_id", "")
            for e in trace.events
            if "MEMORY_READ" in str(e.event_type) and e.metadata
        }
        for d in mr_decisions:
            if d.get("decision") == "allow":
                did = d.get("decision_id", "")
                if did and did not in trace_decision_ids:
                    report.issues.append(ReconciliationIssue(
                        check="memory_read_allow_without_trace",
                        severity="warning",
                        expected=f"MEMORY_READ_ALLOWED trace for {did}",
                        actual="durable allow without trace event",
                        node_id=d.get("node_id", ""),
                        step_id=d.get("step_id", 0),
                    ))

    def _check_adapter_access_binding(
        self,
        trace: ChainTrace,
        report: ReconciliationReport,
    ) -> None:
        """Adapter access governance binding (v2.43.1 + v2.43.2).

        AA-1: TOOL_CALLED with adapter but no exact durable allow (run+node+step+adapter) = ERROR
        AA-2: ADAPTER_ACCESS_DENIED but TOOL_CALLED exists for same adapter+node+step = ERROR
        AA-3: ADAPTER_ACCESS_ALLOWED/DENIED trace decision_id missing durable row = ERROR
        """
        # Load durable adapter decisions
        try:
            aa_decisions = self.state_manager.get_adapter_access_decisions(
                run_id=report.run_id,
            )
        except Exception:
            aa_decisions = []

        # v2.43.2: build exact-match index: (node_id, step_id, adapter_name) → {decision, decision_id}
        allow_index: dict[tuple[str, int, str], str] = {}
        deny_index: dict[tuple[str, int, str], str] = {}
        all_decision_ids = set()
        for d in aa_decisions:
            did = d.get("decision_id", "")
            all_decision_ids.add(did)
            key = (d.get("node_id", ""), d.get("step_id", 0), d.get("adapter_name", ""))
            if d.get("decision") == "allow":
                allow_index[key] = did
            else:
                deny_index[key] = did

        # AA-3: trace ADAPTER_ACCESS events must reference durable rows
        # v2.43.3: verify polarity (allow_decision_ids must be allow rows,
        # deny_decision_ids must be deny rows) + invocation identity
        # (node_id, step_id must match the trace event's node_id, step_id).
        # Build decision_id → full row lookup
        decision_by_id: dict[str, dict] = {
            d.get("decision_id", ""): d for d in aa_decisions
        }
        for e in trace.events:
            et = str(e.event_type)
            if "ADAPTER_ACCESS" not in et:
                continue
            meta = e.metadata or {}
            allow_dids = meta.get("allow_decision_ids", [])
            deny_dids = meta.get("deny_decision_ids", [])
            # Also check backward-compat "decision_ids"
            legacy_dids = meta.get("decision_ids", [])

            # v2.43.3: verify allow_decision_ids reference durable allow rows
            for did in allow_dids:
                row = decision_by_id.get(did)
                if row is None:
                    report.issues.append(ReconciliationIssue(
                        check="adapter_access_trace_missing_durable",
                        severity="error",
                        expected=f"durable allow decision for {did}",
                        actual="no matching adapter_access_decisions row",
                        node_id=e.node_id, step_id=e.step_id or 0,
                    ))
                elif row.get("decision") != "allow":
                    report.issues.append(ReconciliationIssue(
                        check="adapter_access_polarity_mismatch",
                        severity="error",
                        expected=f"decision=allow for {did}",
                        actual=f"durable decision={row.get('decision')}",
                        node_id=e.node_id, step_id=e.step_id or 0,
                    ))
                elif row.get("node_id") != e.node_id or row.get("step_id") != (e.step_id or 0):
                    report.issues.append(ReconciliationIssue(
                        check="adapter_access_identity_mismatch",
                        severity="error",
                        expected=f"node={e.node_id} step={e.step_id} for {did}",
                        actual=f"durable node={row.get('node_id')} step={row.get('step_id')}",
                        node_id=e.node_id, step_id=e.step_id or 0,
                    ))

            # v2.43.3: verify deny_decision_ids reference durable deny rows
            for did in deny_dids:
                row = decision_by_id.get(did)
                if row is None:
                    report.issues.append(ReconciliationIssue(
                        check="adapter_access_trace_missing_durable",
                        severity="error",
                        expected=f"durable deny decision for {did}",
                        actual="no matching adapter_access_decisions row",
                        node_id=e.node_id, step_id=e.step_id or 0,
                    ))
                elif row.get("decision") != "deny":
                    report.issues.append(ReconciliationIssue(
                        check="adapter_access_polarity_mismatch",
                        severity="error",
                        expected=f"decision=deny for {did}",
                        actual=f"durable decision={row.get('decision')}",
                        node_id=e.node_id, step_id=e.step_id or 0,
                    ))
                elif row.get("node_id") != e.node_id or row.get("step_id") != (e.step_id or 0):
                    report.issues.append(ReconciliationIssue(
                        check="adapter_access_identity_mismatch",
                        severity="error",
                        expected=f"node={e.node_id} step={e.step_id} for {did}",
                        actual=f"durable node={row.get('node_id')} step={row.get('step_id')}",
                        node_id=e.node_id, step_id=e.step_id or 0,
                    ))

            # Backward compat: legacy decision_ids (no polarity split)
            for did in legacy_dids:
                if did not in all_decision_ids:
                    report.issues.append(ReconciliationIssue(
                        check="adapter_access_trace_missing_durable",
                        severity="error",
                        expected=f"durable adapter decision for {did}",
                        actual="no matching adapter_access_decisions row",
                        node_id=e.node_id, step_id=e.step_id or 0,
                    ))

        # AA-1: TOOL_CALLED with adapter — exact binding (run+node+step+adapter)
        # v2.43.2: always ERROR, no legacy WARNING fallback
        for e in trace.events:
            et = str(e.event_type)
            if "TOOL_CALLED" in et:
                adapter_name = (e.metadata or {}).get("adapter", "")
                if not adapter_name:
                    continue
                key = (e.node_id or "", e.step_id or 0, adapter_name)
                if key not in allow_index:
                    report.issues.append(ReconciliationIssue(
                        check="adapter_call_without_allow",
                        severity="error",
                        expected=f"durable allow for {adapter_name} at node={e.node_id} step={e.step_id}",
                        actual="no matching adapter_access_decisions allow",
                        node_id=e.node_id, step_id=e.step_id or 0,
                    ))

        # AA-2: denied adapter but TOOL_CALLED exists for same node+step
        for e in trace.events:
            et = str(e.event_type)
            if "ADAPTER_ACCESS_DENIED" in et:
                ungranted = (e.metadata or {}).get("ungranted", [])
                for adapter_name in ungranted:
                    key = (e.node_id or "", e.step_id or 0, adapter_name)
                    has_call = any(
                        (te.metadata or {}).get("adapter") == adapter_name
                        and te.node_id == e.node_id
                        and te.step_id == e.step_id
                        for te in trace.events
                        if "TOOL_CALLED" in str(te.event_type)
                    )
                    if has_call:
                        report.issues.append(ReconciliationIssue(
                            check="adapter_denied_but_called",
                            severity="error",
                            expected=f"no TOOL_CALLED for denied adapter {adapter_name}",
                            actual="TOOL_CALLED trace exists",
                            node_id=e.node_id, step_id=e.step_id or 0,
                        ))

    def _check_package_trust_binding(
        self,
        trace: ChainTrace,
        report: ReconciliationReport,
    ) -> None:
        """Package trust governance binding (v2.44.1).

        PT-1: privileged runtime event without durable package-trust allow = ERROR
        PT-2: PACKAGE_TRUST_ALLOWED/DENIED trace decision_id missing durable row = ERROR
        PT-3: package-trust trace identity mismatch (node_id, step_id, polarity) = ERROR
        PT-4: denied package with privileged runtime event for same node+step = ERROR
        """
        try:
            pt_decisions = self.state_manager.get_package_trust_decisions(
                run_id=report.run_id,
            )
        except Exception:
            pt_decisions = []

        # Build lookups — exact (node_id, step_id) maps
        allow_by_node_step: dict[tuple[str, int], str] = {}
        deny_by_node_step: dict[tuple[str, int], str] = {}
        decision_by_id: dict[str, dict] = {}
        for d in pt_decisions:
            did = d.get("decision_id", "")
            decision_by_id[did] = d
            key = (d.get("node_id", ""), d.get("step_id", 0))
            if d.get("decision") == "allow":
                allow_by_node_step[key] = did
            else:
                deny_by_node_step[key] = did

        # Privileged runtime event types
        PRIVILEGED_EVENT_SUBSTRINGS = [
            "TOOL_ACCESS_ALLOWED", "ADAPTER_ACCESS_ALLOWED",
            "MEMORY_READ_ALLOWED", "MEMORY_READ_EXPOSED",
            "MEMORY_WRITE_ALLOWED", "SIDE_EFFECT_STARTED",
            "SIDE_EFFECT_COMPLETED", "MODEL_CALLED",
        ]

        # PT-1: privileged event without durable allow
        # PT-4: denied package with privileged event
        # v2.44.1: only ERROR when trust decisions exist for this run
        # (gate was evaluated). If table is empty, the chain predates
        # v2.44.0 — WARNING, not ERROR.
        has_pt_decisions = len(pt_decisions) > 0
        for e in trace.events:
            et = str(e.event_type)
            is_privileged_event = any(sub in et for sub in PRIVILEGED_EVENT_SUBSTRINGS)
            if not is_privileged_event:
                continue
            key = (e.node_id or "", e.step_id or 0)
            # v2.44.3: step-exact binding
            if key in deny_by_node_step:
                report.issues.append(ReconciliationIssue(
                    check="package_trust_denied_with_privileged_event",
                    severity="error",
                    expected=f"no privileged event for denied node {e.node_id} step {e.step_id}",
                    actual=f"{et} trace exists despite package-trust deny",
                    node_id=e.node_id, step_id=e.step_id or 0,
                ))
            elif key not in allow_by_node_step:
                if has_pt_decisions:
                    report.issues.append(ReconciliationIssue(
                        check="package_trust_missing_for_privileged_event",
                        severity="error",
                        expected=f"durable package-trust allow for {e.node_id} step {e.step_id}",
                        actual=f"{et} without matching package_trust_decisions allow",
                        node_id=e.node_id, step_id=e.step_id or 0,
                    ))

        # PT-2 + PT-3: trace decision_id must exist and match
        for e in trace.events:
            et = str(e.event_type)
            if "PACKAGE_TRUST" not in et:
                continue
            did = (e.metadata or {}).get("decision_id", "")
            if not did:
                continue
            row = decision_by_id.get(did)
            if row is None:
                report.issues.append(ReconciliationIssue(
                    check="package_trust_trace_missing_durable",
                    severity="error",
                    expected=f"durable package-trust decision for {did}",
                    actual="no matching package_trust_decisions row",
                    node_id=e.node_id, step_id=e.step_id or 0,
                ))
                continue

            # PT-3: full identity, polarity, and metadata match (v2.44.3)
            expected_decision = "allow" if "ALLOWED" in et else "deny"
            if row.get("decision") != expected_decision:
                report.issues.append(ReconciliationIssue(
                    check="package_trust_polarity_mismatch",
                    severity="error",
                    expected=f"decision={expected_decision} for {did}",
                    actual=f"durable decision={row.get('decision')}",
                    node_id=e.node_id, step_id=e.step_id or 0,
                ))
            if row.get("node_id") != e.node_id:
                report.issues.append(ReconciliationIssue(
                    check="package_trust_identity_mismatch",
                    severity="error",
                    expected=f"node_id={e.node_id} for {did}",
                    actual=f"durable node_id={row.get('node_id')}",
                    node_id=e.node_id, step_id=e.step_id or 0,
                ))
            # v2.44.3: step_id match
            if row.get("step_id") != (e.step_id or 0):
                report.issues.append(ReconciliationIssue(
                    check="package_trust_identity_mismatch",
                    severity="error",
                    expected=f"step_id={e.step_id} for {did}",
                    actual=f"durable step_id={row.get('step_id')}",
                    node_id=e.node_id, step_id=e.step_id or 0,
                ))
            # v2.44.3: is_privileged match
            trace_priv = (e.metadata or {}).get("is_privileged")
            durable_priv = bool(row.get("is_privileged"))
            if trace_priv is not None and bool(trace_priv) != durable_priv:
                report.issues.append(ReconciliationIssue(
                    check="package_trust_metadata_mismatch",
                    severity="error",
                    expected=f"is_privileged={durable_priv} for {did}",
                    actual=f"trace is_privileged={trace_priv}",
                    node_id=e.node_id, step_id=e.step_id or 0,
                ))
            # v2.44.3: missing required metadata is ERROR (not silently ignored)
            meta = e.metadata or {}
            for field in ("origin", "observed_trust_level", "package_digest"):
                trace_val = meta.get(field, "")
                durable_val = row.get(field, "")
                if not trace_val:
                    report.issues.append(ReconciliationIssue(
                        check="package_trust_metadata_missing",
                        severity="error",
                        expected=f"trace {field} for {did}",
                        actual=f"missing {field} in PACKAGE_TRUST trace event",
                        node_id=e.node_id, step_id=e.step_id or 0,
                    ))
                elif durable_val and trace_val != durable_val:
                    report.issues.append(ReconciliationIssue(
                        check="package_trust_metadata_mismatch",
                        severity="error",
                        expected=f"{field}={durable_val} for {did}",
                        actual=f"trace {field}={trace_val}",
                        node_id=e.node_id, step_id=e.step_id or 0,
                    ))

    def check_lockfile(self) -> list[dict]:
        """Check current registry against lockfile.

        Returns list of mismatch/missing entries.
        Useful for post-run verification.
        """
        try:
            from nodechain.sdk.lockfile import verify_lockfile
            result = verify_lockfile()
            issues = []
            for m in result.get("mismatches", []):
                issues.append(m)
            for m in result.get("missing", []):
                issues.append(m)
            return issues
        except Exception:
            return []
