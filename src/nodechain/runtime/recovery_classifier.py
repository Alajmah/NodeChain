"""recovery_classifier — derives a recovery_state from durable facts (v2.46.0).

The recovery_state is a *derived view*, never stored on ChainState. It is
re-computed on every snapshot so it can never drift from the underlying durable
state, side-effect ledger, reconciler report, review attempts, and loop state.

Decision priority is fixed (highest first):

    1. terminal          -> COMPLETED / CANCELLED
    2. review pause      -> PAUSED_FOR_HUMAN_REVIEW (only with a pending request)
    3. unknown SE        -> CRASH_NEEDS_OPERATOR (no recovery decision)
                          / CRASH_RECOVERABLE (recovery decision present)
    4. trace health      -> TRACE_INCOMPLETE (reconciler errors)
    5. loop exhaustion   -> LOOP_EXHAUSTED
    6. failure           -> FAILED_RETRYABLE / FAILED_NON_RETRYABLE
    7. fallback          -> CRASH_RECOVERABLE

Every non-terminal, non-clean state carries a non-None ``blocking_reason``
grounded in the durable fact that triggered it, so an operator never sees a
blocked run without an explanation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from nodechain.core.state import ChainState
    from nodechain.runtime.trace_reconciler import ReconciliationReport


class RecoveryState(str, Enum):
    """Operator-facing classification of a run's recovery posture."""

    PAUSED_FOR_HUMAN_REVIEW = "PAUSED_FOR_HUMAN_REVIEW"
    PAUSED_FOR_POLICY_APPROVAL = "PAUSED_FOR_POLICY_APPROVAL"
    PAUSED_FOR_BUDGET_APPROVAL = "PAUSED_FOR_BUDGET_APPROVAL"
    FAILED_RETRYABLE = "FAILED_RETRYABLE"
    FAILED_NON_RETRYABLE = "FAILED_NON_RETRYABLE"
    LOOP_EXHAUSTED = "LOOP_EXHAUSTED"
    TRACE_INCOMPLETE = "TRACE_INCOMPLETE"
    CRASH_RECOVERABLE = "CRASH_RECOVERABLE"
    CRASH_NEEDS_OPERATOR = "CRASH_NEEDS_OPERATOR"
    CANCELLED = "CANCELLED"
    COMPLETED = "COMPLETED"
    # v3.5.0 T7: derived retry-authorized lineage states.
    # These are read-only projections — the parent stays retry_authorized.
    RETRY_AUTHORIZED_PENDING_EXECUTION = "RETRY_AUTHORIZED_PENDING_EXECUTION"
    RETRY_ATTEMPT_IN_FLIGHT = "RETRY_ATTEMPT_IN_FLIGHT"
    RETRY_COMPLETED = "RETRY_COMPLETED"
    RETRY_FAILED = "RETRY_FAILED"
    RETRY_UNKNOWN = "RETRY_UNKNOWN"
    LEGACY_NOT_REPLAYABLE = "LEGACY_NOT_REPLAYABLE"


@dataclass(frozen=True)
class Classification:
    """Result of classifying one run."""

    state: RecoveryState
    blocking_reason: str | None = None


# ── v3.5.0 T9: per-parent lineage projection + deletion-closure partition ──
#
# classify_retry_lineages() produces one RetryLineageProjection per
# retry_authorized parent. The deletion gate consumes this directly; the
# legacy classify_retry_lineage() aggregate (worst-parent select) is kept
# for T7 compatibility.

@dataclass(frozen=True)
class RetryLineageProjection:
    """One retry_authorized parent's effective lineage state.

    A read-only projection: the parent stays retry_authorized regardless of
    the derived state. Consumed by both the metrics dashboard and the
    deletion gate (T9).
    """
    parent_side_effect_key: str
    state: RecoveryState
    blocking_reason: str | None
    latest_child_key: str | None
    capsule_status: str


# Exhaustive partition of the six retry-lineage states.
# A closed lineage has no outstanding work and is safe to delete from a
# retry standpoint (legacy rows carry a warning, not a block).
# An open lineage must block deletion — work is in flight or uncertain.
# Asserted exhaustive in tests: a future state not in either set fails
# closed rather than silently permitting deletion.
CLOSED_RETRY_LINEAGE_STATES: frozenset[RecoveryState] = frozenset({
    RecoveryState.RETRY_COMPLETED,
    RecoveryState.RETRY_FAILED,
    RecoveryState.LEGACY_NOT_REPLAYABLE,
})
OPEN_RETRY_LINEAGE_STATES: frozenset[RecoveryState] = frozenset({
    RecoveryState.RETRY_AUTHORIZED_PENDING_EXECUTION,
    RecoveryState.RETRY_ATTEMPT_IN_FLIGHT,
    RecoveryState.RETRY_UNKNOWN,
})


def classify(
    state: "ChainState",
    side_effects: list[dict[str, Any]],
    report: "ReconciliationReport | None",
    review_attempts: list[dict[str, Any]],
    *,
    recovery_decisions: list[dict[str, Any]] | None = None,
) -> Classification:
    """Map durable facts to a RecoveryState.

    Pure: no I/O. ``side_effects``, ``review_attempts`` and
    ``recovery_decisions`` are the durable rows already loaded by the caller;
    ``report`` is the (optional) trace-reconciler result.
    """
    md = state.metadata or {}
    recovery_decisions = recovery_decisions or []

    # 1. Terminal states.
    if state.status == "completed":
        return Classification(RecoveryState.COMPLETED)
    if state.status == "cancelled":
        return Classification(RecoveryState.CANCELLED)

    # 2. Review pause — only when a governed request is genuinely pending.
    #    A policy-subject request is a policy-approval pause (distinct operator
    #    action from a human review of node output).
    if state.status == "waiting_for_review":
        request = md.get("governed_review_request")
        if request:
            step = request.get("step_id", "?")
            if request.get("subject_type") == "policy":
                return Classification(
                    RecoveryState.PAUSED_FOR_POLICY_APPROVAL,
                    f"policy approval required at step {step}",
                )
            return Classification(
                RecoveryState.PAUSED_FOR_HUMAN_REVIEW,
                f"human review required at step {step}",
            )
        # Status says waiting but no durable request — data drift; fall through
        # so the operator sees it as needing recovery, not as a clean pause.

    # 3. Unknown side effects — crash recovery.
    # v3.5.0 T7: exclude recovery children (they have parent_side_effect_key).
    # Their unknown status is handled by the retry lineage classifier (step 3b).
    unknown = [
        se for se in side_effects
        if se.get("status") == "unknown" and not se.get("parent_side_effect_key")
    ]
    if unknown:
        if recovery_decisions:
            return Classification(
                RecoveryState.CRASH_RECOVERABLE,
                f"{len(unknown)} unknown side effect(s) with a recovery decision pending",
            )
        return Classification(
            RecoveryState.CRASH_NEEDS_OPERATOR,
            f"{len(unknown)} unknown side effect(s) require an operator recovery decision",
        )

    # 3b. v3.5.0 T7: retry_authorized side effects — boundary-aware classification.
    # ChatGPT T7 gate: the projection combines parent authorization + child
    # attempt + dispatch boundary + lease state into an effective recovery state.
    # The parent stays retry_authorized even when the child completes or fails.
    retry_authorized = [se for se in side_effects if se.get("status") == "retry_authorized"]
    if retry_authorized:
        lineage = classify_retry_lineage(
            retry_authorized, side_effects, recovery_decisions,
        )
        if lineage is not None:
            return lineage

    # 4. Trace health — reconciler errors block before any action is meaningful.
    if report is not None and report.errors:
        return Classification(
            RecoveryState.TRACE_INCOMPLETE,
            f"trace reconciliation reported {len(report.errors)} error(s)",
        )

    # 5. Loop exhaustion.
    if md.get("loop_exhausted"):
        loop_name = md["loop_exhausted"]
        return Classification(
            RecoveryState.LOOP_EXHAUSTED,
            f"loop '{loop_name}' exhausted its iteration budget",
        )

    # 5b. Budget pause (v2.47.0): a run paused for budget approval is a
    # distinct operator-actionable state — not a failure. Takes priority over
    # the failure path because the run is waiting for a budget decision, not
    # terminally failed.
    if state.status == "paused_for_budget":
        loop_name = md.get("loop_budget_exceeded", "unknown")
        return Classification(
            RecoveryState.PAUSED_FOR_BUDGET_APPROVAL,
            f"loop '{loop_name}' exceeded its cost budget; awaiting operator "
            f"budget-increase approval",
        )

    # 6. Failure retryability.
    if state.status == "failed":
        failure = md.get("last_failure") or {}
        retryable = bool(failure.get("retryable"))
        if retryable:
            return Classification(
                RecoveryState.FAILED_RETRYABLE,
                "failed node is retryable",
            )
        return Classification(
            RecoveryState.FAILED_NON_RETRYABLE,
            "failed node is not retryable without an operator override",
        )

    # 7. Fallback — surface the run rather than hide it.
    return Classification(
        RecoveryState.CRASH_RECOVERABLE,
        f"run is in status '{state.status}' with no specific recovery signal",
    )


def classify_retry_lineages(
    retry_authorized_parents: list[dict[str, Any]],
    all_side_effects: list[dict[str, Any]],
    recovery_decisions: list[dict[str, Any]] | None,
) -> list[RetryLineageProjection]:
    """v3.5.0 T9: public per-parent lineage projection.

    Returns one RetryLineageProjection per retry_authorized parent. The
    deletion gate and metrics dashboard consume this directly. Unlike the
    legacy aggregate (classify_retry_lineage), this preserves per-parent
    detail for audit breakdowns.

    Each projection combines: parent authorization status, capsule
    availability, latest child attempt status, dispatch boundary, and lease
    state into an effective RecoveryState.
    """
    recovery_decisions = recovery_decisions or []

    # Build child lookup: parent_key → children
    children_by_parent: dict[str, list[dict]] = {}
    for se in all_side_effects:
        parent_key = se.get("parent_side_effect_key")
        if parent_key:
            children_by_parent.setdefault(parent_key, []).append(se)

    projections: list[RetryLineageProjection] = []
    for parent in retry_authorized_parents:
        pkey = parent["idempotency_key"]
        capsule_status = parent.get("capsule_status", "legacy_unavailable")

        if capsule_status != "available":
            # Legacy: no capsule → not replayable. No child to link.
            projections.append(RetryLineageProjection(
                parent_side_effect_key=pkey,
                state=RecoveryState.LEGACY_NOT_REPLAYABLE,
                blocking_reason=f"side effect {pkey} has no replay capsule (legacy)",
                latest_child_key=None,
                capsule_status=capsule_status,
            ))
        else:
            children = children_by_parent.get(pkey, [])
            cls = _classify_one_parent(pkey, children)
            latest_child_key = None
            if children:
                latest = max(children, key=lambda c: c.get("retry_ordinal", 0))
                latest_child_key = latest.get("idempotency_key")
            projections.append(RetryLineageProjection(
                parent_side_effect_key=pkey,
                state=cls.state,
                blocking_reason=cls.blocking_reason,
                latest_child_key=latest_child_key,
                capsule_status=capsule_status,
            ))

    return projections


def classify_retry_lineage(
    retry_authorized_parents: list[dict[str, Any]],
    all_side_effects: list[dict[str, Any]],
    recovery_decisions: list[dict[str, Any]] | None,
) -> Classification | None:
    """v3.5.0 T7: Boundary-aware classification of retry-authorized lineage.

    Compatibility aggregate over classify_retry_lineages(): selects the
    worst (most operator-attention-needed) parent's classification.

    Returns None if no retry_authorized parents have lineage (caller falls through).
    """
    projections = classify_retry_lineages(
        retry_authorized_parents, all_side_effects, recovery_decisions,
    )
    worst: Classification | None = None
    for proj in projections:
        candidate = Classification(proj.state, proj.blocking_reason)
        if worst is None or _severity_rank(candidate.state) > _severity_rank(worst.state):
            worst = candidate
    return worst


def _classify_one_parent(
    parent_key: str, children: list[dict],
) -> Classification:
    """Classify a single retry_authorized parent by its child lineage."""
    from datetime import datetime, timezone

    if not children:
        return Classification(
            RecoveryState.RETRY_AUTHORIZED_PENDING_EXECUTION,
            f"side effect {parent_key} authorized for retry, "
            f"awaiting execution",
        )

    # Find the latest child (highest retry_ordinal)
    latest = max(children, key=lambda c: c.get("retry_ordinal", 0))
    child_status = latest["status"]
    dispatch_at = latest.get("dispatch_attempted_at")
    lease_expiry = latest.get("claim_expires_at")

    if child_status == "completed":
        return Classification(
            RecoveryState.RETRY_COMPLETED,
            f"retry of {parent_key} completed (child {latest['idempotency_key']})",
        )
    if child_status == "failed":
        return Classification(
            RecoveryState.RETRY_FAILED,
            f"retry of {parent_key} definitively failed",
        )
    if child_status == "unknown":
        return Classification(
            RecoveryState.RETRY_UNKNOWN,
            f"retry of {parent_key} outcome unknown; operator intervention required",
        )
    if child_status == "planned":
        return Classification(
            RecoveryState.RETRY_AUTHORIZED_PENDING_EXECUTION,
            f"retry of {parent_key} allocated but not yet dispatched",
        )

    # Child is started — check boundary and lease
    now = datetime.now(timezone.utc)
    lease_expired = True
    if lease_expiry:
        try:
            if datetime.fromisoformat(lease_expiry) > now:
                lease_expired = False
        except (ValueError, TypeError):
            pass  # Can't parse — treat as expired

    if dispatch_at is not None and lease_expired:
        # ChatGPT T7 critical rule: dispatch crossed + lease expired → unknown
        # Never automatically redispatched
        return Classification(
            RecoveryState.RETRY_UNKNOWN,
            f"retry of {parent_key} dispatched but lease expired; "
            f"outcome uncertain, operator intervention required",
        )
    if dispatch_at is None and lease_expired:
        # Safely reclaimable — dispatch boundary never crossed
        return Classification(
            RecoveryState.RETRY_ATTEMPT_IN_FLIGHT,
            f"retry of {parent_key} lease expired before dispatch; "
            f"safely reclaimable",
        )

    # Lease still valid — in flight
    return Classification(
        RecoveryState.RETRY_ATTEMPT_IN_FLIGHT,
        f"retry of {parent_key} in progress",
    )


# Severity ranking: higher = more operator attention needed.
# ChatGPT T7 re-review fix 3: RETRY_UNKNOWN and LEGACY must outrank
# RETRY_COMPLETED so unresolved uncertainty wins over successful closure.
_SEVERITY_ORDER = [
    RecoveryState.RETRY_COMPLETED,               # 0 — least attention
    RecoveryState.RETRY_ATTEMPT_IN_FLIGHT,       # 1
    RecoveryState.RETRY_AUTHORIZED_PENDING_EXECUTION,  # 2
    RecoveryState.RETRY_FAILED,                  # 3
    RecoveryState.LEGACY_NOT_REPLAYABLE,         # 4
    RecoveryState.RETRY_UNKNOWN,                 # 5 — most attention
]


def _severity_rank(state: RecoveryState) -> int:
    """Higher rank = more operator attention needed."""
    try:
        return _SEVERITY_ORDER.index(state)
    except ValueError:
        return 0
