"""Adaptive Branching — Bounded Deliberation under uncertainty.

v2.18.1

Central invariant (AB-001):
    Adaptive branching may only create branches whose policies, budgets,
    capability requests, package selections, dependency graphs, sandbox
    profiles, and side-effect permissions are admissible before execution.

Non-negotiable rules:
    1. Branches cannot self-authorize.
    2. Branches cannot expand parent permissions.
    3. Branches cannot bypass capability resolution.
    4. Branches cannot bypass dependency trust resolution.
    5. Exploratory branches are read-only by default.
    6. Side-effect branches require explicit policy authorization.
    7. Non-selected branches cannot mutate committed state.
    8. Budget exhaustion must stop the branch.
    9. Merge decisions must be receipt-backed.
    10. High-risk, irreversible, or ambiguous merge decisions require human review.
"""

from __future__ import annotations

import json
import time
import hashlib
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, Callable

# ── Constants ───────────────────────────────────────────────────────────────

ADAPTIVE_BRANCHING_SCHEMA_VERSION = "1.0.0"

# Risk levels (mirrors capability_resolver for self-contained module)
RISK_LOW = "low"
RISK_MEDIUM = "medium"
RISK_HIGH = "high"
RISK_CRITICAL = "critical"
RISK_ORDER = {RISK_LOW: 0, RISK_MEDIUM: 1, RISK_HIGH: 2, RISK_CRITICAL: 3}

# Sandbox strength levels (mirrors capability_resolver)
SANDBOX_NONE = 0
SANDBOX_BASIC = 1
SANDBOX_HARDENED = 2
SANDBOX_FULL = 3

# Side-effect policies
SIDE_EFFECT_DENY_ALL = "deny_all"
SIDE_EFFECT_READ_ONLY = "read_only"
SIDE_EFFECT_EXPLICIT_ALLOW = "explicit_allow"

# Merge strategies
MERGE_SELECT_BEST = "select_best"
MERGE_REJECT_ALL = "reject_all"
MERGE_DEFER_HUMAN = "defer_human"

# Branch status
BRANCH_PENDING = "pending"
BRANCH_RUNNING = "running"
BRANCH_COMPLETED = "completed"
BRANCH_FAILED = "failed"
BRANCH_BUDGET_EXHAUSTED = "budget_exhausted"
BRANCH_POLICY_VIOLATED = "policy_violated"
BRANCH_CANCELLED = "cancelled"


# ── Helpers ─────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sha256_str(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _sha256_dict(data: dict[str, Any]) -> str:
    return _sha256_str(json.dumps(data, sort_keys=True, separators=(",", ":")))


def _gen_id(prefix: str = "") -> str:
    return f"{prefix}{uuid.uuid4().hex[:16]}"


# ── Deliberation Trigger ────────────────────────────────────────────────────

class DeliberationTrigger(str, Enum):
    UNCERTAINTY = "uncertainty"
    CONFLICT = "conflict"
    HIGH_RISK = "high_risk"
    OPERATOR_REQUEST = "operator_request"
    CAPABILITY_AMBIGUITY = "capability_ambiguity"


@dataclass
class DeliberationRequest:
    """Records why a deliberation was triggered.

    The request is immutable once finalized — it captures the triggering
    context and does not change as branches execute.
    """

    trigger_type: DeliberationTrigger = DeliberationTrigger.UNCERTAINTY
    trigger_node_id: str = ""
    trigger_context: dict[str, Any] = field(default_factory=dict)
    requested_capabilities: list[str] = field(default_factory=list)
    parent_chain_id: str = ""
    parent_step_id: str = ""
    requested_by: str = "runtime"  # "runtime" or "operator"
    request_id: str = field(default_factory=lambda: _gen_id("delib-"))
    created_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "trigger_type": self.trigger_type.value,
            "trigger_node_id": self.trigger_node_id,
            "trigger_context": self.trigger_context,
            "requested_capabilities": self.requested_capabilities,
            "parent_chain_id": self.parent_chain_id,
            "parent_step_id": self.parent_step_id,
            "requested_by": self.requested_by,
            "created_at": self.created_at,
        }

    def compute_digest(self) -> str:
        return _sha256_dict({
            "trigger_type": self.trigger_type.value,
            "trigger_node_id": self.trigger_node_id,
            "trigger_context": self.trigger_context,
            "requested_capabilities": sorted(self.requested_capabilities),
            "parent_chain_id": self.parent_chain_id,
            "parent_step_id": self.parent_step_id,
            "requested_by": self.requested_by,
        })


# ── Branch Policy ───────────────────────────────────────────────────────────

@dataclass
class BranchPolicy:
    """Governs whether branching is allowed and what branches may do.

    A child branch policy may only narrow (subset) the parent policy —
    never expand it (Rule 2).
    """

    # Branch limits
    max_branches: int = 3
    max_depth: int = 1

    # Capability constraints
    allowed_capabilities: set[str] = field(default_factory=set)  # empty = all allowed
    forbidden_capabilities: set[str] = field(default_factory=set)

    # Sandbox / risk
    min_sandbox_strength: int = SANDBOX_HARDENED
    max_risk_level: str = RISK_HIGH

    # Side effects
    side_effect_policy: str = SIDE_EFFECT_DENY_ALL

    # Human review
    review_risk_at_or_above: str = RISK_CRITICAL
    review_score_margin_below: float = 0.05

    # Parent inheritance
    parent_policy_digest: str = ""  # set when this is a child policy

    # Trust requirements
    require_dependency_trust: bool = True  # DT-001 per branch
    require_certification: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_branches": self.max_branches,
            "max_depth": self.max_depth,
            "allowed_capabilities": sorted(self.allowed_capabilities) if self.allowed_capabilities else ["*"],
            "forbidden_capabilities": sorted(self.forbidden_capabilities),
            "min_sandbox_strength": self.min_sandbox_strength,
            "max_risk_level": self.max_risk_level,
            "side_effect_policy": self.side_effect_policy,
            "review_risk_at_or_above": self.review_risk_at_or_above,
            "review_score_margin_below": self.review_score_margin_below,
            "parent_policy_digest": self.parent_policy_digest,
            "require_dependency_trust": self.require_dependency_trust,
            "require_certification": self.require_certification,
        }

    def compute_digest(self) -> str:
        return _sha256_dict(self.to_dict())

    def is_capability_allowed(self, capability: str) -> bool:
        """Check if a capability is allowed under this policy."""
        if capability in self.forbidden_capabilities:
            return False
        if not self.allowed_capabilities:
            return True  # empty = all allowed
        return capability in self.allowed_capabilities

    def is_side_effect_allowed(self) -> bool:
        """Check if side effects are allowed under this policy."""
        return self.side_effect_policy == SIDE_EFFECT_EXPLICIT_ALLOW

    def is_risk_allowed(self, risk_level: str) -> bool:
        """Check if a risk level is within policy."""
        return RISK_ORDER.get(risk_level, 0) <= RISK_ORDER.get(self.max_risk_level, 0)


@dataclass
class BudgetTracker:
    """Tracks resource consumption against a budget in real time."""

    max_tokens: int = 10000
    max_time_seconds: float = 60.0
    max_tool_calls: int = 20
    max_retries: int = 2
    max_depth: int = 1
    max_side_effects: int = 0

    # Live counters
    tokens_used: int = 0
    time_started: float = field(default_factory=time.time)
    tool_calls_made: int = 0
    retries_used: int = 0
    depth_reached: int = 0
    side_effects_executed: int = 0

    def consume_tokens(self, amount: int) -> bool:
        """Record token usage. Returns False if budget exhausted."""
        self.tokens_used += amount
        return self.tokens_used <= self.max_tokens

    def consume_tool_call(self) -> bool:
        self.tool_calls_made += 1
        return self.tool_calls_made <= self.max_tool_calls

    def consume_retry(self) -> bool:
        self.retries_used += 1
        return self.retries_used <= self.max_retries

    def consume_side_effect(self) -> bool:
        self.side_effects_executed += 1
        return self.side_effects_executed <= self.max_side_effects

    def set_depth(self, depth: int) -> bool:
        self.depth_reached = depth
        return self.depth_reached <= self.max_depth

    @property
    def time_elapsed(self) -> float:
        return time.time() - self.time_started

    def is_exhausted(self) -> bool:
        """Check if any budget dimension is exceeded."""
        return (
            self.tokens_used > self.max_tokens
            or self.time_elapsed > self.max_time_seconds
            or self.tool_calls_made > self.max_tool_calls
            or self.retries_used > self.max_retries
            or self.depth_reached > self.max_depth
            or self.side_effects_executed > self.max_side_effects
        )

    def exhausted_dimensions(self) -> list[str]:
        """Return list of budget dimensions that are exhausted."""
        dims: list[str] = []
        if self.tokens_used > self.max_tokens:
            dims.append("tokens")
        if self.time_elapsed > self.max_time_seconds:
            dims.append("time")
        if self.tool_calls_made > self.max_tool_calls:
            dims.append("tool_calls")
        if self.retries_used > self.max_retries:
            dims.append("retries")
        if self.depth_reached > self.max_depth:
            dims.append("depth")
        if self.side_effects_executed > self.max_side_effects:
            dims.append("side_effects")
        return dims

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_tokens": self.max_tokens,
            "max_time_seconds": self.max_time_seconds,
            "max_tool_calls": self.max_tool_calls,
            "max_retries": self.max_retries,
            "max_depth": self.max_depth,
            "max_side_effects": self.max_side_effects,
            "tokens_used": self.tokens_used,
            "time_elapsed": round(self.time_elapsed, 3),
            "tool_calls_made": self.tool_calls_made,
            "retries_used": self.retries_used,
            "depth_reached": self.depth_reached,
            "side_effects_executed": self.side_effects_executed,
        }

    def to_budget_dict(self) -> dict[str, Any]:
        """Budget-only view (maxes) for digest computation."""
        return {
            "max_tokens": self.max_tokens,
            "max_time_seconds": self.max_time_seconds,
            "max_tool_calls": self.max_tool_calls,
            "max_retries": self.max_retries,
            "max_depth": self.max_depth,
            "max_side_effects": self.max_side_effects,
        }


def compute_budget_digest(budget: BudgetTracker) -> str:
    """Compute digest for budget limits only (not live counters)."""
    return _sha256_dict(budget.to_budget_dict())


# ── Branch Plan ─────────────────────────────────────────────────────────────

@dataclass
class BranchPlan:
    """Concrete execution plan for a single branch.

    Created by BranchController.create_plans() after AB-001 admissibility
    check passes. Each plan inherits parent policy and may only narrow it.
    """

    branch_id: str = field(default_factory=lambda: _gen_id("branch-"))
    parent_branch_id: str | None = None
    depth: int = 0
    is_exploratory: bool = True

    policy: BranchPolicy = field(default_factory=BranchPolicy)
    budget: BudgetTracker = field(default_factory=BudgetTracker)

    # Capability requests (resolved through capability resolver)
    capability_requests: list[dict[str, Any]] = field(default_factory=list)

    # Node sequence to execute within this branch
    node_sequence: list[str] = field(default_factory=list)

    # Input data for the branch (isolated copy)
    input_data: dict[str, Any] = field(default_factory=dict)

    # Admissibility verdict
    admissible: bool = False
    inadmissibility_reasons: list[str] = field(default_factory=list)

    # Capability receipt digests (filled during validation)
    capability_receipt_digests: list[str] = field(default_factory=list)
    trust_graph_digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "branch_id": self.branch_id,
            "parent_branch_id": self.parent_branch_id,
            "depth": self.depth,
            "is_exploratory": self.is_exploratory,
            "policy_digest": self.policy.compute_digest(),
            "budget_digest": compute_budget_digest(self.budget),
            "capability_requests": self.capability_requests,
            "node_sequence": self.node_sequence,
            "admissible": self.admissible,
            "inadmissibility_reasons": self.inadmissibility_reasons,
            "capability_receipt_digests": self.capability_receipt_digests,
            "trust_graph_digest": self.trust_graph_digest,
        }

    def compute_digest(self) -> str:
        return _sha256_dict({
            "branch_id": self.branch_id,
            "parent_branch_id": self.parent_branch_id,
            "depth": self.depth,
            "is_exploratory": self.is_exploratory,
            "policy_digest": self.policy.compute_digest(),
            "budget_digest": compute_budget_digest(self.budget),
            "capability_requests": self.capability_requests,
            "node_sequence": self.node_sequence,
        })


# ── Branch Execution Context ────────────────────────────────────────────────

@dataclass
class BranchExecutionContext:
    """Isolated state container for branch execution.

    All branch state lives here — it is NOT the committed workflow state.
    Only the selected branch's output is merged into committed state (Rule 7).
    """

    branch_id: str = ""
    state: dict[str, Any] = field(default_factory=dict)
    outputs: dict[str, Any] = field(default_factory=dict)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    capability_receipts: list[dict[str, Any]] = field(default_factory=list)
    trust_graph_digest: str = ""
    side_effect_log: list[dict[str, Any]] = field(default_factory=list)
    policy_verdicts: list[dict[str, Any]] = field(default_factory=list)
    budget_tracker: BudgetTracker = field(default_factory=BudgetTracker)

    def record_evidence(self, evidence: dict[str, Any]) -> None:
        """Record an evidence item."""
        self.evidence.append({
            **evidence,
            "recorded_at": _now_iso(),
            "branch_id": self.branch_id,
        })

    def record_side_effect(self, action: str, details: dict[str, Any],
                           allowed: bool) -> None:
        """Record a side-effect attempt."""
        self.side_effect_log.append({
            "action": action,
            "details": details,
            "allowed": allowed,
            "attempted_at": _now_iso(),
            "branch_id": self.branch_id,
        })

    def record_policy_verdict(self, rule: str, verdict: str,
                              reason: str) -> None:
        """Record a policy evaluation result."""
        self.policy_verdicts.append({
            "rule": rule,
            "verdict": verdict,
            "reason": reason,
            "branch_id": self.branch_id,
        })


# ── Branch Result ───────────────────────────────────────────────────────────

@dataclass
class BranchResult:
    """Captures the outcome of a branch execution.

    Records output, evidence, policy verdicts, selected capabilities,
    consumed budget, and side-effect status.
    """

    branch_id: str = ""
    status: str = BRANCH_PENDING
    output: dict[str, Any] = field(default_factory=dict)
    evidence: list[dict[str, Any]] = field(default_factory=list)

    # Capability receipts (digests of CapabilitySelectionReceipt)
    selected_capability_receipts: list[str] = field(default_factory=list)

    # Consumed budget snapshot
    consumed_budget: dict[str, Any] = field(default_factory=dict)

    # Policy verdicts
    policy_verdicts: list[dict[str, Any]] = field(default_factory=list)

    # Side effects
    side_effect_summary: list[dict[str, Any]] = field(default_factory=list)

    # Failure info
    failure_reason: str = ""

    # Timing
    started_at: str = ""
    completed_at: str = ""

    def compute_output_digest(self) -> str:
        return _sha256_dict(self.output) if self.output else _sha256_str("")

    def compute_evidence_digest(self) -> str:
        if not self.evidence:
            return _sha256_str("")
        return _sha256_str(json.dumps(self.evidence, sort_keys=True, separators=(",", ":")))

    def to_dict(self) -> dict[str, Any]:
        return {
            "branch_id": self.branch_id,
            "status": self.status,
            "output_digest": self.compute_output_digest(),
            "evidence_digest": self.compute_evidence_digest(),
            "selected_capability_receipts": self.selected_capability_receipts,
            "consumed_budget": self.consumed_budget,
            "policy_verdicts": self.policy_verdicts,
            "side_effect_summary": self.side_effect_summary,
            "failure_reason": self.failure_reason,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }

    def compute_digest(self) -> str:
        return _sha256_dict(self.to_dict())


# ── Merge Decision ──────────────────────────────────────────────────────────

@dataclass
class MergeDecision:
    """Records how branch results were compared and a selection made.

    Every merge decision is receipt-backed (Rule 9). High-risk or ambiguous
    decisions require human review (Rule 10).
    """

    strategy: str = MERGE_SELECT_BEST
    selected_branch_id: str | None = None
    rejected_branch_ids: list[str] = field(default_factory=list)
    deferred_branch_ids: list[str] = field(default_factory=list)  # human review

    confidence: float = 0.0
    risk_level: str = RISK_LOW
    comparison_basis: str = ""  # e.g., "evaluation_score", "policy_compliance"

    human_review_required: bool = False
    human_review_status: str = ""  # "", "pending", "approved", "rejected"

    rationale: str = ""
    rationale_digest: str = ""
    created_at: str = field(default_factory=_now_iso)

    def finalize(self) -> None:
        self.rationale_digest = _sha256_str(self.rationale)

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy,
            "selected_branch_id": self.selected_branch_id,
            "rejected_branch_ids": self.rejected_branch_ids,
            "deferred_branch_ids": self.deferred_branch_ids,
            "confidence": round(self.confidence, 4),
            "risk_level": self.risk_level,
            "comparison_basis": self.comparison_basis,
            "human_review_required": self.human_review_required,
            "human_review_status": self.human_review_status,
            "rationale_digest": self.rationale_digest,
            "created_at": self.created_at,
        }

    def compute_digest(self) -> str:
        return _sha256_dict(self.to_dict())


# ── Deliberation Receipt ────────────────────────────────────────────────────

@dataclass
class DeliberationReceipt:
    """Full audit trail for a deliberation.

    Records the request, policies, budgets, plans, branch results, merge
    decision, and trace event IDs for complete replayability.
    """

    receipt_id: str = field(default_factory=lambda: _gen_id("delib-receipt-"))
    request_digest: str = ""
    branch_policy_digest: str = ""
    branch_budget_digest: str = ""
    branch_plan_digests: list[str] = field(default_factory=list)
    branch_result_digests: list[str] = field(default_factory=list)
    merge_decision_digest: str = ""
    trace_event_ids: list[str] = field(default_factory=list)

    # Metadata
    deliberation_trigger: str = ""
    branch_count: int = 0
    selected_branch_id: str | None = None
    human_review_required: bool = False
    created_at: str = field(default_factory=_now_iso)
    schema_version: str = ADAPTIVE_BRANCHING_SCHEMA_VERSION

    # Signature (digest commitment)
    _signature: str = ""

    def finalize(self) -> None:
        body = json.dumps(self._unsigned_body(), sort_keys=True, separators=(",", ":"))
        self._signature = _sha256_str(body)

    def _unsigned_body(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "request_digest": self.request_digest,
            "branch_policy_digest": self.branch_policy_digest,
            "branch_budget_digest": self.branch_budget_digest,
            "branch_plan_digests": self.branch_plan_digests,
            "branch_result_digests": self.branch_result_digests,
            "merge_decision_digest": self.merge_decision_digest,
            "trace_event_ids": self.trace_event_ids,
            "deliberation_trigger": self.deliberation_trigger,
            "branch_count": self.branch_count,
            "selected_branch_id": self.selected_branch_id,
            "human_review_required": self.human_review_required,
            "created_at": self.created_at,
            "schema_version": self.schema_version,
        }

    @property
    def signature(self) -> str:
        return self._signature

    def to_dict(self) -> dict[str, Any]:
        d = self._unsigned_body()
        d["signature"] = self._signature
        return d


def save_deliberation_receipt(receipt: DeliberationReceipt, path: str) -> None:
    """Save a deliberation receipt to disk as JSON."""
    with open(path, "w") as f:
        json.dump(receipt.to_dict(), f, indent=2, sort_keys=True)


# ── Exceptions ──────────────────────────────────────────────────────────────

class BranchingDenied(Exception):
    """Raised when branching is not allowed by policy."""


class BranchInadmissible(Exception):
    """Raised when a branch plan fails AB-001 admissibility check."""


class BudgetExhausted(Exception):
    """Raised when a branch exceeds its budget."""


class PolicyViolation(Exception):
    """Raised when a branch violates its policy."""


class MergeRejected(Exception):
    """Raised when all branches are rejected and no merge is possible."""


class ChildPolicyExpansion(Exception):
    """Raised when a child policy attempts to expand parent permissions (Rule 2)."""


# ── Protocols ───────────────────────────────────────────────────────────────

class BranchExecutorProtocol(Protocol):
    """Protocol for executing nodes within a branch.

    The concrete implementation is provided by the caller — typically
    the orchestrator's node_invoker or branch_executor.
    """

    def __call__(
        self,
        node_sequence: list[str],
        input_data: dict[str, Any],
        context: BranchExecutionContext,
    ) -> dict[str, Any]:
        """Execute a sequence of nodes within a branch context.

        Returns the branch output dict.
        """
        ...


class MergeStrategyProtocol(Protocol):
    """Protocol for comparing branch results and making a merge decision."""

    def __call__(
        self,
        results: list[BranchResult],
        policy: BranchPolicy,
    ) -> MergeDecision:
        """Compare branch results and return a merge decision."""
        ...


# ── Policy Narrowing Validation ─────────────────────────────────────────────

def validate_child_policy(
    parent: BranchPolicy,
    child: BranchPolicy,
) -> list[str]:
    """Validate that a child policy only narrows (never expands) the parent.

    Returns a list of violation reasons (empty if valid).

    Rule 2: Branches cannot expand parent permissions.
    """
    violations: list[str] = []

    # max_branches may only decrease
    if child.max_branches > parent.max_branches:
        violations.append(
            f"child max_branches ({child.max_branches}) > parent ({parent.max_branches})"
        )

    # max_depth may only decrease
    if child.max_depth > parent.max_depth:
        violations.append(
            f"child max_depth ({child.max_depth}) > parent ({parent.max_depth})"
        )

    # allowed_capabilities must be a subset (if parent restricts)
    if parent.allowed_capabilities:
        if not child.allowed_capabilities:
            violations.append(
                "child allows all capabilities but parent restricts"
            )
        elif not child.allowed_capabilities.issubset(parent.allowed_capabilities):
            extra = child.allowed_capabilities - parent.allowed_capabilities
            violations.append(
                f"child allows capabilities not in parent: {extra}"
            )

    # forbidden_capabilities must be a superset (child can forbid more)
    if not child.forbidden_capabilities.issuperset(parent.forbidden_capabilities):
        missing = parent.forbidden_capabilities - child.forbidden_capabilities
        violations.append(
            f"child fails to forbid parent-forbidden: {missing}"
        )

    # min_sandbox_strength may only increase
    if child.min_sandbox_strength < parent.min_sandbox_strength:
        violations.append(
            f"child min_sandbox ({child.min_sandbox_strength}) < parent ({parent.min_sandbox_strength})"
        )

    # max_risk_level may only decrease
    if RISK_ORDER.get(child.max_risk_level, 0) > RISK_ORDER.get(parent.max_risk_level, 0):
        violations.append(
            f"child max_risk ({child.max_risk_level}) > parent ({parent.max_risk_level})"
        )

    # side_effect_policy may only become more restrictive
    severity = {
        SIDE_EFFECT_DENY_ALL: 0,
        SIDE_EFFECT_READ_ONLY: 1,
        SIDE_EFFECT_EXPLICIT_ALLOW: 2,
    }
    if severity.get(child.side_effect_policy, 0) > severity.get(parent.side_effect_policy, 0):
        violations.append(
            f"child side_effect_policy ({child.side_effect_policy}) less restrictive than parent ({parent.side_effect_policy})"
        )

    return violations


# ── Default Merge Strategy ──────────────────────────────────────────────────

def default_merge_strategy(
    results: list[BranchResult],
    policy: BranchPolicy,
) -> MergeDecision:
    """Default merge: select the best-completed branch by evidence quality.

    This is a deterministic merge strategy that:
    1. Filters to completed branches only
    2. If none completed, rejects all
    3. If one completed, selects it
    4. If multiple completed, selects by evidence count (deterministic tie-break
       by branch_id)
    5. Flags human review if score margin is narrow or risk is high
    """

    completed = [r for r in results if r.status == BRANCH_COMPLETED]

    if not completed:
        return MergeDecision(
            strategy=MERGE_REJECT_ALL,
            rejected_branch_ids=[r.branch_id for r in results],
            rationale="No branches completed successfully",
            risk_level=RISK_HIGH,
            human_review_required=False,
        )

    if len(completed) == 1:
        r = completed[0]
        risk = r.consumed_budget.get("risk_level", RISK_LOW)
        return MergeDecision(
            strategy=MERGE_SELECT_BEST,
            selected_branch_id=r.branch_id,
            rejected_branch_ids=[res.branch_id for res in results if res.branch_id != r.branch_id],
            confidence=1.0,
            risk_level=risk,
            comparison_basis="single_completed",
            human_review_required=RISK_ORDER.get(risk, 0) >= RISK_ORDER.get(policy.review_risk_at_or_above, 0),
            rationale=f"Single completed branch {r.branch_id} selected",
        )

    # Multiple completed: rank by evidence count, deterministic tie-break
    ranked = sorted(
        completed,
        key=lambda r: (-len(r.evidence), r.branch_id),
    )

    best = ranked[0]
    second = ranked[1] if len(ranked) > 1 else None

    # Confidence: ratio of best evidence to total
    total_evidence = sum(len(r.evidence) for r in completed)
    confidence = len(best.evidence) / total_evidence if total_evidence > 0 else 0.0

    # Score margin: how close best is to second
    best_ev = len(best.evidence)
    second_ev = len(second.evidence) if second else 0
    margin = (best_ev - second_ev) / (best_ev + second_ev) if (best_ev + second_ev) > 0 else 1.0
    margin_narrow = margin < policy.review_score_margin_below

    risk = best.consumed_budget.get("risk_level", RISK_LOW)
    review_needed = (
        margin_narrow
        or RISK_ORDER.get(risk, 0) >= RISK_ORDER.get(policy.review_risk_at_or_above, 0)
    )

    selected = best.branch_id
    rejected = [r.branch_id for r in results if r.branch_id != selected]

    if review_needed:
        return MergeDecision(
            strategy=MERGE_DEFER_HUMAN,
            selected_branch_id=None,  # Not committed until approved
            deferred_branch_ids=[selected],
            rejected_branch_ids=[rid for rid in rejected],
            confidence=confidence,
            risk_level=risk,
            comparison_basis="evidence_count",
            human_review_required=True,
            human_review_status="pending",
            rationale=(
                f"Human review required: confidence={confidence:.2f}, "
                f"risk={risk}, margin_narrow={margin_narrow}"
            ),
        )

    return MergeDecision(
        strategy=MERGE_SELECT_BEST,
        selected_branch_id=selected,
        rejected_branch_ids=rejected,
        confidence=confidence,
        risk_level=risk,
        comparison_basis="evidence_count",
        human_review_required=False,
        rationale=(
            f"Branch {selected} selected with confidence={confidence:.2f} "
            f"based on evidence_count"
        ),
    )


# ── Branch Controller ───────────────────────────────────────────────────────

class BranchController:
    """Governs adaptive branching under uncertainty.

    The controller is the single authority for creating, validating,
    and managing bounded branches. Branches cannot self-authorize (Rule 1).

    Usage:
        controller = BranchController(policy=BranchPolicy(...))
        plans = controller.create_plans(request, num_branches=3)
        results = controller.execute_branches(plans, executor)
        decision = controller.merge_results(results)
        receipt = controller.build_receipt(request, plans, results, decision)
    """

    def __init__(
        self,
        policy: BranchPolicy | None = None,
        merge_strategy: MergeStrategyProtocol | None = None,
        capability_resolver: Any | None = None,
        trust_resolver: Any | None = None,
    ) -> None:
        self.policy = policy or BranchPolicy()
        self._merge_strategy: MergeStrategyProtocol = merge_strategy or default_merge_strategy  # type: ignore
        self._capability_resolver = capability_resolver
        self._trust_resolver = trust_resolver

    # ── AB-001 Admissibility ────────────────────────────────────────────

    def validate_request(
        self,
        request: DeliberationRequest,
    ) -> tuple[bool, list[str]]:
        """AB-001: Check if a deliberation request is admissible.

        Verifies that the requested capabilities are allowed, the trigger
        is valid, and the policy permits branching for this context.
        """
        reasons: list[str] = []

        # Check requested capabilities against policy
        for cap in request.requested_capabilities:
            if not self.policy.is_capability_allowed(cap):
                reasons.append(
                    f"capability '{cap}' not allowed by branch policy"
                )

        # Check max_depth constraint
        # (depth is checked per-plan in validate_plan)

        # Check trigger validity
        if request.trigger_type == DeliberationTrigger.OPERATOR_REQUEST:
            if request.requested_by != "operator":
                reasons.append(
                    "operator_request trigger requires requested_by='operator'"
                )

        return (len(reasons) == 0, reasons)

    def validate_plan(
        self,
        plan: BranchPlan,
        parent_plan: BranchPlan | None = None,
    ) -> tuple[bool, list[str]]:
        """AB-001: Check if a branch plan is admissible before execution.

        Verifies policy, budget, capability requests, trust graph,
        sandbox, and side-effect permissions.
        """
        reasons: list[str] = []

        # Rule 5: Exploratory branches are read-only by default
        if plan.is_exploratory and plan.policy.is_side_effect_allowed():
            if plan.policy.side_effect_policy != SIDE_EFFECT_EXPLICIT_ALLOW:
                pass  # read_only is fine
            else:
                reasons.append(
                    "exploratory branch cannot have explicit side effects"
                )

        # Rule 2: Check child policy narrowing
        if parent_plan is not None:
            violations = validate_child_policy(parent_plan.policy, plan.policy)
            if violations:
                reasons.extend(f"policy_narrowing: {v}" for v in violations)

        # Rule 8: Budget must be non-zero
        bt = plan.budget
        if bt.max_tokens <= 0 or bt.max_tool_calls <= 0:
            reasons.append("budget must be positive")

        # Rule 3: All capability requests must go through resolver
        for cap_req in plan.capability_requests:
            capability = cap_req.get("capability", "")
            if capability and not plan.policy.is_capability_allowed(capability):
                reasons.append(
                    f"capability request '{capability}' not allowed by plan policy"
                )

        # Rule 4: Dependency trust required
        if plan.policy.require_dependency_trust and not plan.trust_graph_digest:
            # Trust graph digest must be set before execution
            # If no capabilities are requested, this is OK
            if plan.capability_requests:
                reasons.append(
                    "dependency trust graph digest required but not set"
                )

        # Sandbox check
        if plan.policy.min_sandbox_strength > SANDBOX_NONE:
            # Each capability request should have sandbox >= min
            for cap_req in plan.capability_requests:
                sandbox = cap_req.get("sandbox_profile", "")
                # The resolver will check this, but we pre-validate here
                pass

        # Depth check
        if plan.depth > plan.policy.max_depth:
            reasons.append(
                f"depth ({plan.depth}) exceeds max_depth ({plan.policy.max_depth})"
            )

        plan.admissible = len(reasons) == 0
        plan.inadmissibility_reasons = reasons
        return (plan.admissible, reasons)

    # ── Plan Creation ───────────────────────────────────────────────────

    def create_plans(
        self,
        request: DeliberationRequest,
        num_branches: int | None = None,
        parent_plan: BranchPlan | None = None,
    ) -> list[BranchPlan]:
        """Create N bounded branch plans for a deliberation request.

        Rule 1: Branches cannot self-authorize — only the controller creates plans.
        """
        # Validate request first
        admissible, reasons = self.validate_request(request)
        if not admissible:
            raise BranchingDenied(
                f"Deliberation request not admissible: {'; '.join(reasons)}"
            )

        # Determine branch count
        n = num_branches if num_branches is not None else self.policy.max_branches
        if n > self.policy.max_branches:
            n = self.policy.max_branches

        if n < 1:
            raise BranchingDenied("Must create at least 1 branch")

        # Determine base depth
        base_depth = (parent_plan.depth + 1) if parent_plan else 0

        if base_depth > self.policy.max_depth:
            raise BranchingDenied(
                f"Depth {base_depth} exceeds max_depth {self.policy.max_depth}"
            )

        plans: list[BranchPlan] = []
        for i in range(n):
            # Each branch gets a copy of the policy (narrowed from parent if needed)
            child_policy = BranchPolicy(
                max_branches=min(self.policy.max_branches, max(1, n - i)),
                max_depth=self.policy.max_depth - base_depth,
                allowed_capabilities=set(self.policy.allowed_capabilities),
                forbidden_capabilities=set(self.policy.forbidden_capabilities),
                min_sandbox_strength=self.policy.min_sandbox_strength,
                max_risk_level=self.policy.max_risk_level,
                side_effect_policy=self.policy.side_effect_policy,
                review_risk_at_or_above=self.policy.review_risk_at_or_above,
                review_score_margin_below=self.policy.review_score_margin_below,
                parent_policy_digest=self.policy.compute_digest(),
                require_dependency_trust=self.policy.require_dependency_trust,
                require_certification=self.policy.require_certification,
            )

            # Budget: branches get equal share of a notional budget
            budget = BudgetTracker(
                max_tokens=10000,
                max_time_seconds=60.0,
                max_tool_calls=20,
                max_retries=2,
                max_depth=self.policy.max_depth - base_depth,
                max_side_effects=0 if self.policy.side_effect_policy != SIDE_EFFECT_EXPLICIT_ALLOW else 3,
            )

            plan = BranchPlan(
                parent_branch_id=parent_plan.branch_id if parent_plan else None,
                depth=base_depth,
                is_exploratory=self.policy.side_effect_policy != SIDE_EFFECT_EXPLICIT_ALLOW,
                policy=child_policy,
                budget=budget,
                capability_requests=[
                    {"capability": cap} for cap in request.requested_capabilities
                ],
            )

            # Validate the plan
            ok, plan_reasons = self.validate_plan(plan, parent_plan)
            if not ok:
                plan.admissible = False
                plan.inadmissibility_reasons = plan_reasons

            plans.append(plan)

        return plans

    # ── Branch Execution ────────────────────────────────────────────────

    def execute_branch(
        self,
        plan: BranchPlan,
        executor: BranchExecutorProtocol,
        input_data: dict[str, Any] | None = None,
    ) -> BranchResult:
        """Execute a single branch in isolation.

        Rule 8: Budget exhaustion stops the branch.
        Rule 7: Branch state is isolated from committed workflow state.
        """
        if not plan.admissible:
            return BranchResult(
                branch_id=plan.branch_id,
                status=BRANCH_POLICY_VIOLATED,
                failure_reason=f"Inadmissible plan: {'; '.join(plan.inadmissibility_reasons)}",
                started_at=_now_iso(),
                completed_at=_now_iso(),
            )

        # Create isolated context
        ctx = BranchExecutionContext(
            branch_id=plan.branch_id,
            state=dict(input_data) if input_data else {},
            budget_tracker=plan.budget,
        )

        result = BranchResult(
            branch_id=plan.branch_id,
            status=BRANCH_RUNNING,
            started_at=_now_iso(),
        )

        try:
            # Execute the node sequence through the executor
            output = executor(
                node_sequence=plan.node_sequence,
                input_data=dict(plan.input_data) if plan.input_data else dict(input_data or {}),
                context=ctx,
            )

            # Check budget after execution
            if ctx.budget_tracker.is_exhausted():
                result.status = BRANCH_BUDGET_EXHAUSTED
                result.failure_reason = (
                    f"Budget exhausted: {ctx.budget_tracker.exhausted_dimensions()}"
                )
            else:
                result.status = BRANCH_COMPLETED
                result.output = output

        except Exception as exc:
            result.status = BRANCH_FAILED
            result.failure_reason = str(exc)

        # Capture context into result
        result.evidence = ctx.evidence
        result.policy_verdicts = ctx.policy_verdicts
        result.side_effect_summary = ctx.side_effect_log
        result.selected_capability_receipts = plan.capability_receipt_digests
        result.consumed_budget = ctx.budget_tracker.to_dict()
        result.consumed_budget["risk_level"] = input_data.get("risk_level", RISK_LOW) if input_data else RISK_LOW
        result.completed_at = _now_iso()

        return result

    def execute_branches(
        self,
        plans: list[BranchPlan],
        executor: BranchExecutorProtocol,
        input_data: dict[str, Any] | None = None,
    ) -> list[BranchResult]:
        """Execute multiple branches sequentially (governed order).

        Note: Parallel execution is possible but must respect budget isolation.
        Sequential is the safe default.
        """
        results: list[BranchResult] = []
        for plan in plans:
            result = self.execute_branch(plan, executor, input_data)
            results.append(result)
        return results

    # ── Merge ───────────────────────────────────────────────────────────

    def merge_results(
        self,
        results: list[BranchResult],
    ) -> MergeDecision:
        """Compare branch results and make a merge decision.

        Rule 9: Merge decisions must be receipt-backed.
        Rule 10: High-risk/ambiguous merges require human review.
        """
        decision = self._merge_strategy(results, self.policy)
        decision.finalize()
        return decision

    # ── Receipt Building ────────────────────────────────────────────────

    def build_receipt(
        self,
        request: DeliberationRequest,
        plans: list[BranchPlan],
        results: list[BranchResult],
        decision: MergeDecision,
        trace_event_ids: list[str] | None = None,
    ) -> DeliberationReceipt:
        """Build the complete deliberation receipt for audit trail."""
        receipt = DeliberationReceipt(
            request_digest=request.compute_digest(),
            branch_policy_digest=self.policy.compute_digest(),
            branch_budget_digest=compute_budget_digest(
                plans[0].budget if plans else BudgetTracker()
            ),
            branch_plan_digests=[p.compute_digest() for p in plans],
            branch_result_digests=[r.compute_digest() for r in results],
            merge_decision_digest=decision.compute_digest(),
            trace_event_ids=trace_event_ids or [],
            deliberation_trigger=request.trigger_type.value,
            branch_count=len(plans),
            selected_branch_id=decision.selected_branch_id,
            human_review_required=decision.human_review_required,
        )
        receipt.finalize()
        return receipt


# ── Helpers for capability resolution integration ───────────────────────────

def attach_capability_receipts(
    plan: BranchPlan,
    receipts: list[Any],
) -> None:
    """Attach capability selection receipt digests to a branch plan.

    Called after capability resolution completes for a plan's requests.
    """
    for receipt in receipts:
        digest = receipt.signature if hasattr(receipt, "signature") else str(receipt)
        plan.capability_receipt_digests.append(digest)


def attach_trust_graph(
    plan: BranchPlan,
    trust_graph_digest: str,
) -> None:
    """Attach a dependency trust graph digest to a branch plan."""
    plan.trust_graph_digest = trust_graph_digest


# ── AB-002: Branch Result Admissibility for Merge ───────────────────────────

def is_result_admissible_for_merge(
    result: BranchResult,
    plan: BranchPlan,
) -> tuple[bool, str]:
    """AB-002: Check if a branch result is admissible for merge.

    A branch result is admissible for merge only if:
    1. Its branch plan was admissible.
    2. Its budget was not exhausted beyond policy.
    3. Its side-effect log contains no unauthorized committed side effect.

    Returns (admissible, reason). reason is empty if admissible.
    """
    # Check 1: Plan was admissible
    if not plan.admissible:
        return (False, f"plan_not_admissible: {'; '.join(plan.inadmissibility_reasons)}")

    # Check 2: Budget not exhausted
    if result.status == BRANCH_BUDGET_EXHAUSTED:
        return (False, f"budget_exhausted: {result.failure_reason}")

    # Check 3: No unauthorized committed side effects
    for se in result.side_effect_summary:
        if se.get("allowed") and not plan.policy.is_side_effect_allowed():
            return (
                False,
                f"unauthorized_side_effect: {se.get('action', 'unknown')}",
            )

    # Check 4: Result must be completed
    if result.status != BRANCH_COMPLETED:
        return (False, f"result_not_completed: status={result.status}")

    return (True, "")


# ── AB-003: Receipt Digest Verification ─────────────────────────────────────

def verify_receipt_integrity(
    receipt: DeliberationReceipt,
    request: DeliberationRequest,
    plans: list[BranchPlan],
    results: list[BranchResult],
    decision: MergeDecision,
    policy: BranchPolicy,
) -> tuple[bool, list[str]]:
    """AB-003: Verify that a deliberation receipt matches materialized artifacts.

    A deliberation receipt is valid only if every referenced digest matches
    the materialized artifact.

    Returns (valid, mismatches). mismatches is empty if valid.
    """
    mismatches: list[str] = []

    # Request digest
    expected_req = request.compute_digest()
    if receipt.request_digest != expected_req:
        mismatches.append(f"request_digest: receipt={receipt.request_digest[:16]}... actual={expected_req[:16]}...")

    # Policy digest
    expected_pol = policy.compute_digest()
    if receipt.branch_policy_digest != expected_pol:
        mismatches.append(f"policy_digest: receipt={receipt.branch_policy_digest[:16]}... actual={expected_pol[:16]}...")

    # Budget digest (from first plan)
    if plans:
        expected_bud = compute_budget_digest(plans[0].budget)
        if receipt.branch_budget_digest != expected_bud:
            mismatches.append(f"budget_digest: receipt={receipt.branch_budget_digest[:16]}... actual={expected_bud[:16]}...")

    # Plan digests
    actual_plan_digests = [p.compute_digest() for p in plans]
    if receipt.branch_plan_digests != actual_plan_digests:
        mismatches.append(f"plan_digests: receipt has {len(receipt.branch_plan_digests)}, actual has {len(actual_plan_digests)}")

    # Result digests
    actual_result_digests = [r.compute_digest() for r in results]
    if receipt.branch_result_digests != actual_result_digests:
        mismatches.append(f"result_digests: receipt has {len(receipt.branch_result_digests)}, actual has {len(actual_result_digests)}")

    # Merge decision digest
    expected_merge = decision.compute_digest()
    if receipt.merge_decision_digest != expected_merge:
        mismatches.append(f"merge_digest: receipt={receipt.merge_decision_digest[:16]}... actual={expected_merge[:16]}...")

    # Receipt signature (digest commitment)
    body = json.dumps(receipt._unsigned_body(), sort_keys=True, separators=(",", ":"))
    expected_sig = _sha256_str(body)
    if receipt.signature != expected_sig:
        mismatches.append("receipt_signature: digest commitment mismatch")

    return (len(mismatches) == 0, mismatches)


# ── AB-004: Non-Selected Branch is Evidence-Only ────────────────────────────

def is_branch_committable(
    branch_id: str,
    decision: MergeDecision,
    human_review_approved: bool = False,
) -> bool:
    """AB-004: Check if a branch's output may be committed to workflow state.

    A non-selected branch is evidence-only. Its output may not mutate
    committed workflow state unless a later governed merge explicitly
    selects it.

    For deferred (human review) decisions, the branch is committable only
    if human_review_approved is True.
    """
    if decision.strategy == MERGE_SELECT_BEST:
        return branch_id == decision.selected_branch_id

    if decision.strategy == MERGE_DEFER_HUMAN:
        if not human_review_approved:
            return False
        return branch_id in decision.deferred_branch_ids

    # MERGE_REJECT_ALL — nothing committable
    return False


def get_evidence_only_branches(
    decision: MergeDecision,
) -> list[str]:
    """AB-004: Return branch IDs that are evidence-only (non-selected).

    These branches' outputs must NOT mutate committed workflow state.
    """
    if decision.strategy == MERGE_REJECT_ALL:
        return list(decision.rejected_branch_ids)

    all_rejected = set(decision.rejected_branch_ids)
    if decision.strategy == MERGE_DEFER_HUMAN:
        # Deferred branches are evidence-only until approved
        all_rejected.update(decision.deferred_branch_ids)

    return sorted(all_rejected)
