"""
NodeChain Governed Review Workbench (v2.21.0)
==============================================

Turns human-review gates into governed, verifiable operator decisions through
digest-bound review requests and decision receipts.

OR-001:
    A human/operator decision is admissible only if it references a materialized
    review request, validates the bound artifacts, satisfies reviewer authority
    policy, records rationale, and emits a decision receipt. No operator decision
    may mutate runtime state directly.

Core primitives:
    ReviewRequest    — materialized request for human review
    ReviewSubject    — what is being reviewed (capability, branch, deployment, etc.)
    ReviewerPolicy   — authority rules for who can review what
    OperatorDecision — an approve/reject decision by a reviewer
    DecisionReceipt  — digest-committed proof of decision
    ReviewQueue      — pending review request management
    ReviewVerifier   — validates decision receipts against requests

Decision types:
    approve_capability_selection / reject_capability_selection
    approve_branch_merge / reject_branch_merge
    approve_compensation / reject_compensation
    approve_deployment / reject_deployment
    approve_remote_binding / reject_remote_binding
    acknowledge_health_finding

Module header: v2.21.0
License: MIT
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# ── OR-001 Invariant ────────────────────────────────────────────────────────

OR_001 = (
    "A human/operator decision is admissible only if it references a materialized "
    "review request, validates the bound artifacts, satisfies reviewer authority "
    "policy, records rationale, and emits a decision receipt. No operator decision "
    "may mutate runtime state directly."
)

REVIEW_SCHEMA_VERSION = "1.0.0"

# ── Decision types ──────────────────────────────────────────────────────────

DECISION_APPROVE_CAPABILITY = "approve_capability_selection"
DECISION_REJECT_CAPABILITY = "reject_capability_selection"
DECISION_APPROVE_BRANCH_MERGE = "approve_branch_merge"
DECISION_REJECT_BRANCH_MERGE = "reject_branch_merge"
DECISION_APPROVE_COMPENSATION = "approve_compensation"
DECISION_REJECT_COMPENSATION = "reject_compensation"
DECISION_APPROVE_DEPLOYMENT = "approve_deployment"
DECISION_REJECT_DEPLOYMENT = "reject_deployment"
DECISION_APPROVE_REMOTE_BINDING = "approve_remote_binding"
DECISION_REJECT_REMOTE_BINDING = "reject_remote_binding"
DECISION_ACKNOWLEDGE_HEALTH = "acknowledge_health_finding"
# Runtime risk-classifier review gate (v2.22.0)
DECISION_APPROVE_CHAIN_REVIEW = "approve_chain_review"
DECISION_REJECT_CHAIN_REVIEW = "reject_chain_review"
DECISION_REVISION_CHAIN_REVIEW = "request_revision_chain_review"

ALL_DECISION_TYPES = frozenset({
    DECISION_APPROVE_CAPABILITY, DECISION_REJECT_CAPABILITY,
    DECISION_APPROVE_BRANCH_MERGE, DECISION_REJECT_BRANCH_MERGE,
    DECISION_APPROVE_COMPENSATION, DECISION_REJECT_COMPENSATION,
    DECISION_APPROVE_DEPLOYMENT, DECISION_REJECT_DEPLOYMENT,
    DECISION_APPROVE_REMOTE_BINDING, DECISION_REJECT_REMOTE_BINDING,
    DECISION_ACKNOWLEDGE_HEALTH,
    DECISION_APPROVE_CHAIN_REVIEW, DECISION_REJECT_CHAIN_REVIEW,
    DECISION_REVISION_CHAIN_REVIEW,
})

# Subject types (what is being reviewed)
SUBJECT_CAPABILITY = "capability_selection"
SUBJECT_BRANCH_MERGE = "branch_merge"
SUBJECT_COMPENSATION = "compensation"
SUBJECT_DEPLOYMENT = "deployment"
SUBJECT_REMOTE_BINDING = "remote_binding"
SUBJECT_HEALTH = "health_finding"
# Runtime risk-classifier review gate (v2.22.0)
SUBJECT_CHAIN_REVIEW = "chain_review"

ALL_SUBJECT_TYPES = frozenset({
    SUBJECT_CAPABILITY, SUBJECT_BRANCH_MERGE, SUBJECT_COMPENSATION,
    SUBJECT_DEPLOYMENT, SUBJECT_REMOTE_BINDING, SUBJECT_HEALTH,
    SUBJECT_CHAIN_REVIEW,
})

# Map subject types to valid decision types
_SUBJECT_DECISION_MAP: dict[str, frozenset[str]] = {
    SUBJECT_CAPABILITY: frozenset({DECISION_APPROVE_CAPABILITY, DECISION_REJECT_CAPABILITY}),
    SUBJECT_BRANCH_MERGE: frozenset({DECISION_APPROVE_BRANCH_MERGE, DECISION_REJECT_BRANCH_MERGE}),
    SUBJECT_COMPENSATION: frozenset({DECISION_APPROVE_COMPENSATION, DECISION_REJECT_COMPENSATION}),
    SUBJECT_DEPLOYMENT: frozenset({DECISION_APPROVE_DEPLOYMENT, DECISION_REJECT_DEPLOYMENT}),
    SUBJECT_REMOTE_BINDING: frozenset({DECISION_APPROVE_REMOTE_BINDING, DECISION_REJECT_REMOTE_BINDING}),
    SUBJECT_HEALTH: frozenset({DECISION_ACKNOWLEDGE_HEALTH}),
    SUBJECT_CHAIN_REVIEW: frozenset({
        DECISION_APPROVE_CHAIN_REVIEW, DECISION_REJECT_CHAIN_REVIEW,
        DECISION_REVISION_CHAIN_REVIEW,
    }),
}

# Decision outcomes
DECISION_APPROVE = "approve"
DECISION_REJECT = "reject"
DECISION_ACKNOWLEDGE = "acknowledge"
DECISION_REVISION = "request_revision"

ALL_DECISION_OUTCOMES = frozenset({
    DECISION_APPROVE, DECISION_REJECT, DECISION_ACKNOWLEDGE, DECISION_REVISION,
})

_OUTCOME_MAP: dict[str, str] = {
    DECISION_APPROVE_CAPABILITY: DECISION_APPROVE,
    DECISION_REJECT_CAPABILITY: DECISION_REJECT,
    DECISION_APPROVE_BRANCH_MERGE: DECISION_APPROVE,
    DECISION_REJECT_BRANCH_MERGE: DECISION_REJECT,
    DECISION_APPROVE_COMPENSATION: DECISION_APPROVE,
    DECISION_REJECT_COMPENSATION: DECISION_REJECT,
    DECISION_APPROVE_DEPLOYMENT: DECISION_APPROVE,
    DECISION_REJECT_DEPLOYMENT: DECISION_REJECT,
    DECISION_APPROVE_REMOTE_BINDING: DECISION_APPROVE,
    DECISION_REJECT_REMOTE_BINDING: DECISION_REJECT,
    DECISION_ACKNOWLEDGE_HEALTH: DECISION_ACKNOWLEDGE,
    DECISION_APPROVE_CHAIN_REVIEW: DECISION_APPROVE,
    DECISION_REJECT_CHAIN_REVIEW: DECISION_REJECT,
    DECISION_REVISION_CHAIN_REVIEW: DECISION_REVISION,
}

# Reviewer roles
ROLE_OPERATOR = "operator"
ROLE_SECURITY_OFFICER = "security_officer"
ROLE_RELEASE_MANAGER = "release_manager"
ROLE_ADMIN = "admin"

ALL_REVIEWER_ROLES = frozenset({
    ROLE_OPERATOR, ROLE_SECURITY_OFFICER, ROLE_RELEASE_MANAGER, ROLE_ADMIN,
})

# Default role authority: which roles can approve which subject types
DEFAULT_ROLE_AUTHORITY: dict[str, frozenset[str]] = {
    ROLE_OPERATOR: frozenset({SUBJECT_HEALTH, SUBJECT_CHAIN_REVIEW}),
    ROLE_SECURITY_OFFICER: frozenset({
        SUBJECT_CAPABILITY, SUBJECT_REMOTE_BINDING, SUBJECT_HEALTH,
    }),
    ROLE_RELEASE_MANAGER: frozenset({
        SUBJECT_DEPLOYMENT, SUBJECT_BRANCH_MERGE, SUBJECT_COMPENSATION,
    }),
    ROLE_ADMIN: frozenset(ALL_SUBJECT_TYPES),
}

# ── Rejection reasons for verifier ──────────────────────────────────────────

REJECT_NO_REQUEST = "reject_no_review_request"
REJECT_SUBJECT_MISMATCH = "reject_subject_digest_mismatch"
REJECT_POLICY_MISMATCH = "reject_policy_digest_mismatch"
REJECT_UNAUTHORIZED = "reject_unauthorized_reviewer"
REJECT_MISSING_RATIONALE = "reject_missing_rationale_high_risk"
REJECT_STALE = "reject_stale_request"
REJECT_DECISION_TYPE_MISMATCH = "reject_decision_type_not_valid_for_subject"
REJECT_DIGEST_INVALID = "reject_receipt_digest_invalid"
REJECT_SUBJECT_TYPE_MISMATCH = "reject_subject_type_mismatch"

ALL_REJECTION_REASONS = frozenset({
    REJECT_NO_REQUEST, REJECT_SUBJECT_MISMATCH, REJECT_POLICY_MISMATCH,
    REJECT_UNAUTHORIZED, REJECT_MISSING_RATIONALE, REJECT_STALE,
    REJECT_DECISION_TYPE_MISMATCH, REJECT_DIGEST_INVALID,
    REJECT_SUBJECT_TYPE_MISMATCH,
})

# ── Health rule IDs (HR-045 through HR-048) ─────────────────────────────────

HR_PENDING_REVIEW_TOO_OLD = "HR-045"
HR_UNAUTHORIZED_DECISION = "HR-046"
HR_STALE_DECISION = "HR-047"
HR_REJECTED_BLOCKING = "HR-048"

# ── Helpers ─────────────────────────────────────────────────────────────────


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_dict(data: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _sha256_str(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def chain_review_decision_type(outcome: str) -> str:
    """Map a runtime review outcome string to its canonical chain_review decision type.

    The runtime review gate speaks bare outcome strings ('approve'/'reject'/
    'request_revision'). This converts them to the governed DECISION_* constant
    required by OperatorDecision for the SUBJECT_CHAIN_REVIEW subject type.

    Raises ValueError for any other outcome (e.g. 'timeout'), since timeouts are
    not operator decisions and must not be materialized as decision receipts.
    """
    mapping = {
        "approve": DECISION_APPROVE_CHAIN_REVIEW,
        "reject": DECISION_REJECT_CHAIN_REVIEW,
        "request_revision": DECISION_REVISION_CHAIN_REVIEW,
    }
    try:
        return mapping[outcome]
    except KeyError as exc:
        raise ValueError(f"Unsupported chain review outcome: {outcome}") from exc


# ── Data Models ─────────────────────────────────────────────────────────────


@dataclass
class ReviewSubject:
    """What is being reviewed.

    Contains a digest of the artifact under review so the
    decision is cryptographically bound to exact state.
    """

    subject_type: str
    subject_id: str
    subject_digest: str  # SHA-256 of the artifact under review
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.subject_type not in ALL_SUBJECT_TYPES:
            raise ValueError(f"Unknown subject type: {self.subject_type}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject_type": self.subject_type,
            "subject_id": self.subject_id,
            "subject_digest": self.subject_digest,
            "metadata": self.metadata,
        }


@dataclass
class ReviewRequest:
    """A materialized request for human review.

    Binds to the exact artifacts that triggered the review:
    - subject_digest: what is under review
    - graph_digest: governance graph at time of request
    - policy_digest: policy in effect at time of request
    - trace_event_ids: execution trace events leading to review
    """

    request_id: str
    subject: ReviewSubject
    reason_for_review: str
    required_reviewer_role: str
    graph_digest: str = ""
    policy_digest: str = ""
    trace_event_ids: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=_now_iso)
    risk_level: str = "medium"  # low, medium, high, critical
    status: str = "pending"  # pending, approved, rejected, acknowledged, expired

    def __post_init__(self):
        if self.required_reviewer_role not in ALL_REVIEWER_ROLES:
            raise ValueError(f"Unknown reviewer role: {self.required_reviewer_role}")

    def compute_digest(self) -> str:
        """Deterministic digest of the review request."""
        return _sha256_dict({
            "request_id": self.request_id,
            "subject": self.subject.to_dict(),
            "reason_for_review": self.reason_for_review,
            "required_reviewer_role": self.required_reviewer_role,
            "graph_digest": self.graph_digest,
            "policy_digest": self.policy_digest,
            "trace_event_ids": sorted(self.trace_event_ids),
            "risk_level": self.risk_level,
            "created_at": self.created_at,
        })

    @property
    def is_stale(self) -> bool:
        """A request is stale if it's older than 72 hours."""
        try:
            created = datetime.fromisoformat(self.created_at)
            age = datetime.now(timezone.utc) - created
            return age.total_seconds() > 72 * 3600
        except (ValueError, TypeError):
            return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "subject": self.subject.to_dict(),
            "reason_for_review": self.reason_for_review,
            "required_reviewer_role": self.required_reviewer_role,
            "graph_digest": self.graph_digest,
            "policy_digest": self.policy_digest,
            "trace_event_ids": sorted(self.trace_event_ids),
            "risk_level": self.risk_level,
            "status": self.status,
            "created_at": self.created_at,
            "request_digest": self.compute_digest(),
        }


@dataclass
class ReviewerPolicy:
    """Authority rules for who can review what.

    Maps reviewer identities to roles, and roles to authorized
    subject types. This is the policy that ReviewVerifier checks
    against when validating an OperatorDecision.
    """

    policy_id: str = "default"
    role_authority: dict[str, frozenset[str]] = field(default_factory=lambda: dict(DEFAULT_ROLE_AUTHORITY))
    require_rationale_for_risk: str = "high"  # Require rationale for high and critical
    max_request_age_hours: int = 72
    policy_version: str = "1.0.0"

    def is_authorized(self, reviewer_role: str, subject_type: str) -> bool:
        """Check if a role is authorized to review a subject type."""
        allowed = self.role_authority.get(reviewer_role, frozenset())
        return subject_type in allowed

    def rationale_required(self, risk_level: str) -> bool:
        """Check if rationale is required for the given risk level."""
        risk_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        threshold = risk_order.get(self.require_rationale_for_risk, 2)
        actual = risk_order.get(risk_level, 0)
        return actual >= threshold

    def compute_digest(self) -> str:
        """Deterministic digest of the reviewer policy."""
        return _sha256_dict({
            "policy_id": self.policy_id,
            "role_authority": {
                role: sorted(list(subjects))
                for role, subjects in sorted(self.role_authority.items())
            },
            "require_rationale_for_risk": self.require_rationale_for_risk,
            "max_request_age_hours": self.max_request_age_hours,
            "policy_version": self.policy_version,
        })

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "role_authority": {
                role: sorted(list(subjects))
                for role, subjects in sorted(self.role_authority.items())
            },
            "require_rationale_for_risk": self.require_rationale_for_risk,
            "max_request_age_hours": self.max_request_age_hours,
            "policy_version": self.policy_version,
            "policy_digest": self.compute_digest(),
        }


@dataclass
class OperatorDecision:
    """An approve/reject decision by a reviewer.

    The decision references the review request and includes rationale.
    The ReviewVerifier validates this before producing a DecisionReceipt.
    """

    decision_type: str
    request_id: str
    reviewer_identity: str
    reviewer_role: str
    rationale: str
    request_digest: str  # Must match ReviewRequest.compute_digest()
    subject_digest: str  # Must match ReviewRequest.subject.subject_digest
    policy_digest: str   # Must match ReviewerPolicy.compute_digest()
    decided_at: str = field(default_factory=_now_iso)
    authority_source: str = "reviewer_policy"  # How authority was derived

    def __post_init__(self):
        if self.decision_type not in ALL_DECISION_TYPES:
            raise ValueError(f"Unknown decision type: {self.decision_type}")
        if self.reviewer_role not in ALL_REVIEWER_ROLES:
            raise ValueError(f"Unknown reviewer role: {self.reviewer_role}")

    @property
    def outcome(self) -> str:
        """approve, reject, or acknowledge."""
        return _OUTCOME_MAP.get(self.decision_type, "unknown")

    @property
    def rationale_digest(self) -> str:
        """SHA-256 of the rationale text."""
        return _sha256_str(self.rationale)

    def compute_digest(self) -> str:
        """Digest of the decision (not the receipt)."""
        return _sha256_dict({
            "decision_type": self.decision_type,
            "request_id": self.request_id,
            "reviewer_identity": self.reviewer_identity,
            "reviewer_role": self.reviewer_role,
            "rationale_digest": _sha256_str(self.rationale),
            "request_digest": self.request_digest,
            "subject_digest": self.subject_digest,
            "policy_digest": self.policy_digest,
            "decided_at": self.decided_at,
            "authority_source": self.authority_source,
        })

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_type": self.decision_type,
            "outcome": self.outcome,
            "request_id": self.request_id,
            "reviewer_identity": self.reviewer_identity,
            "reviewer_role": self.reviewer_role,
            "rationale": self.rationale,
            "rationale_digest": _sha256_str(self.rationale),
            "request_digest": self.request_digest,
            "subject_digest": self.subject_digest,
            "policy_digest": self.policy_digest,
            "decided_at": self.decided_at,
            "authority_source": self.authority_source,
            "decision_digest": self.compute_digest(),
        }


@dataclass
class DecisionReceipt:
    """Digest-committed proof of a decision.

    The receipt is the artifact that the runtime may consume.
    It references the original ReviewRequest digest and is
    cryptographically bound to all decision inputs.
    """

    receipt_id: str
    decision: OperatorDecision
    request_id: str
    request_digest: str
    subject_type: str
    subject_id: str
    subject_digest: str
    policy_digest: str
    schema_version: str = REVIEW_SCHEMA_VERSION
    created_at: str = field(default_factory=_now_iso)
    digest_commitment: str = ""  # SHA-256 commitment of receipt body; production: RSA-PSS-SHA256 or Ed25519

    def compute_receipt_digest(self) -> str:
        """Deterministic digest of the receipt body."""
        return _sha256_dict({
            "receipt_id": self.receipt_id,
            "decision": self.decision.to_dict(),
            "request_id": self.request_id,
            "request_digest": self.request_digest,
            "subject_type": self.subject_type,
            "subject_id": self.subject_id,
            "subject_digest": self.subject_digest,
            "policy_digest": self.policy_digest,
            "schema_version": self.schema_version,
            "created_at": self.created_at,
        })

    def compute_commitment(self) -> str:
        """SHA-256 commitment of receipt body.

        Production must use RSA-PSS-SHA256 or Ed25519 for real signing.
        """
        return self.compute_receipt_digest()

    def commit(self) -> None:
        """Commit the receipt with a SHA-256 digest commitment."""
        self.digest_commitment = self.compute_commitment()

    @property
    def is_committed(self) -> bool:
        return self.digest_commitment != "" and self.digest_commitment == self.compute_commitment()

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "schema_version": self.schema_version,
            "created_at": self.created_at,
            "decision": self.decision.to_dict(),
            "request_id": self.request_id,
            "request_digest": self.request_digest,
            "subject_type": self.subject_type,
            "subject_id": self.subject_id,
            "subject_digest": self.subject_digest,
            "policy_digest": self.policy_digest,
            "receipt_digest": self.compute_receipt_digest(),
            "digest_commitment": self.digest_commitment,
            "is_committed": self.is_committed,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


# ── Verification Result ─────────────────────────────────────────────────────


@dataclass
class VerificationResult:
    """Result of verifying a decision against a review request."""

    admissible: bool
    rejection_reason: str = ""
    receipt: DecisionReceipt | None = None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "admissible": self.admissible,
            "rejection_reason": self.rejection_reason,
            "receipt": self.receipt.to_dict() if self.receipt else None,
            "warnings": self.warnings,
        }


# ── Review Queue ────────────────────────────────────────────────────────────


class ReviewQueue:
    """Manages pending review requests.

    The queue is an in-memory or file-backed collection of ReviewRequests.
    It does NOT mutate runtime state — it only tracks what needs review.
    """

    def __init__(self) -> None:
        self._requests: dict[str, ReviewRequest] = {}
        self._decisions: dict[str, DecisionReceipt] = {}  # request_id → receipt

    def submit(self, request: ReviewRequest) -> str:
        """Submit a new review request. Returns request_id."""
        if request.request_id in self._requests:
            raise ValueError(f"Duplicate request_id: {request.request_id}")
        self._requests[request.request_id] = request
        return request.request_id

    def get(self, request_id: str) -> ReviewRequest | None:
        return self._requests.get(request_id)

    def list_pending(self) -> list[ReviewRequest]:
        """List all pending review requests."""
        return [r for r in self._requests.values() if r.status == "pending"]

    def list_by_subject_type(self, subject_type: str) -> list[ReviewRequest]:
        """List requests by subject type."""
        return [r for r in self._requests.values()
                if r.subject.subject_type == subject_type]

    def list_by_risk(self, risk_level: str) -> list[ReviewRequest]:
        """List requests by risk level."""
        return [r for r in self._requests.values() if r.risk_level == risk_level]

    def list_stale(self) -> list[ReviewRequest]:
        """List requests that are stale (older than 72h)."""
        return [r for r in self._requests.values() if r.is_stale and r.status == "pending"]

    def record_decision(self, request_id: str, receipt: DecisionReceipt) -> None:
        """Record a decision receipt against a request."""
        if request_id not in self._requests:
            raise ValueError(f"Unknown request_id: {request_id}")
        self._decisions[request_id] = receipt
        # Update request status based on outcome
        outcome = receipt.decision.outcome
        if outcome == DECISION_APPROVE:
            self._requests[request_id].status = "approved"
        elif outcome == DECISION_REJECT:
            self._requests[request_id].status = "rejected"
        elif outcome == DECISION_ACKNOWLEDGE:
            self._requests[request_id].status = "acknowledged"
        elif outcome == DECISION_REVISION:
            self._requests[request_id].status = "revision_requested"

    def get_decision(self, request_id: str) -> DecisionReceipt | None:
        return self._decisions.get(request_id)

    @property
    def pending_count(self) -> int:
        return len(self.list_pending())

    @property
    def total_count(self) -> int:
        return len(self._requests)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_requests": self.total_count,
            "pending_count": self.pending_count,
            "pending": [r.to_dict() for r in self.list_pending()],
            "stale": [r.to_dict() for r in self.list_stale()],
            "decisions": {rid: r.receipt_id for rid, r in self._decisions.items()},
        }


# ── Review Verifier ─────────────────────────────────────────────────────────


class ReviewVerifier:
    """Validates operator decisions against review requests and policies.

    OR-001: A decision is admissible only if:
    1. It references a materialized review request
    2. Subject digest matches
    3. Policy digest matches
    4. Reviewer is authorized by policy
    5. Rationale is present for high-risk decisions
    6. Request is not stale
    7. Decision type is valid for the subject type
    """

    def __init__(self, policy: ReviewerPolicy | None = None) -> None:
        self.policy = policy or ReviewerPolicy()

    def verify(
        self,
        decision: OperatorDecision,
        request: ReviewRequest,
    ) -> VerificationResult:
        """Verify a decision against a review request.

        Returns VerificationResult with admissible=True if all checks pass.
        Returns VerificationResult with rejection_reason if any check fails.
        """
        warnings: list[str] = []

        # Check 1: Request ID matches
        if decision.request_id != request.request_id:
            return VerificationResult(
                admissible=False,
                rejection_reason=REJECT_NO_REQUEST,
                warnings=warnings,
            )

        # Check 2: Request digest matches
        actual_request_digest = request.compute_digest()
        if decision.request_digest != actual_request_digest:
            return VerificationResult(
                admissible=False,
                rejection_reason=REJECT_NO_REQUEST,
                warnings=["Decision request_digest does not match actual request digest"],
            )

        # Check 3: Subject digest matches
        if decision.subject_digest != request.subject.subject_digest:
            return VerificationResult(
                admissible=False,
                rejection_reason=REJECT_SUBJECT_MISMATCH,
                warnings=warnings,
            )

        # Check 4: Policy digest matches
        actual_policy_digest = self.policy.compute_digest()
        if decision.policy_digest != actual_policy_digest:
            return VerificationResult(
                admissible=False,
                rejection_reason=REJECT_POLICY_MISMATCH,
                warnings=["Decision policy_digest does not match actual policy digest"],
            )

        # Check 5: Decision type is valid for subject type
        valid_decisions = _SUBJECT_DECISION_MAP.get(request.subject.subject_type, frozenset())
        if decision.decision_type not in valid_decisions:
            return VerificationResult(
                admissible=False,
                rejection_reason=REJECT_DECISION_TYPE_MISMATCH,
                warnings=[
                    f"Decision {decision.decision_type} not valid for "
                    f"subject type {request.subject.subject_type}"
                ],
            )

        # Check 6: Reviewer authority
        if not self.policy.is_authorized(decision.reviewer_role, request.subject.subject_type):
            return VerificationResult(
                admissible=False,
                rejection_reason=REJECT_UNAUTHORIZED,
                warnings=[
                    f"Role {decision.reviewer_role} not authorized for "
                    f"subject type {request.subject.subject_type}"
                ],
            )

        # Check 7: Rationale for high-risk decisions
        if self.policy.rationale_required(request.risk_level):
            if not decision.rationale or len(decision.rationale.strip()) < 3:
                return VerificationResult(
                    admissible=False,
                    rejection_reason=REJECT_MISSING_RATIONALE,
                    warnings=[
                        f"Rationale required for risk level {request.risk_level}"
                    ],
                )

        # Check 8: Request is not stale
        if request.is_stale:
            return VerificationResult(
                admissible=False,
                rejection_reason=REJECT_STALE,
                warnings=[f"Request {request.request_id} is stale (>72h old)"],
            )

        # Check 9: Reviewer role matches required role (if specified)
        # The required_reviewer_role is a minimum bar; admin can always review
        if request.required_reviewer_role != decision.reviewer_role:
            role_hierarchy = {ROLE_OPERATOR: 0, ROLE_SECURITY_OFFICER: 1,
                            ROLE_RELEASE_MANAGER: 1, ROLE_ADMIN: 2}
            required_level = role_hierarchy.get(request.required_reviewer_role, 0)
            actual_level = role_hierarchy.get(decision.reviewer_role, 0)
            if actual_level < required_level:
                return VerificationResult(
                    admissible=False,
                    rejection_reason=REJECT_UNAUTHORIZED,
                    warnings=[
                        f"Role {decision.reviewer_role} insufficient; "
                        f"requires {request.required_reviewer_role}"
                    ],
                )

        # All checks passed — produce receipt
        receipt = DecisionReceipt(
            receipt_id=f"receipt_{decision.request_id}_{_sha256_str(decision.decided_at)[:8]}",
            decision=decision,
            request_id=request.request_id,
            request_digest=actual_request_digest,
            subject_type=request.subject.subject_type,
            subject_id=request.subject.subject_id,
            subject_digest=request.subject.subject_digest,
            policy_digest=actual_policy_digest,
            created_at=decision.decided_at,
        )
        receipt.commit()

        return VerificationResult(
            admissible=True,
            receipt=receipt,
            warnings=warnings,
        )

    def verify_receipt(self, receipt: DecisionReceipt, request: ReviewRequest) -> bool:
        """Verify that a receipt is valid against a request.

        Checks receipt digest commitment and all digest bindings.
        """
        # Receipt must be committed
        if not receipt.is_committed:
            return False

        # Receipt must reference the correct request
        if receipt.request_id != request.request_id:
            return False

        # Request digest must match
        if receipt.request_digest != request.compute_digest():
            return False

        # Subject digest must match
        if receipt.subject_digest != request.subject.subject_digest:
            return False

        return True
