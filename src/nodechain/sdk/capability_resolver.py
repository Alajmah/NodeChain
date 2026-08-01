"""Capability Resolution and Governed Node Selection (v2.17.0).

Given multiple nodes that claim the same capability, this module determines
which one NodeChain may select, under what policy, and with what evidence.

This is the bridge from registry to adaptive composition:

    I do not need to hard-code a specific node forever.
    I can request a governed capability.
    NodeChain can discover eligible implementations.
    NodeChain can reject unsafe ones.
    NodeChain can select the best admissible one.
    NodeChain can prove why it chose it.

CR-001 (critical invariant):
    Capability selection is admissible only among candidates whose complete
    package graph has already passed dependency trust resolution.
    Scoring never overrides policy denial.

CR-002 (evidence authority):
    Capability scores must be derived from trusted registry, certification,
    evaluation, and policy evidence. A candidate package may advertise
    capability, but it must not be the authority for its own score, trust
    level, or certification.

CR-003 (selection stability):
    A selected capability resolution is stable until explicitly re-resolved.
    Newly discovered candidates must not silently replace a pinned selection.

Non-negotiable rules:
    1.  Nodes may advertise capabilities.
    2.  Nodes may not select themselves.
    3.  Capability selection is performed by the resolver, not by candidate nodes.
    4.  Hard policy filters run before scoring.
    5.  A higher score cannot override a policy denial.
    6.  Every candidate graph must pass DT-001.
    7.  Selection must be deterministic under the same inputs.
    8.  Human review is required for high-risk or ambiguous material selections.
    9.  The chosen package must be version-pinned.
    10. The selection receipt must include rejected candidates and reasons.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from .artifact_retention import atomic_write_json


# ── Constants ───────────────────────────────────────────────────────────────

CAPABILITY_SCHEMA_VERSION = "1.0.0"

# Hard filter rejection reasons
REJECT_CONTRACT_MISMATCH = "contract_mismatch"
REJECT_REVOKED = "revoked"
REJECT_DEPRECATED_DISALLOWED = "deprecated_disallowed"
REJECT_UNCERTIFIED = "uncertified"
REJECT_UNTRUSTED_REGISTRY = "untrusted_registry"
REJECT_UNAPPROVED_PUBLISHER = "unapproved_publisher"
REJECT_FORBIDDEN_CAPABILITY = "forbidden_capability"
REJECT_SANDBOX_DOWNGRADE = "sandbox_downgrade"
REJECT_POLICY_DENIED = "policy_denied"
REJECT_DT001_FAILED = "dt001_failed"
REJECT_RISK_TOO_HIGH = "risk_too_high"
REJECT_UNVERIFIED_SCORE = "unverified_self_claimed_score"
REJECT_SELECTION_NOT_PINNED = "selection_not_pinned"

# Risk levels
RISK_LOW = "low"
RISK_MEDIUM = "medium"
RISK_HIGH = "high"
RISK_CRITICAL = "critical"

RISK_ORDER = {RISK_LOW: 0, RISK_MEDIUM: 1, RISK_HIGH: 2, RISK_CRITICAL: 3}

# Trust levels (from frozen surfaces)
TRUST_LEVEL_BUILT_IN = "built_in"
TRUST_LEVEL_LOCAL_TRUSTED = "local_trusted"
TRUST_LEVEL_LOCAL_UNTRUSTED = "local_untrusted"
TRUST_LEVEL_REMOTE_UNTRUSTED = "remote_untrusted"

TRUST_LEVEL_ORDER = {
    TRUST_LEVEL_BUILT_IN: 4,
    TRUST_LEVEL_LOCAL_TRUSTED: 3,
    TRUST_LEVEL_LOCAL_UNTRUSTED: 2,
    TRUST_LEVEL_REMOTE_UNTRUSTED: 1,
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_dict(data: dict[str, Any]) -> str:
    raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _sha256_str(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


# ── CapabilityRequest ───────────────────────────────────────────────────────


@dataclass
class CapabilityRequest:
    """A chain or builder asks for a capability, not a specific package.

    The resolver searches for packages that satisfy this request.
    """

    capability: str  # e.g., "incident.severity.triage"
    input_contract: str = ""  # e.g., "AnomalySet@1"
    output_contract: str = ""  # e.g., "SeverityAssessment@1"

    # Constraints
    certification_required: bool = True
    max_risk: str = RISK_HIGH
    forbidden_capabilities: list[str] = field(default_factory=list)
    required_sandbox: str = ""  # e.g., "hardened_untrusted"
    environment: str = "production"
    registry_filter: list[str] = field(default_factory=list)  # trusted registries

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability": self.capability,
            "input_contract": self.input_contract,
            "output_contract": self.output_contract,
            "certification_required": self.certification_required,
            "max_risk": self.max_risk,
            "forbidden_capabilities": sorted(self.forbidden_capabilities),
            "required_sandbox": self.required_sandbox,
            "environment": self.environment,
            "registry_filter": sorted(self.registry_filter),
        }

    def compute_digest(self) -> str:
        return _sha256_dict(self.to_dict())


# ── CapabilityOffer ─────────────────────────────────────────────────────────


@dataclass
class CapabilityOffer:
    """A package advertises what it can provide.

    This is the candidate side of capability resolution.
    """

    package_id: str
    version: str
    capabilities: list[str] = field(default_factory=list)
    input_contracts: list[str] = field(default_factory=list)
    output_contracts: list[str] = field(default_factory=list)
    risk_level: str = RISK_LOW
    sandbox_profile: str = "hardened_untrusted"
    evaluation_score: float = 0.0
    certification_digest: str = ""
    publisher_fingerprint: str = ""
    registry_id: str = ""
    trust_level: str = TRUST_LEVEL_LOCAL_TRUSTED
    lifecycle: str = "active"
    artifact_digest: str = ""
    manifest_digest: str = ""
    publisher_id: str = ""

    # Dependency graph admissibility (pre-computed by trust resolver)
    dependency_graph_admissible: bool = True
    dependency_graph_digest: str = ""

    # Metadata for scoring
    certification_timestamp: str = ""  # ISO datetime
    latency_ms: float = 0.0
    cost_usd: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_id": self.package_id,
            "version": self.version,
            "capabilities": sorted(self.capabilities),
            "input_contracts": sorted(self.input_contracts),
            "output_contracts": sorted(self.output_contracts),
            "risk_level": self.risk_level,
            "sandbox_profile": self.sandbox_profile,
            "evaluation_score": self.evaluation_score,
            "certification_digest": self.certification_digest,
            "publisher_fingerprint": self.publisher_fingerprint,
            "registry_id": self.registry_id,
            "trust_level": self.trust_level,
            "lifecycle": self.lifecycle,
            "artifact_digest": self.artifact_digest,
            "manifest_digest": self.manifest_digest,
            "publisher_id": self.publisher_id,
            "dependency_graph_admissible": self.dependency_graph_admissible,
            "dependency_graph_digest": self.dependency_graph_digest,
            "certification_timestamp": self.certification_timestamp,
            "latency_ms": self.latency_ms,
            "cost_usd": self.cost_usd,
        }

    def identity_key(self) -> str:
        """Stable identity for deterministic ordering."""
        return f"{self.package_id}@{self.version}"


# ── Sandbox strength (mirrors trust_resolver) ───────────────────────────────

SANDBOX_STRENGTH_ORDER = {
    "none": 0,
    "standard_untrusted": 1,
    "production_untrusted": 2,
    "hardened_untrusted": 3,
}


def sandbox_strength(profile: str) -> int:
    return SANDBOX_STRENGTH_ORDER.get(profile, 0)


# ── CapabilityResolutionPolicy ──────────────────────────────────────────────


@dataclass
class CapabilityResolutionPolicy:
    """Policy-owned scoring weights and hard requirements.

    Scoring is policy-owned, not package-owned. A higher score
    cannot override a policy denial.
    """

    policy_id: str = "default"

    # Scoring weights (sum to 100)
    weights: dict[str, float] = field(default_factory=lambda: {
        "contract_fit": 35.0,
        "evaluation_score": 25.0,
        "certification_recency": 15.0,
        "trust_level": 10.0,
        "risk": 10.0,
        "latency_cost": 5.0,
    })

    # Hard requirements
    certification_required: bool = True
    allow_deprecated: bool = False
    forbid_remote_untrusted_without_sandbox: bool = True

    # Review thresholds
    review_score_margin_below: float = 5.0
    review_risk_at_or_above: str = RISK_HIGH
    review_external_publisher: bool = True

    # Explicit preferences (overrides for tie-breaking)
    preferred_publishers: list[str] = field(default_factory=list)
    preferred_packages: list[str] = field(default_factory=list)

    # Forbidden capabilities (global, merged with request)
    forbidden_capabilities: list[str] = field(default_factory=list)

    # Minimum sandbox
    min_sandbox_profile: str = ""

    # Trusted registries (empty = all allowed)
    trusted_registries: list[str] = field(default_factory=list)

    # Trusted publishers (empty = all allowed)
    trusted_publishers: list[str] = field(default_factory=list)

    # CR-002: Require governed evidence for scoring inputs.
    # When True (default for production safety), candidates without
    # governed evidence for their scores, trust, risk, and certification
    # are rejected. Self-claimed scoring inputs are never trusted.
    require_governed_evidence: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "weights": self.weights,
            "certification_required": self.certification_required,
            "allow_deprecated": self.allow_deprecated,
            "forbid_remote_untrusted_without_sandbox": self.forbid_remote_untrusted_without_sandbox,
            "review_score_margin_below": self.review_score_margin_below,
            "review_risk_at_or_above": self.review_risk_at_or_above,
            "review_external_publisher": self.review_external_publisher,
            "preferred_publishers": sorted(self.preferred_publishers),
            "preferred_packages": sorted(self.preferred_packages),
            "forbidden_capabilities": sorted(self.forbidden_capabilities),
            "min_sandbox_profile": self.min_sandbox_profile,
            "trusted_registries": sorted(self.trusted_registries),
            "trusted_publishers": sorted(self.trusted_publishers),
            "require_governed_evidence": self.require_governed_evidence,
        }

    def compute_digest(self) -> str:
        return _sha256_dict(self.to_dict())


# ── Candidate scoring ───────────────────────────────────────────────────────


@dataclass
class CandidateScore:
    """Scored candidate with per-dimension breakdown."""

    offer: CapabilityOffer
    total_score: float = 0.0
    dimension_scores: dict[str, float] = field(default_factory=dict)
    passed_hard_filters: bool = True
    rejection_reasons: list[str] = field(default_factory=list)
    requires_review: bool = False
    review_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_id": self.offer.package_id,
            "version": self.offer.version,
            "identity_key": self.offer.identity_key(),
            "total_score": round(self.total_score, 4),
            "dimension_scores": {k: round(v, 4) for k, v in self.dimension_scores.items()},
            "passed_hard_filters": self.passed_hard_filters,
            "rejection_reasons": self.rejection_reasons,
            "requires_review": self.requires_review,
            "review_reasons": self.review_reasons,
        }


# ── CapabilitySelectionReceipt ──────────────────────────────────────────────


@dataclass
class CapabilitySelectionReceipt:
    """Evidence trail for capability selection decisions.

    Records the request, selected package, policy, all candidate scores,
    rejected candidates, and human review status.
    """

    receipt_id: str = ""
    request_digest: str = ""
    capability: str = ""
    selected_package_id: str = ""
    selected_version: str = ""
    selected_lockfile_digest: str = ""
    policy_digest: str = ""
    candidate_scores: list[dict[str, Any]] = field(default_factory=list)
    rejected_candidates: list[dict[str, Any]] = field(default_factory=list)
    human_review_required: bool = False
    human_review_status: str = ""  # "", "pending", "approved", "rejected"
    selection_rationale: str = ""
    selected_at: str = ""
    resolver_version: str = CAPABILITY_SCHEMA_VERSION
    _signature: str = ""

    def finalize(self) -> None:
        self.selected_at = _now_iso()
        body = json.dumps(self._unsigned_body(), sort_keys=True, separators=(",", ":"))
        self._signature = _sha256_str(body)

    def _unsigned_body(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "request_digest": self.request_digest,
            "capability": self.capability,
            "selected_package_id": self.selected_package_id,
            "selected_version": self.selected_version,
            "selected_lockfile_digest": self.selected_lockfile_digest,
            "policy_digest": self.policy_digest,
            "candidate_scores": self.candidate_scores,
            "rejected_candidates": self.rejected_candidates,
            "human_review_required": self.human_review_required,
            "human_review_status": self.human_review_status,
            "selection_rationale": self.selection_rationale,
            "selected_at": self.selected_at,
        }

    @property
    def signature(self) -> str:
        return self._signature

    def to_dict(self) -> dict[str, Any]:
        d = self._unsigned_body()
        d["signature"] = self._signature
        d["resolver_version"] = self.resolver_version
        return d


# ── Offer provider protocol ─────────────────────────────────────────────────


class OfferProvider(Protocol):
    """Discovers capability offers from local/remote registry."""

    def __call__(self, capability: str) -> list[CapabilityOffer]:
        ...


# ── Evidence provider (CR-002) ───────────────────────────────────────────────


@dataclass
class GovernedEvidence:
    """Authoritative trust and quality signals from governed evidence.

    A package may declare capabilities and contracts, but scores, trust
    levels, and certification status must come from governed evidence —
    not from the package's own self-claims.
    """

    package_id: str
    version: str
    verified_evaluation_score: float = 0.0
    verified_trust_level: str = ""
    verified_certification_digest: str = ""
    verified_risk_level: str = ""
    evidence_source: str = ""  # e.g. "registry", "evaluation_suite", "certification_authority"
    evidence_digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_id": self.package_id,
            "version": self.version,
            "verified_evaluation_score": self.verified_evaluation_score,
            "verified_trust_level": self.verified_trust_level,
            "verified_certification_digest": self.verified_certification_digest,
            "verified_risk_level": self.verified_risk_level,
            "evidence_source": self.evidence_source,
            "evidence_digest": self.evidence_digest,
        }


class EvidenceProvider(Protocol):
    """Provides authoritative evidence for a candidate.

    CR-002: Scores must be derived from governed evidence, not self-claims.
    If no evidence is found, the candidate's self-claimed score is rejected
    and treated as 0.
    """

    def __call__(self, package_id: str, version: str) -> GovernedEvidence | None:
        ...


# ── CapabilityResolver ──────────────────────────────────────────────────────


class CapabilityResolver:
    """Resolves capability requests to governed node selections.

    Selection flow:
        1. Receive CapabilityRequest.
        2. Discover candidate CapabilityOffers.
        3. Resolve and verify each candidate's dependency graph.
        4. Apply hard filters.
        5. Score remaining candidates.
        6. Select deterministically or require human review.
        7. Pin selected package/version.
        8. Emit CapabilitySelectionReceipt.
    """

    def __init__(
        self,
        offer_provider: OfferProvider,
        policy: CapabilityResolutionPolicy | None = None,
        evidence_provider: EvidenceProvider | None = None,
    ) -> None:
        self.offer_provider = offer_provider
        self.policy = policy or CapabilityResolutionPolicy()
        self.evidence_provider = evidence_provider

    def resolve(
        self,
        request: CapabilityRequest,
        explain: bool = False,
    ) -> tuple[list[CandidateScore], CapabilitySelectionReceipt | None]:
        """Resolve a capability request.

        Returns (all_candidate_scores, selection_receipt_or_None).
        If human review is required, receipt is emitted but selection
        is not finalized (selected_package_id stays empty).
        """
        # 1. Discover candidates
        all_offers = self.offer_provider(request.capability)

        # 2. Score each candidate
        scores: list[CandidateScore] = []
        for offer in all_offers:
            score = self._evaluate_candidate(offer, request)
            scores.append(score)

        # 3. Separate admissible from rejected
        admissible = [s for s in scores if s.passed_hard_filters]
        rejected = [s for s in scores if not s.passed_hard_filters]

        # Sort admissible by score (descending), then deterministic tie-breaks
        admissible_sorted = self._sort_admissible(admissible)

        # 4. Determine if human review is required
        review_required = False
        review_reasons: list[str] = []

        if not admissible_sorted:
            # No admissible candidates
            receipt = self._make_receipt(
                request, scores, [], explain,
                no_selection=True,
                rationale="No admissible candidates found",
            )
            return scores, receipt

        # Check review conditions on top candidate
        top = admissible_sorted[0]
        if top.requires_review:
            review_required = True
            review_reasons.extend(top.review_reasons)

        # Score margin check
        if len(admissible_sorted) > 1:
            margin = top.total_score - admissible_sorted[1].total_score
            if margin < self.policy.review_score_margin_below:
                review_required = True
                review_reasons.append(
                    f"Score margin {margin:.1f} below threshold "
                    f"{self.policy.review_score_margin_below}"
                )

        # 5. Select or defer to human review
        if review_required:
            receipt = self._make_receipt(
                request, scores, admissible_sorted, explain,
                review_required=True,
                review_reasons=review_reasons,
                rationale=f"Human review required: {'; '.join(review_reasons)}",
            )
            return scores, receipt

        # Select top candidate
        selected = top.offer
        receipt = self._make_receipt(
            request, scores, admissible_sorted, explain,
            selected=selected,
            rationale=self._build_rationale(top, admissible_sorted),
        )
        return scores, receipt

    def _evaluate_candidate(
        self,
        offer: CapabilityOffer,
        request: CapabilityRequest,
    ) -> CandidateScore:
        """Run hard filters then score."""
        score = CandidateScore(offer=offer)

        # ── Hard filters (CR-004: before scoring) ───────────────────────

        # CR-006: Dependency graph must pass DT-001
        if not offer.dependency_graph_admissible:
            score.passed_hard_filters = False
            score.rejection_reasons.append(REJECT_DT001_FAILED)

        # Contract mismatch
        if request.capability not in offer.capabilities:
            score.passed_hard_filters = False
            score.rejection_reasons.append(REJECT_CONTRACT_MISMATCH)
        if request.input_contract and request.input_contract not in offer.input_contracts:
            score.passed_hard_filters = False
            score.rejection_reasons.append(REJECT_CONTRACT_MISMATCH)
        if request.output_contract and request.output_contract not in offer.output_contracts:
            score.passed_hard_filters = False
            score.rejection_reasons.append(REJECT_CONTRACT_MISMATCH)

        # Revoked
        if offer.lifecycle == "revoked":
            score.passed_hard_filters = False
            score.rejection_reasons.append(REJECT_REVOKED)

        # Deprecated disallowed
        if offer.lifecycle == "deprecated" and not self.policy.allow_deprecated:
            score.passed_hard_filters = False
            score.rejection_reasons.append(REJECT_DEPRECATED_DISALLOWED)

        # Uncertified
        cert_required = request.certification_required or self.policy.certification_required
        if cert_required and not offer.certification_digest:
            score.passed_hard_filters = False
            score.rejection_reasons.append(REJECT_UNCERTIFIED)

        # Untrusted registry
        if self.policy.trusted_registries and offer.registry_id not in self.policy.trusted_registries:
            score.passed_hard_filters = False
            score.rejection_reasons.append(REJECT_UNTRUSTED_REGISTRY)

        # Unapproved publisher
        if self.policy.trusted_publishers and offer.publisher_fingerprint not in self.policy.trusted_publishers:
            score.passed_hard_filters = False
            score.rejection_reasons.append(REJECT_UNAPPROVED_PUBLISHER)

        # Forbidden capability
        all_forbidden = set(request.forbidden_capabilities) | set(self.policy.forbidden_capabilities)
        if all_forbidden & set(offer.capabilities):
            score.passed_hard_filters = False
            score.rejection_reasons.append(REJECT_FORBIDDEN_CAPABILITY)

        # Sandbox downgrade
        required_sandbox = request.required_sandbox or self.policy.min_sandbox_profile
        if required_sandbox and sandbox_strength(offer.sandbox_profile) < sandbox_strength(required_sandbox):
            score.passed_hard_filters = False
            score.rejection_reasons.append(REJECT_SANDBOX_DOWNGRADE)

        # Risk too high
        max_risk = RISK_ORDER.get(request.max_risk, RISK_ORDER[RISK_HIGH])
        if RISK_ORDER.get(offer.risk_level, 0) > max_risk:
            score.passed_hard_filters = False
            score.rejection_reasons.append(REJECT_RISK_TOO_HIGH)

        # Remote untrusted without sandbox
        if (
            self.policy.forbid_remote_untrusted_without_sandbox
            and offer.trust_level == TRUST_LEVEL_REMOTE_UNTRUSTED
            and offer.sandbox_profile == "none"
        ):
            score.passed_hard_filters = False
            score.rejection_reasons.append(REJECT_SANDBOX_DOWNGRADE)

        # CR-005: If hard filters failed, do not score
        if not score.passed_hard_filters:
            return score

        # ── CR-002: Override self-claimed scores with governed evidence ─

        # CR-002 is now absolute when require_governed_evidence=True (default).
        # A candidate package may advertise capability and contracts,
        # but it must NOT be the authority for its own score, trust level,
        # risk, or certification. These must come from governed evidence.

        effective_eval = offer.evaluation_score
        effective_trust = offer.trust_level
        effective_cert = offer.certification_digest
        effective_risk = offer.risk_level

        if self.policy.require_governed_evidence:
            if self.evidence_provider:
                ev = self.evidence_provider(offer.package_id, offer.version)
                if ev:
                    effective_eval = ev.verified_evaluation_score
                    if ev.verified_trust_level:
                        effective_trust = ev.verified_trust_level
                    if ev.verified_certification_digest:
                        effective_cert = ev.verified_certification_digest
                    if ev.verified_risk_level:
                        effective_risk = ev.verified_risk_level
                else:
                    score.passed_hard_filters = False
                    score.rejection_reasons.append(REJECT_UNVERIFIED_SCORE)
                    return score
            else:
                # No evidence provider configured but policy requires evidence.
                # Cannot accept self-claimed scoring inputs.
                score.passed_hard_filters = False
                score.rejection_reasons.append(REJECT_UNVERIFIED_SCORE)
                return score
        elif self.evidence_provider:
            # Evidence provider exists but policy doesn't require it.
            # Still override with evidence when available.
            ev = self.evidence_provider(offer.package_id, offer.version)
            if ev:
                effective_eval = ev.verified_evaluation_score
                if ev.verified_trust_level:
                    effective_trust = ev.verified_trust_level
                if ev.verified_certification_digest:
                    effective_cert = ev.verified_certification_digest
                if ev.verified_risk_level:
                    effective_risk = ev.verified_risk_level

        # ── Scoring ─────────────────────────────────────────────────────

        weights = self.policy.weights
        w_total = sum(weights.values()) or 1.0

        # Contract fit (exact match on all requested contracts)
        contract_fit = self._score_contract_fit(offer, request)
        score.dimension_scores["contract_fit"] = contract_fit * weights.get("contract_fit", 0) / w_total * 100

        # Evaluation score (from governed evidence when available)
        eval_score = min(effective_eval, 1.0)
        score.dimension_scores["evaluation_score"] = eval_score * weights.get("evaluation_score", 0) / w_total * 100

        # Certification recency
        cert_recency = 1.0 if effective_cert else 0.0
        score.dimension_scores["certification_recency"] = cert_recency * weights.get("certification_recency", 0) / w_total * 100

        # Trust level (from governed evidence when available)
        trust_score = TRUST_LEVEL_ORDER.get(effective_trust, 0) / 4.0
        score.dimension_scores["trust_level"] = trust_score * weights.get("trust_level", 0) / w_total * 100

        # Risk (lower risk = higher score)
        risk_inv = 1.0 - (RISK_ORDER.get(effective_risk, 0) / 3.0)
        score.dimension_scores["risk"] = risk_inv * weights.get("risk", 0) / w_total * 100

        # Latency/cost
        latency_cost = self._score_latency_cost(offer)
        score.dimension_scores["latency_cost"] = latency_cost * weights.get("latency_cost", 0) / w_total * 100

        score.total_score = sum(score.dimension_scores.values())

        # ── Review checks (use effective values) ───────────────────────

        # High-risk node
        if RISK_ORDER.get(effective_risk, 0) >= RISK_ORDER.get(self.policy.review_risk_at_or_above, RISK_ORDER[RISK_HIGH]):
            score.requires_review = True
            score.review_reasons.append(f"High risk: {effective_risk}")

        # External publisher (only truly remote)
        if self.policy.review_external_publisher and effective_trust == TRUST_LEVEL_REMOTE_UNTRUSTED:
            score.requires_review = True
            score.review_reasons.append(f"External/untrusted publisher: {effective_trust}")

        return score

    def _score_contract_fit(self, offer: CapabilityOffer, request: CapabilityRequest) -> float:
        """Score contract alignment. 1.0 = perfect, 0.0 = no fit."""
        fit = 0.0
        checks = 0

        # Capability match
        checks += 1
        if request.capability in offer.capabilities:
            fit += 1.0

        # Input contract
        if request.input_contract:
            checks += 1
            if request.input_contract in offer.input_contracts:
                fit += 1.0

        # Output contract
        if request.output_contract:
            checks += 1
            if request.output_contract in offer.output_contracts:
                fit += 1.0

        return fit / checks if checks > 0 else 0.0

    def _score_latency_cost(self, offer: CapabilityOffer) -> float:
        """Score latency/cost. 1.0 = best (no cost/latency), 0.0 = worst."""
        latency_part = max(0.0, 1.0 - offer.latency_ms / 1000.0) if offer.latency_ms > 0 else 1.0
        cost_part = max(0.0, 1.0 - offer.cost_usd / 10.0) if offer.cost_usd > 0 else 1.0
        return (latency_part + cost_part) / 2.0

    def _sort_admissible(self, candidates: list[CandidateScore]) -> list[CandidateScore]:
        """Deterministic sort: score desc, then tie-breakers (CR-007)."""
        def sort_key(cs: CandidateScore) -> tuple:
            o = cs.offer
            # Primary: total score (negate for descending)
            # Tie-break 1: preferred publisher
            is_preferred_pub = o.publisher_fingerprint in self.policy.preferred_publishers
            # Tie-break 2: preferred package
            is_preferred_pkg = o.package_id in self.policy.preferred_packages
            # Tie-break 3: certification recency (has cert)
            has_cert = bool(o.certification_digest)
            # Tie-break 4: higher evaluation score
            eval_s = o.evaluation_score
            # Tie-break 5: stronger trust level
            trust_s = TRUST_LEVEL_ORDER.get(o.trust_level, 0)
            # Tie-break 6: lower risk
            risk_s = -RISK_ORDER.get(o.risk_level, 0)
            # Tie-break 7: stable identity ordering
            identity = o.identity_key()

            return (
                -cs.total_score,
                -int(is_preferred_pub),
                -int(is_preferred_pkg),
                -int(has_cert),
                -eval_s,
                -trust_s,
                risk_s,
                identity,
            )

        return sorted(candidates, key=sort_key)

    def _build_rationale(
        self,
        top: CandidateScore,
        all_admissible: list[CandidateScore],
    ) -> str:
        parts = [
            f"Selected {top.offer.identity_key()} with score {top.total_score:.2f}",
            f"Dimensions: {', '.join(f'{k}={v:.1f}' for k, v in top.dimension_scores.items())}",
            f"Candidates evaluated: {len(all_admissible)}",
        ]
        if len(all_admissible) > 1:
            parts.append(f"Runner-up: {all_admissible[1].offer.identity_key()} at {all_admissible[1].total_score:.2f}")
        return "; ".join(parts)

    def _make_receipt(
        self,
        request: CapabilityRequest,
        all_scores: list[CandidateScore],
        admissible: list[CandidateScore],
        explain: bool,
        selected: CapabilityOffer | None = None,
        review_required: bool = False,
        review_reasons: list[str] | None = None,
        no_selection: bool = False,
        rationale: str = "",
    ) -> CapabilitySelectionReceipt:
        """Build the selection receipt."""
        rejected = [
            s.to_dict() for s in all_scores
            if not s.passed_hard_filters
        ] if explain else []

        receipt = CapabilitySelectionReceipt(
            receipt_id=_sha256_str(
                f"{request.compute_digest()}:{self.policy.compute_digest()}"
            )[:32],
            request_digest=request.compute_digest(),
            capability=request.capability,
            policy_digest=self.policy.compute_digest(),
            candidate_scores=[s.to_dict() for s in all_scores],
            rejected_candidates=rejected,
            human_review_required=review_required,
            human_review_status="pending" if review_required else "",
            selection_rationale=rationale,
        )

        if selected:
            receipt.selected_package_id = selected.package_id
            receipt.selected_version = selected.version
            receipt.selected_lockfile_digest = selected.dependency_graph_digest

        receipt.finalize()
        return receipt

    # ── CR-003: Selection stability ────────────────────────────────────

    def re_resolve(
        self,
        request: CapabilityRequest,
        pin: CapabilityPin | None = None,
        explain: bool = False,
    ) -> tuple[list[CandidateScore], CapabilitySelectionReceipt]:
        """Explicitly re-resolve a capability request.

        CR-003: A pinned selection is stable until explicitly re-resolved.
        This method is the governed path to updating a selection.
        If a pin is provided and the new selection differs, the receipt
        records that a drift was detected.
        """
        scores, receipt = self.resolve(request, explain=explain)

        if pin and receipt.selected_package_id:
            drift = check_capability_drift(pin, receipt)
            if drift:
                receipt.selection_rationale += (
                    "; WARNING: Re-resolution changed selection from "
                    f"{pin.package_id}@{pin.version} to "
                    f"{receipt.selected_package_id}@{receipt.selected_version}"
                )
        elif pin and not receipt.selected_package_id:
            receipt.selection_rationale += (
                "; WARNING: Re-resolution found no admissible selection; "
                f"pinned selection {pin.package_id}@{pin.version} may be stale"
            )

        return scores, receipt

    def is_selection_stable(
        self,
        pin: CapabilityPin,
        request: CapabilityRequest,
    ) -> bool:
        """CR-003: Check if a pinned selection is still stable.

        A selection is stable when re-resolution would produce the same
        package and version. This does NOT perform a silent switch —
        it only reports stability.
        """
        _, receipt = self.resolve(request)
        if not receipt.selected_package_id:
            return False
        return (
            receipt.selected_package_id == pin.package_id
            and receipt.selected_version == pin.version
        )


# ── Blueprint pinning ───────────────────────────────────────────────────────


@dataclass
class CapabilityPin:
    """Version-pinned capability resolution for blueprint embedding."""

    capability: str
    package_id: str
    version: str
    lockfile_digest: str
    receipt_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability": self.capability,
            "package_id": self.package_id,
            "version": self.version,
            "lockfile_digest": self.lockfile_digest,
            "receipt_digest": self.receipt_digest,
        }


def pin_capability(
    capability: str,
    receipt: CapabilitySelectionReceipt,
) -> CapabilityPin | None:
    """Create a capability pin from a selection receipt.

    Returns None if the receipt has no selection (review pending or no candidates).
    """
    if not receipt.selected_package_id:
        return None
    return CapabilityPin(
        capability=capability,
        package_id=receipt.selected_package_id,
        version=receipt.selected_version,
        lockfile_digest=receipt.selected_lockfile_digest,
        receipt_digest=receipt.receipt_id,
    )


# ── Drift detection ─────────────────────────────────────────────────────────


def check_capability_drift(
    pin: CapabilityPin,
    current_receipt: CapabilitySelectionReceipt,
) -> bool:
    """Check if capability resolution has drifted from the pinned selection.

    Drift occurs when:
    - Selected package or version changed
    - Lockfile digest changed
    - Previously selected candidate is now rejected
    """
    if current_receipt.selected_package_id != pin.package_id:
        return True
    if current_receipt.selected_version != pin.version:
        return True
    if current_receipt.selected_lockfile_digest != pin.lockfile_digest:
        return True
    return False


# ── Persistence ─────────────────────────────────────────────────────────────


def save_selection_receipt(receipt: CapabilitySelectionReceipt, path: str) -> None:
    """Save selection receipt atomically."""
    atomic_write_json(path, receipt.to_dict())


def save_capability_pin(pin: CapabilityPin, path: str) -> None:
    """Save capability pin atomically."""
    atomic_write_json(path, pin.to_dict())
