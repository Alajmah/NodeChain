"""Pydantic v2 models for every ResearchWorkspaceBundleV1 document.

Field names EXACTLY match the JSON schema property names (snake_case). All
models are frozen and reject unknown fields (``extra="forbid"``), mirroring the
``additionalProperties: false`` rule in the JSON schemas. Enum values mirror the
shared definitions in ``research_workspace_definitions.json``.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #


class BundleVersion(str, Enum):
    """Bundle contract version. Fixed to ``"1.0"`` for the V1 contract."""

    V1_0 = "1.0"


class RunStatus(str, Enum):
    """Lifecycle status of a research run."""

    RUNNING = "running"
    PAUSED_FOR_REVIEW = "paused_for_review"
    COMPLETED = "completed"
    COMPLETED_DEGRADED = "completed_degraded"
    FAILED = "failed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"


class ClaimStatus(str, Enum):
    """Validation outcome for a synthesized claim."""

    SUPPORTED = "supported"
    PARTIALLY_SUPPORTED = "partially_supported"
    CONTESTED = "contested"
    UNSUPPORTED = "unsupported"
    REJECTED = "rejected"


class ReviewDecisionType(str, Enum):
    """Decision recorded by a human reviewer at a review gate."""

    APPROVE = "approve"
    REJECT = "reject"
    REVISE = "revise"


class FaultType(str, Enum):
    """Class of failure recorded against an adapter or run step."""

    FAIL_BEFORE_DISPATCH = "fail_before_dispatch"
    TIMEOUT_AFTER_DISPATCH = "timeout_after_dispatch"
    MALFORMED_PROVENANCE = "malformed_provenance"
    PARTIAL_RESULT_SET = "partial_result_set"


class TargetType(str, Enum):
    """The kind of artifact a validation check targets."""

    SOURCE = "source"
    EVIDENCE = "evidence"
    CLAIM = "claim"
    CITATION = "citation"


class NodeType(str, Enum):
    """Type of a plan-step node."""

    MODEL = "model"
    DETERMINISTIC = "deterministic"
    TOOL = "tool"


class TargetDepth(str, Enum):
    """Requested research depth."""

    SHALLOW = "shallow"
    STANDARD = "standard"
    DEEP = "deep"


class OverallUncertainty(str, Enum):
    """Aggregate uncertainty assessment for the run."""

    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"


# --------------------------------------------------------------------------- #
# Base
# --------------------------------------------------------------------------- #


class _BundleModel(BaseModel):
    """Common config: frozen, no extras (mirrors additionalProperties:false)."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        use_enum_values=False,
    )


def _nonempty_str(v: str) -> str:
    if not isinstance(v, str) or not v.strip():
        raise ValueError("must be a non-empty string")
    return v


# --------------------------------------------------------------------------- #
# Shared records
# --------------------------------------------------------------------------- #


class FileHash(_BundleModel):
    """A file path paired with its SHA-256 digest."""

    path: str
    sha256: str

    @field_validator("path")
    @classmethod
    def _check_path(cls, v: str) -> str:
        return _nonempty_str(v)

    @field_validator("sha256")
    @classmethod
    def _check_sha(cls, v: str) -> str:
        import re

        if not re.fullmatch(r"[a-f0-9]{64}", v or ""):
            raise ValueError("sha256 must be 64 lowercase hex characters")
        return v


class SourceRecord(_BundleModel):
    """A retrieved and ingested source record."""

    source_id: str
    origin_api: str
    query_used: str
    retrieved_at: datetime
    title: str
    doi: str | None = None
    authors: list[str] = Field(default_factory=list)
    abstract: str | None = None
    source_hash: str

    @field_validator("source_id", "origin_api", "title")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        return _nonempty_str(v)

    @field_validator("source_hash")
    @classmethod
    def _check_sha(cls, v: str) -> str:
        import re

        if not re.fullmatch(r"[a-f0-9]{64}", v or ""):
            raise ValueError("source_hash must be 64 lowercase hex characters")
        return v


class EvidenceRecord(_BundleModel):
    """An evidence fragment extracted from one or more sources."""

    evidence_id: str
    source_ids: list[str]
    extracted_text: str
    evidence_type: str
    confidence: float

    @field_validator("evidence_id", "extracted_text", "evidence_type")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        return _nonempty_str(v)

    @field_validator("source_ids")
    @classmethod
    def _at_least_one_source(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("source_ids must contain at least one entry")
        for sid in v:
            _nonempty_str(sid)
        return v

    @field_validator("confidence")
    @classmethod
    def _confidence_range(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("confidence must be in [0.0, 1.0]")
        return v


class UncertaintyMarker(_BundleModel):
    """A recorded uncertainty marker associated with one or more claims."""

    marker_id: str
    description: str
    affected_claim_ids: list[str] = Field(default_factory=list)

    @field_validator("marker_id", "description")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        return _nonempty_str(v)


class ValidationResult(_BundleModel):
    """Result of a single automated validation check against a target."""

    validation_id: str
    target_type: TargetType
    target_id: str
    check_name: str
    passed: bool
    message: str = ""

    @field_validator("validation_id", "target_id", "check_name")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        return _nonempty_str(v)


class ClaimRecord(_BundleModel):
    """A synthesized research claim with provenance, status, and history."""

    claim_id: str
    statement: str
    status: ClaimStatus
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    contradicting_evidence_ids: list[str] = Field(default_factory=list)
    citation_ids: list[str] = Field(default_factory=list)
    confidence: float
    uncertainty_markers: list[UncertaintyMarker] = Field(default_factory=list)
    validation_results: list[ValidationResult] = Field(default_factory=list)

    @field_validator("claim_id", "statement")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        return _nonempty_str(v)

    @field_validator("confidence")
    @classmethod
    def _confidence_range(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("confidence must be in [0.0, 1.0]")
        return v


class CitationRecord(_BundleModel):
    """A formatted citation record linking a source to its evidence."""

    citation_id: str
    source_id: str
    evidence_ids: list[str] = Field(default_factory=list)
    formatted_citation: str

    @field_validator("citation_id", "source_id", "formatted_citation")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        return _nonempty_str(v)


class PolicyDecision(_BundleModel):
    """A governance / policy decision recorded during the run."""

    decision_id: str
    decision_type: str
    reason: str
    decided_at: datetime
    decider_identity: str

    @field_validator("decision_id", "decision_type", "reason", "decider_identity")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        return _nonempty_str(v)


class ReviewDecision(_BundleModel):
    """A human review decision recorded at a review gate."""

    review_id: str
    run_id: str
    decision: ReviewDecisionType
    reason: str
    reviewer_identity: str
    decided_at: datetime

    @field_validator(
        "review_id", "run_id", "reason", "reviewer_identity"
    )
    @classmethod
    def _nonempty(cls, v: str) -> str:
        return _nonempty_str(v)


class FailureRecord(_BundleModel):
    """A recorded failure affecting one or more claims."""

    failure_id: str
    adapter_name: str
    fault_type: FaultType
    occurred_at: datetime
    dispatch_occurred: bool
    evidence_unavailable: bool
    affected_claim_ids: list[str] = Field(default_factory=list)

    @field_validator("failure_id", "adapter_name")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        return _nonempty_str(v)


# --------------------------------------------------------------------------- #
# Brief / run / plan embedded sub-objects
# --------------------------------------------------------------------------- #


class BriefTimeRange(_BundleModel):
    start: datetime
    end: datetime


class BriefScope(_BundleModel):
    domains: list[str]
    time_range: BriefTimeRange

    @field_validator("domains")
    @classmethod
    def _domains_nonempty(cls, v: list[str]) -> list[str]:
        for d in v:
            _nonempty_str(d)
        return v


class BriefConstraints(_BundleModel):
    min_sources: int
    max_sources: int
    required_adapters: list[str]
    excluded_adapters: list[str] = Field(default_factory=list)

    @field_validator("min_sources", "max_sources")
    @classmethod
    def _non_negative(cls, v: int) -> int:
        if v < 0:
            raise ValueError("must be >= 0")
        return v

    @field_validator("required_adapters", "excluded_adapters")
    @classmethod
    def _nonempty_entries(cls, v: list[str]) -> list[str]:
        for a in v:
            _nonempty_str(a)
        return v


class RunStepCompleted(_BundleModel):
    node_id: str
    completed_at: datetime
    succeeded: bool
    failure_id: str | None = None

    @field_validator("node_id")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        return _nonempty_str(v)


class PlanStep(_BundleModel):
    node_id: str
    position: int
    node_type: NodeType
    adapter: str | None = None
    query_template: str | None = None
    depends_on: list[str] = Field(default_factory=list)

    @field_validator("node_id")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        return _nonempty_str(v)

    @field_validator("position")
    @classmethod
    def _position(cls, v: int) -> int:
        if v < 1:
            raise ValueError("position must be >= 1")
        return v


# --------------------------------------------------------------------------- #
# Top-level documents
# --------------------------------------------------------------------------- #


class ResearchBrief(_BundleModel):
    bundle_version: BundleVersion = BundleVersion.V1_0
    run_id: str
    created_at: datetime
    question: str
    scope: BriefScope
    constraints: BriefConstraints
    target_depth: TargetDepth
    preferred_language: str | None = None
    memory_context_requested: bool = False

    @field_validator("run_id", "question")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        return _nonempty_str(v)


class ResearchRun(_BundleModel):
    bundle_version: BundleVersion = BundleVersion.V1_0
    run_id: str
    chain_id: str
    started_at: datetime
    updated_at: datetime
    status: RunStatus
    provider_mode: str
    current_step: str
    steps_completed: list[RunStepCompleted] = Field(default_factory=list)
    input_digest: str | None = None
    finalized_at: datetime | None = None
    replay_eligible: bool = False

    @field_validator("run_id", "chain_id", "provider_mode", "current_step")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        return _nonempty_str(v)

    @field_validator("input_digest")
    @classmethod
    def _check_sha_opt(cls, v: str | None) -> str | None:
        if v is None:
            return v
        import re

        if not re.fullmatch(r"[a-f0-9]{64}", v):
            raise ValueError("input_digest must be 64 lowercase hex characters")
        return v


class ResearchPlan(_BundleModel):
    bundle_version: BundleVersion = BundleVersion.V1_0
    run_id: str
    created_at: datetime
    steps: list[PlanStep]
    adapters_required: list[str]
    estimated_cost_usd: float
    revised_from: str | None = None
    loop_triggered: bool = False

    @field_validator("run_id")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        return _nonempty_str(v)

    @field_validator("steps")
    @classmethod
    def _at_least_one_step(cls, v: list[PlanStep]) -> list[PlanStep]:
        if not v:
            raise ValueError("steps must contain at least one entry")
        return v

    @field_validator("estimated_cost_usd")
    @classmethod
    def _non_negative(cls, v: float) -> float:
        if v < 0:
            raise ValueError("estimated_cost_usd must be >= 0")
        return v


class ResearchSources(_BundleModel):
    bundle_version: BundleVersion = BundleVersion.V1_0
    run_id: str
    retrieved_at: datetime
    sources: list[SourceRecord] = Field(default_factory=list)
    adapter_coverage: dict[str, int] = Field(default_factory=dict)
    deduplication_count: int = 0

    @field_validator("run_id")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        return _nonempty_str(v)


class ResearchEvidence(_BundleModel):
    bundle_version: BundleVersion = BundleVersion.V1_0
    run_id: str
    extracted_at: datetime
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    extraction_model: str | None = None
    mean_confidence: float | None = None

    @field_validator("run_id")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        return _nonempty_str(v)

    @field_validator("mean_confidence")
    @classmethod
    def _confidence_range(cls, v: float | None) -> float | None:
        if v is None:
            return v
        if not 0.0 <= v <= 1.0:
            raise ValueError("mean_confidence must be in [0.0, 1.0]")
        return v


class ResearchClaims(_BundleModel):
    bundle_version: BundleVersion = BundleVersion.V1_0
    run_id: str
    synthesized_at: datetime
    claims: list[ClaimRecord] = Field(default_factory=list)
    synthesis_model: str | None = None
    executive_answer: str | None = None

    @field_validator("run_id")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        return _nonempty_str(v)


class ResearchCitations(_BundleModel):
    bundle_version: BundleVersion = BundleVersion.V1_0
    run_id: str
    formatted_at: datetime
    citations: list[CitationRecord] = Field(default_factory=list)
    style: str | None = None

    @field_validator("run_id")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        return _nonempty_str(v)


class ResearchUncertainties(_BundleModel):
    bundle_version: BundleVersion = BundleVersion.V1_0
    run_id: str
    recorded_at: datetime
    uncertainties: list[UncertaintyMarker] = Field(default_factory=list)
    overall_uncertainty: OverallUncertainty | None = None

    @field_validator("run_id")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        return _nonempty_str(v)


class ResearchValidations(_BundleModel):
    bundle_version: BundleVersion = BundleVersion.V1_0
    run_id: str
    executed_at: datetime
    validation_results: list[ValidationResult] = Field(default_factory=list)
    checks_run: list[str] = Field(default_factory=list)
    pass_rate: float | None = None

    @field_validator("run_id")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        return _nonempty_str(v)

    @field_validator("pass_rate")
    @classmethod
    def _confidence_range(cls, v: float | None) -> float | None:
        if v is None:
            return v
        if not 0.0 <= v <= 1.0:
            raise ValueError("pass_rate must be in [0.0, 1.0]")
        return v


class ResearchPolicyDecisions(_BundleModel):
    bundle_version: BundleVersion = BundleVersion.V1_0
    run_id: str
    recorded_at: datetime
    policy_decisions: list[PolicyDecision] = Field(default_factory=list)
    policy_version: str | None = None

    @field_validator("run_id")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        return _nonempty_str(v)


class ResearchReviewDecisions(_BundleModel):
    bundle_version: BundleVersion = BundleVersion.V1_0
    run_id: str
    recorded_at: datetime
    review_decisions: list[ReviewDecision] = Field(default_factory=list)
    review_required: bool = False
    review_completed: bool = False

    @field_validator("run_id")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        return _nonempty_str(v)


class ResearchFailures(_BundleModel):
    bundle_version: BundleVersion = BundleVersion.V1_0
    run_id: str
    recorded_at: datetime
    failures: list[FailureRecord] = Field(default_factory=list)
    degraded_mode: bool = False
    affected_adapter_count: int = 0

    @field_validator("run_id")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        return _nonempty_str(v)


class ResearchWorkspaceManifest(_BundleModel):
    bundle_version: BundleVersion = BundleVersion.V1_0
    run_id: str
    chain_id: str
    blueprint_version: str
    created_at: datetime
    finalized_at: datetime
    run_status: RunStatus
    source_commit: str
    input_digest: str
    artifact_inventory: list[FileHash] = Field(default_factory=list)
    bundle_digest: str
    provider_mode: str
    fixture_corpus_version: str
    trace_reference: str
    replay_eligible: bool

    @field_validator(
        "run_id", "chain_id", "blueprint_version", "source_commit",
        "provider_mode", "fixture_corpus_version",
    )
    @classmethod
    def _nonempty(cls, v: str) -> str:
        return _nonempty_str(v)

    @field_validator("input_digest", "bundle_digest")
    @classmethod
    def _check_sha(cls, v: str) -> str:
        import re

        if not re.fullmatch(r"[a-f0-9]{64}", v or ""):
            raise ValueError("must be 64 lowercase hex characters")
        return v

    @field_validator("trace_reference")
    @classmethod
    def _no_absolute_path(cls, v: str) -> str:
        _nonempty_str(v)
        if v.startswith("/"):
            raise ValueError("trace_reference must be a relative path")
        if ".." in v.split("/"):
            raise ValueError("trace_reference must not contain '..'")
        return v


class ResearchWorkspaceReport(_BundleModel):
    run_id: str
    run_status: RunStatus
    executive_answer: str
    claim_count: int
    supported_claims: int
    contested_claims: int
    sources_cited: int
    adapters_used: list[str]
    failures_recorded: int
    review_required: bool
    review_completed: bool
    replay_eligible: bool

    @field_validator("run_id")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        return _nonempty_str(v)

    @field_validator(
        "claim_count", "supported_claims", "contested_claims",
        "sources_cited", "failures_recorded",
    )
    @classmethod
    def _non_negative(cls, v: int) -> int:
        if v < 0:
            raise ValueError("must be >= 0")
        return v


# --------------------------------------------------------------------------- #
# Container
# --------------------------------------------------------------------------- #


class WorkspaceBundle(BaseModel):
    """Container holding all 15 bundle documents plus the manifest.

    The manifest is included both here and as the ``manifest`` field; it is the
    authoritative inventory of every other document.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    manifest: ResearchWorkspaceManifest
    brief: ResearchBrief
    run: ResearchRun
    plan: ResearchPlan
    sources: ResearchSources
    evidence: ResearchEvidence
    claims: ResearchClaims
    citations: ResearchCitations
    uncertainties: ResearchUncertainties
    validations: ResearchValidations
    policy_decisions: ResearchPolicyDecisions
    review_decisions: ResearchReviewDecisions
    failures: ResearchFailures
    trace: dict[str, Any]
    report: ResearchWorkspaceReport
