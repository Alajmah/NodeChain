"""Pydantic request/response models for the local API (v2.59.0)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


# ── Error model ───────────────────────────────────────────────────────────

class ErrorDetail(BaseModel):
    code: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


class ErrorResponse(BaseModel):
    error: ErrorDetail


# ── Health ────────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
    api_version: str = "v1"


# ── Runs ──────────────────────────────────────────────────────────────────

class RunSummary(BaseModel):
    run_id: str
    chain_id: str
    status: str
    step: int | None = None
    current_node: str | None = None
    updated_at: str | None = None


class RunListResponse(BaseModel):
    runs: list[RunSummary]
    total: int


class RecoverySnapshotResponse(BaseModel):
    run_id: str
    chain_id: str
    status: str
    recovery_state: str | None = None
    current_node: str | None = None
    current_step: int | None = None
    last_successful_step: int | None = None
    failed_step: int | None = None
    blocking_reason: str | None = None
    state_revision: int = 0
    last_update_time: str | None = None
    trace_complete: bool = True
    available_actions: list[str] = Field(default_factory=list)


# ── Evidence ──────────────────────────────────────────────────────────────

class EvidenceResponse(BaseModel):
    run_id: str
    sources: list[dict[str, Any]] = Field(default_factory=list)
    claims: list[dict[str, Any]] = Field(default_factory=list)
    validated_claims: list[dict[str, Any]] = Field(default_factory=list)
    validation_summary: dict[str, Any] = Field(default_factory=dict)
    risk_assessment: dict[str, Any] = Field(default_factory=dict)
    citations: list[dict[str, Any]] = Field(default_factory=list)
    recommendation: str = ""


# ── Report ────────────────────────────────────────────────────────────────

class ReportResponse(BaseModel):
    run_id: str
    report: dict[str, Any]


# ── Profiles ──────────────────────────────────────────────────────────────

class ProfileSummary(BaseModel):
    id: str
    display_name: str
    max_actions: int
    digest: str


class ProfileListResponse(BaseModel):
    profiles: list[ProfileSummary]
    total: int


class ProfileDetailResponse(BaseModel):
    id: str
    display_name: str
    description: str
    version: str
    roles: list[str]
    default_role: str
    digest: str
    action_matrix: dict[str, dict[str, bool]] = Field(default_factory=dict)
    budget: dict[str, Any] = Field(default_factory=dict)
    override: dict[str, Any] = Field(default_factory=dict)
    audit: dict[str, Any] = Field(default_factory=dict)
    batch: dict[str, Any] = Field(default_factory=dict)


# ── Dashboard ─────────────────────────────────────────────────────────────

class DashboardResponse(BaseModel):
    total_runs: int
    recovery_backlog: int
    backlog_by_state: dict[str, int] = Field(default_factory=dict)


# ── Preview ───────────────────────────────────────────────────────────────

class PreviewRequest(BaseModel):
    action: str
    role: str | None = None
    operator_identity: str | None = None
    profile: str | None = None
    profile_file: str | None = None
    target_step_id: int | None = None
    reason: str | None = None
    new_budget: float | None = None


class PreviewResponse(BaseModel):
    run_id: str
    action: str
    admitted: bool
    role: str
    operator_identity: str
    governance_profile_id: str | None = None
    governance_profile_digest: str | None = None
    denial_type: str | None = None
    rejection_reason: str | None = None
    mutated: bool = False
