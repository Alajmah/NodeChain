"""Service adapters bridging RecoveryService/governance to API DTOs (v2.59.0)."""

from __future__ import annotations

from typing import Any

from nodechain.core.state import StateManager
from nodechain.runtime.recovery_service import RecoveryService
from nodechain.runtime.governance_profiles import (
    get_builtin_profile, compute_profile_digest, BUILTIN_PROFILES,
    ALL_ROLES, ALL_ACTIONS,
)
from nodechain.runtime.recovery_policy import ACTION_ALLOWED_ROLES
from nodechain.runtime.recovery_classifier import classify

from nodechain.api.models import (
    RunSummary, RecoverySnapshotResponse, EvidenceResponse,
    ProfileSummary, ProfileDetailResponse, DashboardResponse,
)


def get_run_list(sm: StateManager) -> tuple[list[RunSummary], int]:
    """Get list of all runs."""
    all_runs = sm.list_all_runs()
    summaries = []
    for r in all_runs:
        # Handle both RunSummary objects and dicts
        if hasattr(r, "run_id"):
            summaries.append(RunSummary(
                run_id=r.run_id,
                chain_id=r.chain_id,
                status=r.status,
                step=r.step if hasattr(r, "step") else None,
                current_node=r.current_node if hasattr(r, "current_node") else None,
                updated_at=str(r.updated_at) if hasattr(r, "updated_at") and r.updated_at else None,
            ))
        else:
            summaries.append(RunSummary(
                run_id=r.get("run_id", ""),
                chain_id=r.get("chain_id", ""),
                status=r.get("status", ""),
                step=r.get("step"),
                current_node=r.get("current_node"),
                updated_at=r.get("updated_at"),
            ))
    return summaries, len(summaries)


def get_recovery_snapshot(sm: StateManager, service: RecoveryService, run_id: str) -> RecoverySnapshotResponse | None:
    """Get recovery snapshot for a run."""
    snapshot = service.build_snapshot(run_id)
    if snapshot is None:
        return None
    return RecoverySnapshotResponse(
        run_id=snapshot.run_id,
        chain_id=snapshot.chain_id,
        status=snapshot.status,
        recovery_state=snapshot.recovery_state,
        current_node=snapshot.current_node,
        current_step=snapshot.current_step,
        last_successful_step=snapshot.last_successful_step,
        failed_step=snapshot.failed_step,
        blocking_reason=snapshot.blocking_reason,
        state_revision=snapshot.state_revision,
        last_update_time=snapshot.last_update_time,
        trace_complete=snapshot.trace_complete,
        available_actions=snapshot.available_actions or [],
    )


def get_evidence(sm: StateManager, run_id: str) -> EvidenceResponse | None:
    """Get evidence/citations for a run."""
    state = sm.load(run_id)
    if state is None:
        return None

    outputs = state.outputs or {}
    synth = outputs.get("evidence_synthesizer", {}) if isinstance(outputs.get("evidence_synthesizer"), dict) else {}
    risk = outputs.get("risk_classifier", {}) if isinstance(outputs.get("risk_classifier"), dict) else {}
    val = outputs.get("claim_validator", {}) if isinstance(outputs.get("claim_validator"), dict) else {}
    resp = outputs.get("response_generator", {}) if isinstance(outputs.get("response_generator"), dict) else {}

    return EvidenceResponse(
        run_id=run_id,
        sources=synth.get("sources", []),
        claims=synth.get("claims", []),
        validated_claims=risk.get("validated_claims", []),
        validation_summary=val.get("validation_summary", {}),
        risk_assessment={k: v for k, v in risk.items() if k in ("risk_level", "confidence", "review_required", "risk_factors")},
        citations=resp.get("citations", []),
        recommendation=resp.get("recommendation", ""),
    )


def get_report(service: RecoveryService, run_id: str) -> dict[str, Any] | None:
    """Get recovery report for a run."""
    snapshot = service.build_snapshot(run_id)
    if snapshot is None:
        return None
    return {
        "run_id": run_id,
        "snapshot": snapshot.model_dump() if hasattr(snapshot, "model_dump") else {},
    }


def get_profile_list() -> tuple[list[ProfileSummary], int]:
    """Get list of built-in governance profiles."""
    summaries = []
    for name in sorted(BUILTIN_PROFILES.keys()):
        p = BUILTIN_PROFILES[name]
        summaries.append(ProfileSummary(
            id=p.id,
            display_name=p.display_name,
            max_actions=p.batch.max_actions,
            digest=compute_profile_digest(p),
        ))
    return summaries, len(summaries)


def get_profile_detail(profile_id: str) -> ProfileDetailResponse | None:
    """Get full governance detail for a profile."""
    try:
        p = get_builtin_profile(profile_id)
    except KeyError:
        return None

    # Build action matrix
    action_matrix: dict[str, dict[str, bool]] = {}
    for action_name in ALL_ACTIONS:
        base_roles = ACTION_ALLOWED_ROLES.get(action_name, set())
        action_gov = p.actions.get(action_name)
        profile_roles = action_gov.allowed_roles if action_gov else p.roles.allowed_roles
        action_matrix[action_name] = {
            role: (role in base_roles and role in profile_roles)
            for role in ALL_ROLES
        }

    return ProfileDetailResponse(
        id=p.id,
        display_name=p.display_name,
        description=p.description,
        version=p.version,
        roles=list(p.roles.allowed_roles),
        default_role=p.roles.default_role,
        digest=compute_profile_digest(p),
        action_matrix=action_matrix,
        budget={
            "approve_roles": list(p.budget.approve_roles),
            "require_reason": p.budget.require_reason,
            "max_new_budget_usd": p.budget.max_new_budget_usd,
            "max_increase_multiplier": p.budget.max_increase_multiplier,
        },
        override={
            "non_retryable_retry_requires_admin": p.override.non_retryable_retry_requires_admin,
            "non_retryable_retry_requires_env_override": p.override.non_retryable_retry_requires_env_override,
            "break_glass_requires_env_override": p.override.break_glass_requires_env_override,
        },
        audit={
            "require_operator_identity": p.audit.require_operator_identity,
            "require_reason_for_mutations": p.audit.require_reason_for_mutations,
            "record_profile_digest": p.audit.record_profile_digest,
        },
        batch={
            "enabled": p.batch.enabled,
            "max_actions": p.batch.max_actions,
            "allow_continue_on_error": p.batch.allow_continue_on_error,
            "require_dry_run_before_execute": p.batch.require_dry_run_before_execute,
        },
    )


def get_dashboard(sm: StateManager, service: RecoveryService | None = None) -> DashboardResponse:
    """Get dashboard summary."""
    all_runs = sm.list_all_runs()
    backlog_by_state: dict[str, int] = {}

    for run_summary in all_runs:
        run_id = run_summary.run_id if hasattr(run_summary, "run_id") else run_summary.get("run_id", "")

        # Use RecoveryService.build_snapshot for proper classification
        if service:
            snapshot = service.build_snapshot(run_id)
            recovery_state = snapshot.recovery_state if snapshot else None
        else:
            state = sm.load(run_id)
            if state is None:
                continue
            # Simple status-based fallback
            recovery_state = state.status.upper() if state.status != "completed" else "COMPLETED"

        if recovery_state and recovery_state != "COMPLETED":
            backlog_by_state[recovery_state] = backlog_by_state.get(recovery_state, 0) + 1

    return DashboardResponse(
        total_runs=len(all_runs),
        recovery_backlog=sum(backlog_by_state.values()),
        backlog_by_state=backlog_by_state,
    )
