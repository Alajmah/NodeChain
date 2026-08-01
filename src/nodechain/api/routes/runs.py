"""Runs endpoints — list, snapshot, evidence, report, preview (v2.59.0)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from nodechain.api.auth import verify_token
from nodechain.api.models import (
    RunListResponse, RecoverySnapshotResponse, EvidenceResponse,
    ReportResponse, PreviewRequest, PreviewResponse,
)
from nodechain.api.services import (
    get_run_list, get_recovery_snapshot, get_evidence, get_report,
)
from nodechain.core.state import StateManager
from nodechain.runtime.recovery_service import RecoveryService

router = APIRouter()


def _get_sm(request: Request) -> StateManager:
    return StateManager(db_path=request.app.state.db_path)


def _get_service(request: Request) -> RecoveryService:
    sm = _get_sm(request)
    return RecoveryService(state_manager=sm, trace_dir=request.app.state.trace_dir)


def _not_found(resource: str, identifier: str) -> HTTPException:
    return HTTPException(status_code=404, detail={
        "error": {
            "code": f"{resource}_not_found",
            "message": f"No saved state found for {resource}: {identifier}",
            "details": {},
        }
    })


@router.get("/runs", response_model=RunListResponse)
async def list_runs(request: Request, token: str = Depends(verify_token)) -> RunListResponse:
    """List all runs."""
    sm = _get_sm(request)
    runs, total = get_run_list(sm)
    return RunListResponse(runs=runs, total=total)


@router.get("/runs/{run_id}", response_model=RecoverySnapshotResponse)
async def get_run(request: Request, run_id: str, token: str = Depends(verify_token)) -> RecoverySnapshotResponse:
    """Get recovery snapshot for a run."""
    sm = _get_sm(request)
    service = _get_service(request)
    snapshot = get_recovery_snapshot(sm, service, run_id)
    if snapshot is None:
        raise _not_found("run", run_id)
    return snapshot


@router.get("/runs/{run_id}/evidence", response_model=EvidenceResponse)
async def get_run_evidence(request: Request, run_id: str, token: str = Depends(verify_token)) -> EvidenceResponse:
    """Get evidence and citations for a run."""
    sm = _get_sm(request)
    evidence = get_evidence(sm, run_id)
    if evidence is None:
        raise _not_found("run", run_id)
    return evidence


@router.get("/runs/{run_id}/report", response_model=ReportResponse)
async def get_run_report(request: Request, run_id: str, token: str = Depends(verify_token)) -> ReportResponse:
    """Get recovery report for a run."""
    service = _get_service(request)
    report = get_report(service, run_id)
    if report is None:
        raise _not_found("run", run_id)
    return ReportResponse(run_id=run_id, report=report)


@router.post("/runs/{run_id}/preview", response_model=PreviewResponse)
async def preview_action(
    request: Request,
    run_id: str,
    body: PreviewRequest,
    token: str = Depends(verify_token),
) -> PreviewResponse:
    """Dry-run authorization preview for a recovery action.

    Uses RecoveryService.authorize_action() — same path as real recovery.
    Performs zero state mutation, zero event writes, zero delegation.
    """
    import os

    sm = _get_sm(request)
    state = sm.load(run_id)
    if state is None:
        raise _not_found("run", run_id)

    # Convert action string to RecoveryAction enum
    from nodechain.runtime.recovery_policy import RecoveryAction
    try:
        action_enum = RecoveryAction(body.action.lower().replace("-", "_"))
    except ValueError:
        valid = ", ".join(a.value for a in RecoveryAction)
        raise HTTPException(status_code=400, detail={
            "error": {
                "code": "invalid_action",
                "message": f"Unknown action: {body.action}",
                "details": {"valid_actions": valid},
            }
        })

    service = _get_service(request)

    resolved_role = body.role or os.environ.get("NODECHAIN_OPERATOR_ROLE", "operator")
    resolved_operator = body.operator_identity or os.environ.get("NODECHAIN_OPERATOR_IDENTITY", "console")

    auth_result = service.authorize_action(
        run_id, action_enum,
        operator_identity=resolved_operator,
        target_step_id=body.target_step_id,
        reason=body.reason,
        new_budget=body.new_budget,
        operator_role=resolved_role,
        governance_profile=body.profile,
        governance_profile_file=body.profile_file,
    )

    return PreviewResponse(
        run_id=run_id,
        action=body.action,
        admitted=auth_result.admitted,
        role=resolved_role,
        operator_identity=resolved_operator,
        governance_profile_id=auth_result.governance_profile_id,
        governance_profile_digest=auth_result.governance_profile_digest,
        denial_type=auth_result.denial_type,
        rejection_reason=auth_result.rejection_reason,
        mutated=False,
    )
