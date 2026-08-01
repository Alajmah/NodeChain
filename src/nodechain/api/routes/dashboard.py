"""Dashboard endpoint (v2.59.0)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from nodechain.api.auth import verify_token
from nodechain.api.models import DashboardResponse
from nodechain.api.services import get_dashboard
from nodechain.core.state import StateManager

router = APIRouter()


@router.get("/dashboard", response_model=DashboardResponse)
async def dashboard(request: Request, token: str = Depends(verify_token)) -> DashboardResponse:
    """Get operator dashboard summary (backlog by state)."""
    from nodechain.runtime.recovery_service import RecoveryService
    sm = StateManager(db_path=request.app.state.db_path)
    service = RecoveryService(state_manager=sm, trace_dir=request.app.state.trace_dir)
    return get_dashboard(sm, service)
