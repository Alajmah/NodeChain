"""Health endpoint (v2.59.0)."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from nodechain import __version__
from nodechain.api.auth import verify_token
from nodechain.api.models import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health(token: str = Depends(verify_token)) -> HealthResponse:
    """Server health and version."""
    return HealthResponse(status="ok", version=__version__, api_version="v1")
