"""FastAPI application factory for the local API server (v2.59.0)."""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from nodechain import __version__
from nodechain.api.auth import verify_token, docs_enabled
from nodechain.api.models import (
    ErrorResponse, HealthResponse,
)


def create_app(db_path: str = "data/chain_state.db", trace_dir: str = "data/traces") -> FastAPI:
    """Create the FastAPI application.

    All /api/v1/* endpoints require bearer token auth.
    /docs and /openapi.json are protected by default unless NODECHAIN_API_EXPOSE_DOCS is set.
    """
    expose_docs = docs_enabled()

    app = FastAPI(
        title="NodeChain Operator API",
        description="Local read-only operator API for NodeChain — run status, evidence, recovery preview, and governance profiles.",
        version=__version__,
        docs_url="/docs" if expose_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if expose_docs else None,
    )

    # Store settings in app state
    app.state.db_path = db_path
    app.state.trace_dir = trace_dir

    # Flatten HTTPException detail to the stable error shape
    # FastAPI wraps detail as {"detail": ...}, but we want {"error": {...}} at top level
    from fastapi import HTTPException
    from fastapi.responses import JSONResponse

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request, exc):
        if isinstance(exc.detail, dict) and "error" in exc.detail:
            return JSONResponse(status_code=exc.status_code, content=exc.detail)
        return JSONResponse(status_code=exc.status_code, content={
            "error": {"code": "internal_error", "message": str(exc.detail), "details": {}}
        })

    # ── Import and register routes ─────────────────────────────────
    from nodechain.api.routes import health, runs, profiles, dashboard

    app.include_router(health.router, prefix="/api/v1", tags=["health"])
    app.include_router(runs.router, prefix="/api/v1", tags=["runs"])
    app.include_router(profiles.router, prefix="/api/v1", tags=["profiles"])
    app.include_router(dashboard.router, prefix="/api/v1", tags=["dashboard"])

    return app
