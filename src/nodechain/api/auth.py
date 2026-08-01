"""Token-based auth dependency for the local API (v2.59.0).

Simple bearer token model: NODECHAIN_API_TOKEN env var must be set at startup.
All /api/v1/* endpoints require Authorization: Bearer <token>.
"""

from __future__ import annotations

import os
import secrets

from fastapi import HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_security = HTTPBearer(auto_error=False)


def get_api_token() -> str:
    """Get the required API token from environment. Raises if missing."""
    token = os.environ.get("NODECHAIN_API_TOKEN", "").strip()
    if not token:
        raise RuntimeError(
            "NODECHAIN_API_TOKEN environment variable is required to start the API server. "
            "Set it to a secure random string."
        )
    return token


async def verify_token(
    credentials: HTTPAuthorizationCredentials | None = Security(_security),
) -> str:
    """FastAPI dependency that verifies the bearer token."""
    expected = get_api_token()

    if credentials is None:
        raise HTTPException(status_code=401, detail={
            "error": {
                "code": "unauthorized",
                "message": "Missing Authorization header",
                "details": {},
            }
        })

    if not secrets.compare_digest(credentials.credentials, expected):
        raise HTTPException(status_code=403, detail={
            "error": {
                "code": "forbidden",
                "message": "Invalid API token",
                "details": {},
            }
        })

    return credentials.credentials


def docs_enabled() -> bool:
    """Check if /docs and /openapi.json should be exposed."""
    return os.environ.get("NODECHAIN_API_EXPOSE_DOCS", "").strip() in ("1", "true", "yes")
