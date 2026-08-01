"""Profiles endpoints — list and detail (v2.59.0)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from nodechain.api.auth import verify_token
from nodechain.api.models import ProfileListResponse, ProfileDetailResponse
from nodechain.api.services import get_profile_list, get_profile_detail

router = APIRouter()


@router.get("/profiles", response_model=ProfileListResponse)
async def list_profiles(token: str = Depends(verify_token)) -> ProfileListResponse:
    """List all built-in governance profiles."""
    profiles, total = get_profile_list()
    return ProfileListResponse(profiles=profiles, total=total)


@router.get("/profiles/{profile_id}", response_model=ProfileDetailResponse)
async def get_profile(profile_id: str, token: str = Depends(verify_token)) -> ProfileDetailResponse:
    """Get full governance detail for a profile."""
    detail = get_profile_detail(profile_id)
    if detail is None:
        raise HTTPException(status_code=404, detail={
            "error": {
                "code": "profile_not_found",
                "message": f"Unknown profile: {profile_id}",
                "details": {},
            }
        })
    return detail
