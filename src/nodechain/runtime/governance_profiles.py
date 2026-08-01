"""Governance profiles for operator recovery (v2.52.0).

Named, auditable profiles that make the v2.49–v2.51 recovery authorization
system configurable. Profiles may make recovery stricter but cannot weaken
hard security floors.

Hard floors (enforced by validate_profile_hard_floors):
  1. operator can never approve budgets
  2. non-retryable retry must require admin + override
  3. invalid roles fail closed
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel


# ── Submodels ────────────────────────────────────────────────────────────────

class RolePolicy(BaseModel):
    allowed_roles: list[str]
    default_role: str = "operator"

    model_config = {"extra": "forbid"}


class ActionGovernance(BaseModel):
    allowed_roles: list[str]
    require_reason: bool = False
    require_override: bool = False

    model_config = {"extra": "forbid"}


class BudgetGovernance(BaseModel):
    approve_roles: list[str]
    require_reason: bool = True
    max_new_budget_usd: float | None = None
    max_increase_multiplier: float | None = None

    model_config = {"extra": "forbid"}


class BatchGovernance(BaseModel):
    enabled: bool = True
    max_actions: int = 50
    allow_continue_on_error: bool = True
    require_dry_run_before_execute: bool = False

    model_config = {"extra": "forbid"}


class AuditGovernance(BaseModel):
    require_operator_identity: bool = False
    require_reason_for_mutations: bool = False
    # record_profile_digest is reserved — digest is always recorded regardless
    # of this value. Kept in schema for forward-compat but does not gate behavior.
    record_profile_digest: bool = True

    model_config = {"extra": "forbid"}


class OverrideGovernance(BaseModel):
    non_retryable_retry_requires_admin: bool = True
    non_retryable_retry_requires_env_override: bool = True
    break_glass_requires_env_override: bool = True

    model_config = {"extra": "forbid"}


class GovernanceProfile(BaseModel):
    id: str
    display_name: str
    description: str = ""
    version: str = "1"
    roles: RolePolicy
    actions: dict[str, ActionGovernance]
    budget: BudgetGovernance
    batch: BatchGovernance
    audit: AuditGovernance
    override: OverrideGovernance

    model_config = {"extra": "forbid"}


# ── All roles and actions ───────────────────────────────────────────────────

ALL_ROLES = ["operator", "finance", "admin"]
ALL_ACTIONS = [
    "resume", "retry_step", "approve_review", "reject_review",
    "request_revision", "route_fallback", "cancel_run", "fail_run",
    "export_report", "approve_budget_increase",
    "resolve_side_effect",  # v3.3.0
    "execute_retry_authorized",  # v3.5.0
]


def _default_actions(roles: list[str] | None = None) -> dict[str, ActionGovernance]:
    """Generate action governance for all actions with the given roles."""
    r = roles or ALL_ROLES
    return {
        action: ActionGovernance(allowed_roles=list(r))
        for action in ALL_ACTIONS
    }


# ── Built-in profiles ───────────────────────────────────────────────────────

def _build_builtins() -> dict[str, GovernanceProfile]:
    profiles: dict[str, GovernanceProfile] = {}

    # team-default: preserves v2.51.0 behavior
    profiles["team-default"] = GovernanceProfile(
        id="team-default",
        display_name="Team Default",
        description="Default governed recovery policy for normal team operation.",
        roles=RolePolicy(allowed_roles=ALL_ROLES, default_role="operator"),
        actions=_default_actions(),
        budget=BudgetGovernance(approve_roles=["finance", "admin"], require_reason=True),
        batch=BatchGovernance(max_actions=50, allow_continue_on_error=True),
        audit=AuditGovernance(),
        override=OverrideGovernance(),
    )

    # solo-dev: lower friction, same hard floors
    profiles["solo-dev"] = GovernanceProfile(
        id="solo-dev",
        display_name="Solo Dev",
        description="Lower-friction recovery for solo development and non-production use.",
        roles=RolePolicy(allowed_roles=ALL_ROLES, default_role="operator"),
        actions=_default_actions(),
        budget=BudgetGovernance(approve_roles=["finance", "admin"], require_reason=True),
        batch=BatchGovernance(max_actions=100, allow_continue_on_error=True),
        audit=AuditGovernance(record_profile_digest=True),
        override=OverrideGovernance(),
    )

    # regulated: audit-heavy, strict
    profiles["regulated"] = GovernanceProfile(
        id="regulated",
        display_name="Regulated",
        description="Strict recovery governance for regulated environments.",
        roles=RolePolicy(allowed_roles=ALL_ROLES, default_role="operator"),
        actions={
            a: ActionGovernance(allowed_roles=ALL_ROLES, require_reason=True)
            for a in ALL_ACTIONS
        },
        budget=BudgetGovernance(approve_roles=["finance", "admin"], require_reason=True),
        batch=BatchGovernance(max_actions=20, allow_continue_on_error=False,
                              require_dry_run_before_execute=True),
        audit=AuditGovernance(require_operator_identity=True,
                              require_reason_for_mutations=True,
                              record_profile_digest=True),
        override=OverrideGovernance(),
    )

    # break-glass: admin-only, heavily audited
    profiles["break-glass"] = GovernanceProfile(
        id="break-glass",
        display_name="Break Glass",
        description="Emergency profile: admin-only, highly audited, more permissive for admin.",
        roles=RolePolicy(allowed_roles=["admin"], default_role="admin"),
        actions={
            a: ActionGovernance(allowed_roles=["admin"], require_reason=True)
            for a in ALL_ACTIONS
        },
        budget=BudgetGovernance(approve_roles=["admin"], require_reason=True),
        batch=BatchGovernance(max_actions=10, allow_continue_on_error=False),
        audit=AuditGovernance(require_operator_identity=True,
                              require_reason_for_mutations=True,
                              record_profile_digest=True),
        override=OverrideGovernance(break_glass_requires_env_override=True),
    )

    return profiles


BUILTIN_PROFILES: dict[str, GovernanceProfile] = _build_builtins()


def get_builtin_profile(name: str) -> GovernanceProfile:
    """Get a built-in profile by name. Raises KeyError if unknown."""
    if name not in BUILTIN_PROFILES:
        raise KeyError(f"unknown governance profile: '{name}'. "
                       f"Available: {', '.join(sorted(BUILTIN_PROFILES.keys()))}")
    return BUILTIN_PROFILES[name]


# ── Digest ──────────────────────────────────────────────────────────────────

def compute_profile_digest(profile: GovernanceProfile) -> str:
    """Compute a stable SHA-256 digest of a profile's canonical JSON."""
    canonical = json.dumps(profile.model_dump(), sort_keys=True, separators=(",", ":"))
    h = hashlib.sha256(canonical.encode()).hexdigest()
    return f"sha256:{h[:16]}"


# ── Hard floor validation ───────────────────────────────────────────────────

def validate_profile_hard_floors(profile: GovernanceProfile) -> None:
    """Validate that a profile does not weaken any hard security floor.

    Raises ValueError if a hard floor is violated.
    """
    # Floor 1: operator can never approve budgets
    if "operator" in profile.budget.approve_roles:
        raise ValueError(
            "hard floor violation: 'operator' role must never be allowed "
            "to approve budget increases"
        )

    # Floor 2: non-retryable retry must require admin + override
    if not profile.override.non_retryable_retry_requires_admin:
        raise ValueError(
            "hard floor violation: non-retryable retry override must require admin role"
        )
    if not profile.override.non_retryable_retry_requires_env_override:
        raise ValueError(
            "hard floor violation: non-retryable retry override must require "
            "explicit NODECHAIN_OPERATOR_OVERRIDE"
        )

    # Floor 3: only valid roles
    for role in profile.roles.allowed_roles:
        if role not in ALL_ROLES:
            raise ValueError(
                f"hard floor violation: invalid role '{role}' in profile; "
                f"allowed: {', '.join(ALL_ROLES)}"
            )

    # Floor 4: every action.allowed_roles must be a subset of roles.allowed_roles
    for action_name, action_gov in profile.actions.items():
        for ar in action_gov.allowed_roles:
            if ar not in profile.roles.allowed_roles:
                raise ValueError(
                    f"hard floor violation: action '{action_name}' allows role '{ar}' "
                    f"but profile roles.allowed_roles is {profile.roles.allowed_roles}"
                )


# ── Resolver ────────────────────────────────────────────────────────────────

class GovernanceProfileResolver:
    """Resolves governance profiles with precedence: CLI > env > config > default."""

    CONFIG_PATH = "nodechain.governance.yaml"

    def resolve(
        self,
        *,
        explicit_profile: str | None = None,
        explicit_profile_file: str | None = None,
    ) -> GovernanceProfile:
        # 1. CLI --profile (built-in name)
        if explicit_profile:
            return get_builtin_profile(explicit_profile)

        # 2. CLI --profile-file
        if explicit_profile_file:
            return self._load_from_file(explicit_profile_file)

        # 3. NODECHAIN_GOVERNANCE_PROFILE
        env_name = os.environ.get("NODECHAIN_GOVERNANCE_PROFILE")
        if env_name:
            return get_builtin_profile(env_name)

        # 4. NODECHAIN_GOVERNANCE_PROFILE_FILE
        env_file = os.environ.get("NODECHAIN_GOVERNANCE_PROFILE_FILE")
        if env_file:
            return self._load_from_file(env_file)

        # 5. Project config file
        if Path(self.CONFIG_PATH).exists():
            return self._load_from_file(self.CONFIG_PATH)

        # 6. Default
        return get_builtin_profile("team-default")

    def _load_from_file(self, path: str) -> GovernanceProfile:
        raw = yaml.safe_load(Path(path).read_text())
        if not isinstance(raw, dict):
            raise ValueError(f"governance profile file must be a YAML mapping: {path}")
        profile = GovernanceProfile(**raw)
        validate_profile_hard_floors(profile)
        return profile
