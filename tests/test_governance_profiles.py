"""Tests for governance profile models, built-ins, digest, and validation (v2.52.0 #21)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from nodechain.runtime.governance_profiles import (
    GovernanceProfile,
    GovernanceProfileResolver,
    BUILTIN_PROFILES,
    get_builtin_profile,
    compute_profile_digest,
    validate_profile_hard_floors,
)


# --- built-in profiles exist and validate ------------------------------------

def test_four_builtin_profiles_exist():
    assert set(BUILTIN_PROFILES.keys()) == {"solo-dev", "team-default", "regulated", "break-glass"}


def test_team_default_is_valid():
    p = get_builtin_profile("team-default")
    assert p.id == "team-default"
    assert p.batch.max_actions == 50


def test_solo_dev_is_valid():
    p = get_builtin_profile("solo-dev")
    assert p.batch.max_actions == 100


def test_regulated_is_valid():
    p = get_builtin_profile("regulated")
    assert p.batch.max_actions == 20
    assert p.audit.require_operator_identity is True


def test_break_glass_is_valid():
    p = get_builtin_profile("break-glass")
    assert p.batch.max_actions == 10


def test_unknown_builtin_raises():
    with pytest.raises(KeyError):
        get_builtin_profile("nonexistent")


# --- digest stability --------------------------------------------------------

def test_digest_is_stable():
    p = get_builtin_profile("team-default")
    d1 = compute_profile_digest(p)
    d2 = compute_profile_digest(p)
    assert d1 == d2
    assert d1.startswith("sha256:")


def test_different_profiles_have_different_digests():
    d1 = compute_profile_digest(get_builtin_profile("solo-dev"))
    d2 = compute_profile_digest(get_builtin_profile("regulated"))
    assert d1 != d2


# --- hard floor validation ---------------------------------------------------

def test_all_builtins_pass_hard_floor_validation():
    for name, p in BUILTIN_PROFILES.items():
        validate_profile_hard_floors(p)  # should not raise


def test_profile_with_operator_budget_approval_rejected():
    """Hard floor: operator can never approve budgets."""
    p = get_builtin_profile("team-default")
    p = p.model_copy(update={"budget": p.budget.model_copy(update={"approve_roles": ["operator", "finance"]})})
    with pytest.raises(ValueError, match="operator.*budget|budget.*operator"):
        validate_profile_hard_floors(p)


def test_profile_without_admin_override_requirement_rejected():
    """Hard floor: non-retryable retry must require admin + override."""
    p = get_builtin_profile("team-default")
    p = p.model_copy(update={"override": p.override.model_copy(update={"non_retryable_retry_requires_admin": False})})
    with pytest.raises(ValueError, match="admin|override"):
        validate_profile_hard_floors(p)


# --- resolver ---------------------------------------------------------------

def test_resolver_defaults_to_team_default(monkeypatch):
    monkeypatch.delenv("NODECHAIN_GOVERNANCE_PROFILE", raising=False)
    monkeypatch.delenv("NODECHAIN_GOVERNANCE_PROFILE_FILE", raising=False)
    resolver = GovernanceProfileResolver()
    p = resolver.resolve()
    assert p.id == "team-default"


def test_resolver_explicit_builtin(monkeypatch):
    resolver = GovernanceProfileResolver()
    p = resolver.resolve(explicit_profile="regulated")
    assert p.id == "regulated"


def test_resolver_env_var(monkeypatch):
    monkeypatch.setenv("NODECHAIN_GOVERNANCE_PROFILE", "solo-dev")
    resolver = GovernanceProfileResolver()
    p = resolver.resolve()
    assert p.id == "solo-dev"


def test_resolver_cli_overrides_env(monkeypatch):
    monkeypatch.setenv("NODECHAIN_GOVERNANCE_PROFILE", "regulated")
    resolver = GovernanceProfileResolver()
    p = resolver.resolve(explicit_profile="break-glass")
    assert p.id == "break-glass"


def test_resolver_unknown_profile_raises():
    resolver = GovernanceProfileResolver()
    with pytest.raises((ValueError, KeyError), match="unknown"):
        resolver.resolve(explicit_profile="nonexistent")


# --- profile model schema ----------------------------------------------------

def test_profile_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        GovernanceProfile(
            id="test", display_name="Test", roles={"allowed_roles": ["operator"], "default_role": "operator"},
            actions={}, budget={"approve_roles": ["finance"]}, batch={"max_actions": 10},
            audit={}, override={}, surprise=True,
        )
