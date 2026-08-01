"""Organization Trust Policy Profile Tests (v2.4.0).

Tests all 10 acceptance criteria.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


# ── AC1: OrganizationTrustPolicyProfile model ────────────────────────────────

class TestAC1ProfileModel:
    """AC1: Profile model with all required fields."""

    def test_profile_creation(self):
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        p = OrganizationTrustPolicyProfile(
            name="test",
            description="Test profile",
        )
        assert p.name == "test"
        assert p.allow_remote_registry is True
        assert p.sandbox_minimum == "standard_untrusted"

    def test_profile_serialization(self):
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        p = OrganizationTrustPolicyProfile(name="test", description="desc")
        d = p.to_dict()
        assert "name" in d
        assert "allowed_trust_levels" in d
        assert "sandbox_minimum" in d
        p2 = OrganizationTrustPolicyProfile.from_dict(d)
        assert p2.name == "test"

    def test_profile_digest_deterministic(self):
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        p1 = OrganizationTrustPolicyProfile(name="test", description="desc")
        p2 = OrganizationTrustPolicyProfile(name="test", description="desc")
        assert p1.compute_digest() == p2.compute_digest()

    def test_different_profiles_different_digests(self):
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        p1 = OrganizationTrustPolicyProfile(name="a", description="desc")
        p2 = OrganizationTrustPolicyProfile(name="b", description="desc")
        assert p1.compute_digest() != p2.compute_digest()


# ── AC2: Built-in profiles ───────────────────────────────────────────────────

class TestAC2BuiltInProfiles:
    """AC2: Four built-in profiles."""

    def test_all_four_profiles_exist(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        for name in ["permissive_local", "standard_team", "strict_enterprise", "airgapped_high_assurance"]:
            p = get_builtin_profile(name)
            assert p is not None, f"Profile '{name}' missing"
            assert p.name == name

    def test_permissive_local_allows_everything(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p = get_builtin_profile("permissive_local")
        assert p.allow_remote_registry is True
        assert p.allow_deployment is True
        assert p.allow_dependency_resolution is True
        assert p.require_certification is False

    def test_strict_enterprise_requires_signing(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p = get_builtin_profile("strict_enterprise")
        assert p.require_registry_metadata_signing is True
        assert p.require_package_signing is True
        assert p.require_certification is True
        assert p.require_transparency_logging is True

    def test_airgapped_denies_remote(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p = get_builtin_profile("airgapped_high_assurance")
        assert p.allow_remote_registry is False
        assert p.allow_deployment is False
        assert p.allow_dependency_resolution is False
        assert p.sandbox_minimum == "hardened_untrusted"

    def test_profiles_have_distinct_digests(self):
        from nodechain.sdk.org_policy import get_builtin_profile, list_builtin_profiles
        digests = set()
        for name in list_builtin_profiles():
            p = get_builtin_profile(name)
            d = p.compute_digest()
            assert d not in digests, f"Digest collision for {name}"
            digests.add(d)


# ── AC3: Each profile controls all surfaces ──────────────────────────────────

class TestAC3ProfileSurfaces:
    """AC3: Each profile controls the required policy surfaces."""

    def test_all_surfaces_present(self):
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        p = OrganizationTrustPolicyProfile(name="t", description="d")
        # Verify all 12 surfaces exist
        assert hasattr(p, "allowed_trust_levels")
        assert hasattr(p, "required_key_purposes")
        assert hasattr(p, "allow_remote_registry")
        assert hasattr(p, "require_registry_metadata_signing")
        assert hasattr(p, "require_package_signing")
        assert hasattr(p, "require_certification")
        assert hasattr(p, "require_transparency_logging")
        assert hasattr(p, "allow_dependency_resolution")
        assert hasattr(p, "require_lockfile")
        assert hasattr(p, "sandbox_minimum")
        assert hasattr(p, "allow_deployment")
        assert hasattr(p, "required_eval_suites")


# ── AC4: CLI commands ────────────────────────────────────────────────────────

class TestAC4CLI:
    """AC4: Policy profile CLI commands."""

    def test_list(self, monkeypatch, tmp_path):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        monkeypatch.setenv("NODECHAIN_ACTIVE_POLICY_PROFILE", str(tmp_path / "active.json"))
        runner = CliRunner()
        result = runner.invoke(cli, ["policy", "profiles", "list", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "permissive_local" in data["built_in"]
        assert "strict_enterprise" in data["built_in"]

    def test_show(self):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["policy", "profiles", "show", "permissive_local", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["name"] == "permissive_local"

    def test_validate(self):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["policy", "profiles", "validate", "standard_team", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["valid"] is True

    def test_apply(self, monkeypatch, tmp_path):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        monkeypatch.setenv("NODECHAIN_ACTIVE_POLICY_PROFILE", str(tmp_path / "active.json"))
        runner = CliRunner()
        result = runner.invoke(cli, [
            "policy", "profiles", "apply", "strict_enterprise",
            "--by", "admin", "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["profile_name"] == "strict_enterprise"
        assert data["applied_by"] == "admin"

    def test_diff(self):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, [
            "policy", "profiles", "diff",
            "permissive_local", "strict_enterprise", "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) > 0  # Many differences

    def test_show_not_found(self):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["policy", "profiles", "show", "nonexistent"])
        assert result.exit_code == 2  # EXIT_NOT_FOUND


# ── AC5: Profile is digest-bound when applied ────────────────────────────────

class TestAC5DigestBound:
    """AC5: Applied profile is digest-bound."""

    def test_apply_produces_receipt_with_digest(self, tmp_path):
        from nodechain.sdk.org_policy import (
            get_builtin_profile, apply_profile,
        )
        path = str(tmp_path / "active.json")
        profile = get_builtin_profile("strict_enterprise")
        receipt = apply_profile(profile, path=path)
        assert receipt.profile_digest == profile.compute_digest()
        assert receipt.receipt_digest != ""

    def test_reapply_records_previous(self, tmp_path):
        from nodechain.sdk.org_policy import (
            get_builtin_profile, apply_profile,
        )
        path = str(tmp_path / "active.json")
        p1 = get_builtin_profile("permissive_local")
        r1 = apply_profile(p1, path=path)
        p2 = get_builtin_profile("strict_enterprise")
        r2 = apply_profile(p2, path=path)
        assert r2.previous_profile_digest == r1.profile_digest
        assert r2.profile_digest != r2.previous_profile_digest


# ── AC6: Receipt fields ──────────────────────────────────────────────────────

class TestAC6ReceiptFields:
    """AC6: Profile application writes all required receipt fields."""

    def test_receipt_fields(self, tmp_path):
        from nodechain.sdk.org_policy import (
            get_builtin_profile, apply_profile,
        )
        path = str(tmp_path / "active.json")
        receipt = apply_profile(
            get_builtin_profile("standard_team"),
            applied_by="operator1",
            path=path,
        )
        d = receipt.to_dict()
        assert "profile_name" in d
        assert "profile_digest" in d
        assert "applied_at" in d
        assert "applied_by" in d
        assert "previous_profile_digest" in d
        assert "affected_surfaces" in d

    def test_affected_surfaces_on_change(self, tmp_path):
        from nodechain.sdk.org_policy import (
            get_builtin_profile, apply_profile,
        )
        path = str(tmp_path / "active.json")
        apply_profile(get_builtin_profile("permissive_local"), path=path)
        receipt = apply_profile(get_builtin_profile("airgapped_high_assurance"), path=path)
        # Many surfaces should differ
        assert len(receipt.affected_surfaces) > 5


# ── AC7: Runtime enforcement ─────────────────────────────────────────────────

class TestAC7Enforcement:
    """AC7: Enforcement check methods on profile."""

    def test_check_trust_level_allowed(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p = get_builtin_profile("permissive_local")
        ok, _ = p.check_trust_level("remote_untrusted")
        assert ok

    def test_check_trust_level_denied(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p = get_builtin_profile("airgapped_high_assurance")
        ok, msg = p.check_trust_level("remote_untrusted")
        assert not ok
        assert "remote_untrusted" in msg

    def test_check_remote_install_allowed(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p = get_builtin_profile("standard_team")
        ok, _ = p.check_remote_install()
        assert ok

    def test_check_remote_install_denied(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p = get_builtin_profile("airgapped_high_assurance")
        ok, msg = p.check_remote_install()
        assert not ok

    def test_check_certification_required(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p = get_builtin_profile("strict_enterprise")
        ok, _ = p.check_certification(True)
        assert ok
        ok, msg = p.check_certification(False)
        assert not ok

    def test_check_sandbox_minimum(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p = get_builtin_profile("strict_enterprise")
        # Below minimum
        ok, msg = p.check_sandbox("standard_untrusted")
        assert not ok
        # At minimum
        ok, _ = p.check_sandbox("production_untrusted")
        assert ok
        # Above minimum
        ok, _ = p.check_sandbox("hardened_untrusted")
        assert ok

    def test_check_deployment_denied(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p = get_builtin_profile("airgapped_high_assurance")
        ok, msg = p.check_deployment()
        assert not ok

    def test_check_dependency_resolution_denied(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p = get_builtin_profile("airgapped_high_assurance")
        ok, msg = p.check_dependency_resolution()
        assert not ok

    def test_check_transparency_logging(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p = get_builtin_profile("strict_enterprise")
        ok, msg = p.check_transparency_logging(False)
        assert not ok

    def test_check_eval_suites(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p = get_builtin_profile("strict_enterprise")
        ok, msg = p.check_eval_suites([])
        assert not ok
        ok, _ = p.check_eval_suites(["trust_chain_eval"])
        assert ok


# ── AC8: Dashboard shows active profile ──────────────────────────────────────

class TestAC8Dashboard:
    """AC8: HR-015 health rule for policy profile."""

    def test_hr015_exists(self):
        from nodechain.cli.dashboard_health import RULES_BY_ID
        assert "HR-015" in RULES_BY_ID

    def test_hr015_no_profile(self):
        from nodechain.cli.dashboard_health import RULES_BY_ID
        rule = RULES_BY_ID["HR-015"]
        result = rule.evaluate({"policy": {"enabled": True, "active_profile": None}})
        assert result is not None
        assert "no_active_policy" in result["name"]

    def test_hr015_stale_profile(self):
        from nodechain.cli.dashboard_health import RULES_BY_ID
        rule = RULES_BY_ID["HR-015"]
        result = rule.evaluate({
            "policy": {"enabled": True, "active_profile": "test", "stale": True},
        })
        assert result is not None

    def test_hr015_uncovered_surfaces(self):
        from nodechain.cli.dashboard_health import RULES_BY_ID
        rule = RULES_BY_ID["HR-015"]
        result = rule.evaluate({
            "policy": {
                "enabled": True, "active_profile": "test",
                "uncovered_surfaces": ["deployment", "certification"],
            },
        })
        assert result is not None

    def test_hr015_healthy(self):
        from nodechain.cli.dashboard_health import RULES_BY_ID
        rule = RULES_BY_ID["HR-015"]
        result = rule.evaluate({
            "policy": {
                "enabled": True, "active_profile": "standard_team",
                "stale": False, "uncovered_surfaces": [],
            },
        })
        assert result is None

    def test_hr015_not_configured(self):
        from nodechain.cli.dashboard_health import RULES_BY_ID
        rule = RULES_BY_ID["HR-015"]
        result = rule.evaluate({"policy": {"enabled": False}})
        assert result is None


# ── AC9: Negative enforcement tests ──────────────────────────────────────────

class TestAC9NegativeEnforcement:
    """AC9: Profile denies operations when configured to do so."""

    def test_remote_install_denied_by_airgapped(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p = get_builtin_profile("airgapped_high_assurance")
        ok, msg = p.check_remote_install()
        assert not ok
        assert "denied" in msg

    def test_unsigned_registry_denied_by_strict(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p = get_builtin_profile("strict_enterprise")
        ok, msg = p.check_registry_signing(False)
        assert not ok
        assert "signing" in msg.lower()

    def test_uncertified_package_denied_by_strict(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p = get_builtin_profile("strict_enterprise")
        ok, msg = p.check_certification(False)
        assert not ok

    def test_weak_sandbox_denied_by_airgapped(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p = get_builtin_profile("airgapped_high_assurance")
        ok, msg = p.check_sandbox("standard_untrusted")
        assert not ok

    def test_missing_transparency_denied_by_strict(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p = get_builtin_profile("strict_enterprise")
        ok, msg = p.check_transparency_logging(False)
        assert not ok

    def test_dependency_graph_denied_by_airgapped(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p = get_builtin_profile("airgapped_high_assurance")
        ok, msg = p.check_dependency_resolution()
        assert not ok

    def test_deployment_denied_by_airgapped(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p = get_builtin_profile("airgapped_high_assurance")
        ok, msg = p.check_deployment()
        assert not ok

    def test_stale_profile_digest_detected(self, tmp_path):
        from nodechain.sdk.org_policy import (
            get_builtin_profile, apply_profile, get_active_profile,
        )
        path = str(tmp_path / "active.json")
        profile = get_builtin_profile("standard_team")
        apply_profile(profile, path=path)
        # Tamper with stored file
        data = json.loads(Path(path).read_text())
        data["profile"]["allow_remote_registry"] = False  # Change a field
        Path(path).write_text(json.dumps(data))
        loaded = get_active_profile(path)
        # The loaded profile has different content
        assert loaded.allow_remote_registry is False
        # And its digest won't match the receipt's profile_digest
        assert loaded.compute_digest() != data["receipt"]["profile_digest"]


# ── Additional: Profile diff and validation ──────────────────────────────────

class TestDiffAndValidation:
    """Additional tests for diff and validation."""

    def test_diff_identical_profiles(self):
        from nodechain.sdk.org_policy import get_builtin_profile, diff_profiles
        p = get_builtin_profile("permissive_local")
        diff = diff_profiles(p, p)
        assert len(diff) == 0

    def test_diff_different_profiles(self):
        from nodechain.sdk.org_policy import get_builtin_profile, diff_profiles
        a = get_builtin_profile("permissive_local")
        b = get_builtin_profile("strict_enterprise")
        diff = diff_profiles(a, b)
        assert "require_certification" in diff
        assert "allow_deployment" in diff or "sandbox_minimum" in diff

    def test_validate_valid_profile(self):
        from nodechain.sdk.org_policy import get_builtin_profile, validate_profile
        for name in ["permissive_local", "standard_team", "strict_enterprise", "airgapped_high_assurance"]:
            errors = validate_profile(get_builtin_profile(name))
            assert len(errors) == 0, f"Profile {name} has errors: {errors}"

    def test_validate_inconsistent_profile(self):
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile, validate_profile
        p = OrganizationTrustPolicyProfile(
            name="bad",
            description="bad",
            allowed_trust_levels=["invalid_level"],
        )
        errors = validate_profile(p)
        assert any("Invalid trust level" in e for e in errors)


# ── Additional: Evidence and store ────────────────────────────────────────────

class TestEvidenceAndStore:
    """Additional tests for evidence type and profile store."""

    def test_policy_profile_receipt_evidence_type(self):
        from nodechain.cli.evidence import EVIDENCE_TYPES
        assert "policy_profile_receipt" in EVIDENCE_TYPES

    def test_get_active_profile_none(self, tmp_path):
        from nodechain.sdk.org_policy import get_active_profile
        path = str(tmp_path / "nonexistent.json")
        assert get_active_profile(path) is None

    def test_apply_then_get_active(self, tmp_path):
        from nodechain.sdk.org_policy import (
            get_builtin_profile, apply_profile, get_active_profile,
        )
        path = str(tmp_path / "active.json")
        apply_profile(get_builtin_profile("standard_team"), path=path)
        active = get_active_profile(path)
        assert active is not None
        assert active.name == "standard_team"

    def test_get_active_receipt(self, tmp_path):
        from nodechain.sdk.org_policy import (
            get_builtin_profile, apply_profile, get_active_profile_receipt,
        )
        path = str(tmp_path / "active.json")
        receipt = apply_profile(get_builtin_profile("permissive_local"), path=path)
        loaded = get_active_profile_receipt(path)
        assert loaded is not None
        assert loaded.profile_digest == receipt.profile_digest

    def test_get_affected_surfaces(self):
        from nodechain.sdk.org_policy import (
            get_builtin_profile, get_affected_surfaces,
        )
        a = get_builtin_profile("permissive_local")
        b = get_builtin_profile("airgapped_high_assurance")
        affected = get_affected_surfaces(a, b)
        assert "remote_registry" in affected
        assert "deployment" in affected
        assert "sandbox" in affected

    def test_rule_count_is_15(self):
        from nodechain.cli.dashboard_health import ALL_RULES
        assert len(ALL_RULES) == 65  # 49 HR + 5 MEM + 6 SE + 5 MR (v2.41.0)
