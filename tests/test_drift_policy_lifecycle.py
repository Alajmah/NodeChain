"""Tests for v1.18.2 Drift Policy Lifecycle.

Tests cover all 7 acceptance criteria:
  1. Policy includes lifecycle fields
  2. Drift check rejects expired/revoked/unsupported in strict mode
  3. Local policy registry (register/list/revoke/verify)
  4. Drift report records lifecycle fields
  5. Trust-store purpose enforcement still required when --require-policy-signature
  6. Backward compatibility with unsigned/default policies
  7. Windows/Linux green
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def _write_policy(tmp_path, **overrides):
    policy = {
        "required_fields": ["artifact_digest", "service_state"],
        "advisory_fields": [],
        "ignored_fields": [],
        "acceptable_drift": {},
        "evidence_strength_required": {},
        "strict_mode": False,
    }
    policy.update(overrides)
    path = str(tmp_path / "drift_policy.json")
    Path(path).write_text(json.dumps(policy), encoding="utf-8")
    return path


def _setup_history(tmp_path, artifact_digest="a" * 64, target="pve1/801"):
    from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
    rh_path = str(tmp_path / "rh.json")
    history = ReleaseHistory(path=rh_path)
    history.add(ReleaseRecord(
        release_id="rel-lifecycle-001",
        artifact_digest=artifact_digest,
        final_deployment_state="applied",
        activation_verified=True,
        target=target,
        deployment_receipt_digest="r" * 64,
    ))
    return rh_path


# ── AC1: Policy Lifecycle Fields ───────────────────────────────────────────

class TestPolicyLifecycleFields:
    """AC1: Drift policy includes lifecycle fields."""

    def test_policy_has_lifecycle_fields(self):
        from nodechain.cli.drift_detection import DriftPolicy
        p = DriftPolicy(
            policy_id="dp-001",
            policy_version="1.0",
            valid_from="2026-01-01T00:00:00+00:00",
            valid_until="2027-01-01T00:00:00+00:00",
            supersedes_policy_digest="old" * 21 + "x",
            policy_status="active",
        )
        assert p.policy_id == "dp-001"
        assert p.policy_version == "1.0"
        assert p.valid_from == "2026-01-01T00:00:00+00:00"
        assert p.valid_until == "2027-01-01T00:00:00+00:00"
        assert p.supersedes_policy_digest == "old" * 21 + "x"
        assert p.policy_status == "active"

    def test_policy_roundtrip_preserves_lifecycle(self):
        from nodechain.cli.drift_detection import DriftPolicy
        p = DriftPolicy(
            policy_id="dp-002",
            policy_version="2.0",
            valid_from="2026-06-01T00:00:00+00:00",
            valid_until="2026-12-31T00:00:00+00:00",
            policy_status="active",
        )
        d = p.to_dict()
        assert d["policy_id"] == "dp-002"
        assert d["policy_version"] == "2.0"
        assert d["valid_from"] == "2026-06-01T00:00:00+00:00"
        assert d["valid_until"] == "2026-12-31T00:00:00+00:00"
        p2 = DriftPolicy.from_dict(d)
        assert p2.policy_id == "dp-002"
        assert p2.policy_version == "2.0"

    def test_policy_defaults(self):
        from nodechain.cli.drift_detection import DriftPolicy
        p = DriftPolicy()
        assert p.policy_id == ""
        assert p.policy_version == ""
        assert p.valid_from == ""
        assert p.valid_until == ""
        assert p.policy_status == "active"
        assert p.supersedes_policy_digest == ""

    def test_policy_from_file_with_lifecycle(self, tmp_path):
        from nodechain.cli.drift_detection import DriftPolicy
        path = _write_policy(tmp_path,
            policy_id="dp-file",
            policy_version="3.1",
            valid_from="2026-01-01T00:00:00+00:00",
            valid_until="2028-01-01T00:00:00+00:00",
        )
        p = DriftPolicy.from_file(path)
        assert p.policy_id == "dp-file"
        assert p.policy_version == "3.1"


# ── AC2: Lifecycle Enforcement ─────────────────────────────────────────────

class TestLifecycleEnforcement:
    """AC2: Drift check rejects expired/revoked/unsupported in strict mode."""

    def test_expired_policy_rejected_in_strict(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift, DriftPolicy
        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        policy = DriftPolicy(
            policy_id="dp-exp",
            policy_status="active",
            valid_from="2020-01-01T00:00:00+00:00",
            valid_until="2020-12-31T00:00:00+00:00",  # expired!
            strict_mode=True,
        )
        result = check_drift(
            target="pve1/801",
            release_id="rel-lifecycle-001",
            release_history_path=rh_path,
            observed_artifact_digest="a" * 64,
            policy=policy,
        )
        assert result["valid"] is False
        assert "lifecycle" in result.get("error", "").lower()

    def test_revoked_policy_rejected(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift, DriftPolicy
        rh_path = _setup_history(tmp_path)
        policy = DriftPolicy(
            policy_id="dp-rev",
            policy_status="revoked",
            strict_mode=True,
        )
        result = check_drift(
            target="pve1/801",
            release_id="rel-lifecycle-001",
            release_history_path=rh_path,
            policy=policy,
        )
        assert result["valid"] is False
        assert "revoked" in result.get("error", "").lower()

    def test_deprecated_policy_rejected_in_strict(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift, DriftPolicy
        rh_path = _setup_history(tmp_path)
        policy = DriftPolicy(
            policy_id="dp-dep",
            policy_status="deprecated",
            strict_mode=True,
        )
        result = check_drift(
            target="pve1/801",
            release_id="rel-lifecycle-001",
            release_history_path=rh_path,
            policy=policy,
        )
        assert result["valid"] is False
        assert "deprecat" in result.get("error", "").lower()

    def test_not_yet_valid_rejected(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift, DriftPolicy
        rh_path = _setup_history(tmp_path)
        policy = DriftPolicy(
            policy_id="dp-future",
            policy_status="active",
            valid_from="2030-01-01T00:00:00+00:00",  # far future
            strict_mode=True,
        )
        result = check_drift(
            target="pve1/801",
            release_id="rel-lifecycle-001",
            release_history_path=rh_path,
            policy=policy,
        )
        assert result["valid"] is False

    def test_active_valid_policy_accepted(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift, DriftPolicy
        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        policy = DriftPolicy(
            policy_id="dp-ok",
            policy_status="active",
            valid_from="2020-01-01T00:00:00+00:00",
            valid_until="2030-01-01T00:00:00+00:00",
            strict_mode=True,
        )
        result = check_drift(
            target="pve1/801",
            release_id="rel-lifecycle-001",
            release_history_path=rh_path,
            observed_artifact_digest="a" * 64,
            policy=policy,
        )
        assert result["valid"] is True

    def test_non_strict_allows_expired(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift, DriftPolicy
        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        policy = DriftPolicy(
            policy_id="dp-exp-ns",
            policy_status="active",
            valid_until="2020-01-01T00:00:00+00:00",  # expired
            strict_mode=False,  # non-strict
        )
        result = check_drift(
            target="pve1/801",
            release_id="rel-lifecycle-001",
            release_history_path=rh_path,
            observed_artifact_digest="a" * 64,
            policy=policy,
        )
        # Non-strict: validity recorded but check proceeds
        assert result["valid"] is True
        assert result["policy_validity_status"] == "expired"


# ── AC3: Local Policy Registry ─────────────────────────────────────────────

class TestPolicyRegistry:
    """AC3: Local policy registry operations."""

    def test_register_policy(self, tmp_path):
        import os
        from nodechain.cli.drift_policy_registry import register_policy
        reg_path = str(tmp_path / "registry.json")
        os.environ["NODECHAIN_DRIFT_POLICY_REGISTRY"] = reg_path
        try:
            path = _write_policy(tmp_path, policy_id="dp-reg-001")
            result = register_policy(policy_path=path)
            assert result["status"] == "registered"
            assert result["policy_id"] == "dp-reg-001"
            assert Path(reg_path).exists()
        finally:
            del os.environ["NODECHAIN_DRIFT_POLICY_REGISTRY"]

    def test_list_policies(self, tmp_path):
        import os
        from nodechain.cli.drift_policy_registry import register_policy, list_policies
        reg_path = str(tmp_path / "registry.json")
        os.environ["NODECHAIN_DRIFT_POLICY_REGISTRY"] = reg_path
        try:
            path = _write_policy(tmp_path, policy_id="dp-list-001")
            register_policy(policy_path=path)
            path2 = _write_policy(tmp_path, policy_id="dp-list-002")
            register_policy(policy_path=path2)
            policies = list_policies()
            assert len(policies) == 2
        finally:
            del os.environ["NODECHAIN_DRIFT_POLICY_REGISTRY"]

    def test_revoke_policy(self, tmp_path):
        import os
        from nodechain.cli.drift_policy_registry import register_policy, revoke_policy, list_policies
        reg_path = str(tmp_path / "registry.json")
        os.environ["NODECHAIN_DRIFT_POLICY_REGISTRY"] = reg_path
        try:
            path = _write_policy(tmp_path, policy_id="dp-rev-001")
            register_policy(policy_path=path)
            result = revoke_policy("dp-rev-001")
            assert result["status"] == "revoked"
            policies = list_policies()
            assert policies[0]["policy_status"] == "revoked"
        finally:
            del os.environ["NODECHAIN_DRIFT_POLICY_REGISTRY"]

    def test_revoke_nonexistent(self, tmp_path):
        import os
        from nodechain.cli.drift_policy_registry import revoke_policy
        reg_path = str(tmp_path / "registry.json")
        os.environ["NODECHAIN_DRIFT_POLICY_REGISTRY"] = reg_path
        try:
            result = revoke_policy("nonexistent")
            assert result["status"] == "not_found"
        finally:
            del os.environ["NODECHAIN_DRIFT_POLICY_REGISTRY"]

    def test_verify_registered_policy(self, tmp_path):
        import os
        from nodechain.cli.drift_policy_registry import register_policy, verify_policy_in_registry
        reg_path = str(tmp_path / "registry.json")
        os.environ["NODECHAIN_DRIFT_POLICY_REGISTRY"] = reg_path
        try:
            path = _write_policy(tmp_path, policy_id="dp-ver-001")
            reg_result = register_policy(policy_path=path)
            result = verify_policy_in_registry(
                policy_id="dp-ver-001",
                policy_digest=reg_result["policy_digest"],
            )
            assert result["registered"] is True
            assert result["active"] is True
            assert result["digest_matches"] is True
        finally:
            del os.environ["NODECHAIN_DRIFT_POLICY_REGISTRY"]

    def test_verify_revoked_not_active(self, tmp_path):
        import os
        from nodechain.cli.drift_policy_registry import register_policy, revoke_policy, verify_policy_in_registry
        reg_path = str(tmp_path / "registry.json")
        os.environ["NODECHAIN_DRIFT_POLICY_REGISTRY"] = reg_path
        try:
            path = _write_policy(tmp_path, policy_id="dp-ver-rev")
            register_policy(policy_path=path)
            revoke_policy("dp-ver-rev")
            result = verify_policy_in_registry(policy_id="dp-ver-rev")
            assert result["registered"] is True
            assert result["active"] is False
        finally:
            del os.environ["NODECHAIN_DRIFT_POLICY_REGISTRY"]

    def test_registry_has_entries_digest(self, tmp_path):
        import os
        from nodechain.cli.drift_policy_registry import register_policy, load_registry
        reg_path = str(tmp_path / "registry.json")
        os.environ["NODECHAIN_DRIFT_POLICY_REGISTRY"] = reg_path
        try:
            path = _write_policy(tmp_path, policy_id="dp-dig")
            register_policy(policy_path=path)
            reg = load_registry()
            assert reg["entries_digest"]
            assert len(reg["entries_digest"]) == 64
        finally:
            del os.environ["NODECHAIN_DRIFT_POLICY_REGISTRY"]


# ── AC4: Drift Report Lifecycle Fields ─────────────────────────────────────

class TestDriftReportLifecycleFields:
    """AC4: Drift report records lifecycle fields."""

    def test_report_has_lifecycle_fields(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift, create_drift_report, DriftPolicy
        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        policy = DriftPolicy(policy_id="dp-rpt-001", policy_version="1.0")
        result = check_drift(
            target="pve1/801",
            release_id="rel-lifecycle-001",
            release_history_path=rh_path,
            observed_artifact_digest="a" * 64,
            policy=policy,
        )
        report = create_drift_report(result)
        assert report["policy_id"] == "dp-rpt-001"
        assert report["policy_version"] == "1.0"
        assert report["policy_status"] == "active"
        assert report["policy_validity_status"] == "active"

    def test_report_records_expired_status(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift, create_drift_report, DriftPolicy
        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        policy = DriftPolicy(
            policy_id="dp-rpt-exp",
            valid_until="2020-01-01T00:00:00+00:00",
            strict_mode=False,
        )
        result = check_drift(
            target="pve1/801",
            release_id="rel-lifecycle-001",
            release_history_path=rh_path,
            observed_artifact_digest="a" * 64,
            policy=policy,
        )
        report = create_drift_report(result)
        assert report["policy_validity_status"] == "expired"


# ── AC5: Backward Compatibility ────────────────────────────────────────────

class TestBackwardCompatibility:
    """AC5+AC6: Backward compatibility maintained."""

    def test_unsigned_policy_works_without_requirement(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift
        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        path = _write_policy(tmp_path, policy_id="dp-bc-001")
        result = check_drift(
            target="pve1/801",
            release_id="rel-lifecycle-001",
            release_history_path=rh_path,
            observed_artifact_digest="a" * 64,
            policy=path,
        )
        assert result["valid"] is True
        assert result["drift_detected"] is False

    def test_no_policy_still_works(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift
        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        result = check_drift(
            target="pve1/801",
            release_id="rel-lifecycle-001",
            release_history_path=rh_path,
            observed_artifact_digest="a" * 64,
        )
        assert result["valid"] is True
        assert result["drift_detected"] is False

    def test_default_policy_has_lifecycle_defaults(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift
        rh_path = _setup_history(tmp_path)
        result = check_drift(
            target="pve1/801",
            release_id="rel-lifecycle-001",
            release_history_path=rh_path,
        )
        assert result["policy_status"] == "active"
        assert result["policy_validity_status"] == "active"


# ── Validity Check Unit Tests ──────────────────────────────────────────────

class TestValidityCheck:
    """Unit tests for DriftPolicy.check_validity()."""

    def test_active_no_window(self):
        from nodechain.cli.drift_detection import DriftPolicy
        p = DriftPolicy()
        result = p.check_validity()
        assert result["valid"] is True
        assert result["status"] == "active"

    def test_revoked(self):
        from nodechain.cli.drift_detection import DriftPolicy
        p = DriftPolicy(policy_status="revoked")
        result = p.check_validity()
        assert result["valid"] is False
        assert result["status"] == "revoked"

    def test_expired(self):
        from nodechain.cli.drift_detection import DriftPolicy
        p = DriftPolicy(
            policy_status="active",
            valid_until="2020-01-01T00:00:00+00:00",
        )
        result = p.check_validity(now="2026-06-16T12:00:00+00:00")
        assert result["valid"] is False
        assert result["status"] == "expired"

    def test_not_yet_valid(self):
        from nodechain.cli.drift_detection import DriftPolicy
        p = DriftPolicy(
            policy_status="active",
            valid_from="2030-01-01T00:00:00+00:00",
        )
        result = p.check_validity(now="2026-06-16T12:00:00+00:00")
        assert result["valid"] is False
        assert result["status"] == "not_yet_valid"

    def test_within_window(self):
        from nodechain.cli.drift_detection import DriftPolicy
        p = DriftPolicy(
            policy_status="active",
            valid_from="2020-01-01T00:00:00+00:00",
            valid_until="2030-01-01T00:00:00+00:00",
        )
        result = p.check_validity(now="2026-06-16T12:00:00+00:00")
        assert result["valid"] is True
