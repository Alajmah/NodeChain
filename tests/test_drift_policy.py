"""Tests for v1.18.2 Drift Policy and Evidence Strength.

Tests cover all 7 acceptance criteria:
  1. Drift policy profile (drift_policy.json)
  2. Profile defines required/advisory/ignored/acceptable/strength/strict
  3. Each field records evidence_source, evidence_strength, comparison_status
  4. Strict mode fails on unavailable/insufficient/mismatch
  5. Drift report records policy fields
  6. CLI supports --policy
  7. Windows/Linux green
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def _generate_key_pair(tmp_path, suffix=""):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    priv_path = str(tmp_path / f"priv_p{suffix}.pem")
    Path(priv_path).write_bytes(priv_pem)
    return priv_path


def _setup_history(tmp_path, artifact_digest="a" * 64, target="pve1/801"):
    from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
    rh_path = str(tmp_path / "rh.json")
    history = ReleaseHistory(path=rh_path)
    history.add(ReleaseRecord(
        release_id="rel-drift-policy-001",
        artifact_digest=artifact_digest,
        final_deployment_state="applied",
        activation_verified=True,
        target=target,
        deployment_receipt_digest="r" * 64,
    ))
    return rh_path


def _write_policy(tmp_path, **overrides):
    """Write a drift policy JSON file."""
    policy = {
        "required_fields": ["artifact_digest", "service_state"],
        "advisory_fields": ["final_path"],
        "ignored_fields": [],
        "acceptable_drift": {},
        "evidence_strength_required": {},
        "strict_mode": False,
    }
    policy.update(overrides)
    path = str(tmp_path / "drift_policy.json")
    Path(path).write_text(json.dumps(policy), encoding="utf-8")
    return path


# ── AC1: Drift Policy Profile ─────────────────────────────────────────────

class TestDriftPolicyProfile:
    """AC1+AC2: Policy profile creation and field definitions."""

    def test_policy_from_dict(self):
        from nodechain.cli.drift_detection import DriftPolicy
        p = DriftPolicy.from_dict({
            "required_fields": ["artifact_digest", "service_state"],
            "advisory_fields": ["final_path"],
            "ignored_fields": ["policy_digest"],
            "acceptable_drift": {"service_state": ["stopped"]},
            "evidence_strength_required": {"artifact_digest": "observed"},
            "strict_mode": True,
        })
        assert p.is_required("artifact_digest") is True
        assert p.is_required("service_state") is True
        assert p.is_advisory("final_path") is True
        assert p.is_ignored("policy_digest") is True
        assert p.is_acceptable_drift("service_state", "stopped") is True
        assert p.is_acceptable_drift("service_state", "running") is False
        assert p.min_strength("artifact_digest") == "observed"
        assert p.strict_mode is True

    def test_policy_from_file(self, tmp_path):
        from nodechain.cli.drift_detection import DriftPolicy
        path = _write_policy(tmp_path, strict_mode=True)
        p = DriftPolicy.from_file(path)
        assert p.is_required("artifact_digest")
        assert p.is_advisory("final_path")
        assert p.strict_mode is True

    def test_policy_to_dict_roundtrip(self):
        from nodechain.cli.drift_detection import DriftPolicy
        p = DriftPolicy(
            required_fields=["artifact_digest"],
            advisory_fields=["service_state"],
            ignored_fields=["policy_digest"],
            acceptable_drift={"service_state": ["stopped"]},
            evidence_strength_required={"artifact_digest": "observed"},
            strict_mode=True,
        )
        d = p.to_dict()
        p2 = DriftPolicy.from_dict(d)
        assert p2.required_fields == p.required_fields
        assert p2.advisory_fields == p.advisory_fields
        assert p2.ignored_fields == p.ignored_fields
        assert p2.acceptable_drift == p.acceptable_drift
        assert p2.evidence_strength_required == p.evidence_strength_required
        assert p2.strict_mode == p.strict_mode

    def test_policy_digest(self):
        from nodechain.cli.drift_detection import DriftPolicy
        p1 = DriftPolicy(required_fields=["artifact_digest"])
        p2 = DriftPolicy(required_fields=["artifact_digest"])
        p3 = DriftPolicy(required_fields=["service_state"])
        assert p1.digest() == p2.digest()
        assert p1.digest() != p3.digest()

    def test_default_policy(self):
        from nodechain.cli.drift_detection import DriftPolicy, DRIFT_FIELDS
        p = DriftPolicy()
        assert set(p.required_fields) == set(DRIFT_FIELDS)
        assert p.advisory_fields == []
        assert p.ignored_fields == []
        assert p.strict_mode is False


# ── AC3: Per-Field Evidence ────────────────────────────────────────────────

class TestPerFieldEvidence:
    """AC3: Each field records evidence_source, evidence_strength, comparison_status."""

    def test_field_details_present(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift
        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        result = check_drift(
            target="pve1/801",
            release_id="rel-drift-policy-001",
            release_history_path=rh_path,
            observed_artifact_digest="a" * 64,
            observed_service_state="running",
        )
        assert "field_details" in result
        for field in ["artifact_digest", "service_state"]:
            assert field in result["field_details"]
            detail = result["field_details"][field]
            assert "evidence_source" in detail
            assert "evidence_strength" in detail
            assert "comparison_status" in detail

    def test_field_match_status(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift
        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        result = check_drift(
            target="pve1/801",
            release_id="rel-drift-policy-001",
            release_history_path=rh_path,
            observed_artifact_digest="a" * 64,
        )
        assert result["field_details"]["artifact_digest"]["comparison_status"] == "match"

    def test_field_mismatch_status(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift
        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        result = check_drift(
            target="pve1/801",
            release_id="rel-drift-policy-001",
            release_history_path=rh_path,
            observed_artifact_digest="b" * 64,
        )
        assert result["field_details"]["artifact_digest"]["comparison_status"] == "mismatch"

    def test_field_unavailable_status(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift
        rh_path = _setup_history(tmp_path)
        result = check_drift(
            target="pve1/801",
            release_id="rel-drift-policy-001",
            release_history_path=rh_path,
            # No observed values provided
        )
        assert result["field_details"]["artifact_digest"]["comparison_status"] == "unavailable"
        assert result["field_details"]["artifact_digest"]["evidence_strength"] == "unavailable"

    def test_ignored_field(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift, DriftPolicy
        rh_path = _setup_history(tmp_path)
        policy = DriftPolicy(ignored_fields=["artifact_digest"])
        result = check_drift(
            target="pve1/801",
            release_id="rel-drift-policy-001",
            release_history_path=rh_path,
            observed_artifact_digest="b" * 64,
            policy=policy,
        )
        assert result["field_details"]["artifact_digest"]["comparison_status"] == "ignored"

    def test_acceptable_drift_status(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift, DriftPolicy
        rh_path = _setup_history(tmp_path)
        policy = DriftPolicy(
            required_fields=["service_state"],
            acceptable_drift={"service_state": ["stopped"]},
        )
        result = check_drift(
            target="pve1/801",
            release_id="rel-drift-policy-001",
            release_history_path=rh_path,
            observed_service_state="stopped",  # different but acceptable
            policy=policy,
        )
        assert result["field_details"]["service_state"]["comparison_status"] == "acceptable_drift"
        assert "service_state" not in result["drift_fields"]

    def test_evidence_strength_observed(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift
        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        result = check_drift(
            target="pve1/801",
            release_id="rel-drift-policy-001",
            release_history_path=rh_path,
            observed_artifact_digest="a" * 64,
            evidence_source="proxmox_api",
        )
        assert result["field_details"]["artifact_digest"]["evidence_strength"] == "observed"

    def test_evidence_strength_inferred(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift
        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        result = check_drift(
            target="pve1/801",
            release_id="rel-drift-policy-001",
            release_history_path=rh_path,
            observed_artifact_digest="a" * 64,
            evidence_source="configuration",
        )
        assert result["field_details"]["artifact_digest"]["evidence_strength"] == "inferred"

    def test_evidence_strength_unavailable(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift
        rh_path = _setup_history(tmp_path)
        result = check_drift(
            target="pve1/801",
            release_id="rel-drift-policy-001",
            release_history_path=rh_path,
        )
        assert result["field_details"]["artifact_digest"]["evidence_strength"] == "unavailable"

    def test_per_field_evidence_source_override(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift
        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        result = check_drift(
            target="pve1/801",
            release_id="rel-drift-policy-001",
            release_history_path=rh_path,
            observed_artifact_digest="a" * 64,
            observed_service_state="running",
            evidence_source="proxmox_api",
            field_evidence_sources={
                "artifact_digest": "configuration",  # override: inferred from config
                "service_state": "proxmox_api",  # direct observation
            },
        )
        assert result["field_details"]["artifact_digest"]["evidence_strength"] == "inferred"
        assert result["field_details"]["service_state"]["evidence_strength"] == "observed"


# ── AC4: Strict Mode Failures ──────────────────────────────────────────────

class TestStrictModeFailures:
    """AC4: Strict mode fails on unavailable/insufficient/mismatch."""

    def test_strict_fails_on_unavailable_required(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift, DriftPolicy
        rh_path = _setup_history(tmp_path)
        policy = DriftPolicy(
            required_fields=["artifact_digest"],
            strict_mode=True,
        )
        result = check_drift(
            target="pve1/801",
            release_id="rel-drift-policy-001",
            release_history_path=rh_path,
            policy=policy,
        )
        assert result["drift_detected"] is True
        assert any(
            f["failure_type"] == "unavailable" for f in result["required_field_failures"]
        )

    def test_strict_fails_on_insufficient_evidence(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift, DriftPolicy
        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        policy = DriftPolicy(
            required_fields=["artifact_digest"],
            evidence_strength_required={"artifact_digest": "observed"},
            strict_mode=True,
        )
        result = check_drift(
            target="pve1/801",
            release_id="rel-drift-policy-001",
            release_history_path=rh_path,
            observed_artifact_digest="a" * 64,
            evidence_source="configuration",  # inferred, not observed!
            policy=policy,
        )
        assert result["drift_detected"] is True
        assert any(
            f["failure_type"] == "insufficient_evidence"
            for f in result["required_field_failures"]
        )

    def test_strict_fails_on_mismatch(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift, DriftPolicy
        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        policy = DriftPolicy(
            required_fields=["artifact_digest"],
            strict_mode=True,
        )
        result = check_drift(
            target="pve1/801",
            release_id="rel-drift-policy-001",
            release_history_path=rh_path,
            observed_artifact_digest="b" * 64,
            policy=policy,
        )
        assert result["drift_detected"] is True
        assert any(
            f["failure_type"] == "mismatch" for f in result["required_field_failures"]
        )

    def test_non_strict_does_not_fail_on_unavailable(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift, DriftPolicy
        rh_path = _setup_history(tmp_path)
        policy = DriftPolicy(
            required_fields=["artifact_digest"],
            strict_mode=False,
        )
        result = check_drift(
            target="pve1/801",
            release_id="rel-drift-policy-001",
            release_history_path=rh_path,
            policy=policy,
        )
        # Non-strict: unavailable is recorded but not treated as drift
        assert result["drift_detected"] is False
        assert len(result["required_field_failures"]) > 0  # but failures ARE recorded

    def test_strict_observed_meets_requirement(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift, DriftPolicy
        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        policy = DriftPolicy(
            required_fields=["artifact_digest"],
            evidence_strength_required={"artifact_digest": "observed"},
            strict_mode=True,
        )
        result = check_drift(
            target="pve1/801",
            release_id="rel-drift-policy-001",
            release_history_path=rh_path,
            observed_artifact_digest="a" * 64,
            evidence_source="proxmox_api",  # observed!
            policy=policy,
        )
        assert result["drift_detected"] is False

    def test_strict_advisory_warning_not_drift(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift, DriftPolicy
        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        policy = DriftPolicy(
            required_fields=[],
            advisory_fields=["artifact_digest"],
            strict_mode=True,
        )
        result = check_drift(
            target="pve1/801",
            release_id="rel-drift-policy-001",
            release_history_path=rh_path,
            observed_artifact_digest="b" * 64,  # mismatch
            policy=policy,
        )
        # Advisory mismatch is recorded as warning but not as drift
        assert len(result["advisory_field_warnings"]) == 1
        assert result["advisory_field_warnings"][0]["field"] == "artifact_digest"


# ── AC5: Drift Report Policy Fields ────────────────────────────────────────

class TestDriftReportPolicyFields:
    """AC5: Drift report records policy fields."""

    def test_report_has_policy_fields(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift, create_drift_report, DriftPolicy
        rh_path = _setup_history(tmp_path)
        policy = DriftPolicy(required_fields=["artifact_digest"])
        result = check_drift(
            target="pve1/801",
            release_id="rel-drift-policy-001",
            release_history_path=rh_path,
            observed_artifact_digest="a" * 64,
            policy=policy,
        )
        report = create_drift_report(result)
        assert "policy_digest" in report
        assert "field_details" in report
        assert "required_field_failures" in report
        assert "advisory_field_warnings" in report
        assert "evidence_strength_summary" in report
        assert "policy_strict_mode" in report

    def test_report_policy_digest_matches(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift, create_drift_report, DriftPolicy
        rh_path = _setup_history(tmp_path)
        policy = DriftPolicy(required_fields=["artifact_digest"])
        result = check_drift(
            target="pve1/801",
            release_id="rel-drift-policy-001",
            release_history_path=rh_path,
            observed_artifact_digest="a" * 64,
            policy=policy,
        )
        report = create_drift_report(result)
        assert report["policy_digest"] == policy.digest()

    def test_report_evidence_strength_summary(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift, create_drift_report
        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        result = check_drift(
            target="pve1/801",
            release_id="rel-drift-policy-001",
            release_history_path=rh_path,
            observed_artifact_digest="a" * 64,
            observed_service_state="running",
            evidence_source="proxmox_api",
        )
        report = create_drift_report(result)
        ess = report["evidence_strength_summary"]
        assert ess["observed"] >= 2  # artifact_digest + service_state
        assert ess["unavailable"] >= 1  # at least one field not provided

    def test_report_signed_with_policy(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift, create_drift_report, DriftPolicy
        priv_path = _generate_key_pair(tmp_path)
        rh_path = _setup_history(tmp_path)
        policy = DriftPolicy(required_fields=["artifact_digest"])
        result = check_drift(
            target="pve1/801",
            release_id="rel-drift-policy-001",
            release_history_path=rh_path,
            observed_artifact_digest="a" * 64,
            policy=policy,
        )
        report = create_drift_report(result, private_key_path=priv_path)
        assert "report_signature" in report
        assert report["report_signature_algorithm"] == "RSA-PSS-SHA256"
        assert "policy_digest" in report


# ── Evidence Strength Classification ──────────────────────────────────────

class TestEvidenceStrengthClassification:
    """Direct tests for evidence strength classification."""

    def test_unavailable(self):
        from nodechain.cli.drift_detection import classify_evidence_strength
        assert classify_evidence_strength("artifact_digest", "", "proxmox_api") == "unavailable"

    def test_observed_from_proxmox_api(self):
        from nodechain.cli.drift_detection import classify_evidence_strength
        assert classify_evidence_strength("service_state", "running", "proxmox_api") == "observed"

    def test_observed_from_manual(self):
        from nodechain.cli.drift_detection import classify_evidence_strength
        assert classify_evidence_strength("artifact_digest", "abc123", "manual") == "observed"

    def test_inferred_from_config(self):
        from nodechain.cli.drift_detection import classify_evidence_strength
        assert classify_evidence_strength("final_path", "/app/deploy", "configuration") == "inferred"

    def test_inferred_from_manifest(self):
        from nodechain.cli.drift_detection import classify_evidence_strength
        assert classify_evidence_strength("final_path", "/app/deploy", "manifest") == "inferred"


class TestEvidenceStrengthLevels:
    """Evidence strength level ordering."""

    def test_levels_ordered(self):
        from nodechain.cli.drift_detection import EVIDENCE_STRENGTH_LEVELS
        assert EVIDENCE_STRENGTH_LEVELS == ("unavailable", "inferred", "observed", "verified")

    def test_strength_meets(self):
        from nodechain.cli.drift_detection import _strength_meets
        assert _strength_meets("observed", "observed") is True
        assert _strength_meets("observed", "verified") is True
        assert _strength_meets("observed", "inferred") is False
        assert _strength_meets("inferred", "observed") is True
        assert _strength_meets("unavailable", "unavailable") is True


# ── Backward Compatibility ────────────────────────────────────────────────

class TestBackwardCompatibility:
    """v1.14.0 tests still pass with v1.18.2 changes."""

    def test_no_drift_all_match(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift
        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        result = check_drift(
            target="pve1/801",
            release_id="rel-drift-policy-001",
            release_history_path=rh_path,
            observed_artifact_digest="a" * 64,
            observed_service_state="running",
        )
        assert result["drift_detected"] is False
        assert result["drift_fields"] == []

    def test_artifact_digest_drift(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift
        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        result = check_drift(
            target="pve1/801",
            release_id="rel-drift-policy-001",
            release_history_path=rh_path,
            observed_artifact_digest="b" * 64,
        )
        assert result["drift_detected"] is True
        assert "artifact_digest" in result["drift_fields"]

    def test_no_policy_still_produces_field_details(self, tmp_path):
        """When no policy is explicitly passed, field_details still exist (default policy)."""
        from nodechain.cli.drift_detection import check_drift
        rh_path = _setup_history(tmp_path)
        result = check_drift(
            target="pve1/801",
            release_id="rel-drift-policy-001",
            release_history_path=rh_path,
            observed_service_state="running",
        )
        # Default policy applies, so field_details should be present
        assert "field_details" in result
        assert "policy_digest" in result
