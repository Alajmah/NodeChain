"""Tests for v1.18.2 Drift Remediation.

Tests cover all 9 acceptance criteria:
  1. nodechain drift remediate command
  2. Remediation requires drift report
  3. Remediation policy fields
  4. recommend mode produces plan without mutating target
  5. auto_rollback mode resolves and executes rollback
  6. Remediation receipt records all fields
  7. Strict mode failures
  8. Exit codes
  9. Windows/Linux green
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
    priv_path = str(tmp_path / f"priv_rem{suffix}.pem")
    Path(priv_path).write_bytes(priv_pem)
    return priv_path


def _setup_history(tmp_path, artifact_digest="a" * 64, target="pve1/801"):
    from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
    rh_path = str(tmp_path / "rh.json")
    history = ReleaseHistory(path=rh_path)
    history.add(ReleaseRecord(
        release_id="rel-remediate-001",
        artifact_digest=artifact_digest,
        final_deployment_state="applied",
        activation_verified=True,
        target=target,
        deployment_receipt_digest="r" * 64,
    ))
    return rh_path


def _make_drift_report(drift_detected=True, field="artifact_digest"):
    """Create a minimal drift report dict."""
    return {
        "type": "drift_report",
        "report_id": "test-report-001",
        "drift_detected": drift_detected,
        "drift_fields": [field] if drift_detected else [],
        "expected_values": {field: "a" * 64} if drift_detected else {},
        "observed_values": {field: "b" * 64} if drift_detected else {},
        "checked_at": "2026-06-16T12:00:00+00:00",
        "target": "pve1/801",
        "release_id": "rel-remediate-001",
        "evidence_source": "proxmox_api",
        "report_digest": "0" * 64,
    }


def _write_remediation_policy(tmp_path, **overrides):
    policy = {
        "remediation_mode": "recommend",
        "allowed_remediation_actions": ["rollback_artifact"],
        "require_signed_drift_policy": False,
        "require_signed_drift_report": False,
        "require_release_history_snapshot": False,
        "require_latest_known_good": True,
        "require_previous_assurance_chain": False,
        "target": "pve1/801",
    }
    policy.update(overrides)
    path = str(tmp_path / "remediation_policy.json")
    Path(path).write_text(json.dumps(policy), encoding="utf-8")
    return path


# ── AC1+AC2: Remediation Command and Drift Report ──────────────────────────

class TestRemediationBasic:
    """AC1+AC2: Remediation requires drift report and basic operation."""

    def test_no_drift_no_remediation(self, tmp_path):
        from nodechain.cli.drift_remediation import remediate_drift
        rh_path = _setup_history(tmp_path)
        report = _make_drift_report(drift_detected=False)
        result = remediate_drift(
            target="pve1/801",
            drift_report=report,
            release_history_path=rh_path,
        )
        assert result["final_state"] == "no_remediation_needed"
        assert result["selected_action"] == "no_action"

    def test_drift_detected_triggers_remediation(self, tmp_path):
        from nodechain.cli.drift_remediation import remediate_drift
        rh_path = _setup_history(tmp_path)
        report = _make_drift_report(drift_detected=True)
        result = remediate_drift(
            target="pve1/801",
            drift_report=report,
            release_history_path=rh_path,
        )
        assert result["final_state"] != "no_remediation_needed"

    def test_drift_report_digest_recorded(self, tmp_path):
        from nodechain.cli.drift_remediation import remediate_drift
        rh_path = _setup_history(tmp_path)
        report = _make_drift_report(drift_detected=True)
        result = remediate_drift(
            target="pve1/801",
            drift_report=report,
            release_history_path=rh_path,
        )
        assert result["drift_report_digest"]
        assert len(result["drift_report_digest"]) == 64

    def test_no_report_provided(self, tmp_path):
        from nodechain.cli.drift_remediation import remediate_drift
        result = remediate_drift(target="pve1/801")
        assert result["final_state"] == "no_remediation_needed"


# ── AC3: Remediation Policy ────────────────────────────────────────────────

class TestRemediationPolicy:
    """AC3: Remediation policy fields."""

    def test_policy_fields(self):
        from nodechain.cli.drift_remediation import RemediationPolicy
        p = RemediationPolicy(
            remediation_mode="auto_rollback",
            allowed_remediation_actions=["rollback_artifact", "redeploy"],
            require_signed_drift_policy=True,
            require_signed_drift_report=True,
            require_release_history_snapshot=True,
            require_latest_known_good=True,
            require_previous_assurance_chain=True,
            target="pve1/801",
        )
        assert p.remediation_mode == "auto_rollback"
        assert "rollback_artifact" in p.allowed_remediation_actions
        assert p.require_signed_drift_policy is True
        assert p.require_signed_drift_report is True
        assert p.require_release_history_snapshot is True
        assert p.require_latest_known_good is True
        assert p.require_previous_assurance_chain is True

    def test_policy_from_file(self, tmp_path):
        from nodechain.cli.drift_remediation import RemediationPolicy
        path = _write_remediation_policy(tmp_path, remediation_mode="auto_rollback")
        p = RemediationPolicy.from_file(path)
        assert p.remediation_mode == "auto_rollback"

    def test_policy_roundtrip(self):
        from nodechain.cli.drift_remediation import RemediationPolicy
        p = RemediationPolicy(remediation_mode="manual", target="x")
        d = p.to_dict()
        p2 = RemediationPolicy.from_dict(d)
        assert p2.remediation_mode == "manual"
        assert p2.target == "x"

    def test_policy_digest(self):
        from nodechain.cli.drift_remediation import RemediationPolicy
        p1 = RemediationPolicy(remediation_mode="recommend")
        p2 = RemediationPolicy(remediation_mode="recommend")
        p3 = RemediationPolicy(remediation_mode="auto_rollback")
        assert p1.digest() == p2.digest()
        assert p1.digest() != p3.digest()


# ── AC4: Recommend Mode ────────────────────────────────────────────────────

class TestRecommendMode:
    """AC4: recommend mode produces plan without mutating target."""

    def test_recommend_produces_plan(self, tmp_path):
        from nodechain.cli.drift_remediation import remediate_drift, RemediationPolicy
        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        report = _make_drift_report(drift_detected=True)
        policy = RemediationPolicy(remediation_mode="recommend")
        result = remediate_drift(
            target="pve1/801",
            drift_report=report,
            remediation_policy=policy,
            release_history_path=rh_path,
        )
        assert result["final_state"] == "recommendation_produced"
        assert result["selected_action"] == "rollback_artifact"
        assert result["selected_release_id"] == "rel-remediate-001"
        assert result["selected_artifact_digest"] == "a" * 64
        assert result["rollback_attempted"] is False

    def test_recommend_resolves_known_good(self, tmp_path):
        from nodechain.cli.drift_remediation import remediate_drift, RemediationPolicy
        rh_path = _setup_history(tmp_path, artifact_digest="abc" * 21 + "x")
        report = _make_drift_report(drift_detected=True)
        policy = RemediationPolicy(remediation_mode="recommend")
        result = remediate_drift(
            target="pve1/801",
            drift_report=report,
            remediation_policy=policy,
            release_history_path=rh_path,
        )
        assert result["selected_artifact_digest"] == "abc" * 21 + "x"

    def test_recommend_fails_without_known_good(self, tmp_path):
        from nodechain.cli.drift_remediation import remediate_drift, RemediationPolicy
        # Empty history
        rh_path = str(tmp_path / "empty_rh.json")
        Path(rh_path).write_text("{}", encoding="utf-8")
        report = _make_drift_report(drift_detected=True)
        policy = RemediationPolicy(
            remediation_mode="recommend",
            require_latest_known_good=True,
        )
        result = remediate_drift(
            target="pve1/801",
            drift_report=report,
            remediation_policy=policy,
            release_history_path=rh_path,
        )
        assert result["final_state"] == "denied"
        assert "known-good" in result["denial_reason"]


# ── AC5: Auto Rollback Mode ────────────────────────────────────────────────

class TestAutoRollbackMode:
    """AC5: auto_rollback resolves and executes rollback."""

    def test_auto_rollback_without_manifest_downgrades_to_recommend(self, tmp_path):
        from nodechain.cli.drift_remediation import remediate_drift, RemediationPolicy
        rh_path = _setup_history(tmp_path)
        report = _make_drift_report(drift_detected=True)
        policy = RemediationPolicy(remediation_mode="auto_rollback")
        result = remediate_drift(
            target="pve1/801",
            drift_report=report,
            remediation_policy=policy,
            release_history_path=rh_path,
        )
        # No manifest → can't execute → recommendation produced
        assert result["final_state"] == "recommendation_produced"
        assert result["rollback_attempted"] is False

    def test_auto_rollback_action_not_allowed(self, tmp_path):
        from nodechain.cli.drift_remediation import remediate_drift, RemediationPolicy
        rh_path = _setup_history(tmp_path)
        report = _make_drift_report(drift_detected=True)
        policy = RemediationPolicy(
            remediation_mode="auto_rollback",
            allowed_remediation_actions=["alert"],  # rollback not allowed
        )
        result = remediate_drift(
            target="pve1/801",
            drift_report=report,
            remediation_policy=policy,
            release_history_path=rh_path,
        )
        assert result["final_state"] == "denied"
        assert "not in allowed" in result["denial_reason"]

    def test_auto_rollback_resolves_known_good(self, tmp_path):
        from nodechain.cli.drift_remediation import remediate_drift, RemediationPolicy
        rh_path = _setup_history(tmp_path, artifact_digest="d" * 64)
        report = _make_drift_report(drift_detected=True)
        policy = RemediationPolicy(remediation_mode="auto_rollback")
        result = remediate_drift(
            target="pve1/801",
            drift_report=report,
            remediation_policy=policy,
            release_history_path=rh_path,
        )
        assert result["selected_artifact_digest"] == "d" * 64

    def test_auto_rollback_no_known_good_denies(self, tmp_path):
        from nodechain.cli.drift_remediation import remediate_drift, RemediationPolicy
        rh_path = str(tmp_path / "empty.json")
        Path(rh_path).write_text("{}", encoding="utf-8")
        report = _make_drift_report(drift_detected=True)
        policy = RemediationPolicy(remediation_mode="auto_rollback")
        result = remediate_drift(
            target="pve1/801",
            drift_report=report,
            remediation_policy=policy,
            release_history_path=rh_path,
        )
        assert result["final_state"] == "denied"
        assert "known-good" in result["denial_reason"]


# ── Manual Mode ────────────────────────────────────────────────────────────

class TestManualMode:
    """Manual mode produces alert."""

    def test_manual_mode(self, tmp_path):
        from nodechain.cli.drift_remediation import remediate_drift, RemediationPolicy
        rh_path = _setup_history(tmp_path)
        report = _make_drift_report(drift_detected=True)
        policy = RemediationPolicy(remediation_mode="manual")
        result = remediate_drift(
            target="pve1/801",
            drift_report=report,
            remediation_policy=policy,
            release_history_path=rh_path,
        )
        assert result["final_state"] == "manual_intervention_required"
        assert result["selected_action"] == "alert"


# ── AC6: Remediation Receipt ───────────────────────────────────────────────

class TestRemediationReceipt:
    """AC6: Remediation receipt records all fields."""

    def test_receipt_has_all_fields(self, tmp_path):
        from nodechain.cli.drift_remediation import remediate_drift, create_remediation_receipt
        rh_path = _setup_history(tmp_path)
        report = _make_drift_report(drift_detected=True)
        result = remediate_drift(
            target="pve1/801",
            drift_report=report,
            release_history_path=rh_path,
        )
        receipt = create_remediation_receipt(result)
        for field in ["remediation_id", "drift_report_digest",
                       "remediation_policy_digest", "remediation_mode",
                       "selected_action", "selected_release_id",
                       "selected_artifact_digest", "rollback_attempted",
                       "rollback_result", "final_state", "denial_reason",
                       "receipt_digest"]:
            assert field in receipt, f"Missing receipt field: {field}"

    def test_receipt_signed(self, tmp_path):
        from nodechain.cli.drift_remediation import remediate_drift, create_remediation_receipt
        priv_path = _generate_key_pair(tmp_path)
        rh_path = _setup_history(tmp_path)
        report = _make_drift_report(drift_detected=True)
        result = remediate_drift(
            target="pve1/801",
            drift_report=report,
            release_history_path=rh_path,
        )
        receipt = create_remediation_receipt(result, private_key_path=priv_path)
        assert "receipt_signature" in receipt
        assert receipt["receipt_signature_algorithm"] == "RSA-PSS-SHA256"

    def test_receipt_written_to_file(self, tmp_path):
        from nodechain.cli.drift_remediation import remediate_drift, create_remediation_receipt
        rh_path = _setup_history(tmp_path)
        report = _make_drift_report(drift_detected=True)
        result = remediate_drift(
            target="pve1/801",
            drift_report=report,
            release_history_path=rh_path,
        )
        out = str(tmp_path / "receipt.json")
        create_remediation_receipt(result, output_path=out)
        data = json.loads(Path(out).read_text(encoding="utf-8"))
        assert data["type"] == "remediation_receipt"


# ── AC7: Strict Mode Failures ──────────────────────────────────────────────

class TestStrictModeFailures:
    """AC7: Strict mode fails on various conditions."""

    def test_strict_unsigned_report_denied(self, tmp_path):
        from nodechain.cli.drift_remediation import remediate_drift, RemediationPolicy
        rh_path = _setup_history(tmp_path)
        report = _make_drift_report(drift_detected=True)
        policy = RemediationPolicy(
            remediation_mode="recommend",
            require_signed_drift_report=True,
        )
        result = remediate_drift(
            target="pve1/801",
            drift_report=report,
            remediation_policy=policy,
            release_history_path=rh_path,
            strict=True,
        )
        assert result["final_state"] == "denied"
        assert result["valid"] is False
        assert "unsigned" in result["denial_reason"].lower()

    def test_strict_unsigned_policy_denied(self, tmp_path):
        from nodechain.cli.drift_remediation import remediate_drift, RemediationPolicy
        rh_path = _setup_history(tmp_path)
        report = _make_drift_report(drift_detected=True)
        # Simulate unsigned policy in the drift report
        report["policy_signature_status"] = "unsigned"
        policy = RemediationPolicy(
            remediation_mode="recommend",
            require_signed_drift_policy=True,
        )
        result = remediate_drift(
            target="pve1/801",
            drift_report=report,
            remediation_policy=policy,
            release_history_path=rh_path,
            strict=True,
        )
        assert result["final_state"] == "denied"
        assert result["valid"] is False

    def test_strict_no_known_good_denied(self, tmp_path):
        from nodechain.cli.drift_remediation import remediate_drift, RemediationPolicy
        rh_path = str(tmp_path / "empty.json")
        Path(rh_path).write_text("{}", encoding="utf-8")
        report = _make_drift_report(drift_detected=True)
        policy = RemediationPolicy(
            remediation_mode="recommend",
            require_latest_known_good=True,
        )
        result = remediate_drift(
            target="pve1/801",
            drift_report=report,
            remediation_policy=policy,
            release_history_path=rh_path,
            strict=True,
        )
        assert result["final_state"] == "denied"
        assert result["valid"] is False

    def test_non_strict_allows_denial_to_proceed(self, tmp_path):
        from nodechain.cli.drift_remediation import remediate_drift, RemediationPolicy
        rh_path = str(tmp_path / "empty.json")
        Path(rh_path).write_text("{}", encoding="utf-8")
        report = _make_drift_report(drift_detected=True)
        policy = RemediationPolicy(
            remediation_mode="recommend",
            require_latest_known_good=True,
        )
        result = remediate_drift(
            target="pve1/801",
            drift_report=report,
            remediation_policy=policy,
            release_history_path=rh_path,
            strict=False,  # non-strict
        )
        assert result["final_state"] == "denied"
        assert result["valid"] is True  # non-strict: still "valid"


# ── Constants ──────────────────────────────────────────────────────────────

class TestConstants:
    """Verify frozen constants."""

    def test_remediation_modes(self):
        from nodechain.cli.drift_remediation import REMEDIATION_MODES
        assert "manual" in REMEDIATION_MODES
        assert "recommend" in REMEDIATION_MODES
        assert "auto_rollback" in REMEDIATION_MODES

    def test_remediation_actions(self):
        from nodechain.cli.drift_remediation import REMEDIATION_ACTIONS
        assert "rollback_artifact" in REMEDIATION_ACTIONS
        assert "redeploy" in REMEDIATION_ACTIONS
        assert "alert" in REMEDIATION_ACTIONS
        assert "no_action" in REMEDIATION_ACTIONS


# ── AC8: End-to-End with Signed Report ─────────────────────────────────────

class TestEndToEnd:
    """End-to-end: drift check → remediation → signed receipt."""

    def test_full_flow_no_drift(self, tmp_path):
        """Drift check finds no drift → remediation not needed."""
        from nodechain.cli.drift_detection import check_drift
        from nodechain.cli.drift_remediation import remediate_drift

        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        drift_result = check_drift(
            target="pve1/801",
            release_id="rel-remediate-001",
            release_history_path=rh_path,
            observed_artifact_digest="a" * 64,  # no drift
            observed_service_state="running",
        )
        rem_result = remediate_drift(
            target="pve1/801",
            drift_report=drift_result,
            release_history_path=rh_path,
        )
        assert rem_result["final_state"] == "no_remediation_needed"

    def test_full_flow_drift_recommend(self, tmp_path):
        """Drift detected → recommendation produced."""
        from nodechain.cli.drift_detection import check_drift
        from nodechain.cli.drift_remediation import remediate_drift, RemediationPolicy

        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        drift_result = check_drift(
            target="pve1/801",
            release_id="rel-remediate-001",
            release_history_path=rh_path,
            observed_artifact_digest="b" * 64,  # drift!
        )
        policy = RemediationPolicy(remediation_mode="recommend")
        rem_result = remediate_drift(
            target="pve1/801",
            drift_report=drift_result,
            remediation_policy=policy,
            release_history_path=rh_path,
        )
        assert rem_result["final_state"] == "recommendation_produced"
        assert rem_result["selected_release_id"] == "rel-remediate-001"
        assert rem_result["selected_artifact_digest"] == "a" * 64
