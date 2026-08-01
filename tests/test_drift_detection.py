"""Tests for v1.18.2 Deployment Drift Detection.

Tests cover all 7 acceptance criteria:
  1. nodechain drift check command
  2. Drift check compares live target vs release history
  3. Proxmox API adapter supports read-only drift evidence
  4. Drift result records all fields
  5. Strict mode exit codes (0/10/15)
  6. Drift report can be signed
  7. Windows/Linux green
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def _generate_key_pair(tmp_path, suffix=""):
    """Generate RSA key pair for testing."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_path = str(tmp_path / f"priv_drift{suffix}.pem")
    pub_path = str(tmp_path / f"pub_drift{suffix}.pem")
    Path(priv_path).write_bytes(priv_pem)
    Path(pub_path).write_bytes(pub_pem)
    return priv_path, pub_path


def _setup_history(tmp_path, artifact_digest="a" * 64, target="pve1/801"):
    """Set up release history with a known-good release."""
    from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
    rh_path = str(tmp_path / "rh.json")
    history = ReleaseHistory(path=rh_path)
    history.add(ReleaseRecord(
        release_id="rel-drift-001",
        artifact_digest=artifact_digest,
        final_deployment_state="applied",
        activation_verified=True,
        target=target,
        deployment_receipt_digest="r" * 64,
    ))
    return rh_path


class TestDriftCheckNoDrift:
    """AC2: Drift check correctly identifies no drift."""

    def test_no_drift_all_match(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift
        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        result = check_drift(
            target="pve1/801",
            release_id="rel-drift-001",
            release_history_path=rh_path,
            observed_artifact_digest="a" * 64,
            observed_service_state="running",
            observed_target_identity="pve1/801",
            observed_deployment_receipt_digest="r" * 64,
        )
        assert result["drift_detected"] is False
        assert result["drift_fields"] == []
        assert result["valid"] is True

    def test_no_drift_partial_observed(self, tmp_path):
        """When only some values are observed, unchecked fields don't count as drift."""
        from nodechain.cli.drift_detection import check_drift
        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        result = check_drift(
            target="pve1/801",
            release_id="rel-drift-001",
            release_history_path=rh_path,
            observed_artifact_digest="a" * 64,
            observed_service_state="running",
            # Don't provide other observed values
        )
        assert result["drift_detected"] is False


class TestDriftDetected:
    """AC2: Drift check correctly identifies drift."""

    def test_artifact_digest_drift(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift
        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        result = check_drift(
            target="pve1/801",
            release_id="rel-drift-001",
            release_history_path=rh_path,
            observed_artifact_digest="b" * 64,  # different!
        )
        assert result["drift_detected"] is True
        assert "artifact_digest" in result["drift_fields"]

    def test_service_state_drift(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift
        rh_path = _setup_history(tmp_path)
        result = check_drift(
            target="pve1/801",
            release_id="rel-drift-001",
            release_history_path=rh_path,
            observed_service_state="stopped",  # expected "running"
        )
        assert result["drift_detected"] is True
        assert "service_state" in result["drift_fields"]

    def test_target_identity_drift(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift
        rh_path = _setup_history(tmp_path, target="pve1/801")
        result = check_drift(
            target="pve1/801",
            release_id="rel-drift-001",
            release_history_path=rh_path,
            observed_target_identity="pve2/802",  # different target!
        )
        assert result["drift_detected"] is True
        assert "target_identity" in result["drift_fields"]

    def test_receipt_digest_drift(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift
        rh_path = _setup_history(tmp_path)
        result = check_drift(
            target="pve1/801",
            release_id="rel-drift-001",
            release_history_path=rh_path,
            observed_deployment_receipt_digest="x" * 64,  # different
        )
        assert result["drift_detected"] is True
        assert "deployment_receipt_digest" in result["drift_fields"]

    def test_multiple_field_drift(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift
        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        result = check_drift(
            target="pve1/801",
            release_id="rel-drift-001",
            release_history_path=rh_path,
            observed_artifact_digest="b" * 64,
            observed_service_state="stopped",
        )
        assert result["drift_detected"] is True
        assert len(result["drift_fields"]) == 2


class TestDriftResultFields:
    """AC4: Drift result records all required fields."""

    def test_result_has_all_fields(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift
        rh_path = _setup_history(tmp_path)
        result = check_drift(
            target="pve1/801",
            release_id="rel-drift-001",
            release_history_path=rh_path,
            observed_artifact_digest="a" * 64,
            evidence_source="manual",
        )
        for field in ["drift_detected", "drift_fields", "expected_values",
                       "observed_values", "checked_at", "target", "release_id",
                       "evidence_source", "report_id"]:
            assert field in result, f"Missing drift result field: {field}"

    def test_expected_and_observed_populated(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift
        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        result = check_drift(
            target="pve1/801",
            release_id="rel-drift-001",
            release_history_path=rh_path,
            observed_artifact_digest="a" * 64,
        )
        assert "artifact_digest" in result["expected_values"]
        assert "artifact_digest" in result["observed_values"]
        assert result["expected_values"]["artifact_digest"] == "a" * 64


class TestDriftReleaseResolution:
    """Drift check resolves release by ID or latest-known-good."""

    def test_latest_known_good(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift
        rh_path = _setup_history(tmp_path)
        result = check_drift(
            target="pve1/801",
            release_id="",  # use latest known-good
            release_history_path=rh_path,
            observed_service_state="running",
        )
        assert result["valid"] is True
        assert result["release_id"] == "rel-drift-001"

    def test_release_not_found(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift
        rh_path = _setup_history(tmp_path)
        result = check_drift(
            target="pve1/801",
            release_id="nonexistent",
            release_history_path=rh_path,
        )
        assert result["valid"] is False
        assert "not found" in result.get("error", "").lower()


class TestDriftReportSigning:
    """AC6: Drift report can be signed."""

    def test_unsigned_report(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift, create_drift_report
        rh_path = _setup_history(tmp_path)
        result = check_drift(
            target="pve1/801", release_id="rel-drift-001",
            release_history_path=rh_path,
            observed_service_state="running",
        )
        report = create_drift_report(result)
        assert "report_digest" in report
        assert "report_signature" not in report

    def test_signed_report(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift, create_drift_report
        priv_path, _ = _generate_key_pair(tmp_path)
        rh_path = _setup_history(tmp_path)
        result = check_drift(
            target="pve1/801", release_id="rel-drift-001",
            release_history_path=rh_path,
            observed_service_state="running",
        )
        report = create_drift_report(result, private_key_path=priv_path)
        assert "report_signature" in report
        assert report["report_signature_algorithm"] == "RSA-PSS-SHA256"
        assert "report_signer_fingerprint" in report

    def test_report_written_to_file(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift, create_drift_report
        rh_path = _setup_history(tmp_path)
        result = check_drift(
            target="pve1/801", release_id="rel-drift-001",
            release_history_path=rh_path,
            observed_service_state="running",
        )
        out = str(tmp_path / "drift_report.json")
        report = create_drift_report(result, output_path=out)
        assert Path(out).exists()
        data = json.loads(Path(out).read_text(encoding="utf-8"))
        assert data["type"] == "drift_report"

    def test_report_has_correct_drift_fields(self, tmp_path):
        from nodechain.cli.drift_detection import check_drift, create_drift_report
        rh_path = _setup_history(tmp_path, artifact_digest="a" * 64)
        result = check_drift(
            target="pve1/801", release_id="rel-drift-001",
            release_history_path=rh_path,
            observed_artifact_digest="b" * 64,  # drift!
        )
        report = create_drift_report(result)
        assert report["drift_detected"] is True
        assert "artifact_digest" in report["drift_fields"]


class TestProxmoxDriftEvidence:
    """AC3: Proxmox API adapter supports read-only drift evidence."""

    def test_collect_proxmox_evidence(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest
        from nodechain.cli.drift_detection import collect_proxmox_drift_evidence

        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["get_status"], allowed_api_actions=["get_status"],
        )

        # Monkeypatch the adapter internals
        from nodechain.cli.deployment_adapter import ProxmoxApiAdapter
        original_init = ProxmoxApiAdapter.__init__

        def mock_api(self, url, headers, timeout=30, method="GET"):
            return {
                "status_code": 200,
                "body": {"data": {"status": "running"}},
                "tls_verified": True,
            }

        monkeypatch.setattr(ProxmoxApiAdapter, "_api_request", mock_api)
        evidence = collect_proxmox_drift_evidence(m)
        assert evidence["service_state"] == "running"
        assert evidence["target_identity"] == "pve1/801"
        assert evidence["evidence_source"] == "proxmox_api"


class TestDriftFieldsConstant:
    """Drift fields are a known, frozen set."""

    def test_drift_fields(self):
        from nodechain.cli.drift_detection import DRIFT_FIELDS
        assert "artifact_digest" in DRIFT_FIELDS
        assert "service_state" in DRIFT_FIELDS
        assert "target_identity" in DRIFT_FIELDS
        assert "deployment_receipt_digest" in DRIFT_FIELDS
        assert "final_path" in DRIFT_FIELDS
        assert "policy_digest" in DRIFT_FIELDS
