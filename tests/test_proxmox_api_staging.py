"""Tests for v1.18.2 Proxmox Artifact Staging Integrity.

Tests cover all 7 acceptance criteria:
  1. Separate staging path from final path
  2. Upload always goes to staging first
  3. Finalization step is explicit (promote_artifact)
  4. Receipt records promotion evidence
  5. Strict mode fails on promotion violations
  6. Artifact action matrix documented
  7. Cross-platform green
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest


class TestArtifactActionMatrix:
    """AC6: Artifact action matrix documents upload → promote → apply."""

    def test_matrix_exists(self):
        from nodechain.cli.deployment_adapter import ARTIFACT_ACTION_MATRIX
        assert "upload_artifact" in ARTIFACT_ACTION_MATRIX
        assert "promote_artifact" in ARTIFACT_ACTION_MATRIX
        assert "apply_artifact" in ARTIFACT_ACTION_MATRIX

    def test_matrix_fields(self):
        from nodechain.cli.deployment_adapter import ARTIFACT_ACTION_MATRIX
        for action, entry in ARTIFACT_ACTION_MATRIX.items():
            assert "stage" in entry
            assert "target" in entry
            assert "promotes" in entry
            assert "activates" in entry
            assert "description" in entry

    def test_matrix_stages(self):
        from nodechain.cli.deployment_adapter import ARTIFACT_ACTION_MATRIX
        assert ARTIFACT_ACTION_MATRIX["upload_artifact"]["stage"] == "upload"
        assert ARTIFACT_ACTION_MATRIX["promote_artifact"]["stage"] == "promote"
        assert ARTIFACT_ACTION_MATRIX["apply_artifact"]["stage"] == "apply"

    def test_promote_in_api_actions(self):
        from nodechain.cli.deployment_adapter import PROXMOX_API_ACTIONS
        assert "promote_artifact" in PROXMOX_API_ACTIONS

    def test_promote_in_lifecycle_matrix(self):
        from nodechain.cli.deployment_adapter import PROXMOX_API_LIFECYCLE_MATRIX
        assert "promote_artifact" in PROXMOX_API_LIFECYCLE_MATRIX


class TestPromoteManifestFields:
    """AC1+AC6: Manifest supports promotion fields."""

    def test_promotion_fields(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            require_signed_manifest_for_promotion=True,
            staging_digest_verification_required=True,
            final_digest_verification_required=True,
        )
        assert m.require_signed_manifest_for_promotion is True
        assert m.staging_digest_verification_required is True
        assert m.final_digest_verification_required is True

    def test_defaults(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(adapter_id="x", adapter_type="proxmox_api")
        assert m.require_signed_manifest_for_promotion is True
        assert m.staging_digest_verification_required is True
        assert m.final_digest_verification_required is True

    def test_roundtrip(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            require_signed_manifest_for_promotion=False,
            staging_digest_verification_required=False,
        )
        m2 = AdapterManifest.from_dict(m.to_dict())
        assert m2.require_signed_manifest_for_promotion is False
        assert m2.staging_digest_verification_required is False


class TestUploadGoesToStaging:
    """AC2: Upload always goes to staging when staging_directory is set."""

    def test_upload_uses_staging(self, monkeypatch, tmp_path):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        artifact = tmp_path / "app.tar.gz"
        content = b"staging test"
        artifact.write_bytes(content)
        digest = hashlib.sha256(content).hexdigest()

        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["upload_artifact"], allowed_api_actions=["upload_artifact"],
            artifact_local_path=str(artifact),
            staging_directory="/tmp/staging",
            final_path="/opt/app/app.tar.gz",
            allowed_remote_paths=["/tmp/staging", "/opt/app"],
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        monkeypatch.setattr(adapter, "_api_request", lambda *a, **k: {
            "status_code": 200, "body": {"data": "UPID:upload"}, "tls_verified": True,
        })
        result = adapter.deploy("t", digest, "p", "r")
        assert result["deploy_status"] == "accepted"
        assert result["staging_used"] is True
        # v1.18.2: Upload goes to staging_directory first
        assert result["remote_path"] == "/tmp/staging"


class TestPromoteSuccess:
    """AC3+AC4: Successful promotion with proper receipt."""

    def test_promote_success(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        digest = "abc123def456"
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["promote_artifact"], allowed_api_actions=["promote_artifact"],
            staging_directory="/tmp/staging",
            final_path="/opt/app/app.tar.gz",
            allowed_remote_paths=["/opt/app", "/tmp/staging"],
            remote_storage="local",
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        def mock_api(url, headers, timeout=30, method="GET"):
            if "storage/local/content" in url:
                return {"status_code": 200, "body": {"data": []}, "tls_verified": True}
            return {"status_code": 200, "body": {"data": "OK"}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api)
        result = adapter.deploy("t", digest, "p", "r")
        assert result["deploy_status"] == "accepted"
        assert result["staging_path"] == "/tmp/staging"
        assert result["final_path"] == "/opt/app/app.tar.gz"
        assert result["staging_digest"] == digest
        assert result["final_digest"] == digest
        assert result["promotion_performed"] is True
        assert "promotion_started_at" in result
        assert "promotion_finished_at" in result


class TestPromoteStagingMissing:
    """AC5: Staging path not configured."""

    def test_staging_missing(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["promote_artifact"], allowed_api_actions=["promote_artifact"],
            final_path="/opt/app/app.tar.gz",
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        result = adapter.deploy("t", "d", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["failure_mode"] == "staging_path_missing"


class TestPromoteFinalPathNotAllowed:
    """AC5: Final path outside allowlist."""

    def test_final_path_not_allowed(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["promote_artifact"], allowed_api_actions=["promote_artifact"],
            staging_directory="/tmp/staging",
            final_path="/etc/evil/path",
            allowed_remote_paths=["/opt/app", "/tmp/staging"],
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        result = adapter.deploy("t", "d", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["failure_mode"] == "final_path_not_allowed"


class TestPromoteStagingDigestMismatch:
    """AC5: Staged artifact cannot be verified."""

    def test_staging_verify_fails(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["promote_artifact"], allowed_api_actions=["promote_artifact"],
            staging_directory="/tmp/staging",
            final_path="/opt/app/app.tar.gz",
            allowed_remote_paths=["/opt/app", "/tmp/staging"],
            staging_digest_verification_required=True,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        monkeypatch.setattr(adapter, "_api_request", lambda *a, **k: {
            "status_code": 500, "body": {}, "tls_verified": True,
        })
        result = adapter.deploy("t", "d", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["failure_mode"] == "staging_digest_mismatch"


class TestPromoteOverwriteRejected:
    """AC5: Overwrite not allowed on final path."""

    def test_overwrite_rejected(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["promote_artifact"], allowed_api_actions=["promote_artifact"],
            staging_directory="/tmp/staging",
            final_path="/opt/app/app.tar.gz",
            allowed_remote_paths=["/opt/app", "/tmp/staging"],
            overwrite_policy="reject",
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        def mock_api(url, headers, timeout=30, method="GET"):
            if "storage/local/content" in url:
                return {"status_code": 200, "body": {"data": [
                    {"volid": "local:snippets/app.tar.gz", "size": 100}
                ]}, "tls_verified": True}
            return {"status_code": 200, "body": {"data": "OK"}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api)
        result = adapter.deploy("t", "d", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["failure_mode"] == "overwrite_not_allowed"


class TestPromotionIncomplete:
    """AC5: Promotion API call fails."""

    def test_promotion_api_error(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["promote_artifact"], allowed_api_actions=["promote_artifact"],
            staging_directory="/tmp/staging",
            final_path="/opt/app/app.tar.gz",
            allowed_remote_paths=["/opt/app", "/tmp/staging"],
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        def mock_api(url, headers, timeout=30, method="GET"):
            if "storage/local/content" in url:
                return {"status_code": 200, "body": {"data": []}, "tls_verified": True}
            # PUT to config endpoint fails
            return {"status_code": 500, "body": {"errors": "permission denied"}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api)
        result = adapter.deploy("t", "d", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["failure_mode"] == "promotion_incomplete"
        assert "promotion_started_at" in result


class TestPromotionReceiptFields:
    """AC4: Receipt records all promotion evidence."""

    def test_receipt_has_promotion_fields(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        digest = "feedface"
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["promote_artifact"], allowed_api_actions=["promote_artifact"],
            staging_directory="/tmp/staging",
            final_path="/opt/app/deploy.bin",
            allowed_remote_paths=["/opt/app"],
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        monkeypatch.setattr(adapter, "_api_request", lambda *a, **k: {
            "status_code": 200, "body": {"data": []}, "tls_verified": True,
        })
        result = adapter.deploy("t", digest, "p", "r")
        for field in ["staging_path", "final_path", "staging_digest", "final_digest",
                       "promotion_performed", "promotion_started_at", "promotion_finished_at"]:
            assert field in result, f"Missing: {field}"
