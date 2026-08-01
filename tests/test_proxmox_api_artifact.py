"""Tests for v1.18.2 Proxmox API Artifact Deployment.

Tests cover all 8 acceptance criteria:
  1. upload_artifact action registered
  2. Manifest fields for artifact deployment
  3. Transport is explicit (proxmox_command_shape=api)
  4. Receipt records artifact/transfer evidence
  5. Strict mode failure modes
  6. Secret policy remains enforced
  7. Signed manifest and trust store (verified by existing tests)
  8. Cross-platform green
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path

import pytest


class TestUploadArtifactActionRegistration:
    """AC1: upload_artifact action is registered."""

    def test_in_api_actions(self):
        from nodechain.cli.deployment_adapter import PROXMOX_API_ACTIONS
        assert "upload_artifact" in PROXMOX_API_ACTIONS

    def test_in_lifecycle_matrix(self):
        from nodechain.cli.deployment_adapter import PROXMOX_API_LIFECYCLE_MATRIX
        assert "upload_artifact" in PROXMOX_API_LIFECYCLE_MATRIX

    def test_upload_url(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            remote_storage="local",
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        url = adapter._build_api_url("upload_artifact")
        assert "storage/local/upload" in url
        assert "pve1" in url


class TestArtifactManifestFields:
    """AC2: Manifest supports artifact deployment fields."""

    def test_artifact_fields(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            artifact_digest_required=True,
            remote_digest_verification_required=True,
            max_artifact_size_bytes=10485760,
            overwrite_policy="reject",
            staging_directory="/tmp/staging",
            final_path="/var/lib/artifacts/app.tar.gz",
            remote_storage="local",
            artifact_local_path="/tmp/app.tar.gz",
        )
        assert m.artifact_digest_required is True
        assert m.remote_digest_verification_required is True
        assert m.max_artifact_size_bytes == 10485760
        assert m.overwrite_policy == "reject"
        assert m.staging_directory == "/tmp/staging"
        assert m.final_path == "/var/lib/artifacts/app.tar.gz"
        assert m.remote_storage == "local"
        assert m.artifact_local_path == "/tmp/app.tar.gz"

    def test_defaults(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(adapter_id="x", adapter_type="proxmox_api")
        assert m.artifact_digest_required is True
        assert m.remote_digest_verification_required is True
        assert m.max_artifact_size_bytes == 0  # unlimited
        assert m.overwrite_policy == "reject"
        assert m.remote_storage == "local"

    def test_roundtrip(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            max_artifact_size_bytes=50000,
            overwrite_policy="allow",
            final_path="/opt/app/deploy.tar.gz",
            artifact_local_path="/tmp/art.tar.gz",
        )
        m2 = AdapterManifest.from_dict(m.to_dict())
        assert m2.max_artifact_size_bytes == 50000
        assert m2.overwrite_policy == "allow"
        assert m2.final_path == "/opt/app/deploy.tar.gz"
        assert m2.artifact_local_path == "/tmp/art.tar.gz"


class TestUploadArtifactSuccess:
    """AC3+AC4: Successful upload with proper receipt."""

    def test_upload_success(self, monkeypatch, tmp_path):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        # Create a local artifact
        artifact = tmp_path / "app.tar.gz"
        content = b"Hello NodeChain deployment artifact!"
        artifact.write_bytes(content)
        expected_digest = hashlib.sha256(content).hexdigest()

        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["upload_artifact"], allowed_api_actions=["upload_artifact"],
            artifact_local_path=str(artifact),
            final_path="/opt/app/app.tar.gz",
            allowed_remote_paths=["/opt/app"],
            remote_storage="local",
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        monkeypatch.setattr(adapter, "_api_request", lambda *a, **k: {
            "status_code": 200, "body": {"data": "UPID:upload"}, "tls_verified": True,
        })
        result = adapter.deploy("t", expected_digest, "p", "r")
        assert result["deploy_status"] == "accepted"
        assert result["artifact_digest"] == expected_digest
        assert result["artifact_size_bytes"] == len(content)
        assert result["remote_path"] == "/opt/app/app.tar.gz"
        assert result["remote_digest_matched"] is True
        assert result["proxmox_command_shape"] == "api"
        assert "transfer_started_at" in result
        assert "transfer_finished_at" in result
        assert result["staging_used"] is False


class TestArtifactDigestMissing:
    """AC5: Strict mode fails when artifact digest missing."""

    def test_digest_required_missing(self, monkeypatch, tmp_path):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        artifact = tmp_path / "app.tar.gz"
        artifact.write_bytes(b"test")

        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["upload_artifact"], allowed_api_actions=["upload_artifact"],
            artifact_digest_required=True,
            artifact_local_path=str(artifact),
            final_path="/opt/app/app.tar.gz",
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        result = adapter.deploy("t", "", "p", "r")  # no digest
        assert result["deploy_status"] == "rejected"
        assert result["failure_mode"] == "artifact_digest_missing"


class TestArtifactTooLarge:
    """AC5: Artifact exceeds max size."""

    def test_size_exceeded(self, monkeypatch, tmp_path):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        artifact = tmp_path / "big.tar.gz"
        artifact.write_bytes(b"x" * 200)

        monkeypatch.setenv("PROXMOX_SECRET", "s")
        content = b"x" * 200
        digest = hashlib.sha256(content).hexdigest()
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["upload_artifact"], allowed_api_actions=["upload_artifact"],
            artifact_local_path=str(artifact),
            final_path="/opt/app/app.tar.gz",
            max_artifact_size_bytes=100,  # 100 bytes max
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        result = adapter.deploy("t", digest, "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["failure_mode"] == "artifact_too_large"
        assert result["artifact_size_bytes"] == 200


class TestRemotePathNotAllowed:
    """AC5: Remote path outside allowlist."""

    def test_path_not_in_allowlist(self, monkeypatch, tmp_path):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        artifact = tmp_path / "app.tar.gz"
        content = b"test artifact"
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
            final_path="/etc/passwd/evil",  # not in allowlist
            allowed_remote_paths=["/opt/app", "/tmp/staging"],
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        result = adapter.deploy("t", digest, "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["failure_mode"] == "remote_path_not_allowed"


class TestTransferIncomplete:
    """AC5: Transfer failure (API error)."""

    def test_upload_api_error(self, monkeypatch, tmp_path):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        artifact = tmp_path / "app.tar.gz"
        content = b"test"
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
            final_path="/opt/app/app.tar.gz",
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        monkeypatch.setattr(adapter, "_api_request", lambda *a, **k: {
            "status_code": 500, "body": {"errors": "quota exceeded"}, "tls_verified": True,
        })
        result = adapter.deploy("t", digest, "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["failure_mode"] == "transfer_incomplete"
        assert "transfer_started_at" in result


class TestOverwritePolicy:
    """AC5: Overwrite not allowed."""

    def test_overwrite_rejected(self, monkeypatch, tmp_path):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        artifact = tmp_path / "app.tar.gz"
        content = b"test"
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
            final_path="/opt/app/app.tar.gz",
            allowed_remote_paths=["/opt/app"],
            overwrite_policy="reject",
            remote_storage="local",
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        # First call: content listing showing existing file
        # Second call: would be the upload (but we reject first)
        def mock_api(url, headers, timeout=30, method="GET"):
            if "storage/local/content" in url:
                return {"status_code": 200, "body": {"data": [
                    {"volid": "local:snippets/app.tar.gz", "size": 100}
                ]}, "tls_verified": True}
            return {"status_code": 200, "body": {"data": "UPID:upload"}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api)
        result = adapter.deploy("t", digest, "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["failure_mode"] == "overwrite_not_allowed"


class TestStagingUsed:
    """Staging directory mode."""

    def test_staging_mode(self, monkeypatch, tmp_path):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        artifact = tmp_path / "app.tar.gz"
        content = b"staged artifact"
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
            allowed_remote_paths=["/tmp/staging"],
            remote_storage="local",
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        monkeypatch.setattr(adapter, "_api_request", lambda *a, **k: {
            "status_code": 200, "body": {"data": "UPID:upload"}, "tls_verified": True,
        })
        result = adapter.deploy("t", digest, "p", "r")
        assert result["deploy_status"] == "accepted"
        assert result["staging_used"] is True
        assert result["remote_path"] == "/tmp/staging"


class TestSecretPolicyEnforced:
    """AC6: Secret policy remains enforced for upload_artifact."""

    def test_inline_secret_forbidden(self, monkeypatch, tmp_path):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        artifact = tmp_path / "app.tar.gz"
        content = b"test"
        artifact.write_bytes(content)
        digest = hashlib.sha256(content).hexdigest()

        # Inline secret — should fail validation
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="inline:super-secret-token-value",
            allowed_actions=["upload_artifact"], allowed_api_actions=["upload_artifact"],
            artifact_local_path=str(artifact),
            final_path="/opt/app/app.tar.gz",
            forbid_inline_secrets=True,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        # Validation should fail at _validate_api_manifest
        issues = adapter._validate_api_manifest()
        assert any("inline" in i.lower() for i in issues)
