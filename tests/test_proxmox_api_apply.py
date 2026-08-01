"""Tests for v1.18.2 Proxmox Apply Artifact.

Tests cover all 7 acceptance criteria:
  1. apply_artifact action registered
  2. Manifest supports apply fields
  3. Apply only runs when preconditions met
  4. Receipt records apply evidence
  5. Strict mode failure modes
  6. Transport is explicit (api)
  7. Cross-platform green
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest


class TestApplyActionRegistration:
    """AC1: apply_artifact action is registered."""

    def test_in_api_actions(self):
        from nodechain.cli.deployment_adapter import PROXMOX_API_ACTIONS
        assert "apply_artifact" in PROXMOX_API_ACTIONS

    def test_in_lifecycle_matrix(self):
        from nodechain.cli.deployment_adapter import PROXMOX_API_LIFECYCLE_MATRIX
        assert "apply_artifact" in PROXMOX_API_LIFECYCLE_MATRIX
        assert PROXMOX_API_LIFECYCLE_MATRIX["apply_artifact"]["task_required"] is True

    def test_in_artifact_matrix(self):
        from nodechain.cli.deployment_adapter import ARTIFACT_ACTION_MATRIX
        assert ARTIFACT_ACTION_MATRIX["apply_artifact"]["activates"] is True
        assert ARTIFACT_ACTION_MATRIX["apply_artifact"]["stage"] == "apply"

    def test_apply_url(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        url = adapter._build_api_url("apply_artifact")
        assert "pve1" in url
        assert "801" in url


class TestApplyManifestFields:
    """AC2: Manifest supports apply fields."""

    def test_apply_fields(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_apply_action="restart_service",
            allowed_apply_targets=["/opt/app"],
            require_promoted_artifact=True,
            expected_service_state="running",
            apply_timeout_seconds=300,
            rollback_policy="auto",
        )
        assert m.api_apply_action == "restart_service"
        assert m.allowed_apply_targets == ["/opt/app"]
        assert m.require_promoted_artifact is True
        assert m.expected_service_state == "running"
        assert m.apply_timeout_seconds == 300
        assert m.rollback_policy == "auto"

    def test_defaults(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(adapter_id="x", adapter_type="proxmox_api")
        assert m.api_apply_action == ""
        assert m.allowed_apply_targets == []
        assert m.require_promoted_artifact is True
        assert m.expected_service_state == "running"
        assert m.apply_timeout_seconds == 120
        assert m.rollback_policy == "manual"

    def test_roundtrip(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_apply_action="custom_apply",
            expected_service_state="active",
            rollback_policy="auto",
        )
        m2 = AdapterManifest.from_dict(m.to_dict())
        assert m2.api_apply_action == "custom_apply"
        assert m2.expected_service_state == "active"
        assert m2.rollback_policy == "auto"


class TestApplySuccess:
    """AC3+AC4: Successful apply with proper receipt."""

    def test_apply_success(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        digest = "abc123def456"
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["apply_artifact"], allowed_api_actions=["apply_artifact"],
            require_promoted_artifact=True,
            expected_service_state="running",
            apply_timeout_seconds=30,
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        def mock_api(url, headers, timeout=30, method="GET"):
            if "storage/local/content" in url:
                return {"status_code": 200, "body": {"data": [{"volid": "local:snippets/app"}]}, "tls_verified": True}
            elif "status/current" in url:
                return {"status_code": 200, "body": {"data": {"status": "running", "uptime": 100}}, "tls_verified": True}
            elif "/config" in url and method == "POST":
                return {"status_code": 200, "body": {"data": "UPID:apply:task"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "OK"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", digest, "p", "r")
        assert result["deploy_status"] == "accepted"
        assert result["apply_status"] == "applied"
        assert result["promoted_artifact_digest"] == digest
        assert result["activated_artifact_digest"] == digest
        assert result["service_pre_state"] == "running"
        assert result["service_post_state"] == "running"
        assert result["activation_verified"] is True
        assert "apply_started_at" in result
        assert "apply_finished_at" in result


class TestApplyPromotedArtifactMissing:
    """AC5: Promoted artifact missing."""

    def test_no_digest_provided(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["apply_artifact"], allowed_api_actions=["apply_artifact"],
            require_promoted_artifact=True,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        result = adapter.deploy("t", "", "p", "r")  # no digest
        assert result["deploy_status"] == "rejected"
        assert result["failure_mode"] == "promoted_artifact_missing"

    def test_artifact_not_in_storage(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["apply_artifact"], allowed_api_actions=["apply_artifact"],
            require_promoted_artifact=True,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        monkeypatch.setattr(adapter, "_api_request", lambda *a, **k: {
            "status_code": 500, "body": {}, "tls_verified": True,
        })
        result = adapter.deploy("t", "some_digest", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["failure_mode"] == "promoted_artifact_missing"


class TestApplyFailed:
    """AC5: Apply action fails (API error)."""

    def test_apply_api_error(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["apply_artifact"], allowed_api_actions=["apply_artifact"],
            expected_service_state="running",
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        def mock_api(url, headers, timeout=30, method="GET"):
            if "storage/local/content" in url:
                return {"status_code": 200, "body": {"data": [{"volid": "local:app"}]}, "tls_verified": True}
            elif "status/current" in url:
                return {"status_code": 200, "body": {"data": {"status": "running"}}, "tls_verified": True}
            elif "/config" in url and method == "POST":
                return {"status_code": 500, "body": {"errors": "apply failed"}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api)
        result = adapter.deploy("t", "d", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["failure_mode"] == "apply_failed"
        assert "apply_started_at" in result


class TestApplyTaskFailure:
    """AC5: Apply task fails (UPID task error)."""

    def test_apply_task_error(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["apply_artifact"], allowed_api_actions=["apply_artifact"],
            expected_service_state="running",
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        def mock_api(url, headers, timeout=30, method="GET"):
            if "storage/local/content" in url:
                return {"status_code": 200, "body": {"data": [{"volid": "local:app"}]}, "tls_verified": True}
            elif "status/current" in url:
                return {"status_code": 200, "body": {"data": {"status": "running"}}, "tls_verified": True}
            elif "/config" in url and method == "POST":
                return {"status_code": 200, "body": {"data": "UPID:apply:task"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "ERROR: failed"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", "d", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["failure_mode"] == "apply_failed"


class TestApplyServiceStateMismatch:
    """AC5: Service state mismatch after apply."""

    def test_service_not_running(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["apply_artifact"], allowed_api_actions=["apply_artifact"],
            expected_service_state="running",
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        def mock_api(url, headers, timeout=30, method="GET"):
            if "storage/local/content" in url:
                return {"status_code": 200, "body": {"data": [{"volid": "local:app"}]}, "tls_verified": True}
            elif "status/current" in url:
                # Service is stopped, not running
                return {"status_code": 200, "body": {"data": {"status": "stopped"}}, "tls_verified": True}
            elif "/config" in url and method == "POST":
                return {"status_code": 200, "body": {"data": "UPID:apply"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "OK"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", "d", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["failure_mode"] == "service_state_mismatch"
        assert result["service_post_state"] == "stopped"
        assert result["activation_verified"] is False


class TestApplyReceiptFields:
    """AC4: Receipt records all apply evidence."""

    def test_receipt_has_apply_fields(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        digest = "feedface1234"
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["apply_artifact"], allowed_api_actions=["apply_artifact"],
            expected_service_state="running",
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        def mock_api(url, headers, timeout=30, method="GET"):
            if "storage/local/content" in url:
                return {"status_code": 200, "body": {"data": [{"volid": "local:app"}]}, "tls_verified": True}
            elif "status/current" in url:
                return {"status_code": 200, "body": {"data": {"status": "running", "uptime": 100}}, "tls_verified": True}
            elif "/config" in url and method == "POST":
                return {"status_code": 200, "body": {"data": "UPID:apply"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "OK"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", digest, "p", "r")
        for field in ["apply_started_at", "apply_finished_at", "apply_status",
                       "promoted_artifact_digest", "activated_artifact_digest",
                       "service_pre_state", "service_post_state", "activation_verified"]:
            assert field in result, f"Missing: {field}"
        assert result["promoted_artifact_digest"] == digest
        assert result["activated_artifact_digest"] == digest


class TestApplyTransportExplicit:
    """AC6: Transport is explicit."""

    def test_transport_api(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["apply_artifact"], allowed_api_actions=["apply_artifact"],
            expected_service_state="running",
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        def mock_api(url, headers, timeout=30, method="GET"):
            if "storage/local/content" in url:
                return {"status_code": 200, "body": {"data": [{"volid": "local:app"}]}, "tls_verified": True}
            elif "status/current" in url:
                return {"status_code": 200, "body": {"data": {"status": "running"}}, "tls_verified": True}
            elif "/config" in url and method == "POST":
                return {"status_code": 200, "body": {"data": "OK"}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api)
        result = adapter.deploy("t", "d", "p", "r")
        assert result["proxmox_command_shape"] == "api"
        assert result["shell_used"] is False
