"""Tests for v1.12.0 Proxmox API adapter.

Tests cover:
  - Manifest field serialization
  - API adapter construction
  - Token resolution (env/file/inline)
  - Manifest validation (strict and non-strict)
  - API request construction (URL, headers)
  - Deploy execution with mocked API responses
  - Receipt field completeness
  - Strict-mode enforcement
  - Secret safety (no secrets in receipts)
  - Shared receipt model (SSH/API compatibility)
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest


class TestProxmoxApiManifestFields:
    """v1.12.0 manifest field support."""

    def test_api_manifest_fields(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="px-api-1", adapter_type="proxmox_api",
            api_base_url="https://pve.example.com:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="deploy@pam!cicd",
            token_secret_ref="env:PROXMOX_TOKEN_SECRET",
            verify_tls=True,
            ca_bundle_path="/etc/ssl/certs/pve-ca.pem",
            allow_insecure_tls=False,
        )
        assert m.api_base_url == "https://pve.example.com:8006/api2/json"
        assert m.token_id == "deploy@pam!cicd"
        assert m.token_secret_ref == "env:PROXMOX_TOKEN_SECRET"
        assert m.verify_tls is True
        assert m.ca_bundle_path == "/etc/ssl/certs/pve-ca.pem"
        assert m.allow_insecure_tls is False

    def test_api_manifest_roundtrip(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="px-api-1", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok",
            token_secret_ref="env:SECRET",
            verify_tls=False,
            allow_insecure_tls=True,
        )
        m2 = AdapterManifest.from_dict(m.to_dict())
        assert m2.api_base_url == m.api_base_url
        assert m2.token_id == m.token_id
        assert m2.token_secret_ref == m.token_secret_ref
        assert m2.verify_tls is False
        assert m2.allow_insecure_tls is True

    def test_api_fields_default_values(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
        )
        assert m.api_base_url == ""
        assert m.token_id == ""
        assert m.token_secret_ref == ""
        assert m.verify_tls is True
        assert m.ca_bundle_path == ""
        assert m.allow_insecure_tls is False


class TestProxmoxApiActionAllowlist:
    """PROXMOX_API_ACTIONS constant."""

    def test_valid_actions(self):
        from nodechain.cli.deployment_adapter import PROXMOX_API_ACTIONS
        assert "validate_target" in PROXMOX_API_ACTIONS
        assert "get_status" in PROXMOX_API_ACTIONS

    def test_ssh_actions_not_in_api(self):
        """SSH-only actions should not be valid API actions."""
        from nodechain.cli.deployment_adapter import PROXMOX_API_ACTIONS, PROXMOX_ACTIONS
        assert "execute_deploy" not in PROXMOX_API_ACTIONS
        assert "execute_deploy" not in PROXMOX_API_ACTIONS
        # API has start (v1.12.2) but not upload_artifact/execute_deploy
        assert "start" in PROXMOX_API_ACTIONS
        # SSH has upload/deploy that API doesn't
        assert len(PROXMOX_ACTIONS - PROXMOX_API_ACTIONS) > 0


class TestTokenResolution:
    """Token secret resolution from env/file/inline."""

    def test_resolve_env_token(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("MY_SECRET", "secret-value-123")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok",
            token_secret_ref="env:MY_SECRET",
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        assert adapter._resolve_token_secret() == "secret-value-123"

    def test_resolve_file_token(self, tmp_path):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        secret_file = tmp_path / "secret.txt"
        secret_file.write_text("file-secret-456\n")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok",
            token_secret_ref=f"file:{secret_file}",
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        assert adapter._resolve_token_secret() == "file-secret-456"

    def test_resolve_inline_token(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok",
            token_secret_ref="plain-secret-789",
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        assert adapter._resolve_token_secret() == "plain-secret-789"

    def test_resolve_missing_env_token(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.delenv("NONEXISTENT_SECRET", raising=False)
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            token_secret_ref="env:NONEXISTENT_SECRET",
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        assert adapter._resolve_token_secret() == ""

    def test_resolve_token_id_from_manifest(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            token_id="manifest-token-id",
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        assert adapter._resolve_token_id() == "manifest-token-id"

    def test_resolve_token_id_from_env(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("NODECHAIN_PROXMOX_TOKEN_ID", "env-token-id")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            # token_id not set in manifest
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        assert adapter._resolve_token_id() == "env-token-id"


class TestApiManifestValidation:
    """Manifest validation for API adapter."""

    def test_missing_api_base_url(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            proxmox_node="pve1", target_vmid="801",
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        issues = adapter._validate_api_manifest()
        assert any("api_base_url" in i for i in issues)

    def test_missing_proxmox_node(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            target_vmid="801",
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        issues = adapter._validate_api_manifest()
        assert any("proxmox_node" in i for i in issues)

    def test_missing_vmid(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1",
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        issues = adapter._validate_api_manifest()
        assert any("target_vmid" in i for i in issues)

    def test_missing_token_id(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_secret_ref="env:SECRET",
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        issues = adapter._validate_api_manifest()
        assert any("token_id" in i for i in issues)

    def test_missing_token_secret(self):
        """v1.12.1: Missing token_secret_ref is OK unless require_secret_ref."""
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok",
            # No token_secret_ref, no require_secret_ref
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        issues = adapter._validate_api_manifest()
        # Without require_secret_ref, missing secret is not an error
        assert not any("token_secret_ref" in i for i in issues)
        
        # But with require_secret_ref, it IS an error
        m2 = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok",
            require_secret_ref=True,
        )
        adapter2 = ProxmoxApiAdapter(manifest=m2)
        issues2 = adapter2._validate_api_manifest()
        assert any("required but not set" in i for i in issues2)

    def test_unknown_action_rejected(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:S",
            allowed_actions=["destroy_all"],
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        issues = adapter._validate_api_manifest()
        assert any("Unknown API actions" in i for i in issues)

    def test_vmid_outside_allowlist(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="999",
            token_id="t@pam!tok", token_secret_ref="env:S",
            allowed_vmid_list=["801", "802"],
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        issues = adapter._validate_api_manifest()
        assert any("999" in i and "allowed_vmid_list" in i for i in issues)

    def test_node_outside_allowlist(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="evil", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:S",
            allowed_node_list=["pve1", "pve2"],
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        issues = adapter._validate_api_manifest()
        assert any("evil" in i and "allowed_node_list" in i for i in issues)


class TestApiStrictMode:
    """Strict mode enforcement for API adapter."""

    def test_insecure_tls_rejected_strict(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:S",
            verify_tls=False,
            allow_insecure_tls=False,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        issues = adapter._validate_api_manifest(strict=True)
        assert any("TLS verification is disabled" in i for i in issues)

    def test_insecure_tls_allowed_with_flag(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:S",
            verify_tls=False,
            allow_insecure_tls=True,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        issues = adapter._validate_api_manifest(strict=True)
        assert not any("TLS verification is disabled" in i for i in issues)

    def test_tls_verified_by_default(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:S",
            verify_tls=True,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        issues = adapter._validate_api_manifest(strict=True)
        assert not any("TLS" in i for i in issues)


class TestApiRequestConstruction:
    """URL and header building for API requests."""

    def test_build_api_url_validate_target(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        url = adapter._build_api_url("validate_target")
        assert "pve1" in url
        assert "801" in url
        assert "status/current" in url

    def test_build_api_url_get_status(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        url = adapter._build_api_url("get_status")
        assert "pve1" in url
        assert "801" in url

    def test_build_api_headers(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        headers = adapter._build_api_headers("deploy@pam!cicd", "secret-uuid")
        assert headers["Authorization"] == "PVEAPIToken=deploy@pam!cicd=secret-uuid"
        assert headers["Content-Type"] == "application/json"


class TestApiDeployExecution:
    """Deploy method with mocked API responses."""

    def test_deploy_missing_manifest_rejected(self):
        from nodechain.cli.deployment_adapter import ProxmoxApiAdapter
        adapter = ProxmoxApiAdapter(manifest=None)
        result = adapter.deploy("target", "artifact", "policy", "receipt-id")
        assert result["deploy_status"] == "rejected"

    def test_deploy_validation_failure_rejected(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            # Missing all required fields
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        result = adapter.deploy("target", "artifact", "policy", "receipt-id")
        assert result["deploy_status"] == "rejected"
        assert "Manifest validation failed" in result["deploy_detail"]

    def test_deploy_success_mocked(self, monkeypatch):
        """Successful API call returns accepted receipt."""
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "test-secret")

        m = AdapterManifest(
            adapter_id="px-api-1", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="deploy@pam!cicd",
            token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["validate_target"],
            verify_tls=True,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        # Mock the API request
        def mock_request(url, headers, timeout=30):
            return {
                "status_code": 200,
                "body": {"data": {"status": "running", "vmid": "801"}},
                "tls_verified": True,
            }

        monkeypatch.setattr(adapter, "_api_request", mock_request)
        result = adapter.deploy("target", "artifact", "policy", "receipt-id")
        assert result["deploy_status"] == "accepted"
        assert result["proxmox_node"] == "pve1"
        assert result["vmid"] == "801"
        assert result["action"] == "validate_target"

    def test_deploy_api_failure_rejected(self, monkeypatch):
        """Non-success API response returns rejected receipt."""
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "test-secret")

        m = AdapterManifest(
            adapter_id="px-api-1", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="deploy@pam!cicd",
            token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["get_status"],
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        def mock_request(url, headers, timeout=30):
            return {
                "status_code": 500,
                "body": {"errors": "Internal error"},
                "tls_verified": True,
            }

        monkeypatch.setattr(adapter, "_api_request", mock_request)
        result = adapter.deploy("target", "artifact", "policy", "receipt-id")
        assert result["deploy_status"] == "rejected"
        assert result["response_status_code"] == 500


class TestApiReceiptFields:
    """Receipt field completeness for API adapter."""

    def test_receipt_has_api_shape(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["validate_target"],
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        monkeypatch.setattr(adapter, "_api_request", lambda *a, **k: {
            "status_code": 200, "body": {"data": {}}, "tls_verified": True
        })
        result = adapter.deploy("t", "a", "p", "r")
        assert result["proxmox_command_shape"] == "api"

    def test_receipt_has_tls_verified(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["validate_target"],
            verify_tls=True,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        monkeypatch.setattr(adapter, "_api_request", lambda *a, **k: {
            "status_code": 200, "body": {"data": {}}, "tls_verified": True
        })
        result = adapter.deploy("t", "a", "p", "r")
        assert result["tls_verified"] is True

    def test_receipt_has_response_status_code(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["validate_target"],
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        monkeypatch.setattr(adapter, "_api_request", lambda *a, **k: {
            "status_code": 200, "body": {"data": {}}, "tls_verified": True
        })
        result = adapter.deploy("t", "a", "p", "r")
        assert result["response_status_code"] == 200

    def test_receipt_has_api_endpoint_identity(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["validate_target"],
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        monkeypatch.setattr(adapter, "_api_request", lambda *a, **k: {
            "status_code": 200, "body": {"data": {}}, "tls_verified": True
        })
        result = adapter.deploy("t", "a", "p", "r")
        assert "api_endpoint_identity" in result
        assert "pve1" in result["api_endpoint_identity"]

    def test_receipt_shell_used_false(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["validate_target"],
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        monkeypatch.setattr(adapter, "_api_request", lambda *a, **k: {
            "status_code": 200, "body": {"data": {}}, "tls_verified": True
        })
        result = adapter.deploy("t", "a", "p", "r")
        assert result["shell_used"] is False


class TestSecretSafety:
    """Secrets never appear in receipts."""

    def test_no_token_secret_in_receipt(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "super-secret-value-123")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="deploy@pam!cicd",
            token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["validate_target"],
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        monkeypatch.setattr(adapter, "_api_request", lambda *a, **k: {
            "status_code": 200, "body": {"data": {}}, "tls_verified": True
        })
        result = adapter.deploy("t", "a", "p", "r")
        # The secret value must NOT appear anywhere in the receipt
        result_str = json.dumps(result)
        assert "super-secret-value-123" not in result_str

    def test_no_token_secret_in_manifest_to_dict(self):
        """Manifest to_dict should not contain the resolved secret value."""
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="deploy@pam!cicd",
            token_secret_ref="env:PROXMOX_SECRET",
        )
        d = m.to_dict()
        assert "token_secret_ref" in d  # the reference, not the value
        assert "PROXMOX_SECRET" in d["token_secret_ref"]  # env var name
        # No resolved secret value field
        assert "token_secret" not in d
        assert "token_secret_value" not in d


class TestSharedReceiptModel:
    """SSH and API adapters share the same receipt structure."""

    def test_both_adapters_produce_same_base_fields(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxAdapter, ProxmoxApiAdapter

        # SSH adapter
        ssh_manifest = AdapterManifest(
            adapter_id="ssh", adapter_type="proxmox",
            proxmox_node="pve1", target_vmid="801",
            allowed_actions=["upload_artifact"],
            execution_mode="argv", argv_template=["echo"],
            allow_root=True,
        )
        ssh_adapter = ProxmoxAdapter(manifest=ssh_manifest)
        ssh_result = ssh_adapter.deploy("t", "a", "p", "r")

        # API adapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        api_manifest = AdapterManifest(
            adapter_id="api", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["validate_target"],
        )
        api_adapter = ProxmoxApiAdapter(manifest=api_manifest)
        monkeypatch.setattr(api_adapter, "_api_request", lambda *a, **k: {
            "status_code": 200, "body": {"data": {}}, "tls_verified": True
        })
        api_result = api_adapter.deploy("t", "a", "p", "r")

        # Shared fields
        shared_fields = {
            "deploy_status", "deployer_identity", "deploy_detail",
            "deploy_started_at", "deploy_finished_at",
            "proxmox_node", "vmid", "action",
            "proxmox_command_shape", "shell_used",
        }
        for field in shared_fields:
            assert field in ssh_result, f"SSH adapter missing {field}"
            assert field in api_result, f"API adapter missing {field}"

        # Command shape distinguishes the path
        assert ssh_result["proxmox_command_shape"] == "ssh"
        assert api_result["proxmox_command_shape"] == "api"


class TestApiAdapterRegistry:
    """Adapter registration."""

    def test_proxmox_api_registered(self):
        from nodechain.cli.deployment_adapter import get_adapter, list_adapters
        adapters = list_adapters()
        assert "proxmox_api" in adapters

    def test_get_proxmox_api_adapter(self):
        from nodechain.cli.deployment_adapter import get_adapter, ProxmoxApiAdapter
        adapter = get_adapter("proxmox_api")
        assert isinstance(adapter, ProxmoxApiAdapter)

    def test_get_proxmox_api_adapter_dash(self):
        from nodechain.cli.deployment_adapter import get_adapter, ProxmoxApiAdapter
        adapter = get_adapter("proxmox-api")
        assert isinstance(adapter, ProxmoxApiAdapter)

    def test_system_name(self):
        from nodechain.cli.deployment_adapter import get_adapter
        adapter = get_adapter("proxmox_api")
        assert adapter.system_name == "proxmox_api"


class TestApiNegativeSmokes:
    """Negative smoke tests for API adapter."""

    def test_all_api_violations_produce_rejection(self):
        """Every API policy violation produces a rejected deploy_status."""
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter

        violations = [
            # Missing api_base_url
            AdapterManifest(
                adapter_id="v1", adapter_type="proxmox_api",
                proxmox_node="pve1", target_vmid="801",
                token_id="t", token_secret_ref="env:S",
            ),
            # Missing proxmox_node
            AdapterManifest(
                adapter_id="v2", adapter_type="proxmox_api",
                api_base_url="https://pve:8006",
                target_vmid="801",
                token_id="t", token_secret_ref="env:S",
            ),
            # Missing vmid
            AdapterManifest(
                adapter_id="v3", adapter_type="proxmox_api",
                api_base_url="https://pve:8006",
                proxmox_node="pve1",
                token_id="t", token_secret_ref="env:S",
            ),
            # Missing token_id
            AdapterManifest(
                adapter_id="v4", adapter_type="proxmox_api",
                api_base_url="https://pve:8006",
                proxmox_node="pve1", target_vmid="801",
                token_secret_ref="env:S",
            ),
            # Missing token_secret_ref with require_secret_ref=True
            AdapterManifest(
                adapter_id="v5", adapter_type="proxmox_api",
                api_base_url="https://pve:8006",
                proxmox_node="pve1", target_vmid="801",
                token_id="t",
                require_secret_ref=True,
            ),
            # Unknown action
            AdapterManifest(
                adapter_id="v6", adapter_type="proxmox_api",
                api_base_url="https://pve:8006",
                proxmox_node="pve1", target_vmid="801",
                token_id="t", token_secret_ref="env:S",
                allowed_actions=["destroy_all"],
            ),
            # VMID outside allowlist
            AdapterManifest(
                adapter_id="v7", adapter_type="proxmox_api",
                api_base_url="https://pve:8006",
                proxmox_node="pve1", target_vmid="999",
                token_id="t", token_secret_ref="env:S",
                allowed_vmid_list=["801"],
            ),
            # Node outside allowlist
            AdapterManifest(
                adapter_id="v8", adapter_type="proxmox_api",
                api_base_url="https://pve:8006",
                proxmox_node="evil", target_vmid="801",
                token_id="t", token_secret_ref="env:S",
                allowed_node_list=["pve1"],
            ),
        ]

        for manifest in violations:
            adapter = ProxmoxApiAdapter(manifest=manifest)
            result = adapter.deploy("target", "artifact", "policy", "receipt-id")
            assert result["deploy_status"] == "rejected", (
                f"Expected rejection for {manifest.adapter_id}, "
                f"got {result['deploy_status']}: {result['deploy_detail']}"
            )
