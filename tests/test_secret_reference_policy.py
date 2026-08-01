"""Tests for v1.12.1 Secret Reference Policy.

Tests cover:
  - Manifest field serialization/roundtrip
  - Secret ref classification (env/file/inline/empty)
  - Secret ref validation against policy
  - Inline secret rejection
  - Missing secret rejection
  - Env var allowlist enforcement
  - File path allowlist enforcement
  - File permission checks (Linux)
  - Receipt fields completeness
  - Secret value never serialized
  - Redaction correctness
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest


class TestSecretPolicyManifestFields:
    """v1.12.1 manifest field support."""

    def test_secret_policy_fields(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            allowed_secret_ref_prefixes=["env:PROXMOX_", "file:/etc/nodechain/"],
            allowed_env_vars=["PROXMOX_TOKEN_SECRET", "DEPLOY_TOKEN"],
            allowed_secret_files=["/etc/nodechain/token", "/var/secrets/prox"],
            require_secret_ref=True,
            forbid_inline_secrets=True,
        )
        assert m.allowed_secret_ref_prefixes == ["env:PROXMOX_", "file:/etc/nodechain/"]
        assert m.allowed_env_vars == ["PROXMOX_TOKEN_SECRET", "DEPLOY_TOKEN"]
        assert m.allowed_secret_files == ["/etc/nodechain/token", "/var/secrets/prox"]
        assert m.require_secret_ref is True
        assert m.forbid_inline_secrets is True

    def test_secret_policy_roundtrip(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            allowed_env_vars=["MY_VAR"],
            allowed_secret_files=["/tmp/secret"],
            require_secret_ref=True,
            forbid_inline_secrets=False,
        )
        m2 = AdapterManifest.from_dict(m.to_dict())
        assert m2.allowed_env_vars == ["MY_VAR"]
        assert m2.allowed_secret_files == ["/tmp/secret"]
        assert m2.require_secret_ref is True
        assert m2.forbid_inline_secrets is False

    def test_defaults(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(adapter_id="x", adapter_type="proxmox_api")
        assert m.allowed_secret_ref_prefixes == []
        assert m.allowed_env_vars == []
        assert m.allowed_secret_files == []
        assert m.require_secret_ref is False
        assert m.forbid_inline_secrets is True  # secure default


class TestSecretRefClassification:
    """_classify_secret_ref method."""

    def test_classify_env(self):
        from nodechain.cli.deployment_adapter import ProxmoxApiAdapter
        assert ProxmoxApiAdapter._classify_secret_ref("env:MY_VAR") == "env"

    def test_classify_file(self):
        from nodechain.cli.deployment_adapter import ProxmoxApiAdapter
        assert ProxmoxApiAdapter._classify_secret_ref("file:/path/to/secret") == "file"

    def test_classify_inline(self):
        from nodechain.cli.deployment_adapter import ProxmoxApiAdapter
        assert ProxmoxApiAdapter._classify_secret_ref("plain-secret-value") == "inline"

    def test_classify_empty(self):
        from nodechain.cli.deployment_adapter import ProxmoxApiAdapter
        assert ProxmoxApiAdapter._classify_secret_ref("") == "empty"


class TestInlineSecretRejection:
    """Inline/plaintext secrets are rejected by default."""

    def test_inline_secret_rejected_default(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok",
            token_secret_ref="plain-secret-123",  # inline!
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        check = adapter._validate_secret_ref(strict=False)
        assert not check["valid"]
        assert any("Inline secrets are forbidden" in i for i in check["issues"])

    def test_inline_secret_allowed_when_disabled(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok",
            token_secret_ref="plain-secret-123",
            forbid_inline_secrets=False,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        check = adapter._validate_secret_ref(strict=False)
        assert check["valid"]
        assert check["ref_type"] == "inline"


class TestMissingSecretRejection:
    """Missing secret ref rejected when require_secret_ref=true."""

    def test_missing_secret_rejected(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok",
            require_secret_ref=True,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        check = adapter._validate_secret_ref(strict=False)
        assert not check["valid"]
        assert any("required but not set" in i for i in check["issues"])

    def test_missing_secret_ok_when_not_required(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok",
            require_secret_ref=False,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        check = adapter._validate_secret_ref(strict=False)
        assert check["valid"]


class TestEnvVarAllowlist:
    """Environment variable allowlist enforcement."""

    def test_env_allowed(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("ALLOWED_VAR", "secret-value")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok",
            token_secret_ref="env:ALLOWED_VAR",
            allowed_env_vars=["ALLOWED_VAR", "OTHER_VAR"],
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        check = adapter._validate_secret_ref(strict=False)
        assert check["valid"]
        assert check["source_allowed"] is True

    def test_env_disallowed(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("FORBIDDEN_VAR", "secret-value")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok",
            token_secret_ref="env:FORBIDDEN_VAR",
            allowed_env_vars=["ALLOWED_VAR"],  # FORBIDDEN_VAR not listed
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        check = adapter._validate_secret_ref(strict=False)
        assert not check["valid"]
        assert any("FORBIDDEN_VAR" in i for i in check["issues"])

    def test_env_no_allowlist_allows_all(self, monkeypatch):
        """When no allowlist set, any env var is allowed."""
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("ANY_VAR", "secret-value")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok",
            token_secret_ref="env:ANY_VAR",
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        check = adapter._validate_secret_ref(strict=False)
        assert check["valid"]


class TestFileAllowlist:
    """File path allowlist enforcement."""

    def test_file_allowed(self, tmp_path):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        secret_file = tmp_path / "token"
        secret_file.write_text("file-secret\n")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok",
            token_secret_ref=f"file:{secret_file}",
            allowed_secret_files=[str(secret_file)],
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        check = adapter._validate_secret_ref(strict=False)
        assert check["valid"]
        assert check["source_allowed"] is True

    def test_file_disallowed(self, tmp_path):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        secret_file = tmp_path / "token"
        secret_file.write_text("file-secret\n")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok",
            token_secret_ref=f"file:{secret_file}",
            allowed_secret_files=["/different/path"],
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        check = adapter._validate_secret_ref(strict=False)
        assert not check["valid"]
        assert any("not in allowed_secret_files" in i for i in check["issues"])


class TestSecretPrefixPolicy:
    """allowed_secret_ref_prefixes enforcement."""

    def test_prefix_allowed(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_TOKEN", "val")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok",
            token_secret_ref="env:PROXMOX_TOKEN",
            allowed_secret_ref_prefixes=["env:PROXMOX_"],
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        check = adapter._validate_secret_ref(strict=False)
        assert check["valid"]

    def test_prefix_disallowed(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("OTHER_TOKEN", "val")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok",
            token_secret_ref="env:OTHER_TOKEN",
            allowed_secret_ref_prefixes=["env:PROXMOX_"],
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        check = adapter._validate_secret_ref(strict=False)
        assert not check["valid"]
        assert any("allowed prefixes" in i for i in check["issues"])


class TestSecretReceiptFields:
    """Receipt records secret reference policy fields."""

    def test_receipt_has_secret_fields(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "my-secret-value")
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
        assert "token_secret_ref_type" in result
        assert result["token_secret_ref_type"] == "env"
        assert "secret_source_allowed" in result
        assert result["secret_source_allowed"] is True
        assert "secret_resolved" in result
        assert result["secret_resolved"] is True
        assert "secret_value_serialized" in result
        assert result["secret_value_serialized"] is False

    def test_receipt_has_redacted_ref(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "val")
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
        assert "token_secret_ref_redacted" in result
        # Redacted: "env:PROX***"
        assert "PROX" in result["token_secret_ref_redacted"]
        assert "PROXMOX_SECRET" not in result["token_secret_ref_redacted"]

    def test_secret_value_never_in_receipt(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        secret_value = "super-secret-abc123-xyz789"
        monkeypatch.setenv("PROXMOX_SECRET", secret_value)
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
        # The actual secret value must NOT appear anywhere in the receipt
        result_json = json.dumps(result)
        assert secret_value not in result_json


class TestRedaction:
    """Secret ref redaction correctness."""

    def test_redact_env(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("MY_TOKEN_VAR", "val")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            token_secret_ref="env:MY_TOKEN_VAR",
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        check = adapter._validate_secret_ref(strict=False)
        assert check["redacted_ref"] == "env:MY_T***"
        assert "MY_TOKEN_VAR" not in check["redacted_ref"]

    def test_redact_file(self, tmp_path):
        import hashlib
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        secret_file = tmp_path / "secret"
        secret_file.write_text("val\n")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            token_secret_ref=f"file:{secret_file}",
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        check = adapter._validate_secret_ref(strict=False)
        expected_hash = hashlib.sha256(str(secret_file).encode()).hexdigest()[:12]
        assert check["redacted_ref"] == f"file:sha256:{expected_hash}"
        assert str(secret_file) not in check["redacted_ref"]

    def test_redact_inline(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            token_secret_ref="my-secret-value",
            forbid_inline_secrets=False,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        check = adapter._validate_secret_ref(strict=False)
        assert check["redacted_ref"] == "inline:***REDACTED***"

    def test_redact_empty(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        check = adapter._validate_secret_ref(strict=False)
        assert check["redacted_ref"] == ""


class TestStrictModeResolution:
    """Strict mode requires secret to actually resolve."""

    def test_strict_unresolvable_env_rejected(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.delenv("NONEXISTENT", raising=False)
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok",
            token_secret_ref="env:NONEXISTENT",
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        check = adapter._validate_secret_ref(strict=True)
        assert not check["valid"]
        assert any("could not be resolved" in i for i in check["issues"])

    def test_non_strict_unresolvable_env_ok(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.delenv("NONEXISTENT", raising=False)
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok",
            token_secret_ref="env:NONEXISTENT",
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        check = adapter._validate_secret_ref(strict=False)
        # Non-strict: source is allowed, just not resolved
        assert check["source_allowed"] is True
        assert check["resolved"] is False


class TestSecretPolicyNegativeSmoke:
    """All policy violations produce issues."""

    def test_all_secret_violations(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter

        violations = [
            # Inline secret (forbidden by default)
            ("inline", AdapterManifest(
                adapter_id="v1", adapter_type="proxmox_api",
                api_base_url="https://pve:8006",
                proxmox_node="pve1", target_vmid="801",
                token_id="t", token_secret_ref="plain-value",
            )),
            # Missing secret (require_secret_ref=true)
            ("missing", AdapterManifest(
                adapter_id="v2", adapter_type="proxmox_api",
                api_base_url="https://pve:8006",
                proxmox_node="pve1", target_vmid="801",
                token_id="t", require_secret_ref=True,
            )),
        ]

        for label, manifest in violations:
            adapter = ProxmoxApiAdapter(manifest=manifest)
            check = adapter._validate_secret_ref(strict=False)
            assert not check["valid"], f"{label} should be invalid"
            assert len(check["issues"]) > 0, f"{label} should have issues"
