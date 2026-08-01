"""Tests for v1.12.2 Proxmox API Task Actions.

Tests cover:
  - start action registration in PROXMOX_API_ACTIONS
  - Manifest field serialization
  - _build_api_url for start action (POST endpoint)
  - _api_request POST method support
  - Pre-state verification
  - UPID extraction from response
  - Post-state verification
  - State transition verification
  - Receipt field completeness
  - allowed_api_actions enforcement
  - Pre-state mismatch rejection
  - Task failure rejection
  - Secret policy still enforced during mutations
  - Read-only actions still work unchanged
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


class TestStartActionRegistration:
    """start action is in PROXMOX_API_ACTIONS."""

    def test_start_in_api_actions(self):
        from nodechain.cli.deployment_adapter import PROXMOX_API_ACTIONS
        assert "start" in PROXMOX_API_ACTIONS

    def test_action_ordering(self):
        from nodechain.cli.deployment_adapter import PROXMOX_API_ACTIONS
        assert sorted(PROXMOX_API_ACTIONS) == ["apply_artifact", "get_status", "promote_artifact", "reboot", "rollback_artifact", "start", "stop", "upload_artifact", "validate_target"]


class TestTaskActionManifestFields:
    """v1.12.2 manifest field support."""

    def test_task_fields(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            allowed_api_actions=["start"],
            require_confirmed_target_status=True,
            expected_pre_state="stopped",
            expected_post_state="running",
            task_timeout_seconds=60,
        )
        assert m.allowed_api_actions == ["start"]
        assert m.require_confirmed_target_status is True
        assert m.expected_pre_state == "stopped"
        assert m.expected_post_state == "running"
        assert m.task_timeout_seconds == 60

    def test_task_fields_roundtrip(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            allowed_api_actions=["start", "get_status"],
            require_confirmed_target_status=True,
            expected_pre_state="stopped",
            expected_post_state="running",
            task_timeout_seconds=180,
        )
        m2 = AdapterManifest.from_dict(m.to_dict())
        assert m2.allowed_api_actions == ["start", "get_status"]
        assert m2.require_confirmed_target_status is True
        assert m2.expected_pre_state == "stopped"
        assert m2.expected_post_state == "running"
        assert m2.task_timeout_seconds == 180

    def test_defaults(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(adapter_id="x", adapter_type="proxmox_api")
        assert m.allowed_api_actions == []
        assert m.require_confirmed_target_status is False
        assert m.expected_pre_state == ""
        assert m.expected_post_state == ""
        assert m.task_timeout_seconds == 120


class TestStartActionUrl:
    """_build_api_url for start action."""

    def test_start_url(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        url = adapter._build_api_url("start")
        assert "status/start" in url
        assert "pve1" in url
        assert "801" in url


class TestAllowedApiActionsEnforcement:
    """allowed_api_actions restricts which actions are permitted."""

    def test_action_outside_allowed_api_actions(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:S",
            allowed_actions=["get_status"],
            allowed_api_actions=["start"],  # get_status not in this list
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        issues = adapter._validate_api_manifest()
        assert any("get_status" in i and "allowed_api_actions" in i for i in issues)

    def test_action_in_allowed_api_actions(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:S",
            allowed_actions=["start"],
            allowed_api_actions=["start", "get_status"],
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        issues = adapter._validate_api_manifest()
        assert not any("allowed_api_actions" in i for i in issues)


class TestStartActionExecution:
    """deploy() with start action handles UPID and state verification."""

    def test_start_success(self, monkeypatch):
        """Successful start: pre=stopped → POST → UPID → post=running."""
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "test-secret")

        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="deploy@pam!tok",
            token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["start"],
            allowed_api_actions=["start"],
            require_confirmed_target_status=True,
            expected_pre_state="stopped",
            expected_post_state="running",
            task_timeout_seconds=30,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        call_count = [0]
        def mock_api_request(url, headers, timeout=30, method="GET"):
            call_count[0] += 1
            if "status/current" in url:
                # GET status: first call=stopped, second call=running
                if call_count[0] == 1:
                    return {"status_code": 200, "body": {"data": {"status": "stopped"}}, "tls_verified": True}
                else:
                    return {"status_code": 200, "body": {"data": {"status": "running"}}, "tls_verified": True}
            elif "status/start" in url:
                return {"status_code": 200, "body": {"data": "UPID:pve:00123456:abc:def:deploy@pam:"}, "tls_verified": True}
            elif "/tasks/" in url:
                # Task polling endpoint
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "OK"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        monkeypatch.setattr("time.sleep", lambda x: None)  # skip sleep

        result = adapter.deploy("target", "artifact", "policy", "receipt-id")
        assert result["deploy_status"] == "accepted"
        assert "UPID:" in result["proxmox_task_upid"]
        assert result["pre_state"] == "stopped"
        assert result["post_state"] == "running"
        assert result["state_transition_verified"] is True
        assert result["task_exitstatus"] == "OK"

    def test_start_pre_state_mismatch(self, monkeypatch):
        """Pre-state mismatch rejects the mutation."""
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")

        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["start"], allowed_api_actions=["start"],
            require_confirmed_target_status=True,
            expected_pre_state="stopped",
            expected_post_state="running",
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        def mock_api_request(url, headers, timeout=30, method="GET"):
            if "status/current" in url:
                return {"status_code": 200, "body": {"data": {"status": "running"}}, "tls_verified": True}
            return {"status_code": 200, "body": {"data": {}}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        result = adapter.deploy("target", "artifact", "policy", "receipt-id")
        assert result["deploy_status"] == "rejected"
        assert "Pre-state mismatch" in result["deploy_detail"]
        assert result["pre_state"] == "running"
        assert result["state_transition_verified"] is False

    def test_start_no_upid_rejected(self, monkeypatch):
        """POST returns no UPID → rejected."""
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")

        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["start"], allowed_api_actions=["start"],
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        call_count = [0]
        def mock_api_request(url, headers, timeout=30, method="GET"):
            call_count[0] += 1
            if "status/current" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped"}}, "tls_verified": True}
            elif "status/start" in url:
                return {"status_code": 500, "body": {"errors": "failed"}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("target", "artifact", "policy", "receipt-id")
        assert result["deploy_status"] == "rejected"
        assert result["proxmox_task_upid"] == ""
        assert result["task_exitstatus"] == "FAILED"

    def test_start_post_state_mismatch(self, monkeypatch):
        """POST succeeds, task succeeds, but post-state doesn't match → rejected.

        v1.12.3: task_success=true but state_transition_verified=false →
        overall rejected when expected_post_state is set.
        """
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")

        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["start"], allowed_api_actions=["start"],
            expected_post_state="running",
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        call_count = [0]
        def mock_api_request(url, headers, timeout=30, method="GET"):
            call_count[0] += 1
            if "status/current" in url:
                # Both pre and post return 'stopped' — start didn't change it
                return {"status_code": 200, "body": {"data": {"status": "stopped"}}, "tls_verified": True}
            elif "status/start" in url:
                return {"status_code": 200, "body": {"data": "UPID:pve:00123456:abc:def:deploy@pam:"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "OK"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("target", "artifact", "policy", "receipt-id")
        # v1.12.3: task itself succeeded (OK exitstatus)
        assert result["task_success"] is True
        # But state transition didn't verify → overall rejected
        assert result["state_transition_verified"] is False
        assert result["deploy_status"] == "rejected"


class TestTaskReceiptFields:
    """Receipt records all task fields."""

    def test_receipt_has_task_fields(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")

        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["start"], allowed_api_actions=["start"],
            expected_post_state="running",
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        call_count = [0]
        def mock_api_request(url, headers, timeout=30, method="GET"):
            call_count[0] += 1
            if "status/current" in url:
                if call_count[0] == 1:
                    return {"status_code": 200, "body": {"data": {"status": "stopped"}}, "tls_verified": True}
                return {"status_code": 200, "body": {"data": {"status": "running"}}, "tls_verified": True}
            elif "status/start" in url:
                return {"status_code": 200, "body": {"data": "UPID:test:task"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "OK"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", "a", "p", "r")

        for field in [
            "proxmox_task_upid", "task_started_at", "task_finished_at",
            "task_exitstatus", "pre_state", "post_state", "state_transition_verified",
        ]:
            assert field in result, f"Missing field: {field}"


class TestSecretPolicyStillEnforced:
    """Secret reference policy is still enforced during mutations."""

    def test_mutation_has_secret_fields(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")

        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["start"], allowed_api_actions=["start"],
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        call_count = [0]
        def mock_api_request(url, headers, timeout=30, method="GET"):
            call_count[0] += 1
            if "status/current" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped"}}, "tls_verified": True}
            elif "status/start" in url:
                return {"status_code": 200, "body": {"data": "UPID:test"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "OK"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", "a", "p", "r")
        assert "token_secret_ref_type" in result
        assert result["token_secret_ref_type"] == "env"
        assert result["secret_value_serialized"] is False

    def test_inline_secret_blocked_during_mutation(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="plain-inline-secret",
            allowed_actions=["start"], allowed_api_actions=["start"],
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        result = adapter.deploy("t", "a", "p", "r")
        # Should be rejected because inline secret is forbidden by default
        assert result["deploy_status"] == "rejected"


class TestReadOnlyActionsUnchanged:
    """Read-only actions still work without task fields."""

    def test_validate_target_no_task_fields(self, monkeypatch):
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
        assert result["deploy_status"] == "accepted"
        # Read-only actions should NOT have task fields
        assert "proxmox_task_upid" not in result
        assert "task_started_at" not in result
        assert "state_transition_verified" not in result


class TestStartWithoutPreStateCheck:
    """start without require_confirmed_target_status skips pre-state verification."""

    def test_start_no_pre_state_check(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["start"], allowed_api_actions=["start"],
            # No require_confirmed_target_status
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        call_count = [0]
        def mock_api_request(url, headers, timeout=30, method="GET"):
            call_count[0] += 1
            if "status/current" in url:
                if call_count[0] == 1:
                    return {"status_code": 200, "body": {"data": {"status": "unknown"}}, "tls_verified": True}
                return {"status_code": 200, "body": {"data": {"status": "unknown"}}, "tls_verified": True}
            elif "status/start" in url:
                return {"status_code": 200, "body": {"data": "UPID:test"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "OK"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", "a", "p", "r")
        # Should succeed even with 'unknown' pre-state since no check required
        assert result["deploy_status"] == "accepted"
        # With no expected_post_state set, transition is considered verified
        assert result["state_transition_verified"] is True
