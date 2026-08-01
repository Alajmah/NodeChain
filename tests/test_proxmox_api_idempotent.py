"""Tests for v1.12.4 Proxmox API Idempotent Actions.

Tests cover:
  - stop action registration and URL building
  - Idempotency manifest fields
  - No-op detection when target already in desired state
  - allow_noop_if_already_desired behavior
  - idempotency_policy='reject_noop' behavior
  - stop success with state transition
  - stop already stopped with no-op allowed
  - stop already stopped with no-op rejected
  - Receipt field completeness
  - Pre-state mismatch rejection
  - Task failure
  - Timeout
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


class TestStopActionRegistration:
    """stop action is in PROXMOX_API_ACTIONS."""

    def test_stop_in_api_actions(self):
        from nodechain.cli.deployment_adapter import PROXMOX_API_ACTIONS
        assert "stop" in PROXMOX_API_ACTIONS

    def test_stop_url(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        url = adapter._build_api_url("stop")
        assert "status/stop" in url
        assert "pve1" in url
        assert "801" in url


class TestIdempotencyManifestFields:
    """v1.12.4 manifest field support."""

    def test_idempotency_fields(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            idempotency_policy="allow_noop",
            allow_noop_if_already_desired=True,
        )
        assert m.idempotency_policy == "allow_noop"
        assert m.allow_noop_if_already_desired is True

    def test_idempotency_roundtrip(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            idempotency_policy="allow_noop",
            allow_noop_if_already_desired=True,
        )
        m2 = AdapterManifest.from_dict(m.to_dict())
        assert m2.idempotency_policy == "allow_noop"
        assert m2.allow_noop_if_already_desired is True

    def test_defaults(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(adapter_id="x", adapter_type="proxmox_api")
        assert m.idempotency_policy == "reject_noop"
        assert m.allow_noop_if_already_desired is False


class TestStopSuccess:
    """stop action succeeds with state transition running → stopped."""

    def test_stop_success(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["stop"], allowed_api_actions=["stop"],
            expected_pre_state="running",
            expected_post_state="stopped",
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        call_count = [0]
        def mock_api_request(url, headers, timeout=30, method="GET"):
            call_count[0] += 1
            if "status/current" in url:
                if call_count[0] == 1:
                    return {"status_code": 200, "body": {"data": {"status": "running"}}, "tls_verified": True}
                return {"status_code": 200, "body": {"data": {"status": "stopped"}}, "tls_verified": True}
            elif "status/stop" in url:
                return {"status_code": 200, "body": {"data": "UPID:stop:task"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "OK"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", "a", "p", "r")
        assert result["deploy_status"] == "accepted"
        assert result["pre_state"] == "running"
        assert result["post_state"] == "stopped"
        assert result["state_transition_verified"] is True
        assert result["task_success"] is True
        assert result["no_op"] is False


class TestNoOpAllowed:
    """stop when already stopped with allow_noop → no-op accepted."""

    def test_stop_already_stopped_noop_allowed(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["stop"], allowed_api_actions=["stop"],
            expected_post_state="stopped",
            allow_noop_if_already_desired=True,
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        def mock_api_request(url, headers, timeout=30, method="GET"):
            if "status/current" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        result = adapter.deploy("t", "a", "p", "r")
        assert result["deploy_status"] == "accepted"
        assert result["no_op"] is True
        assert result["effective_action"] == "noop"
        assert result["requested_action"] == "stop"
        assert result["task_exitstatus"] == "NOOP"
        assert result["idempotency_policy"] == "reject_noop"  # default but allow flag overrides

    def test_stop_already_stopped_noop_via_policy(self, monkeypatch):
        """idempotency_policy='allow_noop' also enables no-op."""
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["stop"], allowed_api_actions=["stop"],
            expected_post_state="stopped",
            idempotency_policy="allow_noop",
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        def mock_api_request(url, headers, timeout=30, method="GET"):
            if "status/current" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        result = adapter.deploy("t", "a", "p", "r")
        assert result["deploy_status"] == "accepted"
        assert result["no_op"] is True
        assert result["idempotency_policy"] == "allow_noop"


class TestNoOpRejected:
    """stop when already stopped with reject_noop → proceeds to mutation."""

    def test_stop_already_stopped_reject_noop(self, monkeypatch):
        """With reject_noop, the adapter rejects before mutation.

        v1.18.2: reject_noop now rejects before executing unnecessary mutation
        rather than falling through to the POST.
        """
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["stop"], allowed_api_actions=["stop"],
            expected_post_state="stopped",
            idempotency_policy="reject_noop",
            allow_noop_if_already_desired=False,
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        def mock_api_request(url, headers, timeout=30, method="GET"):
            if "status/current" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        result = adapter.deploy("t", "a", "p", "r")
        # v1.18.2: Rejected before mutation — no POST was executed
        assert result["deploy_status"] == "rejected"
        assert result["effective_action"] == "rejected"
        assert result["task_exitstatus"] == "REJECTED_NOOP"
        assert result["no_op"] is False


class TestNoOpReceiptFields:
    """Receipt records idempotency fields."""

    def test_noop_receipt_has_idempotency_fields(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["stop"], allowed_api_actions=["stop"],
            expected_post_state="stopped",
            allow_noop_if_already_desired=True,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        def mock_api_request(url, headers, timeout=30, method="GET"):
            if "status/current" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        result = adapter.deploy("t", "a", "p", "r")
        for field in ["requested_action", "effective_action", "no_op", "idempotency_policy"]:
            assert field in result, f"Missing: {field}"

    def test_mutation_receipt_has_idempotency_fields(self, monkeypatch):
        """Non-no-op receipts also have idempotency fields."""
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["start"], allowed_api_actions=["start"],
            expected_pre_state="stopped",
            expected_post_state="running",
            task_poll_interval_seconds=0.01, task_max_polls=3,
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
                return {"status_code": 200, "body": {"data": "UPID:test"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "OK"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", "a", "p", "r")
        assert result["no_op"] is False
        assert result["requested_action"] == "start"
        assert result["effective_action"] == "start"


class TestStartNoOp:
    """start when already running with allow_noop → no-op."""

    def test_start_already_running_noop(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["start"], allowed_api_actions=["start"],
            expected_post_state="running",
            allow_noop_if_already_desired=True,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        def mock_api_request(url, headers, timeout=30, method="GET"):
            if "status/current" in url:
                return {"status_code": 200, "body": {"data": {"status": "running"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        result = adapter.deploy("t", "a", "p", "r")
        assert result["deploy_status"] == "accepted"
        assert result["no_op"] is True
        assert result["effective_action"] == "noop"


class TestStopFailure:
    """stop action failure scenarios."""

    def test_stop_task_failure(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["stop"], allowed_api_actions=["stop"],
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        call_count = [0]
        def mock_api_request(url, headers, timeout=30, method="GET"):
            call_count[0] += 1
            if "status/current" in url:
                return {"status_code": 200, "body": {"data": {"status": "running"}}, "tls_verified": True}
            elif "status/stop" in url:
                return {"status_code": 200, "body": {"data": "UPID:stop"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "ERROR: shutdown failed"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", "a", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["task_success"] is False

    def test_stop_timeout(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["stop"], allowed_api_actions=["stop"],
            task_poll_interval_seconds=0.01, task_max_polls=2,
            require_task_success=True,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        call_count = [0]
        def mock_api_request(url, headers, timeout=30, method="GET"):
            call_count[0] += 1
            if "status/current" in url:
                return {"status_code": 200, "body": {"data": {"status": "running"}}, "tls_verified": True}
            elif "status/stop" in url:
                return {"status_code": 200, "body": {"data": "UPID:stop"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "running"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", "a", "p", "r")
        assert result["deploy_status"] == "rejected"

    def test_stop_pre_state_mismatch(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["stop"], allowed_api_actions=["stop"],
            require_confirmed_target_status=True,
            expected_pre_state="running",
            expected_post_state="stopped",
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        def mock_api_request(url, headers, timeout=30, method="GET"):
            if "status/current" in url:
                # Already stopped — doesn't match expected pre-state 'running'
                return {"status_code": 200, "body": {"data": {"status": "stopped"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        result = adapter.deploy("t", "a", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert "Pre-state mismatch" in result["deploy_detail"]


class TestNoOpWithoutExpectedPostState:
    """No-op only triggers when expected_post_state is set."""

    def test_no_expected_post_state_no_noop(self, monkeypatch):
        """Without expected_post_state, no-op detection doesn't trigger."""
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["stop"], allowed_api_actions=["stop"],
            allow_noop_if_already_desired=True,
            # No expected_post_state set
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        call_count = [0]
        def mock_api_request(url, headers, timeout=30, method="GET"):
            call_count[0] += 1
            if "status/current" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped"}}, "tls_verified": True}
            elif "status/stop" in url:
                return {"status_code": 200, "body": {"data": "UPID:stop"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "OK"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", "a", "p", "r")
        # No expected_post_state → no no-op check → mutation executes
        assert result["no_op"] is False
