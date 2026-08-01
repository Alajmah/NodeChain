"""Tests for v1.12.3 Proxmox API Task Polling.

Tests cover:
  - Manifest polling field serialization
  - _build_task_url for UPID-based endpoint
  - _poll_task method: success, failure, timeout
  - Task poll count tracking
  - Task duration measurement
  - task_success vs state_transition_verified separation
  - UPID failure (task exitstatus != OK)
  - Task timeout
  - No UPID scenario
  - Receipt field completeness
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


class TestPollingManifestFields:
    """v1.12.3 manifest field support."""

    def test_polling_fields(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            task_poll_interval_seconds=0.5,
            task_max_polls=20,
            require_task_success=True,
        )
        assert m.task_poll_interval_seconds == 0.5
        assert m.task_max_polls == 20
        assert m.require_task_success is True

    def test_polling_fields_roundtrip(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            task_poll_interval_seconds=2.0,
            task_max_polls=5,
            require_task_success=False,
        )
        m2 = AdapterManifest.from_dict(m.to_dict())
        assert m2.task_poll_interval_seconds == 2.0
        assert m2.task_max_polls == 5
        assert m2.require_task_success is False

    def test_defaults(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(adapter_id="x", adapter_type="proxmox_api")
        assert m.task_poll_interval_seconds == 1.0
        assert m.task_max_polls == 10
        assert m.require_task_success is True


class TestBuildTaskUrl:
    """_build_task_url for UPID-based endpoint."""

    def test_task_url(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        url = adapter._build_task_url("UPID:pve:00123456:abc:def:deploy@pam:")
        assert "tasks" in url
        assert "UPID:pve:00123456:abc:def:deploy@pam:" in url
        assert "status" in url


class TestPollTaskSuccess:
    """_poll_task with successful task completion."""

    def test_poll_immediate_success(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            task_poll_interval_seconds=0.01,
            task_max_polls=5,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        def mock_api_request(url, headers, timeout=30, method="GET"):
            return {
                "status_code": 200,
                "body": {"data": {"status": "stopped", "exitstatus": "OK"}},
                "tls_verified": True,
            }
        monkeypatch.setattr(adapter, "_api_request", mock_api_request)

        result = adapter._poll_task("UPID:test", {})
        assert result["task_status"] == "stopped"
        assert result["task_exitstatus"] == "OK"
        assert result["task_poll_count"] == 1
        assert result["timed_out"] is False

    def test_poll_success_after_retry(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            task_poll_interval_seconds=0.01,
            task_max_polls=5,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        call_count = [0]
        def mock_api_request(url, headers, timeout=30, method="GET"):
            call_count[0] += 1
            if call_count[0] < 3:
                return {
                    "status_code": 200,
                    "body": {"data": {"status": "running"}},
                    "tls_verified": True,
                }
            return {
                "status_code": 200,
                "body": {"data": {"status": "stopped", "exitstatus": "OK"}},
                "tls_verified": True,
            }
        monkeypatch.setattr(adapter, "_api_request", mock_api_request)

        result = adapter._poll_task("UPID:test", {})
        assert result["task_status"] == "stopped"
        assert result["task_poll_count"] == 3
        assert result["timed_out"] is False


class TestPollTaskFailure:
    """_poll_task with failed task."""

    def test_poll_failure_exitstatus(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            task_poll_interval_seconds=0.01,
            task_max_polls=5,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        def mock_api_request(url, headers, timeout=30, method="GET"):
            return {
                "status_code": 200,
                "body": {"data": {"status": "stopped", "exitstatus": "ERROR: command failed"}},
                "tls_verified": True,
            }
        monkeypatch.setattr(adapter, "_api_request", mock_api_request)

        result = adapter._poll_task("UPID:test", {})
        assert result["task_status"] == "stopped"
        assert result["task_exitstatus"] == "ERROR: command failed"
        assert result["timed_out"] is False


class TestPollTaskTimeout:
    """_poll_task with timeout (max polls exceeded)."""

    def test_poll_timeout(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            task_poll_interval_seconds=0.01,
            task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        def mock_api_request(url, headers, timeout=30, method="GET"):
            return {
                "status_code": 200,
                "body": {"data": {"status": "running"}},  # never finishes
                "tls_verified": True,
            }
        monkeypatch.setattr(adapter, "_api_request", mock_api_request)

        result = adapter._poll_task("UPID:test", {})
        assert result["task_status"] == "running"
        assert result["timed_out"] is True
        assert result["task_poll_count"] == 3

    def test_poll_endpoint_unavailable(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            task_poll_interval_seconds=0.01,
            task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        def mock_api_request(url, headers, timeout=30, method="GET"):
            return {"status_code": 500, "body": {}, "tls_verified": True}
        monkeypatch.setattr(adapter, "_api_request", mock_api_request)

        result = adapter._poll_task("UPID:test", {})
        assert result["timed_out"] is True
        assert result["task_status"] == "unknown"


class TestTaskPollDuration:
    """Task duration measurement."""

    def test_duration_positive(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            task_poll_interval_seconds=0.01,
            task_max_polls=5,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        def mock_api_request(url, headers, timeout=30, method="GET"):
            return {
                "status_code": 200,
                "body": {"data": {"status": "stopped", "exitstatus": "OK"}},
                "tls_verified": True,
            }
        monkeypatch.setattr(adapter, "_api_request", mock_api_request)

        result = adapter._poll_task("UPID:test", {})
        assert result["task_duration_ms"] >= 0


class TestTaskSuccessStateSeparation:
    """task_success and state_transition_verified are independent."""

    def test_task_success_true_state_verified_true(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["start"], allowed_api_actions=["start"],
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
        result = adapter.deploy("t", "a", "p", "r")
        assert result["task_success"] is True
        assert result["state_transition_verified"] is True
        assert result["deploy_status"] == "accepted"

    def test_task_success_true_state_verified_false(self, monkeypatch):
        """Task OK but VM didn't reach expected state."""
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["start"], allowed_api_actions=["start"],
            expected_post_state="running",
            task_poll_interval_seconds=0.01, task_max_polls=3,
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
        result = adapter.deploy("t", "a", "p", "r")
        assert result["task_success"] is True
        assert result["state_transition_verified"] is False
        # Overall rejected because state didn't match
        assert result["deploy_status"] == "rejected"

    def test_task_success_false_state_verified_true(self, monkeypatch):
        """Task failed but VM is in expected state (race or stale)."""
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["start"], allowed_api_actions=["start"],
            expected_post_state="running",
            task_poll_interval_seconds=0.01, task_max_polls=3,
            require_task_success=True,
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
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "ERROR"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        result = adapter.deploy("t", "a", "p", "r")
        assert result["task_success"] is False
        assert result["state_transition_verified"] is True
        # Overall rejected because task failed
        assert result["deploy_status"] == "rejected"


class TestTaskPollingReceiptFields:
    """Receipt records all polling fields."""

    def test_receipt_has_polling_fields(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["start"], allowed_api_actions=["start"],
            task_poll_interval_seconds=0.01, task_max_polls=3,
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
        result = adapter.deploy("t", "a", "p", "r")
        for field in ["task_poll_count", "task_duration_ms", "task_api_status", "task_success"]:
            assert field in result, f"Missing field: {field}"

    def test_receipt_task_exitstatus_from_poll(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["start"], allowed_api_actions=["start"],
            task_poll_interval_seconds=0.01, task_max_polls=3,
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
        result = adapter.deploy("t", "a", "p", "r")
        # exitstatus comes from task poll, not hardcoded
        assert result["task_exitstatus"] == "OK"


class TestNoUpidScenario:
    """No UPID from POST → immediate failure."""

    def test_no_upid_task_poll_count_zero(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["start"], allowed_api_actions=["start"],
            task_poll_interval_seconds=0.01, task_max_polls=3,
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
        result = adapter.deploy("t", "a", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["task_poll_count"] == 0
        assert result["task_api_status"] == "no_upid"
        assert result["task_exitstatus"] == "FAILED"
