"""Tests for v1.18.2 Proxmox API Reboot Evidence.

Tests cover:
  - reboot action registration and URL building
  - Reboot evidence manifest fields
  - _capture_boot_evidence method
  - Reboot success with uptime reset detection
  - Reboot with require_boot_id_change
  - Reboot where uptime didn't reset (evidence missing)
  - Reboot pre-state not running → rejected
  - Reboot task failure
  - Receipt field completeness
  - reject_noop hardening (rejects before mutation)
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


class TestRebootActionRegistration:
    """reboot action is in PROXMOX_API_ACTIONS."""

    def test_reboot_in_api_actions(self):
        from nodechain.cli.deployment_adapter import PROXMOX_API_ACTIONS
        assert "reboot" in PROXMOX_API_ACTIONS

    def test_reboot_url(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        url = adapter._build_api_url("reboot")
        assert "status/reboot" in url
        assert "pve1" in url
        assert "801" in url


class TestRebootManifestFields:
    """v1.18.2 manifest field support."""

    def test_reboot_fields(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            require_boot_id_change=True,
            require_uptime_reset=True,
            reboot_timeout_seconds=180,
        )
        assert m.require_boot_id_change is True
        assert m.require_uptime_reset is True
        assert m.reboot_timeout_seconds == 180

    def test_reboot_fields_roundtrip(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            require_boot_id_change=True,
            require_uptime_reset=False,
            reboot_timeout_seconds=600,
        )
        m2 = AdapterManifest.from_dict(m.to_dict())
        assert m2.require_boot_id_change is True
        assert m2.require_uptime_reset is False
        assert m2.reboot_timeout_seconds == 600

    def test_defaults(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(adapter_id="x", adapter_type="proxmox_api")
        assert m.require_boot_id_change is False
        assert m.require_uptime_reset is False
        assert m.reboot_timeout_seconds == 300


class TestCaptureBootEvidence:
    """_capture_boot_evidence method."""

    def test_capture_with_uptime(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        monkeypatch.setattr(adapter, "_api_request", lambda *a, **k: {
            "status_code": 200,
            "body": {"data": {"uptime": 3600, "status": "running"}},
            "tls_verified": True,
        })
        evidence = adapter._capture_boot_evidence({})
        assert evidence["uptime_seconds"] == 3600
        assert evidence["status"] == "running"
        assert evidence["available"] is True

    def test_capture_unavailable(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        monkeypatch.setattr(adapter, "_api_request", lambda *a, **k: {
            "status_code": 500,
            "body": {},
            "tls_verified": True,
        })
        evidence = adapter._capture_boot_evidence({})
        assert evidence["available"] is False
        assert evidence["uptime_seconds"] == 0


class TestRebootSuccess:
    """reboot succeeds with uptime reset."""

    def test_reboot_success_with_uptime_reset(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["reboot"], allowed_api_actions=["reboot"],
            expected_pre_state="running",
            expected_post_state="running",
            require_uptime_reset=True,
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        reboot_done = [False]
        def mock_api_request(url, headers, timeout=30, method="GET"):
            if "status/current" in url:
                # Before reboot: uptime=3600; After: uptime=5
                uptime = 5 if reboot_done[0] else 3600
                return {"status_code": 200, "body": {"data": {"status": "running", "uptime": uptime}}, "tls_verified": True}
            elif "status/reboot" in url:
                reboot_done[0] = True
                return {"status_code": 200, "body": {"data": "UPID:reboot:task"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "OK"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", "a", "p", "r")
        assert result["deploy_status"] == "accepted"
        assert result["pre_uptime_seconds"] == 3600
        assert result["post_uptime_seconds"] == 5
        assert result["uptime_reset_detected"] is True
        assert result["boot_identity_changed"] is True
        assert result["state_transition_verified"] is True

    def test_reboot_success_without_requirement(self, monkeypatch):
        """Without require_uptime_reset, reboot succeeds even without evidence."""
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["reboot"], allowed_api_actions=["reboot"],
            expected_post_state="running",
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        reboot_done = [False]
        def mock_api_request(url, headers, timeout=30, method="GET"):
            if "status/current" in url:
                uptime = 3700 if reboot_done[0] else 3600
                return {"status_code": 200, "body": {"data": {"status": "running", "uptime": uptime}}, "tls_verified": True}
            elif "status/reboot" in url:
                reboot_done[0] = True
                return {"status_code": 200, "body": {"data": "UPID:reboot"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "OK"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", "a", "p", "r")
        # Task succeeded and state verified, no uptime requirement
        assert result["deploy_status"] == "accepted"
        assert result["uptime_reset_detected"] is False  # uptime didn't actually reset


class TestRebootEvidenceFailure:
    """reboot with require_uptime_reset but no reset detected → rejected."""

    def test_reboot_no_uptime_reset_rejected(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["reboot"], allowed_api_actions=["reboot"],
            expected_post_state="running",
            require_uptime_reset=True,
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        reboot_done = [False]
        def mock_api_request(url, headers, timeout=30, method="GET"):
            if "status/current" in url:
                # Uptime INCREASES — no reset
                uptime = 3700 if reboot_done[0] else 3600
                return {"status_code": 200, "body": {"data": {"status": "running", "uptime": uptime}}, "tls_verified": True}
            elif "status/reboot" in url:
                reboot_done[0] = True
                return {"status_code": 200, "body": {"data": "UPID:reboot"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "OK"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", "a", "p", "r")
        # Task succeeded and state verified, but uptime didn't reset
        assert result["task_success"] is True
        assert result["state_transition_verified"] is True
        assert result["uptime_reset_detected"] is False
        # Rejected because require_uptime_reset=true
        assert result["deploy_status"] == "rejected"


class TestRebootPreStateMismatch:
    """reboot when not running → rejected."""

    def test_reboot_not_running(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["reboot"], allowed_api_actions=["reboot"],
            require_confirmed_target_status=True,
            expected_pre_state="running",
            expected_post_state="running",
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        def mock_api_request(url, headers, timeout=30, method="GET"):
            if "status/current" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        result = adapter.deploy("t", "a", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert "Pre-state mismatch" in result["deploy_detail"]


class TestRebootTaskFailure:
    """reboot task fails → rejected."""

    def test_reboot_task_error(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["reboot"], allowed_api_actions=["reboot"],
            expected_post_state="running",
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        reboot_done = [False]
        def mock_api_request(url, headers, timeout=30, method="GET"):
            if "status/current" in url:
                return {"status_code": 200, "body": {"data": {"status": "running", "uptime": 3600}}, "tls_verified": True}
            elif "status/reboot" in url:
                reboot_done[0] = True
                return {"status_code": 200, "body": {"data": "UPID:reboot"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "ERROR: reboot failed"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", "a", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["task_success"] is False


class TestRebootReceiptFields:
    """Receipt records reboot evidence fields."""

    def test_receipt_has_reboot_fields(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["reboot"], allowed_api_actions=["reboot"],
            expected_post_state="running",
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        reboot_done = [False]
        def mock_api_request(url, headers, timeout=30, method="GET"):
            if "status/current" in url:
                uptime = 5 if reboot_done[0] else 3600
                return {"status_code": 200, "body": {"data": {"status": "running", "uptime": uptime}}, "tls_verified": True}
            elif "status/reboot" in url:
                reboot_done[0] = True
                return {"status_code": 200, "body": {"data": "UPID:reboot"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "OK"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", "a", "p", "r")
        for field in ["pre_uptime_seconds", "post_uptime_seconds", "boot_identity_changed", "uptime_reset_detected"]:
            assert field in result, f"Missing: {field}"


class TestRejectNoopHardening:
    """v1.18.2: reject_noop now rejects before mutation."""

    def test_reject_noop_before_mutation(self, monkeypatch):
        """Already in desired state + reject_noop → rejected before POST."""
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
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        def mock_api_request(url, headers, timeout=30, method="GET"):
            if "status/current" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        result = adapter.deploy("t", "a", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["effective_action"] == "rejected"
        assert result["task_exitstatus"] == "REJECTED_NOOP"
        assert "no-op not allowed" in result["deploy_detail"]
