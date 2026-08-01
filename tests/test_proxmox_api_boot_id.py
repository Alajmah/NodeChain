"""Tests for v1.18.2 Proxmox Reboot Boot-ID Proof.

Tests cover:
  - Manifest fields: boot_evidence_source, allow_uptime_only_fallback
  - _capture_boot_id_evidence method
  - Boot ID changed scenario
  - Boot ID unchanged → rejected
  - Boot ID unavailable + fallback allowed → uptime-based acceptance
  - Boot ID unavailable + fallback rejected → rejected
  - Receipt field completeness
  - boot_evidence_source = "auto" fallback behavior
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest


class TestBootIdManifestFields:
    """v1.18.2 manifest field support."""

    def test_boot_id_fields(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            boot_evidence_source="guest_agent",
            allow_uptime_only_fallback=False,
            require_boot_id_change=True,
        )
        assert m.boot_evidence_source == "guest_agent"
        assert m.allow_uptime_only_fallback is False
        assert m.require_boot_id_change is True

    def test_boot_id_fields_roundtrip(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            boot_evidence_source="auto",
            allow_uptime_only_fallback=False,
        )
        m2 = AdapterManifest.from_dict(m.to_dict())
        assert m2.boot_evidence_source == "auto"
        assert m2.allow_uptime_only_fallback is False

    def test_defaults(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(adapter_id="x", adapter_type="proxmox_api")
        assert m.boot_evidence_source == "uptime"
        assert m.allow_uptime_only_fallback is True


class TestCaptureBootIdEvidence:
    """_capture_boot_id_evidence method."""

    def test_boot_id_available(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        boot_id = "abc-123-def-456"
        encoded = base64.b64encode(boot_id.encode()).decode()

        def mock_api_request(url, headers, timeout=30, method="GET"):
            if "agent/file-read" in url:
                return {"status_code": 200, "body": {"data": {"content": encoded}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        evidence = adapter._capture_boot_id_evidence({}, 30)
        assert evidence["available"] is True
        assert evidence["boot_id"] == boot_id
        assert evidence["source"] == "guest_agent"

    def test_boot_id_unavailable(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        def mock_api_request(url, headers, timeout=30, method="GET"):
            return {"status_code": 500, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        evidence = adapter._capture_boot_id_evidence({}, 30)
        assert evidence["available"] is False
        assert evidence["boot_id"] == ""


class TestRebootBootIdChanged:
    """reboot with boot_id that changed → accepted."""

    def test_boot_id_changed_accepted(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["reboot"], allowed_api_actions=["reboot"],
            expected_post_state="running",
            require_boot_id_change=True,
            boot_evidence_source="guest_agent",
            allow_uptime_only_fallback=False,
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        pre_id = "boot-id-aaa"
        post_id = "boot-id-bbb"
        pre_enc = base64.b64encode(pre_id.encode()).decode()
        post_enc = base64.b64encode(post_id.encode()).decode()

        reboot_done = [False]
        def mock_api_request(url, headers, timeout=30, method="GET"):
            if "status/current" in url:
                uptime = 5 if reboot_done[0] else 3600
                return {"status_code": 200, "body": {"data": {"status": "running", "uptime": uptime}}, "tls_verified": True}
            elif "agent/file-read" in url:
                enc = post_enc if reboot_done[0] else pre_enc
                return {"status_code": 200, "body": {"data": {"content": enc}}, "tls_verified": True}
            elif "status/reboot" in url:
                reboot_done[0] = True
                return {"status_code": 200, "body": {"data": "UPID:reboot"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "OK"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", "a", "p", "r")
        assert result["deploy_status"] == "accepted"
        assert result["boot_id_changed"] is True
        assert result["boot_identity_changed"] is True
        assert result["uptime_fallback_used"] is False
        assert result["boot_evidence_source"] == "guest_agent"


class TestRebootBootIdUnchanged:
    """reboot where boot_id didn't change → rejected."""

    def test_boot_id_unchanged_rejected(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["reboot"], allowed_api_actions=["reboot"],
            expected_post_state="running",
            require_boot_id_change=True,
            boot_evidence_source="guest_agent",
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        same_id = "same-boot-id"
        enc = base64.b64encode(same_id.encode()).decode()

        reboot_done = [False]
        def mock_api_request(url, headers, timeout=30, method="GET"):
            if "status/current" in url:
                uptime = 3700 if reboot_done[0] else 3600
                return {"status_code": 200, "body": {"data": {"status": "running", "uptime": uptime}}, "tls_verified": True}
            elif "agent/file-read" in url:
                return {"status_code": 200, "body": {"data": {"content": enc}}, "tls_verified": True}
            elif "status/reboot" in url:
                reboot_done[0] = True
                return {"status_code": 200, "body": {"data": "UPID:reboot"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "OK"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", "a", "p", "r")
        # Task succeeded but boot_id didn't change
        assert result["task_success"] is True
        assert result["state_transition_verified"] is True
        assert result["boot_id_changed"] is False
        assert result["deploy_status"] == "rejected"


class TestBootIdUnavailableFallbackAllowed:
    """Boot ID unavailable + fallback allowed → uptime-based acceptance."""

    def test_unavailable_fallback_allowed(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["reboot"], allowed_api_actions=["reboot"],
            expected_post_state="running",
            require_boot_id_change=True,
            boot_evidence_source="auto",
            allow_uptime_only_fallback=True,
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        reboot_done = [False]
        def mock_api_request(url, headers, timeout=30, method="GET"):
            if "status/current" in url:
                uptime = 5 if reboot_done[0] else 3600
                return {"status_code": 200, "body": {"data": {"status": "running", "uptime": uptime}}, "tls_verified": True}
            elif "agent/file-read" in url:
                # Boot ID unavailable (e.g. LXC container, no guest agent)
                return {"status_code": 500, "body": {}, "tls_verified": True}
            elif "status/reboot" in url:
                reboot_done[0] = True
                return {"status_code": 200, "body": {"data": "UPID:reboot"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "OK"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", "a", "p", "r")
        assert result["deploy_status"] == "accepted"
        assert result["boot_id_changed"] is False
        assert result["uptime_fallback_used"] is True
        assert result["uptime_reset_detected"] is True


class TestBootIdUnavailableFallbackRejected:
    """Boot ID unavailable + fallback rejected → deploy rejected."""

    def test_unavailable_fallback_rejected(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["reboot"], allowed_api_actions=["reboot"],
            expected_post_state="running",
            require_boot_id_change=True,
            boot_evidence_source="guest_agent",
            allow_uptime_only_fallback=False,
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        reboot_done = [False]
        def mock_api_request(url, headers, timeout=30, method="GET"):
            if "status/current" in url:
                uptime = 5 if reboot_done[0] else 3600
                return {"status_code": 200, "body": {"data": {"status": "running", "uptime": uptime}}, "tls_verified": True}
            elif "agent/file-read" in url:
                # Boot ID unavailable
                return {"status_code": 500, "body": {}, "tls_verified": True}
            elif "status/reboot" in url:
                reboot_done[0] = True
                return {"status_code": 200, "body": {"data": "UPID:reboot"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "OK"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", "a", "p", "r")
        # Task succeeded but boot_id unavailable and fallback not allowed
        assert result["task_success"] is True
        assert result["state_transition_verified"] is True
        assert result["deploy_status"] == "rejected"
        # uptime_fallback_used=True means uptime reset was detected (factual)
        # even though it was rejected because allow_uptime_only_fallback=False
        assert result["uptime_fallback_used"] is True


class TestBootIdReceiptFields:
    """Receipt records boot ID evidence fields."""

    def test_receipt_has_boot_id_fields(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["reboot"], allowed_api_actions=["reboot"],
            expected_post_state="running",
            require_boot_id_change=True,
            boot_evidence_source="guest_agent",
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        pre_id = "pre-id-111"
        post_id = "post-id-222"
        pre_enc = base64.b64encode(pre_id.encode()).decode()
        post_enc = base64.b64encode(post_id.encode()).decode()

        reboot_done = [False]
        def mock_api_request(url, headers, timeout=30, method="GET"):
            if "status/current" in url:
                uptime = 5 if reboot_done[0] else 3600
                return {"status_code": 200, "body": {"data": {"status": "running", "uptime": uptime}}, "tls_verified": True}
            elif "agent/file-read" in url:
                enc = post_enc if reboot_done[0] else pre_enc
                return {"status_code": 200, "body": {"data": {"content": enc}}, "tls_verified": True}
            elif "status/reboot" in url:
                reboot_done[0] = True
                return {"status_code": 200, "body": {"data": "UPID:reboot"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "OK"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", "a", "p", "r")
        for field in ["boot_evidence_source", "pre_boot_id", "post_boot_id",
                       "boot_id_changed", "uptime_fallback_used", "boot_id_hashed"]:
            assert field in result, f"Missing: {field}"
        # v1.18.2: Boot IDs are hashed by default
        assert result["boot_id_hashed"] is True
        assert result["pre_boot_id"] != pre_id  # hashed, not raw
        assert result["post_boot_id"] != post_id  # hashed, not raw
        assert len(result["pre_boot_id"]) == 64  # SHA-256 hex


class TestUptimeOnlySourceDefault:
    """Default boot_evidence_source='uptime' doesn't call guest agent."""

    def test_uptime_source_no_guest_agent_call(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["reboot"], allowed_api_actions=["reboot"],
            expected_post_state="running",
            boot_evidence_source="uptime",  # default
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        agent_calls = [0]
        reboot_done = [False]
        def mock_api_request(url, headers, timeout=30, method="GET"):
            if "status/current" in url:
                uptime = 5 if reboot_done[0] else 3600
                return {"status_code": 200, "body": {"data": {"status": "running", "uptime": uptime}}, "tls_verified": True}
            elif "agent/file-read" in url:
                agent_calls[0] += 1
                return {"status_code": 404, "body": {}, "tls_verified": True}
            elif "status/reboot" in url:
                reboot_done[0] = True
                return {"status_code": 200, "body": {"data": "UPID:reboot"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "OK"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api_request)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", "a", "p", "r")
        # Should not have called the guest agent at all
        assert agent_calls[0] == 0
        assert result["deploy_status"] == "accepted"
        assert result["boot_evidence_source"] == "uptime"
        assert result["uptime_reset_detected"] is True
