"""Tests for v1.18.2 Proxmox API Lifecycle Consolidation.

Tests cover all 7 acceptance criteria:
  1. Normalized lifecycle receipt schema for all actions
  2. Action-level evidence matrix
  3. Negative smoke tests for all lifecycle actions
  4. Receipt stores boot IDs safely (hashed by default)
  5. Dry-run policy check
  6. (Docs verified in test by checking constants exist)
  7. Cross-platform green (verified by CI)
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest


class TestLifecycleMatrix:
    """AC2: Action-level evidence matrix documented."""

    def test_matrix_has_all_actions(self):
        from nodechain.cli.deployment_adapter import PROXMOX_API_LIFECYCLE_MATRIX, PROXMOX_API_ACTIONS
        for action in PROXMOX_API_ACTIONS:
            assert action in PROXMOX_API_LIFECYCLE_MATRIX, f"Missing: {action}"

    def test_matrix_fields(self):
        from nodechain.cli.deployment_adapter import PROXMOX_API_LIFECYCLE_MATRIX
        required_fields = {
            "required_pre_state", "required_post_state", "task_required",
            "boot_evidence_required", "noop_allowed", "strict_failure_modes",
        }
        for action, profile in PROXMOX_API_LIFECYCLE_MATRIX.items():
            for field in required_fields:
                assert field in profile, f"Action {action} missing {field}"

    def test_readonly_actions_no_task(self):
        from nodechain.cli.deployment_adapter import PROXMOX_API_LIFECYCLE_MATRIX
        for action in ("validate_target", "get_status"):
            assert PROXMOX_API_LIFECYCLE_MATRIX[action]["task_required"] is False
            assert PROXMOX_API_LIFECYCLE_MATRIX[action]["boot_evidence_required"] is False

    def test_mutation_actions_require_task(self):
        from nodechain.cli.deployment_adapter import PROXMOX_API_LIFECYCLE_MATRIX
        for action in ("start", "stop", "reboot"):
            assert PROXMOX_API_LIFECYCLE_MATRIX[action]["task_required"] is True

    def test_reboot_requires_boot_evidence(self):
        from nodechain.cli.deployment_adapter import PROXMOX_API_LIFECYCLE_MATRIX
        assert PROXMOX_API_LIFECYCLE_MATRIX["reboot"]["boot_evidence_required"] is True
        assert PROXMOX_API_LIFECYCLE_MATRIX["reboot"]["noop_allowed"] is False

    def test_start_stop_allow_noop(self):
        from nodechain.cli.deployment_adapter import PROXMOX_API_LIFECYCLE_MATRIX
        assert PROXMOX_API_LIFECYCLE_MATRIX["start"]["noop_allowed"] is True
        assert PROXMOX_API_LIFECYCLE_MATRIX["stop"]["noop_allowed"] is True

    def test_failure_modes_documented(self):
        from nodechain.cli.deployment_adapter import PROXMOX_API_LIFECYCLE_MATRIX
        for action, profile in PROXMOX_API_LIFECYCLE_MATRIX.items():
            assert isinstance(profile["strict_failure_modes"], list)
            assert len(profile["strict_failure_modes"]) > 0


class TestNormalizedReceiptSchema:
    """AC1: Normalized lifecycle receipt schema."""

    def test_lifecycle_fields_constant(self):
        from nodechain.cli.deployment_adapter import LIFECYCLE_RECEIPT_FIELDS
        assert isinstance(LIFECYCLE_RECEIPT_FIELDS, frozenset)
        assert "deploy_status" in LIFECYCLE_RECEIPT_FIELDS
        assert "proxmox_command_shape" in LIFECYCLE_RECEIPT_FIELDS

    def test_start_receipt_has_base_fields(self, monkeypatch):
        """Start receipt includes all canonical lifecycle fields."""
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter, LIFECYCLE_RECEIPT_FIELDS
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["start"], allowed_api_actions=["start"],
            expected_pre_state="stopped", expected_post_state="running",
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        def mock_api(url, headers, timeout=30, method="GET"):
            if "status/current" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped"}}, "tls_verified": True}
            elif "status/start" in url:
                return {"status_code": 200, "body": {"data": "UPID:start"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "OK"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}
        monkeypatch.setattr(adapter, "_api_request", mock_api)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", "a", "p", "r")
        for field in LIFECYCLE_RECEIPT_FIELDS:
            assert field in result, f"Start receipt missing: {field}"

    def test_get_status_receipt_has_base_fields(self, monkeypatch):
        """get_status receipt includes all canonical lifecycle fields."""
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter, LIFECYCLE_RECEIPT_FIELDS
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["get_status"], allowed_api_actions=["get_status"],
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        monkeypatch.setattr(adapter, "_api_request", lambda *a, **k: {
            "status_code": 200, "body": {"data": {"status": "running", "uptime": 100}},
            "tls_verified": True,
        })
        result = adapter.deploy("t", "a", "p", "r")
        for field in LIFECYCLE_RECEIPT_FIELDS:
            assert field in result, f"get_status receipt missing: {field}"


class TestBootIdSafety:
    """AC4: Receipt stores boot IDs safely."""

    def test_boot_ids_hashed_by_default(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["reboot"], allowed_api_actions=["reboot"],
            expected_post_state="running",
            boot_evidence_source="guest_agent",
            hash_boot_ids=True,
            allow_raw_boot_ids=False,
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        pre_id = "aaa-111"
        post_id = "bbb-222"
        pre_enc = base64.b64encode(pre_id.encode()).decode()
        post_enc = base64.b64encode(post_id.encode()).decode()
        reboot_done = [False]
        def mock_api(url, headers, timeout=30, method="GET"):
            if "status/current" in url:
                uptime = 5 if reboot_done[0] else 3600
                return {"status_code": 200, "body": {"data": {"status": "running", "uptime": uptime}}, "tls_verified": True}
            elif "agent/file-read" in url:
                return {"status_code": 200, "body": {"data": {"content": post_enc if reboot_done[0] else pre_enc}}, "tls_verified": True}
            elif "status/reboot" in url:
                reboot_done[0] = True
                return {"status_code": 200, "body": {"data": "UPID:reboot"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "OK"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}
        monkeypatch.setattr(adapter, "_api_request", mock_api)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", "a", "p", "r")
        assert result["boot_id_hashed"] is True
        assert result["pre_boot_id"] != pre_id  # hashed
        assert result["post_boot_id"] != post_id  # hashed
        assert len(result["pre_boot_id"]) == 64  # SHA-256

    def test_raw_boot_ids_allowed(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["reboot"], allowed_api_actions=["reboot"],
            expected_post_state="running",
            boot_evidence_source="guest_agent",
            hash_boot_ids=False,
            allow_raw_boot_ids=True,
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        pre_id = "raw-pre-id"
        post_id = "raw-post-id"
        pre_enc = base64.b64encode(pre_id.encode()).decode()
        post_enc = base64.b64encode(post_id.encode()).decode()
        reboot_done = [False]
        def mock_api(url, headers, timeout=30, method="GET"):
            if "status/current" in url:
                uptime = 5 if reboot_done[0] else 3600
                return {"status_code": 200, "body": {"data": {"status": "running", "uptime": uptime}}, "tls_verified": True}
            elif "agent/file-read" in url:
                return {"status_code": 200, "body": {"data": {"content": post_enc if reboot_done[0] else pre_enc}}, "tls_verified": True}
            elif "status/reboot" in url:
                reboot_done[0] = True
                return {"status_code": 200, "body": {"data": "UPID:reboot"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "OK"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}
        monkeypatch.setattr(adapter, "_api_request", mock_api)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", "a", "p", "r")
        assert result["boot_id_hashed"] is False
        assert result["pre_boot_id"] == pre_id  # raw
        assert result["post_boot_id"] == post_id  # raw


class TestDryRunPolicyCheck:
    """AC5: --dry-run-policy-check validates without mutation."""

    def test_dry_run_passes_valid_manifest(self, tmp_path):
        from nodechain.cli.deployment_adapter import create_deployment_receipt
        # Create a gate receipt
        gate = {
            "receipt_id": "gate-123",
            "deploy_allowed": True,
            "target": "192.0.2.100",
            "artifact_digest": "abc123",
            "policy_digest": "def456",
        }
        gate_path = tmp_path / "gate.json"
        gate_path.write_text(json.dumps(gate))
        out_path = str(tmp_path / "dry_run.json")
        receipt = create_deployment_receipt(
            gate_receipt_path=str(gate_path),
            adapter_name="dry_run",
            output=out_path,
            dry_run_policy_check=True,
        )
        assert receipt["deploy_status"] == "dry_run_passed"
        assert receipt["dry_run"] is True
        assert receipt["policy_check_passed"] is True
        assert Path(out_path).exists()

    def test_dry_run_proxmox_api_checks_manifest(self, tmp_path, monkeypatch):
        from nodechain.cli.deployment_adapter import create_deployment_receipt, AdapterManifest
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        gate = {"receipt_id": "g1", "deploy_allowed": True, "target": "t", "artifact_digest": "a", "policy_digest": "p"}
        gate_path = tmp_path / "gate.json"
        gate_path.write_text(json.dumps(gate))
        manifest = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t@pam!tok", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["start"], allowed_api_actions=["start"],
        )
        manifest_path = tmp_path / "manifest.json"
        manifest_path.write_text(json.dumps(manifest.to_dict()))
        receipt = create_deployment_receipt(
            gate_receipt_path=str(gate_path),
            adapter_name="proxmox_api",
            manifest_path=str(manifest_path),
            dry_run_policy_check=True,
        )
        assert receipt["deploy_status"] == "dry_run_passed"
        assert receipt["policy_check_passed"] is True
        assert receipt["secret_ref_valid"] is True

    def test_dry_run_fails_on_missing_fields(self, tmp_path):
        from nodechain.cli.deployment_adapter import create_deployment_receipt, AdapterManifest
        gate = {"receipt_id": "g1", "deploy_allowed": True, "target": "t", "artifact_digest": "a", "policy_digest": "p"}
        gate_path = tmp_path / "gate.json"
        gate_path.write_text(json.dumps(gate))
        manifest = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            # Missing api_base_url, proxmox_node, target_vmid, token_id
        )
        manifest_path = tmp_path / "manifest.json"
        manifest_path.write_text(json.dumps(manifest.to_dict()))
        receipt = create_deployment_receipt(
            gate_receipt_path=str(gate_path),
            adapter_name="proxmox_api",
            manifest_path=str(manifest_path),
            dry_run_policy_check=True,
        )
        assert receipt["deploy_status"] == "dry_run_failed"
        assert receipt["policy_check_passed"] is False
        assert len(receipt["policy_check_issues"]) > 0


class TestLifecycleNegativeSmokes:
    """AC3: Negative smoke tests for all lifecycle actions."""

    # --- Action outside allowlist ---

    def test_action_not_in_allowlist(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["start"],
            allowed_api_actions=["start", "stop", "reboot"],  # stop not in allowed_actions
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        result = adapter.deploy("t", "a", "p", "r")
        assert result["deploy_status"] in ("rejected",)

    # --- Pre-state mismatch ---

    def test_start_pre_state_mismatch(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["start"], allowed_api_actions=["start"],
            require_confirmed_target_status=True,
            expected_pre_state="stopped",
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        monkeypatch.setattr(adapter, "_api_request", lambda *a, **k: {
            "status_code": 200, "body": {"data": {"status": "running"}}, "tls_verified": True,
        })
        result = adapter.deploy("t", "a", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert "Pre-state mismatch" in result["deploy_detail"]

    # --- Task failure ---

    def test_start_task_failure(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["start"], allowed_api_actions=["start"],
            expected_pre_state="stopped", expected_post_state="running",
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        def mock_api(url, headers, timeout=30, method="GET"):
            if "status/current" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped"}}, "tls_verified": True}
            elif "status/start" in url:
                return {"status_code": 200, "body": {"data": "UPID:start"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "ERROR: boot failure"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}
        monkeypatch.setattr(adapter, "_api_request", mock_api)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", "a", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["task_success"] is False

    # --- Task timeout ---

    def test_task_timeout(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["start"], allowed_api_actions=["start"],
            expected_pre_state="stopped", expected_post_state="running",
            task_poll_interval_seconds=0.01, task_max_polls=2,
            require_task_success=True,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        def mock_api(url, headers, timeout=30, method="GET"):
            if "status/current" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped"}}, "tls_verified": True}
            elif "status/start" in url:
                return {"status_code": 200, "body": {"data": "UPID:start"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "running"}}, "tls_verified": True}  # never finishes
            return {"status_code": 404, "body": {}, "tls_verified": True}
        monkeypatch.setattr(adapter, "_api_request", mock_api)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", "a", "p", "r")
        assert result["deploy_status"] == "rejected"

    # --- Post-state mismatch ---

    def test_start_post_state_mismatch(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["start"], allowed_api_actions=["start"],
            expected_pre_state="stopped", expected_post_state="running",
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        def mock_api(url, headers, timeout=30, method="GET"):
            if "status/current" in url:
                # Always stopped — never transitions to running
                return {"status_code": 200, "body": {"data": {"status": "stopped"}}, "tls_verified": True}
            elif "status/start" in url:
                return {"status_code": 200, "body": {"data": "UPID:start"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "OK"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}
        monkeypatch.setattr(adapter, "_api_request", mock_api)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", "a", "p", "r")
        assert result["state_transition_verified"] is False
        assert result["deploy_status"] == "rejected"

    # --- No-op rejected ---

    def test_noop_rejected(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["stop"], allowed_api_actions=["stop"],
            expected_post_state="stopped",
            idempotency_policy="reject_noop",
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        monkeypatch.setattr(adapter, "_api_request", lambda *a, **k: {
            "status_code": 200, "body": {"data": {"status": "stopped"}}, "tls_verified": True,
        })
        result = adapter.deploy("t", "a", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert "no-op not allowed" in result["deploy_detail"]

    # --- Boot ID unchanged ---

    def test_reboot_boot_id_unchanged(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["reboot"], allowed_api_actions=["reboot"],
            expected_post_state="running",
            require_boot_id_change=True,
            boot_evidence_source="guest_agent",
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        same_id = "same-id"
        enc = base64.b64encode(same_id.encode()).decode()
        reboot_done = [False]
        def mock_api(url, headers, timeout=30, method="GET"):
            if "status/current" in url:
                return {"status_code": 200, "body": {"data": {"status": "running", "uptime": 3600}}, "tls_verified": True}
            elif "agent/file-read" in url:
                return {"status_code": 200, "body": {"data": {"content": enc}}, "tls_verified": True}
            elif "status/reboot" in url:
                reboot_done[0] = True
                return {"status_code": 200, "body": {"data": "UPID:reboot"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "OK"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}
        monkeypatch.setattr(adapter, "_api_request", mock_api)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", "a", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["boot_id_changed"] is False

    # --- Fallback forbidden ---

    def test_reboot_fallback_forbidden(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["reboot"], allowed_api_actions=["reboot"],
            expected_post_state="running",
            require_boot_id_change=True,
            boot_evidence_source="guest_agent",
            allow_uptime_only_fallback=False,
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        reboot_done = [False]
        def mock_api(url, headers, timeout=30, method="GET"):
            if "status/current" in url:
                uptime = 5 if reboot_done[0] else 3600
                return {"status_code": 200, "body": {"data": {"status": "running", "uptime": uptime}}, "tls_verified": True}
            elif "agent/file-read" in url:
                return {"status_code": 500, "body": {}, "tls_verified": True}  # boot_id unavailable
            elif "status/reboot" in url:
                reboot_done[0] = True
                return {"status_code": 200, "body": {"data": "UPID:reboot"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "OK"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}
        monkeypatch.setattr(adapter, "_api_request", mock_api)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", "a", "p", "r")
        assert result["deploy_status"] == "rejected"


class TestBootIdSafetyManifestFields:
    """AC4: Manifest field support."""

    def test_hash_boot_ids_default(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(adapter_id="x", adapter_type="proxmox_api")
        assert m.hash_boot_ids is True
        assert m.allow_raw_boot_ids is False

    def test_hash_boot_ids_roundtrip(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            hash_boot_ids=False, allow_raw_boot_ids=True,
        )
        m2 = AdapterManifest.from_dict(m.to_dict())
        assert m2.hash_boot_ids is False
        assert m2.allow_raw_boot_ids is True
