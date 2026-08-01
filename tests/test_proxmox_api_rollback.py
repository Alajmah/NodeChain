"""Tests for v1.18.2 Proxmox Rollback Policy.

Tests cover all 7 acceptance criteria:
  1. rollback_artifact action registered
  2. Manifest supports rollback fields
  3. Apply flow triggers rollback on failure
  4. Receipt records rollback evidence
  5. Strict mode failure modes
  6. Test matrix (apply success/no rollback, apply fail/rollback success, etc.)
  7. Cross-platform green
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


class TestRollbackActionRegistration:
    """AC1: rollback_artifact action registered."""

    def test_in_api_actions(self):
        from nodechain.cli.deployment_adapter import PROXMOX_API_ACTIONS
        assert "rollback_artifact" in PROXMOX_API_ACTIONS

    def test_in_lifecycle_matrix(self):
        from nodechain.cli.deployment_adapter import PROXMOX_API_LIFECYCLE_MATRIX
        assert "rollback_artifact" in PROXMOX_API_LIFECYCLE_MATRIX

    def test_in_artifact_matrix(self):
        from nodechain.cli.deployment_adapter import ARTIFACT_ACTION_MATRIX
        assert "rollback_artifact" in ARTIFACT_ACTION_MATRIX
        assert ARTIFACT_ACTION_MATRIX["rollback_artifact"]["stage"] == "rollback"

    def test_rollback_url(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        url = adapter._build_api_url("rollback_artifact")
        assert "pve1" in url
        assert "801" in url


class TestRollbackManifestFields:
    """AC2: Manifest supports rollback fields."""

    def test_rollback_fields(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            previous_artifact_digest="abc123",
            require_previous_receipt_verified=False,
            rollback_target_path="/opt/app/previous",
            rollback_timeout_seconds=300,
            require_rollback_verification=True,
            rollback_on_apply_failure=True,
        )
        assert m.previous_artifact_digest == "abc123"
        assert m.rollback_target_path == "/opt/app/previous"
        assert m.rollback_timeout_seconds == 300
        assert m.require_rollback_verification is True
        assert m.rollback_on_apply_failure is True

    def test_defaults(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(adapter_id="x", adapter_type="proxmox_api")
        assert m.previous_artifact_digest == ""
        assert m.rollback_target_path == ""
        assert m.rollback_timeout_seconds == 120
        assert m.require_rollback_verification is True
        assert m.rollback_on_apply_failure is False

    def test_roundtrip(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            previous_artifact_digest="prev-digest",
            require_previous_receipt_verified=False,
            rollback_on_apply_failure=True,
        )
        m2 = AdapterManifest.from_dict(m.to_dict())
        assert m2.previous_artifact_digest == "prev-digest"
        assert m2.rollback_on_apply_failure is True


class TestExplicitRollbackSuccess:
    """Explicit rollback_artifact action succeeds."""

    def test_explicit_rollback_success(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["rollback_artifact"], allowed_api_actions=["rollback_artifact"],
            previous_artifact_digest="prev-abc-123",
            require_previous_receipt_verified=False,
            expected_service_state="running",
            require_rollback_verification=True,
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        def mock_api(url, headers, timeout=30, method="GET"):
            if "status/current" in url:
                return {"status_code": 200, "body": {"data": {"status": "running"}}, "tls_verified": True}
            elif "/config" in url and method == "PUT":
                return {"status_code": 200, "body": {"data": "UPID:rollback"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "OK"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", "d", "p", "r")
        assert result["deploy_status"] == "accepted"
        assert result["rollback_status"] == "succeeded"
        assert result["rollback_artifact_digest"] == "prev-abc-123"
        assert result["rollback_verified"] is True
        assert result["final_deployment_state"] == "rolled_back"
        assert result["rollback_triggered_by"] == "explicit"


class TestExplicitRollbackNoPreviousArtifact:
    """AC5: Previous artifact missing."""

    def test_no_previous_digest(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["rollback_artifact"], allowed_api_actions=["rollback_artifact"],
            previous_artifact_digest="",  # missing!
            require_previous_receipt_verified=False,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        result = adapter.deploy("t", "d", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["failure_mode"] == "previous_artifact_missing"
        assert result["rollback_attempted"] is True


class TestExplicitRollbackFailure:
    """AC5: Rollback API fails."""

    def test_rollback_api_error(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["rollback_artifact"], allowed_api_actions=["rollback_artifact"],
            previous_artifact_digest="prev-123",
            require_previous_receipt_verified=False,
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        def mock_api(url, headers, timeout=30, method="GET"):
            if "/config" in url and method == "PUT":
                return {"status_code": 500, "body": {"errors": "denied"}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api)
        result = adapter.deploy("t", "d", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["failure_mode"] == "rollback_failed"
        assert result["rollback_status"] == "failed"
        assert result["final_deployment_state"] == "unknown"


class TestExplicitRollbackVerificationFailed:
    """AC5: Rollback succeeded but verification failed."""

    def test_verification_mismatch(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["rollback_artifact"], allowed_api_actions=["rollback_artifact"],
            previous_artifact_digest="prev-123",
            require_previous_receipt_verified=False,
            expected_service_state="running",
            require_rollback_verification=True,
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        def mock_api(url, headers, timeout=30, method="GET"):
            if "status/current" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped"}}, "tls_verified": True}
            elif "/config" in url and method == "PUT":
                return {"status_code": 200, "body": {"data": "UPID:rollback"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "OK"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", "d", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["failure_mode"] == "rollback_verification_failed"
        assert result["rollback_verified"] is False
        assert result["final_deployment_state"] == "rollback_unverified"


class TestApplySuccessNoRollback:
    """AC6: Apply succeeds, no rollback attempted."""

    def test_apply_success_no_rollback(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["apply_artifact"], allowed_api_actions=["apply_artifact"],
            expected_service_state="running",
            rollback_on_apply_failure=True,
            previous_artifact_digest="prev-digest",
            require_previous_receipt_verified=False,
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
        result = adapter.deploy("t", "digest123", "p", "r")
        assert result["deploy_status"] == "accepted"
        assert result["rollback_attempted"] is False
        assert result["rollback_status"] == "not_attempted"
        assert result["final_deployment_state"] == "applied"


class TestApplyFailureTriggersRollback:
    """AC3+AC6: Apply failure triggers automatic rollback."""

    def test_apply_fail_rollback_success(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["apply_artifact"], allowed_api_actions=["apply_artifact"],
            expected_service_state="running",
            rollback_on_apply_failure=True,
            previous_artifact_digest="prev-digest",
            require_previous_receipt_verified=False,
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        call_count = [0]
        def mock_api(url, headers, timeout=30, method="GET"):
            call_count[0] += 1
            if "storage/local/content" in url:
                return {"status_code": 200, "body": {"data": [{"volid": "local:app"}]}, "tls_verified": True}
            elif "status/current" in url:
                return {"status_code": 200, "body": {"data": {"status": "running"}}, "tls_verified": True}
            elif "/config" in url and method == "POST":
                # Apply fails (service post-state is wrong)
                return {"status_code": 200, "body": {"data": "UPID:apply"}, "tls_verified": True}
            elif "/config" in url and method == "PUT":
                # Rollback succeeds
                return {"status_code": 200, "body": {"data": "UPID:rollback"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "OK"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api)
        monkeypatch.setattr("time.sleep", lambda x: None)

        # Override the status mock to make apply fail: service stays stopped after apply
        status_call_count = [0]
        apply_completed = [False]
        rollback_completed = [False]
        def mock_api2(url, headers, timeout=30, method="GET"):
            if "storage/local/content" in url:
                return {"status_code": 200, "body": {"data": [{"volid": "local:app"}]}, "tls_verified": True}
            elif "status/current" in url:
                status_call_count[0] += 1
                # Pre-apply: running. Post-apply: stopped (apply failed to activate).
                # Post-rollback: running (rollback restored service).
                if apply_completed[0] and not rollback_completed[0]:
                    return {"status_code": 200, "body": {"data": {"status": "stopped"}}, "tls_verified": True}
                return {"status_code": 200, "body": {"data": {"status": "running"}}, "tls_verified": True}
            elif "/config" in url and method == "POST":
                apply_completed[0] = True
                return {"status_code": 200, "body": {"data": "UPID:apply"}, "tls_verified": True}
            elif "/config" in url and method == "PUT":
                rollback_completed[0] = True
                return {"status_code": 200, "body": {"data": "UPID:rollback"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "OK"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api2)
        result = adapter.deploy("t", "digest123", "p", "r")
        # Apply failed (pre-state=stopped ≠ expected_pre?), but actually
        # apply itself succeeds but post-state verification fails
        assert result["deploy_status"] == "rejected"
        assert result["rollback_attempted"] is True
        assert result["rollback_triggered_by"] == "apply_failure"
        assert result["final_deployment_state"] == "rolled_back"


class TestApplyFailureNoRollbackConfigured:
    """AC6: Apply fails, rollback not configured → no rollback."""

    def test_apply_fail_no_rollback(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["apply_artifact"], allowed_api_actions=["apply_artifact"],
            expected_service_state="running",
            rollback_on_apply_failure=False,  # not configured
            previous_artifact_digest="prev-digest",
            require_previous_receipt_verified=False,
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        def mock_api(url, headers, timeout=30, method="GET"):
            if "storage/local/content" in url:
                return {"status_code": 200, "body": {"data": [{"volid": "local:app"}]}, "tls_verified": True}
            elif "status/current" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped"}}, "tls_verified": True}
            elif "/config" in url and method == "POST":
                return {"status_code": 500, "body": {"errors": "denied"}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api)
        result = adapter.deploy("t", "digest123", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["rollback_attempted"] is False
        assert result["rollback_status"] == "not_attempted"
        assert result["final_deployment_state"] == "failed"


class TestRollbackReceiptFields:
    """AC4: Receipt records all rollback evidence."""

    def test_receipt_has_rollback_fields(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["rollback_artifact"], allowed_api_actions=["rollback_artifact"],
            previous_artifact_digest="prev-digest-xyz",
            require_previous_receipt_verified=False,
            expected_service_state="running",
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        def mock_api(url, headers, timeout=30, method="GET"):
            if "status/current" in url:
                return {"status_code": 200, "body": {"data": {"status": "running"}}, "tls_verified": True}
            elif "/config" in url and method == "PUT":
                return {"status_code": 200, "body": {"data": "UPID:rollback"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "OK"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", "d", "p", "r")
        for field in ["rollback_attempted", "rollback_started_at", "rollback_finished_at",
                       "rollback_status", "rollback_artifact_digest", "rollback_verified",
                       "final_deployment_state"]:
            assert field in result, f"Missing: {field}"
        assert result["rollback_artifact_digest"] == "prev-digest-xyz"


# ─── v1.18.2: Rollback Provenance Tests ──────────────────────────────────

def _make_verified_receipt(artifact_digest="abc123"):
    """Create a valid prior deployment receipt for provenance testing."""
    return {
        "deploy_status": "accepted",
        "final_deployment_state": "applied",
        "activation_verified": True,
        "activated_artifact_digest": artifact_digest,
        "service_pre_state": "stopped",
        "service_post_state": "running",
        "action": "apply_artifact",
    }


class TestRollbackProvenanceFields:
    """AC1: Manifest supports rollback provenance fields."""

    def test_provenance_fields(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        receipt = _make_verified_receipt("abc123")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            previous_deployment_receipt=receipt,
            previous_deployment_receipt_digest="deadbeef",
            previous_attestation_digest="cafe1234",
            require_previous_receipt_verified=True,
        )
        assert m.previous_deployment_receipt == receipt
        assert m.previous_deployment_receipt_digest == "deadbeef"
        assert m.previous_attestation_digest == "cafe1234"
        assert m.require_previous_receipt_verified is True

    def test_defaults(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(adapter_id="x", adapter_type="proxmox_api")
        assert m.previous_deployment_receipt is None
        assert m.previous_deployment_receipt_digest == ""
        assert m.previous_attestation_digest == ""
        assert m.require_previous_receipt_verified is True

    def test_roundtrip(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        receipt = _make_verified_receipt("abc123")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            previous_deployment_receipt=receipt,
            previous_deployment_receipt_digest="abc",
            require_previous_receipt_verified=True,
        )
        m2 = AdapterManifest.from_dict(m.to_dict())
        assert m2.previous_deployment_receipt == receipt
        assert m2.previous_deployment_receipt_digest == "abc"
        assert m2.require_previous_receipt_verified is True


class TestRollbackToVerifiedPriorRelease:
    """AC2+AC6: Rollback to verified prior release succeeds."""

    def test_verified_prior_release_succeeds(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        prior = _make_verified_receipt("prev-abc-123")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["rollback_artifact"], allowed_api_actions=["rollback_artifact"],
            previous_artifact_digest="prev-abc-123",
            previous_deployment_receipt=prior,
            require_previous_receipt_verified=True,
            expected_service_state="running",
            require_rollback_verification=True,
            task_poll_interval_seconds=0.01, task_max_polls=3,
        )
        adapter = ProxmoxApiAdapter(manifest=m)

        def mock_api(url, headers, timeout=30, method="GET"):
            if "status/current" in url:
                return {"status_code": 200, "body": {"data": {"status": "running"}}, "tls_verified": True}
            elif "/config" in url and method == "PUT":
                return {"status_code": 200, "body": {"data": "UPID:rb"}, "tls_verified": True}
            elif "/tasks/" in url:
                return {"status_code": 200, "body": {"data": {"status": "stopped", "exitstatus": "OK"}}, "tls_verified": True}
            return {"status_code": 404, "body": {}, "tls_verified": True}

        monkeypatch.setattr(adapter, "_api_request", mock_api)
        monkeypatch.setattr("time.sleep", lambda x: None)
        result = adapter.deploy("t", "d", "p", "r")
        assert result["deploy_status"] == "accepted"
        assert result["rollback_status"] == "succeeded"
        assert result["rollback_to_known_good"] is True
        assert result["previous_release_verified"] is True
        assert result["rollback_provenance_status"] == "verified"


class TestRollbackNoPriorReceiptRejected:
    """AC5: Previous receipt missing — strict mode fails."""

    def test_no_prior_receipt_rejected(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["rollback_artifact"], allowed_api_actions=["rollback_artifact"],
            previous_artifact_digest="prev-123",
            previous_deployment_receipt=None,  # missing!
            require_previous_receipt_verified=True,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        result = adapter.deploy("t", "d", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["failure_mode"] == "previous_receipt_missing"
        assert result["rollback_provenance_status"] == "receipt_missing"
        assert result["rollback_to_known_good"] is False


class TestRollbackInvalidReceiptRejected:
    """AC5: Previous receipt invalid — digest mismatch."""

    def test_receipt_digest_mismatch(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        prior = _make_verified_receipt("prev-123")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["rollback_artifact"], allowed_api_actions=["rollback_artifact"],
            previous_artifact_digest="prev-123",
            previous_deployment_receipt=prior,
            previous_deployment_receipt_digest="0000000000000000",  # wrong digest!
            require_previous_receipt_verified=True,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        result = adapter.deploy("t", "d", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["failure_mode"] == "previous_receipt_invalid"
        assert result["rollback_provenance_status"] == "receipt_invalid"


class TestRollbackToUnverifiedArtifactRejected:
    """AC6: Rollback to unverified artifact — prior receipt missing activation_verified."""

    def test_unverified_activation_rejected(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        prior = _make_verified_receipt("prev-123")
        prior["activation_verified"] = False  # not verified!
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["rollback_artifact"], allowed_api_actions=["rollback_artifact"],
            previous_artifact_digest="prev-123",
            previous_deployment_receipt=prior,
            require_previous_receipt_verified=True,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        result = adapter.deploy("t", "d", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["failure_mode"] == "previous_activation_not_verified"
      
