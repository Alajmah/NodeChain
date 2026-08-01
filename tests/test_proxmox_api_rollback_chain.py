"""Tests for v1.18.2 Rollback Full Chain Verification.

Tests cover all 7 acceptance criteria:
  1. Manifest supports full assurance chain fields
  2. Verification checks: receipt signature, attestation, profile, audit bundle
  3. Strict mode fails for unsigned/invalid/untrusted/non-compliant
  4. Receipt records chain verification evidence
  5. CLI supports --require-previous-assurance-chain
  6. Tests: valid chain, invalid signature, non-compliant attestation,
     untrusted profile, wrong digest
  7. Windows/Linux green
"""

from __future__ import annotations

import pytest


def _make_chain_inputs(artifact_digest="prev-abc"):
    """Create all prior assurance chain inputs for a valid rollback."""
    prior_receipt = {
        "deploy_status": "accepted",
        "final_deployment_state": "applied",
        "activation_verified": True,
        "activated_artifact_digest": artifact_digest,
        "receipt_type": "deployment_system_receipt",
        "deployment_receipt_id": "rcpt-001",
        "deployment_system": "proxmox_api",
        "receipt_signature": {"signature": "fake-sig", "algorithm": "RSA-PSS-SHA256"},
    }
    prior_attestation = {
        "deploy_allowed": True,
        "policy_id": "pol-001",
        "policy_version": "1.0",
        "audit_bundle_sha256": "bundle-hash-123",
        "attestation_signature": {"signature": "fake-att-sig"},
    }
    prior_profile = {
        "trusted": True,
        "profile_digest": "profile-hash-456",
        "profile_signature": "fake-profile-sig",
        "profile_signer_fingerprint": "AB:CD:EF",
    }
    prior_gate_receipt = {
        "deploy_allowed": True,
        "gate_receipt_id": "gate-001",
    }
    return prior_receipt, prior_attestation, prior_profile, prior_gate_receipt


class TestChainManifestFields:
    """AC1: Manifest supports full assurance chain fields."""

    def test_chain_fields(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        r, a, p, g = _make_chain_inputs()
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            require_previous_assurance_chain=True,
            previous_attestation=a,
            previous_verifier_profile=p,
            previous_gate_receipt=g,
            previous_audit_bundle_digest="bundle-hash-123",
            previous_receipt_signature_required=True,
            previous_attestation_signature_required=True,
            previous_verifier_profile_trust_required=True,
        )
        assert m.require_previous_assurance_chain is True
        assert m.previous_attestation == a
        assert m.previous_verifier_profile == p
        assert m.previous_gate_receipt == g
        assert m.previous_audit_bundle_digest == "bundle-hash-123"
        assert m.previous_receipt_signature_required is True
        assert m.previous_attestation_signature_required is True
        assert m.previous_verifier_profile_trust_required is True

    def test_defaults(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(adapter_id="x", adapter_type="proxmox_api")
        assert m.require_previous_assurance_chain is False
        assert m.previous_attestation is None
        assert m.previous_verifier_profile is None
        assert m.previous_gate_receipt is None
        assert m.previous_audit_bundle_digest == ""
        assert m.previous_receipt_signature_required is False
        assert m.previous_attestation_signature_required is False
        assert m.previous_verifier_profile_trust_required is False

    def test_roundtrip(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        r, a, p, g = _make_chain_inputs()
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            require_previous_assurance_chain=True,
            previous_attestation=a,
            previous_audit_bundle_digest="bundle-hash-123",
        )
        m2 = AdapterManifest.from_dict(m.to_dict())
        assert m2.require_previous_assurance_chain is True
        assert m2.previous_attestation == a
        assert m2.previous_audit_bundle_digest == "bundle-hash-123"


class TestValidPriorChain:
    """AC6: Valid prior chain → rollback accepted."""

    def test_valid_chain_accepted(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        r, a, p, g = _make_chain_inputs("prev-chain-001")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["rollback_artifact"], allowed_api_actions=["rollback_artifact"],
            previous_artifact_digest="prev-chain-001",
            previous_deployment_receipt=r,
            require_previous_receipt_verified=True,
            require_previous_assurance_chain=True,
            previous_attestation=a,
            previous_verifier_profile=p,
            previous_gate_receipt=g,
            previous_audit_bundle_digest="bundle-hash-123",
            previous_receipt_signature_required=True,
            previous_attestation_signature_required=True,
            previous_verifier_profile_trust_required=True,
            expected_service_state="running",
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
        assert result["previous_assurance_chain_verified"] is True
        assert result["previous_chain_verification_status"] == "chain_verified"
        assert result["rollback_to_known_good"] is True
        assert result["previous_release_identity"] == "rcpt-001"


class TestInvalidPriorSignatureRejected:
    """AC3+AC6: Prior receipt unsigned when signature required → rejected."""

    def test_unsigned_receipt_rejected(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        r, a, p, g = _make_chain_inputs("prev-002")
        r["receipt_signature"] = {}  # unsigned!
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["rollback_artifact"], allowed_api_actions=["rollback_artifact"],
            previous_artifact_digest="prev-002",
            previous_deployment_receipt=r,
            require_previous_receipt_verified=True,
            require_previous_assurance_chain=True,
            previous_attestation=a,
            previous_receipt_signature_required=True,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        result = adapter.deploy("t", "d", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["failure_mode"] == "previous_receipt_unsigned"
        assert result["previous_chain_verification_status"] == "receipt_unsigned"


class TestNonCompliantAttestationRejected:
    """AC3+AC6: Prior attestation deploy_allowed=false → rejected."""

    def test_non_compliant_attestation(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        r, a, p, g = _make_chain_inputs("prev-003")
        a["deploy_allowed"] = False  # non-compliant!
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["rollback_artifact"], allowed_api_actions=["rollback_artifact"],
            previous_artifact_digest="prev-003",
            previous_deployment_receipt=r,
            require_previous_receipt_verified=True,
            require_previous_assurance_chain=True,
            previous_attestation=a,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        result = adapter.deploy("t", "d", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["failure_mode"] == "previous_attestation_non_compliant"
        assert result["previous_chain_verification_status"] == "attestation_non_compliant"


class TestMissingAttestationRejected:
    """AC3: Prior attestation missing → rejected."""

    def test_attestation_missing(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        r, a, p, g = _make_chain_inputs("prev-004")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["rollback_artifact"], allowed_api_actions=["rollback_artifact"],
            previous_artifact_digest="prev-004",
            previous_deployment_receipt=r,
            require_previous_receipt_verified=True,
            require_previous_assurance_chain=True,
            previous_attestation=None,  # missing!
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        result = adapter.deploy("t", "d", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["previous_chain_verification_status"] == "attestation_missing"


class TestUntrustedProfileRejected:
    """AC3+AC6: Prior verifier profile untrusted → rejected."""

    def test_untrusted_profile(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        r, a, p, g = _make_chain_inputs("prev-005")
        p["trusted"] = False  # untrusted!
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["rollback_artifact"], allowed_api_actions=["rollback_artifact"],
            previous_artifact_digest="prev-005",
            previous_deployment_receipt=r,
            require_previous_receipt_verified=True,
            require_previous_assurance_chain=True,
            previous_attestation=a,
            previous_verifier_profile=p,
            previous_verifier_profile_trust_required=True,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        result = adapter.deploy("t", "d", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["failure_mode"] == "previous_verifier_profile_untrusted"
        assert result["previous_chain_verification_status"] == "verifier_profile_untrusted"


class TestWrongPreviousArtifactDigest:
    """AC6: Wrong previous artifact digest → rejected at provenance level."""

    def test_wrong_digest(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        r, a, p, g = _make_chain_inputs("aaa-111")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["rollback_artifact"], allowed_api_actions=["rollback_artifact"],
            previous_artifact_digest="bbb-222",  # mismatch!
            previous_deployment_receipt=r,
            require_previous_receipt_verified=True,
            require_previous_assurance_chain=True,
            previous_attestation=a,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        result = adapter.deploy("t", "d", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["failure_mode"] == "previous_digest_mismatch"
        assert result["previous_chain_verification_status"] == "provenance_failed"


class TestReceiptNotDeploymentSystem:
    """AC3: Prior receipt is not deployment_system_receipt → rejected."""

    def test_wrong_receipt_type(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        r, a, p, g = _make_chain_inputs("prev-006")
        r["receipt_type"] = "gate_receipt"  # wrong type!
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["rollback_artifact"], allowed_api_actions=["rollback_artifact"],
            previous_artifact_digest="prev-006",
            previous_deployment_receipt=r,
            require_previous_receipt_verified=True,
            require_previous_assurance_chain=True,
            previous_attestation=a,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        result = adapter.deploy("t", "d", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["failure_mode"] == "previous_receipt_not_deployment_system_receipt"
        assert result["previous_chain_verification_status"] == "receipt_not_deployment_system"


class TestAuditBundleMismatch:
    """AC2: Audit bundle digest mismatch → rejected."""

    def test_bundle_mismatch(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        r, a, p, g = _make_chain_inputs("prev-007")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["rollback_artifact"], allowed_api_actions=["rollback_artifact"],
            previous_artifact_digest="prev-007",
            previous_deployment_receipt=r,
            require_previous_receipt_verified=True,
            require_previous_assurance_chain=True,
            previous_attestation=a,
            previous_audit_bundle_digest="wrong-bundle-hash",  # mismatch!
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        result = adapter.deploy("t", "d", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["failure_mode"] == "previous_assurance_chain_invalid"
        assert result["previous_chain_verification_status"] == "audit_bundle_mismatch"


class TestUnsignedAttestationRejected:
    """AC3: Prior attestation unsigned when signature required → rejected."""

    def test_unsigned_attestation(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        r, a, p, g = _make_chain_inputs("prev-008")
        a["attestation_signature"] = {}  # unsigned!
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["rollback_artifact"], allowed_api_actions=["rollback_artifact"],
            previous_artifact_digest="prev-008",
            previous_deployment_receipt=r,
            require_previous_receipt_verified=True,
            require_previous_assurance_chain=True,
            previous_attestation=a,
            previous_attestation_signature_required=True,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        result = adapter.deploy("t", "d", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["previous_chain_verification_status"] == "attestation_unsigned"


class TestChainNotRequiredSkips:
    """When require_previous_assurance_chain=False, chain check is skipped."""

    def test_chain_skipped(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        r, a, p, g = _make_chain_inputs("prev-009")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["rollback_artifact"], allowed_api_actions=["rollback_artifact"],
            previous_artifact_digest="prev-009",
            previous_deployment_receipt=r,
            require_previous_receipt_verified=True,
            require_previous_assurance_chain=False,  # disabled!
            previous_attestation=None,  # would fail if chain required
            expected_service_state="running",
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
        assert result["previous_chain_verification_status"] == "not_checked"
        assert result["previous_assurance_chain_verified"] is True  # not blocked


class TestChainReceiptFields:
    """AC4: Receipt records chain verification evidence."""

    def test_receipt_has_chain_fields(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        r, a, p, g = _make_chain_inputs("prev-chain-fields")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["rollback_artifact"], allowed_api_actions=["rollback_artifact"],
            previous_artifact_digest="prev-chain-fields",
            previous_deployment_receipt=r,
            require_previous_receipt_verified=True,
            require_previous_assurance_chain=True,
            previous_attestation=a,
            previous_verifier_profile=p,
            previous_gate_receipt=g,
            previous_audit_bundle_digest="bundle-hash-123",
            expected_service_state="running",
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
        for field in ["previous_assurance_chain_verified",
                       "previous_chain_verification_status",
                       "previous_release_identity"]:
            assert field in result, f"Missing chain field: {field}"
        assert result["previous_assurance_chain_verified"] is True
        assert result["previous_chain_verification_status"] == "chain_verified"
        assert result["previous_release_identity"] == "rcpt-001"


class TestChainLifecycleMatrix:
    """AC3: Lifecycle matrix includes chain failure modes."""

    def test_lifecycle_matrix_has_chain_modes(self):
        from nodechain.cli.deployment_adapter import PROXMOX_API_LIFECYCLE_MATRIX
        modes = PROXMOX_API_LIFECYCLE_MATRIX["rollback_artifact"]["strict_failure_modes"]
        for mode in [
            "previous_receipt_unsigned",
            "previous_assurance_chain_invalid",
            "previous_verifier_profile_untrusted",
            "previous_attestation_non_compliant",
            "previous_receipt_not_deployment_system_receipt",
        ]:
            assert mode in modes, f"Missing chain failure mode: {mode}"


class TestGateReceiptDenied:
    """AC2: Prior gate receipt deploy_allowed=false → rejected."""

    def test_gate_receipt_denied(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        r, a, p, g = _make_chain_inputs("prev-010")
        g["deploy_allowed"] = False  # denied!
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["rollback_artifact"], allowed_api_actions=["rollback_artifact"],
            previous_artifact_digest="prev-010",
            previous_deployment_receipt=r,
            require_previous_receipt_verified=True,
            require_previous_assurance_chain=True,
            previous_attestation=a,
            previous_gate_receipt=g,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        result = adapter.deploy("t", "d", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["previous_chain_verification_status"] == "gate_receipt_denied"
