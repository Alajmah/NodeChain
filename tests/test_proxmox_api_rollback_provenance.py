"""Tests for v1.18.2 Rollback Provenance.

Tests cover all 7 acceptance criteria:
  1. Manifest supports provenance fields
  2. Rollback verifies prior receipt exists and matches
  3. Prior receipt must show applied + activation_verified + digest match
  4. Receipt records provenance evidence
  5. Strict mode fails for missing/invalid/mismatched prior receipt
  6. Tests cover: verified release, unverified artifact, failed deployment, digest mismatch
  7. Windows/Linux green
"""

from __future__ import annotations


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
            previous_deployment_receipt=None,
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
            previous_deployment_receipt_digest="0000000000000000",
            require_previous_receipt_verified=True,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        result = adapter.deploy("t", "d", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["failure_mode"] == "previous_receipt_invalid"
        assert result["rollback_provenance_status"] == "receipt_invalid"


class TestRollbackToUnverifiedArtifactRejected:
    """AC6: Rollback to unverified artifact — activation_verified=false."""

    def test_unverified_activation_rejected(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        prior = _make_verified_receipt("prev-123")
        prior["activation_verified"] = False
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
        assert result["rollback_provenance_status"] == "activation_not_verified"


class TestRollbackToFailedPriorDeploymentRejected:
    """AC6: Rollback to failed prior deployment — final_deployment_state != applied."""

    def test_failed_prior_state_rejected(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        prior = _make_verified_receipt("prev-123")
        prior["final_deployment_state"] = "failed"
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
        assert result["failure_mode"] == "previous_release_not_applied"
        assert result["rollback_provenance_status"] == "release_not_applied"


class TestRollbackArtifactDigestMismatchRejected:
    """AC6: Rollback target digest doesn't match prior receipt artifact digest."""

    def test_digest_mismatch_rejected(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        prior = _make_verified_receipt("aaa-111")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["rollback_artifact"], allowed_api_actions=["rollback_artifact"],
            previous_artifact_digest="bbb-222",
            previous_deployment_receipt=prior,
            require_previous_receipt_verified=True,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        result = adapter.deploy("t", "d", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["failure_mode"] == "previous_digest_mismatch"
        assert result["rollback_provenance_status"] == "digest_mismatch"


class TestRollbackProvenanceOptional:
    """When require_previous_receipt_verified=False, provenance is skipped."""

    def test_provenance_skipped(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["rollback_artifact"], allowed_api_actions=["rollback_artifact"],
            previous_artifact_digest="prev-123",
            previous_deployment_receipt=None,
            require_previous_receipt_verified=False,
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
        assert result["rollback_provenance_status"] == "not_checked"
        assert result["rollback_to_known_good"] is True


class TestRollbackProvenanceReceiptFields:
    """AC4: Receipt records provenance evidence fields."""

    def test_receipt_has_provenance_fields(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        prior = _make_verified_receipt("prev-xyz-789")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["rollback_artifact"], allowed_api_actions=["rollback_artifact"],
            previous_artifact_digest="prev-xyz-789",
            previous_deployment_receipt=prior,
            require_previous_receipt_verified=True,
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
        for field in ["previous_deployment_receipt_digest",
                       "previous_release_verified",
                       "rollback_to_known_good",
                       "rollback_provenance_status"]:
            assert field in result, f"Missing provenance field: {field}"
        assert result["previous_release_verified"] is True
        assert result["rollback_to_known_good"] is True
        assert result["rollback_provenance_status"] == "verified"


class TestRollbackProvenanceLifecycleMatrix:
    """AC5: Lifecycle matrix includes provenance failure modes."""

    def test_lifecycle_matrix_has_provenance_modes(self):
        from nodechain.cli.deployment_adapter import PROXMOX_API_LIFECYCLE_MATRIX
        modes = PROXMOX_API_LIFECYCLE_MATRIX["rollback_artifact"]["strict_failure_modes"]
        for mode in [
            "previous_receipt_missing",
            "previous_receipt_invalid",
            "previous_digest_mismatch",
            "previous_release_not_applied",
            "previous_activation_not_verified",
        ]:
            assert mode in modes, f"Missing failure mode: {mode}"


class TestRollbackProvenanceCorrectDigest:
    """Full path with correct digest verification."""

    def test_correct_digest_passes(self, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter, _sha256_dict
        monkeypatch.setenv("PROXMOX_SECRET", "s")
        prior = _make_verified_receipt("prev-correct-456")
        correct_digest = _sha256_dict(prior)
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["rollback_artifact"], allowed_api_actions=["rollback_artifact"],
            previous_artifact_digest="prev-correct-456",
            previous_deployment_receipt=prior,
            previous_deployment_receipt_digest=correct_digest,
            require_previous_receipt_verified=True,
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
        assert result["rollback_provenance_status"] == "verified"
        assert result["rollback_to_known_good"] is True
        assert result["previous_deployment_receipt_digest"] == correct_digest
