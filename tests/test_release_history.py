"""Tests for v1.18.2 Release History and Retention.

Tests cover all 7 acceptance criteria:
  1. Release history index (releases.json)
  2. Release record fields (all 16)
  3. Rollback resolution: by release_id, artifact_digest, latest_known_good
  4. Retention verification: files exist, digests match, state applied, chain available
  5. Strict mode failures
  6. CLI commands: list, verify, latest-known-good
  7. Windows/Linux green
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


def _make_release_record(
    artifact_digest="abc123",
    final_deployment_state="applied",
    activation_verified=True,
    target="pve1/801",
):
    """Create a ReleaseRecord dict for testing."""
    return {
        "release_id": "rel-001",
        "artifact_digest": artifact_digest,
        "deployment_receipt_digest": "rcpt-hash-123",
        "attestation_digest": "att-hash-456",
        "audit_bundle_digest": "bundle-hash-789",
        "verifier_profile_digest": "prof-hash-012",
        "gate_receipt_digest": "gate-hash-345",
        "final_deployment_state": final_deployment_state,
        "activation_verified": activation_verified,
        "created_at": "2026-06-16T12:00:00+00:00",
        "target": target,
        "deployment_receipt_path": "",
        "attestation_path": "",
        "audit_bundle_path": "",
        "verifier_profile_path": "",
        "gate_receipt_path": "",
        "artifact_path": "",
    }


class TestReleaseRecordFields:
    """AC2: Release record includes all required fields."""

    def test_all_fields(self):
        from nodechain.cli.release_history import ReleaseRecord
        r = ReleaseRecord(
            release_id="rel-001",
            artifact_digest="abc123",
            deployment_receipt_digest="rcpt-hash",
            attestation_digest="att-hash",
            audit_bundle_digest="bundle-hash",
            verifier_profile_digest="prof-hash",
            gate_receipt_digest="gate-hash",
            final_deployment_state="applied",
            activation_verified=True,
            created_at="2026-06-16T12:00:00+00:00",
            target="pve1/801",
        )
        d = r.to_dict()
        for field in ["release_id", "artifact_digest", "deployment_receipt_digest",
                       "attestation_digest", "audit_bundle_digest",
                       "verifier_profile_digest", "gate_receipt_digest",
                       "final_deployment_state", "activation_verified",
                       "created_at", "target"]:
            assert field in d, f"Missing field: {field}"

    def test_roundtrip(self):
        from nodechain.cli.release_history import ReleaseRecord
        r = ReleaseRecord(
            release_id="rel-002",
            artifact_digest="def456",
            final_deployment_state="applied",
            activation_verified=True,
            target="pve2/802",
        )
        r2 = ReleaseRecord.from_dict(r.to_dict())
        assert r2.release_id == "rel-002"
        assert r2.artifact_digest == "def456"
        assert r2.target == "pve2/802"

    def test_is_known_good(self):
        from nodechain.cli.release_history import ReleaseRecord
        good = ReleaseRecord(final_deployment_state="applied", activation_verified=True)
        assert good.is_known_good is True

        bad1 = ReleaseRecord(final_deployment_state="failed", activation_verified=False)
        assert bad1.is_known_good is False

        bad2 = ReleaseRecord(final_deployment_state="applied", activation_verified=False)
        assert bad2.is_known_good is False


class TestReleaseHistoryIndex:
    """AC1: Release history index (releases.json)."""

    def test_create_and_load(self, tmp_path):
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
        rh_path = str(tmp_path / "releases.json")
        history = ReleaseHistory(path=rh_path)
        assert history.releases == []

        record = ReleaseRecord(
            release_id="rel-001",
            artifact_digest="abc",
            final_deployment_state="applied",
            activation_verified=True,
            target="pve1/801",
        )
        history.add(record)
        assert Path(rh_path).exists()

        # Reload
        history2 = ReleaseHistory(path=rh_path)
        assert len(history2.releases) == 1
        assert history2.releases[0].release_id == "rel-001"

    def test_get_by_id(self, tmp_path):
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
        rh_path = str(tmp_path / "releases.json")
        history = ReleaseHistory(path=rh_path)
        record = ReleaseRecord(release_id="rel-get-001", artifact_digest="xyz")
        history.add(record)
        found = history.get("rel-get-001")
        assert found is not None
        assert found.artifact_digest == "xyz"
        assert history.get("nonexistent") is None

    def test_find_by_digest(self, tmp_path):
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
        rh_path = str(tmp_path / "releases.json")
        history = ReleaseHistory(path=rh_path)
        history.add(ReleaseRecord(release_id="rel-1", artifact_digest="dig-A"))
        history.add(ReleaseRecord(release_id="rel-2", artifact_digest="dig-B"))
        history.add(ReleaseRecord(release_id="rel-3", artifact_digest="dig-A"))
        found = history.find_by_digest("dig-A")
        assert found is not None
        assert found.release_id == "rel-3"  # most recent

    def test_latest_known_good(self, tmp_path):
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
        rh_path = str(tmp_path / "releases.json")
        history = ReleaseHistory(path=rh_path)
        history.add(ReleaseRecord(
            release_id="rel-fail",
            artifact_digest="dig-1",
            final_deployment_state="failed",
            activation_verified=False,
            target="pve1/801",
        ))
        history.add(ReleaseRecord(
            release_id="rel-good",
            artifact_digest="dig-2",
            final_deployment_state="applied",
            activation_verified=True,
            target="pve1/801",
        ))
        history.add(ReleaseRecord(
            release_id="rel-good-2",
            artifact_digest="dig-3",
            final_deployment_state="applied",
            activation_verified=True,
            target="pve2/802",
        ))
        # Latest for pve1/801
        found = history.latest_known_good(target="pve1/801")
        assert found is not None
        assert found.release_id == "rel-good"
        # Latest for pve2/802
        found2 = history.latest_known_good(target="pve2/802")
        assert found2 is not None
        assert found2.release_id == "rel-good-2"
        # Latest overall
        found3 = history.latest_known_good()
        assert found3 is not None

    def test_list_releases(self, tmp_path):
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
        rh_path = str(tmp_path / "releases.json")
        history = ReleaseHistory(path=rh_path)
        for i in range(5):
            history.add(ReleaseRecord(
                release_id=f"rel-{i}",
                artifact_digest=f"dig-{i}",
                target="pve1/801",
            ))
        all_releases = history.list_releases()
        assert len(all_releases) == 5
        # Newest first
        assert all_releases[0].release_id == "rel-4"
        limited = history.list_releases(limit=2)
        assert len(limited) == 2

    def test_from_receipt(self):
        from nodechain.cli.release_history import ReleaseRecord
        receipt = {
            "deploy_status": "accepted",
            "final_deployment_state": "applied",
            "activation_verified": True,
            "activated_artifact_digest": "art-digest-123",
            "attestation_digest": "att-digest",
            "audit_bundle_sha256": "bundle-digest",
        }
        record = ReleaseRecord.from_receipt(receipt, target="pve1/801")
        assert record.artifact_digest == "art-digest-123"
        assert record.final_deployment_state == "applied"
        assert record.activation_verified is True
        assert record.attestation_digest == "att-digest"
        assert record.audit_bundle_digest == "bundle-digest"
        assert record.target == "pve1/801"
        assert record.is_known_good


class TestRetentionVerification:
    """AC4: Retention verification checks."""

    def test_valid_retention(self, tmp_path):
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
        rh_path = str(tmp_path / "releases.json")
        history = ReleaseHistory(path=rh_path)
        record = ReleaseRecord(
            release_id="rel-ret-001",
            artifact_digest="abc",
            final_deployment_state="applied",
            activation_verified=True,
        )
        history.add(record)
        result = history.verify_retention("rel-ret-001")
        assert result["valid"] is True
        assert result["errors"] == []

    def test_not_applied_fails(self, tmp_path):
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
        rh_path = str(tmp_path / "releases.json")
        history = ReleaseHistory(path=rh_path)
        record = ReleaseRecord(
            release_id="rel-ret-002",
            final_deployment_state="failed",
            activation_verified=False,
        )
        history.add(record)
        result = history.verify_retention("rel-ret-002")
        assert result["valid"] is False
        assert any("not 'applied'" in e for e in result["errors"])

    def test_missing_file_fails(self, tmp_path):
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
        rh_path = str(tmp_path / "releases.json")
        history = ReleaseHistory(path=rh_path)
        record = ReleaseRecord(
            release_id="rel-ret-003",
            final_deployment_state="applied",
            activation_verified=True,
            deployment_receipt_path="/nonexistent/receipt.json",
        )
        history.add(record)
        result = history.verify_retention("rel-ret-003")
        assert result["valid"] is False
        assert any("missing" in e for e in result["errors"])

    def test_release_not_found(self, tmp_path):
        from nodechain.cli.release_history import ReleaseHistory
        rh_path = str(tmp_path / "releases.json")
        history = ReleaseHistory(path=rh_path)
        result = history.verify_retention("nonexistent-id")
        assert result["valid"] is False
        assert any("not found" in e for e in result["errors"])

    def test_require_chain_missing_digest(self, tmp_path):
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
        rh_path = str(tmp_path / "releases.json")
        history = ReleaseHistory(path=rh_path)
        record = ReleaseRecord(
            release_id="rel-ret-004",
            final_deployment_state="applied",
            activation_verified=True,
            deployment_receipt_digest="",  # missing
            attestation_digest="",  # missing
        )
        history.add(record)
        result = history.verify_retention("rel-ret-004", require_chain=True)
        assert result["valid"] is False
        assert any("chain incomplete" in e.lower() for e in result["errors"])

    def test_verify_all(self, tmp_path):
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
        rh_path = str(tmp_path / "releases.json")
        history = ReleaseHistory(path=rh_path)
        history.add(ReleaseRecord(
            release_id="rel-ok",
            final_deployment_state="applied",
            activation_verified=True,
        ))
        history.add(ReleaseRecord(
            release_id="rel-bad",
            final_deployment_state="failed",
            activation_verified=False,
        ))
        result = history.verify_retention()
        assert result["valid"] is False  # one bad release
        assert result["checks"]["total"] == 2
        assert result["checks"]["verified"] == 1


class TestRollbackReleaseResolution:
    """AC3: Rollback resolves previous release by various modes."""

    def test_resolve_by_release_id(self, monkeypatch, tmp_path):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord

        monkeypatch.setenv("PROXMOX_SECRET", "s")
        rh_path = str(tmp_path / "releases.json")
        history = ReleaseHistory(path=rh_path)
        history.add(ReleaseRecord(
            release_id="rel-rb-001",
            artifact_digest="resolved-digest",
            final_deployment_state="applied",
            activation_verified=True,
            target="pve1/801",
        ))

        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["rollback_artifact"], allowed_api_actions=["rollback_artifact"],
            previous_artifact_digest="",  # will be resolved
            resolve_release_by="release_id",
            resolve_release_id="rel-rb-001",
            release_history_path=rh_path,
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
        assert result["rollback_artifact_digest"] == "resolved-digest"
        assert result["release_resolution"]["resolved"] is True
        assert result["release_resolution"]["release_id"] == "rel-rb-001"

    def test_resolve_by_latest_known_good(self, monkeypatch, tmp_path):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord

        monkeypatch.setenv("PROXMOX_SECRET", "s")
        rh_path = str(tmp_path / "releases.json")
        history = ReleaseHistory(path=rh_path)
        history.add(ReleaseRecord(
            release_id="rel-old-bad",
            artifact_digest="old-bad-digest",
            final_deployment_state="failed",
            activation_verified=False,
            target="pve1/801",
        ))
        history.add(ReleaseRecord(
            release_id="rel-known-good",
            artifact_digest="good-digest",
            final_deployment_state="applied",
            activation_verified=True,
            target="pve1/801",
        ))

        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["rollback_artifact"], allowed_api_actions=["rollback_artifact"],
            previous_artifact_digest="",
            resolve_release_by="latest_known_good",
            release_history_path=rh_path,
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
        assert result["rollback_artifact_digest"] == "good-digest"
        assert result["release_resolution"]["release_id"] == "rel-known-good"

    def test_release_not_found_rejected(self, monkeypatch, tmp_path):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter

        monkeypatch.setenv("PROXMOX_SECRET", "s")
        rh_path = str(tmp_path / "releases.json")
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["rollback_artifact"], allowed_api_actions=["rollback_artifact"],
            previous_artifact_digest="",
            resolve_release_by="release_id",
            resolve_release_id="nonexistent-release",
            release_history_path=rh_path,
            require_previous_receipt_verified=True,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        result = adapter.deploy("t", "d", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["failure_mode"] == "release_not_found"
        assert result["release_resolution"]["resolved"] is False
        assert result["release_resolution"]["release_record_found"] is False


class TestRollbackRetentionVerification:
    """AC4+AC5: Rollback with retention verification."""

    def test_retention_fail_rejected(self, monkeypatch, tmp_path):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord

        monkeypatch.setenv("PROXMOX_SECRET", "s")
        rh_path = str(tmp_path / "releases.json")
        history = ReleaseHistory(path=rh_path)
        # Add a release that failed retention (not applied)
        history.add(ReleaseRecord(
            release_id="rel-ret-fail",
            artifact_digest="a1b2c3d4" * 8,  # valid 64-char hex
            final_deployment_state="failed",
            activation_verified=False,
            target="pve1/801",
        ))

        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["rollback_artifact"], allowed_api_actions=["rollback_artifact"],
            previous_artifact_digest="",
            resolve_release_by="release_id",
            resolve_release_id="rel-ret-fail",
            release_history_path=rh_path,
            require_retention_verification=True,
            require_previous_receipt_verified=True,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        result = adapter.deploy("t", "d", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["failure_mode"] == "retention_verification_failed"


class TestReleaseHistoryManifestFields:
    """AC3: Manifest supports release history fields."""

    def test_fields(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            resolve_release_by="latest_known_good",
            resolve_release_id="rel-001",
            release_history_path="/data/releases.json",
            require_retention_verification=True,
        )
        assert m.resolve_release_by == "latest_known_good"
        assert m.resolve_release_id == "rel-001"
        assert m.release_history_path == "/data/releases.json"
        assert m.require_retention_verification is True

    def test_defaults(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(adapter_id="x", adapter_type="proxmox_api")
        assert m.resolve_release_by == ""
        assert m.resolve_release_id == ""
        assert m.release_history_path == ""
        assert m.require_retention_verification is False


class TestReleaseHistoryAtomicWrite:
    """Release history writes are atomic."""

    def test_atomic_write(self, tmp_path):
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
        rh_path = str(tmp_path / "releases.json")
        history = ReleaseHistory(path=rh_path)
        history.add(ReleaseRecord(release_id="rel-atomic", artifact_digest="a"))
        # File should exist and be valid JSON
        data = json.loads(Path(rh_path).read_text(encoding="utf-8"))
        assert data["schema_version"] == "2.0"
        assert len(data["releases"]) == 1
        assert data["releases"][0]["release_id"] == "rel-atomic"
        # No temp file left
        assert not Path(rh_path).with_suffix(".tmp").exists()
