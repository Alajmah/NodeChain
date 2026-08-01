"""Tests for v1.18.2 Release History Signed Snapshots.

Tests cover all 7 acceptance criteria:
  1. nodechain release-history snapshot command
  2. Snapshot includes required fields
  3. Snapshot can be signed
  4. Snapshot verification checks all fields
  5. Strict rollback can require snapshot
  6. Receipt records snapshot evidence
  7. Windows/Linux green
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def _generate_keys(tmp_path, suffix=""):
    """Generate RSA key pair for testing."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_path = str(tmp_path / f"priv{suffix}.pem")
    pub_path = str(tmp_path / f"pub{suffix}.pem")
    Path(priv_path).write_bytes(priv_pem)
    Path(pub_path).write_bytes(pub_pem)
    return priv_path, pub_path


class TestSnapshotCreation:
    """AC1+AC2: Snapshot creation with required fields."""

    def test_snapshot_has_all_fields(self, tmp_path):
        from nodechain.cli.release_history import (
            ReleaseHistory, ReleaseRecord,
            create_release_history_snapshot,
        )
        rh_path = str(tmp_path / "rh.json")
        rh = ReleaseHistory(path=rh_path)
        rh.add(ReleaseRecord(
            release_id="r1",
            artifact_digest="a1b2c3d4" * 8,
            final_deployment_state="applied",
            activation_verified=True,
            target="pve1/801",
        ))
        out = str(tmp_path / "snap.json")
        snapshot = create_release_history_snapshot(
            output_path=out,
            history_path=rh_path,
        )
        for field in ["schema_version", "release_history_id", "entries_digest",
                       "audit_log_digest", "release_count", "target_summary",
                       "latest_known_good_summary", "created_at", "snapshot_digest"]:
            assert field in snapshot, f"Missing snapshot field: {field}"
        assert snapshot["schema_version"] == "1"
        assert snapshot["release_count"] == 1
        assert snapshot["target_summary"] == {"pve1/801": 1}
        assert snapshot["latest_known_good_summary"]["release_id"] == "r1"
        assert Path(out).exists()

    def test_snapshot_written_to_file(self, tmp_path):
        from nodechain.cli.release_history import (
            ReleaseHistory, ReleaseRecord,
            create_release_history_snapshot,
        )
        rh_path = str(tmp_path / "rh.json")
        rh = ReleaseHistory(path=rh_path)
        rh.add(ReleaseRecord(release_id="r1", artifact_digest="a" * 64))
        out = str(tmp_path / "snap.json")
        create_release_history_snapshot(output_path=out, history_path=rh_path)
        data = json.loads(Path(out).read_text(encoding="utf-8"))
        assert data["type"] == "release_history_snapshot"

    def test_snapshot_empty_history(self, tmp_path):
        from nodechain.cli.release_history import (
            ReleaseHistory, create_release_history_snapshot,
        )
        rh_path = str(tmp_path / "rh.json")
        ReleaseHistory(path=rh_path)  # creates empty history
        snapshot = create_release_history_snapshot(history_path=rh_path)
        assert snapshot["release_count"] == 0
        assert snapshot["latest_known_good_summary"] == {}


class TestSnapshotSigning:
    """AC3: Snapshot can be signed."""

    def test_signed_snapshot(self, tmp_path):
        from nodechain.cli.release_history import create_release_history_snapshot
        priv_path, pub_path = _generate_keys(tmp_path)
        rh_path = str(tmp_path / "rh.json")
        out = str(tmp_path / "snap.json")

        # Create a minimal history
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
        rh = ReleaseHistory(path=rh_path)
        rh.add(ReleaseRecord(release_id="r1", artifact_digest="a" * 64))

        snapshot = create_release_history_snapshot(
            output_path=out,
            private_key_path=priv_path,
            history_path=rh_path,
        )
        assert "snapshot_signature" in snapshot
        assert snapshot["snapshot_signature_algorithm"] == "RSA-PSS-SHA256"
        assert "snapshot_signer_fingerprint" in snapshot

    def test_unsigned_snapshot_has_no_sig(self, tmp_path):
        from nodechain.cli.release_history import (
            ReleaseHistory, ReleaseRecord,
            create_release_history_snapshot,
        )
        rh_path = str(tmp_path / "rh.json")
        rh = ReleaseHistory(path=rh_path)
        rh.add(ReleaseRecord(release_id="r1", artifact_digest="a" * 64))
        snapshot = create_release_history_snapshot(history_path=rh_path)
        assert "snapshot_signature" not in snapshot


class TestSnapshotVerification:
    """AC4: Snapshot verification checks."""

    def test_valid_snapshot_passes(self, tmp_path):
        from nodechain.cli.release_history import (
            ReleaseHistory, ReleaseRecord,
            create_release_history_snapshot,
            verify_release_history_snapshot,
        )
        rh_path = str(tmp_path / "rh.json")
        rh = ReleaseHistory(path=rh_path)
        rh.add(ReleaseRecord(
            release_id="r1", artifact_digest="a" * 64,
            final_deployment_state="applied", activation_verified=True,
        ))
        out = str(tmp_path / "snap.json")
        create_release_history_snapshot(output_path=out, history_path=rh_path)
        result = verify_release_history_snapshot(snapshot_path=out)
        assert result["valid"] is True

    def test_signed_snapshot_validates(self, tmp_path):
        from nodechain.cli.release_history import (
            ReleaseHistory, ReleaseRecord,
            create_release_history_snapshot,
            verify_release_history_snapshot,
        )
        priv_path, pub_path = _generate_keys(tmp_path)
        rh_path = str(tmp_path / "rh.json")
        rh = ReleaseHistory(path=rh_path)
        rh.add(ReleaseRecord(release_id="r1", artifact_digest="a" * 64))
        out = str(tmp_path / "snap.json")
        create_release_history_snapshot(
            output_path=out, private_key_path=priv_path, history_path=rh_path,
        )
        pubkey_pem = Path(pub_path).read_text(encoding="utf-8")
        result = verify_release_history_snapshot(
            snapshot_path=out, public_key_pem=pubkey_pem,
        )
        assert result["valid"] is True
        assert result["details"]["signature_status"] == "valid"

    def test_tampered_digest_fails(self, tmp_path):
        from nodechain.cli.release_history import (
            ReleaseHistory, ReleaseRecord,
            create_release_history_snapshot,
            verify_release_history_snapshot,
        )
        rh_path = str(tmp_path / "rh.json")
        rh = ReleaseHistory(path=rh_path)
        rh.add(ReleaseRecord(release_id="r1", artifact_digest="a" * 64))
        out = str(tmp_path / "snap.json")
        create_release_history_snapshot(output_path=out, history_path=rh_path)
        # Tamper
        data = json.loads(Path(out).read_text(encoding="utf-8"))
        data["snapshot_digest"] = "0" * 64
        Path(out).write_text(json.dumps(data), encoding="utf-8")
        result = verify_release_history_snapshot(snapshot_path=out)
        assert result["valid"] is False
        assert any("digest mismatch" in e for e in result["errors"])

    def test_bad_signature_fails(self, tmp_path):
        from nodechain.cli.release_history import (
            ReleaseHistory, ReleaseRecord,
            create_release_history_snapshot,
            verify_release_history_snapshot,
        )
        priv_path, pub_path = _generate_keys(tmp_path)
        # Generate a DIFFERENT key pair for verification
        priv_path2, pub_path2 = _generate_keys(tmp_path, suffix="2")

        rh_path = str(tmp_path / "rh.json")
        rh = ReleaseHistory(path=rh_path)
        rh.add(ReleaseRecord(release_id="r1", artifact_digest="a" * 64))
        out = str(tmp_path / "snap.json")
        create_release_history_snapshot(
            output_path=out, private_key_path=priv_path, history_path=rh_path,
        )
        # Verify with WRONG key
        wrong_pubkey = Path(pub_path2).read_text(encoding="utf-8")
        result = verify_release_history_snapshot(
            snapshot_path=out, public_key_pem=wrong_pubkey,
        )
        assert result["valid"] is False
        assert result["details"]["signature_status"] == "invalid"

    def test_signed_unverified_warning(self, tmp_path):
        from nodechain.cli.release_history import (
            ReleaseHistory, ReleaseRecord,
            create_release_history_snapshot,
            verify_release_history_snapshot,
        )
        priv_path, _ = _generate_keys(tmp_path)
        rh_path = str(tmp_path / "rh.json")
        rh = ReleaseHistory(path=rh_path)
        rh.add(ReleaseRecord(release_id="r1", artifact_digest="a" * 64))
        out = str(tmp_path / "snap.json")
        create_release_history_snapshot(
            output_path=out, private_key_path=priv_path, history_path=rh_path,
        )
        # No pubkey provided
        result = verify_release_history_snapshot(snapshot_path=out)
        assert result["valid"] is True  # still valid, just can't verify sig
        assert result["details"]["signature_status"] == "signed_unverified"
        assert any("no public key" in w for w in result["warnings"])

    def test_check_live_history_match(self, tmp_path):
        from nodechain.cli.release_history import (
            ReleaseHistory, ReleaseRecord,
            create_release_history_snapshot,
            verify_release_history_snapshot,
        )
        rh_path = str(tmp_path / "rh.json")
        rh = ReleaseHistory(path=rh_path)
        rh.add(ReleaseRecord(release_id="r1", artifact_digest="a" * 64))
        out = str(tmp_path / "snap.json")
        create_release_history_snapshot(output_path=out, history_path=rh_path)
        result = verify_release_history_snapshot(
            snapshot_path=out, check_live_history=True, history_path=rh_path,
        )
        assert result["valid"] is True
        assert result["details"]["live_entries_match"] is True

    def test_check_live_history_mismatch(self, tmp_path):
        from nodechain.cli.release_history import (
            ReleaseHistory, ReleaseRecord,
            create_release_history_snapshot,
            verify_release_history_snapshot,
        )
        rh_path = str(tmp_path / "rh.json")
        rh = ReleaseHistory(path=rh_path)
        rh.add(ReleaseRecord(release_id="r1", artifact_digest="a" * 64))
        out = str(tmp_path / "snap.json")
        create_release_history_snapshot(output_path=out, history_path=rh_path)
        # Modify history after snapshot
        rh.add(ReleaseRecord(release_id="r2", artifact_digest="b" * 64))
        result = verify_release_history_snapshot(
            snapshot_path=out, check_live_history=True, history_path=rh_path,
        )
        assert result["valid"] is False
        assert result["details"]["live_entries_match"] is False

    def test_missing_entries_digest_fails(self, tmp_path):
        from nodechain.cli.release_history import verify_release_history_snapshot
        # Manually create a bad snapshot
        bad = {"schema_version": "1", "release_history_id": "x"}
        Path(tmp_path / "bad.json").write_text(json.dumps(bad), encoding="utf-8")
        result = verify_release_history_snapshot(snapshot_path=str(tmp_path / "bad.json"))
        assert result["valid"] is False
        assert any("entries_digest" in e for e in result["errors"])


class TestStrictRollbackSnapshotRequirement:
    """AC5: Strict rollback can require snapshot."""

    def test_rollback_requires_snapshot(self, monkeypatch, tmp_path):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        from nodechain.cli.release_history import (
            ReleaseHistory, ReleaseRecord,
            create_release_history_snapshot,
        )

        monkeypatch.setenv("PROXMOX_SECRET", "s")
        rh_path = str(tmp_path / "rh.json")
        history = ReleaseHistory(path=rh_path)
        history.add(ReleaseRecord(
            release_id="rel-snap-001",
            artifact_digest="a" * 64,
            final_deployment_state="applied",
            activation_verified=True,
            target="pve1/801",
        ))
        snap_path = str(tmp_path / "snap.json")
        create_release_history_snapshot(
            output_path=snap_path, history_path=rh_path,
        )

        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["rollback_artifact"], allowed_api_actions=["rollback_artifact"],
            previous_artifact_digest="",
            resolve_release_by="release_id",
            resolve_release_id="rel-snap-001",
            release_history_path=rh_path,
            require_retention_verification=True,
            require_previous_receipt_verified=False,
            require_release_history_snapshot=True,
            release_history_snapshot_path=snap_path,
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
        assert result["release_resolution"]["snapshot_verified"] is True

    def test_rollback_rejects_invalid_snapshot(self, monkeypatch, tmp_path):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        from nodechain.cli.release_history import (
            ReleaseHistory, ReleaseRecord,
            create_release_history_snapshot,
        )

        monkeypatch.setenv("PROXMOX_SECRET", "s")
        rh_path = str(tmp_path / "rh.json")
        history = ReleaseHistory(path=rh_path)
        history.add(ReleaseRecord(
            release_id="rel-snap-002",
            artifact_digest="b" * 64,
            final_deployment_state="applied",
            activation_verified=True,
            target="pve1/801",
        ))
        snap_path = str(tmp_path / "snap.json")
        create_release_history_snapshot(
            output_path=snap_path, history_path=rh_path,
        )
        # Tamper snapshot
        data = json.loads(Path(snap_path).read_text(encoding="utf-8"))
        data["snapshot_digest"] = "0" * 64
        Path(snap_path).write_text(json.dumps(data), encoding="utf-8")

        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["rollback_artifact"], allowed_api_actions=["rollback_artifact"],
            previous_artifact_digest="",
            resolve_release_by="release_id",
            resolve_release_id="rel-snap-002",
            release_history_path=rh_path,
            require_retention_verification=True,
            require_previous_receipt_verified=False,
            require_release_history_snapshot=True,
            release_history_snapshot_path=snap_path,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        result = adapter.deploy("t", "d", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["failure_mode"] == "release_history_snapshot_invalid"


class TestSnapshotReceiptFields:
    """AC6: Rollback receipt records snapshot evidence."""

    def test_receipt_has_snapshot_fields_on_rejection(self, monkeypatch, tmp_path):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord

        monkeypatch.setenv("PROXMOX_SECRET", "s")

        # Create valid release history
        rh_path = str(tmp_path / "rh.json")
        history = ReleaseHistory(path=rh_path)
        history.add(ReleaseRecord(
            release_id="rel-snap-r",
            artifact_digest="a" * 64,
            final_deployment_state="applied",
            activation_verified=True,
            target="pve1/801",
        ))

        # Create an INVALID snapshot (tampered digest)
        bad_snap = str(tmp_path / "bad_snap.json")
        bad_data = {
            "schema_version": "1",
            "type": "release_history_snapshot",
            "release_history_id": "x",
            "entries_digest": "a" * 64,
            "audit_log_digest": "b" * 64,
            "release_count": 1,
            "target_summary": {},
            "latest_known_good_summary": {},
            "created_at": "2026-06-16T12:00:00+00:00",
            "snapshot_digest": "0" * 64,  # wrong!
        }
        Path(bad_snap).write_text(json.dumps(bad_data), encoding="utf-8")

        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["rollback_artifact"], allowed_api_actions=["rollback_artifact"],
            previous_artifact_digest="",
            resolve_release_by="release_id",
            resolve_release_id="rel-snap-r",
            release_history_path=rh_path,
            require_retention_verification=True,
            require_previous_receipt_verified=False,
            require_release_history_snapshot=True,
            release_history_snapshot_path=bad_snap,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        result = adapter.deploy("t", "d", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert "release_history_snapshot_verified" in result
        assert result["release_history_snapshot_verified"] is False


class TestSnapshotManifestFields:
    """Manifest fields for snapshots."""

    def test_fields(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            require_release_history_snapshot=True,
            release_history_snapshot_path="/data/snap.json",
        )
        assert m.require_release_history_snapshot is True
        assert m.release_history_snapshot_path == "/data/snap.json"

    def test_defaults(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(adapter_id="x", adapter_type="proxmox_api")
        assert m.require_release_history_snapshot is False
        assert m.release_history_snapshot_path == ""

    def test_roundtrip(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            require_release_history_snapshot=True,
            release_history_snapshot_path="/snap.json",
        )
        m2 = AdapterManifest.from_dict(m.to_dict())
        assert m2.require_release_history_snapshot is True
        assert m2.release_history_snapshot_path == "/snap.json"
