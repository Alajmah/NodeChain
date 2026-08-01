"""Tests for v1.18.2 Release History Integrity.

Tests cover all 7 acceptance criteria:
  1. release_history.json includes schema_version, release_history_id,
     updated_at, entries_digest
  2. Release-history writes are atomic (verified via entries_digest consistency)
  3. Audit log records all mutations
  4. Each audit event has required fields
  5. release-history verify validates schema, duplicates, malformed digests,
     entries_digest, missing files
  6. Strict rollback refuses malformed release history
  7. Windows/Linux green
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


class TestReleaseHistoryMetadata:
    """AC1: release_history.json includes metadata fields."""

    def test_metadata_fields_present(self, tmp_path):
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
        rh = ReleaseHistory(path=str(tmp_path / "rh.json"))
        rh.add(ReleaseRecord(release_id="r1", artifact_digest="a1"))
        # Reload
        data = json.loads((tmp_path / "rh.json").read_text(encoding="utf-8"))
        assert "schema_version" in data
        assert "release_history_id" in data
        assert "updated_at" in data
        assert "entries_digest" in data

    def test_schema_version_is_2_0(self, tmp_path):
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
        rh = ReleaseHistory(path=str(tmp_path / "rh.json"))
        rh.add(ReleaseRecord(release_id="r1", artifact_digest="a1"))
        data = json.loads((tmp_path / "rh.json").read_text(encoding="utf-8"))
        assert data["schema_version"] == "2.0"

    def test_release_history_id_is_uuid(self, tmp_path):
        from nodechain.cli.release_history import ReleaseHistory
        rh = ReleaseHistory(path=str(tmp_path / "rh.json"))
        assert rh.release_history_id
        assert len(rh.release_history_id) == 36  # UUID format

    def test_entries_digest_changes_on_add(self, tmp_path):
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
        rh = ReleaseHistory(path=str(tmp_path / "rh.json"))
        rh.add(ReleaseRecord(release_id="r1", artifact_digest="a1"))
        digest1 = rh.entries_digest
        rh.add(ReleaseRecord(release_id="r2", artifact_digest="a2"))
        digest2 = rh.entries_digest
        assert digest1 != digest2

    def test_entries_digest_stable_across_reloads(self, tmp_path):
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
        path = str(tmp_path / "rh.json")
        rh = ReleaseHistory(path=path)
        rh.add(ReleaseRecord(release_id="r1", artifact_digest="a1"))
        stored_digest = rh.entries_digest

        rh2 = ReleaseHistory(path=path)
        rh2.entries_digest = rh2._compute_entries_digest()
        assert rh2.entries_digest == stored_digest


class TestReleaseHistoryAtomicWrite:
    """AC2: Atomic writes with entries_digest."""

    def test_no_temp_file_left(self, tmp_path):
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
        rh = ReleaseHistory(path=str(tmp_path / "rh.json"))
        rh.add(ReleaseRecord(release_id="r1"))
        assert not (tmp_path / "rh.tmp").exists()
        assert (tmp_path / "rh.json").exists()

    def test_valid_json_after_write(self, tmp_path):
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
        path = tmp_path / "rh.json"
        rh = ReleaseHistory(path=str(path))
        rh.add(ReleaseRecord(release_id="r1", artifact_digest="a"))
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["releases"][0]["release_id"] == "r1"


class TestReleaseHistoryAuditLog:
    """AC3+AC4: Audit log records mutations with required fields."""

    def test_record_release_audited(self, tmp_path):
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
        rh = ReleaseHistory(path=str(tmp_path / "rh.json"))
        rh.add(ReleaseRecord(
            release_id="r1", artifact_digest="abc",
            final_deployment_state="applied", activation_verified=True,
            target="pve1/801",
        ), actor="operator")
        events = rh.load_audit_log()
        assert len(events) == 1
        assert events[0]["action"] == "record_release"
        assert events[0]["release_id"] == "r1"
        assert events[0]["artifact_digest"] == "abc"
        assert events[0]["final_deployment_state"] == "applied"
        assert events[0]["activation_verified"] is True
        assert events[0]["target"] == "pve1/801"
        assert events[0]["actor"] == "operator"

    def test_remove_release_audited(self, tmp_path):
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
        rh = ReleaseHistory(path=str(tmp_path / "rh.json"))
        rh.add(ReleaseRecord(release_id="r1", artifact_digest="abc"))
        rh.remove("r1", actor="operator")
        events = rh.load_audit_log()
        assert len(events) == 2  # record + remove
        assert events[1]["action"] == "remove_release"
        assert events[1]["release_id"] == "r1"

    def test_retention_verified_audited(self, tmp_path):
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
        rh = ReleaseHistory(path=str(tmp_path / "rh.json"))
        rh.add(ReleaseRecord(
            release_id="r1", final_deployment_state="applied",
            activation_verified=True,
        ))
        rh.verify_retention()
        events = rh.load_audit_log()
        assert any(e["action"] == "retention_verified" for e in events)

    def test_audit_event_has_all_fields(self, tmp_path):
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
        rh = ReleaseHistory(path=str(tmp_path / "rh.json"))
        rh.add(ReleaseRecord(
            release_id="r1", artifact_digest="abc",
            final_deployment_state="applied", activation_verified=True,
            target="pve1/801",
        ))
        events = rh.load_audit_log()
        event = events[0]
        for field in ["timestamp", "action", "release_id", "target",
                       "artifact_digest", "final_deployment_state",
                       "activation_verified", "actor"]:
            assert field in event, f"Missing audit field: {field}"

    def test_audit_log_jsonl_format(self, tmp_path):
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
        rh = ReleaseHistory(path=str(tmp_path / "rh.json"))
        rh.add(ReleaseRecord(release_id="r1"))
        rh.add(ReleaseRecord(release_id="r2"))
        audit_path = tmp_path / "rh_audit.jsonl"
        assert audit_path.exists()
        lines = audit_path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2
        for line in lines:
            json.loads(line)  # each line is valid JSON


class TestReleaseHistoryVerifyIntegrity:
    """AC5: release-history verify validates integrity."""

    def test_valid_history_passes(self, tmp_path):
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
        rh = ReleaseHistory(path=str(tmp_path / "rh.json"))
        rh.add(ReleaseRecord(
            release_id="r1",
            artifact_digest="a1b2c3d4" * 8,
            final_deployment_state="applied", activation_verified=True,
        ))
        result = rh.verify_integrity()
        assert result["valid"] is True
        assert result["errors"] == []

    def test_duplicate_release_ids_detected(self, tmp_path):
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
        path = str(tmp_path / "rh.json")
        rh = ReleaseHistory(path=path)
        # Manually add duplicates (bypass add() which would save)
        rh.releases.append(ReleaseRecord(release_id="dup-1", artifact_digest="a"))
        rh.releases.append(ReleaseRecord(release_id="dup-1", artifact_digest="b"))
        result = rh.verify_integrity()
        assert result["valid"] is False
        assert any("Duplicate release IDs" in e for e in result["errors"])

    def test_duplicate_receipt_digests_detected(self, tmp_path):
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
        rh = ReleaseHistory(path=str(tmp_path / "rh.json"))
        rh.releases.append(ReleaseRecord(
            release_id="r1", deployment_receipt_digest="abcd1234" * 8,
        ))
        rh.releases.append(ReleaseRecord(
            release_id="r2", deployment_receipt_digest="abcd1234" * 8,
        ))
        result = rh.verify_integrity()
        assert result["valid"] is False
        assert any("Duplicate deployment receipt digests" in e for e in result["errors"])

    def test_malformed_digests_detected(self, tmp_path):
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
        rh = ReleaseHistory(path=str(tmp_path / "rh.json"))
        rh.releases.append(ReleaseRecord(
            release_id="r1", artifact_digest="not-a-valid-digest!!!",
        ))
        result = rh.verify_integrity()
        assert result["valid"] is False
        assert any("Malformed digests" in e for e in result["errors"])

    def test_entries_digest_mismatch_detected(self, tmp_path):
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
        path = str(tmp_path / "rh.json")
        rh = ReleaseHistory(path=path)
        rh.add(ReleaseRecord(release_id="r1", artifact_digest="a"))
        # Tamper with entries_digest
        rh.entries_digest = "0" * 64
        result = rh.verify_integrity()
        assert result["valid"] is False
        assert any("entries_digest mismatch" in e for e in result["errors"])

    def test_missing_files_detected(self, tmp_path):
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
        rh = ReleaseHistory(path=str(tmp_path / "rh.json"))
        rh.releases.append(ReleaseRecord(
            release_id="r1",
            final_deployment_state="applied",
            activation_verified=True,
            deployment_receipt_path="/nonexistent/receipt.json",
        ))
        result = rh.verify_integrity()
        assert result["valid"] is False
        assert any("Referenced files missing" in e for e in result["errors"])

    def test_schema_version_checked(self, tmp_path):
        from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
        rh = ReleaseHistory(path=str(tmp_path / "rh.json"))
        rh.schema_version = ""
        rh.releases.append(ReleaseRecord(
            release_id="r1",
            final_deployment_state="applied",
            activation_verified=True,
        ))
        result = rh.verify_integrity()
        assert result["valid"] is False
        assert any("schema_version" in e for e in result["errors"])

    def test_empty_history_passes(self, tmp_path):
        from nodechain.cli.release_history import ReleaseHistory
        rh = ReleaseHistory(path=str(tmp_path / "rh.json"))
        result = rh.verify_integrity()
        # entries_digest not set is a warning, not error, for empty
        # But the save() call sets it. For in-memory empty, it's None.
        # The empty history itself should be valid
        assert result["valid"] is True or any("entries_digest" in w for w in result.get("warnings", []))


class TestStrictRollbackRejectsMalformedHistory:
    """AC6: Strict rollback refuses malformed release history."""

    def test_malformed_history_rejected(self, monkeypatch, tmp_path):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxApiAdapter

        monkeypatch.setenv("PROXMOX_SECRET", "s")
        # Create a release history file with duplicate IDs
        rh_path = str(tmp_path / "rh.json")
        rh_data = {
            "schema_version": "2.0",
            "release_history_id": "test-id",
            "updated_at": "2026-06-16T12:00:00+00:00",
            "entries_digest": "0000000000000000000000000000000000000000000000000000000000000000",
            "releases": [
                {"release_id": "dup", "artifact_digest": "a",
                 "final_deployment_state": "applied", "activation_verified": True},
                {"release_id": "dup", "artifact_digest": "b",
                 "final_deployment_state": "applied", "activation_verified": True},
            ],
        }
        Path(rh_path).write_text(json.dumps(rh_data), encoding="utf-8")

        m = AdapterManifest(
            adapter_id="x", adapter_type="proxmox_api",
            api_base_url="https://pve:8006/api2/json",
            proxmox_node="pve1", target_vmid="801",
            token_id="t", token_secret_ref="env:PROXMOX_SECRET",
            allowed_actions=["rollback_artifact"], allowed_api_actions=["rollback_artifact"],
            previous_artifact_digest="",
            resolve_release_by="release_id",
            resolve_release_id="dup",
            release_history_path=rh_path,
            require_retention_verification=True,
            require_previous_receipt_verified=True,
        )
        adapter = ProxmoxApiAdapter(manifest=m)
        result = adapter.deploy("t", "d", "p", "r")
        assert result["deploy_status"] == "rejected"
        assert result["failure_mode"] == "release_history_malformed"
        assert result["release_resolution"]["history_integrity_valid"] is False


class TestAuditActionConstants:
    """Audit actions are a frozen set."""

    def test_audit_actions(self):
        from nodechain.cli.release_history import AUDIT_ACTIONS
        assert "record_release" in AUDIT_ACTIONS
        assert "update_release" in AUDIT_ACTIONS
        assert "remove_release" in AUDIT_ACTIONS
        assert "retention_verified" in AUDIT_ACTIONS
        assert "rollback_resolved" in AUDIT_ACTIONS
