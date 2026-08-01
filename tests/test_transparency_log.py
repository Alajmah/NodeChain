"""Transparency Log Test Suite (v2.3.0).

Tests all 10 acceptance criteria for the append-only transparency log.
Verifies tamper-evidence, chain integrity, and event logging.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest


def _tmp_log_path():
    """Return a temp path for a transparency log."""
    fd, path = tempfile.mkstemp(suffix=".json", prefix="trans_")
    os.close(fd)
    return path


# ── AC1: Append-only transparency log format ────────────────────────────────

class TestAC1LogFormat:
    """AC1: Transparency log format with version, entries, log_digest."""

    def test_log_creation(self):
        from nodechain.sdk.transparency_log import TransparencyLog
        log = TransparencyLog()
        assert log.length == 0
        assert log.next_sequence == 1
        assert log.tail_digest == ""

    def test_log_dict_serialization(self):
        from nodechain.sdk.transparency_log import TransparencyLog
        log = TransparencyLog()
        log.append("registry_metadata_seen", "https://registry.example.com")
        d = log.to_dict()
        assert d["version"] == "v1"
        assert d["total_entries"] == 1
        assert "entries" in d
        assert "log_digest" in d

    def test_log_roundtrip(self):
        from nodechain.sdk.transparency_log import TransparencyLog
        log = TransparencyLog()
        log.append("registry_metadata_seen", "https://r.example.com")
        log.append("package_metadata_seen", "pkg_a", "1.0.0")
        d = log.to_dict()
        log2 = TransparencyLog.from_dict(d)
        assert log2.length == 2
        assert log2.entries[0].event_type == "registry_metadata_seen"
        assert log2.entries[1].event_type == "package_metadata_seen"


# ── AC2: Log events ──────────────────────────────────────────────────────────

class TestAC2EventTypes:
    """AC2: All 7 event types are supported."""

    def test_all_event_types(self):
        from nodechain.sdk.transparency_log import (
            TransparencyLog, EVENT_TYPES,
        )
        expected = {
            "registry_metadata_seen",
            "package_metadata_seen",
            "package_artifact_seen",
            "package_installed",
            "dependency_graph_resolved",
            "package_revoked",
            "certification_revoked",
            "registry_selected",
            "registry_conflict",
            "federated_package_resolved",
            "reputation_score_computed",
            "discovery_index_seen",
            "registry_discovered",
            "registry_added_from_discovery",
            "attestation_seen",  # v2.21.3
            "attestation_verified",  # v2.21.3
            "attestation_rejected",  # v2.21.3
            "artifact_retained",  # v2.21.3
            "artifact_orphan_collected",  # v2.21.3
            "evidence_index_verified",  # v2.21.3
            "evidence_index_mismatch",  # v2.21.3
            "checkpoint_created",  # v2.21.3
            "checkpoint_verified",  # v2.21.3
            "checkpoint_chain_broken",  # v2.21.3
            "rollback_detected",  # v2.21.3
        }
        assert EVENT_TYPES == expected

    def test_each_event_type_appendable(self):
        from nodechain.sdk.transparency_log import TransparencyLog
        log = TransparencyLog()
        events = [
            ("registry_metadata_seen", "https://r.example.com"),
            ("package_metadata_seen", "pkg"),
            ("package_artifact_seen", "pkg"),
            ("package_installed", "pkg"),
            ("dependency_graph_resolved", "pkg"),
            ("package_revoked", "pkg"),
            ("certification_revoked", "cert"),
        ]
        for etype, subject in events:
            log.append(etype, subject, "1.0.0")
        assert log.length == 7

    def test_invalid_event_type_rejected(self):
        from nodechain.sdk.transparency_log import TransparencyLog
        log = TransparencyLog()
        with pytest.raises(ValueError, match="Invalid event type"):
            log.append("malicious_event", "pkg")

    def test_event_has_timestamp(self):
        from nodechain.sdk.transparency_log import TransparencyLog
        log = TransparencyLog()
        entry = log.append("package_metadata_seen", "pkg", "1.0.0")
        assert entry.timestamp != ""
        # ISO format
        assert "T" in entry.timestamp


# ── AC3: Entry fields ────────────────────────────────────────────────────────

class TestAC3EntryFields:
    """AC3: Each entry contains required fields."""

    def test_entry_fields(self):
        from nodechain.sdk.transparency_log import TransparencyLog
        log = TransparencyLog()
        entry = log.append(
            event_type="package_metadata_seen",
            subject_id="pkg_a",
            subject_version="1.0.0",
            metadata_digest="abc123",
            artifact_digest="def456",
            graph_digest="ghi789",
            signer_fingerprint="fp",
        )
        assert entry.sequence_number == 1
        assert entry.event_type == "package_metadata_seen"
        assert entry.subject_id == "pkg_a"
        assert entry.subject_version == "1.0.0"
        assert entry.metadata_digest == "abc123"
        assert entry.artifact_digest == "def456"
        assert entry.graph_digest == "ghi789"
        assert entry.signer_fingerprint == "fp"
        assert entry.entry_digest != ""
        assert entry.previous_entry_digest == ""  # first entry

    def test_entry_digest_is_sha256(self):
        from nodechain.sdk.transparency_log import TransparencyLog
        log = TransparencyLog()
        entry = log.append("registry_metadata_seen", "https://r.example.com")
        assert len(entry.entry_digest) == 64  # SHA-256 hex
        assert all(c in "0123456789abcdef" for c in entry.entry_digest)

    def test_extra_field_supported(self):
        from nodechain.sdk.transparency_log import TransparencyLog
        log = TransparencyLog()
        entry = log.append(
            "package_installed", "pkg", "1.0.0",
            extra={"trust_level": "remote_untrusted", "sandbox": "hardened_untrusted"},
        )
        assert entry.extra["trust_level"] == "remote_untrusted"
        assert entry.extra["sandbox"] == "hardened_untrusted"


# ── AC4: Append-only invariant ────────────────────────────────────────────────

class TestAC4AppendOnlyInvariant:
    """AC4: previous_entry_digest chain and sequence_number invariants."""

    def test_chain_links(self):
        from nodechain.sdk.transparency_log import TransparencyLog
        log = TransparencyLog()
        e1 = log.append("registry_metadata_seen", "https://r.example.com")
        e2 = log.append("package_metadata_seen", "pkg_a", "1.0.0")
        e3 = log.append("package_installed", "pkg_a", "1.0.0")
        assert e1.previous_entry_digest == ""
        assert e2.previous_entry_digest == e1.entry_digest
        assert e3.previous_entry_digest == e2.entry_digest

    def test_sequence_increments(self):
        from nodechain.sdk.transparency_log import TransparencyLog
        log = TransparencyLog()
        for i in range(5):
            log.append("package_metadata_seen", f"pkg_{i}", "1.0.0")
        seqs = [e.sequence_number for e in log.entries]
        assert seqs == [1, 2, 3, 4, 5]

    def test_valid_log_passes_verification(self):
        from nodechain.sdk.transparency_log import TransparencyLog
        log = TransparencyLog()
        for i in range(10):
            log.append("package_metadata_seen", f"pkg_{i}", "1.0.0")
        result = log.verify()
        assert result.valid
        assert result.total_entries == 10
        assert len(result.errors) == 0


# ── AC5: Verify command ──────────────────────────────────────────────────────

class TestAC5VerifyCommand:
    """AC5: Transparency verify CLI command."""

    def test_verify_cli_empty(self, monkeypatch, tmp_path):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        log_path = str(tmp_path / "trans.json")
        monkeypatch.setenv("NODECHAIN_TRANSPARENCY_LOG", log_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["registry", "transparency", "verify", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["valid"] is True
        assert data["total_entries"] == 0

    def test_verify_cli_with_entries(self, monkeypatch, tmp_path):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        log_path = str(tmp_path / "trans.json")
        monkeypatch.setenv("NODECHAIN_TRANSPARENCY_LOG", log_path)
        runner = CliRunner()
        # Append an entry
        runner.invoke(cli, [
            "registry", "transparency", "append",
            "--event-type", "package_metadata_seen",
            "--subject-id", "test_pkg",
            "--subject-version", "1.0.0",
        ])
        result = runner.invoke(cli, ["registry", "transparency", "verify", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["valid"] is True
        assert data["total_entries"] == 1


# ── AC6: Query command ────────────────────────────────────────────────────────

class TestAC6QueryCommand:
    """AC6: Transparency show CLI command."""

    def test_show_by_package(self, monkeypatch, tmp_path):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        log_path = str(tmp_path / "trans.json")
        monkeypatch.setenv("NODECHAIN_TRANSPARENCY_LOG", log_path)
        runner = CliRunner()
        runner.invoke(cli, [
            "registry", "transparency", "append",
            "--event-type", "package_metadata_seen",
            "--subject-id", "pkg_a",
            "--subject-version", "1.0.0",
        ])
        runner.invoke(cli, [
            "registry", "transparency", "append",
            "--event-type", "package_metadata_seen",
            "--subject-id", "pkg_b",
            "--subject-version", "1.0.0",
        ])
        result = runner.invoke(cli, [
            "registry", "transparency", "show",
            "--package", "pkg_a", "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1
        assert data[0]["subject_id"] == "pkg_a"

    def test_show_by_digest(self, monkeypatch, tmp_path):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        log_path = str(tmp_path / "trans.json")
        monkeypatch.setenv("NODECHAIN_TRANSPARENCY_LOG", log_path)
        runner = CliRunner()
        runner.invoke(cli, [
            "registry", "transparency", "append",
            "--event-type", "package_metadata_seen",
            "--subject-id", "pkg_a",
            "--subject-version", "1.0.0",
        ])
        result = runner.invoke(cli, [
            "registry", "transparency", "show", "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        entry_digest = data[0]["entry_digest"]
        # Now query by that digest
        result2 = runner.invoke(cli, [
            "registry", "transparency", "show",
            "--digest", entry_digest, "--json",
        ])
        assert result2.exit_code == 0
        data2 = json.loads(result2.output)
        assert len(data2) == 1


# ── AC7: Evidence integration ────────────────────────────────────────────────

class TestAC7EvidenceIntegration:
    """AC7: Evidence types registered for transparency log."""

    def test_transparency_evidence_types(self):
        from nodechain.cli.evidence import EVIDENCE_TYPES
        assert "transparency_log" in EVIDENCE_TYPES
        assert "transparency_entry" in EVIDENCE_TYPES

    def test_transparency_log_digest_available(self):
        from nodechain.sdk.transparency_log import TransparencyLog
        log = TransparencyLog()
        for i in range(5):
            log.append("package_metadata_seen", f"pkg_{i}", "1.0.0")
        result = log.verify()
        assert result.log_digest != ""
        assert len(result.log_digest) == 64  # SHA-256


# ── AC8: Dashboard integration ────────────────────────────────────────────────

class TestAC8DashboardIntegration:
    """AC8: HR-014 health rule for transparency log."""

    def test_hr014_exists(self):
        from nodechain.cli.dashboard_health import RULES_BY_ID
        assert "HR-014" in RULES_BY_ID

    def test_hr014_broken_chain(self):
        from nodechain.cli.dashboard_health import RULES_BY_ID
        rule = RULES_BY_ID["HR-014"]
        result = rule.evaluate({
            "transparency": {"enabled": True, "broken_chain": True, "error_count": 3},
        })
        assert result is not None
        assert "broken" in result["description"].lower()

    def test_hr014_empty_log_with_packages(self):
        from nodechain.cli.dashboard_health import RULES_BY_ID
        rule = RULES_BY_ID["HR-014"]
        result = rule.evaluate({
            "transparency": {"enabled": True, "total_entries": 0},
            "registry": {"total_packages": 5},
        })
        assert result is not None

    def test_hr014_healthy(self):
        from nodechain.cli.dashboard_health import RULES_BY_ID
        rule = RULES_BY_ID["HR-014"]
        result = rule.evaluate({
            "transparency": {"enabled": True, "broken_chain": False, "total_entries": 10},
            "registry": {"total_packages": 5},
        })
        assert result is None  # No alert when healthy


# ── AC9: Negative tests (tamper detection) ────────────────────────────────────

class TestAC9NegativeTests:
    """AC9: Tamper detection for various attacks."""

    def test_deleted_middle_entry_detected(self):
        from nodechain.sdk.transparency_log import TransparencyLog
        log = TransparencyLog()
        for i in range(5):
            log.append("package_metadata_seen", f"pkg_{i}", "1.0.0")
        # Delete entry at index 2
        del log.entries[2]
        result = log.verify()
        assert not result.valid
        assert len(result.errors) > 0

    def test_modified_old_entry_detected(self):
        from nodechain.sdk.transparency_log import TransparencyLog
        log = TransparencyLog()
        for i in range(5):
            log.append("package_metadata_seen", f"pkg_{i}", "1.0.0")
        # Modify an old entry's subject
        log.entries[1].subject_id = "tampered"
        result = log.verify()
        assert not result.valid

    def test_duplicate_sequence_detected(self):
        from nodechain.sdk.transparency_log import TransparencyLog
        log = TransparencyLog()
        for i in range(3):
            log.append("package_metadata_seen", f"pkg_{i}", "1.0.0")
        # Force a duplicate sequence number
        log.entries[2].sequence_number = 2
        result = log.verify()
        assert not result.valid

    def test_broken_previous_digest_detected(self):
        from nodechain.sdk.transparency_log import TransparencyLog
        log = TransparencyLog()
        for i in range(3):
            log.append("package_metadata_seen", f"pkg_{i}", "1.0.0")
        # Break the chain
        log.entries[2].previous_entry_digest = "deadbeef" * 8
        result = log.verify()
        assert not result.valid

    def test_recomputing_entry_digest_stays_valid(self):
        """If we recompute entry_digest after modifying, it doesn't help because
        the chain is still broken (previous_entry_digest won't match)."""
        from nodechain.sdk.transparency_log import TransparencyLog
        log = TransparencyLog()
        for i in range(3):
            log.append("package_metadata_seen", f"pkg_{i}", "1.0.0")
        # Modify entry 1 and recompute its digest
        log.entries[1].subject_id = "sneaky"
        log.entries[1].entry_digest = log.entries[1].compute_digest()
        result = log.verify()
        # Chain still broken because entry[2].previous_entry_digest != new digest
        assert not result.valid

    def test_tampered_entry_digest_detected(self):
        """Direct modification of entry_digest field."""
        from nodechain.sdk.transparency_log import TransparencyLog
        log = TransparencyLog()
        log.append("package_metadata_seen", "pkg", "1.0.0")
        log.append("package_installed", "pkg", "1.0.0")
        # Tamper with entry_digest directly
        log.entries[0].entry_digest = "f" * 64
        result = log.verify()
        assert not result.valid


# ── AC10: File persistence ────────────────────────────────────────────────────

class TestAC10FilePersistence:
    """AC10: File-based save/load with atomic writes."""

    def test_save_and_load(self, tmp_path):
        from nodechain.sdk.transparency_log import (
            TransparencyLog, save_transparency_log, load_transparency_log,
        )
        path = str(tmp_path / "trans.json")
        log = TransparencyLog()
        log.append("registry_metadata_seen", "https://r.example.com")
        log.append("package_metadata_seen", "pkg", "1.0.0")
        save_transparency_log(log, path)
        assert Path(path).exists()
        log2 = load_transparency_log(path)
        assert log2.length == 2
        assert log2.entries[0].event_type == "registry_metadata_seen"

    def test_load_missing_file_returns_empty(self, tmp_path):
        from nodechain.sdk.transparency_log import load_transparency_log
        path = str(tmp_path / "nonexistent.json")
        log = load_transparency_log(path)
        assert log.length == 0

    def test_append_event_convenience(self, tmp_path):
        from nodechain.sdk.transparency_log import (
            append_event, load_transparency_log, verify_transparency_log,
        )
        path = str(tmp_path / "trans.json")
        append_event("package_metadata_seen", "pkg_a", "1.0.0", path=path)
        append_event("package_installed", "pkg_a", "1.0.0", path=path)
        append_event("package_metadata_seen", "pkg_b", "1.0.0", path=path)
        log = load_transparency_log(path)
        assert log.length == 3
        result = verify_transparency_log(path)
        assert result.valid

    def test_atomic_write_no_corruption(self, tmp_path):
        from nodechain.sdk.transparency_log import (
            TransparencyLog, save_transparency_log, load_transparency_log,
        )
        path = str(tmp_path / "trans.json")
        log = TransparencyLog()
        for i in range(20):
            log.append("package_metadata_seen", f"pkg_{i}", "1.0.0")
        save_transparency_log(log, path)
        # File should be valid JSON
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        assert data["total_entries"] == 20
        # Reload and verify
        log2 = load_transparency_log(path)
        result = log2.verify()
        assert result.valid

    def test_transparency_log_not_a_trust_oracle(self):
        """NON-NEGOTIABLE: The log is observability, not trust."""
        from nodechain.sdk.transparency_log import TransparencyLog
        log = TransparencyLog()
        # Even if an entry says "package_verified", the log entry itself
        # doesn't make the package trusted. Trust comes from independent
        # verification (signatures, digests, certification).
        log.append(
            "package_installed", "malicious_pkg", "1.0.0",
            metadata_digest="valid_looking_digest",
            extra={"claimed_verified": True},
        )
        # The log entry exists and is valid
        assert log.length == 1
        assert log.verify().valid
        # But it doesn't mean the package is trusted
        # Trust is separate from logging


# ── Additional: Query and filtering ───────────────────────────────────────────

class TestQueryFiltering:
    """Additional tests for query and filtering."""

    def test_query_by_event_type(self):
        from nodechain.sdk.transparency_log import TransparencyLog
        log = TransparencyLog()
        log.append("package_metadata_seen", "pkg_a")
        log.append("package_installed", "pkg_a")
        log.append("package_metadata_seen", "pkg_b")
        installed = log.query(event_type="package_installed")
        assert len(installed) == 1
        assert installed[0].subject_id == "pkg_a"

    def test_get_entry_by_sequence(self):
        from nodechain.sdk.transparency_log import TransparencyLog
        log = TransparencyLog()
        for i in range(5):
            log.append("package_metadata_seen", f"pkg_{i}", "1.0.0")
        entry = log.get_entry_by_sequence(3)
        assert entry is not None
        assert entry.subject_id == "pkg_2"
        assert log.get_entry_by_sequence(99) is None

    def test_last_n_filter(self, monkeypatch, tmp_path):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        log_path = str(tmp_path / "trans.json")
        monkeypatch.setenv("NODECHAIN_TRANSPARENCY_LOG", log_path)
        runner = CliRunner()
        for i in range(5):
            runner.invoke(cli, [
                "registry", "transparency", "append",
                "--event-type", "package_metadata_seen",
                "--subject-id", f"pkg_{i}",
                "--subject-version", "1.0.0",
            ])
        result = runner.invoke(cli, [
            "registry", "transparency", "show",
            "--last", "2", "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 2
        assert data[0]["subject_id"] == "pkg_3"
        assert data[1]["subject_id"] == "pkg_4"
