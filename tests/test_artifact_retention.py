"""Artifact Retention and Evidence Index Protection Tests (v2.21.3).

12 acceptance criteria.

Governing rules:
    Evidence index is derived from retained artifacts.
    Retained artifacts are not trusted merely because an index mentions them.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest


# ── AC1: Content-addressed storage ──────────────────────────────────────────

class TestAC1ContentAddressed:
    def test_retain_artifact(self, tmp_path):
        from nodechain.sdk.artifact_retention import ContentAddressedStore
        store = ContentAddressedStore(tmp_path / "store")
        content = b"hello world"
        meta = store.retain(content)
        expected_digest = hashlib.sha256(content).hexdigest()
        assert meta.digest == expected_digest
        assert meta.byte_size == len(content)
        # Verify path structure
        artifact_path = store._artifact_path(meta.digest)
        assert artifact_path.exists()
        assert meta.digest[:2] in str(artifact_path)

    def test_same_content_same_path(self, tmp_path):
        from nodechain.sdk.artifact_retention import ContentAddressedStore
        store = ContentAddressedStore(tmp_path / "store")
        m1 = store.retain(b"duplicate")
        m2 = store.retain(b"duplicate")
        assert m1.digest == m2.digest
        assert store._artifact_path(m1.digest) == store._artifact_path(m2.digest)


# ── AC2: Immutable artifact metadata ────────────────────────────────────────

class TestAC2Metadata:
    def test_metadata_fields(self, tmp_path):
        from nodechain.sdk.artifact_retention import ContentAddressedStore
        store = ContentAddressedStore(tmp_path / "store")
        meta = store.retain(
            b"content", media_type="application/json",
            producer="test", subject_ref="pkg-a",
            source_type="audit_bundle",
        )
        assert meta.media_type == "application/json"
        assert meta.producer == "test"
        assert meta.subject_ref == "pkg-a"
        assert meta.source_type == "audit_bundle"
        assert meta.retained_at != ""

    def test_metadata_serialization(self, tmp_path):
        from nodechain.sdk.artifact_retention import ContentAddressedStore, ArtifactMetadata
        store = ContentAddressedStore(tmp_path / "store")
        meta = store.retain(b"data", producer="p")
        loaded = store.get_metadata(meta.digest)
        assert loaded is not None
        assert loaded.digest == meta.digest
        assert loaded.producer == "p"


# ── AC3: Atomic writes ──────────────────────────────────────────────────────

class TestAC3AtomicWrites:
    def test_artifact_fully_written(self, tmp_path):
        from nodechain.sdk.artifact_retention import ContentAddressedStore
        store = ContentAddressedStore(tmp_path / "store")
        store.retain(b"atomic test")
        # No temp files should remain
        artifacts_dir = store.artifacts_dir
        for item in artifacts_dir.rglob(".tmp_*"):
            assert False, f"Temp file found: {item}"

    def test_index_fully_written(self, tmp_path):
        from nodechain.sdk.artifact_retention import ContentAddressedStore
        store = ContentAddressedStore(tmp_path / "store")
        store.retain(b"test")
        assert store.index_path.exists()
        # Should be valid JSON
        json.loads(store.index_path.read_text())


# ── AC4: Writer serialization ───────────────────────────────────────────────

class TestAC4WriterSerialization:
    def test_lock_file_created(self, tmp_path):
        from nodechain.sdk.artifact_retention import ContentAddressedStore
        store = ContentAddressedStore(tmp_path / "store")
        store.retain(b"data")
        assert store._lock_path.exists()


# ── AC5: Evidence index integrity ───────────────────────────────────────────

class TestAC5IndexIntegrity:
    def test_index_digest_computed(self, tmp_path):
        from nodechain.sdk.artifact_retention import ContentAddressedStore
        store = ContentAddressedStore(tmp_path / "store")
        store.retain(b"test1")
        store.retain(b"test2")
        index = store.load_index()
        assert index["index_digest"] != ""

    def test_tampered_index_detected(self, tmp_path):
        from nodechain.sdk.artifact_retention import ContentAddressedStore, RetentionError
        store = ContentAddressedStore(tmp_path / "store")
        store.retain(b"test")
        # Tamper with index
        index = store.load_index_unchecked()
        index["entries"]["fake_digest"] = {"digest": "fake", "byte_size": 0, "retained_at": "now"}
        index["index_digest"] = "old_digest"
        store.index_path.write_text(json.dumps(index, indent=2))
        with pytest.raises(RetentionError, match="mismatch"):
            store.load_index()


# ── AC6: Receipt integrity on load ──────────────────────────────────────────

class TestAC6ReceiptIntegrity:
    def test_valid_receipt_passes(self, tmp_path):
        from nodechain.sdk.artifact_retention import ContentAddressedStore
        store = ContentAddressedStore(tmp_path / "store")
        receipt = {"id": "r1", "data": "x"}
        receipt["receipt_digest"] = hashlib.sha256(
            json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        assert store.verify_receipt(receipt) is True

    def test_tampered_receipt_fails(self, tmp_path):
        from nodechain.sdk.artifact_retention import ContentAddressedStore
        store = ContentAddressedStore(tmp_path / "store")
        receipt = {"id": "r1", "data": "x", "receipt_digest": "abc123"}
        assert store.verify_receipt(receipt) is False


# ── AC7: Artifact integrity on read ─────────────────────────────────────────

class TestAC7ArtifactIntegrity:
    def test_correct_artifact_reads(self, tmp_path):
        from nodechain.sdk.artifact_retention import ContentAddressedStore
        store = ContentAddressedStore(tmp_path / "store")
        content = b"integrity test"
        meta = store.retain(content)
        loaded = store.get_artifact(meta.digest)
        assert loaded == content

    def test_corrupted_artifact_detected(self, tmp_path):
        from nodechain.sdk.artifact_retention import (
            ContentAddressedStore, ArtifactIntegrityError,
        )
        store = ContentAddressedStore(tmp_path / "store")
        meta = store.retain(b"original content")
        # Corrupt the artifact file
        path = store._artifact_path(meta.digest)
        path.write_bytes(b"corrupted content")
        with pytest.raises(ArtifactIntegrityError, match="mismatch"):
            store.get_artifact(meta.digest)


# ── AC8: Missing/orphaned artifact detection ────────────────────────────────

class TestAC8MissingOrphaned:
    def test_missing_artifact_detected(self, tmp_path):
        from nodechain.sdk.artifact_retention import ContentAddressedStore
        store = ContentAddressedStore(tmp_path / "store")
        store.retain(b"will be deleted")
        digest = store.list_artifacts()[0]
        # Delete the artifact file
        store._artifact_path(digest).unlink()
        missing = store.find_missing()
        assert digest in missing

    def test_orphaned_artifact_detected(self, tmp_path):
        from nodechain.sdk.artifact_retention import ContentAddressedStore
        store = ContentAddressedStore(tmp_path / "store")
        # Create orphaned artifact (not in index)
        orphan_content = b"orphan"
        orphan_digest = hashlib.sha256(orphan_content).hexdigest()
        orphan_path = store._artifact_path(orphan_digest)
        orphan_path.parent.mkdir(parents=True, exist_ok=True)
        orphan_path.write_bytes(orphan_content)
        orphans = store.find_orphaned()
        assert orphan_digest in orphans


# ── AC9: Retention manifest ─────────────────────────────────────────────────

class TestAC9Manifest:
    def test_manifest_generated(self, tmp_path):
        from nodechain.sdk.artifact_retention import (
            ContentAddressedStore, generate_manifest, save_manifest, load_manifest,
        )
        store = ContentAddressedStore(tmp_path / "store")
        store.retain(b"a")
        store.retain(b"b")
        manifest = generate_manifest(store, policy_profile_digest="pp_digest")
        assert manifest.artifact_count == 2
        assert manifest.manifest_digest != ""

        path = str(tmp_path / "manifest.json")
        digest = save_manifest(manifest, path)
        loaded = load_manifest(path)
        assert loaded.artifact_count == 2
        assert loaded.manifest_digest == manifest.manifest_digest

    def test_tampered_manifest_detected(self, tmp_path):
        from nodechain.sdk.artifact_retention import (
            ContentAddressedStore, generate_manifest, save_manifest, load_manifest,
            RetentionError,
        )
        store = ContentAddressedStore(tmp_path / "store")
        store.retain(b"test")
        manifest = generate_manifest(store)
        path = str(tmp_path / "manifest.json")
        save_manifest(manifest, path)
        # Tamper
        data = json.loads(Path(path).read_text())
        data["artifact_count"] = 99
        Path(path).write_text(json.dumps(data, indent=2))
        with pytest.raises(RetentionError, match="mismatch"):
            load_manifest(path)


# ── AC10: Safe garbage collection ───────────────────────────────────────────

class TestAC10GC:
    def test_gc_collects_orphans(self, tmp_path):
        from nodechain.sdk.artifact_retention import (
            ContentAddressedStore, collect_orphans,
        )
        store = ContentAddressedStore(tmp_path / "store")
        store.retain(b"indexed")
        # Add orphan
        orphan_content = b"orphan data"
        orphan_digest = hashlib.sha256(orphan_content).hexdigest()
        orphan_path = store._artifact_path(orphan_digest)
        orphan_path.parent.mkdir(parents=True, exist_ok=True)
        orphan_path.write_bytes(orphan_content)

        receipt = collect_orphans(store)
        assert receipt.artifacts_removed == 1
        assert orphan_digest in receipt.orphaned_collected
        assert not orphan_path.exists()
        assert receipt.receipt_digest != ""

    def test_gc_never_deletes_referenced(self, tmp_path):
        from nodechain.sdk.artifact_retention import (
            ContentAddressedStore, collect_orphans,
        )
        store = ContentAddressedStore(tmp_path / "store")
        meta = store.retain(b"important")
        collect_orphans(store)
        # Referenced artifact must still exist
        assert store._artifact_path(meta.digest).exists()


# ── AC11: Path safety ───────────────────────────────────────────────────────

class TestAC11PathSafety:
    def test_traversal_rejected(self, tmp_path):
        from nodechain.sdk.artifact_retention import validate_object_path, PathSafetyError
        base = tmp_path / "base"
        base.mkdir()
        malicious = base / ".." / ".." / "etc" / "passwd"
        with pytest.raises(PathSafetyError):
            validate_object_path(base, malicious)

    def test_symlink_rejected(self, tmp_path):
        from nodechain.sdk.artifact_retention import validate_object_path, PathSafetyError
        base = tmp_path / "base"
        base.mkdir()
        target = tmp_path / "outside.txt"
        target.write_text("data")
        link = base / "link.txt"
        try:
            link.symlink_to(target)
            with pytest.raises(PathSafetyError):
                validate_object_path(base, link)
        except OSError:
            pass  # symlinks may not work on all platforms


# ── AC12: Full integrity verification ───────────────────────────────────────

class TestAC12FullVerification:
    def test_verify_all_healthy(self, tmp_path):
        from nodechain.sdk.artifact_retention import ContentAddressedStore
        store = ContentAddressedStore(tmp_path / "store")
        store.retain(b"a")
        store.retain(b"b")
        result = store.verify_integrity()
        assert result["valid"]
        assert result["index_verified"]
        assert result["artifacts_checked"] == 2
        assert result["orphans"] == []
        assert result["missing"] == []

    def test_verify_finds_issues(self, tmp_path):
        from nodechain.sdk.artifact_retention import ContentAddressedStore
        store = ContentAddressedStore(tmp_path / "store")
        meta = store.retain(b"data")
        # Corrupt the artifact
        store._artifact_path(meta.digest).write_bytes(b"corrupt")
        result = store.verify_integrity()
        assert not result["valid"]
        assert meta.digest in result["artifacts_failed"]


# ── Profile fields ──────────────────────────────────────────────────────────

class TestProfileFields:
    def test_new_fields_exist(self):
        from nodechain.sdk.org_policy import OrganizationTrustPolicyProfile
        p = OrganizationTrustPolicyProfile(name="t", description="t")
        assert hasattr(p, "require_evidence_index_verification")
        assert hasattr(p, "artifact_retention_policy_id")

    def test_strict_profile_enables_verification(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        p = get_builtin_profile("strict_enterprise")
        assert p.require_evidence_index_verification is True

    def test_profile_roundtrip(self):
        from nodechain.sdk.org_policy import get_builtin_profile, list_builtin_profiles
        for name in list_builtin_profiles():
            p = get_builtin_profile(name)
            d = p.to_dict()
            p2 = type(p).from_dict(d)
            assert p2.require_evidence_index_verification == p.require_evidence_index_verification
            assert p2.compute_digest() == p.compute_digest()


# ── Runtime integration ────────────────────────────────────────────────────

class TestRuntimeIntegration:
    def test_health_rules_count(self):
        from nodechain.cli.dashboard_health import ALL_RULES
        assert len(ALL_RULES) == 65  # 49 HR + 5 MEM + 6 SE + 5 MR (v2.41.0)

    def test_evidence_types(self):
        from nodechain.cli.evidence import EVIDENCE_TYPES
        assert "retention_manifest" in EVIDENCE_TYPES
        assert "garbage_collection_receipt" in EVIDENCE_TYPES

    def test_transparency_events(self):
        from nodechain.sdk.transparency_log import EVENT_TYPES
        assert "artifact_retained" in EVENT_TYPES
        assert "evidence_index_verified" in EVENT_TYPES
        assert "evidence_index_mismatch" in EVENT_TYPES

    def test_cli_group(self):
        from nodechain.cli.main import cli
        assert "retention" in cli.commands
        ret = cli.commands["retention"]
        assert "retain" in ret.commands
        assert "verify" in ret.commands
        assert "manifest" in ret.commands
        assert "gc" in ret.commands
        assert "list" in ret.commands

    def test_frozen_surface(self):
        from nodechain.cli.main import cli
        assert "retention" in cli.commands
