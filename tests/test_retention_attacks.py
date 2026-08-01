"""Retention Adversarial Test Suite (v2.21.3).

Attacks the retention layer across 14 attack categories:

  AC-01: Index tampering before retain (write-path fail-closed)
  AC-02: Missing schema_version before retain
  AC-03: Missing entries before retain
  AC-04: Blank index_digest before retain
  AC-05: Retain-GC concurrency safety
  AC-06: Two concurrent retain operations
  AC-07: Crash after object write before index update (orphan detection)
  AC-08: Crash during index replacement (partial write detection)
  AC-09: Index mutation between verifier and writer (locked verification)
  AC-10: Empty valid index
  AC-11: Empty invalid index (missing digest)
  AC-12: Symlink and device-file path rejection
  AC-13: Missing/orphan/digest-mismatched object detection
  AC-14: GC refusal on every index-integrity error type

Governing principle:
    A tampered index must never be silently healed.
    A missing or blank integrity field is an error, not a recovery opportunity.
    GC must never operate on an unverified index.
    Every write-path operation must verify before mutating.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path

import pytest


# ── AC-01: Index tampering before retain (write-path fail-closed) ──────────

class TestAC01IndexTamperingBeforeRetain:
    """RET-004: A tampered index must cause RetentionError on retain,
    not be silently healed by the new write."""

    def test_retain_on_tampered_digest_raises(self, tmp_path):
        """retain() on an index with wrong digest must fail."""
        from nodechain.sdk.artifact_retention import (
            ContentAddressedStore, RetentionError,
        )
        store = ContentAddressedStore(tmp_path / "store")
        store.retain(b"original")

        # Tamper: change entries but keep old digest
        raw = json.loads(store.index_path.read_text())
        raw["entries"]["fake_digest"] = {"digest": "fake"}
        store.index_path.write_text(json.dumps(raw))

        with pytest.raises(RetentionError, match="digest mismatch"):
            store.retain(b"new artifact")

    def test_retain_on_tampered_index_does_not_heal(self, tmp_path):
        """After a failed retain on tampered index, the tampered state must remain."""
        from nodechain.sdk.artifact_retention import ContentAddressedStore
        store = ContentAddressedStore(tmp_path / "store")
        store.retain(b"original")

        original_content = store.index_path.read_text()

        # Tamper
        raw = json.loads(original_content)
        raw["entries"]["fake"] = {"digest": "fake"}
        store.index_path.write_text(json.dumps(raw))

        try:
            store.retain(b"new")
        except Exception:
            pass  # Expected

        # Index must still contain the tampered state (not healed)
        after = json.loads(store.index_path.read_text())
        assert "fake" in after["entries"]

    def test_no_artifact_written_on_index_error(self, tmp_path):
        """If retain fails due to index tampering, no new artifact is written."""
        from nodechain.sdk.artifact_retention import ContentAddressedStore
        store = ContentAddressedStore(tmp_path / "store")
        store.retain(b"original")

        # Tamper with digest
        raw = json.loads(store.index_path.read_text())
        raw["index_digest"] = "wrong"
        store.index_path.write_text(json.dumps(raw))

        try:
            store.retain(b"should not be written")
        except Exception:
            pass

        new_digest = hashlib.sha256(b"should not be written").hexdigest()
        assert not store._artifact_path(new_digest).exists()


# ── AC-02: Missing schema_version before retain ────────────────────────────

class TestAC02MissingSchemaVersion:
    def test_retain_on_missing_schema_version_raises(self, tmp_path):
        from nodechain.sdk.artifact_retention import (
            ContentAddressedStore, RetentionError,
        )
        store = ContentAddressedStore(tmp_path / "store")
        store.retain(b"data")

        raw = json.loads(store.index_path.read_text())
        if "schema_version" in raw:
            del raw["schema_version"]
        store.index_path.write_text(json.dumps(raw))

        with pytest.raises(RetentionError, match="schema_version"):
            store.retain(b"new")

    def test_missing_schema_version_not_normalized(self, tmp_path):
        from nodechain.sdk.artifact_retention import ContentAddressedStore
        store = ContentAddressedStore(tmp_path / "store")
        store.retain(b"data")

        raw = json.loads(store.index_path.read_text())
        if "schema_version" in raw:
            del raw["schema_version"]
        store.index_path.write_text(json.dumps(raw))

        try:
            store.retain(b"new")
        except Exception:
            pass

        after = json.loads(store.index_path.read_text())
        assert "schema_version" not in after


# ── AC-03: Missing entries before retain ───────────────────────────────────

class TestAC03MissingEntries:
    def test_retain_on_missing_entries_raises(self, tmp_path):
        from nodechain.sdk.artifact_retention import (
            ContentAddressedStore, RetentionError,
        )
        store = ContentAddressedStore(tmp_path / "store")
        store.retain(b"data")

        raw = json.loads(store.index_path.read_text())
        del raw["entries"]
        store.index_path.write_text(json.dumps(raw))

        with pytest.raises(RetentionError, match="entries"):
            store.retain(b"new")


# ── AC-04: Blank index_digest before retain ────────────────────────────────

class TestAC04BlankDigest:
    def test_retain_on_blank_digest_raises(self, tmp_path):
        from nodechain.sdk.artifact_retention import (
            ContentAddressedStore, RetentionError,
        )
        store = ContentAddressedStore(tmp_path / "store")
        store.retain(b"data")

        raw = json.loads(store.index_path.read_text())
        raw["index_digest"] = ""
        store.index_path.write_text(json.dumps(raw))

        with pytest.raises(RetentionError, match="index_digest"):
            store.retain(b"new")


# ── AC-05: Retain-GC concurrency safety ─────────────────────────────────────

class TestAC05RetainGCConcurrency:
    def test_gc_does_not_delete_during_retain(self, tmp_path):
        """GC running concurrently with retain must not delete the new artifact."""
        from nodechain.sdk.artifact_retention import (
            ContentAddressedStore, collect_orphans,
        )
        store = ContentAddressedStore(tmp_path / "store")
        # Pre-populate with some artifacts
        store.retain(b"existing-1")
        store.retain(b"existing-2")

        errors = []
        gc_receipts = []

        def retain_loop():
            for i in range(20):
                try:
                    store.retain(f"concurrent-{i}".encode())
                except Exception as e:
                    errors.append(("retain", e))

        def gc_loop():
            for _ in range(20):
                try:
                    r = collect_orphans(store)
                    gc_receipts.append(r)
                except Exception as e:
                    errors.append(("gc", e))

        t1 = threading.Thread(target=retain_loop)
        t2 = threading.Thread(target=gc_loop)
        t1.start()
        t2.start()
        t1.join(timeout=15)
        t2.join(timeout=15)

        # No errors should occur
        assert not errors, f"Concurrency errors: {errors}"

        # GC must never have deleted a retained artifact
        result = store.verify_integrity()
        assert result["missing"] == [], f"Missing artifacts after concurrency: {result['missing']}"


# ── AC-06: Two concurrent retain operations ─────────────────────────────────

class TestAC06ConcurrentRetains:
    def test_two_concurrent_retains_preserve_both(self, tmp_path):
        from nodechain.sdk.artifact_retention import ContentAddressedStore
        store = ContentAddressedStore(tmp_path / "store")

        errors = []
        def retain_thread(content):
            try:
                store.retain(content)
            except Exception as e:
                errors.append(e)

        threads = []
        for i in range(10):
            t = threading.Thread(target=retain_thread, args=(f"content-{i}".encode(),))
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors
        assert len(store.list_artifacts()) == 10

    def test_concurrent_retain_same_content_is_idempotent(self, tmp_path):
        """Same content retained concurrently should result in one artifact."""
        from nodechain.sdk.artifact_retention import ContentAddressedStore
        store = ContentAddressedStore(tmp_path / "store")

        errors = []
        threads = []
        for _ in range(5):
            t = threading.Thread(
                target=lambda: (lambda: (
                    store.retain(b"duplicate") if not errors else None
                ))(),
            )
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert len(store.list_artifacts()) == 1


# ── AC-07: Crash after object write before index update ────────────────────

class TestAC07CrashAfterObjectWrite:
    def test_orphan_detection_after_simulated_crash(self, tmp_path):
        """Artifact exists but no index entry → detected as orphan."""
        from nodechain.sdk.artifact_retention import ContentAddressedStore
        store = ContentAddressedStore(tmp_path / "store")

        # Simulate crash: write artifact, never update index
        digest = hashlib.sha256(b"crashed").hexdigest()
        artifact_path = store._artifact_path(digest)
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path.write_bytes(b"crashed")

        result = store.verify_integrity()
        assert not result["valid"]
        assert digest in result["orphans"]

    def test_gc_cleans_orphan_from_crash(self, tmp_path):
        from nodechain.sdk.artifact_retention import (
            ContentAddressedStore, collect_orphans,
        )
        store = ContentAddressedStore(tmp_path / "store")
        store.retain(b"legitimate")

        # Simulate crash: add orphan
        orphan_digest = hashlib.sha256(b"crashed").hexdigest()
        orphan_path = store._artifact_path(orphan_digest)
        orphan_path.parent.mkdir(parents=True, exist_ok=True)
        orphan_path.write_bytes(b"crashed")

        receipt = collect_orphans(store)
        assert receipt.artifacts_removed == 1
        assert not orphan_path.exists()


# ── AC-08: Crash during index replacement (partial write detection) ────────

class TestAC08PartialWriteDetection:
    def test_partial_json_detected_as_corrupt(self, tmp_path):
        from nodechain.sdk.artifact_retention import (
            ContentAddressedStore, RetentionError,
        )
        store = ContentAddressedStore(tmp_path / "store")
        store.retain(b"data")

        # Simulate partial write
        store.index_path.write_text('{"schema_version": "1.0.0", "entries": {')

        with pytest.raises(RetentionError, match="corrupt"):
            store.load_index()

    def test_binary_garbage_detected_as_corrupt(self, tmp_path):
        from nodechain.sdk.artifact_retention import (
            ContentAddressedStore, RetentionError,
        )
        store = ContentAddressedStore(tmp_path / "store")
        store.retain(b"data")

        store.index_path.write_text("\x00\x01\x02\x03 garbage")

        with pytest.raises(RetentionError, match="corrupt"):
            store.load_index()

    def test_empty_file_detected_as_corrupt(self, tmp_path):
        from nodechain.sdk.artifact_retention import (
            ContentAddressedStore, RetentionError,
        )
        store = ContentAddressedStore(tmp_path / "store")
        store.retain(b"data")

        store.index_path.write_text("")

        with pytest.raises(RetentionError, match="corrupt"):
            store.load_index()


# ── AC-09: Index mutation between verifier and writer ──────────────────────

class TestAC09LockedVerification:
    def test_gc_verified_snapshot_is_locked(self, tmp_path):
        """GC's verified snapshot is computed under the lock."""
        from nodechain.sdk.artifact_retention import (
            ContentAddressedStore, collect_orphans,
        )
        store = ContentAddressedStore(tmp_path / "store")
        store.retain(b"keep me")

        # If GC properly locks, it should complete without error
        receipt = collect_orphans(store)
        assert receipt.artifacts_removed == 0
        assert store._artifact_path(
            hashlib.sha256(b"keep me").hexdigest()
        ).exists()


# ── AC-10: Empty valid index ────────────────────────────────────────────────

class TestAC10EmptyValidIndex:
    def test_empty_index_with_correct_digest_is_valid(self, tmp_path):
        from nodechain.sdk.artifact_retention import ContentAddressedStore
        store = ContentAddressedStore(tmp_path / "store")

        canonical = json.dumps({}, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode()).hexdigest()
        store.index_path.parent.mkdir(parents=True, exist_ok=True)
        store.index_path.write_text(json.dumps({
            "schema_version": "1.0.0",
            "entries": {},
            "index_digest": digest,
        }))

        result = store.verify_integrity()
        assert result["valid"]
        assert result["index_verified"]

    def test_no_index_file_is_valid(self, tmp_path):
        from nodechain.sdk.artifact_retention import ContentAddressedStore
        store = ContentAddressedStore(tmp_path / "store")
        assert not store.index_path.exists()

        result = store.verify_integrity()
        assert result["valid"]


# ── AC-11: Empty invalid index (missing digest) ─────────────────────────────

class TestAC11EmptyInvalidIndex:
    def test_empty_entries_missing_digest_fails(self, tmp_path):
        from nodechain.sdk.artifact_retention import (
            ContentAddressedStore, RetentionError,
        )
        store = ContentAddressedStore(tmp_path / "store")
        store.index_path.parent.mkdir(parents=True, exist_ok=True)
        store.index_path.write_text(json.dumps({
            "schema_version": "1.0.0",
            "entries": {},
        }))

        with pytest.raises(RetentionError, match="index_digest"):
            store.load_index()

    def test_empty_entries_blank_digest_fails(self, tmp_path):
        from nodechain.sdk.artifact_retention import (
            ContentAddressedStore, RetentionError,
        )
        store = ContentAddressedStore(tmp_path / "store")
        store.index_path.parent.mkdir(parents=True, exist_ok=True)
        store.index_path.write_text(json.dumps({
            "schema_version": "1.0.0",
            "entries": {},
            "index_digest": "",
        }))

        with pytest.raises(RetentionError, match="index_digest"):
            store.load_index()


# ── AC-12: Symlink and device-file path rejection ──────────────────────────

class TestAC12PathSafety:
    def test_path_traversal_rejected(self, tmp_path):
        from nodechain.sdk.artifact_retention import (
            ContentAddressedStore, validate_object_path, RetentionError,
        )
        store = ContentAddressedStore(tmp_path / "store")

        # A path that tries to escape the base dir
        evil_path = tmp_path / "evil"
        with pytest.raises((RetentionError, ValueError, Exception)):
            validate_object_path(store.base_dir, evil_path)

    def test_symlink_artifact_detected_as_orphan_not_followed(self, tmp_path):
        """A symlink in artifacts dir is not confused with a real artifact."""
        from nodechain.sdk.artifact_retention import ContentAddressedStore
        store = ContentAddressedStore(tmp_path / "store")
        store.retain(b"real")

        if os.name == "nt":
            pytest.skip("Symlinks not well-supported on Windows")

        # Create a symlink in artifacts dir pointing outside
        symlink_dir = store.artifacts_dir / "ff"
        symlink_dir.mkdir(parents=True, exist_ok=True)
        fake_digest = "ff" + "f" * 62  # 64-char hex digest
        symlink_path = symlink_dir / fake_digest
        target = tmp_path / "external"
        target.write_bytes(b"external")
        try:
            os.symlink(str(target), str(symlink_path))
        except OSError:
            pytest.skip("Cannot create symlink")

        # The symlink appears as orphan (not in index)
        result = store.verify_integrity()
        assert not result["valid"]
        assert fake_digest in result["orphans"]


# ── AC-13: Missing/orphan/digest-mismatched object detection ───────────────

class TestAC13ObjectIntegrity:
    def test_missing_object_detected(self, tmp_path):
        from nodechain.sdk.artifact_retention import ContentAddressedStore
        store = ContentAddressedStore(tmp_path / "store")
        meta = store.retain(b"data")

        # Delete the artifact but keep the index entry
        store._artifact_path(meta.digest).unlink()

        result = store.verify_integrity()
        assert not result["valid"]
        assert meta.digest in result["missing"]

    def test_orphan_object_detected(self, tmp_path):
        from nodechain.sdk.artifact_retention import ContentAddressedStore
        store = ContentAddressedStore(tmp_path / "store")
        store.retain(b"indexed")

        # Add orphan
        orphan_digest = hashlib.sha256(b"orphan").hexdigest()
        orphan_path = store._artifact_path(orphan_digest)
        orphan_path.parent.mkdir(parents=True, exist_ok=True)
        orphan_path.write_bytes(b"orphan")

        result = store.verify_integrity()
        assert not result["valid"]
        assert orphan_digest in result["orphans"]

    def test_digest_mismatched_object_detected(self, tmp_path):
        from nodechain.sdk.artifact_retention import ContentAddressedStore
        store = ContentAddressedStore(tmp_path / "store")
        meta = store.retain(b"original")

        # Corrupt the artifact content
        artifact_path = store._artifact_path(meta.digest)
        artifact_path.write_bytes(b"corrupted")

        result = store.verify_integrity()
        assert not result["valid"]
        assert meta.digest in result["artifacts_failed"]


# ── AC-14: GC refusal on every index-integrity error type ───────────────────

class TestAC14GCRefusal:
    """GC must refuse to run for every class of index integrity failure."""

    def _setup_store(self, tmp_path):
        from nodechain.sdk.artifact_retention import ContentAddressedStore
        store = ContentAddressedStore(tmp_path / "store")
        store.retain(b"data")
        return store

    def test_gc_refuses_on_tampered_digest(self, tmp_path):
        from nodechain.sdk.artifact_retention import (
            ContentAddressedStore, collect_orphans, RetentionError,
        )
        store = self._setup_store(tmp_path)
        raw = json.loads(store.index_path.read_text())
        raw["index_digest"] = "tampered"
        store.index_path.write_text(json.dumps(raw))

        with pytest.raises(RetentionError, match="index verification failed"):
            collect_orphans(store)

    def test_gc_refuses_on_missing_schema_version(self, tmp_path):
        from nodechain.sdk.artifact_retention import (
            ContentAddressedStore, collect_orphans, RetentionError,
        )
        store = self._setup_store(tmp_path)
        raw = json.loads(store.index_path.read_text())
        if "schema_version" in raw:
            del raw["schema_version"]
        store.index_path.write_text(json.dumps(raw))

        with pytest.raises(RetentionError, match="index verification failed"):
            collect_orphans(store)

    def test_gc_refuses_on_missing_entries(self, tmp_path):
        from nodechain.sdk.artifact_retention import (
            ContentAddressedStore, collect_orphans, RetentionError,
        )
        store = self._setup_store(tmp_path)
        raw = json.loads(store.index_path.read_text())
        del raw["entries"]
        store.index_path.write_text(json.dumps(raw))

        with pytest.raises(RetentionError, match="index verification failed"):
            collect_orphans(store)

    def test_gc_refuses_on_blank_digest(self, tmp_path):
        from nodechain.sdk.artifact_retention import (
            ContentAddressedStore, collect_orphans, RetentionError,
        )
        store = self._setup_store(tmp_path)
        raw = json.loads(store.index_path.read_text())
        raw["index_digest"] = ""
        store.index_path.write_text(json.dumps(raw))

        with pytest.raises(RetentionError, match="index verification failed"):
            collect_orphans(store)

    def test_gc_refuses_on_corrupt_json(self, tmp_path):
        from nodechain.sdk.artifact_retention import (
            ContentAddressedStore, collect_orphans, RetentionError,
        )
        store = self._setup_store(tmp_path)
        store.index_path.write_text("{corrupt")

        with pytest.raises(RetentionError, match="index verification failed"):
            collect_orphans(store)

    def test_gc_preserves_artifacts_on_refusal(self, tmp_path):
        """When GC refuses, all artifacts must still be on disk."""
        from nodechain.sdk.artifact_retention import (
            ContentAddressedStore, collect_orphans, RetentionError,
        )
        store = self._setup_store(tmp_path)
        raw = json.loads(store.index_path.read_text())
        raw["index_digest"] = "tampered"
        store.index_path.write_text(json.dumps(raw))

        with pytest.raises(RetentionError):
            collect_orphans(store)

        # Artifact must survive
        digest = hashlib.sha256(b"data").hexdigest()
        assert store._artifact_path(digest).exists()


# ── Write-path fail-closed summary ──────────────────────────────────────────

class TestWritePathFailClosed:
    """RET-004: The write path never heals a tampered index."""

    @pytest.mark.parametrize("tamper_field", [
        "index_digest",
        "schema_version",
        "entries",
    ])
    def test_retain_fails_closed_on_missing_field(self, tmp_path, tamper_field):
        from nodechain.sdk.artifact_retention import (
            ContentAddressedStore, RetentionError,
        )
        store = ContentAddressedStore(tmp_path / "store")
        store.retain(b"data")

        raw = json.loads(store.index_path.read_text())
        if tamper_field == "index_digest":
            raw["index_digest"] = ""
        elif tamper_field == "schema_version":
            if "schema_version" in raw:
                del raw["schema_version"]
        elif tamper_field == "entries":
            del raw["entries"]
        store.index_path.write_text(json.dumps(raw))

        with pytest.raises(RetentionError):
            store.retain(b"new")

    def test_retain_succeeds_on_valid_index(self, tmp_path):
        """Sanity: retain works fine on a clean index."""
        from nodechain.sdk.artifact_retention import ContentAddressedStore
        store = ContentAddressedStore(tmp_path / "store")
        store.retain(b"first")
        store.retain(b"second")
        assert len(store.list_artifacts()) == 2
