"""Artifact Retention and Evidence Index Protection (v2.9.0).

NON-NEGOTIABLE RULES:
    Evidence index is derived from retained artifacts.
    Retained artifacts are not trusted merely because an index mentions them.

    Every artifact is content-addressed (SHA-256).
    Every index entry is verified on read.
    Every receipt digest is recomputed on load.
    Writes are atomic (temp file + fsync + atomic replace).
    Path traversal is rejected.
    Symlinks and device files are rejected.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class RetentionError(Exception):
    """Raised when artifact retention or evidence index integrity fails."""


class ArtifactIntegrityError(RetentionError):
    """Raised when an artifact's content doesn't match its digest."""


class PathSafetyError(RetentionError):
    """Raised when a path is unsafe (traversal, symlink, device file)."""


class RetentionPolicyDenial(RetentionError):
    """Raised when a retention policy denies an operation."""


# ── Path Safety ─────────────────────────────────────────────────────────────

def validate_object_path(base_dir: Path, object_path: Path) -> None:
    """Validate that object_path is safe and contained within base_dir.

    Rejects:
    - Path traversal (../, absolute paths)
    - Symlinks (in any component)
    - Device files or special files
    """
    base_resolved = base_dir.resolve()
    try:
        target_resolved = object_path.resolve(strict=False)
    except (OSError, RuntimeError) as e:
        raise PathSafetyError(f"Cannot resolve path: {e}") from e

    # Check containment
    try:
        target_resolved.relative_to(base_resolved)
    except ValueError:
        raise PathSafetyError(
            f"Path '{object_path}' escapes base directory '{base_dir}'"
        ) from None

    # Check for symlinks in the path components
    current = base_resolved
    for part in object_path.parts:
        if part in ("..",):
            raise PathSafetyError(f"Path traversal detected: '{object_path}'")
        current = current / part
        if current.is_symlink():
            raise PathSafetyError(f"Symlink in path: '{current}'")

    # Check if it's a device file or special file
    if object_path.exists():
        if not object_path.is_file() and not object_path.is_dir():
            raise PathSafetyError(f"Not a regular file or directory: '{object_path}'")
        # Check for symlinks specifically on the target
        if object_path.is_symlink():
            raise PathSafetyError(f"Target is a symlink: '{object_path}'")


# ── Atomic Write ────────────────────────────────────────────────────────────

def atomic_write(path: str | Path, data: bytes) -> None:
    """Write data atomically: temp file + fsync + atomic replace.

    This ensures that the file at `path` is either fully written or not
    changed at all, even if the process crashes mid-write.

    v2.9.3: Also fsyncs the parent directory after replace for stronger
    crash-durability semantics. The directory fsync ensures the rename
    is committed to disk, not just the file data.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)

    # Create temp file in the same directory (ensures same filesystem for rename)
    fd, tmp_path = tempfile.mkstemp(
        dir=str(target.parent),
        prefix=".tmp_",
        suffix=target.suffix or ".tmp",
    )
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())

        # Atomic replace
        os.replace(tmp_path, str(target))

        # v2.9.3: fsync parent directory for crash-durability
        _fsync_dir(target.parent)
    except Exception:
        # Clean up temp file on failure
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _fsync_dir(dir_path: Path) -> None:
    """Best-effort directory fsync after atomic replace.

    On Linux/macOS, fsyncing the directory entry ensures the rename
    survives a power loss. On Windows, this is a no-op (NTFS provides
    different crash-durability semantics).
    """
    try:
        dir_fd = os.open(str(dir_path), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        pass  # Not all platforms/filesystems support directory fsync


def atomic_write_json(path: str | Path, data: Any) -> None:
    """Write JSON data atomically."""
    raw = json.dumps(data, indent=2, sort_keys=True).encode("utf-8")
    atomic_write(path, raw)


# ── Content-Addressed Storage ──────────────────────────────────────────────

@dataclass
class ArtifactMetadata:
    """Immutable metadata for a retained artifact."""
    digest: str               # SHA-256 hex of the artifact content
    byte_size: int
    media_type: str           # e.g., "application/json", "application/octet-stream"
    retained_at: str          # ISO-8601 timestamp
    producer: str = ""        # what produced this artifact
    subject_ref: str = ""     # what the artifact is about (package, attestation, etc.)
    source_type: str = ""     # evidence type this artifact represents

    def to_dict(self) -> dict[str, Any]:
        return {
            "digest": self.digest,
            "byte_size": self.byte_size,
            "media_type": self.media_type,
            "retained_at": self.retained_at,
            "producer": self.producer,
            "subject_ref": self.subject_ref,
            "source_type": self.source_type,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ArtifactMetadata:
        return cls(
            digest=d["digest"],
            byte_size=d["byte_size"],
            media_type=d.get("media_type", "application/octet-stream"),
            retained_at=d["retained_at"],
            producer=d.get("producer", ""),
            subject_ref=d.get("subject_ref", ""),
            source_type=d.get("source_type", ""),
        )


class ContentAddressedStore:
    """Content-addressed artifact store.

    Artifacts are stored at: <base_dir>/artifacts/<sha256_prefix>/<full_digest>

    The SHA-256 prefix directory prevents any single directory from
    containing too many files.
    """

    def __init__(self, base_dir: str | Path) -> None:
        self.base_dir = Path(base_dir)
        self.artifacts_dir = self.base_dir / "artifacts"
        self.index_path = self.base_dir / "index.json"
        self.manifest_path = self.base_dir / "manifest.json"
        self._lock_path = self.base_dir / ".write.lock"

    def _artifact_path(self, digest: str) -> Path:
        """Return the path for a content-addressed artifact."""
        if len(digest) < 3:
            raise RetentionError(f"Invalid digest: {digest}")
        return self.artifacts_dir / digest[:2] / digest

    def _acquire_lock(self) -> int:
        """Acquire an exclusive write lock (writer serialization).

        v2.9.1: Uses fcntl on Unix, msvcrt on Windows.
        """
        import time
        self.base_dir.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self._lock_path), os.O_CREAT | os.O_RDWR)
        try:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX)
        except ImportError:
            # Windows: use msvcrt.locking for a real cross-process lock
            try:
                import msvcrt
                while True:
                    try:
                        msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
                        break
                    except OSError:
                        time.sleep(0.001)
            except ImportError:
                # Fallback: no locking available
                pass
        return fd

    def _release_lock(self, fd: int) -> None:
        try:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_UN)
        except ImportError:
            try:
                import msvcrt
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            except (ImportError, OSError):
                pass
        os.close(fd)

    def retain(
        self,
        content: bytes,
        media_type: str = "application/octet-stream",
        producer: str = "",
        subject_ref: str = "",
        source_type: str = "",
    ) -> ArtifactMetadata:
        """Retain an artifact in content-addressed storage.

        The artifact is stored at artifacts/<sha256[:2]>/<full_sha256>.
        If the artifact already exists, it is not duplicated (idempotent).

        Returns ArtifactMetadata.
        """
        digest = hashlib.sha256(content).hexdigest()
        artifact_path = self._artifact_path(digest)

        # Path safety
        validate_object_path(self.base_dir, artifact_path)

        # Acquire writer lock
        fd = self._acquire_lock()
        try:
            # v2.9.3: Verify existing index BEFORE writing anything.
            # A tampered index must cause RetentionError without side effects.
            if self.index_path.exists():
                self.load_index()  # raises RetentionError if tampered

            # Write artifact if it doesn't exist
            if not artifact_path.exists():
                artifact_path.parent.mkdir(parents=True, exist_ok=True)
                atomic_write(artifact_path, content)

            # Verify written content
            written = artifact_path.read_bytes()
            actual_digest = hashlib.sha256(written).hexdigest()
            if actual_digest != digest:
                raise ArtifactIntegrityError(
                    f"Artifact integrity check failed: expected={digest}, actual={actual_digest}"
                )

            metadata = ArtifactMetadata(
                digest=digest,
                byte_size=len(content),
                media_type=media_type,
                retained_at=datetime.now(timezone.utc).isoformat(),
                producer=producer,
                subject_ref=subject_ref,
                source_type=source_type,
            )

            # v2.9.1: Index update must happen inside the lock.
            # This prevents the race where another process or GC sees
            # the artifact on disk before it appears in the index.
            self._update_index_locked(metadata)
        finally:
            self._release_lock(fd)

        return metadata

    def _update_index_locked(self, metadata: ArtifactMetadata) -> None:
        """Update the evidence index with new artifact metadata.

        v2.9.3: Must be called while holding the store lock.
        The existing index is VERIFIED before mutation. A tampered or
        malformed index causes RetentionError — it is never silently healed.
        """
        # v2.9.3: Verify existing index before mutation (fail-closed)
        # This prevents a retain() from silently overwriting evidence of tampering.
        if self.index_path.exists():
            verified_index = self.load_index()
        else:
            # No index file = legitimate empty state
            verified_index = {
                "schema_version": "1.0.0",
                "entries": {},
            }

        verified_index.setdefault("entries", {})[metadata.digest] = metadata.to_dict()

        # Recompute index digest
        canonical = json.dumps(
            verified_index["entries"], sort_keys=True, separators=(",", ":"),
        )
        verified_index["index_digest"] = hashlib.sha256(canonical.encode()).hexdigest()
        verified_index["updated_at"] = datetime.now(timezone.utc).isoformat()
        verified_index["schema_version"] = verified_index.get("schema_version", "1.0.0")

        atomic_write_json(self.index_path, verified_index)

    def _load_index_raw(self) -> dict[str, Any]:
        """Load raw index without verification or normalization.

        v2.9.1: Unlike load_index_unchecked, this does NOT normalize
        missing 'entries' to empty. It returns what's on disk.
        """
        if not self.index_path.exists():
            return {"schema_version": "1.0.0", "entries": {}, "index_digest": "", "updated_at": ""}
        try:
            raw = self.index_path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError) as e:
            raise RetentionError(f"Evidence index is corrupt: {e}") from e
        return data

    def _update_index(self, metadata: ArtifactMetadata) -> None:
        """Update index (acquires lock internally)."""
        fd = self._acquire_lock()
        try:
            self._update_index_locked(metadata)
        finally:
            self._release_lock(fd)

    def load_index_unchecked(self) -> dict[str, Any]:
        """Load index without verification (internal use)."""
        if not self.index_path.exists():
            return {"entries": {}, "index_digest": "", "updated_at": ""}
        try:
            raw = self.index_path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError) as e:
            raise RetentionError(f"Evidence index is corrupt: {e}") from e
        if "entries" not in data:
            data = {"entries": {}, "index_digest": "", "updated_at": ""}
        return data

    def load_index(self) -> dict[str, Any]:
        """Load evidence index and verify its digest.

        v2.9.2: Existing index.json MUST have schema_version, entries,
        and index_digest. Missing/blank index_digest is an integrity error.
        No index file at all = legitimate empty state.
        """
        # No index file = legitimate empty state
        if not self.index_path.exists():
            return {
                "schema_version": "1.0.0",
                "entries": {},
                "index_digest": hashlib.sha256(
                    json.dumps({}, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest(),
                "updated_at": "",
            }

        index = self._load_index_raw()

        # v2.9.2: schema_version is mandatory
        if not index.get("schema_version"):
            raise RetentionError(
                "Evidence index missing required 'schema_version' field"
            )

        # v2.9.1: entries is mandatory
        if "entries" not in index:
            raise RetentionError(
                "Evidence index missing required 'entries' field"
            )

        # v2.9.2: index_digest is mandatory on existing index files
        stored = index.get("index_digest", "")
        if not stored:
            raise RetentionError(
                "Evidence index missing required 'index_digest' (blank or absent)"
            )

        # v2.9.2: Always verify digest, including empty entries
        entries = index.get("entries", {})
        canonical = json.dumps(
            entries, sort_keys=True, separators=(",", ":"),
        )
        computed = hashlib.sha256(canonical.encode()).hexdigest()

        if computed != stored:
            raise RetentionError(
                f"Evidence index digest mismatch: stored={stored}, computed={computed}"
            )

        return index

    def get_artifact(self, digest: str) -> bytes:
        """Retrieve artifact content and verify its digest.

        v2.9.0: The artifact digest is recomputed after read.
        Mismatch raises ArtifactIntegrityError.
        """
        artifact_path = self._artifact_path(digest)
        validate_object_path(self.base_dir, artifact_path)

        if not artifact_path.exists():
            raise RetentionError(f"Artifact not found: {digest}")

        content = artifact_path.read_bytes()
        actual_digest = hashlib.sha256(content).hexdigest()
        if actual_digest != digest:
            raise ArtifactIntegrityError(
                f"Artifact digest mismatch: expected={digest}, actual={actual_digest}"
            )
        return content

    def get_metadata(self, digest: str) -> ArtifactMetadata | None:
        """Get artifact metadata from the index."""
        index = self.load_index()
        entry = index.get("entries", {}).get(digest)
        if entry is None:
            return None
        return ArtifactMetadata.from_dict(entry)

    def list_artifacts(self) -> list[str]:
        """List all artifact digests in the index."""
        index = self.load_index()
        return sorted(index.get("entries", {}).keys())

    def verify_receipt(self, receipt: dict[str, Any]) -> bool:
        """Verify a receipt's digest on read.

        Recomputes receipt_digest and compares.
        """
        stored = receipt.get("receipt_digest", "")
        if not stored:
            return False  # no digest = invalid
        payload = {k: v for k, v in receipt.items() if k != "receipt_digest"}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        computed = hashlib.sha256(canonical.encode()).hexdigest()
        return computed == stored

    def find_orphaned(self, verified_index: dict[str, Any] | None = None) -> list[str]:
        """Find artifacts on disk that have no index entry.

        v2.9.2: Accepts an optional pre-verified index to scan from.
        Falls back to load_index_unchecked() only if no index is passed
        (for backward-compatible find-only use, not for GC).
        """
        if verified_index is not None:
            index = verified_index
        else:
            index = self.load_index_unchecked()
        indexed = set(index.get("entries", {}).keys())
        orphans: list[str] = []

        if not self.artifacts_dir.exists():
            return orphans

        for prefix_dir in self.artifacts_dir.iterdir():
            if not prefix_dir.is_dir():
                continue
            for artifact_file in prefix_dir.iterdir():
                if artifact_file.is_file():
                    digest = artifact_file.name
                    if digest not in indexed:
                        orphans.append(digest)
        return sorted(orphans)

    def find_missing(self, verified_index: dict[str, Any] | None = None) -> list[str]:
        """Find index entries that have no artifact on disk.

        v2.9.2: Accepts an optional pre-verified index to scan from.
        """
        if verified_index is not None:
            index = verified_index
        else:
            index = self.load_index_unchecked()
        missing: list[str] = []
        for digest in index.get("entries", {}):
            artifact_path = self._artifact_path(digest)
            if not artifact_path.exists():
                missing.append(digest)
        return sorted(missing)

    def verify_integrity(self) -> dict[str, Any]:
        """Full integrity check: index digest + all artifacts + orphans/missing."""
        result: dict[str, Any] = {
            "valid": True,
            "index_verified": False,
            "artifacts_checked": 0,
            "artifacts_failed": [],
            "orphans": [],
            "missing": [],
        }

        try:
            verified_index = self.load_index()
            result["index_verified"] = True
        except RetentionError as e:
            result["valid"] = False
            result["index_verified"] = False
            result["error"] = str(e)
            return result

        # v2.9.2: Use the verified snapshot for all subsequent checks
        for digest in verified_index.get("entries", {}):
            artifact_path = self._artifact_path(digest)
            if artifact_path.exists():
                try:
                    self.get_artifact(digest)
                    result["artifacts_checked"] += 1
                except ArtifactIntegrityError:
                    result["artifacts_failed"].append(digest)
                    result["valid"] = False

        result["orphans"] = self.find_orphaned(verified_index=verified_index)
        result["missing"] = self.find_missing(verified_index=verified_index)

        # v2.9.1: Orphans make integrity invalid — they indicate index/storage disagreement
        if result["artifacts_failed"] or result["missing"] or result["orphans"]:
            result["valid"] = False

        return result


# ── Retention Manifest ──────────────────────────────────────────────────────

@dataclass
class RetentionManifest:
    """Manifest summarizing the retention state at a point in time."""
    manifest_digest: str = ""
    generated_at: str = ""
    policy_profile_digest: str = ""
    retention_policy_id: str = ""
    artifact_count: int = 0
    total_byte_size: int = 0
    artifact_digests: list[str] = field(default_factory=list)
    index_digest: str = ""

    def __post_init__(self) -> None:
        if not self.manifest_digest:
            self.manifest_digest = self._compute_digest()

    def _compute_digest(self) -> str:
        d = {
            "generated_at": self.generated_at,
            "policy_profile_digest": self.policy_profile_digest,
            "retention_policy_id": self.retention_policy_id,
            "artifact_count": self.artifact_count,
            "total_byte_size": self.total_byte_size,
            "artifact_digests": self.artifact_digests,
            "index_digest": self.index_digest,
        }
        return hashlib.sha256(
            json.dumps(d, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        d = {
            "generated_at": self.generated_at,
            "policy_profile_digest": self.policy_profile_digest,
            "retention_policy_id": self.retention_policy_id,
            "artifact_count": self.artifact_count,
            "total_byte_size": self.total_byte_size,
            "artifact_digests": self.artifact_digests,
            "index_digest": self.index_digest,
        }
        d["manifest_digest"] = hashlib.sha256(
            json.dumps(d, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> RetentionManifest:
        return cls(
            manifest_digest=d.get("manifest_digest", ""),
            generated_at=d.get("generated_at", ""),
            policy_profile_digest=d.get("policy_profile_digest", ""),
            retention_policy_id=d.get("retention_policy_id", ""),
            artifact_count=d.get("artifact_count", 0),
            total_byte_size=d.get("total_byte_size", 0),
            artifact_digests=d.get("artifact_digests", []),
            index_digest=d.get("index_digest", ""),
        )


def generate_manifest(
    store: ContentAddressedStore,
    policy_profile_digest: str = "",
    retention_policy_id: str = "",
) -> RetentionManifest:
    """Generate a retention manifest for the current store state."""
    index = store.load_index()
    entries = index.get("entries", {})

    artifact_digests = sorted(entries.keys())
    total_size = sum(e.get("byte_size", 0) for e in entries.values())

    manifest = RetentionManifest(
        generated_at=datetime.now(timezone.utc).isoformat(),
        policy_profile_digest=policy_profile_digest,
        retention_policy_id=retention_policy_id,
        artifact_count=len(artifact_digests),
        total_byte_size=total_size,
        artifact_digests=artifact_digests,
        index_digest=index.get("index_digest", ""),
    )
    return manifest


def save_manifest(manifest: RetentionManifest, path: str | Path) -> str:
    """Save manifest atomically. Returns the manifest digest."""
    data = manifest.to_dict()
    digest = data["manifest_digest"]
    atomic_write_json(path, data)
    return digest


def load_manifest(path: str | Path) -> RetentionManifest:
    """Load manifest and verify its digest."""
    try:
        raw = Path(path).read_text(encoding="utf-8")
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as e:
        raise RetentionError(f"Manifest is corrupt: {e}") from e
    except FileNotFoundError:
        raise RetentionError(f"Manifest not found: {path}") from None

    stored_digest = data.get("manifest_digest", "")
    if not stored_digest:
        raise RetentionError("Manifest has no digest")

    payload = {k: v for k, v in data.items() if k != "manifest_digest"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    computed = hashlib.sha256(canonical.encode()).hexdigest()

    if computed != stored_digest:
        raise RetentionError(
            f"Manifest digest mismatch: stored={stored_digest}, computed={computed}"
        )

    return RetentionManifest.from_dict(data)


# ── Safe Garbage Collection ────────────────────────────────────────────────

@dataclass
class GarbageCollectionReceipt:
    """Receipt for a garbage collection operation."""
    gc_id: str
    collected_at: str
    orphaned_collected: list[str] = field(default_factory=list)
    artifacts_removed: int = 0
    bytes_freed: int = 0
    retention_policy_id: str = ""
    receipt_digest: str = ""

    def __post_init__(self) -> None:
        if not self.receipt_digest:
            self.receipt_digest = self._compute_digest()

    def _compute_digest(self) -> str:
        d = {
            "gc_id": self.gc_id,
            "collected_at": self.collected_at,
            "orphaned_collected": self.orphaned_collected,
            "artifacts_removed": self.artifacts_removed,
            "bytes_freed": self.bytes_freed,
            "retention_policy_id": self.retention_policy_id,
        }
        return hashlib.sha256(
            json.dumps(d, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        d = {
            "gc_id": self.gc_id,
            "collected_at": self.collected_at,
            "orphaned_collected": self.orphaned_collected,
            "artifacts_removed": self.artifacts_removed,
            "bytes_freed": self.bytes_freed,
            "retention_policy_id": self.retention_policy_id,
        }
        d["receipt_digest"] = hashlib.sha256(
            json.dumps(d, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return d


def collect_orphans(
    store: ContentAddressedStore,
    retention_policy_id: str = "",
) -> GarbageCollectionReceipt:
    """Safely collect orphaned artifacts (on disk but not in index).

    NEVER deletes referenced objects.
    Only removes artifacts that have no index entry.

    v2.9.2: Verification happens AFTER lock acquisition. The verified index
    snapshot is the one GC scans from — no unchecked reads under lock.
    """
    # v2.9.2: Acquire lock FIRST, then verify inside the lock.
    # This prevents index mutation between preflight and lock acquisition.
    fd = store._acquire_lock()
    try:
        # Verified index snapshot — this is the stable view GC operates from
        try:
            verified_index = store.load_index()
        except RetentionError as e:
            raise RetentionError(
                f"Cannot collect orphans: evidence index verification failed: {e}"
            ) from e

        # Scan from verified snapshot, NOT from unchecked load
        orphans = store.find_orphaned(verified_index=verified_index)
        removed = 0
        bytes_freed = 0

        for digest in orphans:
            artifact_path = store._artifact_path(digest)
            validate_object_path(store.base_dir, artifact_path)
            try:
                size = artifact_path.stat().st_size
                artifact_path.unlink()
                removed += 1
                bytes_freed += size
            except OSError:
                pass  # skip files we can't remove

        # Clean up empty prefix directories
        if store.artifacts_dir.exists():
            for prefix_dir in store.artifacts_dir.iterdir():
                if prefix_dir.is_dir() and not any(prefix_dir.iterdir()):
                    try:
                        prefix_dir.rmdir()
                    except OSError:
                        pass

        receipt = GarbageCollectionReceipt(
            gc_id=hashlib.sha256(
                f"gc:{datetime.now(timezone.utc).isoformat()}".encode()
            ).hexdigest()[:16],
            collected_at=datetime.now(timezone.utc).isoformat(),
            orphaned_collected=orphans,
            artifacts_removed=removed,
            bytes_freed=bytes_freed,
            retention_policy_id=retention_policy_id,
        )
    finally:
        store._release_lock(fd)

    return receipt
