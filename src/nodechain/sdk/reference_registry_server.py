"""Reference Remote Registry Server (v2.14.0).

A stateful reference implementation of the NodeChain Remote Registry
Trust Protocol. Proves the other side of the contract: a trustworthy
remote distribution protocol end to end.

SIGNATURE PROTOCOL NOTE:
    This reference implementation uses SHA-256 digest commitments for receipts
    and metadata. The `signature` fields on PublicationReceipt and lifecycle
    artifacts are digest commitments, NOT asymmetric cryptographic signatures.
    In production, these should be RSA-PSS-SHA256 or Ed25519 signatures.

Server state:
    registry_id, protocol version, signing identity, metadata generation,
    package index, immutable artifact records, publisher authorization
    records, revocation/deprecation records.

Publish flow (RR-001 immutability):
    receive package → validate manifest → verify publisher authorization →
    verify declared artifact digest → reject duplicate (package_id +
    version) with different identity → create immutable package metadata →
    atomically advance digest-committed registry metadata generation →
    emit receipt.

Endpoints:
    GET  /.well-known/nodechain-registry.json        — registry metadata
    GET  /packages/{id}/versions/{ver}.json          — package metadata
    GET  /packages/{id}/versions/{ver}/artifact      — artifact bytes
    GET  /health                                      — health check
    POST /publish                                     — publish new package

Core invariant (RR-001):
    A package version is immutable. Once package_id + version is published,
    any later publication must have the same complete identity or be
    rejected as a conflict.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from .artifact_retention import atomic_write, atomic_write_json


# ── Constants ───────────────────────────────────────────────────────────────

PROTOCOL_VERSION = "v1"
MAX_ARTIFACT_SIZE = 50 * 1024 * 1024  # 50 MB
DEFAULT_METADATA_EXPIRY_HOURS = 24

LIFECYCLE_ACTIVE = "active"
LIFECYCLE_DEPRECATED = "deprecated"
LIFECYCLE_REVOKED = "revoked"

ALL_LIFECYCLE_STATES = {LIFECYCLE_ACTIVE, LIFECYCLE_DEPRECATED, LIFECYCLE_REVOKED}


# ── Helpers ─────────────────────────────────────────────────────────────────


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_dict(data: dict[str, Any]) -> str:
    raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


# ── Publisher Authorization ─────────────────────────────────────────────────


@dataclass
class PublisherAuthorization:
    """Record of an approved publisher."""

    publisher_id: str = ""
    publisher_fingerprint: str = ""
    approved_packages: list[str] = field(default_factory=list)  # empty = all
    approved_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "publisher_id": self.publisher_id,
            "publisher_fingerprint": self.publisher_fingerprint,
            "approved_packages": list(self.approved_packages),
            "approved_at": self.approved_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PublisherAuthorization:
        return cls(
            publisher_id=data.get("publisher_id", ""),
            publisher_fingerprint=data.get("publisher_fingerprint", ""),
            approved_packages=data.get("approved_packages", []),
            approved_at=data.get("approved_at", ""),
        )

    def can_publish(self, package_id: str) -> bool:
        """Check if this publisher can publish the given package."""
        if not self.approved_packages:
            return True  # Empty = all packages
        return package_id in self.approved_packages


# ── Immutable Package Record ────────────────────────────────────────────────


@dataclass
class ImmutablePackageRecord:
    """An immutable record of a published package version.

    RR-001: Once created, this record never changes.
    The same package_id + version must always produce the same record.
    """

    package_id: str = ""
    version: str = ""
    artifact_digest: str = ""
    artifact_size: int = 0
    manifest_digest: str = ""
    certification_digest: str = ""
    publisher_fingerprint: str = ""
    publisher_id: str = ""
    capabilities: list[str] = field(default_factory=list)
    sandbox_profile: str = "hardened_untrusted"
    description: str = ""
    nodes: list[str] = field(default_factory=list)
    lifecycle: str = LIFECYCLE_ACTIVE
    published_at: str = ""
    deprecated_at: str = ""
    revoked_at: str = ""
    revocation_reason: str = ""

    def immutable_identity_fields(self) -> dict[str, str]:
        """The 8 immutable identity-bearing fields for RR-001 comparison.

        These fields CANNOT change after first publication. A different
        value for any of them under the same package_id + version is a
        conflict that must be rejected.

        Note: lifecycle is NOT included here — it is mutable registry
        metadata that changes through authorized signed transitions
        (revoke/deprecate). See lifecycle_fields().
        """
        return {
            "package_id": self.package_id,
            "version": self.version,
            "artifact_digest": self.artifact_digest,
            "manifest_digest": self.manifest_digest,
            "publisher_fingerprint": self.publisher_fingerprint,
            "publisher_id": self.publisher_id,
            "certification_digest": self.certification_digest,
            "sandbox_profile": self.sandbox_profile,
        }

    def lifecycle_fields(self) -> dict[str, str]:
        """Mutable registry lifecycle metadata.

        These fields change through authorized signed registry metadata
        transitions (revoke, deprecate). They are NOT part of the immutable
        release identity.
        """
        return {
            "lifecycle": self.lifecycle,
            "revoked_at": self.revoked_at,
            "deprecated_at": self.deprecated_at,
            "revocation_reason": self.revocation_reason,
        }

    def identity_fields(self) -> dict[str, str]:
        """All 12 fields for full record comparison.

        DEPRECATED: Use immutable_identity_fields() for RR-001 checks.
        This method is kept for backward compatibility.
        """
        return {
            **self.immutable_identity_fields(),
            "lifecycle": self.lifecycle,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_id": self.package_id,
            "version": self.version,
            "artifact_digest": self.artifact_digest,
            "artifact_size": self.artifact_size,
            "manifest_digest": self.manifest_digest,
            "certification_digest": self.certification_digest,
            "publisher_fingerprint": self.publisher_fingerprint,
            "publisher_id": self.publisher_id,
            "capabilities": list(self.capabilities),
            "sandbox_profile": self.sandbox_profile,
            "description": self.description,
            "nodes": list(self.nodes),
            "lifecycle": self.lifecycle,
            "published_at": self.published_at,
            "deprecated_at": self.deprecated_at,
            "revoked_at": self.revoked_at,
            "revocation_reason": self.revocation_reason,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ImmutablePackageRecord:
        return cls(
            package_id=data.get("package_id", ""),
            version=data.get("version", ""),
            artifact_digest=data.get("artifact_digest", ""),
            artifact_size=data.get("artifact_size", 0),
            manifest_digest=data.get("manifest_digest", ""),
            certification_digest=data.get("certification_digest", ""),
            publisher_fingerprint=data.get("publisher_fingerprint", ""),
            publisher_id=data.get("publisher_id", ""),
            capabilities=data.get("capabilities", []),
            sandbox_profile=data.get("sandbox_profile", "hardened_untrusted"),
            description=data.get("description", ""),
            nodes=data.get("nodes", []),
            lifecycle=data.get("lifecycle", LIFECYCLE_ACTIVE),
            published_at=data.get("published_at", ""),
            deprecated_at=data.get("deprecated_at", ""),
            revoked_at=data.get("revoked_at", ""),
            revocation_reason=data.get("revocation_reason", ""),
        )


# ── Publication Receipt ─────────────────────────────────────────────────────


@dataclass
class PublicationReceipt:
    """Signed receipt for a successful publication."""

    receipt_id: str = ""
    package_id: str = ""
    version: str = ""
    artifact_digest: str = ""
    publisher_fingerprint: str = ""
    registry_id: str = ""
    generation: int = 0
    published_at: str = ""
    registry_signer_fingerprint: str = ""
    receipt_digest: str = ""
    signature: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "package_id": self.package_id,
            "version": self.version,
            "artifact_digest": self.artifact_digest,
            "publisher_fingerprint": self.publisher_fingerprint,
            "registry_id": self.registry_id,
            "generation": self.generation,
            "published_at": self.published_at,
            "registry_signer_fingerprint": self.registry_signer_fingerprint,
            "receipt_digest": self.receipt_digest,
            "signature": self.signature,
        }


# ── Exceptions ──────────────────────────────────────────────────────────────


class PublishError(Exception):
    """Base error for publication failures."""


class PackageConflictError(PublishError):
    """RR-001: Same package_id + version with different identity."""


class UnauthorizedPublisherError(PublishError):
    """Publisher not authorized to publish this package."""


class PackageRevokedError(PublishError):
    """Attempt to modify a revoked package."""


# ── Registry State ──────────────────────────────────────────────────────────


class RegistryState:
    """Persistent state of the reference registry.

    Stores:
        - Registry identity (id, signer fingerprint, generation)
        - Approved publishers
        - Immutable package records (keyed by package_id:version)
        - Package index digest (SHA-256 of all active package identities)
        - Lifecycle records (revocation/deprecation)
    """

    SCHEMA_VERSION = "1.0.0"

    def __init__(self, state_path: str | Path) -> None:
        self.state_path = Path(state_path)
        self._lock = threading.RLock()

    def _load(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return {
                "schema_version": self.SCHEMA_VERSION,
                "registry_id": "",
                "registry_signer_fingerprint": "",
                "generation": 0,
                "publishers": {},
                "packages": {},
                "created_at": _now_iso(),
            }
        raw = self.state_path.read_text(encoding="utf-8")
        data = json.loads(raw)
        data.setdefault("publishers", {})
        data.setdefault("packages", {})
        data.setdefault("generation", 0)
        return data

    def _save(self, data: dict[str, Any]) -> None:
        data["schema_version"] = self.SCHEMA_VERSION
        atomic_write_json(self.state_path, data)

    # ── Registry identity ───────────────────────────────────────────────

    def get_registry_id(self) -> str:
        with self._lock:
            return self._load().get("registry_id", "")

    def set_registry_identity(self, registry_id: str, signer_fingerprint: str) -> None:
        with self._lock:
            data = self._load()
            data["registry_id"] = registry_id
            data["registry_signer_fingerprint"] = signer_fingerprint
            self._save(data)

    def get_generation(self) -> int:
        with self._lock:
            return self._load().get("generation", 0)

    def get_signer_fingerprint(self) -> str:
        with self._lock:
            return self._load().get("registry_signer_fingerprint", "")

    # ── Publisher management ─────────────────────────────────────────────

    def approve_publisher(
        self,
        publisher_id: str,
        publisher_fingerprint: str,
        approved_packages: list[str] | None = None,
    ) -> None:
        with self._lock:
            data = self._load()
            auth = PublisherAuthorization(
                publisher_id=publisher_id,
                publisher_fingerprint=publisher_fingerprint,
                approved_packages=approved_packages or [],
                approved_at=_now_iso(),
            )
            data["publishers"][publisher_fingerprint] = auth.to_dict()
            self._save(data)

    def is_publisher_authorized(
        self, publisher_fingerprint: str, package_id: str,
    ) -> bool:
        """Check if a publisher is authorized to publish a package.

        Fail closed: unknown publisher = not authorized.
        """
        with self._lock:
            data = self._load()
            record = data["publishers"].get(publisher_fingerprint)
            if not record:
                return False  # Unknown publisher
            auth = PublisherAuthorization.from_dict(record)
            return auth.can_publish(package_id)

    def get_publisher(self, publisher_fingerprint: str) -> PublisherAuthorization | None:
        with self._lock:
            data = self._load()
            record = data["publishers"].get(publisher_fingerprint)
            if record:
                return PublisherAuthorization.from_dict(record)
            return None

    # ── Package records ─────────────────────────────────────────────────

    def _pkg_key(self, package_id: str, version: str) -> str:
        return f"{package_id}:{version}"

    def get_package(self, package_id: str, version: str) -> ImmutablePackageRecord | None:
        with self._lock:
            data = self._load()
            record = data["packages"].get(self._pkg_key(package_id, version))
            if record:
                return ImmutablePackageRecord.from_dict(record)
            return None

    def has_package(self, package_id: str, version: str) -> bool:
        return self.get_package(package_id, version) is not None

    def list_packages(self) -> list[ImmutablePackageRecord]:
        with self._lock:
            data = self._load()
            return [
                ImmutablePackageRecord.from_dict(r)
                for r in data["packages"].values()
            ]

    def check_identity_conflict(
        self, package_id: str, version: str, proposed: ImmutablePackageRecord,
    ) -> bool:
        """RR-001: Check if proposed record conflicts with existing.

        Compares only the 8 immutable identity fields, NOT lifecycle.
        Lifecycle changes are authorized transitions, not conflicts.

        Returns True if there is a conflict (different immutable fields).
        Returns False if either (a) no existing record or (b) identical
        immutable identity.
        """
        existing = self.get_package(package_id, version)
        if existing is None:
            return False  # No existing → no conflict
        # Compare only immutable identity fields
        return existing.immutable_identity_fields() != proposed.immutable_identity_fields()

    # ── Publication (atomic) ─────────────────────────────────────────────

    def publish_package(
        self,
        record: ImmutablePackageRecord,
    ) -> int:
        """Record an immutable package and atomically advance generation.

        Returns the new generation number.
        Raises PackageConflictError if RR-001 violated.
        """
        with self._lock:
            data = self._load()
            key = self._pkg_key(record.package_id, record.version)

            existing = data["packages"].get(key)
            if existing:
                existing_rec = ImmutablePackageRecord.from_dict(existing)
                if existing_rec.immutable_identity_fields() != record.immutable_identity_fields():
                    raise PackageConflictError(
                        f"RR-001: Package {key} already published with "
                        f"different immutable identity. Existing artifact: "
                        f"{existing_rec.artifact_digest[:16]}..., "
                        f"proposed: {record.artifact_digest[:16]}..."
                    )
                # Same immutable identity = idempotent re-publish, no generation bump
                return data["generation"]

            record.published_at = _now_iso()
            data["packages"][key] = record.to_dict()
            data["generation"] = data.get("generation", 0) + 1
            self._save(data)
            return data["generation"]

    # ── Lifecycle (revoke/deprecate) ─────────────────────────────────────

    def revoke_package(
        self, package_id: str, version: str, reason: str = "",
    ) -> int:
        """Revoke a package version. Advances generation."""
        with self._lock:
            data = self._load()
            key = self._pkg_key(package_id, version)
            record = data["packages"].get(key)
            if not record:
                raise KeyError(f"Package {key} not found")
            if record.get("lifecycle") == LIFECYCLE_REVOKED:
                return data["generation"]  # Already revoked
            record["lifecycle"] = LIFECYCLE_REVOKED
            record["revoked_at"] = _now_iso()
            record["revocation_reason"] = reason
            data["packages"][key] = record
            data["generation"] = data.get("generation", 0) + 1
            self._save(data)
            return data["generation"]

    def deprecate_package(self, package_id: str, version: str) -> int:
        """Deprecate a package version. Advances generation."""
        with self._lock:
            data = self._load()
            key = self._pkg_key(package_id, version)
            record = data["packages"].get(key)
            if not record:
                raise KeyError(f"Package {key} not found")
            if record.get("lifecycle") == LIFECYCLE_REVOKED:
                raise PackageRevokedError(f"Package {key} is revoked, cannot deprecate")
            if record.get("lifecycle") == LIFECYCLE_DEPRECATED:
                return data["generation"]  # Already deprecated
            record["lifecycle"] = LIFECYCLE_DEPRECATED
            record["deprecated_at"] = _now_iso()
            data["packages"][key] = record
            data["generation"] = data.get("generation", 0) + 1
            self._save(data)
            return data["generation"]

    # ── Package index digest ─────────────────────────────────────────────

    def compute_package_index_digest(self) -> str:
        """SHA-256 of all active (non-revoked) package identity fields."""
        with self._lock:
            packages = self.list_packages()
            active = [p for p in packages if p.lifecycle != LIFECYCLE_REVOKED]
            identities = sorted(
                [json.dumps(p.immutable_identity_fields(), sort_keys=True) for p in active]
            )
            return _sha256_dict({"packages": identities})


# ── Reference Registry Server ───────────────────────────────────────────────


class ReferenceRegistryServer:
    """Full reference registry server with publish/read/lifecycle.

    Wraps RegistryState with signing and receipt generation.
    Designed for testing and reference — not production deployment.
    """

    def __init__(
        self,
        state_path: str | Path,
        artifact_dir: str | Path,
        registry_id: str = "",
        registry_signer_fingerprint: str = "",
    ) -> None:
        self.state = RegistryState(state_path)
        self.artifact_dir = Path(artifact_dir)
        self.artifact_dir.mkdir(parents=True, exist_ok=True)

        if registry_id and registry_signer_fingerprint:
            self.state.set_registry_identity(registry_id, registry_signer_fingerprint)

    def publish(
        self,
        package_id: str,
        version: str,
        artifact_bytes: bytes,
        manifest_digest: str = "",
        certification_digest: str = "",
        publisher_fingerprint: str = "",
        publisher_id: str = "",
        capabilities: list[str] | None = None,
        sandbox_profile: str = "hardened_untrusted",
        description: str = "",
        nodes: list[str] | None = None,
    ) -> PublicationReceipt:
        """Publish a package version.

        Steps:
            1. Check artifact size limit
            2. Verify publisher authorization
            3. Compute artifact digest
            4. Check RR-001 immutability
            5. Store artifact atomically
            6. Record immutable package
            7. Advance generation
            8. Emit receipt

        Raises:
            UnauthorizedPublisherError: Publisher not approved
            PackageConflictError: RR-001 identity mismatch
        """
        # 1. Size limit
        if len(artifact_bytes) > MAX_ARTIFACT_SIZE:
            raise PublishError(
                f"Artifact exceeds size limit: {len(artifact_bytes)} > {MAX_ARTIFACT_SIZE}"
            )

        # 2. Publisher authorization (fail closed)
        if not self.state.is_publisher_authorized(publisher_fingerprint, package_id):
            raise UnauthorizedPublisherError(
                f"Publisher {publisher_fingerprint} not authorized "
                f"to publish {package_id}"
            )

        # 3. Compute digest
        artifact_digest = _sha256_bytes(artifact_bytes)

        # 4. Check for revoked package
        existing = self.state.get_package(package_id, version)
        if existing and existing.lifecycle == LIFECYCLE_REVOKED:
            raise PackageRevokedError(
                f"Package {package_id}:{version} is revoked, cannot re-publish"
            )

        # 5. Build immutable record
        record = ImmutablePackageRecord(
            package_id=package_id,
            version=version,
            artifact_digest=artifact_digest,
            artifact_size=len(artifact_bytes),
            manifest_digest=manifest_digest,
            certification_digest=certification_digest,
            publisher_fingerprint=publisher_fingerprint,
            publisher_id=publisher_id,
            capabilities=capabilities or ["read_only"],
            sandbox_profile=sandbox_profile,
            description=description,
            nodes=nodes or [],
        )

        # 6. RR-001 check
        if self.state.check_identity_conflict(package_id, version, record):
            raise PackageConflictError(
                f"RR-001: Package {package_id}:{version} already published "
                f"with different identity"
            )

        # 7. Store artifact atomically
        artifact_path = self.artifact_dir / artifact_digest
        if not artifact_path.exists():
            atomic_write(artifact_path, artifact_bytes)

        # 8. Publish (atomic generation advance)
        generation = self.state.publish_package(record)

        # 9. Emit receipt
        receipt = PublicationReceipt(
            receipt_id=hashlib.sha256(
                f"{package_id}:{version}:{artifact_digest}:{generation}".encode()
            ).hexdigest()[:32],
            package_id=package_id,
            version=version,
            artifact_digest=artifact_digest,
            publisher_fingerprint=publisher_fingerprint,
            registry_id=self.state.get_registry_id(),
            generation=generation,
            published_at=_now_iso(),
            registry_signer_fingerprint=self.state.get_signer_fingerprint(),
        )
        receipt_digest = _sha256_dict({
            "receipt_id": receipt.receipt_id,
            "package_id": receipt.package_id,
            "version": receipt.version,
            "artifact_digest": receipt.artifact_digest,
            "publisher_fingerprint": receipt.publisher_fingerprint,
            "registry_id": receipt.registry_id,
            "generation": receipt.generation,
            "published_at": receipt.published_at,
        })
        receipt.receipt_digest = receipt_digest

        return receipt

    def revoke(self, package_id: str, version: str, reason: str = "") -> int:
        """Revoke a package version."""
        return self.state.revoke_package(package_id, version, reason)

    def deprecate(self, package_id: str, version: str) -> int:
        """Deprecate a package version."""
        return self.state.deprecate_package(package_id, version)

    def get_artifact_path(self, artifact_digest: str) -> Path:
        """Get path to stored artifact by digest."""
        return self.artifact_dir / artifact_digest

    def get_signed_metadata(self) -> dict[str, Any]:
        """Build v2.13.0-compatible registry metadata with digest commitment.

        Returns SignedRegistryMetadata-compatible dict with generation,
        issued_at, expires_at, package_index_digest, metadata_digest,
        and a digest commitment in the signature field.

        NOTE: The signature field contains a SHA-256 digest commitment, not
        an asymmetric cryptographic signature. Production servers must sign
        the metadata_digest using RSA-PSS-SHA256 or Ed25519.
        """
        now = datetime.now(timezone.utc)
        packages = self.state.list_packages()
        active_packages = [p for p in packages if p.lifecycle == LIFECYCLE_ACTIVE]

        metadata = {
            "registry_id": self.state.get_registry_id(),
            "protocol_version": PROTOCOL_VERSION,
            "signer_fingerprint": self.state.get_signer_fingerprint(),
            "registry_name": "NodeChain Reference Registry",
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(hours=DEFAULT_METADATA_EXPIRY_HOURS)).isoformat(),
            "generation": self.state.get_generation(),
            "package_index_digest": self.state.compute_package_index_digest(),
            "packages_base_url": "",
            "active_package_count": len(active_packages),
            "total_package_count": len(packages),
        }

        # Compute metadata_digest (SHA-256 of canonical form, excluding digest/signature)
        canonical = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
        metadata["metadata_digest"] = hashlib.sha256(canonical).hexdigest()

        # Digest commitment (NOT cryptographic signature — see SIGNATURE PROTOCOL NOTE)
        metadata["signature"] = metadata["metadata_digest"]

        return metadata
