"""Remote Registry Trust Protocol v1 (v2.13.0).

Establishes trust in remote registry metadata through:
    - Digest-committed metadata with freshness, generation, and expiry
    - Registry onboarding (registry_id bound to approved signer)
    - Freshness enforcement (reject expired metadata in strict mode)
    - Rollback prevention (reject lower generation than highest accepted)
    - Equivocation detection (same identity + generation, different digest)
    - Endpoint identity drift detection
    - Mirror authorization via canonical registry identity
    - Offline verification with explicit freshness policy

SIGNATURE PROTOCOL NOTE:
    This reference implementation uses SHA-256 digest commitments for metadata
    integrity (metadata_digest). The `signature` field on SignedRegistryMetadata
    is a digest commitment, NOT an asymmetric cryptographic signature.

    In a production deployment, this field should hold an RSA-PSS-SHA256 or
    Ed25519 signature over the metadata digest, verified using the signer's
    public key (identified by signer_fingerprint) before calling the evaluator.

Core invariant:
    Registry metadata is trusted only when the signer is approved for the
    registry_id, the metadata is fresh, the generation is monotonic, and
    the metadata digest is consistent with prior observations.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from .artifact_retention import atomic_write_json


# ── Protocol Constants ──────────────────────────────────────────────────────

PROTOCOL_VERSION = "v1"
DEFAULT_FRESHNESS_MAX_AGE_HOURS = 24
DEFAULT_EXPIRY_GRACE_HOURS = 0

TRUST_VERDICT_TRUSTED = "trusted"
TRUST_VERDICT_EXPIRED = "expired"
TRUST_VERDICT_ROLLBACK = "rollback"
TRUST_VERDICT_EQUIVOCATION = "equivocation"
TRUST_VERDICT_UNAPPROVED_SIGNER = "unapproved_signer"
TRUST_VERDICT_ENDPOINT_DRIFT = "endpoint_drift"
TRUST_VERDICT_STALE = "stale"
TRUST_VERDICT_SUPERSEDED = "superseded_signer"
TRUST_VERDICT_UNTRUSTED = "untrusted"

ALL_TRUST_VERDICTS = {
    TRUST_VERDICT_TRUSTED,
    TRUST_VERDICT_EXPIRED,
    TRUST_VERDICT_ROLLBACK,
    TRUST_VERDICT_EQUIVOCATION,
    TRUST_VERDICT_UNAPPROVED_SIGNER,
    TRUST_VERDICT_ENDPOINT_DRIFT,
    TRUST_VERDICT_STALE,
    TRUST_VERDICT_SUPERSEDED,
    TRUST_VERDICT_UNTRUSTED,
}


# Signature protocol note (TRUST-001/TRUST-002 clarification)
SIGNATURE_PROTOCOL_NOTE = (
    "Reference implementation: signature fields hold SHA-256 digest commitments, "
    "not asymmetric cryptographic signatures. Production deployments must verify "
    "RSA-PSS-SHA256 or Ed25519 signatures using the signer's public key before "
    "trusting metadata."
)


# ── Digest-Committed Registry Metadata v1 ──────────────────────────────────


@dataclass
class SignedRegistryMetadata:
    """v2.13.0: Registry metadata with freshness and generation.

    NOTE: The `signature` field is a SHA-256 digest commitment in this
    reference implementation. Production deployments should use RSA-PSS-SHA256
    or Ed25519 signatures. See SIGNATURE_PROTOCOL_NOTE.

    Extends RemoteRegistryMetadata with:
        issued_at: When this metadata was issued by the registry
        expires_at: When this metadata expires
        generation: Monotonic counter (higher = newer)
        package_index_digest: SHA-256 of the package index at this generation
    """

    registry_id: str = ""
    protocol_version: str = PROTOCOL_VERSION
    signer_fingerprint: str = ""
    registry_name: str = ""
    issued_at: str = ""
    expires_at: str = ""
    generation: int = 1
    package_index_digest: str = ""
    packages_base_url: str = ""
    metadata_digest: str = ""
    signature: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = {
            "registry_id": self.registry_id,
            "protocol_version": self.protocol_version,
            "signer_fingerprint": self.signer_fingerprint,
            "registry_name": self.registry_name,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "generation": self.generation,
            "package_index_digest": self.package_index_digest,
            "packages_base_url": self.packages_base_url,
        }
        return d

    def compute_digest(self) -> str:
        """SHA-256 of canonical metadata (excluding signature and metadata_digest)."""
        d = self.to_dict()
        raw = json.dumps(d, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(raw).hexdigest()

    def canonical_identity(self) -> str:
        """Canonical registry identity key: registry_id + signer_fingerprint."""
        return f"{self.registry_id}:{self.signer_fingerprint}"

    def is_expired(self, now: datetime | None = None) -> bool:
        """Check if metadata has expired."""
        if not self.expires_at:
            return False
        if now is None:
            now = datetime.now(timezone.utc)
        try:
            exp = datetime.fromisoformat(self.expires_at)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            return now > exp
        except (ValueError, TypeError):
            return True  # Bad expiry = treat as expired

    def verify_digest_integrity(self) -> bool:
        """Verify that metadata_digest matches the computed digest.

        This is a SHA-256 integrity check, NOT a cryptographic signature
        verification. Production deployments must also verify the `signature`
        field using the signer's public key.
        """
        if not self.metadata_digest:
            return True  # No digest to verify (pre-v2.13 compatibility)
        return self.compute_digest() == self.metadata_digest

    def age_hours(self, now: datetime | None = None) -> float:
        """Age in hours since issued_at."""
        if not self.issued_at:
            return float("inf")
        if now is None:
            now = datetime.now(timezone.utc)
        try:
            issued = datetime.fromisoformat(self.issued_at)
            if issued.tzinfo is None:
                issued = issued.replace(tzinfo=timezone.utc)
            delta = now - issued
            return delta.total_seconds() / 3600.0
        except (ValueError, TypeError):
            return float("inf")


# ── Accepted Metadata Record ────────────────────────────────────────────────


@dataclass
class AcceptedMetadataRecord:
    """Record of previously accepted registry metadata for rollback detection."""

    registry_id: str = ""
    signer_fingerprint: str = ""
    generation: int = 0
    metadata_digest: str = ""
    accepted_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "registry_id": self.registry_id,
            "signer_fingerprint": self.signer_fingerprint,
            "generation": self.generation,
            "metadata_digest": self.metadata_digest,
            "accepted_at": self.accepted_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AcceptedMetadataRecord:
        return cls(
            registry_id=data.get("registry_id", ""),
            signer_fingerprint=data.get("signer_fingerprint", ""),
            generation=data.get("generation", 0),
            metadata_digest=data.get("metadata_digest", ""),
            accepted_at=data.get("accepted_at", ""),
        )


# ── Endpoint Identity Record ────────────────────────────────────────────────


@dataclass
class EndpointIdentityRecord:
    """Record of a transport endpoint's known registry identity."""

    endpoint_url: str = ""
    registry_id: str = ""
    signer_fingerprint: str = ""
    first_seen_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint_url": self.endpoint_url,
            "registry_id": self.registry_id,
            "signer_fingerprint": self.signer_fingerprint,
            "first_seen_at": self.first_seen_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EndpointIdentityRecord:
        return cls(
            endpoint_url=data.get("endpoint_url", ""),
            registry_id=data.get("registry_id", ""),
            signer_fingerprint=data.get("signer_fingerprint", ""),
            first_seen_at=data.get("first_seen_at", ""),
        )


# ── Trust Verdict ───────────────────────────────────────────────────────────


@dataclass
class RegistryTrustVerdict:
    """Result of evaluating registry metadata trustworthiness."""

    verdict: str = TRUST_VERDICT_UNTRUSTED
    trusted: bool = False
    registry_id: str = ""
    signer_fingerprint: str = ""
    generation: int = 0
    metadata_digest: str = ""
    detail: str = ""
    freshness_ok: bool = False
    generation_ok: bool = False
    equivocation_ok: bool = False
    signer_approved: bool = False
    endpoint_ok: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "trusted": self.trusted,
            "registry_id": self.registry_id,
            "signer_fingerprint": self.signer_fingerprint,
            "generation": self.generation,
            "metadata_digest": self.metadata_digest,
            "detail": self.detail,
            "freshness_ok": self.freshness_ok,
            "generation_ok": self.generation_ok,
            "equivocation_ok": self.equivocation_ok,
            "signer_approved": self.signer_approved,
            "endpoint_ok": self.endpoint_ok,
        }


# ── Registry Trust Store ────────────────────────────────────────────────────


class RegistryTrustStore:
    """Persistent store for registry trust state.

    Tracks:
        - Approved registry signers (registry_id → set of approved fingerprints)
        - Highest accepted generation per registry identity (rollback prevention)
        - Accepted metadata digests (equivocation detection)
        - Endpoint identity mappings (endpoint drift detection)
    """

    SCHEMA_VERSION = "1.0.0"

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock_path = Path(str(path) + ".lock")

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {
                "schema_version": self.SCHEMA_VERSION,
                "approved_signers": {},       # registry_id → [fingerprints]
                "accepted_metadata": {},      # canonical_identity → AcceptedMetadataRecord
                "endpoint_identities": {},     # endpoint_url → EndpointIdentityRecord
                "superseded_signers": {},     # registry_id → [{old_fp, new_fp, generation, timestamp}]
            }
        raw = self.path.read_text(encoding="utf-8")
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("Registry trust store is not a dict")
        data.setdefault("approved_signers", {})
        data.setdefault("accepted_metadata", {})
        data.setdefault("endpoint_identities", {})
        data.setdefault("superseded_signers", {})
        return data

    def _save(self, data: dict[str, Any]) -> None:
        data["schema_version"] = self.SCHEMA_VERSION
        atomic_write_json(self.path, data)

    # ── Approved signers ────────────────────────────────────────────────

    def approve_signer(self, registry_id: str, signer_fingerprint: str) -> None:
        """Approve a signer fingerprint for a registry_id."""
        data = self._load()
        data["approved_signers"].setdefault(registry_id, [])
        if signer_fingerprint not in data["approved_signers"][registry_id]:
            data["approved_signers"][registry_id].append(signer_fingerprint)
        self._save(data)

    def is_signer_approved(self, registry_id: str, signer_fingerprint: str) -> bool:
        """Check if a signer fingerprint is approved for a registry_id.

        v2.12.1 fail-closed: empty allowlist = not approved.
        """
        data = self._load()
        approved = data["approved_signers"].get(registry_id, [])
        if not approved:
            return False  # Empty allowlist = fail closed
        return signer_fingerprint in approved

    # ── Superseded signers (LG-011) ─────────────────────────────────────

    def record_signer_supersession(
        self,
        registry_id: str,
        old_signer_fingerprint: str,
        new_signer_fingerprint: str,
        rotation_generation: int = 0,
    ) -> None:
        """Record that old_signer has been superseded by new_signer.

        LG-011: Once a client has accepted a valid signer-rotation record,
        the superseded signer must not authorize newer metadata generations.
        """
        data = self._load()
        data["superseded_signers"].setdefault(registry_id, [])
        data["superseded_signers"][registry_id].append({
            "old_signer_fingerprint": old_signer_fingerprint,
            "new_signer_fingerprint": new_signer_fingerprint,
            "rotation_generation": rotation_generation,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        # Keep old signer in approved list but mark as superseded.
        # The evaluator checks approval FIRST, then supersession for newer gens.
        # This allows old-signer metadata at <= rotation_gen to still be valid
        # while rejecting old-signer metadata at > rotation_gen (LG-011).
        approved = data["approved_signers"].get(registry_id, [])
        if new_signer_fingerprint not in approved:
            data["approved_signers"].setdefault(registry_id, []).append(new_signer_fingerprint)
        self._save(data)

    def is_signer_superseded(
        self, registry_id: str, signer_fingerprint: str,
    ) -> bool:
        """Check if a signer has been superseded for a registry_id.

        Returns True if this signer was rotated out.
        """
        data = self._load()
        rotations = data.get("superseded_signers", {}).get(registry_id, [])
        return any(
            r["old_signer_fingerprint"] == signer_fingerprint for r in rotations
        )

    def get_supersession_generation(
        self, registry_id: str, signer_fingerprint: str,
    ) -> int | None:
        """Get the generation at which a signer was superseded.

        Returns None if signer was not superseded.
        """
        data = self._load()
        rotations = data.get("superseded_signers", {}).get(registry_id, [])
        for r in rotations:
            if r["old_signer_fingerprint"] == signer_fingerprint:
                return r.get("rotation_generation", 0)
        return None

    # ── Accepted metadata (rollback + equivocation) ─────────────────────

    def get_accepted_metadata(
        self, registry_id: str, signer_fingerprint: str,
    ) -> AcceptedMetadataRecord | None:
        """Get previously accepted metadata for a canonical identity."""
        key = f"{registry_id}:{signer_fingerprint}"
        data = self._load()
        record = data["accepted_metadata"].get(key)
        if record:
            return AcceptedMetadataRecord.from_dict(record)
        return None

    def record_accepted_metadata(self, metadata: SignedRegistryMetadata) -> None:
        """Record accepted metadata for rollback/equivocation detection."""
        key = metadata.canonical_identity()
        record = AcceptedMetadataRecord(
            registry_id=metadata.registry_id,
            signer_fingerprint=metadata.signer_fingerprint,
            generation=metadata.generation,
            metadata_digest=metadata.compute_digest(),
            accepted_at=datetime.now(timezone.utc).isoformat(),
        )
        data = self._load()
        data["accepted_metadata"][key] = record.to_dict()
        self._save(data)

    # ── Endpoint identity ───────────────────────────────────────────────

    def get_endpoint_identity(self, endpoint_url: str) -> EndpointIdentityRecord | None:
        """Get known registry identity for an endpoint."""
        data = self._load()
        record = data["endpoint_identities"].get(endpoint_url)
        if record:
            return EndpointIdentityRecord.from_dict(record)
        return None

    def record_endpoint_identity(
        self, endpoint_url: str, registry_id: str, signer_fingerprint: str,
    ) -> None:
        """Record the registry identity observed at an endpoint."""
        record = EndpointIdentityRecord(
            endpoint_url=endpoint_url,
            registry_id=registry_id,
            signer_fingerprint=signer_fingerprint,
            first_seen_at=datetime.now(timezone.utc).isoformat(),
        )
        data = self._load()
        data["endpoint_identities"][endpoint_url] = record.to_dict()
        self._save(data)


# ── Trust Evaluator ─────────────────────────────────────────────────────────


class RegistryTrustEvaluator:
    """Evaluates registry metadata trustworthiness.

    Implements the full trust protocol:
        1. Signer approval check
        2. Freshness enforcement
        3. Rollback prevention
        4. Equivocation detection
        5. Endpoint identity drift detection
    """

    def __init__(
        self,
        trust_store: RegistryTrustStore,
        max_age_hours: int = DEFAULT_FRESHNESS_MAX_AGE_HOURS,
        strict_freshness: bool = True,
    ) -> None:
        self.trust_store = trust_store
        self.max_age_hours = max_age_hours
        self.strict_freshness = strict_freshness

    def evaluate(
        self,
        metadata: SignedRegistryMetadata,
        endpoint_url: str = "",
    ) -> RegistryTrustVerdict:
        """Evaluate metadata trustworthiness.

        Returns a RegistryTrustVerdict. Only trusted=True when all checks pass.
        """
        verdict = RegistryTrustVerdict(
            registry_id=metadata.registry_id,
            signer_fingerprint=metadata.signer_fingerprint,
            generation=metadata.generation,
            metadata_digest=metadata.compute_digest(),
        )

        # Check 1: Signer approval
        approved = self.trust_store.is_signer_approved(
            metadata.registry_id, metadata.signer_fingerprint,
        )
        verdict.signer_approved = approved
        if not approved:
            verdict.verdict = TRUST_VERDICT_UNAPPROVED_SIGNER
            verdict.detail = (
                f"Signer {metadata.signer_fingerprint} is not approved "
                f"for registry {metadata.registry_id}"
            )
            return verdict

        # Check 1b: LG-011 — Superseded signer for generations >= rotation
        if self.trust_store.is_signer_superseded(
            metadata.registry_id, metadata.signer_fingerprint,
        ):
            supersession_gen = self.trust_store.get_supersession_generation(
                metadata.registry_id, metadata.signer_fingerprint,
            )
            if supersession_gen is not None and metadata.generation >= supersession_gen:
                verdict.verdict = TRUST_VERDICT_SUPERSEDED
                verdict.detail = (
                    f"Signer {metadata.signer_fingerprint} was superseded "
                    f"at generation {supersession_gen}. Cannot authorize "
                    f"generation {metadata.generation}."
                )
                return verdict

        # Check 1c: Digest integrity (metadata_digest matches content)
        if not metadata.verify_digest_integrity():
            verdict.verdict = TRUST_VERDICT_UNTRUSTED
            verdict.detail = (
                f"Metadata digest mismatch: claimed {metadata.metadata_digest} "
                f"does not match computed digest"
            )
            return verdict

        # Check 2: Freshness
        now = datetime.now(timezone.utc)
        is_expired = metadata.is_expired(now)
        age = metadata.age_hours(now)

        if is_expired:
            verdict.verdict = TRUST_VERDICT_EXPIRED
            verdict.detail = (
                f"Metadata expired at {metadata.expires_at}"
            )
            return verdict

        if self.strict_freshness and age > self.max_age_hours:
            verdict.verdict = TRUST_VERDICT_STALE
            verdict.detail = (
                f"Metadata is {age:.1f} hours old "
                f"(max: {self.max_age_hours}h)"
            )
            return verdict

        verdict.freshness_ok = True

        # Check 3: Rollback prevention
        accepted = self.trust_store.get_accepted_metadata(
            metadata.registry_id, metadata.signer_fingerprint,
        )
        if accepted and metadata.generation < accepted.generation:
            verdict.verdict = TRUST_VERDICT_ROLLBACK
            verdict.detail = (
                f"Metadata generation {metadata.generation} is lower than "
                f"accepted generation {accepted.generation}"
            )
            return verdict

        verdict.generation_ok = True

        # Check 4: Equivocation detection
        if accepted and metadata.generation == accepted.generation:
            computed = metadata.compute_digest()
            if computed != accepted.metadata_digest:
                verdict.verdict = TRUST_VERDICT_EQUIVOCATION
                verdict.detail = (
                    f"Same generation {metadata.generation} but different "
                    f"metadata digest: expected {accepted.metadata_digest[:16]}..., "
                    f"got {computed[:16]}..."
                )
                return verdict

        verdict.equivocation_ok = True

        # Check 5: Endpoint identity drift
        if endpoint_url:
            endpoint_record = self.trust_store.get_endpoint_identity(endpoint_url)
            if endpoint_record:
                if (endpoint_record.registry_id != metadata.registry_id or
                    endpoint_record.signer_fingerprint != metadata.signer_fingerprint):
                    verdict.verdict = TRUST_VERDICT_ENDPOINT_DRIFT
                    verdict.detail = (
                        f"Endpoint {endpoint_url} previously served "
                        f"registry {endpoint_record.registry_id} "
                        f"(signer: {endpoint_record.signer_fingerprint[:16]}...), "
                        f"now serving registry {metadata.registry_id} "
                        f"(signer: {metadata.signer_fingerprint[:16]}...)"
                    )
                    return verdict
            verdict.endpoint_ok = True
        else:
            verdict.endpoint_ok = True  # No endpoint to check

        # All checks passed
        verdict.verdict = TRUST_VERDICT_TRUSTED
        verdict.trusted = True
        verdict.detail = "All trust checks passed"

        return verdict

    def accept(
        self,
        metadata: SignedRegistryMetadata,
        endpoint_url: str = "",
    ) -> RegistryTrustVerdict:
        """Evaluate and, if trusted, record the metadata as accepted.

        This is the primary entry point for registry metadata verification.
        After acceptance, the metadata is recorded for future rollback and
        equivocation detection.
        """
        verdict = self.evaluate(metadata, endpoint_url)
        if verdict.trusted:
            self.trust_store.record_accepted_metadata(metadata)
            if endpoint_url:
                self.trust_store.record_endpoint_identity(
                    endpoint_url,
                    metadata.registry_id,
                    metadata.signer_fingerprint,
                )
        return verdict


# ── Transport Provenance ────────────────────────────────────────────────────


@dataclass
class TransportProvenance:
    """v2.13.0: Transport-level provenance for forensic detail.

    The canonical identity is the durable trust identity.
    The transport provenance is forensic detail.
    """

    requested_url: str = ""
    final_url: str = ""
    redirect_chain: list[str] = field(default_factory=list)
    fetched_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "requested_url": self.requested_url,
            "final_url": self.final_url,
            "redirect_chain": list(self.redirect_chain),
            "fetched_at": self.fetched_at,
        }
