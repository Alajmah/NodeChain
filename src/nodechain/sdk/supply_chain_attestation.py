"""Supply Chain Attestations (v2.8.0).

NON-NEGOTIABLE RULES:
    Attestation is evidence.
    Attestation is not automatic trust.

    A valid attestation must NEVER:
      - Automatically upgrade a package's trust level
      - Bypass certification requirements
      - Bypass sandbox requirements
      - Override a federation conflict

    Attestation complements trust; it does not replace trust.

Design:
    SupplyChainAttestation binds an exact artifact digest to a package
    identity/version, a build/provenance subject, and an issuer identity.
    Verification confirms the signature and issuer. Policy checks determine
    whether the attestation is sufficient for a given operation, but even
    a fully verified attestation does not change the trust level of the
    underlying package.

SLSA-like levels:
    none < source < build < provenance

    These levels describe evidence depth, not trust depth. A "provenance"
    attestation provides more evidence than a "source" attestation, but
    neither changes the package trust level.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AttestationError(Exception):
    """Raised when an attestation is invalid or verification fails."""


class AttestationPolicyDenial(Exception):
    """Raised when an attestation is denied by policy."""


# ── SLSA-like attestation levels ────────────────────────────────────────────

#: Ordered from weakest to strongest evidence
ATTESTATION_LEVELS = ["none", "source", "build", "provenance"]

#: Attestation types (what is being attested)
ATTESTATION_TYPES = frozenset({
    "provenance",      # full build provenance (builder identity, build steps)
    "build",           # build-level attestation (artifact built from source)
    "source",          # source-level attestation (source identity verified)
    "vulnerability_scan",  # vulnerability scan result
    "license_scan",    # license compliance scan
    "sbom",            # software bill of materials
})


def level_rank(level: str) -> int:
    """Return the rank of an attestation level (higher = more evidence)."""
    if level not in ATTESTATION_LEVELS:
        return -1
    return ATTESTATION_LEVELS.index(level)


# ── Supply Chain Attestation ────────────────────────────────────────────────

@dataclass
class SupplyChainAttestation:
    """A supply chain attestation binding artifact to provenance.

    An attestation is EVIDENCE about an artifact's origin and build process.
    It does not confer trust. It does not upgrade trust level. It does not
    bypass any gate. It is evidence that policy may consider.
    """
    attestation_id: str
    artifact_digest: str          # SHA-256 of the package artifact
    package_name: str
    package_version: str
    attestation_type: str         # one of ATTESTATION_TYPES
    attestation_level: str        # one of ATTESTATION_LEVELS
    subject: str                  # what the attestation covers (builder, CI system)
    issuer: str                   # who issued the attestation
    issuer_fingerprint: str       # fingerprint of the issuer's signing key
    issued_at: str                # ISO-8601 timestamp
    valid_until: str = ""         # ISO-8601 expiry, empty = no expiry
    statement: dict[str, Any] = field(default_factory=dict)
    signature: str = ""           # RSA-PSS-SHA256 hex signature
    attestation_digest: str = ""  # SHA-256 of canonical form (excluding self)

    def to_dict(self) -> dict[str, Any]:
        d = {
            "attestation_id": self.attestation_id,
            "artifact_digest": self.artifact_digest,
            "package_name": self.package_name,
            "package_version": self.package_version,
            "attestation_type": self.attestation_type,
            "attestation_level": self.attestation_level,
            "subject": self.subject,
            "issuer": self.issuer,
            "issuer_fingerprint": self.issuer_fingerprint,
            "issued_at": self.issued_at,
            "valid_until": self.valid_until,
            "statement": self.statement,
            "signature": self.signature,
        }
        d["attestation_digest"] = compute_attestation_digest(d)
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SupplyChainAttestation:
        return cls(
            attestation_id=d["attestation_id"],
            artifact_digest=d["artifact_digest"],
            package_name=d["package_name"],
            package_version=d["package_version"],
            attestation_type=d.get("attestation_type", "build"),
            attestation_level=d.get("attestation_level", "build"),
            subject=d["subject"],
            issuer=d["issuer"],
            issuer_fingerprint=d["issuer_fingerprint"],
            issued_at=d["issued_at"],
            valid_until=d.get("valid_until", ""),
            statement=d.get("statement", {}),
            signature=d.get("signature", ""),
            attestation_digest=d.get("attestation_digest", ""),
        )

    def is_expired(self) -> bool:
        """Check if the attestation has expired."""
        if not self.valid_until:
            return False
        try:
            expiry = datetime.fromisoformat(self.valid_until.replace("Z", "+00:00"))
            return datetime.now(timezone.utc) > expiry
        except (ValueError, TypeError):
            return True  # invalid expiry = expired

    def matches_artifact(self, artifact_digest: str) -> bool:
        """Check if this attestation matches a given artifact digest."""
        return self.artifact_digest == artifact_digest

    def matches_package(self, package_name: str, package_version: str = "") -> bool:
        """Check if this attestation matches a given package."""
        if self.package_name != package_name:
            return False
        if package_version and self.package_version != package_version:
            return False
        return True


def compute_attestation_digest(data: dict[str, Any]) -> str:
    """Compute SHA-256 digest of an attestation's canonical form.

    Excludes the attestation_digest field itself (self-referential).
    """
    payload = {k: v for k, v in data.items() if k != "attestation_digest"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def sign_attestation(
    attestation: SupplyChainAttestation,
    private_key_pem: str | None = None,
    private_key: Any = None,
) -> str:
    """Sign an attestation with RSA-PSS-SHA256.

    Returns the hex signature.
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    if private_key is None and private_key_pem:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(), password=None,
        )

    if private_key is None:
        raise AttestationError("No private key provided for signing")

    data = attestation.to_dict()
    payload = {k: v for k, v in data.items()
               if k not in ("signature", "attestation_digest")}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))

    sig = private_key.sign(
        canonical.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return sig.hex()


# ── Attestation Verification ────────────────────────────────────────────────

@dataclass
class AttestationVerifyResult:
    """Result of verifying a supply chain attestation."""
    attestation_id: str
    valid: bool
    issuer_verified: bool = False
    signature_verified: bool = False
    digest_valid: bool = False
    not_expired: bool = False
    level: str = ""
    reason: str = ""
    verifier_key_digest: str = ""
    # v2.8.2: Cryptographic binding between issuer fingerprint and verifier key
    issuer_key_fingerprint_match: bool = False
    derived_fingerprint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "attestation_id": self.attestation_id,
            "valid": self.valid,
            "issuer_verified": self.issuer_verified,
            "signature_verified": self.signature_verified,
            "digest_valid": self.digest_valid,
            "not_expired": self.not_expired,
            "level": self.level,
            "reason": self.reason,
            "verifier_key_digest": self.verifier_key_digest,
            "issuer_key_fingerprint_match": self.issuer_key_fingerprint_match,
            "derived_fingerprint": self.derived_fingerprint,
        }


def derive_fingerprint(public_key_pem: str) -> str:
    """Derive a SHA-256 fingerprint from a public key PEM.

    v2.8.2: This ensures the issuer fingerprint is cryptographically
    bound to the verification key, not just string-matched.

    Uses the same formula as the rest of the platform:
        SHA-256(DER-encoded SubjectPublicKeyInfo)[:32]
    """
    from cryptography.hazmat.primitives import serialization
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(public_der).hexdigest()[:32]


class AttestationIssuerResolver:
    """Maps issuer fingerprints to public key PEMs.

    v2.8.2: Cryptographic binding between issuer identity and verification key.
    The resolver provides the public key for a given issuer fingerprint.
    During verification, the fingerprint is recomputed from the resolved key
    and compared to the attestation's issuer_fingerprint.
    """

    def __init__(self) -> None:
        self._keys: dict[str, str] = {}  # fingerprint -> public_key_pem

    def add_issuer(self, fingerprint: str, public_key_pem: str) -> None:
        """Register a trusted attestation issuer."""
        self._keys[fingerprint] = public_key_pem

    def resolve(self, fingerprint: str) -> str | None:
        """Resolve an issuer fingerprint to a public key PEM."""
        return self._keys.get(fingerprint)

    @property
    def known_fingerprints(self) -> list[str]:
        return list(self._keys.keys())


def verify_attestation(
    attestation: SupplyChainAttestation,
    public_key_pem: str | None = None,
    expected_issuer_fingerprint: str | None = None,
    expected_artifact_digest: str | None = None,
    issuer_resolver: AttestationIssuerResolver | None = None,
) -> AttestationVerifyResult:
    """Verify a supply chain attestation.

    Checks:
    1. Attestation digest matches content
    2. Signature is cryptographically valid (when public key provided)
    3. Issuer fingerprint matches expected (when provided)
    4. Artifact digest matches expected (when provided)
    5. Not expired

    Returns AttestationVerifyResult.
    """
    result = AttestationVerifyResult(
        attestation_id=attestation.attestation_id,
        valid=False,
        level=attestation.attestation_level,
    )

    # 1. Digest check
    data = attestation.to_dict()
    expected_digest = compute_attestation_digest(data)
    if attestation.attestation_digest and attestation.attestation_digest != expected_digest:
        result.reason = f"Attestation digest mismatch: stored={attestation.attestation_digest}, computed={expected_digest}"
        return result
    result.digest_valid = True

    # 2. Expiry check
    if attestation.is_expired():
        result.reason = "Attestation has expired"
        return result
    result.not_expired = True

    # 3. Issuer fingerprint check
    if expected_issuer_fingerprint is not None:
        if attestation.issuer_fingerprint != expected_issuer_fingerprint:
            result.reason = (
                f"Issuer fingerprint mismatch: expected={expected_issuer_fingerprint}, "
                f"actual={attestation.issuer_fingerprint}"
            )
            return result
    result.issuer_verified = True

    # 4. Artifact digest check
    if expected_artifact_digest is not None:
        if attestation.artifact_digest != expected_artifact_digest:
            result.reason = (
                f"Artifact digest mismatch: expected={expected_artifact_digest}, "
                f"actual={attestation.artifact_digest}"
            )
            return result

    # 5. Resolve public key (v2.8.2: via resolver or direct)
    resolved_key_pem = public_key_pem
    if issuer_resolver is not None and resolved_key_pem is None:
        resolved_key_pem = issuer_resolver.resolve(attestation.issuer_fingerprint)
        if resolved_key_pem is None:
            result.reason = (
                f"Attestation issuer '{attestation.issuer_fingerprint}' "
                "is not known to the issuer resolver"
            )
            return result

    # 6. Signature verification + fingerprint binding
    if attestation.signature and resolved_key_pem:
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding

            public_key = serialization.load_pem_public_key(resolved_key_pem.encode())

            # v2.8.2: Derive fingerprint from the verification key and compare
            public_der = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            derived_fp = hashlib.sha256(public_der).hexdigest()[:32]
            result.derived_fingerprint = derived_fp

            if derived_fp != attestation.issuer_fingerprint:
                result.reason = (
                    f"Issuer key fingerprint mismatch: "
                    f"attestation claims '{attestation.issuer_fingerprint}' "
                    f"but verification key derives '{derived_fp}'"
                )
                return result
            result.issuer_key_fingerprint_match = True

            payload = {k: v for k, v in data.items()
                       if k not in ("signature", "attestation_digest")}
            canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            public_key.verify(
                bytes.fromhex(attestation.signature),
                canonical.encode(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            result.signature_verified = True
            result.verifier_key_digest = hashlib.sha256(resolved_key_pem.encode()).hexdigest()
        except Exception as e:
            result.reason = f"Signature verification failed: {e}"
            return result
    elif attestation.signature and not resolved_key_pem:
        # Signature present but no key to verify
        result.signature_verified = False
        result.reason = "Signature present but no public key provided for verification"
        return result

    result.valid = True
    result.reason = "Attestation verified"
    return result


# ── Attestation Policy ──────────────────────────────────────────────────────

def check_attestation_policy(
    attestation: SupplyChainAttestation,
    verify_result: AttestationVerifyResult,
    org_profile: Any | None = None,
) -> tuple[bool, str]:
    """Check if an attestation is accepted by organization policy.

    IMPORTANT: Even when accepted, an attestation does NOT:
      - Upgrade the package trust level
      - Bypass certification
      - Bypass sandbox requirements
      - Override federation conflicts

    Returns (accepted, reason).
    """
    if not verify_result.valid:
        return False, f"Attestation not verified: {verify_result.reason}"

    if org_profile is None:
        return True, "No profile restrictions on attestations"

    # Check if attestations are required
    require_attestations = getattr(org_profile, "require_supply_chain_attestations", False)
    if not require_attestations:
        return True, "Attestations not required by profile"

    # Check minimum level
    min_level = getattr(org_profile, "minimum_attestation_level", "none")
    if level_rank(attestation.attestation_level) < level_rank(min_level):
        return False, (
            f"Attestation level '{attestation.attestation_level}' "
            f"below minimum '{min_level}' required by profile"
        )

    # Check trusted issuers (v2.8.1: fail closed on empty allowlist)
    trusted_issuers = getattr(org_profile, "trusted_attestation_issuers", [])
    require_sig = getattr(org_profile, "require_attestation_signature", False)
    allow_any = getattr(org_profile, "allow_any_attestation_issuer", False)

    if require_sig and not allow_any:
        # v2.8.1: When signature is required, issuer allowlist must be explicit.
        # Empty trusted_attestation_issuers fails closed.
        if not trusted_issuers:
            return False, (
                "Profile requires signed attestations but "
                "trusted_attestation_issuers is empty — "
                "strict profiles must define an explicit issuer allowlist "
                "or set allow_any_attestation_issuer=True"
            )
        if attestation.issuer_fingerprint not in trusted_issuers:
            return False, (
                f"Attestation issuer '{attestation.issuer_fingerprint}' "
                "not in trusted_attestation_issuers"
            )
    elif trusted_issuers and attestation.issuer_fingerprint not in trusted_issuers:
        # Non-signature mode: still check allowlist if provided
        return False, (
            f"Attestation issuer '{attestation.issuer_fingerprint}' "
            "not in trusted_attestation_issuers"
        )

    # Check signature verification (when required)
    if require_sig and not verify_result.signature_verified:
        return False, "Profile requires cryptographically verified attestation signatures"

    return True, "Attestation accepted by policy"


# ── Attestation Receipt ─────────────────────────────────────────────────────

@dataclass
class AttestationReceipt:
    """Receipt recording the observation and verification of an attestation.

    Binds the attestation to the verifying policy profile.
    """
    attestation_id: str
    artifact_digest: str
    package_name: str
    package_version: str
    attestation_type: str
    attestation_level: str
    issuer: str
    issuer_fingerprint: str
    verified: bool
    verification_reason: str = ""
    policy_accepted: bool = False
    policy_profile_digest: str = ""
    observed_at: str = ""
    receipt_digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = {
            "attestation_id": self.attestation_id,
            "artifact_digest": self.artifact_digest,
            "package_name": self.package_name,
            "package_version": self.package_version,
            "attestation_type": self.attestation_type,
            "attestation_level": self.attestation_level,
            "issuer": self.issuer,
            "issuer_fingerprint": self.issuer_fingerprint,
            "verified": self.verified,
            "verification_reason": self.verification_reason,
            "policy_accepted": self.policy_accepted,
            "policy_profile_digest": self.policy_profile_digest,
            "observed_at": self.observed_at,
        }
        d["receipt_digest"] = hashlib.sha256(
            json.dumps(d, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return d


# ── Attestation Store ───────────────────────────────────────────────────────

@dataclass
class AttestationStoreEntry:
    """An entry in the attestation store."""
    attestation: SupplyChainAttestation
    receipt: AttestationReceipt
    added_at: str = ""


class AttestationStore:
    """File-backed store for supply chain attestations."""

    def __init__(self) -> None:
        self._entries: dict[str, AttestationStoreEntry] = {}  # attestation_id -> entry

    def add(self, entry: AttestationStoreEntry) -> None:
        self._entries[entry.attestation.attestation_id] = entry

    def get(self, attestation_id: str) -> AttestationStoreEntry | None:
        return self._entries.get(attestation_id)

    def find_for_artifact(self, artifact_digest: str) -> list[AttestationStoreEntry]:
        """Find all attestations for a given artifact digest."""
        return [
            e for e in self._entries.values()
            if e.attestation.matches_artifact(artifact_digest)
        ]

    def find_for_package(
        self, package_name: str, package_version: str = "",
    ) -> list[AttestationStoreEntry]:
        """Find all attestations for a given package."""
        return [
            e for e in self._entries.values()
            if e.attestation.matches_package(package_name, package_version)
        ]

    def all_entries(self) -> list[AttestationStoreEntry]:
        return list(self._entries.values())

    @property
    def count(self) -> int:
        return len(self._entries)


def save_attestation_store(store: AttestationStore, path: str) -> None:
    """Save attestation store to file."""
    data = {
        "entries": [
            {
                "attestation": e.attestation.to_dict(),
                "receipt": e.receipt.to_dict(),
                "added_at": e.added_at,
            }
            for e in store.all_entries()
        ],
    }
    Path(path).write_text(
        json.dumps(data, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def load_attestation_store(path: str) -> AttestationStore:
    """Load attestation store from file."""
    try:
        raw = Path(path).read_text(encoding="utf-8")
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as e:
        raise AttestationError(f"Attestation store is corrupt: {e}") from e
    except FileNotFoundError:
        return AttestationStore()

    store = AttestationStore()
    for item in data.get("entries", []):
        att = SupplyChainAttestation.from_dict(item["attestation"])
        receipt_d = item["receipt"]
        receipt = AttestationReceipt(
            attestation_id=receipt_d["attestation_id"],
            artifact_digest=receipt_d["artifact_digest"],
            package_name=receipt_d["package_name"],
            package_version=receipt_d["package_version"],
            attestation_type=receipt_d["attestation_type"],
            attestation_level=receipt_d["attestation_level"],
            issuer=receipt_d["issuer"],
            issuer_fingerprint=receipt_d["issuer_fingerprint"],
            verified=receipt_d["verified"],
            verification_reason=receipt_d.get("verification_reason", ""),
            policy_accepted=receipt_d.get("policy_accepted", False),
            policy_profile_digest=receipt_d.get("policy_profile_digest", ""),
            observed_at=receipt_d.get("observed_at", ""),
        )
        entry = AttestationStoreEntry(
            attestation=att,
            receipt=receipt,
            added_at=item.get("added_at", ""),
        )
        store.add(entry)

    return store


# ── Bundle helper ───────────────────────────────────────────────────────────

def create_attestation(
    artifact_digest: str,
    package_name: str,
    package_version: str,
    attestation_type: str = "build",
    attestation_level: str = "build",
    subject: str = "",
    issuer: str = "",
    issuer_fingerprint: str = "",
    statement: dict[str, Any] | None = None,
    valid_until: str = "",
    private_key: Any = None,
) -> SupplyChainAttestation:
    """Create and optionally sign a supply chain attestation."""
    if attestation_type not in ATTESTATION_TYPES:
        raise AttestationError(f"Invalid attestation type: {attestation_type}")
    if attestation_level not in ATTESTATION_LEVELS:
        raise AttestationError(f"Invalid attestation level: {attestation_level}")

    attestation_id = hashlib.sha256(
        f"{artifact_digest}:{package_name}:{package_version}:{attestation_type}".encode()
    ).hexdigest()[:16]

    att = SupplyChainAttestation(
        attestation_id=attestation_id,
        artifact_digest=artifact_digest,
        package_name=package_name,
        package_version=package_version,
        attestation_type=attestation_type,
        attestation_level=attestation_level,
        subject=subject,
        issuer=issuer,
        issuer_fingerprint=issuer_fingerprint,
        issued_at=datetime.now(timezone.utc).isoformat(),
        valid_until=valid_until,
        statement=statement or {},
    )

    if private_key is not None:
        att.signature = sign_attestation(att, private_key=private_key)

    # Compute digest
    d = att.to_dict()
    att.attestation_digest = d["attestation_digest"]

    return att
