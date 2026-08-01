"""Signed Evidence Checkpoints and Recovery Verification (v2.10.0).

Converts the retention layer from locally consistent storage into a
reviewable evidence-history subsystem.

Core design principles:
    1. A checkpoint is a signed snapshot of the retention state at a point in time.
    2. Checkpoints form a chain: each references its predecessor's digest.
    3. No checkpoint rewriting without retaining a detectable discontinuity.
    4. Verification confirms: manifest integrity, checkpoint signature,
       predecessor continuity, retained artifact availability, artifact digest validity.
    5. Recovery reports surface: orphans, missing artifacts, corrupted artifacts,
       broken chains, and unresolved operations.

Checkpoint chain structure:
    checkpoint_id
    sequence_number          # monotonic
    previous_checkpoint_digest  # "" for genesis
    manifest_digest           # RetentionManifest digest
    index_digest              # Evidence index digest at checkpoint time
    policy_profile_digest     # Active org policy profile digest
    artifact_count            # Number of indexed artifacts
    generated_at              # ISO timestamp
    signer_fingerprint        # SHA-256(DER SubjectPublicKeyInfo)[:32]
    checkpoint_digest         # SHA-256 of all fields except signature and itself
    signature                 # RSA-PSS-SHA256 hex signature over checkpoint_digest

Crash-safety invariants (v2.10.9):
    CP-022: checkpoint_prepared state persisted before chain.save().
           Reconciliation can match checkpoint_digest against the chain
           even if mark_chain_committed never ran.
    CP-023: reconcile() is store-aware. A prepared operation whose
           manifest artifact exists in the store needs intervention.
    CP-024: Aborted checkpoint manifests are excluded from future snapshots.
    CP-025: CheckpointJournal has its own lock for all mutations.
    CP-026: chain.save() is atomic (temp file + fsync + os.replace + dir fsync).
           A checkpoint may be auto-aborted from checkpoint_prepared only when
           chain persistence cannot expose a partially committed checkpoint.
           Since chain.save() uses atomic_write_json(), a crash during save
           leaves either the old file intact or the new file fully written.
           There is no partial-commit window.
           Regression assertion: test_cp026_chain_save_atomicity.
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

from .artifact_retention import (
    ContentAddressedStore,
    RetentionError,
    atomic_write_json,
)


class CheckpointError(Exception):
    """Raised when checkpoint creation or verification fails."""


class CheckpointSignerResolver:
    """Maps checkpoint signer fingerprints to their public keys.

    v2.10.3: Organization-authorized checkpoint signing.
    A checkpoint signer is not trusted merely because a signature verifies.
    The signer must be authorized by the active organization policy.
    """

    def __init__(self) -> None:
        self._signers: dict[str, str] = {}  # fingerprint → public_key_pem

    def add_signer(self, public_key_pem: str) -> str:
        """Add a signer from a PEM-encoded public key.

        Returns the derived fingerprint.
        """
        fingerprint = derive_fingerprint(public_key_pem)
        self._signers[fingerprint] = public_key_pem
        return fingerprint

    def get_key(self, fingerprint: str) -> str | None:
        """Get public key for a fingerprint."""
        return self._signers.get(fingerprint)

    def is_known(self, fingerprint: str) -> bool:
        """Check if a fingerprint is registered."""
        return fingerprint in self._signers

    @property
    def known_fingerprints(self) -> list[str]:
        return sorted(self._signers.keys())


def check_checkpoint_signer_policy(
    checkpoint: EvidenceCheckpoint,
    profile: Any,  # OrganizationTrustPolicyProfile
    signer_resolver: CheckpointSignerResolver | None = None,
) -> tuple[bool, str]:
    """Check if a checkpoint signer is authorized under an org policy.

    v2.10.4: Resolver provides keys, not authorization.
    A signer known to the resolver but not in the profile's trusted list
    is NOT authorized.

    Enforcement chain:
    1. If profile.allow_any_checkpoint_signer → allow (crypto-only mode)
    2. If require_checkpoint_signer_authorization:
       a. trusted_checkpoint_signers must be non-empty
       b. signer fingerprint must be in trusted_checkpoint_signers
       c. (resolver is consulted by caller to obtain the key for verification)
    3. Otherwise → cryptographic verification only
    """
    # Step 1: Opt-in allow-any
    if getattr(profile, "allow_any_checkpoint_signer", False):
        return True, ""

    # Step 2: Strict authorization
    require_auth = getattr(profile, "require_checkpoint_signer_authorization", False)
    trusted_list = getattr(profile, "trusted_checkpoint_signers", [])

    if require_auth:
        # trusted_checkpoint_signers must be non-empty
        if not trusted_list:
            return False, (
                "Checkpoint signer authorization required but no trusted "
                "checkpoint signers configured"
            )
        # Signer must be in the profile's trusted list
        if checkpoint.signer_fingerprint not in trusted_list:
            return False, (
                f"Checkpoint signer fingerprint {checkpoint.signer_fingerprint} "
                f"is not in the trusted checkpoint signers list"
            )
        return True, ""

    # Step 3: Authorization not required — crypto-only
    return True, ""


def resolve_verification_key(
    checkpoint: EvidenceCheckpoint,
    profile: Any | None,
    signer_resolver: CheckpointSignerResolver | None,
    caller_public_key_pem: str | None,
) -> tuple[str | None, str | None]:
    """Resolve the correct public key for checkpoint verification.

    v2.10.4: Enforces profile-authorized signer selection.

    Returns (key_pem, error).
    - If key_pem is None and error is set, verification must not proceed.
    - If key_pem is None and error is None, no profile enforcement active
      and no caller key → caller handles (e.g. indeterminate).

    Enforcement:
    1. No profile → use caller-supplied key (backwards-compatible)
    2. allow_any_checkpoint_signer → use caller-supplied key
    3. require_checkpoint_signer_authorization:
       a. Signer must be in trusted_checkpoint_signers
       b. Resolver must be provided
       c. Resolver must return key for this signer
       d. derive_fingerprint(resolved_key) must equal checkpoint.signer_fingerprint
       e. Caller-supplied key is IGNORED
    """
    # Step 1: No profile → backwards-compatible
    if profile is None:
        return caller_public_key_pem, None

    # Step 2: Allow-any → crypto-only, use caller key
    if getattr(profile, "allow_any_checkpoint_signer", False):
        return caller_public_key_pem, None

    # Step 3: Strict authorization
    require_auth = getattr(profile, "require_checkpoint_signer_authorization", False)
    if not require_auth:
        return caller_public_key_pem, None

    # 3a: Signer must be in trusted list
    trusted_list = getattr(profile, "trusted_checkpoint_signers", [])
    if not trusted_list:
        return None, (
            "Checkpoint signer authorization required but no trusted "
            "checkpoint signers configured"
        )

    if checkpoint.signer_fingerprint not in trusted_list:
        return None, (
            f"Checkpoint signer fingerprint {checkpoint.signer_fingerprint} "
            f"is not in the trusted checkpoint signers list"
        )

    # 3b: Resolver must be provided
    if signer_resolver is None:
        return None, (
            "Checkpoint signer authorization requires a CheckpointSignerResolver "
            "but none was provided"
        )

    # 3c: Resolver must return key for this signer
    resolved_key = signer_resolver.get_key(checkpoint.signer_fingerprint)
    if resolved_key is None:
        return None, (
            f"Checkpoint signer fingerprint {checkpoint.signer_fingerprint} "
            f"is in the trusted list but not found in the resolver"
        )

    # 3d: Fingerprint binding
    resolved_fp = derive_fingerprint(resolved_key)
    if resolved_fp != checkpoint.signer_fingerprint:
        return None, (
            "Resolver key fingerprint does not match checkpoint signer_fingerprint"
        )

    # 3e: Return resolved key (caller key ignored)
    return resolved_key, None


# ── Checkpoint Operation Journal (v2.10.7) ────────────────────────────────

# Journal statuses
JOURNAL_PREPARED = "prepared"
JOURNAL_MANIFEST_RETAINED = "manifest_retained"
JOURNAL_CHECKPOINT_PREPARED = "checkpoint_prepared"  # v2.10.9: checkpoint identity recorded before chain save
JOURNAL_CHAIN_COMMITTED = "chain_committed"  # chain saved, journal not yet committed
JOURNAL_COMMITTED = "committed"
JOURNAL_ABORTED = "aborted"


@dataclass
class CheckpointOperation:
    """A checkpoint creation operation tracked in the journal."""
    operation_id: str
    status: str
    sequence: int
    predecessor_digest: str
    manifest_digest: str
    policy_profile_digest: str
    signer_fingerprint: str
    started_at: str
    completed_at: str = ""
    abort_reason: str = ""
    checkpoint_id: str = ""  # v2.10.8: set before chain save
    checkpoint_digest: str = ""  # v2.10.8: set before chain save

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "status": self.status,
            "sequence": self.sequence,
            "predecessor_digest": self.predecessor_digest,
            "manifest_digest": self.manifest_digest,
            "policy_profile_digest": self.policy_profile_digest,
            "signer_fingerprint": self.signer_fingerprint,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "abort_reason": self.abort_reason,
            "checkpoint_id": self.checkpoint_id,
            "checkpoint_digest": self.checkpoint_digest,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CheckpointOperation:
        return cls(
            operation_id=d["operation_id"],
            status=d["status"],
            sequence=d.get("sequence", 0),
            predecessor_digest=d.get("predecessor_digest", ""),
            manifest_digest=d.get("manifest_digest", ""),
            policy_profile_digest=d.get("policy_profile_digest", ""),
            signer_fingerprint=d.get("signer_fingerprint", ""),
            started_at=d.get("started_at", ""),
            completed_at=d.get("completed_at", ""),
            abort_reason=d.get("abort_reason", ""),
            checkpoint_id=d.get("checkpoint_id", ""),
            checkpoint_digest=d.get("checkpoint_digest", ""),
        )


class CheckpointJournal:
    """Durable journal for checkpoint operations.

    v2.10.7 (CP-018): Ensures evidence-commit durability.
    v2.10.8 (CP-019/020/021): Manifest digest binding, strict loading,
    crash reconciliation with intermediate chain_committed state.

    Lifecycle:
        prepared -> manifest_retained -> chain_committed -> committed
        prepared -> manifest_retained -> aborted
        prepared -> aborted

    A missing journal file means no operations recorded.
    An existing journal with corrupt content raises CheckpointError.
    """

    SCHEMA_VERSION = "1.0.0"

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock_path = Path(str(path) + ".lock")

    def _acquire_lock(self) -> int:
        """v2.10.9 (CP-025): Acquire exclusive journal lock."""
        import time
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = None
        for _ in range(100):  # 10 second timeout
            try:
                fd = os.open(
                    str(self._lock_path),
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                )
                return fd
            except FileExistsError:
                time.sleep(0.1)
        raise CheckpointError("Timeout acquiring journal lock")

    def _release_lock(self, fd: int) -> None:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            self._lock_path.unlink()
        except FileNotFoundError:
            pass

    def _load(self) -> dict[str, Any]:
        """Load journal, strictly.

        v2.10.8 (CP-020): Existing corrupt file raises CheckpointError.
        Missing file returns empty journal (legitimate initial state).
        """
        if not self.path.exists():
            return {"schema_version": self.SCHEMA_VERSION, "operations": []}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            raise CheckpointError(
                f"Checkpoint journal is corrupt and cannot be loaded: {e}"
            ) from e
        if "schema_version" not in data:
            raise CheckpointError(
                "Checkpoint journal missing schema_version field"
            )
        if "operations" not in data:
            raise CheckpointError(
                "Checkpoint journal missing operations field"
            )
        if not isinstance(data["operations"], list):
            raise CheckpointError(
                "Checkpoint journal operations is not a list"
            )
        for i, op in enumerate(data["operations"]):
            if not isinstance(op, dict):
                raise CheckpointError(
                    f"Checkpoint journal operation {i} is not a dict"
                )
            for req in ("operation_id", "status"):
                if req not in op:
                    raise CheckpointError(
                        f"Checkpoint journal operation {i} missing required field: {req}"
                    )
        return data

    def _save(self, data: dict[str, Any]) -> None:
        atomic_write_json(self.path, data)

    def prepare(
        self,
        operation_id: str,
        sequence: int,
        predecessor_digest: str,
        manifest_digest: str,
        policy_profile_digest: str,
        signer_fingerprint: str,
    ) -> CheckpointOperation:
        """Record a prepared checkpoint operation.

        v2.10.8 (CP-019): manifest_digest is the expected digest of the
        manifest artifact that will be retained.
        """
        op = CheckpointOperation(
            operation_id=operation_id,
            status=JOURNAL_PREPARED,
            sequence=sequence,
            predecessor_digest=predecessor_digest,
            manifest_digest=manifest_digest,
            policy_profile_digest=policy_profile_digest,
            signer_fingerprint=signer_fingerprint,
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        fd = self._acquire_lock()
        try:
            data = self._load()
            data["operations"].append(op.to_dict())
            self._save(data)
        finally:
            self._release_lock(fd)
        return op

    def mark_manifest_retained(
        self, operation_id: str, manifest_digest: str = "",
    ) -> None:
        """Mark operation as having retained a manifest artifact.

        v2.10.8 (CP-019): Records the actual manifest digest and verifies
        it matches the prepared digest if one was set.
        v2.10.9 (CP-025): Under journal lock.
        """
        fd = self._acquire_lock()
        try:
            data = self._load()
            for op in data["operations"]:
                if op["operation_id"] == operation_id:
                    prepared_digest = op.get("manifest_digest", "")
                    if prepared_digest and manifest_digest and prepared_digest != manifest_digest:
                        raise CheckpointError(
                            f"Manifest digest mismatch: prepared={prepared_digest}, "
                            f"actual={manifest_digest}"
                        )
                    op["status"] = JOURNAL_MANIFEST_RETAINED
                    if manifest_digest:
                        op["manifest_digest"] = manifest_digest
                    break
            self._save(data)
        finally:
            self._release_lock(fd)

    def mark_checkpoint_prepared(
        self, operation_id: str, checkpoint_id: str, checkpoint_digest: str,
    ) -> None:
        """Record checkpoint identity BEFORE chain save.

        v2.10.9 (CP-022): Persists checkpoint_id and checkpoint_digest
        so that reconciliation can identify an already-committed checkpoint
        even if chain_committed was never recorded.
        """
        fd = self._acquire_lock()
        try:
            data = self._load()
            for op in data["operations"]:
                if op["operation_id"] == operation_id:
                    op["status"] = JOURNAL_CHECKPOINT_PREPARED
                    op["checkpoint_id"] = checkpoint_id
                    op["checkpoint_digest"] = checkpoint_digest
                    break
            self._save(data)
        finally:
            self._release_lock(fd)

    def mark_chain_committed(
        self, operation_id: str, checkpoint_id: str, checkpoint_digest: str,
    ) -> None:
        """Mark that the checkpoint has been appended to the chain.

        v2.10.8 (CP-021): Intermediate state between manifest retention
        and journal commit. Survives crashes.
        v2.10.9 (CP-025): Under journal lock.
        """
        fd = self._acquire_lock()
        try:
            data = self._load()
            for op in data["operations"]:
                if op["operation_id"] == operation_id:
                    op["status"] = JOURNAL_CHAIN_COMMITTED
                    op["checkpoint_id"] = checkpoint_id
                    op["checkpoint_digest"] = checkpoint_digest
                    break
            self._save(data)
        finally:
            self._release_lock(fd)

    def mark_committed(self, operation_id: str) -> None:
        """Mark operation as fully committed (journal finalized)."""
        fd = self._acquire_lock()
        try:
            data = self._load()
            for op in data["operations"]:
                if op["operation_id"] == operation_id:
                    op["status"] = JOURNAL_COMMITTED
                    op["completed_at"] = datetime.now(timezone.utc).isoformat()
                    break
            self._save(data)
        finally:
            self._release_lock(fd)

    def mark_aborted(self, operation_id: str, reason: str) -> None:
        """Mark operation as aborted with reason."""
        fd = self._acquire_lock()
        try:
            data = self._load()
            for op in data["operations"]:
                if op["operation_id"] == operation_id:
                    op["status"] = JOURNAL_ABORTED
                    op["completed_at"] = datetime.now(timezone.utc).isoformat()
                    op["abort_reason"] = reason
                    break
            self._save(data)
        finally:
            self._release_lock(fd)

    def get_operations(self) -> list[CheckpointOperation]:
        """Return all operations."""
        data = self._load()
        return [CheckpointOperation.from_dict(op) for op in data.get("operations", [])]

    def get_uncommitted(self) -> list[CheckpointOperation]:
        """Return operations not yet committed."""
        return [
            op for op in self.get_operations()
            if op.status in (
                JOURNAL_MANIFEST_RETAINED, JOURNAL_PREPARED,
                JOURNAL_CHAIN_COMMITTED, JOURNAL_CHECKPOINT_PREPARED,
            )
        ]

    def get_aborted(self) -> list[CheckpointOperation]:
        """Return aborted operations."""
        return [
            op for op in self.get_operations()
            if op.status == JOURNAL_ABORTED
        ]

    def get_manifest_digests_in_progress(self) -> set[str]:
        """Return manifest digests for operations that retained manifests
        but are not fully committed.

        These must not be garbage collected.
        """
        result = set()
        for op in self.get_operations():
            if op.status in (JOURNAL_MANIFEST_RETAINED, JOURNAL_ABORTED, JOURNAL_CHAIN_COMMITTED, JOURNAL_CHECKPOINT_PREPARED):
                if op.manifest_digest:
                    result.add(op.manifest_digest)
        return result

    def get_aborted_manifest_digests(self) -> set[str]:
        """Return manifest digests for aborted operations specifically.

        v2.10.8: These manifests must be excluded from future checkpoint snapshots.
        """
        result = set()
        for op in self.get_aborted():
            if op.manifest_digest:
                result.add(op.manifest_digest)
        return result

    def reconcile(
        self,
        chain: CheckpointChain | None = None,
        store: ContentAddressedStore | None = None,
    ) -> list[CheckpointOperation]:
        """Reconcile nonterminal operations against chain and store.

        v2.10.9 (CP-022/023): Deterministic crash recovery.

        For each nonterminal operation:
        - chain_committed -> committed (crash after chain save, before journal commit)
        - checkpoint_prepared + checkpoint_digest in chain -> committed
        - checkpoint_prepared + checkpoint_digest NOT in chain -> needs intervention
        - manifest_retained + checkpoint_digest in chain -> committed
        - manifest_retained + no checkpoint_digest + store has manifest -> needs intervention
        - manifest_retained + store missing manifest -> invalid
        - prepared + store has expected manifest -> needs intervention (crash after retain)
        - prepared + store missing manifest -> safe to abort

        Returns operations that still need intervention after reconciliation.
        """
        nonterminal = self.get_uncommitted()
        if not nonterminal:
            return []

        needs_intervention = []

        chain_digests = set()
        if chain is not None:
            for cp in chain.get_checkpoints():
                chain_digests.add(cp.checkpoint_digest)

        def manifest_in_store(digest: str) -> bool:
            if not store or not digest:
                return False
            return store._artifact_path(digest).exists()

        fd = self._acquire_lock()
        try:
            data = self._load()
            ops_by_id = {op["operation_id"]: op for op in data["operations"]}
            now = datetime.now(timezone.utc).isoformat()

            for op in nonterminal:
                if op.status == JOURNAL_CHAIN_COMMITTED:
                    ops_by_id[op.operation_id]["status"] = JOURNAL_COMMITTED
                    ops_by_id[op.operation_id]["completed_at"] = now

                elif op.status == JOURNAL_CHECKPOINT_PREPARED:
                    if op.checkpoint_digest and op.checkpoint_digest in chain_digests:
                        ops_by_id[op.operation_id]["status"] = JOURNAL_COMMITTED
                        ops_by_id[op.operation_id]["completed_at"] = now
                    else:
                        # Checkpoint identity recorded but chain save didn't complete
                        ops_by_id[op.operation_id]["status"] = JOURNAL_ABORTED
                        ops_by_id[op.operation_id]["completed_at"] = now
                        ops_by_id[op.operation_id]["abort_reason"] = (
                            "Reconciled: checkpoint prepared but chain save incomplete"
                        )

                elif op.status == JOURNAL_MANIFEST_RETAINED:
                    if op.checkpoint_digest and op.checkpoint_digest in chain_digests:
                        # Crash after chain save but before checkpoint_prepared recorded
                        ops_by_id[op.operation_id]["status"] = JOURNAL_COMMITTED
                        ops_by_id[op.operation_id]["completed_at"] = now
                    elif manifest_in_store(op.manifest_digest):
                        # Manifest retained but checkpoint never completed
                        needs_intervention.append(op)
                    else:
                        needs_intervention.append(op)

                elif op.status == JOURNAL_PREPARED:
                    # v2.10.9 (CP-023): Check if manifest was actually retained
                    if manifest_in_store(op.manifest_digest):
                        # Crash after retain, before mark_manifest_retained
                        needs_intervention.append(op)
                    else:
                        # No artifact was retained — safe to abort
                        ops_by_id[op.operation_id]["status"] = JOURNAL_ABORTED
                        ops_by_id[op.operation_id]["completed_at"] = now
                        ops_by_id[op.operation_id]["abort_reason"] = (
                            "Reconciled: prepared without manifest retention"
                        )

            self._save(data)
        finally:
            self._release_lock(fd)

        return needs_intervention



@dataclass
class EvidenceCheckpoint:
    """A signed snapshot of the retention state."""

    checkpoint_id: str
    sequence_number: int
    previous_checkpoint_digest: str  # "" for genesis
    manifest_digest: str
    index_digest: str
    policy_profile_digest: str
    artifact_count: int
    generated_at: str
    signer_fingerprint: str
    checkpoint_digest: str = ""
    signature: str = ""

    def __post_init__(self) -> None:
        if not self.checkpoint_digest:
            self.checkpoint_digest = self._compute_digest()

    def _compute_digest(self) -> str:
        """Compute SHA-256 over all fields except checkpoint_digest and signature."""
        d = self._signed_payload()
        return hashlib.sha256(
            json.dumps(d, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def _signed_payload(self) -> dict[str, Any]:
        """Return the fields that are covered by the digest/signature."""
        return {
            "checkpoint_id": self.checkpoint_id,
            "sequence_number": self.sequence_number,
            "previous_checkpoint_digest": self.previous_checkpoint_digest,
            "manifest_digest": self.manifest_digest,
            "index_digest": self.index_digest,
            "policy_profile_digest": self.policy_profile_digest,
            "artifact_count": self.artifact_count,
            "generated_at": self.generated_at,
            "signer_fingerprint": self.signer_fingerprint,
        }

    def to_dict(self) -> dict[str, Any]:
        d = self._signed_payload()
        d["checkpoint_digest"] = self.checkpoint_digest
        d["signature"] = self.signature
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceCheckpoint:
        return cls(
            checkpoint_id=data["checkpoint_id"],
            sequence_number=data["sequence_number"],
            previous_checkpoint_digest=data.get("previous_checkpoint_digest", ""),
            manifest_digest=data["manifest_digest"],
            index_digest=data["index_digest"],
            policy_profile_digest=data.get("policy_profile_digest", ""),
            artifact_count=data.get("artifact_count", 0),
            generated_at=data["generated_at"],
            signer_fingerprint=data["signer_fingerprint"],
            checkpoint_digest=data.get("checkpoint_digest", ""),
            signature=data.get("signature", ""),
        )


@dataclass
class RecoveryReport:
    """Result of a full recovery verification."""

    valid: bool
    checkpoint_verified: bool
    chain_continuous: bool
    manifest_intact: bool
    artifacts_available: bool
    artifact_digests_valid: bool
    recoverable_orphans: list[str] = field(default_factory=list)
    missing_artifacts: list[str] = field(default_factory=list)
    corrupted_artifacts: list[str] = field(default_factory=list)
    broken_chain_at: int | None = None  # sequence_number where chain breaks
    unresolved_operations: list[str] = field(default_factory=list)
    checkpoint_sequence: int = 0
    error: str = ""
    checkpoint_indeterminate: bool = False  # v2.10.5: strict policy inputs missing
    uncommitted_operations: list[str] = field(default_factory=list)  # v2.10.7 CP-018
    aborted_operations: list[str] = field(default_factory=list)  # v2.10.7 CP-018


# ── Checkpoint Signing ──────────────────────────────────────────────────────


def sign_checkpoint(
    checkpoint: EvidenceCheckpoint,
    private_key_pem: str | None = None,
    private_key: Any = None,
) -> str:
    """Sign a checkpoint with RSA-PSS-SHA256 over checkpoint_digest.

    Returns the hex signature.
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    if private_key is None and private_key_pem:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(), password=None,
        )

    if private_key is None:
        raise CheckpointError("No private key provided for signing")

    sig = private_key.sign(
        checkpoint.checkpoint_digest.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return sig.hex()


def derive_fingerprint(public_key_pem: str) -> str:
    """Derive fingerprint from a PEM-encoded public key.

    Formula: SHA-256(DER-encoded SubjectPublicKeyInfo)[:32]
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    pub_key = serialization.load_pem_public_key(public_key_pem.encode())
    der = pub_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()[:32]


def derive_fingerprint_from_private(private_key_pem: str) -> str:
    """Derive fingerprint from the public key embedded in a private key.

    v2.10.5: Used to verify private/public key correspondence.
    """
    from cryptography.hazmat.primitives import serialization

    priv_key = serialization.load_pem_private_key(
        private_key_pem.encode(), password=None,
    )
    der = priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()[:32]


def verify_checkpoint_signature(
    checkpoint: EvidenceCheckpoint,
    public_key_pem: str,
) -> bool:
    """Verify checkpoint signature using RSA-PSS-SHA256.

    v2.10.1: Unconditional signer-fingerprint binding.
    Steps:
    1. Recompute checkpoint_digest from payload fields.
    2. Derive fingerprint from supplied public key and compare to
       checkpoint.signer_fingerprint. Fail closed on mismatch.
    3. Verify RSA-PSS-SHA256 signature over checkpoint_digest.
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    # Step 1: Verify checkpoint_digest matches recomputed digest
    recomputed = hashlib.sha256(
        json.dumps(
            checkpoint._signed_payload(),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()

    if recomputed != checkpoint.checkpoint_digest:
        return False

    if not checkpoint.signature:
        return False

    # Step 2 (v2.10.1): Unconditional fingerprint binding
    key_fingerprint = derive_fingerprint(public_key_pem)
    if key_fingerprint != checkpoint.signer_fingerprint:
        return False

    # Step 3: Verify RSA-PSS-SHA256 signature
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    try:
        public_key.verify(
            bytes.fromhex(checkpoint.signature),
            checkpoint.checkpoint_digest.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


# ── Checkpoint Chain ────────────────────────────────────────────────────────


class CheckpointChain:
    """Manages an ordered chain of evidence checkpoints.

    The chain is stored as a JSON file with:
    {
        "schema_version": "1.0.0",
        "checkpoints": [...],
        "chain_id": "...",
    }
    """

    SCHEMA_VERSION = "1.0.0"

    def __init__(self, chain_path: str | Path) -> None:
        self.chain_path = Path(chain_path)
        self._lock_path = self.chain_path.parent / ".checkpoint_chain.lock"

    def _acquire_lock(self) -> int:
        """v2.10.1: Acquire exclusive chain lock."""
        import time
        self.chain_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self._lock_path), os.O_CREAT | os.O_RDWR)
        try:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX)
        except ImportError:
            try:
                import msvcrt
                while True:
                    try:
                        msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
                        break
                    except OSError:
                        time.sleep(0.001)
            except ImportError:
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

    def load(self) -> dict[str, Any]:
        """Load chain file."""
        if not self.chain_path.exists():
            return {
                "schema_version": self.SCHEMA_VERSION,
                "checkpoints": [],
                "chain_id": "",
            }
        raw = self.chain_path.read_text(encoding="utf-8")
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError) as e:
            raise CheckpointError(f"Checkpoint chain is corrupt: {e}") from e
        return data

    def save(self, data: dict[str, Any]) -> None:
        """Atomically write chain file."""
        self.chain_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(self.chain_path, data)

    def get_checkpoints(self) -> list[EvidenceCheckpoint]:
        """Return all checkpoints in sequence order."""
        data = self.load()
        checkpoints = [
            EvidenceCheckpoint.from_dict(c)
            for c in data.get("checkpoints", [])
        ]
        return sorted(checkpoints, key=lambda c: c.sequence_number)

    def get_latest(self) -> EvidenceCheckpoint | None:
        """Return the most recent checkpoint, or None if empty."""
        cps = self.get_checkpoints()
        return cps[-1] if cps else None

    def append(self, checkpoint: EvidenceCheckpoint) -> None:
        """Append a checkpoint to the chain.

        v2.10.1: Entire operation is under chain lock.

        Validates:
        - sequence_number is monotonic
        - previous_checkpoint_digest matches latest checkpoint's digest
        """
        fd = self._acquire_lock()
        try:
            data = self.load()
            checkpoints = data.get("checkpoints", [])

            if checkpoints:
                latest = max(checkpoints, key=lambda c: c.get("sequence_number", 0))
                expected_seq = latest["sequence_number"] + 1
                expected_prev = latest.get("checkpoint_digest", "")

                if checkpoint.sequence_number != expected_seq:
                    raise CheckpointError(
                        f"Sequence number discontinuity: expected {expected_seq}, "
                        f"got {checkpoint.sequence_number}"
                    )

                if checkpoint.previous_checkpoint_digest != expected_prev:
                    raise CheckpointError(
                        "Previous checkpoint digest mismatch: chain continuity broken"
                    )
            else:
                # Genesis checkpoint
                if checkpoint.sequence_number != 1:
                    raise CheckpointError(
                        f"Genesis checkpoint must have sequence_number=1, "
                        f"got {checkpoint.sequence_number}"
                    )
                if checkpoint.previous_checkpoint_digest != "":
                    raise CheckpointError(
                        "Genesis checkpoint must have empty previous_checkpoint_digest"
                    )

            checkpoints.append(checkpoint.to_dict())
            data["checkpoints"] = checkpoints
            data["schema_version"] = self.SCHEMA_VERSION
            if not data.get("chain_id"):
                data["chain_id"] = checkpoint.checkpoint_id

            self.save(data)
        finally:
            self._release_lock(fd)


# ── Checkpoint Creation ─────────────────────────────────────────────────────



def _get_aborted_manifest_exclusions(chain_path: str) -> set[str]:
    """v2.10.9 (CP-024): Get manifest digests from aborted operations.

    These are excluded from checkpoint snapshots.
    """
    try:
        journal = CheckpointJournal(chain_path + ".journal")
        return journal.get_aborted_manifest_digests()
    except CheckpointError:
        return set()


def create_checkpoint(
    store: ContentAddressedStore,
    chain: CheckpointChain,
    private_key_pem: str,
    public_key_pem: str,
    policy_profile_digest: str = "",
    profile: Any | None = None,
    signer_resolver: CheckpointSignerResolver | None = None,
) -> EvidenceCheckpoint:
    """Create a signed checkpoint of the current retention state.

    v2.10.6: Transactional ordering — manifest retention happens inside
    the chain lock after all preconditions pass. Failed checkpoint creation
    leaves no retained artifacts. Strict creation requires resolver
    consistency for genesis checkpoints.

    Steps:
    0. Verify private/public key correspondence.
    0a. Under strict profiles, verify signer authorization + resolver binding.
    1. Verify the store index (fail-closed).
    2. Acquire chain lock.
    3. Verify existing chain under policy.
    4. Determine sequence/predecessor.
    5. Create and retain manifest artifact.
    6. Create checkpoint with chain continuity.
    7. Sign with RSA-PSS-SHA256.
    8. Append to chain under lock.
    9. Release lock.

    Returns the signed checkpoint.
    """
    from .artifact_retention import RetentionManifest

    # Step 0 (v2.10.5): Verify private/public key correspondence
    signer_fp = derive_fingerprint(public_key_pem)
    if signer_fp != derive_fingerprint_from_private(private_key_pem):
        raise CheckpointError(
            "Private key does not correspond to the provided public key"
        )

    # Step 0a (v2.10.5 CP-015 + v2.10.6 CP-017): Under strict profiles,
    # verify signer authorization AND resolver consistency.
    # This applies even for genesis checkpoints.
    if profile is not None and getattr(profile, "require_checkpoint_signer_authorization", False):
        # Check signer is in the allowlist
        authorized, reason = check_checkpoint_signer_policy(
            EvidenceCheckpoint(
                checkpoint_id="",
                sequence_number=0,
                previous_checkpoint_digest="",
                manifest_digest="",
                index_digest="",
                policy_profile_digest=policy_profile_digest,
                artifact_count=0,
                generated_at="",
                signer_fingerprint=signer_fp,
            ),
            profile,
        )
        if not authorized:
            raise CheckpointError(f"Unauthorized checkpoint signer: {reason}")

        # v2.10.6 (CP-017): Verify resolver can resolve this signer
        if not getattr(profile, "allow_any_checkpoint_signer", False):
            if signer_resolver is None:
                raise CheckpointError(
                    "Strict checkpoint creation requires a CheckpointSignerResolver"
                )
            resolved_key = signer_resolver.get_key(signer_fp)
            if resolved_key is None:
                raise CheckpointError(
                    f"Checkpoint signer fingerprint {signer_fp} is authorized "
                    f"but not found in the resolver"
                )
            # Verify resolver key fingerprint matches
            if derive_fingerprint(resolved_key) != signer_fp:
                raise CheckpointError(
                    "Resolver key fingerprint does not match the checkpoint signer"
                )

    # Step 1: Verify store index
    try:
        verified_index = store.load_index()
    except RetentionError as e:
        raise CheckpointError(
            f"Cannot create checkpoint: store index verification failed: {e}"
        ) from e

    # Pre-compute manifest data (do NOT retain yet)
    entries = verified_index.get("entries", {})
    index_digest = verified_index.get("index_digest", "")
    artifact_count = len(entries)

    manifest = RetentionManifest(
        generated_at=datetime.now(timezone.utc).isoformat(),
        artifact_count=artifact_count,
        total_byte_size=sum(
            e.get("byte_size", 0) for e in entries.values()
        ),
        index_digest=index_digest,
        policy_profile_digest=policy_profile_digest,
        retention_policy_id="",
        artifact_digests=sorted(
            # v2.10.9 (CP-024): Exclude aborted checkpoint manifest digests
            # from normal checkpoint snapshots.
            d for d in entries.keys()
            if d not in _get_aborted_manifest_exclusions(str(chain.chain_path))
        ),
    )
    manifest_data = manifest.to_dict()
    manifest_json = json.dumps(manifest_data, sort_keys=True, separators=(",", ":")).encode()

    # Step 2 (v2.10.6 CP-016): Acquire chain lock BEFORE retaining manifest
    fd = chain._acquire_lock()
    try:
        # Step 3: Verify existing chain before extending it (CP-010)
        existing_cps = chain.get_checkpoints()
        if existing_cps:
            chain_result = verify_checkpoint_chain(chain, public_key_pem, profile, signer_resolver)
            if not chain_result.chain_valid:
                raise CheckpointError(
                    f"Cannot create checkpoint: existing chain is invalid: "
                    f"{'; '.join(chain_result.errors[:2])}"
                )

        latest = existing_cps[-1] if existing_cps else None
        if latest:
            seq = latest.sequence_number + 1
            prev_digest = latest.checkpoint_digest
        else:
            seq = 1
            prev_digest = ""

        # Step 5 (v2.10.8 CP-019): Compute expected manifest digest before retention
        expected_manifest_digest = hashlib.sha256(manifest_json).hexdigest()

        # Prepare journal with exact manifest digest (CP-019)
        journal = CheckpointJournal(str(chain.chain_path) + ".journal")
        operation_id = hashlib.sha256(
            f"op:{seq}:{datetime.now(timezone.utc).isoformat()}".encode()
        ).hexdigest()[:16]
        journal.prepare(
            operation_id=operation_id,
            sequence=seq,
            predecessor_digest=prev_digest,
            manifest_digest=expected_manifest_digest,
            policy_profile_digest=policy_profile_digest,
            signer_fingerprint=signer_fp,
        )

        try:
            # Step 5a: Retain manifest INSIDE the lock
            manifest_artifact = store.retain(
                manifest_json,
                media_type="application/vnd.nodechain.retention-manifest+json",
                producer="checkpoint",
                source_type="retention_manifest",
            )
            manifest_digest = manifest_artifact.digest

            # v2.10.8 (CP-019): Verify digest matches prepared value
            if manifest_digest != expected_manifest_digest:
                journal.mark_aborted(operation_id, "Manifest digest mismatch")
                raise CheckpointError(
                    f"Manifest digest mismatch: expected={expected_manifest_digest}, "
                    f"actual={manifest_digest}"
                )

            # Journal: manifest is retained (CP-019: pass actual digest)
            journal.mark_manifest_retained(operation_id, manifest_digest)

            checkpoint = EvidenceCheckpoint(
                checkpoint_id=hashlib.sha256(
                    f"checkpoint:{seq}:{datetime.now(timezone.utc).isoformat()}".encode()
                ).hexdigest()[:16],
                sequence_number=seq,
                previous_checkpoint_digest=prev_digest,
                manifest_digest=manifest_digest,
                index_digest=index_digest,
                policy_profile_digest=policy_profile_digest,
                artifact_count=artifact_count,
                generated_at=datetime.now(timezone.utc).isoformat(),
                signer_fingerprint=signer_fp,
            )

            # Step 7: Sign
            checkpoint.signature = sign_checkpoint(
                checkpoint, private_key_pem=private_key_pem,
            )

            # v2.10.9 (CP-022): Record checkpoint identity BEFORE chain save
            # so that reconciliation can identify an already-committed checkpoint
            # even if chain.save succeeds but mark_chain_committed never runs.
            journal.mark_checkpoint_prepared(
                operation_id, checkpoint.checkpoint_id, checkpoint.checkpoint_digest,
            )

            # Step 8: Append to chain
            data = chain.load()
            cps = data.get("checkpoints", [])
            cps.append(checkpoint.to_dict())
            data["checkpoints"] = cps
            data["schema_version"] = chain.SCHEMA_VERSION
            if not data.get("chain_id"):
                data["chain_id"] = checkpoint.checkpoint_id
            chain.save(data)

            # v2.10.8 (CP-021): Mark chain committed
            journal.mark_chain_committed(
                operation_id, checkpoint.checkpoint_id, checkpoint.checkpoint_digest,
            )
        except Exception as e:
            # Journal: aborted with reason
            journal.mark_aborted(operation_id, str(e))
            raise

        # Journal: fully committed (outside except so this crash window
        # leaves operation at chain_committed for reconciliation)
        journal.mark_committed(operation_id)
    finally:
        chain._release_lock(fd)

    return checkpoint


# ── Checkpoint Verification ─────────────────────────────────────────────────


@dataclass
class CheckpointVerifyResult:
    """Result of verifying a single checkpoint against a store."""
    checkpoint_id: str
    valid: bool
    signature_valid: bool = False
    digest_valid: bool = False
    manifest_matches: bool = False
    artifacts_available: bool = False
    artifact_digests_valid: bool = False
    missing_artifacts: list[str] = field(default_factory=list)
    corrupted_artifacts: list[str] = field(default_factory=list)
    error: str = ""


def verify_checkpoint(
    checkpoint: EvidenceCheckpoint,
    store: ContentAddressedStore,
    public_key_pem: str,
    expected_fingerprint: str | None = None,
    profile: Any | None = None,
    signer_resolver: CheckpointSignerResolver | None = None,
) -> CheckpointVerifyResult:
    """Verify a checkpoint against the current store state.

    v2.10.1: Signer-fingerprint binding is now unconditional.
    Checks:
    1. checkpoint_digest matches recomputed payload digest
    2. signature is valid RSA-PSS-SHA256
    3. signer_fingerprint matches fingerprint(supplied key) — unconditional
    4. manifest_digest matches current index entries
    5. index_digest matches current index
    6. All indexed artifacts exist on disk
    7. All artifact digests are valid
    """
    result = CheckpointVerifyResult(
        checkpoint_id=checkpoint.checkpoint_id,
        valid=True,
    )

    # Step 1: Verify checkpoint digest
    recomputed = hashlib.sha256(
        json.dumps(
            checkpoint._signed_payload(),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()

    if recomputed != checkpoint.checkpoint_digest:
        result.valid = False
        result.error = "Checkpoint digest mismatch"
        return result
    result.digest_valid = True

    # Step 2a (v2.10.4): Resolve verification key under profile authorization
    verification_key, key_error = resolve_verification_key(
        checkpoint, profile, signer_resolver, public_key_pem,
    )
    if key_error:
        result.valid = False
        result.error = f"Signer authorization failed: {key_error}"
        return result
    if verification_key is None:
        result.valid = False
        result.error = "No verification key available for checkpoint"
        return result

    # Step 2: Verify signature (includes unconditional fingerprint binding)
    result.signature_valid = verify_checkpoint_signature(checkpoint, verification_key)
    if not result.signature_valid:
        result.valid = False
        result.error = "Checkpoint signature or signer fingerprint verification failed"
        return result

    # Step 4: Verify manifest artifact — semantic binding (CP-006)
    # v2.10.2: Parse as RetentionManifest and verify internal fields
    from .artifact_retention import RetentionManifest

    manifest_path = store._artifact_path(checkpoint.manifest_digest)
    if not manifest_path.exists():
        result.valid = False
        result.error = "Checkpoint manifest artifact missing"
        result.missing_artifacts.append(checkpoint.manifest_digest)
        return result

    manifest_content = manifest_path.read_bytes()
    actual_manifest_digest = hashlib.sha256(manifest_content).hexdigest()
    if actual_manifest_digest != checkpoint.manifest_digest:
        result.valid = False
        result.error = "Checkpoint manifest artifact digest mismatch"
        return result

    # v2.10.2: Parse and validate manifest as RetentionManifest
    try:
        manifest_data = json.loads(manifest_content)
        manifest = RetentionManifest.from_dict(manifest_data)
    except (json.JSONDecodeError, ValueError, KeyError, TypeError) as e:
        result.valid = False
        result.error = f"Manifest artifact is not a valid RetentionManifest: {e}"
        return result

    # v2.10.2: Verify manifest internal digest (excludes manifest_digest field)
    recomputed_internal = manifest._compute_digest()
    if manifest.manifest_digest != recomputed_internal:
        result.valid = False
        result.error = "RetentionManifest internal digest mismatch"
        return result

    # v2.10.2: Bind manifest fields to checkpoint fields
    if manifest.index_digest != checkpoint.index_digest:
        result.valid = False
        result.error = "Manifest index_digest does not match checkpoint index_digest"
        return result

    if manifest.artifact_count != checkpoint.artifact_count:
        result.valid = False
        result.error = (
            f"Manifest artifact_count ({manifest.artifact_count}) does not match "
            f"checkpoint artifact_count ({checkpoint.artifact_count})"
        )
        return result

    if manifest.policy_profile_digest != checkpoint.policy_profile_digest:
        result.valid = False
        result.error = "Manifest policy_profile_digest does not match checkpoint"
        return result

    # v2.10.3: Manifest self-consistency checks
    if manifest.artifact_count != len(manifest.artifact_digests):
        result.valid = False
        result.error = (
            f"Manifest artifact_count ({manifest.artifact_count}) does not match "
            f"len(artifact_digests) ({len(manifest.artifact_digests)})"
        )
        return result

    # Check for duplicate digests
    if len(manifest.artifact_digests) != len(set(manifest.artifact_digests)):
        result.valid = False
        result.error = "Manifest contains duplicate artifact digests"
        return result

    # Check SHA-256 format (64 hex chars)
    for d in manifest.artifact_digests:
        if len(d) != 64 or not all(c in '0123456789abcdef' for c in d):
            result.valid = False
            result.error = f"Invalid digest format in manifest: {d}"
            return result

    result.manifest_matches = True

    # Step 5: Verify snapshot artifacts from manifest (CP-006)
    # Verify the checkpoint snapshot's artifact set, not just the live index
    snapshot_digests = set(manifest.artifact_digests)
    all_available = True
    all_digests_valid = True

    for digest in snapshot_digests:
        artifact_path = store._artifact_path(digest)
        if not artifact_path.exists():
            result.missing_artifacts.append(digest)
            all_available = False
            continue
        content = artifact_path.read_bytes()
        actual = hashlib.sha256(content).hexdigest()
        if actual != digest:
            result.corrupted_artifacts.append(digest)
            all_digests_valid = False
            result.corrupted_artifacts.append(digest)
            all_digests_valid = False

    result.artifacts_available = all_available
    result.artifact_digests_valid = all_digests_valid

    if not all_available or not all_digests_valid:
        result.valid = False

    return result


# ── Chain Verification ──────────────────────────────────────────────────────


@dataclass
class ChainVerifyResult:
    """Result of verifying a checkpoint chain."""
    chain_valid: bool
    checkpoints_verified: int = 0
    signature_failures: list[int] = field(default_factory=list)
    digest_failures: list[int] = field(default_factory=list)
    continuity_breaks: list[int] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def verify_checkpoint_chain(
    chain: CheckpointChain,
    public_key_pem: str,
    profile: Any | None = None,
    signer_resolver: CheckpointSignerResolver | None = None,
) -> ChainVerifyResult:
    """Verify the integrity of an entire checkpoint chain.

    Checks:
    1. Each checkpoint's digest matches its payload
    2. Each checkpoint's signature is valid
    3. Chain continuity: each checkpoint's previous_digest matches predecessor
    4. Sequence numbers are monotonic
    """
    result = ChainVerifyResult(chain_valid=True)
    checkpoints = chain.get_checkpoints()

    prev_digest = ""
    prev_seq = 0

    for cp in checkpoints:
        # Check sequence monotonicity
        if cp.sequence_number != prev_seq + 1:
            result.continuity_breaks.append(cp.sequence_number)
            result.chain_valid = False
            result.errors.append(
                f"Sequence discontinuity at #{cp.sequence_number}: "
                f"expected {prev_seq + 1}"
            )

        # Check chain continuity
        if cp.sequence_number > 1 and cp.previous_checkpoint_digest != prev_digest:
            result.continuity_breaks.append(cp.sequence_number)
            result.chain_valid = False
            result.errors.append(
                f"Chain continuity broken at #{cp.sequence_number}: "
                f"previous_checkpoint_digest does not match predecessor"
            )

        # Check digest
        recomputed = hashlib.sha256(
            json.dumps(
                cp._signed_payload(),
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()

        if recomputed != cp.checkpoint_digest:
            result.digest_failures.append(cp.sequence_number)
            result.chain_valid = False
            result.errors.append(
                f"Digest mismatch at checkpoint #{cp.sequence_number}"
            )

        # Check signature (v2.10.4: with profile-aware key resolution)
        cp_key, cp_key_err = resolve_verification_key(
            cp, profile, signer_resolver, public_key_pem,
        )
        if cp_key_err:
            result.signature_failures.append(cp.sequence_number)
            result.chain_valid = False
            result.errors.append(
                f"Signer authorization failed at checkpoint #{cp.sequence_number}: {cp_key_err}"
            )
        elif cp_key is None or not verify_checkpoint_signature(cp, cp_key):
            result.signature_failures.append(cp.sequence_number)
            result.chain_valid = False
            result.errors.append(
                f"Signature verification failed at checkpoint #{cp.sequence_number}"
            )

        result.checkpoints_verified += 1
        prev_digest = cp.checkpoint_digest
        prev_seq = cp.sequence_number

    return result


# ── Recovery Report ─────────────────────────────────────────────────────────


def generate_recovery_report(
    store: ContentAddressedStore,
    chain: CheckpointChain | None = None,
    public_key_pem: str | None = None,
    profile: Any | None = None,
    signer_resolver: CheckpointSignerResolver | None = None,
) -> RecoveryReport:
    """Generate a full recovery report for the retention store.

    v2.10.5: Under strict profiles, checkpoint verification inputs are
    mandatory. Missing chain/resolver/key makes the report indeterminate.
    """
    report = RecoveryReport(
        valid=True,
        checkpoint_verified=False,
        chain_continuous=True,
        manifest_intact=True,
        artifacts_available=True,
        artifact_digests_valid=True,
    )

    # v2.10.5 (CP-014): Strict recovery must not skip checkpoint verification
    if profile is not None and getattr(profile, "require_checkpoint_signer_authorization", False):
        if chain is None:
            report.valid = False
            report.checkpoint_indeterminate = True
            report.error = "Checkpoint chain required by active policy"
            return report
        if signer_resolver is None and not getattr(profile, "allow_any_checkpoint_signer", False):
            report.valid = False
            report.checkpoint_indeterminate = True
            report.error = "Checkpoint signer resolver required by active policy"
            return report
        if public_key_pem is None and not getattr(profile, "allow_any_checkpoint_signer", False):
            report.valid = False
            report.checkpoint_indeterminate = True
            report.error = "Verification key context required by active policy"
            return report

    # Check store integrity
    try:
        verified_index = store.load_index()
    except RetentionError as e:
        report.valid = False
        report.manifest_intact = False
        report.error = f"Index verification failed: {e}"
        return report

    # Check artifacts
    entries = verified_index.get("entries", {})
    for digest in entries:
        artifact_path = store._artifact_path(digest)
        if not artifact_path.exists():
            report.missing_artifacts.append(digest)
            report.artifacts_available = False
            report.valid = False
            continue
        content = artifact_path.read_bytes()
        actual = hashlib.sha256(content).hexdigest()
        if actual != digest:
            report.corrupted_artifacts.append(digest)
            report.artifact_digests_valid = False
            report.valid = False

    # v2.10.7 (CP-018): Reconcile checkpoint operation journal
    if chain is not None:
        journal = CheckpointJournal(str(chain.chain_path) + ".journal")
        uncommitted = journal.get_uncommitted()
        if uncommitted:
            report.uncommitted_operations = [op.operation_id for op in uncommitted]
            report.valid = False
            if not report.error:
                report.error = (
                    f"{len(uncommitted)} uncommitted checkpoint operations found"
                )
        aborted = journal.get_aborted()
        if aborted:
            report.aborted_operations = [op.operation_id for op in aborted]

    # Check for orphans
    report.recoverable_orphans = store.find_orphaned(verified_index=verified_index)
    if report.recoverable_orphans:
        report.valid = False

    # Check chain if provided
    if chain is not None and public_key_pem is not None:
        chain_result = verify_checkpoint_chain(
            chain, public_key_pem, profile, signer_resolver,
        )
        report.checkpoint_verified = chain_result.chain_valid
        report.chain_continuous = chain_result.chain_valid

        if not chain_result.chain_valid:
            report.valid = False
            if chain_result.continuity_breaks:
                report.broken_chain_at = chain_result.continuity_breaks[0]
            report.error = "; ".join(chain_result.errors[:3])

        # Verify latest checkpoint against current state
        latest = chain.get_latest()
        if latest:
            report.checkpoint_sequence = latest.sequence_number
            cp_result = verify_checkpoint(
                latest, store, public_key_pem,
                profile=profile, signer_resolver=signer_resolver,
            )
            if not cp_result.valid:
                report.valid = False
                report.missing_artifacts.extend(cp_result.missing_artifacts)
                report.corrupted_artifacts.extend(cp_result.corrupted_artifacts)

    return report


# ── Rollback Detection ──────────────────────────────────────────────────────


@dataclass
class RollbackDetectionResult:
    """Result of checking for whole-store rollback against an external anchor.

    v2.10.2: Added 'indeterminate' outcome for unverified anchors.
    """
    rollback_detected: bool
    expected_sequence: int
    actual_sequence: int
    expected_manifest_digest: str
    actual_manifest_digest: str
    anchor_verified: bool = False
    is_descendant: bool = False
    indeterminate: bool = False
    error: str = ""


def detect_rollback(
    store: ContentAddressedStore,
    external_checkpoint: EvidenceCheckpoint,
    chain: CheckpointChain | None = None,
    public_key_pem: str | None = None,
    profile: Any | None = None,
    signer_resolver: CheckpointSignerResolver | None = None,
) -> RollbackDetectionResult:
    """Detect if the store has been rolled back to a prior state.

    v2.10.2: Verified lineage model.

    Algorithm:
    1. External anchor signature and signer identity are MANDATORY.
       Without a public key, return indeterminate. (CP-009)
    2. Verify external anchor signature and fingerprint binding.
    3. If chain is provided, verify entire local chain before using it. (CP-008)
    4. Confirm anchor belongs to verified local lineage.
    5. Equal-or-higher local seq without anchor lineage = incompatible, fail closed. (CP-007)
    6. Local seq < external seq = rollback/truncation.
    7. Anchor present in verified chain = forward progression.
    8. No chain = indeterminate (not manifest fallback).
    """
    _anchor = external_checkpoint

    # Step 1 (CP-009): External anchor verification is mandatory
    if public_key_pem is None:
        return RollbackDetectionResult(
            rollback_detected=False,
            expected_sequence=_anchor.sequence_number,
            actual_sequence=0,
            expected_manifest_digest=_anchor.manifest_digest,
            actual_manifest_digest="",
            anchor_verified=False,
            indeterminate=True,
            error="External anchor verification key is required for rollback detection",
        )

    # Step 2 (v2.10.4): Resolve verification key under profile authorization
    verification_key, key_error = resolve_verification_key(
        _anchor, profile, signer_resolver, public_key_pem,
    )
    if key_error:
        return RollbackDetectionResult(
            rollback_detected=False,
            expected_sequence=_anchor.sequence_number,
            actual_sequence=0,
            expected_manifest_digest=_anchor.manifest_digest,
            actual_manifest_digest="",
            anchor_verified=False,
            indeterminate=True,
            error=f"Anchor signer authorization failed: {key_error}",
        )
    if verification_key is None:
        return RollbackDetectionResult(
            rollback_detected=False,
            expected_sequence=_anchor.sequence_number,
            actual_sequence=0,
            expected_manifest_digest=_anchor.manifest_digest,
            actual_manifest_digest="",
            anchor_verified=False,
            indeterminate=True,
            error="No verification key available for anchor checkpoint",
        )

    # Verify external anchor signature + fingerprint binding
    anchor_verified = verify_checkpoint_signature(_anchor, verification_key)
    if not anchor_verified:
        return RollbackDetectionResult(
            rollback_detected=True,
            expected_sequence=_anchor.sequence_number,
            actual_sequence=0,
            expected_manifest_digest=_anchor.manifest_digest,
            actual_manifest_digest="",
            anchor_verified=False,
            error="External checkpoint signature or signer fingerprint verification failed",
        )

    # Step 3 (CP-008): If chain is provided, verify it before using
    if chain is not None:
        # Verify local chain
        chain_result = verify_checkpoint_chain(
            chain, public_key_pem, profile, signer_resolver,
        )
        if not chain_result.chain_valid:
            return RollbackDetectionResult(
                rollback_detected=True,
                expected_sequence=_anchor.sequence_number,
                actual_sequence=0,
                expected_manifest_digest=_anchor.manifest_digest,
                actual_manifest_digest="",
                anchor_verified=anchor_verified,
                error=f"Local chain verification failed: {'; '.join(chain_result.errors[:2])}",
            )

        local_checkpoints = chain.get_checkpoints()
        latest_local = local_checkpoints[-1] if local_checkpoints else None

        if latest_local is not None:
            # Step 4: Confirm anchor belongs to verified lineage
            anchor_in_chain = any(
                cp.checkpoint_digest == _anchor.checkpoint_digest
                for cp in local_checkpoints
            )

            if anchor_in_chain:
                # Step 7: Forward progression — anchor is in verified chain
                return RollbackDetectionResult(
                    rollback_detected=False,
                    expected_sequence=_anchor.sequence_number,
                    actual_sequence=latest_local.sequence_number,
                    expected_manifest_digest=_anchor.manifest_digest,
                    actual_manifest_digest=latest_local.manifest_digest,
                    anchor_verified=anchor_verified,
                    is_descendant=True,
                )

            # Step 5 (CP-007): Anchor NOT in chain but seq >= anchor seq
            # This is incompatible lineage / discontinuity — fail closed
            if latest_local.sequence_number >= _anchor.sequence_number:
                return RollbackDetectionResult(
                    rollback_detected=True,
                    expected_sequence=_anchor.sequence_number,
                    actual_sequence=latest_local.sequence_number,
                    expected_manifest_digest=_anchor.manifest_digest,
                    actual_manifest_digest=latest_local.manifest_digest,
                    anchor_verified=anchor_verified,
                    error=(
                        f"Incompatible lineage: local chain at #{latest_local.sequence_number} "
                        f"does not contain external anchor #{_anchor.sequence_number}"
                    ),
                )

            # Step 6: Local seq < external seq = rollback/truncation
            return RollbackDetectionResult(
                rollback_detected=True,
                expected_sequence=_anchor.sequence_number,
                actual_sequence=latest_local.sequence_number,
                expected_manifest_digest=_anchor.manifest_digest,
                actual_manifest_digest=latest_local.manifest_digest,
                anchor_verified=anchor_verified,
                error=(
                    f"Local chain at #{latest_local.sequence_number} "
                    f"is behind external anchor #{_anchor.sequence_number}"
                ),
            )

        # Empty chain with provided path — indeterminate
        return RollbackDetectionResult(
            rollback_detected=False,
            expected_sequence=_anchor.sequence_number,
            actual_sequence=0,
            expected_manifest_digest=_anchor.manifest_digest,
            actual_manifest_digest="",
            anchor_verified=anchor_verified,
            indeterminate=True,
            error="Local chain is empty — cannot determine lineage without verified chain",
        )

    # Step 8 (CP-009): No chain = indeterminate, not manifest fallback
    return RollbackDetectionResult(
        rollback_detected=False,
        expected_sequence=_anchor.sequence_number,
        actual_sequence=0,
        expected_manifest_digest=_anchor.manifest_digest,
        actual_manifest_digest="",
        anchor_verified=anchor_verified,
        indeterminate=True,
        error="No local chain provided — cannot verify lineage for rollback detection",
    )
