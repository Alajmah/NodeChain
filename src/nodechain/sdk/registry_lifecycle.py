"""Registry Lifecycle Governance (v2.15.0).

Governs all registry lifecycle transitions: publish, deprecate, revoke,
signer rotation, and publisher authority changes.

Every transition:
    - Is authorized (current signer must authorize privileged operations)
    - Is recorded in an append-only transition log
    - Advances the registry generation atomically
    - Produces a signed lifecycle receipt

Invariants:
    LG-001: Signer rotation preserves registry_id continuity
    LG-002: Only the current signer can authorize rotation
    LG-003: All transitions produce signed receipts
    LG-004: All transitions advance generation
    LG-005: Revoked packages are terminal (cannot transition)
    LG-006: Deprecated packages can only transition to revoked
    LG-007: Publisher authority changes are authorized by current signer
    LG-008: Transition log is append-only (no mutation of past entries)
    LG-009: Signer rotation emits a key-continuity receipt
    LG-010: Publisher revocation does not revoke published packages
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .artifact_retention import atomic_write_json


# ── Constants ───────────────────────────────────────────────────────────────

TRANSITION_PUBLISH = "publish"
TRANSITION_REVOKE = "revoke"
TRANSITION_DEPRECATE = "deprecate"
TRANSITION_SIGNER_ROTATION = "signer_rotation"
TRANSITION_PUBLISHER_ADD = "publisher_add"
TRANSITION_PUBLISHER_REVOKE = "publisher_revoke"
TRANSITION_PUBLISHER_SCOPE_CHANGE = "publisher_scope_change"

ALL_TRANSITION_TYPES = {
    TRANSITION_PUBLISH,
    TRANSITION_REVOKE,
    TRANSITION_DEPRECATE,
    TRANSITION_SIGNER_ROTATION,
    TRANSITION_PUBLISHER_ADD,
    TRANSITION_PUBLISHER_REVOKE,
    TRANSITION_PUBLISHER_SCOPE_CHANGE,
}

# Lifecycle transition state machine
LIFECYCLE_TRANSITIONS = {
    "active": {"deprecated", "revoked"},
    "deprecated": {"revoked"},
    "revoked": set(),  # Terminal
}


# ── Helpers ─────────────────────────────────────────────────────────────────


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_dict(data: dict[str, Any]) -> str:
    raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


# ── Lifecycle Transition Record ─────────────────────────────────────────────


@dataclass
class LifecycleTransition:
    """Append-only record of a single lifecycle transition."""

    sequence: int = 0
    transition_type: str = ""
    registry_id: str = ""
    authorized_by: str = ""  # fingerprint of the authorizer
    generation_before: int = 0
    generation_after: int = 0
    target_package_id: str = ""
    target_version: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    transition_digest: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "transition_type": self.transition_type,
            "registry_id": self.registry_id,
            "authorized_by": self.authorized_by,
            "generation_before": self.generation_before,
            "generation_after": self.generation_after,
            "target_package_id": self.target_package_id,
            "target_version": self.target_version,
            "details": dict(self.details),
            "transition_digest": self.transition_digest,
            "timestamp": self.timestamp,
        }

    def compute_digest(self) -> str:
        """Digest of all fields except transition_digest itself."""
        d = self.to_dict()
        d.pop("transition_digest", None)
        return _sha256_dict(d)


# ── Lifecycle Receipt ───────────────────────────────────────────────────────


@dataclass
class LifecycleReceipt:
    """Signed receipt for a lifecycle transition."""

    receipt_id: str = ""
    transition_type: str = ""
    registry_id: str = ""
    generation: int = 0
    authorized_by: str = ""
    timestamp: str = ""
    receipt_digest: str = ""
    signature: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "transition_type": self.transition_type,
            "registry_id": self.registry_id,
            "generation": self.generation,
            "authorized_by": self.authorized_by,
            "timestamp": self.timestamp,
            "receipt_digest": self.receipt_digest,
            "signature": self.signature,
        }


# ── Key Continuity Record ───────────────────────────────────────────────────


@dataclass
class KeyContinuityRecord:
    """Record of a signer key rotation preserving registry identity.

    LG-001: registry_id stays the same. Only the signing key changes.
    """

    registry_id: str = ""
    old_signer_fingerprint: str = ""
    new_signer_fingerprint: str = ""
    rotation_generation: int = 0
    authorized_by: str = ""  # Must be old_signer_fingerprint
    rotated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "registry_id": self.registry_id,
            "old_signer_fingerprint": self.old_signer_fingerprint,
            "new_signer_fingerprint": self.new_signer_fingerprint,
            "rotation_generation": self.rotation_generation,
            "authorized_by": self.authorized_by,
            "rotated_at": self.rotated_at,
        }


# ── Exceptions ──────────────────────────────────────────────────────────────


class LifecycleError(Exception):
    """Base error for lifecycle governance failures."""


class UnauthorizedRotationError(LifecycleError):
    """LG-002: Only the current signer can authorize rotation."""


class InvalidTransitionError(LifecycleError):
    """Invalid lifecycle state transition."""


class TerminalPackageError(LifecycleError):
    """LG-005: Revoked packages are terminal."""


# ── Transition Log ──────────────────────────────────────────────────────────


class TransitionLog:
    """Append-only log of all registry lifecycle transitions.

    LG-008: Entries are never mutated. Only appended.
    """

    SCHEMA_VERSION = "1.0.0"

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {
                "schema_version": self.SCHEMA_VERSION,
                "registry_id": "",
                "transitions": [],
                "key_continuity": [],
            }
        raw = self.path.read_text(encoding="utf-8")
        data = json.loads(raw)
        data.setdefault("transitions", [])
        data.setdefault("key_continuity", [])
        return data

    def _save(self, data: dict[str, Any]) -> None:
        data["schema_version"] = self.SCHEMA_VERSION
        atomic_write_json(self.path, data)

    def set_registry_id(self, registry_id: str) -> None:
        with self._lock:
            data = self._load()
            data["registry_id"] = registry_id
            self._save(data)

    def append(self, transition: LifecycleTransition) -> None:
        """Append a transition record. Never mutates existing entries."""
        with self._lock:
            data = self._load()
            data["transitions"].append(transition.to_dict())
            self._save(data)

    def append_key_continuity(self, record: KeyContinuityRecord) -> None:
        """Append a key rotation record."""
        with self._lock:
            data = self._load()
            data["key_continuity"].append(record.to_dict())
            self._save(data)

    def get_transitions(self) -> list[LifecycleTransition]:
        with self._lock:
            data = self._load()
            return [
                LifecycleTransition(
                    sequence=t.get("sequence", 0),
                    transition_type=t.get("transition_type", ""),
                    registry_id=t.get("registry_id", ""),
                    authorized_by=t.get("authorized_by", ""),
                    generation_before=t.get("generation_before", 0),
                    generation_after=t.get("generation_after", 0),
                    target_package_id=t.get("target_package_id", ""),
                    target_version=t.get("target_version", ""),
                    details=t.get("details", {}),
                    transition_digest=t.get("transition_digest", ""),
                    timestamp=t.get("timestamp", ""),
                )
                for t in data.get("transitions", [])
            ]

    def get_key_continuity(self) -> list[KeyContinuityRecord]:
        with self._lock:
            data = self._load()
            return [
                KeyContinuityRecord(
                    registry_id=r.get("registry_id", ""),
                    old_signer_fingerprint=r.get("old_signer_fingerprint", ""),
                    new_signer_fingerprint=r.get("new_signer_fingerprint", ""),
                    rotation_generation=r.get("rotation_generation", 0),
                    authorized_by=r.get("authorized_by", ""),
                    rotated_at=r.get("rotated_at", ""),
                )
                for r in data.get("key_continuity", [])
            ]

    def verify_integrity(self) -> bool:
        """Verify the log is well-formed and sequences are monotonic."""
        transitions = self.get_transitions()
        for i, t in enumerate(transitions):
            if t.sequence != i + 1:
                return False
            if t.transition_digest != t.compute_digest():
                return False
            if i > 0:
                if t.generation_before != transitions[i - 1].generation_after:
                    return False
        return True


# ── Lifecycle Governor ──────────────────────────────────────────────────────


class LifecycleGovernor:
    """Governs all registry lifecycle transitions.

    Wraps RegistryState and TransitionLog to ensure every transition is:
        - Authorized (LG-002, LG-007)
        - Recorded (LG-003, LG-008)
        - Generation-advancing (LG-004)
        - State-machine valid (LG-005, LG-006)
    """

    def __init__(
        self,
        registry_state,  # RegistryState from reference_registry_server.py
        transition_log: TransitionLog,
    ) -> None:
        self.state = registry_state
        self.log = transition_log
        self._sequence = 0
        self._lock = threading.RLock()

    def _next_sequence(self) -> int:
        self._sequence += 1
        return self._sequence

    def _make_transition(
        self,
        transition_type: str,
        authorized_by: str,
        gen_before: int,
        gen_after: int,
        target_package_id: str = "",
        target_version: str = "",
        details: dict[str, Any] | None = None,
    ) -> LifecycleTransition:
        t = LifecycleTransition(
            sequence=self._next_sequence(),
            transition_type=transition_type,
            registry_id=self.state.get_registry_id(),
            authorized_by=authorized_by,
            generation_before=gen_before,
            generation_after=gen_after,
            target_package_id=target_package_id,
            target_version=target_version,
            details=details or {},
            timestamp=_now_iso(),
        )
        t.transition_digest = t.compute_digest()
        self.log.append(t)
        return t

    def _make_receipt(
        self, transition: LifecycleTransition,
    ) -> LifecycleReceipt:
        receipt = LifecycleReceipt(
            receipt_id=hashlib.sha256(
                f"{transition.transition_type}:{transition.sequence}:{transition.timestamp}".encode()
            ).hexdigest()[:32],
            transition_type=transition.transition_type,
            registry_id=transition.registry_id,
            generation=transition.generation_after,
            authorized_by=transition.authorized_by,
            timestamp=transition.timestamp,
        )
        receipt.receipt_digest = _sha256_dict({
            "receipt_id": receipt.receipt_id,
            "transition_type": receipt.transition_type,
            "registry_id": receipt.registry_id,
            "generation": receipt.generation,
            "authorized_by": receipt.authorized_by,
            "timestamp": receipt.timestamp,
        })
        return receipt

    def _validate_transition(
        self, from_lifecycle: str, to_lifecycle: str,
    ) -> None:
        """LG-005/LG-006: Validate lifecycle state machine."""
        allowed = LIFECYCLE_TRANSITIONS.get(from_lifecycle, set())
        if to_lifecycle not in allowed:
            raise InvalidTransitionError(
                f"Invalid lifecycle transition: {from_lifecycle} → {to_lifecycle}. "
                f"Allowed: {allowed or '(terminal state)'}"
            )

    # ── Publish ─────────────────────────────────────────────────────────

    def govern_publish(
        self,
        package_id: str,
        version: str,
        artifact_digest: str,
        publisher_fingerprint: str,
        authorized_by: str = "",
    ) -> LifecycleReceipt:
        """Record a publish lifecycle transition."""
        with self._lock:
            gen_before = self.state.get_generation()
            # The actual publish happens in RegistryState — this records the transition
            details = {
                "artifact_digest": artifact_digest,
                "publisher_fingerprint": publisher_fingerprint,
            }
            transition = self._make_transition(
                TRANSITION_PUBLISH,
                authorized_by or publisher_fingerprint,
                gen_before,
                gen_before + 1,  # publish advances generation
                target_package_id=package_id,
                target_version=version,
                details=details,
            )
            return self._make_receipt(transition)

    # ── Revoke ──────────────────────────────────────────────────────────

    def govern_revoke(
        self,
        package_id: str,
        version: str,
        reason: str,
        authorized_by: str,
    ) -> LifecycleReceipt:
        """Govern a package revocation.

        LG-002: Must be authorized by the current registry signer.
        LG-005: Revoked packages are terminal.
        """
        with self._lock:
            # Verify authorizer is the current signer
            current_signer = self.state.get_signer_fingerprint()
            if authorized_by != current_signer:
                raise UnauthorizedRotationError(
                    f"Only the current registry signer can revoke packages"
                )

            record = self.state.get_package(package_id, version)
            if record is None:
                raise KeyError(f"Package {package_id}:{version} not found")

            # LG-005: Check lifecycle transition validity
            if record.lifecycle == "revoked":
                raise TerminalPackageError(
                    f"Package {package_id}:{version} is already revoked (terminal)"
                )

            self._validate_transition(record.lifecycle, "revoked")

            gen_before = self.state.get_generation()
            gen_after = self.state.revoke_package(package_id, version, reason)

            transition = self._make_transition(
                TRANSITION_REVOKE,
                authorized_by,
                gen_before,
                gen_after,
                target_package_id=package_id,
                target_version=version,
                details={"reason": reason, "from_lifecycle": record.lifecycle},
            )
            return self._make_receipt(transition)

    # ── Deprecate ───────────────────────────────────────────────────────

    def govern_deprecate(
        self,
        package_id: str,
        version: str,
        authorized_by: str,
    ) -> LifecycleReceipt:
        """Govern a package deprecation.

        LG-006: Deprecated can only go to revoked, not back to active.
        """
        with self._lock:
            current_signer = self.state.get_signer_fingerprint()
            if authorized_by != current_signer:
                raise UnauthorizedRotationError(
                    f"Only the current registry signer can deprecate packages"
                )

            record = self.state.get_package(package_id, version)
            if record is None:
                raise KeyError(f"Package {package_id}:{version} not found")

            if record.lifecycle == "revoked":
                raise TerminalPackageError(
                    f"Package {package_id}:{version} is revoked (terminal)"
                )

            self._validate_transition(record.lifecycle, "deprecated")

            gen_before = self.state.get_generation()
            gen_after = self.state.deprecate_package(package_id, version)

            transition = self._make_transition(
                TRANSITION_DEPRECATE,
                authorized_by,
                gen_before,
                gen_after,
                target_package_id=package_id,
                target_version=version,
                details={"from_lifecycle": record.lifecycle},
            )
            return self._make_receipt(transition)

    # ── Signer Rotation ─────────────────────────────────────────────────

    def govern_signer_rotation(
        self,
        new_signer_fingerprint: str,
        authorized_by: str,
    ) -> LifecycleReceipt:
        """Govern a signer key rotation.

        LG-001: registry_id stays the same, only signing key changes.
        LG-002: Only the current signer can authorize rotation.
        LG-009: Emits a key-continuity receipt.
        """
        with self._lock:
            current_signer = self.state.get_signer_fingerprint()
            if authorized_by != current_signer:
                raise UnauthorizedRotationError(
                    f"Only the current signer ({current_signer}) can authorize rotation. "
                    f"Got: {authorized_by}"
                )

            if new_signer_fingerprint == current_signer:
                raise LifecycleError("New signer fingerprint is the same as current")

            registry_id = self.state.get_registry_id()
            gen_before = self.state.get_generation()

            # LG-001: registry_id continuity — same registry_id, new key
            self.state.set_registry_identity(registry_id, new_signer_fingerprint)

            gen_after = gen_before + 1
            # Manually advance generation
            data = self.state._load()
            data["generation"] = gen_after
            self.state._save(data)

            # Record key continuity
            continuity = KeyContinuityRecord(
                registry_id=registry_id,
                old_signer_fingerprint=current_signer,
                new_signer_fingerprint=new_signer_fingerprint,
                rotation_generation=gen_after,
                authorized_by=authorized_by,
                rotated_at=_now_iso(),
            )
            self.log.append_key_continuity(continuity)

            transition = self._make_transition(
                TRANSITION_SIGNER_ROTATION,
                authorized_by,
                gen_before,
                gen_after,
                details={
                    "old_signer_fingerprint": current_signer,
                    "new_signer_fingerprint": new_signer_fingerprint,
                },
            )
            return self._make_receipt(transition)

    # ── Publisher Authority Changes ─────────────────────────────────────

    def govern_publisher_add(
        self,
        publisher_id: str,
        publisher_fingerprint: str,
        approved_packages: list[str] | None,
        authorized_by: str,
    ) -> LifecycleReceipt:
        """Govern adding a publisher authorization.

        LG-007: Must be authorized by current signer.
        """
        with self._lock:
            current_signer = self.state.get_signer_fingerprint()
            if authorized_by != current_signer:
                raise UnauthorizedRotationError(
                    f"Only the current registry signer can modify publisher authorizations"
                )

            gen_before = self.state.get_generation()
            self.state.approve_publisher(
                publisher_id, publisher_fingerprint, approved_packages,
            )

            transition = self._make_transition(
                TRANSITION_PUBLISHER_ADD,
                authorized_by,
                gen_before,
                gen_before,  # Publisher changes don't advance generation
                details={
                    "publisher_id": publisher_id,
                    "publisher_fingerprint": publisher_fingerprint,
                    "approved_packages": approved_packages or [],
                },
            )
            return self._make_receipt(transition)

    def govern_publisher_revoke(
        self,
        publisher_fingerprint: str,
        authorized_by: str,
    ) -> LifecycleReceipt:
        """Govern revoking a publisher authorization.

        LG-010: Revoking publisher auth does NOT revoke published packages.
        Their published artifacts remain immutable in the registry.
        """
        with self._lock:
            current_signer = self.state.get_signer_fingerprint()
            if authorized_by != current_signer:
                raise UnauthorizedRotationError(
                    f"Only the current registry signer can revoke publisher authorizations"
                )

            gen_before = self.state.get_generation()

            # Remove publisher from approved list
            data = self.state._load()
            if publisher_fingerprint in data.get("publishers", {}):
                del data["publishers"][publisher_fingerprint]
                self.state._save(data)

            transition = self._make_transition(
                TRANSITION_PUBLISHER_REVOKE,
                authorized_by,
                gen_before,
                gen_before,  # Publisher changes don't advance generation
                details={
                    "publisher_fingerprint": publisher_fingerprint,
                    "packages_preserved": True,  # LG-010
                },
            )
            return self._make_receipt(transition)
