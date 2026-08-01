"""Governed Remote Installation (v2.12.0).

Makes remote package installation a checkpoint-governed operation with
durable idempotency keys, phase tracking, and crash recovery.

If the process crashes during download, extraction, or local registration,
recovery follows the same discipline established for checkpoint operations:
reconcile, verify, resume or escalate — never silently repeat an install
or leave the system in an indeterminate state.

Install phases:
    pending → downloading → downloaded → extracting → extracted
            → registering → committed

Recovery rules:
    pending:      safe to start fresh
    downloading:  safe to re-download (idempotent GET)
    downloaded:   artifact verified, safe to extract
    extracting:   re-extract from verified artifact
    extracted:    safe to register
    registering:  re-register with RI-001 identity verification
    committed:    skip — already installed
    failed:       needs intervention

Side-effect contract: remote install is idempotent_with_key when the
same package_id + version + artifact_digest is used. A different artifact
digest for the same version is a conflict, not a retry.
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

from .artifact_retention import atomic_write_json


# ── Phase constants ─────────────────────────────────────────────────────────

PHASE_PENDING = "pending"
PHASE_DOWNLOADING = "downloading"
PHASE_DOWNLOADED = "downloaded"
PHASE_EXTRACTING = "extracting"
PHASE_EXTRACTED = "extracted"
PHASE_REGISTERING = "registering"
PHASE_COMMITTED = "committed"
PHASE_ABORTED = "aborted"
PHASE_FAILED = "failed"
PHASE_CONFLICT = "install_conflict"  # v2.12.1 RI-001: identity mismatch at registration

# Phases that have durable side effects and cannot be silently retried
DURABLE_PHASES = {PHASE_DOWNLOADED, PHASE_EXTRACTED, PHASE_REGISTERING, PHASE_COMMITTED}
# Phases that are safe to retry from scratch
SAFE_RETRY_PHASES = {PHASE_PENDING, PHASE_DOWNLOADING, PHASE_EXTRACTING}

ALL_PHASES = {
    PHASE_PENDING, PHASE_DOWNLOADING, PHASE_DOWNLOADED,
    PHASE_EXTRACTING, PHASE_EXTRACTED, PHASE_REGISTERING,
    PHASE_COMMITTED, PHASE_ABORTED, PHASE_FAILED,
    PHASE_CONFLICT,
}


# ── Install Operation ───────────────────────────────────────────────────────


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def compute_install_key(
    remote_url: str, package_id: str, version: str, artifact_digest: str = "",
) -> str:
    """Compute durable idempotency key for an install operation.

    v2.12.0: Uses remote_url for backward compatibility.
    v2.12.1: Prefer compute_canonical_install_key() for registry-identity-based keys.

    The key is deterministic: same package + version + digest = same key.
    This makes installation idempotent — a retry with the same key produces
    the same outcome without side effects.
    """
    payload = json.dumps({
        "remote_url": remote_url,
        "package_id": package_id,
        "version": version,
        "artifact_digest": artifact_digest,
    }, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()[:32]


# v2.12.1: Canonical identity fields that must match for idempotent registration
IDENTITY_FIELDS = [
    "package_id",
    "package_version",
    "artifact_digest",       # package_digest in registry entries
    "manifest_digest",
    "publisher_fingerprint",
    "registry_fingerprint",  # registry_signer_fingerprint
    "registry_id",
    "certification_digest",
    "trust_level",
]


def compute_canonical_install_key(
    registry_id: str,
    registry_signer_fingerprint: str,
    package_id: str,
    version: str,
    artifact_digest: str,
) -> str:
    """v2.12.1: Compute canonical install key using registry identity.

    Uses registry_id + signer fingerprint instead of transport URL.
    This ensures mirrors, redirects, and trailing-slash variants
    produce the same canonical identity.

    RI-001: The canonical identity is the durable trust identity.
    The transport URL is ephemeral.
    """
    payload = json.dumps({
        "registry_id": registry_id,
        "registry_signer_fingerprint": registry_signer_fingerprint,
        "package_id": package_id,
        "version": version,
        "artifact_digest": artifact_digest,
    }, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()[:32]


def compare_registry_identity(
    existing_entry: dict[str, Any],
    remote_entry: dict[str, Any],
) -> list[str]:
    """v2.12.1 RI-001: Compare identity-bearing fields between entries.

    Returns list of mismatched field names. Empty list = exact match.
    Non-empty = install conflict.
    """
    field_map = {
        "package_id": "package_id",
        "package_version": "package_version",
        "artifact_digest": "package_digest",
        "manifest_digest": "manifest_digest",
        "publisher_fingerprint": "publisher_fingerprint",
        "registry_fingerprint": "registry_signer_fingerprint",
        "registry_id": "registry_id",
        "certification_digest": "certification_digest",
        "trust_level": "trust_level",
    }
    mismatches = []
    for canonical_field, entry_field in field_map.items():
        existing_val = existing_entry.get(entry_field, "")
        remote_val = remote_entry.get(entry_field, "")
        if existing_val != remote_val:
            mismatches.append(canonical_field)
    return mismatches


class InstallConflictError(Exception):
    """v2.12.1 RI-001: Existing registry entry identity mismatch."""
    def __init__(self, package_id: str, version: str, mismatches: list[str]):
        self.package_id = package_id
        self.version = version
        self.mismatches = mismatches
        super().__init__(
            f"Install conflict for {package_id}@{version}: "
            f"identity mismatch on fields: {', '.join(mismatches)}"
        )


def verify_registration_idempotency(
    existing_entry: dict[str, Any],
    remote_entry: dict[str, Any],
) -> dict[str, Any]:
    """v2.12.1 RI-001: Verify that existing registration matches remote identity.

    Returns:
        {
            "idempotent": bool,  # True = safe to skip registration
            "conflict": bool,    # True = identity mismatch
            "mismatches": list[str],  # Mismatched field names
        }
    """
    mismatches = compare_registry_identity(existing_entry, remote_entry)
    if not mismatches:
        return {
            "idempotent": True,
            "conflict": False,
            "mismatches": [],
        }
    return {
        "idempotent": False,
        "conflict": True,
        "mismatches": mismatches,
    }


@dataclass
class InstallOperation:
    """A single governed install operation tracked in the journal."""

    operation_id: str = ""
    install_key: str = ""
    remote_url: str = ""
    package_id: str = ""
    version: str = ""
    artifact_digest: str = ""
    phase: str = PHASE_PENDING
    installed_path: str = ""
    receipt_digest: str = ""
    started_at: str = ""
    completed_at: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "install_key": self.install_key,
            "remote_url": self.remote_url,
            "package_id": self.package_id,
            "version": self.version,
            "artifact_digest": self.artifact_digest,
            "phase": self.phase,
            "installed_path": self.installed_path,
            "receipt_digest": self.receipt_digest,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InstallOperation:
        return cls(
            operation_id=data.get("operation_id", ""),
            install_key=data.get("install_key", ""),
            remote_url=data.get("remote_url", ""),
            package_id=data.get("package_id", ""),
            version=data.get("version", ""),
            artifact_digest=data.get("artifact_digest", ""),
            phase=data.get("phase", PHASE_PENDING),
            installed_path=data.get("installed_path", ""),
            receipt_digest=data.get("receipt_digest", ""),
            started_at=data.get("started_at", ""),
            completed_at=data.get("completed_at", ""),
            error=data.get("error", ""),
        )


# ── Install Journal ────────────────────────────────────────────────────────


class InstallJournalError(Exception):
    """Install journal is corrupt or invalid."""
    pass


class InstallJournal:
    """Durable journal of install operations.

    Stored as JSON at {install_dir}/.install_journal.
    Survives crashes — used by InstallRecoveryManager to determine
    which operations completed and which need intervention.
    """

    SCHEMA_VERSION = "1.0.0"

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock_path = Path(str(path) + ".lock")

    def _acquire_lock(self) -> int:
        import time
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        for _ in range(100):
            try:
                return os.open(
                    str(self._lock_path),
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                )
            except FileExistsError:
                time.sleep(0.1)
        raise InstallJournalError("Timeout acquiring install journal lock")

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
        if not self.path.exists():
            return {"schema_version": self.SCHEMA_VERSION, "operations": []}
        raw = self.path.read_text(encoding="utf-8")
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError) as e:
            raise InstallJournalError(
                f"Install journal is corrupt: {e}"
            ) from e
        if not isinstance(data, dict):
            raise InstallJournalError("Install journal is not a dict")
        if "operations" not in data:
            raise InstallJournalError("Install journal missing 'operations'")
        if "schema_version" not in data:
            raise InstallJournalError("Install journal missing 'schema_version'")
        return data

    def _save(self, data: dict[str, Any]) -> None:
        data["schema_version"] = self.SCHEMA_VERSION
        atomic_write_json(self.path, data)

    def begin(
        self,
        operation_id: str,
        remote_url: str,
        package_id: str,
        version: str,
        artifact_digest: str = "",
    ) -> InstallOperation:
        """Begin tracking a new install operation."""
        install_key = compute_install_key(remote_url, package_id, version, artifact_digest)
        op = InstallOperation(
            operation_id=operation_id,
            install_key=install_key,
            remote_url=remote_url,
            package_id=package_id,
            version=version,
            artifact_digest=artifact_digest,
            phase=PHASE_PENDING,
            started_at=_now_iso(),
        )
        fd = self._acquire_lock()
        try:
            data = self._load()
            data["operations"].append(op.to_dict())
            self._save(data)
        finally:
            self._release_lock(fd)
        return op

    def update_phase(
        self, operation_id: str, phase: str,
        **extra: Any,
    ) -> None:
        """Update the phase of an operation."""
        if phase not in ALL_PHASES:
            raise InstallJournalError(f"Invalid phase: {phase}")
        fd = self._acquire_lock()
        try:
            data = self._load()
            for op in data["operations"]:
                if op["operation_id"] == operation_id:
                    op["phase"] = phase
                    for k, v in extra.items():
                        op[k] = v
                    if phase in (PHASE_COMMITTED, PHASE_ABORTED, PHASE_FAILED, PHASE_CONFLICT):
                        op["completed_at"] = _now_iso()
                    break
            self._save(data)
        finally:
            self._release_lock(fd)

    def get_operations(self) -> list[InstallOperation]:
        data = self._load()
        return [InstallOperation.from_dict(op) for op in data.get("operations", [])]

    def get_pending(self) -> list[InstallOperation]:
        """Return operations not yet committed, aborted, failed, or conflicted."""
        return [
            op for op in self.get_operations()
            if op.phase not in (PHASE_COMMITTED, PHASE_ABORTED, PHASE_FAILED, PHASE_CONFLICT)
        ]

    def get_by_key(self, install_key: str) -> InstallOperation | None:
        """Find an operation by its install key (idempotency check)."""
        for op in self.get_operations():
            if op.install_key == install_key:
                return op
        return None


# ── Install Recovery ────────────────────────────────────────────────────────


@dataclass
class InstallRecoveryDecision:
    """Recovery decision for a single interrupted install operation."""

    operation_id: str = ""
    package_id: str = ""
    version: str = ""
    phase_at_crash: str = ""
    recovery_action: str = ""  # skip, resume_from_phase, needs_intervention
    resume_from_phase: str = ""
    install_key: str = ""
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "package_id": self.package_id,
            "version": self.version,
            "phase_at_crash": self.phase_at_crash,
            "recovery_action": self.recovery_action,
            "resume_from_phase": self.resume_from_phase,
            "install_key": self.install_key,
            "detail": self.detail,
        }


# Recovery actions
INSTALL_SKIP = "skip"
INSTALL_RESUME = "resume_from_phase"
INSTALL_INTERVENTION = "needs_intervention"


def classify_install_recovery(phase: str, installed_path: str = "") -> str:
    """Determine the safe recovery action for an interrupted install.

    Rules:
        pending / downloading: safe to restart (no durable side effect yet)
        downloaded:            artifact verified, safe to extract
        extracting:            re-extract from verified artifact
        extracted:             safe to register
        registering:           re-register with identity verification (RI-001)
        committed:             skip — already done
        install_conflict:      needs intervention (RI-001 identity mismatch)
    """
    if phase == PHASE_COMMITTED:
        return INSTALL_SKIP
    elif phase == PHASE_CONFLICT:
        # v2.12.1 RI-001: identity conflict requires operator intervention
        return INSTALL_INTERVENTION
    elif phase in (PHASE_PENDING, PHASE_DOWNLOADING):
        return INSTALL_RESUME
    elif phase == PHASE_DOWNLOADED:
        # Artifact downloaded and verified, but not extracted
        # Check if artifact file still exists
        if installed_path and Path(installed_path).exists():
            return INSTALL_RESUME
        return INSTALL_INTERVENTION
    elif phase == PHASE_EXTRACTING:
        # Extraction was in progress — may be partial
        if installed_path and Path(installed_path).exists():
            # Check if extraction looks complete
            return INSTALL_RESUME
        return INSTALL_INTERVENTION
    elif phase == PHASE_EXTRACTED:
        # Extracted but not registered
        if installed_path and Path(installed_path).exists():
            return INSTALL_RESUME
        return INSTALL_INTERVENTION
    elif phase == PHASE_REGISTERING:
        # Registration was in progress — registry may or may not have the entry
        return INSTALL_RESUME
    else:
        return INSTALL_INTERVENTION


def get_resume_phase(phase: str, installed_path: str = "") -> str:
    """Get the phase to resume from after a crash."""
    action = classify_install_recovery(phase, installed_path)
    if action == INSTALL_SKIP:
        return PHASE_COMMITTED
    if action == INSTALL_INTERVENTION:
        return phase  # Stay at current phase for manual resolution

    # For resume actions, determine where to pick up
    if phase in (PHASE_PENDING, PHASE_DOWNLOADING):
        return PHASE_PENDING  # Start fresh
    elif phase == PHASE_DOWNLOADED:
        return PHASE_EXTRACTING
    elif phase in (PHASE_EXTRACTING,):
        return PHASE_EXTRACTING  # Re-extract
    elif phase == PHASE_EXTRACTED:
        return PHASE_REGISTERING
    elif phase == PHASE_REGISTERING:
        return PHASE_REGISTERING  # Re-register
    return phase


class InstallRecoveryManager:
    """Reconciles interrupted install operations after a crash.

    Reads the install journal, classifies each pending operation,
    and produces a recovery plan.
    """

    def __init__(self, journal: InstallJournal) -> None:
        self.journal = journal

    def reconcile(self) -> list[InstallRecoveryDecision]:
        """Reconcile all pending install operations.

        Returns list of decisions. Each operation gets exactly one
        decision: skip, resume, or needs_intervention.
        """
        pending = self.journal.get_pending()
        decisions = []

        for op in pending:
            action = classify_install_recovery(op.phase, op.installed_path)
            resume_phase = get_resume_phase(op.phase, op.installed_path)

            decisions.append(InstallRecoveryDecision(
                operation_id=op.operation_id,
                package_id=op.package_id,
                version=op.version,
                phase_at_crash=op.phase,
                recovery_action=action,
                resume_from_phase=resume_phase if action == INSTALL_RESUME else "",
                install_key=op.install_key,
                detail=(
                    f"Install of {op.package_id}@{op.version} was in "
                    f"'{op.phase}' phase at crash"
                ),
            ))

        return decisions

    def has_committed(self, install_key: str) -> bool:
        """Check if an install with this key was already committed."""
        op = self.journal.get_by_key(install_key)
        return op is not None and op.phase == PHASE_COMMITTED

    def get_idempotency_status(self, install_key: str) -> dict[str, Any]:
        """Get idempotency status for an install key.

        Returns:
            {
                "already_installed": bool,
                "phase": str,
                "operation_id": str,
                "safe_to_proceed": bool,
            }
        """
        op = self.journal.get_by_key(install_key)
        if op is None:
            return {
                "already_installed": False,
                "phase": "",
                "operation_id": "",
                "safe_to_proceed": True,
            }
        if op.phase == PHASE_COMMITTED:
            return {
                "already_installed": True,
                "phase": op.phase,
                "operation_id": op.operation_id,
                "safe_to_proceed": False,  # Already done, skip
            }
        # There's a pending or failed operation — need to reconcile first
        return {
            "already_installed": False,
            "phase": op.phase,
            "operation_id": op.operation_id,
            "safe_to_proceed": False,  # Must reconcile first
        }


# ── Governed Install Receipt ────────────────────────────────────────────────


@dataclass
class GovernedInstallReceipt:
    """Enhanced install receipt with journal reference and idempotency.

    Extends the concept of RemoteInstallReceipt with:
    - install_key (durable idempotency key)
    - journal_operation_id (links to the install journal)
    - phase_at_completion (should always be 'committed')
    - recovery_provenance (if this install was a recovery from a crash)
    """

    receipt_type: str = "governed_install_receipt"
    receipt_id: str = ""
    install_key: str = ""
    journal_operation_id: str = ""
    remote_url: str = ""
    package_id: str = ""
    version: str = ""
    artifact_digest: str = ""
    installed_path: str = ""
    installed_at: str = field(default_factory=_now_iso)
    trust_level: str = "remote_untrusted"
    verification_checks: list[dict[str, Any]] = field(default_factory=list)
    phase_at_completion: str = PHASE_COMMITTED
    recovery_provenance: str = ""  # "fresh" or "recovered"
    receipt_digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = {
            "type": self.receipt_type,
            "receipt_id": self.receipt_id,
            "install_key": self.install_key,
            "journal_operation_id": self.journal_operation_id,
            "remote_url": self.remote_url,
            "package_id": self.package_id,
            "version": self.version,
            "artifact_digest": self.artifact_digest,
            "installed_path": self.installed_path,
            "installed_at": self.installed_at,
            "trust_level": self.trust_level,
            "verification_checks": list(self.verification_checks),
            "phase_at_completion": self.phase_at_completion,
            "recovery_provenance": self.recovery_provenance,
        }
        d["receipt_digest"] = hashlib.sha256(
            json.dumps(d, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GovernedInstallReceipt:
        return cls(
            receipt_id=data.get("receipt_id", ""),
            install_key=data.get("install_key", ""),
            journal_operation_id=data.get("journal_operation_id", ""),
            remote_url=data.get("remote_url", ""),
            package_id=data.get("package_id", ""),
            version=data.get("version", ""),
            artifact_digest=data.get("artifact_digest", ""),
            installed_path=data.get("installed_path", ""),
            installed_at=data.get("installed_at", ""),
            trust_level=data.get("trust_level", "remote_untrusted"),
            verification_checks=data.get("verification_checks", []),
            phase_at_completion=data.get("phase_at_completion", PHASE_COMMITTED),
            recovery_provenance=data.get("recovery_provenance", ""),
            receipt_digest=data.get("receipt_digest", ""),
        )
