"""Remote Registry Transparency Log (v2.3.0).

Append-only, tamper-evident log of remote registry interactions.
Chained SHA-256 digests make any modification to historical entries
detectable.

NON-NEGOTIABLE RULE:
    Logged does not mean trusted.
    Logged means observable and tamper-evident.

Trust still comes from signature, digest, certification, policy, sandbox,
and registry state. The log adds historical accountability, replay evidence,
tamper detection, and registry behavior auditability.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


# ── Constants ────────────────────────────────────────────────────────────────

TRANSPARENCY_LOG_VERSION = "v1"


class TransparencyLogError(Exception):
    """Raised when a transparency log is corrupt or invalid."""

# Valid event types
EVENT_TYPES = frozenset({
    "registry_metadata_seen",
    "package_metadata_seen",
    "package_artifact_seen",
    "package_installed",
    "dependency_graph_resolved",
    "package_revoked",
    "certification_revoked",
    "registry_selected",  # v2.5.0
    "registry_conflict",  # v2.5.0
    "federated_package_resolved",  # v2.5.0
    "reputation_score_computed",  # v2.6.0
    "discovery_index_seen",  # v2.7.0
    "registry_discovered",  # v2.7.0
    "registry_added_from_discovery",  # v2.7.0
    "attestation_seen",  # v2.8.0
    "attestation_verified",  # v2.8.0
    "attestation_rejected",  # v2.8.0
    "artifact_retained",  # v2.9.0
    "artifact_orphan_collected",  # v2.9.0
    "evidence_index_verified",  # v2.9.0
    "evidence_index_mismatch",  # v2.9.0
    "checkpoint_created",  # v2.10.0
    "checkpoint_verified",  # v2.10.0
    "checkpoint_chain_broken",  # v2.10.0
    "rollback_detected",  # v2.10.0
})


class TransparencyEvent(str, Enum):
    """Types of events logged in the transparency log."""
    REGISTRY_METADATA_SEEN = "registry_metadata_seen"
    PACKAGE_METADATA_SEEN = "package_metadata_seen"
    PACKAGE_ARTIFACT_SEEN = "package_artifact_seen"
    PACKAGE_INSTALLED = "package_installed"
    DEPENDENCY_GRAPH_RESOLVED = "dependency_graph_resolved"
    PACKAGE_REVOKED = "package_revoked"
    CERTIFICATION_REVOKED = "certification_revoked"


# ── Log Entry ────────────────────────────────────────────────────────────────

@dataclass
class TransparencyLogEntry:
    """Single entry in the transparency log.

    Each entry chains to the previous entry via previous_entry_digest.
    The entry_digest covers the canonical serialization of all fields
    except entry_digest itself.
    """
    sequence_number: int
    timestamp: str
    event_type: str
    subject_id: str
    subject_version: str = ""
    metadata_digest: str = ""
    artifact_digest: str = ""
    graph_digest: str = ""
    previous_entry_digest: str = ""
    signer_fingerprint: str = ""
    entry_digest: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def canonical_payload(self) -> str:
        """Return canonical JSON of all fields except entry_digest."""
        payload = {
            "sequence_number": self.sequence_number,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "subject_id": self.subject_id,
            "subject_version": self.subject_version,
            "metadata_digest": self.metadata_digest,
            "artifact_digest": self.artifact_digest,
            "graph_digest": self.graph_digest,
            "previous_entry_digest": self.previous_entry_digest,
            "signer_fingerprint": self.signer_fingerprint,
            "extra": self.extra,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def compute_digest(self) -> str:
        """Compute SHA-256 digest of the canonical payload."""
        return hashlib.sha256(self.canonical_payload().encode()).hexdigest()

    def finalize(self) -> TransparencyLogEntry:
        """Compute and set entry_digest if not already set."""
        if not self.entry_digest:
            self.entry_digest = self.compute_digest()
        return self

    def verify_digest(self) -> bool:
        """Verify that entry_digest matches computed digest."""
        return self.entry_digest == self.compute_digest()

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        d = {
            "sequence_number": self.sequence_number,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "subject_id": self.subject_id,
            "subject_version": self.subject_version,
            "metadata_digest": self.metadata_digest,
            "artifact_digest": self.artifact_digest,
            "graph_digest": self.graph_digest,
            "previous_entry_digest": self.previous_entry_digest,
            "signer_fingerprint": self.signer_fingerprint,
            "entry_digest": self.entry_digest,
        }
        if self.extra:
            d["extra"] = self.extra
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> TransparencyLogEntry:
        """Deserialize from dictionary."""
        return cls(
            sequence_number=d["sequence_number"],
            timestamp=d["timestamp"],
            event_type=d["event_type"],
            subject_id=d["subject_id"],
            subject_version=d.get("subject_version", ""),
            metadata_digest=d.get("metadata_digest", ""),
            artifact_digest=d.get("artifact_digest", ""),
            graph_digest=d.get("graph_digest", ""),
            previous_entry_digest=d.get("previous_entry_digest", ""),
            signer_fingerprint=d.get("signer_fingerprint", ""),
            entry_digest=d.get("entry_digest", ""),
            extra=d.get("extra", {}),
        )


# ── Transparency Log ────────────────────────────────────────────────────────

@dataclass
class TransparencyLogVerifyResult:
    """Result of verifying a transparency log."""
    valid: bool = False
    total_entries: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    first_sequence: int = 0
    last_sequence: int = 0
    log_digest: str = ""


class TransparencyLog:
    """Append-only transparency log with chained digests.

    The log is stored as a JSON file containing a list of entries.
    Each entry's previous_entry_digest chains to the prior entry's
    entry_digest. The first entry has previous_entry_digest = "".

    Tamper-evidence:
    - Modifying any field in an old entry invalidates its entry_digest.
    - Deleting an entry breaks the chain (previous_entry_digest mismatch).
    - Inserting an entry requires recomputing all subsequent digests.
    """

    def __init__(self, entries: list[TransparencyLogEntry] | None = None):
        self.entries: list[TransparencyLogEntry] = entries or []

    @property
    def length(self) -> int:
        return len(self.entries)

    @property
    def next_sequence(self) -> int:
        """Next sequence number (0-based or 1-based)."""
        if not self.entries:
            return 1
        return self.entries[-1].sequence_number + 1

    @property
    def tail_digest(self) -> str:
        """Digest of the last entry, or empty string if log is empty."""
        if not self.entries:
            return ""
        return self.entries[-1].entry_digest

    def append(
        self,
        event_type: str,
        subject_id: str,
        subject_version: str = "",
        metadata_digest: str = "",
        artifact_digest: str = "",
        graph_digest: str = "",
        signer_fingerprint: str = "",
        extra: dict[str, Any] | None = None,
    ) -> TransparencyLogEntry:
        """Append a new entry to the log.

        Args:
            event_type: One of EVENT_TYPES.
            subject_id: Package ID or registry URL.
            subject_version: Package version if applicable.
            metadata_digest: SHA-256 of metadata.
            artifact_digest: SHA-256 of artifact.
            graph_digest: SHA-256 of dependency graph.
            signer_fingerprint: Fingerprint of signer if signed.
            extra: Additional structured data.

        Returns:
            The created TransparencyLogEntry.

        Raises:
            ValueError: If event_type is not valid.
        """
        if event_type not in EVENT_TYPES:
            raise ValueError(
                f"Invalid event type '{event_type}'. "
                f"Must be one of: {', '.join(sorted(EVENT_TYPES))}"
            )

        entry = TransparencyLogEntry(
            sequence_number=self.next_sequence,
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            subject_id=subject_id,
            subject_version=subject_version,
            metadata_digest=metadata_digest,
            artifact_digest=artifact_digest,
            graph_digest=graph_digest,
            previous_entry_digest=self.tail_digest,
            signer_fingerprint=signer_fingerprint,
            extra=extra or {},
        )
        entry.finalize()
        self.entries.append(entry)
        return entry

    def verify(self) -> TransparencyLogVerifyResult:
        """Verify the integrity of the entire log chain.

        Checks:
        1. Sequence numbers are consecutive starting from 1.
        2. previous_entry_digest matches prior entry's entry_digest.
        3. Each entry's entry_digest matches its computed digest.
        4. No duplicate sequence numbers.
        """
        result = TransparencyLogVerifyResult()
        result.total_entries = len(self.entries)

        if not self.entries:
            result.valid = True
            result.log_digest = hashlib.sha256(b"").hexdigest()
            return result

        seen_sequences: set[int] = set()
        prev_digest = ""

        for i, entry in enumerate(self.entries):
            # Check sequence starts at 1
            if i == 0:
                if entry.sequence_number != 1:
                    result.errors.append(
                        f"First entry sequence_number is {entry.sequence_number}, expected 1"
                    )

            # Check sequence increments by 1
            if i > 0:
                if entry.sequence_number != self.entries[i - 1].sequence_number + 1:
                    result.errors.append(
                        f"Sequence gap at entry {entry.sequence_number}: "
                        f"expected {self.entries[i - 1].sequence_number + 1}"
                    )

            # Check no duplicate sequence
            if entry.sequence_number in seen_sequences:
                result.errors.append(
                    f"Duplicate sequence_number {entry.sequence_number}"
                )
            seen_sequences.add(entry.sequence_number)

            # Check previous_entry_digest chain
            if entry.previous_entry_digest != prev_digest:
                result.errors.append(
                    f"Broken chain at sequence {entry.sequence_number}: "
                    f"previous_entry_digest mismatch "
                    f"(expected {prev_digest[:12]}..., got {entry.previous_entry_digest[:12]}...)"
                )

            # Check entry digest
            if not entry.verify_digest():
                result.errors.append(
                    f"Entry digest mismatch at sequence {entry.sequence_number}: "
                    f"entry may have been modified"
                )

            prev_digest = entry.entry_digest

        result.first_sequence = self.entries[0].sequence_number
        result.last_sequence = self.entries[-1].sequence_number
        result.log_digest = prev_digest
        result.valid = len(result.errors) == 0
        return result

    def query(
        self,
        package: str | None = None,
        digest: str | None = None,
        event_type: str | None = None,
    ) -> list[TransparencyLogEntry]:
        """Query log entries by package ID or digest."""
        results = []
        for entry in self.entries:
            if package and entry.subject_id != package:
                continue
            if digest and entry.entry_digest != digest:
                continue
            if event_type and entry.event_type != event_type:
                continue
            results.append(entry)
        return results

    def get_entry_by_sequence(self, seq: int) -> TransparencyLogEntry | None:
        """Get entry by sequence number."""
        for entry in self.entries:
            if entry.sequence_number == seq:
                return entry
        return None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "version": TRANSPARENCY_LOG_VERSION,
            "total_entries": len(self.entries),
            "log_digest": self.tail_digest,
            "entries": [e.to_dict() for e in self.entries],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> TransparencyLog:
        """Deserialize from dictionary."""
        entries = [TransparencyLogEntry.from_dict(e) for e in d.get("entries", [])]
        return cls(entries=entries)


# ── File I/O ────────────────────────────────────────────────────────────────

def get_transparency_log_path() -> str:
    """Get the transparency log path from env or default."""
    return os.environ.get(
        "NODECHAIN_TRANSPARENCY_LOG",
        os.path.join("data", "transparency_log.json"),
    )


def load_transparency_log(path: str | None = None) -> TransparencyLog:
    """Load transparency log from file.

    Returns empty log if file doesn't exist.
    """
    path = path or get_transparency_log_path()
    p = Path(path)
    if not p.exists():
        return TransparencyLog()
    raw = p.read_text(encoding="utf-8")
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as e:
        raise TransparencyLogError(
            f"Transparency log file is corrupt at {path}: {e}"
        ) from e
    if not isinstance(data, dict):
        raise TransparencyLogError(
            f"Transparency log at {path} is not a valid JSON object"
        )
    return TransparencyLog.from_dict(data)


def save_transparency_log(
    log: TransparencyLog,
    path: str | None = None,
) -> str:
    """Save transparency log to file atomically.

    Returns the path written to.
    """
    path = path or get_transparency_log_path()
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(
        json.dumps(log.to_dict(), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    tmp.replace(p)
    return str(p)


def append_event(
    event_type: str,
    subject_id: str,
    subject_version: str = "",
    metadata_digest: str = "",
    artifact_digest: str = "",
    graph_digest: str = "",
    signer_fingerprint: str = "",
    extra: dict[str, Any] | None = None,
    path: str | None = None,
) -> TransparencyLogEntry:
    """Convenience: load log, append event, save log.

    Returns the created entry.
    """
    log = load_transparency_log(path)
    entry = log.append(
        event_type=event_type,
        subject_id=subject_id,
        subject_version=subject_version,
        metadata_digest=metadata_digest,
        artifact_digest=artifact_digest,
        graph_digest=graph_digest,
        signer_fingerprint=signer_fingerprint,
        extra=extra,
    )
    save_transparency_log(log, path)
    return entry


def verify_transparency_log(path: str | None = None) -> TransparencyLogVerifyResult:
    """Load and verify a transparency log file."""
    log = load_transparency_log(path)
    return log.verify()
