"""Canonical side-effect identity utilities (v2.38.0).

Single source of truth for request_hash and response_hash derivation across
all side-effect lifecycle paths. Eliminates the v2.36.0 drift where pre-call
journaling hashed the full payload while post-call paths hashed a narrow
operation slice — producing different digests for the same side effect.

v3.5.0: adds ReplayCapsule, make_retry_side_effect_key, canonical_request_digest,
and canonical capsule serialization for retry-authorized execution.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from typing import Any


def compute_side_effect_request_hash(
    side_effect_type: str,
    node_id: str,
    idempotency_key: str = "",
    payload: dict[str, Any] | None = None,
    operation: dict[str, Any] | None = None,
) -> str:
    """Compute a canonical request hash for a side effect.

    The hash is deterministic and stable across pre-call journaling and
    post-call completion/failure. Inputs are:

    - side_effect_type (canonical)
    - node_id
    - operation dict (preferred, if provided) OR full payload (fallback)

    Note: idempotency_key is accepted for signature compatibility but is NOT
    included in the hash (it can be derived FROM the hash, creating a circular
    dependency for search keys like ``search:<adapter>:<request_hash>``).

    The operation dict should be the specific, normalized operation parameters
    (e.g. {terms, max, filters} for search; {subject, content} for memory).
    When no operation is available, the full envelope payload is used.

    Returns a 16-character hex string (sha256 prefix).
    """
    # Build the canonical input: type + node + operation/payload
    parts = {
        "type": side_effect_type,
        "node_id": node_id,
    }
    if operation is not None:
        parts["operation"] = _normalize_for_hash(operation)
    elif payload is not None:
        parts["payload"] = _normalize_for_hash(payload)
    # Sort keys for deterministic serialization
    canonical = json.dumps(parts, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def compute_side_effect_response_hash(
    results: list[dict[str, Any]] | None = None,
    external_reference: str = "",
) -> str:
    """Compute a canonical response hash from operation results.

    For search: hashes the sorted DOI/title of the top-N adapter results.
    For memory writes: the external_reference (write_ref) is passed directly.
    """
    if external_reference:
        return external_reference
    if results:
        # Sort by DOI (fallback to title) for deterministic ordering
        identifiers = sorted(
            r.get("raw_data", {}).get(
                "doi", r.get("raw_data", {}).get("title", "")
            )
            for r in results[:10]
        )
        canonical = json.dumps(identifiers, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]
    return ""


def make_canonical_search_key(adapter_name: str, request_hash: str) -> str:
    """Build the canonical ledger/emitter key for a search side effect.

    The canonical form is ``search:<adapter_name>:<request_hash>`` — the same
    format used by ``SideEffectJournalMixin._journal_search_operations`` and
    the trace emitter's SIDE_EFFECT_STARTED/SIDE_EFFECT_COMPLETED events.

    v3.0.0: introduced to close the key-format drift between the search node's
    internal ``<adapter>:<hash>`` key and the ledger's ``search:<adapter>:<hash>``
    key. Both journaling and node-reported completion MUST use this helper so a
    completion record's ``side_effect_key`` exactly matches its ledger row.

    Returns "" if either part is empty (fail-closed — no partial key).
    """
    if not adapter_name or not request_hash:
        return ""
    return f"search:{adapter_name}:{request_hash}"


def _normalize_for_hash(data: dict[str, Any]) -> dict[str, Any]:
    """Normalize a dict for stable hashing (sorted keys, stringified values)."""
    normalized: dict[str, Any] = {}
    for key in sorted(data.keys()):
        val = data[key]
        if isinstance(val, list):
            normalized[key] = sorted(val) if all(
                isinstance(v, str) for v in val
            ) else val
        elif isinstance(val, dict):
            normalized[key] = _normalize_for_hash(val)
        else:
            normalized[key] = val
    return normalized


# ── v3.5.0: Replay Capsule + Retry Key Derivation ────────────────────


# Fixed namespace UUID for deterministic retry-key derivation (v3.5.0).
# Generated once; never changed. Ensures make_retry_side_effect_key produces
# the same key for the same inputs across processes, versions, and machines.
_RETRY_KEY_NAMESPACE = uuid.UUID("a3f7c2d1-4e8b-4f2a-9c6d-7e1b3a5f8d02")

# v3.5.0: maximum canonical plaintext size for replay capsules (INV-004, DEC-001).
# Applies to UTF-8 bytes of the canonical JSON serialization, before encryption.
MAX_CAPSULE_SIZE_BYTES = 65536  # 64 KiB

# v3.5.0: canonical serialization version for replay capsules.
CAPSULE_SCHEMA_VERSION = 1
CANONICALIZATION_VERSION = "1"


def canonicalize_capsule_payload(value: Any) -> bytes:
    """Serialize a value to canonical JSON bytes for capsule storage.

    v3.5.0: canonical serialization is explicit and versioned. Uses sorted keys,
    compact separators, no ASCII escaping, and rejects NaN/Infinity.

    Raises TypeError for non-JSON-serializable values (no default=str fallback,
    which could produce unstable representations).
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def compute_canonical_request_digest(canonical_bytes: bytes) -> str:
    """Compute the full SHA-256 digest over canonical capsule operation bytes.

    v3.5.0: the recovery gate requires a full digest, not the 16-char prefix
    used by request_hash (which is for key compatibility only). The invariant:
    the bytes encrypted as the canonical operation are exactly the bytes hashed
    for canonical_request_digest.
    """
    return hashlib.sha256(canonical_bytes).hexdigest()


def make_capsule_id(
    run_id: str,
    side_effect_key: str,
    schema_version: int = CAPSULE_SCHEMA_VERSION,
) -> str:
    """Deterministically derive an attempt-scoped capsule ID (v3.5.0).

    ChatGPT revised T6 blocker 3: capsule_id must be scoped to the attempt
    identity (run_id + side_effect_key), NOT to content alone. Two runs
    executing the same canonical operation must produce different capsule IDs
    because encryption is bound to run_id + side_effect_key.

    A changed operation under the same attempt produces the same capsule_id
    but a different capsule_digest — which is exactly the conflict the store
    must reject.
    """
    if not run_id or not side_effect_key:
        raise ValueError(
            "make_capsule_id requires non-empty run_id and side_effect_key"
        )
    derived = uuid.uuid5(
        _RETRY_KEY_NAMESPACE,
        f"{run_id}::{side_effect_key}::v{schema_version}",
    )
    return f"cap:{derived}"


# ChatGPT T6 3rd re-review fix 3: shared capsule convergence comparison.
# All three INSERT paths must compare the same set of immutable fields.
_CAPSULE_EQUIVALENCE_FIELDS = (
    "capsule_digest",
    "capsule_schema_version",
    "canonicalization_version",
    "source_binding_json",
    "payload_sensitivity",
    "serialization_version",
    "key_version",
)


def capsules_logically_equivalent(existing: dict, candidate: dict) -> bool:
    """Check if two capsule rows are logically equivalent (immutable fields match).

    ChatGPT T6 3rd re-review fix 3: all convergence paths must compare the
    same set of immutable binding fields. Ciphertext and nonce are NOT compared
    because an idempotent reconstruction may legitimately produce fresh
    encryption material before discovering the existing row.

    Args:
        existing: dict of persisted capsule fields (from SELECT).
        candidate: dict of candidate capsule fields (from the new INSERT).

    Returns True if all immutable fields match, False otherwise.
    """
    for field in _CAPSULE_EQUIVALENCE_FIELDS:
        ex_val = existing.get(field)
        new_val = candidate.get(field)
        if ex_val != new_val:
            return False
    return True


def make_retry_side_effect_key(
    parent_side_effect_key: str,
    recovery_decision_id: str,
) -> str:
    """Deterministically derive a retry child attempt key (v3.5.0, INV-002).

    One recovery decision binds to at most one child attempt. Duplicate
    EXECUTE_RETRY_AUTHORIZED commands converge on the same key.

    Uses UUIDv5 with a fixed namespace — the same inputs always produce the
    same key across processes, versions, and machines.
    """
    if not parent_side_effect_key or not recovery_decision_id:
        raise ValueError(
            "make_retry_side_effect_key requires non-empty "
            "parent_side_effect_key and recovery_decision_id"
        )
    derived = uuid.uuid5(
        _RETRY_KEY_NAMESPACE,
        f"{parent_side_effect_key}::{recovery_decision_id}",
    )
    return f"retry:{derived}"


@dataclass
class ReplayCapsule:
    """v3.5.0: durable replay material for a governed side effect (INV-004).

    Persisted proactively at SIDE_EFFECT_STARTED time. Contains the canonical
    operation payload (no credentials), operation identity, source binding
    (node/contract/adapter versions), and schema versions. Encrypted at rest
    with AES-256-GCM under the per-run DEK.
    """
    capsule_id: str
    canonical_request_digest: str  # full SHA-256 over canonical_bytes
    side_effect_type: str
    operation_name: str
    adapter_id: str
    adapter_version: str
    node_id: str
    node_version: str
    contract_id: str
    contract_version: str
    original_invocation_id: str
    capsule_schema_version: int = CAPSULE_SCHEMA_VERSION
    canonicalization_version: str = CANONICALIZATION_VERSION
    external_idempotency_key_reference: str | None = None
    payload_sensitivity: str = "standard"
    # canonical_bytes is NOT persisted as a field — it's encrypted and stored
    # as encrypted_payload in the capsule table. This field carries the
    # plaintext bytes only during the persistence transaction.
    canonical_bytes: bytes = field(default=b"", repr=False)

    def to_metadata(self) -> dict[str, Any]:
        """Return metadata dict for the capsule table (excludes plaintext)."""
        return {
            "capsule_id": self.capsule_id,
            "capsule_digest": self.canonical_request_digest,
            "capsule_schema_version": self.capsule_schema_version,
            "canonicalization_version": self.canonicalization_version,
            "side_effect_type": self.side_effect_type,
            "operation_name": self.operation_name,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "node_id": self.node_id,
            "node_version": self.node_version,
            "contract_id": self.contract_id,
            "contract_version": self.contract_version,
            "original_invocation_id": self.original_invocation_id,
            "external_idempotency_key_reference": self.external_idempotency_key_reference,
            "payload_sensitivity": self.payload_sensitivity,
        }

    def to_source_binding(self) -> dict[str, str]:
        """Return source binding for RecoveryEnvelopeV1."""
        return {
            "node_id": self.node_id,
            "node_version": self.node_version,
            "contract_id": self.contract_id,
            "contract_version": self.contract_version,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
        }

