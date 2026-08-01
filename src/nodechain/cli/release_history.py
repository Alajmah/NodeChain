"""Release History and Retention (v1.13.6, v1.13.7).

Provides a persistent release history index that tracks every deployment,
enables rollback-by-release-id resolution, and verifies that referenced
artifacts are retained and intact.

v1.13.7 adds integrity metadata, audit logging, and comprehensive verification.

Release history file: data/release_history.json (or $NODECHAIN_RELEASE_HISTORY)
Audit log file: data/release_history_audit.jsonl (or $NODECHAIN_RELEASE_HISTORY_AUDIT)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sha256_dict(data: dict[str, Any]) -> str:
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


#: v1.13.7: Valid hex digest pattern (SHA-256 = 64 hex chars)
_HEX_DIGEST_RE = re.compile(r"^[a-f0-9]{64}$")


def _is_valid_hex_digest(digest: str) -> bool:
    """Check if a string is a valid 64-char hex digest (or empty)."""
    if not digest:
        return True  # Empty is valid (not all fields are required)
    return bool(_HEX_DIGEST_RE.match(digest))


class ReleaseRecord:
    """A single release entry in the release history."""

    def __init__(
        self,
        release_id: str = "",
        artifact_digest: str = "",
        deployment_receipt_digest: str = "",
        attestation_digest: str = "",
        audit_bundle_digest: str = "",
        verifier_profile_digest: str = "",
        gate_receipt_digest: str = "",
        final_deployment_state: str = "",
        activation_verified: bool = False,
        created_at: str = "",
        target: str = "",
        # Optional: file paths for retention verification
        deployment_receipt_path: str = "",
        attestation_path: str = "",
        audit_bundle_path: str = "",
        verifier_profile_path: str = "",
        gate_receipt_path: str = "",
        artifact_path: str = "",
    ) -> None:
        self.release_id = release_id or str(uuid.uuid4())
        self.artifact_digest = artifact_digest
        self.deployment_receipt_digest = deployment_receipt_digest
        self.attestation_digest = attestation_digest
        self.audit_bundle_digest = audit_bundle_digest
        self.verifier_profile_digest = verifier_profile_digest
        self.gate_receipt_digest = gate_receipt_digest
        self.final_deployment_state = final_deployment_state
        self.activation_verified = activation_verified
        self.created_at = created_at or _now_iso()
        self.target = target
        # File paths for retention
        self.deployment_receipt_path = deployment_receipt_path
        self.attestation_path = attestation_path
        self.audit_bundle_path = audit_bundle_path
        self.verifier_profile_path = verifier_profile_path
        self.gate_receipt_path = gate_receipt_path
        self.artifact_path = artifact_path

    @property
    def is_known_good(self) -> bool:
        """A release is known-good if applied and activation_verified."""
        return (
            self.final_deployment_state == "applied"
            and self.activation_verified is True
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "release_id": self.release_id,
            "artifact_digest": self.artifact_digest,
            "deployment_receipt_digest": self.deployment_receipt_digest,
            "attestation_digest": self.attestation_digest,
            "audit_bundle_digest": self.audit_bundle_digest,
            "verifier_profile_digest": self.verifier_profile_digest,
            "gate_receipt_digest": self.gate_receipt_digest,
            "final_deployment_state": self.final_deployment_state,
            "activation_verified": self.activation_verified,
            "created_at": self.created_at,
            "target": self.target,
            "deployment_receipt_path": self.deployment_receipt_path,
            "attestation_path": self.attestation_path,
            "audit_bundle_path": self.audit_bundle_path,
            "verifier_profile_path": self.verifier_profile_path,
            "gate_receipt_path": self.gate_receipt_path,
            "artifact_path": self.artifact_path,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ReleaseRecord":
        return cls(
            release_id=data.get("release_id", ""),
            artifact_digest=data.get("artifact_digest", ""),
            deployment_receipt_digest=data.get("deployment_receipt_digest", ""),
            attestation_digest=data.get("attestation_digest", ""),
            audit_bundle_digest=data.get("audit_bundle_digest", ""),
            verifier_profile_digest=data.get("verifier_profile_digest", ""),
            gate_receipt_digest=data.get("gate_receipt_digest", ""),
            final_deployment_state=data.get("final_deployment_state", ""),
            activation_verified=data.get("activation_verified", False),
            created_at=data.get("created_at", ""),
            target=data.get("target", ""),
            deployment_receipt_path=data.get("deployment_receipt_path", ""),
            attestation_path=data.get("attestation_path", ""),
            audit_bundle_path=data.get("audit_bundle_path", ""),
            verifier_profile_path=data.get("verifier_profile_path", ""),
            gate_receipt_path=data.get("gate_receipt_path", ""),
            artifact_path=data.get("artifact_path", ""),
        )

    @classmethod
    def from_receipt(
        cls,
        receipt: dict[str, Any],
        target: str = "",
        artifact_path: str = "",
        receipt_path: str = "",
        attestation_path: str = "",
        audit_bundle_path: str = "",
        verifier_profile_path: str = "",
        gate_receipt_path: str = "",
    ) -> "ReleaseRecord":
        """Create a ReleaseRecord from a deployment receipt."""
        receipt_digest = _sha256_dict(receipt) if receipt else ""
        return cls(
            release_id=str(uuid.uuid4()),
            artifact_digest=(
                receipt.get("activated_artifact_digest")
                or receipt.get("artifact_digest")
                or receipt.get("promoted_artifact_digest")
                or ""
            ),
            deployment_receipt_digest=receipt_digest,
            attestation_digest=receipt.get("attestation_digest", ""),
            audit_bundle_digest=receipt.get("audit_bundle_sha256", ""),
            verifier_profile_digest=receipt.get("verifier_profile_digest", ""),
            gate_receipt_digest=receipt.get("gate_receipt_digest", ""),
            final_deployment_state=receipt.get("final_deployment_state", ""),
            activation_verified=receipt.get("activation_verified", False),
            target=target,
            artifact_path=artifact_path,
            deployment_receipt_path=receipt_path,
            attestation_path=attestation_path,
            audit_bundle_path=audit_bundle_path,
            verifier_profile_path=verifier_profile_path,
            gate_receipt_path=gate_receipt_path,
        )


#: v1.13.7: Valid audit actions
AUDIT_ACTIONS = frozenset({
    "record_release",
    "update_release",
    "remove_release",
    "retention_verified",
    "rollback_resolved",
})


class ReleaseHistory:
    """Persistent release history index with integrity metadata and audit log.

    Stored as JSON at data/release_history.json (or $NODECHAIN_RELEASE_HISTORY).
    Audit log stored as JSONL at data/release_history_audit.jsonl.
    """

    SCHEMA_VERSION = "2.0"  # v1.13.7: bumped from "1.0"

    def __init__(self, path: str = "") -> None:
        if not path:
            path = os.environ.get(
                "NODECHAIN_RELEASE_HISTORY",
                str(Path("data/release_history.json")),
            )
        self.path = Path(path)
        self.releases: list[ReleaseRecord] = []
        # v1.13.7: Integrity metadata
        self.schema_version: str = self.SCHEMA_VERSION
        self.release_history_id: str = str(uuid.uuid4())
        self.updated_at: str = _now_iso()
        self.entries_digest: str = ""
        self._audit_path = self.path.with_name(
            self.path.stem + "_audit.jsonl"
        )
        self._load()

    def _load(self) -> None:
        """Load release history from disk."""
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                self.releases = [
                    ReleaseRecord.from_dict(r) for r in data.get("releases", [])
                ]
                # v1.13.7: Load integrity metadata
                self.schema_version = data.get("schema_version", "1.0")
                self.release_history_id = data.get("release_history_id", str(uuid.uuid4()))
                self.updated_at = data.get("updated_at", _now_iso())
                self.entries_digest = data.get("entries_digest", "")
            except (json.JSONDecodeError, KeyError):
                self.releases = []
        else:
            self.releases = []

    def _compute_entries_digest(self) -> str:
        """Compute SHA-256 of canonical release entries (v1.13.7).

        The digest is computed over the sorted list of release dicts,
        excluding volatile metadata (updated_at).
        """
        entries = [r.to_dict() for r in self.releases]
        return _sha256_dict({"releases": entries})

    def save(self) -> None:
        """Save release history to disk atomically (v1.13.7: with metadata)."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.updated_at = _now_iso()
        self.entries_digest = self._compute_entries_digest()
        data = {
            "schema_version": self.SCHEMA_VERSION,
            "release_history_id": self.release_history_id,
            "updated_at": self.updated_at,
            "entries_digest": self.entries_digest,
            "releases": [r.to_dict() for r in self.releases],
        }
        # Atomic write: temp file + rename
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    def audit(
        self,
        action: str,
        release_id: str = "",
        target: str = "",
        artifact_digest: str = "",
        final_deployment_state: str = "",
        activation_verified: bool = False,
        actor: str = "",
    ) -> dict[str, Any]:
        """Record an audit event (v1.13.7).

        Args:
            action: One of AUDIT_ACTIONS.
            release_id: Affected release ID.
            target: Target identifier.
            artifact_digest: Artifact digest.
            final_deployment_state: Deployment state.
            activation_verified: Activation verification status.
            actor: Identity of the actor (if available).

        Returns:
            The audit event dict.
        """
        event = {
            "timestamp": _now_iso(),
            "action": action,
            "release_id": release_id,
            "target": target,
            "artifact_digest": artifact_digest,
            "final_deployment_state": final_deployment_state,
            "activation_verified": activation_verified,
            "actor": actor,
        }
        # Append to JSONL audit log
        self._audit_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._audit_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
        return event

    def load_audit_log(self) -> list[dict[str, Any]]:
        """Load the audit log entries (v1.13.7)."""
        if not self._audit_path.exists():
            return []
        events = []
        for line in self._audit_path.read_text(encoding="utf-8").strip().split("\n"):
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return events

    def add(self, record: ReleaseRecord, actor: str = "") -> str:
        """Add a release record. Returns the release_id.

        v1.13.7: Records 'record_release' audit event.
        """
        self.releases.append(record)
        self.save()
        self.audit(
            action="record_release",
            release_id=record.release_id,
            target=record.target,
            artifact_digest=record.artifact_digest,
            final_deployment_state=record.final_deployment_state,
            activation_verified=record.activation_verified,
            actor=actor,
        )
        return record.release_id

    def remove(self, release_id: str, actor: str = "") -> bool:
        """Remove a release record. Returns True if removed.

        v1.13.7: Records 'remove_release' audit event.
        """
        original_len = len(self.releases)
        self.releases = [r for r in self.releases if r.release_id != release_id]
        if len(self.releases) < original_len:
            self.save()
            self.audit(
                action="remove_release",
                release_id=release_id,
                actor=actor,
            )
            return True
        return False

    def get(self, release_id: str) -> ReleaseRecord | None:
        """Get a release by release_id."""
        for r in self.releases:
            if r.release_id == release_id:
                return r
        return None

    def find_by_digest(self, artifact_digest: str) -> ReleaseRecord | None:
        """Find the most recent release with matching artifact digest."""
        for r in reversed(self.releases):
            if r.artifact_digest == artifact_digest:
                return r
        return None

    def latest_known_good(self, target: str = "") -> ReleaseRecord | None:
        """Find the latest known-good release for a target.

        Known-good means:
          - final_deployment_state = applied
          - activation_verified = True
        """
        for r in reversed(self.releases):
            if r.is_known_good:
                if target and r.target and r.target != target:
                    continue
                return r
        return None

    def list_releases(
        self, target: str = "", limit: int = 0
    ) -> list[ReleaseRecord]:
        """List releases, optionally filtered by target."""
        result = self.releases
        if target:
            result = [r for r in result if r.target == target]
        if limit and limit > 0:
            result = result[-limit:]
        return list(reversed(result))  # newest first

    def verify_integrity(self) -> dict[str, Any]:
        """Verify release history integrity (v1.13.7).

        Comprehensive checks:
          1. Schema version present
          2. No duplicate release IDs
          3. No duplicate deployment receipt digests
          4. All digests are valid hex SHA-256 (or empty)
          5. entries_digest matches computed value
          6. All referenced files exist and match digests

        Returns:
            {valid: bool, errors: list[str], warnings: list[str],
             checks: dict[str, Any]}
        """
        errors: list[str] = []
        warnings: list[str] = []
        checks: dict[str, Any] = {}

        # Check 1: Schema version
        checks["schema_version"] = self.schema_version
        if not self.schema_version:
            errors.append("Missing schema_version")
            checks["schema_present"] = False
        else:
            checks["schema_present"] = True

        # Check 2: release_history_id present
        checks["release_history_id_present"] = bool(self.release_history_id)
        if not self.release_history_id:
            errors.append("Missing release_history_id")

        # Check 3: No duplicate release IDs
        release_ids = [r.release_id for r in self.releases]
        seen_ids: set[str] = set()
        dup_ids: list[str] = []
        for rid in release_ids:
            if rid in seen_ids:
                dup_ids.append(rid)
            seen_ids.add(rid)
        checks["duplicate_release_ids"] = dup_ids
        if dup_ids:
            errors.append(f"Duplicate release IDs: {dup_ids}")

        # Check 4: No duplicate deployment receipt digests
        receipt_digests = [
            r.deployment_receipt_digest for r in self.releases
            if r.deployment_receipt_digest
        ]
        seen_receipts: set[str] = set()
        dup_receipts: list[str] = []
        for rd in receipt_digests:
            if rd in seen_receipts:
                dup_receipts.append(rd[:12] + "...")
            seen_receipts.add(rd)
        checks["duplicate_receipt_digests"] = dup_receipts
        if dup_receipts:
            errors.append(f"Duplicate deployment receipt digests: {dup_receipts}")

        # Check 5: All digests are valid hex SHA-256 (or empty)
        malformed: list[str] = []
        for r in self.releases:
            for field_name in (
                "artifact_digest", "deployment_receipt_digest",
                "attestation_digest", "audit_bundle_digest",
                "verifier_profile_digest", "gate_receipt_digest",
            ):
                val = getattr(r, field_name, "")
                if val and not _is_valid_hex_digest(val):
                    malformed.append(
                        f"{r.release_id[:12]}.{field_name}={val[:20]}..."
                    )
        checks["malformed_digests"] = malformed
        if malformed:
            errors.append(f"Malformed digests: {malformed}")

        # Check 6: entries_digest matches
        computed = self._compute_entries_digest()
        checks["entries_digest_computed"] = computed[:16] + "..."
        if self.entries_digest:
            if self.entries_digest != computed:
                errors.append(
                    f"entries_digest mismatch: stored={self.entries_digest[:16]}... "
                    f"computed={computed[:16]}..."
                )
                checks["entries_digest_match"] = False
            else:
                checks["entries_digest_match"] = True
        else:
            warnings.append("entries_digest not set (computed but not stored)")
            checks["entries_digest_match"] = None

        # Check 7: Referenced files exist (best-effort)
        missing_files: list[str] = []
        for r in self.releases:
            for field_name in (
                "deployment_receipt_path", "attestation_path",
                "audit_bundle_path", "verifier_profile_path",
                "gate_receipt_path", "artifact_path",
            ):
                val = getattr(r, field_name, "")
                if val and not Path(val).exists():
                    missing_files.append(
                        f"{r.release_id[:12]}.{field_name}={val}"
                    )
        checks["missing_files"] = missing_files
        if missing_files:
            errors.append(f"Referenced files missing: {len(missing_files)} files")

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "checks": checks,
        }

    def verify_retention(
        self,
        release_id: str = "",
        require_chain: bool = False,
    ) -> dict[str, Any]:
        """Verify that referenced artifacts are retained and intact."""
        record: ReleaseRecord | None = None
        if release_id:
            record = self.get(release_id)
            if not record:
                return {
                    "valid": False,
                    "errors": [f"Release {release_id} not found"],
                    "warnings": [],
                    "checks": {},
                    "release_id": release_id,
                }
        else:
            # Verify all releases
            results = []
            all_valid = True
            for r in self.releases:
                vr = self.verify_retention(r.release_id, require_chain)
                if not vr["valid"]:
                    all_valid = False
                results.append(vr)
            # v1.13.7: Audit retention verification
            self.audit(
                action="retention_verified",
                actor="system",
            )
            return {
                "valid": all_valid,
                "errors": [],
                "warnings": [],
                "checks": {"total": len(results), "verified": sum(1 for r in results if r["valid"])},
                "results": results,
                "release_id": "",
            }

        assert record is not None
        errors: list[str] = []
        warnings: list[str] = []
        checks: dict[str, Any] = {}

        # Check 1: Release state
        if record.final_deployment_state != "applied":
            errors.append(
                f"Release state is '{record.final_deployment_state}', not 'applied'"
            )
            checks["final_deployment_state"] = record.final_deployment_state
        else:
            checks["final_deployment_state"] = "applied"

        # Check 2: Activation verified
        if not record.activation_verified:
            errors.append("Release activation_verified is false")
            checks["activation_verified"] = False
        else:
            checks["activation_verified"] = True

        # Check 3: Referenced files exist
        path_checks = {
            "deployment_receipt": record.deployment_receipt_path,
            "attestation": record.attestation_path,
            "audit_bundle": record.audit_bundle_path,
            "verifier_profile": record.verifier_profile_path,
            "gate_receipt": record.gate_receipt_path,
            "artifact": record.artifact_path,
        }
        for name, path in path_checks.items():
            if path:
                if Path(path).exists():
                    checks[f"{name}_exists"] = True
                    digest = _sha256_text(Path(path).read_text(encoding="utf-8"))
                    expected = ""
                    if name == "deployment_receipt":
                        expected = record.deployment_receipt_digest
                    elif name == "attestation":
                        expected = record.attestation_digest
                    elif name == "audit_bundle":
                        expected = record.audit_bundle_digest
                    elif name == "verifier_profile":
                        expected = record.verifier_profile_digest
                    elif name == "gate_receipt":
                        expected = record.gate_receipt_digest
                    elif name == "artifact":
                        expected = record.artifact_digest
                    if expected and digest != expected:
                        errors.append(f"{name} digest mismatch: expected {expected[:12]}..., got {digest[:12]}...")
                        checks[f"{name}_digest_match"] = False
                    else:
                        checks[f"{name}_digest_match"] = True
                else:
                    errors.append(f"{name} file missing: {path}")
                    checks[f"{name}_exists"] = False
            else:
                if require_chain and name in ("deployment_receipt", "attestation"):
                    errors.append(f"{name} path not set (chain required)")
                    checks[f"{name}_exists"] = False
                else:
                    checks[f"{name}_exists"] = None  # not set

        # Check 4: Assurance chain available (if required)
        if require_chain:
            chain_available = (
                bool(record.deployment_receipt_digest)
                and bool(record.attestation_digest)
            )
            if not chain_available:
                errors.append("Assurance chain incomplete (missing receipt or attestation digest)")
                checks["chain_available"] = False
            else:
                checks["chain_available"] = True

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "checks": checks,
            "release_id": record.release_id,
        }


# ── v1.13.8: Signed Snapshots ──────────────────────────────────────────────

#: v1.13.8: Snapshot schema version
RELEASE_HISTORY_SNAPSHOT_SCHEMA_VERSION = "1"

#: v1.13.8: Fields stripped from snapshot before digest/sign
_SNAP_SIG_FIELDS = frozenset({
    "snapshot_signature", "snapshot_signature_algorithm",
    "snapshot_signer_fingerprint", "snapshot_digest",
})


def _canonicalize_snapshot(snap: dict[str, Any]) -> bytes:
    """Create canonical bytes of snapshot content for signing."""
    stripped = {k: v for k, v in snap.items()
                if k not in _SNAP_SIG_FIELDS}
    return json.dumps(stripped, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _compute_audit_log_digest(events: list[dict[str, Any]]) -> str:
    """Compute SHA-256 digest of the audit log events."""
    canonical = json.dumps(events, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def create_release_history_snapshot(
    output_path: str = "",
    private_key_path: str = "",
    history_path: str = "",
) -> dict[str, Any]:
    """Create a snapshot of the current release history state (v1.13.8).

    Args:
        output_path: Path to write snapshot JSON. If empty, returns without writing.
        private_key_path: Path to PEM private key for signing the snapshot.
        history_path: Path to release history file (default: NODECHAIN_RELEASE_HISTORY).

    Returns:
        Snapshot dict with metadata, digests, and optional signature.
    """
    history = ReleaseHistory(path=history_path)

    # Build target summary
    target_summary: dict[str, int] = {}
    for r in history.releases:
        if r.target:
            target_summary[r.target] = target_summary.get(r.target, 0) + 1

    # Build latest known-good summary
    lkg = history.latest_known_good()
    lkg_summary: dict[str, Any] = {}
    if lkg:
        lkg_summary = {
            "release_id": lkg.release_id,
            "artifact_digest": lkg.artifact_digest,
            "target": lkg.target,
            "created_at": lkg.created_at,
        }

    # Compute audit log digest
    audit_events = history.load_audit_log()
    audit_digest = _compute_audit_log_digest(audit_events)

    snapshot: dict[str, Any] = {
        "schema_version": RELEASE_HISTORY_SNAPSHOT_SCHEMA_VERSION,
        "type": "release_history_snapshot",
        "release_history_id": history.release_history_id,
        "entries_digest": history.entries_digest or history._compute_entries_digest(),
        "audit_log_digest": audit_digest,
        "release_count": len(history.releases),
        "target_summary": dict(sorted(target_summary.items())),
        "latest_known_good_summary": lkg_summary,
        "created_at": _now_iso(),
    }

    # Compute snapshot digest
    snapshot["snapshot_digest"] = hashlib.sha256(
        _canonicalize_snapshot(snapshot)
    ).hexdigest()

    # Sign if requested
    if private_key_path:
        snapshot = _sign_release_history_snapshot(snapshot, private_key_path)

    if output_path:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(snapshot, indent=2, sort_keys=True), encoding="utf-8")

    return snapshot


def _sign_release_history_snapshot(
    snapshot: dict[str, Any], private_key_path: str
) -> dict[str, Any]:
    """Sign a release history snapshot with RSA-PSS-SHA256 (v1.13.8)."""
    import base64
    from nodechain.cli.bundle_signing import _load_private_key
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes, serialization

    private_key = _load_private_key(private_key_path)
    signed_data = _canonicalize_snapshot(snapshot)

    signature = private_key.sign(
        signed_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=hashes.SHA256().digest_size,
        ),
        hashes.SHA256(),
    )

    public_key = private_key.public_key()
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = hashlib.sha256(public_der).hexdigest()[:32]

    enriched = dict(snapshot)
    enriched["snapshot_signature"] = base64.b64encode(signature).decode("ascii")
    enriched["snapshot_signature_algorithm"] = "RSA-PSS-SHA256"
    enriched["snapshot_signer_fingerprint"] = fingerprint

    return enriched


def verify_release_history_snapshot(
    snapshot_path: str = "",
    snapshot_dict: dict[str, Any] | None = None,
    public_key_pem: str = "",
    check_live_history: bool = False,
    history_path: str = "",
) -> dict[str, Any]:
    """Verify a release history snapshot (v1.13.8).

    Args:
        snapshot_path: Path to snapshot JSON file.
        snapshot_dict: Snapshot dict (alternative to path).
        public_key_pem: PEM public key for signature verification.
        check_live_history: If True, compare against current release history.
        history_path: Path to release history file.

    Returns:
        {valid: bool, errors: list, warnings: list, details: dict}
    """
    import base64
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes, serialization

    errors: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {}

    # Load snapshot
    if snapshot_dict is None:
        if not snapshot_path:
            return {"valid": False, "errors": ["No snapshot provided"], "warnings": [], "details": {}}
        snapshot_dict = json.loads(Path(snapshot_path).read_text(encoding="utf-8"))

    # Check 1: Schema version
    sv = snapshot_dict.get("schema_version", "")
    details["schema_version"] = sv == RELEASE_HISTORY_SNAPSHOT_SCHEMA_VERSION
    if sv != RELEASE_HISTORY_SNAPSHOT_SCHEMA_VERSION:
        errors.append(f"Invalid snapshot schema_version: {sv!r}")

    # Check 2: Snapshot digest
    stored_digest = snapshot_dict.get("snapshot_digest", "")
    if stored_digest:
        computed = hashlib.sha256(_canonicalize_snapshot(snapshot_dict)).hexdigest()
        details["snapshot_digest"] = stored_digest == computed
        if stored_digest != computed:
            errors.append("Snapshot digest mismatch (tampered content)")
    else:
        details["snapshot_digest"] = False
        errors.append("Snapshot digest missing")

    # Check 3: release_history_id present
    rhid = snapshot_dict.get("release_history_id", "")
    details["release_history_id"] = bool(rhid)
    if not rhid:
        errors.append("release_history_id missing")

    # Check 4: entries_digest present
    ed = snapshot_dict.get("entries_digest", "")
    details["entries_digest"] = bool(ed)
    if not ed:
        errors.append("entries_digest missing")

    # Check 5: audit_log_digest present
    ald = snapshot_dict.get("audit_log_digest", "")
    details["audit_log_digest"] = bool(ald)
    if not ald:
        errors.append("audit_log_digest missing")

    # Check 6: Signature
    sig_b64 = snapshot_dict.get("snapshot_signature", "")
    if sig_b64:
        if not public_key_pem:
            warnings.append("Snapshot is signed but no public key provided for verification")
            details["signature_status"] = "signed_unverified"
        else:
            try:
                public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
                signature = base64.b64decode(sig_b64)
                signed_data = _canonicalize_snapshot(snapshot_dict)
                public_key.verify(
                    signature,
                    signed_data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=hashes.SHA256().digest_size,
                    ),
                    hashes.SHA256(),
                )
                details["signature_status"] = "valid"
            except Exception as exc:
                details["signature_status"] = "invalid"
                errors.append(f"Snapshot signature invalid: {exc}")
    else:
        details["signature_status"] = "none"

    # Check 7: Compare against live history if requested
    if check_live_history:
        history = ReleaseHistory(path=history_path)
        live_entries = history.entries_digest or history._compute_entries_digest()
        snap_entries = snapshot_dict.get("entries_digest", "")
        details["live_entries_match"] = live_entries == snap_entries
        if live_entries != snap_entries:
            errors.append(
                f"Live entries_digest mismatch: snapshot={snap_entries[:16]}... "
                f"live={live_entries[:16]}..."
            )

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "details": details,
    }
