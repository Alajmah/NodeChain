"""Local trust store for signing keys (v1.8.3).

Manages a local JSON file mapping signer names to their trusted public keys
and fingerprints. This is the trusted root for verifier profile signatures,
adapter manifest signatures, and receipt signatures.

Commands:
  nodechain trust-store add-key <name> <public_key.pem> [--purpose ...]
  nodechain trust-store list
  nodechain trust-store remove-key <name>
  nodechain trust-store migrate [--purpose ...]       (v1.10.5)
  nodechain trust-store verify                        (v1.10.6)

The trust store lives at:
  - NODECHAIN_TRUST_STORE env var if set
  - data/trust_store.json (relative to project root)

Trust store integrity (v1.10.6):
  - trust_store_id: UUID generated on creation
  - updated_at: ISO 8601 timestamp of last write
  - entries_digest: SHA-256 of canonical key entries
  - Atomic writes via temp file + rename
  - Audit log records all mutations

Strict trust store mode (v1.10.5):
  --strict-trust-store rejects legacy keys (those without explicit
  allowed_purposes). Non-strict mode accepts legacy keys with all purposes
  but marks them in listing output.

  Strict mode (v1.10.6+) also refuses malformed or unverifiable stores.

Key purposes (v1.10.4):
  verifier_profile_signing  — sign/verify verifier profiles
  adapter_manifest_signing  — sign/verify adapter manifests
  audit_bundle_signing      — sign/verify audit bundles
  attestation_signing       — sign/verify attestations
  receipt_signing           — sign/verify gate and deployment receipts
  drift_policy_signing      — sign/verify drift policies (v1.14.2)
  evaluation_report_signing — sign/verify evaluation reports (v1.16.0)
  evaluation_suite_signing  — sign/verify evaluation suites (v1.16.1)
  certification_signing     — sign/verify certifications (v1.16.3)
  evidence_report_signing   — sign/verify evidence reports (v1.17.0)
  registry_publishing       — publish/verify certified registry entries (v1.18.0)
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import uuid
from pathlib import Path
from typing import Any

#: Schema version for the trust store format.
TRUST_STORE_SCHEMA_VERSION = "1"

#: Schema version for trust store snapshots (v1.10.7).
TRUST_STORE_SNAPSHOT_SCHEMA_VERSION = "1"

#: Known key purposes (v1.10.4).
VALID_PURPOSES = frozenset({
    "verifier_profile_signing",
    "adapter_manifest_signing",
    "audit_bundle_signing",
    "attestation_signing",
    "receipt_signing",
    "drift_policy_signing",  # v1.14.2
    "evaluation_report_signing",  # v1.16.0
    "evaluation_suite_signing",  # v1.16.1
    "certification_signing",  # v1.16.3
    "evidence_report_signing",  # v1.17.0
    "registry_publishing",  # v1.18.0
    "remote_registry_signing",  # v2.0.0
    "remote_package_publishing",  # v2.0.0
})

#: All purposes — used for backward compat migration.
ALL_PURPOSES = sorted(VALID_PURPOSES)

#: Sentinel value for keys with no purpose constraint (legacy).
LEGACY_NO_PURPOSE = "__all__"

#: Fields excluded from entries digest computation.
_DIGEST_EXCLUDED_META = frozenset({
    "entries_digest", "updated_at", "audit_log",
})


def _trust_store_path() -> Path:
    """Return the path to the trust store JSON file."""
    env_path = os.environ.get("NODECHAIN_TRUST_STORE", "")
    if env_path:
        return Path(env_path)
    return Path("data/trust_store.json")


def _compute_entries_digest(store: dict[str, Any]) -> str:
    """Compute SHA-256 digest of key entries (v1.10.6).

    Excludes metadata fields (entries_digest, updated_at, audit_log)
    so the digest captures only the key material.
    """
    keys_data = store.get("keys", {})
    canonical = json.dumps(keys_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _write_audit_event(
    store: dict[str, Any],
    action: str,
    key_id: str = "",
    fingerprint: str = "",
    purposes_before: list[str] | None = None,
    purposes_after: list[str] | None = None,
    actor: str = "",
) -> None:
    """Append an audit event to the trust store (v1.10.6).

    Args:
        store: Trust store dict (mutated in-place).
        action: Event action (add_key, remove_key, migrate_key, etc.).
        key_id: Key name/ID.
        fingerprint: Key fingerprint.
        purposes_before: Purposes before the change.
        purposes_after: Purposes after the change.
        actor: Actor identity if available.
    """
    event = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "action": action,
        "key_id": key_id,
        "fingerprint": fingerprint,
        "purposes_before": purposes_before or [],
        "purposes_after": purposes_after or [],
    }
    if actor:
        event["actor"] = actor

    if "audit_log" not in store:
        store["audit_log"] = []
    store["audit_log"].append(event)


def load_trust_store() -> dict[str, Any]:
    """Load the trust store, creating an empty one if it does not exist.

    Returns:
        Trust store dict with keys: schema_version, type, keys,
        trust_store_id, updated_at, entries_digest, audit_log.
    """
    path = _trust_store_path()
    if path.exists():
        store = json.loads(path.read_text(encoding="utf-8"))
        if "keys" not in store:
            store["keys"] = {}
        if "audit_log" not in store:
            store["audit_log"] = []
        return store

    return {
        "schema_version": TRUST_STORE_SCHEMA_VERSION,
        "type": "trust_store",
        "trust_store_id": str(uuid.uuid4()),
        "keys": {},
        "audit_log": [],
    }


def save_trust_store(store: dict[str, Any]) -> None:
    """Save the trust store to disk atomically (v1.10.6).

    Writes to a temp file then renames, ensuring crash consistency.
    Updates trust_store_id, updated_at, and entries_digest.
    """
    path = _trust_store_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    # Ensure integrity metadata
    if "trust_store_id" not in store:
        store["trust_store_id"] = str(uuid.uuid4())
    store["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    store["entries_digest"] = _compute_entries_digest(store)

    # Atomic write: temp file + rename
    content = json.dumps(store, indent=2, sort_keys=True)
    tmp_path = path.with_suffix(".tmp")
    tmp_path.write_text(content, encoding="utf-8")
    tmp_path.replace(path)


def add_key(
    name: str,
    public_key_path: str,
    purposes: list[str] | None = None,
) -> dict[str, Any]:
    """Add a trusted public key to the trust store.

    Args:
        name: Human-friendly name for the signer.
        public_key_path: Path to PEM public key file.
        purposes: List of allowed purposes (v1.10.4). If None or empty,
                  defaults to ALL_PURPOSES (backward compat).

    Returns:
        Dict with name, fingerprint, purposes, and status.

    Raises:
        ValueError: If any purpose is not in VALID_PURPOSES.
    """
    from nodechain.cli.bundle_signing import compute_public_key_fingerprint

    # Validate purposes
    if purposes:
        invalid = [p for p in purposes if p not in VALID_PURPOSES]
        if invalid:
            raise ValueError(
                f"Unknown purpose(s): {invalid}. "
                f"Valid: {sorted(VALID_PURPOSES)}"
            )
        allowed = sorted(set(purposes))
    else:
        allowed = list(ALL_PURPOSES)

    pem_data = Path(public_key_path).read_text(encoding="utf-8")
    fingerprint = compute_public_key_fingerprint(public_key_path)

    store = load_trust_store()

    # Check for existing key with same name
    purposes_before = None
    if name in store["keys"]:
        purposes_before = store["keys"][name].get("allowed_purposes")

    store["keys"][name] = {
        "fingerprint": fingerprint,
        "public_key_pem": pem_data,
        "added_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "allowed_purposes": allowed,
    }

    # v1.10.6: Audit log
    _write_audit_event(
        store, "add_key",
        key_id=name,
        fingerprint=fingerprint,
        purposes_before=purposes_before,
        purposes_after=allowed,
    )

    save_trust_store(store)

    return {
        "name": name,
        "fingerprint": fingerprint,
        "purposes": allowed,
        "status": "added",
    }


def remove_key(name: str) -> dict[str, str]:
    """Remove a trusted key from the trust store.

    Args:
        name: Name of the signer to remove.

    Returns:
        Dict with name and status (removed or not_found).
    """
    store = load_trust_store()
    if name in store["keys"]:
        info = store["keys"][name]
        purposes_before = info.get("allowed_purposes")
        fp = info.get("fingerprint", "")

        # v1.10.6: Audit log
        _write_audit_event(
            store, "remove_key",
            key_id=name,
            fingerprint=fp,
            purposes_before=purposes_before,
            purposes_after=[],
        )

        del store["keys"][name]
        save_trust_store(store)
        return {"name": name, "status": "removed"}
    return {"name": name, "status": "not_found"}


def list_keys() -> list[dict[str, Any]]:
    """List all trusted keys in the trust store.

    Returns:
        List of dicts with name, fingerprint, added_at, allowed_purposes,
        and is_legacy flag (v1.10.5).
    """
    store = load_trust_store()
    result = []
    for name, info in store["keys"].items():
        raw_purposes = info.get("allowed_purposes")
        legacy = raw_purposes is None
        purposes = list(raw_purposes) if raw_purposes else list(ALL_PURPOSES)
        result.append({
            "name": name,
            "fingerprint": info["fingerprint"],
            "added_at": info.get("added_at", ""),
            "allowed_purposes": purposes,
            "is_legacy": legacy,
        })
    return result


def lookup_by_fingerprint(fingerprint: str) -> str | None:
    """Look up a trusted key by its fingerprint.

    Args:
        fingerprint: SHA-256 fingerprint hex string.

    Returns:
        The PEM public key string if found, None otherwise.
    """
    store = load_trust_store()
    for name, info in store["keys"].items():
        if info["fingerprint"] == fingerprint:
            return info["public_key_pem"]
    return None


def is_legacy_key(info: dict[str, Any]) -> bool:
    """Check if a trust store key entry is a legacy key (no allowed_purposes).

    Args:
        info: Key entry dict from trust store.

    Returns:
        True if the key has no allowed_purposes field.
    """
    return info.get("allowed_purposes") is None


def is_trusted_fingerprint(
    fingerprint: str,
    purpose: str = "",
    strict: bool = False,
) -> bool:
    """Check if a fingerprint is in the trust store.

    Args:
        fingerprint: SHA-256 fingerprint hex string.
        purpose: If set, also require that the key has this purpose.
        strict: If True, reject legacy keys without explicit purposes (v1.10.5)
                and verify trust store integrity (v1.10.6).

    Returns:
        True if the fingerprint is trusted (and has purpose if checked).
    """
    # v1.10.6: Strict mode verifies trust store integrity
    if strict:
        result = verify_trust_store(strict=True)
        if not result["valid"]:
            return False

    store = load_trust_store()
    for info in store["keys"].values():
        if info["fingerprint"] == fingerprint:
            purposes = info.get("allowed_purposes")
            if purposes is None:
                # Legacy key without purposes
                if strict:
                    return False  # v1.10.5: reject in strict mode
                return True
            if not purpose:
                return True
            return purpose in purposes
    return False


def check_purpose(
    fingerprint: str,
    purpose: str,
    strict: bool = False,
) -> dict[str, Any]:
    """Check if a trusted key has a specific purpose.

    Args:
        fingerprint: SHA-256 fingerprint hex string.
        purpose: Required purpose (must be in VALID_PURPOSES).
        strict: If True, reject legacy keys without explicit purposes (v1.10.5).

    Returns:
        {allowed: bool, reason: str, purposes: list}
    """
    store = load_trust_store()
    for info in store["keys"].values():
        if info["fingerprint"] == fingerprint:
            purposes = info.get("allowed_purposes")
            if purposes is None:
                if strict:
                    return {
                        "allowed": False,
                        "reason": (
                            "Legacy key without explicit purposes rejected "
                            "in strict trust store mode. Run: "
                            "nodechain trust-store migrate"
                        ),
                        "purposes": [],
                    }
                return {
                    "allowed": True,
                    "reason": "Legacy key (no purpose constraint)",
                    "purposes": list(ALL_PURPOSES),
                }
            if purpose in purposes:
                return {
                    "allowed": True,
                    "reason": f"Key has purpose: {purpose}",
                    "purposes": purposes,
                }
            return {
                "allowed": False,
                "reason": (
                    f"Key lacks required purpose '{purpose}'. "
                    f"Allowed: {purposes}"
                ),
                "purposes": purposes,
            }
    return {
        "allowed": False,
        "reason": f"Fingerprint {fingerprint} not in trust store",
        "purposes": [],
    }


def migrate_legacy_keys(
    purposes: list[str] | None = None,
) -> dict[str, Any]:
    """Migrate legacy keys by adding explicit allowed_purposes (v1.10.5).

    Args:
        purposes: Purposes to assign. If None, uses ALL_PURPOSES.

    Returns:
        {migrated: int, names: list, purposes: list}
    """
    if purposes:
        invalid = [p for p in purposes if p not in VALID_PURPOSES]
        if invalid:
            raise ValueError(
                f"Unknown purpose(s): {invalid}. Valid: {sorted(VALID_PURPOSES)}"
            )
        assign = sorted(set(purposes))
    else:
        assign = list(ALL_PURPOSES)

    store = load_trust_store()
    migrated_names = []
    for name, info in store["keys"].items():
        if info.get("allowed_purposes") is None:
            # v1.10.6: Audit log
            _write_audit_event(
                store, "migrate_key",
                key_id=name,
                fingerprint=info.get("fingerprint", ""),
                purposes_before=None,
                purposes_after=assign,
            )
            info["allowed_purposes"] = assign
            migrated_names.append(name)

    if migrated_names:
        save_trust_store(store)

    return {
        "migrated": len(migrated_names),
        "names": migrated_names,
        "purposes": assign,
    }


# ── Trust Store Verification (v1.10.6) ─────────────────────────────────────


def verify_trust_store(strict: bool = False) -> dict[str, Any]:
    """Validate trust store integrity (v1.10.6).

    Checks:
      1. Schema version present and valid
      2. No duplicate key names
      3. No duplicate fingerprints
      4. All purposes are valid
      5. PEM keys are parseable
      6. entries_digest matches content

    Args:
        strict: If True, any issue is an error. If False, warnings only.

    Returns:
        {valid: bool, errors: list, warnings: list, checks: dict}
    """
    from cryptography.hazmat.primitives import serialization

    errors: list[str] = []
    warnings: list[str] = []
    checks: dict[str, bool] = {}

    path = _trust_store_path()
    if not path.exists():
        return {
            "valid": False,
            "errors": ["Trust store file does not exist"],
            "warnings": [],
            "checks": {"file_exists": False},
        }

    try:
        store = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return {
            "valid": False,
            "errors": [f"Malformed JSON: {exc}"],
            "warnings": [],
            "checks": {"valid_json": False},
        }

    # Check 1: Schema version
    sv = store.get("schema_version", "")
    checks["schema_version"] = sv == TRUST_STORE_SCHEMA_VERSION
    if not checks["schema_version"]:
        msg = f"Invalid schema_version: {sv!r} (expected {TRUST_STORE_SCHEMA_VERSION!r})"
        errors.append(msg) if strict else warnings.append(msg)

    # Check 2: No duplicate key names (JSON keys are inherently unique, but check)
    keys = store.get("keys", {})
    checks["no_duplicate_keys"] = True  # JSON object keys are unique by definition

    # Check 3: No duplicate fingerprints
    fingerprints = [info.get("fingerprint", "") for info in keys.values()]
    seen_fps = set()
    dup_fps = []
    for fp in fingerprints:
        if fp in seen_fps:
            dup_fps.append(fp)
        seen_fps.add(fp)
    checks["no_duplicate_fingerprints"] = len(dup_fps) == 0
    if dup_fps:
        errors.append(f"Duplicate fingerprints: {dup_fps}")

    # Check 4: All purposes valid
    invalid_purpose_entries = []
    for name, info in keys.items():
        purposes = info.get("allowed_purposes")
        if purposes is None:
            continue  # Legacy key, skip
        for p in purposes:
            if p not in VALID_PURPOSES:
                invalid_purpose_entries.append(f"{name}: {p}")
    checks["valid_purposes"] = len(invalid_purpose_entries) == 0
    if invalid_purpose_entries:
        errors.append(f"Invalid purposes: {invalid_purpose_entries}")

    # Check 5: PEM keys parseable
    malformed_pem = []
    for name, info in keys.items():
        pem = info.get("public_key_pem", "")
        if not pem:
            malformed_pem.append(f"{name}: empty PEM")
            continue
        try:
            serialization.load_pem_public_key(pem.encode("utf-8"))
        except Exception:
            malformed_pem.append(f"{name}: malformed PEM")
    checks["valid_pem"] = len(malformed_pem) == 0
    if malformed_pem:
        errors.append(f"Malformed PEM keys: {malformed_pem}")

    # Check 6: entries_digest matches
    stored_digest = store.get("entries_digest", "")
    if stored_digest:
        computed = _compute_entries_digest(store)
        checks["entries_digest"] = stored_digest == computed
        if stored_digest != computed:
            errors.append(
                f"entries_digest mismatch: stored={stored_digest[:16]}... "
                f"computed={computed[:16]}..."
            )
    else:
        checks["entries_digest"] = False
        msg = "entries_digest missing (pre-v1.10.6 trust store)"
        errors.append(msg) if strict else warnings.append(msg)

    valid = len(errors) == 0
    return {
        "valid": valid,
        "errors": errors,
        "warnings": warnings,
        "checks": checks,
    }


# ── Trust Store Snapshots (v1.10.7) ───────────────────────────────────────


#: Fields excluded from snapshot digest computation.
_SNAP_SIG_FIELDS = frozenset({
    "snapshot_signature", "snapshot_signature_algorithm",
    "snapshot_signer_fingerprint", "snapshot_digest",
})


def _compute_audit_log_digest(store: dict[str, Any]) -> str:
    """Compute SHA-256 digest of the audit log (v1.10.7)."""
    audit_log = store.get("audit_log", [])
    canonical = json.dumps(audit_log, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _canonicalize_snapshot(snap: dict[str, Any]) -> bytes:
    """Create canonical bytes of snapshot content for signing."""
    stripped = {k: v for k, v in snap.items()
                if k not in _SNAP_SIG_FIELDS}
    return json.dumps(stripped, sort_keys=True, separators=(",", ":")).encode("utf-8")


def create_trust_store_snapshot(
    output_path: str = "",
    private_key_path: str = "",
) -> dict[str, Any]:
    """Create a snapshot of the current trust store state (v1.10.7).

    Args:
        output_path: Path to write snapshot JSON. If empty, returns without writing.
        private_key_path: Path to PEM private key for signing the snapshot.

    Returns:
        Snapshot dict with metadata, digests, and optional signature.
    """
    store = load_trust_store()
    keys = store.get("keys", {})

    # Build purposes summary
    purposes_summary: dict[str, int] = {}
    for info in keys.values():
        purposes = info.get("allowed_purposes")
        if purposes is None:
            purposes_summary["__legacy__"] = purposes_summary.get("__legacy__", 0) + 1
        else:
            for p in purposes:
                purposes_summary[p] = purposes_summary.get(p, 0) + 1

    snapshot: dict[str, Any] = {
        "schema_version": TRUST_STORE_SNAPSHOT_SCHEMA_VERSION,
        "type": "trust_store_snapshot",
        "trust_store_id": store.get("trust_store_id", ""),
        "entries_digest": store.get("entries_digest", _compute_entries_digest(store)),
        "audit_log_digest": _compute_audit_log_digest(store),
        "key_count": len(keys),
        "purposes_summary": dict(sorted(purposes_summary.items())),
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }

    # Compute snapshot digest
    snapshot["snapshot_digest"] = hashlib.sha256(
        _canonicalize_snapshot(snapshot)
    ).hexdigest()

    # Sign if requested
    if private_key_path:
        snapshot = _sign_snapshot(snapshot, private_key_path)

    if output_path:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(snapshot, indent=2, sort_keys=True), encoding="utf-8")

    return snapshot


def _sign_snapshot(snapshot: dict[str, Any], private_key_path: str) -> dict[str, Any]:
    """Sign a trust store snapshot with RSA-PSS-SHA256 (v1.10.7)."""
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


def verify_trust_store_snapshot(
    snapshot_path: str = "",
    snapshot_dict: dict[str, Any] | None = None,
    public_key_pem: str = "",
    check_live_store: bool = False,
) -> dict[str, Any]:
    """Verify a trust store snapshot (v1.10.7).

    Args:
        snapshot_path: Path to snapshot JSON file.
        snapshot_dict: Snapshot dict (alternative to path).
        public_key_pem: PEM public key for signature verification.
        check_live_store: If True, compare snapshot against current trust store.

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
    details["schema_version"] = sv == TRUST_STORE_SNAPSHOT_SCHEMA_VERSION
    if sv != TRUST_STORE_SNAPSHOT_SCHEMA_VERSION:
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

    # Check 3: Signature (if present)
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

    # Check 4: Compare against live store if requested
    if check_live_store:
        store = load_trust_store()
        live_entries = store.get("entries_digest", _compute_entries_digest(store))
        snap_entries = snapshot_dict.get("entries_digest", "")
        details["live_store_matches"] = live_entries == snap_entries
        if live_entries != snap_entries:
            errors.append(
                "Snapshot does not match live trust store (entries changed since snapshot)"
            )
        details["trust_store_id_matches"] = (
            store.get("trust_store_id", "") == snapshot_dict.get("trust_store_id", "")
        )

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "details": details,
    }


# ── Profile signing ────────────────────────────────────────────────────────


def _canonicalize_profile(profile: dict[str, Any]) -> bytes:
    """Create canonical bytes of profile content for signing.

    Signs everything EXCEPT signature fields and computed digest.
    """
    stripped = {k: v for k, v in profile.items()
                if k not in ("profile_signature", "profile_signature_algorithm",
                             "profile_signer_fingerprint", "profile_digest")}
    return json.dumps(stripped, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_profile(
    profile: dict[str, Any],
    private_key_path: str,
) -> dict[str, Any]:
    """Sign a verifier profile and return enriched profile with signature.

    Args:
        profile: The verifier profile dict.
        private_key_path: Path to PEM private key.

    Returns:
        Profile with added signature fields:
          profile_signature: base64-encoded RSA-PSS signature
          profile_signature_algorithm: "RSA-PSS-SHA256"
          profile_signer_fingerprint: SHA-256 fingerprint of signer's public key
    """
    import base64
    from nodechain.cli.bundle_signing import _load_private_key
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes, serialization

    private_key = _load_private_key(private_key_path)
    signed_data = _canonicalize_profile(profile)

    signature = private_key.sign(
        signed_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=hashes.SHA256().digest_size,
        ),
        hashes.SHA256(),
    )

    # Compute fingerprint from the public key derived from the private key
    public_key = private_key.public_key()
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = hashlib.sha256(public_der).hexdigest()[:32]

    enriched = dict(profile)
    enriched["profile_signature"] = base64.b64encode(signature).decode("ascii")
    enriched["profile_signature_algorithm"] = "RSA-PSS-SHA256"
    enriched["profile_signer_fingerprint"] = fingerprint

    return enriched


def verify_profile_signature(
    profile: dict[str, Any],
    public_key_pem: str,
) -> dict[str, Any]:
    """Verify a signed verifier profile.

    Args:
        profile: The signed verifier profile dict.
        public_key_pem: PEM-encoded public key string.

    Returns:
        {valid: bool, reason: str, fingerprint: str}
    """
    import base64
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes, serialization

    signature_b64 = profile.get("profile_signature", "")
    if not signature_b64:
        return {
            "valid": False,
            "reason": "No signature in profile",
            "fingerprint": "",
        }

    algorithm = profile.get("profile_signature_algorithm", "")
    if algorithm != "RSA-PSS-SHA256":
        return {
            "valid": False,
            "reason": f"Unsupported algorithm: {algorithm}",
            "fingerprint": profile.get("profile_signer_fingerprint", ""),
        }

    signature = base64.b64decode(signature_b64)

    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    except Exception as exc:
        return {
            "valid": False,
            "reason": f"Cannot load public key: {exc}",
            "fingerprint": profile.get("profile_signer_fingerprint", ""),
        }

    signed_data = _canonicalize_profile(profile)

    try:
        public_key.verify(
            signature,
            signed_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=hashes.SHA256().digest_size,
            ),
            hashes.SHA256(),
        )
    except Exception as exc:
        return {
            "valid": False,
            "reason": f"Signature verification failed: {exc}",
            "fingerprint": profile.get("profile_signer_fingerprint", ""),
        }

    return {
        "valid": True,
        "reason": "Profile signature valid",
        "fingerprint": profile.get("profile_signer_fingerprint", ""),
    }
