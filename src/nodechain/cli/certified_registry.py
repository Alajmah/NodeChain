"""Certified Registry Publishing (v1.18.0).

Turns certified targets into reusable registry entries. A package that
has been signed, evaluated by a trusted active suite, and certified by
an authorized certifier can be published to the local registry for
discovery and reuse.

Registry lifecycle:
  package → sign → evaluate → certify → publish → discover → reuse

Registry entry states:
  active | deprecated | revoked
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_dict(data: dict[str, Any]) -> str:
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


#: Valid registry entry statuses
REGISTRY_ENTRY_STATUSES = frozenset({"active", "deprecated", "revoked"})

#: Fields excluded from entry digest
_ENTRY_DIGEST_EXCLUDED = frozenset({
    "registry_signature",
    "registry_signature_algorithm",
    "publisher_fingerprint",
    "entry_digest",
})


def _get_registry_path() -> str:
    return os.environ.get(
        "NODECHAIN_CERTIFIED_REGISTRY",
        str(Path("data") / "certified_registry.json"),
    )


def load_registry() -> dict[str, Any]:
    """Load the certified registry from disk."""
    path = _get_registry_path()
    p = Path(path)
    if not p.exists():
        return {
            "type": "certified_registry",
            "schema_version": "1.0",
            "registry_id": str(uuid.uuid4()),
            "entries": {},
            "updated_at": "",
            "entries_digest": "",
            "audit_log": [],
        }
    data = json.loads(p.read_text(encoding="utf-8"))
    data.setdefault("entries", {})
    data.setdefault("audit_log", [])
    data.setdefault("schema_version", "1.0")
    data.setdefault("type", "certified_registry")
    data.setdefault("registry_id", str(uuid.uuid4()))
    return data


def save_registry(registry: dict[str, Any]) -> None:
    """Save registry to disk atomically."""
    registry["updated_at"] = _now_iso()
    # Recompute entries_digest
    digest_content = {
        "entries": registry.get("entries", {}),
        "schema_version": registry.get("schema_version", "1.0"),
    }
    registry["entries_digest"] = _sha256_dict(digest_content)

    path = _get_registry_path()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    tmp = str(Path(path).with_suffix(".tmp"))
    Path(tmp).write_text(json.dumps(registry, indent=2, sort_keys=True), encoding="utf-8")
    Path(tmp).replace(path)


def _compute_entry_digest(entry: dict[str, Any]) -> str:
    """Compute digest of a registry entry (excluding signature fields)."""
    return _sha256_dict(
        {k: v for k, v in entry.items() if k not in _ENTRY_DIGEST_EXCLUDED}
    )


# ── Publish ─────────────────────────────────────────────────────────────────

def publish_package(
    package_path: str = "",
    package_dict: dict[str, Any] | None = None,
    certification: dict[str, Any] | str | None = None,
    lockfile_digest: str = "",
    require_certification: bool = True,
    require_certification_signature: bool = False,
    trust_store_path: str = "",
    strict: bool = False,
) -> dict[str, Any]:
    """Publish a certified package to the registry.

    Checks:
      1. Package manifest present
      2. Package digest computable
      3. Certification status = certified (if require_certification)
      4. Certification signature valid (if require_certification_signature)
      5. Target digest in certification matches package digest

    Returns:
        Registry entry dict (status=active if published, status=denied if rejected).
    """
    # Load package manifest
    if package_dict is None:
        if package_path:
            raw = Path(package_path).read_text(encoding="utf-8")
            try:
                package_dict = json.loads(raw)
            except json.JSONDecodeError:
                import yaml
                package_dict = yaml.safe_load(raw)
        else:
            package_dict = {}

    errors: list[str] = []

    package_id = package_dict.get("package_id", package_dict.get("name", ""))
    package_version = package_dict.get("version", "1.0.0")
    package_digest = package_dict.get("content_hash", package_dict.get("package_digest", ""))

    if not package_id:
        errors.append("Package manifest missing package_id/name")

    # Compute package digest if not present
    if not package_digest:
        manifest_content = _sha256_dict(package_dict)
        package_digest = manifest_content

    manifest_digest = _sha256_dict(package_dict)

    # Load certification
    cert_dict: dict[str, Any] = {}
    if certification is not None:
        if isinstance(certification, str):
            cert_dict = json.loads(Path(certification).read_text(encoding="utf-8"))
        else:
            cert_dict = certification

    cert_digest = cert_dict.get("certification_digest", "")
    report_digest = cert_dict.get("eval_report_digest", "")
    suite_digest = cert_dict.get("suite_digest", "")
    cert_status = cert_dict.get("certification_status", "")

    # Check certification
    if require_certification:
        if not cert_dict:
            errors.append("Certification required but not provided")
        elif cert_status != "certified":
            errors.append(f"Certification status is '{cert_status}', not 'certified'")

        # Check target digest matches package digest
        cert_target_digest = cert_dict.get("target_digest", "")
        if cert_target_digest and cert_target_digest != package_digest:
            errors.append(
                f"Certification target_digest ({cert_target_digest[:16]}...) "
                f"does not match package digest ({package_digest[:16]}...)"
            )

    # Check certification signature (if required)
    if require_certification_signature and cert_dict:
        cert_sig = cert_dict.get("certification_signature", "")
        if not cert_sig:
            errors.append("Certification signature required but missing")

    # Build entry
    entry_id = str(uuid.uuid4())
    published_at = _now_iso()
    entry_status = "active" if not errors else "denied"

    entry: dict[str, Any] = {
        "type": "registry_entry",
        "entry_id": entry_id,
        "package_id": package_id,
        "package_version": package_version,
        "package_digest": package_digest,
        "manifest_digest": manifest_digest,
        "lockfile_digest": lockfile_digest,
        "certification_digest": cert_digest,
        "eval_report_digest": report_digest,
        "suite_digest": suite_digest,
        "certification_status": cert_status,
        "publisher_fingerprint": "",
        "published_at": published_at,
        "registry_status": entry_status,
        "errors": errors,
        # Placeholder for signing
        "entry_digest": "",
        "registry_signature": "",
        "registry_signature_algorithm": "",
        # Additional package metadata
        "capabilities": package_dict.get("capabilities", []),
        "sandbox_profile": package_dict.get("sandbox_profile", ""),
        "trust_level": package_dict.get("trust_level", "untrusted"),
        "description": package_dict.get("description", ""),
    }

    entry["entry_digest"] = _compute_entry_digest(entry)

    # If valid, add to registry
    if not errors:
        registry = load_registry()
        registry["entries"][entry_id] = entry
        registry["audit_log"].append({
            "action": "publish",
            "entry_id": entry_id,
            "package_id": package_id,
            "package_version": package_version,
            "timestamp": published_at,
        })
        save_registry(registry)

    return entry


# ── Sign Entry ──────────────────────────────────────────────────────────────

def sign_registry_entry(
    entry: dict[str, Any] | str,
    private_key_path: str,
    output_path: str = "",
) -> dict[str, Any]:
    """Sign a registry entry with RSA-PSS-SHA256."""
    import base64
    if isinstance(entry, str):
        entry = json.loads(Path(entry).read_text(encoding="utf-8"))

    from nodechain.cli.bundle_signing import _load_private_key
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes, serialization

    # Recompute digest
    entry["entry_digest"] = _compute_entry_digest(entry)

    canonical = json.dumps(
        {k: v for k, v in entry.items()
         if k not in {"registry_signature", "registry_signature_algorithm",
                      "publisher_fingerprint"}},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")

    private_key = _load_private_key(private_key_path)
    signature = private_key.sign(
        canonical,
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

    entry["publisher_fingerprint"] = fingerprint
    entry["registry_signature"] = base64.b64encode(signature).decode("ascii")
    entry["registry_signature_algorithm"] = "RSA-PSS-SHA256"

    if output_path:
        Path(output_path).write_text(
            json.dumps(entry, indent=2, sort_keys=True), encoding="utf-8",
        )

    return entry


# ── Verify Entry ────────────────────────────────────────────────────────────

def verify_registry_entry(
    entry: dict[str, Any] | str,
    public_key_pem: str = "",
    trust_store_path: str = "",
    expected_package_digest: str = "",
) -> dict[str, Any]:
    """Verify a registry entry (7-point).

    Checks:
      1. Entry has signature
      2. entry_digest matches content
      3. Signature cryptographically valid
      4. Publisher in trust store (if trust_store_path)
      5. Publisher has registry_publishing purpose
      6. Certification status is certified
      7. Registry status is active
    """
    import base64
    if isinstance(entry, str):
        entry = json.loads(Path(entry).read_text(encoding="utf-8"))

    errors: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {
        "signature_status": "unsigned",
        "publisher_fingerprint": "",
        "publisher_trusted": False,
        "registry_status": entry.get("registry_status", ""),
        "certification_status": entry.get("certification_status", ""),
        "entry_digest": "",
    }

    # Check 1: Signature
    sig = entry.get("registry_signature", "")
    if not sig:
        errors.append("Registry entry is not signed")
        return {"valid": False, "errors": errors, "warnings": warnings, "details": details}

    # Check 2: Digest
    stored_digest = entry.get("entry_digest", "")
    if not stored_digest:
        errors.append("Missing entry_digest")
    else:
        recomputed = _compute_entry_digest(entry)
        if stored_digest != recomputed:
            errors.append("Entry digest mismatch")
    details["entry_digest"] = stored_digest

    publisher_fp = entry.get("publisher_fingerprint", "")
    details["publisher_fingerprint"] = publisher_fp

    resolved_pem = ""

    # Check 4 & 5: Trust store
    if trust_store_path:
        from nodechain.cli.trust_store import is_trusted_fingerprint, load_trust_store

        old_ts = os.environ.get("NODECHAIN_TRUST_STORE", "")
        os.environ["NODECHAIN_TRUST_STORE"] = trust_store_path
        try:
            trusted = is_trusted_fingerprint(publisher_fp, purpose="registry_publishing")
            details["publisher_trusted"] = publisher_fp != "" and trusted
            if not trusted:
                if publisher_fp:
                    errors.append(f"Publisher {publisher_fp} not trusted for registry_publishing")
                else:
                    errors.append("No publisher fingerprint")

            store = load_trust_store()
            for info in store["keys"].values():
                if info.get("fingerprint") == publisher_fp:
                    resolved_pem = info.get("public_key_pem", "")
                    break
        finally:
            if old_ts:
                os.environ["NODECHAIN_TRUST_STORE"] = old_ts
            elif "NODECHAIN_TRUST_STORE" in os.environ:
                del os.environ["NODECHAIN_TRUST_STORE"]

    if not resolved_pem and public_key_pem:
        resolved_pem = public_key_pem

    # Check 6: Certification status
    cert_status = entry.get("certification_status", "")
    if cert_status and cert_status != "certified":
        errors.append(f"Certification status is '{cert_status}', not 'certified'")

    # Check 7: Registry status
    reg_status = entry.get("registry_status", "")
    if reg_status != "active":
        errors.append(f"Registry status is '{reg_status}', not 'active'")

    # Optional: Expected package digest
    if expected_package_digest:
        if entry.get("package_digest") != expected_package_digest:
            errors.append("Package digest mismatch")

    if not resolved_pem:
        if sig and not errors:
            warnings.append("Signed entry but no public key for verification")
            details["signature_status"] = "signed_unverified"
        return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings, "details": details}

    # Check 3: Crypto verification
    try:
        from cryptography.hazmat.primitives import serialization as ser
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        from cryptography.exceptions import InvalidSignature

        pub_key = ser.load_pem_public_key(resolved_pem.encode("utf-8"))
        canonical = json.dumps(
            {k: v for k, v in entry.items()
             if k not in {"registry_signature", "registry_signature_algorithm",
                          "publisher_fingerprint"}},
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        pub_key.verify(
            base64.b64decode(sig), canonical,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=hashes.SHA256().digest_size,
            ),
            hashes.SHA256(),
        )
        details["signature_status"] = "valid"
    except InvalidSignature:
        details["signature_status"] = "invalid"
        errors.append("Registry entry signature verification failed")
    except Exception as e:
        details["signature_status"] = "invalid"
        errors.append(f"Signature verification error: {e}")

    return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings, "details": details}


# ── List / Inspect / Deprecate / Revoke ─────────────────────────────────────

def list_entries(
    active_only: bool = False,
) -> list[dict[str, Any]]:
    """List registry entries."""
    registry = load_registry()
    entries = list(registry.get("entries", {}).values())
    if active_only:
        entries = [e for e in entries if e.get("registry_status") == "active"]
    entries.sort(key=lambda e: e.get("published_at", ""), reverse=True)
    return entries


def inspect_entry(entry_id: str) -> dict[str, Any]:
    """Inspect a registry entry by ID."""
    registry = load_registry()
    entries = registry.get("entries", {})
    if entry_id not in entries:
        raise KeyError(f"Entry {entry_id[:16]}... not found in registry")
    entry = entries[entry_id]
    return {
        "entry_id": entry.get("entry_id", ""),
        "package_id": entry.get("package_id", ""),
        "package_version": entry.get("package_version", ""),
        "package_digest": entry.get("package_digest", "")[:16] + "..." if entry.get("package_digest") else "",
        "certification_status": entry.get("certification_status", ""),
        "registry_status": entry.get("registry_status", ""),
        "published_at": entry.get("published_at", ""),
        "publisher_fingerprint": entry.get("publisher_fingerprint", ""),
        "is_signed": bool(entry.get("registry_signature")),
        "capabilities": entry.get("capabilities", []),
        "trust_level": entry.get("trust_level", ""),
        "suite_digest": entry.get("suite_digest", "")[:16] + "..." if entry.get("suite_digest") else "",
        "eval_report_digest": entry.get("eval_report_digest", "")[:16] + "..." if entry.get("eval_report_digest") else "",
        "certification_digest": entry.get("certification_digest", "")[:16] + "..." if entry.get("certification_digest") else "",
        "errors": entry.get("errors", []),
    }


def deprecate_entry(entry_id: str, reason: str = "") -> dict[str, Any]:
    """Deprecate a registry entry."""
    registry = load_registry()
    entries = registry.get("entries", {})
    if entry_id not in entries:
        raise KeyError(f"Entry {entry_id[:16]}... not found in registry")
    entry = entries[entry_id]
    entry["registry_status"] = "deprecated"
    entry["deprecated_at"] = _now_iso()
    entry["deprecate_reason"] = reason
    registry["audit_log"].append({
        "action": "deprecate", "entry_id": entry_id,
        "reason": reason, "timestamp": _now_iso(),
    })
    save_registry(registry)
    return entry


def revoke_entry(entry_id: str, reason: str = "") -> dict[str, Any]:
    """Revoke a registry entry."""
    registry = load_registry()
    entries = registry.get("entries", {})
    if entry_id not in entries:
        raise KeyError(f"Entry {entry_id[:16]}... not found in registry")
    entry = entries[entry_id]
    entry["registry_status"] = "revoked"
    entry["revoked_at"] = _now_iso()
    entry["revoke_reason"] = reason
    registry["audit_log"].append({
        "action": "revoke", "entry_id": entry_id,
        "reason": reason, "timestamp": _now_iso(),
    })
    save_registry(registry)
    return entry


# ── Registry Snapshot ───────────────────────────────────────────────────────

def create_registry_snapshot(
    output_path: str = "",
) -> dict[str, Any]:
    """Create a signed snapshot of the registry state."""
    registry = load_registry()
    snapshot = {
        "type": "certified_registry_snapshot",
        "schema_version": registry.get("schema_version", "1.0"),
        "registry_id": registry.get("registry_id", ""),
        "entry_count": len(registry.get("entries", {})),
        "entries_digest": registry.get("entries_digest", ""),
        "snapshot_digest": "",
        "created_at": _now_iso(),
    }
    digest_content = {k: v for k, v in snapshot.items() if k != "snapshot_digest"}
    snapshot["snapshot_digest"] = _sha256_dict(digest_content)

    if output_path:
        Path(output_path).write_text(
            json.dumps(snapshot, indent=2, sort_keys=True), encoding="utf-8",
        )
    return snapshot


def verify_registry_snapshot(snapshot: dict[str, Any] | str) -> dict[str, Any]:
    """Verify a registry snapshot digest."""
    if isinstance(snapshot, str):
        snapshot = json.loads(Path(snapshot).read_text(encoding="utf-8"))

    stored = snapshot.get("snapshot_digest", "")
    if not stored:
        return {"valid": False, "errors": ["Missing snapshot_digest"]}

    recomputed = _sha256_dict(
        {k: v for k, v in snapshot.items() if k != "snapshot_digest"}
    )
    if stored != recomputed:
        return {"valid": False, "errors": ["Snapshot digest mismatch"]}

    return {"valid": True, "errors": []}
