"""Evaluation Suite Registry (v1.16.2).

Local registry for evaluation suites, providing:
  - register: Add a suite to the registry
  - list: List all registered suites
  - revoke: Revoke a suite by digest
  - verify: Verify a suite is in the registry and active

The registry is stored at data/eval_suite_registry.json by default,
overridable via NODECHAIN_EVAL_SUITE_REGISTRY env var.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_dict(data: dict[str, Any]) -> str:
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _get_registry_path() -> str:
    return os.environ.get(
        "NODECHAIN_EVAL_SUITE_REGISTRY",
        str(Path("data") / "eval_suite_registry.json"),
    )


def load_registry() -> dict[str, Any]:
    """Load the suite registry from disk."""
    path = _get_registry_path()
    p = Path(path)
    if not p.exists():
        return {
            "schema_version": "1.0",
            "entries": {},
            "audit_log": [],
        }
    data = json.loads(p.read_text(encoding="utf-8"))
    data.setdefault("entries", {})
    data.setdefault("audit_log", [])
    data.setdefault("schema_version", "1.0")
    return data


def save_registry(registry: dict[str, Any]) -> None:
    """Save the suite registry to disk atomically."""
    path = _get_registry_path()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    tmp = str(Path(path).with_suffix(".tmp"))
    Path(tmp).write_text(json.dumps(registry, indent=2, sort_keys=True), encoding="utf-8")
    Path(tmp).replace(path)


def registry_digest(registry: dict[str, Any] | None = None) -> str:
    """Compute digest of the current registry state."""
    if registry is None:
        registry = load_registry()
    return _sha256_dict({
        "entries": registry.get("entries", {}),
        "schema_version": registry.get("schema_version", "1.0"),
    })


def register_suite(
    suite_path: str = "",
    suite_dict: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Register an evaluation suite in the local registry.

    Args:
        suite_path: Path to the suite file (JSON or YAML).
        suite_dict: Already-parsed suite dict (alternative to suite_path).

    Returns:
        The registered entry.
    """
    if suite_dict is None:
        raw = Path(suite_path).read_text(encoding="utf-8")
        try:
            suite_dict = json.loads(raw)
        except json.JSONDecodeError:
            import yaml
            suite_dict = yaml.safe_load(raw)

    suite_id = suite_dict.get("suite_id", "")
    suite_version = suite_dict.get("suite_version", "1.0.0")
    suite_status = suite_dict.get("suite_status", "active")

    # Compute digest of suite content (excluding signature fields)
    content = {k: v for k, v in suite_dict.items()
               if k not in {"suite_signature", "suite_signature_algorithm",
                            "suite_signer_fingerprint", "type"}}
    digest = _sha256_dict(content)

    registry = load_registry()
    entries = registry["entries"]

    # Check for existing
    if digest in entries:
        return entries[digest]

    entry = {
        "suite_id": suite_id,
        "suite_version": suite_version,
        "suite_digest": digest,
        "suite_status": suite_status,
        "valid_from": suite_dict.get("valid_from", ""),
        "valid_until": suite_dict.get("valid_until", ""),
        "supersedes_suite_digest": suite_dict.get("supersedes_suite_digest", ""),
        "registered_at": _now_iso(),
        "source_path": suite_path,
    }

    entries[digest] = entry

    # Audit log
    registry["audit_log"].append({
        "action": "register",
        "suite_digest": digest,
        "suite_id": suite_id,
        "timestamp": _now_iso(),
    })

    save_registry(registry)
    return entry


def list_suites(
    active_only: bool = False,
) -> list[dict[str, Any]]:
    """List all registered suites."""
    registry = load_registry()
    entries = list(registry["entries"].values())
    if active_only:
        entries = [e for e in entries if e.get("suite_status") == "active"]
    entries.sort(key=lambda e: e.get("registered_at", ""), reverse=True)
    return entries


def revoke_suite(
    suite_digest: str,
    reason: str = "",
) -> dict[str, Any]:
    """Revoke a registered suite by digest."""
    registry = load_registry()
    entries = registry["entries"]

    if suite_digest not in entries:
        raise KeyError(f"Suite {suite_digest[:16]}... not found in registry")

    entry = entries[suite_digest]
    entry["suite_status"] = "revoked"
    entry["revoked_at"] = _now_iso()
    entry["revoke_reason"] = reason

    registry["audit_log"].append({
        "action": "revoke",
        "suite_digest": suite_digest,
        "suite_id": entry.get("suite_id", ""),
        "reason": reason,
        "timestamp": _now_iso(),
    })

    save_registry(registry)
    return entry


def verify_suite_in_registry(
    suite_digest: str,
    require_active: bool = True,
) -> dict[str, Any]:
    """Verify that a suite is in the registry and optionally active.

    Returns:
        {valid, errors, details}
    """
    registry = load_registry()
    entries = registry["entries"]

    errors: list[str] = []
    details: dict[str, Any] = {
        "in_registry": False,
        "suite_status": "",
        "suite_id": "",
        "suite_version": "",
    }

    if suite_digest not in entries:
        errors.append(f"Suite {suite_digest[:16]}... not found in registry")
        return {"valid": False, "errors": errors, "details": details}

    entry = entries[suite_digest]
    details["in_registry"] = True
    details["suite_status"] = entry.get("suite_status", "")
    details["suite_id"] = entry.get("suite_id", "")
    details["suite_version"] = entry.get("suite_version", "")

    if require_active and entry.get("suite_status") != "active":
        errors.append(f"Suite is {entry.get('suite_status')}, not active")

    # Check validity window
    now = _now_iso()
    valid_from = entry.get("valid_from", "")
    valid_until = entry.get("valid_until", "")
    if valid_from and now < valid_from:
        errors.append(f"Suite not yet valid (valid_from={valid_from})")
    if valid_until and now > valid_until:
        errors.append(f"Suite expired (valid_until={valid_until})")

    return {"valid": len(errors) == 0, "errors": errors, "details": details}
