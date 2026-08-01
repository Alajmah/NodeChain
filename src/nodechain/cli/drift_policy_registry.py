"""Drift Policy Registry (v1.14.3).

A local registry for drift policies with lifecycle tracking. Supports
registration, listing, revocation, and verification of drift policies.

The registry is stored at data/drift_policy_registry.json (or $NODECHAIN_DRIFT_POLICY_REGISTRY).
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REGISTRY_SCHEMA_VERSION = "1.0"


def _registry_path() -> Path:
    """Return the path to the drift policy registry."""
    env_path = os.environ.get("NODECHAIN_DRIFT_POLICY_REGISTRY", "")
    if env_path:
        return Path(env_path)
    return Path("data/drift_policy_registry.json")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_dict(data: dict[str, Any]) -> str:
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def load_registry() -> dict[str, Any]:
    """Load the policy registry, creating an empty one if needed."""
    path = _registry_path()
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {
        "schema_version": REGISTRY_SCHEMA_VERSION,
        "type": "drift_policy_registry",
        "registry_id": f"dpr-{hashlib.sha256(str(path).encode()).hexdigest()[:8]}",
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
        "entries_digest": "",
        "policies": {},
    }


def save_registry(registry: dict[str, Any]) -> None:
    """Save the policy registry with atomic write."""
    registry["updated_at"] = _now_iso()
    registry["entries_digest"] = _compute_entries_digest(registry)
    path = _registry_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(registry, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def _compute_entries_digest(registry: dict[str, Any]) -> str:
    """Compute SHA-256 digest of registry entries."""
    policies = registry.get("policies", {})
    canonical = json.dumps(policies, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def register_policy(
    policy_path: str = "",
    policy_dict: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Register a drift policy in the local registry.

    Args:
        policy_path: Path to signed drift policy JSON.
        policy_dict: Policy dict (alternative to path).

    Returns:
        {policy_id, policy_version, policy_digest, status, registered_at}
    """
    if policy_dict is None:
        policy_dict = json.loads(Path(policy_path).read_text(encoding="utf-8"))

    policy_id = policy_dict.get("policy_id", "")
    if not policy_id:
        policy_id = f"policy-{hashlib.sha256(json.dumps(policy_dict, sort_keys=True).encode()).hexdigest()[:8]}"
        policy_dict["policy_id"] = policy_id

    policy_version = policy_dict.get("policy_version", "1.0")
    policy_digest = policy_dict.get("policy_digest", _sha256_dict(
        {k: v for k, v in policy_dict.items()
         if k not in {"policy_signature", "policy_signature_algorithm",
                      "policy_signer_fingerprint", "type"}}
    ))
    policy_status = policy_dict.get("policy_status", "active")

    registry = load_registry()
    registry["policies"][policy_id] = {
        "policy_id": policy_id,
        "policy_version": policy_version,
        "policy_digest": policy_digest,
        "policy_status": policy_status,
        "registered_at": _now_iso(),
        "valid_from": policy_dict.get("valid_from", ""),
        "valid_until": policy_dict.get("valid_until", ""),
        "supersedes_policy_digest": policy_dict.get("supersedes_policy_digest", ""),
        "signer_fingerprint": policy_dict.get("policy_signer_fingerprint", ""),
    }
    save_registry(registry)

    return {
        "policy_id": policy_id,
        "policy_version": policy_version,
        "policy_digest": policy_digest,
        "status": "registered",
        "registered_at": registry["policies"][policy_id]["registered_at"],
    }


def list_policies() -> list[dict[str, Any]]:
    """List all registered drift policies."""
    registry = load_registry()
    return list(registry["policies"].values())


def revoke_policy(policy_id: str) -> dict[str, Any]:
    """Revoke a registered drift policy.

    Args:
        policy_id: The policy ID to revoke.

    Returns:
        {policy_id, status}
    """
    registry = load_registry()
    if policy_id not in registry["policies"]:
        return {"policy_id": policy_id, "status": "not_found"}
    registry["policies"][policy_id]["policy_status"] = "revoked"
    save_registry(registry)
    return {"policy_id": policy_id, "status": "revoked"}


def verify_policy_in_registry(
    policy_id: str = "",
    policy_digest: str = "",
) -> dict[str, Any]:
    """Verify that a policy is registered and not revoked.

    Args:
        policy_id: Policy ID to check.
        policy_digest: Expected digest (if checking a specific version).

    Returns:
        {registered, active, digest_matches, entry}
    """
    registry = load_registry()
    entry = registry["policies"].get(policy_id)
    if not entry:
        return {
            "registered": False,
            "active": False,
            "digest_matches": False,
            "entry": None,
        }
    digest_matches = True
    if policy_digest and entry["policy_digest"] != policy_digest:
        digest_matches = False
    return {
        "registered": True,
        "active": entry["policy_status"] == "active",
        "digest_matches": digest_matches,
        "entry": entry,
    }


def registry_digest() -> str:
    """Get the entries_digest of the current registry."""
    registry = load_registry()
    return registry.get("entries_digest", "")
