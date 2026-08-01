"""Registry lockfile — reproducible package provenance.

Generates and verifies a lockfile recording the exact state of
loaded local registry packages: IDs, versions, paths, content hashes.

Usage:
    nodechain registry lock         # Generate lockfile
    nodechain registry verify       # Verify current state against lockfile
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nodechain.registry.local_registry import RegistryIndex


LOCKFILE_NAME = "registry.lock.json"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def generate_lockfile(
    registry: RegistryIndex | None = None,
    output_path: str | Path | None = None,
    include_blocked: bool = False,
) -> dict[str, Any]:
    """
    Generate a lockfile from the current registry state.

    Records package_id, node_id, version, origin, path, content_hash
    for every registered package.

    Args:
        registry: Pre-scanned registry (scans if None)
        output_path: Where to write the lockfile
        include_blocked: If True, include packages that fail policy checks
                         (recorded with policy_status=blocked)

    Returns the lockfile dict.
    """
    if registry is None:
        registry = RegistryIndex()
        registry.scan()

    if output_path is None:
        output_path = Path(LOCKFILE_NAME)

    packages = []
    for pkg_info in registry.list_packages():
        node_id = pkg_info["node_id"]
        pkg = registry.get_package(node_id)
        if pkg is None:
            continue

        entry = {
            "node_id": node_id,
            "name": pkg.manifest.name,
            "version": pkg.manifest.version,
            "origin": "local_registry",
            "path": str(pkg.path) if pkg.path else None,
            "content_hash": pkg.content_hash(),
            "content_digest": pkg.content_digest(),  # v2.67.3: full-length enforcement digest
            "locked_at": _now_iso(),
        }

        # Read capabilities if available
        if pkg.path:
            try:
                import yaml
                yaml_path = Path(pkg.path) / "node.yaml"
                if not yaml_path.exists():
                    yaml_path = Path(pkg.path) / "package.yaml"
                if yaml_path.exists():
                    raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
                    caps = raw.get("capabilities")
                    if caps:
                        entry["capabilities"] = caps
                    min_ver = raw.get("nodechain_min_version")
                    if not min_ver:
                        meta = raw.get("meta", {})
                        min_ver = meta.get("nodechain_min_version")
                    if min_ver:
                        entry["nodechain_min_version"] = min_ver
            except Exception:
                pass

        # Check policy status
        policy_status = "allowed"
        policy_reasons: list[str] = []
        try:
            from nodechain.sdk.policy_enforcer import PackagePolicyEnforcer, PolicyDecision
            enforcer = PackagePolicyEnforcer()
            policy_result = enforcer.enforce_package(
                package_id=node_id,
                node_id=node_id,
                package_path=Path(pkg.path) if pkg.path else None,
            )
            if policy_result.decision == PolicyDecision.BLOCK:
                policy_status = "blocked"
                policy_reasons = policy_result.reasons
            entry["policy_status"] = policy_status
            if policy_reasons:
                entry["policy_reasons"] = policy_reasons
        except Exception:
            pass

        # Skip blocked packages unless include_blocked
        if policy_status == "blocked" and not include_blocked:
            continue

        packages.append(entry)

    lockfile = {
        "version": "1.0",
        "generated_at": _now_iso(),
        "nodechain_version": _get_runtime_version(),
        "packages": packages,
        "package_count": len(packages),
    }

    # Write to file
    output_path = Path(output_path)
    output_path.write_text(json.dumps(lockfile, indent=2) + "\n", encoding="utf-8")

    return lockfile


def verify_lockfile(
    lockfile_path: str | Path | None = None,
    registry: RegistryIndex | None = None,
) -> dict[str, Any]:
    """
    Verify current registry state against a lockfile.

    Checks:
      - All locked packages still exist
      - Content hashes match
      - Versions match

    Returns a verification result dict.
    """
    if lockfile_path is None:
        lockfile_path = Path(LOCKFILE_NAME)

    lockfile_path = Path(lockfile_path)
    if not lockfile_path.exists():
        return {
            "valid": False,
            "error": f"Lockfile not found: {lockfile_path}",
            "mismatches": [],
            "missing": [],
            "extra": [],
        }

    lockfile = json.loads(lockfile_path.read_text(encoding="utf-8"))

    if registry is None:
        registry = RegistryIndex()
        registry.scan()

    # Build current state map
    current: dict[str, dict[str, Any]] = {}
    for pkg_info in registry.list_packages():
        nid = pkg_info["node_id"]
        pkg = registry.get_package(nid)
        if pkg:
            current[nid] = {
                "version": pkg.manifest.version,
                "content_hash": pkg.content_hash(),
                "path": str(pkg.path) if pkg.path else None,
            }

    # Build locked state map
    locked: dict[str, dict[str, Any]] = {}
    for entry in lockfile.get("packages", []):
        locked[entry["node_id"]] = entry

    mismatches = []
    missing = []
    extra_nodes = []

    # Check locked packages exist and match
    for nid, lock_entry in locked.items():
        if nid not in current:
            missing.append({
                "node_id": nid,
                "reason": "Package no longer in registry",
                "locked_version": lock_entry.get("version"),
            })
            continue

        cur = current[nid]
        if cur["content_hash"] != lock_entry.get("content_hash"):
            mismatches.append({
                "node_id": nid,
                "field": "content_hash",
                "locked": lock_entry.get("content_hash"),
                "current": cur["content_hash"],
                "reason": "Content hash changed — package code was modified",
            })
        if cur["version"] != lock_entry.get("version"):
            mismatches.append({
                "node_id": nid,
                "field": "version",
                "locked": lock_entry.get("version"),
                "current": cur["version"],
                "reason": "Version changed",
            })

    # Check for new packages not in lockfile
    for nid in current:
        if nid not in locked:
            extra_nodes.append({
                "node_id": nid,
                "reason": "New package not in lockfile",
                "current_version": current[nid]["version"],
            })

    is_clean = len(mismatches) == 0 and len(missing) == 0

    return {
        "valid": is_clean,
        "lockfile_generated_at": lockfile.get("generated_at"),
        "lockfile_nodechain_version": lockfile.get("nodechain_version"),
        "locked_count": len(locked),
        "current_count": len(current),
        "mismatches": mismatches,
        "missing": missing,
        "extra": extra_nodes,
    }


def _get_runtime_version() -> str:
    try:
        from nodechain import __version__
        return __version__
    except (ImportError, AttributeError):
        return "0.0.0"


def enforce_lockfile_for_nodes(
    node_ids: list[str],
    lockfile_path: str | Path | None = None,
    registry: "RegistryIndex | None" = None,
) -> tuple[bool, list[str]]:
    """Fail-closed lockfile enforcement for specific resolved nodes (v2.67.3).

    Unlike the advisory verify_lockfile(), this checks that every node in
    ``node_ids`` has a valid lockfile entry that matches the live package,
    and returns failure for any of these conditions:

      - lockfile missing on disk
      - node entry missing from lockfile
      - version mismatch
      - origin != "local_registry"
      - content_digest missing from the lockfile entry
      - content_digest mismatch against the live package
      - package not currently admitted by RegistryIndex

    Args:
        node_ids: Node IDs that were resolved from the registry for this run
                  (only successful NodeLoader resolutions should be passed).
        lockfile_path: Path to the lockfile. Defaults to registry.lock.json.
        registry: Pre-scanned registry. A new RegistryIndex().scan() if None.

    Returns:
        (ok, errors) — ok is True only if every node passed all checks.
    """
    errors: list[str] = []

    if lockfile_path is None:
        lockfile_path = Path(LOCKFILE_NAME)
    lockfile_path = Path(lockfile_path)

    # Condition: lockfile missing
    if not lockfile_path.exists():
        return False, [
            f"Lockfile required for registry-resolved execution but not found: {lockfile_path}. "
            "Generate it explicitly with `nodechain registry lock`."
        ]

    try:
        lockfile = json.loads(lockfile_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, [f"Lockfile unreadable ({lockfile_path}): {exc}"]

    locked_by_id = {e["node_id"]: e for e in lockfile.get("packages", [])}

    # Scan registry if not provided
    if registry is None:
        registry = RegistryIndex()
        registry.scan()

    for nid in node_ids:
        # Condition: node entry missing from lockfile
        if nid not in locked_by_id:
            errors.append(f"{nid}: missing lockfile entry")
            continue

        entry = locked_by_id[nid]

        # Condition: package not currently admitted by registry
        pkg = registry.get_package(nid)
        if pkg is None:
            errors.append(f"{nid}: not admitted by local registry")
            continue

        # Condition: version mismatch
        entry_version = entry.get("version")
        if entry_version != pkg.manifest.version:
            errors.append(
                f"{nid}: version mismatch (lockfile={entry_version}, "
                f"package={pkg.manifest.version})"
            )

        # Condition: origin mismatch
        entry_origin = entry.get("origin")
        if entry_origin != "local_registry":
            errors.append(f"{nid}: origin mismatch (lockfile={entry_origin})")

        # Condition: content_digest missing from lockfile entry
        entry_digest = entry.get("content_digest")
        if not entry_digest:
            errors.append(f"{nid}: content_digest missing from lockfile entry")
            continue

        # Condition: content_digest mismatch against live package
        live_digest = pkg.content_digest()
        if entry_digest != live_digest:
            errors.append(
                f"{nid}: content_digest mismatch "
                f"(lockfile={entry_digest[:16]}…, package={live_digest[:16]}…)"
            )

    return (len(errors) == 0), errors
