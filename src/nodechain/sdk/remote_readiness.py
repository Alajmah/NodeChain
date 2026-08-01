"""Remote Registry Readiness (v1.22.1).

Freezes local schemas, hardens package safety, and maps trust levels
to sandbox presets — preparing the local platform for v2.0.0 remote
registry without adding remote functionality.

Key deliverables:
  1. Frozen package manifest schema (schema v1)
  2. Frozen registry entry schema (schema v1)
  3. Trust-level to sandbox-preset mapping (explicit, enforced)
  4. Archive safety validation (pre-remote hardening)
  5. Remote registry threat model constant for documentation
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Any


# ── Frozen Schema Versions ──────────────────────────────────────────────────

PACKAGE_MANIFEST_SCHEMA_VERSION = "1.0.0"
REGISTRY_ENTRY_SCHEMA_VERSION = "1.0.0"

#: Frozen required fields for package manifests
PACKAGE_MANIFEST_REQUIRED_FIELDS = frozenset({
    "package_id",
    "version",
    "description",
    "nodes",
    "capabilities",
    "sandbox_profile",
    "trust_level",
})

#: Frozen required fields for registry entries
REGISTRY_ENTRY_REQUIRED_FIELDS = frozenset({
    "entry_id",
    "package_id",
    "package_version",
    "package_digest",
    "certification_status",
    "registry_status",
    "published_at",
})

#: Valid trust levels (frozen, ordered by trust descending)
TRUST_LEVELS = ("built_in", "local_trusted", "local_untrusted", "remote_untrusted")


# ── Trust Level → Sandbox Preset Mapping ────────────────────────────────────

#: Maps trust levels to required sandbox preset
#: remote_untrusted always gets the strongest available preset
TRUST_TO_PRESET = {
    "built_in": "none",
    "local_trusted": "none",
    "local_untrusted": "standard_untrusted",
    "remote_untrusted": "hardened_untrusted",
}


def resolve_sandbox_preset(trust_level: str) -> str:
    """Resolve the required sandbox preset for a trust level.

    Rules:
      - built_in: no sandbox required
      - local_trusted: no sandbox required (passed policy checks)
      - local_untrusted: at least standard_untrusted
      - remote_untrusted: hardened_untrusted (strongest)

    On platforms where hardened_untrusted is unavailable (non-Linux),
    the resolver falls back to the strongest available.
    """
    if trust_level not in TRUST_LEVELS:
        raise ValueError(f"Unknown trust level: {trust_level}. Valid: {TRUST_LEVELS}")

    preset = TRUST_TO_PRESET[trust_level]

    # Platform fallback for remote_untrusted
    if trust_level == "remote_untrusted":
        if not sys.platform.startswith("linux"):
            # hardened_untrusted requires Linux namespaces
            preset = "production_untrusted"

    return preset


def is_upgrade_allowed(current: str, target: str) -> bool:
    """Check if a trust level upgrade is allowed.

    Trust levels can only be downgraded, never upgraded automatically.
    built_in > local_trusted > local_untrusted > remote_untrusted

    Upgrading (e.g., remote_untrusted → local_trusted) requires
    explicit operator action and is NOT automatic.
    """
    order = {level: i for i, level in enumerate(TRUST_LEVELS)}
    if current not in order or target not in order:
        return False
    # Downgrade (higher index) is always allowed
    # Upgrade (lower index) is NOT allowed automatically
    return order[target] >= order[current]


# ── Archive Safety ──────────────────────────────────────────────────────────

#: Safety limits for package archives
MAX_PACKAGE_FILES = 500
MAX_PACKAGE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB
MAX_FILE_PATH_LENGTH = 255


class ArchiveSafetyError(Exception):
    """Raised when a package archive fails safety validation."""
    pass


def validate_archive_paths(file_paths: list[str]) -> list[str]:
    """Validate that all paths in an archive are safe for extraction.

    Blocks:
      - Absolute paths (e.g., /etc/passwd, C:\\Windows)
      - Path traversal (e.g., ../../etc/passwd)
      - Symlink escapes (detected by path analysis)
      - Paths exceeding MAX_FILE_PATH_LENGTH

    Returns list of safe paths. Raises ArchiveSafetyError if any path is unsafe.
    """
    violations: list[str] = []

    for filepath in file_paths:
        # Check for absolute paths
        p = Path(filepath)
        if p.is_absolute() or filepath.startswith("/"):
            violations.append(f"Absolute path blocked: {filepath}")
            continue

        # Windows absolute paths
        if len(filepath) >= 2 and filepath[1] == ":":
            violations.append(f"Windows absolute path blocked: {filepath}")
            continue

        # Check for path traversal (.. components)
        parts = filepath.replace("\\", "/").split("/")
        if ".." in parts:
            violations.append(f"Path traversal blocked: {filepath}")
            continue

        # Check path length
        if len(filepath) > MAX_FILE_PATH_LENGTH:
            violations.append(f"Path too long ({len(filepath)} > {MAX_FILE_PATH_LENGTH}): {filepath}")
            continue

    if violations:
        raise ArchiveSafetyError(
            f"Archive safety validation failed ({len(violations)} violations):\n"
            + "\n".join(f"  - {v}" for v in violations[:20])
        )

    return file_paths


def validate_archive_size(total_size: int, file_count: int) -> None:
    """Validate archive meets size and count limits.

    Raises ArchiveSafetyError if limits exceeded.
    """
    if file_count > MAX_PACKAGE_FILES:
        raise ArchiveSafetyError(
            f"Too many files in archive: {file_count} > {MAX_PACKAGE_FILES}"
        )

    if total_size > MAX_PACKAGE_SIZE_BYTES:
        raise ArchiveSafetyError(
            f"Archive too large: {total_size} bytes > {MAX_PACKAGE_SIZE_BYTES} bytes"
        )


def inspect_tar_archive(archive_path: str | Path) -> dict[str, Any]:
    """Inspect a tar archive for safety without extracting.

    Returns dict with:
      - safe: bool
      - file_count: int
      - total_size: int
      - files: list of member paths
      - violations: list of safety violations
    """
    archive_path = Path(archive_path)
    violations: list[str] = []
    files: list[str] = []
    total_size = 0

    try:
        with tarfile.open(archive_path, "r:*") as tar:
            members = tar.getmembers()

            for member in members:
                files.append(member.name)
                total_size += member.size

                # Check for symlinks/hardlinks that escape
                if member.issym() or member.islnk():
                    linkname = member.linkname
                    if linkname.startswith("/") or ".." in linkname.replace("\\", "/").split("/"):
                        violations.append(f"Symlink escape blocked: {member.name} -> {linkname}")

                # Check for executable bits on non-standard files
                if member.isfile() and member.mode & 0o111:
                    # Executable files in packages are suspicious
                    if not member.name.endswith((".py", ".sh")):
                        violations.append(f"Executable file in archive: {member.name}")

            # Validate paths
            try:
                validate_archive_paths(files)
            except ArchiveSafetyError as e:
                violations.extend(str(e).split("\n")[1:])

            # Validate size
            try:
                validate_archive_size(total_size, len(files))
            except ArchiveSafetyError as e:
                violations.append(str(e))

    except tarfile.TarError as e:
        return {
            "safe": False,
            "error": f"Tar error: {e}",
            "file_count": 0,
            "total_size": 0,
            "files": [],
            "violations": [f"Unreadable archive: {e}"],
        }

    return {
        "safe": len(violations) == 0,
        "file_count": len(files),
        "total_size": total_size,
        "files": files,
        "violations": violations,
    }


def inspect_zip_archive(archive_path: str | Path) -> dict[str, Any]:
    """Inspect a zip archive for safety without extracting."""
    archive_path = Path(archive_path)
    violations: list[str] = []
    files: list[str] = []
    total_size = 0

    try:
        with zipfile.ZipFile(archive_path, "r") as zf:
            for info in zf.infolist():
                files.append(info.filename)
                total_size += info.file_size

            try:
                validate_archive_paths(files)
            except ArchiveSafetyError as e:
                violations.extend(str(e).split("\n")[1:])

            try:
                validate_archive_size(total_size, len(files))
            except ArchiveSafetyError as e:
                violations.append(str(e))

    except zipfile.BadZipFile as e:
        return {
            "safe": False,
            "error": f"Zip error: {e}",
            "file_count": 0,
            "total_size": 0,
            "files": [],
            "violations": [f"Unreadable archive: {e}"],
        }

    return {
        "safe": len(violations) == 0,
        "file_count": len(files),
        "total_size": total_size,
        "files": files,
        "violations": violations,
    }


def safe_extract(archive_path: str | Path, dest_dir: str | Path) -> list[str]:
    """Safely extract an archive, validating all paths before extraction.

    Returns list of extracted file paths.
    Raises ArchiveSafetyError if any path is unsafe.
    """
    archive_path = Path(archive_path)
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)

    if archive_path.suffix == ".zip" or archive_path.suffixes[-2:] == [".zip", ""]:
        result = inspect_zip_archive(archive_path)
    else:
        result = inspect_tar_archive(archive_path)

    if not result["safe"]:
        raise ArchiveSafetyError(
            f"Archive failed safety inspection:\n"
            + "\n".join(f"  - {v}" for v in result["violations"])
        )

    extracted: list[str] = []

    # Extract with path validation per-member
    if archive_path.suffix == ".zip":
        with zipfile.ZipFile(archive_path, "r") as zf:
            for info in zf.infolist():
                target = dest_dir / info.filename
                # Final check: resolved path must be within dest_dir
                try:
                    target.resolve().relative_to(dest_dir.resolve())
                except ValueError:
                    raise ArchiveSafetyError(f"Extraction escapes dest dir: {info.filename}")
                zf.extract(info, dest_dir)
                extracted.append(info.filename)
    else:
        with tarfile.open(archive_path, "r:*") as tar:
            for member in tar.getmembers():
                target = dest_dir / member.name
                try:
                    target.resolve().relative_to(dest_dir.resolve())
                except ValueError:
                    raise ArchiveSafetyError(f"Extraction escapes dest dir: {member.name}")
                tar.extract(member, dest_dir)
                extracted.append(member.name)

    return extracted


# ── Remote Registry Threat Model ────────────────────────────────────────────

REMOTE_REGISTRY_THREATS: list[dict[str, str]] = [
    {
        "threat": "Registry compromise",
        "description": "Attacker controls the registry server and serves malicious packages",
        "mitigation": "Publisher signatures + certification chain + trust store binding",
    },
    {
        "threat": "Publisher key compromise",
        "description": "Attacker obtains a publisher's private key and signs malicious packages",
        "mitigation": "Key rotation support + revocation + certification expiry",
    },
    {
        "threat": "Replay/stale metadata",
        "description": "Attacker serves old valid metadata for a since-patched package",
        "mitigation": "Metadata timestamp verification + version pinning + lockfile binding",
    },
    {
        "threat": "TLS interception",
        "description": "Man-in-the-middle intercepts registry traffic",
        "mitigation": "Certificate pinning + registry metadata signature verification",
    },
    {
        "threat": "Lockfile binding bypass",
        "description": "Package replaced after lockfile verification",
        "mitigation": "Artifact SHA-256 verified at install AND load time",
    },
    {
        "threat": "Offline verification bypass",
        "description": "Attacker blocks network to prevent revocation checks",
        "mitigation": "Local trust store cache + signed snapshots + staleness warning",
    },
    {
        "threat": "Package substitution",
        "description": "Same package_id/version but different artifact served",
        "mitigation": "Artifact digest in registry metadata + lockfile digest binding",
    },
    {
        "threat": "Dependency confusion",
        "description": "Remote registry serves a package with same name as local",
        "mitigation": "Explicit registry source in package identity + source-scoped resolution",
    },
    {
        "threat": "Unsafe archive extraction",
        "description": "Malicious archive with path traversal or symlinks",
        "mitigation": "safe_extract() with path validation + size limits + no symlink escape",
    },
    {
        "threat": "Install-time code execution",
        "description": "Package runs code during installation (setup hooks)",
        "mitigation": "No install hooks + manifest validation before any execution",
    },
]


def get_remote_registry_readiness() -> dict[str, Any]:
    """Check if the local platform is ready for remote registry.

    Returns readiness assessment with recommendations.
    """
    from nodechain.cli.dashboard_health import collect_dashboard_v2

    data = collect_dashboard_v2()
    issues = data["issues"]

    readiness_issues: list[str] = []

    # Check 1: Trust store must be initialized
    trust = data["sections"].get("trust", {})
    if not trust.get("trust_store_exists"):
        readiness_issues.append("Trust store not initialized — required for publisher verification")

    # Check 2: No unsigned snapshots
    if trust.get("trust_store_exists") and not trust.get("snapshot_signed"):
        readiness_issues.append("Trust store snapshot unsigned — required for offline verification")

    # Check 3: No revoked entries in registry
    registry = data["sections"].get("registry", {})
    if registry.get("revoked", 0) > 0:
        readiness_issues.append(f"{registry['revoked']} revoked registry entries — clean up before remote")

    # Check 4: No legacy keys
    if trust.get("legacy_keys", 0) > 0:
        readiness_issues.append(f"{trust['legacy_keys']} legacy keys — migrate before remote")

    ready = len(readiness_issues) == 0

    return {
        "type": "remote_registry_readiness",
        "ready": ready,
        "schema_versions": {
            "package_manifest": PACKAGE_MANIFEST_SCHEMA_VERSION,
            "registry_entry": REGISTRY_ENTRY_SCHEMA_VERSION,
        },
        "trust_levels": list(TRUST_LEVELS),
        "trust_to_preset": TRUST_TO_PRESET,
        "issues": readiness_issues,
        "threat_count": len(REMOTE_REGISTRY_THREATS),
        "timestamp": data["timestamp"],
    }
