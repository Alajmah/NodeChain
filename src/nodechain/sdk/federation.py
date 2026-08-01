"""Multi-Registry Federation (v2.5.0).

Allows the platform to resolve packages across multiple remote registries
while maintaining the non-negotiable federation rule:

    A registry is not trusted because it is reachable.
    A registry is eligible only if the active organization profile allows it.

Selection pipeline:
    discover candidates
    → verify registry metadata
    → verify package metadata
    → apply organization policy
    → detect conflicts
    → select deterministic winner
    → write evidence and transparency entries
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ── Constants ────────────────────────────────────────────────────────────────

FEDERATION_CONFIG_VERSION = "v1"


class FederationConfigError(Exception):
    """Raised when federation config is corrupt or invalid."""


# ── Federated Registry Config ────────────────────────────────────────────────

@dataclass
class FederatedRegistryConfig:
    """Configuration for a single federated remote registry.

    Each registry has its own trust level, allowed publishers,
    allowed packages, and priority. The organization policy controls
    whether federation is permitted at all.
    """
    registry_id: str
    base_url: str
    trust_level: str = "remote_untrusted"
    allowed_publishers: list[str] = field(default_factory=list)
    allowed_packages: list[str] = field(default_factory=list)  # empty = all
    priority: int = 100  # lower = higher priority
    enabled: bool = True
    required_signer_fingerprint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "registry_id": self.registry_id,
            "base_url": self.base_url,
            "trust_level": self.trust_level,
            "allowed_publishers": self.allowed_publishers,
            "allowed_packages": self.allowed_packages,
            "priority": self.priority,
            "enabled": self.enabled,
            "required_signer_fingerprint": self.required_signer_fingerprint,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> FederatedRegistryConfig:
        return cls(
            registry_id=d["registry_id"],
            base_url=d["base_url"],
            trust_level=d.get("trust_level", "remote_untrusted"),
            allowed_publishers=d.get("allowed_publishers", []),
            allowed_packages=d.get("allowed_packages", []),
            priority=d.get("priority", 100),
            enabled=d.get("enabled", True),
            required_signer_fingerprint=d.get("required_signer_fingerprint", ""),
        )

    def is_publisher_allowed(self, publisher_fingerprint: str) -> bool:
        """Check if a publisher is allowed by this registry config."""
        if not self.allowed_publishers:
            return True  # Empty = all publishers allowed
        return publisher_fingerprint in self.allowed_publishers

    def is_package_allowed(self, package_id: str) -> bool:
        """Check if a package is allowed by this registry config."""
        if not self.allowed_packages:
            return True  # Empty = all packages allowed
        return package_id in self.allowed_packages


# ── Federation Config Store ──────────────────────────────────────────────────

@dataclass
class FederationConfigStore:
    """Stores federated registry configurations."""
    registries: list[FederatedRegistryConfig] = field(default_factory=list)
    version: str = FEDERATION_CONFIG_VERSION

    def add(self, config: FederatedRegistryConfig) -> None:
        """Add a registry config. Replaces if same registry_id exists."""
        self.registries = [r for r in self.registries if r.registry_id != config.registry_id]
        self.registries.append(config)

    def remove(self, registry_id: str) -> bool:
        """Remove a registry config by ID. Returns True if removed."""
        before = len(self.registries)
        self.registries = [r for r in self.registries if r.registry_id != registry_id]
        return len(self.registries) < before

    def get(self, registry_id: str) -> FederatedRegistryConfig | None:
        """Get a registry config by ID."""
        for r in self.registries:
            if r.registry_id == registry_id:
                return r
        return None

    @property
    def enabled_registries(self) -> list[FederatedRegistryConfig]:
        """Return enabled registries sorted by priority (lower = higher)."""
        return sorted(
            [r for r in self.registries if r.enabled],
            key=lambda r: (r.priority, r.registry_id),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "registries": [r.to_dict() for r in self.registries],
        }

    def compute_digest(self) -> str:
        """Compute SHA-256 digest of the config's canonical form."""
        import hashlib
        canonical = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> FederationConfigStore:
        return cls(
            registries=[FederatedRegistryConfig.from_dict(r) for r in d.get("registries", [])],
            version=d.get("version", FEDERATION_CONFIG_VERSION),
        )


def get_federation_config_path() -> str:
    """Get the federation config path from env or default."""
    return os.environ.get(
        "NODECHAIN_FEDERATION_CONFIG",
        os.path.join("data", "federation_config.json"),
    )


def load_federation_config(path: str | None = None) -> FederationConfigStore:
    """Load federation config from file.

    Raises FederationConfigError if the file is corrupt.
    Returns empty store if file doesn't exist.
    """
    path = path or get_federation_config_path()
    p = Path(path)
    if not p.exists():
        return FederationConfigStore()
    raw = p.read_text(encoding="utf-8")
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as e:
        raise FederationConfigError(
            f"Federation config file is corrupt at {path}: {e}"
        ) from e
    if not isinstance(data, dict):
        raise FederationConfigError(
            f"Federation config at {path} is not a valid JSON object"
        )
    return FederationConfigStore.from_dict(data)


def save_federation_config(
    store: FederationConfigStore,
    path: str | None = None,
) -> str:
    """Save federation config to file atomically."""
    path = path or get_federation_config_path()
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(store.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(p)
    return str(p)


# ── Federation Resolution ────────────────────────────────────────────────────

@dataclass
class FederationCandidate:
    """A candidate package from a specific registry."""
    registry_id: str
    base_url: str
    priority: int
    package_id: str
    version: str
    artifact_digest: str
    metadata_digest: str
    publisher_fingerprint: str
    signer_fingerprint: str = ""
    metadata_signed: bool = False
    certified: bool = False  # v2.5.1: certification is distinct from signing

    @property
    def candidate_key(self) -> str:
        """Unique key for this candidate."""
        return f"{self.registry_id}:{self.package_id}@{self.version}"


@dataclass
class FederationResolveResult:
    """Result of federated package resolution."""
    package_id: str
    version: str
    selected: FederationCandidate | None = None
    candidates: list[FederationCandidate] = field(default_factory=list)
    rejected: list[dict[str, str]] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    policy_profile_digest: str = ""
    all_passed: bool = False
    resolved_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = {
            "package_id": self.package_id,
            "version": self.version,
            "selected_registry_id": self.selected.registry_id if self.selected else None,
            "selected_package_digest": self.selected.artifact_digest if self.selected else "",
            "candidate_registry_ids": [c.registry_id for c in self.candidates],
            "rejected_registry_reasons": self.rejected,
            "conflicts": self.conflicts,
            "policy_profile_digest": self.policy_profile_digest,
            "all_passed": self.all_passed,
            "resolved_at": self.resolved_at,
        }
        return d


def resolve_federated_package(
    package_id: str,
    version: str,
    fetch_metadata_fn: Any,
    store: FederationConfigStore,
    org_profile: Any | None = None,
) -> FederationResolveResult:
    """Resolve a package across federated registries.

    Selection pipeline:
    1. Discover candidates from enabled registries
    2. Filter by registry config (allowed publishers/packages)
    3. Apply organization policy
    4. Detect digest conflicts
    5. Select deterministic winner by priority

    Args:
        package_id: Package to resolve.
        version: Package version.
        fetch_metadata_fn: Callable(registry_id, package_id, version) -> metadata dict.
        store: Federation config store.
        org_profile: Optional OrganizationTrustPolicyProfile.

    Returns:
        FederationResolveResult with selection details.
    """
    result = FederationResolveResult(
        package_id=package_id,
        version=version,
        resolved_at=datetime.now(timezone.utc).isoformat(),
    )

    # Policy profile digest
    if org_profile:
        result.policy_profile_digest = org_profile.compute_digest()

    # Check if federation is allowed by policy
    if org_profile:
        ok, msg = org_profile.check_remote_install()
        if not ok:
            result.rejected.append({
                "registry_id": "(policy)",
                "reason": f"Policy denied federation: {msg}",
            })
            return result

    # Phase 1: Discover candidates from enabled registries
    candidates: list[FederationCandidate] = []
    for reg in store.enabled_registries:
        # Check package allowlist
        if not reg.is_package_allowed(package_id):
            result.rejected.append({
                "registry_id": reg.registry_id,
                "reason": f"Package '{package_id}' not in allowed list",
            })
            continue

        # Fetch metadata
        try:
            meta = fetch_metadata_fn(reg.registry_id, package_id, version)
        except Exception as e:
            result.rejected.append({
                "registry_id": reg.registry_id,
                "reason": f"Metadata fetch failed: {e}",
            })
            continue

        candidate = FederationCandidate(
            registry_id=reg.registry_id,
            base_url=reg.base_url,
            priority=reg.priority,
            package_id=package_id,
            version=version,
            artifact_digest=meta.get("artifact_digest", ""),
            metadata_digest=meta.get("metadata_digest", ""),
            publisher_fingerprint=meta.get("publisher_fingerprint", ""),
            signer_fingerprint=meta.get("signer_fingerprint", ""),
            metadata_signed=meta.get("metadata_signed", False),
            certified=meta.get("certified", False),  # v2.5.1: separate from signing
        )

        # Phase 2: Registry config checks
        if not reg.is_publisher_allowed(candidate.publisher_fingerprint):
            result.rejected.append({
                "registry_id": reg.registry_id,
                "reason": f"Publisher '{candidate.publisher_fingerprint[:12]}...' not allowed",
            })
            continue

        # Required signer check
        if reg.required_signer_fingerprint:
            if candidate.signer_fingerprint != reg.required_signer_fingerprint:
                result.rejected.append({
                    "registry_id": reg.registry_id,
                    "reason": f"Signer mismatch: expected {reg.required_signer_fingerprint[:12]}...",
                })
                continue

        candidates.append(candidate)

    result.candidates = candidates

    if not candidates:
        return result

    # Phase 3: Apply organization policy checks
    if org_profile:
        checked: list[FederationCandidate] = []
        for c in candidates:
            # Check registry signing requirement
            ok, msg = org_profile.check_registry_signing(c.metadata_signed)
            if not ok:
                result.rejected.append({
                    "registry_id": c.registry_id,
                    "reason": f"Policy: {msg}",
                })
                continue
            # Check certification (v2.5.1: signing ≠ certification — checked separately)
            ok, msg = org_profile.check_certification(c.certified)
            if not ok:
                result.rejected.append({
                    "registry_id": c.registry_id,
                    "reason": f"Policy: {msg}",
                })
                continue
            # Check sandbox (all remote packages use remote_untrusted)
            ok, msg = org_profile.check_sandbox("hardened_untrusted")
            if not ok:
                result.rejected.append({
                    "registry_id": c.registry_id,
                    "reason": f"Policy: {msg}",
                })
                continue
            checked.append(c)
        candidates = checked
        result.candidates = candidates

    if not candidates:
        return result

    # Phase 4: Detect digest conflicts
    digest_groups: dict[str, list[FederationCandidate]] = {}
    for c in candidates:
        digest_groups.setdefault(c.artifact_digest, []).append(c)

    if len(digest_groups) > 1:
        # Conflict: different digests from different registries
        conflict_descs = []
        for digest, group in digest_groups.items():
            registries = [g.registry_id for g in group]
            conflict_descs.append(
                f"digest {digest[:12]}... from {', '.join(registries)}"
            )
        conflict_msg = "; ".join(conflict_descs)
        result.conflicts.append(
            f"Digest conflict for {package_id}@{version}: {conflict_msg}"
        )
        # Fail closed on conflict
        return result

    # Phase 5: Select deterministic winner by priority
    # All candidates have same digest (no conflict), pick highest priority
    winner = min(candidates, key=lambda c: (c.priority, c.registry_id))
    result.selected = winner
    result.all_passed = True

    return result


def verify_federation(store: FederationConfigStore) -> dict[str, Any]:
    """Verify federation configuration integrity.

    Returns a report with warnings and errors.
    """
    report: dict[str, Any] = {
        "total_registries": len(store.registries),
        "enabled": len(store.enabled_registries),
        "disabled": len(store.registries) - len(store.enabled_registries),
        "errors": [],
        "warnings": [],
    }

    # Check for duplicate registry IDs
    seen_ids: set[str] = set()
    for reg in store.registries:
        if reg.registry_id in seen_ids:
            report["errors"].append(f"Duplicate registry_id: {reg.registry_id}")
        seen_ids.add(reg.registry_id)

    # Check for disabled registries
    for reg in store.registries:
        if not reg.enabled:
            report["warnings"].append(f"Registry '{reg.registry_id}' is disabled")

    # Check for unreachable URLs (basic format check)
    for reg in store.registries:
        if not reg.base_url.startswith(("http://", "https://")):
            report["errors"].append(
                f"Registry '{reg.registry_id}' has invalid base_url: {reg.base_url}"
            )

    report["valid"] = len(report["errors"]) == 0
    return report
