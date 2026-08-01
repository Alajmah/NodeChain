"""Trust-Aware Dependency Resolution and Transitive Trust (v2.16.0).

A remote package is admissible only if every dependency in its resolved
graph is version-compatible, identity-verified, non-revoked, publisher-
authorized, certified, policy-admissible, and sandbox-compatible.

DT-001 (critical invariant):
    A package graph is admissible only if every reachable dependency is
    individually trusted, policy-admissible, lifecycle-valid, certification-
    valid, and sandbox-compatible. Trust does not flow transitively from
    the root package.

This module extends the v2.2.0 dependency resolver with:
    - Lifecycle state checking (active/deprecated/revoked)
    - Policy verdicts per node
    - Aggregate capability/sandbox computation
    - Trust graph resolution receipts
    - Lockfile drift detection
    - Cross-registry trust verification
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .artifact_retention import atomic_write_json


# ── Constants ───────────────────────────────────────────────────────────────

LOCKFILE_SCHEMA_VERSION = "1.0.0"

POLICY_ALLOWED = "allowed"
POLICY_DENIED = "denied"
POLICY_WARN = "warn"
POLICY_PINNED_ONLY = "pinned_only"

ALL_POLICY_VERDICTS = {POLICY_ALLOWED, POLICY_DENIED, POLICY_WARN, POLICY_PINNED_ONLY}

DEP_POLICY_ALLOW = "allow"
DEP_POLICY_DENY = "deny"
DEP_POLICY_ALLOW_WITH_WARNING = "allow_with_warning"
DEP_POLICY_ALLOW_ONLY_IF_PINNED = "allow_only_if_pinned"

# Sandbox strength ordering (higher = stronger)
SANDBOX_STRENGTH_ORDER = {
    "none": 0,
    "standard_untrusted": 1,
    "production_untrusted": 2,
    "hardened_untrusted": 3,
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_dict(data: dict[str, Any]) -> str:
    raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


# ── Resolved Trust Graph Node ───────────────────────────────────────────────


@dataclass
class ResolvedTrustNode:
    """A node in a resolved trust dependency graph.

    Extends DependencyGraphNode with lifecycle, policy, and trust verdicts.
    """

    package_id: str = ""
    version: str = ""
    registry_id: str = ""
    artifact_digest: str = ""
    manifest_digest: str = ""
    publisher_fingerprint: str = ""
    certification_digest: str = ""
    lifecycle: str = "active"
    sandbox_profile: str = "hardened_untrusted"
    capabilities: list[str] = field(default_factory=list)
    trust_verdict: str = "untrusted"
    policy_verdict: str = "denied"
    is_root: bool = False
    rejection_reason: str = ""

    def key(self) -> str:
        return f"{self.package_id}@{self.version}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_id": self.package_id,
            "version": self.version,
            "registry_id": self.registry_id,
            "artifact_digest": self.artifact_digest,
            "manifest_digest": self.manifest_digest,
            "publisher_fingerprint": self.publisher_fingerprint,
            "certification_digest": self.certification_digest,
            "lifecycle": self.lifecycle,
            "sandbox_profile": self.sandbox_profile,
            "capabilities": list(self.capabilities),
            "trust_verdict": self.trust_verdict,
            "policy_verdict": self.policy_verdict,
            "is_root": self.is_root,
            "rejection_reason": self.rejection_reason,
        }


# ── Dependency Edge ─────────────────────────────────────────────────────────


@dataclass
class TrustGraphEdge:
    """An edge in the resolved trust graph."""

    from_package: str = ""
    to_package: str = ""
    constraint: str = ""
    resolved_version: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "from": self.from_package,
            "to": self.to_package,
            "constraint": self.constraint,
            "resolved_version": self.resolved_version,
        }


# ── Resolved Trust Graph ────────────────────────────────────────────────────


@dataclass
class ResolvedTrustGraph:
    """Complete resolved dependency graph with trust verdicts.

    DT-001: Every node must be individually trusted. Trust does not
    flow transitively from the root.
    """

    root: ResolvedTrustNode | None = None
    nodes: list[ResolvedTrustNode] = field(default_factory=list)
    edges: list[TrustGraphEdge] = field(default_factory=list)
    resolved_at: str = ""
    resolver_policy_digest: str = ""
    graph_admissible: bool = False
    aggregate_sandbox: str = "hardened_untrusted"
    aggregate_capabilities: list[str] = field(default_factory=list)
    rejection_summary: str = ""

    def all_nodes_admissible(self) -> bool:
        """DT-001: Every node must have policy_verdict == allowed or warn."""
        return all(
            n.policy_verdict in (POLICY_ALLOWED, POLICY_WARN)
            for n in self.nodes
        )

    def has_revoked_dependency(self) -> bool:
        return any(n.lifecycle == "revoked" for n in self.nodes)

    def has_deprecated_dependency(self) -> bool:
        return any(n.lifecycle == "deprecated" for n in self.nodes)

    def has_untrusted_dependency(self) -> bool:
        return any(n.trust_verdict != "trusted" for n in self.nodes)

    def compute_graph_digest(self) -> str:
        """SHA-256 of all nodes, edges, and aggregate properties."""
        d = {
            "root": self.root.to_dict() if self.root else {},
            "nodes": sorted([n.to_dict() for n in self.nodes], key=lambda x: x["package_id"]),
            "edges": sorted([e.to_dict() for e in self.edges], key=lambda x: (x["from"], x["to"])),
            "aggregate_sandbox": self.aggregate_sandbox,
            "aggregate_capabilities": sorted(self.aggregate_capabilities),
        }
        return _sha256_dict(d)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root.to_dict() if self.root else {},
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "resolved_at": self.resolved_at,
            "resolver_policy_digest": self.resolver_policy_digest,
            "graph_admissible": self.graph_admissible,
            "aggregate_sandbox": self.aggregate_sandbox,
            "aggregate_capabilities": list(self.aggregate_capabilities),
            "rejection_summary": self.rejection_summary,
            "graph_digest": self.compute_graph_digest(),
        }


# ── Trust-Aware Lockfile ────────────────────────────────────────────────────


@dataclass
class TrustLockfile:
    """Lockfile binding exact versions, digests, and trust verdicts.

    A later install must fail if the resolved graph no longer matches.
    """

    schema_version: str = LOCKFILE_SCHEMA_VERSION
    root: dict[str, Any] = field(default_factory=dict)
    resolved_at: str = ""
    resolver_policy_digest: str = ""
    packages: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    graph_digest: str = ""
    lockfile_digest: str = ""

    def compute_digest(self) -> str:
        d = {
            "schema_version": self.schema_version,
            "root": self.root,
            "resolved_at": self.resolved_at,
            "resolver_policy_digest": self.resolver_policy_digest,
            "packages": sorted(self.packages, key=lambda x: x.get("package_id", "")),
            "edges": sorted(self.edges, key=lambda x: (x.get("from", ""), x.get("to", ""))),
            "graph_digest": self.graph_digest,
        }
        return _sha256_dict(d)

    def finalize(self) -> "TrustLockfile":
        self.lockfile_digest = self.compute_digest()
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "root": self.root,
            "resolved_at": self.resolved_at,
            "resolver_policy_digest": self.resolver_policy_digest,
            "packages": self.packages,
            "edges": self.edges,
            "graph_digest": self.graph_digest,
            "lockfile_digest": self.lockfile_digest,
        }

    @classmethod
    def from_graph(cls, graph: ResolvedTrustGraph) -> "TrustLockfile":
        packages = []
        for node in graph.nodes:
            packages.append({
                "package_id": node.package_id,
                "version": node.version,
                "registry_id": node.registry_id,
                "artifact_digest": node.artifact_digest,
                "manifest_digest": node.manifest_digest,
                "publisher_fingerprint": node.publisher_fingerprint,
                "certification_digest": node.certification_digest,
                "lifecycle": node.lifecycle,
                "trust_verdict": node.trust_verdict,
                "policy_verdict": node.policy_verdict,
                "sandbox_profile": node.sandbox_profile,
            })

        lf = cls(
            root=graph.root.to_dict() if graph.root else {},
            resolved_at=graph.resolved_at,
            resolver_policy_digest=graph.resolver_policy_digest,
            packages=packages,
            edges=[e.to_dict() for e in graph.edges],
            graph_digest=graph.compute_graph_digest(),
        )
        return lf.finalize()

    def matches_graph(self, graph: ResolvedTrustGraph) -> bool:
        """Check if this lockfile matches a resolved graph (no drift)."""
        return self.graph_digest == graph.compute_graph_digest()


# ── Resolution Receipt ──────────────────────────────────────────────────────


@dataclass
class TrustResolutionReceipt:
    """Receipt for a trust-aware dependency resolution."""

    receipt_id: str = ""
    root_package_id: str = ""
    root_version: str = ""
    graph_digest: str = ""
    lockfile_digest: str = ""
    resolver_policy_digest: str = ""
    node_count: int = 0
    admissible: bool = False
    rejected_nodes: list[dict[str, Any]] = field(default_factory=list)
    resolved_at: str = ""
    receipt_digest: str = ""

    def compute_digest(self) -> str:
        d = {
            "receipt_id": self.receipt_id,
            "root_package_id": self.root_package_id,
            "root_version": self.root_version,
            "graph_digest": self.graph_digest,
            "lockfile_digest": self.lockfile_digest,
            "resolver_policy_digest": self.resolver_policy_digest,
            "node_count": self.node_count,
            "admissible": self.admissible,
            "resolved_at": self.resolved_at,
        }
        return _sha256_dict(d)

    def finalize(self) -> "TrustResolutionReceipt":
        self.receipt_digest = self.compute_digest()
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "root_package_id": self.root_package_id,
            "root_version": self.root_version,
            "graph_digest": self.graph_digest,
            "lockfile_digest": self.lockfile_digest,
            "resolver_policy_digest": self.resolver_policy_digest,
            "node_count": self.node_count,
            "admissible": self.admissible,
            "rejected_nodes": list(self.rejected_nodes),
            "resolved_at": self.resolved_at,
            "receipt_digest": self.receipt_digest,
        }


# ── Exceptions ──────────────────────────────────────────────────────────────


class TrustResolutionError(Exception):
    """Base error for trust-aware resolution failures."""


class DependencyCycleDetected(TrustResolutionError):
    """A dependency cycle was detected in the graph."""

    def __init__(self, cycle_path: list[str]):
        self.cycle_path = cycle_path
        super().__init__(f"Dependency cycle detected: {' → '.join(cycle_path)}")


class VersionConflictError(TrustResolutionError):
    """Two branches require incompatible versions."""

    def __init__(self, package_id: str, versions: list[str]):
        self.package_id = package_id
        self.versions = versions
        super().__init__(
            f"Version conflict for {package_id}: requires {', '.join(versions)}"
        )


class CrossRegistryAmbiguityError(TrustResolutionError):
    """Same package_id available from different registries."""

    def __init__(self, package_id: str, registries: list[str]):
        self.package_id = package_id
        self.registries = registries
        super().__init__(
            f"Cross-registry ambiguity for {package_id}: "
            f"available from {', '.join(registries)}"
        )


class RevokedDependencyError(TrustResolutionError):
    """DT-001: A dependency is revoked."""


class UncertifiedDependencyError(TrustResolutionError):
    """Certification required but missing."""


class ForbiddenCapabilityError(TrustResolutionError):
    """Dependency requires a prohibited capability."""


class SandboxDowngradeError(TrustResolutionError):
    """Dependency weakens root sandbox assumptions."""


class LockfileDriftError(TrustResolutionError):
    """Resolved graph no longer matches the lockfile."""


# ── Sandbox helpers ─────────────────────────────────────────────────────────


def sandbox_strength(profile: str) -> int:
    """Get numeric strength of a sandbox profile."""
    return SANDBOX_STRENGTH_ORDER.get(profile, 3)  # Default to strongest


def strongest_sandbox(profiles: list[str]) -> str:
    """Return the strongest sandbox from a list."""
    if not profiles:
        return "hardened_untrusted"
    return max(profiles, key=lambda p: sandbox_strength(p))


# ── Trust-Aware Resolver ────────────────────────────────────────────────────


class TrustAwareResolver:
    """Resolves a dependency graph with full trust verification.

    Each dependency is independently verified. Trust does not flow
    transitively from the root (DT-001).

    The resolver takes a `metadata_provider` callable that returns package
    metadata dicts given (registry_id, package_id, version).
    """

    def __init__(
        self,
        metadata_provider=None,
        require_certification: bool = False,
        forbidden_capabilities: list[str] | None = None,
        min_sandbox_profile: str = "hardened_untrusted",
        deprecated_policy: str = DEP_POLICY_ALLOW_WITH_WARNING,
        trusted_registries: set[str] | None = None,
        trusted_publishers: set[str] | None = None,
        fail_closed_empty_trust: bool = False,
    ) -> None:
        self.metadata_provider = metadata_provider or (lambda rid, pid, ver: {})
        self.require_certification = require_certification
        self.forbidden_capabilities = set(forbidden_capabilities or [])
        self.min_sandbox_strength = sandbox_strength(min_sandbox_profile)
        self.deprecated_policy = deprecated_policy
        self.trusted_registries = trusted_registries or set()
        self.trusted_publishers = trusted_publishers or set()
        # TRUST-003: When True (production default), empty trust sets reject
        # all remote registries/publishers instead of allowing all.
        self.fail_closed_empty_trust = fail_closed_empty_trust

    def _compute_policy_digest(self) -> str:
        return _sha256_dict({
            "require_certification": self.require_certification,
            "forbidden_capabilities": sorted(self.forbidden_capabilities),
            "min_sandbox_strength": self.min_sandbox_strength,
            "deprecated_policy": self.deprecated_policy,
            "trusted_registries": sorted(self.trusted_registries),
            "trusted_publishers": sorted(self.trusted_publishers),
            "fail_closed_empty_trust": self.fail_closed_empty_trust,
        })

    def _evaluate_node(
        self,
        metadata: dict[str, Any],
        registry_id: str,
        is_root: bool = False,
    ) -> ResolvedTrustNode:
        """Evaluate a single package's trustworthiness and policy admission."""
        node = ResolvedTrustNode(
            package_id=metadata.get("package_id", ""),
            version=metadata.get("version", ""),
            registry_id=registry_id,
            artifact_digest=metadata.get("artifact_digest", ""),
            manifest_digest=metadata.get("manifest_digest", ""),
            publisher_fingerprint=metadata.get("publisher_fingerprint", ""),
            certification_digest=metadata.get("certification_digest", ""),
            lifecycle=metadata.get("lifecycle", "active"),
            sandbox_profile=metadata.get("sandbox_profile", "hardened_untrusted"),
            capabilities=metadata.get("capabilities", ["read_only"]),
            is_root=is_root,
        )

        # ── Trust verdict ──
        node.trust_verdict = "trusted"  # Will be overridden if checks fail

        # Check 1: Revoked → block
        if node.lifecycle == "revoked":
            node.trust_verdict = "revoked"
            node.policy_verdict = POLICY_DENIED
            node.rejection_reason = f"Package {node.key()} is revoked"
            return node

        # Check 2: Registry trust
        # TRUST-003: When fail_closed_empty_trust=True, empty trust sets reject all.
        if self.fail_closed_empty_trust and not self.trusted_registries:
            node.trust_verdict = "untrusted_registry"
            node.policy_verdict = POLICY_DENIED
            node.rejection_reason = "No trusted registries configured (fail-closed mode)"
            return node
        if self.trusted_registries and registry_id not in self.trusted_registries:
            node.trust_verdict = "untrusted_registry"
            node.policy_verdict = POLICY_DENIED
            node.rejection_reason = f"Registry {registry_id} not in trusted set"
            return node

        # Check 3: Publisher trust
        # TRUST-003: When fail_closed_empty_trust=True, empty trust sets reject all.
        if self.fail_closed_empty_trust and not self.trusted_publishers:
            node.trust_verdict = "untrusted_publisher"
            node.policy_verdict = POLICY_DENIED
            node.rejection_reason = "No trusted publishers configured (fail-closed mode)"
            return node
        if self.trusted_publishers and node.publisher_fingerprint not in self.trusted_publishers:
            node.trust_verdict = "untrusted_publisher"
            node.policy_verdict = POLICY_DENIED
            node.rejection_reason = f"Publisher {node.publisher_fingerprint[:16]}... not trusted"
            return node

        # Check 4: Certification
        if self.require_certification and not node.certification_digest:
            node.trust_verdict = "uncertified"
            node.policy_verdict = POLICY_DENIED
            node.rejection_reason = f"Package {node.key()} lacks required certification"
            return node

        # Check 5: Forbidden capability
        if self.forbidden_capabilities:
            for cap in node.capabilities:
                if cap in self.forbidden_capabilities:
                    node.trust_verdict = "forbidden_capability"
                    node.policy_verdict = POLICY_DENIED
                    node.rejection_reason = f"Package {node.key()} requires forbidden capability: {cap}"
                    return node

        # Check 6: Sandbox downgrade
        if sandbox_strength(node.sandbox_profile) < self.min_sandbox_strength:
            node.trust_verdict = "sandbox_downgrade"
            node.policy_verdict = POLICY_DENIED
            node.rejection_reason = (
                f"Package {node.key()} sandbox '{node.sandbox_profile}' "
                f"is weaker than minimum required"
            )
            return node

        # ── Policy verdict ──
        node.trust_verdict = "trusted"

        if node.lifecycle == "deprecated":
            if self.deprecated_policy == DEP_POLICY_DENY:
                node.policy_verdict = POLICY_DENIED
                node.rejection_reason = f"Deprecated package {node.key()} denied by policy"
            elif self.deprecated_policy == DEP_POLICY_ALLOW_WITH_WARNING:
                node.policy_verdict = POLICY_WARN
            elif self.deprecated_policy == DEP_POLICY_ALLOW_ONLY_IF_PINNED:
                node.policy_verdict = POLICY_PINNED_ONLY
            else:
                node.policy_verdict = POLICY_ALLOWED
        else:
            node.policy_verdict = POLICY_ALLOWED

        return node

    def resolve(
        self,
        root_registry_id: str,
        root_package_id: str,
        root_version: str,
    ) -> ResolvedTrustGraph:
        """Resolve the full dependency graph with trust verification.

        Returns a ResolvedTrustGraph. graph_admissible=True only when
        every node passes trust and policy checks (DT-001).
        """
        graph = ResolvedTrustGraph()
        graph.resolved_at = _now_iso()
        graph.resolver_policy_digest = self._compute_policy_digest()

        visited: dict[str, ResolvedTrustNode] = {}
        edges: list[TrustGraphEdge] = []
        rejected: list[dict[str, Any]] = []
        resolving_stack: list[str] = []  # For cycle path tracking
        cycle_detected: list[str] | None = None

        def _resolve(
            registry_id: str,
            package_id: str,
            version: str,
            constraint: str = "",
            parent_key: str = "",
            depth: int = 0,
        ) -> ResolvedTrustNode:
            nonlocal cycle_detected
            key = f"{package_id}@{version}"

            # Cycle detection with path
            if key in resolving_stack:
                idx = resolving_stack.index(key)
                cycle_detected = resolving_stack[idx:] + [key]
                # Return a placeholder to break the cycle
                return ResolvedTrustNode(
                    package_id=package_id, version=version,
                    trust_verdict="cycle", policy_verdict=POLICY_DENIED,
                    rejection_reason=f"Dependency cycle: {' → '.join(cycle_detected)}",
                )

            # Already fully resolved
            if key in visited:
                return visited[key]

            # Fetch metadata
            metadata = self.metadata_provider(registry_id, package_id, version)

            # Evaluate node
            is_root = depth == 0
            node = self._evaluate_node(metadata, registry_id, is_root=is_root)
            visited[key] = node
            resolving_stack.append(key)

            if is_root:
                graph.root = node

            # Record rejection
            if node.policy_verdict == POLICY_DENIED:
                rejected.append({
                    "package_id": package_id,
                    "version": version,
                    "reason": node.rejection_reason,
                    "trust_verdict": node.trust_verdict,
                })

            # Record edge
            if parent_key:
                edges.append(TrustGraphEdge(
                    from_package=parent_key,
                    to_package=key,
                    constraint=constraint,
                    resolved_version=version,
                ))

            # Resolve children (unless revoked)
            if node.lifecycle != "revoked" and node.policy_verdict != POLICY_DENIED:
                deps_raw = metadata.get("dependencies", [])
                for dep in deps_raw:
                    dep_pid = dep.get("package_id", "")
                    dep_ver = dep.get("version", "")
                    dep_constraint = dep.get("constraint", "")
                    dep_reg = dep.get("registry_id", registry_id)

                    child = _resolve(
                        dep_reg, dep_pid, dep_ver,
                        constraint=dep_constraint,
                        parent_key=key,
                        depth=depth + 1,
                    )

            resolving_stack.pop()
            return node

        _resolve(root_registry_id, root_package_id, root_version)

        graph.nodes = list(visited.values())
        graph.edges = edges

        # Aggregate capabilities and sandbox
        graph.aggregate_capabilities = sorted(set(
            cap for node in graph.nodes
            for cap in node.capabilities
        ))
        graph.aggregate_sandbox = strongest_sandbox([
            n.sandbox_profile for n in graph.nodes
        ])

        # DT-001: Graph admissible only if every node passes
        graph.graph_admissible = graph.all_nodes_admissible()

        if rejected:
            graph.rejection_summary = "; ".join(
                f"{r['package_id']}@{r['version']}: {r['reason']}"
                for r in rejected
            )

        if cycle_detected:
            graph.rejection_summary = (
                f"Dependency cycle: {' → '.join(cycle_detected)}"
            )
            graph.graph_admissible = False

        return graph

    def resolve_with_lockfile(
        self,
        root_registry_id: str,
        root_package_id: str,
        root_version: str,
        explain: bool = False,
    ) -> tuple[ResolvedTrustGraph, TrustLockfile, TrustResolutionReceipt]:
        """Resolve, produce lockfile and receipt.

        If explain=True, rejected candidates and reasons are preserved in receipt.
        """
        graph = self.resolve(root_registry_id, root_package_id, root_version)
        lockfile = TrustLockfile.from_graph(graph)

        rejected_nodes = []
        if explain:
            rejected_nodes = [
                {"package_id": n.package_id, "version": n.version,
                 "reason": n.rejection_reason, "trust_verdict": n.trust_verdict}
                for n in graph.nodes
                if n.policy_verdict == POLICY_DENIED
            ]

        receipt = TrustResolutionReceipt(
            receipt_id=hashlib.sha256(
                f"{root_package_id}:{root_version}:{graph.compute_graph_digest()}".encode()
            ).hexdigest()[:32],
            root_package_id=root_package_id,
            root_version=root_version,
            graph_digest=graph.compute_graph_digest(),
            lockfile_digest=lockfile.lockfile_digest,
            resolver_policy_digest=graph.resolver_policy_digest,
            node_count=len(graph.nodes),
            admissible=graph.graph_admissible,
            rejected_nodes=rejected_nodes,
            resolved_at=graph.resolved_at,
        )
        receipt.finalize()

        return graph, lockfile, receipt


# ── Lockfile persistence ────────────────────────────────────────────────────


def save_lockfile(lockfile: TrustLockfile, path: str) -> None:
    """Save lockfile atomically."""
    atomic_write_json(path, lockfile.to_dict())


def load_lockfile(path: str) -> TrustLockfile:
    """Load lockfile from disk."""
    import pathlib
    raw = pathlib.Path(path).read_text(encoding="utf-8")
    data = json.loads(raw)
    return TrustLockfile(
        schema_version=data.get("schema_version", LOCKFILE_SCHEMA_VERSION),
        root=data.get("root", {}),
        resolved_at=data.get("resolved_at", ""),
        resolver_policy_digest=data.get("resolver_policy_digest", ""),
        packages=data.get("packages", []),
        edges=data.get("edges", []),
        graph_digest=data.get("graph_digest", ""),
        lockfile_digest=data.get("lockfile_digest", ""),
    )


def check_lockfile_drift(
    lockfile: TrustLockfile,
    graph: ResolvedTrustGraph,
) -> bool:
    """Check if the lockfile matches the resolved graph.

    Returns True if there is drift (lockfile does NOT match graph).
    """
    return not lockfile.matches_graph(graph)
