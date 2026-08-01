"""Remote Dependency Resolution and Transitive Trust (v2.2.0).

Resolves remote package dependencies with strict independent verification.
Every dependency must independently pass the full 8-point verification.

Non-negotiable rule:
  root package verified ≠ dependencies trusted
  every dependency must independently verify
  every dependency remains separately revocable
  no dependency execution during install

Design objects:
  RemoteDependencySpec       — single dependency requirement
  RemoteDependencyGraph      — resolved graph of all packages
  RemoteDependencyLockfile   — reproducible locked graph
  DependencyResolutionReceipt — evidence of resolution
  DependencyGraphVerifier    — per-node verification
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_dict(data: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


# ── Dependency Spec ─────────────────────────────────────────────────────────


@dataclass
class RemoteDependencySpec:
    """A single dependency requirement declared in package metadata.

    Fields:
      package_id: Dependency package identifier
      version_constraint: Semantic version constraint (e.g., "1.0.0", ">=1.0.0")
      required: If False, missing dependency is a warning not an error
      expected_publisher_fingerprint: Expected publisher key fingerprint
      expected_capabilities: Capabilities the dependency is allowed to declare
    """
    package_id: str = ""
    version_constraint: str = ""
    required: bool = True
    expected_publisher_fingerprint: str = ""
    expected_capabilities: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_id": self.package_id,
            "version_constraint": self.version_constraint,
            "required": self.required,
            "expected_publisher_fingerprint": self.expected_publisher_fingerprint,
            "expected_capabilities": list(self.expected_capabilities),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RemoteDependencySpec":
        return cls(
            package_id=data.get("package_id", ""),
            version_constraint=data.get("version_constraint", ""),
            required=data.get("required", True),
            expected_publisher_fingerprint=data.get("expected_publisher_fingerprint", ""),
            expected_capabilities=data.get("expected_capabilities", []),
        )


def parse_dependencies(metadata_dict: dict[str, Any]) -> list[RemoteDependencySpec]:
    """Extract dependency specs from package metadata dict.

    Supports both 'dependencies' (list of dicts) and empty/missing.
    """
    deps_raw = metadata_dict.get("dependencies", [])
    return [RemoteDependencySpec.from_dict(d) for d in deps_raw]


# ── Dependency Graph Node ───────────────────────────────────────────────────


@dataclass
class DependencyGraphNode:
    """A node in the resolved dependency graph."""
    package_id: str = ""
    version: str = ""
    remote_url: str = ""
    artifact_digest: str = ""
    metadata_digest: str = ""
    publisher_fingerprint: str = ""
    certification_digest: str = ""
    capabilities: list[str] = field(default_factory=list)
    sandbox_profile: str = ""
    dependencies: list[RemoteDependencySpec] = field(default_factory=list)
    is_root: bool = False
    verified: bool = False
    verification_checks: list[dict[str, Any]] = field(default_factory=list)

    @property
    def key(self) -> str:
        """Unique key for this node in the graph."""
        return f"{self.package_id}@{self.version}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_id": self.package_id,
            "version": self.version,
            "remote_url": self.remote_url,
            "artifact_digest": self.artifact_digest,
            "metadata_digest": self.metadata_digest,
            "publisher_fingerprint": self.publisher_fingerprint,
            "certification_digest": self.certification_digest,
            "capabilities": list(self.capabilities),
            "sandbox_profile": self.sandbox_profile,
            "dependencies": [d.to_dict() for d in self.dependencies],
            "is_root": self.is_root,
            "verified": self.verified,
            "verification_checks": list(self.verification_checks),
        }


# ── Dependency Graph ────────────────────────────────────────────────────────


@dataclass
class RemoteDependencyGraph:
    """A resolved dependency graph.

    Contains all packages (root + dependencies) with their relationships.
    The graph is a DAG — cycles are rejected during resolution.
    """
    nodes: dict[str, DependencyGraphNode] = field(default_factory=dict)
    root_key: str = ""
    resolution_errors: list[str] = field(default_factory=list)
    resolution_warnings: list[str] = field(default_factory=list)

    @property
    def root(self) -> DependencyGraphNode | None:
        if self.root_key and self.root_key in self.nodes:
            return self.nodes[self.root_key]
        return None

    @property
    def all_nodes(self) -> list[DependencyGraphNode]:
        return list(self.nodes.values())

    @property
    def dependency_nodes(self) -> list[DependencyGraphNode]:
        return [n for n in self.nodes.values() if not n.is_root]

    @property
    def all_verified(self) -> bool:
        return all(n.verified for n in self.nodes.values())

    def compute_graph_digest(self) -> str:
        """Compute a deterministic digest of the entire graph."""
        graph_data = {
            "root": self.root_key,
            "nodes": {
                k: {
                    "package_id": n.package_id,
                    "version": n.version,
                    "artifact_digest": n.artifact_digest,
                    "publisher_fingerprint": n.publisher_fingerprint,
                    "dependencies": [d.to_dict() for d in n.dependencies],
                }
                for k, n in sorted(self.nodes.items())
            },
        }
        return _sha256_dict(graph_data)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root_key": self.root_key,
            "nodes": {k: n.to_dict() for k, n in self.nodes.items()},
            "graph_digest": self.compute_graph_digest(),
            "resolution_errors": list(self.resolution_errors),
            "resolution_warnings": list(self.resolution_warnings),
            "node_count": len(self.nodes),
            "dependency_count": len(self.dependency_nodes),
        }


# ── Dependency Lockfile ─────────────────────────────────────────────────────


@dataclass
class RemoteDependencyLockfile:
    """A locked dependency graph for reproducible installs.

    Records the exact versions, digests, and fingerprints of every
    package in the resolved graph. Installing from a lockfile skips
    resolution and verifies exact matches.
    """
    lockfile_type: str = "remote_dependency_lockfile"
    lockfile_version: str = "1.0"
    root_package_id: str = ""
    root_version: str = ""
    remote_url: str = ""
    packages: list[dict[str, Any]] = field(default_factory=list)
    graph_digest: str = ""
    created_at: str = field(default_factory=_now_iso)
    lockfile_digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.lockfile_type,
            "lockfile_version": self.lockfile_version,
            "root_package_id": self.root_package_id,
            "root_version": self.root_version,
            "remote_url": self.remote_url,
            "packages": list(self.packages),
            "graph_digest": self.graph_digest,
            "created_at": self.created_at,
            "lockfile_digest": self.lockfile_digest,
        }

    def compute_digest(self) -> str:
        data = self.to_dict()
        del data["lockfile_digest"]
        return _sha256_dict(data)

    def finalize(self) -> "RemoteDependencyLockfile":
        self.lockfile_digest = self.compute_digest()
        return self

    @classmethod
    def from_graph(cls, graph: RemoteDependencyGraph) -> "RemoteDependencyLockfile":
        """Create a lockfile from a resolved graph."""
        packages = []
        for node in sorted(graph.all_nodes, key=lambda n: n.key):
            packages.append({
                "package_id": node.package_id,
                "version": node.version,
                "remote_url": node.remote_url,
                "artifact_digest": node.artifact_digest,
                "metadata_digest": node.metadata_digest,
                "publisher_fingerprint": node.publisher_fingerprint,
                "certification_digest": node.certification_digest,
                "capabilities": list(node.capabilities),
                "sandbox_profile": node.sandbox_profile,
                "is_root": node.is_root,
                "dependencies": [d.to_dict() for d in node.dependencies],
            })

        root = graph.root
        lf = cls(
            root_package_id=root.package_id if root else "",
            root_version=root.version if root else "",
            remote_url=root.remote_url if root else "",
            packages=packages,
            graph_digest=graph.compute_graph_digest(),
        )
        return lf.finalize()


# ── Resolution Receipt ──────────────────────────────────────────────────────


@dataclass
class DependencyResolutionReceipt:
    """Evidence of a resolved and verified dependency graph."""
    receipt_type: str = "dependency_resolution_receipt"
    receipt_id: str = ""
    root_package_id: str = ""
    root_version: str = ""
    remote_url: str = ""
    graph_digest: str = ""
    lockfile_digest: str = ""
    node_count: int = 0
    dependency_count: int = 0
    all_verified: bool = False
    per_package_receipts: list[dict[str, Any]] = field(default_factory=list)
    resolution_errors: list[str] = field(default_factory=list)
    resolution_warnings: list[str] = field(default_factory=list)
    resolved_at: str = field(default_factory=_now_iso)
    receipt_digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.receipt_type,
            "receipt_id": self.receipt_id,
            "root_package_id": self.root_package_id,
            "root_version": self.root_version,
            "remote_url": self.remote_url,
            "graph_digest": self.graph_digest,
            "lockfile_digest": self.lockfile_digest,
            "node_count": self.node_count,
            "dependency_count": self.dependency_count,
            "all_verified": self.all_verified,
            "per_package_receipts": list(self.per_package_receipts),
            "resolution_errors": list(self.resolution_errors),
            "resolution_warnings": list(self.resolution_warnings),
            "resolved_at": self.resolved_at,
            "receipt_digest": self.receipt_digest,
        }

    def compute_digest(self) -> str:
        data = self.to_dict()
        del data["receipt_digest"]
        return _sha256_dict(data)

    def finalize(self) -> "DependencyResolutionReceipt":
        self.receipt_digest = self.compute_digest()
        return self


# ── Dependency Resolver ─────────────────────────────────────────────────────


class DependencyResolutionError(Exception):
    """Raised when dependency resolution fails."""
    pass


class DependencyCycleError(DependencyResolutionError):
    """Raised when a dependency cycle is detected."""
    def __init__(self, cycle_path: list[str]):
        self.cycle_path = cycle_path
        super().__init__(f"Dependency cycle detected: {' → '.join(cycle_path)}")


class DependencyConflictError(DependencyResolutionError):
    """Raised when conflicting versions are required."""
    def __init__(self, package_id: str, versions: list[str]):
        self.package_id = package_id
        self.versions = versions
        super().__init__(
            f"Version conflict for '{package_id}': required versions {versions}"
        )


def resolve_dependencies(
    root_package_id: str,
    root_version: str,
    remote_url: str,
    fetch_metadata_fn: Any,
    fetch_artifact_fn: Any = None,
    max_depth: int = 16,
    strict: bool = True,
) -> RemoteDependencyGraph:
    """Resolve a package and all its dependencies.

    Args:
        root_package_id: Root package to resolve.
        root_version: Root package version.
        remote_url: Remote registry URL.
        fetch_metadata_fn: Callable(package_id, version) -> metadata dict.
        fetch_artifact_fn: Optional callable(package_id, version) -> bytes.
        max_depth: Maximum resolution depth (prevents infinite loops).
        strict: If True (default), cycles are hard errors. If False, warnings.

    Returns:
        RemoteDependencyGraph with all nodes resolved.

    Raises:
        DependencyCycleError: If a cycle is detected in strict mode.
        DependencyConflictError: If version conflicts exist.
        DependencyResolutionError: If resolution fails.
    """
    graph = RemoteDependencyGraph()
    _resolve_recursive(
        graph, root_package_id, root_version, remote_url,
        fetch_metadata_fn, set(), [], max_depth, is_root=True,
        strict=strict,
    )
    return graph


def _resolve_recursive(
    graph: RemoteDependencyGraph,
    package_id: str,
    version: str,
    remote_url: str,
    fetch_metadata_fn: Any,
    visiting: set[str],
    path: list[str],
    max_depth: int,
    is_root: bool = False,
    strict: bool = True,
) -> str:
    """Recursively resolve a package and its dependencies.

    Returns the graph key for this node.
    """
    key = f"{package_id}@{version}"

    # Cycle detection
    if key in visiting:
        cycle = path + [key]
        cycle_str = ' → '.join(cycle)
        if strict:
            # Fail closed: cycle is a hard error
            graph.resolution_errors.append(f"Dependency cycle detected: {cycle_str}")
            raise DependencyCycleError(cycle)
        else:
            graph.resolution_warnings.append(f"Dependency cycle detected: {cycle_str}")
            return key

    # Already resolved?
    if key in graph.nodes:
        return key

    # Depth check
    if len(path) >= max_depth:
        graph.resolution_errors.append(
            f"Max dependency depth ({max_depth}) exceeded at {key}"
        )
        return key

    # Fetch metadata
    try:
        metadata = fetch_metadata_fn(package_id, version)
    except Exception as e:
        graph.resolution_errors.append(f"Failed to fetch metadata for {key}: {e}")
        # Create a placeholder node
        node = DependencyGraphNode(
            package_id=package_id, version=version, remote_url=remote_url,
            is_root=is_root, verified=False,
            verification_checks=[{"check": "metadata_fetch", "passed": False, "detail": str(e)}],
        )
        graph.nodes[key] = node
        if is_root:
            graph.root_key = key
        return key

    # Check for version conflict with existing nodes of same package_id
    for existing_key, existing_node in graph.nodes.items():
        if existing_node.package_id == package_id and existing_node.version != version:
            graph.resolution_errors.append(
                f"Version conflict: '{package_id}' required as both {existing_node.version} and {version}"
            )
            # Don't raise — collect errors and report at end

    # Build node
    node = DependencyGraphNode(
        package_id=package_id,
        version=version,
        remote_url=remote_url,
        artifact_digest=metadata.get("artifact_digest", ""),
        metadata_digest=metadata.get("metadata_digest", ""),
        publisher_fingerprint=metadata.get("publisher_fingerprint", ""),
        certification_digest=metadata.get("certification_digest", ""),
        capabilities=metadata.get("capabilities", []),
        sandbox_profile=metadata.get("sandbox_profile", ""),
        dependencies=parse_dependencies(metadata),
        is_root=is_root,
    )
    graph.nodes[key] = node
    if is_root:
        graph.root_key = key

    # Recursively resolve dependencies
    visiting.add(key)
    for dep in node.dependencies:
        dep_version = dep.version_constraint or "latest"
        _resolve_recursive(
            graph, dep.package_id, dep_version, remote_url,
            fetch_metadata_fn, visiting, path + [key], max_depth,
            strict=strict,
        )
    visiting.discard(key)

    return key


# ── Graph Verifier ──────────────────────────────────────────────────────────


def verify_dependency_graph(
    graph: RemoteDependencyGraph,
    verify_fn: Any,
) -> list[dict[str, Any]]:
    """Verify every node in the dependency graph.

    Args:
        graph: The resolved dependency graph.
        verify_fn: Callable(node) -> list[VerificationCheck].

    Returns:
        List of per-node verification results.
    """
    results = []
    for key, node in graph.nodes.items():
        checks = verify_fn(node)
        node.verification_checks = [c.to_dict() if hasattr(c, 'to_dict') else c for c in checks]
        node.verified = all(
            (c.passed if hasattr(c, 'passed') else c.get("passed", False))
            for c in checks
        )
        results.append({
            "package_id": node.package_id,
            "version": node.version,
            "key": key,
            "verified": node.verified,
            "checks": node.verification_checks,
        })
    return results


def verify_dependency_bounds(
    parent: DependencyGraphNode,
    child: DependencyGraphNode,
    dep_spec: RemoteDependencySpec,
) -> list[dict[str, Any]]:
    """Verify a dependency stays within bounds declared by its parent.

    Checks:
      1. Publisher fingerprint matches expected (if specified)
      2. Capabilities are within parent-declared bounds (if specified)
      3. Sandbox profile is not weaker than parent's
    """
    violations = []

    # Check 1: Publisher fingerprint
    if dep_spec.expected_publisher_fingerprint:
        if child.publisher_fingerprint != dep_spec.expected_publisher_fingerprint:
            violations.append({
                "check": "dependency_publisher_match",
                "passed": False,
                "detail": f"Expected fingerprint {dep_spec.expected_publisher_fingerprint[:12]}..., "
                          f"got {child.publisher_fingerprint[:12]}...",
            })
    else:
        violations.append({
            "check": "dependency_publisher_match",
            "passed": True,
            "detail": "No expected fingerprint specified",
        })

    # Check 2: Capabilities within bounds
    if dep_spec.expected_capabilities:
        child_caps = set(child.capabilities)
        expected_caps = set(dep_spec.expected_capabilities)
        unexpected = child_caps - expected_caps
        if unexpected:
            violations.append({
                "check": "dependency_capabilities_within_bounds",
                "passed": False,
                "detail": f"Unexpected capabilities: {unexpected}",
            })
        else:
            violations.append({
                "check": "dependency_capabilities_within_bounds",
                "passed": True,
                "detail": "All capabilities within bounds",
            })
    else:
        violations.append({
            "check": "dependency_capabilities_within_bounds",
            "passed": True,
            "detail": "No capability bounds specified",
        })

    # Check 3: Sandbox not weaker than parent
    SANDBOX_STRENGTH = {"none": 0, "minimal": 1, "standard_untrusted": 2,
                         "production_untrusted": 3, "hardened_untrusted": 4}
    # Check 3: Sandbox not weaker than parent (graph-wide, not just root)
    # DEP-FINDING-002 fix: apply graph-wide, not just when parent.is_root
    parent_strength = SANDBOX_STRENGTH.get(parent.sandbox_profile, 0)
    child_strength = SANDBOX_STRENGTH.get(child.sandbox_profile, 0)
    # Remote untrusted floor: every dependency must be at least standard_untrusted
    remote_untrusted_floor = SANDBOX_STRENGTH.get("standard_untrusted", 2)
    effective_floor = max(parent_strength, remote_untrusted_floor)
    if child_strength < effective_floor:
        violations.append({
            "check": "dependency_sandbox_not_weaker",
            "passed": False,
            "detail": f"Dependency sandbox '{child.sandbox_profile}' weaker than "
                      f"effective floor ({effective_floor}, parent={parent.sandbox_profile})",
        })
    else:
        violations.append({
            "check": "dependency_sandbox_not_weaker",
            "passed": True,
            "detail": f"Dependency sandbox '{child.sandbox_profile}' OK",
        })

    return violations


# ── Full Resolution + Verification + Lockfile ───────────────────────────────


def resolve_and_verify(
    root_package_id: str,
    root_version: str,
    remote_url: str,
    fetch_metadata_fn: Any,
    verify_node_fn: Any,
    fetch_artifact_fn: Any = None,
) -> tuple[RemoteDependencyGraph, DependencyResolutionReceipt, RemoteDependencyLockfile]:
    """Full resolution + verification + lockfile generation.

    This is the main entry point for `install --with-dependencies`.

    Returns:
        (graph, receipt, lockfile)
    """
    # Step 1: Resolve
    graph = resolve_dependencies(
        root_package_id=root_package_id,
        root_version=root_version,
        remote_url=remote_url,
        fetch_metadata_fn=fetch_metadata_fn,
        fetch_artifact_fn=fetch_artifact_fn,
    )

    # Step 2: Verify each node
    verify_dependency_graph(graph, verify_node_fn)

    # Step 3: Verify dependency bounds
    for node in graph.all_nodes:
        for dep in node.dependencies:
            dep_key = f"{dep.package_id}@{dep.version_constraint or 'latest'}"
            if dep_key in graph.nodes:
                bound_checks = verify_dependency_bounds(node, graph.nodes[dep_key], dep)
                node.verification_checks.extend(bound_checks)
                if not all(c.get("passed", False) for c in bound_checks):
                    node.verified = False

    # Step 4: Build lockfile
    lockfile = RemoteDependencyLockfile.from_graph(graph)

    # Step 5: Build receipt
    root = graph.root
    receipt = DependencyResolutionReceipt(
        receipt_id=str(uuid.uuid4()),
        root_package_id=root_package_id,
        root_version=root_version,
        remote_url=remote_url,
        graph_digest=graph.compute_graph_digest(),
        lockfile_digest=lockfile.lockfile_digest,
        node_count=len(graph.nodes),
        dependency_count=len(graph.dependency_nodes),
        all_verified=graph.all_verified,
        per_package_receipts=[
            {
                "package_id": n.package_id,
                "version": n.version,
                "verified": n.verified,
                "check_count": len(n.verification_checks),
            }
            for n in graph.all_nodes
        ],
        resolution_errors=list(graph.resolution_errors),
        resolution_warnings=list(graph.resolution_warnings),
    ).finalize()

    return graph, receipt, lockfile
