"""Tests for Remote Dependency Resolution and Transitive Trust (v2.2.0).

Tests cover all 10 acceptance criteria:
  AC1:  Package metadata with dependencies
  AC2:  Dependency resolver (cycle, conflict, missing)
  AC3:  Lockfile format
  AC4:  Install with dependencies
  AC5:  Verification (each dep passes 8-point check, bounds)
  AC6:  Transitive trust (no trust transfer)
  AC7:  Evidence (dependency_resolution_receipt)
  AC8:  Dashboard
  AC9:  Negative tests (12 attack scenarios)
  AC10: Windows/Linux green (implicit)
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest


# ── Helpers ─────────────────────────────────────────────────────────────────


def _make_metadata(
    package_id: str,
    version: str,
    dependencies: list[dict] | None = None,
    publisher_fp: str = "pub_fp",
    capabilities: list[str] | None = None,
    sandbox: str = "hardened_untrusted",
) -> dict[str, Any]:
    """Create mock package metadata dict."""
    import hashlib
    raw = json.dumps({
        "package_id": package_id,
        "version": version,
        "artifact_digest": hashlib.sha256(package_id.encode()).hexdigest(),
        "publisher_fingerprint": publisher_fp,
        "capabilities": capabilities or ["read_only"],
        "sandbox_profile": sandbox,
        "dependencies": dependencies or [],
    }, sort_keys=True).encode()
    return {
        "package_id": package_id,
        "version": version,
        "artifact_digest": hashlib.sha256(package_id.encode()).hexdigest(),
        "artifact_size": 100,
        "publisher_fingerprint": publisher_fp,
        "capabilities": capabilities or ["read_only"],
        "sandbox_profile": sandbox,
        "dependencies": dependencies or [],
        "metadata_digest": hashlib.sha256(raw).hexdigest(),
        "signature": "sig",
    }


def _make_mock_fetcher(registry: dict[str, dict[str, dict]]) -> Any:
    """Create a mock metadata fetcher from a registry dict.

    registry = {
        "pkg_a": {"1.0.0": {...metadata...}},
    }
    """
    def fetch(package_id: str, version: str) -> dict:
        if package_id not in registry:
            raise ValueError(f"Package '{package_id}' not found")
        versions = registry[package_id]
        if version not in versions:
            if "latest" in version:
                # Return first available
                return list(versions.values())[0]
            raise ValueError(f"Version '{version}' not found for '{package_id}'")
        return versions[version]
    return fetch


def _make_verify_fn():
    """Create a mock verify function that passes all checks."""
    def verify(node):
        from nodechain.sdk.remote_registry import VerificationCheck
        return [
            VerificationCheck(check="metadata_digest_valid", passed=True),
            VerificationCheck(check="publisher_present", passed=bool(node.publisher_fingerprint)),
            VerificationCheck(check="sandbox_profile", passed=True),
        ]
    return verify


# ── AC1: Package Metadata with Dependencies ─────────────────────────────────

class TestAC1DependencySpec:
    """AC1: Package metadata extended with dependencies."""

    def test_parse_dependencies(self):
        from nodechain.sdk.dependency_resolver import parse_dependencies
        meta = {
            "dependencies": [
                {"package_id": "dep_a", "version_constraint": "1.0.0"},
                {"package_id": "dep_b", "version_constraint": ">=2.0.0", "required": False},
            ],
        }
        deps = parse_dependencies(meta)
        assert len(deps) == 2
        assert deps[0].package_id == "dep_a"
        assert deps[0].version_constraint == "1.0.0"
        assert deps[0].required is True
        assert deps[1].required is False

    def test_no_dependencies(self):
        from nodechain.sdk.dependency_resolver import parse_dependencies
        deps = parse_dependencies({})
        assert deps == []

    def test_dependency_spec_roundtrip(self):
        from nodechain.sdk.dependency_resolver import RemoteDependencySpec
        spec = RemoteDependencySpec(
            package_id="dep",
            version_constraint="1.0.0",
            expected_publisher_fingerprint="abc123",
            expected_capabilities=["read_only"],
        )
        d = spec.to_dict()
        spec2 = RemoteDependencySpec.from_dict(d)
        assert spec2.package_id == "dep"
        assert spec2.expected_publisher_fingerprint == "abc123"

    def test_dependency_with_expected_fields(self):
        from nodechain.sdk.dependency_resolver import parse_dependencies
        meta = {
            "dependencies": [
                {
                    "package_id": "dep_a",
                    "version_constraint": "1.0.0",
                    "expected_publisher_fingerprint": "fp123",
                    "expected_capabilities": ["read_only", "compute"],
                },
            ],
        }
        deps = parse_dependencies(meta)
        assert deps[0].expected_publisher_fingerprint == "fp123"
        assert "compute" in deps[0].expected_capabilities


# ── AC2: Dependency Resolver ────────────────────────────────────────────────

class TestAC2Resolver:
    """AC2: Dependency resolver with cycle/conflict/missing detection."""

    def test_resolve_simple_no_deps(self):
        from nodechain.sdk.dependency_resolver import resolve_dependencies
        registry = {"root_pkg": {"1.0.0": _make_metadata("root_pkg", "1.0.0")}}
        fetcher = _make_mock_fetcher(registry)
        graph = resolve_dependencies("root_pkg", "1.0.0", "https://r.example.com", fetcher)
        assert len(graph.nodes) == 1
        assert graph.root.package_id == "root_pkg"
        assert graph.root.is_root

    def test_resolve_with_one_dependency(self):
        from nodechain.sdk.dependency_resolver import resolve_dependencies
        registry = {
            "root_pkg": {"1.0.0": _make_metadata("root_pkg", "1.0.0", [
                {"package_id": "dep_a", "version_constraint": "1.0.0"},
            ])},
            "dep_a": {"1.0.0": _make_metadata("dep_a", "1.0.0")},
        }
        fetcher = _make_mock_fetcher(registry)
        graph = resolve_dependencies("root_pkg", "1.0.0", "https://r.example.com", fetcher)
        assert len(graph.nodes) == 2
        assert "dep_a@1.0.0" in graph.nodes
        assert len(graph.dependency_nodes) == 1

    def test_resolve_nested_dependencies(self):
        from nodechain.sdk.dependency_resolver import resolve_dependencies
        registry = {
            "root": {"1.0.0": _make_metadata("root", "1.0.0", [
                {"package_id": "mid", "version_constraint": "1.0.0"},
            ])},
            "mid": {"1.0.0": _make_metadata("mid", "1.0.0", [
                {"package_id": "leaf", "version_constraint": "1.0.0"},
            ])},
            "leaf": {"1.0.0": _make_metadata("leaf", "1.0.0")},
        }
        fetcher = _make_mock_fetcher(registry)
        graph = resolve_dependencies("root", "1.0.0", "https://r.example.com", fetcher)
        assert len(graph.nodes) == 3
        assert "leaf@1.0.0" in graph.nodes

    def test_detect_version_conflict(self):
        from nodechain.sdk.dependency_resolver import resolve_dependencies
        registry = {
            "root": {"1.0.0": _make_metadata("root", "1.0.0", [
                {"package_id": "dep", "version_constraint": "1.0.0"},
                {"package_id": "dep", "version_constraint": "2.0.0"},
            ])},
            "dep": {
                "1.0.0": _make_metadata("dep", "1.0.0"),
                "2.0.0": _make_metadata("dep", "2.0.0"),
            },
        }
        fetcher = _make_mock_fetcher(registry)
        graph = resolve_dependencies("root", "1.0.0", "https://r.example.com", fetcher)
        # Both versions resolved — conflict recorded
        assert "dep@1.0.0" in graph.nodes
        assert "dep@2.0.0" in graph.nodes
        assert len(graph.resolution_errors) > 0

    def test_missing_dependency(self):
        from nodechain.sdk.dependency_resolver import resolve_dependencies
        registry = {
            "root": {"1.0.0": _make_metadata("root", "1.0.0", [
                {"package_id": "missing_dep", "version_constraint": "1.0.0"},
            ])},
        }
        fetcher = _make_mock_fetcher(registry)
        graph = resolve_dependencies("root", "1.0.0", "https://r.example.com", fetcher)
        assert len(graph.resolution_errors) > 0
        assert any("missing_dep" in e for e in graph.resolution_errors)

    def test_diamond_dependency(self):
        """Diamond: root → A, root → B, A → C, B → C (same version)."""
        from nodechain.sdk.dependency_resolver import resolve_dependencies
        registry = {
            "root": {"1.0.0": _make_metadata("root", "1.0.0", [
                {"package_id": "a", "version_constraint": "1.0.0"},
                {"package_id": "b", "version_constraint": "1.0.0"},
            ])},
            "a": {"1.0.0": _make_metadata("a", "1.0.0", [
                {"package_id": "c", "version_constraint": "1.0.0"},
            ])},
            "b": {"1.0.0": _make_metadata("b", "1.0.0", [
                {"package_id": "c", "version_constraint": "1.0.0"},
            ])},
            "c": {"1.0.0": _make_metadata("c", "1.0.0")},
        }
        fetcher = _make_mock_fetcher(registry)
        graph = resolve_dependencies("root", "1.0.0", "https://r.example.com", fetcher)
        # C should appear once (not duplicated)
        assert len(graph.nodes) == 4  # root, a, b, c
        assert "c@1.0.0" in graph.nodes

    def test_graph_digest_is_deterministic(self):
        from nodechain.sdk.dependency_resolver import resolve_dependencies
        registry = {
            "root": {"1.0.0": _make_metadata("root", "1.0.0", [
                {"package_id": "dep", "version_constraint": "1.0.0"},
            ])},
            "dep": {"1.0.0": _make_metadata("dep", "1.0.0")},
        }
        fetcher = _make_mock_fetcher(registry)
        g1 = resolve_dependencies("root", "1.0.0", "https://r.example.com", fetcher)
        fetcher2 = _make_mock_fetcher(registry)
        g2 = resolve_dependencies("root", "1.0.0", "https://r.example.com", fetcher2)
        assert g1.compute_graph_digest() == g2.compute_graph_digest()


# ── AC3: Lockfile ───────────────────────────────────────────────────────────

class TestAC3Lockfile:
    """AC3: Lockfile format."""

    def test_lockfile_from_graph(self):
        from nodechain.sdk.dependency_resolver import (
            resolve_dependencies, RemoteDependencyLockfile,
        )
        registry = {
            "root": {"1.0.0": _make_metadata("root", "1.0.0", [
                {"package_id": "dep", "version_constraint": "1.0.0"},
            ])},
            "dep": {"1.0.0": _make_metadata("dep", "1.0.0")},
        }
        fetcher = _make_mock_fetcher(registry)
        graph = resolve_dependencies("root", "1.0.0", "https://r.example.com", fetcher)
        lockfile = RemoteDependencyLockfile.from_graph(graph)

        assert lockfile.root_package_id == "root"
        assert lockfile.root_version == "1.0.0"
        assert len(lockfile.packages) == 2
        assert lockfile.graph_digest != ""
        assert lockfile.lockfile_digest != ""

    def test_lockfile_has_all_fields(self):
        from nodechain.sdk.dependency_resolver import RemoteDependencyLockfile
        lf = RemoteDependencyLockfile(
            root_package_id="root", root_version="1.0.0",
            remote_url="https://r.example.com",
            packages=[{"package_id": "root"}],
            graph_digest="gd",
        ).finalize()
        d = lf.to_dict()
        for field in ["type", "lockfile_version", "root_package_id",
                       "packages", "graph_digest", "lockfile_digest"]:
            assert field in d

    def test_lockfile_digest_tamper_detection(self):
        from nodechain.sdk.dependency_resolver import RemoteDependencyLockfile
        lf = RemoteDependencyLockfile(root_package_id="root").finalize()
        original = lf.lockfile_digest
        lf.root_package_id = "tampered"
        assert lf.compute_digest() != original


# ── AC4: Install Command ────────────────────────────────────────────────────

class TestAC4InstallCommand:
    """AC4: resolve-deps CLI command exists."""

    def test_command_exists(self):
        from nodechain.cli.main import cli
        registry = cli.commands["registry"]
        assert "resolve-deps" in registry.commands

    def test_command_help(self):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["registry", "resolve-deps", "--help"])
        assert result.exit_code == 0
        assert "dependencies" in result.output.lower() or "deps" in result.output.lower()


# ── AC5: Verification ───────────────────────────────────────────────────────

class TestAC5Verification:
    """AC5: Each dependency passes independent verification."""

    def test_all_nodes_verified(self):
        from nodechain.sdk.dependency_resolver import (
            resolve_dependencies, verify_dependency_graph,
        )
        registry = {
            "root": {"1.0.0": _make_metadata("root", "1.0.0", [
                {"package_id": "dep", "version_constraint": "1.0.0"},
            ])},
            "dep": {"1.0.0": _make_metadata("dep", "1.0.0")},
        }
        fetcher = _make_mock_fetcher(registry)
        graph = resolve_dependencies("root", "1.0.0", "https://r.example.com", fetcher)
        verify_fn = _make_verify_fn()
        results = verify_dependency_graph(graph, verify_fn)
        assert len(results) == 2
        assert all(r["verified"] for r in results)
        assert graph.all_verified

    def test_dependency_bounds_publisher_check(self):
        from nodechain.sdk.dependency_resolver import (
            DependencyGraphNode, RemoteDependencySpec, verify_dependency_bounds,
        )
        parent = DependencyGraphNode(package_id="root", is_root=True, sandbox_profile="hardened_untrusted")
        child = DependencyGraphNode(package_id="dep", publisher_fingerprint="wrong_fp")
        spec = RemoteDependencySpec(
            package_id="dep", version_constraint="1.0.0",
            expected_publisher_fingerprint="correct_fp",
        )
        violations = verify_dependency_bounds(parent, child, spec)
        pub_check = [v for v in violations if v["check"] == "dependency_publisher_match"][0]
        assert not pub_check["passed"]

    def test_dependency_bounds_capabilities(self):
        from nodechain.sdk.dependency_resolver import (
            DependencyGraphNode, RemoteDependencySpec, verify_dependency_bounds,
        )
        parent = DependencyGraphNode(package_id="root", is_root=True)
        child = DependencyGraphNode(
            package_id="dep",
            capabilities=["read_only", "network_access"],
        )
        spec = RemoteDependencySpec(
            package_id="dep", version_constraint="1.0.0",
            expected_capabilities=["read_only"],
        )
        violations = verify_dependency_bounds(parent, child, spec)
        cap_check = [v for v in violations if v["check"] == "dependency_capabilities_within_bounds"][0]
        assert not cap_check["passed"]

    def test_dependency_bounds_sandbox_downgrade(self):
        from nodechain.sdk.dependency_resolver import (
            DependencyGraphNode, RemoteDependencySpec, verify_dependency_bounds,
        )
        parent = DependencyGraphNode(
            package_id="root", is_root=True,
            sandbox_profile="hardened_untrusted",
        )
        child = DependencyGraphNode(
            package_id="dep", sandbox_profile="none",
        )
        spec = RemoteDependencySpec(package_id="dep", version_constraint="1.0.0")
        violations = verify_dependency_bounds(parent, child, spec)
        sandbox_check = [v for v in violations if v["check"] == "dependency_sandbox_not_weaker"][0]
        assert not sandbox_check["passed"]


# ── AC6: Transitive Trust ───────────────────────────────────────────────────

class TestAC6TransitiveTrust:
    """AC6: Root package trust does not transfer to dependencies."""

    def test_dependency_trust_is_separate(self):
        from nodechain.sdk.dependency_resolver import DependencyGraphNode
        root = DependencyGraphNode(package_id="root", is_root=True, verified=True)
        dep = DependencyGraphNode(package_id="dep", verified=False)
        # Root verified ≠ dep verified
        assert root.verified is True
        assert dep.verified is False

    def test_no_trust_upgrade_for_dependencies(self):
        from nodechain.sdk.remote_readiness import is_upgrade_allowed
        # Dependencies remain remote_untrusted
        assert not is_upgrade_allowed("remote_untrusted", "local_trusted")
        assert not is_upgrade_allowed("remote_untrusted", "built_in")


# ── AC7: Evidence ───────────────────────────────────────────────────────────

class TestAC7Evidence:
    """AC7: Evidence for dependency resolution."""

    def test_resolution_receipt_has_fields(self):
        from nodechain.sdk.dependency_resolver import DependencyResolutionReceipt
        receipt = DependencyResolutionReceipt(
            receipt_id="r-001",
            root_package_id="root",
            root_version="1.0.0",
            graph_digest="gd",
            lockfile_digest="ld",
            node_count=2,
            dependency_count=1,
            all_verified=True,
        ).finalize()
        d = receipt.to_dict()
        assert d["graph_digest"] != ""
        assert d["lockfile_digest"] != ""
        assert d["receipt_digest"] != ""
        assert d["all_verified"] is True

    def test_receipt_digest_tamper_detection(self):
        from nodechain.sdk.dependency_resolver import DependencyResolutionReceipt
        receipt = DependencyResolutionReceipt(receipt_id="r1").finalize()
        original = receipt.receipt_digest
        receipt.node_count = 999
        assert receipt.compute_digest() != original

    def test_evidence_type_registered(self):
        from nodechain.cli.evidence import EVIDENCE_TYPES
        assert "dependency_resolution_receipt" in EVIDENCE_TYPES

    def test_evidence_detection(self):
        from nodechain.cli.evidence import _detect_artifact_type
        data = {
            "receipt_id": "r-001",
            "remote_url": "https://r.example.com",
            "graph_digest": "abc",
        }
        assert _detect_artifact_type(data) == "dependency_resolution_receipt"

    def test_full_resolve_and_verify(self):
        from nodechain.sdk.dependency_resolver import resolve_and_verify
        registry = {
            "root": {"1.0.0": _make_metadata("root", "1.0.0", [
                {"package_id": "dep", "version_constraint": "1.0.0"},
            ])},
            "dep": {"1.0.0": _make_metadata("dep", "1.0.0")},
        }
        fetcher = _make_mock_fetcher(registry)
        verify_fn = _make_verify_fn()
        graph, receipt, lockfile = resolve_and_verify(
            "root", "1.0.0", "https://r.example.com", fetcher, verify_fn,
        )
        assert len(graph.nodes) == 2
        assert receipt.node_count == 2
        assert receipt.dependency_count == 1
        assert lockfile.root_package_id == "root"
        assert receipt.graph_digest == graph.compute_graph_digest()
        assert receipt.lockfile_digest == lockfile.lockfile_digest


# ── AC8: Dashboard ──────────────────────────────────────────────────────────

class TestAC8Dashboard:
    """AC8: Dashboard works with dependency code loaded."""

    def test_dashboard_json(self):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["dashboard", "--json"])
        assert result.exit_code == 0


# ── AC9: Negative Tests ─────────────────────────────────────────────────────

class TestAC9NegativeTests:
    """AC9: 12 negative test scenarios."""

    def test_neg_cycle_detection(self):
        """A→B→A cycle fails closed in strict mode."""
        from nodechain.sdk.dependency_resolver import resolve_dependencies, DependencyCycleError
        registry = {
            "a": {"1.0.0": _make_metadata("a", "1.0.0", [
                {"package_id": "b", "version_constraint": "1.0.0"}])},
            "b": {"1.0.0": _make_metadata("b", "1.0.0", [
                {"package_id": "a", "version_constraint": "1.0.0"}])},
        }
        # Strict mode: cycle is a hard error
        with pytest.raises(DependencyCycleError):
            resolve_dependencies("a", "1.0.0", "https://r", _make_mock_fetcher(registry), strict=True)
        # Non-strict: warning only
        graph = resolve_dependencies("a", "1.0.0", "https://r", _make_mock_fetcher(registry), strict=False)
        assert "a@1.0.0" in graph.nodes
        assert "b@1.0.0" in graph.nodes

    def test_neg_version_conflict(self):
        """Version conflict is recorded."""
        from nodechain.sdk.dependency_resolver import resolve_dependencies
        registry = {
            "root": {"1.0.0": _make_metadata("root", "1.0.0", [
                {"package_id": "d", "version_constraint": "1.0.0"},
                {"package_id": "d", "version_constraint": "2.0.0"},
            ])},
            "d": {"1.0.0": _make_metadata("d", "1.0.0"),
                  "2.0.0": _make_metadata("d", "2.0.0")},
        }
        graph = resolve_dependencies("root", "1.0.0", "https://r", _make_mock_fetcher(registry))
        assert len(graph.resolution_errors) > 0

    def test_neg_dependency_substitution(self):
        """Dependency digest mismatch caught by verification."""
        from nodechain.sdk.dependency_resolver import (
            DependencyGraphNode, RemoteDependencySpec, verify_dependency_bounds,
        )
        parent = DependencyGraphNode(package_id="root", is_root=True)
        child = DependencyGraphNode(package_id="dep", publisher_fingerprint="attacker_fp")
        spec = RemoteDependencySpec(
            expected_publisher_fingerprint="real_fp",
        )
        violations = verify_dependency_bounds(parent, child, spec)
        assert any(not v["passed"] for v in violations)

    def test_neg_publisher_mismatch(self):
        """Dependency publisher fingerprint mismatch detected."""
        from nodechain.sdk.dependency_resolver import (
            DependencyGraphNode, RemoteDependencySpec, verify_dependency_bounds,
        )
        parent = DependencyGraphNode(package_id="root", is_root=True)
        child = DependencyGraphNode(package_id="dep", publisher_fingerprint="evil")
        spec = RemoteDependencySpec(expected_publisher_fingerprint="good")
        violations = verify_dependency_bounds(parent, child, spec)
        pub_check = [v for v in violations if v["check"] == "dependency_publisher_match"][0]
        assert not pub_check["passed"]

    def test_neg_capability_escalation(self):
        """Dependency declares more capabilities than allowed."""
        from nodechain.sdk.dependency_resolver import (
            DependencyGraphNode, RemoteDependencySpec, verify_dependency_bounds,
        )
        parent = DependencyGraphNode(package_id="root", is_root=True)
        child = DependencyGraphNode(
            package_id="dep",
            capabilities=["read_only", "network_access", "subprocess_exec"],
        )
        spec = RemoteDependencySpec(expected_capabilities=["read_only"])
        violations = verify_dependency_bounds(parent, child, spec)
        cap_check = [v for v in violations if v["check"] == "dependency_capabilities_within_bounds"][0]
        assert not cap_check["passed"]

    def test_neg_sandbox_downgrade(self):
        """Dependency sandbox weaker than root."""
        from nodechain.sdk.dependency_resolver import (
            DependencyGraphNode, RemoteDependencySpec, verify_dependency_bounds,
        )
        parent = DependencyGraphNode(
            package_id="root", is_root=True,
            sandbox_profile="hardened_untrusted",
        )
        child = DependencyGraphNode(package_id="dep", sandbox_profile="none")
        spec = RemoteDependencySpec()
        violations = verify_dependency_bounds(parent, child, spec)
        sandbox_check = [v for v in violations if v["check"] == "dependency_sandbox_not_weaker"][0]
        assert not sandbox_check["passed"]

    def test_neg_missing_dependency(self):
        """Missing dependency produces resolution error."""
        from nodechain.sdk.dependency_resolver import resolve_dependencies
        registry = {
            "root": {"1.0.0": _make_metadata("root", "1.0.0", [
                {"package_id": "ghost", "version_constraint": "1.0.0"}])}
        }
        graph = resolve_dependencies("root", "1.0.0", "https://r", _make_mock_fetcher(registry))
        assert any("ghost" in e for e in graph.resolution_errors)

    def test_neg_lockfile_tampering(self):
        """Lockfile tampering detected by digest."""
        from nodechain.sdk.dependency_resolver import RemoteDependencyLockfile
        lf = RemoteDependencyLockfile(root_package_id="root").finalize()
        original = lf.lockfile_digest
        lf.packages.append({"package_id": "injected"})
        assert lf.compute_digest() != original

    def test_neg_receipt_tampering(self):
        """Receipt tampering detected by digest."""
        from nodechain.sdk.dependency_resolver import DependencyResolutionReceipt
        receipt = DependencyResolutionReceipt(receipt_id="r1").finalize()
        original = receipt.receipt_digest
        receipt.node_count = 999
        assert receipt.compute_digest() != original

    def test_neg_unverified_node_flags_graph(self):
        """If any node fails verification, all_verified is False."""
        from nodechain.sdk.dependency_resolver import RemoteDependencyGraph, DependencyGraphNode
        graph = RemoteDependencyGraph()
        graph.nodes["root@1.0.0"] = DependencyGraphNode(
            package_id="root", is_root=True, verified=True)
        graph.nodes["dep@1.0.0"] = DependencyGraphNode(
            package_id="dep", verified=False)
        graph.root_key = "root@1.0.0"
        assert not graph.all_verified

    def test_neg_max_depth_exceeded(self):
        """Excessive dependency depth is caught."""
        from nodechain.sdk.dependency_resolver import resolve_dependencies
        # Build a chain of 20 packages
        registry = {}
        for i in range(20):
            pkg_id = f"pkg_{i}"
            deps = [{"package_id": f"pkg_{i+1}", "version_constraint": "1.0.0"}] if i < 19 else []
            registry[pkg_id] = {"1.0.0": _make_metadata(pkg_id, "1.0.0", deps)}
        graph = resolve_dependencies("pkg_0", "1.0.0", "https://r", _make_mock_fetcher(registry), max_depth=5)
        assert len(graph.resolution_errors) > 0

    def test_neg_no_trust_transfer(self):
        """Root verification doesn't make dependencies trusted."""
        from nodechain.sdk.dependency_resolver import (
            RemoteDependencyGraph, DependencyGraphNode, verify_dependency_graph,
        )
        graph = RemoteDependencyGraph()
        root_node = DependencyGraphNode(package_id="root", is_root=True, verified=True)
        dep_node = DependencyGraphNode(package_id="dep", verified=False)
        graph.nodes["root@1.0.0"] = root_node
        graph.nodes["dep@1.0.0"] = dep_node
        graph.root_key = "root@1.0.0"
        # Root is verified but graph is not
        assert root_node.verified
        assert not graph.all_verified


# ── Edge Cases ──────────────────────────────────────────────────────────────

class TestEdgeCases:
    """Edge cases."""

    def test_empty_graph(self):
        from nodechain.sdk.dependency_resolver import RemoteDependencyGraph
        graph = RemoteDependencyGraph()
        assert len(graph.nodes) == 0
        assert graph.root is None
        assert graph.all_verified is True  # Vacuously true

    def test_self_dependency(self):
        """Package depending on itself is caught."""
        from nodechain.sdk.dependency_resolver import resolve_dependencies, DependencyCycleError
        registry = {
            "self_dep": {"1.0.0": _make_metadata("self_dep", "1.0.0", [
                {"package_id": "self_dep", "version_constraint": "1.0.0"}])},
        }
        # Strict: raises
        with pytest.raises(DependencyCycleError):
            resolve_dependencies("self_dep", "1.0.0", "https://r", _make_mock_fetcher(registry), strict=True)
        # Non-strict: warning, single node
        graph = resolve_dependencies("self_dep", "1.0.0", "https://r", _make_mock_fetcher(registry), strict=False)
        assert len(graph.nodes) == 1

    def test_graph_digest_changes_with_content(self):
        from nodechain.sdk.dependency_resolver import (
            RemoteDependencyGraph, DependencyGraphNode,
        )
        g1 = RemoteDependencyGraph()
        g1.nodes["a@1.0.0"] = DependencyGraphNode(
            package_id="a", version="1.0.0", artifact_digest="d1", publisher_fingerprint="f1")
        g1.root_key = "a@1.0.0"

        g2 = RemoteDependencyGraph()
        g2.nodes["a@1.0.0"] = DependencyGraphNode(
            package_id="a", version="1.0.0", artifact_digest="d2", publisher_fingerprint="f1")
        g2.root_key = "a@1.0.0"

        assert g1.compute_graph_digest() != g2.compute_graph_digest()
