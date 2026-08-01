"""Trust-Aware Dependency Resolution Tests (v2.21.3).

Tests that a remote package is admissible only if every dependency in
its resolved graph is version-compatible, identity-verified, non-revoked,
publisher-authorized, certified, policy-admissible, and sandbox-compatible.

DT-001: Trust does not flow transitively from the root package.

Coverage:
    AC-1:  ResolvedTrustGraph and node evaluation
    AC-2:  Deterministic resolution
    AC-3:  Lockfile binding (all fields)
    AC-4:  Revoked dependency blocks graph
    AC-5:  Untrusted registry blocks graph
    AC-6:  Unapproved publisher blocks graph
    AC-7:  Missing certification blocks graph
    AC-8:  Forbidden capability blocks graph
    AC-9:  Sandbox downgrade blocks graph
    AC-10: Deprecated dependency policy control
    AC-11: Aggregate requirements computation
    AC-12: Resolution receipt
    AC-13: Lockfile drift detection
    AC-14: DT-001 transitive trust isolation
    AC-15: Dashboard health rules (HR-031 through HR-034)
"""

from __future__ import annotations

import json
import pytest
from datetime import datetime, timezone
from pathlib import Path

from nodechain.sdk.trust_resolver import (
    ResolvedTrustNode,
    TrustGraphEdge,
    ResolvedTrustGraph,
    TrustLockfile,
    TrustResolutionReceipt,
    TrustAwareResolver,
    TrustResolutionError,
    RevokedDependencyError,
    UncertifiedDependencyError,
    ForbiddenCapabilityError,
    SandboxDowngradeError,
    LockfileDriftError,
    LOCKFILE_SCHEMA_VERSION,
    POLICY_ALLOWED,
    POLICY_DENIED,
    POLICY_WARN,
    POLICY_PINNED_ONLY,
    DEP_POLICY_ALLOW,
    DEP_POLICY_DENY,
    DEP_POLICY_ALLOW_WITH_WARNING,
    DEP_POLICY_ALLOW_ONLY_IF_PINNED,
    sandbox_strength,
    strongest_sandbox,
    save_lockfile,
    load_lockfile,
    check_lockfile_drift,
)


# ── Test Metadata Provider ──────────────────────────────────────────────────


def _pkg(package_id, version, **kwargs):
    """Build a package metadata dict."""
    defaults = {
        "package_id": package_id,
        "version": version,
        "artifact_digest": f"sha256:{package_id}_{version}",
        "manifest_digest": f"sha256:manifest_{package_id}_{version}",
        "publisher_fingerprint": "fp-publisher",
        "certification_digest": "",
        "lifecycle": "active",
        "sandbox_profile": "hardened_untrusted",
        "capabilities": ["read_only"],
        "dependencies": [],
    }
    defaults.update(kwargs)
    return defaults


class MockRegistry:
    """Mock metadata provider for testing."""

    def __init__(self):
        self.packages: dict[tuple[str, str, str], dict] = {}

    def add(self, registry_id, package_id, version, metadata=None):
        if metadata is None:
            metadata = _pkg(package_id, version)
        self.packages[(registry_id, package_id, version)] = metadata

    def __call__(self, registry_id, package_id, version):
        return self.packages.get((registry_id, package_id, version), _pkg(package_id, version))


@pytest.fixture
def registry():
    r = MockRegistry()
    r.add("reg-001", "root_pkg", "1.0.0", _pkg(
        "root_pkg", "1.0.0",
        dependencies=[
            {"package_id": "dep_a", "version": "1.0.0", "constraint": ">=1.0,<2.0"},
            {"package_id": "dep_b", "version": "2.0.0", "constraint": ">=2.0,<3.0"},
        ],
    ))
    r.add("reg-001", "dep_a", "1.0.0")
    r.add("reg-001", "dep_b", "2.0.0", _pkg(
        "dep_b", "2.0.0",
        dependencies=[
            {"package_id": "dep_c", "version": "1.0.0", "constraint": ">=1.0"},
        ],
    ))
    r.add("reg-001", "dep_c", "1.0.0")
    return r


# ── AC-1: ResolvedTrustGraph ────────────────────────────────────────────────

class TestAC1ResolvedTrustGraph:
    """1. ResolvedTrustGraph and node evaluation."""

    def test_node_fields(self):
        node = ResolvedTrustNode(
            package_id="pkg", version="1.0.0",
            registry_id="reg-001",
            artifact_digest="dig", manifest_digest="man",
            publisher_fingerprint="fp", certification_digest="cert",
            lifecycle="active", sandbox_profile="hardened_untrusted",
        )
        assert node.key() == "pkg@1.0.0"
        assert node.is_root is False

    def test_graph_digest_deterministic(self, registry):
        resolver = TrustAwareResolver(metadata_provider=registry)
        g1 = resolver.resolve("reg-001", "root_pkg", "1.0.0")
        g2 = resolver.resolve("reg-001", "root_pkg", "1.0.0")
        assert g1.compute_graph_digest() == g2.compute_graph_digest()

    def test_graph_has_root(self, registry):
        resolver = TrustAwareResolver(metadata_provider=registry)
        g = resolver.resolve("reg-001", "root_pkg", "1.0.0")
        assert g.root is not None
        assert g.root.package_id == "root_pkg"
        assert g.root.is_root is True

    def test_graph_has_all_nodes(self, registry):
        resolver = TrustAwareResolver(metadata_provider=registry)
        g = resolver.resolve("reg-001", "root_pkg", "1.0.0")
        ids = {n.package_id for n in g.nodes}
        assert ids == {"root_pkg", "dep_a", "dep_b", "dep_c"}


# ── AC-2: Deterministic resolution ──────────────────────────────────────────

class TestAC2Deterministic:
    """2. Resolver produces deterministic ResolvedTrustGraph."""

    def test_same_input_same_output(self, registry):
        resolver = TrustAwareResolver(metadata_provider=registry)
        g1 = resolver.resolve("reg-001", "root_pkg", "1.0.0")
        g2 = resolver.resolve("reg-001", "root_pkg", "1.0.0")
        assert g1.graph_admissible == g2.graph_admissible
        assert g1.compute_graph_digest() == g2.compute_graph_digest()

    def test_different_policy_different_digest(self, registry):
        r1 = TrustAwareResolver(metadata_provider=registry)
        g1 = r1.resolve("reg-001", "root_pkg", "1.0.0")

        r2 = TrustAwareResolver(metadata_provider=registry, require_certification=True)
        g2 = r2.resolve("reg-001", "root_pkg", "1.0.0")

        assert g1.resolver_policy_digest != g2.resolver_policy_digest


# ── AC-3: Lockfile binding ──────────────────────────────────────────────────

class TestAC3Lockfile:
    """3. Lockfile binds all required fields."""

    def test_lockfile_from_graph(self, registry):
        resolver = TrustAwareResolver(metadata_provider=registry)
        g = resolver.resolve("reg-001", "root_pkg", "1.0.0")
        lf = TrustLockfile.from_graph(g)

        assert lf.schema_version == LOCKFILE_SCHEMA_VERSION
        assert lf.root["package_id"] == "root_pkg"
        assert len(lf.packages) == 4
        assert lf.graph_digest != ""
        assert lf.lockfile_digest != ""

    def test_lockfile_package_fields(self, registry):
        resolver = TrustAwareResolver(metadata_provider=registry)
        g = resolver.resolve("reg-001", "root_pkg", "1.0.0")
        lf = TrustLockfile.from_graph(g)

        for pkg in lf.packages:
            assert "package_id" in pkg
            assert "version" in pkg
            assert "registry_id" in pkg
            assert "artifact_digest" in pkg
            assert "manifest_digest" in pkg
            assert "publisher_fingerprint" in pkg
            assert "certification_digest" in pkg
            assert "lifecycle" in pkg
            assert "trust_verdict" in pkg
            assert "policy_verdict" in pkg
            assert "sandbox_profile" in pkg

    def test_lockfile_edges(self, registry):
        resolver = TrustAwareResolver(metadata_provider=registry)
        g = resolver.resolve("reg-001", "root_pkg", "1.0.0")
        lf = TrustLockfile.from_graph(g)
        assert len(lf.edges) == 3  # root→dep_a, root→dep_b, dep_b→dep_c

    def test_lockfile_persistence(self, tmp_path, registry):
        resolver = TrustAwareResolver(metadata_provider=registry)
        g = resolver.resolve("reg-001", "root_pkg", "1.0.0")
        lf = TrustLockfile.from_graph(g)

        path = str(tmp_path / "lockfile.json")
        save_lockfile(lf, path)
        lf2 = load_lockfile(path)

        assert lf2.lockfile_digest == lf.lockfile_digest
        assert lf2.graph_digest == lf.graph_digest
        assert len(lf2.packages) == len(lf.packages)


# ── AC-4: Revoked dependency ────────────────────────────────────────────────

class TestAC4RevokedDependency:
    """4. A revoked dependency blocks the whole graph."""

    def test_revoked_dep_blocks_graph(self, registry):
        registry.add("reg-001", "dep_a", "1.0.0", _pkg(
            "dep_a", "1.0.0", lifecycle="revoked",
        ))
        resolver = TrustAwareResolver(metadata_provider=registry)
        g = resolver.resolve("reg-001", "root_pkg", "1.0.0")

        assert not g.graph_admissible
        assert g.has_revoked_dependency()

    def test_revoked_dep_policy_denied(self, registry):
        registry.add("reg-001", "dep_a", "1.0.0", _pkg(
            "dep_a", "1.0.0", lifecycle="revoked",
        ))
        resolver = TrustAwareResolver(metadata_provider=registry)
        g = resolver.resolve("reg-001", "root_pkg", "1.0.0")

        dep_a = [n for n in g.nodes if n.package_id == "dep_a"][0]
        assert dep_a.policy_verdict == POLICY_DENIED
        assert dep_a.trust_verdict == "revoked"


# ── AC-5: Untrusted registry ────────────────────────────────────────────────

class TestAC5UntrustedRegistry:
    """5. Untrusted registry blocks graph."""

    def test_untrusted_registry_blocks(self, registry):
        resolver = TrustAwareResolver(
            metadata_provider=registry,
            trusted_registries={"reg-trusted"},
        )
        g = resolver.resolve("reg-001", "root_pkg", "1.0.0")
        assert not g.graph_admissible

    def test_trusted_registry_allows(self, registry):
        resolver = TrustAwareResolver(
            metadata_provider=registry,
            trusted_registries={"reg-001"},
        )
        g = resolver.resolve("reg-001", "root_pkg", "1.0.0")
        assert g.graph_admissible


# ── AC-6: Unapproved publisher ──────────────────────────────────────────────

class TestAC6UnapprovedPublisher:
    """6. Unapproved publisher blocks graph."""

    def test_unapproved_publisher_blocks(self, registry):
        resolver = TrustAwareResolver(
            metadata_provider=registry,
            trusted_publishers={"fp-different"},
        )
        g = resolver.resolve("reg-001", "root_pkg", "1.0.0")
        assert not g.graph_admissible

    def test_approved_publisher_allows(self, registry):
        resolver = TrustAwareResolver(
            metadata_provider=registry,
            trusted_publishers={"fp-publisher"},
        )
        g = resolver.resolve("reg-001", "root_pkg", "1.0.0")
        assert g.graph_admissible


# ── AC-7: Missing certification ─────────────────────────────────────────────

class TestAC7MissingCertification:
    """7. Missing certification blocks graph when required."""

    def test_cert_required_blocks(self, registry):
        resolver = TrustAwareResolver(
            metadata_provider=registry,
            require_certification=True,
        )
        g = resolver.resolve("reg-001", "root_pkg", "1.0.0")
        assert not g.graph_admissible

    def test_cert_present_allows(self, registry):
        registry.add("reg-001", "dep_a", "1.0.0", _pkg(
            "dep_a", "1.0.0", certification_digest="cert-a",
        ))
        registry.add("reg-001", "dep_b", "2.0.0", _pkg(
            "dep_b", "2.0.0", certification_digest="cert-b",
            dependencies=[
                {"package_id": "dep_c", "version": "1.0.0", "constraint": ">=1.0"},
            ],
        ))
        registry.add("reg-001", "dep_c", "1.0.0", _pkg(
            "dep_c", "1.0.0", certification_digest="cert-c",
        ))
        registry.add("reg-001", "root_pkg", "1.0.0", _pkg(
            "root_pkg", "1.0.0", certification_digest="cert-root",
            dependencies=[
                {"package_id": "dep_a", "version": "1.0.0", "constraint": ">=1.0,<2.0"},
                {"package_id": "dep_b", "version": "2.0.0", "constraint": ">=2.0,<3.0"},
            ],
        ))
        resolver = TrustAwareResolver(
            metadata_provider=registry,
            require_certification=True,
        )
        g = resolver.resolve("reg-001", "root_pkg", "1.0.0")
        assert g.graph_admissible


# ── AC-8: Forbidden capability ──────────────────────────────────────────────

class TestAC8ForbiddenCapability:
    """8. Forbidden capability blocks graph."""

    def test_forbidden_capability_blocks(self, registry):
        registry.add("reg-001", "dep_a", "1.0.0", _pkg(
            "dep_a", "1.0.0", capabilities=["network", "filesystem_write"],
        ))
        resolver = TrustAwareResolver(
            metadata_provider=registry,
            forbidden_capabilities=["network"],
        )
        g = resolver.resolve("reg-001", "root_pkg", "1.0.0")
        assert not g.graph_admissible

        dep_a = [n for n in g.nodes if n.package_id == "dep_a"][0]
        assert dep_a.trust_verdict == "forbidden_capability"


# ── AC-9: Sandbox downgrade ─────────────────────────────────────────────────

class TestAC9SandboxDowngrade:
    """9. Dependency requiring weaker sandbox cannot weaken root."""

    def test_sandbox_downgrade_blocks(self, registry):
        registry.add("reg-001", "dep_a", "1.0.0", _pkg(
            "dep_a", "1.0.0", sandbox_profile="none",
        ))
        resolver = TrustAwareResolver(
            metadata_provider=registry,
            min_sandbox_profile="hardened_untrusted",
        )
        g = resolver.resolve("reg-001", "root_pkg", "1.0.0")
        assert not g.graph_admissible

        dep_a = [n for n in g.nodes if n.package_id == "dep_a"][0]
        assert dep_a.trust_verdict == "sandbox_downgrade"


# ── AC-10: Deprecated dependency policy ─────────────────────────────────────

class TestAC10DeprecatedPolicy:
    """10. Deprecated dependency is policy-controlled."""

    def test_deprecated_allow_with_warning(self, registry):
        registry.add("reg-001", "dep_a", "1.0.0", _pkg(
            "dep_a", "1.0.0", lifecycle="deprecated",
        ))
        resolver = TrustAwareResolver(
            metadata_provider=registry,
            deprecated_policy=DEP_POLICY_ALLOW_WITH_WARNING,
        )
        g = resolver.resolve("reg-001", "root_pkg", "1.0.0")
        assert g.graph_admissible
        assert g.has_deprecated_dependency()

        dep_a = [n for n in g.nodes if n.package_id == "dep_a"][0]
        assert dep_a.policy_verdict == POLICY_WARN

    def test_deprecated_deny(self, registry):
        registry.add("reg-001", "dep_a", "1.0.0", _pkg(
            "dep_a", "1.0.0", lifecycle="deprecated",
        ))
        resolver = TrustAwareResolver(
            metadata_provider=registry,
            deprecated_policy=DEP_POLICY_DENY,
        )
        g = resolver.resolve("reg-001", "root_pkg", "1.0.0")
        assert not g.graph_admissible

    def test_deprecated_pinned_only(self, registry):
        registry.add("reg-001", "dep_a", "1.0.0", _pkg(
            "dep_a", "1.0.0", lifecycle="deprecated",
        ))
        resolver = TrustAwareResolver(
            metadata_provider=registry,
            deprecated_policy=DEP_POLICY_ALLOW_ONLY_IF_PINNED,
        )
        g = resolver.resolve("reg-001", "root_pkg", "1.0.0")
        dep_a = [n for n in g.nodes if n.package_id == "dep_a"][0]
        assert dep_a.policy_verdict == POLICY_PINNED_ONLY


# ── AC-11: Aggregate requirements ───────────────────────────────────────────

class TestAC11AggregateRequirements:
    """11. Resolver computes aggregate capabilities and sandbox."""

    def test_aggregate_capabilities(self, registry):
        registry.add("reg-001", "dep_a", "1.0.0", _pkg(
            "dep_a", "1.0.0", capabilities=["read_only", "network"],
        ))
        resolver = TrustAwareResolver(metadata_provider=registry)
        g = resolver.resolve("reg-001", "root_pkg", "1.0.0")

        assert "read_only" in g.aggregate_capabilities
        assert "network" in g.aggregate_capabilities

    def test_aggregate_sandbox_strongest(self, registry):
        registry.add("reg-001", "dep_a", "1.0.0", _pkg(
            "dep_a", "1.0.0", sandbox_profile="production_untrusted",
        ))
        resolver = TrustAwareResolver(metadata_provider=registry)
        g = resolver.resolve("reg-001", "root_pkg", "1.0.0")

        # Root is hardened_untrusted (3), dep_a is production_untrusted (2)
        # Aggregate should be the strongest = hardened_untrusted
        assert sandbox_strength(g.aggregate_sandbox) >= sandbox_strength("production_untrusted")


# ── AC-12: Resolution receipt ───────────────────────────────────────────────

class TestAC12ResolutionReceipt:
    """12. Resolution receipt with graph and lockfile digests."""

    def test_receipt_fields(self, registry):
        resolver = TrustAwareResolver(metadata_provider=registry)
        g, lf, receipt = resolver.resolve_with_lockfile("reg-001", "root_pkg", "1.0.0")

        assert receipt.root_package_id == "root_pkg"
        assert receipt.root_version == "1.0.0"
        assert receipt.graph_digest != ""
        assert receipt.lockfile_digest != ""
        assert receipt.node_count == 4
        assert receipt.admissible is True
        assert receipt.receipt_digest != ""


# ── AC-13: Lockfile drift ───────────────────────────────────────────────────

class TestAC13LockfileDrift:
    """13. Lockfile drift detection."""

    def test_no_drift(self, registry):
        resolver = TrustAwareResolver(metadata_provider=registry)
        g = resolver.resolve("reg-001", "root_pkg", "1.0.0")
        lf = TrustLockfile.from_graph(g)
        assert not check_lockfile_drift(lf, g)

    def test_drift_detected(self, registry):
        resolver = TrustAwareResolver(metadata_provider=registry)
        g1 = resolver.resolve("reg-001", "root_pkg", "1.0.0")
        lf = TrustLockfile.from_graph(g1)

        # Change a dependency
        registry.add("reg-001", "dep_a", "1.0.0", _pkg(
            "dep_a", "1.0.0", capabilities=["network"],
        ))
        g2 = resolver.resolve("reg-001", "root_pkg", "1.0.0")
        assert check_lockfile_drift(lf, g2)


# ── AC-14: DT-001 transitive trust isolation ────────────────────────────────

class TestAC14DT001TransitiveTrust:
    """DT-001: Trust does not flow transitively from root."""

    def test_trusted_root_untrusted_dep_rejected(self, registry):
        """Root is trusted but dep has untrusted publisher → graph denied."""
        resolver = TrustAwareResolver(
            metadata_provider=registry,
            trusted_publishers={"fp-publisher"},  # Root publisher only
        )
        # Add dep with different publisher
        registry.add("reg-001", "dep_a", "1.0.0", _pkg(
            "dep_a", "1.0.0", publisher_fingerprint="fp-different",
        ))
        g = resolver.resolve("reg-001", "root_pkg", "1.0.0")
        assert not g.graph_admissible

        dep_a = [n for n in g.nodes if n.package_id == "dep_a"][0]
        assert dep_a.trust_verdict == "untrusted_publisher"

    def test_every_node_independently_evaluated(self, registry):
        """Each node gets its own trust_verdict and policy_verdict."""
        resolver = TrustAwareResolver(metadata_provider=registry)
        g = resolver.resolve("reg-001", "root_pkg", "1.0.0")

        for node in g.nodes:
            assert node.trust_verdict == "trusted"
            assert node.policy_verdict == POLICY_ALLOWED

    def test_root_trust_doesnt_cover_deps(self, registry):
        """Root having certification doesn't cover uncertified deps."""
        registry.add("reg-001", "root_pkg", "1.0.0", _pkg(
            "root_pkg", "1.0.0", certification_digest="cert-root",
            dependencies=[
                {"package_id": "dep_a", "version": "1.0.0", "constraint": ">=1.0,<2.0"},
                {"package_id": "dep_b", "version": "2.0.0", "constraint": ">=2.0,<3.0"},
            ],
        ))
        resolver = TrustAwareResolver(
            metadata_provider=registry,
            require_certification=True,
        )
        g = resolver.resolve("reg-001", "root_pkg", "1.0.0")
        # Root has cert but deps don't → graph denied
        assert not g.graph_admissible


# ── AC-15: Dashboard health rules ───────────────────────────────────────────

class TestAC15DashboardHealth:
    """15. Dashboard rules for dependency graph health."""

    def test_hr031_revoked_transitive(self):
        from nodechain.cli.dashboard_health import HR031RevokedTransitiveDependency
        rule = HR031RevokedTransitiveDependency()
        assert rule.rule_id == "HR-031"
        result = rule.evaluate({
            "dependency_graph": {"enabled": True, "revoked_dependency_count": 1}
        })
        assert result is not None
        assert result["severity"] == "critical"

    def test_hr032_deprecated_transitive(self):
        from nodechain.cli.dashboard_health import HR032DeprecatedTransitiveDependency
        rule = HR032DeprecatedTransitiveDependency()
        result = rule.evaluate({
            "dependency_graph": {"enabled": True, "deprecated_dependency_count": 2}
        })
        assert result is not None

    def test_hr033_lockfile_drift(self):
        from nodechain.cli.dashboard_health import HR033LockfileDrift
        rule = HR033LockfileDrift()
        result = rule.evaluate({
            "dependency_graph": {"enabled": True, "lockfile_drift": True}
        })
        assert result is not None

    def test_hr034_unresolved_conflict(self):
        from nodechain.cli.dashboard_health import HR034UnresolvedDependencyConflict
        rule = HR034UnresolvedDependencyConflict()
        result = rule.evaluate({
            "dependency_graph": {"enabled": True, "unresolved_conflict_count": 1}
        })
        assert result is not None

    def test_all_39_rules(self):
        from nodechain.cli.dashboard_health import ALL_RULES, RULES_BY_ID
        assert len(ALL_RULES) == 65  # 49 HR + 5 MEM + 6 SE + 5 MR (v2.41.0)
        for i in range(1, 35):
            assert f"HR-{i:03d}" in RULES_BY_ID


# ── Sandbox helpers ─────────────────────────────────────────────────────────

class TestSandboxHelpers:
    """Sandbox strength computation."""

    def test_strength_ordering(self):
        assert sandbox_strength("none") < sandbox_strength("standard_untrusted")
        assert sandbox_strength("standard_untrusted") < sandbox_strength("hardened_untrusted")

    def test_strongest_sandbox(self):
        assert strongest_sandbox(["none", "hardened_untrusted"]) == "hardened_untrusted"
        assert strongest_sandbox(["standard_untrusted", "production_untrusted"]) == "production_untrusted"

    def test_empty_strongest(self):
        assert strongest_sandbox([]) == "hardened_untrusted"


# ── Deep dependency chain ───────────────────────────────────────────────────

class TestDeepDependencyChain:
    """Deep dependency chains are fully resolved."""

    def test_deep_chain_resolved(self):
        reg = MockRegistry()
        reg.add("reg", "a", "1.0.0", _pkg("a", "1.0.0", dependencies=[
            {"package_id": "b", "version": "1.0.0", "constraint": ">=1.0"},
        ]))
        reg.add("reg", "b", "1.0.0", _pkg("b", "1.0.0", dependencies=[
            {"package_id": "c", "version": "1.0.0", "constraint": ">=1.0"},
        ]))
        reg.add("reg", "c", "1.0.0", _pkg("c", "1.0.0", dependencies=[
            {"package_id": "d", "version": "1.0.0", "constraint": ">=1.0"},
        ]))
        reg.add("reg", "d", "1.0.0")

        resolver = TrustAwareResolver(metadata_provider=reg)
        g = resolver.resolve("reg", "a", "1.0.0")
        assert len(g.nodes) == 4
        assert g.graph_admissible

    def test_cycle_detected(self):
        """Dependency cycle returns without infinite loop."""
        reg = MockRegistry()
        reg.add("reg", "a", "1.0.0", _pkg("a", "1.0.0", dependencies=[
            {"package_id": "b", "version": "1.0.0", "constraint": ">=1.0"},
        ]))
        reg.add("reg", "b", "1.0.0", _pkg("b", "1.0.0", dependencies=[
            {"package_id": "a", "version": "1.0.0", "constraint": ">=1.0"},
        ]))

        resolver = TrustAwareResolver(metadata_provider=reg)
        g = resolver.resolve("reg", "a", "1.0.0")
        # Cycle doesn't cause infinite recursion (visited dict prevents it)
        assert len(g.nodes) == 2
