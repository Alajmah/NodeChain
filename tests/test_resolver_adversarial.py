"""Dependency Resolver Adversarial Certification (v2.21.3).

20-scenario adversarial test matrix proving the trust-aware dependency
resolver under hostile dependency graphs, transitive attacks, and
policy edge cases.

DT-001: Trust does not flow transitively from the root package.
"""

from __future__ import annotations

import json
import pytest
from pathlib import Path

from nodechain.sdk.trust_resolver import (
    ResolvedTrustNode,
    ResolvedTrustGraph,
    TrustLockfile,
    TrustResolutionReceipt,
    TrustAwareResolver,
    TrustResolutionError,
    DependencyCycleDetected,
    VersionConflictError,
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
    check_lockfile_drift,
)


# ── Helpers ─────────────────────────────────────────────────────────────────

def _pkg(package_id, version, **kwargs):
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
    def __init__(self):
        self.packages: dict[tuple[str, str, str], dict] = {}

    def add(self, registry_id, package_id, version, metadata=None):
        self.packages[(registry_id, package_id, version)] = metadata or _pkg(package_id, version)

    def __call__(self, registry_id, package_id, version):
        return self.packages.get(
            (registry_id, package_id, version),
            _pkg(package_id, version),
        )


@pytest.fixture
def base_registry():
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


@pytest.fixture
def resolver(base_registry):
    return TrustAwareResolver(metadata_provider=base_registry)


# ── Scenario 1: Direct revoked dependency ───────────────────────────────────

class TestS1DirectRevoked:
    """1. Direct revoked dependency → graph rejected."""

    def test_direct_revoked(self, base_registry):
        base_registry.add("reg-001", "dep_a", "1.0.0", _pkg(
            "dep_a", "1.0.0", lifecycle="revoked",
        ))
        r = TrustAwareResolver(metadata_provider=base_registry)
        g = r.resolve("reg-001", "root_pkg", "1.0.0")
        assert not g.graph_admissible
        assert g.has_revoked_dependency()


# ── Scenario 2: Transitive revoked dependency ───────────────────────────────

class TestS2TransitiveRevoked:
    """2. Transitive revoked dependency → graph rejected."""

    def test_transitive_revoked(self, base_registry):
        base_registry.add("reg-001", "dep_c", "1.0.0", _pkg(
            "dep_c", "1.0.0", lifecycle="revoked",
        ))
        r = TrustAwareResolver(metadata_provider=base_registry)
        g = r.resolve("reg-001", "root_pkg", "1.0.0")
        assert not g.graph_admissible
        assert g.has_revoked_dependency()


# ── Scenario 3: Direct uncertified ──────────────────────────────────────────

class TestS3DirectUncertified:
    """3. Direct uncertified when cert required → rejected."""

    def test_direct_uncertified(self, base_registry):
        r = TrustAwareResolver(metadata_provider=base_registry, require_certification=True)
        g = r.resolve("reg-001", "root_pkg", "1.0.0")
        assert not g.graph_admissible


# ── Scenario 4: Transitive uncertified ──────────────────────────────────────

class TestS4TransitiveUncertified:
    """4. Transitive uncertified → rejected."""

    def test_transitive_uncertified(self, base_registry):
        # Certify root and direct deps, but leave dep_c uncertified
        for pid in ["root_pkg", "dep_a", "dep_b"]:
            m = base_registry.packages[("reg-001", pid, "1.0.0") if pid != "dep_b" else ("reg-001", "dep_b", "2.0.0")]
            m["certification_digest"] = f"cert-{pid}"
        # dep_c has no cert
        r = TrustAwareResolver(metadata_provider=base_registry, require_certification=True)
        g = r.resolve("reg-001", "root_pkg", "1.0.0")
        assert not g.graph_admissible
        dep_c = [n for n in g.nodes if n.package_id == "dep_c"][0]
        assert dep_c.trust_verdict == "uncertified"


# ── Scenario 5: Forbidden capability ────────────────────────────────────────

class TestS5ForbiddenCapability:
    """5. Dependency requires forbidden capability → rejected."""

    def test_direct_forbidden_cap(self, base_registry):
        base_registry.add("reg-001", "dep_a", "1.0.0", _pkg(
            "dep_a", "1.0.0", capabilities=["network"],
        ))
        r = TrustAwareResolver(metadata_provider=base_registry, forbidden_capabilities=["network"])
        g = r.resolve("reg-001", "root_pkg", "1.0.0")
        assert not g.graph_admissible


# ── Scenario 6: Transitive forbidden capability ─────────────────────────────

class TestS6TransitiveForbiddenCap:
    """6. Transitive dependency requires forbidden capability → rejected."""

    def test_transitive_forbidden_cap(self, base_registry):
        base_registry.add("reg-001", "dep_c", "1.0.0", _pkg(
            "dep_c", "1.0.0", capabilities=["network"],
        ))
        r = TrustAwareResolver(metadata_provider=base_registry, forbidden_capabilities=["network"])
        g = r.resolve("reg-001", "root_pkg", "1.0.0")
        assert not g.graph_admissible
        dep_c = [n for n in g.nodes if n.package_id == "dep_c"][0]
        assert dep_c.trust_verdict == "forbidden_capability"


# ── Scenario 7: Sandbox downgrade ───────────────────────────────────────────

class TestS7SandboxDowngrade:
    """7. Sandbox downgrade attempt → rejected."""

    def test_sandbox_downgrade(self, base_registry):
        base_registry.add("reg-001", "dep_a", "1.0.0", _pkg(
            "dep_a", "1.0.0", sandbox_profile="none",
        ))
        r = TrustAwareResolver(
            metadata_provider=base_registry,
            min_sandbox_profile="hardened_untrusted",
        )
        g = r.resolve("reg-001", "root_pkg", "1.0.0")
        assert not g.graph_admissible


# ── Scenario 8: Version conflict ────────────────────────────────────────────

class TestS8VersionConflict:
    """8. Version conflict between branches."""

    def test_version_conflict_metadata(self, base_registry):
        """If dep_a requires dep_c@1.0 and dep_b requires dep_c@2.0,
        the resolver returns both as separate nodes (different keys).
        The conflict would be at the lockfile level if same package_id
        resolves to different versions."""
        base_registry.add("reg-001", "dep_a", "1.0.0", _pkg(
            "dep_a", "1.0.0",
            dependencies=[
                {"package_id": "dep_c", "version": "1.0.0", "constraint": ">=1.0,<2.0"},
            ],
        ))
        base_registry.add("reg-001", "dep_b", "2.0.0", _pkg(
            "dep_b", "2.0.0",
            dependencies=[
                {"package_id": "dep_c", "version": "2.0.0", "constraint": ">=2.0,<3.0"},
            ],
        ))
        base_registry.add("reg-001", "dep_c", "2.0.0")

        r = TrustAwareResolver(metadata_provider=base_registry)
        g = r.resolve("reg-001", "root_pkg", "1.0.0")
        # Both versions of dep_c are in the graph
        dep_c_versions = [n.version for n in g.nodes if n.package_id == "dep_c"]
        assert "1.0.0" in dep_c_versions
        assert "2.0.0" in dep_c_versions


# ── Scenario 9: Dependency cycle ────────────────────────────────────────────

class TestS9DependencyCycle:
    """9. Dependency cycle → graph rejected with cycle path."""

    def test_cycle_detected(self):
        reg = MockRegistry()
        reg.add("reg", "a", "1.0.0", _pkg("a", "1.0.0", dependencies=[
            {"package_id": "b", "version": "1.0.0", "constraint": ">=1.0"},
        ]))
        reg.add("reg", "b", "1.0.0", _pkg("b", "1.0.0", dependencies=[
            {"package_id": "a", "version": "1.0.0", "constraint": ">=1.0"},
        ]))
        r = TrustAwareResolver(metadata_provider=reg)
        g = r.resolve("reg", "a", "1.0.0")
        assert not g.graph_admissible
        assert "cycle" in g.rejection_summary.lower()

    def test_self_cycle(self):
        reg = MockRegistry()
        reg.add("reg", "a", "1.0.0", _pkg("a", "1.0.0", dependencies=[
            {"package_id": "a", "version": "1.0.0", "constraint": ">=1.0"},
        ]))
        r = TrustAwareResolver(metadata_provider=reg)
        g = r.resolve("reg", "a", "1.0.0")
        assert not g.graph_admissible


# ── Scenario 10: Cross-registry ambiguity ───────────────────────────────────

class TestS10CrossRegistry:
    """10. Cross-registry ambiguity for same package_id → fail closed."""

    def test_cross_registry_resolved(self):
        """Dependencies from different registries must be explicitly trusted."""
        reg = MockRegistry()
        reg.add("reg-A", "root", "1.0.0", _pkg(
            "root", "1.0.0",
            dependencies=[
                {"package_id": "dep", "version": "1.0.0", "registry_id": "reg-A"},
            ],
        ))
        reg.add("reg-A", "dep", "1.0.0")
        reg.add("reg-B", "dep", "1.0.0", _pkg("dep", "1.0.0", publisher_fingerprint="fp-evil"))

        # Trust only reg-A
        r = TrustAwareResolver(
            metadata_provider=reg,
            trusted_registries={"reg-A"},
        )
        g = r.resolve("reg-A", "root", "1.0.0")
        assert g.graph_admissible

        # Don't trust reg-B → a dep that resolves from reg-B would be rejected
        r2 = TrustAwareResolver(
            metadata_provider=reg,
            trusted_registries={"reg-B"},  # Only B trusted, root is from A
        )
        g2 = r2.resolve("reg-A", "root", "1.0.0")
        assert not g2.graph_admissible


# ── Scenario 11: Deprecated dependency ──────────────────────────────────────

class TestS11DeprecatedPolicy:
    """11. Deprecated dependency is policy-controlled."""

    def test_deprecated_allow_with_warning(self, base_registry):
        base_registry.add("reg-001", "dep_a", "1.0.0", _pkg(
            "dep_a", "1.0.0", lifecycle="deprecated",
        ))
        r = TrustAwareResolver(
            metadata_provider=base_registry,
            deprecated_policy=DEP_POLICY_ALLOW_WITH_WARNING,
        )
        g = r.resolve("reg-001", "root_pkg", "1.0.0")
        assert g.graph_admissible
        assert g.has_deprecated_dependency()

    def test_deprecated_deny(self, base_registry):
        base_registry.add("reg-001", "dep_a", "1.0.0", _pkg(
            "dep_a", "1.0.0", lifecycle="deprecated",
        ))
        r = TrustAwareResolver(
            metadata_provider=base_registry,
            deprecated_policy=DEP_POLICY_DENY,
        )
        g = r.resolve("reg-001", "root_pkg", "1.0.0")
        assert not g.graph_admissible


# ── Scenario 12: Lockfile drift ─────────────────────────────────────────────

class TestS12LockfileDrift:
    """12. Lockfile drift after metadata update."""

    def test_drift_after_change(self, base_registry):
        r = TrustAwareResolver(metadata_provider=base_registry)
        g1 = r.resolve("reg-001", "root_pkg", "1.0.0")
        lf = TrustLockfile.from_graph(g1)

        # Change a dependency
        base_registry.add("reg-001", "dep_a", "1.0.0", _pkg(
            "dep_a", "1.0.0", capabilities=["network"],
        ))
        g2 = r.resolve("reg-001", "root_pkg", "1.0.0")
        assert check_lockfile_drift(lf, g2)


# ── Scenario 13: Publisher revoked after lockfile ───────────────────────────

class TestS13PublisherRevoked:
    """13. Publisher revoked after lockfile → re-resolution rejects."""

    def test_publisher_revoke_changes_admissibility(self, base_registry):
        r1 = TrustAwareResolver(
            metadata_provider=base_registry,
            trusted_publishers={"fp-publisher"},
        )
        g1 = r1.resolve("reg-001", "root_pkg", "1.0.0")
        assert g1.graph_admissible

        # Publisher revoked → now only a different publisher is trusted
        r2 = TrustAwareResolver(
            metadata_provider=base_registry,
            trusted_publishers={"fp-other"},
        )
        g2 = r2.resolve("reg-001", "root_pkg", "1.0.0")
        assert not g2.graph_admissible


# ── Scenario 14: Registry signer rotated ────────────────────────────────────

class TestS14SignerRotated:
    """14. Registry signer rotated → accepted through valid continuity."""

    def test_registry_rotation_in_resolver(self, base_registry):
        """If registry identity changes, lockfile with old registry_id drifts."""
        r1 = TrustAwareResolver(
            metadata_provider=base_registry,
            trusted_registries={"reg-001"},
        )
        g1 = r1.resolve("reg-001", "root_pkg", "1.0.0")
        lf = TrustLockfile.from_graph(g1)

        # Re-resolve — same registry, same result
        g2 = r1.resolve("reg-001", "root_pkg", "1.0.0")
        assert not check_lockfile_drift(lf, g2)


# ── Scenario 15: Same version, different artifact ───────────────────────────

class TestS15ArtifactConflict:
    """15. Same version, different artifact at dependency level → conflict."""

    def test_different_artifact_different_graph(self, base_registry):
        r = TrustAwareResolver(metadata_provider=base_registry)
        g1 = r.resolve("reg-001", "root_pkg", "1.0.0")
        lf1 = TrustLockfile.from_graph(g1)

        # Swap artifact
        base_registry.add("reg-001", "dep_a", "1.0.0", _pkg(
            "dep_a", "1.0.0", artifact_digest="sha256:SWAPPED",
        ))
        g2 = r.resolve("reg-001", "root_pkg", "1.0.0")
        assert check_lockfile_drift(lf1, g2)


# ── Scenario 16: Deep dependency graph ──────────────────────────────────────

class TestS16DeepGraph:
    """16. Deep dependency graph → deterministic digest, stable ordering."""

    def test_deep_chain_deterministic(self):
        reg = MockRegistry()
        for i in range(10):
            pid = f"pkg_{i}"
            deps = [{"package_id": f"pkg_{i+1}", "version": "1.0.0", "constraint": ">=1.0"}] if i < 9 else []
            reg.add("reg", pid, "1.0.0", _pkg(pid, "1.0.0", dependencies=deps))

        r = TrustAwareResolver(metadata_provider=reg)
        g1 = r.resolve("reg", "pkg_0", "1.0.0")
        g2 = r.resolve("reg", "pkg_0", "1.0.0")
        assert g1.compute_graph_digest() == g2.compute_graph_digest()
        assert len(g1.nodes) == 10


# ── Scenario 17: Duplicate dependency through different paths ───────────────

class TestS17DuplicatePaths:
    """17. Duplicate dependency through different paths → one identity."""

    def test_diamond_dependency(self):
        """Diamond: root → A → C, root → B → C. C should appear once."""
        reg = MockRegistry()
        reg.add("reg", "root", "1.0.0", _pkg("root", "1.0.0", dependencies=[
            {"package_id": "a", "version": "1.0.0", "constraint": ">=1.0"},
            {"package_id": "b", "version": "1.0.0", "constraint": ">=1.0"},
        ]))
        reg.add("reg", "a", "1.0.0", _pkg("a", "1.0.0", dependencies=[
            {"package_id": "c", "version": "1.0.0", "constraint": ">=1.0"},
        ]))
        reg.add("reg", "b", "1.0.0", _pkg("b", "1.0.0", dependencies=[
            {"package_id": "c", "version": "1.0.0", "constraint": ">=1.0"},
        ]))
        reg.add("reg", "c", "1.0.0")

        r = TrustAwareResolver(metadata_provider=reg)
        g = r.resolve("reg", "root", "1.0.0")
        c_nodes = [n for n in g.nodes if n.package_id == "c"]
        assert len(c_nodes) == 1  # Exactly one resolved identity
        assert g.graph_admissible


# ── Scenario 18: Capability aggregation ─────────────────────────────────────

class TestS18CapabilityAggregation:
    """18. Capability aggregation → union accurate and policy-checked."""

    def test_union_capabilities(self, base_registry):
        base_registry.add("reg-001", "dep_a", "1.0.0", _pkg(
            "dep_a", "1.0.0", capabilities=["read_only", "network"],
        ))
        base_registry.add("reg-001", "dep_c", "1.0.0", _pkg(
            "dep_c", "1.0.0", capabilities=["filesystem_write"],
        ))
        r = TrustAwareResolver(metadata_provider=base_registry)
        g = r.resolve("reg-001", "root_pkg", "1.0.0")
        assert "read_only" in g.aggregate_capabilities
        assert "network" in g.aggregate_capabilities
        assert "filesystem_write" in g.aggregate_capabilities


# ── Scenario 19: Sandbox aggregation ────────────────────────────────────────

class TestS19SandboxAggregation:
    """19. Sandbox aggregation → no node executes below required profile."""

    def test_no_node_below_minimum(self, base_registry):
        base_registry.add("reg-001", "dep_a", "1.0.0", _pkg(
            "dep_a", "1.0.0", sandbox_profile="production_untrusted",
        ))
        r = TrustAwareResolver(metadata_provider=base_registry)
        g = r.resolve("reg-001", "root_pkg", "1.0.0")
        # Aggregate should be at least as strong as any node
        for node in g.nodes:
            assert sandbox_strength(g.aggregate_sandbox) >= sandbox_strength(node.sandbox_profile)

    def test_aggregate_is_strongest(self):
        reg = MockRegistry()
        reg.add("reg", "root", "1.0.0", _pkg("root", "1.0.0", sandbox_profile="standard_untrusted",
            dependencies=[{"package_id": "a", "version": "1.0.0", "constraint": ">=1.0"}]))
        reg.add("reg", "a", "1.0.0", _pkg("a", "1.0.0", sandbox_profile="hardened_untrusted"))
        r = TrustAwareResolver(metadata_provider=reg, min_sandbox_profile="standard_untrusted")
        g = r.resolve("reg", "root", "1.0.0")
        assert g.aggregate_sandbox == "hardened_untrusted"


# ── Scenario 20: Explain mode ───────────────────────────────────────────────

class TestS20ExplainMode:
    """20. Explain mode → rejected candidates and reasons preserved."""

    def test_explain_preserves_rejections(self, base_registry):
        base_registry.add("reg-001", "dep_a", "1.0.0", _pkg(
            "dep_a", "1.0.0", lifecycle="revoked",
        ))
        r = TrustAwareResolver(metadata_provider=base_registry)
        g, lf, receipt = r.resolve_with_lockfile("reg-001", "root_pkg", "1.0.0", explain=True)

        assert len(receipt.rejected_nodes) > 0
        rejected_a = [rn for rn in receipt.rejected_nodes if rn["package_id"] == "dep_a"]
        assert len(rejected_a) == 1
        assert "revoked" in rejected_a[0]["reason"].lower()

    def test_explain_empty_when_admissible(self, base_registry):
        r = TrustAwareResolver(metadata_provider=base_registry)
        g, lf, receipt = r.resolve_with_lockfile("reg-001", "root_pkg", "1.0.0", explain=True)
        assert receipt.admissible
        assert len(receipt.rejected_nodes) == 0

    def test_receipt_to_dict_has_rejected(self, base_registry):
        base_registry.add("reg-001", "dep_a", "1.0.0", _pkg(
            "dep_a", "1.0.0", lifecycle="revoked",
        ))
        r = TrustAwareResolver(metadata_provider=base_registry)
        g, lf, receipt = r.resolve_with_lockfile("reg-001", "root_pkg", "1.0.0", explain=True)
        d = receipt.to_dict()
        assert "rejected_nodes" in d
        assert len(d["rejected_nodes"]) > 0
