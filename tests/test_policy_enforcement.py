"""Tests for package policy enforcement.

AC1: Package load fails if nodechain_min_version > runtime version.
AC2: Strict mode blocks packages with undeclared capabilities.
AC3: Strict mode blocks side-effecting nodes without side_effects declarations.
AC4: Runtime governance context receives package-declared side effects.
AC5: Package capability policy blocks network/subprocess/filesystem before execution.
AC6: Report records package capability policy decision.
AC7: CLI validate distinguishes declared capabilities from enforced permissions.
AC8: Existing 804 tests remain green.
"""

import os
import pytest
from pathlib import Path

from nodechain.sdk.policy_enforcer import (
    PackagePolicyEnforcer,
    PackagePolicyResult,
    PolicyDecision,
    parse_version,
)
from nodechain.sdk.loader import NodeLoader, NodeLoadError


class TestVersionGate:
    """AC1: Package load fails if nodechain_min_version > runtime version."""

    def test_version_gate_blocks_future_package(self):
        """AC1: future_node requires 99.0.0, should be blocked.
        v2.45.2: now blocked at admission — denied package not in registry."""
        loader = NodeLoader()
        # v2.45.2: future_node denied by registry admission (version policy BLOCK)
        # It's not in the loadable index, so load() raises "not found"
        with pytest.raises(NodeLoadError, match="not found in registry"):
            loader.load("future_node")

    def test_version_gate_allows_compatible(self):
        """AC1: echo_node requires 0.3.4, runtime is 0.3.5, allowed."""
        loader = NodeLoader()
        node = loader.load("echo_node")
        assert node.manifest.node_id == "echo_node"

    def test_version_check_method(self):
        """AC1: Version check method works."""
        enforcer = PackagePolicyEnforcer()
        ok, msg = enforcer.check_version("0.3.4")
        assert ok is True

    def test_version_check_blocks_higher(self):
        """AC1: Higher version requirement blocked."""
        enforcer = PackagePolicyEnforcer()
        ok, msg = enforcer.check_version("99.0.0")
        assert ok is False
        assert "99.0.0" in msg

    def test_version_check_empty_skips(self):
        """AC1: Empty version requirement passes."""
        enforcer = PackagePolicyEnforcer()
        ok, msg = enforcer.check_version("")
        assert ok is True

    def test_skip_policy_flag(self):
        """AC1: skip_policy=True bypasses version gate.
        v2.45.2: skip_policy does not bypass registry admission.
        future_node denied by admission — not loadable even with skip."""
        loader = NodeLoader()
        # v2.45.2: admission blocks at scan, not at load — skip_policy
        # only bypasses load-time enforcement, not registry admission
        with pytest.raises(NodeLoadError, match="not found in registry"):
            loader.load("future_node", skip_policy=True)


class TestParseVersion:
    """Version parsing utility."""

    def test_simple_version(self):
        assert parse_version("1.2.3") == (1, 2, 3)

    def test_version_comparison(self):
        assert parse_version("0.3.4") < parse_version("0.3.5")
        assert parse_version("0.3.5") >= parse_version("0.3.4")

    def test_major_version(self):
        assert parse_version("99.0.0") > parse_version("0.3.5")


class TestStrictModeCapabilities:
    """AC2/AC5: Strict mode blocks undeclared/dangerous capabilities."""

    def test_strict_mode_from_env(self):
        """AC2: Strict mode reads from NODECHAIN_GOVERNANCE_STRICT."""
        old = os.environ.get("NODECHAIN_GOVERNANCE_STRICT")
        try:
            os.environ["NODECHAIN_GOVERNANCE_STRICT"] = "1"
            enforcer = PackagePolicyEnforcer()
            assert enforcer.strict is True
        finally:
            if old is None:
                os.environ.pop("NODECHAIN_GOVERNANCE_STRICT", None)
            else:
                os.environ["NODECHAIN_GOVERNANCE_STRICT"] = old

    def test_strict_mode_explicit(self):
        """AC2: Strict mode can be set explicitly."""
        enforcer = PackagePolicyEnforcer(strict=True)
        assert enforcer.strict is True

    def test_strict_blocks_network(self):
        """AC5: Strict mode blocks network capability."""
        enforcer = PackagePolicyEnforcer(strict=True)
        result = enforcer.enforce_package(
            package_id="test",
            node_id="test",
            package_yaml={
                "capabilities": {"network": True},
            },
        )
        assert result.decision == PolicyDecision.BLOCK
        assert any("network" in r for r in result.reasons)

    def test_strict_blocks_subprocess(self):
        """AC5: Strict mode blocks subprocess capability."""
        enforcer = PackagePolicyEnforcer(strict=True)
        result = enforcer.enforce_package(
            package_id="test",
            node_id="test",
            package_yaml={
                "capabilities": {"subprocess": True},
            },
        )
        assert result.decision == PolicyDecision.BLOCK

    def test_strict_blocks_write_filesystem(self):
        """AC5: Strict mode blocks write filesystem."""
        enforcer = PackagePolicyEnforcer(strict=True)
        result = enforcer.enforce_package(
            package_id="test",
            node_id="test",
            package_yaml={
                "capabilities": {"filesystem": "write"},
            },
        )
        assert result.decision == PolicyDecision.BLOCK

    def test_strict_allows_safe_capabilities(self):
        """AC5: Strict mode allows safe capabilities."""
        enforcer = PackagePolicyEnforcer(strict=True)
        result = enforcer.enforce_package(
            package_id="test",
            node_id="test",
            package_yaml={
                "capabilities": {
                    "network": False,
                    "filesystem": "none",
                    "memory_write": False,
                    "external_api": False,
                },
            },
        )
        assert result.decision == PolicyDecision.ALLOW

    def test_non_strict_warns(self):
        """AC5: Non-strict mode allows but the audit is still clean."""
        enforcer = PackagePolicyEnforcer(strict=False)
        result = enforcer.enforce_package(
            package_id="test",
            node_id="test",
            package_yaml={
                "capabilities": {"network": True},
            },
        )
        # Non-strict doesn't block on capabilities (no version issue)
        assert result.decision == PolicyDecision.ALLOW


class TestSideEffectAudit:
    """AC3: Strict mode blocks undeclared side effects."""

    def test_check_side_effects_clean(self):
        """AC3: Declared side effects pass."""
        enforcer = PackagePolicyEnforcer(strict=True)
        dec, issues = enforcer.check_side_effects(
            declared_side_effects=["network", "external_api"],
            observed_side_effects=["network", "external_api"],
        )
        assert dec == PolicyDecision.ALLOW
        assert issues == []

    def test_check_side_effects_undeclared_strict(self):
        """AC3: Undeclared side effect blocks in strict mode."""
        enforcer = PackagePolicyEnforcer(strict=True)
        dec, issues = enforcer.check_side_effects(
            declared_side_effects=["network"],
            observed_side_effects=["network", "memory_write"],
        )
        assert dec == PolicyDecision.BLOCK
        assert any("memory_write" in i for i in issues)

    def test_check_side_effects_undeclared_non_strict(self):
        """AC3: Undeclared side effect warns in non-strict mode."""
        enforcer = PackagePolicyEnforcer(strict=False)
        dec, issues = enforcer.check_side_effects(
            declared_side_effects=[],
            observed_side_effects=["network"],
        )
        assert dec == PolicyDecision.WARN


class TestPolicyResult:
    """AC6: Policy results are structured."""

    def test_result_fields(self):
        """AC6: PackagePolicyResult has correct fields."""
        result = PackagePolicyResult(
            package_id="test",
            node_id="test",
            decision=PolicyDecision.ALLOW,
            version_check="ok",
            capability_audit="clean",
            side_effect_audit="clean",
        )
        assert result.decision == PolicyDecision.ALLOW
        assert result.version_check == "ok"
        assert result.reasons == []

    def test_loader_stores_policy_results(self):
        """AC6: Loader stores policy results for reporting."""
        loader = NodeLoader()
        loader.load("echo_node")
        results = loader.policy_results
        assert "echo_node" in results
        assert results["echo_node"].decision == PolicyDecision.ALLOW
        assert results["echo_node"].version_check == "ok"


class TestPackagePathEnforcement:
    """AC4/AC5: Enforcement from real package files."""

    def test_echo_node_policy_from_file(self):
        """AC4: Policy check reads from actual node.yaml."""
        enforcer = PackagePolicyEnforcer()
        result = enforcer.enforce_package(
            package_id="echo_node",
            node_id="echo_node",
            package_path=Path("nodes/echo_node"),
        )
        assert result.decision == PolicyDecision.ALLOW
        assert result.version_check == "ok"
        assert result.capability_audit == "clean"

    def test_text_transforms_policy_from_file(self):
        """AC4: Policy check reads from actual package.yaml."""
        enforcer = PackagePolicyEnforcer()
        result = enforcer.enforce_package(
            package_id="text-transforms",
            node_id="uppercase_node",
            package_path=Path("nodes/text_transforms"),
        )
        assert result.decision == PolicyDecision.ALLOW

    def test_future_node_policy_blocked_from_file(self):
        """AC5: Version gate blocks from file."""
        enforcer = PackagePolicyEnforcer()
        result = enforcer.enforce_package(
            package_id="future_node",
            node_id="future_node",
            package_path=Path("nodes/future_node"),
        )
        assert result.decision == PolicyDecision.BLOCK
        assert result.version_check == "blocked"

    def test_nonexistent_package_skips(self):
        """AC5: Nonexistent package path skips checks."""
        enforcer = PackagePolicyEnforcer()
        result = enforcer.enforce_package(
            package_id="nonexistent",
            node_id="nonexistent",
            package_path=Path("nodes/nonexistent"),
        )
        assert result.decision == PolicyDecision.ALLOW
        assert result.version_check == "skipped"
