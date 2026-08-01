"""Tests for Node SDK and Registry.

AC1: Developer can create a node package from a template.
AC2: Package includes implementation, contract, schemas, tests, and manifest.
AC3: nodechain node validate checks contract/schema/side-effect declarations.
AC4: nodechain node test runs package-local tests.
AC5: Local registry can discover and load the package.
AC6: Blueprint validation can resolve node contracts from registry.
AC7: Golden demo runs using at least one registry-loaded node.
AC8: Existing 676 tests remain green.
"""

import pytest
from pathlib import Path

from nodechain.sdk.package import NodePackage, NodePackageMeta
from nodechain.registry.local_registry import RegistryIndex
from nodechain.core.contract import NodeContract


EXAMPLE_NODE = "nodes/echo_node"


class TestNodePackage:
    """AC1 + AC2: Package loading and structure."""

    def test_load_from_directory(self):
        """AC1: Load package from directory."""
        pkg = NodePackage.from_directory(EXAMPLE_NODE)
        assert pkg.manifest.node_id == "echo_node"

    def test_load_from_yaml(self):
        """AC1: Load package from node.yaml."""
        pkg = NodePackage.from_yaml(f"{EXAMPLE_NODE}/node.yaml")
        assert pkg.manifest.node_id == "echo_node"

    def test_package_has_manifest(self):
        """AC2: Package has manifest with identity."""
        pkg = NodePackage.from_directory(EXAMPLE_NODE)
        assert pkg.manifest.name == "Echo Node"
        assert pkg.manifest.node_type == "deterministic"
        assert pkg.manifest.version == "1.0.0"

    def test_package_has_contract(self):
        """AC2: Package has contract with entry/exit."""
        pkg = NodePackage.from_directory(EXAMPLE_NODE)
        contract = pkg.manifest.contract
        assert contract.entry.input_type == "raw_user_query"
        assert contract.exit.output_type == "raw_user_query"
        assert "query" in contract.entry.required_fields

    def test_package_has_implementation(self):
        """AC2: Package has implementation.py."""
        pkg = NodePackage.from_directory(EXAMPLE_NODE)
        assert pkg.get_implementation_path() is not None

    def test_package_has_tests(self):
        """AC2: Package has test files."""
        pkg = NodePackage.from_directory(EXAMPLE_NODE)
        assert pkg.get_test_path() is not None

    def test_package_meta(self):
        """AC2: Package has metadata."""
        pkg = NodePackage.from_directory(EXAMPLE_NODE)
        assert pkg.package_meta.author == "NodeChain"
        assert pkg.package_meta.license == "MIT"


class TestNodeValidate:
    """AC3: nodechain node validate checks declarations."""

    def test_valid_package_passes(self):
        """AC3: Valid package has no issues."""
        pkg = NodePackage.from_directory(EXAMPLE_NODE)
        issues = pkg.validate_package()
        assert issues == []

    def test_missing_implementation_detected(self, tmp_path):
        """AC3: Missing implementation.py detected."""
        # Create a minimal node.yaml without implementation.py
        yaml_content = {
            "manifest": {
                "node_id": "test_node",
                "node_type": "deterministic",
                "name": "Test",
                "description": "Test node",
            },
            "contract": {
                "contract_id": "test.v1",
                "entry": {
                    "input_type": "raw_user_query",
                    "schema_ref": "test",
                    "required_fields": ["query"],
                },
                "exit": {
                    "output_type": "raw_user_query",
                    "schema_ref": "test",
                    "guaranteed_fields": ["query"],
                },
                "side_effects": [],
                "requirements": {},
            },
        }
        import yaml
        with open(tmp_path / "node.yaml", "w") as f:
            yaml.dump(yaml_content, f)

        pkg = NodePackage.from_directory(tmp_path)
        issues = pkg.validate_package()
        assert any("implementation.py" in i for i in issues)

    def test_missing_yaml_raises(self, tmp_path):
        """AC3: Missing node.yaml raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            NodePackage.from_directory(tmp_path)


class TestLocalRegistry:
    """AC5: Local registry discovers and loads packages."""

    def test_scan_finds_echo_node(self):
        """AC5: Registry finds echo_node."""
        reg = RegistryIndex()
        count = reg.scan()
        assert count >= 1

    def test_list_packages(self):
        """AC5: Registry lists packages."""
        reg = RegistryIndex()
        pkgs = reg.list_packages()
        node_ids = [p["node_id"] for p in pkgs]
        assert "echo_node" in node_ids

    def test_inspect_package(self):
        """AC5: Registry inspects a specific package."""
        reg = RegistryIndex()
        info = reg.inspect("echo_node")
        assert info is not None
        assert info["name"] == "Echo Node"
        assert "contract" in info

    def test_inspect_nonexistent_returns_none(self):
        """AC5: Inspect nonexistent returns None."""
        reg = RegistryIndex()
        info = reg.inspect("nonexistent_node")
        assert info is None

    def test_get_contract(self):
        """AC5: Registry provides contract for a node."""
        reg = RegistryIndex()
        contract = reg.get_contract("echo_node")
        assert contract is not None
        assert contract.entry.input_type == "raw_user_query"

    def test_search(self):
        """AC5: Registry search finds packages."""
        reg = RegistryIndex()
        results = reg.search("echo")
        assert len(results) >= 1
        assert results[0]["node_id"] == "echo_node"

    def test_search_no_results(self):
        """AC5: Search with no matches returns empty."""
        reg = RegistryIndex()
        results = reg.search("nonexistent_xyzzy")
        assert len(results) == 0


class TestBlueprintResolution:
    """AC6: Blueprint validation resolves node contracts from registry."""

    def test_resolve_known_node(self):
        """AC6: Known node resolves from registry."""
        reg = RegistryIndex()
        result = reg.resolve_blueprint_contracts(["echo_node"])
        assert result["echo_node"]["resolved"] is True
        assert result["echo_node"]["contract_id"] == "utility.echo.v1"

    def test_resolve_unknown_node(self):
        """AC6: Unknown node does not resolve."""
        reg = RegistryIndex()
        result = reg.resolve_blueprint_contracts(["unknown_node"])
        assert result["unknown_node"]["resolved"] is False

    def test_resolve_mixed_nodes(self):
        """AC6: Mixed known/unknown nodes resolve correctly."""
        reg = RegistryIndex()
        result = reg.resolve_blueprint_contracts(["echo_node", "unknown_node"])
        assert result["echo_node"]["resolved"] is True
        assert result["unknown_node"]["resolved"] is False

    def test_extra_paths(self, tmp_path):
        """AC6: Extra search paths work."""
        reg = RegistryIndex(extra_paths=["nonexistent_dir", "nodes"])
        reg.scan()
        assert reg.package_count >= 1


class TestNodeTest:
    """AC4: nodechain node test runs package-local tests."""

    def test_node_has_test_path(self):
        """AC4: Package reports test file path."""
        pkg = NodePackage.from_directory(EXAMPLE_NODE)
        test_path = pkg.get_test_path()
        assert test_path is not None
        assert test_path.exists()

    def test_node_has_implementation(self):
        """AC4: Package has loadable implementation."""
        pkg = NodePackage.from_directory(EXAMPLE_NODE)
        impl_path = pkg.get_implementation_path()
        assert impl_path is not None
        assert impl_path.exists()
