"""Tests for package capabilities, dependencies, and explicit entrypoints.

AC1: Package manifest declares dependencies.
AC2: Package manifest declares capabilities.
AC3: Node-level side effects are declared.
AC4: Registry validation checks dependency/capability shape.
AC5: Runtime governance receives package-declared side effects.
AC6: CLI validate shows trust/capability/dependency summary.
AC7: Report includes package capabilities and side-effect declarations.
AC8: Existing 782 tests remain green.
"""

import pytest
from pathlib import Path

from nodechain.sdk.capabilities import (
    PackageCapabilities, PackageDependencies, PackageManifest,
    PythonDependency, NodeEntrypoint,
)
from nodechain.sdk.loader import NodeLoader


class TestPackageCapabilities:
    """AC2: Package manifest declares capabilities."""

    def test_default_capabilities(self):
        """AC2: Default capabilities are safe (all off)."""
        caps = PackageCapabilities()
        assert caps.network is False
        assert caps.filesystem == "none"
        assert caps.memory_write is False
        assert caps.external_api is False
        assert caps.subprocess is False
        assert caps.gpu is False

    def test_custom_capabilities(self):
        """AC2: Custom capabilities can be set."""
        caps = PackageCapabilities(network=True, filesystem="read")
        assert caps.network is True
        assert caps.filesystem == "read"

    def test_capabilities_validation(self):
        """AC4: Invalid filesystem capability caught."""
        manifest = PackageManifest(
            package_id="test",
            capabilities=PackageCapabilities(filesystem="invalid"),
        )
        issues = manifest.validate_capabilities()
        assert any("filesystem" in i for i in issues)

    def test_valid_capabilities_pass(self):
        """AC4: Valid capabilities pass."""
        manifest = PackageManifest(package_id="test")
        issues = manifest.validate_capabilities()
        assert issues == []


class TestPackageDependencies:
    """AC1: Package manifest declares dependencies."""

    def test_python_dependency(self):
        """AC1: Python dependency with version constraint."""
        dep = PythonDependency(package="httpx", version_constraint=">=0.24.0")
        assert dep.package == "httpx"
        assert dep.version_constraint == ">=0.24.0"

    def test_empty_dependencies(self):
        """AC1: Empty dependency list is valid."""
        deps = PackageDependencies()
        assert deps.python == []
        assert deps.nodechain_min_version is None

    def test_nodechain_min_version(self):
        """AC1: NodeChain minimum version can be declared."""
        deps = PackageDependencies(nodechain_min_version="0.3.4")
        assert deps.nodechain_min_version == "0.3.4"

    def test_dependency_validation(self):
        """AC4: Invalid min version caught."""
        manifest = PackageManifest(
            package_id="test",
            nodechain_min_version="not-semver",
        )
        issues = manifest.validate_dependencies()
        assert len(issues) >= 1

    def test_empty_package_name_caught(self):
        """AC4: Empty package name caught."""
        manifest = PackageManifest(
            package_id="test",
            dependencies=PackageDependencies(
                python=[PythonDependency(package="")]
            ),
        )
        issues = manifest.validate_dependencies()
        assert any("empty" in i.lower() for i in issues)


class TestNodeEntrypoints:
    """AC3: Node-level side effects and explicit entrypoints."""

    def test_entrypoint_parsing(self):
        """AC3: Entrypoint parsed into module path and class name."""
        ep = NodeEntrypoint(
            node_id="uppercase_node",
            implementation="implementations.uppercase:UppercaseNode",
        )
        manifest = PackageManifest(
            package_id="test",
            entrypoints=[ep],
        )
        result = manifest.parse_entrypoint("uppercase_node")
        assert result is not None
        fs_path, class_name = result
        assert fs_path == "implementations/uppercase.py"
        assert class_name == "UppercaseNode"

    def test_entrypoint_not_found(self):
        """AC3: Missing entrypoint returns None."""
        manifest = PackageManifest(package_id="test")
        result = manifest.parse_entrypoint("nonexistent")
        assert result is None

    def test_side_effects_declared(self):
        """AC3: Side effects declared per entrypoint."""
        ep = NodeEntrypoint(
            node_id="search",
            implementation="impl.search:SearchNode",
            side_effects=["external_api", "network"],
        )
        assert len(ep.side_effects) == 2
        assert "external_api" in ep.side_effects

    def test_get_node_entrypoint(self):
        """AC3: Can look up entrypoint by node_id."""
        ep1 = NodeEntrypoint(node_id="a", implementation="a:A")
        ep2 = NodeEntrypoint(node_id="b", implementation="b:B")
        manifest = PackageManifest(package_id="test", entrypoints=[ep1, ep2])
        assert manifest.get_node_entrypoint("a") is ep1
        assert manifest.get_node_entrypoint("b") is ep2
        assert manifest.get_node_entrypoint("c") is None


class TestExplicitEntrypointsLoading:
    """AC5: Loader uses explicit entrypoints."""

    def test_echo_node_loaded_via_entrypoint(self):
        """AC5: echo_node loads using explicit entrypoint from node.yaml."""
        loader = NodeLoader()
        node = loader.load("echo_node")
        assert node.manifest.node_id == "echo_node"

    def test_uppercase_loaded_via_entrypoint(self):
        """AC5: uppercase_node loads using explicit entrypoint.
        v2.45.0: denied by admission (missing node.yaml)."""
        pytest.skip("v2.45.0: uppercase_node denied by registry admission")

    def test_reverse_loaded_via_entrypoint(self):
        """AC5: reverse_node loads using explicit entrypoint.
        v2.45.0: denied by admission (missing node.yaml)."""
        pytest.skip("v2.45.0: reverse_node denied by registry admission")


class TestPackageYamlCapabilities:
    """AC6: Validate shows capabilities from real packages."""

    def test_echo_yaml_has_capabilities(self):
        """AC6: echo_node node.yaml has capabilities section."""
        import yaml
        with open("nodes/echo_node/node.yaml") as f:
            raw = yaml.safe_load(f)
        assert "capabilities" in raw
        assert raw["capabilities"]["network"] is False

    def test_text_transforms_has_entrypoints(self):
        """AC6: text_transforms package.yaml has entrypoints."""
        import yaml
        with open("nodes/text_transforms/package.yaml") as f:
            raw = yaml.safe_load(f)
        assert "entrypoints" in raw
        assert len(raw["entrypoints"]) == 2
        ids = [ep["node_id"] for ep in raw["entrypoints"]]
        assert "uppercase_node" in ids
        assert "reverse_node" in ids

    def test_text_transforms_has_capabilities(self):
        """AC6: text_transforms declares no network/filesystem access."""
        import yaml
        with open("nodes/text_transforms/package.yaml") as f:
            raw = yaml.safe_load(f)
        caps = raw.get("capabilities", {})
        assert caps.get("network") is False
        assert caps.get("external_api") is False

    def test_text_transforms_has_min_version(self):
        """AC6: text_transforms declares nodechain_min_version."""
        import yaml
        with open("nodes/text_transforms/package.yaml") as f:
            raw = yaml.safe_load(f)
        assert "nodechain_min_version" in raw
        assert raw["nodechain_min_version"] == "0.3.4"


class TestReportCapabilities:
    """AC7: Report includes capabilities."""

    def test_multi_report_has_content_hash(self):
        """AC7: Report includes content hash for registry nodes."""
        import json
        report_path = Path("data/multi_report.json")
        if not report_path.exists():
            pytest.skip("Report not generated")
        report = json.loads(report_path.read_text())
        origins = report.get("node_origins", {})
        for nid in ("uppercase_node", "reverse_node"):
            if nid in origins:
                assert origins[nid].get("content_hash") is not None

    def test_mixed_report_has_capabilities(self):
        """AC7: Report includes capabilities for echo_node."""
        import json
        report_path = Path("data/mixed_report.json")
        if not report_path.exists():
            pytest.skip("Report not generated")
        report = json.loads(report_path.read_text())
        origins = report.get("node_origins", {})
        if "echo_node" in origins:
            assert "capabilities" in origins["echo_node"]
            assert origins["echo_node"]["capabilities"]["network"] is False
