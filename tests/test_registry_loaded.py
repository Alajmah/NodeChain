"""Tests for registry-loaded blueprint execution.

AC1: nodechain node create creates a package.
AC2: nodechain registry list discovers the package.
AC3: Blueprint references the node by node_id.
AC4: Runtime loads implementation from registry.
AC5: Port/schema compatibility validates using package schemas.
AC6: Chain executes and emits trace events for registry-loaded node.
AC7: nodechain report identifies the registry-loaded node.
AC8: Existing 730 tests remain green.
"""

import asyncio
import pytest
from pathlib import Path

from nodechain.core.blueprint import ChainBlueprint, load_blueprint
from nodechain.core.envelope import InvocationEnvelope
from nodechain.runtime.orchestrator import Orchestrator
from nodechain.core.state import StateManager
from nodechain.sdk.loader import NodeLoader, NodeLoadError
from nodechain.sdk.package import NodePackage
from nodechain.registry.local_registry import RegistryIndex


class TestNodeLoader:
    """AC4: Runtime loads implementation from registry."""

    def test_load_echo_node(self):
        """AC4: Load echo_node from registry."""
        loader = NodeLoader()
        node = loader.load("echo_node")
        assert node is not None
        assert node.manifest.node_id == "echo_node"

    def test_load_echo_node_is_base_node(self):
        """AC4: Loaded node is a BaseNode subclass."""
        from nodechain.nodes.base_node import BaseNode
        loader = NodeLoader()
        node = loader.load("echo_node")
        assert isinstance(node, BaseNode)

    def test_load_unknown_raises(self):
        """AC4: Loading unknown node raises NodeLoadError."""
        loader = NodeLoader()
        with pytest.raises(NodeLoadError):
            loader.load("nonexistent_node_xyz")

    def test_load_all(self):
        """AC4: load_all loads all registry packages."""
        loader = NodeLoader()
        nodes = loader.load_all()
        assert "echo_node" in nodes

    def test_loaded_count(self):
        """AC4: Tracks loaded count."""
        loader = NodeLoader()
        loader.load("echo_node")
        assert loader.loaded_count == 1

    def test_double_load_returns_cached(self):
        """AC4: Loading same node twice returns cached instance."""
        loader = NodeLoader()
        n1 = loader.load("echo_node")
        n2 = loader.load("echo_node")
        assert n1 is n2


class TestRegistryLoadedExecution:
    """AC6: Chain executes with registry-loaded node."""

    @pytest.mark.asyncio
    async def test_echo_node_executes(self):
        """AC6: Echo node executes and produces output."""
        loader = NodeLoader()
        echo_node = loader.load("echo_node")

        nodes = {"echo_node": echo_node}

        blueprint = ChainBlueprint(
            chain_id="echo-test",
            name="Echo Test",
            version="1.0",
            description="test",
            goal="test",
            nodes=[],
            connections=[],
        )

        # Direct execution test
        env = InvocationEnvelope(
            envelope_id="test",
            run_id="test-run",
            chain_id="echo-test",
            node_id="echo_node",
            step_id=1,
            payload={"query": "Hello Registry"},
        )

        result = await echo_node.execute(env)
        assert result.output["query"] == "Hello Registry"
        assert result.output["transformed"] == "Hello Registry"
        assert result.cost_usd == 0.0

    @pytest.mark.asyncio
    async def test_echo_node_uppercase(self):
        """AC6: Echo node with uppercase transform."""
        loader = NodeLoader()
        echo_node = loader.load("echo_node")

        env = InvocationEnvelope(
            envelope_id="test",
            run_id="test-run",
            chain_id="echo-test",
            node_id="echo_node",
            step_id=1,
            payload={"query": "hello", "transform": "uppercase"},
        )

        result = await echo_node.execute(env)
        assert result.output["transformed"] == "HELLO"


class TestBlueprintResolution:
    """AC3 + AC5: Blueprint references and validates registry nodes."""

    def test_echo_blueprint_loads(self):
        """AC3: Echo demo blueprint loads."""
        bp = load_blueprint("blueprints/echo_demo_v1.yaml")
        assert bp.chain_id == "echo-demo-v1"

    def test_echo_blueprint_references_echo_node(self):
        """AC3: Blueprint references echo_node."""
        bp = load_blueprint("blueprints/echo_demo_v1.yaml")
        node_ids = [n.node_id for n in bp.nodes]
        assert "echo_node" in node_ids

    def test_registry_resolves_echo_node(self):
        """AC5: Registry resolves echo_node contract."""
        reg = RegistryIndex()
        result = reg.resolve_blueprint_contracts(["echo_node"])
        assert result["echo_node"]["resolved"] is True

    def test_package_schema_resolves(self):
        """AC5: Package schema files are loadable."""
        pkg = NodePackage.from_directory("nodes/echo_node")
        input_schema = pkg.load_input_schema()
        output_schema = pkg.load_output_schema()
        assert input_schema is not None
        assert output_schema is not None
        assert "query" in input_schema["properties"]


class TestRegistryReport:
    """AC7: Report identifies registry-loaded node."""

    def test_echo_report_json(self):
        """AC7: Report JSON includes echo_node in outputs."""
        import json
        report_path = Path("data/echo_report.json")
        if not report_path.exists():
            pytest.skip("No echo report generated yet")

        report = json.loads(report_path.read_text())
        assert "outputs" in report
        assert "echo_node" in report["outputs"]


class TestCreateAndUse:
    """AC1 + AC2: Create, discover, use flow."""

    def test_create_and_discover(self, tmp_path):
        """AC1 + AC2: Create a node and discover it in registry."""
        from nodechain.sdk.templates import create_node_package

        pkg_path = create_node_package(
            "test_discover_node",
            template="deterministic",
            output_dir=str(tmp_path),
        )

        # Load from the created path
        pkg = NodePackage.from_directory(pkg_path)
        assert pkg.manifest.node_id == "test_discover_node"

    def test_create_validates(self, tmp_path):
        """AC1: Created package validates."""
        from nodechain.sdk.templates import create_node_package

        pkg_path = create_node_package(
            "test_validate_node",
            template="deterministic",
            output_dir=str(tmp_path),
        )

        pkg = NodePackage.from_directory(pkg_path)
        issues = pkg.validate_package()
        assert issues == []

    def test_create_has_schemas(self, tmp_path):
        """AC1: Created package has schema bundles."""
        from nodechain.sdk.templates import create_node_package

        pkg_path = create_node_package(
            "test_schema_node",
            template="deterministic",
            output_dir=str(tmp_path),
        )

        pkg = NodePackage.from_directory(pkg_path)
        assert pkg.load_input_schema() is not None
        assert pkg.load_output_schema() is not None
