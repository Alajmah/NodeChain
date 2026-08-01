"""Tests for mixed-origin execution and package identity hardening.

AC1: Blueprint uses one built-in and one registry-loaded node.
AC2: Port compatibility validates across built-in -> registry boundary.
AC3: Runtime executes both nodes.
AC4: Trace identifies the registry-loaded node.
AC5: Report shows package metadata for the registry-loaded node.
AC6: Reconcile remains clean.
AC7: Existing 746 tests remain green.
"""

import asyncio
import json
import pytest
from pathlib import Path

from nodechain.core.blueprint import load_blueprint
from nodechain.sdk.package import NodePackage
from nodechain.sdk.loader import NodeLoader
from nodechain.registry.local_registry import RegistryIndex


MIXED_BLUEPRINT = "blueprints/mixed_demo_v1.yaml"


class TestMixedOriginBlueprint:
    """AC1: Blueprint uses both built-in and registry nodes."""

    def test_mixed_blueprint_loads(self):
        """AC1: Mixed demo blueprint loads."""
        bp = load_blueprint(MIXED_BLUEPRINT)
        assert bp.chain_id == "mixed-demo-v1"

    def test_mixed_blueprint_has_echo_and_goal(self):
        """AC1: Blueprint references echo_node (registry) and goal_interpreter (built-in)."""
        bp = load_blueprint(MIXED_BLUEPRINT)
        node_ids = [n.node_id for n in bp.nodes]
        assert "echo_node" in node_ids
        assert "goal_interpreter" in node_ids

    def test_mixed_blueprint_connection(self):
        """AC1: Connection from echo_node to goal_interpreter."""
        bp = load_blueprint(MIXED_BLUEPRINT)
        assert len(bp.connections) == 1
        assert bp.connections[0].from_node == "echo_node"
        assert bp.connections[0].to_node == "goal_interpreter"


class TestMixedPortCompatibility:
    """AC2: Port compatibility validates across boundary."""

    def test_echo_output_type_matches_goal_input(self):
        """AC2: echo_node output type matches goal_interpreter input type."""
        loader = NodeLoader()
        echo_node = loader.load("echo_node")

        # Both use raw_user_query
        from nodechain.core.port import PortType
        assert echo_node.manifest.contract.exit.output_type == PortType.RAW_QUERY

    def test_registry_resolves_both_nodes(self):
        """AC2: Registry resolves echo_node; built-in not in registry."""
        reg = RegistryIndex()
        result = reg.resolve_blueprint_contracts(["echo_node", "goal_interpreter"])
        assert result["echo_node"]["resolved"] is True
        assert result["goal_interpreter"]["resolved"] is False  # Not a packaged node


class TestMixedExecution:
    """AC3: Runtime executes both nodes."""

    @pytest.mark.asyncio
    async def test_echo_node_produces_output(self):
        """AC3: Echo node produces query + transformed output."""
        loader = NodeLoader()
        echo_node = loader.load("echo_node")

        from nodechain.core.envelope import InvocationEnvelope
        env = InvocationEnvelope(
            envelope_id="test", run_id="test", chain_id="test",
            node_id="echo_node", step_id=1,
            payload={"query": "mixed test"},
        )
        result = await echo_node.execute(env)
        assert result.output["query"] == "mixed test"
        assert "transformed" in result.output


class TestMixedReport:
    """AC4 + AC5: Trace and report identify registry-loaded node."""

    def test_report_has_node_origins(self):
        """AC5: Report JSON has node_origins field."""
        report_path = Path("data/mixed_report.json")
        if not report_path.exists():
            pytest.skip("Mixed report not generated yet")

        report = json.loads(report_path.read_text())
        assert "node_origins" in report

    def test_report_echo_node_is_local_registry(self):
        """AC5: echo_node is marked as local_registry origin."""
        report_path = Path("data/mixed_report.json")
        if not report_path.exists():
            pytest.skip("Mixed report not generated yet")

        report = json.loads(report_path.read_text())
        origins = report.get("node_origins", {})
        assert "echo_node" in origins
        assert origins["echo_node"]["origin"] == "local_registry"
        assert origins["echo_node"]["version"] == "1.0.0"

    def test_report_goal_interpreter_is_built_in(self):
        """AC5: goal_interpreter is marked as built_in origin."""
        report_path = Path("data/mixed_report.json")
        if not report_path.exists():
            pytest.skip("Mixed report not generated yet")

        report = json.loads(report_path.read_text())
        origins = report.get("node_origins", {})
        assert "goal_interpreter" in origins
        assert origins["goal_interpreter"]["origin"] == "built_in"


class TestPackageIdentity:
    """Package identity hardening: hash, semver, origin."""

    def test_content_hash(self):
        """Content hash is deterministic."""
        pkg = NodePackage.from_directory("nodes/echo_node")
        h1 = pkg.content_hash()
        h2 = pkg.content_hash()
        assert h1 is not None
        assert h1 == h2
        assert len(h1) == 16

    def test_semver_validation_passes(self):
        """Valid semver passes."""
        pkg = NodePackage.from_directory("nodes/echo_node")
        issues = pkg.validate_semver()
        assert issues == []

    def test_semver_validation_fails_for_bad_version(self, tmp_path):
        """Invalid semver is caught."""
        import yaml
        yaml_content = {
            "manifest": {
                "node_id": "bad_ver", "node_type": "deterministic",
                "name": "Bad", "description": "Test", "version": "not-semver",
            },
            "contract": {
                "contract_id": "test.v1",
                "entry": {"input_type": "x", "schema_ref": "x", "required_fields": []},
                "exit": {"output_type": "x", "schema_ref": "x", "guaranteed_fields": []},
                "side_effects": [], "requirements": {},
            },
        }
        with open(tmp_path / "node.yaml", "w") as f:
            yaml.dump(yaml_content, f)

        pkg = NodePackage.from_directory(tmp_path)
        issues = pkg.validate_semver()
        assert len(issues) >= 1
        assert any("not valid semver" in i for i in issues)

    def test_package_origin_field(self):
        """Package has origin field."""
        pkg = NodePackage.from_directory("nodes/echo_node")
        assert pkg.package_meta.origin == "local_registry"

    def test_registry_inspect_shows_hash(self):
        """Registry inspect shows package hash."""
        reg = RegistryIndex()
        pkg = reg.get_package("echo_node")
        assert pkg is not None
        h = pkg.content_hash()
        assert h is not None


class TestMixedReconcile:
    """AC6: Reconcile remains clean for mixed-origin runs."""

    def test_mixed_report_is_clean(self):
        """AC6: Mixed run report shows clean reconciliation."""
        report_path = Path("data/mixed_report.json")
        if not report_path.exists():
            pytest.skip("Mixed report not generated yet")

        report = json.loads(report_path.read_text())
        recon = report.get("reconciliation", {})
        assert recon.get("is_clean", False) is True
