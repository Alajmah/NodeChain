"""Release candidate smoke tests for v1.0.0-rc1.

These tests verify the frozen public surfaces and demo paths are intact.
They do NOT execute actual chains (that requires mock provider / network).
Instead they verify the surface contract: commands, schemas, exit codes,
trust invariants, demo scripts, and version consistency.

Run: python -m pytest tests/test_rc1_smoke.py -v
"""

import json
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent


# ── 1. CLI Surface Frozen ──────────────────────────────────────────

class TestCLISurfaceFrozen:
    """Verify all top-level CLI commands exist."""

    EXPECTED_TOP_LEVEL = {
        "run", "inspect", "reconcile", "resume", "presets",
        "report", "trace", "trust", "trust-store", "deploy-receipt", "assurance", "deploy", "registry", "node",
        "audit-bundle",
            "attest",
            "release-history", "drift", "eval",
            "evidence", "trace-replay", "dashboard",
        "compose", "policy", "marketplace", "supply-chain", "retention",
        "checkpoint",
            "graph",
            "console",
            "review",
            "recover",
            "api",
    }

    EXPECTED_REGISTRY_SUB = {"list", "inspect", "lock", "verify", "publish", "certified-list", "certified-inspect", "certified-verify", "deprecate", "revoke", "install", "resolve", "install-remote", "serve", "remote-build", "resolve-deps", "transparency", "federation", "reputation"}
    EXPECTED_NODE_SUB = {"validate", "test", "create", "check-compat"}

    def test_top_level_commands(self):
        from nodechain.cli.main import cli
        assert set(cli.commands.keys()) == self.EXPECTED_TOP_LEVEL

    def test_registry_subcommands(self):
        from nodechain.cli.main import cli
        registry = cli.commands["registry"]
        assert set(registry.commands.keys()) == self.EXPECTED_REGISTRY_SUB

    def test_node_subcommands(self):
        from nodechain.cli.main import cli
        node = cli.commands["node"]
        assert set(node.commands.keys()) == self.EXPECTED_NODE_SUB

    def test_run_has_all_frozen_flags(self):
        from nodechain.cli.main import cli
        run_cmd = cli.commands["run"]
        flag_names = set()
        for p in run_cmd.params:
            for name in p.opts:
                flag_names.add(name.lstrip("-"))
        expected_flags = {"blueprint", "b", "trace-dir", "t", "model", "m",
                          "strict", "review-mode", "provider", "json",
                          "locked", "trust-check"}
        assert expected_flags.issubset(flag_names), \
            f"Missing flags: {expected_flags - flag_names}"


# ── 2. Exit Code Table Frozen ──────────────────────────────────────

class TestExitCodesFrozen:

    def test_all_ten_codes(self):
        from nodechain.cli.exit_codes import (
            EXIT_OK, EXIT_NOT_FOUND, EXIT_RECONCILE_ERRORS,
            EXIT_RECONCILE_RECOVERY, EXIT_RUN_VALIDATION,
            EXIT_RUN_PAUSED, EXIT_RUN_FAILED,
            EXIT_RESUME_NOT_RESUMABLE, EXIT_RESUME_FAILED,
            EXIT_TRUST_VIOLATION,
        )
        expected = {0, 1, 2, 3, 10, 11, 12, 13, 14, 15}
        actual = {
            EXIT_OK, EXIT_NOT_FOUND, EXIT_RECONCILE_ERRORS,
            EXIT_RECONCILE_RECOVERY, EXIT_RUN_VALIDATION,
            EXIT_RUN_PAUSED, EXIT_RUN_FAILED,
            EXIT_RESUME_NOT_RESUMABLE, EXIT_RESUME_FAILED,
            EXIT_TRUST_VIOLATION,
        }
        assert actual == expected


# ── 3. Trust Invariant Codes Frozen ────────────────────────────────

class TestTrustInvariantsFrozen:

    def test_five_invariant_codes(self):
        from nodechain.sdk.trust_summary import TrustSummary, NodeTrustRecord
        # Create a summary that triggers all violations
        summary = TrustSummary(run_id="freeze", locked_mode=True, lockfile_verified=False)
        summary.add_node(NodeTrustRecord(
            node_id="bad",
            trust_level="local_untrusted",
            isolation_mode="in_process",
        ))
        violations = summary.validate_invariants(strict=True)
        codes = {v.code for v in violations}
        assert "INV-001" in codes
        assert "INV-005" in codes

    def test_invariant_codes_are_strings(self):
        from nodechain.sdk.trust_summary import TrustSummary, NodeTrustRecord
        summary = TrustSummary(run_id="t")
        summary.add_node(NodeTrustRecord(
            node_id="bad",
            trust_level="local_untrusted",
            isolation_mode="in_process",
        ))
        for v in summary.validate_invariants():
            assert isinstance(v.code, str)
            assert v.code.startswith("INV-")


# ── 4. Schema Files Present ────────────────────────────────────────

class TestSchemasFrozen:

    EXPECTED_SCHEMAS = {
        "chain_blueprint.json", "chain_state.json", "chain_trace.json",
        "invocation_envelope.json", "node_contract.json",
        "node_manifest.json", "policy.json",
    }

    EXPECTED_SEMANTIC_TYPES = {
        "chain_trace_output.json", "context_bundle.json",
        "evidence_base.json", "final_response.json",
        "memory_write_decision.json", "normalized_research_goal.json",
        "qualified_source_set.json", "raw_search_results.json",
        "raw_user_query.json", "risk_assessment.json", "source_set.json",
        "task_plan.json", "validated_evidence_base.json",
    }

    def test_core_schemas_exist(self):
        for name in self.EXPECTED_SCHEMAS:
            assert (PROJECT_ROOT / "schemas" / name).exists(), \
                f"Missing schema: {name}"

    def test_semantic_type_schemas_exist(self):
        for name in self.EXPECTED_SEMANTIC_TYPES:
            assert (PROJECT_ROOT / "schemas" / "semantic_types" / name).exists(), \
                f"Missing semantic type: {name}"

    def test_schemas_are_valid_json(self):
        for name in self.EXPECTED_SCHEMAS:
            path = PROJECT_ROOT / "schemas" / name
            data = json.loads(path.read_text(encoding="utf-8"))
            assert "type" in data or "$schema" in data, \
                f"Schema {name} doesn't look like valid JSON Schema"


# ── 5. Demo Scripts Present ────────────────────────────────────────

class TestDemoScripts:

    def test_demo_milestone_1_sh(self):
        assert (PROJECT_ROOT / "examples" / "demo_milestone_1.sh").exists()

    def test_demo_milestone_1_bat(self):
        assert (PROJECT_ROOT / "examples" / "demo_milestone_1.bat").exists()

    def test_demo_branch_sh(self):
        assert (PROJECT_ROOT / "examples" / "demo_branch.sh").exists()

    def test_demo_branch_bat(self):
        assert (PROJECT_ROOT / "examples" / "demo_branch.bat").exists()

    def test_demo_trust_sh(self):
        assert (PROJECT_ROOT / "examples" / "demo_trust.sh").exists()

    def test_demo_trust_bat(self):
        assert (PROJECT_ROOT / "examples" / "demo_trust.bat").exists()


# ── 6. Frozen Surface Document ────────────────────────────────────

class TestFrozenSurfaceDoc:

    def test_frozen_surfaces_doc_exists(self):
        assert (PROJECT_ROOT / "docs" / "frozen-surfaces.md").exists()

    def test_frozen_doc_has_cli_section(self):
        doc = (PROJECT_ROOT / "docs" / "frozen-surfaces.md").read_text(encoding="utf-8")
        assert "CLI Surface" in doc
        assert "Frozen" in doc

    def test_frozen_doc_has_exit_codes(self):
        doc = (PROJECT_ROOT / "docs" / "frozen-surfaces.md").read_text(encoding="utf-8")
        for code in ["EXIT_OK", "EXIT_TRUST_VIOLATION", "EXIT_NOT_FOUND"]:
            assert code in doc

    def test_frozen_doc_has_invariants(self):
        doc = (PROJECT_ROOT / "docs" / "frozen-surfaces.md").read_text(encoding="utf-8")
        for code in ["INV-001", "INV-005"]:
            assert code in doc

    def test_frozen_doc_has_migration_notes(self):
        doc = (PROJECT_ROOT / "docs" / "frozen-surfaces.md").read_text(encoding="utf-8")
        assert "Migration" in doc


# ── 7. Architecture Document Complete ─────────────────────────────

class TestArchitectureDoc:

    def test_has_trust_model_section(self):
        doc = (PROJECT_ROOT / "ARCHITECTURE.md").read_text(encoding="utf-8")
        assert "Trust Model" in doc

    def test_has_honest_boundaries(self):
        doc = (PROJECT_ROOT / "ARCHITECTURE.md").read_text(encoding="utf-8")
        assert "Honest Boundaries" in doc or "does NOT" in doc

    def test_has_enforcement_layers(self):
        doc = (PROJECT_ROOT / "ARCHITECTURE.md").read_text(encoding="utf-8")
        assert "Enforcement" in doc or "enforcement" in doc


# ── 8. Registry Packages ──────────────────────────────────────────

class TestRegistryFrozen:

    EXPECTED_PACKAGES = {
        "echo_node", "future_node", "sandbox_test_node", "text_transforms",
    }

    def test_registry_packages_exist(self):
        for pkg in self.EXPECTED_PACKAGES:
            assert (PROJECT_ROOT / "nodes" / pkg).exists(), \
                f"Missing registry package: {pkg}"

    def test_echo_node_has_manifest(self):
        assert (PROJECT_ROOT / "nodes" / "echo_node" / "node.yaml").exists()

    def test_text_transforms_has_package_manifest(self):
        assert (PROJECT_ROOT / "nodes" / "text_transforms" / "package.yaml").exists()

    def test_sandbox_test_node_has_manifest(self):
        assert (PROJECT_ROOT / "nodes" / "sandbox_test_node" / "node.yaml").exists()


# ── 9. Version Consistency ────────────────────────────────────────

class TestVersionFrozen:

    def test_version_is_rc1(self):
        import nodechain
        assert nodechain.__version__ == "3.5.1"

    def test_pyproject_matches(self):
        toml = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        assert 'version = "3.5.1"' in toml

    def test_release_guard_matches(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "trg", PROJECT_ROOT / "tests" / "test_release_guard.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert mod.EXPECTED_VERSION == "3.5.1"
