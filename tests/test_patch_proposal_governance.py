"""v2.72 tests for patch proposal governance.

Tests the governance properties that define the v2.72 boundary:
"governed proposal of change, not governed execution of change."
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nodechain.nodes.patch_generator import PatchGeneratorNode
from nodechain.nodes.patch_validator import PatchValidatorNode
from nodechain.nodes.patch_risk_classifier import PatchRiskClassifierNode
from nodechain.nodes.patch_report_assembler import PatchReportAssemblerNode
from nodechain.core.envelope import InvocationEnvelope
from nodechain.core.port import PortType


class TestPatchValidatorGovernance:
    """v2.72: the governance-proof node. Must NEVER touch the real repo."""

    def test_repo_unchanged_after_validation(self, tmp_path):
        """The real repo working tree must be byte-for-byte unchanged after
        patch validation runs."""
        # Create a test repo
        (tmp_path / "test.py").write_text("x = 1\n")
        os.system(f"cd {tmp_path} && git init && git add . && git commit -m init")

        original_hash = __import__("hashlib").sha256(
            (tmp_path / "test.py").read_bytes()
        ).hexdigest()

        validator = PatchValidatorNode(
            repo_root=str(tmp_path),
            allowed_paths=["*.py"],
        )

        # A simple patch that would modify test.py
        diff = """--- a/test.py
+++ b/test.py
@@ -1,1 +1,1 @@
-x = 1
+x = 2
"""
        env = InvocationEnvelope(
            envelope_id="t", run_id="t", chain_id="t",
            node_id="patch_validator", step_id=1,
            payload={"patch_proposals": [{
                "proposal_id": "P1",
                "finding_id": "F1",
                "target_file": "test.py",
                "unified_diff": diff,
            }]},
        )
        result = asyncio.run(validator.execute(env))

        # CRITICAL: real repo must be unchanged
        after_hash = __import__("hashlib").sha256(
            (tmp_path / "test.py").read_bytes()
        ).hexdigest()
        assert after_hash == original_hash, \
            "REAL REPO MODIFIED — governance violation"
        assert result.output["validation_summary"]["repo_working_tree_unchanged"] is True

    def test_rejects_path_traversal(self, tmp_path):
        """Patches targeting ../ paths must be rejected."""
        (tmp_path / "safe.py").write_text("x = 1\n")
        os.system(f"cd {tmp_path} && git init && git add . && git commit -m init 2>/dev/null")

        validator = PatchValidatorNode(repo_root=str(tmp_path), allowed_paths=["*.py"])
        ok, msg = validator._check_path_safety("../../etc/passwd")
        assert not ok, "path traversal must be rejected"

    def test_rejects_absolute_path(self, tmp_path):
        """Absolute paths must be rejected."""
        validator = PatchValidatorNode(repo_root=str(tmp_path), allowed_paths=["*.py"])
        ok, msg = validator._check_path_safety("/etc/passwd")
        assert not ok

    def test_rejects_empty_diff(self):
        """Empty diffs must fail structure validation."""
        validator = PatchValidatorNode()
        ok, msg = validator._validate_diff_structure("")
        assert not ok

    def test_rejects_diff_without_hunk_markers(self):
        """Diffs without @@ markers must fail."""
        validator = PatchValidatorNode()
        ok, msg = validator._validate_diff_structure("--- a/x\n+++ b/x\nsome content")
        assert not ok

    def test_rejects_rename(self):
        """Rename operations must be rejected in v2.72."""
        validator = PatchValidatorNode()
        diff = "--- a/old.py\n+++ b/new.py\nrename from old.py\nrename to new.py\n"
        ok, msg = validator._check_no_delete_rename(diff)
        assert not ok


class TestPatchRiskClassifier:
    """v2.72: deterministic LOW/MEDIUM/HIGH risk classification."""

    def test_auth_file_is_high_risk(self):
        node = PatchRiskClassifierNode()
        patch = {"target_file": "src/auth/credentials.py", "unified_diff": "+token = secret"}
        risk, reasons = node._classify_risk(patch)
        assert risk == "HIGH"

    def test_test_file_is_low_risk(self):
        node = PatchRiskClassifierNode()
        patch = {"target_file": "tests/test_foo.py", "unified_diff": "+assert True"}
        risk, reasons = node._classify_risk(patch)
        assert risk == "LOW"

    def test_large_diff_is_high_risk(self):
        node = PatchRiskClassifierNode()
        lines = "\n".join(f"+line {i}" for i in range(50))
        patch = {"target_file": "src/app.py", "unified_diff": lines}
        risk, reasons = node._classify_risk(patch)
        assert risk == "HIGH"

    def test_empty_validated_list_produces_empty_output(self):
        node = PatchRiskClassifierNode()
        env = InvocationEnvelope(
            envelope_id="t", run_id="t", chain_id="t",
            node_id="patch_risk_classifier", step_id=1,
            payload={"validated_patches": [], "validation_summary": {}},
        )
        result = asyncio.run(node.execute(env))
        assert result.output["classified_patches"] == []


class TestPatchReportAssembler:
    """v2.72: the report must be honest about what was NOT done."""

    def test_governance_status_all_false(self):
        """The governance_status must explicitly state no patch was applied,
        no tests were run, no commit was made."""
        node = PatchReportAssemblerNode()
        env = InvocationEnvelope(
            envelope_id="t", run_id="t", chain_id="t",
            node_id="patch_report_assembler", step_id=1,
            payload={
                "classified_patches": [],
                "risk_summary": {"total_validated": 0},
            },
        )
        result = asyncio.run(node.execute(env))
        gs = result.output["governance_status"]
        assert gs["patch_applied_to_real_repo"] is False
        assert gs["tests_run"] is False
        assert gs["commit_created"] is False
        assert gs["push_performed"] is False
        assert gs["repo_working_tree_unchanged"] is True
        assert result.output["proposed_only"] is True

    def test_all_patches_marked_proposed_only(self):
        """Every patch in the report must have status='proposed_only'."""
        node = PatchReportAssemblerNode()
        env = InvocationEnvelope(
            envelope_id="t", run_id="t", chain_id="t",
            node_id="patch_report_assembler", step_id=1,
            payload={
                "classified_patches": [
                    {"proposal_id": "P1", "target_file": "a.py", "risk_level": "LOW",
                     "unified_diff": "--- a\n+++ b\n", "rationale": "fix"},
                    {"proposal_id": "P2", "target_file": "b.py", "risk_level": "MEDIUM",
                     "unified_diff": "--- a\n+++ b\n", "rationale": "fix"},
                ],
                "risk_summary": {"total_validated": 2},
            },
        )
        result = asyncio.run(node.execute(env))
        for p in result.output["patches"]:
            assert p["status"] == "proposed_only"


class TestBlueprintStructure:
    """v2.72: blueprint must be well-formed with the 9-node chain."""

    def test_blueprint_exists(self):
        bp = Path(__file__).resolve().parent.parent / "blueprints" / "code_review_with_patches_v1.yaml"
        assert bp.exists()

    def test_blueprint_has_9_nodes(self):
        import yaml
        bp = Path(__file__).resolve().parent.parent / "blueprints" / "code_review_with_patches_v1.yaml"
        with open(bp) as f:
            data = yaml.safe_load(f)
        assert len(data["nodes"]) == 9
        # v2.71 nodes present
        for n in ["code_review_request", "file_reader", "code_analyzer",
                   "finding_classifier", "review_report_generator"]:
            assert n in [nd["node_id"] for nd in data["nodes"]]
        # v2.72 nodes present
        for n in ["patch_generator", "patch_validator", "patch_risk_classifier",
                   "patch_report_assembler"]:
            assert n in [nd["node_id"] for nd in data["nodes"]]

    def test_blueprint_has_8_connections(self):
        """9 nodes need 8 connections."""
        import yaml
        bp = Path(__file__).resolve().parent.parent / "blueprints" / "code_review_with_patches_v1.yaml"
        with open(bp) as f:
            data = yaml.safe_load(f)
        assert len(data["connections"]) == 8
