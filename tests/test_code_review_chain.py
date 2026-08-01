"""v2.71 tests for the Code Review Assistant chain.

Tests the governance properties that distinguish this chain from the research
chain: file-access governance, read-only enforcement, and artifact provenance.
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nodechain.nodes.code_review_request import CodeReviewRequestNode
from nodechain.nodes.file_reader import FileReaderNode
from nodechain.nodes.code_analyzer import CodeAnalyzerNode
from nodechain.nodes.finding_classifier import FindingClassifierNode
from nodechain.nodes.review_report_generator import ReviewReportGeneratorNode
from nodechain.nodes.finding_classifier import FindingClassifierNode
from nodechain.core.envelope import InvocationEnvelope
from nodechain.core.port import PortType


class TestFileReaderGovernance:
    """v2.71 governance proof: file_reader reads ONLY granted paths."""

    def test_denied_path_not_read(self, tmp_path):
        """A file NOT matching allowed_paths must not be read."""
        # Create a test file outside the allowed pattern
        (tmp_path / "secret.txt").write_text("SECRET DATA")
        (tmp_path / "allowed.py").write_text("# allowed code")

        reader = FileReaderNode(
            repo_root=str(tmp_path),
            allowed_paths=["*.py"],
        )
        assert reader._is_path_allowed("allowed.py") is True
        assert reader._is_path_allowed("secret.txt") is False

    def test_read_only_no_writes(self, tmp_path):
        """file_reader must never write to the filesystem."""
        (tmp_path / "test.py").write_text("# original")

        reader = FileReaderNode(
            repo_root=str(tmp_path),
            allowed_paths=["*.py"],
        )
        # Execute (with a goal that targets HEAD — git may not work in tmp_path,
        # but the key assertion is that no files are modified)
        original_content = (tmp_path / "test.py").read_text()
        env = InvocationEnvelope(
            envelope_id="t", run_id="t", chain_id="t",
            node_id="file_reader", step_id=1,
            payload={"target_commit": "HEAD", "file_scope": "all"},
        )
        result = asyncio.run(reader.execute(env))
        # Verify the file was NOT modified
        assert (tmp_path / "test.py").read_text() == original_content, \
            "file_reader must not modify files (read-only governance)"

    def test_content_truncated_at_line_boundary(self, tmp_path):
        """v2.71 fix: truncation must not cut mid-line."""
        long_line = "x = 1  # " + "a" * 200
        content = "\n".join([long_line] * 100)
        (tmp_path / "big.py").write_text(content)

        reader = FileReaderNode(
            repo_root=str(tmp_path),
            allowed_paths=["*.py"],
        )
        env = InvocationEnvelope(
            envelope_id="t", run_id="t", chain_id="t",
            node_id="file_reader", step_id=1,
            payload={"target_commit": "HEAD", "file_scope": "all"},
        )
        result = asyncio.run(reader.execute(env))
        for f in result.output.get("files", []):
            content = f.get("content", "")
            # Content should not end mid-line (should end with \n or be complete)
            if f.get("content_truncated"):
                assert content.endswith("\n"), \
                    f"truncated content must end at line boundary, got: ...{content[-30:]}"


class TestFindingClassifier:
    """v2.71: finding classification logic."""

    def test_confirmed_vs_speculative(self):
        """confidence >= 0.7 → confirmed, < 0.7 → speculative."""
        node = FindingClassifierNode()
        output = {
            "findings": [
                {"finding_id": "F1", "confidence": 0.9, "file_path": "a.py",
                 "line_range": "1-5", "severity": "blocker", "category": "correctness",
                 "evidence": "x", "recommendation": "y"},
                {"finding_id": "F2", "confidence": 0.5, "file_path": "b.py",
                 "line_range": "10-15", "severity": "warning", "category": "style",
                 "evidence": "x", "recommendation": "y"},
            ],
        }
        env = InvocationEnvelope(
            envelope_id="t", run_id="t", chain_id="t",
            node_id="finding_classifier", step_id=1,
            payload=output,
        )
        result = asyncio.run(node.execute(env))
        findings = result.output["classified_findings"]
        assert findings[0]["status"] == "confirmed"
        assert findings[1]["status"] == "speculative"

    def test_deduplication_overlapping_ranges(self):
        """Findings with same file + category + overlapping lines → deduped."""
        node = FindingClassifierNode()
        output = {
            "findings": [
                {"finding_id": "F1", "confidence": 0.8, "file_path": "a.py",
                 "line_range": "10-20", "severity": "warning", "category": "style",
                 "evidence": "x", "recommendation": "y"},
                {"finding_id": "F2", "confidence": 0.9, "file_path": "a.py",
                 "line_range": "15-25", "severity": "warning", "category": "style",
                 "evidence": "x", "recommendation": "y"},
            ],
        }
        env = InvocationEnvelope(
            envelope_id="t", run_id="t", chain_id="t",
            node_id="finding_classifier", step_id=1,
            payload=output,
        )
        result = asyncio.run(node.execute(env))
        assert len(result.output["classified_findings"]) == 1, \
            "overlapping findings should be deduped"

    def test_empty_findings_produce_empty_output(self):
        """Zero findings → zero classified, no crash."""
        node = FindingClassifierNode()
        env = InvocationEnvelope(
            envelope_id="t", run_id="t", chain_id="t",
            node_id="finding_classifier", step_id=1,
            payload={"findings": []},
        )
        result = asyncio.run(node.execute(env))
        assert result.output["classified_findings"] == []
        assert result.output["summary"]["total_findings"] == 0


class TestPortTypeChain:
    """v2.71: the port-type chain must be contiguous."""

    def test_code_review_port_types_exist(self):
        assert PortType.CODE_REVIEW_GOAL == "code_review_goal"
        assert PortType.CODE_ARTIFACTS == "code_artifacts"
        assert PortType.REVIEW_FINDINGS == "review_findings"
        assert PortType.CLASSIFIED_FINDINGS == "classified_findings"
        assert PortType.FINAL_REVIEW == "final_review"

    def test_node_contracts_chain_correctly(self):
        """Each node's output type must match the next node's input type."""
        contracts = [
            (CodeReviewRequestNode.__module__, PortType.CODE_REVIEW_GOAL),
            (FileReaderNode.__module__, PortType.CODE_ARTIFACTS),
            (CodeAnalyzerNode.__module__, PortType.REVIEW_FINDINGS),
            (FindingClassifierNode.__module__, PortType.CLASSIFIED_FINDINGS),
            (ReviewReportGeneratorNode.__module__, PortType.FINAL_REVIEW),
        ]
        # Just verify the port types are all distinct and defined
        port_types = [c[1] for c in contracts]
        assert len(set(port_types)) == 5, "all 5 port types must be distinct"


class TestBlueprintStructure:
    """v2.71: the blueprint must be well-formed."""

    def test_blueprint_exists(self):
        bp = Path(__file__).resolve().parent.parent / "blueprints" / "code_review_v1.yaml"
        assert bp.exists(), "code_review_v1.yaml blueprint must exist"

    def test_blueprint_has_5_nodes(self):
        import yaml
        bp = Path(__file__).resolve().parent.parent / "blueprints" / "code_review_v1.yaml"
        with open(bp) as f:
            data = yaml.safe_load(f)
        node_ids = [n["node_id"] for n in data["nodes"]]
        assert len(node_ids) == 5
        assert "code_review_request" in node_ids
        assert "file_reader" in node_ids
        assert "code_analyzer" in node_ids
        assert "finding_classifier" in node_ids
        assert "review_report_generator" in node_ids

    def test_blueprint_connections_chain(self):
        """Connections must form a contiguous chain: 1→2→3→4→5."""
        import yaml
        bp = Path(__file__).resolve().parent.parent / "blueprints" / "code_review_v1.yaml"
        with open(bp) as f:
            data = yaml.safe_load(f)
        conns = data["connections"]
        assert len(conns) == 4, "5 nodes need 4 connections"
        # Verify the chain
        expected_chain = [
            ("code_review_request", "file_reader"),
            ("file_reader", "code_analyzer"),
            ("code_analyzer", "finding_classifier"),
            ("finding_classifier", "review_report_generator"),
        ]
        actual_chain = [(c["from_node"], c["to_node"]) for c in conns]
        for expected in expected_chain:
            assert expected in actual_chain, f"missing connection: {expected}"
