"""v2.73 tests for governed temp-workspace test execution.

Tests the governance properties that define the v2.73 boundary:
"governed, bounded, temp-workspace execution — NOT full sandbox."
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nodechain.nodes.sandbox_test_runner import SandboxTestRunnerNode, ENV_ALLOWLIST, PYTEST_PROFILE
from nodechain.nodes.test_result_classifier import TestResultClassifierNode
from nodechain.core.envelope import InvocationEnvelope
from nodechain.core.port import PortType
from nodechain.core.contract import SideEffectType


class TestSandboxGovernance:
    """v2.73: the governed-execution-proof node."""

    def test_code_execution_is_declared_side_effect(self):
        """The sandbox_test_runner contract must declare code_execution as a
        side effect — it's not just a capability."""
        from nodechain.nodes.sandbox_test_runner import SANDBOX_TEST_RUNNER_CONTRACT
        se_types = [se.effect_type for se in SANDBOX_TEST_RUNNER_CONTRACT.side_effects]
        assert "code_execution" in se_types, \
            "code_execution must be a declared side effect, not just a capability"

    def test_command_profile_uses_no_shell(self):
        """pytest must run with shell=False — no shell injection."""
        assert PYTEST_PROFILE["shell"] is False

    def test_command_profile_has_timeout(self):
        """pytest execution must be bounded by a timeout."""
        assert PYTEST_PROFILE["timeout_seconds"] > 0
        assert PYTEST_PROFILE["timeout_seconds"] <= 300  # reasonable cap

    def test_command_profile_has_output_cap(self):
        """Output must be capped to prevent memory exhaustion."""
        assert PYTEST_PROFILE["max_output_bytes"] > 0
        assert PYTEST_PROFILE["max_output_bytes"] <= 100000  # 100KB cap

    def test_env_allowlist_excludes_common_secrets(self):
        """The env allowlist must not include common secret-bearing vars."""
        forbidden = {"AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "DATABASE_URL",
                     "SECRET_KEY", "PRIVATE_KEY", "PYPI_TOKEN"}
        for var in forbidden:
            assert var not in ENV_ALLOWLIST, f"{var} must not be in env allowlist"

    def test_repo_unchanged_after_no_patches(self, tmp_path):
        """When no patches are tested, the repo must remain unchanged."""
        os.system(f"cd {tmp_path} && git init && git add . && git commit -m init 2>/dev/null")
        node = SandboxTestRunnerNode(repo_root=str(tmp_path))
        env = InvocationEnvelope(
            envelope_id="t", run_id="t", chain_id="t",
            node_id="sandbox_test_runner", step_id=1,
            payload={"classified_patches": []},
        )
        result = asyncio.run(node.execute(env))
        assert result.output["execution_summary"]["repo_git_status_unchanged"] is True


class TestTestResultClassifier:
    """v2.73: deterministic verdict from exit code, never model-judged."""

    def test_pass_verdict_from_exit_code_0(self):
        node = TestResultClassifierNode()
        record = {
            "patch_id": "P1",
            "patch_apply_status": "succeeded",
            "test_status": "passed",
            "process_exit_code": 0,
        }
        verdict = node._classify(record)
        assert verdict["verdict"] == "pass"
        assert verdict["recommendation"] == "accept_patch"
        assert verdict["confidence"] == "deterministic"

    def test_fail_verdict_from_nonzero_exit(self):
        node = TestResultClassifierNode()
        record = {
            "patch_id": "P1",
            "patch_apply_status": "succeeded",
            "test_status": "failed",
            "process_exit_code": 1,
        }
        verdict = node._classify(record)
        assert verdict["verdict"] == "fail"
        assert verdict["recommendation"] == "reject_patch"

    def test_not_run_when_patch_apply_fails(self):
        """TRACE TRUTH: if patch application fails, verdict is not_run, NOT fail."""
        node = TestResultClassifierNode()
        record = {
            "patch_id": "P1",
            "patch_apply_status": "failed",
            "test_status": "not_run",
            "process_exit_code": None,
        }
        verdict = node._classify(record)
        assert verdict["verdict"] == "not_run"
        assert "patch_apply_failed" in verdict["reason_codes"][0]

    def test_timeout_verdict(self):
        node = TestResultClassifierNode()
        record = {
            "patch_id": "P1",
            "patch_apply_status": "succeeded",
            "test_status": "timeout",
            "process_exit_code": None,
            "process_timed_out": True,
            "duration_ms": 120000,
        }
        verdict = node._classify(record)
        assert verdict["verdict"] == "timeout"
        assert verdict["recommendation"] == "needs_manual_review"

    def test_output_truncated_adds_reason_code(self):
        node = TestResultClassifierNode()
        record = {
            "patch_id": "P1",
            "patch_apply_status": "succeeded",
            "test_status": "passed",
            "process_exit_code": 0,
            "output_truncated": True,
        }
        verdict = node._classify(record)
        assert "output_truncated" in verdict["reason_codes"]

    def test_empty_records_produces_empty_verdicts(self):
        node = TestResultClassifierNode()
        env = InvocationEnvelope(
            envelope_id="t", run_id="t", chain_id="t",
            node_id="test_result_classifier", step_id=1,
            payload={"test_records": [], "execution_summary": {}},
        )
        result = asyncio.run(node.execute(env))
        assert result.output["verdicts"] == []
        assert result.output["classification_summary"]["deterministic"] is True


class TestSideEffectTypeCanonical:
    """v2.73: code_execution and sandbox_file_write must be canonical types."""

    def test_code_execution_is_canonical(self):
        from nodechain.core.contract import normalize_side_effect_type
        assert normalize_side_effect_type("code_execution") == "code_execution"

    def test_sandbox_file_write_is_canonical(self):
        from nodechain.core.contract import normalize_side_effect_type
        assert normalize_side_effect_type("sandbox_file_write") == "sandbox_file_write"

    def test_legacy_types_still_canonical(self):
        from nodechain.core.contract import normalize_side_effect_type
        assert normalize_side_effect_type("external_call") == "external_call"
        assert normalize_side_effect_type("memory_write") == "memory_write"


class TestBlueprintStructure:
    """v2.73: blueprint must have the 10-node chain."""

    def test_blueprint_exists(self):
        bp = Path(__file__).resolve().parent.parent / "blueprints" / "code_review_full_v1.yaml"
        assert bp.exists()

    def test_blueprint_has_10_nodes(self):
        import yaml
        bp = Path(__file__).resolve().parent.parent / "blueprints" / "code_review_full_v1.yaml"
        with open(bp) as f:
            data = yaml.safe_load(f)
        assert len(data["nodes"]) == 10
        node_ids = [n["node_id"] for n in data["nodes"]]
        for n in ["sandbox_test_runner", "test_result_classifier"]:
            assert n in node_ids

    def test_blueprint_has_9_connections(self):
        """10 nodes need 9 connections."""
        import yaml
        bp = Path(__file__).resolve().parent.parent / "blueprints" / "code_review_full_v1.yaml"
        with open(bp) as f:
            data = yaml.safe_load(f)
        assert len(data["connections"]) == 9
