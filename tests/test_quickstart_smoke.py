"""v2.85 — Quickstart smoke test.

Validates that the documented 5-minute local proof path in
docs/5-minute-local-proof.md does not rot. Each step of the quickstart is
exercised programmatically; if any command breaks, this test fails.

This is NOT a test of NodeChain's runtime semantics (those have their own
comprehensive suites). It only verifies the quickstart command sequence works.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestQuickstartSmoke:
    """The documented quickstart path must work end-to-end."""

    def test_step1_validate_schemas(self):
        """scripts/validate_schemas.py runs and exits 0 (the first quickstart command)."""
        result = subprocess.run(
            [sys.executable, "scripts/validate_schemas.py"],
            capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=30,
        )
        assert result.returncode == 0, (
            f"validate_schemas.py failed (exit {result.returncode}): {result.stderr[:300]}"
        )
        assert "[OK]" in result.stdout

    def test_step2_echo_demo_runs(self):
        """The echo demo blueprint runs with --provider mock and produces a trace."""
        result = subprocess.run(
            [sys.executable, "-m", "nodechain.cli.main", "run",
             "hello nodechain", "-b", "blueprints/echo_demo_v1.yaml",
             "--provider", "mock"],
            capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=60,
            env={**os.environ, "NODECHAIN_PROVIDER": "mock"},
        )
        assert result.returncode == 0, (
            f"echo demo failed (exit {result.returncode}): {result.stderr[:500]}"
        )
        assert "completed" in result.stdout.lower()
        assert "Trace saved" in result.stdout

    def test_step3_trace_inspectable(self, tmp_path):
        """The trace produced by the echo demo can be inspected."""
        # Run the echo demo and capture the run_id
        env = {**os.environ, "NODECHAIN_PROVIDER": "mock"}
        run_result = subprocess.run(
            [sys.executable, "-m", "nodechain.cli.main", "run",
             "hello nodechain", "-b", "blueprints/echo_demo_v1.yaml",
             "--provider", "mock"],
            capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=60,
            env=env,
        )
        assert run_result.returncode == 0

        # Find the run_id from the output
        import re
        m = re.search(r"Run ID:\s*([a-f0-9-]+)", run_result.stdout)
        assert m, f"could not find Run ID in output: {run_result.stdout[:300]}"
        run_id = m.group(1)

        # Verify the trace file exists
        trace_file = REPO_ROOT / "data" / "traces" / f"{run_id}.json"
        assert trace_file.exists(), f"trace file not found: {trace_file}"

        # Verify the trace file is valid JSON and has the expected shape
        with open(trace_file) as f:
            trace = json.load(f)
        assert trace["chain_id"] == "echo-demo-v1"
        assert trace["final_status"] == "completed"
        assert len(trace["events"]) > 0

        # Verify the trace inspection command works
        inspect_result = subprocess.run(
            [sys.executable, "-m", "nodechain.cli.main", "trace", run_id],
            capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=30,
        )
        assert inspect_result.returncode == 0, (
            f"trace inspection failed: {inspect_result.stderr[:300]}"
        )
        assert "Node Invoked" in inspect_result.stdout or "echo" in inspect_result.stdout.lower()

    def test_step4_trace_replay_verifies(self):
        """The trace-replay command runs 7 consistency checks on a trace."""
        # Run the echo demo
        env = {**os.environ, "NODECHAIN_PROVIDER": "mock"}
        run_result = subprocess.run(
            [sys.executable, "-m", "nodechain.cli.main", "run",
             "hello nodechain", "-b", "blueprints/echo_demo_v1.yaml",
             "--provider", "mock"],
            capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=60,
            env=env,
        )
        assert run_result.returncode == 0

        import re
        m = re.search(r"Run ID:\s*([a-f0-9-]+)", run_result.stdout)
        assert m
        run_id = m.group(1)
        trace_path = REPO_ROOT / "data" / "traces" / f"{run_id}.json"

        # Run trace-replay
        replay_result = subprocess.run(
            [sys.executable, "-m", "nodechain.cli.main", "trace-replay", "run",
             "--trace", str(trace_path)],
            capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=30,
        )
        assert replay_result.returncode == 0, (
            f"trace-replay failed: {replay_result.stderr[:300]}"
        )
        assert "passed" in replay_result.stdout.lower()

    def test_step5_optional_chains_exist(self):
        """The optional stretch-goal blueprints referenced in the quickstart exist."""
        for bp in [
            "blueprints/multi_node_demo_v1.yaml",
            "blueprints/branch_demo_v1.yaml",
            "blueprints/reuse_proof_quick_fact_check_v1.yaml",
        ]:
            assert (REPO_ROOT / bp).exists(), f"quickstart-referenced blueprint missing: {bp}"
