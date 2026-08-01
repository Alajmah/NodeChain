"""Graph Explorer CLI Parity Tests (v2.21.3).

Tests that the CLI exposes all SDK materialization paths.
AC-01 through AC-08 from the v2.21.3 closure criteria.
"""

from __future__ import annotations

import json
import pytest
from pathlib import Path
from click.testing import CliRunner

from nodechain.cli.main import cli


# ── Helpers ─────────────────────────────────────────────────────────────────

def _write_json(path: Path, data: dict | list) -> str:
    path.write_text(json.dumps(data))
    return str(path)


LOCKFILE = {
    "packages": [
        {"package_id": "pkg_a", "version": "1.0.0", "registry_id": "reg_1",
         "publisher_fingerprint": "fp_1", "lifecycle": "active",
         "dependencies": [{"package_id": "dep_x", "version": "2.0.0"}]}
    ]
}

CAP_RECEIPT = {
    "receipt_id": "cap_001", "capability": "search",
    "selected_package_id": "sel_pkg", "selected_version": "1.0",
    "rejected_candidates": [
        {"package_id": "rej_pkg", "version": "0.9", "rejection_reason": "untrusted"}
    ],
}

DELIB_RECEIPT = {
    "receipt_id": "delib_001", "signature": "sig_abc",
    "deliberation_trigger": "uncertainty", "branch_count": 2,
    "selected_branch_id": "b1",
}

BRANCH_PLANS = [
    {"branch_id": "b1", "admissible": True, "depth": 0},
    {"branch_id": "b2", "admissible": True, "depth": 0},
]

BRANCH_RESULTS = [
    {"branch_id": "b1", "status": "completed", "output_digest": "od1"},
    {"branch_id": "b2", "status": "completed", "output_digest": "od2"},
]

MERGE_DECISION = {
    "strategy": "select_best", "selected_branch_id": "b1",
    "rejected_branch_ids": ["b2"], "confidence": 0.7,
    "human_review_required": False,
}

HEALTH_SECTIONS = {
    "issues": [
        {"rule_id": "HR-001", "name": "unsigned", "severity": "warning"},
        {"rule_id": "HR-044", "name": "review_pending", "severity": "degraded"},
    ]
}

TRACE_EVENTS = [
    {"event_id": "e1", "node_id": "n1", "event_type": "node_invoked", "step_id": 1},
    {"event_id": "e2", "node_id": "n1", "event_type": "node_succeeded", "step_id": 2},
]


# ── AC-01: graph export supports all artifact flags ─────────────────────────

class TestAC01AllFlagsSupported:
    """AC-01: graph export supports all artifact types."""

    def test_lockfile_flag(self, tmp_path):
        lf = _write_json(tmp_path / "lockfile.json", LOCKFILE)
        runner = CliRunner()
        result = runner.invoke(cli, ["graph", "export", "--lockfile", lf])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["node_count"] > 0
        assert "trust_lockfile" in data["source_artifacts"]

    def test_capability_receipt_flag(self, tmp_path):
        cr = _write_json(tmp_path / "cap.json", CAP_RECEIPT)
        runner = CliRunner()
        result = runner.invoke(cli, ["graph", "export", "--capability-receipt", cr])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["node_count"] > 0

    def test_deliberation_receipt_flag(self, tmp_path):
        dr = _write_json(tmp_path / "delib.json", DELIB_RECEIPT)
        runner = CliRunner()
        result = runner.invoke(cli, ["graph", "export", "--deliberation-receipt", dr])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["node_count"] > 0

    def test_health_sections_flag(self, tmp_path):
        hs = _write_json(tmp_path / "health.json", HEALTH_SECTIONS)
        runner = CliRunner()
        result = runner.invoke(cli, ["graph", "export", "--health-sections", hs])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["node_count"] > 0
        assert "dashboard_health" in data["source_artifacts"]

    def test_trace_events_flag(self, tmp_path):
        te = _write_json(tmp_path / "trace.json", TRACE_EVENTS)
        runner = CliRunner()
        result = runner.invoke(cli, ["graph", "export", "--trace-events", te])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["node_count"] > 0
        assert "trace_events" in data["source_artifacts"]

    def test_branch_plans_flag(self, tmp_path):
        dr = _write_json(tmp_path / "delib.json", DELIB_RECEIPT)
        bp = _write_json(tmp_path / "plans.json", BRANCH_PLANS)
        runner = CliRunner()
        result = runner.invoke(cli, [
            "graph", "export",
            "--deliberation-receipt", dr,
            "--branch-plans", bp,
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        # Should have branch plan nodes
        node_types = [n["type"] for n in data["nodes"]]
        assert "branch_plan" in node_types

    def test_branch_results_flag(self, tmp_path):
        dr = _write_json(tmp_path / "delib.json", DELIB_RECEIPT)
        br = _write_json(tmp_path / "results.json", BRANCH_RESULTS)
        runner = CliRunner()
        result = runner.invoke(cli, [
            "graph", "export",
            "--deliberation-receipt", dr,
            "--branch-results", br,
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        node_types = [n["type"] for n in data["nodes"]]
        assert "branch_result" in node_types

    def test_merge_decision_flag(self, tmp_path):
        dr = _write_json(tmp_path / "delib.json", DELIB_RECEIPT)
        md = _write_json(tmp_path / "merge.json", MERGE_DECISION)
        runner = CliRunner()
        result = runner.invoke(cli, [
            "graph", "export",
            "--deliberation-receipt", dr,
            "--merge-decision", md,
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        node_types = [n["type"] for n in data["nodes"]]
        assert "merge_decision" in node_types

    def test_no_artifacts_errors(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["graph", "export"])
        assert result.exit_code == 10


# ── AC-02: graph verify supports same artifact set ──────────────────────────

class TestAC02VerifyParity:
    """AC-02: graph verify supports the same artifact set."""

    def test_verify_lockfile(self, tmp_path):
        lf = _write_json(tmp_path / "lockfile.json", LOCKFILE)
        runner = CliRunner()
        result = runner.invoke(cli, ["graph", "verify", "--lockfile", lf])
        assert result.exit_code == 0
        assert "OK" in result.output

    def test_verify_capability_receipt(self, tmp_path):
        cr = _write_json(tmp_path / "cap.json", CAP_RECEIPT)
        runner = CliRunner()
        result = runner.invoke(cli, ["graph", "verify", "--capability-receipt", cr])
        assert result.exit_code == 0
        assert "OK" in result.output

    def test_verify_health_sections(self, tmp_path):
        hs = _write_json(tmp_path / "health.json", HEALTH_SECTIONS)
        runner = CliRunner()
        result = runner.invoke(cli, ["graph", "verify", "--health-sections", hs])
        assert result.exit_code == 0
        assert "OK" in result.output

    def test_verify_trace_events(self, tmp_path):
        te = _write_json(tmp_path / "trace.json", TRACE_EVENTS)
        runner = CliRunner()
        result = runner.invoke(cli, ["graph", "verify", "--trace-events", te])
        assert result.exit_code == 0
        assert "OK" in result.output

    def test_verify_no_artifacts_errors(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["graph", "verify"])
        assert result.exit_code == 10

    def test_verify_deliberation_with_branch_artifacts(self, tmp_path):
        dr = _write_json(tmp_path / "delib.json", DELIB_RECEIPT)
        bp = _write_json(tmp_path / "plans.json", BRANCH_PLANS)
        br = _write_json(tmp_path / "results.json", BRANCH_RESULTS)
        md = _write_json(tmp_path / "merge.json", MERGE_DECISION)
        runner = CliRunner()
        result = runner.invoke(cli, [
            "graph", "verify",
            "--deliberation-receipt", dr,
            "--branch-plans", bp,
            "--branch-results", br,
            "--merge-decision", md,
        ])
        assert result.exit_code == 0
        assert "OK" in result.output


# ── AC-03: Deliberation graph CLI renders all elements ─────────────────────

class TestAC03DeliberationFullGraph:
    """AC-03: Deliberation graph CLI renders receipt, plans, results, merge, review."""

    def test_full_deliberation_graph(self, tmp_path):
        dr = _write_json(tmp_path / "delib.json", DELIB_RECEIPT)
        bp = _write_json(tmp_path / "plans.json", BRANCH_PLANS)
        br = _write_json(tmp_path / "results.json", BRANCH_RESULTS)
        md = _write_json(tmp_path / "merge.json", MERGE_DECISION)
        runner = CliRunner()
        result = runner.invoke(cli, [
            "graph", "export",
            "--deliberation-receipt", dr,
            "--branch-plans", bp,
            "--branch-results", br,
            "--merge-decision", md,
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        node_types = set(n["type"] for n in data["nodes"])
        assert "branch_plan" in node_types
        assert "branch_result" in node_types
        assert "merge_decision" in node_types

    def test_deliberation_with_human_review(self, tmp_path):
        receipt = {**DELIB_RECEIPT, "selected_branch_id": None}
        decision = {**MERGE_DECISION, "strategy": "defer_human",
                    "selected_branch_id": None,
                    "deferred_branch_ids": ["b1"],
                    "human_review_required": True,
                    "human_review_status": "pending"}
        dr = _write_json(tmp_path / "delib.json", receipt)
        md = _write_json(tmp_path / "merge.json", decision)
        runner = CliRunner()
        result = runner.invoke(cli, [
            "graph", "export",
            "--deliberation-receipt", dr,
            "--merge-decision", md,
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        node_types = set(n["type"] for n in data["nodes"])
        assert "human_review" in node_types


# ── AC-04: Health overlay CLI ───────────────────────────────────────────────

class TestAC04HealthOverlay:
    """AC-04: Health overlay CLI attaches HR-001 through HR-044."""

    def test_multiple_health_rules(self, tmp_path):
        sections = {
            "issues": [
                {"rule_id": "HR-001", "name": "unsigned", "severity": "warning"},
                {"rule_id": "HR-040", "name": "active_deliberation", "severity": "degraded"},
                {"rule_id": "HR-042", "name": "branch_violation", "severity": "critical"},
                {"rule_id": "HR-044", "name": "review_pending", "severity": "degraded"},
            ]
        }
        hs = _write_json(tmp_path / "health.json", sections)
        runner = CliRunner()
        result = runner.invoke(cli, ["graph", "export", "--health-sections", hs])
        assert result.exit_code == 0
        data = json.loads(result.output)
        hr_nodes = [n for n in data["nodes"] if n["type"] == "health_rule"]
        assert len(hr_nodes) == 4


# ── AC-05: Trace-event graph CLI ────────────────────────────────────────────

class TestAC05TraceEventGraph:
    """AC-05: Trace-event graph CLI renders ordered relationships."""

    def test_ordered_trace_events(self, tmp_path):
        events = [
            {"event_id": "e1", "node_id": "n1", "event_type": "node_invoked", "step_id": 1},
            {"event_id": "e2", "node_id": "n1", "event_type": "node_succeeded", "step_id": 2},
            {"event_id": "e3", "node_id": "n2", "event_type": "node_failed", "step_id": 3},
        ]
        te = _write_json(tmp_path / "trace.json", events)
        runner = CliRunner()
        result = runner.invoke(cli, ["graph", "export", "--trace-events", te])
        assert result.exit_code == 0
        data = json.loads(result.output)
        trace_nodes = [n for n in data["nodes"] if n["type"] == "trace_event"]
        assert len(trace_nodes) == 3
        # Should have edges linking sequential events
        assert data["edge_count"] > 0


# ── AC-06: Missing artifacts produce warnings ───────────────────────────────

class TestAC06WarningsInCLI:
    """AC-06: Missing artifact references produce warnings, not invented nodes."""

    def test_empty_lockfile_warnings(self, tmp_path):
        lf = _write_json(tmp_path / "lockfile.json", {"packages": []})
        runner = CliRunner()
        result = runner.invoke(cli, ["graph", "export", "--lockfile", lf])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["warnings"]) > 0

    def test_missing_selected_package_warnings(self, tmp_path):
        receipt = {"capability": "c", "receipt_id": "r"}
        cr = _write_json(tmp_path / "cap.json", receipt)
        runner = CliRunner()
        result = runner.invoke(cli, ["graph", "export", "--capability-receipt", cr])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["warnings"]) > 0


# ── AC-07: Deterministic digest across combinations ─────────────────────────

class TestAC07Determinism:
    """AC-07: Graph digest is deterministic across all supported combinations."""

    def test_merged_graph_deterministic(self, tmp_path):
        lf = _write_json(tmp_path / "lockfile.json", LOCKFILE)
        cr = _write_json(tmp_path / "cap.json", CAP_RECEIPT)
        runner = CliRunner()
        r1 = runner.invoke(cli, ["graph", "export", "--lockfile", lf, "--capability-receipt", cr])
        r2 = runner.invoke(cli, ["graph", "export", "--lockfile", lf, "--capability-receipt", cr])
        assert r1.exit_code == 0
        assert r2.exit_code == 0
        d1 = json.loads(r1.output)
        d2 = json.loads(r2.output)
        assert d1["graph_digest"] == d2["graph_digest"]

    def test_mermaid_format_supported(self, tmp_path):
        lf = _write_json(tmp_path / "lockfile.json", LOCKFILE)
        runner = CliRunner()
        result = runner.invoke(cli, ["graph", "export", "--lockfile", lf, "--format", "mermaid"])
        assert result.exit_code == 0
        assert "graph TD" in result.output

    def test_output_to_file(self, tmp_path):
        lf = _write_json(tmp_path / "lockfile.json", LOCKFILE)
        out = str(tmp_path / "output.json")
        runner = CliRunner()
        result = runner.invoke(cli, ["graph", "export", "--lockfile", lf, "--output", out])
        assert result.exit_code == 0
        assert Path(out).exists()
        data = json.loads(Path(out).read_text())
        assert data["node_count"] > 0


# ── AC-08: Tests cover CLI parity, not only SDK ─────────────────────────────

class TestAC08CLIParityCoverage:
    """AC-08: Tests cover CLI parity — all SDK paths accessible from CLI."""

    def test_all_export_flags_documented(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["graph", "export", "--help"])
        assert result.exit_code == 0
        help_text = result.output
        assert "--lockfile" in help_text
        assert "--capability-receipt" in help_text
        assert "--deliberation-receipt" in help_text
        assert "--branch-plans" in help_text
        assert "--branch-results" in help_text
        assert "--merge-decision" in help_text
        assert "--health-sections" in help_text
        assert "--trace-events" in help_text

    def test_all_verify_flags_documented(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["graph", "verify", "--help"])
        assert result.exit_code == 0
        help_text = result.output
        assert "--lockfile" in help_text
        assert "--capability-receipt" in help_text
        assert "--deliberation-receipt" in help_text
        assert "--branch-plans" in help_text
        assert "--branch-results" in help_text
        assert "--merge-decision" in help_text
        assert "--health-sections" in help_text
        assert "--trace-events" in help_text
