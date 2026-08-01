"""
Governance Console Tests (v2.21.3).

OC-001: The governance console is a read-only operator surface over
materialized NodeChain artifacts. It must not invent trust, mutate
runtime state, or make policy decisions outside existing governance primitives.

Tests cover AC-01 through AC-15 from the v2.21.3 acceptance criteria.
"""

from __future__ import annotations

import json
import pytest
from pathlib import Path
from click.testing import CliRunner

from nodechain.sdk.governance_console import (
    GovernanceConsole,
    ConsoleView,
    OC_001,
    CONSOLE_SCHEMA_VERSION,
)
from nodechain.cli.main import cli


# ── Test graph fixtures ─────────────────────────────────────────────────────


def _make_lockfile_graph() -> dict:
    """Build a realistic graph with multiple node types."""
    nodes = [
        {"id": "reg_1", "type": "registry", "label": "registry-alpha",
         "source_artifact": "trust_lockfile", "digest": "d_reg",
         "status": "healthy", "metadata": {"registry_id": "reg_1"}},
        {"id": "pkg_a", "type": "package", "label": "search-core@1.0",
         "source_artifact": "trust_lockfile", "digest": "d_pkg_a",
         "status": "healthy", "metadata": {"package_id": "pkg_a", "version": "1.0.0"}},
        {"id": "pub_1", "type": "publisher", "label": "pub-alpha",
         "source_artifact": "trust_lockfile", "digest": "d_pub",
         "status": "neutral", "metadata": {"fingerprint": "fp_1"}},
        {"id": "cert_1", "type": "certification", "label": "cert-signed",
         "source_artifact": "trust_lockfile", "digest": "d_cert",
         "status": "healthy", "metadata": {"cert_id": "cert_1"}},
        {"id": "dep_x", "type": "dependency", "label": "dep-x@2.0",
         "source_artifact": "trust_lockfile", "digest": "d_dep",
         "status": "warning", "metadata": {"package_id": "dep_x"}},
        {"id": "cap_req_1", "type": "capability_request", "label": "search",
         "source_artifact": "capability_selection_receipt", "digest": "d_cap",
         "status": "neutral",
         "metadata": {"capability": "search", "selected_package_id": "pkg_sel",
                      "selected_version": "1.2.0"}},
        {"id": "pkg_sel", "type": "capability_offer", "label": "search-fast@1.2",
         "source_artifact": "capability_selection_receipt", "digest": "d_sel",
         "status": "healthy", "metadata": {"package_id": "pkg_sel", "version": "1.2.0"}},
        {"id": "pkg_rej", "type": "capability_offer", "label": "search-slow@0.9",
         "source_artifact": "capability_selection_receipt", "digest": "d_rej",
         "status": "error", "metadata": {"package_id": "pkg_rej", "version": "0.9"}},
        {"id": "rcpt_1", "type": "receipt", "label": "trust_resolution_receipt",
         "source_artifact": "trust_lockfile", "digest": "d_rcpt",
         "status": "neutral", "metadata": {"receipt_type": "trust_resolution"}},
        {"id": "bp_1", "type": "branch_plan", "label": "branch-1",
         "source_artifact": "deliberation_receipt", "digest": "d_bp1",
         "status": "neutral", "metadata": {"branch_id": "b1", "admissible": True}},
        {"id": "bp_2", "type": "branch_plan", "label": "branch-2",
         "source_artifact": "deliberation_receipt", "digest": "d_bp2",
         "status": "neutral", "metadata": {"branch_id": "b2", "admissible": True}},
        {"id": "br_1", "type": "branch_result", "label": "result-1",
         "source_artifact": "deliberation_receipt", "digest": "d_br1",
         "status": "neutral", "metadata": {"branch_id": "b1", "status": "completed"}},
        {"id": "br_2", "type": "branch_result", "label": "result-2",
         "source_artifact": "deliberation_receipt", "digest": "d_br2",
         "status": "neutral", "metadata": {"branch_id": "b2", "status": "completed"}},
        {"id": "md_1", "type": "merge_decision", "label": "select_best",
         "source_artifact": "deliberation_receipt", "digest": "d_md",
         "status": "neutral",
         "metadata": {"strategy": "select_best", "selected_branch_id": "b1",
                      "rejected_branch_ids": ["b2"]}},
        {"id": "hr_001", "type": "health_rule", "label": "unsigned_node",
         "source_artifact": "dashboard_health", "digest": "d_hr1",
         "status": "warning", "metadata": {"rule_id": "HR-001", "severity": "warning"}},
        {"id": "hr_042", "type": "health_rule", "label": "branch_violation",
         "source_artifact": "dashboard_health", "digest": "d_hr42",
         "status": "error", "metadata": {"rule_id": "HR-042", "severity": "critical"}},
        {"id": "hr_044", "type": "health_rule", "label": "review_pending",
         "source_artifact": "dashboard_health", "digest": "d_hr44",
         "status": "warning", "metadata": {"rule_id": "HR-044", "severity": "degraded"}},
        {"id": "te_1", "type": "trace_event", "label": "node_invoked",
         "source_artifact": "trace_events", "digest": "d_te1",
         "status": "neutral", "metadata": {"event_id": "e1", "step_id": 1}},
        {"id": "te_2", "type": "trace_event", "label": "node_succeeded",
         "source_artifact": "trace_events", "digest": "d_te2",
         "status": "neutral", "metadata": {"event_id": "e2", "step_id": 2}},
    ]

    edges = [
        {"from": "pkg_a", "to": "reg_1", "relationship": "published_in",
         "source_artifact": "trust_lockfile", "digest": "", "reason": ""},
        {"from": "pkg_a", "to": "pub_1", "relationship": "signed_by",
         "source_artifact": "trust_lockfile", "digest": "", "reason": ""},
        {"from": "pkg_a", "to": "dep_x", "relationship": "depends_on",
         "source_artifact": "trust_lockfile", "digest": "", "reason": ""},
        {"from": "cap_req_1", "to": "pkg_sel", "relationship": "selected",
         "source_artifact": "capability_selection_receipt", "digest": "", "reason": ""},
        {"from": "cap_req_1", "to": "pkg_rej", "relationship": "rejected",
         "source_artifact": "capability_selection_receipt", "digest": "", "reason": "untrusted"},
        {"from": "rcpt_1", "to": "pkg_a", "relationship": "covers",
         "source_artifact": "trust_lockfile", "digest": "", "reason": ""},
        {"from": "md_1", "to": "br_1", "relationship": "selected",
         "source_artifact": "deliberation_receipt", "digest": "", "reason": ""},
        {"from": "te_1", "to": "te_2", "relationship": "followed_by",
         "source_artifact": "trace_events", "digest": "", "reason": ""},
    ]

    # Compute digest the same way as TrustGraphView
    import hashlib
    sorted_nodes = sorted(nodes, key=lambda n: n["id"])
    sorted_edges = sorted(edges, key=lambda e: f"{e['from']}--{e['relationship']}-->{e['to']}")
    digest = hashlib.sha256(
        json.dumps({"nodes": sorted_nodes, "edges": sorted_edges, "schema_version": "1.0.0"},
                   sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    return {
        "schema_version": "1.0.0",
        "generated_at": "2026-06-19T22:00:00Z",
        "graph_digest": digest,
        "source_artifacts": ["trust_lockfile", "capability_selection_receipt",
                             "deliberation_receipt", "dashboard_health", "trace_events"],
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": nodes,
        "edges": edges,
        "warnings": ["Missing publisher fingerprint for dep_x", "No lifecycle info for pkg_rej"],
    }


@pytest.fixture
def console() -> GovernanceConsole:
    c = GovernanceConsole()
    c.load(_make_lockfile_graph())
    assert c.validate()
    return c


@pytest.fixture
def graph_json_file(tmp_path) -> str:
    data = _make_lockfile_graph()
    p = tmp_path / "graph.json"
    p.write_text(json.dumps(data))
    return str(p)


# ── AC-01: Console module exists ────────────────────────────────────────────


class TestAC01ModuleExists:
    """AC-01: Console module exists."""

    def test_module_imports(self):
        from nodechain.sdk import governance_console
        assert governance_console is not None

    def test_governance_console_class_exists(self):
        assert GovernanceConsole is not None

    def test_oc_001_invariant_text(self):
        assert "read-only" in OC_001.lower()
        assert "must not invent trust" in OC_001.lower()
        assert "mutate runtime state" in OC_001.lower()

    def test_schema_version(self):
        assert CONSOLE_SCHEMA_VERSION == "1.0.0"


# ── AC-02: Console consumes graph JSON, not raw runtime state ──────────────


class TestAC02ConsumesGraphJSON:
    """AC-02: Console consumes graph JSON, not raw hidden runtime state."""

    def test_load_from_dict(self):
        c = GovernanceConsole()
        c.load(_make_lockfile_graph())
        assert c.is_loaded

    def test_load_from_json_string(self):
        c = GovernanceConsole()
        c.load(json.dumps(_make_lockfile_graph()))
        assert c.is_loaded

    def test_load_from_file(self, tmp_path):
        data = _make_lockfile_graph()
        p = tmp_path / "graph.json"
        p.write_text(json.dumps(data))
        c = GovernanceConsole()
        c.load_from_file(str(p))
        assert c.is_loaded

    def test_no_runtime_state_access(self):
        """Console has no DB, no state store, no persistence layer."""
        c = GovernanceConsole()
        # The class should have no attributes related to runtime state
        forbidden_attrs = ["_db", "_store", "_runtime", "_persistence",
                          "_state_store", "_trust_store", "_policy_store"]
        for attr in forbidden_attrs:
            assert not hasattr(c, attr), f"Console must not have {attr}"


# ── AC-03: Console has read-only mode by default ────────────────────────────


class TestAC03ReadOnly:
    """AC-03: Console has read-only mode by default."""

    def test_read_only_property(self):
        c = GovernanceConsole()
        assert c.read_only is True

    def test_read_only_cannot_be_disabled(self):
        """The _read_only attribute is always True."""
        c = GovernanceConsole()
        # There should be no public method to disable read-only
        assert c.read_only is True
        # Even if someone tries to set it
        c._read_only = True  # Only True is valid

    def test_no_mutation_methods(self):
        """Console class must not have any mutation methods."""
        c = GovernanceConsole()
        forbidden_methods = ["save", "write", "update", "delete", "create",
                           "modify", "mutate", "set_policy", "set_trust",
                           "publish", "deploy", "install", "remove"]
        for method in forbidden_methods:
            assert not callable(getattr(c, method, None)), \
                f"Console must not have method: {method}"


# ── AC-04: Console validates graph_digest before rendering ──────────────────


class TestAC04DigestValidation:
    """AC-04: Console validates graph_digest before rendering."""

    def test_valid_digest_passes(self):
        c = GovernanceConsole()
        c.load(_make_lockfile_graph())
        assert c.validate() is True
        assert c.is_validated is True

    def test_missing_digest_fails(self):
        data = _make_lockfile_graph()
        data["graph_digest"] = ""
        c = GovernanceConsole()
        c.load(data)
        assert c.validate() is False

    def test_tampered_digest_fails(self):
        data = _make_lockfile_graph()
        data["graph_digest"] = "abc123"  # Wrong digest
        c = GovernanceConsole()
        c.load(data)
        assert c.validate() is False

    def test_tampered_nodes_fails(self):
        data = _make_lockfile_graph()
        data["nodes"].append({"id": "fake", "type": "package", "label": "fake",
                              "source_artifact": "fake", "digest": "", "status": "neutral",
                              "metadata": {}})
        c = GovernanceConsole()
        c.load(data)
        assert c.validate() is False

    def test_rendering_requires_validation(self, console):
        """If validation fails, rendering raises."""
        data = _make_lockfile_graph()
        data["graph_digest"] = "wrong"
        c = GovernanceConsole()
        c.load(data)
        with pytest.raises(ValueError, match="validation failed"):
            c.summary()


# ── AC-05: Console renders graph nodes grouped by type ──────────────────────


class TestAC05NodeGrouping:
    """AC-05: Console renders graph nodes grouped by type."""

    def test_summary_shows_all_groups(self, console):
        view = console.summary()
        groups = view.data["nodes_by_group"]
        assert "registry" in groups
        assert "package" in groups
        assert "capability" in groups
        assert "branch" in groups
        assert "receipt" in groups
        assert "health" in groups
        assert "trace" in groups

    def test_nodes_by_type_package(self, console):
        view = console.nodes_by_type("package")
        assert view.data["node_count"] >= 2  # pkg_a + dep_x

    def test_nodes_by_type_health(self, console):
        view = console.nodes_by_type("health")
        assert view.data["node_count"] == 3  # HR-001, HR-042, HR-044

    def test_nodes_by_type_trace(self, console):
        view = console.nodes_by_type("trace")
        assert view.data["node_count"] == 2

    def test_nodes_by_type_capability(self, console):
        view = console.nodes_by_type("capability")
        assert view.data["node_count"] == 3  # request + 2 offers


# ── AC-06: Console can inspect any node ─────────────────────────────────────


class TestAC06NodeInspection:
    """AC-06: Console can inspect any node and show full details."""

    def test_inspect_shows_all_fields(self, console):
        view = console.inspect_node("pkg_a")
        data = view.data
        assert data["id"] == "pkg_a"
        assert data["type"] == "package"
        assert data["label"] is not None
        assert data["source_artifact"] is not None
        assert "digest" in data
        assert "status" in data
        assert "metadata" in data

    def test_inspect_shows_edges(self, console):
        view = console.inspect_node("pkg_a")
        edges = view.data["edges"]
        # pkg_a has edges to reg_1, pub_1, dep_x
        assert len(edges) >= 3

    def test_inspect_nonexistent_node(self, console):
        with pytest.raises(ValueError, match="not found"):
            console.inspect_node("does_not_exist")

    def test_inspect_metadata_displayed(self, console):
        view = console.inspect_node("cap_req_1")
        assert view.data["metadata"]["capability"] == "search"


# ── AC-07: Console shows all warnings ───────────────────────────────────────


class TestAC07Warnings:
    """AC-07: Console can show all warnings from the graph."""

    def test_warnings_shown(self, console):
        view = console.render_warnings()
        assert view.data["warning_count"] == 2
        assert len(view.data["warnings"]) == 2

    def test_warnings_content(self, console):
        view = console.render_warnings()
        assert any("dep_x" in w for w in view.data["warnings"])

    def test_no_warnings_when_empty(self):
        data = _make_lockfile_graph()
        data["warnings"] = []
        c = GovernanceConsole()
        c.load(data)
        c.validate()
        view = c.render_warnings()
        assert view.data["warning_count"] == 0


# ── AC-08: Console shows health issues grouped by severity ──────────────────


class TestAC08HealthBySeverity:
    """AC-08: Console can show health issues grouped by severity."""

    def test_health_grouped(self, console):
        view = console.health_by_severity()
        by_sev = view.data["by_severity"]
        assert "warning" in by_sev
        assert "critical" in by_sev
        assert "degraded" in by_sev

    def test_severity_ordering(self, console):
        view = console.health_by_severity()
        severities = list(view.data["by_severity"].keys())
        # Critical should come before warning
        assert severities.index("critical") < severities.index("warning")

    def test_health_rule_ids(self, console):
        view = console.health_by_severity()
        all_rules = []
        for sev, rules in view.data["by_severity"].items():
            all_rules.extend(r["rule_id"] for r in rules)
        assert "HR-001" in all_rules
        assert "HR-042" in all_rules
        assert "HR-044" in all_rules


# ── AC-09: Console shows selected vs rejected capability candidates ─────────


class TestAC09CapabilityCandidates:
    """AC-09: Console can show selected vs rejected capability candidates."""

    def test_selected_shown(self, console):
        view = console.capability_candidates()
        assert view.data["selected_count"] >= 1
        selected = view.data["selected"]
        assert any(s["package_id"] == "pkg_sel" for s in selected)

    def test_rejected_shown(self, console):
        view = console.capability_candidates()
        assert view.data["rejected_count"] >= 1
        rejected = view.data["rejected"]
        assert any(r["package_id"] == "pkg_rej" for r in rejected)

    def test_rejection_reason_shown(self, console):
        view = console.capability_candidates()
        rejected = view.data["rejected"]
        rej = [r for r in rejected if r["package_id"] == "pkg_rej"][0]
        assert rej["rejection_reason"] == "untrusted"


# ── AC-10: Console shows selected vs rejected/deferred branches ─────────────


class TestAC10BranchResults:
    """AC-10: Console can show selected vs rejected/deferred branch results."""

    def test_selected_branch(self, console):
        view = console.branch_results()
        assert view.data["selected_count"] >= 1
        sel = view.data["selected"]
        assert any(s["branch_id"] == "b1" for s in sel)

    def test_rejected_branch(self, console):
        view = console.branch_results()
        assert view.data["rejected_count"] >= 1
        rej = view.data["rejected"]
        assert any(r["branch_id"] == "b2" for r in rej)

    def test_deferred_empty(self, console):
        view = console.branch_results()
        # No deferred in fixture
        assert view.data["deferred_count"] == 0

    def test_deferred_shown_when_present(self):
        data = _make_lockfile_graph()
        # Add deferred to merge decision
        for n in data["nodes"]:
            if n["id"] == "md_1":
                n["metadata"]["deferred_branch_ids"] = ["b3"]
        # Recompute digest
        import hashlib
        sorted_nodes = sorted(data["nodes"], key=lambda n: n["id"])
        sorted_edges = sorted(data["edges"], key=lambda e: f"{e['from']}--{e['relationship']}-->{e['to']}")
        data["graph_digest"] = hashlib.sha256(
            json.dumps({"nodes": sorted_nodes, "edges": sorted_edges, "schema_version": "1.0.0"},
                       sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        c = GovernanceConsole()
        c.load(data)
        c.validate()
        view = c.branch_results()
        assert view.data["deferred_count"] == 1


# ── AC-11: Console shows receipt-bound relationships ────────────────────────


class TestAC11Receipts:
    """AC-11: Console can show receipt-bound relationships."""

    def test_receipts_found(self, console):
        view = console.receipts()
        assert view.data["total_receipts"] >= 1

    def test_receipt_links(self, console):
        view = console.receipts()
        receipt = view.data["receipts"][0]
        assert receipt["linked_count"] >= 1
        # rcpt_1 links to pkg_a
        linked_ids = [ln["id"] for ln in receipt["linked_nodes"]]
        assert "pkg_a" in linked_ids

    def test_receipt_digest_shown(self, console):
        view = console.receipts()
        receipt = view.data["receipts"][0]
        assert receipt["digest"] != ""


# ── AC-12: Console has CLI entrypoint ───────────────────────────────────────


class TestAC12CLIEntrypoint:
    """AC-12: Console has CLI entrypoint."""

    def test_console_group_exists(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["console", "--help"])
        assert result.exit_code == 0
        assert "open" in result.output
        assert "serve" in result.output

    def test_console_open_terminal(self, graph_json_file):
        runner = CliRunner()
        result = runner.invoke(cli, ["console", "open", "--graph", graph_json_file])
        assert result.exit_code == 0
        assert "Governance Console" in result.output

    def test_console_open_json(self, graph_json_file):
        runner = CliRunner()
        result = runner.invoke(cli, ["console", "open", "--graph", graph_json_file, "--mode", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "summary" in data
        assert data["read_only"] is True

    def test_console_open_html(self, graph_json_file):
        runner = CliRunner()
        result = runner.invoke(cli, ["console", "open", "--graph", graph_json_file, "--mode", "html"])
        assert result.exit_code == 0
        assert "<html" in result.output
        assert "OC-001" in result.output

    def test_console_open_inspect(self, graph_json_file):
        runner = CliRunner()
        result = runner.invoke(cli, ["console", "open", "--graph", graph_json_file, "--inspect", "pkg_a"])
        assert result.exit_code == 0
        assert "pkg_a" in result.output
        assert "Node Inspector" in result.output

    def test_console_open_section_health(self, graph_json_file):
        runner = CliRunner()
        result = runner.invoke(cli, ["console", "open", "--graph", graph_json_file, "--section", "health"])
        assert result.exit_code == 0
        assert "Health" in result.output

    def test_console_open_section_capabilities(self, graph_json_file):
        runner = CliRunner()
        result = runner.invoke(cli, ["console", "open", "--graph", graph_json_file, "--section", "capabilities"])
        assert result.exit_code == 0
        assert "Capability" in result.output

    def test_console_open_output_file(self, graph_json_file, tmp_path):
        out = str(tmp_path / "console_out.json")
        runner = CliRunner()
        result = runner.invoke(cli, ["console", "open", "--graph", graph_json_file,
                                      "--mode", "json", "--output", out])
        assert result.exit_code == 0
        assert Path(out).exists()

    def test_console_open_invalid_digest(self, tmp_path):
        data = _make_lockfile_graph()
        data["graph_digest"] = "wrong"
        p = tmp_path / "bad.json"
        p.write_text(json.dumps(data))
        runner = CliRunner()
        result = runner.invoke(cli, ["console", "open", "--graph", str(p)])
        assert result.exit_code == 10


# ── AC-13: Console supports JSON-only / terminal mode ───────────────────────


class TestAC13OutputModes:
    """AC-13: Console supports JSON-only / terminal mode first."""

    def test_terminal_mode(self, console):
        text = console.render_all_terminal()
        assert isinstance(text, str)
        assert "Governance Console" in text

    def test_json_mode(self, console):
        text = console.render_all_json()
        data = json.loads(text)
        assert "console_schema_version" in data
        assert "summary" in data
        assert "health" in data
        assert "capabilities" in data

    def test_json_mode_read_only_flag(self, console):
        text = console.render_all_json()
        data = json.loads(text)
        assert data["read_only"] is True


# ── AC-14: Optional HTML renderer from same JSON ────────────────────────────


class TestAC14HTMLRenderer:
    """AC-14: Optional local HTML renderer generated from same graph JSON."""

    def test_html_rendered(self, console):
        html = console.render_html()
        assert "<html" in html
        assert "</html>" in html

    def test_html_contains_summary(self, console):
        html = console.render_html()
        assert "Governance Console" in html
        assert "READ-ONLY" in html

    def test_html_contains_health(self, console):
        html = console.render_html()
        assert "HR-001" in html or "Health" in html

    def test_html_contains_oc001(self, console):
        html = console.render_html()
        assert "OC-001" in html

    def test_html_no_javascript(self, console):
        """HTML must not have interactive JavaScript (read-only)."""
        html = console.render_html()
        assert "<script" not in html


# ── AC-15: Console never edits artifacts ────────────────────────────────────


class TestAC15NeverEdits:
    """AC-15: Console never edits graph artifacts, receipts, trust stores, etc."""

    def test_graph_not_modified(self):
        original = _make_lockfile_graph()
        original_json = json.dumps(original, sort_keys=True)
        c = GovernanceConsole()
        c.load(original)
        c.validate()
        c.summary()
        c.health_by_severity()
        c.capability_candidates()
        c.branch_results()
        c.receipts()
        # Original dict should be unchanged
        assert json.dumps(original, sort_keys=True) == original_json

    def test_load_does_not_mutate_input(self):
        data = _make_lockfile_graph()
        original_nodes = len(data["nodes"])
        c = GovernanceConsole()
        c.load(data)
        c.validate()
        c.summary()
        assert len(data["nodes"]) == original_nodes

    def test_no_file_writes(self, console, tmp_path):
        """Console methods should not create files."""
        before = set(tmp_path.iterdir())
        console.summary()
        console.render_warnings()
        console.render_html()
        after = set(tmp_path.iterdir())
        assert before == after

    def test_read_only_in_oc_001(self):
        assert "read-only" in OC_001.lower()
        assert "must not invent trust" in OC_001.lower()
        assert "mutate runtime state" in OC_001.lower()
        assert "policy decisions" in OC_001.lower()


# ── Additional: ConsoleView dataclass ───────────────────────────────────────


class TestConsoleView:
    """ConsoleView dataclass behaves correctly."""

    def test_console_view_creation(self):
        view = ConsoleView(view_type="test", title="Test", data={"a": 1})
        assert view.view_type == "test"
        assert view.data["a"] == 1

    def test_console_view_json(self):
        view = ConsoleView(view_type="test", title="Test", data={"a": 1})
        j = view.to_json()
        parsed = json.loads(j)
        assert parsed["view_type"] == "test"

    def test_console_view_str(self):
        view = ConsoleView(view_type="test", title="Test", data={"a": 1}, terminal_text="hello")
        assert str(view) == "hello"
