"""Tests for Visual Trust Graph / Capability Graph Explorer (v2.21.3).

Covers VG-001 and acceptance criteria AC-01 through AC-15.
"""

from __future__ import annotations

import json
import pytest
from pathlib import Path

from nodechain.sdk.visual_graph import (
    # Data model
    GraphNode,
    GraphEdge,
    TrustGraphView,
    GraphExporter,
    # Constants
    VISUAL_GRAPH_SCHEMA_VERSION,
    NT_REGISTRY, NT_PACKAGE, NT_PUBLISHER, NT_CERTIFICATION,
    NT_CAPABILITY_REQUEST, NT_BRANCH_PLAN, NT_BRANCH_RESULT,
    NT_MERGE_DECISION, NT_HUMAN_REVIEW, NT_RECEIPT,
    NT_HEALTH_RULE, NT_TRACE_EVENT,
    ET_TRUSTS, ET_PUBLISHED_BY, ET_CERTIFIED_BY, ET_DEPENDS_ON,
    ET_REJECTED, ET_SELECTED, ET_BONDS, ET_MERGED,
    ET_DEFERRED, ET_REVIEW_GATE,
    STATUS_HEALTHY, STATUS_WARNING, STATUS_ERROR, STATUS_INFO, STATUS_NEUTRAL,
    # Helpers
    export_graph_json, export_graph_mermaid, verify_graph_determinism,
)


# ── AC-01: Graph data model ─────────────────────────────────────────────────

class TestAC01GraphDataModel:
    """AC-01: Graph data model exists."""

    def test_graph_node_creation(self):
        n = GraphNode(
            id="pkg:test@1.0",
            type=NT_PACKAGE,
            label="test@1.0",
            source_artifact="trust_lockfile",
        )
        assert n.id == "pkg:test@1.0"
        assert n.type == NT_PACKAGE

    def test_graph_node_required_fields(self):
        n = GraphNode(
            id="test",
            type=NT_PACKAGE,
            label="test",
            source_artifact="lockfile",
        )
        d = n.to_dict()
        assert "id" in d
        assert "type" in d
        assert "label" in d
        assert "source_artifact" in d
        assert "digest" in d
        assert "status" in d

    def test_graph_edge_creation(self):
        e = GraphEdge(
            from_node="a",
            to_node="b",
            relationship=ET_TRUSTS,
            source_artifact="lockfile",
        )
        assert e.from_node == "a"
        assert e.to_node == "b"

    def test_graph_edge_required_fields(self):
        e = GraphEdge(
            from_node="a",
            to_node="b",
            relationship=ET_DEPENDS_ON,
            source_artifact="lockfile",
        )
        d = e.to_dict()
        assert "from" in d
        assert "to" in d
        assert "relationship" in d
        assert "source_artifact" in d
        assert "digest" in d
        assert "reason" in d

    def test_trust_graph_view_creation(self):
        g = TrustGraphView()
        assert g.nodes == []
        assert g.edges == []
        assert g.warnings == []
        assert g.schema_version == VISUAL_GRAPH_SCHEMA_VERSION


# ── AC-02: Graph exporter builds from artifacts ─────────────────────────────

class TestAC02GraphExporter:
    """AC-02: Graph exporter can build from various artifact types."""

    def test_build_from_lockfile(self):
        exporter = GraphExporter()
        lockfile = {
            "packages": [
                {
                    "package_id": "test_pkg",
                    "version": "1.0.0",
                    "registry_id": "reg-001",
                    "publisher_fingerprint": "fp_abc",
                    "artifact_digest": "sha256:abc",
                    "certification_digest": "sha256:cert",
                    "lifecycle": "active",
                    "trust_verdict": "trusted",
                    "dependencies": [
                        {"package_id": "dep_a", "version": "2.0.0"},
                    ],
                },
            ]
        }
        graph = exporter.build_from_lockfile(lockfile)
        assert len(graph.nodes) > 0
        assert any(n.type == NT_PACKAGE for n in graph.nodes)
        assert any(n.type == NT_REGISTRY for n in graph.nodes)
        assert any(n.type == NT_PUBLISHER for n in graph.nodes)

    def test_build_from_capability_receipt(self):
        exporter = GraphExporter()
        receipt = {
            "receipt_id": "r001",
            "capability": "search",
            "selected_package_id": "search_pkg",
            "selected_version": "1.0.0",
            "request_digest": "req_dig",
            "signature": "sig",
            "rejected_candidates": [
                {"package_id": "bad_pkg", "version": "0.9", "rejection_reason": "untrusted"},
            ],
            "candidate_scores": [
                {"package_id": "alt_pkg", "version": "1.1", "total_score": 0.8},
            ],
        }
        graph = exporter.build_from_capability_receipt(receipt)
        assert any(n.type == NT_CAPABILITY_REQUEST for n in graph.nodes)
        assert any(n.type == NT_RECEIPT for n in graph.nodes)

    def test_build_from_deliberation_receipt(self):
        exporter = GraphExporter()
        receipt = {
            "receipt_id": "delib001",
            "signature": "sig",
            "deliberation_trigger": "uncertainty",
            "branch_count": 2,
            "selected_branch_id": "b1",
        }
        plans = [
            {"branch_id": "b1", "admissible": True, "depth": 0},
            {"branch_id": "b2", "admissible": True, "depth": 0},
        ]
        results = [
            {"branch_id": "b1", "status": "completed", "output_digest": "od1"},
            {"branch_id": "b2", "status": "completed", "output_digest": "od2"},
        ]
        decision = {
            "strategy": "select_best",
            "selected_branch_id": "b1",
            "rejected_branch_ids": ["b2"],
            "confidence": 0.7,
            "human_review_required": False,
        }
        graph = exporter.build_from_deliberation_receipt(receipt, plans, results, decision)
        assert any(n.type == NT_BRANCH_PLAN for n in graph.nodes)
        assert any(n.type == NT_BRANCH_RESULT for n in graph.nodes)
        assert any(n.type == NT_MERGE_DECISION for n in graph.nodes)

    def test_build_from_health_sections(self):
        exporter = GraphExporter()
        sections = {
            "issues": [
                {"rule_id": "HR-001", "name": "unsigned_snapshot", "severity": "warning"},
                {"rule_id": "HR-042", "name": "branch_violation", "severity": "critical"},
            ]
        }
        graph = exporter.build_from_health_sections(sections)
        assert any(n.type == NT_HEALTH_RULE for n in graph.nodes)

    def test_build_from_trace_events(self):
        exporter = GraphExporter()
        events = [
            {"event_id": "e1", "node_id": "n1", "event_type": "node_invoked", "step_id": 1},
            {"event_id": "e2", "node_id": "n1", "event_type": "node_succeeded", "step_id": 2},
        ]
        graph = exporter.build_from_trace_events(events)
        assert any(n.type == NT_TRACE_EVENT for n in graph.nodes)


# ── AC-03: Every graph node has required fields ──────────────────────────────

class TestAC03NodeFields:
    """AC-03: Every node has id, type, label, source_artifact, digest, status."""

    def test_lockfile_nodes_have_all_fields(self):
        exporter = GraphExporter()
        graph = exporter.build_from_lockfile({
            "packages": [{"package_id": "p", "version": "1", "registry_id": "r"}]
        })
        for node in graph.nodes:
            d = node.to_dict()
            assert "id" in d
            assert "type" in d
            assert "label" in d
            assert "source_artifact" in d
            assert "digest" in d
            assert "status" in d

    def test_capability_nodes_have_all_fields(self):
        exporter = GraphExporter()
        graph = exporter.build_from_capability_receipt({
            "capability": "c", "selected_package_id": "p", "selected_version": "1",
            "receipt_id": "r",
        })
        for node in graph.nodes:
            d = node.to_dict()
            assert d["source_artifact"]  # non-empty


# ── AC-04: Every graph edge has required fields ──────────────────────────────

class TestAC04EdgeFields:
    """AC-04: Every edge has from, to, relationship, source_artifact, digest."""

    def test_lockfile_edges_have_all_fields(self):
        exporter = GraphExporter()
        graph = exporter.build_from_lockfile({
            "packages": [{"package_id": "p", "version": "1", "registry_id": "r",
                          "publisher_fingerprint": "fp",
                          "dependencies": [{"package_id": "d", "version": "1"}]}]
        })
        for edge in graph.edges:
            d = edge.to_dict()
            assert "from" in d
            assert "to" in d
            assert "relationship" in d
            assert "source_artifact" in d
            assert "digest" in d
            assert "reason" in d


# ── AC-05: Rejected candidates visible ───────────────────────────────────────

class TestAC05RejectedVisible:
    """AC-05: Rejected candidates are visible, not hidden."""

    def test_rejected_in_capability_graph(self):
        exporter = GraphExporter()
        receipt = {
            "capability": "search",
            "selected_package_id": "good",
            "selected_version": "1",
            "receipt_id": "r",
            "rejected_candidates": [
                {"package_id": "bad1", "version": "1", "rejection_reason": "untrusted"},
                {"package_id": "bad2", "version": "2", "rejection_reason": "revoked"},
            ],
        }
        graph = exporter.build_from_capability_receipt(receipt)
        # Find rejected edges
        rejected_edges = [e for e in graph.edges if e.relationship == ET_REJECTED]
        assert len(rejected_edges) == 2
        # Find rejected nodes
        rejected_nodes = [n for n in graph.nodes
                          if n.metadata.get("rejected")]
        assert len(rejected_nodes) == 2
        # Rejection reasons visible
        for rn in rejected_nodes:
            assert rn.metadata.get("rejection_reason")


# ── AC-06: Deprecated/revoked visually distinguishable ──────────────────────

class TestAC06StatusDistinguishable:
    """AC-06: Deprecated/revoked/untrusted packages are visually distinguishable."""

    def test_revoked_package_has_error_status(self):
        exporter = GraphExporter()
        graph = exporter.build_from_lockfile({
            "packages": [{"package_id": "revoked_pkg", "version": "1",
                          "lifecycle": "revoked"}]
        })
        pkg_node = [n for n in graph.nodes if "revoked_pkg" in n.id][0]
        assert pkg_node.status == STATUS_ERROR

    def test_deprecated_package_has_warning_status(self):
        exporter = GraphExporter()
        graph = exporter.build_from_lockfile({
            "packages": [{"package_id": "dep_pkg", "version": "1",
                          "lifecycle": "deprecated"}]
        })
        pkg_node = [n for n in graph.nodes if "dep_pkg" in n.id][0]
        assert pkg_node.status == STATUS_WARNING

    def test_active_package_has_healthy_status(self):
        exporter = GraphExporter()
        graph = exporter.build_from_lockfile({
            "packages": [{"package_id": "ok_pkg", "version": "1",
                          "lifecycle": "active"}]
        })
        pkg_node = [n for n in graph.nodes if "ok_pkg" in n.id][0]
        assert pkg_node.status == STATUS_HEALTHY


# ── AC-07: Capability selection shows hard-filter reasons ───────────────────

class TestAC07CapabilitySelectionDetails:
    """AC-07: Capability selection shows hard-filter reasons and score/rank."""

    def test_rejection_reasons_in_graph(self):
        exporter = GraphExporter()
        receipt = {
            "capability": "c",
            "selected_package_id": "sel",
            "selected_version": "1",
            "receipt_id": "r",
            "rejected_candidates": [
                {"package_id": "rej", "version": "1",
                 "rejection_reason": "REJECT_UNTRUSTED_REGISTRY"},
            ],
        }
        graph = exporter.build_from_capability_receipt(receipt)
        rej_edge = [e for e in graph.edges if e.relationship == ET_REJECTED][0]
        assert rej_edge.reason == "REJECT_UNTRUSTED_REGISTRY"

    def test_candidate_scores_in_graph(self):
        exporter = GraphExporter()
        receipt = {
            "capability": "c",
            "selected_package_id": "sel",
            "selected_version": "1",
            "receipt_id": "r",
            "candidate_scores": [
                {"package_id": "alt", "version": "1", "total_score": 0.85, "rank": 2},
            ],
        }
        graph = exporter.build_from_capability_receipt(receipt)
        alt_node = [n for n in graph.nodes if "alt" in n.id]
        assert len(alt_node) >= 1
        assert alt_node[0].metadata.get("score") == 0.85


# ── AC-08: Adaptive branch graph shows all elements ─────────────────────────

class TestAC08BranchGraph:
    """AC-08: Adaptive branch graph shows plan, budget, result, status, merge, review."""

    def test_branch_graph_shows_plans(self):
        exporter = GraphExporter()
        receipt = {"receipt_id": "d", "signature": "s"}
        plans = [{"branch_id": "b1", "admissible": True, "depth": 0}]
        graph = exporter.build_from_deliberation_receipt(receipt, plans, [], None)
        assert any(n.type == NT_BRANCH_PLAN for n in graph.nodes)

    def test_branch_graph_shows_results(self):
        exporter = GraphExporter()
        receipt = {"receipt_id": "d"}
        results = [{"branch_id": "b1", "status": "completed", "output_digest": "x"}]
        graph = exporter.build_from_deliberation_receipt(receipt, [], results, None)
        assert any(n.type == NT_BRANCH_RESULT for n in graph.nodes)

    def test_branch_graph_shows_merge(self):
        exporter = GraphExporter()
        receipt = {"receipt_id": "d"}
        decision = {"strategy": "select_best", "selected_branch_id": "b1"}
        graph = exporter.build_from_deliberation_receipt(receipt, [], [], decision)
        assert any(n.type == NT_MERGE_DECISION for n in graph.nodes)

    def test_branch_graph_shows_human_review(self):
        exporter = GraphExporter()
        receipt = {"receipt_id": "d"}
        decision = {"strategy": "defer_human", "human_review_required": True,
                    "human_review_status": "pending"}
        graph = exporter.build_from_deliberation_receipt(receipt, [], [], decision)
        assert any(n.type == NT_HUMAN_REVIEW for n in graph.nodes)

    def test_budget_exhausted_visible(self):
        exporter = GraphExporter()
        receipt = {"receipt_id": "d"}
        results = [{"branch_id": "b1", "status": "budget_exhausted", "output_digest": ""}]
        graph = exporter.build_from_deliberation_receipt(receipt, [], results, None)
        result_node = [n for n in graph.nodes if n.type == NT_BRANCH_RESULT][0]
        assert result_node.status == STATUS_WARNING


# ── AC-09: Dashboard health rules attach to graph ───────────────────────────

class TestAC09HealthAttachment:
    """AC-09: Dashboard health rules can attach to graph nodes."""

    def test_health_rules_become_nodes(self):
        exporter = GraphExporter()
        sections = {
            "issues": [
                {"rule_id": "HR-001", "name": "unsigned", "severity": "warning"},
                {"rule_id": "HR-044", "name": "review_pending", "severity": "degraded"},
            ]
        }
        graph = exporter.build_from_health_sections(sections)
        assert len([n for n in graph.nodes if n.type == NT_HEALTH_RULE]) == 2

    def test_critical_health_is_error(self):
        exporter = GraphExporter()
        sections = {"issues": [{"rule_id": "HR-042", "severity": "critical"}]}
        graph = exporter.build_from_health_sections(sections)
        hr_node = graph.nodes[0]
        assert hr_node.status == STATUS_ERROR


# ── AC-10: Export format is deterministic ───────────────────────────────────

class TestAC10DeterministicExport:
    """AC-10: Export format is deterministic."""

    def test_same_input_same_digest(self):
        exporter = GraphExporter()
        lockfile = {"packages": [{"package_id": "p", "version": "1", "registry_id": "r"}]}
        g1 = exporter.build_from_lockfile(lockfile)
        g2 = exporter.build_from_lockfile(lockfile)
        assert g1.compute_digest() == g2.compute_digest()

    def test_different_input_different_digest(self):
        exporter = GraphExporter()
        g1 = exporter.build_from_lockfile({"packages": [{"package_id": "a", "version": "1"}]})
        g2 = exporter.build_from_lockfile({"packages": [{"package_id": "b", "version": "1"}]})
        assert g1.compute_digest() != g2.compute_digest()

    def test_json_sorted_keys(self):
        exporter = GraphExporter()
        graph = exporter.build_from_lockfile({
            "packages": [{"package_id": "p", "version": "1"}]
        })
        j = graph.to_json()
        data = json.loads(j)
        # Nodes sorted by id
        node_ids = [n["id"] for n in data["nodes"]]
        assert node_ids == sorted(node_ids)


# ── AC-11: Same artifacts produce same graph digest ─────────────────────────

class TestAC11GraphDigest:
    """AC-11: Same artifacts produce same graph digest."""

    def test_capability_receipt_deterministic(self):
        exporter = GraphExporter()
        receipt = {
            "capability": "c", "selected_package_id": "p", "selected_version": "1",
            "receipt_id": "r",
        }
        g1 = exporter.build_from_capability_receipt(receipt)
        g2 = exporter.build_from_capability_receipt(receipt)
        assert verify_graph_determinism(g1, g2)

    def test_deliberation_receipt_deterministic(self):
        exporter = GraphExporter()
        receipt = {"receipt_id": "d", "signature": "s"}
        plans = [{"branch_id": "b1", "admissible": True}]
        g1 = exporter.build_from_deliberation_receipt(receipt, plans, [], None)
        g2 = exporter.build_from_deliberation_receipt(receipt, plans, [], None)
        assert verify_graph_determinism(g1, g2)

    def test_merge_graphs_deterministic(self):
        exporter = GraphExporter()
        g1 = exporter.build_from_lockfile({"packages": [{"package_id": "a", "version": "1"}]})
        g2 = exporter.build_from_lockfile({"packages": [{"package_id": "b", "version": "1"}]})
        merged1 = exporter.merge_graphs([g1, g2])
        merged2 = exporter.merge_graphs([g1, g2])
        assert verify_graph_determinism(merged1, merged2)


# ── AC-12: Missing artifacts produce warnings ───────────────────────────────

class TestAC12MissingArtifactWarnings:
    """AC-12: Missing artifact references produce warnings, not invented nodes."""

    def test_empty_lockfile_warns(self):
        exporter = GraphExporter()
        graph = exporter.build_from_lockfile({"packages": []})
        assert len(graph.warnings) > 0
        assert any("no packages" in w for w in graph.warnings)

    def test_missing_package_id_warns(self):
        exporter = GraphExporter()
        graph = exporter.build_from_lockfile({
            "packages": [{"version": "1", "registry_id": "r"}]
        })
        assert any("package_id" in w for w in graph.warnings)

    def test_missing_selected_package_warns(self):
        exporter = GraphExporter()
        graph = exporter.build_from_capability_receipt({
            "capability": "c", "receipt_id": "r",
        })
        assert any("selected" in w.lower() for w in graph.warnings)

    def test_no_invented_nodes(self):
        """VG-001: Missing refs must not create invented nodes."""
        exporter = GraphExporter()
        graph = exporter.build_from_lockfile({
            "packages": [{"package_id": "p", "version": "1",
                          "dependencies": [{"package_id": "", "version": "1"}]}]
        })
        # No node with empty id
        for node in graph.nodes:
            assert node.id != ""
            assert node.label != ""


# ── AC-13: CLI command exists ───────────────────────────────────────────────

class TestAC13CLI:
    """AC-13: CLI command exists: nodechain graph export."""

    def test_graph_export_command_exists(self):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["graph", "--help"])
        assert result.exit_code == 0

    def test_graph_export_subcommand_exists(self):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["graph", "export", "--help"])
        assert result.exit_code == 0


# ── AC-14: JSON output stable and documented ────────────────────────────────

class TestAC14JSONOutput:
    """AC-14: JSON output is stable and documented."""

    def test_json_has_schema_version(self):
        exporter = GraphExporter()
        graph = exporter.build_from_lockfile({"packages": []})
        data = json.loads(graph.to_json())
        assert data["schema_version"] == VISUAL_GRAPH_SCHEMA_VERSION

    def test_json_has_graph_digest(self):
        exporter = GraphExporter()
        graph = exporter.build_from_lockfile({"packages": []})
        data = json.loads(graph.to_json())
        assert "graph_digest" in data
        assert len(data["graph_digest"]) == 64

    def test_json_has_counts(self):
        exporter = GraphExporter()
        graph = exporter.build_from_lockfile({
            "packages": [{"package_id": "p", "version": "1", "registry_id": "r"}]
        })
        data = json.loads(graph.to_json())
        assert "node_count" in data
        assert "edge_count" in data
        assert data["node_count"] > 0

    def test_json_has_source_artifacts(self):
        exporter = GraphExporter()
        graph = exporter.build_from_lockfile({"packages": []})
        data = json.loads(graph.to_json())
        assert "source_artifacts" in data
        assert "trust_lockfile" in data["source_artifacts"]


# ── AC-15: Optional HTML/SVG renderer ───────────────────────────────────────

class TestAC15Renderer:
    """AC-15: Optional HTML/SVG renderer — Mermaid export exists."""

    def test_mermaid_export(self):
        exporter = GraphExporter()
        graph = exporter.build_from_lockfile({
            "packages": [{"package_id": "p", "version": "1", "registry_id": "r"}]
        })
        mermaid = graph.to_mermaid()
        assert mermaid.startswith("graph TD")

    def test_mermaid_has_nodes(self):
        exporter = GraphExporter()
        graph = exporter.build_from_lockfile({
            "packages": [{"package_id": "p", "version": "1", "registry_id": "r"}]
        })
        mermaid = graph.to_mermaid()
        lines = [l.strip() for l in mermaid.split("\n") if l.strip()]
        assert len(lines) > 1  # header + nodes

    def test_export_to_file(self, tmp_path):
        exporter = GraphExporter()
        graph = exporter.build_from_lockfile({"packages": []})
        json_path = str(tmp_path / "graph.json")
        mermaid_path = str(tmp_path / "graph.mmd")
        export_graph_json(graph, json_path)
        export_graph_mermaid(graph, mermaid_path)
        assert Path(json_path).exists()
        assert Path(mermaid_path).exists()


# ── VG-001: No invented trust relationships ────────────────────────────────

class TestVG001NoInvention:
    """VG-001: Every node/edge must be backed by a materialized artifact."""

    def test_all_nodes_have_source_artifact(self):
        exporter = GraphExporter()
        lockfile = {
            "packages": [
                {"package_id": "p", "version": "1", "registry_id": "r",
                 "publisher_fingerprint": "fp",
                 "certification_digest": "cd",
                 "dependencies": [{"package_id": "d", "version": "1"}]}
            ]
        }
        graph = exporter.build_from_lockfile(lockfile)
        for node in graph.nodes:
            assert node.source_artifact != "", f"Node {node.id} has no source_artifact"

    def test_all_edges_have_source_artifact(self):
        exporter = GraphExporter()
        receipt = {
            "capability": "c", "selected_package_id": "p", "selected_version": "1",
            "receipt_id": "r",
            "rejected_candidates": [{"package_id": "x", "version": "1", "rejection_reason": "r"}],
        }
        graph = exporter.build_from_capability_receipt(receipt)
        for edge in graph.edges:
            assert edge.source_artifact != "", f"Edge {edge.id} has no source_artifact"

    def test_no_inferred_trust_between_unrelated_packages(self):
        """Two packages with no dependency relationship must not have an edge."""
        exporter = GraphExporter()
        graph = exporter.build_from_lockfile({
            "packages": [
                {"package_id": "a", "version": "1"},
                {"package_id": "b", "version": "1"},
            ]
        })
        # No edge between a and b (they're independent)
        for edge in graph.edges:
            if edge.relationship == ET_DEPENDS_ON:
                assert "pkg:a" not in edge.from_node or "pkg:b" not in edge.to_node
                assert "pkg:b" not in edge.from_node or "pkg:a" not in edge.to_node


# ── Deduplication ───────────────────────────────────────────────────────────

class TestDeduplication:
    """Nodes and edges are deduplicated."""

    def test_duplicate_nodes_deduped(self):
        g = TrustGraphView()
        g.add_node(GraphNode(id="a", type=NT_PACKAGE, label="a", source_artifact="t"))
        g.add_node(GraphNode(id="a", type=NT_PACKAGE, label="a", source_artifact="t"))
        assert len(g.nodes) == 1

    def test_duplicate_edges_deduped(self):
        g = TrustGraphView()
        e = GraphEdge(from_node="a", to_node="b", relationship=ET_TRUSTS, source_artifact="t")
        g.add_edge(e)
        g.add_edge(e)
        assert len(g.edges) == 1


# ── Merge graphs ────────────────────────────────────────────────────────────

class TestMergeGraphs:
    """Multiple graphs can be merged."""

    def test_merge_preserves_all_nodes(self):
        exporter = GraphExporter()
        g1 = exporter.build_from_lockfile({"packages": [{"package_id": "a", "version": "1"}]})
        g2 = exporter.build_from_lockfile({"packages": [{"package_id": "b", "version": "1"}]})
        merged = exporter.merge_graphs([g1, g2])
        assert len(merged.nodes) >= len(g1.nodes) + len(g2.nodes) - (
            len(set(n.id for n in g1.nodes) & set(n.id for n in g2.nodes))
        )

    def test_merge_preserves_warnings(self):
        exporter = GraphExporter()
        g1 = exporter.build_from_lockfile({"packages": []})
        g2 = exporter.build_from_lockfile({"packages": []})
        merged = exporter.merge_graphs([g1, g2])
        assert len(merged.warnings) >= 2  # Both had warnings


# ── Schema version ──────────────────────────────────────────────────────────

class TestSchemaVersion:
    def test_schema_version(self):
        assert VISUAL_GRAPH_SCHEMA_VERSION == "1.0.0"
