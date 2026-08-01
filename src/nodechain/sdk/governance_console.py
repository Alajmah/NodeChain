"""
NodeChain Governance Console (v2.20.0)
=======================================

A read-only operator surface over materialized NodeChain artifacts.

OC-001:
    The governance console is a read-only operator surface over materialized
    NodeChain artifacts. It must not invent trust, mutate runtime state, or make
    policy decisions outside existing governance primitives.

Core principles:
1. The console consumes graph JSON (from v2.19.x graph export), not raw runtime state.
2. The console validates graph_digest before rendering.
3. The console is read-only by default — it never edits artifacts.
4. The console renders nodes grouped by type for operator inspection.
5. The console supports JSON-only and terminal (Rich) output modes.
6. An optional HTML renderer exists, generated from the same graph JSON.

Architecture:
    GovernanceConsole
        .load(graph_json: str | dict) -> None        # Load graph JSON
        .validate() -> bool                           # Validate digest
        .summary() -> dict                            # Summary view
        .nodes_by_type(type: str) -> list[dict]       # Grouped nodes
        .inspect_node(node_id: str) -> dict           # Node detail
        .warnings() -> list[str]                      # Graph warnings
        .health_by_severity() -> dict                 # Health grouped
        .capability_candidates() -> dict              # Selected/rejected
        .branch_results() -> dict                     # Selected/rejected/deferred
        .receipts() -> dict                           # Receipt-bound relationships
        .render_json() -> str                         # JSON output
        .render_terminal() -> str                     # Rich terminal output
        .render_html() -> str                         # HTML output

Module header: v2.20.1
License: MIT
"""

from __future__ import annotations

import hashlib
import html
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# ── OC-001 Invariant ────────────────────────────────────────────────────────

OC_001 = (
    "The governance console is a read-only operator surface over materialized "
    "NodeChain artifacts. It must not invent trust, mutate runtime state, or "
    "make policy decisions outside existing governance primitives."
)

# ── Console schema ──────────────────────────────────────────────────────────

CONSOLE_SCHEMA_VERSION = "1.0.0"


def _esc(value: Any) -> str:
    """HTML-escape a graph-derived value before insertion into HTML (CONSOLE-001).

    Every value that comes from graph JSON — labels, package IDs, rejection
    reasons, branch IDs, receipt IDs, severity names, warnings — must pass
    through this function before being interpolated into HTML.
    """
    if value is None:
        return ""
    return html.escape(str(value), quote=True)

# Node type groups for rendering
NODE_TYPE_GROUPS: dict[str, list[str]] = {
    "registry": ["registry"],
    "package": ["package", "dependency"],
    "publisher": ["publisher"],
    "certification": ["certification", "lifecycle", "policy_verdict"],
    "capability": ["capability_request", "capability_offer"],
    "branch": ["branch_plan", "branch_result", "merge_decision", "human_review"],
    "receipt": ["receipt"],
    "health": ["health_rule"],
    "trace": ["trace_event"],
}

# Severity ordering for health display
SEVERITY_ORDER = ["critical", "error", "degraded", "warning", "healthy", "info", "neutral"]

# ── Validation ──────────────────────────────────────────────────────────────


def _sha256_dict(data: dict[str, Any]) -> str:
    """Deterministic SHA-256 of a dictionary."""
    return hashlib.sha256(
        json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _recompute_digest(graph: dict[str, Any]) -> str:
    """Recompute the graph digest from nodes and edges.

    The digest is computed over sorted nodes and edges plus schema_version,
    matching the TrustGraphView.compute_digest() algorithm.
    """
    nodes = sorted(graph.get("nodes", []), key=lambda n: n.get("id", ""))
    edges = sorted(graph.get("edges", []), key=lambda e: f"{e.get('from','')}--{e.get('relationship','')}-->{e.get('to','')}")
    return _sha256_dict({
        "nodes": nodes,
        "edges": edges,
        "schema_version": graph.get("schema_version", "1.0.0"),
    })


# ── Console view dataclass ──────────────────────────────────────────────────


@dataclass
class ConsoleView:
    """A renderable console view.

    Contains structured data for JSON output and
    a pre-formatted string for terminal output.
    """

    view_type: str
    title: str
    data: dict[str, Any] = field(default_factory=dict)
    terminal_text: str = ""

    def to_json(self, indent: int = 2) -> str:
        return json.dumps({
            "view_type": self.view_type,
            "title": self.title,
            "data": self.data,
        }, indent=indent, sort_keys=True)

    def __str__(self) -> str:
        if self.terminal_text:
            return self.terminal_text
        return self.to_json()


# ── Governance Console ──────────────────────────────────────────────────────


class GovernanceConsole:
    """Read-only operator governance console over graph JSON.

    OC-001: The console is strictly read-only. It loads graph JSON,
    validates its digest, and renders inspectable views. It does not
    modify, create, or delete any artifact, receipt, trust store entry,
    policy, package, or runtime state.

    Usage:
        console = GovernanceConsole()
        console.load(graph_json_str)
        assert console.validate()
        view = console.summary()
        print(view)
    """

    def __init__(self) -> None:
        self._graph: dict[str, Any] | None = None
        self._validated: bool = False
        self._read_only: bool = True  # Always True — OC-001

    # ── Loading ─────────────────────────────────────────────────────────

    def load(self, graph_data: str | dict[str, Any]) -> None:
        """Load graph JSON for rendering.

        Accepts either a JSON string or a pre-parsed dict.
        Does not touch any runtime state.
        """
        if isinstance(graph_data, str):
            self._graph = json.loads(graph_data)
        elif isinstance(graph_data, dict):
            self._graph = graph_data
        else:
            raise TypeError(f"graph_data must be str or dict, got {type(graph_data)}")

        self._validated = False

    def load_from_file(self, path: str) -> None:
        """Load graph JSON from a file path."""
        with open(path, "r", encoding="utf-8") as f:
            self.load(f.read())

    @property
    def is_loaded(self) -> bool:
        return self._graph is not None

    @property
    def is_validated(self) -> bool:
        return self._validated

    @property
    def read_only(self) -> bool:
        """Always True — OC-001."""
        return self._read_only

    # ── Validation ──────────────────────────────────────────────────────

    def validate(self) -> bool:
        """Validate graph digest (AC-04).

        Recomputes the digest from nodes and edges and compares
        against the stored graph_digest. Returns True if they match.

        Raises RuntimeError if no graph is loaded.
        """
        if self._graph is None:
            raise RuntimeError("No graph loaded")

        stored_digest = self._graph.get("graph_digest", "")
        if not stored_digest:
            self._validated = False
            return False

        recomputed = _recompute_digest(self._graph)
        self._validated = recomputed == stored_digest
        return self._validated

    # ── Internal helpers ────────────────────────────────────────────────

    def _require_graph(self) -> dict[str, Any]:
        if self._graph is None:
            raise RuntimeError("No graph loaded")
        return self._graph

    def _require_validated(self) -> dict[str, Any]:
        graph = self._require_graph()
        if not self._validated:
            if not self.validate():
                raise ValueError(
                    "Graph digest validation failed — refusing to render "
                    "(OC-001: console validates graph_digest before rendering)"
                )
        return graph

    def _nodes(self) -> list[dict[str, Any]]:
        return self._require_validated().get("nodes", [])

    def _edges(self) -> list[dict[str, Any]]:
        return self._require_validated().get("edges", [])

    def _warnings(self) -> list[str]:
        return self._require_validated().get("warnings", [])

    def _node_by_id(self, node_id: str) -> dict[str, Any] | None:
        for n in self._nodes():
            if n.get("id") == node_id:
                return n
        return None

    def _edges_for_node(self, node_id: str) -> list[dict[str, Any]]:
        """All edges involving the given node (as from or to)."""
        result = []
        for e in self._edges():
            if e.get("from") == node_id or e.get("to") == node_id:
                result.append(e)
        return result

    def _group_nodes(self) -> dict[str, list[dict[str, Any]]]:
        """Group all nodes by type group (AC-05)."""
        groups: dict[str, list[dict[str, Any]]] = {
            g: [] for g in NODE_TYPE_GROUPS
        }
        groups["_other"] = []
        for node in self._nodes():
            placed = False
            for group_name, type_list in NODE_TYPE_GROUPS.items():
                if node.get("type", "") in type_list:
                    groups[group_name].append(node)
                    placed = True
                    break
            if not placed:
                groups["_other"].append(node)
        return groups

    # ── Views (AC-03 through AC-11) ─────────────────────────────────────

    def summary(self) -> ConsoleView:
        """High-level summary of the loaded graph (AC-03, AC-05)."""
        graph = self._require_validated()
        nodes = self._nodes()
        edges = self._edges()
        warnings = self._warnings()
        groups = self._group_nodes()

        group_counts = {
            g: len(nodes_list) for g, nodes_list in groups.items() if nodes_list
        }

        data = {
            "schema_version": graph.get("schema_version", "?"),
            "graph_digest": graph.get("graph_digest", "?")[:16] + "...",
            "source_artifacts": graph.get("source_artifacts", []),
            "node_count": len(nodes),
            "edge_count": len(edges),
            "warning_count": len(warnings),
            "nodes_by_group": group_counts,
            "read_only": True,
            "oc_001": OC_001,
        }

        # Terminal rendering
        lines = [
            "═══ NodeChain Governance Console ═══",
            f"  Read-Only: YES (OC-001)",
            f"  Schema:    {data['schema_version']}",
            f"  Digest:    {data['graph_digest']}",
            f"  Sources:   {', '.join(data['source_artifacts']) or 'none'}",
            f"  Nodes:     {data['node_count']}",
            f"  Edges:     {data['edge_count']}",
            f"  Warnings:  {data['warning_count']}",
            "",
            "  ── Nodes by Group ──",
        ]
        for g, count in sorted(group_counts.items()):
            lines.append(f"    {g:20s} {count}")
        lines.append("")
        lines.append("  Use 'console inspect <node_id>' for node details.")

        return ConsoleView(
            view_type="summary",
            title="Console Summary",
            data=data,
            terminal_text="\n".join(lines),
        )

    def nodes_by_type(self, type_group: str) -> ConsoleView:
        """Render nodes grouped by type (AC-05)."""
        groups = self._group_nodes()
        nodes = groups.get(type_group, groups.get("_other", []))

        data = {
            "type_group": type_group,
            "node_count": len(nodes),
            "nodes": [{"id": n.get("id"), "type": n.get("type"),
                       "label": n.get("label"), "status": n.get("status", "neutral"),
                       "source_artifact": n.get("source_artifact")} for n in nodes],
        }

        lines = [f"═══ Nodes: {type_group} ({len(nodes)}) ═══"]
        for n in nodes:
            status_marker = self._status_icon(n.get("status", "neutral"))
            lines.append(f"  {status_marker} {n.get('id', '?'):30s} {n.get('label', '?')}")

        return ConsoleView(
            view_type="nodes_by_type",
            title=f"Nodes: {type_group}",
            data=data,
            terminal_text="\n".join(lines),
        )

    def inspect_node(self, node_id: str) -> ConsoleView:
        """Inspect a single node with full details (AC-06)."""
        node = self._node_by_id(node_id)
        if node is None:
            raise ValueError(f"Node not found: {node_id}")

        edges = self._edges_for_node(node_id)

        data = {
            "id": node.get("id"),
            "type": node.get("type"),
            "label": node.get("label"),
            "source_artifact": node.get("source_artifact"),
            "digest": node.get("digest", ""),
            "status": node.get("status", "neutral"),
            "metadata": node.get("metadata", {}),
            "edges": [{"from": e.get("from"), "to": e.get("to"),
                       "relationship": e.get("relationship"),
                       "source_artifact": e.get("source_artifact"),
                       "reason": e.get("reason", "")} for e in edges],
        }

        lines = [
            f"═══ Node Inspector ═══",
            f"  ID:               {data['id']}",
            f"  Type:             {data['type']}",
            f"  Label:            {data['label']}",
            f"  Source Artifact:  {data['source_artifact']}",
            f"  Digest:           {data['digest'][:32] + '...' if len(data['digest']) > 32 else data['digest']}",
            f"  Status:           {data['status']}",
        ]
        if data["metadata"]:
            lines.append("  Metadata:")
            for k, v in sorted(data["metadata"].items()):
                lines.append(f"    {k}: {v}")
        if edges:
            lines.append(f"  Edges ({len(edges)}):")
            for e in edges:
                direction = "→" if e.get("from") == node_id else "←"
                other = e.get("to") if e.get("from") == node_id else e.get("from")
                lines.append(f"    {direction} {other} [{e.get('relationship')}]")
        else:
            lines.append("  Edges: none")

        return ConsoleView(
            view_type="node_inspector",
            title=f"Node: {node_id}",
            data=data,
            terminal_text="\n".join(lines),
        )

    def render_warnings(self) -> ConsoleView:
        """Show all warnings from the graph (AC-07)."""
        warnings = self._warnings()

        data = {
            "warning_count": len(warnings),
            "warnings": warnings,
        }

        lines = [f"═══ Warnings ({len(warnings)}) ═══"]
        if warnings:
            for i, w in enumerate(warnings, 1):
                lines.append(f"  {i}. {w}")
        else:
            lines.append("  No warnings.")

        return ConsoleView(
            view_type="warnings",
            title="Graph Warnings",
            data=data,
            terminal_text="\n".join(lines),
        )

    def health_by_severity(self) -> ConsoleView:
        """Show health issues grouped by severity (AC-08)."""
        nodes = self._nodes()
        health_nodes = [n for n in nodes if n.get("type") == "health_rule"]

        # Group by severity from metadata or node status
        by_severity: dict[str, list[dict[str, Any]]] = {}
        for n in health_nodes:
            severity = n.get("metadata", {}).get("severity", n.get("status", "neutral"))
            by_severity.setdefault(severity, []).append(n)

        # Sort by severity order
        sorted_groups = {}
        for sev in SEVERITY_ORDER:
            if sev in by_severity:
                sorted_groups[sev] = by_severity[sev]
        # Add any unknown severities at end
        for sev in sorted(by_severity.keys()):
            if sev not in sorted_groups:
                sorted_groups[sev] = by_severity[sev]

        data = {
            "total_issues": len(health_nodes),
            "by_severity": {
                sev: [{"rule_id": n.get("metadata", {}).get("rule_id", n.get("id")),
                       "name": n.get("label"),
                       "severity": sev,
                       "source_artifact": n.get("source_artifact")} for n in nodes_list]
                for sev, nodes_list in sorted_groups.items()
            },
        }

        lines = [f"═══ Health Console ({len(health_nodes)} issues) ═══"]
        for sev, rules in sorted_groups.items():
            icon = self._severity_icon(sev)
            lines.append(f"\n  {icon} {sev.upper()} ({len(rules)})")
            for r in rules:
                rule_id = r.get("metadata", {}).get("rule_id", r.get("id"))
                lines.append(f"    {rule_id:10s} {r.get('label', '?')}")

        if not health_nodes:
            lines.append("  No health issues detected.")

        return ConsoleView(
            view_type="health_by_severity",
            title="Health Issues by Severity",
            data=data,
            terminal_text="\n".join(lines),
        )

    def capability_candidates(self) -> ConsoleView:
        """Show selected vs rejected capability candidates (AC-09)."""
        nodes = self._nodes()
        edges = self._edges()

        # Find capability request nodes
        cap_requests = [n for n in nodes if n.get("type") == "capability_request"]

        selected: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []

        for req in cap_requests:
            # Find edges from this request
            req_edges = [e for e in edges if e.get("from") == req.get("id")]
            for e in req_edges:
                target = self._node_by_id(e.get("to", ""))
                if target is None:
                    continue
                candidate = {
                    "request_id": req.get("id"),
                    "capability": req.get("metadata", {}).get("capability",
                               req.get("label", "?")),
                    "package_id": target.get("metadata", {}).get("package_id",
                                target.get("id")),
                    "version": target.get("metadata", {}).get("version", "?"),
                    "relationship": e.get("relationship"),
                    "rejection_reason": e.get("reason", ""),
                    "source_artifact": target.get("source_artifact"),
                }
                if e.get("relationship") == "selected":
                    selected.append(candidate)
                elif "reject" in e.get("relationship", "").lower():
                    rejected.append(candidate)

        # Also check metadata for selected/rejected info
        for req in cap_requests:
            meta = req.get("metadata", {})
            sel_pkg = meta.get("selected_package_id")
            if sel_pkg and not any(c["package_id"] == sel_pkg for c in selected):
                selected.append({
                    "request_id": req.get("id"),
                    "capability": meta.get("capability", req.get("label", "?")),
                    "package_id": sel_pkg,
                    "version": meta.get("selected_version", "?"),
                    "relationship": "selected",
                    "rejection_reason": "",
                    "source_artifact": req.get("source_artifact"),
                })

        data = {
            "total_requests": len(cap_requests),
            "selected": selected,
            "rejected": rejected,
            "selected_count": len(selected),
            "rejected_count": len(rejected),
        }

        lines = [f"═══ Capability Inspector ═══"]
        lines.append(f"\n  ▸ SELECTED ({len(selected)})")
        for c in selected:
            lines.append(f"    {c['capability']:20s} → {c['package_id']} ({c['version']})")
        lines.append(f"\n  ▸ REJECTED ({len(rejected)})")
        for c in rejected:
            reason = f" — {c['rejection_reason']}" if c["rejection_reason"] else ""
            lines.append(f"    {c['package_id']:30s}{reason}")

        if not selected and not rejected:
            lines.append("  No capability selections found.")

        return ConsoleView(
            view_type="capability_candidates",
            title="Capability Candidates",
            data=data,
            terminal_text="\n".join(lines),
        )

    def branch_results(self) -> ConsoleView:
        """Show selected vs rejected/deferred branch results (AC-10)."""
        nodes = self._nodes()

        # Find merge decision nodes for outcomes
        merge_nodes = [n for n in nodes if n.get("type") == "merge_decision"]
        plan_nodes = [n for n in nodes if n.get("type") == "branch_plan"]
        result_nodes = [n for n in nodes if n.get("type") == "branch_result"]
        review_nodes = [n for n in nodes if n.get("type") == "human_review"]

        selected_branches: list[dict[str, Any]] = []
        rejected_branches: list[dict[str, Any]] = []
        deferred_branches: list[dict[str, Any]] = []

        for md in merge_nodes:
            meta = md.get("metadata", {})
            strategy = meta.get("strategy", md.get("label", "?"))

            sel = meta.get("selected_branch_id")
            if sel:
                selected_branches.append({
                    "branch_id": sel,
                    "strategy": strategy,
                    "merge_decision_id": md.get("id"),
                })

            for bid in meta.get("rejected_branch_ids", []):
                rejected_branches.append({
                    "branch_id": bid,
                    "strategy": strategy,
                    "reason": meta.get("rejection_reason", ""),
                })

            for bid in meta.get("deferred_branch_ids", []):
                deferred_branches.append({
                    "branch_id": bid,
                    "strategy": strategy,
                    "human_review_required": True,
                })

        # Also infer from result status
        for rn in result_nodes:
            meta = rn.get("metadata", {})
            status = meta.get("status", rn.get("status", "neutral"))
            bid = meta.get("branch_id", rn.get("id"))
            if status == "selected" and not any(b["branch_id"] == bid for b in selected_branches):
                selected_branches.append({"branch_id": bid, "strategy": "inferred", "merge_decision_id": ""})
            elif status == "rejected" and not any(b["branch_id"] == bid for b in rejected_branches):
                rejected_branches.append({"branch_id": bid, "strategy": "inferred", "reason": ""})

        data = {
            "total_plans": len(plan_nodes),
            "total_results": len(result_nodes),
            "total_reviews": len(review_nodes),
            "selected": selected_branches,
            "rejected": rejected_branches,
            "deferred": deferred_branches,
            "selected_count": len(selected_branches),
            "rejected_count": len(rejected_branches),
            "deferred_count": len(deferred_branches),
        }

        lines = ["═══ Branch / Deliberation Inspector ═══"]
        lines.append(f"  Plans: {len(plan_nodes)}  Results: {len(result_nodes)}  Reviews: {len(review_nodes)}")

        lines.append(f"\n  ✓ SELECTED ({len(selected_branches)})")
        for b in selected_branches:
            lines.append(f"    {b['branch_id']:20s} via {b['strategy']}")

        lines.append(f"\n  ✗ REJECTED ({len(rejected_branches)})")
        for b in rejected_branches:
            reason = f" — {b['reason']}" if b.get("reason") else ""
            lines.append(f"    {b['branch_id']:20s}{reason}")

        lines.append(f"\n  ⏸ DEFERRED ({len(deferred_branches)})")
        for b in deferred_branches:
            lines.append(f"    {b['branch_id']:20s} (human review required)")

        if not selected_branches and not rejected_branches and not deferred_branches:
            lines.append("  No branch outcomes found.")

        return ConsoleView(
            view_type="branch_results",
            title="Branch Results",
            data=data,
            terminal_text="\n".join(lines),
        )

    def receipts(self) -> ConsoleView:
        """Show receipt-bound relationships (AC-11)."""
        nodes = self._nodes()
        edges = self._edges()

        receipt_nodes = [n for n in nodes if n.get("type") == "receipt"]

        receipt_data = []
        for rn in receipt_nodes:
            # Find edges from this receipt
            receipt_edges = [e for e in edges if e.get("from") == rn.get("id") or e.get("to") == rn.get("id")]
            linked_nodes = []
            for e in receipt_edges:
                other_id = e.get("to") if e.get("from") == rn.get("id") else e.get("from")
                other = self._node_by_id(other_id)
                if other:
                    linked_nodes.append({
                        "id": other.get("id"),
                        "type": other.get("type"),
                        "label": other.get("label"),
                        "relationship": e.get("relationship"),
                        "source_artifact": other.get("source_artifact"),
                    })

            receipt_data.append({
                "receipt_id": rn.get("id"),
                "label": rn.get("label"),
                "digest": rn.get("digest", ""),
                "source_artifact": rn.get("source_artifact"),
                "linked_nodes": linked_nodes,
                "linked_count": len(linked_nodes),
            })

        data = {
            "total_receipts": len(receipt_nodes),
            "receipts": receipt_data,
        }

        lines = [f"═══ Receipt Explorer ({len(receipt_nodes)}) ═══"]
        for r in receipt_data:
            lines.append(f"\n  ▸ {r['receipt_id']}")
            lines.append(f"    Label:    {r['label']}")
            digest_display = r['digest'][:32] + "..." if len(r['digest']) > 32 else r['digest']
            lines.append(f"    Digest:   {digest_display}")
            lines.append(f"    Artifact: {r['source_artifact']}")
            if r["linked_nodes"]:
                lines.append(f"    Links ({r['linked_count']}):")
                for ln in r["linked_nodes"]:
                    lines.append(f"      {ln['relationship']:20s} → {ln['id']} ({ln['type']})")
            else:
                lines.append("    Links: none")

        if not receipt_nodes:
            lines.append("  No receipts found in graph.")

        return ConsoleView(
            view_type="receipts",
            title="Receipt Explorer",
            data=data,
            terminal_text="\n".join(lines),
        )

    # ── Full render ─────────────────────────────────────────────────────

    def render_all_terminal(self) -> str:
        """Render the full console in terminal mode."""
        sections = [
            self.summary().terminal_text,
            "",
            self.render_warnings().terminal_text,
            "",
            self.health_by_severity().terminal_text,
            "",
            self.capability_candidates().terminal_text,
            "",
            self.branch_results().terminal_text,
            "",
            self.receipts().terminal_text,
        ]
        return "\n".join(sections)

    def render_all_json(self) -> str:
        """Render the full console as structured JSON."""
        return json.dumps({
            "console_schema_version": CONSOLE_SCHEMA_VERSION,
            "oc_001": OC_001,
            "read_only": True,
            "validated": self._validated,
            "summary": self.summary().data,
            "warnings": self.render_warnings().data,
            "health": self.health_by_severity().data,
            "capabilities": self.capability_candidates().data,
            "branches": self.branch_results().data,
            "receipts": self.receipts().data,
        }, indent=2, sort_keys=True)

    def render_html(self) -> str:
        """Render as standalone HTML (AC-14).

        Generated from the same graph JSON — no additional data sources.
        """
        summary = self.summary().data
        warnings = self.render_warnings().data
        health = self.health_by_severity().data
        caps = self.capability_candidates().data
        branches = self.branch_results().data
        receipts = self.receipts().data

        # Build health rows
        health_rows = ""
        for sev, rules in health.get("by_severity", {}).items():
            for r in rules:
                health_rows += (
                    f'<tr class="severity-{_esc(sev)}"><td>{_esc(r.get("rule_id",""))}</td>'
                    f'<td>{_esc(sev)}</td><td>{_esc(r.get("name",""))}</td></tr>'
                )

        # Build capability rows
        cap_rows = ""
        for c in caps.get("selected", []):
            cap_rows += (
                f'<tr class="row-selected"><td>{_esc(c.get("capability",""))}</td>'
                f'<td>{_esc(c.get("package_id",""))}</td><td>{_esc(c.get("version",""))}</td>'
                f'<td>SELECTED</td><td></td></tr>'
            )
        for c in caps.get("rejected", []):
            cap_rows += (
                f'<tr class="row-rejected"><td>{_esc(c.get("capability",""))}</td>'
                f'<td>{_esc(c.get("package_id",""))}</td><td>{_esc(c.get("version",""))}</td>'
                f'<td>REJECTED</td><td>{_esc(c.get("rejection_reason",""))}</td></tr>'
            )

        # Build branch rows
        branch_rows = ""
        for b in branches.get("selected", []):
            branch_rows += (
                f'<tr class="row-selected"><td>{_esc(b.get("branch_id",""))}</td>'
                f'<td>SELECTED</td><td>{_esc(b.get("strategy",""))}</td><td></td></tr>'
            )
        for b in branches.get("rejected", []):
            branch_rows += (
                f'<tr class="row-rejected"><td>{_esc(b.get("branch_id",""))}</td>'
                f'<td>REJECTED</td><td>{_esc(b.get("strategy",""))}</td>'
                f'<td>{_esc(b.get("reason",""))}</td></tr>'
            )
        for b in branches.get("deferred", []):
            branch_rows += (
                f'<tr class="row-deferred"><td>{_esc(b.get("branch_id",""))}</td>'
                f'<td>DEFERRED</td><td>{_esc(b.get("strategy",""))}</td>'
                f'<td>Human review required</td></tr>'
            )

        # Build warning items
        warning_items = ""
        for w in warnings.get("warnings", []):
            warning_items += f'<li>{_esc(w)}</li>'
        if not warning_items:
            warning_items = "<li>No warnings</li>"

        # Build receipt cards
        receipt_cards = ""
        for r in receipts.get("receipts", []):
            link_items = ""
            for ln in r.get("linked_nodes", []):
                link_items += f'<li>{_esc(ln.get("relationship",""))}: {_esc(ln.get("id",""))} ({_esc(ln.get("type",""))})</li>'
            if not link_items:
                link_items = "<li>No links</li>"
            receipt_cards += f'''
            <div class="card receipt-card">
                <h3>{_esc(r.get("receipt_id",""))}</h3>
                <p>{_esc(r.get("label",""))}</p>
                <p class="digest">Digest: {_esc(r.get("digest","")[:32])}...</p>
                <p>Source: {_esc(r.get("source_artifact",""))}</p>
                <ul>{link_items}</ul>
            </div>'''

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>NodeChain Governance Console</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #0d1117; color: #c9d1d9; }}
  h1 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }}
  h2 {{ color: #79c0ff; margin-top: 30px; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
  .badge-readonly {{ background: #238636; color: #fff; }}
  .badge-oc {{ background: #1f6feb; color: #fff; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 10px; margin: 15px 0; }}
  .summary-item {{ background: #161b22; padding: 12px; border-radius: 6px; border: 1px solid #30363d; }}
  .summary-item .label {{ font-size: 12px; color: #8b949e; }}
  .summary-item .value {{ font-size: 20px; font-weight: bold; color: #58a6ff; }}
  table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
  th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #30363d; }}
  th {{ color: #8b949e; font-size: 12px; text-transform: uppercase; }}
  .severity-critical {{ color: #f85149; }}
  .severity-error {{ color: #f85149; }}
  .severity-degraded {{ color: #d29922; }}
  .severity-warning {{ color: #d29922; }}
  .severity-healthy {{ color: #3fb950; }}
  .row-selected {{ background: rgba(35, 134, 54, 0.1); }}
  .row-rejected {{ background: rgba(248, 81, 73, 0.1); }}
  .row-deferred {{ background: rgba(210, 153, 34, 0.1); }}
  .card {{ background: #161b22; padding: 16px; border-radius: 6px; border: 1px solid #30363d; margin: 10px 0; }}
  .receipt-card h3 {{ color: #79c0ff; margin: 0 0 8px 0; }}
  .receipt-card .digest {{ font-family: monospace; font-size: 11px; color: #8b949e; }}
  .receipt-card ul {{ padding-left: 20px; color: #8b949e; }}
  .footer {{ margin-top: 40px; padding-top: 15px; border-top: 1px solid #30363d; font-size: 12px; color: #8b949e; }}
  ul.warnings {{ color: #d29922; }}
</style>
</head>
<body>
<h1>NodeChain Governance Console</h1>
<p>
  <span class="badge badge-readonly">READ-ONLY</span>
  <span class="badge badge-oc">OC-001</span>
</p>

<div class="summary-grid">
  <div class="summary-item"><div class="label">Nodes</div><div class="value">{summary.get('node_count', 0)}</div></div>
  <div class="summary-item"><div class="label">Edges</div><div class="value">{summary.get('edge_count', 0)}</div></div>
  <div class="summary-item"><div class="label">Warnings</div><div class="value">{summary.get('warning_count', 0)}</div></div>
  <div class="summary-item"><div class="label">Sources</div><div class="value">{_esc(', '.join(summary.get('source_artifacts', [])))}</div></div>
</div>

<h2>⚠️ Warnings</h2>
<ul class="warnings">{warning_items}</ul>

<h2>🏥 Health Issues</h2>
<table>
  <thead><tr><th>Rule</th><th>Severity</th><th>Name</th></tr></thead>
  <tbody>{health_rows}</tbody>
</table>

<h2>⚡ Capability Selection</h2>
<table>
  <thead><tr><th>Capability</th><th>Package</th><th>Version</th><th>Status</th><th>Reason</th></tr></thead>
  <tbody>{cap_rows}</tbody>
</table>

<h2>🔀 Branch Outcomes</h2>
<table>
  <thead><tr><th>Branch</th><th>Status</th><th>Strategy</th><th>Detail</th></tr></thead>
  <tbody>{branch_rows}</tbody>
</table>

<h2>🧾 Receipts</h2>
{receipt_cards}

<div class="footer">
  NodeChain Governance Console v2.20.0 — Read-only (OC-001) — Generated from graph JSON<br>
  Digest: {_esc(summary.get('graph_digest', '?'))}
</div>
</body>
</html>"""

    # ── Static helpers ──────────────────────────────────────────────────

    @staticmethod
    def _status_icon(status: str) -> str:
        icons = {
            "healthy": "✓",
            "warning": "⚠",
            "error": "✗",
            "info": "ℹ",
            "neutral": "•",
        }
        return icons.get(status, "•")

    @staticmethod
    def _severity_icon(severity: str) -> str:
        icons = {
            "critical": "🔴",
            "error": "🔴",
            "degraded": "🟡",
            "warning": "🟡",
            "healthy": "🟢",
            "info": "🔵",
            "neutral": "⚪",
        }
        return icons.get(severity, "⚪")
