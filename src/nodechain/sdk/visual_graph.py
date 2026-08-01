"""Visual Trust Graph — Governance Graph Explorer.

v2.19.0

Central invariant (VG-001):
    Every visual graph edge and node must be backed by a materialized runtime,
    trust, capability, dependency, branch, receipt, or dashboard artifact.
    The graph explorer must not invent inferred trust relationships.

The graph exporter materializes verifiable governance graphs from real
artifacts — it does not infer or invent relationships.
"""

from __future__ import annotations

import json
import hashlib
import time
from dataclasses import dataclass, field
from typing import Any

# ── Constants ───────────────────────────────────────────────────────────────

VISUAL_GRAPH_SCHEMA_VERSION = "1.0.0"

# Node types
NT_REGISTRY = "registry"
NT_PACKAGE = "package"
NT_PUBLISHER = "publisher"
NT_CERTIFICATION = "certification"
NT_LIFECYCLE = "lifecycle"
NT_CAPABILITY_REQUEST = "capability_request"
NT_CAPABILITY_OFFER = "capability_offer"
NT_BRANCH_PLAN = "branch_plan"
NT_BRANCH_RESULT = "branch_result"
NT_MERGE_DECISION = "merge_decision"
NT_HUMAN_REVIEW = "human_review"
NT_RECEIPT = "receipt"
NT_POLICY_VERDICT = "policy_verdict"
NT_HEALTH_RULE = "health_rule"
NT_TRACE_EVENT = "trace_event"
NT_DEPENDENCY = "dependency"

# Edge types (relationships)
ET_TRUSTS = "trusts"
ET_PUBLISHED_BY = "published_by"
ET_CERTIFIED_BY = "certified_by"
ET_DEPENDS_ON = "depends_on"
ET_REJECTED = "rejected"
ET_SELECTED = "selected"
ET_OFFERS = "offers"
ET_REQUESTED = "requested"
ET_ADMITTED = "admitted"
ET_DENIED = "denied"
ET_MERGED = "merged"
ET_DEFERRED = "deferred"
ET_BONDS = "bonds"
ET_TRIGGERS = "triggers"
ET_REVIEW_GATE = "review_gate"
ET_HEALTH_ALERT = "health_alert"

# Status colors (for rendering hints)
STATUS_HEALTHY = "healthy"
STATUS_WARNING = "warning"
STATUS_ERROR = "error"
STATUS_INFO = "info"
STATUS_NEUTRAL = "neutral"


# ── Helpers ─────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sha256_str(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _sha256_dict(data: dict[str, Any]) -> str:
    return _sha256_str(json.dumps(data, sort_keys=True, separators=(",", ":")))


# ── Graph Data Model ────────────────────────────────────────────────────────

@dataclass
class GraphNode:
    """A node in the governance graph.

    Every node has source_artifact — the runtime/trust/capability artifact
    it was materialized from. VG-001: no invented nodes.
    """

    id: str
    type: str
    label: str
    source_artifact: str  # What artifact this came from
    digest: str = ""
    status: str = STATUS_NEUTRAL
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "label": self.label,
            "source_artifact": self.source_artifact,
            "digest": self.digest,
            "status": self.status,
            "metadata": self.metadata,
        }


@dataclass
class GraphEdge:
    """An edge in the governance graph.

    Every edge has source_artifact and a relationship type.
    VG-001: no inferred trust relationships.
    """

    from_node: str
    to_node: str
    relationship: str
    source_artifact: str
    digest: str = ""
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return f"{self.from_node}--{self.relationship}-->{self.to_node}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "from": self.from_node,
            "to": self.to_node,
            "relationship": self.relationship,
            "source_artifact": self.source_artifact,
            "digest": self.digest,
            "reason": self.reason,
            "metadata": self.metadata,
        }


@dataclass
class TrustGraphView:
    """A complete governance graph view.

    Materialized from real artifacts — lockfiles, receipts, traces,
    health sections. Contains nodes, edges, warnings for missing refs,
    and a graph digest for determinism.
    """

    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    schema_version: str = VISUAL_GRAPH_SCHEMA_VERSION
    generated_at: str = field(default_factory=_now_iso)
    source_artifacts: list[str] = field(default_factory=list)

    def add_node(self, node: GraphNode) -> None:
        # Deduplicate by id
        existing_ids = {n.id for n in self.nodes}
        if node.id not in existing_ids:
            self.nodes.append(node)

    def add_edge(self, edge: GraphEdge) -> None:
        # Deduplicate by id
        existing_ids = {e.id for e in self.edges}
        if edge.id not in existing_ids:
            self.edges.append(edge)

    def compute_digest(self) -> str:
        """Deterministic graph digest — same artifacts produce same digest."""
        node_data = [n.to_dict() for n in sorted(self.nodes, key=lambda n: n.id)]
        edge_data = [e.to_dict() for e in sorted(self.edges, key=lambda e: e.id)]
        return _sha256_dict({
            "nodes": node_data,
            "edges": edge_data,
            "schema_version": self.schema_version,
        })

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "graph_digest": self.compute_digest(),
            "source_artifacts": sorted(self.source_artifacts),
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "nodes": [n.to_dict() for n in sorted(self.nodes, key=lambda n: n.id)],
            "edges": [e.to_dict() for e in sorted(self.edges, key=lambda e: e.id)],
            "warnings": self.warnings,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def to_mermaid(self) -> str:
        """Export as Mermaid flowchart for quick visualization."""
        lines = ["graph TD"]
        for node in sorted(self.nodes, key=lambda n: n.id):
            safe_id = node.id.replace("-", "_")
            shape_map = {
                NT_REGISTRY: f"{{{node.label}}}",
                NT_PACKAGE: f"[{node.label}]",
                NT_PUBLISHER: f"({node.label})",
                NT_CERTIFICATION: f"[{node.label}]",
                NT_RECEIPT: f"[{node.label}]",
                NT_BRANCH_PLAN: f"[{node.label}]",
                NT_BRANCH_RESULT: f"[{node.label}]",
                NT_MERGE_DECISION: f"{{{node.label}}}",
                NT_HUMAN_REVIEW: f"[/{node.label}/]",
            }
            shape = shape_map.get(node.type, f"[{node.label}]")
            status_style = ""
            if node.status == STATUS_ERROR:
                status_style = ":::error"
            elif node.status == STATUS_WARNING:
                status_style = ":::warning"
            elif node.status == STATUS_HEALTHY:
                status_style = ":::healthy"
            lines.append(f"    {safe_id}{shape}{status_style}")

        for edge in sorted(self.edges, key=lambda e: e.id):
            from_id = edge.from_node.replace("-", "_")
            to_id = edge.to_node.replace("-", "_")
            label = edge.relationship
            if edge.reason:
                label = f"{edge.relationship}|{edge.reason}"
            lines.append(f"    {from_id} -->|{label}| {to_id}")

        return "\n".join(lines)


# ── Graph Exporter ──────────────────────────────────────────────────────────

class GraphExporter:
    """Builds governance graphs from materialized runtime artifacts.

    VG-001: Every node and edge must be backed by a real artifact.
    Missing references produce warnings, not invented graph nodes.

    Usage:
        exporter = GraphExporter()
        graph = exporter.build_from_capability_receipt(receipt_dict)
        graph = exporter.build_from_deliberation_receipt(receipt_dict)
        graph = exporter.build_from_lockfile(lockfile_dict)
        graph = exporter.build_from_health_sections(sections_dict)
    """

    def build_from_lockfile(
        self,
        lockfile: dict[str, Any],
    ) -> TrustGraphView:
        """Build package trust + dependency graph from a trust lockfile.

        View: Registry → Package → Publisher → Certification → Lifecycle
        View: Root package → dependencies → transitive dependencies
        """
        graph = TrustGraphView(source_artifacts=["trust_lockfile"])
        warnings: list[str] = []

        packages = lockfile.get("packages", [])
        if not packages:
            warnings.append("lockfile contains no packages")

        for pkg in packages:
            pkg_id = pkg.get("package_id", "")
            version = pkg.get("version", "")
            node_id = f"pkg:{pkg_id}@{version}"

            if not pkg_id:
                warnings.append("package entry missing package_id")
                continue

            # Package node
            status = STATUS_HEALTHY
            lifecycle = pkg.get("lifecycle", "active")
            if lifecycle in ("revoked",):
                status = STATUS_ERROR
            elif lifecycle in ("deprecated",):
                status = STATUS_WARNING

            graph.add_node(GraphNode(
                id=node_id,
                type=NT_PACKAGE,
                label=f"{pkg_id}@{version}",
                source_artifact="trust_lockfile",
                digest=pkg.get("artifact_digest", ""),
                status=status,
                metadata={
                    "lifecycle": lifecycle,
                    "trust_verdict": pkg.get("trust_verdict", ""),
                    "registry_id": pkg.get("registry_id", ""),
                },
            ))

            # Registry node
            reg_id = pkg.get("registry_id", "")
            if reg_id:
                reg_node_id = f"reg:{reg_id}"
                graph.add_node(GraphNode(
                    id=reg_node_id,
                    type=NT_REGISTRY,
                    label=reg_id,
                    source_artifact="trust_lockfile",
                    status=STATUS_INFO,
                ))
                graph.add_edge(GraphEdge(
                    from_node=reg_node_id,
                    to_node=node_id,
                    relationship=ET_TRUSTS,
                    source_artifact="trust_lockfile",
                    reason=pkg.get("trust_verdict", ""),
                ))

            # Publisher node
            pub_fp = pkg.get("publisher_fingerprint", "")
            if pub_fp:
                pub_node_id = f"pub:{pub_fp}"
                graph.add_node(GraphNode(
                    id=pub_node_id,
                    type=NT_PUBLISHER,
                    label=f"Publisher:{pub_fp[:12]}",
                    source_artifact="trust_lockfile",
                    status=STATUS_INFO,
                ))
                graph.add_edge(GraphEdge(
                    from_node=node_id,
                    to_node=pub_node_id,
                    relationship=ET_PUBLISHED_BY,
                    source_artifact="trust_lockfile",
                ))

            # Certification node
            cert_digest = pkg.get("certification_digest", "")
            if cert_digest:
                cert_node_id = f"cert:{pkg_id}"
                graph.add_node(GraphNode(
                    id=cert_node_id,
                    type=NT_CERTIFICATION,
                    label=f"Cert:{pkg_id}",
                    source_artifact="trust_lockfile",
                    digest=cert_digest,
                    status=STATUS_HEALTHY,
                ))
                graph.add_edge(GraphEdge(
                    from_node=node_id,
                    to_node=cert_node_id,
                    relationship=ET_CERTIFIED_BY,
                    source_artifact="trust_lockfile",
                ))

            # Dependency edges
            deps = pkg.get("dependencies", [])
            for dep in deps:
                dep_id = dep.get("package_id", "")
                dep_ver = dep.get("version", "")
                if dep_id:
                    dep_node_id = f"pkg:{dep_id}@{dep_ver}"
                    # Add dependency node if not already present
                    graph.add_node(GraphNode(
                        id=dep_node_id,
                        type=NT_PACKAGE,
                        label=f"{dep_id}@{dep_ver}",
                        source_artifact="trust_lockfile",
                        digest=dep.get("artifact_digest", ""),
                        status=STATUS_INFO,
                        metadata={"dependency": True},
                    ))
                    graph.add_edge(GraphEdge(
                        from_node=node_id,
                        to_node=dep_node_id,
                        relationship=ET_DEPENDS_ON,
                        source_artifact="trust_lockfile",
                        reason=dep.get("version_constraint", ""),
                    ))
                else:
                    warnings.append(f"dependency of {pkg_id} missing package_id")

        graph.warnings = warnings
        return graph

    def build_from_capability_receipt(
        self,
        receipt: dict[str, Any],
    ) -> TrustGraphView:
        """Build capability graph from a CapabilitySelectionReceipt.

        View: CapabilityRequest → candidates → rejected candidates → selected
        """
        graph = TrustGraphView(source_artifacts=["capability_selection_receipt"])
        warnings: list[str] = []

        capability = receipt.get("capability", "")
        selected_pkg = receipt.get("selected_package_id", "")
        selected_ver = receipt.get("selected_version", "")

        # Request node
        req_node_id = f"capreq:{capability}"
        graph.add_node(GraphNode(
            id=req_node_id,
            type=NT_CAPABILITY_REQUEST,
            label=f"Request: {capability}",
            source_artifact="capability_selection_receipt",
            digest=receipt.get("request_digest", ""),
            status=STATUS_INFO,
        ))

        # Receipt node
        receipt_node_id = f"receipt:{receipt.get('receipt_id', 'unknown')}"
        graph.add_node(GraphNode(
            id=receipt_node_id,
            type=NT_RECEIPT,
            label=f"Selection Receipt",
            source_artifact="capability_selection_receipt",
            digest=receipt.get("signature", ""),
            status=STATUS_HEALTHY,
            metadata={
                "policy_digest": receipt.get("policy_digest", ""),
                "selected_at": receipt.get("selected_at", ""),
            },
        ))

        # Selected package
        if selected_pkg:
            sel_node_id = f"pkg:{selected_pkg}@{selected_ver}"
            status = STATUS_HEALTHY
            risk_level = ""
            graph.add_node(GraphNode(
                id=sel_node_id,
                type=NT_PACKAGE,
                label=f"{selected_pkg}@{selected_ver}",
                source_artifact="capability_selection_receipt",
                status=status,
                metadata={"selected": True},
            ))
            graph.add_edge(GraphEdge(
                from_node=req_node_id,
                to_node=sel_node_id,
                relationship=ET_SELECTED,
                source_artifact="capability_selection_receipt",
            ))
            graph.add_edge(GraphEdge(
                from_node=receipt_node_id,
                to_node=sel_node_id,
                relationship=ET_BONDS,
                source_artifact="capability_selection_receipt",
            ))
        else:
            warnings.append("receipt has no selected package")

        # Rejected candidates
        rejected = receipt.get("rejected_candidates", [])
        for rej in rejected:
            rej_pkg = rej.get("package_id", "")
            rej_ver = rej.get("version", "")
            reason = rej.get("rejection_reason", "")
            if rej_pkg:
                rej_node_id = f"pkg:{rej_pkg}@{rej_ver}"
                graph.add_node(GraphNode(
                    id=rej_node_id,
                    type=NT_PACKAGE,
                    label=f"{rej_pkg}@{rej_ver}",
                    source_artifact="capability_selection_receipt",
                    status=STATUS_ERROR,
                    metadata={"rejected": True, "rejection_reason": reason},
                ))
                graph.add_edge(GraphEdge(
                    from_node=req_node_id,
                    to_node=rej_node_id,
                    relationship=ET_REJECTED,
                    source_artifact="capability_selection_receipt",
                    reason=reason,
                ))

        # Candidate scores (visible, not hidden)
        candidates = receipt.get("candidate_scores", [])
        for cand in candidates:
            cand_pkg = cand.get("package_id", "")
            if cand_pkg and cand_pkg != selected_pkg:
                cand_node_id = f"pkg:{cand_pkg}@{cand.get('version', '')}"
                graph.add_node(GraphNode(
                    id=cand_node_id,
                    type=NT_PACKAGE,
                    label=f"{cand_pkg}@{cand.get('version', '')}",
                    source_artifact="capability_selection_receipt",
                    status=STATUS_NEUTRAL,
                    metadata={
                        "score": cand.get("total_score", 0),
                        "rank": cand.get("rank", 0),
                        "human_review": cand.get("human_review_required", False),
                    },
                ))

        graph.warnings = warnings
        return graph

    def build_from_deliberation_receipt(
        self,
        receipt: dict[str, Any],
        plans: list[dict[str, Any]] | None = None,
        results: list[dict[str, Any]] | None = None,
        decision: dict[str, Any] | None = None,
    ) -> TrustGraphView:
        """Build adaptive branching graph from a DeliberationReceipt.

        View: DeliberationRequest → BranchPlans → BranchResults → MergeDecision
        """
        graph = TrustGraphView(source_artifacts=["deliberation_receipt"])
        warnings: list[str] = []

        # Receipt node
        receipt_id = receipt.get("receipt_id", "unknown")
        receipt_node_id = f"receipt:{receipt_id}"
        graph.add_node(GraphNode(
            id=receipt_node_id,
            type=NT_RECEIPT,
            label=f"Deliberation Receipt",
            source_artifact="deliberation_receipt",
            digest=receipt.get("signature", ""),
            status=STATUS_HEALTHY,
            metadata={
                "trigger": receipt.get("deliberation_trigger", ""),
                "branch_count": receipt.get("branch_count", 0),
                "selected_branch_id": receipt.get("selected_branch_id"),
            },
        ))

        # Branch plan nodes
        if plans:
            for plan in plans:
                branch_id = plan.get("branch_id", "")
                if not branch_id:
                    warnings.append("plan missing branch_id")
                    continue
                plan_node_id = f"branch_plan:{branch_id}"
                status = STATUS_HEALTHY if plan.get("admissible") else STATUS_ERROR
                graph.add_node(GraphNode(
                    id=plan_node_id,
                    type=NT_BRANCH_PLAN,
                    label=f"Plan: {branch_id[:12]}",
                    source_artifact="branch_plan",
                    digest=plan.get("policy_digest", ""),
                    status=status,
                    metadata={
                        "depth": plan.get("depth", 0),
                        "exploratory": plan.get("is_exploratory", True),
                        "admissible": plan.get("admissible", False),
                    },
                ))
                graph.add_edge(GraphEdge(
                    from_node=receipt_node_id,
                    to_node=plan_node_id,
                    relationship=ET_BONDS,
                    source_artifact="deliberation_receipt",
                ))

        # Branch result nodes
        if results:
            for result in results:
                branch_id = result.get("branch_id", "")
                if not branch_id:
                    warnings.append("result missing branch_id")
                    continue
                result_node_id = f"branch_result:{branch_id}"
                status_map = {
                    "completed": STATUS_HEALTHY,
                    "failed": STATUS_ERROR,
                    "budget_exhausted": STATUS_WARNING,
                    "policy_violated": STATUS_ERROR,
                    "cancelled": STATUS_NEUTRAL,
                }
                rstatus = result.get("status", "pending")
                status = status_map.get(rstatus, STATUS_NEUTRAL)
                graph.add_node(GraphNode(
                    id=result_node_id,
                    type=NT_BRANCH_RESULT,
                    label=f"Result: {branch_id[:12]}",
                    source_artifact="branch_result",
                    digest=result.get("output_digest", ""),
                    status=status,
                    metadata={
                        "status": rstatus,
                        "evidence_count": len(result.get("evidence", [])),
                        "side_effects": len(result.get("side_effect_summary", [])),
                    },
                ))
                # Link plan → result
                plan_node_id = f"branch_plan:{branch_id}"
                graph.add_edge(GraphEdge(
                    from_node=plan_node_id,
                    to_node=result_node_id,
                    relationship=ET_ADMITTED if rstatus == "completed" else ET_DENIED,
                    source_artifact="branch_result",
                ))

        # Merge decision node
        if decision:
            merge_node_id = f"merge:{receipt_id}"
            strategy = decision.get("strategy", "select_best")
            status = STATUS_HEALTHY if strategy == "select_best" else (
                STATUS_WARNING if strategy == "defer_human" else STATUS_ERROR
            )
            graph.add_node(GraphNode(
                id=merge_node_id,
                type=NT_MERGE_DECISION,
                label=f"Merge: {strategy}",
                source_artifact="merge_decision",
                digest=decision.get("rationale_digest", ""),
                status=status,
                metadata={
                    "confidence": decision.get("confidence", 0),
                    "risk_level": decision.get("risk_level", ""),
                    "human_review_required": decision.get("human_review_required", False),
                },
            ))
            graph.add_edge(GraphEdge(
                from_node=merge_node_id,
                to_node=receipt_node_id,
                relationship=ET_MERGED,
                source_artifact="merge_decision",
            ))

            # Selected/rejected/deferred edges
            selected = decision.get("selected_branch_id")
            if selected:
                result_node_id = f"branch_result:{selected}"
                graph.add_edge(GraphEdge(
                    from_node=merge_node_id,
                    to_node=result_node_id,
                    relationship=ET_SELECTED,
                    source_artifact="merge_decision",
                ))

            for rej_id in decision.get("rejected_branch_ids", []):
                result_node_id = f"branch_result:{rej_id}"
                graph.add_edge(GraphEdge(
                    from_node=merge_node_id,
                    to_node=result_node_id,
                    relationship=ET_REJECTED,
                    source_artifact="merge_decision",
                ))

            for def_id in decision.get("deferred_branch_ids", []):
                result_node_id = f"branch_result:{def_id}"
                graph.add_edge(GraphEdge(
                    from_node=merge_node_id,
                    to_node=result_node_id,
                    relationship=ET_DEFERRED,
                    source_artifact="merge_decision",
                    reason="human_review",
                ))

            # Human review gate
            if decision.get("human_review_required"):
                review_node_id = f"review:{receipt_id}"
                graph.add_node(GraphNode(
                    id=review_node_id,
                    type=NT_HUMAN_REVIEW,
                    label="Human Review Gate",
                    source_artifact="merge_decision",
                    status=STATUS_WARNING,
                    metadata={"status": decision.get("human_review_status", "pending")},
                ))
                graph.add_edge(GraphEdge(
                    from_node=merge_node_id,
                    to_node=review_node_id,
                    relationship=ET_REVIEW_GATE,
                    source_artifact="merge_decision",
                ))

        graph.warnings = warnings
        return graph

    def build_from_health_sections(
        self,
        sections: dict[str, Any],
    ) -> TrustGraphView:
        """Build health overlay graph from dashboard sections.

        Maps HR-001 through HR-044 onto health rule nodes.
        """
        graph = TrustGraphView(source_artifacts=["dashboard_health"])

        # Health rule nodes from issues
        issues = sections.get("issues", [])
        if not issues and "rule_summary" in sections:
            # Alternative format: rule_summary with details
            for rule_id, details in sections.get("rule_summary", {}).items():
                if isinstance(details, dict) and details.get("triggered"):
                    issues.append({
                        "rule_id": rule_id,
                        "name": details.get("name", rule_id),
                        "severity": details.get("severity", ""),
                        "description": details.get("description", ""),
                    })

        for issue in issues:
            rule_id = issue.get("rule_id", "")
            if not rule_id:
                continue
            node_id = f"health:{rule_id}"
            severity = issue.get("severity", "warning")
            status_map = {
                "healthy": STATUS_HEALTHY,
                "warning": STATUS_WARNING,
                "degraded": STATUS_WARNING,
                "critical": STATUS_ERROR,
                "unhealthy": STATUS_ERROR,
                "unknown": STATUS_NEUTRAL,
            }
            status = status_map.get(severity, STATUS_WARNING)
            graph.add_node(GraphNode(
                id=node_id,
                type=NT_HEALTH_RULE,
                label=f"{rule_id}: {issue.get('name', '')}",
                source_artifact="dashboard_health",
                status=status,
                metadata={
                    "severity": severity,
                    "description": issue.get("description", ""),
                    "recommendation": issue.get("recommendation", ""),
                },
            ))

        return graph

    def build_from_trace_events(
        self,
        events: list[dict[str, Any]],
    ) -> TrustGraphView:
        """Build trace event graph from a list of trace events."""
        graph = TrustGraphView(source_artifacts=["trace_events"])

        for evt in events:
            evt_id = evt.get("event_id", f"evt-{evt.get('step_id', 0)}")
            node_id = f"trace:{evt_id}"
            event_type = evt.get("event_type", "")
            status = STATUS_INFO
            if "failed" in event_type.lower():
                status = STATUS_ERROR
            elif "completed" in event_type.lower() or "succeeded" in event_type.lower():
                status = STATUS_HEALTHY

            node_id_safe = evt.get("node_id", "runtime")
            graph.add_node(GraphNode(
                id=node_id,
                type=NT_TRACE_EVENT,
                label=f"{node_id_safe}: {event_type}",
                source_artifact="trace_event",
                status=status,
                metadata={
                    "run_id": evt.get("run_id", ""),
                    "step_id": evt.get("step_id", 0),
                    "event_type": event_type,
                },
            ))

            # Link sequential events
            step = evt.get("step_id", 0)
            if step > 0:
                prev_id = None
                for n in graph.nodes:
                    if n.metadata.get("step_id") == step - 1:
                        prev_id = n.id
                        break
                if prev_id:
                    graph.add_edge(GraphEdge(
                        from_node=prev_id,
                        to_node=node_id,
                        relationship="next",
                        source_artifact="trace_event",
                    ))

        return graph

    def merge_graphs(self, graphs: list[TrustGraphView]) -> TrustGraphView:
        """Merge multiple graph views into one."""
        merged = TrustGraphView(
            source_artifacts=[],
        )
        for g in graphs:
            for n in g.nodes:
                merged.add_node(n)
            for e in g.edges:
                merged.add_edge(e)
            merged.warnings.extend(g.warnings)
            merged.source_artifacts.extend(g.source_artifacts)

        return merged


# ── Determinism Helpers ─────────────────────────────────────────────────────

def export_graph_json(graph: TrustGraphView, path: str) -> None:
    """Write graph JSON to disk."""
    with open(path, "w") as f:
        f.write(graph.to_json())


def export_graph_mermaid(graph: TrustGraphView, path: str) -> None:
    """Write graph as Mermaid diagram to disk."""
    with open(path, "w") as f:
        f.write(graph.to_mermaid())


def verify_graph_determinism(
    graph1: TrustGraphView,
    graph2: TrustGraphView,
) -> bool:
    """VG-001 determinism: same artifacts must produce same graph digest."""
    return graph1.compute_digest() == graph2.compute_digest()
