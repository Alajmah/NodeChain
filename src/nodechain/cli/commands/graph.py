"""v2.80 — Click declarations for the graph command group.

Relocated from cli/main.py (was inline at L4801-4990). The implementation
logic stays in cli/sdk/visual_graph.py; this module holds only the Click
declaration shell + lazy delegation. Behavior is identical to the
pre-relocation code.
"""
from __future__ import annotations

import json
from pathlib import Path

import click

@click.group(name="graph")
def graph_group() -> None:
    """Visual trust graph and governance graph explorer."""
    pass


@graph_group.command(name="export")
@click.option("--lockfile", "-l", type=click.Path(exists=True), default=None,
              help="Path to trust lockfile JSON")
@click.option("--capability-receipt", "-c", type=click.Path(exists=True), default=None,
              help="Path to capability selection receipt JSON")
@click.option("--deliberation-receipt", "-d", type=click.Path(exists=True), default=None,
              help="Path to deliberation receipt JSON")
@click.option("--branch-plans", type=click.Path(exists=True), default=None,
              help="Path to branch plans JSON (list of plan dicts)")
@click.option("--branch-results", type=click.Path(exists=True), default=None,
              help="Path to branch results JSON (list of result dicts)")
@click.option("--merge-decision", type=click.Path(exists=True), default=None,
              help="Path to merge decision JSON")
@click.option("--health-sections", type=click.Path(exists=True), default=None,
              help="Path to dashboard health sections JSON")
@click.option("--trace-events", type=click.Path(exists=True), default=None,
              help="Path to trace events JSON (list of event dicts)")
@click.option("--format", "-f", type=click.Choice(["json", "mermaid"]), default="json",
              help="Output format")
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Output file path (default: stdout)")
@click.pass_context
def graph_export(
    ctx: click.Context,
    lockfile: str | None,
    capability_receipt: str | None,
    deliberation_receipt: str | None,
    branch_plans: str | None,
    branch_results: str | None,
    merge_decision: str | None,
    health_sections: str | None,
    trace_events: str | None,
    format: str,
    output: str | None,
) -> None:
    """Export a visual governance graph from runtime artifacts.

    VG-001: Every node and edge is backed by a materialized artifact.
    The graph explorer does not invent inferred trust relationships.

    Artifact sources (at least one required):
      --lockfile             Trust lockfile (package trust + dependency graph)
      --capability-receipt   Capability selection receipt
      --deliberation-receipt Deliberation receipt (adaptive branching)
      --branch-plans         Branch plans for deliberation graph
      --branch-results       Branch results for deliberation graph
      --merge-decision       Merge decision for deliberation graph
      --health-sections      Dashboard health sections (HR-001–HR-044)
      --trace-events         Trace events (ordered execution graph)
    """
    from nodechain.sdk.visual_graph import GraphExporter

    all_artifacts = [lockfile, capability_receipt, deliberation_receipt,
                     branch_plans, branch_results, merge_decision,
                     health_sections, trace_events]
    if not any(all_artifacts):
        click.echo("Error: at least one artifact source is required\n"
                       "  --lockfile, --capability-receipt, --deliberation-receipt,\n"
                       "  --branch-plans, --branch-results, --merge-decision,\n"
                       "  --health-sections, --trace-events", err=True)
        ctx.exit(10)

    exporter = GraphExporter()
    graphs = []

    if lockfile:
        data = json.loads(Path(lockfile).read_text())
        graphs.append(exporter.build_from_lockfile(data))

    if capability_receipt:
        data = json.loads(Path(capability_receipt).read_text())
        graphs.append(exporter.build_from_capability_receipt(data))

    if deliberation_receipt:
        data = json.loads(Path(deliberation_receipt).read_text())
        plans_data = json.loads(Path(branch_plans).read_text()) if branch_plans else None
        results_data = json.loads(Path(branch_results).read_text()) if branch_results else None
        decision_data = json.loads(Path(merge_decision).read_text()) if merge_decision else None
        graphs.append(exporter.build_from_deliberation_receipt(
            data, plans_data, results_data, decision_data,
        ))

    if health_sections:
        data = json.loads(Path(health_sections).read_text())
        graphs.append(exporter.build_from_health_sections(data))

    if trace_events:
        data = json.loads(Path(trace_events).read_text())
        graphs.append(exporter.build_from_trace_events(data))

    if len(graphs) == 1:
        graph = graphs[0]
    else:
        graph = exporter.merge_graphs(graphs)

    if format == "json":
        content = graph.to_json()
    else:
        content = graph.to_mermaid()

    if output:
        Path(output).write_text(content)
        click.echo(f"Graph exported to {output} ({len(graph.nodes)} nodes, {len(graph.edges)} edges)")
    else:
        click.echo(content)


@graph_group.command(name="verify")
@click.option("--lockfile", "-l", type=click.Path(exists=True), default=None,
              help="Path to trust lockfile JSON")
@click.option("--capability-receipt", "-c", type=click.Path(exists=True), default=None,
              help="Path to capability selection receipt JSON")
@click.option("--deliberation-receipt", "-d", type=click.Path(exists=True), default=None,
              help="Path to deliberation receipt JSON")
@click.option("--branch-plans", type=click.Path(exists=True), default=None,
              help="Path to branch plans JSON (list of plan dicts)")
@click.option("--branch-results", type=click.Path(exists=True), default=None,
              help="Path to branch results JSON (list of result dicts)")
@click.option("--merge-decision", type=click.Path(exists=True), default=None,
              help="Path to merge decision JSON")
@click.option("--health-sections", type=click.Path(exists=True), default=None,
              help="Path to dashboard health sections JSON")
@click.option("--trace-events", type=click.Path(exists=True), default=None,
              help="Path to trace events JSON")
@click.pass_context
def graph_verify(
    ctx: click.Context,
    lockfile: str | None,
    capability_receipt: str | None,
    deliberation_receipt: str | None,
    branch_plans: str | None,
    branch_results: str | None,
    merge_decision: str | None,
    health_sections: str | None,
    trace_events: str | None,
) -> None:
    """Verify graph determinism (VG-001).

    Rebuilds the graph twice from the same artifacts and checks
    that the graph digest is identical.
    """
    from nodechain.sdk.visual_graph import GraphExporter, verify_graph_determinism

    all_artifacts = [lockfile, capability_receipt, deliberation_receipt,
                     branch_plans, branch_results, merge_decision,
                     health_sections, trace_events]
    if not any(all_artifacts):
        click.echo("Error: at least one artifact source is required", err=True)
        ctx.exit(10)

    def _build():
        exporter = GraphExporter()
        graphs = []
        if lockfile:
            graphs.append(exporter.build_from_lockfile(json.loads(Path(lockfile).read_text())))
        if capability_receipt:
            graphs.append(exporter.build_from_capability_receipt(json.loads(Path(capability_receipt).read_text())))
        if deliberation_receipt:
            plans_data = json.loads(Path(branch_plans).read_text()) if branch_plans else None
            results_data = json.loads(Path(branch_results).read_text()) if branch_results else None
            decision_data = json.loads(Path(merge_decision).read_text()) if merge_decision else None
            graphs.append(exporter.build_from_deliberation_receipt(
                json.loads(Path(deliberation_receipt).read_text()),
                plans_data, results_data, decision_data,
            ))
        if health_sections:
            graphs.append(exporter.build_from_health_sections(json.loads(Path(health_sections).read_text())))
        if trace_events:
            graphs.append(exporter.build_from_trace_events(json.loads(Path(trace_events).read_text())))
        if len(graphs) == 1:
            return graphs[0]
        return exporter.merge_graphs(graphs)

    g1 = _build()
    g2 = _build()

    deterministic = verify_graph_determinism(g1, g2)
    digest = g1.compute_digest()

    if deterministic:
        click.echo(f"OK: Graph is deterministic. Digest: {digest[:16]}...")
    else:
        click.echo("FAIL: Graph is NOT deterministic.", err=True)
        ctx.exit(10)


def register(cli: click.Group) -> None:
    """Wire the graph group into the root CLI."""
    cli.add_command(graph_group)
