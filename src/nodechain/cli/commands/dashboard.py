"""v2.79 — Click declarations for the dashboard command group.

Relocated from cli/main.py (was inline at L4749-4998 in the pre-relocation
file). The implementation logic stays in cli/dashboard.py and
cli/dashboard_health.py; this module holds only the Click declaration shell
+ lazy delegation. Behavior is identical to the pre-relocation code.

dashboard is a group with invoke_without_command=True, so `nodechain
dashboard` (no subcommand) renders the unified view, while `nodechain
dashboard <section>` renders a single section.
"""
from __future__ import annotations

import json
import time

import click
from rich.console import Console

console = Console()


@click.group(invoke_without_command=True)
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.option("--watch", is_flag=True, help="Auto-refresh every 5 seconds")
@click.pass_context
def dashboard(ctx, as_json: bool, watch: bool) -> None:
    """Operator dashboard — unified read-only operational view.

    Aggregates status across all six platform spines:
    runtime, trust, registry, evidence, operations, and evaluation.

    Read-only by default. Never mutates state.
    """
    if ctx.invoked_subcommand is None:
        from nodechain.cli.dashboard import collect_dashboard, render_dashboard

        def _show() -> None:
            data = collect_dashboard()
            if as_json:

                click.echo(json.dumps(data, indent=2, sort_keys=True))
            else:
                console.print(render_dashboard(data))

        if watch:
            try:
                while True:
                    console.clear()
                    _show()
                    time.sleep(5)
            except KeyboardInterrupt:
                pass
        else:
            _show()


@dashboard.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def runs(as_json: bool) -> None:
    """Show runtime run status."""
    from nodechain.cli.dashboard import collect_dashboard, render_dashboard
    from rich.console import Console
    console = Console()
    data = collect_dashboard()
    if as_json:

        click.echo(json.dumps(data["sections"]["runtime"], indent=2, sort_keys=True))
    else:
        console.print(render_dashboard(data, section="runtime"))


@dashboard.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def trust(as_json: bool) -> None:
    """Show trust store status."""
    from nodechain.cli.dashboard import collect_dashboard, render_dashboard
    from rich.console import Console
    console = Console()
    data = collect_dashboard()
    if as_json:

        click.echo(json.dumps(data["sections"]["trust"], indent=2, sort_keys=True))
    else:
        console.print(render_dashboard(data, section="trust"))


@dashboard.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def registry(as_json: bool) -> None:
    """Show certified registry status."""
    from nodechain.cli.dashboard import collect_dashboard, render_dashboard
    from rich.console import Console
    console = Console()
    data = collect_dashboard()
    if as_json:

        click.echo(json.dumps(data["sections"]["registry"], indent=2, sort_keys=True))
    else:
        console.print(render_dashboard(data, section="registry"))


@dashboard.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def evidence(as_json: bool) -> None:
    """Show evidence index status."""
    from nodechain.cli.dashboard import collect_dashboard, render_dashboard
    from rich.console import Console
    console = Console()
    data = collect_dashboard()
    if as_json:

        click.echo(json.dumps(data["sections"]["evidence"], indent=2, sort_keys=True))
    else:
        console.print(render_dashboard(data, section="evidence"))


@dashboard.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def deployments(as_json: bool) -> None:
    """Show deployment and release status."""
    from nodechain.cli.dashboard import collect_dashboard, render_dashboard
    from rich.console import Console
    console = Console()
    data = collect_dashboard()
    if as_json:

        click.echo(json.dumps(data["sections"]["operations"], indent=2, sort_keys=True))
    else:
        console.print(render_dashboard(data, section="deployments"))


@dashboard.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def drift(as_json: bool) -> None:
    """Show drift detection status."""
    from nodechain.cli.dashboard import collect_dashboard, render_dashboard
    from rich.console import Console
    console = Console()
    data = collect_dashboard()
    if as_json:

        click.echo(json.dumps(data["sections"]["operations"], indent=2, sort_keys=True))
    else:
        console.print(render_dashboard(data, section="drift"))


@dashboard.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def evaluations(as_json: bool) -> None:
    """Show evaluation and certification status."""
    from nodechain.cli.dashboard import collect_dashboard, render_dashboard
    from rich.console import Console
    console = Console()
    data = collect_dashboard()
    if as_json:

        click.echo(json.dumps(data["sections"]["evaluation"], indent=2, sort_keys=True))
    else:
        console.print(render_dashboard(data, section="evaluations"))


# ── v2.67.3: Reuse + Scorecards dashboard subcommands ─────────────────────

@dashboard.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def reuse(as_json: bool) -> None:
    """Show registry-resolved reuse proof status (v2.67.3).

    Displays shared node provenance, lockfile status, and content_digest
    verification for the registry-resolved deterministic nodes.
    """
    from nodechain.cli.dashboard import collect_dashboard, render_dashboard
    from rich.console import Console
    console = Console()
    data = collect_dashboard()
    if as_json:
        click.echo(json.dumps(data["sections"]["reuse"], indent=2, sort_keys=True))
    else:
        console.print(render_dashboard(data, section="reuse"))


@dashboard.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.option("--refresh", is_flag=True, help="Run scorecards and update cache before rendering")
def scorecards(as_json: bool, refresh: bool) -> None:
    """Show cached node quality scorecards (v2.67.3).

    By default, reads the cached scorecard report. Use --refresh to run
    the deterministic node scorecard evaluation and update the cache.

    \b
    Examples:
      nodechain dashboard scorecards
      nodechain dashboard scorecards --refresh
    """
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION
    from rich.console import Console
    console = Console()
    refresh_error: str | None = None

    if refresh:
        from nodechain.runtime.node_quality_scorecard import (
            run_registry_node_scorecard, write_scorecard_cache,
            get_shared_registry_node_ids, load_scorecard_cache,
        )
        old_cache = load_scorecard_cache()

        try:
            node_ids = get_shared_registry_node_ids()
            console.print(f"[bold blue]Refreshing scorecards for {len(node_ids)} node(s)...[/]")
            reports = []
            for nid in node_ids:
                console.print(f"  Evaluating: {nid}")
                report = run_registry_node_scorecard(nid)
                reports.append(report)
            write_scorecard_cache(reports)
            console.print(f"[green]Scorecard cache updated.[/]")
        except Exception as exc:
            refresh_error = str(exc)
            console.print(f"[red]Refresh failed: {refresh_error}[/]")
            if old_cache:
                console.print(f"[yellow]Showing previous (stale) cache.[/]")

    from nodechain.cli.dashboard import collect_dashboard, render_dashboard
    data = collect_dashboard()
    if refresh_error:
        data["sections"]["scorecards"]["refresh_error"] = refresh_error
    if as_json:
        click.echo(json.dumps(data["sections"]["scorecards"], indent=2, sort_keys=True))
    else:
        console.print(render_dashboard(data, section="scorecards"))


@dashboard.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def health(as_json: bool) -> None:
    """Show overall health status and issues."""
    from nodechain.cli.dashboard_health import collect_dashboard_v2
    from nodechain.cli.dashboard import render_dashboard
    from rich.console import Console
    console = Console()
    data = collect_dashboard_v2()
    if as_json:

        health_data = {
            "api_version": data["api_version"],
            "overall_health": data["overall_health"],
            "issues": data["issues"],
            "issue_count": data["issue_count"],
            "rule_summary": data["rule_summary"],
            "timestamp": data["timestamp"],
        }
        click.echo(json.dumps(health_data, indent=2, sort_keys=True))
    else:
        console.print(render_dashboard(data, section="health"))


@dashboard.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def rules(as_json: bool) -> None:
    """Show health rule evaluation details."""
    from nodechain.cli.dashboard_health import collect_dashboard_v2, render_health_rules
    from rich.console import Console
    console = Console()
    data = collect_dashboard_v2()
    if as_json:

        click.echo(json.dumps(data["rule_summary"], indent=2, sort_keys=True))
    else:
        console.print(render_health_rules(data))


def register(cli: click.Group) -> None:
    """Wire the dashboard group into the root CLI."""
    cli.add_command(dashboard)
