"""Trace Viewer — formatted CLI output for chain traces."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from nodechain.cli.exit_codes import EXIT_NOT_FOUND

console = Console()


def view_trace(trace_file: str) -> None:
    """Load and display a chain trace in readable format."""
    path = Path(trace_file)
    if not path.exists():
        console.print(f"[red]Trace file not found: {trace_file}[/red]")
        sys.exit(EXIT_NOT_FOUND)

    with open(path) as f:
        trace = json.load(f)

    # Header
    console.print(Panel(
        f"[bold]Run ID:[/bold] {trace.get('run_id', 'unknown')}\n"
        f"[bold]Chain:[/bold] {trace.get('chain_name', 'unknown')}\n"
        f"[bold]Status:[/bold] {trace.get('final_status', 'unknown')}\n"
        f"[bold]Duration:[/bold] {trace.get('total_duration_ms', 0)}ms\n"
        f"[bold]Cost:[/bold] ${trace.get('total_cost_usd', 0):.4f}",
        title="[bold blue]Chain Trace[/bold blue]",
    ))

    # Events table
    events = trace.get("events", [])
    if not events:
        console.print("[yellow]No events in trace[/yellow]")
        return

    table = Table(title="Trace Events", show_lines=True)
    table.add_column("Step", style="cyan", width=5)
    table.add_column("Event", style="white", width=25)
    table.add_column("Node", style="green", width=25)
    table.add_column("Actor", style="yellow", width=10)
    table.add_column("Cost", style="magenta", width=8)
    table.add_column("Latency", style="blue", width=8)
    table.add_column("Decision", style="white", width=30)

    for event in events:
        table.add_row(
            str(event.get("step_id", "")),
            event.get("event_type", "").replace("_", " ").title(),
            event.get("node_id", ""),
            event.get("actor", ""),
            f"${event.get('cost_usd', 0):.4f}" if event.get("cost_usd") else "",
            f"{event.get('latency_ms', 0)}ms" if event.get("latency_ms") else "",
            (event.get("decision", "") or "")[:30],
        )

    console.print(table)

    # Summary
    summary = trace.get("summary", {})
    if summary:
        console.print(f"\n[bold]Summary:[/bold]")
        console.print(f"  Nodes executed: {summary.get('nodes_executed', 0)}")
        console.print(f"  Loops entered: {summary.get('loops_entered', 0)}")
        console.print(f"  Human reviews: {summary.get('human_reviews', 0)}")
        console.print(f"  Memory writes: {summary.get('memory_writes_committed', 0)}/{summary.get('memory_writes_attempted', 0)}")
        console.print(f"  Trace complete: {'[ok]' if summary.get('trace_complete') else 'X'}")

    # Truth rule verification
    if not summary.get("trace_complete", True):
        console.print("\n[bold red]! Trace Truth Rule violation detected![/bold red]")
