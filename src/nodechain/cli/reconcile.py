"""Reconcile command — run TraceReconciler on a saved run."""

from __future__ import annotations

import json
import sys

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from nodechain.core.state import StateManager
from nodechain.core.trace import ChainTrace, TraceEvent
from nodechain.runtime.trace_reconciler import TraceReconciler

console = Console()


from nodechain.cli.exit_codes import (
    EXIT_OK, EXIT_NOT_FOUND, EXIT_RECONCILE_ERRORS, EXIT_RECONCILE_RECOVERY,
)


def reconcile_run(run_id: str, db_path: str = "data/chain_state.db", trace_dir: str = "data/traces") -> int:
    """Reconcile a chain run: cross-check trace against persistent state.

    Returns exit code:
        0 = clean (no errors)
        1 = hard reconciliation errors
        2 = run not found
        3 = recovery required (unknown side effects)
    """
    sm = StateManager(db_path=db_path)

    # Load saved state
    state = sm.load(run_id)
    if state is None:
        console.print(f"[red]No saved state found for run: {run_id}[/red]")
        return EXIT_NOT_FOUND

    # Load trace file
    trace_path = _find_trace(run_id, trace_dir)
    if trace_path is None:
        console.print(f"[red]No trace file found for run: {run_id}[/red]")
        console.print(f"[dim]Searched: {trace_dir}/{run_id}*.json[/dim]")
        return EXIT_NOT_FOUND

    with open(trace_path) as f:
        trace_data = json.load(f)

    trace = ChainTrace.from_dict(trace_data) if hasattr(ChainTrace, "from_dict") else _build_trace(trace_data)

    # Run reconciler
    reconciler = TraceReconciler(state_manager=sm)
    report = reconciler.reconcile(trace)

    # Classify issues
    errors = [i for i in report.issues if i.severity == "error"]
    warnings = [i for i in report.issues if i.severity == "warning"]
    recovery_required = any(i.check == "side_effect_recovery_required" for i in warnings)

    # Determine status label
    if errors:
        status_label = "ERRORS FOUND"
        status_color = "red"
    elif warnings:
        status_label = "CLEAN WITH WARNINGS"
        status_color = "yellow"
    else:
        status_label = "CLEAN"
        status_color = "green"

    console.print(Panel(
        f"[bold]Run ID:[/bold]           {run_id}\n"
        f"[bold]Result:[/bold]           [{status_color}]{status_label}[/{status_color}]\n"
        f"[bold]Checks passed:[/bold]    {report.checks_passed}\n"
        f"[bold]Errors:[/bold]           {len(errors)}\n"
        f"[bold]Warnings:[/bold]         {len(warnings)}\n"
        f"[bold]Recovery required:[/bold] {recovery_required}",
        title="[bold blue]Reconciliation Report[/bold blue]",
    ))

    if report.issues:
        table = Table(title="Issues", show_lines=True)
        table.add_column("Check", style="cyan", width=30)
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Expected", style="green", width=35)
        table.add_column("Actual", style="red", width=35)

        for issue in report.issues:
            sev_color = "red" if issue.severity == "error" else "yellow"
            table.add_row(
                issue.check,
                f"[{sev_color}]{issue.severity}[/{sev_color}]",
                (issue.expected or "")[:35],
                (issue.actual or "")[:35],
            )

        console.print(table)

        if errors:
            console.print(f"\n[bold red]Errors ({len(errors)}):[/bold red]")
            for e in errors:
                console.print(f"  X {e.check}: {e.actual}")

        if warnings:
            console.print(f"\n[bold yellow]Warnings ({len(warnings)}):[/bold yellow]")
            for w in warnings:
                console.print(f"  ! {w.check}: {w.actual}")
    else:
        console.print("\n[green]All checks passed. Trace is clean.[/green]")

    # Exit code
    if errors:
        return EXIT_RECONCILE_ERRORS
    if recovery_required:
        return EXIT_RECONCILE_RECOVERY
    return EXIT_OK


def _find_trace(run_id: str, trace_dir: str) -> str | None:
    """Find the trace file for a run."""
    from pathlib import Path
    trace_path = Path(trace_dir) / f"{run_id}.json"
    if trace_path.exists():
        return str(trace_path)
    # Try partial match
    for p in Path(trace_dir).glob(f"{run_id[:8]}*.json"):
        return str(p)
    return None


def _build_trace(trace_data: dict) -> ChainTrace:
    """Build a ChainTrace from raw JSON dict."""
    events = []
    for e in trace_data.get("events", []):
        events.append(TraceEvent(
            run_id=e.get("run_id", ""),
            chain_id=e.get("chain_id", ""),
            node_id=e.get("node_id", ""),
            step_id=e.get("step_id", 0),
            event_type=e.get("event_type", ""),
            actor=e.get("actor", ""),
            decision=e.get("decision", ""),
            metadata=e.get("metadata"),
            cost_usd=e.get("cost_usd", 0),
            latency_ms=e.get("latency_ms", 0),
            timestamp=e.get("timestamp", ""),
        ))

    return ChainTrace(
        run_id=trace_data.get("run_id", ""),
        chain_id=trace_data.get("chain_id", ""),
        chain_name=trace_data.get("chain_name", ""),
        events=events,
        final_status=trace_data.get("final_status", "unknown"),
        total_cost_usd=trace_data.get("total_cost_usd", 0),
        total_duration_ms=trace_data.get("total_duration_ms", 0),
    )
