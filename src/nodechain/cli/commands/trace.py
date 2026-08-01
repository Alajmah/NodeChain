"""v2.86 — Click declaration for the trace command.

Relocated from cli/main.py (was inline at L1279-1302). The implementation
logic stays in cli/trace_viewer.py; this module holds only the Click
declaration shell + lazy delegation. Behavior is identical to the
pre-relocation code.

This is a STANDALONE command (not a group), so register(cli) wires the
command directly into the root CLI.
"""
from __future__ import annotations

import click
from rich.console import Console

console = Console()


@click.command()
@click.argument("trace_file", required=True)
@click.option("--trace-dir", default="data/traces", help="Directory to search for trace files")
def trace(trace_file: str, trace_dir: str) -> None:
    """View a chain trace in readable format.

    Accepts either a file path or a run ID. If a run ID is given,
    searches in --trace-dir (default: data/traces/) for {run_id}.json.
    """
    from pathlib import Path
    from nodechain.cli.trace_viewer import view_trace
    from nodechain.cli.exit_codes import EXIT_NOT_FOUND

    path = Path(trace_file)
    if not path.exists():
        # Try resolving as a run ID in trace_dir
        resolved = Path(trace_dir) / f"{trace_file}.json"
        if resolved.exists():
            trace_file = str(resolved)
        else:
            console.print(f"[red]Trace file not found: {trace_file}[/red]")
            console.print(f"[dim]Also tried: {resolved}[/dim]")
            ctx = click.get_current_context()
            ctx.exit(EXIT_NOT_FOUND)
    view_trace(trace_file)


def register(cli: click.Group) -> None:
    """Wire the trace command into the root CLI."""
    cli.add_command(trace)
