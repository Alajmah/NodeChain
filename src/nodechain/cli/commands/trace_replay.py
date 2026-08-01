"""v2.86 — Click declarations for the trace-replay command group.

Relocated from cli/main.py (was inline at L3788-3822). The implementation
logic stays in cli/trace_replay.py; this module holds only the Click
declaration shell + lazy delegation. Behavior is identical to the
pre-relocation code.
"""
from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console

console = Console()


@click.group(name="trace-replay")
def trace_replay_group() -> None:
    """Trace replay and verification (v1.17.0)."""


@trace_replay_group.command(name="run")
@click.option("--trace", "trace_path", required=True, help="Trace JSON file")
@click.option("--strict", is_flag=True, default=False, help="Strict mode")
@click.option("--output", "-o", default="", help="Output replay report JSON")
def trace_replay_run_cmd(trace_path: str, strict: bool, output: str) -> None:
    """Replay and verify a chain trace (v1.17.0)."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION
    from nodechain.cli.trace_replay import replay_trace

    report = replay_trace(trace_path, strict=strict)

    if output:
        Path(output).write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    if report["passed"]:
        console.print(f"[green]\u2705 Trace replay passed[/green]")
        console.print(f"  Events:  {report['event_count']}")
        console.print(f"  Checks:  {len(report['checks'])}")
        for check in report["checks"]:
            status = "\u2705" if check["passed"] else "\u274c"
            console.print(f"    {status} {check['check']}: {check['detail']}")
    else:
        console.print(f"[red]\u274c Trace replay failed[/red]")
        for err in report.get("errors", []):
            console.print(f"  {err}")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


def register(cli: click.Group) -> None:
    """Wire the trace-replay group into the root CLI."""
    cli.add_command(trace_replay_group)
