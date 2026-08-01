"""v2.86 — Click declaration for the report command.

Relocated from cli/main.py (was inline at L1119-1143). The implementation
logic stays in cli/report.py; this module holds only the Click
declaration shell + lazy delegation. Behavior is identical to the
pre-relocation code.

This is a STANDALONE command (not a group), so register(cli) wires the
command directly into the root CLI.
"""
from __future__ import annotations

import click


@click.command()
@click.argument("run_id", required=True)
@click.option(
    "--db", "db_path",
    default="data/chain_state.db",
    help="Path to chain state database",
)
@click.option(
    "--trace-dir", "-t",
    default="data/traces",
    help="Directory for trace files",
)
@click.option(
    "--output", "-o",
    default=None,
    help="Save report as JSON to this file",
)
def report(run_id: str, db_path: str, trace_dir: str, output: str | None) -> None:
    """Generate a comprehensive report for a chain run.

    Combines execution flow, side effects, reconciliation results,
    and node outputs into a single readable summary.
    """
    from nodechain.cli.report import report_run
    report_run(run_id, db_path, trace_dir, output)


def register(cli: click.Group) -> None:
    """Wire the report command into the root CLI."""
    cli.add_command(report)
