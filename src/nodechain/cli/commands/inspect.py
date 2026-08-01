"""v2.86 — Click declaration for the inspect command.

Relocated from cli/main.py (was inline at L236-252). The implementation
logic stays in cli/inspect.py; this module holds only the Click
declaration shell + lazy delegation. Behavior is identical to the
pre-relocation code.

This is a STANDALONE command (not a group), so register(cli) wires the
command directly into the root CLI.
"""
from __future__ import annotations

import click


@click.command()
@click.pass_context
@click.argument("run_id", required=True)
@click.option(
    "--db", "db_path",
    default="data/chain_state.db",
    help="Path to chain state database",
)
def inspect(ctx, run_id: str, db_path: str) -> None:
    """Show detailed state for a saved chain run.

    Displays execution order, completed steps, side effects, and outputs.
    """
    from nodechain.cli.inspect import inspect_run
    code = inspect_run(run_id, db_path)
    if code != 0:
        ctx.exit(code)


def register(cli: click.Group) -> None:
    """Wire the inspect command into the root CLI."""
    cli.add_command(inspect)
