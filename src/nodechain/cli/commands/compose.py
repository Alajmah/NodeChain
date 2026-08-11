"""Click declarations for the compose command group.

H0.3: the ``--plan`` execution path has been retired because it loaded
registry packages directly and called ``orchestrate_composition()``, which
executed ``await node.execute(envelope)`` outside the canonical
``Orchestrator`` — bypassing every governed authority. The command now fails
closed with a stable reason code before any package loading or node
execution. Plan validation (``compose validate``) remains read-only.
"""
from __future__ import annotations

import json

import click
from rich.console import Console

from nodechain.cli.exit_codes import EXIT_VALIDATION
from nodechain.runtime.chain_orchestrator import (
    GOVERNED_COMPOSITION_BACKEND_REQUIRED,
)

console = Console()


@click.group(invoke_without_command=True)
@click.option("--plan", "plan_path", default="", help="Path to composition plan YAML")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.pass_context
def compose(ctx, plan_path: str, as_json: bool) -> None:
    """Composition plan tooling — validation only (H0.3).

    Composition plan validation is supported via ``compose validate``.
    Direct execution (``compose --plan ...``) has been retired: the legacy
    executor ran Harness Nodes outside the canonical Orchestrator and
    bypassed every governed authority. Execution now fails closed with a
    stable reason code before any package loading or node execution.

    To validate a plan, use:

      nodechain compose validate --plan blueprints/composition_cross_domain_v1.yaml
    """
    if ctx.invoked_subcommand is None:
        if not plan_path:
            console.print("[yellow]Use --plan with a composition plan YAML.[/]")
            console.print("  nodechain compose validate --plan blueprints/composition_cross_domain_v1.yaml")
            console.print(
                "[dim]Note: direct execution via `compose --plan` was retired in H0.3 "
                "(governed composition backend required).[/]"
            )
            return
        # H0.3: fail closed before any package loading or node execution. The
        # legacy --plan path loaded registry packages and called
        # orchestrate_composition(), which executed nodes outside the
        # canonical Orchestrator. We refuse here, before RegistryIndex.scan()
        # or pkg.load(), so no admission/loading occurs.
        if as_json:
            click.echo(json.dumps({
                "error": GOVERNED_COMPOSITION_BACKEND_REQUIRED,
                "message": (
                    "composition execution is not available; direct execution "
                    "via `compose --plan` was retired in H0.3. Plan validation "
                    "remains available via `compose validate --plan ...`."
                ),
            }, indent=2, sort_keys=True))
        else:
            console.print(
                f"[red]Error:[/red] composition execution is not available "
                f"({GOVERNED_COMPOSITION_BACKEND_REQUIRED})."
            )
            console.print(
                "[dim]Direct execution via `compose --plan` was retired in H0.3. "
                "Plan validation remains available via `compose validate --plan ...`.[/]"
            )
        ctx.exit(EXIT_VALIDATION)


@compose.command()
@click.option("--plan", "plan_path", required=True, help="Composition plan YAML")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def validate(plan_path: str, as_json: bool) -> None:
    """Validate a composition plan without executing."""
    from nodechain.runtime.chain_orchestrator import CompositionPlan
    from nodechain.cli.exit_codes import EXIT_VALIDATION

    try:
        plan = CompositionPlan.from_yaml(plan_path)
        order = plan.topological_order()
        digest = plan.compute_digest()
    except ValueError as e:
        console.print(f"[red]Invalid plan: {e}[/]")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)
        return

    if as_json:

        click.echo(json.dumps({
            "valid": True,
            "plan_id": plan.plan_id,
            "digest": digest,
            "execution_order": order,
            "sub_chain_count": len(plan.sub_chains),
        }, indent=2))
    else:
        console.print(f"[green]Valid composition plan[/]")
        console.print(f"  Plan ID:     {plan.plan_id}")
        console.print(f"  Digest:      {digest[:16]}...")
        console.print(f"  Sub-chains:  {len(plan.sub_chains)}")
        console.print(f"  Exec order:  {' -> '.join(order)}")


def register(cli: click.Group) -> None:
    """Wire the compose group into the root CLI."""
    cli.add_command(compose)
