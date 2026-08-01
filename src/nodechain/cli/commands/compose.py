"""v2.86 — Click declarations for the compose command group.

Relocated from cli/main.py (was inline at L3792-3884). The implementation
logic stays in nodechain.runtime.chain_orchestrator and
nodechain.registry.local_registry; this module holds only the Click
declaration shell + lazy delegation. Behavior is identical to the
pre-relocation code.
"""
from __future__ import annotations

import json

import click
from rich.console import Console

console = Console()


@click.group(invoke_without_command=True)
@click.option("--plan", "plan_path", default="", help="Path to composition plan YAML")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.pass_context
def compose(ctx, plan_path: str, as_json: bool) -> None:
    """Multi-chain orchestration — compose and execute chain-of-chains.

    A composition plan defines multiple sub-chains with dependencies.
    The orchestrator executes them in topological order and aggregates results.

    Read-only plan validation by default. Executes with --plan.
    """
    if ctx.invoked_subcommand is None:
        if not plan_path:
            console.print("[yellow]Use --plan to specify a composition plan YAML.[/]")
            console.print("  nodechain compose --plan blueprints/composition_cross_domain_v1.yaml")
            return
        from nodechain.runtime.chain_orchestrator import CompositionPlan, orchestrate_composition
        from nodechain.registry.local_registry import RegistryIndex
        import asyncio as _aio

        plan = CompositionPlan.from_yaml(plan_path)

        # Build node registry
        registry = RegistryIndex()
        registry.scan()
        node_registry = {}
        from nodechain.nodes.base_node import BaseNode
        for pkg_info in registry.list_packages():
            pkg = registry.get_package(pkg_info["node_id"])
            if pkg:
                try:
                    cls = pkg.load()
                    if isinstance(cls, list):
                        for c in cls:
                            inst = c()
                            node_registry[inst.manifest().node_id] = inst
                    else:
                        inst = cls()
                        node_registry[inst.manifest().node_id] = inst
                except Exception:
                    pass

        result = _aio.run(orchestrate_composition(plan, node_registry))

        if as_json:

            click.echo(json.dumps(result, indent=2, sort_keys=True))
        else:
            console.print(f"[bold]Composition: {plan.description}[/]")
            console.print(f"  Plan ID:     {plan.plan_id}")
            console.print(f"  Plan digest: {plan.compute_digest()[:16]}...")
            console.print(f"  Status:      {result['status']}")
            console.print(f"  Chains:      {len(result['sub_chain_results'])}")
            console.print(f"  Duration:    {result['duration_ms']:.1f}ms")
            console.print()
            for sr in result["sub_chain_results"]:
                status_color = "green" if sr["status"] == "completed" else "red" if sr["status"] == "failed" else "yellow"
                console.print(f"  [{status_color}]{sr['status']:12s}[/] {sr['chain_id']}")


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
