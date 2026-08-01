"""Inspect command — show saved chain state, outputs, and side effects."""

from __future__ import annotations

import os
import sys

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree

from nodechain.core.state import StateManager

console = Console()


from nodechain.cli.exit_codes import EXIT_OK, EXIT_NOT_FOUND


def inspect_run(run_id: str, db_path: str = "data/chain_state.db") -> int:
    """Show detailed state for a saved chain run.

    Returns exit code: 0 = ok, 2 = not found.
    """
    sm = StateManager(db_path=db_path)

    state = sm.load(run_id)
    if state is None:
        console.print(f"[red]No saved state found for run: {run_id}[/red]")
        return EXIT_NOT_FOUND

    # Header
    status_color = "green" if state.status == "completed" else "yellow" if state.status == "running" else "red"
    console.print(Panel(
        f"[bold]Run ID:[/bold]       {state.run_id}\n"
        f"[bold]Chain ID:[/bold]     {state.chain_id}\n"
        f"[bold]Status:[/bold]       [{status_color}]{state.status}[/{status_color}]\n"
        f"[bold]Step:[/bold]         {state.step}\n"
        f"[bold]Current Node:[/bold] {state.current_node or '(none)'}\n"
        f"[bold]Revision:[/bold]     {state.revision}",
        title="[bold blue]Chain State[/bold blue]",
    ))

    # Show review state if waiting
    review_req = state.metadata.get("review_request") if state.metadata else None
    # v2.22.0: only show "WAITING FOR REVIEW" when actually paused. A run that
    # completed/failed after a review gate should not display a stale waiting panel
    # just because the legacy review_request metadata persists in state.
    if state.status == "waiting_for_review":
        console.print(Panel(
            f"[bold yellow]WAITING FOR REVIEW[/bold yellow]\n"
            f"[bold]Risk Level:[/bold] {review_req.get('risk_assessment', {}).get('risk_level', 'unknown') if review_req else 'unknown'}\n"
            f"[bold]Step:[/bold] {review_req.get('step_id', '?') if review_req else '?'}\n"
            f"[bold]Node:[/bold] {review_req.get('node_id', '?') if review_req else '?'}",
            title="[bold yellow]Human Review[/bold yellow]",
        ))
    elif review_req and state.metadata.get("governed_decision_receipt"):
        # v2.22.0: show the resolved governed receipt for completed/failed runs.
        receipt = state.metadata["governed_decision_receipt"]
        console.print(Panel(
            f"[bold green]REVIEW RESOLVED[/bold green]\n"
            f"[bold]Decision:[/bold]      {receipt.get('decision', {}).get('outcome', '?')}\n"
            f"[bold]Receipt ID:[/bold]    {receipt.get('receipt_id', '?')}\n"
            f"[bold]Receipt Digest:[/bold] {receipt.get('digest_commitment', '?')[:16]}...\n"
            f"[bold]Subject Type:[/bold]  {receipt.get('subject_type', '?')}",
            title="[bold green]Human Review[/bold green]",
        ))

    # Completed steps (execution order)
    if state.completed_steps:
        tree = Tree("Execution Flow")
        for step_id, node_id in sorted(state.completed_steps.items()):
            marker = "[ok]"
            tree.add(f"[dim]Step {step_id}.[/dim] {marker} {node_id}")
        console.print(tree)

    # Side effects
    side_effects = sm.get_side_effects(run_id)
    if side_effects:
        se_table = Table(title="Side Effects", show_lines=True)
        se_table.add_column("Step", style="cyan", width=6)
        se_table.add_column("Node", style="green", width=20)
        se_table.add_column("Type", style="white", width=18)
        se_table.add_column("Key", style="yellow", width=25)
        se_table.add_column("Status", style="magenta", width=10)
        se_table.add_column("Retryable", style="blue", width=8)

        for se in side_effects:
            status = se["status"]
            color = "green" if status == "completed" else "red" if status == "failed" else "yellow" if status == "unknown" else "white"
            se_table.add_row(
                str(se["step_id"]),
                se["node_id"],
                se["side_effect_type"],
                se["idempotency_key"][:25],
                f"[{color}]{status}[/{color}]",
                "Yes" if se["retryable"] else "No",
            )
        console.print(se_table)
    else:
        console.print("\n[dim]No side effects recorded[/dim]")

    # v1.3.8: Show policy preset and enforcement info
    preset = os.environ.get("NODECHAIN_POLICY_PRESET", "")
    if preset:
        preset_source = os.environ.get("NODECHAIN_POLICY_PRESET_SOURCE", "")
        sandbox_profile = os.environ.get("NODECHAIN_SANDBOX_PROFILE", "")
        preset_lines = [
            f"[bold]Policy Preset:[/bold]    {preset}",
            f"[bold]Preset Source:[/bold]   {preset_source}",
            f"[bold]Sandbox Profile:[/bold] {sandbox_profile}",
        ]
        from nodechain.sdk.policy_presets import get_preset as _gp
        preset_obj = _gp(preset)
        if preset_obj:
            if preset_obj.seccomp_required:
                preset_lines.append("[bold]Seccomp:[/bold]          required (Linux)")
            if preset_obj.mount_confinement_required:
                preset_lines.append("[bold]Mount Confinement:[/bold] required (Linux chroot)")
            if getattr(preset_obj, 'pid_namespace_required', False):
                preset_lines.append("[bold]PID Namespace:[/bold]    required (Linux)")
            if getattr(preset_obj, 'procfs_isolation_required', False):
                preset_lines.append("[bold]Procfs Isolation:[/bold] required (Linux)")
        # v1.4.2: namespace detection in inspect
        try:
            from nodechain.sdk.namespace_profile import detect_namespaces
            ns_caps = detect_namespaces()
            if ns_caps.namespace_available or ns_caps.already_nested:
                preset_lines.append(f"[bold]Namespace Mode:[/bold]    {ns_caps.namespace_mode}")
                preset_lines.append(f"[bold]Already Nested:[/bold]   {ns_caps.already_nested}")
                ns_types = []
                if ns_caps.network_namespace_available:
                    ns_types.append("network")
                if ns_caps.mount_namespace_available:
                    ns_types.append("mount")
                if ns_caps.pid_namespace_available:
                    ns_types.append("pid")
                if ns_caps.user_namespace_available:
                    ns_types.append("user")
                if ns_types:
                    preset_lines.append(f"[bold]Available Types:[/bold]  {', '.join(ns_types)}")
                if getattr(ns_caps, 'mount_namespace_enforced', False):
                    preset_lines.append("[bold]Mount NS Enforced:[/bold] True")
                if getattr(ns_caps, 'mount_confinement_enforced', False):
                    preset_lines.append("[bold]Mount Confinement Enforced:[/bold] True")
        except Exception:
            pass
        console.print(Panel(
            "\n".join(preset_lines),
            title="[bold cyan]Policy Preset[/bold cyan]",
        ))

    # Output summary
    if state.outputs:
        console.print(f"\n[bold]Outputs ({len(state.outputs)} nodes):[/bold]")
        for node_id, output in state.outputs.items():
            if isinstance(output, dict):
                keys = list(output.keys())[:5]
                preview = ", ".join(keys)
                if len(output) > 5:
                    preview += f" (+{len(output)-5} more)"
            else:
                preview = str(output)[:60]
            console.print(f"  [green][ok][/green] {node_id}: {preview}")

    # Events count
    events = sm.get_events(run_id)
    console.print(f"\n[dim]Events: {len(events)} | DB: {db_path}[/dim]")
    return EXIT_OK
