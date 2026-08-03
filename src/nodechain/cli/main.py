"""NodeChain CLI — command-line interface for the graph runtime kernel."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import click

from rich.console import Console
from rich.panel import Panel

from nodechain.cli.exit_codes import EXIT_OK, EXIT_NOT_FOUND, EXIT_TRUST_VIOLATION, EXIT_VALIDATION
import hashlib

console = Console()


@click.group()
@click.version_option(version=__import__("nodechain").__version__)
def cli() -> None:
    """NodeChain — Autonomous AI systems from composable Harness Nodes."""
    pass


@cli.command()
@click.pass_context
@click.argument("query", required=True)
@click.option(
    "--blueprint", "-b",
    default="blueprints/research_decision_v1.yaml",
    help="Path to chain blueprint YAML",
)
@click.option(
    "--trace-dir", "-t",
    default="data/traces",
    help="Directory for trace output",
)
@click.option(
    "--model", "-m",
    default=None,
    help="Model to use for LLM calls",
)
@click.option(
    "--strict", is_flag=True, default=False,
    help="Enable strict governance mode (warnings become errors)",
)
@click.option(
    "--review-mode",
    type=click.Choice(["interactive", "auto-approve", "auto-reject", "auto-revision", "disabled", "pause"]),
    default=None,
    help="Human review gate mode",
)
@click.option(
    "--provider",
    type=click.Choice(["lim", "mock", "custom"]),
    default=None,
    help="Model provider to use",
)
@click.option(
    "--json", "json_output",
    default=None,
    help="Write run metadata (run_id, status) as JSON to this file",
)
@click.option(
    "--locked", is_flag=True, default=False,
    help="Verify registry lockfile before execution",
)
@click.option(
    "--trust-check", is_flag=True, default=False,
    help="Run trust invariant validation after execution (exit 15 on violations)",
)
@click.option(
    "--sandbox-profile",
    type=click.Choice(["none", "python_hooks", "subprocess_isolated", "os_profile"]),
    default=None,
    help="Override sandbox profile for untrusted nodes (v1.1.0)",
)
@click.option(
    "--policy-preset", "policy_preset",
    type=click.Choice(["minimal", "standard_untrusted", "production_untrusted", "hardened_untrusted"]),
    default=None,
    help="Policy preset for sandbox/resource governance (v1.3.5)",
)
@click.option(
    "--registry-resolved", "registry_resolved",
    is_flag=True,
    default=False,
    help="Resolve shared/reusable nodes from the local registry (not direct wiring) and "
         "enforce the lockfile fail-closed. Requires an existing registry.lock.json (v2.67.3).",
)
def run(
    ctx,
    query: str,
    blueprint: str,
    trace_dir: str,
    model: str,
    strict: bool,
    review_mode: str | None,
    provider: str | None,
    json_output: str | None,
    locked: bool,
    trust_check: bool,
    sandbox_profile: str | None,
    policy_preset: str | None,
    registry_resolved: bool,
) -> None:
    """Run the Research and Decision Assistant chain."""
    # Apply env overrides from flags
    if strict:
        os.environ["NODECHAIN_GOVERNANCE_STRICT"] = "1"
    if review_mode:
        os.environ["NODECHAIN_REVIEW_MODE"] = review_mode
    if provider:
        os.environ["NODECHAIN_PROVIDER"] = provider
    if sandbox_profile:
        os.environ["NODECHAIN_SANDBOX_PROFILE"] = sandbox_profile

    # Resolve policy preset (v1.3.5)
    # Order: CLI override → blueprint declaration → default (none)
    effective_preset = policy_preset or ""
    preset_source = ""
    if not effective_preset:
        # Check blueprint for policy_preset declaration
        try:
            from nodechain.core.blueprint import load_blueprint
            bp = load_blueprint(blueprint)
            if bp.policy_preset:
                effective_preset = bp.policy_preset
                preset_source = "blueprint"
        except Exception:
            pass
    else:
        preset_source = "cli"

    # Apply preset
    if effective_preset:
        from nodechain.sdk.policy_presets import get_preset
        preset = get_preset(effective_preset)
        if preset:
            os.environ["NODECHAIN_POLICY_PRESET"] = effective_preset
            os.environ["NODECHAIN_POLICY_PRESET_SOURCE"] = preset_source or "cli"
            # Apply sandbox profile from preset if not explicitly set
            if not sandbox_profile:
                os.environ["NODECHAIN_SANDBOX_PROFILE"] = preset.sandbox_profile

    # Verify lockfile if --locked
    if locked:
        from nodechain.sdk.lockfile import verify_lockfile
        result = verify_lockfile()
        if not result.get("valid", False):
            if "error" in result:
                console.print(f"[red]Lockfile error: {result['error']}[/red]")
            else:
                console.print("[red]Registry DRIFTED -- lockfile verification failed[/red]")
                for m in result.get("mismatches", []):
                    console.print(f"  MISMATCH {m['node_id']}: {m['field']}")
                for m in result.get("missing", []):
                    console.print(f"  MISSING {m['node_id']}")
            ctx.exit(10)
            return

    # v1.3.9: Create explicit RunnerConfig from resolved preset
    runner_config = None
    if effective_preset:
        from nodechain.sdk.policy_presets import get_preset as _get_preset
        from nodechain.runtime.subprocess_runner import RunnerConfig
        preset_obj = _get_preset(effective_preset)
        if preset_obj:
            runner_config = RunnerConfig.from_preset(preset_obj)

    # v2.67.3: registry-resolved mode — shared nodes resolved from local registry,
    # not direct _create_nodes wiring; lockfile enforced fail-closed.
    if registry_resolved:
        console.print(Panel(
            "[bold cyan]Registry-resolved mode enabled:[/bold cyan]\n"
            "  • shared nodes excluded from built-ins\n"
            "  • local registry resolution required\n"
            "  • lockfile enforcement required",
            title="v2.67.3 Registry-Resolved Reuse Proof",
        ))

    from nodechain.cli.run import run_chain
    code = asyncio.run(run_chain(
        query, blueprint, trace_dir, model, json_output,
        runner_config=runner_config,
        registry_resolved=registry_resolved,
        enforce_lockfile=registry_resolved,
    ))
    
    # Post-run trust check
    if trust_check and code == EXIT_OK:
        from nodechain.sdk.trust_summary import TrustSummary
        from nodechain.runtime.persistence import StateManager
        sm = StateManager()
        # Try to get the last run_id
        try:
            import glob
            traces = sorted(glob.glob(f"{trace_dir}/*.json"), key=os.path.getmtime, reverse=True)
            if traces:
                with open(traces[0]) as f:
                    trace_data = json.load(f)
                run_id = trace_data.get("run_id", "")
                if run_id:
                    state = sm.load(run_id)
                    if state:
                        summary = TrustSummary(run_id=run_id, locked_mode=locked)
                        # Populate preset info (v1.3.5)
                        summary.policy_preset = os.environ.get("NODECHAIN_POLICY_PRESET", "")
                        summary.preset_source = os.environ.get("NODECHAIN_POLICY_PRESET_SOURCE", "")
                        violations = summary.validate_invariants(strict=strict)
                        if violations:
                            error_count = sum(1 for v in violations if v.severity == "error")
                            if error_count > 0:
                                console.print(f"\n[red]TRUST VIOLATION[/red] ({error_count} errors):")
                                for v in violations:
                                    console.print(f"  [{v.code}] {v.node_id}: {v.invariant}")
                                ctx.exit(15)
                                return
        except Exception as exc:
            if strict:
                console.print(f"\n[red]TRUST CHECK ERROR[/red]: {exc}")
                ctx.exit(15)
                return
            else:
                console.print(f"\n[yellow]TRUST CHECK WARNING[/yellow]: {exc}")
    
    if code != 0:
        ctx.exit(code)


# v2.86: inspect relocated to cli/commands/inspect.py (register call below)


@cli.command()
@click.pass_context
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
def reconcile(ctx, run_id: str, db_path: str, trace_dir: str) -> None:
    """Reconcile a chain run: cross-check trace against persistent state.

    Runs the TraceReconciler to verify trace events match the ledger,
    side effects are consistent, and no corruption is detected.
    """
    from nodechain.cli.reconcile import reconcile_run
    code = reconcile_run(run_id, db_path, trace_dir)
    if code != 0:
        ctx.exit(code)


@cli.command()
@click.pass_context
@click.argument("run_id", required=True)
@click.option(
    "--db", "db_path",
    default="data/chain_state.db",
    help="Path to chain state database",
)
@click.option(
    "--blueprint", "-b",
    default="blueprints/research_decision_v1.yaml",
    help="Path to chain blueprint YAML",
)
@click.option(
    "--trace-dir", "-t",
    default="data/traces",
    help="Directory for trace output",
)
@click.option(
    "--review-mode",
    type=click.Choice(["interactive", "auto-approve", "auto-reject", "auto-revision", "disabled", "pause"]),
    default=None,
    help="Override review mode for resumed run",
)
def resume(ctx, run_id: str, db_path: str, blueprint: str, trace_dir: str, review_mode: str | None) -> None:
    """Resume a paused or failed chain run.

    Reconstructs the orchestrator from the blueprint and resumes
    execution from the last persisted state.
    """
    # Apply review mode override for resume
    if review_mode:
        os.environ["NODECHAIN_REVIEW_MODE"] = review_mode
    from nodechain.cli.resume import resume_run
    code = resume_run(run_id, db_path, blueprint, trace_dir)
    if code != 0:
        ctx.exit(code)


# ── recover (v2.46.0 Operator Recovery Console) ────────────────────
@cli.group(name="recover")
def recover_group() -> None:
    """Operator Recovery Console — inspect and act on paused/blocked runs (v2.46.0)."""
    pass


@recover_group.command("list")
@click.pass_context
@click.option(
    "--db", "db_path",
    default="data/chain_state.db",
    help="Path to chain state database",
)
@click.option(
    "--trace-dir", "-t",
    default="data/traces",
    help="Directory for trace output",
)
def recover_list_cmd(ctx, db_path: str, trace_dir: str) -> None:
    """List every persisted run with its derived recovery state."""
    from nodechain.cli.recover import recover_list
    code = recover_list(db_path, trace_dir)
    if code != 0:
        ctx.exit(code)


@recover_group.command("inspect")
@click.pass_context
@click.argument("run_id", required=True)
@click.option(
    "--db", "db_path",
    default="data/chain_state.db",
    help="Path to chain state database",
)
@click.option(
    "--trace-dir", "-t",
    default="data/traces",
    help="Directory for trace output",
)
def recover_inspect_cmd(ctx, run_id: str, db_path: str, trace_dir: str) -> None:
    """Show the full recovery snapshot for one run."""
    from nodechain.cli.recover import recover_inspect
    code = recover_inspect(run_id, db_path, trace_dir)
    if code != 0:
        ctx.exit(code)


@recover_group.command("trace")
@click.pass_context
@click.argument("run_id", required=True)
@click.option(
    "--db", "db_path",
    default="data/chain_state.db",
    help="Path to chain state database",
)
@click.option(
    "--trace-dir", "-t",
    default="data/traces",
    help="Directory for trace output",
)
def recover_trace_cmd(ctx, run_id: str, db_path: str, trace_dir: str) -> None:
    """Show trace health (reconciler report) for one run."""
    from nodechain.cli.recover import recover_trace
    code = recover_trace(run_id, db_path, trace_dir)
    if code != 0:
        ctx.exit(code)


# ── recover preview (v2.58.0 Operator Workbench) ───────────────────
@recover_group.command("preview")
@click.pass_context
@click.argument("run_id", required=True)
@click.argument("action", required=True)
@click.option("--db", "db_path", default="data/chain_state.db", help="Path to chain state database")
@click.option("--role", default=None, help="Operator role (operator/finance/admin)")
@click.option("--profile", default=None, help="Governance profile name")
@click.option("--profile-file", default=None, help="Governance profile YAML file path")
@click.option("--step", "target_step_id", type=int, default=None, help="Target step ID for retry")
@click.option("--reason", default=None, help="Reason for the action")
@click.option("--new-budget", default=None, type=float, help="Proposed new budget (for budget increase)")
@click.option("--operator", "operator_identity", default=None, help="Operator identity")
def recover_preview_cmd(
    ctx, run_id: str, action: str, db_path: str,
    role: str | None, profile: str | None, profile_file: str | None,
    target_step_id: int | None, reason: str | None,
    new_budget: float | None, operator_identity: str | None,
) -> None:
    """Preview whether an action would be allowed — dry-run authorization (v2.58.0).

    Uses the EXACT same authorization path as real recovery actions.
    Performs zero state mutation, zero event writes, zero delegation.
    Shows: allowed/denied, role used, profile used, denial type, and reason.
    """
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_RECOVERY_NOT_FOUND, EXIT_RECOVERY_BLOCKED
    from nodechain.core.state import StateManager
    from nodechain.runtime.recovery_service import RecoveryService
    import os

    sm = StateManager(db_path=db_path)
    state = sm.load(run_id)
    if state is None:
        console.print(f"[red]No saved state found for run: {run_id}[/red]")
        ctx.exit(EXIT_RECOVERY_NOT_FOUND)
        return

    # Convert action string to RecoveryAction enum
    from nodechain.runtime.recovery_policy import RecoveryAction
    try:
        action_enum = RecoveryAction(action.lower().replace("-", "_"))
    except ValueError:
        valid = ", ".join(a.value for a in RecoveryAction)
        console.print(f"[red]Unknown action '{action}'. Valid: {valid}[/red]")
        ctx.exit(EXIT_RECOVERY_BLOCKED)
        return

    service = RecoveryService(state_manager=sm)

    resolved_role = role or os.environ.get("NODECHAIN_OPERATOR_ROLE", "operator")
    resolved_operator = operator_identity or os.environ.get("NODECHAIN_OPERATOR_IDENTITY", "console")

    auth_result = service.authorize_action(
        run_id, action_enum,
        operator_identity=resolved_operator,
        target_step_id=target_step_id,
        reason=reason,
        new_budget=new_budget,
        operator_role=resolved_role,
        governance_profile=profile,
        governance_profile_file=profile_file,
    )

    from rich.panel import Panel
    from rich.table import Table

    # Decision panel
    if auth_result.admitted:
        decision_color = "green"
        decision_text = "ALLOWED"
    else:
        decision_color = "red"
        decision_text = "DENIED"

    console.print(Panel(
        f"[bold]Action:[/bold]       {action}\n"
        f"[bold]Run:[/bold]          {run_id}\n"
        f"[bold]Decision:[/bold]     [{decision_color}]{decision_text}[/{decision_color}]\n"
        f"[bold]Role:[/bold]         {resolved_role}\n"
        f"[bold]Operator:[/bold]     {resolved_operator}\n"
        f"[bold]Profile:[/bold]      {auth_result.governance_profile_id or '(default)'}\n"
        f"[bold]Denial Type:[/bold]  {auth_result.denial_type or '(none)'}\n"
        f"[bold]Reason:[/bold]       {auth_result.rejection_reason or '(admitted)'}",
        title=f"[bold {decision_color}]Preview: {action}[/bold {decision_color}]",
    ))

    if auth_result.governance_profile_digest:
        console.print(f"  [dim]Profile digest: {auth_result.governance_profile_digest}[/dim]")

    console.print(f"\n  [dim]This was a dry-run preview. No state was mutated.[/dim]")
    ctx.exit(EXIT_OK)


# ── recover actions (v2.46.0 Phase 4) ──────────────────────────────
@recover_group.command("resume")
@click.pass_context
@click.argument("run_id", required=True)
@click.option("--db", "db_path", default="data/chain_state.db")
@click.option("--trace-dir", "-t", default="data/traces")
@click.option("--blueprint", default="blueprints/research_decision_v1.yaml")
@click.option("--role", default=None,
              help="Operator role: operator, finance, admin")
@click.option("--profile", default=None,
              help="Governance profile name")
@click.option("--profile-file", default=None,
              help="Governance profile YAML file path")
@click.option("--operator", default=None, help="Operator identity for audit")
def recover_resume_cmd(ctx, run_id, db_path, trace_dir, blueprint, operator, role, profile, profile_file) -> None:
    """Resume a paused/crash-recovered run through the governed boundary."""
    from nodechain.cli.recover import _run_action
    from nodechain.runtime.recovery_policy import RecoveryAction
    code = _run_action(run_id, RecoveryAction.RESUME, db_path, trace_dir,
                       blueprint=blueprint, operator=operator, role=role, profile=profile, profile_file=profile_file)
    if code != 0:
        ctx.exit(code)


@recover_group.command("retry")
@click.pass_context
@click.argument("run_id", required=True)
@click.option("--step", "target_step_id", type=int, required=True,
              help="Step id to retry (required: step/invocation precision)")
@click.option("--db", "db_path", default="data/chain_state.db")
@click.option("--trace-dir", "-t", default="data/traces")
@click.option("--blueprint", default="blueprints/research_decision_v1.yaml")
@click.option("--role", default=None,
              help="Operator role: operator, finance, admin")
@click.option("--profile", default=None,
              help="Governance profile name")
@click.option("--profile-file", default=None,
              help="Governance profile YAML file path")
@click.option("--operator", default=None)
def recover_retry_cmd(ctx, run_id, target_step_id, db_path, trace_dir, blueprint, operator, role, profile, profile_file) -> None:
    """Retry a failed step by step_id (never node_id alone — looped-node safe)."""
    from nodechain.cli.recover import _run_action
    from nodechain.runtime.recovery_policy import RecoveryAction
    code = _run_action(run_id, RecoveryAction.RETRY_STEP, db_path, trace_dir,
                       blueprint=blueprint, target_step_id=target_step_id,
                       operator=operator, role=role, profile=profile, profile_file=profile_file)
    if code != 0:
        ctx.exit(code)


@recover_group.command("budget")
@click.pass_context
@click.argument("run_id", required=True)
@click.option("--new-budget", "new_budget", type=float, required=True,
              help="New absolute budget ceiling (must exceed previous + accumulated cost)")
@click.option("--reason", default=None, help="Reason for budget increase")
@click.option("--db", "db_path", default="data/chain_state.db")
@click.option("--trace-dir", "-t", default="data/traces")
@click.option("--blueprint", default="blueprints/research_decision_v1.yaml")
@click.option("--operator", default=None)
@click.option("--role", default=None,
              help="Operator role: operator, finance, admin (default: NODECHAIN_OPERATOR_ROLE or operator)")
@click.option("--profile", default=None,
              help="Governance profile name")
@click.option("--profile-file", default=None,
              help="Governance profile YAML file path")
def recover_budget_cmd(ctx, run_id, new_budget, reason, db_path, trace_dir, blueprint, operator, role, profile, profile_file) -> None:
    """Approve a budget increase for a budget-paused run (v2.47.0).
    Requires role: finance or admin (v2.49.0)."""
    from nodechain.cli.recover import _run_action
    from nodechain.runtime.recovery_policy import RecoveryAction
    code = _run_action(run_id, RecoveryAction.APPROVE_BUDGET_INCREASE, db_path, trace_dir,
                       blueprint=blueprint, reason=reason, operator=operator,
                       new_budget=new_budget, role=role, profile=profile, profile_file=profile_file)
    if code != 0:
        ctx.exit(code)


@recover_group.command("fallback")
@click.pass_context
@click.argument("run_id", required=True)
@click.option("--step", "target_step_id", type=int, required=True,
              help="Failed step id to route to fallback (required)")
@click.option("--db", "db_path", default="data/chain_state.db")
@click.option("--trace-dir", "-t", default="data/traces")
@click.option("--blueprint", default="blueprints/research_decision_v1.yaml")
@click.option("--role", default=None,
              help="Operator role: operator, finance, admin")
@click.option("--profile", default=None,
              help="Governance profile name")
@click.option("--profile-file", default=None,
              help="Governance profile YAML file path")
@click.option("--operator", default=None)
def recover_fallback_cmd(ctx, run_id, target_step_id, db_path, trace_dir, blueprint, operator, role, profile, profile_file) -> None:
    """Route a failed step to its fallback strategy (fallback-capable types only)."""
    from nodechain.cli.recover import _run_action
    from nodechain.runtime.recovery_policy import RecoveryAction
    code = _run_action(run_id, RecoveryAction.ROUTE_FALLBACK, db_path, trace_dir,
                       blueprint=blueprint, target_step_id=target_step_id,
                       operator=operator, role=role, profile=profile, profile_file=profile_file)
    if code != 0:
        ctx.exit(code)


@recover_group.command("approve")
@click.pass_context
@click.argument("run_id", required=True)
@click.option("--decision", type=click.Choice(["approve", "reject"]),
              required=True, help="Review decision")
@click.option("--db", "db_path", default="data/chain_state.db")
@click.option("--trace-dir", "-t", default="data/traces")
@click.option("--blueprint", default="blueprints/research_decision_v1.yaml")
@click.option("--role", default=None,
              help="Operator role: operator, finance, admin")
@click.option("--profile", default=None,
              help="Governance profile name")
@click.option("--profile-file", default=None,
              help="Governance profile YAML file path")
@click.option("--operator", default=None)
def recover_approve_cmd(ctx, run_id, decision, db_path, trace_dir, blueprint, operator, role, profile, profile_file) -> None:
    """Approve or reject a paused human-review gate."""
    from nodechain.cli.recover import _run_action
    from nodechain.runtime.recovery_policy import RecoveryAction
    action = (RecoveryAction.APPROVE_REVIEW if decision == "approve"
              else RecoveryAction.REJECT_REVIEW)
    code = _run_action(run_id, action, db_path, trace_dir,
                       blueprint=blueprint, operator=operator, role=role, profile=profile, profile_file=profile_file)
    if code != 0:
        ctx.exit(code)


@recover_group.command("revise")
@click.pass_context
@click.argument("run_id", required=True)
@click.option("--instructions", required=True, help="Revision instructions for the node")
@click.option("--db", "db_path", default="data/chain_state.db")
@click.option("--trace-dir", "-t", default="data/traces")
@click.option("--blueprint", default="blueprints/research_decision_v1.yaml")
@click.option("--role", default=None,
              help="Operator role: operator, finance, admin")
@click.option("--profile", default=None,
              help="Governance profile name")
@click.option("--profile-file", default=None,
              help="Governance profile YAML file path")
@click.option("--operator", default=None)
def recover_revise_cmd(ctx, run_id, instructions, db_path, trace_dir, blueprint, operator, role, profile, profile_file) -> None:
    """Request revision of a paused human-review gate."""
    from nodechain.cli.recover import _run_action
    from nodechain.runtime.recovery_policy import RecoveryAction
    code = _run_action(run_id, RecoveryAction.REQUEST_REVISION, db_path, trace_dir,
                       blueprint=blueprint, instructions=instructions, operator=operator, role=role, profile=profile, profile_file=profile_file)
    if code != 0:
        ctx.exit(code)


@recover_group.command("cancel")
@click.pass_context
@click.argument("run_id", required=True)
@click.option("--reason", default=None, help="Reason for cancellation")
@click.option("--db", "db_path", default="data/chain_state.db")
@click.option("--trace-dir", "-t", default="data/traces")
@click.option("--role", default=None,
              help="Operator role: operator, finance, admin")
@click.option("--profile", default=None,
              help="Governance profile name")
@click.option("--profile-file", default=None,
              help="Governance profile YAML file path")
@click.option("--operator", default=None)
def recover_cancel_cmd(ctx, run_id, reason, db_path, trace_dir, operator, role, profile, profile_file) -> None:
    """Cancel a non-terminal run (operator terminal action)."""
    from nodechain.cli.recover import _run_action
    from nodechain.runtime.recovery_policy import RecoveryAction
    code = _run_action(run_id, RecoveryAction.CANCEL_RUN, db_path, trace_dir,
                       reason=reason, operator=operator, role=role, profile=profile, profile_file=profile_file)
    if code != 0:
        ctx.exit(code)


@recover_group.command("fail")
@click.pass_context
@click.argument("run_id", required=True)
@click.option("--reason", default=None, help="Reason for failure")
@click.option("--db", "db_path", default="data/chain_state.db")
@click.option("--trace-dir", "-t", default="data/traces")
@click.option("--role", default=None,
              help="Operator role: operator, finance, admin")
@click.option("--profile", default=None,
              help="Governance profile name")
@click.option("--profile-file", default=None,
              help="Governance profile YAML file path")
@click.option("--operator", default=None)
def recover_fail_cmd(ctx, run_id, reason, db_path, trace_dir, operator, role, profile, profile_file) -> None:
    """Mark a non-terminal run as failed (operator terminal action)."""
    from nodechain.cli.recover import _run_action
    from nodechain.runtime.recovery_policy import RecoveryAction
    code = _run_action(run_id, RecoveryAction.FAIL_RUN, db_path, trace_dir,
                       reason=reason, operator=operator, role=role, profile=profile, profile_file=profile_file)
    if code != 0:
        ctx.exit(code)


@recover_group.command("batch")
@click.pass_context
@click.option("--file", "batch_file", required=True,
              help="YAML batch file path")
@click.option("--dry-run", is_flag=True, default=False,
              help="Plan only; do not execute actions")
@click.option("--continue-on-error", is_flag=True, default=False,
              help="Continue after denied/failed actions (overrides fail-fast)")
@click.option("--db", "db_path", default="data/chain_state.db")
@click.option("--trace-dir", "-t", default="data/traces")
@click.option("--blueprint", default="blueprints/research_decision_v1.yaml")
@click.option("--operator", default=None)
@click.option("--role", default=None,
              help="Operator role: operator, finance, admin")
@click.option("--profile", default=None,
              help="Governance profile name")
@click.option("--profile-file", default=None,
              help="Governance profile YAML file path")
def recover_batch_cmd(ctx, batch_file, dry_run, continue_on_error, db_path, trace_dir, blueprint, operator, role, profile, profile_file) -> None:
    """Execute a YAML batch of recovery actions (v2.50.0).

    Each action is authorized independently. Non-atomic — no rollback.
    Default: fail-fast (stop on first denial/failure).
    """
    from nodechain.cli.recover import _run_batch
    code = _run_batch(batch_file, db_path, trace_dir, blueprint,
                      dry_run=dry_run, continue_on_error=continue_on_error,
                      operator=operator, role=role, profile=profile, profile_file=profile_file)
    if code != 0:
        ctx.exit(code)


@recover_group.command("report")
@click.pass_context
@click.argument("run_id", required=True)
@click.option("--output", "-o", default=None, help="Write report JSON to this path")
@click.option("--db", "db_path", default="data/chain_state.db")
@click.option("--trace-dir", "-t", default="data/traces")
def recover_report_cmd(ctx, run_id, output, db_path, trace_dir) -> None:
    """Export a recovery report (snapshot + audit) as JSON."""
    from nodechain.cli.recover import recover_report
    code = recover_report(run_id, db_path, trace_dir, output)
    if code != 0:
        ctx.exit(code)


# ── recover side-effect resolution (v3.3.0) ───────────────────────
@recover_group.command("list-unknown")
@click.pass_context
@click.argument("run_id", required=True)
@click.option("--db", "db_path", default="data/chain_state.db")
def recover_list_unknown_cmd(ctx, run_id, db_path) -> None:
    """List side effects in 'unknown' status awaiting a recovery decision (v3.3.0)."""
    from nodechain.cli.recover import recover_list_unknown
    code = recover_list_unknown(run_id, db_path)
    if code != 0:
        ctx.exit(code)


@recover_group.command("resolve-side-effect")
@click.pass_context
@click.argument("run_id", required=True)
@click.option("--side-effect-key", "side_effect_key", required=True,
              help="Idempotency key of the unknown side effect to resolve")
@click.option("--decision", "decision", required=True,
              type=click.Choice(["verified_completed", "verified_failed",
                                 "mark_unrecoverable", "safe_to_retry"]),
              help="Recovery decision value")
@click.option("--reason", default="", help="Reason for the decision (required for failed/unrecoverable/retry)")
@click.option("--external-reference", "external_reference", default="",
              help="External evidence reference (required for verified_completed if no response-hash)")
@click.option("--response-hash", "response_hash", default="",
              help="Response hash evidence (required for verified_completed if no external-reference)")
@click.option("--db", "db_path", default="data/chain_state.db")
@click.option("--trace-dir", "-t", default="data/traces")
@click.option("--role", default=None, help="Operator role: operator, finance, admin")
@click.option("--profile", default=None, help="Governance profile name")
@click.option("--profile-file", default=None, help="Governance profile YAML file path")
@click.option("--operator", default=None)
def recover_resolve_side_effect_cmd(ctx, run_id, side_effect_key, decision, reason,
                                     external_reference, response_hash, db_path, trace_dir,
                                     role, profile, profile_file, operator) -> None:
    """Resolve an unknown side effect through a governed recovery decision (v3.3.0)."""
    from nodechain.cli.recover import recover_resolve_side_effect
    code = recover_resolve_side_effect(
        run_id, side_effect_key, decision, db_path, trace_dir,
        reason=reason, external_reference=external_reference, response_hash=response_hash,
        operator=operator, role=role, profile=profile, profile_file=profile_file,
    )
    if code != 0:
        ctx.exit(code)


@recover_group.command("execute-retry-authorized")
@click.pass_context
@click.argument("run_id", required=True)
@click.option("--side-effect-key", "side_effect_key", required=True,
              help="Idempotency key of the retry_authorized parent side effect")
@click.option("--recovery-decision-id", "recovery_decision_id", required=True,
              help="Decision ID of the safe_to_retry recovery decision")
@click.option("--reason", default="", help="Reason for executing the retry")
@click.option("--db", "db_path", default="data/chain_state.db")
@click.option("--trace-dir", "-t", default="data/traces")
@click.option("--role", default=None, help="Operator role: operator, finance, admin")
@click.option("--profile", default=None, help="Governance profile name")
@click.option("--profile-file", default=None, help="Governance profile YAML file path")
@click.option("--operator", default=None)
def recover_execute_retry_authorized_cmd(ctx, run_id, side_effect_key,
                                          recovery_decision_id, reason,
                                          db_path, trace_dir, role, profile,
                                          profile_file, operator) -> None:
    """Execute a retry-authorized side effect through the recovery dispatch seam (v3.5.0)."""
    from nodechain.cli.recover import recover_execute_retry_authorized
    code = recover_execute_retry_authorized(
        run_id, side_effect_key, recovery_decision_id, db_path, trace_dir,
        reason=reason, operator=operator, role=role,
        profile=profile, profile_file=profile_file,
    )
    if code != 0:
        ctx.exit(code)


# ── recover evidence (v2.58.0 Operator Workbench) ──────────────────
@recover_group.command("evidence")
@click.pass_context
@click.argument("run_id", required=True)
@click.option("--db", "db_path", default="data/chain_state.db")
@click.option("--json", "json_output", is_flag=True, help="Output as machine-readable JSON")
def recover_evidence_cmd(ctx, run_id: str, db_path: str, json_output: bool) -> None:
    """Browse evidence and citations for a run (v2.58.0).

    Shows sources, claims, citations, validation summary, risk classification,
    and final recommendation — without requiring raw SQLite/JSON access.
    """
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_RECOVERY_NOT_FOUND
    from nodechain.core.state import StateManager
    import json as json_mod

    sm = StateManager(db_path=db_path)
    state = sm.load(run_id)
    if state is None:
        console.print(f"[red]No saved state found for run: {run_id}[/red]")
        ctx.exit(EXIT_RECOVERY_NOT_FOUND)
        return

    outputs = state.outputs or {}

    if json_output:
        evidence = {
            "run_id": run_id,
            "sources": outputs.get("evidence_synthesizer", {}).get("sources", []) if isinstance(outputs.get("evidence_synthesizer"), dict) else [],
            "claims": outputs.get("evidence_synthesizer", {}).get("claims", []) if isinstance(outputs.get("evidence_synthesizer"), dict) else [],
            "validated_claims": outputs.get("risk_classifier", {}).get("validated_claims", []) if isinstance(outputs.get("risk_classifier"), dict) else [],
            "validation_summary": outputs.get("claim_validator", {}).get("validation_summary", {}) if isinstance(outputs.get("claim_validator"), dict) else {},
            "risk_assessment": {k: v for k, v in outputs.get("risk_classifier", {}).items() if k in ("risk_level", "confidence", "review_required", "risk_factors")} if isinstance(outputs.get("risk_classifier"), dict) else {},
            "citations": outputs.get("response_generator", {}).get("citations", []) if isinstance(outputs.get("response_generator"), dict) else [],
            "recommendation": outputs.get("response_generator", {}).get("recommendation", "") if isinstance(outputs.get("response_generator"), dict) else "",
        }
        console.print(json_mod.dumps(evidence, indent=2, default=str))
        ctx.exit(EXIT_OK)
        return

    from rich.panel import Panel
    from rich.table import Table

    # Sources
    synth = outputs.get("evidence_synthesizer", {})
    if isinstance(synth, dict):
        sources = synth.get("sources", [])
        claims = synth.get("claims", [])
        console.print(Panel(
            f"[bold]Sources:[/bold]  {len(sources)}\n"
            f"[bold]Claims:[/bold]   {len(claims)}",
            title="[bold blue]Evidence Summary[/bold blue]",
        ))

        if sources:
            src_table = Table(title="Sources", show_lines=True, header_style="bold cyan")
            src_table.add_column("#", style="dim", width=4)
            src_table.add_column("Source ID", style="yellow", width=20)
            src_table.add_column("Title", style="white", width=50)
            for i, s in enumerate(sources[:15], 1):
                src_table.add_row(str(i), str(s.get("source_id", "?"))[:20], str(s.get("title", "?"))[:50])
            console.print(src_table)

        if claims:
            cl_table = Table(title="Evidence Claims", show_lines=True, header_style="bold cyan")
            cl_table.add_column("ID", style="dim", width=6)
            cl_table.add_column("Confidence", justify="right", width=12)
            cl_table.add_column("Support", width=10)
            cl_table.add_column("Statement", style="white", width=50)
            for c in claims[:10]:
                cl_table.add_row(
                    str(c.get("claim_id", "?"))[:6],
                    f"{c.get('confidence', '?')}",
                    str(c.get("support_strength", "?")),
                    str(c.get("statement", "?"))[:50],
                )
            console.print(cl_table)

    # Validation summary
    val_output = outputs.get("claim_validator", {})
    if isinstance(val_output, dict):
        summary = val_output.get("validation_summary", {})
        if summary:
            console.print(Panel(
                "\n".join(f"[bold]{k}:[/bold] {v}" for k, v in summary.items()),
                title="[bold cyan]Validation Summary[/bold cyan]",
            ))

    # Risk classification
    risk_output = outputs.get("risk_classifier", {})
    if isinstance(risk_output, dict):
        risk_level = risk_output.get("risk_level", "")
        if risk_level:
            color = "red" if risk_level == "HIGH" else "yellow" if risk_level == "MEDIUM" else "green"
            console.print(Panel(
                f"[bold]Risk Level:[/bold]     [{color}]{risk_level}[/{color}]\n"
                f"[bold]Confidence:[/bold]     {risk_output.get('confidence', '?')}\n"
                f"[bold]Review Required:[/bold] {risk_output.get('review_required', '?')}\n"
                f"[bold]Risk Factors:[/bold]   {', '.join(risk_output.get('risk_factors', []))}",
                title="[bold cyan]Risk Classification[/bold cyan]",
            ))

    # Final recommendation
    resp_output = outputs.get("response_generator", {})
    if isinstance(resp_output, dict):
        recommendation = resp_output.get("recommendation", "")
        if recommendation:
            citations = resp_output.get("citations", [])
            console.print(Panel(
                f"{recommendation[:200]}{'...' if len(recommendation) > 200 else ''}\n\n"
                f"[bold]Citations:[/bold] {len(citations)}",
                title="[bold cyan]Final Recommendation[/bold cyan]",
            ))

    ctx.exit(EXIT_OK)


# ── recover dashboard (v2.58.0 Operator Workbench) ─────────────────
@recover_group.command("dashboard")
@click.pass_context
@click.option("--db", "db_path", default="data/chain_state.db")
@click.option("--trace-dir", "-t", default="data/traces")
def recover_dashboard_cmd(ctx, db_path: str, trace_dir: str) -> None:
    """Show the operator dashboard (v2.58.0).

    Rich CLI dashboard showing: recovery backlog, blocked/paused runs,
    budget-paused runs, trace health, trust posture, and recent denials.
    All data is derived from persisted state — read-only.
    """
    from nodechain.cli.exit_codes import EXIT_OK
    from nodechain.core.state import StateManager
    from nodechain.runtime.recovery_service import RecoveryService
    from nodechain.runtime.recovery_classifier import classify
    from rich.panel import Panel
    from rich.table import Table

    sm = StateManager(db_path=db_path)
    service = RecoveryService(state_manager=sm, trace_dir=trace_dir)

    all_runs = sm.list_all_runs()
    if not all_runs:
        console.print("[dim]No runs found.[/dim]")
        ctx.exit(EXIT_OK)
        return

    # Classify each run
    backlog: dict[str, list] = {}
    for run_summary in all_runs:
        run_id = run_summary.get("run_id", "")
        state = sm.load(run_id)
        if state is None:
            continue
        recovery_state = classify(state)
        if recovery_state and recovery_state != "COMPLETED":
            backlog.setdefault(recovery_state, []).append({
                "run_id": run_id,
                "status": state.status,
                "node": state.current_node or "(none)",
                "step": state.step,
            })

    # Dashboard header
    total_backlog = sum(len(v) for v in backlog.values())
    console.print(Panel(
        f"[bold]Total Runs:[/bold]       {len(all_runs)}\n"
        f"[bold]Recovery Backlog:[/bold] {total_backlog}\n"
        f"[bold]States:[/bold]           {', '.join(f'{k}({len(v)})' for k, v in sorted(backlog.items())) if backlog else '(none)'}",
        title="[bold blue]NodeChain Operator Dashboard[/bold blue]",
    ))

    # Backlog table
    if backlog:
        bl_table = Table(title="Recovery Backlog", show_lines=True, header_style="bold cyan")
        bl_table.add_column("State", style="magenta", width=30)
        bl_table.add_column("Run ID", style="yellow", width=25)
        bl_table.add_column("Status", width=12)
        bl_table.add_column("Current Node", style="green", width=20)
        for state_name, runs in sorted(backlog.items()):
            for r in runs:
                status = r["status"]
                color = "red" if status == "failed" else "yellow" if status == "paused" else "white"
                bl_table.add_row(
                    state_name,
                    r["run_id"][:25],
                    f"[{color}]{status}[/{color}]",
                    r["node"][:20],
                )
        console.print(bl_table)
    else:
        console.print("[green]\u2713 No recovery backlog — all runs are terminal.[/green]")

    # Recent operator actions (denials)
    try:
        from nodechain.core.state import get_operator_actions
        recent_actions = get_operator_actions(db_path, limit=10)
        denied = [a for a in recent_actions if not a.get("admitted", True)]
        if denied:
            console.print(f"\n[red]\u26a0  {len(denied)} recent denied action(s)[/red]")
            for a in denied[:5]:
                console.print(f"    [dim]{a.get('action_id', '?')}:[/dim] "
                              f"{a.get('action', '?')} on {a.get('run_id', '?')[:20]} — "
                              f"{a.get('rejection_reason', '?')[:60]}")
    except Exception:
        pass  # operator_action_log may not exist on all DBs

    ctx.exit(EXIT_OK)


# ── recover profiles (v2.52.0) ─────────────────────────────────────
@recover_group.group("profiles")
def recover_profiles_group() -> None:
    """Inspect and validate governance profiles (v2.52.0)."""
    pass


@recover_profiles_group.command("list")
def recover_profiles_list_cmd() -> None:
    """List all built-in governance profiles."""
    from nodechain.runtime.governance_profiles import BUILTIN_PROFILES, compute_profile_digest
    from rich.console import Console as RichConsole
    from rich.table import Table
    console = RichConsole()
    table = Table(title="Governance Profiles", show_lines=True)
    table.add_column("ID", style="cyan", width=15)
    table.add_column("Display Name", style="white", width=15)
    table.add_column("Batch Max", style="yellow", width=10)
    table.add_column("Digest", style="dim", width=20)
    for pid, p in BUILTIN_PROFILES.items():
        table.add_row(pid, p.display_name, str(p.batch.max_actions),
                      compute_profile_digest(p))
    console.print(table)


@recover_profiles_group.command("show")
@click.argument("profile_id", required=True)
@click.option("--file", "profile_file", default="", help="Custom profile YAML file (overrides built-in lookup)")
def recover_profiles_show_cmd(profile_id, profile_file) -> None:
    """Show full governance details of a profile (v2.58.0).

    Displays action matrix, budget caps, override requirements, audit settings,
    and batch policy — not just the summary fields.
    """
    from nodechain.runtime.governance_profiles import (
        get_builtin_profile, compute_profile_digest, GovernanceProfileResolver,
        ALL_ROLES, ALL_ACTIONS,
    )
    from nodechain.runtime.recovery_policy import ACTION_ALLOWED_ROLES
    from rich.console import Console as RichConsole
    from rich.panel import Panel
    from rich.table import Table

    console = RichConsole()

    # Resolve profile: --file takes precedence, then built-in
    if profile_file:
        try:
            from nodechain.runtime.governance_profiles import GovernanceProfileResolver
            p = GovernanceProfileResolver._load_from_file(profile_file)
        except Exception as e:
            console.print(f"[red]Failed to load profile: {e}[/red]")
            return
    else:
        try:
            p = get_builtin_profile(profile_id)
        except KeyError as e:
            console.print(f"[red]{e}[/red]")
            return

    digest = compute_profile_digest(p)

    # ── Summary panel ──────────────────────────────────────────────
    console.print(Panel(
        f"[bold]ID:[/bold]            {p.id}\n"
        f"[bold]Display:[/bold]       {p.display_name}\n"
        f"[bold]Description:[/bold]   {p.description}\n"
        f"[bold]Version:[/bold]       {p.version}\n"
        f"[bold]Roles:[/bold]         {', '.join(p.roles.allowed_roles)}\n"
        f"[bold]Default Role:[/bold]  {p.roles.default_role}\n"
        f"[bold]Digest:[/bold]        {digest}",
        title=f"[bold blue]Profile: {p.id}[/bold blue]",
    ))

    # ── Action Matrix table ────────────────────────────────────────
    action_table = Table(
        title="Action Matrix",
        show_lines=True, header_style="bold cyan",
    )
    action_table.add_column("Action", style="white", width=28)
    for role in ALL_ROLES:
        action_table.add_column(role, justify="center", width=10)

    for action_name in ALL_ACTIONS:
        # Base RBAC matrix
        base_roles = ACTION_ALLOWED_ROLES.get(action_name, set())

        # Profile-specific action governance
        action_gov = p.actions.get(action_name)
        profile_roles = action_gov.allowed_roles if action_gov else p.roles.allowed_roles

        # Effective: role must be in both base RBAC and profile
        row = [action_name]
        for role in ALL_ROLES:
            if role in base_roles and role in profile_roles:
                row.append("[green]\u2713[/green]")
            else:
                row.append("[red]\u2717[/red]")
        action_table.add_row(*row)

    console.print(action_table)

    # ── Per-action requirements table ──────────────────────────────
    req_table = Table(
        title="Per-Action Requirements",
        show_lines=True, header_style="bold cyan",
    )
    req_table.add_column("Action", style="white", width=28)
    req_table.add_column("Reason Required", justify="center", width=16)
    req_table.add_column("Override Required", justify="center", width=16)

    for action_name in ALL_ACTIONS:
        action_gov = p.actions.get(action_name)
        req_reason = action_gov.require_reason if action_gov else False
        req_override = action_gov.require_override if action_gov else False
        req_table.add_row(
            action_name,
            "[yellow]Yes[/yellow]" if req_reason else "[dim]No[/dim]",
            "[yellow]Yes[/yellow]" if req_override else "[dim]No[/dim]",
        )

    console.print(req_table)

    # ── Budget governance ──────────────────────────────────────────
    budget_lines = [
        f"[bold]Approve Roles:[/bold]     {', '.join(p.budget.approve_roles)}",
        f"[bold]Reason Required:[/bold]   {p.budget.require_reason}",
    ]
    if p.budget.max_new_budget_usd is not None:
        budget_lines.append(f"[bold]Max New Budget:[/bold]    ${p.budget.max_new_budget_usd:.2f}")
    else:
        budget_lines.append("[bold]Max New Budget:[/bold]    [dim](unlimited)[/dim]")
    if p.budget.max_increase_multiplier is not None:
        budget_lines.append(f"[bold]Max Multiplier:[/bold]     {p.budget.max_increase_multiplier}x")
    else:
        budget_lines.append("[bold]Max Multiplier:[/bold]     [dim](unlimited)[/dim]")
    console.print(Panel(
        "\n".join(budget_lines),
        title="[bold cyan]Budget Governance[/bold cyan]",
    ))

    # ── Override governance ────────────────────────────────────────
    console.print(Panel(
        f"[bold]Non-retryable retry requires admin:[/bold]    {p.override.non_retryable_retry_requires_admin}\n"
        f"[bold]Non-retryable retry requires env:[/bold]       {p.override.non_retryable_retry_requires_env_override}\n"
        f"[bold]Break-glass requires env override:[/bold]      {p.override.break_glass_requires_env_override}",
        title="[bold cyan]Override Governance[/bold cyan]",
    ))

    # ── Audit governance ───────────────────────────────────────────
    console.print(Panel(
        f"[bold]Require operator identity:[/bold]     {p.audit.require_operator_identity}\n"
        f"[bold]Require reason for mutations:[/bold]   {p.audit.require_reason_for_mutations}\n"
        f"[bold]Record profile digest:[/bold]          {p.audit.record_profile_digest}",
        title="[bold cyan]Audit Governance[/bold cyan]",
    ))

    # ── Batch governance ───────────────────────────────────────────
    console.print(Panel(
        f"[bold]Batch enabled:[/bold]                {p.batch.enabled}\n"
        f"[bold]Max actions:[/bold]                  {p.batch.max_actions}\n"
        f"[bold]Allow continue-on-error:[/bold]      {p.batch.allow_continue_on_error}\n"
        f"[bold]Require dry-run before execute:[/bold] {p.batch.require_dry_run_before_execute}",
        title="[bold cyan]Batch Governance[/bold cyan]",
    ))


@recover_profiles_group.command("validate")
@click.option("--file", "profile_file", required=True, help="Custom profile YAML file")
def recover_profiles_validate_cmd(profile_file) -> None:
    """Validate a custom governance profile YAML file."""
    from nodechain.runtime.governance_profiles import GovernanceProfileResolver, compute_profile_digest
    from rich.console import Console as RichConsole
    console = RichConsole()
    resolver = GovernanceProfileResolver()
    try:
        p = resolver.resolve(explicit_profile_file=profile_file)
        console.print(f"[green]Valid: {p.id}[/green]")
        console.print(f"[dim]Digest: {compute_profile_digest(p)}[/dim]")
    except Exception as e:
        console.print(f"[red]Invalid: {e}[/red]")


# v2.86: report relocated to cli/commands/report.py (register call below)


@cli.command()
@click.argument("run_id", required=True)
@click.option("--db", "db_path", default="data/chain_state.db")
@click.option("--strict", is_flag=True, help="Exit nonzero on trust violations")
def trust(run_id: str, db_path: str, strict: bool) -> None:
    """Inspect trust enforcement for a run.

    Shows trust levels, isolation modes, policy enforcement,
    and environment controls for each node.

    Use --strict to exit nonzero on trust violations.
    """
    from nodechain.sdk.trust_summary import TrustSummary, NodeTrustRecord
    from nodechain.runtime.persistence import StateManager

    sm = StateManager(db_path=db_path)
    state = sm.load(run_id)
    if state is None:
        click.echo(f"No saved state found for run: {run_id}")
        sys.exit(EXIT_NOT_FOUND)

    summary = TrustSummary(run_id=run_id)

    # Load trust info from origins if available
    origins = getattr(state, "node_origins", {}) or {}
    for node_id, origin in origins.items():
        record = NodeTrustRecord(
            node_id=node_id,
            trust_level=origin.get("trust_level", "built_in"),
            isolation_mode=origin.get("isolation_mode", "in_process"),
            child_policy_enforced=origin.get("child_policy_enforced", False),
            env_filtered=origin.get("env_filtered", False),
            temp_dir_isolated=origin.get("temp_dir_isolated", False),
            timeout_limit=origin.get("timeout_limit", 0),
            output_limit=origin.get("output_limit", 0),
            memory_limit=origin.get("memory_limit", 0),
            origin=origin.get("origin", "built_in"),
        )
        summary.add_node(record)

    summary_dict = summary.to_dict()

    click.echo(f"\nTrust Summary for run: {run_id}")
    click.echo(f"{'='*60}")
    click.echo(f"Lockfile verified: {summary.lockfile_verified}")
    click.echo(f"Locked mode:       {summary.locked_mode}")
    # v1.3.6: show policy preset
    if summary.policy_preset:
        click.echo(f"Policy preset:     {summary.policy_preset}")
        click.echo(f"Preset source:     {summary.preset_source}")
    click.echo(f"Compliant:         {summary.is_compliant}")
    click.echo(f"\nEnforcement Surface:")
    for k, v in summary_dict["enforcement_surface"].items():
        click.echo(f"  {k:20s} {v}")
    click.echo(f"\nNodes ({len(summary_dict['nodes'])}):")
    for node in summary_dict["nodes"]:
        click.echo(f"  {node['node_id']:25s} trust={node['trust_level']:20s} isolation={node['isolation_mode']}")
        # Show seccomp fields when relevant (v1.2.5)
        if node.get("sandbox_profile_used"):
            click.echo(f"    sandbox_profile:  {node.get('sandbox_profile_used', '-')}")
            click.echo(f"    sandbox_backend:  {node.get('sandbox_backend', '-')}")
            click.echo(f"    seccomp_enforced: {node.get('seccomp_enforced', False)}")
            click.echo(f"    syscall_filter:   {node.get('syscall_filtering_enforced', False)}")
            if node.get("seccomp_profile_name"):
                click.echo(f"    seccomp_profile:  {node['seccomp_profile_name']}")
            # v1.3.6: show cgroup limit fields when relevant
            if node.get("cgroup_accounting_scope"):
                click.echo(f"    cgroup_scope:     {node.get('cgroup_accounting_scope', '-')}")
                click.echo(f"    cgroup_limits_req: {node.get('cgroup_limits_requested', False)}")
                click.echo(f"    cgroup_limits_enf: {node.get('cgroup_limits_enforced', False)}")
                if node.get("cgroup_memory_max_mb"):
                    click.echo(f"    memory_max:       {node['cgroup_memory_max_mb']}MB")
                if node.get("cgroup_pids_max"):
                    click.echo(f"    pids_max:         {node['cgroup_pids_max']}")
                if node.get("cgroup_cpu_max_quota"):
                    click.echo(f"    cpu_quota:        {node['cgroup_cpu_max_quota']}")
                # v1.4.2: namespace fields
                if node.get("network_namespace_requested") or node.get("network_namespace_enforced"):
                    click.echo(f"    net_ns_requested: {node.get('network_namespace_requested', False)}")
                    click.echo(f"    net_ns_enforced:  {node.get('network_namespace_enforced', False)}")
                    if node.get("network_namespace_error"):
                        click.echo(f"    net_ns_error:     {node['network_namespace_error']}")
                # v1.4.4: mount namespace fields
                if node.get("mount_namespace_requested") or node.get("mount_namespace_enforced"):
                    click.echo(f"    mnt_ns_requested: {node.get('mount_namespace_requested', False)}")
                    click.echo(f"    mnt_ns_enforced:  {node.get('mount_namespace_enforced', False)}")
                    if node.get("mount_namespace_error"):
                        click.echo(f"    mnt_ns_error:     {node['mount_namespace_error']}")
                # v1.4.6: mount confinement fields
                if node.get("mount_confinement_requested") or node.get("mount_confinement_enforced"):
                    click.echo(f"    mnt_conf_req:     {node.get('mount_confinement_requested', False)}")
                    click.echo(f"    mnt_conf_enf:     {node.get('mount_confinement_enforced', False)}")
                    if node.get("mount_confinement_error"):
                        click.echo(f"    mnt_conf_error:   {node['mount_confinement_error']}")
                    if node.get("temp_root_created"):
                        click.echo(f"    temp_root_created: {node['temp_root_created']}")
                    if node.get("allowed_mounts"):
                        click.echo(f"    allowed_mounts:   {', '.join(node['allowed_mounts'])}")
                # v1.5.0: PID namespace fields
                if node.get("pid_namespace_requested") or node.get("pid_namespace_enforced"):
                    click.echo(f"    pid_ns_requested: {node.get('pid_namespace_requested', False)}")
                    click.echo(f"    pid_ns_enforced:  {node.get('pid_namespace_enforced', False)}")
                    if node.get("pid_namespace_error"):
                        click.echo(f"    pid_ns_error:     {node['pid_namespace_error']}")
                    if node.get("pid_namespace_mode"):
                        click.echo(f"    pid_ns_mode:      {node['pid_namespace_mode']}")
                    # v1.5.1: procfs view
                    if node.get("procfs_namespace_view_enforced"):
                        click.echo(f"    procfs_isolated:  {node['procfs_namespace_view_enforced']}")
                    if node.get("procfs_error"):
                        click.echo(f"    procfs_error:     {node['procfs_error']}")
                if node.get("namespace_mode"):
                    click.echo(f"    namespace_mode:   {node['namespace_mode']}")

    # Validate invariants
    violations = summary.validate_invariants(strict=strict)
    if violations:
        click.echo(f"\nTrust Violations ({len(violations)}):")
        for v in violations:
            click.echo(f"  [{v.code}] {v.severity.upper():7s} {v.node_id:25s} {v.invariant}")
            click.echo(f"           expected={v.expected}  actual={v.actual}")
    else:
        click.echo(f"\nNo trust violations.")

    click.echo()

    # Exit nonzero in strict mode if violations exist
    if strict and violations:
        error_count = sum(1 for v in violations if v.severity == "error")
        if error_count > 0:
            sys.exit(EXIT_TRUST_VIOLATION)


# v2.86: trace relocated to cli/commands/trace.py (register call below)


# ── Registry & SDK commands ──

@cli.command(name="presets")
@click.pass_context
def list_presets(ctx) -> None:
    """List available policy presets."""
    from nodechain.sdk.policy_presets import PRESETS
    for name, preset in PRESETS.items():
        console.print(f"\n[bold]{name}[/bold]")
        console.print(f"  {preset.description}")
        console.print(f"  sandbox_profile: {preset.sandbox_profile}")
        # Hardening layers
        layers = []
        if preset.seccomp_required:
            layers.append("seccomp")
        if preset.cgroup_limits_requested:
            layers.append(f"cgroup ({preset.cgroup_memory_max_mb}MB/{preset.cgroup_pids_max}pids/{preset.cgroup_cpu_max_quota}cpu)")
        if preset.network_namespace_required:
            layers.append("network namespace")
        if preset.mount_confinement_required:
            layers.append("mount confinement (chroot)")
        if preset.pid_namespace_required:
            layers.append("PID namespace")
        if layers:
            console.print(f"  hardening_layers: {', '.join(layers)}")
        if preset.trust_check_required:
            console.print(f"  trust_check: required")


# v2.79: audit-bundle relocated to cli/commands/audit_bundle.py (register call below)


@cli.command(name="attest")
@click.argument("run_id", required=False)
@click.option("--bundle", "bundle_path", default="", help="Path to audit bundle ZIP")
@click.option("--output", "-o", default="", help="Output attestation JSON path")
@click.option("--sign", "sign_key", default="", help="Sign attestation with this private key PEM")
@click.option("--verify", "verify_path", default=None, help="Verify an attestation JSON")
@click.option("--pubkey", "pubkey_path", default="", help="Public key PEM for signature verification")
@click.option("--require-signature", is_flag=True, default=False, help="Fail if attestation is not signed")
@click.option("--strict", is_flag=True, default=False, help="Fail on non-compliant trust verdict")
@click.option("--deployment-target", default="", help="Deployment target identifier")
@click.option("--artifact-digest", default="", help="Expected artifact/package SHA-256 digest")
@click.option("--expected-bundle", "expected_bundle_path", default="", help="Expected audit bundle ZIP to verify hash")
@click.option("--expect-artifact-digest", default="", help="Expected artifact SHA-256 digest")
@click.option("--expect-lockfile-digest", default="", help="Expected lockfile SHA-256 digest")
@click.option("--expect-policy-digest", default="", help="Expected policy SHA-256 digest")
@click.option("--expect-target", default="", help="Expected deployment target")
@click.option("--policy-id", default="", help="Policy identifier to bind")
@click.option("--policy-version", default="", help="Policy version")
@click.option("--profile", "profile_path", default="", help="Verifier profile JSON file")
@click.option("--require-profile-signature", is_flag=True, default=False, help="Fail if verifier profile is not signed by a trusted key (CI mode)")
def attest(
    run_id: str | None,
    bundle_path: str,
    output: str,
    sign_key: str,
    verify_path: str | None,
    pubkey_path: str,
    require_signature: bool,
    strict: bool,
    deployment_target: str,
    artifact_digest: str,
    expected_bundle_path: str,
    expect_artifact_digest: str,
    expect_lockfile_digest: str,
    expect_policy_digest: str,
    expect_target: str,
    policy_id: str,
    policy_version: str,
    profile_path: str,
    require_profile_signature: bool,
) -> None:
    """Generate or verify a deployment attestation.

    Generate:  nodechain attest <run_id> --bundle audit.zip --output attestation.json
    Sign:      nodechain attest <run_id> --bundle a.zip --sign private.pem
    Verify:    nodechain attest --verify attestation.json --pubkey public.pem
    CI mode:   nodechain attest --verify a.json --pubkey pub.pem --require-signature --strict
    """
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION

    if verify_path:
        from nodechain.cli.attestation import verify_attestation
        result = verify_attestation(
            verify_path,
            pubkey_path=pubkey_path,
            require_signature=require_signature,
            strict=strict,
            expected_bundle_path=expected_bundle_path,
            expected_artifact_digest=expect_artifact_digest,
            expected_lockfile_digest=expect_lockfile_digest,
            expected_policy_digest=expect_policy_digest,
            expected_target=expect_target,
            profile_path=profile_path,
            require_profile_signature=require_profile_signature,
        )
        if result["valid"]:
            console.print(f"[green]✅ Attestation valid: {verify_path}[/green]")
            for check, val in result.get("checks", {}).items():
                console.print(f"  {check}: {val}")
            if result["warnings"]:
                console.print(f"  Warnings: {len(result['warnings'])}")
                for w in result["warnings"]:
                    console.print(f"    - {w}")
            ctx = click.get_current_context()
            ctx.exit(EXIT_OK)
        else:
            console.print(f"[red]❌ Attestation invalid: {verify_path}[/red]")
            for e in result["errors"]:
                console.print(f"  ERROR: {e}")
            for w in result["warnings"]:
                console.print(f"  WARN: {w}")
            ctx = click.get_current_context()
            ctx.exit(EXIT_VALIDATION)
    elif run_id and bundle_path:
        from nodechain.cli.attestation import generate_attestation
        code = generate_attestation(
            run_id, bundle_path, output, deployment_target, artifact_digest, sign_key,
            policy_id=policy_id, policy_version=policy_version,
        )
        ctx = click.get_current_context()
        ctx.exit(code)
    else:
        console.print("[red]Error: Provide run_id + --bundle to generate, or --verify to check.[/red]")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)


@cli.group()
def registry() -> None:
    """Node registry operations."""
    pass


@registry.command("list")
@click.option("--path", "-p", multiple=True, help="Additional search paths")
def registry_list_cmd(path: tuple[str, ...]) -> None:
    """List all registered node packages."""
    from nodechain.cli.sdk_cli import registry_list
    registry_list(extra_paths=list(path) or None)


@registry.command("inspect")
@click.argument("node_id")
@click.option("--path", "-p", multiple=True, help="Additional search paths")
def registry_inspect_cmd(node_id: str, path: tuple[str, ...]) -> None:
    """Show detailed info about a registered node."""
    from nodechain.cli.sdk_cli import registry_inspect
    registry_inspect(node_id, extra_paths=list(path) or None)


@registry.command("lock")
@click.option("-o", "--output", default=None, help="Output path for lockfile")
@click.option("--include-blocked", is_flag=True, default=False, help="Include packages that fail policy checks")
def registry_lock_cmd(output: str | None, include_blocked: bool) -> None:
    """Generate a registry lockfile."""
    from nodechain.cli.sdk_cli import registry_lock
    registry_lock(output_path=output, include_blocked=include_blocked)


@registry.command("verify")
@click.option("-l", "--lockfile", default=None, help="Path to lockfile")
def registry_verify_cmd(lockfile: str | None) -> None:
    """Verify registry against lockfile."""
    from nodechain.cli.sdk_cli import registry_verify
    registry_verify(lockfile_path=lockfile)


@registry.command("publish")
@click.option("--package", "package_path", required=True, help="Package manifest YAML or JSON")
@click.option("--certification", "cert_path", required=True, help="Certification JSON")
@click.option("--lockfile-digest", default="", help="Lockfile digest")
@click.option("--require-cert-signature", is_flag=True, default=False, help="Require signed certification")
@click.option("--trust-store", "ts_path", default="", help="Trust store path")
@click.option("--strict", is_flag=True, default=False, help="Strict publishing checks")
def registry_publish_cmd(package_path: str, cert_path: str, lockfile_digest: str,
                          require_cert_signature: bool, ts_path: str, strict: bool) -> None:
    """Publish a certified package to the registry (v1.18.0)."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION
    from nodechain.cli.certified_registry import publish_package

    entry = publish_package(
        package_path=package_path,
        certification=cert_path,
        lockfile_digest=lockfile_digest,
        require_certification_signature=require_cert_signature,
        trust_store_path=ts_path,
        strict=strict,
    )
    if entry["registry_status"] == "active":
        console.print(f"[green]\u2705 Package published to registry[/green]")
        console.print(f"  Package: {entry['package_id']} v{entry['package_version']}")
        console.print(f"  Entry:   {entry['entry_id'][:16]}...")
        console.print(f"  Digest:  {entry['package_digest'][:16]}...")
    else:
        console.print(f"[red]\u274c Publication denied[/red]")
        for err in entry.get("errors", []):
            console.print(f"  {err}")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@registry.command("certified-list")
@click.option("--active-only", is_flag=True, default=False, help="Show only active entries")
def registry_certified_list_cmd(active_only: bool) -> None:
    """List certified registry entries (v1.18.0)."""
    from nodechain.cli.exit_codes import EXIT_OK
    from nodechain.cli.certified_registry import list_entries

    entries = list_entries(active_only=active_only)
    if not entries:
        console.print("[yellow]No certified entries[/yellow]")
    else:
        for e in entries:
            color = "green" if e.get("registry_status") == "active" else "red"
            console.print(f"  [{color}]{e['registry_status']}[/{color}] {e['package_id']} v{e['package_version']} ({e['entry_id'][:8]}...)")

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@registry.command("certified-inspect")
@click.option("--entry-id", required=True, help="Registry entry ID")
def registry_certified_inspect_cmd(entry_id: str) -> None:
    """Inspect a certified registry entry (v1.18.0)."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION
    from nodechain.cli.certified_registry import inspect_entry

    try:
        summary = inspect_entry(entry_id)
        color = "green" if summary["registry_status"] == "active" else "red"
        console.print(f"  [{color}]{summary['registry_status']}[/{color}] {summary['package_id']} v{summary['package_version']}")
        console.print(f"  Cert:    {summary['certification_status']}")
        console.print(f"  Signed:  {'yes' if summary['is_signed'] else 'no'}")
        console.print(f"  Capabilities: {summary['capabilities']}")
    except KeyError as e:
        console.print(f"[red]\u274c {e}[/red]")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@registry.command("certified-verify")
@click.option("--entry-id", required=True, help="Registry entry ID")
@click.option("--pubkey", default="", help="Public key PEM")
@click.option("--trust-store", "ts_path", default="", help="Trust store path")
def registry_certified_verify_cmd(entry_id: str, pubkey: str, ts_path: str) -> None:
    """Verify a certified registry entry (v1.18.0)."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION
    from nodechain.cli.certified_registry import load_registry, verify_registry_entry

    registry_data = load_registry()
    entry = registry_data.get("entries", {}).get(entry_id)
    if not entry:
        console.print(f"[red]\u274c Entry not found[/red]")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)

    result = verify_registry_entry(entry, public_key_pem=pubkey, trust_store_path=ts_path)
    if result["valid"]:
        console.print(f"[green]\u2705 Registry entry valid[/green]")
    else:
        console.print(f"[red]\u274c Registry entry invalid[/red]")
        for err in result["errors"]:
            console.print(f"  {err}")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@registry.command("deprecate")
@click.option("--entry-id", required=True, help="Entry to deprecate")
@click.option("--reason", default="", help="Deprecation reason")
def registry_deprecate_cmd(entry_id: str, reason: str) -> None:
    """Deprecate a registry entry (v1.18.0)."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION
    from nodechain.cli.certified_registry import deprecate_entry

    try:
        deprecate_entry(entry_id, reason=reason)
        console.print(f"[yellow]\u2705 Entry deprecated[/yellow]")
    except KeyError as e:
        console.print(f"[red]\u274c {e}[/red]")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@registry.command("revoke")
@click.option("--entry-id", required=True, help="Entry to revoke")
@click.option("--reason", default="", help="Revocation reason")
def registry_revoke_cmd(entry_id: str, reason: str) -> None:
    """Revoke a registry entry (v1.18.0)."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION
    from nodechain.cli.certified_registry import revoke_entry

    try:
        revoke_entry(entry_id, reason=reason)
        console.print(f"[red]\u2705 Entry revoked[/red]")
    except KeyError as e:
        console.print(f"[red]\u274c {e}[/red]")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@registry.command("install")
@click.option("--package-id", required=True, help="Package ID to install")
@click.option("--version", default="", help="Version constraint")
@click.option("--certified-only", is_flag=True, default=False, help="Require active certification")
@click.option("--trusted-publisher-only", is_flag=True, default=False, help="Require trusted publisher")
@click.option("--trust-store", "ts_path", default="", help="Trust store path")
@click.option("--allowed-capabilities", default="", help="Comma-separated allowed capabilities")
@click.option("--require-active-only", is_flag=True, default=False, help="Reject deprecated entries")
def registry_install_cmd(package_id: str, version: str, certified_only: bool,
                          trusted_publisher_only: bool, ts_path: str,
                          allowed_capabilities: str, require_active_only: bool) -> None:
    """Install a certified package from the registry (v1.18.1)."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_TRUST_VIOLATION
    from nodechain.cli.registry_consumption import install_package, ConsumptionPolicy

    caps = [c.strip() for c in allowed_capabilities.split(",") if c.strip()] if allowed_capabilities else None
    policy = ConsumptionPolicy(
        certified_only=certified_only,
        trusted_publisher_only=trusted_publisher_only,
        allowed_capabilities=caps,
        require_active_only=require_active_only,
    )
    result = install_package(
        package_id=package_id, version=version,
        policy=policy, trust_store_path=ts_path,
    )
    if result["resolved"]:
        console.print(f"[green]\u2705 Package installed[/green]")
        console.print(f"  Package: {package_id} v{version or 'latest'}")
        console.print(f"  Verdict: {result['policy_verdict']}")
    else:
        console.print(f"[red]\u274c Installation refused[/red]")
        for err in result.get("errors", []):
            console.print(f"  {err}")
        ctx = click.get_current_context()
        ctx.exit(EXIT_TRUST_VIOLATION)

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@registry.command("resolve")
@click.option("--package-id", required=True, help="Package ID to resolve")
@click.option("--version", default="", help="Version constraint")
@click.option("--certified-only", is_flag=True, default=False, help="Require certification")
def registry_resolve_cmd(package_id: str, version: str, certified_only: bool) -> None:
    """Resolve a package from the certified registry (v1.18.1)."""
    from nodechain.cli.exit_codes import EXIT_OK
    from nodechain.cli.registry_consumption import resolve_package, ConsumptionPolicy

    policy = ConsumptionPolicy(certified_only=certified_only)
    result = resolve_package(package_id=package_id, version=version, policy=policy)
    if result.resolved:
        console.print(f"[green]\u2705 Resolved[/green]")
        console.print(f"  Package: {package_id}")
        console.print(f"  Entry:   {result.entry.get('entry_id', '')[:16]}...")
    else:
        console.print(f"[yellow]\u26a0\ufe0f  Not resolved[/yellow]")
        for err in result.errors:
            console.print(f"  {err}")

    console.print(f"\nChecks:")
    for check in result.checks:
        status = "\u2705" if check["passed"] else "\u274c"
        console.print(f"  {status} {check['check']}: {check['detail']}")

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@registry.command("install-remote")
@click.argument("package_id")
@click.option("--version", required=True, help="Package version")
@click.option("--remote", "remote_url", required=True, help="Remote registry URL (HTTPS)")
@click.option("--install-dir", default="", help="Installation directory")
@click.option("--trust-store", "ts_path", default="", help="Trust store path")
@click.option("--insecure", is_flag=True, default=False, help="Allow non-TLS (NOT recommended)")
@click.option("--strict", is_flag=True, default=True, help="Strict verification (default)")
def registry_install_remote_cmd(
    package_id: str, version: str, remote_url: str,
    install_dir: str, ts_path: str, insecure: bool, strict: bool,
) -> None:
    """Install a package from a remote registry (v2.0.0).

    Fetches, verifies, and installs a remote certified package.
    Remote packages receive trust_level=remote_untrusted.
    """
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_TRUST_VIOLATION
    from nodechain.sdk.remote_registry import install_remote_package

    result = install_remote_package(
        remote_url=remote_url,
        package_id=package_id,
        version=version,
        install_dir=install_dir,
        trust_store_path=ts_path,
        require_tls=not insecure,
        strict=strict,
    )

    if result["installed"]:
        console.print(f"[green]\u2705 Remote package installed[/green]")
        console.print(f"  Package: {package_id} v{version}")
        console.print(f"  Source:  {remote_url}")
        console.print(f"  Trust:   remote_untrusted")
        console.print(f"  Path:    {result['installed_path']}")
        console.print(f"\nVerification checks ({len(result['checks'])}):")
        for check in result["checks"]:
            status = "\u2705" if check.get("passed") else "\u274c"
            console.print(f"  {status} {check['check']}")
    else:
        console.print(f"[red]\u274c Remote installation failed[/red]")
        console.print(f"  Package: {package_id} v{version}")
        console.print(f"  Source:  {remote_url}")
        for err in result.get("errors", []):
            console.print(f"  {err}")
        console.print(f"\nChecks ({len(result['checks'])}):")
        for check in result["checks"]:
            status = "\u2705" if check.get("passed") else "\u274c"
            console.print(f"  {status} {check['check']}: {check.get('detail', '')}")
        ctx = click.get_current_context()
        ctx.exit(EXIT_TRUST_VIOLATION)

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@registry.command("serve")
@click.option("--root", "root_dir", required=True, type=click.Path(exists=True), help="Registry root directory")
@click.option("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
@click.option("--port", default=8765, type=int, help="Bind port (default: 8765)")
@click.option("--strict/--no-strict", default=True, help="Require signed metadata (default: strict)")
def registry_serve_cmd(root_dir: str, host: str, port: int, strict: bool) -> None:
    """Serve a remote registry (v2.1.0).

    Serves protocol v1 endpoints from a local directory.
    The server is read-only and serves signed metadata + artifacts.
    """
    from nodechain.sdk.remote_registry_server import serve_registry
    serve_registry(root_dir=root_dir, host=host, port=port, strict=strict, blocking=True)


@registry.command("remote-build")
@click.option("--root", "root_dir", required=True, type=click.Path(exists=True), help="Registry root directory")
@click.option("--sign", "sign_key", default="", help="Path to PEM private key for registry signing")
@click.option("--registry-id", default="", help="Registry identifier")
@click.option("--registry-name", default="NodeChain Registry", help="Registry display name")
def registry_remote_build_cmd(root_dir: str, sign_key: str, registry_id: str, registry_name: str) -> None:
    """Build signed remote registry metadata (v2.1.0).

    Scans the root directory for packages and creates signed registry.json.
    """
    from nodechain.sdk.remote_registry_server import build_registry_metadata, write_registry_to_disk
    from nodechain.cli.exit_codes import EXIT_OK

    result = build_registry_metadata(
        root_dir=root_dir,
        registry_id=registry_id,
        registry_name=registry_name,
        signer_private_key_path=sign_key,
    )
    write_registry_to_disk(root_dir, result)

    console.print(f"[green]\u2705 Registry built[/green]")
    console.print(f"  Root:  {root_dir}")
    console.print(f"  ID:    {result['registry_id']}")
    console.print(f"  Name:  {result['registry_name']}")
    console.print(f"  Packages: {result.get('package_count', 0)}")
    console.print(f"  Signed: {'yes' if result.get('signature') else 'no'}")
    console.print(f"  Digest: {result.get('metadata_digest', '')[:16]}...")

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@registry.command("resolve-deps")
@click.option("--package-id", required=True, help="Root package ID")
@click.option("--version", required=True, help="Root package version")
@click.option("--remote", "remote_url", required=True, help="Remote registry URL")
@click.option("--insecure", is_flag=True, default=False, help="Allow non-TLS")
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON")
def registry_resolve_deps_cmd(
    package_id: str, version: str, remote_url: str,
    insecure: bool, as_json: bool,
) -> None:
    """Resolve and verify a package with all dependencies (v2.2.0).

    Resolves the dependency graph, verifies each package independently,
    and generates a lockfile for reproducible installs.
    """
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_TRUST_VIOLATION
    from nodechain.sdk.remote_registry import RemoteRegistryClient
    from nodechain.sdk.dependency_resolver import resolve_and_verify
    from nodechain.sdk.remote_readiness import resolve_sandbox_preset
    

    client = RemoteRegistryClient(
        base_url=remote_url, require_tls=not insecure,
    )

    def fetch_meta(pid: str, ver: str):
        meta = client.fetch_package_metadata(pid, ver)
        return meta.to_dict()

    def verify_node(node):
        from nodechain.sdk.remote_registry import VerificationCheck
        checks = []
        checks.append(VerificationCheck(
            check="metadata_digest_valid",
            passed=bool(node.metadata_digest),
            detail="Metadata digest present",
        ))
        checks.append(VerificationCheck(
            check="publisher_present",
            passed=bool(node.publisher_fingerprint),
            detail="Publisher fingerprint present",
        ))
        checks.append(VerificationCheck(
            check="sandbox_profile",
            passed=node.sandbox_profile in ("hardened_untrusted", "production_untrusted", "standard_untrusted")
                  or not node.is_root,
            detail=f"Sandbox: {node.sandbox_profile}",
        ))
        return checks

    graph, receipt, lockfile = resolve_and_verify(
        root_package_id=package_id,
        root_version=version,
        remote_url=remote_url,
        fetch_metadata_fn=fetch_meta,
        verify_node_fn=verify_node,
    )

    if as_json:
        print(json.dumps({
            "graph": graph.to_dict(),
            "receipt": receipt.to_dict(),
            "lockfile": lockfile.to_dict(),
        }, indent=2, sort_keys=True))
    else:
        console.print(f"[green]\u2705 Dependency graph resolved[/green]")
        console.print(f"  Root:     {package_id} v{version}")
        console.print(f"  Nodes:    {len(graph.nodes)}")
        console.print(f"  Deps:     {len(graph.dependency_nodes)}")
        console.print(f"  Verified: {graph.all_verified}")
        console.print(f"  Graph:    {graph.compute_graph_digest()[:16]}...")
        if graph.resolution_errors:
            console.print(f"[red]  Errors:   {len(graph.resolution_errors)}[/red]")
            for err in graph.resolution_errors:
                console.print(f"    {err}")
        if graph.resolution_warnings:
            console.print(f"[yellow]  Warnings: {len(graph.resolution_warnings)}[/yellow]")

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@registry.group("transparency", invoke_without_command=True)
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON")
@click.pass_context
def transparency_cmd(ctx: click.Context, as_json: bool) -> None:
    """Transparency log operations (v2.3.0).

    Append-only, tamper-evident log of remote registry interactions.
    Logged does not mean trusted — trust comes from signatures,
    digests, certification, and policy. The log adds historical
    accountability and tamper detection.
    """
    if ctx.invoked_subcommand is None:
        # Default: show summary
        from nodechain.sdk.transparency_log import load_transparency_log, verify_transparency_log
        

        log = load_transparency_log()
        result = log.verify()

        if as_json:
            print(json.dumps({
                "total_entries": result.total_entries,
                "valid": result.valid,
                "first_sequence": result.first_sequence,
                "last_sequence": result.last_sequence,
                "log_digest": result.log_digest,
                "errors": result.errors,
                "warnings": result.warnings,
            }, indent=2))
        else:
            if result.valid:
                console.print(f"[green]\u2705 Transparency log is valid[/green]")
            else:
                console.print(f"[red]\u274c Transparency log has {len(result.errors)} error(s)[/red]")
            console.print(f"  Entries:  {result.total_entries}")
            console.print(f"  Range:    {result.first_sequence} – {result.last_sequence}")
            console.print(f"  Digest:   {result.log_digest[:16]}...")
            for err in result.errors:
                console.print(f"[red]  ERROR:   {err}[/red]")


@transparency_cmd.command("verify")
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON")
def transparency_verify_cmd(as_json: bool) -> None:
    """Verify the integrity of the transparency log chain."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_TRUST_VIOLATION
    from nodechain.sdk.transparency_log import verify_transparency_log
    

    result = verify_transparency_log()

    if as_json:
        print(json.dumps({
            "valid": result.valid,
            "total_entries": result.total_entries,
            "errors": result.errors,
            "warnings": result.warnings,
            "first_sequence": result.first_sequence,
            "last_sequence": result.last_sequence,
            "log_digest": result.log_digest,
        }, indent=2))
    else:
        if result.valid:
            console.print(f"[green]\u2705 Chain valid — {result.total_entries} entries verified[/green]")
            console.print(f"  Sequence: {result.first_sequence} \u2013 {result.last_sequence}")
            console.print(f"  Digest:   {result.log_digest[:16]}...")
        else:
            console.print(f"[red]\u274c Chain broken — {len(result.errors)} error(s)[/red]")
            for err in result.errors:
                console.print(f"  \u2022 {err}")

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK if result.valid else EXIT_TRUST_VIOLATION)


@transparency_cmd.command("show")
@click.option("--package", default=None, help="Filter by package ID")
@click.option("--digest", default=None, help="Filter by entry digest")
@click.option("--event-type", default=None, help="Filter by event type")
@click.option("--last", "last_n", type=int, default=None, help="Show last N entries")
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON")
def transparency_show_cmd(
    package: str | None, digest: str | None, event_type: str | None,
    last_n: int | None, as_json: bool,
) -> None:
    """Show transparency log entries."""
    from nodechain.sdk.transparency_log import load_transparency_log
    

    log = load_transparency_log()
    entries = log.query(package=package, digest=digest, event_type=event_type)

    if last_n is not None:
        entries = entries[-last_n:]

    if as_json:
        print(json.dumps([e.to_dict() for e in entries], indent=2))
    else:
        if not entries:
            console.print("[yellow]No entries found[/yellow]")
        else:
            for entry in entries:
                console.print(
                    f"  #{entry.sequence_number} "
                    f"[{entry.event_type}] "
                    f"{entry.subject_id}@{entry.subject_version} "
                    f"({entry.entry_digest[:12]}...)"
                )

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@transparency_cmd.command("append")
@click.option("--event-type", required=True, help="Event type")
@click.option("--subject-id", required=True, help="Subject package ID or registry URL")
@click.option("--subject-version", default="", help="Subject version")
@click.option("--metadata-digest", default="", help="Metadata SHA-256")
@click.option("--artifact-digest", default="", help="Artifact SHA-256")
@click.option("--graph-digest", default="", help="Dependency graph SHA-256")
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON")
def transparency_append_cmd(
    event_type: str, subject_id: str, subject_version: str,
    metadata_digest: str, artifact_digest: str, graph_digest: str,
    as_json: bool,
) -> None:
    """Append an entry to the transparency log."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION
    from nodechain.sdk.transparency_log import append_event
    

    try:
        entry = append_event(
            event_type=event_type,
            subject_id=subject_id,
            subject_version=subject_version,
            metadata_digest=metadata_digest,
            artifact_digest=artifact_digest,
            graph_digest=graph_digest,
        )
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)
        return

    if as_json:
        print(json.dumps(entry.to_dict(), indent=2))
    else:
        console.print(f"[green]\u2705 Entry appended[/green]")
        console.print(f"  Sequence:  {entry.sequence_number}")
        console.print(f"  Type:      {entry.event_type}")
        console.print(f"  Subject:   {entry.subject_id}@{entry.subject_version}")
        console.print(f"  Digest:    {entry.entry_digest[:16]}...")

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@registry.group("federation", invoke_without_command=True)
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON")
@click.pass_context
def federation_cmd(ctx: click.Context, as_json: bool) -> None:
    """Multi-registry federation operations (v2.5.0).

    A registry is not trusted because it is reachable.
    A registry is eligible only if the active organization profile allows it.
    """
    if ctx.invoked_subcommand is None:
        from nodechain.sdk.federation import load_federation_config, verify_federation
        

        store = load_federation_config()
        report = verify_federation(store)

        if as_json:
            print(json.dumps({
                "total": report["total_registries"],
                "enabled": report["enabled"],
                "disabled": report["disabled"],
                "valid": report["valid"],
                "errors": report["errors"],
                "warnings": report["warnings"],
            }, indent=2))
        else:
            if report["valid"]:
                console.print(f"[green]\u2705 Federation config valid[/green]")
            else:
                console.print(f"[red]\u274c Federation config has errors[/red]")
            console.print(f"  Total:    {report['total_registries']}")
            console.print(f"  Enabled:  {report['enabled']}")
            console.print(f"  Disabled: {report['disabled']}")
            for err in report["errors"]:
                console.print(f"[red]  ERROR: {err}[/red]")
            for warn in report["warnings"]:
                console.print(f"[yellow]  WARN: {warn}[/yellow]")


@federation_cmd.command("list")
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON")
def federation_list_cmd(as_json: bool) -> None:
    """List federated registries."""
    from nodechain.sdk.federation import load_federation_config
    

    store = load_federation_config()
    if as_json:
        print(json.dumps([r.to_dict() for r in store.registries], indent=2))
    else:
        if not store.registries:
            console.print("[yellow]No federated registries configured[/yellow]")
        else:
            for reg in store.enabled_registries:
                status = "\u2705" if reg.enabled else "\u274c"
                console.print(
                    f"  [{reg.priority}] {reg.registry_id} "
                    f"({reg.base_url}) {status}"
                )

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@federation_cmd.command("add")
@click.option("--registry-id", required=True, help="Unique registry identifier")
@click.option("--base-url", required=True, help="Registry base URL")
@click.option("--priority", type=int, default=100, help="Priority (lower = higher)")
@click.option("--trust-level", default="remote_untrusted", help="Trust level")
@click.option("--publisher", "publishers", multiple=True, help="Allowed publisher fingerprint")
@click.option("--package", "packages", multiple=True, help="Allowed package ID")
@click.option("--signer", default="", help="Required signer fingerprint")
@click.option("--disabled", is_flag=True, default=False, help="Add as disabled")
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON")
def federation_add_cmd(
    registry_id: str, base_url: str, priority: int, trust_level: str,
    publishers: tuple, packages: tuple, signer: str, disabled: bool,
    as_json: bool,
) -> None:
    """Add a federated registry."""
    from nodechain.sdk.federation import (
        FederatedRegistryConfig, load_federation_config, save_federation_config,
    )
    

    store = load_federation_config()
    config = FederatedRegistryConfig(
        registry_id=registry_id,
        base_url=base_url,
        priority=priority,
        trust_level=trust_level,
        allowed_publishers=list(publishers),
        allowed_packages=list(packages),
        required_signer_fingerprint=signer,
        enabled=not disabled,
    )
    store.add(config)
    save_federation_config(store)

    if as_json:
        print(json.dumps(config.to_dict(), indent=2))
    else:
        console.print(f"[green]\u2705 Registry '{registry_id}' added[/green]")

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@federation_cmd.command("remove")
@click.argument("registry_id")
def federation_remove_cmd(registry_id: str) -> None:
    """Remove a federated registry."""
    from nodechain.sdk.federation import load_federation_config, save_federation_config

    store = load_federation_config()
    if store.remove(registry_id):
        save_federation_config(store)
        console.print(f"[green]\u2705 Registry '{registry_id}' removed[/green]")
    else:
        console.print(f"[red]Registry '{registry_id}' not found[/red]")
        ctx = click.get_current_context()
        ctx.exit(EXIT_NOT_FOUND)

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@federation_cmd.command("verify")
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON")
def federation_verify_cmd(as_json: bool) -> None:
    """Verify federation configuration."""
    from nodechain.sdk.federation import load_federation_config, verify_federation
    

    store = load_federation_config()
    report = verify_federation(store)

    if as_json:
        print(json.dumps(report, indent=2))
    else:
        if report["valid"]:
            console.print(f"[green]\u2705 Valid \u2014 {report['enabled']} enabled, {report['disabled']} disabled[/green]")
        else:
            console.print(f"[red]\u274c {len(report['errors'])} error(s)[/red]")
            for err in report["errors"]:
                console.print(f"  \u2022 {err}")
        for warn in report["warnings"]:
            console.print(f"[yellow]  WARN: {warn}[/yellow]")

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK if report["valid"] else EXIT_VALIDATION)


@federation_cmd.command("resolve")
@click.option("--package-id", required=True, help="Package ID to resolve")
@click.option("--version", required=True, help="Package version")
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON")
def federation_resolve_cmd(package_id: str, version: str, as_json: bool) -> None:
    """Resolve a package across federated registries."""
    from nodechain.sdk.federation import load_federation_config, resolve_federated_package
    from nodechain.sdk.org_policy import get_active_profile
    

    store = load_federation_config()
    profile = get_active_profile()

    # Mock fetcher for demonstration (real implementation would use RemoteRegistryClient)
    def fetcher(registry_id: str, pid: str, ver: str):
        return {
            "artifact_digest": hashlib.sha256(f"{pid}{ver}".encode()).hexdigest(),
            "metadata_digest": hashlib.sha256(f"meta-{pid}{ver}".encode()).hexdigest(),
            "publisher_fingerprint": "pub_fp",
            "signer_fingerprint": "signer_fp",
            "metadata_signed": True,
        }

    result = resolve_federated_package(
        package_id=package_id,
        version=version,
        fetch_metadata_fn=fetcher,
        store=store,
        org_profile=profile,
    )

    if as_json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        if result.all_passed:
            console.print(f"[green]\u2705 Resolved[/green]")
            console.print(f"  Package:  {package_id}@{version}")
            console.print(f"  Registry: {result.selected.registry_id}")
            console.print(f"  Digest:   {result.selected.artifact_digest[:16]}...")
            console.print(f"  Candidates: {len(result.candidates)}")
        elif result.conflicts:
            console.print(f"[red]\u274c Conflict detected[/red]")
            for c in result.conflicts:
                console.print(f"  \u2022 {c}")
        else:
            console.print(f"[red]\u274c No valid candidates[/red]")
            for r in result.rejected:
                console.print(f"  \u2022 {r['registry_id']}: {r['reason']}")

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK if result.all_passed else (EXIT_VALIDATION if result.conflicts else EXIT_NOT_FOUND))


@registry.group("reputation")
@click.pass_context
def reputation_cmd(ctx: click.Context) -> None:
    """Registry reputation and health scoring (v2.6.0)."""
    ctx.ensure_object(dict)


@reputation_cmd.command("show")
@click.option("--json", "as_json", is_flag=True, default=False, help="Output JSON")
def reputation_show_cmd(as_json: bool) -> None:
    """Show all registry reputation scores."""
    from nodechain.sdk.reputation import load_reputation_store, generate_reputation_report
    store = load_reputation_store()
    report = generate_reputation_report(store)
    if as_json:
        
        click.echo(json.dumps(report.to_dict(), indent=2))
    else:
        if not report.scores:
            console.print("[dim]No reputation scores recorded[/dim]")
        else:
            for s in report.scores:
                console.print(
                    f"  {s.registry_id}: {s.score:.1f} ({s.grade}) "
                    f"checked={s.last_checked[:19]}"
                )
    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@reputation_cmd.command("score")
@click.argument("registry_id")
@click.option("--availability", type=float, default=100.0)
@click.option("--metadata-freshness", type=float, default=100.0)
@click.option("--signature-validity", type=float, default=100.0)
@click.option("--transparency-consistency", type=float, default=100.0)
@click.option("--conflict-history", type=float, default=100.0)
@click.option("--revocation-responsiveness", type=float, default=100.0)
@click.option("--install-success-rate", type=float, default=100.0)
@click.option("--policy-compliance", type=float, default=100.0)
@click.option("--latency", type=float, default=None)
@click.option("--json", "as_json", is_flag=True, default=False)
def reputation_score_cmd(
    registry_id: str,
    availability: float, metadata_freshness: float,
    signature_validity: float, transparency_consistency: float,
    conflict_history: float, revocation_responsiveness: float,
    install_success_rate: float, policy_compliance: float,
    latency: float | None, as_json: bool,
) -> None:
    """Score a registry's health."""
    from nodechain.sdk.reputation import (
        ScoringInputs, score_registry, ReputationStore, save_reputation_store,
        load_reputation_store,
    )
    inputs = ScoringInputs(
        registry_id=registry_id,
        availability=availability,
        metadata_freshness=metadata_freshness,
        signature_validity=signature_validity,
        transparency_consistency=transparency_consistency,
        conflict_history=conflict_history,
        revocation_responsiveness=revocation_responsiveness,
        install_success_rate=install_success_rate,
        policy_compliance=policy_compliance,
        latency=latency,
    )
    score = score_registry(inputs)
    store = load_reputation_store()
    store.set(score)
    save_reputation_store(store)
    if as_json:
        
        click.echo(json.dumps(score.to_dict(), indent=2))
    else:
        console.print(f"[green]\u2705 {registry_id}: {score.score:.1f} ({score.grade})[/green]")
    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@reputation_cmd.command("verify")
@click.option("--json", "as_json", is_flag=True, default=False)
def reputation_verify_cmd(as_json: bool) -> None:
    """Verify reputation store integrity."""
    from nodechain.sdk.reputation import load_reputation_store, verify_reputation_store
    store = load_reputation_store()
    result = verify_reputation_store(store)
    if as_json:
        
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        if result.valid:
            console.print("[green]\u2705 All reputation scores valid[/green]")
        else:
            console.print(f"[red]\u274c {len(result.issues)} issue(s) found[/red]")
            for i in result.issues:
                console.print(f"  \u2022 {i}")
    ctx = click.get_current_context()
    ctx.exit(EXIT_OK if result.valid else EXIT_VALIDATION)


@reputation_cmd.command("refresh")
@click.option("--registry-id", default=None, help="Refresh specific registry")
@click.option("--json", "as_json", is_flag=True, default=False)
def reputation_refresh_cmd(registry_id: str | None, as_json: bool) -> None:
    """Refresh reputation scores (re-verify all stored scores)."""
    from nodechain.sdk.reputation import load_reputation_store, verify_reputation_store, ReputationStore, save_reputation_store
    store = load_reputation_store()
    if registry_id:
        score = store.get(registry_id)
        if score:
            score.last_checked = datetime.now(timezone.utc).isoformat()
            console.print(f"[green]\u2705 Refreshed {registry_id}[/green]")
        else:
            console.print(f"[yellow]\u26a0  Registry '{registry_id}' not found in store[/yellow]")
    else:
        for s in store.all_scores:
            s.last_checked = datetime.now(timezone.utc).isoformat()
        console.print(f"[green]\u2705 Refreshed {len(store.all_scores)} score(s)[/green]")
    save_reputation_store(store)
    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@cli.group("marketplace")
@click.pass_context
def marketplace_cmd(ctx: click.Context) -> None:
    """Public discovery and marketplace operations (v2.7.0).

    Discovery adds reachability. Discovery does not add trust.
    """
    ctx.ensure_object(dict)


@marketplace_cmd.command("discover")
@click.argument("source_url")
@click.option("--json", "as_json", is_flag=True, default=False)
def marketplace_discover_cmd(source_url: str, as_json: bool) -> None:
    """Fetch a discovery index from a source URL."""
    from nodechain.sdk.discovery import (
        fetch_discovery_index, check_discovery_policy,
        DiscoveryIndexReceipt, DiscoveryStoreEntry,
        save_discovery_store, load_discovery_store,
    )
    from nodechain.sdk.org_policy import get_active_profile

    profile = get_active_profile()

    def mock_fetcher(url):
        import os
        if os.path.exists(url):
            with open(url, "rb") as f:
                return f.read()
        raise FileNotFoundError(f"Cannot fetch {url}")

    try:
        index = fetch_discovery_index(source_url, fetcher_fn=mock_fetcher)
    except Exception as e:
        console.print(f"[red]\u274c Failed to fetch index: {e}[/red]")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)
        return

    allowed, reason = check_discovery_policy(index, profile)
    if not allowed:
        console.print(f"[red]\u274c Policy denied: {reason}[/red]")
        ctx = click.get_current_context()
        ctx.exit(EXIT_TRUST_VIOLATION)
        return

    receipt = DiscoveryIndexReceipt(
        index_id=index.index_id,
        source_url=source_url,
        index_digest=index.index_digest,
        fetched_at=datetime.now(timezone.utc).isoformat(),
        signer_fingerprint=index.signer_fingerprint,
        signature_verified=bool(index.signature),
        registry_count=len(index.registries),
        publisher_count=len(index.publishers),
        package_count=len(index.packages),
    )
    if profile:
        receipt.policy_profile_digest = profile.compute_digest()

    store = load_discovery_store()
    store.set(DiscoveryStoreEntry(
        index=index,
        fetched_at=datetime.now(timezone.utc).isoformat(),
        receipt=receipt,
    ))
    save_discovery_store(store)

    if as_json:
        
        click.echo(json.dumps(receipt.to_dict(), indent=2))
    else:
        console.print(f"[green]\u2705 Index '{index.index_id}' fetched[/green]")
        console.print(f"  Registries: {len(index.registries)}")
        console.print(f"  Digest: {index.index_digest[:16]}...")
    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@marketplace_cmd.command("search")
@click.option("--query", "-q", default="", help="Search query")
@click.option("--category", "-c", default="", help="Filter by category")
@click.option("--package", "-p", default="", help="Filter by package")
@click.option("--json", "as_json", is_flag=True, default=False)
def marketplace_search_cmd(query: str, category: str, package: str, as_json: bool) -> None:
    """Search discovered registries."""
    from nodechain.sdk.discovery import load_discovery_store, search_discovery_index
    store = load_discovery_store()
    results = []
    for entry in store.all_entries:
        results.extend(search_discovery_index(entry.index, query, category, package))
    if as_json:
        
        click.echo(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        if not results:
            console.print("[dim]No results[/dim]")
        else:
            for r in results:
                console.print(f"  {r.registry_id}: {r.display_name} ({r.base_url})")
    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@marketplace_cmd.command("inspect")
@click.argument("registry_id")
@click.option("--json", "as_json", is_flag=True, default=False)
def marketplace_inspect_cmd(registry_id: str, as_json: bool) -> None:
    """Inspect a discovered registry listing."""
    from nodechain.sdk.discovery import load_discovery_store
    store = load_discovery_store()
    found = None
    for entry in store.all_entries:
        for reg in entry.index.registries:
            if reg.registry_id == registry_id:
                found = reg
                break
    if not found:
        console.print(f"[red]\u274c Not found[/red]")
        ctx = click.get_current_context()
        ctx.exit(EXIT_NOT_FOUND)
        return
    if as_json:
        
        click.echo(json.dumps(found.to_dict(), indent=2))
    else:
        console.print(f"  ID: {found.registry_id}")
        console.print(f"  URL: {found.base_url}")
    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@marketplace_cmd.command("add-registry")
@click.argument("registry_id")
@click.option("--json", "as_json", is_flag=True, default=False)
def marketplace_add_registry_cmd(registry_id: str, as_json: bool) -> None:
    """Add a discovered registry to federation config."""
    from nodechain.sdk.discovery import (
        load_discovery_store, add_registry_from_discovery, MarketplacePolicyDenial,
    )
    from nodechain.sdk.federation import load_federation_config, save_federation_config
    from nodechain.sdk.org_policy import get_active_profile

    disc_store = load_discovery_store()
    found_listing = None
    found_index = None
    for entry in disc_store.all_entries:
        for reg in entry.index.registries:
            if reg.registry_id == registry_id:
                found_listing = reg
                found_index = entry.index
                break
    if not found_listing:
        console.print(f"[red]\u274c Not found[/red]")
        ctx = click.get_current_context()
        ctx.exit(EXIT_NOT_FOUND)
        return

    profile = get_active_profile()
    fed_store = load_federation_config()
    try:
        receipt = add_registry_from_discovery(found_listing, found_index, fed_store, profile)
        save_federation_config(fed_store)
    except MarketplacePolicyDenial as e:
        console.print(f"[red]\u274c Policy denied: {e}[/red]")
        ctx = click.get_current_context()
        ctx.exit(EXIT_TRUST_VIOLATION)
        return

    if as_json:
        
        click.echo(json.dumps(receipt.to_dict(), indent=2))
    else:
        console.print(f"[green]\u2705 Added '{registry_id}' (disabled)[/green]")
    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@marketplace_cmd.command("verify")
@click.option("--json", "as_json", is_flag=True, default=False)
def marketplace_verify_cmd(as_json: bool) -> None:
    """Verify all cached discovery indices."""
    from nodechain.sdk.discovery import load_discovery_store, verify_discovery_index
    store = load_discovery_store()
    all_issues = []
    for entry in store.all_entries:
        result = verify_discovery_index(entry.index)
        if not result.valid:
            for i in result.issues:
                all_issues.append(f"{entry.index.index_id}: {i}")
    if as_json:
        
        click.echo(json.dumps({"valid": len(all_issues) == 0, "issues": all_issues}, indent=2))
    else:
        if all_issues:
            console.print(f"[red]\u274c {len(all_issues)} issue(s)[/red]")
        else:
            console.print("[green]\u2705 All valid[/green]")
    ctx = click.get_current_context()
    ctx.exit(EXIT_OK if not all_issues else EXIT_VALIDATION)


# ── Supply Chain Attestation Commands (v2.8.0) ─────────────────────────────

@cli.group("supply-chain")
def supply_chain_cmd() -> None:
    """Supply chain attestation operations (v2.8.0).

    Attestation is evidence. Attestation is not automatic trust.
    """
    pass


@supply_chain_cmd.command("create")
@click.option("--artifact-digest", required=True, help="SHA-256 of the package artifact")
@click.option("--package", "package_name", required=True, help="Package name")
@click.option("--version", "package_version", required=True, help="Package version")
@click.option("--type", "attestation_type", default="build",
              type=click.Choice(["provenance", "build", "source", "vulnerability_scan", "license_scan", "sbom"]),
              help="Attestation type")
@click.option("--level", "attestation_level", default="build",
              type=click.Choice(["none", "source", "build", "provenance"]),
              help="Attestation level (SLSA-like)")
@click.option("--subject", default="", help="What the attestation covers")
@click.option("--issuer", default="", help="Issuer identity")
@click.option("--issuer-fingerprint", default="", help="Issuer key fingerprint")
@click.option("--output", "-o", default="", help="Output JSON path")
@click.option("--json", "as_json", is_flag=True, default=False)
def supply_chain_create_cmd(
    artifact_digest: str, package_name: str, package_version: str,
    attestation_type: str, attestation_level: str, subject: str,
    issuer: str, issuer_fingerprint: str, output: str, as_json: bool,
) -> None:
    """Create a supply chain attestation."""
    from nodechain.sdk.supply_chain_attestation import create_attestation
    att = create_attestation(
        artifact_digest=artifact_digest,
        package_name=package_name,
        package_version=package_version,
        attestation_type=attestation_type,
        attestation_level=attestation_level,
        subject=subject,
        issuer=issuer,
        issuer_fingerprint=issuer_fingerprint,
    )
    data = att.to_dict()
    if output:
        from pathlib import Path as _Path
        _Path(output).write_text(json.dumps(data, indent=2), encoding="utf-8")
    if as_json:
        click.echo(json.dumps(data, indent=2))
    else:
        console.print(f"[green]\u2705 Attestation created: {att.attestation_id}[/green]")
        console.print(f"  Package: {package_name}@{package_version}")
        console.print(f"  Type: {attestation_type} / Level: {attestation_level}")
        console.print(f"  Digest: {att.attestation_digest[:16]}...")
    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@supply_chain_cmd.command("verify")
@click.option("--attestation", "attestation_path", required=True, help="Path to attestation JSON")
@click.option("--pubkey", "public_key_path", default=None, help="Public key PEM for signature verification")
@click.option("--expected-issuer", default=None, help="Expected issuer fingerprint")
@click.option("--expected-digest", default=None, help="Expected artifact digest")
@click.option("--json", "as_json", is_flag=True, default=False)
def supply_chain_verify_cmd(
    attestation_path: str, public_key_path: str | None,
    expected_issuer: str | None, expected_digest: str | None, as_json: bool,
) -> None:
    """Verify a supply chain attestation."""
    from nodechain.sdk.supply_chain_attestation import (
        SupplyChainAttestation, verify_attestation,
    )
    
    data = json.loads(open(attestation_path, encoding="utf-8").read())
    att = SupplyChainAttestation.from_dict(data)
    public_key_pem = None
    if public_key_path:
        public_key_pem = open(public_key_path, encoding="utf-8").read()
    result = verify_attestation(
        att, public_key_pem=public_key_pem,
        expected_issuer_fingerprint=expected_issuer,
        expected_artifact_digest=expected_digest,
    )
    rd = result.to_dict()
    if as_json:
        click.echo(json.dumps(rd, indent=2))
    else:
        if result.valid:
            console.print(f"[green]\u2705 Valid: {result.reason}[/green]")
        else:
            console.print(f"[red]\u274c Invalid: {result.reason}[/red]")
    ctx = click.get_current_context()
    ctx.exit(EXIT_OK if result.valid else EXIT_VALIDATION)


@supply_chain_cmd.command("list")
@click.option("--package", "package_name", default="", help="Filter by package name")
@click.option("--json", "as_json", is_flag=True, default=False)
def supply_chain_list_cmd(package_name: str, as_json: bool) -> None:
    """List all stored attestations."""
    from nodechain.sdk.supply_chain_attestation import load_attestation_store
    import os
    store_path = os.environ.get("NODECHAIN_ATTESTATION_STORE", "data/attestation_store.json")
    store = load_attestation_store(store_path)
    if package_name:
        entries = store.find_for_package(package_name)
    else:
        entries = store.all_entries()
    if as_json:
        items = [e.attestation.to_dict() for e in entries]
        click.echo(json.dumps(items, indent=2))
    else:
        if not entries:
            console.print("[dim]No attestations found[/dim]")
        else:
            for e in entries:
                att = e.attestation
                console.print(f"  {att.attestation_id}  {att.package_name}@{att.package_version}  "
                            f"{att.attestation_type}/{att.attestation_level}")
    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@supply_chain_cmd.command("inspect")
@click.argument("attestation_id")
@click.option("--json", "as_json", is_flag=True, default=False)
def supply_chain_inspect_cmd(attestation_id: str, as_json: bool) -> None:
    """Inspect a specific attestation."""
    from nodechain.sdk.supply_chain_attestation import load_attestation_store
    import os
    store_path = os.environ.get("NODECHAIN_ATTESTATION_STORE", "data/attestation_store.json")
    store = load_attestation_store(store_path)
    entry = store.get(attestation_id)
    if entry is None:
        console.print(f"[red]Attestation '{attestation_id}' not found[/red]")
        ctx = click.get_current_context()
        ctx.exit(EXIT_NOT_FOUND)
    att = entry.attestation
    data = att.to_dict()
    if as_json:
        click.echo(json.dumps(data, indent=2))
    else:
        console.print(f"\n[bold]Attestation: {att.attestation_id}[/bold]")
        console.print(f"  Package: {att.package_name}@{att.package_version}")
        console.print(f"  Artifact: {att.artifact_digest[:16]}...")
        console.print(f"  Type: {att.attestation_type} / Level: {att.attestation_level}")
        console.print(f"  Issuer: {att.issuer} ({att.issuer_fingerprint[:16]}...)")
        console.print(f"  Issued: {att.issued_at}")
        if att.signature:
            console.print("  Signature: [green]present[/green]")
        else:
            console.print("  Signature: [dim]absent[/dim]")
        console.print(f"  Digest: {att.attestation_digest[:16]}...")
    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@cli.group()
def node() -> None:
    """Node package operations."""
    pass


# ── Artifact Retention Commands (v2.9.0) ──────────────────────────────────

@cli.group("retention")
def retention_cmd() -> None:
    """Artifact retention and evidence index operations (v2.9.0).

    Evidence index is derived from retained artifacts.
    Retained artifacts are not trusted merely because an index mentions them.
    """
    pass


@retention_cmd.command("retain")
@click.option("--file", "file_path", required=True, help="Path to file to retain")
@click.option("--media-type", default="application/octet-stream")
@click.option("--producer", default="")
@click.option("--subject", "subject_ref", default="")
@click.option("--source-type", default="")
@click.option("--store", "store_dir", default="data/artifacts", help="Artifact store directory")
@click.option("--json", "as_json", is_flag=True, default=False)
def retention_retain_cmd(file_path, media_type, producer, subject_ref, source_type, store_dir, as_json):
    """Retain an artifact in content-addressed storage."""
    from nodechain.sdk.artifact_retention import ContentAddressedStore
    store = ContentAddressedStore(store_dir)
    content = open(file_path, "rb").read()
    meta = store.retain(content, media_type=media_type, producer=producer,
                        subject_ref=subject_ref, source_type=source_type)
    data = meta.to_dict()
    if as_json:
        click.echo(json.dumps(data, indent=2))
    else:
        console.print(f"[green]\u2705 Artifact retained: {meta.digest[:16]}...[/green]")
        console.print(f"  Size: {meta.byte_size} bytes")
    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@retention_cmd.command("verify")
@click.option("--store", "store_dir", default="data/artifacts", help="Artifact store directory")
@click.option("--json", "as_json", is_flag=True, default=False)
def retention_verify_cmd(store_dir, as_json):
    """Verify evidence index and all artifact integrity."""
    from nodechain.sdk.artifact_retention import ContentAddressedStore
    store = ContentAddressedStore(store_dir)
    result = store.verify_integrity()
    if as_json:
        click.echo(json.dumps(result, indent=2))
    else:
        if result["valid"]:
            console.print(f"[green]\u2705 Index verified, {result['artifacts_checked']} artifacts checked[/green]")
        else:
            console.print(f"[red]\u274c Integrity issues found[/red]")
            for f in result.get("artifacts_failed", []):
                console.print(f"  Failed: {f[:16]}...")
            for m in result.get("missing", []):
                console.print(f"  Missing: {m[:16]}...")
    ctx = click.get_current_context()
    ctx.exit(EXIT_OK if result["valid"] else EXIT_VALIDATION)


@retention_cmd.command("manifest")
@click.option("--store", "store_dir", default="data/artifacts", help="Artifact store directory")
@click.option("--output", "-o", default="", help="Output manifest JSON path")
@click.option("--policy-digest", default="")
@click.option("--policy-id", default="")
@click.option("--json", "as_json", is_flag=True, default=False)
def retention_manifest_cmd(store_dir, output, policy_digest, policy_id, as_json):
    """Generate a retention manifest."""
    from nodechain.sdk.artifact_retention import (
        ContentAddressedStore, generate_manifest, save_manifest,
    )
    store = ContentAddressedStore(store_dir)
    manifest = generate_manifest(store, policy_profile_digest=policy_digest, retention_policy_id=policy_id)
    manifest_path = output or str(store.manifest_path)
    digest = save_manifest(manifest, manifest_path)
    data = manifest.to_dict()
    if as_json:
        click.echo(json.dumps(data, indent=2))
    else:
        console.print(f"[green]\u2705 Manifest generated: {digest[:16]}...[/green]")
        console.print(f"  Artifacts: {manifest.artifact_count}")
        console.print(f"  Total size: {manifest.total_byte_size} bytes")
    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@retention_cmd.command("gc")
@click.option("--store", "store_dir", default="data/artifacts", help="Artifact store directory")
@click.option("--policy-id", default="")
@click.option("--json", "as_json", is_flag=True, default=False)
def retention_gc_cmd(store_dir, policy_id, as_json):
    """Safely collect orphaned artifacts."""
    from nodechain.sdk.artifact_retention import ContentAddressedStore, collect_orphans
    store = ContentAddressedStore(store_dir)
    receipt = collect_orphans(store, retention_policy_id=policy_id)
    data = receipt.to_dict()
    if as_json:
        click.echo(json.dumps(data, indent=2))
    else:
        console.print(f"[green]\u2705 Collected {receipt.artifacts_removed} orphan(s)[/green]")
        console.print(f"  Freed: {receipt.bytes_freed} bytes")
    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@retention_cmd.command("list")
@click.option("--store", "store_dir", default="data/artifacts", help="Artifact store directory")
@click.option("--json", "as_json", is_flag=True, default=False)
def retention_list_cmd(store_dir, as_json):
    """List all retained artifacts."""
    from nodechain.sdk.artifact_retention import ContentAddressedStore
    store = ContentAddressedStore(store_dir)
    digests = store.list_artifacts()
    if as_json:
        click.echo(json.dumps(digests, indent=2))
    else:
        if not digests:
            console.print("[dim]No artifacts retained[/dim]")
        else:
            for d in digests:
                meta = store.get_metadata(d)
                size = meta.byte_size if meta else "?"
                console.print(f"  {d[:16]}...  {size} bytes")
    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@node.command("validate")
@click.argument("path")
def node_validate_cmd(path: str) -> None:
    """Validate a node package at the given path."""
    from nodechain.cli.sdk_cli import node_validate
    node_validate(path)


@node.command("test")
@click.argument("path")
def node_test_cmd(path: str) -> None:
    """Run package-local tests for a node package."""
    from nodechain.cli.sdk_cli import node_test
    node_test(path)


@node.command("create")
@click.argument("node_id")
@click.option("--template", "-t", default="deterministic",
              type=click.Choice(["deterministic", "model", "tool"]),
              help="Node template type")
@click.option("--output", "-o", default="nodes", help="Output directory")
@click.option("--name", "-n", default=None, help="Human-readable name")
@click.option("--tags", default=None, help="Comma-separated tags")
def node_create_cmd(node_id: str, template: str, output: str, name: str | None, tags: str | None) -> None:
    """Create a new node package from a template."""
    from nodechain.sdk.templates import create_node_package
    from nodechain.sdk.package import NodePackage

    try:
        pkg_path = create_node_package(
            node_id=node_id,
            template=template,
            output_dir=output,
            name=name,
            tags=tags,
        )
    except FileExistsError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(10)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(10)

    console.print(f"[green]Created node package:[/green] {pkg_path}")
    console.print(f"  Template:  {template}")
    console.print(f"  Node ID:   {node_id}")
    console.print(f"  Type:      {template}")
    console.print(f"\n  Files created:")
    for f in sorted(pkg_path.rglob("*")):
        if f.is_file():
            console.print(f"    {f.relative_to(pkg_path)}")

    # Validate the generated package
    try:
        pkg = NodePackage.from_directory(pkg_path)
        issues = pkg.validate_package()
        if issues:
            console.print(f"\n  [yellow]Validation warnings:[/yellow]")
            for issue in issues:
                console.print(f"    ! {issue}")
        else:
            console.print(f"\n  [green]Package validates successfully.[/green]")
    except Exception as e:
        console.print(f"\n  [red]Validation error: {e}[/red]")


@node.command("check-compat")
@click.argument("blueprint")
@click.argument("node_id")
@click.option("--path", "-p", multiple=True, help="Additional search paths")
def node_check_compat_cmd(blueprint: str, node_id: str, path: tuple[str, ...]) -> None:
    """Check node compatibility with a blueprint."""
    from nodechain.sdk.compat import check_blueprint_compat

    result = check_blueprint_compat(
        blueprint_path=blueprint,
        node_id=node_id,
        extra_paths=list(path) or None,
    )

    if "error" in result:
        console.print(f"[red]{result['error']}[/red]")
        sys.exit(2)

    status = "COMPATIBLE" if result["compatible"] else "INCOMPATIBLE"
    color = "green" if result["compatible"] else "red"

    console.print(f"[bold]Compatibility:[/bold] [{color}]{status}[/{color}]")
    console.print(f"  Node:       {result['node_id']}")
    console.print(f"  Blueprint:  {result['blueprint_id']}")
    console.print(f"  In blueprint: {'yes' if result['node_found_in_blueprint'] else 'no'}")
    console.print(f"  Connections: {result['compatible_connections']}/{result['connections_checked']} compatible")

    if result.get("issues"):
        console.print(f"\n  [red]Issues:[/red]")
        for issue in result["issues"]:
            console.print(f"    X {issue}")

    if result.get("warnings"):
        console.print(f"\n  [yellow]Warnings:[/yellow]")
        for warning in result["warnings"]:
            console.print(f"    ! {warning}")


@cli.group(name="checkpoint")
def checkpoint_group() -> None:
    """Signed evidence checkpoints and recovery verification (v2.10.0)."""
    pass


@checkpoint_group.command("create")
@click.option("--store-dir", default="data/evidence", help="Retention store directory")
@click.option("--chain-path", default="data/checkpoint_chain.json", help="Checkpoint chain file")
@click.option("--private-key", required=True, help="Private key PEM file path")
@click.option("--public-key", required=True, help="Public key PEM file path")
@click.option("--profile-digest", default="", help="Active policy profile digest")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def checkpoint_create_cmd(store_dir: str, chain_path: str, private_key: str, public_key: str, profile_digest: str, as_json: bool) -> None:
    """Create a signed evidence checkpoint."""
    from nodechain.sdk.artifact_retention import ContentAddressedStore
    from nodechain.sdk.evidence_checkpoint import CheckpointChain, create_checkpoint

    store = ContentAddressedStore(store_dir)
    chain = CheckpointChain(chain_path)
    priv_pem = Path(private_key).read_text()
    pub_pem = Path(public_key).read_text()

    cp = create_checkpoint(store, chain, priv_pem, pub_pem, profile_digest)

    if as_json:
        import json as _json
        click.echo(_json.dumps(cp.to_dict(), indent=2))
    else:
        console.print(f"[green]Checkpoint #{cp.sequence_number} created[/green]")
        console.print(f"  ID: {cp.checkpoint_id}")
        console.print(f"  Digest: {cp.checkpoint_digest[:32]}...")
        console.print(f"  Artifacts: {cp.artifact_count}")
        console.print(f"  Previous: {cp.previous_checkpoint_digest[:32] if cp.previous_checkpoint_digest else '(genesis)'}...")


@checkpoint_group.command("verify")
@click.option("--store-dir", default="data/evidence", help="Retention store directory")
@click.option("--chain-path", default="data/checkpoint_chain.json", help="Checkpoint chain file")
@click.option("--public-key", required=True, help="Public key PEM file path")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def checkpoint_verify_cmd(store_dir: str, chain_path: str, public_key: str, as_json: bool) -> None:
    """Verify latest checkpoint against current store state."""
    from nodechain.sdk.artifact_retention import ContentAddressedStore
    from nodechain.sdk.evidence_checkpoint import CheckpointChain, verify_checkpoint

    store = ContentAddressedStore(store_dir)
    chain = CheckpointChain(chain_path)
    pub_pem = Path(public_key).read_text()

    latest = chain.get_latest()
    if latest is None:
        console.print("[yellow]No checkpoints in chain[/yellow]")
        sys.exit(2)

    result = verify_checkpoint(latest, store, pub_pem)

    if as_json:
        import json as _json
        click.echo(_json.dumps({
            "checkpoint_id": result.checkpoint_id,
            "valid": result.valid,
            "signature_valid": result.signature_valid,
            "manifest_matches": result.manifest_matches,
            "missing": result.missing_artifacts,
            "corrupted": result.corrupted_artifacts,
        }, indent=2))
    else:
        status = "green]VALID[/green]" if result.valid else "red]INVALID[/red]"
        console.print(f"Checkpoint: [{status}")
        console.print(f"  Signature: {'OK' if result.signature_valid else 'FAILED'}")
        console.print(f"  Manifest:  {'OK' if result.manifest_matches else 'MISMATCH'}")
        if result.missing_artifacts:
            console.print(f"  Missing:   {len(result.missing_artifacts)}")
        if result.corrupted_artifacts:
            console.print(f"  Corrupted: {len(result.corrupted_artifacts)}")


@checkpoint_group.command("chain")
@click.option("--chain-path", default="data/checkpoint_chain.json", help="Checkpoint chain file")
@click.option("--public-key", required=True, help="Public key PEM file path")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def checkpoint_chain_cmd(chain_path: str, public_key: str, as_json: bool) -> None:
    """Verify checkpoint chain continuity and signatures."""
    from nodechain.sdk.evidence_checkpoint import CheckpointChain, verify_checkpoint_chain

    chain = CheckpointChain(chain_path)
    pub_pem = Path(public_key).read_text()

    result = verify_checkpoint_chain(chain, pub_pem)

    if as_json:
        import json as _json
        click.echo(_json.dumps({
            "chain_valid": result.chain_valid,
            "checkpoints_verified": result.checkpoints_verified,
            "signature_failures": result.signature_failures,
            "digest_failures": result.digest_failures,
            "continuity_breaks": result.continuity_breaks,
        }, indent=2))
    else:
        status = "green]VALID[/green]" if result.chain_valid else "red]BROKEN[/red]"
        console.print(f"Chain: [{status}")
        console.print(f"  Checkpoints: {result.checkpoints_verified}")
        if result.signature_failures:
            console.print(f"  Signature failures: {result.signature_failures}")
        if result.digest_failures:
            console.print(f"  Digest failures: {result.digest_failures}")
        if result.continuity_breaks:
            console.print(f"  Continuity breaks: {result.continuity_breaks}")


@checkpoint_group.command("recovery")
@click.option("--store-dir", default="data/evidence", help="Retention store directory")
@click.option("--chain-path", default="data/checkpoint_chain.json", help="Checkpoint chain file")
@click.option("--public-key", default="", help="Public key PEM file path")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def checkpoint_recovery_cmd(store_dir: str, chain_path: str, public_key: str, as_json: bool) -> None:
    """Generate a full recovery report."""
    from nodechain.sdk.artifact_retention import ContentAddressedStore
    from nodechain.sdk.evidence_checkpoint import CheckpointChain, generate_recovery_report

    store = ContentAddressedStore(store_dir)
    chain = CheckpointChain(chain_path) if Path(chain_path).exists() else None
    pub_pem = Path(public_key).read_text() if public_key else None

    report = generate_recovery_report(store, chain, pub_pem)

    if as_json:
        import json as _json
        click.echo(_json.dumps({
            "valid": report.valid,
            "checkpoint_verified": report.checkpoint_verified,
            "chain_continuous": report.chain_continuous,
            "manifest_intact": report.manifest_intact,
            "artifacts_available": report.artifacts_available,
            "recoverable_orphans": report.recoverable_orphans,
            "missing_artifacts": report.missing_artifacts,
            "corrupted_artifacts": report.corrupted_artifacts,
            "broken_chain_at": report.broken_chain_at,
            "checkpoint_sequence": report.checkpoint_sequence,
        }, indent=2))
    else:
        status = "green]HEALTHY[/green]" if report.valid else "red]ISSUES[/red]"
        console.print(f"Recovery: [{status}")
        console.print(f"  Manifest:   {'OK' if report.manifest_intact else 'BROKEN'}")
        console.print(f"  Artifacts:  {'OK' if report.artifacts_available else 'MISSING'}")
        console.print(f"  Digests:    {'OK' if report.artifact_digests_valid else 'CORRUPTED'}")
        if report.recoverable_orphans:
            console.print(f"  Orphans:    {len(report.recoverable_orphans)}")
        if report.checkpoint_verified:
            console.print(f"  Checkpoint: #{report.checkpoint_sequence} verified")
        elif chain:
            console.print(f"  Checkpoint: [red]ISSUES[/red]")
        if report.broken_chain_at:
            console.print(f"  Chain broken at: #{report.broken_chain_at}")


@cli.group(name="trust-store")
def trust_store_group() -> None:
    """Manage the local trust store for verifier profile signing keys."""
    pass


@trust_store_group.command("add-key")
@click.argument("name")
@click.argument("public_key_path")
@click.option("--purpose", "purposes", multiple=True,
              help="Allowed purpose (repeatable). Valid: verifier_profile_signing, adapter_manifest_signing, audit_bundle_signing, attestation_signing, receipt_signing")
def trust_store_add_key(name: str, public_key_path: str, purposes: tuple[str, ...]) -> None:
    """Add a trusted public key to the trust store."""
    from nodechain.cli.trust_store import add_key
    result = add_key(name, public_key_path, purposes=list(purposes) if purposes else None)
    console.print(f"[green]✅ Key added:[/green] {result['name']}")
    console.print(f"  Fingerprint: {result['fingerprint']}")
    console.print(f"  Purposes: {', '.join(result['purposes'])}")


@trust_store_group.command("list")
def trust_store_list_keys() -> None:
    """List all trusted keys in the trust store."""
    from nodechain.cli.trust_store import list_keys
    keys = list_keys()
    if not keys:
        console.print("[yellow]Trust store is empty.[/yellow]")
        return
    console.print(f"[bold]Trusted keys ({len(keys)}):[/bold]")
    for k in keys:
        purposes_str = ", ".join(k.get("allowed_purposes", []))
        legacy_marker = " [yellow](LEGACY: no explicit purposes)[/yellow]" if k.get("is_legacy") else ""
        console.print(
            f"  {k['name']:25s} {k['fingerprint']}  "
            f"purposes: [{purposes_str}]  added: {k['added_at'][:10]}{legacy_marker}"
        )


@trust_store_group.command("remove-key")
@click.argument("name")
def trust_store_remove_key(name: str) -> None:
    """Remove a trusted key from the trust store."""
    from nodechain.cli.trust_store import remove_key
    result = remove_key(name)
    if result["status"] == "removed":
        console.print(f"[green]✅ Key removed:[/green] {name}")
    else:
        console.print(f"[yellow]Key not found:[/yellow] {name}")


@trust_store_group.command("migrate")
@click.option("--purpose", "purposes", multiple=True,
              help="Purpose to assign to legacy keys (repeatable). Defaults to all.")
def trust_store_migrate(purposes: tuple[str, ...]) -> None:
    """Migrate legacy keys by adding explicit allowed_purposes (v1.10.5)."""
    from nodechain.cli.trust_store import migrate_legacy_keys
    result = migrate_legacy_keys(purposes=list(purposes) if purposes else None)
    if result["migrated"] == 0:
        console.print("[green]No legacy keys found. Trust store is already migrated.[/green]")
    else:
        console.print(f"[green]✅ Migrated {result['migrated']} legacy key(s):[/green]")
        for name in result["names"]:
            console.print(f"  {name}")
        console.print(f"  Purposes assigned: {', '.join(result['purposes'])}")


@trust_store_group.command("verify")
@click.option("--strict", is_flag=True, default=False, help="Treat warnings as errors")
def trust_store_verify(strict: bool) -> None:
    """Validate trust store integrity (v1.10.6)."""
    from nodechain.cli.trust_store import verify_trust_store
    result = verify_trust_store(strict=strict)

    if result["valid"]:
        console.print("[green]✅ Trust store is valid[/green]")
        for check, passed in result["checks"].items():
            icon = "✅" if passed else "⚠️"
            console.print(f"  {icon} {check}")
        if result["warnings"]:
            for w in result["warnings"]:
                console.print(f"  [yellow]⚠️  {w}[/yellow]")
        sys.exit(0)
    else:
        console.print("[red]❌ Trust store validation failed[/red]")
        for e in result["errors"]:
            console.print(f"  [red]  {e}[/red]")
        for check, passed in result["checks"].items():
            icon = "✅" if passed else "❌"
            console.print(f"  {icon} {check}")
        sys.exit(10)


@trust_store_group.command("snapshot")
@click.option("--output", "-o", default="", help="Output snapshot JSON path")
@click.option("--sign", "sign_key", default="", help="Sign snapshot with this private key PEM")
def trust_store_snapshot(output: str, sign_key: str) -> None:
    """Create a signed snapshot of the trust store state (v1.10.7)."""
    from nodechain.cli.trust_store import create_trust_store_snapshot
    snapshot = create_trust_store_snapshot(
        output_path=output,
        private_key_path=sign_key,
    )
    console.print(f"[green]\u2705 Trust store snapshot created[/green]")
    console.print(f"  trust_store_id: {snapshot['trust_store_id']}")
    console.print(f"  key_count: {snapshot['key_count']}")
    console.print(f"  entries_digest: {snapshot['entries_digest'][:16]}...")
    console.print(f"  audit_log_digest: {snapshot['audit_log_digest'][:16]}...")
    if snapshot.get("snapshot_signature"):
        console.print(f"  [green]Signed by: {snapshot['snapshot_signer_fingerprint']}[/green]")
    if output:
        console.print(f"  Written to: {output}")


@trust_store_group.command("verify-snapshot")
@click.argument("snapshot_path")
@click.option("--pubkey", "public_key_path", default="", help="Public key PEM for signature verification")
@click.option("--check-live", is_flag=True, default=False, help="Compare against current trust store")
def trust_store_verify_snapshot(snapshot_path: str, public_key_path: str, check_live: bool) -> None:
    """Verify a trust store snapshot (v1.10.7)."""
    from nodechain.cli.trust_store import verify_trust_store_snapshot
    pubkey_pem = ""
    if public_key_path:
        pubkey_pem = Path(public_key_path).read_text(encoding="utf-8")
    result = verify_trust_store_snapshot(
        snapshot_path=snapshot_path,
        public_key_pem=pubkey_pem,
        check_live_store=check_live,
    )
    if result["valid"]:
        console.print("[green]\u2705 Snapshot is valid[/green]")
        for check, val in result["details"].items():
            icon = "\u2705" if val else "\u26a0\ufe0f"
            console.print(f"  {icon} {check}: {val}")
        sys.exit(0)
    else:
        console.print("[red]\u274c Snapshot verification failed[/red]")
        for e in result["errors"]:
            console.print(f"  [red]  {e}[/red]")
        sys.exit(10)


@cli.group(name="deploy-receipt")
def deploy_receipt_group() -> None:
    """Create or verify deployment receipts."""
    pass


@deploy_receipt_group.command("create")
@click.option("--attestation", "attestation_path", required=True, help="Path to attestation JSON")
@click.option("--profile", "profile_path", default="", help="Path to verifier profile JSON")
@click.option("--output", "-o", default="", help="Output receipt JSON path")
@click.option("--sign", "sign_key", default="", help="Sign receipt with this private key PEM")
def deploy_receipt_create(
    attestation_path: str,
    profile_path: str,
    output: str,
    sign_key: str,
) -> None:
    """Create a deployment receipt from a verified attestation."""
    from nodechain.cli.deploy_receipt import create_receipt
    receipt = create_receipt(
        attestation_path=attestation_path,
        profile_path=profile_path,
        output=output,
        sign_key=sign_key,
    )
    status = "ALLOWED" if receipt["deploy_allowed"] else "DENIED"
    color = "green" if receipt["deploy_allowed"] else "red"
    console.print(f"[bold]Deployment gate:[/bold] [{color}]{status}[/{color}]")
    console.print(f"  Receipt ID:    {receipt['receipt_id']}")
    console.print(f"  Attestation:   {receipt['attestation_digest'][:16]}...")
    if receipt.get("verifier_profile_digest"):
        console.print(f"  Profile:       {receipt['verifier_profile_digest'][:16]}...")
    console.print(f"  Deploy:        {receipt['deploy_allowed']}")
    if receipt.get("denial_reason"):
        console.print(f"  Denial reason: {receipt['denial_reason']}")
    console.print(f"  Signed:        {bool(receipt.get('receipt_signature'))}")
    if output:
        console.print(f"  Written to:    {output}")


@deploy_receipt_group.command("verify")
@click.argument("receipt_path")
@click.option("--pubkey", "pubkey_path", default="", help="Public key PEM for signature verification")
@click.option("--strict", is_flag=True, default=False, help="Exit 15 if deploy_allowed is false")
@click.option("--expect-attestation-digest", default="", help="Expected attestation SHA-256")
@click.option("--expect-profile-digest", default="", help="Expected profile SHA-256")
def deploy_receipt_verify(
    receipt_path: str,
    pubkey_path: str,
    strict: bool,
    expect_attestation_digest: str,
    expect_profile_digest: str,
) -> None:
    """Verify a deployment receipt."""
    from nodechain.cli.deploy_receipt import verify_receipt
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION, EXIT_TRUST_VIOLATION

    result = verify_receipt(
        receipt_path,
        pubkey_path=pubkey_path,
        strict=strict,
        expected_attestation_digest=expect_attestation_digest,
        expected_profile_digest=expect_profile_digest,
    )

    if result["valid"]:
        console.print(f"[green]✅ Receipt valid: {receipt_path}[/green]")
        for check, val in result.get("checks", {}).items():
            console.print(f"  {check}: {val}")
        for w in result["warnings"]:
            console.print(f"  WARN: {w}")
        ctx = click.get_current_context()
        ctx.exit(EXIT_OK)
    else:
        console.print(f"[red]❌ Receipt invalid: {receipt_path}[/red]")
        for e in result["errors"]:
            console.print(f"  ERROR: {e}")
        for w in result["warnings"]:
            console.print(f"  WARN: {w}")
        ctx = click.get_current_context()
        # Distinguish strict deny from invalid
        if strict and result.get("checks", {}).get("deploy_allowed") is False:
            ctx.exit(EXIT_TRUST_VIOLATION)
        ctx.exit(EXIT_VALIDATION)


@cli.command(name="assurance")
@click.option("--bundle", "bundle_path", default="", help="Audit bundle ZIP")
@click.option("--attestation", "attestation_path", default="", help="Attestation JSON")
@click.option("--profile", "profile_path", default="", help="Verifier profile JSON")
@click.option("--receipt", "receipt_path", default="", help="Deployment receipt JSON")
@click.option("--pubkey", "pubkey_path", default="", help="Public key PEM for signature verification")
@click.option("--require-signatures", is_flag=True, default=False, help="Require all artifacts to be signed")
@click.option("--strict", is_flag=True, default=False, help="Exit 15 if deploy_allowed is false")
@click.option("--trust-store", is_flag=True, default=False, help="Verify profile signature against local trust store")
def assurance_cmd(
    bundle_path: str,
    attestation_path: str,
    profile_path: str,
    receipt_path: str,
    pubkey_path: str,
    require_signatures: bool,
    strict: bool,
    trust_store: bool,
) -> None:
    """Verify the entire assurance chain in one command.

    Cross-checks digests between artifacts and verifies all signatures.
    Produces one final verdict: valid/invalid + deploy_allowed/denied.
    """
    from nodechain.cli.assurance import verify_assurance_chain
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION, EXIT_TRUST_VIOLATION

    result = verify_assurance_chain(
        bundle_path=bundle_path,
        attestation_path=attestation_path,
        profile_path=profile_path,
        receipt_path=receipt_path,
        pubkey_path=pubkey_path,
        require_signatures=require_signatures,
        strict=strict,
        use_trust_store=trust_store,
    )

    # Print stage-by-stage results
    for stage in result["stages"]:
        icon = "✅" if stage["status"] else "❌"
        detail = f" — {stage['detail']}" if stage["detail"] else ""
        console.print(f"  {icon} {stage['stage']}{detail}")

    if result["assurance_chain_valid"]:
        deploy = result["deploy_allowed"]
        verdict = "ALLOWED" if deploy else "DENIED"
        color = "green" if deploy else "red"
        console.print(f"\n[bold]Assurance chain:[/bold] VALID")
        console.print(f"[bold]Deployment:[/bold] [{color}]{verdict}[/{color}]")
        if result["denial_reason"]:
            console.print(f"  Reason: {result['denial_reason']}")
        for w in result["warnings"]:
            console.print(f"  WARN: {w}")
        ctx = click.get_current_context()
        ctx.exit(EXIT_OK)
    else:
        console.print(f"\n[red]❌ Assurance chain INVALID[/red]")
        for e in result["errors"]:
            console.print(f"  ERROR: {e}")
        for w in result["warnings"]:
            console.print(f"  WARN: {w}")
        if strict and not result["deploy_allowed"]:
            console.print(f"\n[red]Deployment DENIED (strict mode)[/red]")
            ctx = click.get_current_context()
            ctx.exit(EXIT_TRUST_VIOLATION)
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)


@cli.command(name="deploy")
@click.option("--receipt", "gate_receipt_path", default="", help="Gate receipt JSON from deploy-receipt")
@click.option("--adapter", default="dry-run", help="Deployment adapter name")
@click.option("--output", "-o", default="", help="Output deployment receipt JSON")
@click.option("--sign", "sign_key", default="", help="Sign deployment receipt with private key PEM")
@click.option("--verify", "verify_path", default=None, help="Verify a deployment receipt")
@click.option("--pubkey", "pubkey_path", default="", help="Public key PEM for signature verification")
@click.option("--strict", is_flag=True, default=False, help="Exit 15 if deploy status != accepted")
@click.option("--gate-receipt", "expected_gate_receipt_path", default="", help="Gate receipt to cross-check")
@click.option("--manifest", "manifest_path", default="", help="Adapter manifest JSON (v1.10.1)")
@click.option("--require-adapter-manifest-signature", is_flag=True, default=False, help="Require manifest signed by trusted key (v1.10.3)")
@click.option("--strict-trust-store", is_flag=True, default=False, help="Reject legacy keys without explicit purposes (v1.10.5)")
@click.option("--require-trust-store-snapshot", "snapshot_path", default="", help="Require valid trust store snapshot (v1.10.7)")
@click.option("--dry-run-policy-check", is_flag=True, default=False, help="Validate manifest/action/secret/TLS/target without mutation (v1.12.7)")
@click.option("--require-previous-assurance-chain", is_flag=True, default=False, help="Require full prior assurance chain for rollback (v1.13.5)")
@click.option("--require-release-history-snapshot", "rh_snapshot_path", default="", help="Require valid release history snapshot (v1.13.8)")
def deploy_cmd(
    gate_receipt_path: str,
    adapter: str,
    output: str,
    sign_key: str,
    verify_path: str | None,
    pubkey_path: str,
    strict: bool,
    expected_gate_receipt_path: str,
    manifest_path: str,
    require_adapter_manifest_signature: bool,
    strict_trust_store: bool,
    snapshot_path: str,
    dry_run_policy_check: bool,
    require_previous_assurance_chain: bool,
    rh_snapshot_path: str,
) -> None:
    """Deploy via an adapter or verify a deployment-system receipt.

    Deploy:   nodechain deploy --receipt gate_receipt.json --adapter dry-run
    Verify:   nodechain deploy --verify deploy_receipt.json --pubkey pub.pem
    """
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION, EXIT_TRUST_VIOLATION

    if verify_path:
        from nodechain.cli.deployment_adapter import verify_deployment_receipt
        result = verify_deployment_receipt(
            verify_path,
            pubkey_path=pubkey_path,
            strict=strict,
            expected_gate_receipt_path=expected_gate_receipt_path,
        )
        if result["valid"]:
            console.print(f"[green]✅ Deployment receipt valid: {verify_path}[/green]")
            for check, val in result.get("checks", {}).items():
                console.print(f"  {check}: {val}")
            ctx = click.get_current_context()
            ctx.exit(EXIT_OK)
        else:
            console.print(f"[red]❌ Deployment receipt invalid: {verify_path}[/red]")
            for e in result["errors"]:
                console.print(f"  ERROR: {e}")
            if strict and result.get("checks", {}).get("deploy_status") != "accepted":
                ctx = click.get_current_context()
                ctx.exit(EXIT_TRUST_VIOLATION)
            ctx = click.get_current_context()
            ctx.exit(EXIT_VALIDATION)
    else:
        from nodechain.cli.deployment_adapter import create_deployment_receipt, list_adapters
        try:
            receipt = create_deployment_receipt(
                gate_receipt_path=gate_receipt_path,
                adapter_name=adapter,
                output=output,
                sign_key=sign_key,
                manifest_path=manifest_path,
                strict=strict,
                require_manifest_signature=require_adapter_manifest_signature,
                strict_trust_store=strict_trust_store,
                snapshot_path=snapshot_path,
                dry_run_policy_check=dry_run_policy_check,
                require_previous_assurance_chain=require_previous_assurance_chain,
                rh_snapshot_path=rh_snapshot_path,
            )
            status = receipt["deploy_status"].upper()
            color = "green" if receipt["deploy_status"] == "accepted" else "red"
            console.print(f"[bold]Deployment system:[/bold] {receipt['deployment_system']}")
            console.print(f"  Status:        [{color}]{status}[/{color}]")
            console.print(f"  Target:        {receipt['target']}")
            console.print(f"  Deployer:      {receipt['deployer_identity']}")
            console.print(f"  Receipt ID:    {receipt['deployment_receipt_id']}")
            if receipt.get("receipt_signature"):
                console.print(f"  Signed:        yes")
            if output:
                console.print(f"  Written to:    {output}")
        except Exception as exc:
            console.print(f"[red]Error: {exc}[/red]")
            ctx = click.get_current_context()
            ctx.exit(EXIT_VALIDATION)


# v2.79: release-history relocated to cli/commands/release_history.py (register call below)


# ── v1.14.0: Drift Detection Commands ─────────────────────────────────────

@cli.group(name="drift")
def drift_group() -> None:
    """Deployment drift detection (v1.14.0)."""


@drift_group.group(name="policy")
def drift_policy_group() -> None:
    """Drift policy management (v1.14.2)."""


@drift_policy_group.command(name="sign")
@click.option("--policy", "policy_path", required=True, help="Drift policy JSON to sign")
@click.option("--key", "key_path", required=True, help="Private key PEM")
@click.option("--output", "-o", default="", help="Output signed policy JSON (default: overwrite input)")
def drift_policy_sign_cmd(policy_path: str, key_path: str, output: str) -> None:
    """Sign a drift policy with RSA-PSS-SHA256 (v1.14.2)."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION
    from nodechain.cli.drift_detection import sign_drift_policy

    try:
        signed = sign_drift_policy(policy_path, key_path, output_path=output)
        console.print(f"[green]✅ Drift policy signed[/green]")
        console.print(f"  Digest:     {signed.get('policy_digest', '')[:16]}...")
        console.print(f"  Fingerprint: {signed.get('policy_signer_fingerprint', '')}")
        console.print(f"  Algorithm:  {signed.get('policy_signature_algorithm', '')}")
    except Exception as e:
        console.print(f"[red]❌ Failed to sign policy: {e}[/red]")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@drift_policy_group.command(name="verify")
@click.option("--policy", "policy_path", required=True, help="Signed drift policy JSON")
@click.option("--pubkey", default="", help="Public key PEM for verification")
@click.option("--trust-store", "ts_path", default="", help="Trust store path")
def drift_policy_verify_cmd(policy_path: str, pubkey: str, ts_path: str) -> None:
    """Verify a signed drift policy (v1.14.2)."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION
    from nodechain.cli.drift_detection import verify_drift_policy_signature

    result = verify_drift_policy_signature(
        policy_path=policy_path,
        public_key_pem=pubkey,
        trust_store_path=ts_path,
    )
    if result["valid"]:
        console.print(f"[green]✅ Policy signature valid[/green]")
        console.print(f"  Status:      {result['details']['signature_status']}")
        console.print(f"  Fingerprint: {result['details']['signer_fingerprint']}")
        console.print(f"  Trusted:     {result['details']['signer_trusted']}")
    else:
        console.print(f"[red]❌ Policy signature invalid[/red]")
        for err in result["errors"]:
            console.print(f"  Error: {err}")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@drift_policy_group.command(name="register")
@click.option("--policy", "policy_path", required=True, help="Drift policy JSON to register")
def drift_policy_register_cmd(policy_path: str) -> None:
    """Register a drift policy in the local registry (v1.14.3)."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION
    from nodechain.cli.drift_policy_registry import register_policy

    try:
        result = register_policy(policy_path=policy_path)
        console.print(f"[green]✅ Policy registered[/green]")
        console.print(f"  ID:       {result['policy_id']}")
        console.print(f"  Version:  {result['policy_version']}")
        console.print(f"  Digest:   {result['policy_digest'][:16]}...")
    except Exception as e:
        console.print(f"[red]❌ Failed to register: {e}[/red]")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@drift_policy_group.command(name="list")
def drift_policy_list_cmd() -> None:
    """List all registered drift policies (v1.14.3)."""
    from nodechain.cli.exit_codes import EXIT_OK
    from nodechain.cli.drift_policy_registry import list_policies

    policies = list_policies()
    if not policies:
        console.print("[dim]No drift policies registered[/dim]")
    else:
        for p in policies:
            status_color = "green" if p["policy_status"] == "active" else "red"
            console.print(f"  [{status_color}]{p['policy_status']}[/] {p['policy_id']} v{p['policy_version']}")

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@drift_policy_group.command(name="revoke")
@click.option("--policy-id", required=True, help="Policy ID to revoke")
def drift_policy_revoke_cmd(policy_id: str) -> None:
    """Revoke a registered drift policy (v1.14.3)."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION
    from nodechain.cli.drift_policy_registry import revoke_policy

    result = revoke_policy(policy_id)
    if result["status"] == "revoked":
        console.print(f"[green]✅ Policy revoked: {policy_id}[/green]")
    else:
        console.print(f"[red]❌ Policy not found: {policy_id}[/red]")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@drift_policy_group.command(name="verify-registry")
@click.option("--policy-id", required=True, help="Policy ID to verify in registry")
@click.option("--policy-digest", default="", help="Expected policy digest")
def drift_policy_verify_registry_cmd(policy_id: str, policy_digest: str) -> None:
    """Verify a policy is registered and active (v1.14.3)."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION
    from nodechain.cli.drift_policy_registry import verify_policy_in_registry

    result = verify_policy_in_registry(policy_id=policy_id, policy_digest=policy_digest)
    if result["registered"] and result["active"] and result["digest_matches"]:
        console.print(f"[green]✅ Policy verified in registry[/green]")
        console.print(f"  ID:       {policy_id}")
        console.print(f"  Status:   {result['entry']['policy_status']}")
    else:
        console.print(f"[red]❌ Policy verification failed[/red]")
        if not result["registered"]:
            console.print(f"  Not registered")
        if not result["active"]:
            console.print(f"  Not active")
        if not result["digest_matches"]:
            console.print(f"  Digest mismatch")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@drift_group.command(name="remediate")
@click.option("--target", required=True, help="Target identifier (e.g., pve1/801)")
@click.option("--policy", "rem_policy_path", default="", help="Remediation policy JSON")
@click.option("--drift-report", "report_path", default="", help="Drift report JSON")
@click.option("--release-history", "rh_path", default="", help="Release history path")
@click.option("--release-history-snapshot", "snap_path", default="", help="Release history snapshot path")
@click.option("--trust-store", "ts_path", default="", help="Trust store path")
@click.option("--sign", "sign_key", default="", help="Sign remediation receipt with private key PEM")
@click.option("--output", "-o", default="", help="Output remediation receipt JSON")
@click.option("--strict", is_flag=True, default=False, help="Strict mode: exit 15 on denial/failure")
def drift_remediate_cmd(
    target: str,
    rem_policy_path: str,
    report_path: str,
    rh_path: str,
    snap_path: str,
    ts_path: str,
    sign_key: str,
    output: str,
    strict: bool,
) -> None:
    """Perform governed drift remediation (v1.15.0)."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION, EXIT_TRUST_VIOLATION
    from nodechain.cli.drift_remediation import remediate_drift, create_remediation_receipt, RemediationPolicy

    policy = RemediationPolicy.from_file(rem_policy_path) if rem_policy_path else None

    result = remediate_drift(
        target=target,
        drift_report_path=report_path,
        remediation_policy=policy,
        release_history_path=rh_path,
        release_history_snapshot_path=snap_path,
        trust_store_path=ts_path,
        strict=strict,
    )

    receipt = create_remediation_receipt(result, output_path=output, private_key_path=sign_key)

    if result["final_state"] == "no_remediation_needed":
        console.print(f"[green]✅ No remediation needed for {target}[/green]")
    elif result["final_state"] == "recommendation_produced":
        console.print(f"[yellow]📋 Remediation recommendation for {target}[/yellow]")
        console.print(f"  Action:  {result['selected_action']}")
        console.print(f"  Release: {result.get('selected_release_id', 'N/A')}")
        console.print(f"  Mode:    {result['remediation_mode']}")
    elif result["final_state"] == "rolled_back":
        console.print(f"[green]✅ Remediation completed for {target}[/green]")
        console.print(f"  Action:  {result['selected_action']}")
        console.print(f"  Release: {result.get('selected_release_id', 'N/A')}")
    elif result["final_state"] in ("denied", "failed"):
        console.print(f"[red]❌ Remediation {result['final_state']} for {target}[/red]")
        console.print(f"  Reason: {result.get('denial_reason', 'unknown')}")
        if strict:
            ctx = click.get_current_context()
            ctx.exit(EXIT_TRUST_VIOLATION)
    elif result["final_state"] == "manual_intervention_required":
        console.print(f"[yellow]⚠️  Manual intervention required for {target}[/yellow]")
    elif result["final_state"] == "drift_detected":
        console.print(f"[yellow]⚠️  Drift detected on {target}[/yellow]")

    if output:
        console.print(f"  Written: {output}")
    console.print(f"  ID:      {receipt['remediation_id']}")

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@drift_group.command(name="check")
@click.option("--target", required=True, help="Target identifier (e.g., pve1/801)")
@click.option("--release-id", default="", help="Release ID to check against (default: latest known-good)")
@click.option("--release-history", "rh_path", default="", help="Release history file path")
@click.option("--observed-artifact", "obs_artifact", default="", help="Observed artifact digest")
@click.option("--observed-service-state", "obs_state", default="", help="Observed service state")
@click.option("--observed-target", "obs_target", default="", help="Observed target identity")
@click.option("--policy", "policy_path", default="", help="Drift policy JSON file (v1.14.1)")
@click.option("--require-policy-signature", is_flag=True, default=False, help="Require signed policy verified against trust store (v1.14.2)")
@click.option("--trust-store", "ts_path", default="", help="Trust store path for policy signature verification")
@click.option("--sign", "sign_key", default="", help="Sign drift report with private key PEM")
@click.option("--output", "-o", default="", help="Output drift report JSON")
@click.option("--strict", is_flag=True, default=False, help="Exit 15 on drift, 10 on invalid")
def drift_check_cmd(
    target: str,
    release_id: str,
    rh_path: str,
    obs_artifact: str,
    obs_state: str,
    obs_target: str,
    policy_path: str,
    require_policy_sig: bool,
    ts_path: str,
    sign_key: str,
    output: str,
    strict: bool,
) -> None:
    """Check for deployment drift against release history."""
    from nodechain.cli.exit_codes import EXIT_OK, EXIT_VALIDATION, EXIT_TRUST_VIOLATION
    from nodechain.cli.drift_detection import check_drift, create_drift_report, DriftPolicy

    policy = policy_path if policy_path else None
    if strict and isinstance(policy, str):
        # Load to set strict_mode, but pass path for signature verification
        loaded = DriftPolicy.from_file(policy)
        loaded.strict_mode = True
        # Write the strict policy back temporarily
        # Actually just pass through the path and strict flag

    result = check_drift(
        target=target,
        release_id=release_id,
        release_history_path=rh_path,
        observed_artifact_digest=obs_artifact,
        observed_service_state=obs_state,
        observed_target_identity=obs_target,
        policy=policy,
        require_policy_signature=require_policy_sig,
        trust_store_path=ts_path,
    )

    # If strict flag set, mark drift on required failures
    if strict and result.get("valid") and not result["drift_detected"]:
        if result.get("policy_required_failures_count", 0) > 0:
            result["drift_detected"] = True

    if not result.get("valid", True):
        console.print(f"[red]❌ Drift check invalid: {result.get('error', 'unknown')}[/red]")
        ctx = click.get_current_context()
        ctx.exit(EXIT_VALIDATION)

    # Create report
    report = create_drift_report(result, output_path=output, private_key_path=sign_key)

    if result["drift_detected"]:
        console.print(f"[red]⚠️  Drift detected on {target}![/red]")
        console.print(f"  Release:      {result['release_id']}")
        console.print(f"  Drift fields: {', '.join(result['drift_fields'])}")
        for field in result["drift_fields"]:
            exp = result["expected_values"].get(field, "")
            obs = result["observed_values"].get(field, "")
            console.print(f"    {field}: expected={exp[:20]}... observed={obs[:20]}...")
        # v1.14.1: Show evidence strength summary
        if "evidence_strength_summary" in result:
            ess = result["evidence_strength_summary"]
            console.print(f"  Evidence:     observed={ess.get('observed',0)} verified={ess.get('verified',0)} inferred={ess.get('inferred',0)} unavailable={ess.get('unavailable',0)}")
        if result.get("required_field_failures"):
            console.print(f"  Failures:     {len(result['required_field_failures'])} required field failure(s)")
            for fail in result["required_field_failures"]:
                console.print(f"    {fail['field']}: {fail['failure_type']}")
        console.print(f"  Report ID:    {report['report_id']}")
        if report.get("report_signature"):
            console.print(f"  Signed:       yes")
        if strict:
            ctx = click.get_current_context()
            ctx.exit(EXIT_TRUST_VIOLATION)
    else:
        console.print(f"[green]✅ No drift detected on {target}[/green]")
        console.print(f"  Release:      {result['release_id']}")
        console.print(f"  Checked at:   {result['checked_at'][:19]}")
        # v1.14.1: Show evidence strength summary
        if "evidence_strength_summary" in result:
            ess = result["evidence_strength_summary"]
            console.print(f"  Evidence:     observed={ess.get('observed',0)} verified={ess.get('verified',0)} inferred={ess.get('inferred',0)} unavailable={ess.get('unavailable',0)}")
        if output:
            console.print(f"  Written to:   {output}")

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


# v2.80: eval group (incl. suite, certification subgroups) relocated to cli/commands/eval.py


# ── v1.17.0: Evidence and Trace Replay ─────────────────────────────────────
# v2.79: evidence group relocated to cli/commands/evidence.py (register call below)
# v2.86: trace-replay group relocated to cli/commands/trace_replay.py (register call below)


# v2.79: dashboard relocated to cli/commands/dashboard.py (register call below)


# v2.86: compose group relocated to cli/commands/compose.py (register call below)


# ── Policy Profile Commands (v2.4.0) ──────────────────────────────────────


@cli.group("policy")
def policy() -> None:
    """Organization trust policy profile operations (v2.4.0)."""
    pass


@policy.group("profiles", invoke_without_command=True)
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON")
@click.pass_context
def policy_profiles(ctx: click.Context, as_json: bool) -> None:
    """Organization trust policy profile operations."""
    if ctx.invoked_subcommand is None:
        # Default: list profiles
        ctx.invoke(policy_profiles_list_cmd, as_json=as_json)


@policy_profiles.command("list")
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON")
def policy_profiles_list_cmd(as_json: bool) -> None:
    """List built-in and active policy profiles."""
    from nodechain.sdk.org_policy import list_builtin_profiles, get_active_profile, get_active_profile_receipt
    

    builtins = list_builtin_profiles()
    active = get_active_profile()
    active_receipt = get_active_profile_receipt()

    if as_json:
        print(json.dumps({
            "built_in": builtins,
            "active": active.name if active else None,
            "active_digest": active_receipt.profile_digest if active_receipt else None,
        }, indent=2))
    else:
        console.print("[bold]Built-in Profiles:[/bold]")
        for name in builtins:
            marker = " [green](active)[/green]" if active and active.name == name else ""
            console.print(f"  \u2022 {name}{marker}")
        if active and active.name not in builtins:
            console.print(f"  \u2022 {active.name} [green](active, custom)[/green]")
        if not active:
            console.print("[yellow]  No active profile[/yellow]")

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@policy_profiles.command("show")
@click.argument("name")
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON")
def policy_profiles_show_cmd(name: str, as_json: bool) -> None:
    """Show details of a policy profile."""
    from nodechain.sdk.org_policy import get_builtin_profile, get_active_profile
    

    profile = get_builtin_profile(name)
    if not profile:
        # Check if it's the active profile name
        active = get_active_profile()
        if active and active.name == name:
            profile = active
        else:
            console.print(f"[red]Profile '{name}' not found[/red]")
            ctx = click.get_current_context()
            ctx.exit(EXIT_NOT_FOUND)
            return

    digest = profile.compute_digest()

    if as_json:
        d = profile.to_dict()
        d["digest"] = digest
        print(json.dumps(d, indent=2, sort_keys=True))
    else:
        console.print(f"[bold]{profile.name}[/bold] (v{profile.version})")
        console.print(f"  {profile.description}")
        console.print(f"  Digest:     {digest[:16]}...")
        console.print(f"\n[bold]Policy Surfaces:[/bold]")
        console.print(f"  Trust levels:             {', '.join(profile.allowed_trust_levels)}")
        console.print(f"  Remote registry:          {'allowed' if profile.allow_remote_registry else 'denied'}")
        console.print(f"  Registry signing:         {'required' if profile.require_registry_metadata_signing else 'not required'}")
        console.print(f"  Package signing:          {'required' if profile.require_package_signing else 'not required'}")
        console.print(f"  Certification:            {'required' if profile.require_certification else 'not required'}")
        console.print(f"  Transparency logging:     {'required' if profile.require_transparency_logging else 'not required'}")
        console.print(f"  Dependency resolution:    {'allowed' if profile.allow_dependency_resolution else 'denied'}")
        console.print(f"  Lockfile:                 {'required' if profile.require_lockfile else 'not required'}")
        console.print(f"  Sandbox minimum:          {profile.sandbox_minimum}")
        console.print(f"  Deployment:               {'allowed' if profile.allow_deployment else 'denied'}")
        if profile.required_eval_suites:
            console.print(f"  Required eval suites:     {', '.join(profile.required_eval_suites)}")
        if profile.required_key_purposes:
            console.print(f"  Required key purposes:    {', '.join(profile.required_key_purposes)}")

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@policy_profiles.command("validate")
@click.argument("name")
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON")
def policy_profiles_validate_cmd(name: str, as_json: bool) -> None:
    """Validate a built-in policy profile."""
    from nodechain.sdk.org_policy import get_builtin_profile, validate_profile
    

    profile = get_builtin_profile(name)
    if not profile:
        console.print(f"[red]Profile '{name}' not found[/red]")
        ctx = click.get_current_context()
        ctx.exit(EXIT_NOT_FOUND)
        return

    errors = validate_profile(profile)

    if as_json:
        print(json.dumps({
            "name": name,
            "valid": len(errors) == 0,
            "errors": errors,
        }, indent=2))
    else:
        if errors:
            console.print(f"[red]\u274c Profile '{name}' has {len(errors)} error(s)[/red]")
            for err in errors:
                console.print(f"  \u2022 {err}")
        else:
            console.print(f"[green]\u2705 Profile '{name}' is valid[/green]")

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK if not errors else EXIT_VALIDATION)


@policy_profiles.command("apply")
@click.argument("name")
@click.option("--by", "applied_by", default="", help="Applied by (operator name)")
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON")
def policy_profiles_apply_cmd(name: str, applied_by: str, as_json: bool) -> None:
    """Apply a policy profile as the active organizational policy."""
    from nodechain.sdk.org_policy import get_builtin_profile, apply_profile
    

    profile = get_builtin_profile(name)
    if not profile:
        console.print(f"[red]Profile '{name}' not found[/red]")
        ctx = click.get_current_context()
        ctx.exit(EXIT_NOT_FOUND)
        return

    receipt = apply_profile(profile, applied_by=applied_by)

    if as_json:
        print(json.dumps(receipt.to_dict(), indent=2))
    else:
        console.print(f"[green]\u2705 Profile '{name}' applied[/green]")
        console.print(f"  Digest:    {receipt.profile_digest[:16]}...")
        console.print(f"  Applied:   {receipt.applied_at}")
        if receipt.previous_profile_digest:
            console.print(f"  Previous:  {receipt.previous_profile_digest[:16]}...")
        if receipt.affected_surfaces:
            console.print(f"  Affected:  {', '.join(receipt.affected_surfaces)}")

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


@policy_profiles.command("diff")
@click.argument("profile_a")
@click.argument("profile_b")
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON")
def policy_profiles_diff_cmd(profile_a: str, profile_b: str, as_json: bool) -> None:
    """Show differences between two policy profiles."""
    from nodechain.sdk.org_policy import get_builtin_profile, diff_profiles
    

    a = get_builtin_profile(profile_a)
    b = get_builtin_profile(profile_b)
    if not a:
        console.print(f"[red]Profile '{profile_a}' not found[/red]")
        ctx = click.get_current_context()
        ctx.exit(EXIT_NOT_FOUND)
        return
    if not b:
        console.print(f"[red]Profile '{profile_b}' not found[/red]")
        ctx = click.get_current_context()
        ctx.exit(EXIT_NOT_FOUND)
        return

    diff = diff_profiles(a, b)

    if as_json:
        print(json.dumps(diff, indent=2, sort_keys=True))
    else:
        if not diff:
            console.print(f"[green]No differences between '{profile_a}' and '{profile_b}'[/green]")
        else:
            console.print(f"[bold]Differences ({profile_a} → {profile_b}):[/bold]")
            for field, values in diff.items():
                console.print(f"  {field}:")
                console.print(f"    {profile_a}: {values['a']}")
                console.print(f"    {profile_b}: {values['b']}")

    ctx = click.get_current_context()
    ctx.exit(EXIT_OK)


# v2.80: graph group relocated to cli/commands/graph.py


# v2.80: console group relocated to cli/commands/console.py


# ── Review commands (v2.21.0) ───────────────────────────────────────────

@cli.group(name="review")
def review_group() -> None:
    """Governed human review / operator decision workbench (v2.21.0).

    OR-001: Decisions are admissible only if they reference a materialized
    review request, validate bound artifacts, satisfy reviewer authority,
    record rationale, and emit a decision receipt.
    """
    pass


@review_group.command(name="queue")
@click.option("--status", "-s", type=click.Choice(["pending", "all", "stale"]), default="pending",
              help="Filter by status (default: pending)")
@click.option("--subject-type", "-t", type=str, default=None,
              help="Filter by subject type")
@click.option("--format", "-f", type=click.Choice(["terminal", "json"]), default="terminal",
              help="Output format")
@click.pass_context
def review_queue(
    ctx: click.Context,
    status: str,
    subject_type: str | None,
    format: str,
) -> None:
    """List review requests in the queue.

    Note: The queue is file-backed. Load from a JSON file of ReviewRequests.
    """
    from nodechain.sdk.review_workbench import ReviewQueue, ReviewRequest

    click.echo("Review queue is file-backed. Provide a --file to load.")
    click.echo("Use 'review submit' to create requests and 'review decide' to act.")
    click.echo("Use 'review list --file <queue.json>' to inspect.")


@review_group.command(name="submit")
@click.option("--request-id", "-r", required=True, help="Unique request ID")
@click.option("--subject-type", "-t", required=True,
              type=click.Choice(["capability_selection", "branch_merge", "compensation",
                                 "deployment", "remote_binding", "health_finding"]),
              help="What is being reviewed")
@click.option("--subject-id", "-i", required=True, help="ID of subject under review")
@click.option("--subject-digest", "-d", required=True, help="SHA-256 digest of subject")
@click.option("--reason", required=True, help="Reason for review")
@click.option("--role", required=True,
              type=click.Choice(["operator", "security_officer", "release_manager", "admin"]),
              help="Required reviewer role")
@click.option("--risk", default="medium",
              type=click.Choice(["low", "medium", "high", "critical"]),
              help="Risk level (default: medium)")
@click.option("--graph-digest", default="", help="Governance graph digest at time of request")
@click.option("--policy-digest", default="", help="Policy digest at time of request")
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Output file for review request JSON")
@click.pass_context
def review_submit(
    ctx: click.Context,
    request_id: str,
    subject_type: str,
    subject_id: str,
    subject_digest: str,
    reason: str,
    role: str,
    risk: str,
    graph_digest: str,
    policy_digest: str,
    output: str | None,
) -> None:
    """Submit a new review request."""
    from nodechain.sdk.review_workbench import ReviewRequest, ReviewSubject

    subject = ReviewSubject(
        subject_type=subject_type,
        subject_id=subject_id,
        subject_digest=subject_digest,
    )
    request = ReviewRequest(
        request_id=request_id,
        subject=subject,
        reason_for_review=reason,
        required_reviewer_role=role,
        graph_digest=graph_digest,
        policy_digest=policy_digest,
        risk_level=risk,
    )

    content = json.dumps(request.to_dict(), indent=2, sort_keys=True)

    if output:
        Path(output).write_text(content, encoding="utf-8")
        click.echo(f"Review request written to {output}")
    else:
        click.echo(content)


@review_group.command(name="decide")
@click.option("--request", "-r", type=click.Path(exists=True), required=True,
              help="Path to review request JSON")
@click.option("--decision", "-d", required=True,
              type=click.Choice([
                  "approve_capability_selection", "reject_capability_selection",
                  "approve_branch_merge", "reject_branch_merge",
                  "approve_compensation", "reject_compensation",
                  "approve_deployment", "reject_deployment",
                  "approve_remote_binding", "reject_remote_binding",
                  "acknowledge_health_finding",
              ]),
              help="Decision type")
@click.option("--reviewer", required=True, help="Reviewer identity")
@click.option("--role", required=True,
              type=click.Choice(["operator", "security_officer", "release_manager", "admin"]),
              help="Reviewer role")
@click.option("--rationale", required=True, help="Decision rationale")
@click.option("--policy", "-p", type=click.Path(exists=True), default=None,
              help="Path to reviewer policy JSON (optional — uses default if omitted)")
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Output file for decision receipt JSON")
@click.pass_context
def review_decide(
    ctx: click.Context,
    request: str,
    decision: str,
    reviewer: str,
    role: str,
    rationale: str,
    policy: str | None,
    output: str | None,
) -> None:
    """Make a decision on a review request.

    Produces a decision receipt if the decision is admissible.
    """
    from nodechain.sdk.review_workbench import (
        ReviewRequest, ReviewSubject, OperatorDecision,
        ReviewVerifier, ReviewerPolicy,
    )

    # Load review request
    req_data = json.loads(Path(request).read_text())
    subject = ReviewSubject(
        subject_type=req_data["subject"]["subject_type"],
        subject_id=req_data["subject"]["subject_id"],
        subject_digest=req_data["subject"]["subject_digest"],
        metadata=req_data["subject"].get("metadata", {}),
    )
    review_req = ReviewRequest(
        request_id=req_data["request_id"],
        subject=subject,
        reason_for_review=req_data["reason_for_review"],
        required_reviewer_role=req_data["required_reviewer_role"],
        graph_digest=req_data.get("graph_digest", ""),
        policy_digest=req_data.get("policy_digest", ""),
        trace_event_ids=req_data.get("trace_event_ids", []),
        risk_level=req_data.get("risk_level", "medium"),
        created_at=req_data["created_at"],
    )

    # Load policy
    if policy:
        pol_data = json.loads(Path(policy).read_text())
        reviewer_policy = ReviewerPolicy(
            policy_id=pol_data.get("policy_id", "custom"),
            role_authority={k: frozenset(v) for k, v in pol_data.get("role_authority", {}).items()},
            require_rationale_for_risk=pol_data.get("require_rationale_for_risk", "high"),
            max_request_age_hours=pol_data.get("max_request_age_hours", 72),
        )
    else:
        reviewer_policy = ReviewerPolicy()

    # Build decision
    dec = OperatorDecision(
        decision_type=decision,
        request_id=review_req.request_id,
        reviewer_identity=reviewer,
        reviewer_role=role,
        rationale=rationale,
        request_digest=review_req.compute_digest(),
        subject_digest=review_req.subject.subject_digest,
        policy_digest=reviewer_policy.compute_digest(),
    )

    # Verify
    verifier = ReviewVerifier(policy=reviewer_policy)
    result = verifier.verify(dec, review_req)

    if result.admissible:
        content = json.dumps(result.receipt.to_dict(), indent=2, sort_keys=True)
        if output:
            Path(output).write_text(content, encoding="utf-8")
            click.echo(f"Decision receipt written to {output}")
        else:
            click.echo(content)
    else:
        click.echo(f"Decision REJECTED: {result.rejection_reason}", err=True)
        for w in result.warnings:
            click.echo(f"  {w}", err=True)
        ctx.exit(10)


def main() -> None:
    cli()


# ── v2.59.0: Local API Server ──────────────────────────────────────

@cli.group(name="api")
def api_group() -> None:
    """Local API server (v2.59.0).

    Exposes run status, evidence, profiles, dashboard, and dry-run preview
    through a localhost-only, token-protected API.
    """
    pass


@api_group.command("serve")
@click.option("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
@click.option("--port", default=8765, type=int, help="Port (default: 8765)")
@click.option("--db", "db_path", default="data/chain_state.db", help="Path to chain state database")
@click.option("--trace-dir", "-t", default="data/traces", help="Directory for trace output")
def api_serve_cmd(host: str, port: int, db_path: str, trace_dir: str) -> None:
    """Start the local API server (v2.59.0).

    Requires NODECHAIN_API_TOKEN environment variable to be set.
    Binds to localhost by default for security.
    """
    import os
    import sys
    from nodechain.cli.exit_codes import EXIT_VALIDATION

    # Verify token is set
    token = os.environ.get("NODECHAIN_API_TOKEN", "").strip()
    if not token:
        console.print("[red]ERROR: NODECHAIN_API_TOKEN environment variable is required.[/red]")
        console.print("[dim]Set it to a secure random string before starting the API server.[/dim]")
        console.print("[dim]Example: export NODECHAIN_API_TOKEN=$(python -c \"import secrets; print(secrets.token_hex(32))\")[/dim]")
        sys.exit(EXIT_VALIDATION)

    try:
        import uvicorn
        from nodechain.api.app import create_app
    except ImportError as e:
        console.print(f"[red]Failed to import API dependencies: {e}[/red]")
        console.print("[dim]Install with: pip install fastapi uvicorn[/dim]")
        sys.exit(EXIT_VALIDATION)

    expose_docs = os.environ.get("NODECHAIN_API_EXPOSE_DOCS", "").strip() in ("1", "true", "yes")

    # v2.60.0: Security warning for non-localhost binds
    if host not in ("127.0.0.1", "localhost", "::1"):
        console.print("[red bold]⚠  SECURITY WARNING: Binding to non-localhost address![/red bold]")
        console.print(f"[red]Host {host} is accessible from other machines on this network.[/red]")
        console.print("[red]Ensure NODECHAIN_API_TOKEN is set to a strong value.[/red]")
        console.print("[red]Consider using 127.0.0.1 unless you intentionally need remote access.[/red]")
        console.print()

    console.print(Panel(
        f"[bold]Host:[/bold]        {host}\n"
        f"[bold]Port:[/bold]        {port}\n"
        f"[bold]Database:[/bold]    {db_path}\n"
        f"[bold]Trace Dir:[/bold]   {trace_dir}\n"
        f"[bold]Docs:[/bold]        {'exposed' if expose_docs else 'hidden (set NODECHAIN_API_EXPOSE_DOCS=1)'}\n"
        f"[bold]Auth:[/bold]        Bearer token (NODECHAIN_API_TOKEN)",
        title="[bold blue]NodeChain API Server[/bold blue]",
    ))

    app = create_app(db_path=db_path, trace_dir=trace_dir)
    uvicorn.run(app, host=host, port=port)


# ── v2.79: relocated command groups ────────────────────────────────────────
# Wave-1 cluster: groups whose Click declarations were moved to cli/commands/*.
# Each module exports a register(cli) function that adds the group here.
# The implementation logic remains in the sibling cli/*.py modules.
from nodechain.cli.commands import evidence as _evidence_commands
_evidence_commands.register(cli)

from nodechain.cli.commands import release_history as _release_history_commands
_release_history_commands.register(cli)

from nodechain.cli.commands import audit_bundle as _audit_bundle_commands
_audit_bundle_commands.register(cli)

from nodechain.cli.commands import dashboard as _dashboard_commands
_dashboard_commands.register(cli)

from nodechain.cli.commands import eval as _eval_commands
_eval_commands.register(cli)

from nodechain.cli.commands import graph as _graph_commands
_graph_commands.register(cli)

from nodechain.cli.commands import console as _console_commands
_console_commands.register(cli)

# v2.86 wave-3: read-oriented commands relocated from main.py.
from nodechain.cli.commands import inspect as _inspect_commands
_inspect_commands.register(cli)

from nodechain.cli.commands import report as _report_commands
_report_commands.register(cli)

from nodechain.cli.commands import trace as _trace_commands
_trace_commands.register(cli)

from nodechain.cli.commands import trace_replay as _trace_replay_commands
_trace_replay_commands.register(cli)

from nodechain.cli.commands import compose as _compose_commands
_compose_commands.register(cli)


if __name__ == "__main__":
    main()
