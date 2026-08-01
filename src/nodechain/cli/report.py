"""Report command — generate a comprehensive human-readable run report."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from nodechain.cli.exit_codes import EXIT_NOT_FOUND
from rich.panel import Panel
from rich.markdown import Markdown

from nodechain.core.state import StateManager
from nodechain.runtime.trace_reconciler import TraceReconciler

console = Console()


def report_run(
    run_id: str,
    db_path: str = "data/chain_state.db",
    trace_dir: str = "data/traces",
    output_file: str | None = None,
) -> None:
    """Generate a comprehensive report for a chain run."""
    sm = StateManager(db_path=db_path)

    state = sm.load(run_id)
    if state is None:
        console.print(f"[red]No saved state found for run: {run_id}[/red]")
        sys.exit(EXIT_NOT_FOUND)

    # Build report sections
    sections = []

    # ── Header ──
    status_color = "green" if state.status == "completed" else "yellow" if state.status == "running" else "red"
    console.print(Panel(
        f"[bold]Run ID:[/bold]       {state.run_id}\n"
        f"[bold]Chain ID:[/bold]     {state.chain_id}\n"
        f"[bold]Status:[/bold]       [{status_color}]{state.status}[/{status_color}]\n"
        f"[bold]Steps:[/bold]        {state.step}\n"
        f"[bold]Revision:[/bold]     {state.revision}",
        title="[bold blue]Run Report[/bold blue]",
    ))

    # v1.3.9: Human-readable policy preset + enforcement panel
    import os as _os
    preset = _os.environ.get("NODECHAIN_POLICY_PRESET", "")
    if preset:
        preset_source = _os.environ.get("NODECHAIN_POLICY_PRESET_SOURCE", "")
        sandbox_profile = _os.environ.get("NODECHAIN_SANDBOX_PROFILE", "")
        preset_lines = [
            f"[bold]Policy Preset:[/bold]    {preset}",
            f"[bold]Preset Source:[/bold]   {preset_source}",
            f"[bold]Sandbox Profile:[/bold] {sandbox_profile}",
        ]
        # Show enforcement expectations from preset
        from nodechain.sdk.policy_presets import get_preset as _gp
        preset_obj = _gp(preset)
        if preset_obj:
            if preset_obj.sandbox_profile == "os_profile":
                preset_lines.append("[bold]Seccomp:[/bold]         enabled (Linux)")
            if preset_obj.cgroup_memory_max_mb > 0:
                preset_lines.append(f"[bold]Memory Limit:[/bold]   {preset_obj.cgroup_memory_max_mb}MB")
            if preset_obj.cgroup_pids_max > 0:
                preset_lines.append(f"[bold]PIDs Limit:[/bold]     {preset_obj.cgroup_pids_max}")
            if preset_obj.cgroup_cpu_max_quota > 0:
                preset_lines.append(f"[bold]CPU Quota:[/bold]      {preset_obj.cgroup_cpu_max_quota}µs/period")
            if preset_obj.network_namespace_required:
                preset_lines.append("[bold]Network NS:[/bold]     required (Linux)")
            if preset_obj.mount_confinement_required:
                preset_lines.append("[bold]Mount Confinement:[/bold] required (Linux chroot)")
            if getattr(preset_obj, 'pid_namespace_required', False):
                preset_lines.append("[bold]PID Namespace:[/bold]    required (Linux)")
            if getattr(preset_obj, 'procfs_isolation_required', False):
                preset_lines.append("[bold]Procfs Isolation:[/bold] required (Linux)")
        # v1.4.2: Add namespace detection status
        try:
            from nodechain.sdk.namespace_profile import detect_namespaces
            ns_caps = detect_namespaces()
            if ns_caps.namespace_available or ns_caps.already_nested:
                preset_lines.append("")  # separator
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
                if ns_caps.uts_namespace_available:
                    ns_types.append("uts")
                if ns_caps.ipc_namespace_available:
                    ns_types.append("ipc")
                if ns_types:
                    preset_lines.append(f"[bold]Available Types:[/bold]  {', '.join(ns_types)}")
                # v1.4.4: mount namespace enforcement state
                if getattr(ns_caps, 'mount_namespace_enforced', False):
                    preset_lines.append("[bold]Mount NS Enforced:[/bold] True")
                # v1.4.6: mount confinement enforcement state
                if getattr(ns_caps, 'mount_confinement_enforced', False):
                    preset_lines.append("[bold]Mount Confinement Enforced:[/bold] True")
        except Exception:
            pass
        console.print(Panel(
            "\n".join(preset_lines),
            title="[bold cyan]Policy Preset & Enforcement[/bold cyan]",
        ))

    # ── Execution Flow ──
    completed_steps = sm.get_completed_steps(run_id)
    if completed_steps:
        table = Table(title="Execution Flow", show_lines=False)
        table.add_column("Step", style="cyan", width=6)
        table.add_column("Node", style="green", width=30)
        table.add_column("Status", style="white", width=12)

        for step_id, node_id in sorted(completed_steps.items()):
            has_output = node_id in (state.outputs or {})
            table.add_row(
                str(step_id),
                node_id,
                "[ok] completed" if has_output else "[  ] no output",
            )
        console.print(table)

    # ── Side Effects ──
    side_effects = sm.get_side_effects(run_id)
    if side_effects:
        se_table = Table(title="Side Effects", show_lines=True)
        se_table.add_column("Step", style="cyan", width=6)
        se_table.add_column("Node", style="green", width=20)
        se_table.add_column("Type", style="white", width=18)
        se_table.add_column("Key", style="yellow", width=30)
        se_table.add_column("Status", style="magenta", width=10)

        for se in side_effects:
            status = se["status"]
            color = "green" if status == "completed" else "red" if status == "failed" else "yellow" if status == "unknown" else "white"
            se_table.add_row(
                str(se["step_id"]),
                se["node_id"],
                se["side_effect_type"],
                se["idempotency_key"][:30],
                f"[{color}]{status}[/{color}]",
            )
        console.print(se_table)

        # Lifecycle summary
        by_status: dict[str, int] = {}
        for se in side_effects:
            by_status[se["status"]] = by_status.get(se["status"], 0) + 1

        n_started = by_status.get("started", 0)
        n_unknown = by_status.get("unknown", 0)
        n_completed = by_status.get("completed", 0)
        n_failed = by_status.get("failed", 0)
        n_planned = by_status.get("planned", 0)

        summary_parts = []
        if n_completed: summary_parts.append(f"{n_completed} completed")
        if n_failed: summary_parts.append(f"{n_failed} failed")
        if n_started: summary_parts.append(f"[yellow]{n_started} started[/yellow]")
        if n_unknown: summary_parts.append(f"[yellow]{n_unknown} unknown[/yellow]")
        if n_planned: summary_parts.append(f"{n_planned} planned")

        console.print(f"  Summary: {', '.join(summary_parts)}")

        if n_started > 0:
            console.print(f"  [red]WARNING: {n_started} side-effect rows still in 'started' state (identity mismatch or incomplete lifecycle)[/red]")
        if n_unknown > 0:
            console.print(f"  [yellow]NOTE: {n_unknown} side effects in 'unknown' state (crash recovery may be needed)[/yellow]")

    # ── Loop Summary ──
    if state.loop_state:
        loop_table = Table(title="Loop Summary", show_lines=True)
        loop_table.add_column("Loop ID", style="cyan", width=30)
        loop_table.add_column("Iterations", style="green", width=12)
        loop_table.add_column("Reason", style="white", width=40)
        loop_table.add_column("Status", style="magenta", width=15)

        for loop_id, ls in state.loop_state.items():
            iteration = ls.iteration
            reason = ls.reason or "-"
            # Determine status
            if iteration > 0:
                status = "active"
            else:
                status = "not entered"
            loop_table.add_row(
                loop_id,
                str(iteration),
                reason[:40],
                status,
            )
        console.print(loop_table)

        # Compute cumulative cost from trace if available
        trace_path = _find_trace(run_id, trace_dir)
        if trace_path:
            with open(trace_path) as f:
                trace_data = json.load(f)
            events = trace_data.get("events", [])
            # Find loop paths from blueprint governance if available
            loop_costs: dict[str, float] = {}
            for loop_id, ls in state.loop_state.items():
                cost = 0.0
                for evt in events:
                    if evt.get("cost_usd") and evt.get("cost_usd", 0) > 0:
                        cost += evt.get("cost_usd", 0)
                loop_costs[loop_id] = cost
            if loop_costs:
                cost_parts = []
                for lid, c in loop_costs.items():
                    cost_parts.append(f"{lid}: ${c:.4f}")
                console.print(f"  Cumulative cost: {', '.join(cost_parts)}")

    # ── Reconciliation ──
    trace_path = _find_trace(run_id, trace_dir)
    reconciliation_report = None
    if trace_path:
        with open(trace_path) as f:
            trace_data = json.load(f)

        from nodechain.cli.reconcile import _build_trace
        trace = _build_trace(trace_data)
        reconciler = TraceReconciler(state_manager=sm)
        report = reconciler.reconcile(trace)
        reconciliation_report = report

        status = "OK CLEAN" if report.is_clean else "X ISSUES"
        color = "green" if report.is_clean else "red"
        console.print(f"\n[bold]Reconciliation:[/bold] [{color}]{status}[/{color}]")
        console.print(f"  Checks passed: {report.checks_passed}")
        if report.issues:
            for issue in report.issues:
                icon = "X" if issue.severity == "error" else "!️"
                console.print(f"  {icon} {issue.check}: {issue.actual}")
    else:
        console.print("\n[yellow]No trace file found — reconciliation skipped[/yellow]")

    # ── Branch Summary ──
    branch_summaries = []
    if trace_path and trace_data:
        events = trace_data.get("events", [])
        branch_summaries = _extract_branch_summary(events)
        if branch_summaries:
            _render_branch_summary(branch_summaries)

    # ── Outputs ──
    if state.outputs:
        console.print(f"\n[bold]Node Outputs:[/bold]")
        for node_id, output in state.outputs.items():
            if isinstance(output, dict):
                # Special formatting for key nodes
                if node_id == "response_generator":
                    _render_response(output)
                elif node_id == "goal_interpreter":
                    goal = output.get("normalized_goal", output.get("research_goal", ""))
                    console.print(f"  [green]goal_interpreter:[/green] {str(goal)[:100]}")
                elif node_id == "risk_classifier":
                    level = output.get("risk_level", "unknown")
                    rcolor = "red" if level == "high" else "yellow" if level == "medium" else "green"
                    console.print(f"  [{rcolor}]risk_classifier:[/{rcolor}] {level}")
                else:
                    keys = list(output.keys())[:4]
                    preview = ", ".join(keys)
                    console.print(f"  [green]{node_id}:[/green] {{{preview}}}")

    # ── Save report ──
    if output_file:
        report_data = _build_report_dict(state, completed_steps, side_effects, reconciliation_report, branch_summaries)
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w") as f:
            json.dump(report_data, f, indent=2, default=str)
        console.print(f"\n[green]Report saved: {output_file}[/green]")


def _extract_branch_summary(events: list[dict]) -> list[dict]:
    """Extract branch execution summaries from trace events."""
    summaries = []

    # Find join_completed events — they have the full picture
    for evt in events:
        if evt.get("type") != "join_completed":
            continue
        meta = evt.get("metadata", {})
        summary = {
            "join_id": meta.get("join_id", "unknown"),
            "wait_for": meta.get("wait_for", "unknown"),
            "completed": meta.get("completed_branches", []),
            "failed": meta.get("failed_branches", []),
            "cancelled": meta.get("cancelled_branches", []),
            "ignored": meta.get("ignored_branches", []),
            "first_completed": meta.get("first_completed_branch"),
        }
        summaries.append(summary)

    # Find quorum events for quorum-specific metadata
    for evt in events:
        if evt.get("type") == "quorum_reached":
            meta = evt.get("metadata", {})
            for s in summaries:
                if s["join_id"] == meta.get("join_id"):
                    s["quorum_required"] = meta.get("quorum_required")
                    s["quorum_reached"] = meta.get("quorum_reached")
                    s["winning_branches"] = meta.get("winning_branches", [])
        elif evt.get("type") == "quorum_impossible":
            meta = evt.get("metadata", {})
            for s in summaries:
                if s["join_id"] == meta.get("join_id"):
                    s["quorum_required"] = meta.get("quorum_required")
                    s["quorum_failed"] = True
                    s["quorum_remaining"] = meta.get("remaining_possible")

    # Find cancellation/ignore events
    for evt in events:
        evt_type = evt.get("type", "")
        if evt_type in ("ignore_late_enforced", "first_success_only_enforced", "cancellation_policy_not_enforced"):
            meta = evt.get("metadata", {})
            for s in summaries:
                if s["join_id"] == meta.get("join_id"):
                    s["policy_event"] = evt_type

    return summaries


def _render_branch_summary(summaries: list[dict]) -> None:
    """Render branch execution summary table."""
    for summary in summaries:
        console.print(f"\n[bold]Branch Summary:[/bold] join [cyan]{summary['join_id']}[/cyan]")

        # Wait-for + quorum info
        wf = summary.get("wait_for", "unknown")
        info_parts = [f"wait_for={wf}"]

        if "quorum_required" in summary:
            info_parts.append(f"quorum={summary['quorum_required']}")
            if "quorum_reached" in summary:
                info_parts.append(f"reached={summary['quorum_reached']}")
            if summary.get("quorum_failed"):
                info_parts.append("[red]IMPOSSIBLE[/red]")

        if summary.get("policy_event"):
            info_parts.append(f"policy={summary['policy_event']}")

        console.print(f"  {', '.join(info_parts)}")

        # Branch status table
        table = Table(show_lines=False, show_header=True)
        table.add_column("Branch", style="cyan", width=20)
        table.add_column("Status", style="white", width=15)

        for b in summary.get("completed", []):
            label = "completed"
            if b == summary.get("first_completed"):
                label = "[green]first-winner[/green]"
            elif b in summary.get("ignored", []):
                label = "[yellow]ignored-late[/yellow]"
            elif b in summary.get("winning_branches", []):
                label = "[green]quorum-winner[/green]"
            table.add_row(b, label)

        for b in summary.get("failed", []):
            table.add_row(b, "[red]failed[/red]")

        for b in summary.get("cancelled", []):
            table.add_row(b, "[magenta]cancelled[/magenta]")

        for b in summary.get("ignored", []):
            if b not in (summary.get("completed", [])):
                table.add_row(b, "[yellow]ignored[/yellow]")

        console.print(table)


def _render_response(output: dict) -> None:
    """Render the response generator output."""
    rec = output.get("recommendation", "")
    if rec:
        console.print(Panel(rec, title="[bold green]Recommendation[/bold green]"))

    summary = output.get("executive_summary", "")
    if summary:
        console.print(f"  [bold]Summary:[/bold] {summary[:200]}")

    conf = output.get("confidence_statement", {})
    if conf:
        level = conf.get("level", "UNKNOWN")
        numeric = conf.get("numeric", 0)
        console.print(f"  [bold]Confidence:[/bold] {level} ({numeric:.0%})")


def _find_trace(run_id: str, trace_dir: str) -> str | None:
    """Find the trace file for a run."""
    from pathlib import Path
    trace_path = Path(trace_dir) / f"{run_id}.json"
    if trace_path.exists():
        return str(trace_path)
    for p in Path(trace_dir).glob(f"{run_id[:8]}*.json"):
        return str(p)
    return None


def _build_report_dict(state, completed_steps, side_effects, reconciliation=None, branch_summaries=None) -> dict:
    """Build a JSON-serializable report dict."""
    report = {
        "run_id": state.run_id,
        "chain_id": state.chain_id,
        "status": state.status,
        "step": state.step,
        "revision": state.revision,
        "completed_steps": {str(k): v for k, v in completed_steps.items()},
        "side_effects": side_effects,
        "outputs": {k: str(v)[:200] for k, v in (state.outputs or {}).items()},
    }
    if state.loop_state:
        report["loops"] = {
            loop_id: {
                "iteration": ls.iteration,
                "reason": ls.reason,
                "entered_at": ls.entered_at,
            }
            for loop_id, ls in state.loop_state.items()
        }
    if reconciliation:
        errors = [i for i in reconciliation.issues if i.severity == "error"]
        warnings = [i for i in reconciliation.issues if i.severity == "warning"]
        report["reconciliation"] = {
            "is_clean": reconciliation.is_clean,
            "checks_passed": reconciliation.checks_passed,
            "errors": len(errors),
            "warnings": len(warnings),
            "issues": [
                {"check": i.check, "severity": i.severity, "expected": i.expected, "actual": i.actual}
                for i in reconciliation.issues
            ],
        }
    if branch_summaries:
        report["branches"] = branch_summaries

    # Node origins (built_in vs local_registry)
    try:
        from nodechain.registry.local_registry import RegistryIndex
        registry = RegistryIndex()
        registry.scan()
        registry_ids = {pkg["node_id"] for pkg in registry.list_packages()}
        origins = {}
        for step_id, node_id in completed_steps.items():
            if node_id in registry_ids:
                pkg = registry.get_package(node_id)
                origins[node_id] = {
                    "origin": "local_registry",
                    "version": pkg.manifest.version if pkg else "unknown",
                    "path": pkg.path if pkg else None,
                    "content_hash": pkg.content_hash() if pkg else None,
                }
                # Add capabilities from package yaml
                if pkg.path:
                    pkg_yaml = Path(pkg.path) / "node.yaml"
                    if not pkg_yaml.exists():
                        pkg_yaml = Path(pkg.path) / "package.yaml"
                    if pkg_yaml.exists():
                        try:
                            import yaml as _y
                            raw = _y.safe_load(pkg_yaml.read_text())
                            caps = raw.get("capabilities")
                            if caps:
                                origins[node_id]["capabilities"] = caps
                            se = raw.get("side_effects", [])
                            if se:
                                origins[node_id]["declared_side_effects"] = se
                        except Exception:
                            pass
            else:
                origins[node_id] = {"origin": "built_in"}
        report["node_origins"] = origins
    except Exception:
        pass  # Registry not available

    # AC6: Package policy decisions
    try:
        from nodechain.sdk.policy_enforcer import PackagePolicyEnforcer, PolicyDecision
        enforcer = PackagePolicyEnforcer()
        policy_decisions = {}
        for step_id, node_id in completed_steps.items():
            if node_id in origins and origins[node_id].get("origin") == "local_registry":
                pkg_path = origins[node_id].get("path")
                if pkg_path:
                    result = enforcer.enforce_package(
                        package_id=node_id,
                        node_id=node_id,
                        package_path=Path(pkg_path),
                    )
                    policy_decisions[node_id] = {
                        "decision": result.decision.value,
                        "version_check": result.version_check,
                        "capability_audit": result.capability_audit,
                        "side_effect_audit": result.side_effect_audit,
                    }
                    if result.reasons:
                        policy_decisions[node_id]["reasons"] = result.reasons
        if policy_decisions:
            report["package_policy"] = policy_decisions
    except Exception:
        pass

    # Trust levels and execution isolation
    try:
        from nodechain.sdk.trust import resolve_trust_from_package, get_execution_policy
        trust_info = {}
        for step_id, node_id in completed_steps.items():
            if node_id in origins and origins[node_id].get("origin") == "local_registry":
                pkg_path = origins[node_id].get("path")
                if pkg_path:
                    trust = resolve_trust_from_package(node_id, Path(pkg_path))
                    policy = get_execution_policy(trust)
                    trust_info[node_id] = {
                        "trust_level": trust.value,
                        "execution_policy": policy.to_dict(),
                    }
            elif node_id in origins:
                trust_info[node_id] = {
                    "trust_level": "built_in",
                    "execution_policy": {"isolation_mode": "in_process"},
                }
        if trust_info:
            report["trust_levels"] = trust_info

    except Exception:
        pass

    # Unified sandbox status
    try:
        # Report cgroup capability (v1.3.0)
        cgroup_info = {}
        try:
            from nodechain.sdk.cgroup_profile import detect_cgroup
            cg_caps = detect_cgroup()
            cgroup_info = cg_caps.to_dict()
        except Exception:
            pass

        report["sandbox_status"] = {
            "imports": "enforced",
            "filesystem": "enforced",
            "subprocess": "enforced",
            "network": "enforced",
            "process_isolation": "available",
            "isolation_modes": ["in_process", "subprocess"],
            "cgroup": cgroup_info,
        }
    except Exception:
        pass

    # Trust summary
    try:
        from nodechain.sdk.trust_summary import TrustSummary, NodeTrustRecord
        trust = TrustSummary(run_id=run_id)
        trust.lockfile_verified = report.get("lockfile_verified", "missing") == "verified"
        trust.locked_mode = report.get("locked_mode", False)
        # v1.3.6: populate preset info from env
        import os as _os
        trust.policy_preset = _os.environ.get("NODECHAIN_POLICY_PRESET", "")
        trust.preset_source = _os.environ.get("NODECHAIN_POLICY_PRESET_SOURCE", "")
        report["trust_summary"] = trust.to_dict()
    except Exception:
        pass

    # Lockfile verification status and provenance
    try:
        from nodechain.sdk.lockfile import verify_lockfile, LOCKFILE_NAME
        import hashlib
        lock_result = verify_lockfile()
        lockfile_path = Path(LOCKFILE_NAME)
        report["lockfile_path"] = str(lockfile_path)
        report["locked_mode"] = True

        # Hash the lockfile itself for provenance
        if lockfile_path.exists():
            lf_hash = hashlib.sha256(lockfile_path.read_bytes()).hexdigest()[:16]
            report["lockfile_hash"] = lf_hash
        else:
            report["lockfile_hash"] = None

        if lock_result.get("error"):
            report["lockfile_verified"] = "missing"
        elif lock_result["valid"]:
            report["lockfile_verified"] = "true"
        else:
            report["lockfile_verified"] = "drifted"
        report["lockfile"] = {
            "valid": lock_result["valid"],
            "locked_count": lock_result.get("locked_count", 0),
            "current_count": lock_result.get("current_count", 0),
        }
        if lock_result.get("mismatches"):
            report["lockfile"]["mismatches"] = lock_result["mismatches"]
        if lock_result.get("missing"):
            report["lockfile"]["missing"] = lock_result["missing"]
    except Exception:
        report["lockfile_verified"] = "missing"
        report["locked_mode"] = False

    return report
