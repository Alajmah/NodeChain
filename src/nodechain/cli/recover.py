"""`nodechain recover` — Operator Recovery Console (v2.46.0).

The recovery console turns pause/resume/retry/review-blocks from internal
runtime capabilities into an explicit operator workflow. It is a thin layer
over ``RecoveryService``: the commands render a derived ``RecoverySnapshot``
or run summary and never mutate the database directly. Mutating actions
(resume, retry, approve, ...) land in Phase 3/4 and delegate to the existing
runtime primitives through ``RecoveryService.apply_action``.

Registered as a Click subgroup in ``cli/main.py``.
"""

from __future__ import annotations

import asyncio
import json as _json
import os
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from nodechain.cli.exit_codes import (
    EXIT_OK,
    EXIT_RECOVERY_NOT_FOUND,
    EXIT_RECOVERY_NOT_ACTIONABLE,
    EXIT_RECOVERY_BLOCKED,
)
from nodechain.core.state import StateManager
from nodechain.runtime.recovery_policy import RecoveryAction
from nodechain.runtime.recovery_service import RecoveryService

console = Console()


# ── Orchestrator delegate builder ────────────────────────────────────────────
# Reconstructs the Orchestrator exactly as the resume CLI does, then returns a
# delegate callable the RecoveryService invokes. Kept here (CLI layer) so the
# service stays free of model-adapter/Chroma dependencies and testable without
# a live environment. Returns None if construction fails (caller surfaces it).

def _build_orchestrator_delegate(db_path: str, blueprint: str, trace_dir: str):
    """Build the orchestrator-backed delegate for resume/retry/approve/reject/revise.

    Returns a callable ``(action, run_id, *, target_step_id, reason,
    instructions) -> resulting_status``. Mirrors cli/resume.py's construction
    so the SAME Orchestrator.resume / ReviewManager.resolve_resume_review path
    handles operator-initiated recovery.
    """
    from nodechain.adapters.lim_model_adapter import LIMModelAdapter
    from nodechain.core.blueprint import load_blueprint
    from nodechain.memory.manager import MemoryManager
    from nodechain.adapters.chroma_adapter import ChromaAdapter
    from nodechain.runtime.orchestrator import Orchestrator
    from nodechain.cli.run import _create_nodes

    blueprint_obj = load_blueprint(blueprint)

    provider = os.environ.get("NODECHAIN_PROVIDER", "lim").lower()
    model_name = os.environ.get("NODECHAIN_MODEL", "auto")
    lim_url = os.environ.get("LIM_BASE_URL", "http://localhost:8766")
    if provider == "mock":
        from nodechain.adapters.mock_model_adapter import MockModelAdapter
        model_adapter = MockModelAdapter()
    else:
        model_adapter = LIMModelAdapter(lim_url=lim_url, model=model_name)

    memory_manager = None
    try:
        chroma_host = os.environ.get("CHROMA_HOST", "localhost")
        chroma_port = os.environ.get("CHROMA_PORT", "8000")
        chroma = ChromaAdapter(base_url=f"http://{chroma_host}:{chroma_port}")
        memory_manager = MemoryManager(chroma=chroma)
    except Exception:
        pass

    nodes = _create_nodes(model_adapter, trace_dir, memory_manager=memory_manager)
    # #1: pass the SAME state_manager the console authorized against, so
    # `recover resume --db custom.db` executes against custom.db, not the
    # Orchestrator's default StateManager(). Auth and execution must agree.
    exec_state_manager = StateManager(db_path=db_path)
    orchestrator = Orchestrator(
        blueprint=blueprint_obj, nodes=nodes, state_manager=exec_state_manager,
    )

    def delegate(action: RecoveryAction, run_id: str, *,
                 target_step_id: int | None = None,
                 reason: str | None = None,
                 instructions: str | None = None,
                 new_budget: float | None = None) -> str:
        # #2: stage review_decision ONLY after admission (this delegate runs
        # inside apply_action's post-authorization path). Derived from the
        # action enum + instructions so no mutation happens before the gate.
        if action is RecoveryAction.APPROVE_REVIEW:
            _set_review_decision(exec_state_manager, run_id, "approve")
        elif action is RecoveryAction.REJECT_REVIEW:
            _set_review_decision(exec_state_manager, run_id, "reject")
        elif action is RecoveryAction.REQUEST_REVISION:
            _set_review_decision(exec_state_manager, run_id, "revise",
                                 instructions=instructions)

        # Orchestrator.resume handles retry of the failed step + review
        # resolution through the existing runtime path. target_step_id is
        # recorded in the ledger (step/invocation precision).
        if action is RecoveryAction.ROUTE_FALLBACK:
            # #13: operator-initiated fallback for one failed step, routed
            # through FailureManager.route_fallback (allowlist-only).
            return asyncio.run(orchestrator.route_fallback(run_id, target_step_id))
        if action is RecoveryAction.APPROVE_BUDGET_INCREASE:
            # v2.47.0: raise the loop budget ceiling (carry cost) + resume.
            return asyncio.run(orchestrator.approve_budget_increase(run_id, float(new_budget)))
        trace = asyncio.run(orchestrator.resume(run_id))
        resulting = exec_state_manager.load(run_id)
        return resulting.status if resulting else "unknown"

    return delegate


def _set_review_decision(sm: StateManager, run_id: str, decision: str,
                         *, instructions: str | None = None) -> None:
    """Write the operator's review decision into state.metadata before resume."""
    state = sm.load(run_id)
    if state is None:
        return
    md = dict(state.metadata or {})
    md["review_decision"] = decision
    if instructions:
        md["revision_instructions"] = instructions
    state.metadata = md
    sm.save(state)


def recover_list(db_path: str, trace_dir: str) -> int:
    """List every persisted run with its derived recovery state.

    Operators triage the backlog here; completed/cancelled runs are included
    so the picture is complete, ordered most-recently-updated first.
    """
    sm = StateManager(db_path=db_path)
    service = RecoveryService(state_manager=sm, trace_dir=trace_dir)
    summaries = service.list_runs()

    if not summaries:
        console.print("[dim]No runs found.[/dim]")
        return EXIT_OK

    table = Table(title="Recoverable Runs", show_lines=True)
    table.add_column("Run ID", style="cyan", width=20)
    table.add_column("Chain", style="blue", width=12)
    table.add_column("Status", style="white", width=18)
    table.add_column("Recovery State", style="magenta", width=26)
    table.add_column("Step", style="yellow", width=6)
    table.add_column("Trace Health", width=12)
    table.add_column("Blocking Reason", style="red", width=36)
    table.add_column("Updated", style="dim", width=20)

    for summary in summaries:
        # Derive the recovery state cheaply for the list view: build a snapshot
        # per row so the operator sees the same classification as `inspect`.
        snapshot = service.build_snapshot(summary.run_id)
        recovery_state = snapshot.recovery_state if snapshot else "?"
        reason = (snapshot.blocking_reason if snapshot else None) or ""
        status_color = _status_color(summary.status)
        # T9: trace health column — independent of recovery_state so terminal
        # classifications (COMPLETED/CANCELLED) don't mask trace errors.
        if snapshot and snapshot.trace_errors:
            trace_health = f"[red]ERROR ({len(snapshot.trace_errors)})[/red]"
        elif snapshot and snapshot.trace_warnings:
            trace_health = f"[yellow]WARN ({len(snapshot.trace_warnings)})[/yellow]"
        elif snapshot and snapshot.trace_complete:
            trace_health = "[green]CLEAN[/green]"
        else:
            trace_health = "?"
        table.add_row(
            summary.run_id,
            summary.chain_id,
            f"[{status_color}]{summary.status}[/{status_color}]",
            recovery_state,
            str(summary.step),
            trace_health,
            reason,
            (summary.updated_at or "")[:19],
        )

    console.print(table)
    console.print(f"[dim]{len(summaries)} run(s)[/dim]")
    return EXIT_OK


def recover_inspect(run_id: str, db_path: str, trace_dir: str) -> int:
    """Show the full recovery snapshot for one run (v2.58.0: + evidence section)."""
    sm = StateManager(db_path=db_path)
    service = RecoveryService(state_manager=sm, trace_dir=trace_dir)
    snapshot = service.build_snapshot(run_id)
    if snapshot is None:
        console.print(f"[red]No saved state found for run: {run_id}[/red]")
        return EXIT_RECOVERY_NOT_FOUND
    _render_snapshot(snapshot)

    # v2.58.0: Evidence/citation section
    state = sm.load(run_id)
    if state and state.outputs:
        _render_evidence_summary(state.outputs)

    return EXIT_OK


def recover_list_unknown(run_id: str, db_path: str) -> int:
    """List side effects in 'unknown' status for a run (v3.3.0).

    Operators use this to see which crash-window side effects await a
    recovery decision before calling ``recover resolve-side-effect``.
    """
    sm = StateManager(db_path=db_path)
    unknown = [se for se in sm.get_side_effects(run_id) if se.get("status") == "unknown"]
    if not unknown:
        console.print(f"[green]No unknown side effects for run {run_id}.[/green]")
        return EXIT_OK
    table = Table(title=f"Unknown Side Effects — {run_id}")
    table.add_column("Key", style="cyan")
    table.add_column("Type", style="magenta")
    table.add_column("Node", style="blue")
    table.add_column("Step", style="dim")
    table.add_column("Request Hash", style="dim")
    for se in unknown:
        table.add_row(
            se.get("idempotency_key", ""),
            se.get("side_effect_type", ""),
            se.get("node_id", ""),
            str(se.get("step_id", "")),
            se.get("request_hash", "")[:16] if se.get("request_hash") else "",
        )
    console.print(table)
    console.print(
        f"[yellow]{len(unknown)} unknown side effect(s) awaiting recovery decision.[/yellow]\n"
        f"Resolve with: nodechain recover resolve-side-effect --run-id {run_id} "
        f"--side-effect-key <key> --decision <verified_completed|verified_failed|mark_unrecoverable|safe_to_retry> --reason \"...\""
    )
    return EXIT_OK


def _render_evidence_summary(outputs: dict) -> None:
    """Render a compact evidence/citation summary from node outputs (v2.58.0).

    Degrades gracefully when runs lack evidence fields (pre-v2.55.0 runs).
    """
    from rich.table import Table

    # Check if any evidence-related output exists
    has_evidence = False

    # Citations from response_generator
    resp_output = outputs.get("response_generator", {})
    if isinstance(resp_output, dict):
        citations = resp_output.get("citations", [])
        if citations:
            has_evidence = True
            ct_table = Table(title="Citations", show_lines=True, header_style="bold cyan")
            ct_table.add_column("#", style="dim", width=4)
            ct_table.add_column("Source Ref", style="yellow", width=20)
            ct_table.add_column("Claim Supported", style="white", width=50)
            for i, ct in enumerate(citations, 1):
                ct_table.add_row(
                    str(i),
                    str(ct.get("source_ref", "?"))[:20],
                    str(ct.get("claim_supported", "?"))[:50],
                )
            console.print(ct_table)

    # Validated claims from claim_validator or risk_classifier pass-through
    for node_id in ("claim_validator", "risk_classifier"):
        node_output = outputs.get(node_id, {})
        if isinstance(node_output, dict):
            vc = node_output.get("validated_claims", [])
            if vc:
                has_evidence = True
                vc_table = Table(title=f"Validated Claims (via {node_id})", show_lines=True, header_style="bold cyan")
                vc_table.add_column("ID", style="dim", width=6)
                vc_table.add_column("Status", width=22)
                vc_table.add_column("Confidence", justify="right", width=12)
                vc_table.add_column("Statement", style="white", width=40)
                for c in vc[:10]:  # cap at 10 for terminal readability
                    status = c.get("status", "?")
                    status_color = "green" if status == "confirmed" else "yellow" if "partial" in status else "red"
                    vc_table.add_row(
                        str(c.get("claim_id", "?"))[:6],
                        f"[{status_color}]{status}[/{status_color}]",
                        f"{c.get('adjusted_confidence', c.get('confidence', '?'))}",
                        str(c.get("statement", "?"))[:40],
                    )
                console.print(vc_table)
                break  # Only show once (risk_classifier passes through the same data)

    # Quarantined claims from evidence_synthesizer
    synth_output = outputs.get("evidence_synthesizer", {})
    if isinstance(synth_output, dict):
        claims = synth_output.get("claims", [])
        quarantined = [c for c in claims if c.get("status") == "quarantined_fabricated_source"]
        if quarantined:
            has_evidence = True
            console.print(f"\n[red]\u26a0  {len(quarantined)} quarantined claim(s) (fabricated source IDs)[/red]")
            for c in quarantined:
                console.print(f"    [dim]{c.get('claim_id', '?')}:[/dim] {c.get('quarantine_reason', '?')}")

    if not has_evidence:
        console.print("\n[dim]No evidence/citation data available for this run.[/dim]")


def recover_trace(run_id: str, db_path: str, trace_dir: str) -> int:
    """Show trace health (reconciler report) for one run."""
    sm = StateManager(db_path=db_path)
    service = RecoveryService(state_manager=sm, trace_dir=trace_dir)
    state = sm.load(run_id)
    if state is None:
        console.print(f"[red]No saved state found for run: {run_id}[/red]")
        return EXIT_RECOVERY_NOT_FOUND

    report = service.build_trace_health(run_id)
    if report.errors:
        status_label, status_color = "ERRORS FOUND", "red"
    elif report.warnings:
        status_label, status_color = "CLEAN WITH WARNINGS", "yellow"
    else:
        status_label, status_color = "CLEAN", "green"
    console.print(Panel(
        f"[bold]Run ID:[/bold]          {run_id}\n"
        f"[bold]Result:[/bold]          [{status_color}]{status_label}[/{status_color}]\n"
        f"[bold]Checks passed:[/bold]   {report.checks_passed}\n"
        f"[bold]Errors:[/bold]          {len(report.errors)}\n"
        f"[bold]Warnings:[/bold]        {len(report.warnings)}",
        title="[bold blue]Trace Health[/bold blue]",
    ))
    if report.issues:
        table = Table(title="Issues", show_lines=True)
        table.add_column("Check", style="cyan", width=28)
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Expected", style="green", width=32)
        table.add_column("Actual", style="red", width=32)
        for issue in report.issues:
            sev_color = "red" if issue.severity == "error" else "yellow"
            table.add_row(
                issue.check,
                f"[{sev_color}]{issue.severity}[/{sev_color}]",
                issue.expected,
                issue.actual,
            )
        console.print(table)
    else:
        console.print("[green]All checks passed. Trace is clean.[/green]")
    return EXIT_OK


# --- action dispatch --------------------------------------------------------

def _run_action(
    run_id: str, action: RecoveryAction, db_path: str, trace_dir: str,
    *, blueprint: str = "blueprints/research_decision_v1.yaml",
    target_step_id: int | None = None,
    reason: str | None = None, instructions: str | None = None,
    operator: str | None = None, new_budget: float | None = None,
    role: str | None = None, profile: str | None = None,
    profile_file: str | None = None,
) -> int:
    """Shared action dispatcher: build service, install delegate if needed,
    apply the action, render result + audit trail."""
    sm = StateManager(db_path=db_path)
    service = RecoveryService(state_manager=sm, trace_dir=trace_dir)
    if action not in (RecoveryAction.CANCEL_RUN, RecoveryAction.FAIL_RUN,
                      RecoveryAction.EXPORT_REPORT):
        # Delegation actions need the orchestrator delegate.
        try:
            delegate = _build_orchestrator_delegate(db_path, blueprint, trace_dir)
        except Exception as e:
            console.print(f"[red]Failed to build orchestrator delegate: {e}[/red]")
            return EXIT_RECOVERY_BLOCKED
        service.set_action_delegate(delegate)

    operator_identity = operator or os.environ.get("NODECHAIN_OPERATOR_IDENTITY", "console")
    operator_role = role or os.environ.get("NODECHAIN_OPERATOR_ROLE", "operator")
    # NOT here before apply_action. The delegate derives the decision from the
    # action enum + instructions, so a refused review never mutates persisted
    # state. apply_action remains the governed write boundary.

    result = service.apply_action(
        run_id, action, operator_identity=operator_identity,
        target_step_id=target_step_id, reason=reason, instructions=instructions,
        new_budget=new_budget, operator_role=operator_role,
        governance_profile=profile, governance_profile_file=profile_file,
    )
    _render_action_result(run_id, action, result)
    if not result.admitted:
        return EXIT_RECOVERY_BLOCKED
    return EXIT_OK


def _render_action_result(run_id: str, action: RecoveryAction, result) -> None:
    color = "green" if result.admitted else "red"
    label = "ALLOWED" if result.admitted else "BLOCKED"
    console.print(Panel(
        f"[bold]Run ID:[/bold]      {run_id}\n"
        f"[bold]Action:[/bold]      {action.value}\n"
        f"[bold]Result:[/bold]      [{color}]{label}[/{color}]\n"
        f"[bold]Resulting State:[/bold] {result.resulting_state or '(unchanged)'}\n"
        + (f"[bold]Reason:[/bold]     {result.rejection_reason}\n"
           if result.rejection_reason else ""),
        title="[bold blue]Recovery Action[/bold blue]",
    ))
    if result.trace_event_id:
        console.print(f"[dim]Trace event: {result.trace_event_id}[/dim]")
    if result.action_id:
        console.print(f"[dim]Audit row:   {result.action_id}[/dim]")


def recover_resolve_side_effect(
    run_id: str, side_effect_key: str, decision: str, db_path: str, trace_dir: str,
    *, reason: str = "", external_reference: str = "", response_hash: str = "",
    operator: str | None = None, role: str | None = None,
    profile: str | None = None, profile_file: str | None = None,
) -> int:
    """Resolve an unknown side effect via a governed recovery decision (v3.3.0).

    No orchestrator delegate is needed — resolution is a ledger-layer
    operation routed directly to
    ``StateManager.resolve_side_effect_recovery_decision``.
    """
    sm = StateManager(db_path=db_path)
    service = RecoveryService(state_manager=sm, trace_dir=trace_dir)
    # RESOLVE_SIDE_EFFECT does NOT need the orchestrator delegate.

    operator_identity = operator or os.environ.get("NODECHAIN_OPERATOR_IDENTITY", "console")
    operator_role = role or os.environ.get("NODECHAIN_OPERATOR_ROLE", "operator")

    result = service.apply_action(
        run_id, RecoveryAction.RESOLVE_SIDE_EFFECT,
        operator_identity=operator_identity, operator_role=operator_role,
        reason=reason,
        side_effect_key=side_effect_key,
        side_effect_decision=decision,
        external_reference=external_reference or None,
        response_hash=response_hash or None,
        governance_profile=profile, governance_profile_file=profile_file,
    )
    _render_action_result(run_id, RecoveryAction.RESOLVE_SIDE_EFFECT, result)
    if not result.admitted:
        return EXIT_RECOVERY_BLOCKED
    return EXIT_OK


def recover_execute_retry_authorized(
    run_id: str, side_effect_key: str, recovery_decision_id: str,
    db_path: str, trace_dir: str,
    *, reason: str = "",
    operator: str | None = None, role: str | None = None,
    profile: str | None = None, profile_file: str | None = None,
) -> int:
    """Execute a retry-authorized side effect through the recovery seam (v3.5.0).

    ChatGPT T8: must NOT reuse _build_orchestrator_delegate(). The retry
    coordinator is a separate seam (INV-005) — it dispatches through the
    RecoveryDispatchGuard, not the typed-port orchestrator loop.

    Constructs and injects SideEffectRetryCoordinator via
    service.set_retry_coordinator(). The coordinator needs:
    - KEK (resolved at this composition boundary via the dedicated helper)
    - adapter_factory (constructs fresh adapter instances by name)
    """
    # v3.5.1 (#8) B3: this is the execution composition boundary — resolve
    # the KEK mode here and inject. Read-only commands (list/inspect) may use
    # the production-default StateManager because KEK loading is lazy.
    from nodechain.core.capsule_crypto import resolve_kek_manager_from_environment
    sm = StateManager(db_path=db_path, kek_manager=resolve_kek_manager_from_environment())
    service = RecoveryService(state_manager=sm, trace_dir=trace_dir)

    operator_identity = operator or os.environ.get("NODECHAIN_OPERATOR_IDENTITY", "console")
    operator_role = role or os.environ.get("NODECHAIN_OPERATOR_ROLE", "operator")

    # ChatGPT T8 fix 5: KEK resolution deferred to the coordinator (lazy),
    # not resolved here before authorization. The coordinator loads the KEK
    # inside the governed execution path after apply_action authorizes.

    # ChatGPT T8 fix 3: fresh adapter construction via trusted class registry,
    # NOT _get_adapter() which returns globally cached instances.
    from nodechain.runtime.recovery_dispatch_guard import TRUSTED_ADAPTER_CLASSES
    from nodechain.runtime.side_effect_retry_coordinator import (
        SideEffectRetryCoordinator,
    )
    # v3.5.0 T9: shared metrics emitter — one instance for both the service
    # (policy_denied/rejected) and the coordinator (lifecycle/outcome).
    from nodechain.runtime.recovery_metrics import make_emitter
    metrics = make_emitter(db_path)

    def adapter_factory(name: str):
        """Construct a fresh adapter instance for recovery isolation."""
        cls = TRUSTED_ADAPTER_CLASSES.get(name)
        if cls is None:
            raise ValueError(f"Unknown or untrusted adapter: {name}")
        return cls()

    coordinator = SideEffectRetryCoordinator(
        sm, kek=None,  # lazy — coordinator resolves via KekManager inside governed path
        adapter_factory=adapter_factory,
        metrics_emitter=metrics,
    )
    service.set_retry_coordinator(coordinator)
    service.set_metrics_emitter(metrics)

    result = service.apply_action(
        run_id, RecoveryAction.EXECUTE_RETRY_AUTHORIZED,
        operator_identity=operator_identity, operator_role=operator_role,
        reason=reason,
        side_effect_key=side_effect_key,
        recovery_decision_id=recovery_decision_id,
        governance_profile=profile, governance_profile_file=profile_file,
    )

    # Load chain state for rendering
    state = sm.load(run_id)

    # Render the three-truth outcome (INV-009)
    _render_retry_result(run_id, side_effect_key, result, sm, state)

    if not result.admitted:
        return EXIT_RECOVERY_BLOCKED
    return EXIT_OK


def _render_retry_result(
    run_id: str, side_effect_key: str, result, sm: StateManager, state=None,
) -> None:
    """Render the three-truth outcome for a retry-authorized execution (INV-009).

    ChatGPT T8 fix 2: render ALL three independent truths:
    Truth 1: node invocation outcome
    Truth 2: child side-effect status
    Truth 3: operator-action outcome + dispatch occurred
    Plus: parent history (unchanged), chain status, further recovery guidance.
    """
    color = "green" if result.admitted else "red"
    label = "ALLOWED" if result.admitted else "BLOCKED"

    # Load the parent for history
    parent = sm.get_side_effect_by_key(run_id, side_effect_key)
    parent_status = parent["status"] if parent else "(not found)"

    # Extract three-truth fields from the retry result if available
    retry_result = getattr(result, "retry_result", None)
    if retry_result:
        node_outcome = retry_result.node_invocation_outcome
        child_status = retry_result.child_status
        operator_outcome = retry_result.operator_action_outcome
        dispatch_performed = retry_result.dispatch_performed
    else:
        node_outcome = "not attempted"
        child_status = result.resulting_state or "(unknown)"
        operator_outcome = "blocked"
        dispatch_performed = False

    chain_status = state.status if state else "(unknown)"

    # Determine further recovery
    further_recovery = "none"
    if not result.admitted:
        further_recovery = "retry not attempted"
    elif child_status == "unknown":
        further_recovery = "operator intervention required (outcome uncertain)"
    elif child_status == "failed":
        further_recovery = "operator may re-authorize if eligible"
    elif child_status in ("planned", "started"):
        further_recovery = "execution in progress"

    console.print(Panel(
        f"[bold]Run ID:[/bold]              {run_id}\n"
        f"[bold]Action:[/bold]              execute_retry_authorized\n"
        f"[bold]Result:[/bold]              [{color}]{label}[/{color}]\n"
        f"\n[bold dim]── Three-Truth Outcome (INV-009) ──[/bold dim]\n"
        f"[bold]Node Invocation:[/bold]     {node_outcome}\n"
        f"[bold]Side-Effect Status:[/bold]  {child_status}\n"
        f"[bold]Operator Action:[/bold]     {operator_outcome}\n"
        f"[bold]Dispatch Occurred:[/bold]   {dispatch_performed}\n"
        f"\n[bold dim]── History & State ──[/bold dim]\n"
        f"[bold]Original Attempt:[/bold]    {parent_status}\n"
        f"[bold]Chain Status:[/bold]        {chain_status}\n"
        f"[bold]Further Recovery:[/bold]    {further_recovery}\n"
        + (f"\n[bold]Reason:[/bold]            {result.rejection_reason}"
           if result.rejection_reason else ""),
        title="[bold blue]Retry-Authorized Execution[/bold blue]",
    ))
    if result.trace_event_id:
        console.print(f"[dim]Trace event: {result.trace_event_id}[/dim]")
    if result.action_id:
        console.print(f"[dim]Audit row:   {result.action_id}[/dim]")


# --- report export ----------------------------------------------------------

def recover_report(
    run_id: str, db_path: str, trace_dir: str, output: str | None = None,
) -> int:
    """Build and optionally export a recovery report."""
    sm = StateManager(db_path=db_path)
    service = RecoveryService(state_manager=sm, trace_dir=trace_dir)
    snapshot = service.build_snapshot(run_id)
    if snapshot is None:
        console.print(f"[red]No saved state found for run: {run_id}[/red]")
        return EXIT_RECOVERY_NOT_FOUND
    report = service.apply_action(
        run_id, RecoveryAction.EXPORT_REPORT,
        operator_identity=os.environ.get("NODECHAIN_OPERATOR_IDENTITY", "console"),
    )
    blob = _json.dumps(snapshot.model_dump(), indent=2)
    if output:
        with open(output, "w") as f:
            f.write(blob)
        console.print(f"[green]Recovery report written to {output}[/green]")
    else:
        console.print(blob)
    _render_action_result(run_id, RecoveryAction.EXPORT_REPORT, report)
    return EXIT_OK if report.admitted else EXIT_RECOVERY_BLOCKED


# --- rendering ---------------------------------------------------------------

def _render_snapshot(snapshot) -> None:
    status_color = _status_color(snapshot.status)
    console.print(Panel(
        f"[bold]Run ID:[/bold]            {snapshot.run_id}\n"
        f"[bold]Chain ID:[/bold]          {snapshot.chain_id}\n"
        f"[bold]Status:[/bold]            [{status_color}]{snapshot.status}[/{status_color}]\n"
        f"[bold]Recovery State:[/bold]    [magenta]{snapshot.recovery_state}[/magenta]\n"
        f"[bold]Current Node:[/bold]      {snapshot.current_node or '(none)'}\n"
        f"[bold]Current Step:[/bold]      {snapshot.current_step if snapshot.current_step is not None else '(none)'}\n"
        f"[bold]Last Success:[/bold]      {snapshot.last_successful_step if snapshot.last_successful_step is not None else '(none)'}\n"
        f"[bold]Failed Step:[/bold]       {snapshot.failed_step if snapshot.failed_step is not None else '(none)'}\n"
        f"[bold]Blocking Reason:[/bold]   {snapshot.blocking_reason or '(none)'}\n"
        f"[bold]State Revision:[/bold]    {snapshot.state_revision}\n"
        f"[bold]Last Update:[/bold]       {(snapshot.last_update_time or '')[:19]}\n"
        f"[bold]Trace Complete:[/bold]    {'yes' if snapshot.trace_complete else 'no — see issues'}",
        title="[bold blue]Recovery Snapshot[/bold blue]",
    ))

    # T9: render trace errors (repair failures, reconciliation errors)
    if snapshot.trace_errors:
        console.print("\n[bold red]Trace Errors[/bold red]")
        for e in snapshot.trace_errors:
            console.print(f"  ✗ {e}")

    if snapshot.trace_warnings:
        console.print("\n[bold yellow]Trace Warnings[/bold yellow]")
        for w in snapshot.trace_warnings:
            console.print(f"  ! {w}")

    if snapshot.loop_counters:
        console.print("\n[bold]Loop Counters[/bold]")
        for name, n in snapshot.loop_counters.items():
            console.print(f"  [blue]{name}[/blue]: {n}")

    if snapshot.retry_counters:
        console.print("\n[bold]Retry Counters[/bold]")
        for name, n in snapshot.retry_counters.items():
            console.print(f"  [blue]{name}[/blue]: {n}")

    if snapshot.pending_review:
        console.print(Panel(
            _format_kv(snapshot.pending_review),
            title="[bold yellow]Pending Human Review[/bold yellow]",
        ))

    if snapshot.available_actions:
        console.print(f"\n[bold green]Available actions:[/bold green] "
                      f"{', '.join(snapshot.available_actions)}")
    else:
        console.print("\n[dim]No operator actions available.[/dim]")


def _format_kv(d: dict) -> str:
    return "\n".join(f"[bold]{k}:[/bold] {v}" for k, v in d.items())


# --- batch execution (v2.50.0) -----------------------------------------------

def _run_batch(
    batch_file: str, db_path: str, trace_dir: str, blueprint: str,
    *, dry_run: bool = False, continue_on_error: bool = False,
    operator: str | None = None, role: str | None = None,
    profile: str | None = None, profile_file: str | None = None,
) -> int:
    """Execute (or dry-run) a YAML recovery batch."""
    from nodechain.runtime.batch_recovery import parse_batch_file, BatchExecutor

    try:
        spec = parse_batch_file(batch_file)
    except Exception as e:
        console.print(f"[red]Batch file error: {e}[/red]")
        return 1

    sm = StateManager(db_path=db_path)
    service = RecoveryService(state_manager=sm, trace_dir=trace_dir)

    effective_dry_run = dry_run or spec.dry_run
    effective_identity = operator or spec.operator_identity or os.environ.get(
        "NODECHAIN_OPERATOR_IDENTITY", "console")
    effective_role = role or spec.operator_role or os.environ.get(
        "NODECHAIN_OPERATOR_ROLE", "operator")
    # v2.52.0: CLI profile overrides YAML profile.
    effective_profile = profile or spec.governance_profile or os.environ.get(
        "NODECHAIN_GOVERNANCE_PROFILE", "")
    effective_profile_file = profile_file or os.environ.get(
        "NODECHAIN_GOVERNANCE_PROFILE_FILE", "")
    if effective_profile:
        spec.governance_profile = effective_profile
    # v2.52.0: preserve profile_file for custom profiles through batch execution
    if effective_profile_file:
        spec.governance_profile_file = effective_profile_file

    mode_label = "DRY-RUN" if effective_dry_run else "EXECUTE"
    console.print(Panel(
        f"[bold]Batch ID:[/bold]     {spec.batch_id}\n"
        f"[bold]Mode:[/bold]         {mode_label}\n"
        f"[bold]Operator:[/bold]     {effective_identity} ({effective_role})\n"
        f"[bold]Profile:[/bold]      {effective_profile or 'team-default'}\n"
        f"[bold]Actions:[/bold]      {len(spec.actions)}\n"
        f"[bold]Continue:[/bold]     {continue_on_error}",
        title=f"[bold blue]Batch {mode_label}[/bold blue]",
    ))

    executor = BatchExecutor(service)
    summary = executor.execute(
        spec,
        dry_run=effective_dry_run,
        continue_on_error=continue_on_error,
        operator_identity=effective_identity,
        operator_role=effective_role,
    )

    # Print per-action results
    for r in summary.results:
        status_color = {
            "admitted": "green", "executed": "green",
            "denied": "red", "failed": "red", "skipped": "yellow",
            "pending": "dim",
        }.get(r.status, "white")
        console.print(
            f"  [{status_color}][{r.index+1}][/{status_color}] "
            f"{r.action.value} {r.run_id} → {r.status}"
            + (f" ({r.denial_type})" if r.denial_type else "")
        )

    # Print summary
    console.print(Panel(
        f"[bold]Total:[/bold]     {summary.total_actions}\n"
        f"[bold]Admitted:[/bold]  {summary.admitted_count}\n"
        f"[bold]Denied:[/bold]    {summary.denied_count}\n"
        f"[bold]Executed:[/bold]  {summary.executed_count}\n"
        f"[bold]Skipped:[/bold]   {summary.skipped_count}\n"
        f"[bold]Status:[/bold]    {summary.overall_status}",
        title="[bold blue]Batch Summary[/bold blue]",
    ))

    # Exit code: 0 if all admitted, 1 if any denial/failure
    if summary.denied_count > 0 or summary.failed_count > 0:
        return 1
    return 0


def _status_color(status: str) -> str:
    if status in ("completed",):
        return "green"
    if status in ("failed", "cancelled"):
        return "red"
    if status in ("waiting_for_review", "paused"):
        return "yellow"
    return "white"
