"""Research workspace CLI commands.

Commands:
    nodechain research run <brief> [--corpus <path>]
    nodechain research review <run-id> --decision approve|reject|revise \
        --reason "<reason>" --reviewer "<identity>"
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel

from nodechain.cli.exit_codes import (
    EXIT_OK,
    EXIT_NOT_FOUND,
    EXIT_RUN_PAUSED,
    EXIT_RUN_FAILED,
    EXIT_RUN_VALIDATION,
    EXIT_RESUME_NOT_RESUMABLE,
)

console = Console()


# --------------------------------------------------------------------------- #
# Command group
# --------------------------------------------------------------------------- #


@click.group("research")
def research() -> None:
    """Governed research workspace commands (Phase 5)."""
    pass


# --------------------------------------------------------------------------- #
# research run
# --------------------------------------------------------------------------- #


@research.command("run")
@click.argument("brief", required=True)
@click.option(
    "--profile",
    "profile",
    default="fixture",
    type=click.Choice(["fixture", "live"]),
    help="Acquisition profile: 'fixture' (default) runs the sealed corpus "
         "path and requires --corpus; 'live' acquires sources through the "
         "existing governed academic adapters and rejects --corpus.",
)
@click.option(
    "--corpus",
    "corpus_path",
    default=None,
    required=False,
    type=click.Path(exists=True),
    help="Path to the sealed fixture corpus YAML file "
         "(required for --profile fixture).",
)
@click.option(
    "--workspace",
    "workspace_dir",
    default=None,
    help="Operational workspace directory (default: data/research_workspace). "
         "Created implicitly on first run — the workspace root is the parent "
         "of runs/, not a separate identity.",
)
@click.option(
    "--db",
    "db_path",
    default=None,
    help="Path to the run state database (default: <workspace>/run.db).",
)
@click.option(
    "--trace-dir",
    "trace_dir",
    default=None,
    help="Directory for trace files (default: <workspace>/traces).",
)
@click.option(
    "--json-output",
    "json_output",
    default=None,
    help="Write machine-readable JSON output to this path.",
)
def research_run(
    brief: str,
    profile: str,
    corpus_path: str | None,
    workspace_dir: str | None,
    db_path: str | None,
    trace_dir: str | None,
    json_output: str | None,
) -> None:
    """Execute a sealed research workspace run.

    BRIEF is either a path to a brief file (YAML/JSON) or an inline question
    string.
    """
    from nodechain.research.runner import ResearchBrief, WorkspaceRunner

    # Fail-closed profile/corpus combination rules — no silent fallback in
    # either direction.
    if profile == "fixture" and corpus_path is None:
        console.print(
            "[red]Error:[/red] the fixture acquisition profile requires "
            "--corpus"
        )
        sys.exit(EXIT_RUN_VALIDATION)
    if profile == "live" and corpus_path is not None:
        console.print(
            "[red]Error:[/red] the live acquisition profile does not accept "
            "--corpus"
        )
        sys.exit(EXIT_RUN_VALIDATION)

    # Load brief: file path or inline question.
    brief_path = Path(brief)
    if brief_path.exists():
        rb = ResearchBrief.from_file(brief_path)
    else:
        rb = ResearchBrief.from_question(brief)

    acquisition_line = (
        f"Corpus: {corpus_path}" if profile == "fixture"
        else "Acquisition: live governed academic adapters"
    )
    console.print(Panel(
        f"[bold blue]Phase 5 Research Workspace[/bold blue]\n\n"
        f"Question: {rb.question}\n"
        f"Profile: {profile}\n"
        f"{acquisition_line}",
        title="Starting Sealed Run" if profile == "fixture"
        else "Starting Live Run",
    ))

    runner = WorkspaceRunner(
        brief=rb,
        corpus_path=corpus_path,
        profile=profile,
        db_path=db_path,
        trace_dir=trace_dir,
        workspace_dir=workspace_dir,
    )

    if profile == "fixture":
        console.print(f"[dim]Corpus digest: {runner.corpus_digest[:16]}...[/dim]")

    result = runner.run()

    if result.paused:
        workspace_arg = (
            f' --workspace "{workspace_dir}"'
            if workspace_dir is not None
            else ""
        )
        console.print(Panel(
            f"[yellow]PAUSED FOR REVIEW[/yellow]\n\n"
            f"Run ID: {result.run_id}\n"
            f"Status: {result.state.status}\n\n"
            f"Review with:\n"
            f"  nodechain research review {result.run_id}"
            f"{workspace_arg} "
            f"--decision approve|reject|revise "
            f'--reason "..." --reviewer "..."',
            title="Review Required",
        ))
        paused_meta = {
            "run_id": result.run_id,
            "status": "paused",
            "paused_for_review": True,
            "acquisition_profile": profile,
            "corpus_digest": result.corpus_digest,
        }
        if workspace_dir is not None:
            paused_meta["workspace_dir"] = workspace_dir
        _maybe_write_json(json_output, paused_meta)
        sys.exit(EXIT_RUN_PAUSED)  # paused exit code
    elif result.completed:
        console.print(Panel(
            f"[green]COMPLETED[/green]\n\n"
            f"Run ID: {result.run_id}\n"
            f"Final status: {result.trace.final_status}",
            title="Run Complete",
        ))
        _maybe_write_json(json_output, {
            "run_id": result.run_id,
            "status": "completed",
            "final_status": result.trace.final_status,
            "acquisition_profile": profile,
            "corpus_digest": result.corpus_digest,
        })
        sys.exit(EXIT_OK)
    elif result.failed:
        console.print(Panel(
            f"[red]FAILED[/red]\n\n"
            f"Run ID: {result.run_id}\n"
            f"Final status: {result.trace.final_status}",
            title="Run Failed",
        ))
        _maybe_write_json(json_output, {
            "run_id": result.run_id,
            "status": "failed",
            "final_status": result.trace.final_status,
            "acquisition_profile": profile,
            "corpus_digest": result.corpus_digest,
        })
        sys.exit(EXIT_RUN_FAILED)  # failed exit code


# --------------------------------------------------------------------------- #
# research review
# --------------------------------------------------------------------------- #


@research.command("review")
@click.argument("run_id", required=True)
@click.option(
    "--decision",
    required=True,
    type=click.Choice(["approve", "reject", "revise"]),
    help="Review decision.",
)
@click.option(
    "--reason",
    required=True,
    help="Reason for the decision.",
)
@click.option(
    "--reviewer",
    required=True,
    help="Identity of the reviewer.",
)
@click.option(
    "--workspace",
    "workspace_dir",
    default=None,
    help="Operational workspace directory (auto-discovered from descriptor by default).",
)
def research_review(
    run_id: str,
    decision: str,
    reason: str,
    reviewer: str,
    workspace_dir: str | None,
) -> None:
    """Submit a review decision for a paused run and resume.

    RUN_ID is the identifier of the paused run. The corpus, brief, and database
    are auto-discovered from the persisted run descriptor — no resupply needed.
    """
    import json
    import uuid
    from datetime import datetime, timezone
    from pathlib import Path

    from nodechain.core.state import StateManager
    from nodechain.research.runner import WorkspaceRunner
    from nodechain.research.run_descriptor import load_descriptor

    # Discover the workspace and descriptor.
    ws = workspace_dir or "data/research_workspace"
    try:
        desc = load_descriptor(ws, run_id)
    except FileNotFoundError:
        console.print(f"[red]Error:[/red] no descriptor for run {run_id} in {ws}")
        sys.exit(EXIT_NOT_FOUND)

    # Verify the run exists and is paused using the descriptor's DB path.
    sm = StateManager(desc.db_path)
    state = sm.load(run_id)
    if state is None:
        console.print(f"[red]Error:[/red] run {run_id} not found in {desc.db_path}")
        sys.exit(EXIT_NOT_FOUND)
    if state.status not in ("waiting_for_review", "paused", "paused_for_budget"):
        console.print(
            f"[red]Error:[/red] run {run_id} is not paused "
            f"(status: {state.status})"
        )
        sys.exit(EXIT_RESUME_NOT_RESUMABLE)

    # Persist durable review evidence BEFORE attempting resume.
    review_id = str(uuid.uuid4())
    submitted_at = datetime.now(timezone.utc).isoformat()
    decision_map = {
        "approve": "approve",
        "reject": "reject",
        "revise": "request_revision",
    }
    runtime_decision = decision_map[decision]
    review_record = {
        "review_id": review_id,
        "run_id": run_id,
        "reviewer": reviewer,
        "requested_decision": decision,
        "runtime_decision": runtime_decision,
        "reason": reason,
        "submitted_at": submitted_at,
        "descriptor_digest": desc.descriptor_digest,
    }
    from nodechain.research.run_descriptor import save_review_record, save_outcome_record
    review_path = save_review_record(desc.workspace_dir, run_id, review_record)

    console.print(Panel(
        f"[bold blue]Review Decision[/bold blue]\n\n"
        f"Run ID: {run_id}\n"
        f"Decision: {decision} (runtime: {runtime_decision})\n"
        f"Reviewer: {reviewer}\n"
        f"Reason: {reason}\n"
        f"Review ID: {review_id}\n"
        f"Evidence: {review_path}",
        title="Resuming Run",
    ))

    # Reconstruct the runner from the descriptor via the reconstruction
    # authority. from_descriptor restores runner._run_descriptor, which the
    # terminal resume() path requires to call finalize_bundle(). The earlier
    # manual WorkspaceRunner(...) reconstruction left _run_descriptor unset,
    # so CLI resume silently skipped terminal bundle finalization.
    runner = WorkspaceRunner.from_descriptor(desc)

    # Apply the review decision (stores one-shot env vars).
    runner.apply_review(decision, reason, reviewer)

    # Reconstruct the orchestrator bound to the persisted run_id.
    # compose_for_resume binds the guard to the persisted ID for capsule lookup.
    # The existing orchestrator.resume(persisted_run_id) loads state from DB.
    runner.compose_for_resume(desc.run_id)
    # Resume through the existing runtime seam — do NOT manually replace state.
    # orchestrator.resume(run_id) loads state from the DB internally.
    result = runner.resume(run_id=desc.run_id)

    # Persist the resume outcome separately.
    outcome_record = {
        "review_id": review_id,
        "run_id": run_id,
        "resume_status": result.trace.final_status,
        "resumed_at": datetime.now(timezone.utc).isoformat(),
    }
    outcome_path = save_outcome_record(
        desc.workspace_dir, run_id, review_id, outcome_record
    )

    if result.completed:
        console.print(Panel(
            f"[green]COMPLETED AFTER REVIEW[/green]\n\n"
            f"Run ID: {result.run_id}\n"
            f"Final status: {result.trace.final_status}",
            title="Run Complete",
        ))
        sys.exit(EXIT_OK)
    elif result.paused:
        console.print(Panel(
            f"[yellow]STILL PAUSED[/yellow]\n\n"
            f"Run ID: {result.run_id}\n"
            f"Status: {result.state.status}",
            title="Review Round",
        ))
        sys.exit(EXIT_RUN_PAUSED)
    else:
        console.print(Panel(
            f"[red]FAILED AFTER REVIEW[/red]\n\n"
            f"Run ID: {result.run_id}\n"
            f"Final status: {result.trace.final_status}",
            title="Run Failed",
        ))
        sys.exit(EXIT_RUN_FAILED)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _maybe_write_json(path: str | None, data: dict) -> None:
    if path:
        Path(path).write_text(
            json.dumps(data, indent=2, sort_keys=True), encoding="utf-8"
        )


# ========================================================================== #
# H1.2: Read-side operator commands (runtime-state read-only through
# open_workspace; export additionally writes only its explicit output
# artifact)
# ========================================================================== #


_DEFAULT_WORKSPACE = "data/research_workspace"


def _snapshot_to_dict(snap) -> dict:
    """Serialize a ResearchWorkspaceSnapshot for JSON output."""
    return snap.model_dump(mode="json")


def _jsonable(value):
    """Convert Pydantic models (and lists of them) to plain JSON values.

    A Pydantic model becomes model_dump(mode="json"); a list converts each
    element; plain JSON values pass through unchanged.
    """
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, list):
        return [_jsonable(v) for v in value]
    return value


def _print_section_table(snap, console_: Console) -> None:
    """Print a compact section-availability table."""
    from rich.table import Table
    table = Table(title="Workspace Sections", show_lines=False)
    table.add_column("Section", style="cyan")
    table.add_column("State", style="green")
    for name in ("objective", "plan", "sources", "qualified_sources",
                 "evidence", "claims", "citations", "uncertainties",
                 "trace", "terminal_bundle"):
        section = getattr(snap, name, None)
        if section is not None:
            state = section.state
            style = ("green" if state == "terminal_verified"
                     else "yellow" if "live" in state else "dim")
            table.add_row(name, f"[{style}]{state}[/{style}]")
    console_.print(table)


@research.command("open")
@click.option("--workspace", "workspace_dir", default=_DEFAULT_WORKSPACE,
              help="Workspace directory.")
@click.option("--run-id", "run_id", default=None,
              help="Specific run to select (default: most recently persisted).")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
def research_open(workspace_dir: str, run_id: str | None, as_json: bool) -> None:
    """Open a research workspace and show its overview.

    Creates nothing — this is a read-only observation through the H1.1
    ResearchWorkspaceSnapshot. A nonexistent workspace returns an empty
    overview, not an error.
    """
    from nodechain.research.workspace import open_workspace
    snap = open_workspace(workspace_dir, run_id=run_id)
    if as_json:
        click.echo(json.dumps(_snapshot_to_dict(snap), indent=2,
                              default=str))
        return
    if not snap.runs:
        console.print(Panel(
            f"[dim]No discoverable runs in {workspace_dir}[/dim]",
            title="Workspace",
        ))
        return
    from rich.table import Table
    table = Table(title=f"Workspace: {snap.workspace_root}")
    table.add_column("Run ID", style="cyan")
    table.add_column("Status")
    table.add_column("Profile")
    table.add_column("Revision")
    table.add_column("Bundle")
    for r in snap.runs:
        marker = " →" if r.run_id == snap.selected_run_id else ""
        table.add_row(r.run_id + marker, r.execution_status or "—",
                      r.acquisition_profile, str(r.revision), r.bundle_status)
    console.print(table)
    sel = next((r for r in snap.runs if r.run_id == snap.selected_run_id), None)
    if sel:
        console.print(f"\n[bold]Selected:[/bold] {sel.run_id}")
        console.print(f"  Execution: {sel.execution_status or '—'}")
        console.print(f"  Acquisition profile: {snap.acquisition_profile}")
        console.print(f"  Reproducibility: {snap.reproducibility_mode}")
        console.print(f"  Research outcome: {snap.research_outcome or '—'}")
        console.print(f"  Bundle: {snap.bundle_status}")


@research.command("runs")
@click.option("--workspace", "workspace_dir", default=_DEFAULT_WORKSPACE,
              help="Workspace directory.")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
def research_runs(workspace_dir: str, as_json: bool) -> None:
    """List all discoverable runs in a workspace."""
    from nodechain.research.workspace import open_workspace
    snap = open_workspace(workspace_dir)
    if as_json:
        click.echo(json.dumps(
            {"runs": [r.model_dump(mode="json") for r in snap.runs]},
            indent=2, default=str))
        return
    if not snap.runs:
        console.print(f"[dim]No runs in {workspace_dir}[/dim]")
        return
    from rich.table import Table
    table = Table(title=f"Runs in {workspace_dir}")
    table.add_column("Run ID", style="cyan")
    table.add_column("Status")
    table.add_column("Profile")
    table.add_column("Rev")
    table.add_column("Step")
    table.add_column("Current Node")
    table.add_column("Bundle")
    table.add_column("Updated")
    for r in snap.runs:
        table.add_row(r.run_id, r.execution_status or "—",
                      r.acquisition_profile, str(r.revision),
                      str(r.step), r.current_node or "—", r.bundle_status,
                      r.updated_at[:19] if r.updated_at else "—")
    console.print(table)


@research.command("inspect")
@click.argument("run_id", required=True)
@click.option("--workspace", "workspace_dir", default=_DEFAULT_WORKSPACE,
              help="Workspace directory.")
@click.option("--section", "section", default=None,
              help="Show only one section (objective, plan, sources, etc.).")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
def research_inspect(run_id: str, workspace_dir: str, section: str | None,
                     as_json: bool) -> None:
    """Inspect one run: all sections with availability states, faults,
    recovery evidence, review truth, and the governed recovery handoff."""
    from nodechain.research.workspace import open_workspace
    try:
        snap = open_workspace(workspace_dir, run_id=run_id)
    except FileNotFoundError:
        console.print(f"[red]Error:[/red] no descriptor for run {run_id}")
        sys.exit(EXIT_NOT_FOUND)
    if as_json:
        click.echo(json.dumps(_snapshot_to_dict(snap), indent=2,
                              default=str))
        return
    console.print(Panel(
        f"[bold]{run_id}[/bold]\n"
        f"Execution: {snap.execution_status or '—'}  "
        f"Revision: {snap.runtime_revision}\n"
        f"Research outcome: {snap.research_outcome or '—'}  "
        f"Bundle: {snap.bundle_status}",
        title="Run Inspection",
    ))
    if section:
        attr = getattr(snap, section, None)
        if attr is None:
            console.print(f"[red]Unknown section:[/red] {section}")
            sys.exit(EXIT_NOT_FOUND)
        if hasattr(attr, "state"):
            console.print(f"\n[bold]{section}[/bold]: {attr.state}")
            if attr.data is not None:
                click.echo(json.dumps(_jsonable(attr.data), indent=2,
                                      default=str))
        else:
            click.echo(json.dumps(_jsonable(attr), indent=2, default=str))
        return
    _print_section_table(snap, console)
    if snap.faults:
        console.print(f"\n[bold red]Faults ({len(snap.faults)}):[/bold red]")
        for f in snap.faults:
            console.print(f"  {f.fault_id}: {f.fault_type} @ {f.node_id}"
                          f" — {f.reason}")
    # AC5a — governed recovery handoff: resolve the descriptor's DB path
    # and print the EXISTING recovery console syntax (no new action).
    actionable = [se for se in snap.recovery.side_effects
                  if se.get("status") in ("unknown", "retry_authorized")]
    if actionable:
        from nodechain.research.run_descriptor import load_descriptor
        # open_workspace already resolved and verified this descriptor; a
        # failure here is a real error that must surface, not something to
        # paper over with an unusable placeholder path.
        desc = load_descriptor(workspace_dir, run_id)
        desc_db = desc.db_path
        console.print(f"\n[bold yellow]Recovery required ({len(actionable)} "
                      f"actionable side effects):[/bold yellow]")
        for se in actionable:
            console.print(f"  side effect: {se.get('type', '?')}:"
                          f"{se.get('target', se.get('idempotency_key', '?'))}"
                          f"  status: {se.get('status', '?')}")
        unknown = [se for se in actionable
                   if se.get("status") == "unknown"]
        console.print(
            f"\n[bold]Next:[/bold] use the existing governed recovery "
            f"console:\n"
            f"  nodechain recover inspect {run_id} --db \"{desc_db}\""
        )
        if unknown:
            console.print(
                f"  nodechain recover list-unknown {run_id} "
                f"--db \"{desc_db}\""
            )


@research.command("verify")
@click.argument("run_id", required=True)
@click.option("--workspace", "workspace_dir", default=_DEFAULT_WORKSPACE,
              help="Workspace directory.")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
def research_verify(run_id: str, workspace_dir: str, as_json: bool) -> None:
    """Verify a run's terminal bundle through BundleReader integrity."""
    from nodechain.research.workspace import (
        BUNDLE_ABSENT, BUNDLE_INVALID, BUNDLE_VERIFIED, open_workspace,
    )
    try:
        snap = open_workspace(workspace_dir, run_id=run_id)
    except FileNotFoundError:
        console.print(f"[red]Error:[/red] no descriptor for run {run_id}")
        sys.exit(EXIT_NOT_FOUND)
    tb = snap.terminal_bundle.data
    result = {
        "run_id": run_id,
        "bundle_status": snap.bundle_status,
        "bundle_digest": getattr(tb, "bundle_digest", "") if tb else "",
        "run_status": getattr(tb, "run_status", "") if tb else "",
        "document_count": getattr(tb, "document_count", 0) if tb else 0,
        "documents": list(getattr(tb, "documents", []) or []) if tb else [],
    }
    if as_json:
        # Rendering mode must not change verification semantics: an invalid
        # bundle exits nonzero after the JSON is emitted.
        click.echo(json.dumps(result, indent=2))
        if snap.bundle_status == BUNDLE_INVALID:
            sys.exit(EXIT_RUN_VALIDATION)
        return
    if snap.bundle_status == BUNDLE_VERIFIED:
        docs = "".join(f"\n  - {name}" for name in result["documents"])
        console.print(Panel(
            f"[green]VERIFIED[/green]\n\n"
            f"Bundle digest: {result['bundle_digest'][:16]}...\n"
            f"Run status: {result['run_status']}\n"
            f"Documents: {result['document_count']}{docs}",
            title="Terminal Bundle",
        ))
    elif snap.bundle_status == BUNDLE_INVALID:
        console.print(Panel(
            f"[red]INVALID[/red]\n\n"
            f"Bundle exists but integrity verification failed.",
            title="Terminal Bundle",
        ))
        sys.exit(EXIT_RUN_VALIDATION)
    else:
        console.print(f"[dim]No terminal bundle for run {run_id}[/dim]")


@research.command("compare")
@click.argument("run_id_a", required=True)
@click.argument("run_id_b", required=True)
@click.option("--workspace", "workspace_dir", default=_DEFAULT_WORKSPACE,
              help="Workspace directory.")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
def research_compare(run_id_a: str, run_id_b: str, workspace_dir: str,
                     as_json: bool) -> None:
    """Compare two runs side by side."""
    from nodechain.research.workspace import open_workspace
    try:
        snap_a = open_workspace(workspace_dir, run_id=run_id_a)
        snap_b = open_workspace(workspace_dir, run_id=run_id_b)
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(EXIT_NOT_FOUND)

    def _count(section_data) -> int:
        if isinstance(section_data, list):
            return len(section_data)
        if isinstance(section_data, dict):
            for key in ("sources", "qualified_sources", "claims", "evidence"):
                if key in section_data and isinstance(section_data[key], list):
                    return len(section_data[key])
        return 0

    result = {
        "run_a": {
            "run_id": run_id_a,
            "execution_status": snap_a.execution_status,
            "research_outcome": snap_a.research_outcome,
            "bundle_status": snap_a.bundle_status,
            "revision": snap_a.runtime_revision,
            "sources_count": _count(snap_a.sources.data),
            "qualified_sources_count": _count(snap_a.qualified_sources.data),
            "claims_count": _count(snap_a.claims.data),
        },
        "run_b": {
            "run_id": run_id_b,
            "execution_status": snap_b.execution_status,
            "research_outcome": snap_b.research_outcome,
            "bundle_status": snap_b.bundle_status,
            "revision": snap_b.runtime_revision,
            "sources_count": _count(snap_b.sources.data),
            "qualified_sources_count": _count(snap_b.qualified_sources.data),
            "claims_count": _count(snap_b.claims.data),
        },
    }
    if as_json:
        click.echo(json.dumps(result, indent=2))
        return
    from rich.table import Table
    table = Table(title=f"Run Comparison: {run_id_a} vs {run_id_b}")
    table.add_column("Property")
    table.add_column(run_id_a, style="cyan")
    table.add_column(run_id_b, style="magenta")
    for key in ("execution_status", "research_outcome", "bundle_status",
                "revision", "sources_count", "qualified_sources_count",
                "claims_count"):
        table.add_row(key, str(result["run_a"][key]), str(result["run_b"][key]))
    console.print(table)


@research.command("export")
@click.argument("run_id", required=True)
@click.option("--output", "output_path", required=True,
              help="Output path for the exported bundle (directory or .zip).")
@click.option("--workspace", "workspace_dir", default=_DEFAULT_WORKSPACE,
              help="Workspace directory.")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
def research_export(run_id: str, output_path: str, workspace_dir: str,
                    as_json: bool) -> None:
    """Export a run's verified terminal bundle.

    Operates only on a bundle that passes BundleReader integrity
    verification. Copies the authoritative artifact — never regenerates
    or reinterprets it.
    """
    import shutil as _shutil
    from nodechain.research.workspace import BUNDLE_VERIFIED, open_workspace
    try:
        snap = open_workspace(workspace_dir, run_id=run_id)
    except FileNotFoundError:
        console.print(f"[red]Error:[/red] no descriptor for run {run_id}")
        sys.exit(EXIT_NOT_FOUND)
    if snap.bundle_status != BUNDLE_VERIFIED:
        console.print(
            f"[red]Error:[/red] bundle is {snap.bundle_status}, not verified"
        )
        sys.exit(EXIT_NOT_FOUND)

    bundle_dir = (Path(workspace_dir) / "runs" / run_id / "bundle").resolve()
    out = Path(output_path).resolve()
    if out.suffix == ".zip":
        # Zip the verified bundle directory.
        out.parent.mkdir(parents=True, exist_ok=True)
        _shutil.make_archive(str(out.with_suffix("")), "zip",
                             root_dir=str(bundle_dir.parent),
                             base_dir=bundle_dir.name)
        exported = out
    else:
        # Copy the bundle directory.
        if out.exists():
            console.print(f"[red]Error:[/red] output already exists: {out}")
            sys.exit(EXIT_RUN_VALIDATION)
        _shutil.copytree(bundle_dir, out)
        exported = out

    result = {
        "run_id": run_id,
        "exported_to": str(exported),
        "bundle_digest": (snap.terminal_bundle.data.bundle_digest
                          if snap.terminal_bundle.data else ""),
    }
    if as_json:
        click.echo(json.dumps(result, indent=2))
        return
    console.print(Panel(
        f"[green]EXPORTED[/green]\n\n"
        f"Run: {run_id}\n"
        f"Output: {exported}\n"
        f"Digest: {result['bundle_digest'][:16]}...",
        title="Bundle Export",
    ))


@research.command("report")
@click.argument("run_id", required=True)
@click.option("--workspace", "workspace_dir", default=_DEFAULT_WORKSPACE,
              help="Workspace directory.")
@click.option("--output", "output_path", default=None,
              help="Write a UTF-8 Markdown memo to this path.")
@click.option("--json", "as_json", is_flag=True,
              help="Emit the structured ResearchMemoV1 JSON instead of the "
                   "terminal presentation.")
def research_report(run_id: str, workspace_dir: str, output_path: str | None,
                    as_json: bool) -> None:
    """Render a verified terminal bundle as a human-readable memo.

    The memo is a deterministic view of evidence the governed run already
    produced — no model call, no network, no re-research. Only a
    BundleReader-verified terminal bundle may be reported; absent or
    invalid bundles fail nonzero and create no artifact.
    """
    from nodechain.research.report import build_memo, render_markdown
    bundle_dir = Path(workspace_dir) / "runs" / run_id / "bundle"
    if not (bundle_dir / "manifest.json").exists():
        console.print(
            f"[red]Error:[/red] no terminal bundle for run {run_id}"
        )
        sys.exit(EXIT_NOT_FOUND)
    try:
        memo = build_memo(bundle_dir)
    except FileNotFoundError:
        console.print(f"[red]Error:[/red] no terminal bundle for run {run_id}")
        sys.exit(EXIT_NOT_FOUND)
    except Exception as exc:
        # Integrity failure (or malformed bundle) — never render an
        # unverified bundle, never create the output artifact.
        console.print(
            f"[red]Error:[/red] bundle failed verification for {run_id}: "
            f"{exc}"
        )
        sys.exit(EXIT_RUN_VALIDATION)

    if output_path is not None:
        out = Path(output_path)
        if out.exists():
            console.print(f"[red]Error:[/red] output already exists: {out}")
            sys.exit(EXIT_RUN_VALIDATION)
        # A report artifact inside the canonical bundle would add a
        # sixteenth physical member and invalidate the source bundle's
        # integrity verification — reject containment, including through
        # symlinked parents.
        try:
            out_resolved = out.resolve(strict=False)
            bundle_resolved = bundle_dir.resolve(strict=False)
            out_resolved.relative_to(bundle_resolved)
        except ValueError:
            pass  # not contained — safe
        else:
            console.print(
                f"[red]Error:[/red] report output must not be written "
                f"inside the canonical bundle: {out}"
            )
            sys.exit(EXIT_RUN_VALIDATION)
        markdown = render_markdown(memo)
        out.parent.mkdir(parents=True, exist_ok=True)
        # Bytes, not text: deterministic line endings on every platform.
        out.write_bytes(markdown.encode("utf-8"))

    if as_json:
        click.echo(json.dumps(memo.model_dump(mode="json"), indent=2))
        return

    if output_path is not None:
        console.print(Panel(
            f"[green]REPORT WRITTEN[/green]\n\nRun: {run_id}\n"
            f"Output: {output_path}\n"
            f"Source bundle digest: {memo.bundle_digest[:16]}...",
            title="Research Memo",
        ))
        return

    from nodechain.research.report import render_rich
    render_rich(memo, console)
