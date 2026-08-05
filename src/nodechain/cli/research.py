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
    "--corpus",
    "corpus_path",
    required=True,
    type=click.Path(exists=True),
    help="Path to the sealed fixture corpus YAML file.",
)
@click.option(
    "--db",
    "db_path",
    default=None,
    help="Path to the run state database (default: data/research_workspace.db).",
)
@click.option(
    "--trace-dir",
    "trace_dir",
    default=None,
    help="Directory for trace files (default: data/traces).",
)
@click.option(
    "--json-output",
    "json_output",
    default=None,
    help="Write machine-readable JSON output to this path.",
)
def research_run(
    brief: str,
    corpus_path: str,
    db_path: str | None,
    trace_dir: str | None,
    json_output: str | None,
) -> None:
    """Execute a sealed research workspace run.

    BRIEF is either a path to a brief file (YAML/JSON) or an inline question
    string.
    """
    from nodechain.research.runner import ResearchBrief, WorkspaceRunner

    # Load brief: file path or inline question.
    brief_path = Path(brief)
    if brief_path.exists():
        rb = ResearchBrief.from_file(brief_path)
    else:
        rb = ResearchBrief.from_question(brief)

    console.print(Panel(
        f"[bold blue]Phase 5 Research Workspace[/bold blue]\n\n"
        f"Question: {rb.question}\n"
        f"Corpus: {corpus_path}",
        title="Starting Sealed Run",
    ))

    runner = WorkspaceRunner(
        brief=rb,
        corpus_path=corpus_path,
        db_path=db_path,
        trace_dir=trace_dir,
    )

    console.print(f"[dim]Corpus digest: {runner.corpus_digest[:16]}...[/dim]")

    result = runner.run()

    if result.paused:
        console.print(Panel(
            f"[yellow]PAUSED FOR REVIEW[/yellow]\n\n"
            f"Run ID: {result.run_id}\n"
            f"Status: {result.state.status}\n\n"
            f"Review with:\n"
            f"  nodechain research review {result.run_id} "
            f"--decision approve|reject|revise "
            f"--reason \"...\" --reviewer \"...\"",
            title="Review Required",
        ))
        _maybe_write_json(json_output, {
            "run_id": result.run_id,
            "status": "paused",
            "paused_for_review": True,
            "corpus_digest": result.corpus_digest,
        })
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
    from nodechain.research.runner import ResearchBrief, WorkspaceRunner
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

    # Reconstruct the runner from the descriptor (no resupplied inputs).
    runner = WorkspaceRunner(
        brief=ResearchBrief.from_question(desc.question),
        corpus_path=desc.corpus_path,
        workspace_dir=desc.workspace_dir,
        db_path=desc.db_path,
        trace_dir=desc.trace_dir,
        chain_id=desc.chain_id,
    )

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
