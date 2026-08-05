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
    "--corpus",
    "corpus_path",
    required=True,
    type=click.Path(exists=True),
    help="Path to the sealed fixture corpus YAML file (same as the run).",
)
@click.option(
    "--brief",
    default=None,
    help="Brief file or question (same as the original run).",
)
@click.option(
    "--db",
    "db_path",
    default=None,
    help="Path to the run state database (must match the original run).",
)
def research_review(
    run_id: str,
    decision: str,
    reason: str,
    reviewer: str,
    corpus_path: str,
    brief: str | None,
    db_path: str | None,
) -> None:
    """Submit a review decision for a paused run and resume.

    RUN_ID is the identifier of the paused run.
    """
    from nodechain.core.state import StateManager
    from nodechain.research.runner import ResearchBrief, WorkspaceRunner

    # Verify the run exists and is paused.
    sm = StateManager(db_path or "data/research_workspace.db")
    state = sm.load(run_id)
    if state is None:
        console.print(f"[red]Error:[/red] run {run_id} not found")
        sys.exit(EXIT_NOT_FOUND)
    if state.status not in ("waiting_for_review", "paused", "paused_for_budget"):
        console.print(
            f"[red]Error:[/red] run {run_id} is not paused "
            f"(status: {state.status})"
        )
        sys.exit(EXIT_RESUME_NOT_RESUMABLE)

    console.print(Panel(
        f"[bold blue]Review Decision[/bold blue]\n\n"
        f"Run ID: {run_id}\n"
        f"Decision: {decision}\n"
        f"Reviewer: {reviewer}\n"
        f"Reason: {reason}",
        title="Resuming Run",
    ))

    # Record the decision through the existing runtime review seam.
    # The runner sets the env vars that HumanAdapter reads on resume.
    # We need a brief to reconstruct the orchestrator (resume reconstructs it).
    if brief is None:
        brief = state.metadata.get("research_question", "")
    rb = (
        ResearchBrief.from_file(brief)
        if brief and Path(brief).exists()
        else ResearchBrief.from_question(brief or "review-resume")
    )

    runner = WorkspaceRunner(
        brief=rb,
        corpus_path=corpus_path,
        db_path=db_path,
    )

    # Apply the review decision (sets env vars for the resume path).
    runner.apply_review(decision, reason, reviewer)

    # Reconstruct the orchestrator and resume.
    runner._compose()
    runner.orchestrator.state = state  # restore the paused state
    result = runner.resume()

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
