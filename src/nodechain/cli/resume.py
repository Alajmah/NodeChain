"""Resume command — resume a paused/failed chain run."""

from __future__ import annotations

import os
import sys

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from nodechain.adapters.lim_model_adapter import LIMModelAdapter
from nodechain.core.blueprint import load_blueprint
from nodechain.memory.manager import MemoryManager
from nodechain.adapters.chroma_adapter import ChromaAdapter
from nodechain.runtime.orchestrator import Orchestrator
from nodechain.cli.run import _create_nodes

console = Console()


from nodechain.cli.exit_codes import (
    EXIT_OK, EXIT_NOT_FOUND, EXIT_RESUME_NOT_RESUMABLE, EXIT_RESUME_FAILED,
)


def resume_run(
    run_id: str,
    db_path: str = "data/chain_state.db",
    blueprint_path: str = "blueprints/research_decision_v1.yaml",
    trace_dir: str = "data/traces",
) -> int:
    """Resume a paused or failed chain run.

    Returns exit code:
        0 = completed
        2 = not found
        13 = not resumable (completed)
        14 = resume failed
    """
    import asyncio

    # Verify state exists
    from nodechain.core.state import StateManager
    sm = StateManager(db_path=db_path)
    state = sm.load(run_id)
    if state is None:
        console.print(f"[red]No saved state found for run: {run_id}[/red]")
        return EXIT_NOT_FOUND

    status_color = "yellow" if state.status == "running" else "red"
    console.print(Panel(
        f"[bold]Run ID:[/bold]       {run_id}\n"
        f"[bold]Status:[/bold]       [{status_color}]{state.status}[/{status_color}]\n"
        f"[bold]Last Step:[/bold]    {state.step}\n"
        f"[bold]Current Node:[/bold] {state.current_node or '(none)'}",
        title="[bold blue]Resuming Chain[/bold blue]",
    ))

    if state.status == "completed":
        console.print(f"[yellow]Run is already completed. Nothing to resume.[/yellow]")
        return EXIT_RESUME_NOT_RESUMABLE

    if state.status not in ("running", "failed", "paused", "waiting_for_review"):
        console.print(f"[yellow]Run is in '{state.status}' state. Resume may not be appropriate.[/yellow]")

    # Load blueprint
    try:
        blueprint = load_blueprint(blueprint_path)
    except Exception as e:
        console.print(f"[red]Failed to load blueprint: {e}[/red]")
        return EXIT_RESUME_FAILED

    # Create model adapter
    provider = os.environ.get("NODECHAIN_PROVIDER", "lim").lower()
    model_name = os.environ.get("NODECHAIN_MODEL", "auto")
    lim_url = os.environ.get("LIM_BASE_URL", "http://localhost:8766")

    try:
        if provider == "mock":
            from nodechain.adapters.mock_model_adapter import MockModelAdapter
            model_adapter = MockModelAdapter()
        else:
            model_adapter = LIMModelAdapter(lim_url=lim_url, model=model_name)
    except Exception as e:
        console.print(f"[red]Failed to initialize model: {e}[/red]")
        return EXIT_RESUME_FAILED

    # Memory manager
    memory_manager = None
    chroma_host = os.environ.get("CHROMA_HOST", "localhost")
    chroma_port = os.environ.get("CHROMA_PORT", "8000")
    try:
        chroma = ChromaAdapter(base_url=f"http://{chroma_host}:{chroma_port}")
        memory_manager = MemoryManager(chroma=chroma)
    except Exception:
        pass

    # Create nodes and orchestrator
    nodes = _create_nodes(model_adapter, trace_dir, memory_manager=memory_manager)
    orchestrator = Orchestrator(
        blueprint=blueprint,
        nodes=nodes,
    )

    # Resume
    console.print("\n[bold]Resuming execution...[/bold]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Resuming chain...", total=None)
        trace = asyncio.run(orchestrator.resume(run_id))
        progress.update(task, description="Resume complete!")

    # Display results
    from nodechain.cli.run import _display_results
    _display_results(trace, orchestrator)

    # Check final status for exit code
    if trace.final_status == "completed":
        return EXIT_OK
    else:
        return EXIT_RESUME_FAILED
