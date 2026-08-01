"""Human Adapter — CLI-based human review gate with timeout."""

from __future__ import annotations

import asyncio
import sys
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt


console = Console()


class HumanAdapter:
    """CLI-based human review gate. Presents a summary of the chain state
    and waits for an operator decision with a timeout.

    Decisions:
      - approve: Continue chain execution
      - reject: Fail the chain
      - request_revision: Route back to task planner

    Args:
        timeout_minutes: Minutes before automatic timeout.
        decision_provider: Injected decision source for testing/automation.
            Can be a string ("approve"/"reject"/"request_revision") or
            a callable that returns a string or coroutine.
    """

    def __init__(
        self,
        timeout_minutes: int = 30,
        decision_provider: Any | None = None,
    ):
        self.timeout_minutes = timeout_minutes
        self._decision_provider = decision_provider

    async def request_review(
        self,
        risk_assessment: dict[str, Any],
        chain_outputs: dict[str, Any],
        chain_name: str = "NodeChain",
    ) -> str:
        """
        Present review payload to human operator and await decision.
        Returns 'approve', 'reject', 'request_revision', or 'timeout'.
        """
        self._display_review(risk_assessment, chain_outputs, chain_name)

        # Use injected provider if available (for testing/automation)
        if self._decision_provider is not None:
            if callable(self._decision_provider):
                result = self._decision_provider(risk_assessment, chain_outputs)
                if asyncio.iscoroutine(result):
                    result = await result
                return result
            elif isinstance(self._decision_provider, str):
                return self._decision_provider

        # Run the blocking input in a thread with timeout
        timeout_sec = self.timeout_minutes * 60
        try:
            decision = await asyncio.wait_for(
                asyncio.to_thread(self._get_decision),
                timeout=timeout_sec,
            )
        except asyncio.TimeoutError:
            console.print(
                f"\n[bold red][TIMEOUT] Review timed out after {self.timeout_minutes} minutes.[/bold red]"
            )
            return "timeout"

        return decision

    def _display_review(
        self,
        risk_assessment: dict[str, Any],
        chain_outputs: dict[str, Any],
        chain_name: str,
    ) -> None:
        """Display the review payload to the operator."""
        console.print()
        console.print(
            Panel.fit(
                f"[bold yellow][PAUSE]  HUMAN REVIEW REQUIRED[/bold yellow]\n"
                f"Chain: {chain_name}",
                style="yellow",
            )
        )

        # Risk summary
        risk_table = Table(title="Risk Assessment", show_header=True)
        risk_table.add_column("Field", style="cyan")
        risk_table.add_column("Value", style="white")

        risk_table.add_row("Risk Level", risk_assessment.get("risk_level", "UNKNOWN"))
        risk_table.add_row(
            "Confidence",
            f"{risk_assessment.get('confidence_score', 0):.0%}",
        )
        risk_table.add_row(
            "Review Required",
            str(risk_assessment.get("review_required", True)),
        )

        concerns = risk_assessment.get("key_concerns", [])
        if concerns:
            risk_table.add_row("Key Concerns", "\n".join(f"• {c}" for c in concerns))

        console.print(risk_table)

        # Evidence summary
        evidence = chain_outputs.get("evidence_synthesizer", {})
        if evidence:
            claims = evidence.get("claims", [])
            console.print(
                f"\n[bold]Evidence:[/bold] {len(claims)} claims synthesized"
            )

        # Sources summary
        sources = chain_outputs.get("source_ingestion", {})
        if sources:
            source_count = len(sources.get("sources", []))
            console.print(f"[bold]Sources:[/bold] {source_count} sources ingested")

        console.print()

    def _get_decision(self) -> str:
        """Blocking input from operator."""
        console.print("[bold]Available actions:[/bold]")
        console.print("  [green]approve[/green]          — Continue execution")
        console.print("  [red]reject[/red]             — Fail the chain")
        console.print("  [blue]request_revision[/blue]  — Route back to task planner")
        console.print()

        while True:
            choice = Prompt.ask(
                "[bold]Your decision[/bold]",
                choices=["approve", "reject", "request_revision"],
                default="approve",
            )
            return choice
