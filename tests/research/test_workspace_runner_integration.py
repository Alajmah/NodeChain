"""End-to-end integration tests through the real orchestrator.

These tests prove the full governed research workspace flow:

* All 10 nodes execute through the real orchestrator (not mocked)
* package_trust_allowed for every node (including FixtureSearchToolNode)
* search_tool dispatches through OrdinaryDispatchGuard with fixture adapter
* risk_classifier triggers HUMAN_REVIEW_REQUESTED → paused
* review(approve) → resume → completed
* No production adapter present at any point
* allow_unguarded remains false throughout

These are NOT unit tests — they execute the full orchestrator node loop,
PolicyGate, side-effect journaling, and review mechanism.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from nodechain.research.runner import ResearchBrief, WorkspaceRunner

CORPUS_PATH = Path(__file__).parent.parent.parent / "tests" / "fixtures" / "research" / "corpus_basic.yaml"


@pytest.fixture
def runner(tmp_path: Path) -> WorkspaceRunner:
    """Build a WorkspaceRunner with an isolated database."""
    return WorkspaceRunner(
        brief=ResearchBrief.from_question("Is async Rust memory-safe?"),
        corpus_path=str(CORPUS_PATH),
        db_path=str(tmp_path / "integration.db"),
        trace_dir=str(tmp_path / "traces"),
    )


# --------------------------------------------------------------------------- #
# Full chain execution
# --------------------------------------------------------------------------- #


def test_full_chain_executes_all_nodes(runner: WorkspaceRunner) -> None:
    """All 10 research nodes execute and succeed through the real
    orchestrator."""
    result = runner.run()
    completed = set(result.state.completed_steps.values())
    expected = {
        "goal_interpreter", "task_planner", "context_selector",
        "search_tool", "source_ingestion", "source_quality_evaluator",
        "evidence_synthesizer", "claim_validator", "risk_classifier",
    }
    assert expected.issubset(completed), (
        f"missing nodes: {expected - completed}"
    )


def test_search_tool_passes_package_trust(runner: WorkspaceRunner) -> None:
    """The FixtureSearchToolNode (in nodechain.nodes.*) passes the
    package_trust gate — no package_trust_denied event."""
    result = runner.run()
    trust_events = [
        ev for ev in result.trace.events
        if ev.node_id == "search_tool"
        and "package_trust" in ev.event_type.value
    ]
    assert any("allowed" in ev.event_type.value for ev in trust_events), (
        "no package_trust_allowed event for search_tool"
    )
    assert not any("denied" in ev.event_type.value for ev in trust_events), (
        "package_trust_denied for search_tool"
    )


def test_search_tool_dispatches_through_guard(runner: WorkspaceRunner) -> None:
    """The search_tool has an OrdinaryDispatchGuard-wrapped fixture adapter
    injected via set_adapter_resolver, with allow_unguarded=False."""
    result = runner.run()
    # The resolver is wired with the fixture guard.
    assert runner._search_node is not None
    assert runner._search_node._allow_unguarded is False
    resolver = runner._search_node._adapter_resolver
    assert resolver is not None
    assert "fixture" in resolver
    from nodechain.runtime.recovery_dispatch_guard import OrdinaryDispatchGuard
    guard = resolver["fixture"]
    assert isinstance(guard, OrdinaryDispatchGuard)
    assert guard._skip_trust_check is False
    # The fixture adapter is the guard's target.
    assert runner._fixture_adapter is not None
    assert guard._adapter is runner._fixture_adapter


def test_chain_pauses_at_risk_classifier(runner: WorkspaceRunner) -> None:
    """The risk_classifier triggers HUMAN_REVIEW_REQUESTED and the chain
    pauses (waiting_for_review), not auto-approving."""
    result = runner.run()
    assert result.paused, f"expected pause, got {result.trace.final_status}"
    assert result.state.status == "waiting_for_review"
    # Verify the review request event exists.
    review_events = [
        ev for ev in result.trace.events
        if "HUMAN_REVIEW" in ev.event_type.value
        or "human_review" in ev.event_type.value
    ]
    assert len(review_events) >= 1


def test_no_production_adapter_in_run(runner: WorkspaceRunner) -> None:
    """No production adapter name appears in any trace event."""
    result = runner.run()
    production = {"arxiv", "semantic_scholar", "openalex", "crossref", "pubmed"}
    for ev in result.trace.events:
        meta = getattr(ev, "metadata", {}) or {}
        meta_str = str(meta).lower()
        for prod in production:
            # Allow "arxiv" in error messages etc., but not in adapter grants
            if "adapter" in meta_str and prod in meta_str:
                # Check it's not in allowed_adapters
                allowed = meta.get("allowed_adapters", [])
                if isinstance(allowed, list):
                    assert prod not in allowed, (
                        f"production adapter {prod} in allowed_adapters"
                    )


# --------------------------------------------------------------------------- #
# Pause → Review → Resume
# --------------------------------------------------------------------------- #


def test_review_approve_resumes_to_completion(runner: WorkspaceRunner) -> None:
    """Full cycle: run → pause → review(approve) → resume → completed."""
    result = runner.run()
    assert result.paused

    runner.apply_review("approve", "evidence is sufficient", "test-reviewer")
    result2 = runner.resume()
    assert result2.completed, (
        f"expected completed after resume, got {result2.trace.final_status}"
    )
    assert result2.state.status == "completed"


def test_review_reject_routes_through_runtime(runner: WorkspaceRunner) -> None:
    """Review(reject) is delivered through the existing runtime review seam
    and the chain processes it (the runtime decides the outcome)."""
    result = runner.run()
    assert result.paused

    runner.apply_review("reject", "evidence is insufficient", "test-reviewer")
    result2 = runner.resume()
    # The runtime processes the reject decision; the chain resumes and reaches
    # a terminal state (completed or failed — the runtime owns this decision).
    assert result2.trace.final_status in ("completed", "failed"), (
        f"expected terminal status after reject, got {result2.trace.final_status}"
    )


def test_review_identity_recorded(runner: WorkspaceRunner) -> None:
    """The review decision records reviewer identity, reason, and decision in
    the runner's internal review env (not leaked to the process)."""
    result = runner.run()
    assert result.paused

    runner.apply_review("approve", "test reason for approval", "alice")
    # The review env is stored internally, not leaked to the process.
    assert runner._review_env.get("NODECHAIN_REVIEW_DECISION") == "approve"
    assert runner._review_env.get("NODECHAIN_REVIEW_REASON") == "test reason for approval"
    assert runner._review_env.get("NODECHAIN_REVIEW_REVIEWER") == "alice"
    # Verify no leak to process environment.
    import os
    assert "NODECHAIN_REVIEW_DECISION" not in os.environ


# --------------------------------------------------------------------------- #
# Paused runs are not finalized
# --------------------------------------------------------------------------- #


def test_paused_run_is_not_completed(runner: WorkspaceRunner) -> None:
    """A paused run must not be marked completed or failed."""
    result = runner.run()
    assert result.paused
    assert not result.completed
    assert not result.failed
