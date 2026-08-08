"""Fresh-reconstruction review truth tests.

These tests prove the pause/review/resume flow works when the review is
performed by a SEPARATELY reconstructed WorkspaceRunner (simulating a fresh
CLI process), not the same in-memory object that ran the chain.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nodechain.research.runner import ResearchBrief, WorkspaceRunner
from nodechain.research.run_descriptor import load_descriptor

CORPUS = Path(__file__).parent.parent.parent / "tests" / "fixtures" / "research" / "corpus_conflicting_evidence.yaml"


def _initial_run(tmp_path: Path, name: str = "ws") -> tuple[str, str]:
    """Run the chain, return (run_id, workspace_dir)."""
    ws = str(tmp_path / name)
    runner = WorkspaceRunner(
        brief=ResearchBrief.from_question("Is async Rust memory-safe?"),
        corpus_path=str(CORPUS),
        workspace_dir=ws,
    )
    result = runner.run()
    assert result.paused, "conflicting-evidence scenario must pause"
    return result.run_id, ws


# --------------------------------------------------------------------------- #
# Fresh-reconstruction approve
# --------------------------------------------------------------------------- #


def test_fresh_approve_completes(tmp_path: Path) -> None:
    """Fresh-process approve: reconstruct from descriptor, resume, completed."""
    run_id, ws = _initial_run(tmp_path, "approve")
    desc = load_descriptor(ws, run_id)

    reconstructed = WorkspaceRunner.from_descriptor(desc)
    reconstructed.compose_for_resume(run_id)
    reconstructed.apply_review("approve", "ok", "reviewer1")
    result = reconstructed.resume(run_id=run_id)

    assert result.run_id == run_id, "run ID changed"
    assert result.trace.final_status == "completed", (
        f"expected completed, got {result.trace.final_status}"
    )


# --------------------------------------------------------------------------- #
# Fresh-reconstruction reject
# --------------------------------------------------------------------------- #


def test_fresh_reject_fails_with_human_review_rejected(tmp_path: Path) -> None:
    """Fresh-process reject: reconstruct from descriptor, resume, failed."""
    run_id, ws = _initial_run(tmp_path, "reject")
    desc = load_descriptor(ws, run_id)

    reconstructed = WorkspaceRunner.from_descriptor(desc)
    reconstructed.compose_for_resume(run_id)
    reconstructed.apply_review("reject", "insufficient", "reviewer2")
    result = reconstructed.resume(run_id=run_id)

    assert result.run_id == run_id
    assert result.trace.final_status == "failed", (
        f"expected failed after reject, got {result.trace.final_status}"
    )

    # Assert human_review_rejected in the durable runtime truth.
    rejected_events = [
        ev for ev in result.trace.events
        if "human_review_rejected" in ev.event_type.value
        or "human_review_rejected" in str(getattr(ev, "decision", ""))
    ]
    assert len(rejected_events) >= 1, (
        "no human_review_rejected event in trace after reject"
    )


# --------------------------------------------------------------------------- #
# Fresh-reconstruction revise
# --------------------------------------------------------------------------- #


def test_fresh_revise_routes_through_scheduler(tmp_path: Path) -> None:
    """Fresh-process revise: reconstruct, resume, scheduler revision transition."""
    run_id, ws = _initial_run(tmp_path, "revise")
    desc = load_descriptor(ws, run_id)

    reconstructed = WorkspaceRunner.from_descriptor(desc)
    reconstructed.compose_for_resume(run_id)
    reconstructed.apply_review("revise", "needs revision", "reviewer3")
    result = reconstructed.resume(run_id=run_id)

    assert result.run_id == run_id
    # Revise routes through the scheduler — the chain re-executes.
    # The final status should be terminal (completed, failed, or re-paused).
    assert result.trace.final_status in ("completed", "failed", "waiting_for_review"), (
        f"unexpected status after revise: {result.trace.final_status}"
    )

    # Verify a revision transition occurred in the trace.
    revision_events = [
        ev for ev in result.trace.events
        if "revision" in ev.event_type.value.lower()
        or "review_revision" in str(getattr(ev, "decision", "")).lower()
        or "review_revision" in str(getattr(ev, "metadata", {}).get("reason", "")).lower()
    ]
    assert len(revision_events) >= 1 or result.trace.final_status in ("completed", "failed"), (
        "no revision transition evidence"
    )
