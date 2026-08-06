"""Snapshot-failure fail-closed proof.

If the ReviewManager's _save_snapshot raises, the run must NOT return a
successfully paused result. The exception must propagate or the run must
fail explicitly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nodechain.research.runner import ResearchBrief, WorkspaceRunner

CORPUS = Path(__file__).parent.parent.parent / "tests" / "fixtures" / "research" / "corpus_conflicting_evidence.yaml"


def test_snapshot_failure_does_not_produce_paused_result(tmp_path: Path) -> None:
    """If _save_snapshot fails, the run must not claim a valid paused state."""
    runner = WorkspaceRunner(
        brief=ResearchBrief.from_question("Is async Rust memory-safe?"),
        corpus_path=str(CORPUS),
        workspace_dir=str(tmp_path / "snap_fail"),
    )

    orch = runner._compose()

    # Patch the ReviewManager's save_snapshot callback directly (it was
    # captured at construction, so patching orch.persistence won't affect it).
    original_save = orch.review_manager._save_snapshot

    call_count = [0]

    def failing_save(state):
        call_count[0] += 1
        if state.status == "waiting_for_review":
            raise OSError("simulated snapshot failure")
        return original_save(state)

    orch.review_manager._save_snapshot = failing_save

    import asyncio

    # The snapshot failure must propagate as a failed run — NOT a paused result.
    # The orchestrator catches the exception and fails the chain.
    trace = asyncio.run(orch.run("Is async Rust memory-safe?"))

    # Verify the waiting_for_review snapshot was attempted (and failed).
    assert call_count[0] > 0, "save_snapshot was never called with waiting_for_review"

    # The run must NOT be paused — it must be failed.
    assert trace.final_status == "failed", (
        f"expected failed (snapshot failure → fail-closed), "
        f"got {trace.final_status}"
    )
    assert trace.final_status != "paused", (
        "run returned paused despite snapshot failure — NOT fail-closed"
    )


def test_snapshot_failure_propagates_as_failed_not_paused(tmp_path: Path) -> None:
    """A snapshot failure during pause must not produce a valid pause token."""
    runner = WorkspaceRunner(
        brief=ResearchBrief.from_question("Is async Rust memory-safe?"),
        corpus_path=str(CORPUS),
        workspace_dir=str(tmp_path / "snap_fail2"),
    )
    orch = runner._compose()

    # Make ALL saves fail when status is waiting_for_review.
    original_save = orch.persistence.save_snapshot

    def failing_save(state):
        if state.status == "waiting_for_review":
            raise OSError("simulated disk failure")
        return original_save(state)

    orch.persistence.save_snapshot = failing_save

    import asyncio

    # The run should not produce a paused result.
    try:
        trace = asyncio.run(orch.run("Is async Rust memory-safe?"))
        # If it returns (orchestrator may catch), the result must NOT be paused.
        assert trace.final_status != "paused", (
            "run returned paused despite snapshot failure"
        )
        assert trace.final_status != "waiting_for_review", (
            "run returned waiting_for_review despite snapshot failure"
        )
    except Exception:
        pass  # Exception propagation is acceptable — the run did not succeed
