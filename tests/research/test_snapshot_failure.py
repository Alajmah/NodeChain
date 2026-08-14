"""Snapshot-failure fail-closed proof (H0.5 rewiring).

If the review pause transition's persistence raises, the run must NOT
return a successfully paused result. The exception must propagate or the
run must fail explicitly. H0.5 moved the pause persistence boundary from
the retired ``_save_snapshot`` callback to the atomic review-transition
seam (``_commit_review_transition`` → ``commit_lifecycle``), so the fault
injection patches that seam.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nodechain.research.runner import ResearchBrief, WorkspaceRunner

CORPUS = Path(__file__).parent.parent.parent / "tests" / "fixtures" / "research" / "corpus_conflicting_evidence.yaml"


def test_snapshot_failure_does_not_produce_paused_result(tmp_path: Path) -> None:
    """If the pause transition fails, the run must not claim a valid paused state."""
    runner = WorkspaceRunner(
        brief=ResearchBrief.from_question("Is async Rust memory-safe?"),
        corpus_path=str(CORPUS),
        workspace_dir=str(tmp_path / "snap_fail"),
    )

    orch = runner._compose()

    # Patch the review-transition seam directly (it was captured at
    # construction, so patching orch.persistence won't affect it).
    original_transition = orch.review_manager._commit_review_transition

    call_count = [0]

    def failing_transition(state, event, *, status, **kwargs):
        call_count[0] += 1
        if status == "waiting_for_review":
            raise OSError("simulated snapshot failure")
        return original_transition(state, event, status=status, **kwargs)

    orch.review_manager._commit_review_transition = failing_transition

    import asyncio

    # The transition failure must propagate as a failed run — NOT a paused
    # result. The orchestrator catches the exception and fails the chain.
    trace = asyncio.run(orch.run("Is async Rust memory-safe?"))

    # Verify the waiting_for_review transition was attempted (and failed).
    assert call_count[0] > 0, "transition was never called with waiting_for_review"

    # The run must NOT be paused — it must be failed.
    assert trace.final_status == "failed", (
        f"expected failed (snapshot failure → fail-closed), "
        f"got {trace.final_status}"
    )
    assert trace.final_status != "paused", (
        "run returned paused despite snapshot failure — NOT fail-closed"
    )


def test_snapshot_failure_propagates_as_failed_not_paused(tmp_path: Path) -> None:
    """A pause-transition failure must not produce a valid pause token."""
    runner = WorkspaceRunner(
        brief=ResearchBrief.from_question("Is async Rust memory-safe?"),
        corpus_path=str(CORPUS),
        workspace_dir=str(tmp_path / "snap_fail2"),
    )
    orch = runner._compose()

    original_transition = orch.review_manager._commit_review_transition

    def failing_transition(state, event, *, status, **kwargs):
        if status == "waiting_for_review":
            raise OSError("simulated disk failure")
        return original_transition(state, event, status=status, **kwargs)

    orch.review_manager._commit_review_transition = failing_transition

    import asyncio

    trace = asyncio.run(orch.run("Is async Rust memory-safe?"))

    # Assert exact fail-closed truths (no broad except handler).
    assert trace.final_status == "failed", (
        f"expected failed, got {trace.final_status}"
    )

    # Persisted state must NOT be waiting_for_review.
    from nodechain.core.state import StateManager
    from nodechain.core.capsule_crypto import KekManager
    sm = StateManager(runner._db_path, kek_manager=KekManager(local_dev=True, kek_path=runner._kek_path))
    loaded = sm.load(orch.state.run_id)
    if loaded is not None:
        assert loaded.status != "waiting_for_review", (
            f"persisted status is waiting_for_review despite snapshot failure: {loaded.status}"
        )

    # No valid pause/review token exposed.
    assert trace.final_status != "paused"
    assert trace.final_status != "waiting_for_review"

    # The failure must identify snapshot persistence as the cause.
    # Check trace events for a failure event that references the snapshot
    # or persistence failure. Require a concrete reason — not just the
    # existence of a chain_failed event.
    chain_failed_events = [
        ev for ev in trace.events
        if "chain_failed" in ev.event_type.value.lower()
    ]
    assert len(chain_failed_events) >= 1, "no chain_failed event"

    failure_evidence = " ".join(
        str(getattr(ev, "decision", ""))
        + " " + str(getattr(ev, "metadata", {}))
        + " " + str(getattr(ev, "reason_codes", []))
        for ev in chain_failed_events
    ).lower()
    assert (
        "simulated disk failure" in failure_evidence
        or "snapshot" in failure_evidence
        or "persist" in failure_evidence
        or "save_snapshot" in failure_evidence
    ), (
        f"failure evidence does not identify snapshot persistence as cause: "
        f"{failure_evidence[:200]}"
    )
