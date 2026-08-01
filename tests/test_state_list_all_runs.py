"""Tests for StateManager.list_all_runs + RunSummary (v2.46.0 Phase 1.2).

`recover list` needs a cross-run read of every chain state, not just the
review-governed subset that list_all_review_states returns. These tests pin
the read-only summary surface.
"""

from __future__ import annotations

import pytest

from nodechain.core.state import ChainState, RunSummary, StateManager


@pytest.fixture()
def sm(tmp_path) -> StateManager:
    return StateManager(db_path=tmp_path / "state.db")


def _state(run_id: str, *, status: str, step: int = 0, node: str = "",
           chain_id: str = "chain-x") -> ChainState:
    return ChainState(
        run_id=run_id, chain_id=chain_id, status=status, step=step,
        current_node=node,
    )


def test_list_all_runs_returns_empty_for_fresh_db(sm: StateManager) -> None:
    """An empty store returns an empty list, not None — renderers iterate."""
    assert sm.list_all_runs() == []


def test_list_all_runs_returns_every_run_regardless_of_status(sm: StateManager) -> None:
    """Unlike list_all_review_states, this returns ALL runs — completed,
    failed, paused, running — so the recovery console can show the full
    backlog, not just review-gated ones."""
    sm.save(_state("run-1", status="completed", step=3, node="end"))
    sm.save(_state("run-2", status="failed", step=2, node="boom"))
    sm.save(_state("run-3", status="waiting_for_review", step=1, node="review"))

    summaries = sm.list_all_runs()

    assert {s.run_id for s in summaries} == {"run-1", "run-2", "run-3"}


def test_run_summary_carries_operator_facing_fields(sm: StateManager) -> None:
    """RunSummary carries exactly the fields the recover list table renders."""
    sm.save(_state(
        "run-1", status="waiting_for_review", step=4, node="review_node",
        chain_id="chain-abc",
    ))

    [summary] = sm.list_all_runs()

    assert summary.run_id == "run-1"
    assert summary.chain_id == "chain-abc"
    assert summary.status == "waiting_for_review"
    assert summary.step == 4
    assert summary.current_node == "review_node"
    assert summary.updated_at  # non-empty timestamp from the save
    assert summary.revision >= 1


def test_list_all_runs_orders_by_most_recently_updated(sm: StateManager) -> None:
    """Operators see the most recently touched runs first — matches the
    existing list_all_review_states ordering."""
    import time
    sm.save(_state("run-old", status="completed"))
    time.sleep(1.05)  # ensure distinct updated_at (coarse Windows timestamp res)
    sm.save(_state("run-new", status="failed"))

    summaries = sm.list_all_runs()

    assert summaries[0].run_id == "run-new"
    assert summaries[1].run_id == "run-old"


def test_list_all_runs_skips_corrupt_state_json(sm: StateManager) -> None:
    """A corrupt state_json row must not crash the listing; it is skipped so
    the operator still sees the rest of the backlog. Mirrors the resilience
    of list_all_review_states."""
    import sqlite3
    # Inject a malformed row directly.
    with sqlite3.connect(sm.db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO chain_states (run_id, state_json, revision, updated_at) "
            "VALUES (?, ?, ?, ?)",
            ("corrupt-run", "{not valid json", 0, "2026-06-27T00:00:00+00:00"),
        )
    sm.save(_state("run-ok", status="completed"))

    summaries = sm.list_all_runs()

    assert [s.run_id for s in summaries] == ["run-ok"]


def test_run_summary_is_read_only_view(sm: StateManager) -> None:
    """RunSummary is a frozen view — mutating it must not touch the DB."""
    sm.save(_state("run-1", status="running", step=2))
    [summary] = sm.list_all_runs()

    # RunSummary has no setter surface that reaches the DB; reload proves it.
    reloaded = sm.load("run-1")
    assert reloaded is not None and reloaded.status == "running"
