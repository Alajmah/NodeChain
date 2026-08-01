"""Tests for the `nodechain recover` CLI subgroup — read commands (v2.46.0 Phase 1.5).

Pins the three read-only recovery commands: ``list``, ``inspect``, ``trace``.
They render a RecoverySnapshot/RunSummary via Rich and return structured exit
codes. Action commands land in Phase 4.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nodechain.cli.main import cli
from nodechain.core.state import ChainState, StateManager


@pytest.fixture()
def store(tmp_path):
    """A (StateManager, db_path, trace_dir) triple seeded with runs."""
    sm = StateManager(db_path=tmp_path / "state.db")
    trace_dir = tmp_path / "traces"
    trace_dir.mkdir()
    return sm, str(tmp_path / "state.db"), str(trace_dir)


def _seed_run(sm: StateManager, run_id: str, **kw) -> None:
    sm.save(ChainState(run_id=run_id, chain_id="c", **kw))


def _seed_trace(trace_dir: str, run_id: str, status: str = "completed") -> None:
    Path(trace_dir, f"{run_id}.json").write_text(json.dumps({
        "chain_id": "c", "run_id": run_id, "status": status,
        "started_at": "2026-06-27T00:00:00+00:00",
        "events": [],
    }))


# --- recover list ------------------------------------------------------------

def test_recover_list_shows_runs(tmp_path, store) -> None:
    sm, db, trace_dir = store
    _seed_run(sm, "run-1", status="completed", step=3, current_node="end")
    _seed_run(sm, "run-2", status="failed", step=2, current_node="boom")

    runner = CliRunner()
    result = runner.invoke(cli, [
        "recover", "list", "--db", db, "--trace-dir", trace_dir,
    ])

    assert result.exit_code == 0, result.output
    assert "run-1" in result.output
    assert "run-2" in result.output


def test_recover_list_empty_shows_message(tmp_path, store) -> None:
    _, db, trace_dir = store
    runner = CliRunner()
    result = runner.invoke(cli, [
        "recover", "list", "--db", db, "--trace-dir", trace_dir,
    ])
    assert result.exit_code == 0
    # No crash; some human-friendly empty state message.
    assert "no" in result.output.lower() or "0" in result.output


# --- recover inspect ---------------------------------------------------------

def test_recover_inspect_shows_snapshot(tmp_path, store) -> None:
    sm, db, trace_dir = store
    _seed_run(sm, "run-1", status="completed", step=2, current_node="end")
    _seed_trace(trace_dir, "run-1")

    runner = CliRunner()
    result = runner.invoke(cli, [
        "recover", "inspect", "run-1", "--db", db, "--trace-dir", trace_dir,
    ])

    assert result.exit_code == 0, result.output
    assert "run-1" in result.output
    assert "COMPLETED" in result.output.upper()


def test_recover_inspect_unknown_run_returns_not_found(tmp_path, store) -> None:
    _, db, trace_dir = store
    runner = CliRunner()
    result = runner.invoke(cli, [
        "recover", "inspect", "no-such-run", "--db", db, "--trace-dir", trace_dir,
    ])
    assert result.exit_code == 2  # EXIT_NOT_FOUND
    assert "no-such-run" in result.output


def test_recover_inspect_shows_blocking_reason_and_actions(tmp_path, store) -> None:
    sm, db, trace_dir = store
    _seed_run(
        sm, "run-1", status="waiting_for_review", step=3, current_node="rev",
        metadata={"governed_review_request": {"request_id": "req-1", "step_id": 3}},
    )
    _seed_trace(trace_dir, "run-1", status="waiting_for_review")

    runner = CliRunner()
    result = runner.invoke(cli, [
        "recover", "inspect", "run-1", "--db", db, "--trace-dir", trace_dir,
    ])

    assert result.exit_code == 0, result.output
    # Blocking reason and at least one candidate action are surfaced.
    assert "review" in result.output.lower()
    assert "approve" in result.output.lower() or "reject" in result.output.lower()


# --- recover trace -----------------------------------------------------------

def test_recover_trace_shows_health(tmp_path, store) -> None:
    sm, db, trace_dir = store
    _seed_run(sm, "run-1", status="completed")
    _seed_trace(trace_dir, "run-1")

    runner = CliRunner()
    result = runner.invoke(cli, [
        "recover", "trace", "run-1", "--db", db, "--trace-dir", trace_dir,
    ])

    assert result.exit_code == 0, result.output
    assert "run-1" in result.output


def test_recover_trace_unknown_run_returns_not_found(tmp_path, store) -> None:
    _, db, trace_dir = store
    runner = CliRunner()
    result = runner.invoke(cli, [
        "recover", "trace", "no-such-run", "--db", db, "--trace-dir", trace_dir,
    ])
    assert result.exit_code == 2
