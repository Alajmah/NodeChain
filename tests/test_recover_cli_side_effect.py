"""Tests for the v3.4.0 side-effect recovery CLI surface:

  - ``nodechain recover list-unknown``
  - ``nodechain recover resolve-side-effect``

Both are thin wrappers over ``StateManager`` / ``RecoveryService.apply_action``
and share the governed write boundary exercised by
``test_recovery_side_effect_resolution.py``. These tests assert the CLI
plumbing: argument wiring, exit codes, and the rendered output.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from nodechain.cli.main import cli
from nodechain.core.state import ChainState, StateManager


# --- fixtures -------------------------------------------------------------

@pytest.fixture()
def store(tmp_path):
    sm = StateManager(db_path=tmp_path / "state.db")
    trace_dir = tmp_path / "traces"
    trace_dir.mkdir()
    return sm, str(tmp_path / "state.db"), str(trace_dir)


def _seed_run(sm: StateManager, run_id: str = "r1", *, status: str = "running") -> None:
    """Seed a non-terminal run. RESOLVE_SIDE_EFFECT is admitted for any
    non-terminal recovery state."""
    sm.save(ChainState(run_id=run_id, chain_id="c", status=status, step=1,
                       current_node="search_tool"))


def _seed_unknown_side_effect(sm: StateManager, *, run_id: str, key: str,
                              node_id: str = "search_tool") -> None:
    """Seed an unknown side-effect ledger row (the resolution precondition).

    Mirrors the helper in test_recovery_side_effect_resolution.py: record
    started, then transition to unknown."""
    sm.record_side_effect(
        run_id=run_id, step_id=1, node_id=node_id,
        side_effect_type="external_call",
        idempotency_key=key,
        status="started",
    )
    sm.update_side_effect_status(run_id, key, status="unknown")


# --- list-unknown ---------------------------------------------------------

def test_list_unknown_shows_unknown_effect(store) -> None:
    """A seeded unknown side effect appears in the listing."""
    sm, db, _trace_dir = store
    _seed_run(sm, "r1")
    _seed_unknown_side_effect(sm, run_id="r1", key="se:cli-1")

    result = CliRunner().invoke(cli, [
        "recover", "list-unknown", "r1", "--db", db,
    ])

    assert result.exit_code == 0, result.output
    assert "se:cli-1" in result.output
    assert "unknown side effect" in result.output.lower()


def test_list_unknown_empty_when_none(store) -> None:
    """With no unknown effects, the empty-state message is shown."""
    sm, db, _trace_dir = store
    _seed_run(sm, "r1")
    # A completed side effect is present but NOT unknown → filtered out.
    sm.record_side_effect(
        run_id="r1", step_id=1, node_id="search_tool",
        side_effect_type="external_call", idempotency_key="se:done-1",
        status="completed",
    )

    result = CliRunner().invoke(cli, [
        "recover", "list-unknown", "r1", "--db", db,
    ])

    assert result.exit_code == 0, result.output
    assert "no unknown side effects" in result.output.lower()
    assert "se:done-1" not in result.output


# --- resolve-side-effect --------------------------------------------------

def test_resolve_side_effect_completed(store) -> None:
    """verified_completed + external-reference → exit 0 and the ledger
    transitions unknown→completed."""
    sm, db, trace_dir = store
    _seed_run(sm, "r1")
    _seed_unknown_side_effect(sm, run_id="r1", key="se:cli-2")

    result = CliRunner().invoke(cli, [
        "recover", "resolve-side-effect", "r1",
        "--side-effect-key", "se:cli-2",
        "--decision", "verified_completed",
        "--external-reference", "ref-1",
        "--db", db, "--trace-dir", trace_dir,
        "--operator", "op@x",
    ])

    assert result.exit_code == 0, result.output
    row = sm.get_side_effect_by_key("r1", "se:cli-2")
    assert row is not None
    assert row["status"] == "completed"
    assert row["external_reference"] == "ref-1"


def test_resolve_side_effect_missing_evidence_rejected(store) -> None:
    """verified_completed with neither external-reference nor response-hash is
    rejected by the ledger-layer evidence check (governed denial → non-zero
    exit)."""
    sm, db, trace_dir = store
    _seed_run(sm, "r1")
    _seed_unknown_side_effect(sm, run_id="r1", key="se:cli-3")

    result = CliRunner().invoke(cli, [
        "recover", "resolve-side-effect", "r1",
        "--side-effect-key", "se:cli-3",
        "--decision", "verified_completed",
        # no external-reference, no response-hash
        "--db", db, "--trace-dir", trace_dir,
        "--operator", "op@x",
    ])

    assert result.exit_code != 0
    assert "blocked" in result.output.lower()
    # Ledger untouched.
    row = sm.get_side_effect_by_key("r1", "se:cli-3")
    assert row is not None
    assert row["status"] == "unknown"


def test_resolve_side_effect_nonexistent_key_rejected(store) -> None:
    """A side-effect key with no matching ledger row is rejected (SIDE_EFFECT_NOT_FOUND
    surfaced as a delegation failure → non-zero exit)."""
    sm, db, trace_dir = store
    _seed_run(sm, "r1")
    # No side effect seeded for 'se:nonexistent'.

    result = CliRunner().invoke(cli, [
        "recover", "resolve-side-effect", "r1",
        "--side-effect-key", "se:nonexistent",
        "--decision", "verified_completed",
        "--external-reference", "ref-x",
        "--db", db, "--trace-dir", trace_dir,
        "--operator", "op@x",
    ])

    assert result.exit_code != 0
    assert "blocked" in result.output.lower()
