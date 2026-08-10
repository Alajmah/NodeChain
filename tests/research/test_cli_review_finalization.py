"""CLI-level regression proof: research review/resume finalization (H0.1).

These tests drive the actual Click CLI commands (``nodechain research run``
then ``nodechain research review``) through ``click.testing.CliRunner``,
proving the wiring correction that routes review/resume reconstruction
through ``WorkspaceRunner.from_descriptor``.

Before H0.1 the review command reconstructed the runner manually and left
``runner._run_descriptor`` unset, so the terminal ``resume()`` path skipped
``finalize_bundle()``. The CLI resumed the run but produced no terminal
bundle. These tests pin the corrected behavior:

  * approve  — completes, terminal bundle exists, integrity passes
  * reject   — fails, terminal bundle still exists as a truthful failed
               artifact, integrity passes
  * revise   — scheduler revision path runs on the original run ID
  * finalization failure — an injected C5 failure propagates; the CLI
               does not report successful completion
  * identity — run ID, descriptor digest, corpus identity and chain ID
               are unchanged across CLI reconstruction

They also guard the accepted second-resume/no-reexecution semantics: an
approve must not duplicate search-dispatch side-effect evidence.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from nodechain.cli.exit_codes import (
    EXIT_OK,
    EXIT_RUN_FAILED,
    EXIT_RUN_PAUSED,
)
from nodechain.cli.main import cli
from nodechain.research.bundle import BundleReader

CORPUS = (
    Path(__file__).parent.parent.parent
    / "tests"
    / "fixtures"
    / "research"
    / "corpus_conflicting_evidence.yaml"
)

#: The workspace directory the ``research run`` command defaults to, relative
#: to cwd. The command exposes ``--db`` and ``--trace-dir`` but not
#: ``--workspace``, so we chdir into a per-test temp dir and let this default
#: resolve there.
DEFAULT_WS = "data/research_workspace"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _initial_run_paused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[str, Path]:
    """Drive ``nodechain research run`` through the CLI; return (run_id, ws).

    The conflicting-evidence scenario pauses at the risk_classifier review
    gate, so the CLI exits with EXIT_RUN_PAUSED. We read the run ID from the
    machine-readable JSON output (``--json-output``) rather than scraping the
    rich panel, which wraps text with box-drawing characters.
    """
    monkeypatch.chdir(tmp_path)
    ws = tmp_path / DEFAULT_WS
    json_out = tmp_path / "run_result.json"

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "research", "run",
            "Is async Rust memory-safe?",
            "--corpus", str(CORPUS),
            "--json-output", str(json_out),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == EXIT_RUN_PAUSED, (
        f"initial run did not pause: exit={result.exit_code}\n{result.output}"
    )
    assert json_out.exists(), f"JSON output not written at {json_out}"
    doc = json.loads(json_out.read_text(encoding="utf-8"))
    run_id = doc["run_id"]
    assert run_id, f"no run_id in JSON output: {doc}"
    return run_id, ws


def _extract_run_id(output: str) -> str:
    """Fallback: pull the run ID out of the CLI's paused-state panel.

    Kept for diagnostics; the primary path reads ``--json-output``.
    """
    for line in output.splitlines():
        if "Run ID:" in line:
            # Split on the last colon to tolerate box-drawing prefixes.
            return line.rsplit(":", 1)[1].strip()
    return ""


def _bundle_dir(ws: Path, run_id: str) -> Path:
    return ws / "runs" / run_id / "bundle"


def _db_path(ws: Path) -> str:
    return str(ws / "run.db")


def _count_search_side_effects(ws: Path, run_id: str) -> int:
    """Count persisted search-dispatch ledger rows for a run.

    The idempotency_key for a search dispatch is ``search:<adapter>:<digest>``.
    No-duplicate-evidence means this count must not increase when an approved
    resume completes without re-executing search dispatch.
    """
    conn = sqlite3.connect(_db_path(ws))
    try:
        row = conn.execute(
            "SELECT COUNT(*) FROM side_effect_ledger "
            "WHERE run_id = ? AND idempotency_key LIKE 'search:%'",
            (run_id,),
        ).fetchone()
        return int(row[0]) if row else 0
    finally:
        conn.close()


def _load_descriptor(ws: Path, run_id: str) -> dict:
    """Load the persisted run descriptor identity fields."""
    from nodechain.research.run_descriptor import load_descriptor
    desc = load_descriptor(str(ws), run_id)
    return {
        "run_id": desc.run_id,
        "chain_id": desc.chain_id,
        "corpus_path": desc.corpus_path,
        "corpus_digest": desc.corpus_digest,
        "descriptor_digest": desc.descriptor_digest,
    }


# --------------------------------------------------------------------------- #
# approve
# --------------------------------------------------------------------------- #


def test_cli_approve_completes_and_finalizes_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fresh CLI approve: resumes, completes, terminal bundle verifies."""
    run_id, ws = _initial_run_paused(tmp_path, monkeypatch)
    count_before = _count_search_side_effects(ws, run_id)

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "research", "review", run_id,
            "--decision", "approve",
            "--reason", "evidence is sufficient",
            "--reviewer", "test-reviewer",
            "--workspace", str(ws),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == EXIT_OK, (
        f"approve did not complete cleanly: exit={result.exit_code}\n"
        f"{result.output}"
    )

    bdir = _bundle_dir(ws, run_id)
    assert (bdir / "manifest.json").exists(), (
        f"terminal bundle manifest missing at {bdir}"
    )
    reader = BundleReader(bdir)
    assert reader.verify_integrity() is True, (
        "terminal bundle failed integrity verification"
    )
    manifest = reader.get_manifest()
    # The conflicting-evidence corpus classifies as completed_degraded (low
    # claim confidence). Both completed and completed_degraded are terminal;
    # the H0.1 truth is that a terminal bundle exists at all. Before the fix,
    # no bundle was produced on the CLI resume path.
    assert str(manifest.run_status.value if hasattr(manifest.run_status, "value") else manifest.run_status) in (
        "completed",
        "completed_degraded",
    ), (
        f"bundle run_status={manifest.run_status!r}, "
        f"expected a completed-terminal status"
    )

    # No-duplicate-evidence: the approved resume must not re-execute search
    # dispatch. The accepted second-resume/no-reexecution semantics means the
    # side-effect ledger row count for search dispatch is unchanged.
    count_after = _count_search_side_effects(ws, run_id)
    assert count_after == count_before, (
        f"search side-effect rows grew on approve resume: "
        f"{count_before} -> {count_after} (duplicate dispatch detected)"
    )


# --------------------------------------------------------------------------- #
# reject
# --------------------------------------------------------------------------- #


def test_cli_reject_fails_and_finalizes_truthful_failed_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fresh CLI reject: terminates failed, bundle still exists as a truthful
    failed terminal artifact, integrity passes."""
    run_id, ws = _initial_run_paused(tmp_path, monkeypatch)

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "research", "review", run_id,
            "--decision", "reject",
            "--reason", "evidence is insufficient",
            "--reviewer", "test-reviewer",
            "--workspace", str(ws),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == EXIT_RUN_FAILED, (
        f"reject did not exit failed: exit={result.exit_code}\n{result.output}"
    )

    bdir = _bundle_dir(ws, run_id)
    assert (bdir / "manifest.json").exists(), (
        f"failed-run terminal bundle manifest missing at {bdir}"
    )
    reader = BundleReader(bdir)
    assert reader.verify_integrity() is True, (
        "failed-run terminal bundle failed integrity verification"
    )
    manifest = reader.get_manifest()
    assert manifest.run_status == "failed", (
        f"bundle run_status={manifest.run_status!r}, expected 'failed'"
    )


# --------------------------------------------------------------------------- #
# revise
# --------------------------------------------------------------------------- #


def test_cli_revise_routes_through_scheduler_on_original_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fresh CLI revise: scheduler revision path occurs on the original run ID.

    After revise the run may re-pause or reach a terminal state. If it
    terminates, an integrity-verified bundle must exist. If it re-pauses,
    no false terminal bundle may be present.
    """
    run_id, ws = _initial_run_paused(tmp_path, monkeypatch)

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "research", "review", run_id,
            "--decision", "revise",
            "--reason", "needs revision",
            "--reviewer", "test-reviewer",
            "--workspace", str(ws),
        ],
        catch_exceptions=False,
    )

    bdir = _bundle_dir(ws, run_id)
    if result.exit_code == EXIT_RUN_PAUSED:
        # Re-paused: no false terminal bundle.
        assert not (bdir / "manifest.json").exists(), (
            "false terminal bundle created for a re-paused revise"
        )
    elif result.exit_code in (EXIT_OK, EXIT_RUN_FAILED):
        # Terminal: integrity-verified bundle must exist.
        assert (bdir / "manifest.json").exists(), (
            f"terminal bundle missing after revise at {bdir}"
        )
        reader = BundleReader(bdir)
        assert reader.verify_integrity() is True, (
            "revise terminal bundle failed integrity verification"
        )
    else:
        pytest.fail(
            f"revise produced unexpected exit code: {result.exit_code}\n"
            f"{result.output}"
        )


# --------------------------------------------------------------------------- #
# finalization failure
# --------------------------------------------------------------------------- #


def test_cli_finalization_failure_propagates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An injected C5 finalization failure must propagate through the CLI.

    The CLI must not render or return successful completion when bundle
    finalization fails. We patch ``finalize_bundle`` on the
    ``bundle_finalizer`` module (which ``resume()`` imports lazily) so the
    terminal resume path raises, and assert the CLI surfaces the error
    rather than exiting OK.
    """
    run_id, ws = _initial_run_paused(tmp_path, monkeypatch)

    from nodechain.research import bundle_finalizer

    def _fail(*args, **kwargs):
        raise bundle_finalizer.BundleFinalizationError(
            "injected C5 finalization failure (H0.1 regression test)"
        )

    runner = CliRunner()
    with patch.object(bundle_finalizer, "finalize_bundle", side_effect=_fail):
        result = runner.invoke(
            cli,
            [
                "research", "review", run_id,
                "--decision", "approve",
                "--reason", "evidence is sufficient",
                "--reviewer", "test-reviewer",
                "--workspace", str(ws),
            ],
            # Let Click capture the exception so we can inspect exit_code.
            catch_exceptions=True,
        )

    assert result.exit_code != EXIT_OK, (
        "CLI reported success (exit 0) despite an injected finalization "
        "failure — finalization error did not propagate"
    )
    assert isinstance(
        result.exception, bundle_finalizer.BundleFinalizationError
    ), (
        f"expected BundleFinalizationError to propagate, got "
        f"{type(result.exception).__name__}: {result.exception}"
    )


# --------------------------------------------------------------------------- #
# identity
# --------------------------------------------------------------------------- #


def test_cli_identity_stable_across_reconstruction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Run ID, descriptor digest, corpus identity and chain ID are unchanged
    across CLI reconstruction (initial run descriptor vs. post-review)."""
    run_id, ws = _initial_run_paused(tmp_path, monkeypatch)
    before = _load_descriptor(ws, run_id)

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "research", "review", run_id,
            "--decision", "approve",
            "--reason", "identity check",
            "--reviewer", "test-reviewer",
            "--workspace", str(ws),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == EXIT_OK, (
        f"identity approve did not complete: exit={result.exit_code}\n"
        f"{result.output}"
    )

    after = _load_descriptor(ws, run_id)
    assert after["run_id"] == before["run_id"], "run ID changed across reconstruction"
    assert after["chain_id"] == before["chain_id"], "chain ID changed"
    assert after["corpus_path"] == before["corpus_path"], "corpus path changed"
    assert after["corpus_digest"] == before["corpus_digest"], (
        "corpus digest changed across reconstruction"
    )
    assert after["descriptor_digest"] == before["descriptor_digest"], (
        "descriptor digest changed across reconstruction"
    )
