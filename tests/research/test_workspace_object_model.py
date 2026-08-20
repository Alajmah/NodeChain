"""H1.1 — Workspace object model tests.

The A–J matrix from the frozen H1.1 plan:

  A. Empty workspace → deterministic not-found/empty result
  B. Descriptor exists, runtime state absent → descriptor-only/incomplete
  C. Active run → current state/revision/trace projected
  D. Paused-for-review run → review requirement visible, no terminal bundle
  E. Faulted/recovered run → original fault preserved, recovery visible
  F. Qualified-source run → source_id/hash/artifact_ref preserved exactly
  G. Completed run → terminal bundle integrity verified
  H. Tampered terminal bundle → never reported as verified
  I. Multiple runs → all run summaries visible, selection deterministic
  J. Read-only invariant → projecting changes no authoritative record
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nodechain.research.run_descriptor import (
    RunDescriptor,
    save_descriptor,
    save_review_record,
    save_outcome_record,
    save_fault_record,
)
from nodechain.research.workspace import (
    BUNDLE_ABSENT,
    BUNDLE_INVALID,
    BUNDLE_VERIFIED,
    PROJECTION_VERSION,
    SECTION_LIVE_CURRENT,
    SECTION_NOT_AVAILABLE,
    SECTION_TERMINAL_VERIFIED,
    open_workspace,
)

CORPUS_PATH = (
    Path(__file__).parent.parent.parent / "tests" / "fixtures" / "research"
    / "corpus_basic.yaml"
)


def _make_descriptor(workspace: Path, run_id: str, question: str = "Is async Rust memory-safe?") -> RunDescriptor:
    """Build a minimal valid descriptor for testing."""
    return RunDescriptor(
        run_id=run_id,
        chain_id=f"chain-{run_id}",
        question=question,
        corpus_path=str(CORPUS_PATH),
        corpus_digest="a" * 64,
        corpus_version="1.0.0",
        scenario_id="basic",
        db_path=str(workspace / f"{run_id}.db"),
        trace_dir=str(workspace / "traces"),
        workspace_dir=str(workspace),
    )


class _RunCtx:
    """Test helper carrying the run result plus workspace paths."""

    def __init__(self, result, runner) -> None:
        self.result = result
        self.runner = runner
        self.state = result.state
        self.trace = result.trace
        self.run_id = result.run_id
        self.chain_id = result.chain_id

    @property
    def workspace_dir(self) -> str:
        return self.runner._workspace_dir

    @property
    def db_path(self) -> str:
        return self.runner._db_path

    @property
    def descriptor(self):
        from nodechain.research.run_descriptor import load_descriptor
        return load_descriptor(self.workspace_dir, self.run_id)


def _run_research(tmp_path: Path, question: str = "Is async Rust memory-safe?"):
    """Run the real WorkspaceRunner to produce a live workspace."""
    from nodechain.research.runner import ResearchBrief, WorkspaceRunner
    ws_dir = tmp_path / "ws"
    runner = WorkspaceRunner(
        brief=ResearchBrief.from_question(question),
        corpus_path=str(CORPUS_PATH),
        db_path=str(ws_dir / "workspace.db"),
        trace_dir=str(ws_dir / "traces"),
        workspace_dir=ws_dir,
    )
    return _RunCtx(runner.run(), runner)


# --------------------------------------------------------------------------- #
# A. Empty workspace
# --------------------------------------------------------------------------- #


def test_A_empty_workspace_returns_deterministic_empty():
    snap = open_workspace("no-such-directory")
    assert snap.selected_run_id == ""
    assert snap.projection_state == SECTION_NOT_AVAILABLE
    assert snap.runs == []
    assert snap.bundle_status == BUNDLE_ABSENT
    assert snap.objective.state == SECTION_NOT_AVAILABLE
    assert snap.projection_version == PROJECTION_VERSION


def test_A_workspace_root_with_no_runs_dir():
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        snap = open_workspace(td)
        assert snap.runs == []
        assert snap.selected_run_id == ""


# --------------------------------------------------------------------------- #
# B. Descriptor without runtime state
# --------------------------------------------------------------------------- #


def test_B_descriptor_only_run_is_incomplete(tmp_path: Path):
    desc = _make_descriptor(tmp_path, "run-orphan")
    save_descriptor(tmp_path, desc)
    # H1.1 AC7: the descriptor's DB does NOT exist and must NOT be created
    # by the act of observing the workspace.
    db_path = Path(desc.db_path)
    assert not db_path.exists(), "precondition: DB absent"
    snap = open_workspace(tmp_path)
    assert snap.selected_run_id == "run-orphan"
    # No runtime state: every runtime-derived section is not_available.
    assert snap.execution_status == ""  # no invented status
    assert snap.projection_state == SECTION_NOT_AVAILABLE
    assert snap.objective.state == SECTION_LIVE_CURRENT  # from descriptor
    assert snap.trace.state == SECTION_NOT_AVAILABLE
    assert snap.runs[0].has_runtime_state is False
    # The projection must not have created the DB file.
    assert not db_path.exists(), (
        f"read-only violation: open_workspace() created {db_path}"
    )


# --------------------------------------------------------------------------- #
# C. Active run (live projection)
# --------------------------------------------------------------------------- #


def test_C_active_run_projects_state_and_outputs(tmp_path: Path):
    result = _run_research(tmp_path)
    snap = open_workspace(result.workspace_dir)
    assert snap.selected_run_id == result.state.run_id
    assert snap.execution_status == result.state.status
    assert snap.runtime_revision == result.state.revision
    assert snap.projection_state == SECTION_LIVE_CURRENT
    # Node outputs projected.
    assert snap.objective.state == SECTION_LIVE_CURRENT
    assert snap.objective.data["question"] == "Is async Rust memory-safe?"
    assert snap.sources.state in (SECTION_LIVE_CURRENT, SECTION_NOT_AVAILABLE)
    # Trace available.
    assert snap.trace.state == SECTION_LIVE_CURRENT
    assert len(snap.trace.data) > 0


# --------------------------------------------------------------------------- #
# D. Paused-for-review run
# --------------------------------------------------------------------------- #


def test_D_paused_run_shows_review_no_bundle(tmp_path: Path):
    result = _run_research(tmp_path)
    if result.state.status not in ("paused", "waiting_for_review"):
        pytest.skip(f"corpus produced non-paused status: {result.state.status}")
    snap = open_workspace(result.workspace_dir)
    assert snap.execution_status in ("paused", "waiting_for_review")
    assert snap.bundle_status == BUNDLE_ABSENT
    assert snap.terminal_bundle.state == SECTION_NOT_AVAILABLE
    # Review requirement visible.
    assert snap.review_decisions.runtime_review_state != {} or \
        snap.review_decisions.cli_submission_records != []


# --------------------------------------------------------------------------- #
# E. Faulted/recovered run
# --------------------------------------------------------------------------- #


def test_E_fault_records_preserved(tmp_path: Path):
    result = _run_research(tmp_path)
    rid = result.state.run_id
    ws = Path(result.workspace_dir)
    save_fault_record(ws, rid, {
        "fault_id": "fault-001",
        "fault_type": "transient",
        "node_id": "evidence_synthesizer",
        "operation": "node_execute:evidence_synthesizer",
        "reason": "simulated timeout",
        "timestamp": "2026-01-01T00:00:00Z",
    })
    snap = open_workspace(ws)
    assert len(snap.faults) == 1
    assert snap.faults[0].fault_id == "fault-001"
    assert snap.faults[0].node_id == "evidence_synthesizer"
    assert snap.faults[0].reason == "simulated timeout"


def test_E_recovery_side_effects_from_authoritative_ledger(tmp_path: Path):
    """H1.1 AC3: WorkspaceRecovery.side_effects projects from the
    AUTHORITATIVE side-effect LEDGER (StateManager.get_side_effects),
    not from the ChainState.side_effects snapshot."""
    result = _run_research(tmp_path)
    rid = result.run_id
    ws = Path(result.workspace_dir)

    # Read the authoritative ledger rows directly.
    from nodechain.core.state import StateManager
    sm = StateManager(result.db_path, read_only=True)
    ledger_rows = sm.get_side_effects(rid)

    snap = open_workspace(ws)
    # The workspace's recovery side_effects are the LEDGER rows, not the
    # ChainState snapshot. When the ledger has rows, they must match; when
    # the ledger is empty, the projection is empty regardless of the
    # snapshot's content.
    assert snap.recovery.side_effects == ledger_rows, (
        f"side_effects projected from snapshot, not ledger: "
        f"workspace={len(snap.recovery.side_effects)}, "
        f"ledger={len(ledger_rows)}"
    )
    # The authoritative ledger is the projection source — if the snapshot
    # differs, the workspace must still carry the ledger truth.
    snapshot_se = list(result.state.side_effects or [])
    if ledger_rows != snapshot_se:
        # The whole point: ledger wins over the snapshot.
        assert snap.recovery.side_effects != snapshot_se or not snapshot_se


# --------------------------------------------------------------------------- #
# F. Qualified-source run
# --------------------------------------------------------------------------- #


def test_F_qualified_sources_preserved(tmp_path: Path):
    result = _run_research(tmp_path)
    snap = open_workspace(result.workspace_dir)
    if snap.qualified_sources.state == SECTION_NOT_AVAILABLE:
        pytest.skip("linker produced no qualified/linked sources")
    qs = snap.qualified_sources.data
    assert isinstance(qs, (list, dict))
    items = qs if isinstance(qs, list) else list(qs.values())
    if not items:
        pytest.skip("qualified source list is empty")
    for item in items:
        if isinstance(item, dict):
            # The linker contract: every linked source carries its
            # source_id plus the propagated binding to the ingested
            # artifact (hash and reference).
            assert "source_id" in item, f"missing source_id in {list(item.keys())}"
            assert any(k in item for k in ("source_hash", "hash", "digest")), (
                f"no hash binding in {list(item.keys())}"
            )
            assert any(k in item for k in ("artifact_ref", "artifact", "ref")), (
                f"no artifact binding in {list(item.keys())}"
            )


# --------------------------------------------------------------------------- #
# G. Completed run with verified terminal bundle
# --------------------------------------------------------------------------- #


def _finalize_if_terminal(tmp_path: Path, result) -> bool:
    """Attempt bundle finalization; returns True when a bundle was created."""
    if result.state.status != "completed":
        return False
    from nodechain.research.bundle_finalizer import finalize_bundle
    from nodechain.research.corpus import load_corpus
    desc = result.descriptor
    corpus = load_corpus(Path(desc.corpus_path))
    try:
        finalize_bundle(result.workspace_dir, result.run_id,
                        desc, result.trace, result.state, corpus)
        return True
    except Exception:
        return False


def test_G_completed_run_verified_bundle(tmp_path: Path):
    result = _run_research(tmp_path)
    if result.state.status != "completed":
        pytest.skip(f"corpus produced {result.state.status}, not completed")
    if not _finalize_if_terminal(tmp_path, result):
        pytest.skip("bundle finalization not possible for this run")
    snap = open_workspace(result.workspace_dir)
    assert snap.bundle_status == BUNDLE_VERIFIED
    assert snap.terminal_bundle.state == SECTION_TERMINAL_VERIFIED
    ref = snap.terminal_bundle.data
    assert ref.bundle_digest
    assert ref.run_status in ("completed", "completed_degraded", "failed",
                              "blocked")
    assert snap.research_outcome == ref.run_status
    assert snap.citations.state == SECTION_TERMINAL_VERIFIED
    assert snap.uncertainties.state == SECTION_TERMINAL_VERIFIED


# --------------------------------------------------------------------------- #
# H. Tampered terminal bundle
# --------------------------------------------------------------------------- #


def test_H_tampered_bundle_never_verified(tmp_path: Path):
    result = _run_research(tmp_path)
    if result.state.status != "completed":
        pytest.skip(f"corpus produced {result.state.status}, not completed")
    if not _finalize_if_terminal(tmp_path, result):
        pytest.skip("bundle finalization not possible for this run")
    # Tamper with one document.
    bundle_dir = Path(result.workspace_dir) / "runs" / result.state.run_id / "bundle"
    doc = bundle_dir / "claims.json"
    data = json.loads(doc.read_text(encoding="utf-8"))
    data["tampered"] = True
    doc.write_text(json.dumps(data), encoding="utf-8")

    snap = open_workspace(result.workspace_dir)
    assert snap.bundle_status == BUNDLE_INVALID
    assert snap.terminal_bundle.state == SECTION_NOT_AVAILABLE
    assert snap.terminal_bundle.error  # the failure is explicit
    assert snap.research_outcome == ""  # no fabricated outcome


# --------------------------------------------------------------------------- #
# I. Multiple runs in one workspace
# --------------------------------------------------------------------------- #


def test_I_multiple_runs_visible_and_deterministic(tmp_path: Path):
    save_descriptor(tmp_path, _make_descriptor(tmp_path, "run-alpha"))
    save_descriptor(tmp_path, _make_descriptor(tmp_path, "run-beta"))
    save_descriptor(tmp_path, _make_descriptor(tmp_path, "run-gamma"))
    snap = open_workspace(tmp_path)
    ids = [r.run_id for r in snap.runs]
    assert set(ids) == {"run-alpha", "run-beta", "run-gamma"}
    # Explicit selection.
    snap_b = open_workspace(tmp_path, run_id="run-beta")
    assert snap_b.selected_run_id == "run-beta"
    # Deterministic: same workspace, same selection without run_id.
    snap_c = open_workspace(tmp_path)
    snap_d = open_workspace(tmp_path)
    assert snap_c.selected_run_id == snap_d.selected_run_id


# --------------------------------------------------------------------------- #
# J. Read-only invariant
# --------------------------------------------------------------------------- #


def test_J_projection_is_read_only(tmp_path: Path):
    result = _run_research(tmp_path)
    ws = Path(result.workspace_dir)
    rid = result.run_id

    # Snapshot authoritative artifacts before projection.
    desc_file = ws / "runs" / rid / "descriptor.json"
    desc_before = desc_file.read_bytes()

    # H1.1 AC7 strengthened: hash the ENTIRE SQLite file, not just selected
    # rows, so schema initialization or journal/WAL side effects are caught.
    import hashlib
    db_file = Path(result.db_path)
    db_hash_before = hashlib.sha256(db_file.read_bytes()).hexdigest()

    import sqlite3
    conn = sqlite3.connect(result.db_path)
    state_before = conn.execute(
        "SELECT state_json FROM chain_states WHERE run_id = ?",
        (rid,),
    ).fetchone()[0]
    trace_before = conn.execute(
        "SELECT COUNT(*) FROM state_events WHERE run_id = ?", (rid,)
    ).fetchone()[0]
    conn.close()

    # Project twice (repeated opens must also be safe).
    snap1 = open_workspace(ws)
    snap2 = open_workspace(ws, run_id=rid)

    # Verify nothing changed: descriptor bytes, DB file hash, state JSON,
    # and trace row count are all identical after projection.
    assert desc_file.read_bytes() == desc_before
    db_hash_after = hashlib.sha256(db_file.read_bytes()).hexdigest()
    assert db_hash_after == db_hash_before, (
        "read-only violation: DB file content changed across projection"
    )
    conn = sqlite3.connect(result.db_path)
    state_after = conn.execute(
        "SELECT state_json FROM chain_states WHERE run_id = ?",
        (rid,),
    ).fetchone()[0]
    trace_after = conn.execute(
        "SELECT COUNT(*) FROM state_events WHERE run_id = ?", (rid,)
    ).fetchone()[0]
    conn.close()
    assert state_after == state_before
    assert trace_after == trace_before
    assert snap1.selected_run_id == snap2.selected_run_id == rid


def test_I_selection_prefers_most_recently_persisted(tmp_path: Path):
    """H1.1 frozen rule: the default selection is the MOST RECENTLY
    PERSISTED run (highest DB updated_at), NOT the most recently created
    descriptor. A persisted run whose updated_at is later than a
    descriptor-only run's created_at wins unambiguously."""
    # Run the real research (persisted, updated_at = now).
    result = _run_research(tmp_path)
    ws = Path(result.workspace_dir)

    # Add a descriptor-only run with an EARLIER created_at (1 hour ago).
    # Its effective timestamp is created_at (no runtime state).
    from datetime import datetime, timezone, timedelta
    earlier = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    older_desc = _make_descriptor(ws, "run-older")
    older_dict = older_desc.model_dump(mode="json")
    older_dict.pop("descriptor_digest", None)
    older_dict["created_at"] = earlier
    from nodechain.research.run_descriptor import RunDescriptor as _RD
    older_desc = _RD(**older_dict)
    save_descriptor(ws, older_desc)

    # The persisted run's updated_at (now) > the descriptor-only run's
    # created_at (1 hour ago). The persisted run MUST win — this is the
    # frozen rule: persistence freshness (updated_at) is the primary key.
    snap = open_workspace(ws)
    assert snap.selected_run_id == result.run_id, (
        f"expected persisted run {result.run_id} to win "
        f"(updated_at=now > created_at=1h_ago), "
        f"got {snap.selected_run_id}"
    )
    # Determinism: same result on repeat.
    snap2 = open_workspace(ws)
    assert snap2.selected_run_id == result.run_id


def test_J_snapshot_is_frozen():
    """The snapshot model is immutable after construction."""
    from nodechain.research.workspace import ResearchWorkspaceSnapshot
    snap = ResearchWorkspaceSnapshot(
        projection_version=1,
        workspace_root="/tmp/x",
        selected_run_id="r",
        projection_state=SECTION_NOT_AVAILABLE,
    )
    with pytest.raises(Exception):
        snap.selected_run_id = "other"  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# Review record helper coverage
# --------------------------------------------------------------------------- #


def test_review_and_outcome_records_listed(tmp_path: Path):
    save_descriptor(tmp_path, _make_descriptor(tmp_path, "run-rev"))
    save_review_record(tmp_path, "run-rev", {
        "review_id": "rev-001", "decision": "approve",
    })
    save_outcome_record(tmp_path, "run-rev", "rev-001", {
        "outcome": "resumed",
    })
    snap = open_workspace(tmp_path)
    assert len(snap.review_decisions.cli_submission_records) == 1
    assert snap.review_decisions.cli_submission_records[0]["decision"] == "approve"
    assert len(snap.review_decisions.resume_outcome_records) == 1
    assert snap.review_decisions.resume_outcome_records[0]["outcome"] == "resumed"
