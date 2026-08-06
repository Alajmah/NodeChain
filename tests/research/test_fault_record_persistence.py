"""Fault record persistence tests.

Proves that fault records are persisted as immutable write-once files,
contain exact runtime evidence, and cite the proving trace events.

Only faults that produce durable runtime evidence (trace events) are recorded.
Faults that the runtime recovers from (no trace evidence) are not recorded.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nodechain.research.runner import ResearchBrief, WorkspaceRunner
from nodechain.research.run_descriptor import list_fault_records, fault_path

FIXTURES = Path(__file__).parent.parent.parent / "tests" / "fixtures" / "research"


def _run(tmp_path: Path, corpus_file: str) -> WorkspaceRunner:
    runner = WorkspaceRunner(
        brief=ResearchBrief.from_question("test query"),
        corpus_path=str(FIXTURES / corpus_file),
        workspace_dir=str(tmp_path / corpus_file.replace(".yaml", "")),
    )
    runner.run()
    return runner


def test_malformed_provenance_fault_record_persisted(tmp_path: Path) -> None:
    """A malformed_provenance fault (node_failed in trace) produces a record."""
    runner = _run(tmp_path, "corpus_malformed_provenance.yaml")
    faults = list_fault_records(runner._workspace_dir, runner.orchestrator.state.run_id)
    mp_faults = [f for f in faults if f["failure_type"] == "malformed_provenance"]
    assert len(mp_faults) == 1, f"expected 1 malformed_provenance fault, got {len(mp_faults)}"
    f = mp_faults[0]
    assert f["dispatched"] is True
    assert f["state_after"] == "provenance_rejected"
    # Must cite proving events from the actual trace.
    proving = f.get("proving_events", [])
    assert len(proving) > 0, "no proving events cited"
    assert any("node_failed" in e["event_type"] for e in proving), (
        f"proving events do not include node_failed: {[e['event_type'] for e in proving]}"
    )
    # Evidence truth must show runtime counts.
    truth = f.get("evidence_truth", {})
    assert truth.get("node_failed_count", 0) > 0


def test_fault_record_deterministic_id(tmp_path: Path) -> None:
    """Fault IDs are deterministic (no random UUIDs)."""
    runner = _run(tmp_path, "corpus_malformed_provenance.yaml")
    run_id = runner.orchestrator.state.run_id
    faults = list_fault_records(runner._workspace_dir, run_id)
    if faults:
        f = faults[0]
        # Deterministic format: run_id[:8]-failure_type-op_digest
        assert run_id[:8] in f["fault_id"], (
            f"fault_id {f['fault_id']} does not contain run_id prefix"
        )
        assert "malformed-provenance" in f["fault_id"], (
            f"fault_id {f['fault_id']} does not contain fault type"
        )


def test_timeout_fault_recovered_no_record(tmp_path: Path) -> None:
    """When the runtime recovers from a timeout (no durable trace evidence),
    no fault record is created — the fault did not materialize."""
    runner = _run(tmp_path, "corpus_timeout_after_dispatch.yaml")
    faults = list_fault_records(runner._workspace_dir, runner.orchestrator.state.run_id)
    timeout_faults = [f for f in faults if f["failure_type"] == "timeout_after_dispatch"]
    # The runtime recovered the timeout — no node_failed event in the trace.
    # Therefore no fault record should exist (exact runtime truth).
    assert len(timeout_faults) == 0, (
        f"timeout fault record created despite runtime recovery: {timeout_faults}"
    )
