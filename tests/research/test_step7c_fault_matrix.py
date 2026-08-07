"""Step 7C: Four-fault proof matrix + integrity tests.

Proves the complete fault-record contract for each fault class and
integrity properties of the event-projection fault recorder.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from nodechain.research.runner import ResearchBrief, WorkspaceRunner
from nodechain.research.run_descriptor import list_fault_records

FIXTURES = Path(__file__).parent.parent.parent / "tests" / "fixtures" / "research"


def _run(tmp_path: Path, corpus: str) -> WorkspaceRunner:
    runner = WorkspaceRunner(
        brief=ResearchBrief.from_question("test query"),
        corpus_path=str(FIXTURES / corpus),
        workspace_dir=str(tmp_path / corpus.replace(".yaml", "")),
    )
    runner.run()
    return runner


# --------------------------------------------------------------------------- #
# Fail before dispatch
# --------------------------------------------------------------------------- #


def test_fail_before_dispatch_fault_record(tmp_path: Path) -> None:
    """fail_before_dispatch produces a fault record citing the exact event."""
    runner = _run(tmp_path, "corpus_fail_before_dispatch.yaml")
    run_id = runner.orchestrator.state.run_id
    faults = list_fault_records(runner._workspace_dir, run_id)
    fbd = [f for f in faults if f["failure_type"] == "fail_before_dispatch"]
    assert len(fbd) == 1, f"expected 1 fail_before_dispatch fault, got {len(fbd)}"
    f = fbd[0]
    assert f["reason_codes"] == ["LANE_ADMISSION_REJECTED"]
    assert f["state_after"] == "not_dispatched"
    # Proving event ID resolves to a real trace event.
    trace_by_id = {ev.event_id: ev for ev in runner.orchestrator.trace.events}
    for eid in f["proving_event_ids"]:
        assert eid in trace_by_id, f"proving event {eid} not in trace"
        ev = trace_by_id[eid]
        assert "LANE_ADMISSION_REJECTED" in ev.reason_codes


# --------------------------------------------------------------------------- #
# Timeout with recovery
# --------------------------------------------------------------------------- #


def test_timeout_recovered_remains_recorded(tmp_path: Path) -> None:
    """Timeout fault record exists even when the node eventually succeeds."""
    runner = _run(tmp_path, "corpus_timeout_after_dispatch.yaml")
    run_id = runner.orchestrator.state.run_id
    faults = list_fault_records(runner._workspace_dir, run_id)
    timeout = [f for f in faults if f["failure_type"] == "timeout_after_dispatch"]
    assert len(timeout) == 1
    f = timeout[0]
    assert f["reason_codes"] == ["SEARCH_TIMEOUT_AFTER_DISPATCH"]
    assert f["state_after"] == "timeout"
    # Every proving event resolves.
    trace_by_id = {ev.event_id: ev for ev in runner.orchestrator.trace.events}
    for eid in f["proving_event_ids"]:
        assert eid in trace_by_id


# --------------------------------------------------------------------------- #
# Malformed provenance — no recognized reason code in trace
# --------------------------------------------------------------------------- #


def test_malformed_provenance_no_record_without_reason_code(tmp_path: Path) -> None:
    """No fault record for malformed_provenance because the trace doesn't
    carry SEARCH_PROVENANCE_MALFORMED (ProvenanceError doesn't carry it)."""
    runner = _run(tmp_path, "corpus_malformed_provenance.yaml")
    faults = list_fault_records(runner._workspace_dir, runner.orchestrator.state.run_id)
    mp = [f for f in faults if f["failure_type"] == "malformed_provenance"]
    assert len(mp) == 0


# --------------------------------------------------------------------------- #
# Partial result set — no recognized reason code in trace
# --------------------------------------------------------------------------- #


def test_partial_result_set_no_record_without_reason_code(tmp_path: Path) -> None:
    """No fault record for partial_result_set because the trace doesn't
    carry SEARCH_PARTIAL_RESULT_SET (adapter returns results normally)."""
    runner = _run(tmp_path, "corpus_partial_result_set.yaml")
    faults = list_fault_records(runner._workspace_dir, runner.orchestrator.state.run_id)
    prs = [f for f in faults if f["failure_type"] == "partial_result_set"]
    assert len(prs) == 0


# --------------------------------------------------------------------------- #
# Integrity tests
# --------------------------------------------------------------------------- #


def test_stable_literature_creates_no_fault_records(tmp_path: Path) -> None:
    """A clean run (no faults) produces zero fault records."""
    runner = _run(tmp_path, "corpus_basic.yaml")
    faults = list_fault_records(runner._workspace_dir, runner.orchestrator.state.run_id)
    assert faults == [], f"unexpected fault records in clean run: {faults}"


def test_deterministic_reprojection(tmp_path: Path) -> None:
    """Reprojecting the same trace produces the same fault IDs.
    The second projection hits write-once (FileExistsError) because the
    deterministic ID already exists. This is correct behavior: same input
    → same ID → no mutation."""
    runner = _run(tmp_path, "corpus_timeout_after_dispatch.yaml")
    run_id = runner.orchestrator.state.run_id
    faults_1 = list_fault_records(runner._workspace_dir, run_id)
    assert len(faults_1) > 0
    # Re-run the projection on the same trace — write-once rejects.
    with pytest.raises(FileExistsError):
        runner._record_faults(run_id, runner.orchestrator.trace)
    # Fault records are unchanged.
    faults_2 = list_fault_records(runner._workspace_dir, run_id)
    ids_1 = {f["fault_id"] for f in faults_1}
    ids_2 = {f["fault_id"] for f in faults_2}
    assert ids_1 == ids_2


def test_no_record_from_unrelated_node_events(tmp_path: Path) -> None:
    """Events from nodes other than search_tool with no recognized reason
    codes produce no fault records."""
    runner = _run(tmp_path, "corpus_basic.yaml")
    # The trace may have events from goal_interpreter, task_planner, etc.
    # None should carry recognized fault reason codes.
    for ev in runner.orchestrator.trace.events:
        for rc in ev.reason_codes:
            assert rc not in WorkspaceRunner._RECOGNIZED_FAULT_CODES, (
                f"unexpected fault reason code {rc} on event {ev.event_type}"
            )
