"""Step 7C: Four-fault proof matrix + integrity tests.

All four fault classes produce authoritative trace evidence and project
to durable fault records via pure trace-event projection.
"""

from __future__ import annotations

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
# All four fault classes produce fault records
# --------------------------------------------------------------------------- #


def test_fail_before_dispatch_fault_record(tmp_path: Path) -> None:
    runner = _run(tmp_path, "corpus_fail_before_dispatch.yaml")
    run_id = runner.orchestrator.state.run_id
    faults = list_fault_records(runner._workspace_dir, run_id)
    fbd = [f for f in faults if f["failure_type"] == "fail_before_dispatch"]
    assert len(fbd) == 1
    f = fbd[0]
    assert f["reason_codes"] == ["LANE_ADMISSION_REJECTED"]
    assert f["state_after"] == "not_dispatched"
    assert f["trace_id"]
    # Proving event resolves.
    trace_by_id = {ev.event_id: ev for ev in runner.orchestrator.trace.events}
    for eid in f["proving_event_ids"]:
        assert eid in trace_by_id


def test_timeout_recovered_fault_record(tmp_path: Path) -> None:
    runner = _run(tmp_path, "corpus_timeout_after_dispatch.yaml")
    run_id = runner.orchestrator.state.run_id
    faults = list_fault_records(runner._workspace_dir, run_id)
    timeout = [f for f in faults if f["failure_type"] == "timeout_after_dispatch"]
    assert len(timeout) == 1
    f = timeout[0]
    assert f["reason_codes"] == ["SEARCH_TIMEOUT_AFTER_DISPATCH"]
    assert f["state_after"] == "timeout"
    assert f["trace_id"]
    trace_by_id = {ev.event_id: ev for ev in runner.orchestrator.trace.events}
    for eid in f["proving_event_ids"]:
        assert eid in trace_by_id


def test_malformed_provenance_fault_record(tmp_path: Path) -> None:
    runner = _run(tmp_path, "corpus_malformed_provenance.yaml")
    run_id = runner.orchestrator.state.run_id
    faults = list_fault_records(runner._workspace_dir, run_id)
    mp = [f for f in faults if f["failure_type"] == "malformed_provenance"]
    assert len(mp) == 1
    f = mp[0]
    assert f["reason_codes"] == ["SEARCH_PROVENANCE_MALFORMED"]
    assert f["state_after"] == "provenance_rejected"
    assert f["trace_id"]
    trace_by_id = {ev.event_id: ev for ev in runner.orchestrator.trace.events}
    for eid in f["proving_event_ids"]:
        assert eid in trace_by_id


def test_partial_result_set_fault_record(tmp_path: Path) -> None:
    runner = _run(tmp_path, "corpus_partial_result_set.yaml")
    run_id = runner.orchestrator.state.run_id
    faults = list_fault_records(runner._workspace_dir, run_id)
    prs = [f for f in faults if f["failure_type"] == "partial_result_set"]
    assert len(prs) == 1
    f = prs[0]
    assert f["reason_codes"] == ["SEARCH_PARTIAL_RESULT_SET"]
    assert f["state_after"] == "partial"
    assert f["trace_id"]
    trace_by_id = {ev.event_id: ev for ev in runner.orchestrator.trace.events}
    for eid in f["proving_event_ids"]:
        assert eid in trace_by_id


# --------------------------------------------------------------------------- #
# Integrity tests
# --------------------------------------------------------------------------- #


def test_stable_literature_creates_no_fault_records(tmp_path: Path) -> None:
    runner = _run(tmp_path, "corpus_basic.yaml")
    faults = list_fault_records(runner._workspace_dir, runner.orchestrator.state.run_id)
    assert faults == [], f"unexpected fault records in clean run: {faults}"


def test_deterministic_reprojection(tmp_path: Path) -> None:
    runner = _run(tmp_path, "corpus_timeout_after_dispatch.yaml")
    run_id = runner.orchestrator.state.run_id
    faults_1 = list_fault_records(runner._workspace_dir, run_id)
    assert len(faults_1) > 0
    with pytest.raises(FileExistsError):
        runner._record_faults(run_id, runner.orchestrator.trace)
    faults_2 = list_fault_records(runner._workspace_dir, run_id)
    ids_1 = {f["fault_id"] for f in faults_1}
    ids_2 = {f["fault_id"] for f in faults_2}
    assert ids_1 == ids_2


def test_no_record_from_unrelated_node_events(tmp_path: Path) -> None:
    runner = _run(tmp_path, "corpus_basic.yaml")
    for ev in runner.orchestrator.trace.events:
        for rc in ev.reason_codes:
            assert rc not in WorkspaceRunner._RECOGNIZED_FAULT_CODES
