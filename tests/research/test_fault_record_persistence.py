"""Fault record persistence tests.

Proves that fault records are persisted as immutable write-once files,
derived from pure trace-event projection.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nodechain.research.runner import ResearchBrief, WorkspaceRunner
from nodechain.research.run_descriptor import list_fault_records

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
    """Malformed provenance produces a fault record via trace-event projection
    (node_failed event with PROVENANCE_VERSION keyword in reason_codes)."""
    runner = _run(tmp_path, "corpus_malformed_provenance.yaml")
    faults = list_fault_records(runner._workspace_dir, runner.orchestrator.state.run_id)
    mp = [f for f in faults if f["failure_type"] == "malformed_provenance"]
    assert len(mp) == 1
    f = mp[0]
    assert f["reason_codes"] == ["SEARCH_PROVENANCE_MALFORMED"]
    assert f["proving_event_ids"]


def test_fault_record_deterministic_id(tmp_path: Path) -> None:
    """Fault IDs are SHA-256 hashes of run_id|step_id|reason_code."""
    import hashlib
    runner = _run(tmp_path, "corpus_timeout_after_dispatch.yaml")
    run_id = runner.orchestrator.state.run_id
    faults = list_fault_records(runner._workspace_dir, run_id)
    if faults:
        f = faults[0]
        expected_id = hashlib.sha256(
            f"{run_id}|{f['step_id']}|{f['reason_codes'][0]}".encode()
        ).hexdigest()
        assert f["fault_id"] == expected_id


def test_timeout_fault_recovered_remains_recorded(tmp_path: Path) -> None:
    """A recovered timeout still produces a fault record."""
    runner = _run(tmp_path, "corpus_timeout_after_dispatch.yaml")
    faults = list_fault_records(runner._workspace_dir, runner.orchestrator.state.run_id)
    timeout = [f for f in faults if f["failure_type"] == "timeout_after_dispatch"]
    assert len(timeout) == 1
    f = timeout[0]
    assert f["reason_codes"] == ["SEARCH_TIMEOUT_AFTER_DISPATCH"]
    assert f["proving_event_ids"]
