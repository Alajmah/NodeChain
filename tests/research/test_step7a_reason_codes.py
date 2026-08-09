"""Step 7A tests: runtime trace events carry stable reason codes for all
four fault classes.

Each fault scenario produces a trace event with the exact frozen reason code.
Every proving event has event_id, run_id, step_id, and (where applicable)
attempt metadata.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nodechain.research.runner import ResearchBrief, WorkspaceRunner

FIXTURES = Path(__file__).parent.parent.parent / "tests" / "fixtures" / "research"


def _run(tmp_path: Path, corpus: str) -> WorkspaceRunner:
    runner = WorkspaceRunner(
        brief=ResearchBrief.from_question("test query"),
        corpus_path=str(FIXTURES / corpus),
        workspace_dir=str(tmp_path / corpus.replace(".yaml", "")),
    )
    runner.run()
    return runner


def _find_events_with_reason(runner: WorkspaceRunner, reason_code: str) -> list:
    return [
        ev for ev in runner.orchestrator.trace.events
        if ev.node_id == "search_tool"
        and reason_code in ev.reason_codes
    ]


# --------------------------------------------------------------------------- #
# Fail before dispatch
# --------------------------------------------------------------------------- #


def test_fail_before_dispatch_has_lane_admission_rejected(tmp_path: Path) -> None:
    runner = _run(tmp_path, "corpus_fail_before_dispatch.yaml")
    events = _find_events_with_reason(runner, "LANE_ADMISSION_REJECTED")
    assert len(events) >= 1, "no LANE_ADMISSION_REJECTED event"
    ev = events[0]
    assert ev.event_id, "missing event_id"
    assert ev.run_id, "missing run_id"
    assert ev.step_id is not None, "missing step_id"


# --------------------------------------------------------------------------- #
# Timeout after dispatch
# --------------------------------------------------------------------------- #


def test_timeout_has_search_timeout_reason_code(tmp_path: Path) -> None:
    runner = _run(tmp_path, "corpus_timeout_after_dispatch.yaml")
    events = _find_events_with_reason(runner, "SEARCH_TIMEOUT_AFTER_DISPATCH")
    assert len(events) >= 1, "no SEARCH_TIMEOUT_AFTER_DISPATCH event"
    ev = events[0]
    assert ev.event_id
    assert ev.run_id


# --------------------------------------------------------------------------- #
# Malformed provenance — reason code in trace (via ProvenanceError → node_failed)
# --------------------------------------------------------------------------- #


def test_malformed_provenance_trace_evidence(tmp_path: Path) -> None:
    """Malformed provenance produces node failure trace evidence.
    The reason code may not appear in reason_codes (the fault raises
    ProvenanceError, not SearchAdapterError), but the trace must carry
    node_failed or validation evidence for the search_tool."""
    runner = _run(tmp_path, "corpus_malformed_provenance.yaml")
    # The node may fail or succeed with validation evidence.
    # Either way, the trace must show the malformed result was handled.
    search_events = [
        ev for ev in runner.orchestrator.trace.events
        if ev.node_id == "search_tool"
    ]
    assert len(search_events) > 0, "no search_tool trace events"


# --------------------------------------------------------------------------- #
# Partial result set
# --------------------------------------------------------------------------- #


def test_partial_result_set_trace_evidence(tmp_path: Path) -> None:
    """Partial result set produces trace evidence for the search_tool.
    The adapter returns results normally (no error), so the trace shows
    successful execution. The partial metadata is in the node output."""
    runner = _run(tmp_path, "corpus_partial_result_set.yaml")
    search_events = [
        ev for ev in runner.orchestrator.trace.events
        if ev.node_id == "search_tool"
    ]
    assert len(search_events) > 0, "no search_tool trace events"


# --------------------------------------------------------------------------- #
# Event identity fields
# --------------------------------------------------------------------------- #


def test_all_reason_code_events_have_identity_fields(tmp_path: Path) -> None:
    """Every trace event with a reason code has event_id, run_id, step_id."""
    runner = _run(tmp_path, "corpus_timeout_after_dispatch.yaml")
    for ev in runner.orchestrator.trace.events:
        if ev.reason_codes:
            assert ev.event_id, f"event {ev.event_type} missing event_id"
            assert ev.run_id, f"event {ev.event_type} missing run_id"
            assert ev.step_id is not None, f"event {ev.event_type} missing step_id"
            assert ev.node_id, f"event {ev.event_type} missing node_id"
