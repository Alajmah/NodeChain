"""Step 7 frozen chronology proof: failure → scheduled → recovered ordering.

Asserts exact event ordering and identity correlation for the provenance
retry path through the real orchestrator.
"""

from __future__ import annotations

from pathlib import Path

from nodechain.research.runner import ResearchBrief, WorkspaceRunner

FIXTURES = Path(__file__).parent.parent.parent / "tests" / "fixtures" / "research"


def test_provenance_retry_chronology(tmp_path: Path) -> None:
    """Provenance fault produces truthful failure → scheduled → recovered
    chronology with shared original_failure_event_id and non-empty digest."""
    runner = WorkspaceRunner(
        brief=ResearchBrief.from_question("test query"),
        corpus_path=str(FIXTURES / "corpus_malformed_provenance.yaml"),
        workspace_dir=str(tmp_path / "chrono"),
    )
    result = runner.run()
    events = result.trace.events

    # Find fault, scheduled, and recovered events.
    fault_idx = sched_idx = recov_idx = -1
    fault_event_id = sched_orig = recov_orig = None
    sched_digest = None

    for i, ev in enumerate(events):
        if ev.node_id != "search_tool":
            continue
        codes = " ".join(ev.reason_codes)
        meta = getattr(ev, "metadata", {}) or {}

        if "SEARCH_PROVENANCE_MALFORMED" in codes and "node_failed" in ev.event_type.value.lower():
            fault_idx = i
            fault_event_id = ev.event_id
        elif "SEARCH_RETRY_SCHEDULED" in codes:
            sched_idx = i
            sched_orig = meta.get("original_failure_event_id")
            sched_digest = meta.get("operation_digest", "")
        elif "SEARCH_RETRY_RECOVERED" in codes:
            recov_idx = i
            recov_orig = meta.get("original_failure_event_id")

    # All three events exist.
    assert fault_idx >= 0, "no fault event"
    assert sched_idx >= 0, "no SEARCH_RETRY_SCHEDULED event"
    assert recov_idx >= 0, "no SEARCH_RETRY_RECOVERED event"

    # Correct chronological ordering.
    assert fault_idx < sched_idx, f"fault({fault_idx}) must precede scheduled({sched_idx})"
    assert sched_idx < recov_idx, f"scheduled({sched_idx}) must precede recovered({recov_idx})"

    # Shared original_failure_event_id.
    assert sched_orig == fault_event_id, (
        f"scheduled.original_failure_event_id ({sched_orig}) != fault event_id ({fault_event_id})"
    )
    assert recov_orig == fault_event_id, (
        f"recovered.original_failure_event_id ({recov_orig}) != fault event_id ({fault_event_id})"
    )

    # Non-empty operation digest on the scheduling event.
    assert sched_digest, f"scheduled event has empty operation_digest"
