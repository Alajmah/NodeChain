#!/usr/bin/env python
"""Generate the H1.5 controlled governance scenario pack.

Creates, inside a facilitator-chosen workspace, the two fixed study
scenarios through EXISTING NodeChain authorities only (no manual database
edits, no invented evidence):

  1. Review scenario — a genuine runtime review-required run over the
     conflicting-evidence sealed corpus. The run pauses at the risk review
     gate with admitted-decision authority pending.

  2. Fault/recovery scenario — a genuine timeout-after-dispatch fault over
     the sealed timeout corpus. Dispatch really occurred; the side-effect
     ledger holds a non-completed ('started') row; the recovery handoff
     surfaces the governed next actions.

Both runs deliberately stay PAUSED — the participant must encounter a
waiting decision and a real recovery state, not their resolutions.

Usage:
    python generate_scenario_pack.py <study-workspace> <participant-id>

Prints the run IDs and the facilitator answer key (do not show the key to
the participant during the scored portion).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT / "src"))

FIXTURES = REPO_ROOT / "tests" / "fixtures" / "research"
REVIEW_CORPUS = FIXTURES / "corpus_conflicting_evidence.yaml"
FAULT_CORPUS = FIXTURES / "corpus_timeout_after_dispatch.yaml"

EXPECTED_SHA = "5d54190c87136ff217b0d2f4899d6a04ea1b486a"


def _git_sha() -> str:
    import subprocess
    return subprocess.run(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    workspace = Path(sys.argv[1]).resolve()
    participant = sys.argv[2]
    workspace.mkdir(parents=True, exist_ok=True)

    sha = _git_sha()
    if sha != EXPECTED_SHA:
        print(
            f"REFUSING: product SHA {sha[:12]} is not the frozen study "
            f"baseline {EXPECTED_SHA[:12]}. Check out the study baseline "
            f"before generating scenarios."
        )
        return 1

    from nodechain.research.runner import WorkspaceRunner
    from nodechain.research.run_descriptor import (
        list_fault_records, load_descriptor,
    )
    from nodechain.research.workspace import open_workspace

    print(f"Generating H1.5 scenario pack for {participant} in {workspace}")

    # Scenario 1 — genuine review-required run.
    review_runner = WorkspaceRunner(
        "Is the evidence about conflicting safety findings consistent?",
        corpus_path=REVIEW_CORPUS, workspace_dir=workspace,
    )
    review_result = review_runner.run()
    review_state_ok = review_result.paused and (
        review_result.state.status in ("waiting_for_review", "paused"))

    # Scenario 2 — genuine timeout-after-dispatch fault with recovery state.
    fault_runner = WorkspaceRunner(
        "Does the search operation time out after dispatch?",
        corpus_path=FAULT_CORPUS, workspace_dir=workspace,
    )
    fault_result = fault_runner.run()
    faults = list_fault_records(workspace, fault_result.run_id)
    snap = open_workspace(str(workspace), run_id=fault_result.run_id)
    actionable = [
        se for se in snap.recovery.side_effects
        if se.get("status") in ("unknown", "started", "retry_authorized")
    ]
    fault_ok = (
        any(f.get("failure_type") == "timeout_after_dispatch" for f in faults)
        and any(f.get("dispatch_attempted") is True for f in faults)
        and bool(actionable)
    )

    manifest = {
        "participant_id": participant,
        "product_sha": sha,
        "review_run_id": review_result.run_id,
        "review_state": review_result.state.status,
        "fault_run_id": fault_result.run_id,
        "fault_types": [f.get("failure_type") for f in faults],
        "actionable_side_effects": len(actionable),
    }
    (workspace / f"scenario-pack-{participant}.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8")

    print(json.dumps(manifest, indent=2))
    print("\n--- FACILITATOR ANSWER KEY (do not reveal during scoring) ---")
    print(f"""
Review scenario ({review_result.run_id}):
  WHY intervention: risk classifier demanded human review over genuinely
    conflicting evidence; the run is {review_result.state.status}.
  Authority: the operator, via 'nodechain research review <run-id>
    --decision approve|reject|revise --reason ... --reviewer ...'.
  Outcome: approve -> run resumes to a terminal bundle; reject -> failed
    terminal bundle; revise -> revision loop.
Fault/recovery scenario ({fault_result.run_id}):
  Fault: timeout_after_dispatch; dispatch OCCURRED (the side effect was
    started on the wire and never completed).
  Evidence: fault record + side-effect ledger row status 'started'.
  Governed next actions (printed by 'nodechain research inspect'):
    nodechain recover inspect {fault_result.run_id} --db "<workspace run.db>"
    nodechain recover list-unknown {fault_result.run_id} --db "<workspace run.db>"
  Unknown to the system: whether the external service acted before the
    timeout — that is exactly what reconciliation must determine.
Verification: both scenarios must report ok above; the pack manifest is
  written next to the workspace for provenance.
""")
    if not (review_state_ok and fault_ok):
        print("SCENARIO PACK INVALID — do not use for scored sessions.")
        return 1
    print("Scenario pack OK.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
