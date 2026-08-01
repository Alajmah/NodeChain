"""Tests for `nodechain recover` CLI action commands (v2.46.0 Phase 4.2).

The action commands (resume/retry/approve/reject/revise/cancel/fail/report) are
thin wrappers over RecoveryService.apply_action. They install an orchestrator
delegate, submit the action, render the result + audit trail, and return exit
codes. These tests stub the orchestrator builder so they run without a live
model adapter / Chroma.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nodechain.cli.main import cli
from nodechain.core.state import ChainState, StateManager


@pytest.fixture()
def store(tmp_path):
    sm = StateManager(db_path=tmp_path / "state.db")
    trace_dir = tmp_path / "traces"
    trace_dir.mkdir()
    return sm, str(tmp_path / "state.db"), str(trace_dir)


def _seed(sm: StateManager, run_id: str, **kw) -> None:
    sm.save(ChainState(run_id=run_id, chain_id="c", **kw))


def _seed_trace(trace_dir: str, run_id: str, status: str = "running") -> None:
    Path(trace_dir, f"{run_id}.json").write_text(json.dumps({
        "chain_id": "c", "run_id": run_id, "status": status,
        "started_at": "2026-06-27T00:00:00+00:00", "events": [],
    }))


# --- cancel/fail (no orchestrator needed) ------------------------------------

def test_recover_cancel_sets_cancelled(store, monkeypatch) -> None:
    sm, db, trace_dir = store
    _seed(sm, "r1", status="running")

    result = CliRunner().invoke(cli, [
        "recover", "cancel", "r1", "--reason", "abort",
        "--db", db, "--trace-dir", trace_dir,
        "--operator", "alice",
    ])

    assert result.exit_code == 0, result.output
    assert sm.load("r1").status == "cancelled"
    assert "cancelled" in result.output.lower()


def test_recover_fail_sets_failed(store) -> None:
    sm, db, trace_dir = store
    _seed(sm, "r1", status="waiting_for_review")

    result = CliRunner().invoke(cli, [
        "recover", "fail", "r1", "--reason", "unrecoverable",
        "--db", db, "--trace-dir", trace_dir,
    ])

    assert result.exit_code == 0, result.output
    assert sm.load("r1").status == "failed"


def test_recover_cancel_blocked_for_terminal(store) -> None:
    """A completed run cannot be cancelled — policy refuses, exit code reflects it."""
    sm, db, trace_dir = store
    _seed(sm, "r1", status="completed")
    _seed_trace(trace_dir, "r1", status="completed")

    result = CliRunner().invoke(cli, [
        "recover", "cancel", "r1", "--db", db, "--trace-dir", trace_dir,
    ])
    assert result.exit_code != 0  # blocked
    assert "blocked" in result.output.lower() or "terminal" in result.output.lower()


# --- report -----------------------------------------------------------------

def test_recover_report_exports_json(store) -> None:
    sm, db, trace_dir = store
    _seed(sm, "r1", status="running")
    _seed_trace(trace_dir, "r1")
    import tempfile
    out = str(Path(tempfile.mkdtemp()) / "report.json")

    result = CliRunner().invoke(cli, [
        "recover", "report", "r1", "--output", out,
        "--db", db, "--trace-dir", trace_dir,
    ])
    assert result.exit_code == 0, result.output
    data = json.loads(Path(out).read_text())
    assert data["run_id"] == "r1"
    assert "recovery_state" in data


# --- resume/approve with a stubbed orchestrator delegate ---------------------

def test_recover_resume_with_orchestrator_stub(store, monkeypatch) -> None:
    """resume routes through the orchestrator delegate. We stub the builder so
    the test needs no live model/Chroma; the stub returns a completed trace."""
    sm, db, trace_dir = store
    _seed(sm, "r1", status="paused")

    def fake_builder(db_path, blueprint, trace_dir):
        def delegate(action, run_id, **kw):
            # Simulate orchestrator.resume completing the run.
            st = sm.load(run_id)
            st.status = "completed"
            sm.save(st)
            return "completed"
        return delegate
    monkeypatch.setattr("nodechain.cli.recover._build_orchestrator_delegate", fake_builder)

    result = CliRunner().invoke(cli, [
        "recover", "resume", "r1", "--db", db, "--trace-dir", trace_dir,
    ])
    assert result.exit_code == 0, result.output
    assert sm.load("r1").status == "completed"
    assert "resumed" in result.output.lower() or "completed" in result.output.lower()


def test_recover_approve_routes_to_delegate(store, monkeypatch) -> None:
    """approve_review sets review_decision (inside the delegate, after admission)
    and delegates to orchestrator.resume, which runs resolve_resume_review."""
    sm, db, trace_dir = store
    _seed(sm, "r1", status="waiting_for_review",
          metadata={"governed_review_request": {"request_id": "req-1", "step_id": 2}})

    seen = {}

    def fake_builder(db_path, blueprint, trace_dir):
        def delegate(action, run_id, **kw):
            # Simulate the real delegate staging review_decision post-admission.
            st = sm.load(run_id)
            md = dict(st.metadata or {})
            md["review_decision"] = "approve"
            st.metadata = md
            sm.save(st)
            seen["review_decision"] = st.metadata.get("review_decision")
            st.status = "completed"
            sm.save(st)
            return "completed"
        return delegate
    monkeypatch.setattr("nodechain.cli.recover._build_orchestrator_delegate", fake_builder)

    result = CliRunner().invoke(cli, [
        "recover", "approve", "r1", "--decision", "approve",
        "--db", db, "--trace-dir", trace_dir,
    ])
    assert result.exit_code == 0, result.output
    # The delegate set review_decision into state metadata (after admission).
    assert seen["review_decision"] == "approve"


# --- reject terminates -------------------------------------------------------

def test_recover_reject_terminates(store, monkeypatch) -> None:
    sm, db, trace_dir = store
    _seed(sm, "r1", status="waiting_for_review",
          metadata={"governed_review_request": {"request_id": "req-1", "step_id": 2}})

    def fake_builder(db_path, blueprint, trace_dir):
        def delegate(action, run_id, **kw):
            # Orchestrator.resolve_resume_review persists rejected_by_reviewer.
            st = sm.load(run_id)
            st.status = "failed"
            sm.save(st)
            return "failed"
        return delegate
    monkeypatch.setattr("nodechain.cli.recover._build_orchestrator_delegate", fake_builder)

    result = CliRunner().invoke(cli, [
        "recover", "approve", "r1", "--decision", "reject",
        "--db", db, "--trace-dir", trace_dir,
    ])
    assert result.exit_code == 0, result.output
    assert sm.load("r1").status == "failed"


# --- retry with step precision -----------------------------------------------

def test_recover_retry_passes_step_id(store, monkeypatch) -> None:
    sm, db, trace_dir = store
    _seed(sm, "r1", status="failed",
          metadata={"last_failure": {"retryable": True, "step_id": 4}})

    received = {}

    def fake_builder(db_path, blueprint, trace_dir):
        def delegate(action, run_id, **kw):
            received.update(kw)
            st = sm.load(run_id)
            st.status = "running"
            sm.save(st)
            return "running"
        return delegate
    monkeypatch.setattr("nodechain.cli.recover._build_orchestrator_delegate", fake_builder)

    result = CliRunner().invoke(cli, [
        "recover", "retry", "r1", "--step", "4",
        "--db", db, "--trace-dir", trace_dir,
    ])
    assert result.exit_code == 0, result.output
    assert received["target_step_id"] == 4


# ── Phase 4 rework: boundary/truth fixes (#1, #2, #3) ──────────────────────────

def test_rework1_orchestrator_uses_selected_db_path(store, monkeypatch) -> None:
    """#1: recover resume --db custom.db must run the orchestrator against
    custom.db, not the default StateManager(). We call the real builder and
    assert the Orchestrator it constructs receives a state_manager whose
    db_path matches --db."""
    sm, db, trace_dir = store
    _seed(sm, "r1", status="paused")
    captured = {}

    import nodechain.runtime.orchestrator as orch_mod
    orig_init = orch_mod.Orchestrator.__init__

    def spy_init(self, *a, **kw):
        captured.update(kw)
        # Don't actually construct; stub a no-op resume.
        self.resume = lambda run_id: None
    monkeypatch.setattr(orch_mod.Orchestrator, "__init__", spy_init)

    import nodechain.cli.recover as rec
    delegate = rec._build_orchestrator_delegate(db, "blueprints/research_decision_v1.yaml", trace_dir)
    delegate.__wrapped__ if hasattr(delegate, "__wrapped__") else None
    # The orchestrator was constructed during builder; check the state_manager.
    sm_arg = captured.get("state_manager")
    assert sm_arg is not None, "Orchestrator must be constructed with state_manager"
    # Compare resolved paths (StateManager stores a pathlib.Path; db is a str).
    import pathlib
    assert pathlib.Path(str(sm_arg.db_path)) == pathlib.Path(db), \
        "state_manager must use the --db path"


def test_rework2_refused_review_does_not_mutate_metadata(store, monkeypatch) -> None:
    """#2: a refused approve must NOT persist review_decision. The policy gate
    (apply_action) must run before any state mutation. We force a refusal by
    marking the review already-decided, then assert metadata is untouched."""
    sm, db, trace_dir = store
    _seed(sm, "r1", status="waiting_for_review",
          metadata={
              "governed_review_request": {"request_id": "req-1", "step_id": 2},
              "governed_decision_receipt": {"receipt_id": "rc-1", "decision": "approve"},
          })
    invoked = []

    def fake_builder(db_path, blueprint, trace_dir):
        def delegate(action, run_id, **kw):
            invoked.append(action)  # should NOT be called — policy refuses first
            return "completed"
        return delegate
    monkeypatch.setattr("nodechain.cli.recover._build_orchestrator_delegate", fake_builder)

    CliRunner().invoke(cli, [
        "recover", "approve", "r1", "--decision", "approve",
        "--db", db, "--trace-dir", trace_dir,
    ])

    assert invoked == []  # delegate never ran (policy refused)
    md = sm.load("r1").metadata
    # review_decision must NOT have been written by the refused action.
    assert "review_decision" not in md


def test_rework3_retry_mismatched_step_refused(store, monkeypatch) -> None:
    """#3: recover retry --step 999 for a run whose failed step is 4 must be
    refused. target_step_id must match the durable failed step, not just be
    present."""
    sm, db, trace_dir = store
    _seed(sm, "r1", status="failed",
          metadata={"last_failure": {"retryable": True, "step_id": 4}})
    invoked = []

    def fake_builder(db_path, blueprint, trace_dir):
        def delegate(action, run_id, **kw):
            invoked.append(kw.get("target_step_id"))
            return "running"
        return delegate
    monkeypatch.setattr("nodechain.cli.recover._build_orchestrator_delegate", fake_builder)

    result = CliRunner().invoke(cli, [
        "recover", "retry", "r1", "--step", "999",  # wrong step
        "--db", db, "--trace-dir", trace_dir,
    ])
    assert result.exit_code != 0  # refused
    assert invoked == []  # delegate never ran


def test_rework3_retry_matching_step_admitted(store, monkeypatch) -> None:
    """#3 mirror: --step matching the failed step IS admitted."""
    sm, db, trace_dir = store
    _seed(sm, "r1", status="failed",
          metadata={"last_failure": {"retryable": True, "step_id": 4}})

    def fake_builder(db_path, blueprint, trace_dir):
        def delegate(action, run_id, **kw):
            st = sm.load(run_id); st.status = "running"; sm.save(st)
            return "running"
        return delegate
    monkeypatch.setattr("nodechain.cli.recover._build_orchestrator_delegate", fake_builder)

    result = CliRunner().invoke(cli, [
        "recover", "retry", "r1", "--step", "4",  # correct step
        "--db", db, "--trace-dir", trace_dir,
    ])
    assert result.exit_code == 0, result.output
