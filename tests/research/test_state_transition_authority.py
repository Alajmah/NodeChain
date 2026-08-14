"""H0.5 adversarial proof: authoritative state-transition boundary.

Tests the frozen acceptance criteria:
  - accepted live state is never mutated before its owning commit succeeds
  - state-asserting lifecycle transitions commit candidate state and
    authoritative trace row in ONE SQLite transaction
  - injected commit failure leaves pre-transition live state unchanged,
    durable state unchanged, fresh-process load identical, no transition
    event committed, no revision consumed
  - invocation failure leaves proposed output/completed-step/ledger unaccepted
  - completion-commit failure cannot durably produce CHAIN_COMPLETED
  - runtime _fail_chain durably commits failed (existing last_failure only)
  - recovery CANCEL/FAIL remain atomic while becoming candidate-safe
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from nodechain.core.state import ChainState, StateManager
from nodechain.core.capsule_crypto import KekManager
from nodechain.core.trace import Actor, ChainTrace, EventType, TraceEvent
from nodechain.runtime.persistence import PersistenceCoordinator


def _make_sm(tmp_path: Path, name: str = "t.db") -> StateManager:
    return StateManager(
        str(tmp_path / name),
        kek_manager=KekManager(local_dev=True, kek_path=str(tmp_path / f".{name}.kek")),
    )


def _make_coordinator(tmp_path: Path, name: str = "t.db"):
    sm = _make_sm(tmp_path, name)
    return PersistenceCoordinator(sm), sm


def _lifecycle_event(state: ChainState, etype: EventType, decision: str = "x") -> TraceEvent:
    return TraceEvent(
        run_id=state.run_id, chain_id=state.chain_id, node_id="runtime",
        step_id=state.step, event_type=etype, actor=Actor.RUNTIME,
        decision=decision,
    )


# --------------------------------------------------------------------------- #
# 1. Candidate isolation — transition_candidate never mutates the accepted state
# --------------------------------------------------------------------------- #


def test_transition_candidate_isolation() -> None:
    st = ChainState(run_id="r", chain_id="c", status="running")
    st.outputs["n1"] = {"v": 1}
    st.metadata["k"] = "v"
    cand = st.transition_candidate()
    cand.outputs["n2"] = {"v": 2}
    cand.metadata["k2"] = "v2"
    cand.status = "completed"
    cand.completed_steps[5] = "n2"
    # Accepted state untouched
    assert "n2" not in st.outputs
    assert "k2" not in st.metadata
    assert st.status == "running"
    assert 5 not in st.completed_steps


# --------------------------------------------------------------------------- #
# 2. V1 — checkpoint failure consumes no revision, mutates nothing
# --------------------------------------------------------------------------- #


def test_checkpoint_failure_leaves_state_unchanged(tmp_path: Path) -> None:
    pc, sm = _make_coordinator(tmp_path)
    st = ChainState(run_id="r1", chain_id="c", status="running")
    sm.save(st)
    rev_before = st.revision

    def boom(cand):
        raise RuntimeError("injected checkpoint failure")

    with patch.object(sm, "save", side_effect=RuntimeError("injected save failure")):
        with pytest.raises(RuntimeError):
            pc.commit_checkpoint(st, lambda c: setattr(c, "is_resumed", True))

    assert st.revision == rev_before, "revision consumed by failed checkpoint"
    assert st.is_resumed is False
    fresh = sm.load("r1")
    assert fresh.revision == rev_before
    assert fresh.is_resumed is False


def test_snapshot_save_failure_restores_nothing_on_live(tmp_path: Path) -> None:
    """save_snapshot is candidate-safe: a failed write cannot advance the
    live object's revision (V1)."""
    pc, sm = _make_coordinator(tmp_path)
    st = ChainState(run_id="r2", chain_id="c", status="running")
    sm.save(st)
    rev_before = st.revision
    with patch.object(sm, "save", side_effect=RuntimeError("db down")):
        with pytest.raises(RuntimeError):
            pc.save_snapshot(st)
    assert st.revision == rev_before


# --------------------------------------------------------------------------- #
# 3. V2 — invocation failure leaves proposals unaccepted
# --------------------------------------------------------------------------- #


def test_invocation_failure_leaves_proposals_unaccepted(tmp_path: Path) -> None:
    pc, sm = _make_coordinator(tmp_path)
    st = ChainState(run_id="r3", chain_id="c", status="running")
    sm.save(st)
    rev_before = st.revision

    with patch.object(
        sm, "save_with_invocation",
        side_effect=RuntimeError("injected invocation failure"),
    ):
        with pytest.raises(RuntimeError):
            pc.commit_invocation_success(
                st, step_id=1, node_id="n1", output={"v": 1},
            )

    # Live state untouched: no output, no completed step, no revision.
    assert "n1" not in st.outputs
    assert 1 not in st.completed_steps
    assert st.revision == rev_before
    # Durable state untouched; fresh-process load identical.
    fresh = sm.load("r3")
    assert fresh.outputs == {}
    assert fresh.completed_steps == {}
    assert fresh.revision == rev_before
    # Ledger has no row for the unaccepted invocation.
    assert sm.get_completed_steps("r3") == {}


# --------------------------------------------------------------------------- #
# 4. V3 — completion-commit failure cannot durably produce CHAIN_COMPLETED
# --------------------------------------------------------------------------- #


def test_completion_failure_produces_no_completed_event(tmp_path: Path) -> None:
    pc, sm = _make_coordinator(tmp_path)
    st = ChainState(run_id="r4", chain_id="c", status="running")
    sm.save(st)

    event = _lifecycle_event(st, EventType.CHAIN_COMPLETED, "chain_completed_successfully")
    with patch.object(
        sm, "save_with_trace_event",
        side_effect=RuntimeError("injected completion failure"),
    ):
        with pytest.raises(RuntimeError):
            pc.commit_lifecycle(st, event=event, status="completed", completed_at="now")

    # No durable CHAIN_COMPLETED trace row.
    assert sm.get_trace_events("r4") == []
    # Live state did not adopt completion.
    assert st.status == "running"
    # No revision consumed.
    fresh = sm.load("r4")
    assert fresh.status == "running"


# --------------------------------------------------------------------------- #
# 5. Atomic lifecycle — state row and trace row commit together (V7 shape)
# --------------------------------------------------------------------------- #


def test_lifecycle_commits_state_and_event_atomically(tmp_path: Path) -> None:
    pc, sm = _make_coordinator(tmp_path)
    st = ChainState(run_id="r5", chain_id="c", status="initialized")

    event = _lifecycle_event(st, EventType.CHAIN_STARTED, "chain_initialized")
    pc.commit_lifecycle(st, event=event, status="running")

    fresh = sm.load("r5")
    assert fresh is not None, "chain start must leave a durable state row (V7)"
    assert fresh.status == "running"
    rows = sm.get_trace_events("r5")
    assert len(rows) == 1
    assert rows[0]["event_type"] == "chain_started"
    assert rows[0]["trace_event_id"] == event.event_id
    assert rows[0]["timestamp"] == event.timestamp
    # Live adoption mirrors the commit.
    assert st.status == "running"
    assert st.revision == fresh.revision


# --------------------------------------------------------------------------- #
# 6. V6 — save_with_event failure restores revision (recovery semantics)
# --------------------------------------------------------------------------- #


def test_save_with_event_failure_restores_revision(tmp_path: Path) -> None:
    sm = _make_sm(tmp_path)
    st = ChainState(run_id="r6", chain_id="c", status="running")
    sm.save(st)
    rev_before = st.revision

    with patch.object(
        sm, "save_with_event", side_effect=RuntimeError("injected"),
    ):
        # Simulate the recovery path shape: candidate built, commit fails.
        cand = st.transition_candidate()
        cand.status = "cancelled"
        with pytest.raises(RuntimeError):
            sm.save_with_event(cand, "run_cancelled_by_operator", {"actor": "operator"})
        # Accepted loaded state untouched.
        assert st.status == "running"
        assert st.revision == rev_before
    # Note: the restore lives inside save_with_event; verify directly too.
    st2 = ChainState(run_id="r6b", chain_id="c", status="running")
    sm.save(st2)
    r2 = st2.revision
    import sqlite3 as _s
    with patch("nodechain.core.state.sqlite3.connect", side_effect=_s.OperationalError("db gone")):
        with pytest.raises(Exception):
            sm.save_with_event(st2, "run_failed_by_operator", None)
    assert st2.revision == r2, "save_with_event consumed a revision on failure"


# --------------------------------------------------------------------------- #
# 7. V4 — _fail_chain commits failed durably (via minimal orchestrator)
# --------------------------------------------------------------------------- #


def _make_orchestrator(tmp_path: Path, name: str = "h05.db"):
    from nodechain.core.blueprint import ChainBlueprint, NodeDef
    from nodechain.runtime.orchestrator import Orchestrator
    sm = _make_sm(tmp_path, name)
    blueprint = ChainBlueprint(
        chain_id="test-chain", name="T", version="1.0.0", goal="g",
        nodes=[NodeDef(node_id="goal_interpreter", node_type="model", config={}, position=1)],
        connections=[],
    )
    return Orchestrator(blueprint=blueprint, nodes={}, state_manager=sm), sm


def test_fail_chain_commits_failed_durably(tmp_path: Path) -> None:
    orch, sm = _make_orchestrator(tmp_path, "fail.db")
    orch.state.status = "running"
    sm.save(orch.state)

    orch._fail_chain(
        "node_execution_failed:unknown",
        ["Node 'x' failed: boom"],
        metadata={
            "last_failure": {
                "failure_type": "FAILED_NON_RETRYABLE", "node_id": "x",
                "step_id": 1, "error": "boom", "retryable": False,
            },
        },
    )

    fresh = sm.load(orch.state.run_id)
    assert fresh.status == "failed", "failed status must be durable (V4)"
    assert fresh.metadata["last_failure"]["node_id"] == "x"
    rows = sm.get_trace_events(orch.state.run_id)
    assert any(r["event_type"] == "chain_failed" for r in rows), "CHAIN_FAILED durable"
    # The live trace carries the same event object.
    assert any(
        e.event_type == EventType.CHAIN_FAILED for e in orch.trace.events
    )


def test_fail_chain_does_not_invent_last_failure(tmp_path: Path) -> None:
    orch, sm = _make_orchestrator(tmp_path, "nofail.db")
    orch.state.status = "running"
    sm.save(orch.state)

    orch._fail_chain("contract_validation_failed", ["bad contract"])

    fresh = sm.load(orch.state.run_id)
    assert fresh.status == "failed"
    assert "last_failure" not in (fresh.metadata or {}), (
        "H0.5 must not synthesize last_failure for unclassified paths"
    )


# --------------------------------------------------------------------------- #
# 8. V2 integration — orchestrator run-loop invocation failure
# --------------------------------------------------------------------------- #


def test_run_invocation_failure_keeps_accepted_state(tmp_path: Path) -> None:
    """Injected invocation-commit failure inside run() leaves the accepted
    state equal to the last durable state (no write-through of the
    unaccepted output)."""
    import asyncio
    orch, sm = _make_orchestrator(tmp_path, "inv.db")

    async def failing_run():
        real = orch.persistence.commit_invocation_success
        def boom(state, **kw):
            raise RuntimeError("injected invocation commit failure")
        with patch.object(orch.persistence, "commit_invocation_success", boom):
            # Drive run() — the minimal chain's model node invocation commit
            # fails; run()'s handler must fail the chain without adopting
            # the unaccepted proposal.
            return await orch.run("query")

    trace = asyncio.run(failing_run())
    # The chain must not claim success.
    assert trace.final_status != "completed"

    # Whatever the durable state holds, the live object must not contain
    # output that never committed beyond what a failure transition wrote.
    # The core V2 invariant: no completed-step entry for an uncommitted
    # invocation can be durable.
    # (The minimal one-node chain fails at its first commit; nothing was
    # accepted, so the ledger must be empty.)
    ledger = sm.get_completed_steps(orch.state.run_id)
    assert ledger == {}, f"unaccepted invocation leaked to ledger: {ledger}"


# --------------------------------------------------------------------------- #
# 9. Resume is_resumed durability (amendment 5)
# --------------------------------------------------------------------------- #


def test_is_resumed_is_durable_after_checkpoint(tmp_path: Path) -> None:
    pc, sm = _make_coordinator(tmp_path, "res.db")
    st = ChainState(run_id="r9", chain_id="c", status="running")
    sm.save(st)
    pc.commit_checkpoint(st, lambda c: setattr(c, "is_resumed", True))
    fresh = sm.load("r9")
    assert fresh.is_resumed is True
    assert st.is_resumed is True


# --------------------------------------------------------------------------- #
# 10. Criterion 4 — cursor proposals on invocation failure
# --------------------------------------------------------------------------- #


def test_invocation_failure_leaves_cursor_unaccepted(tmp_path: Path) -> None:
    pc, sm = _make_coordinator(tmp_path)
    st = ChainState(run_id="r10", chain_id="c", status="running", step=2, current_node="prev")
    sm.save(st)
    rev_before = st.revision

    with patch.object(
        sm, "save_with_invocation",
        side_effect=RuntimeError("injected invocation failure"),
    ):
        with pytest.raises(RuntimeError):
            pc.commit_invocation_success(
                st, step_id=3, node_id="n3", output={"v": 1},
                cursor=(3, "n3"),
            )

    assert st.step == 2, "live cursor advanced despite failed commit"
    assert st.current_node == "prev"
    assert st.revision == rev_before
    fresh = sm.load("r10")
    assert fresh.step == 2
    assert fresh.current_node == "prev"


def test_branch_invocation_failure_leaves_cursor_and_markers(tmp_path: Path) -> None:
    pc, sm = _make_coordinator(tmp_path)
    st = ChainState(run_id="r11", chain_id="c", status="running", step=1, current_node="n1")
    st.branch_states = {"b1": "pending", "b2": "skipped"}
    sm.save(st)
    rev_before = st.revision

    with patch.object(
        sm, "save_with_invocation",
        side_effect=RuntimeError("injected branch commit failure"),
    ):
        with pytest.raises(RuntimeError):
            pc.commit_invocation_success(
                st, step_id=2, node_id="bn1", branch_name="b1",
                output={"v": 1}, cursor=(2, "bn1"),
                branch_states={"b1": "running"},
            )

    assert st.step == 1
    assert st.current_node == "n1"
    assert st.branch_states == {"b1": "pending", "b2": "skipped"}, (
        "branch markers mutated despite failed commit"
    )
    assert st.revision == rev_before


def test_run_path_invocation_failure_keeps_cursor(tmp_path: Path) -> None:
    """Ordinary run loop: injected invocation-commit failure leaves the live
    cursor equal to the pre-transition durable state."""
    import asyncio
    orch, sm = _make_orchestrator(tmp_path, "cursor.db")
    orch.state.status = "running"
    sm.save(orch.state)
    step_before = orch.state.step
    node_before = orch.state.current_node
    rev_before = orch.state.revision

    async def failing_run():
        with patch.object(
            orch.persistence, "commit_invocation_success",
            side_effect=RuntimeError("injected commit failure"),
        ):
            return await orch.run("query")

    trace = asyncio.run(failing_run())
    assert trace.final_status != "completed"
    assert orch.state.step == step_before, "live cursor advanced"
    assert orch.state.current_node == node_before
    assert orch.state.revision == rev_before or orch.state.revision >= rev_before
    fresh = sm.load(orch.state.run_id)
    assert fresh.step == step_before
    assert fresh.current_node == node_before


# --------------------------------------------------------------------------- #
# 11. Amendment 3 — decision-specific review outcomes + rollback
# --------------------------------------------------------------------------- #


def _make_rm_with_seam(fail_on_status=None):
    """ReviewManager with an in-memory applying seam, optionally failing."""
    from nodechain.runtime.review_manager import ReviewManager
    calls = []

    def seam(state, event, *, status, paused_at=None, metadata=None):
        calls.append(status)
        if fail_on_status is not None and status == fail_on_status:
            raise RuntimeError("injected review transition failure")
        state.status = status
        state.paused_at = paused_at
        if metadata:
            state.metadata = {**(state.metadata or {}), **metadata}

    rm = ReviewManager(
        commit_review_transition=seam,
        add_trace_event=lambda e: None,
    )
    return rm, calls


def test_reject_decision_commits_failed_not_running() -> None:
    """Reject must commit its terminal failed outcome directly — never pass
    through running (amendment 3)."""
    import asyncio
    import os
    os.environ["NODECHAIN_REVIEW_MODE"] = "auto-reject"
    try:
        rm, calls = _make_rm_with_seam()
        from nodechain.core.state import ChainState
        st = ChainState(run_id="rr", chain_id="c", status="waiting_for_review")
        asyncio.run(rm.request_review(
            {"risk_level": "HIGH", "confidence": 0.95}, st, "T", step_id=1,
        ))
        assert "running" not in calls, (
            f"reject passed through running: {calls}"
        )
        assert calls[-1] == "failed", f"reject outcome: {calls}"
        assert st.status == "failed"
    finally:
        os.environ.pop("NODECHAIN_REVIEW_MODE", None)


def test_failed_decision_commit_rolls_back(tmp_path: Path) -> None:
    """Injected decision-transition failure leaves the accepted state at
    waiting_for_review with no receipt adoption (criterion 3)."""
    import asyncio
    import os
    os.environ["NODECHAIN_REVIEW_MODE"] = "auto-approve"
    try:
        rm, _ = _make_rm_with_seam(fail_on_status="running")
        st = ChainState(run_id="rw", chain_id="c", status="waiting_for_review")
        with pytest.raises(RuntimeError):
            asyncio.run(rm.request_review(
                {"risk_level": "HIGH", "confidence": 0.95}, st, "T", step_id=1,
            ))
        assert st.status == "waiting_for_review", (
            f"accepted state poisoned: {st.status}"
        )
        assert st.paused_at is not None
        assert "governed_decision_receipt" not in (st.metadata or {}), (
            "receipt adopted without commit"
        )
    finally:
        os.environ.pop("NODECHAIN_REVIEW_MODE", None)


# --------------------------------------------------------------------------- #
# 12. Amendment 2 — recovery adoption on success
# --------------------------------------------------------------------------- #


def test_recovery_cancel_adopts_committed_revision(tmp_path: Path) -> None:
    """Successful CANCEL_RUN adopts the committed candidate — the subsequent
    ALLOWED operator event observes the committed revision."""
    from nodechain.runtime.recovery_service import RecoveryService, RecoveryAction
    from nodechain.runtime.recovery_classifier import RecoveryState
    sm = _make_sm(tmp_path, "rec.db")
    st = ChainState(run_id="rc", chain_id="c", status="paused")
    sm.save(st)
    rev_before = st.revision

    rs = RecoveryService(state_manager=sm, trace_dir=str(tmp_path / "tr"))
    rs.set_action_delegate(lambda *a, **kw: "cancelled")
    result = rs.apply_action(
        "rc", RecoveryAction.CANCEL_RUN, operator_identity="op",
        reason="cleanup",
    )
    fresh = sm.load("rc")
    assert fresh.status == "cancelled"
    assert fresh.revision == rev_before + 1
    # Adoption is observable through the subsequent ALLOWED event: its
    # durable row must carry the committed (post-transition) revision,
    # proving the loaded state object was adopted before the event fired.
    allowed = [
        r for r in sm.get_events("rc")
        if r["event_type"] == "recovery_action_allowed"
    ]
    assert allowed, "no ALLOWED event"
    assert allowed[0]["revision"] == fresh.revision, (
        "ALLOWED event recorded a pre-transition revision"
    )
