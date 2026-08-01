"""v3.5.1 H1 — Fix #13: invocation completion semantics.

v3.5.0 defect: is_step_completed and get_completed_steps did NOT filter on
status='completed' (unlike their sibling is_node_completed, which did). A
failed, pending, running, or unknown invocation row was treated as
completed, suppressing legitimate resume/retry. save_with_invocation used
INSERT OR IGNORE with no compatibility check against an existing row's
node/status identity, so a conflicting duplicate was silently dropped.

v3.5.1 contract:

* is_step_completed / get_completed_steps filter status='completed'.
* A failed/pending/running/unknown row is NOT completed and does not
  suppress resume.
* Identical completed replay converges (idempotent).
* A conflicting (different node or different status) duplicate at the same
  (run_id, step_id) is detected as an integrity conflict, not silently
  ignored.

Written FIRST (RED).
"""

from __future__ import annotations

import sqlite3

import pytest

from nodechain.core.state import StateManager


@pytest.fixture()
def sm(tmp_path) -> StateManager:
    return StateManager(db_path=str(tmp_path / "inv.db"))


class TestStepCompletionFiltersStatus:
    """is_step_completed / get_completed_steps must require status='completed'."""

    def test_failed_row_is_not_completed(self, sm):
        sm.record_invocation("r1", 1, "node_a", status="failed")
        assert sm.is_step_completed("r1", 1) is False

    def test_pending_row_is_not_completed(self, sm):
        sm.record_invocation("r1", 1, "node_a", status="pending")
        assert sm.is_step_completed("r1", 1) is False

    def test_running_row_is_not_completed(self, sm):
        sm.record_invocation("r1", 1, "node_a", status="running")
        assert sm.is_step_completed("r1", 1) is False

    def test_unknown_row_is_not_completed(self, sm):
        sm.record_invocation("r1", 1, "node_a", status="unknown")
        assert sm.is_step_completed("r1", 1) is False

    def test_completed_row_is_completed(self, sm):
        sm.record_invocation("r1", 1, "node_a", status="completed")
        assert sm.is_step_completed("r1", 1) is True

    def test_get_completed_steps_excludes_non_completed(self, sm):
        sm.record_invocation("r1", 1, "node_a", status="completed")
        sm.record_invocation("r1", 2, "node_b", status="failed")
        sm.record_invocation("r1", 3, "node_c", status="pending")

        steps = sm.get_completed_steps("r1")
        assert steps == {1: "node_a"}, (
            f"get_completed_steps returned non-completed rows: {steps}"
        )

    def test_failed_invocation_does_not_suppress_resume(self, sm):
        """A failed invocation at step 1 must not block re-running step 1."""
        sm.record_invocation("r1", 1, "node_a", status="failed")
        # The orchestrator's resume gate calls is_step_completed; a failed
        # row must report False so the step re-runs.
        assert sm.is_step_completed("r1", 1) is False
        assert 1 not in sm.get_completed_steps("r1")


class TestDuplicateInvocationCompatibility:
    """save_with_invocation must not silently accept an incompatible duplicate."""

    def test_identical_completed_replay_converges(self, sm):
        """Re-inserting the same (run, step, node, completed) is idempotent."""
        from nodechain.core.state import ChainState
        state = ChainState(run_id="r1", chain_id="c")
        sm.save_with_invocation(state, step_id=1, node_id="node_a",
                                invocation_status="completed")
        # Replay identical — must not raise, must remain completed.
        state2 = ChainState(run_id="r1", chain_id="c")
        sm.save_with_invocation(state2, step_id=1, node_id="node_a",
                                invocation_status="completed")
        assert sm.is_step_completed("r1", 1) is True

    def test_conflicting_node_at_same_step_is_detected(self, sm):
        """A different node_id at the same (run, step) is an integrity conflict."""
        from nodechain.core.state import ChainState, SideEffectIntegrityError
        state = ChainState(run_id="r1", chain_id="c")
        sm.save_with_invocation(state, step_id=1, node_id="node_a",
                                invocation_status="completed")
        # A different node claiming the same step must NOT be silently ignored.
        state2 = ChainState(run_id="r1", chain_id="c")
        with pytest.raises(SideEffectIntegrityError):
            sm.save_with_invocation(state2, step_id=1, node_id="node_b",
                                    invocation_status="completed")

    def test_conflicting_status_at_same_step_is_detected(self, sm):
        """completed then failed at the same (run, step, node) is a conflict."""
        from nodechain.core.state import ChainState, SideEffectIntegrityError
        state = ChainState(run_id="r1", chain_id="c")
        sm.save_with_invocation(state, step_id=1, node_id="node_a",
                                invocation_status="completed")
        state2 = ChainState(run_id="r1", chain_id="c")
        with pytest.raises(SideEffectIntegrityError):
            sm.save_with_invocation(state2, step_id=1, node_id="node_a",
                                    invocation_status="failed")


class TestStandaloneRecordInvocationConflictDetection:
    """v3.5.1 (#13) B2: record_invocation (the standalone path) must detect
    conflicts too, not silently discard via INSERT OR IGNORE. The production
    invariant must not depend on which public write path the caller uses."""

    def test_conflicting_node_at_same_step_is_detected(self, sm):
        from nodechain.core.state import SideEffectIntegrityError
        sm.record_invocation("r1", 1, "node_a", status="completed")
        with pytest.raises(SideEffectIntegrityError):
            sm.record_invocation("r1", 1, "node_b", status="completed")

    def test_conflicting_status_at_same_step_is_detected(self, sm):
        from nodechain.core.state import SideEffectIntegrityError
        sm.record_invocation("r1", 1, "node_a", status="completed")
        with pytest.raises(SideEffectIntegrityError):
            sm.record_invocation("r1", 1, "node_a", status="failed")

    def test_identical_replay_converges(self, sm):
        """Identical replay is idempotent — no raise."""
        sm.record_invocation("r1", 1, "node_a", status="completed")
        sm.record_invocation("r1", 1, "node_a", status="completed")  # no raise
        assert sm.is_step_completed("r1", 1) is True


class TestRevisionNotAdvancedOnIntegrityError:
    """v3.5.1 (#13) B2: state.revision must not advance when save_with_invocation
    raises an integrity error — the transaction rolled back, so the in-memory
    state must reflect that."""

    def test_revision_unchanged_after_conflict(self, sm):
        from nodechain.core.state import ChainState, SideEffectIntegrityError
        state = ChainState(run_id="r1", chain_id="c")
        sm.save_with_invocation(state, step_id=1, node_id="node_a",
                                invocation_status="completed")
        rev_after_first = state.revision

        # This conflicting write must raise AND not advance the revision.
        state2 = ChainState(run_id="r1", chain_id="c")
        sm.save_with_invocation(state2, step_id=1, node_id="node_a")  # baseline
        rev_before_conflict = state2.revision
        state3 = ChainState(run_id="r1", chain_id="c")
        with pytest.raises(SideEffectIntegrityError):
            sm.save_with_invocation(state3, step_id=1, node_id="node_b",
                                    invocation_status="completed")
        # The failed-conflict ChainState must NOT have its revision advanced.
        assert state3.revision == 0, (
            f"revision advanced to {state3.revision} after a rolled-back "
            f"integrity error; the in-memory state must stay at 0"
        )

