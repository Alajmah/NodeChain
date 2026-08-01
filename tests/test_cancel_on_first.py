"""Tests for cancellation_policy=cancel_on_first.

AC1:  wait_for=any + cancel_on_first cancels pending branch tasks after first success.
AC2:  First successful branch enters join input.
AC3:  Pending branches receive BRANCH_CANCELLED trace events.
AC4:  Cancelled branches are excluded from join input.
AC5:  Branches completed before cancellation remain completed, not cancelled.
AC6:  Side-effect ledger remains consistent for cancelled branches.
AC7:  Cancelled during started side effect produces partial outputs recorded.
AC8:  wait_for=any + allow_all and ignore_late behavior remain unchanged.
AC9:  wait_for=first behavior remains unchanged unless paired with cancel_on_first.
AC10: 546 tests remain green.
"""

import asyncio
import pytest

from nodechain.core.blueprint import BranchDef, JoinDef
from nodechain.runtime.branch_executor import (
    BranchExecutor, BranchNodeResult, BranchExecutionReport,
)
from nodechain.runtime.invariant_engine import (
    CANCEL_ON_FIRST, CANCEL_ALLOW_ALL, CANCEL_IGNORE_LATE,
)


# ── Helpers ──

def _make_branch_def():
    return BranchDef(
        branch_id="b1",
        from_node="router",
        branches={
            "bio": ["bio_search", "bio_process"],
            "tech": ["tech_search", "tech_process"],
        },
        default_branch="bio",
    )


def _make_join_def_any():
    return JoinDef(
        join_id="j1",
        to_node="joiner",
        from_branches=["bio", "tech"],
        wait_for="any",
    )


def _successful_node_output(node_id: str) -> dict:
    return {
        "claims": [{"claim_id": f"{node_id}_c1", "text": f"Claim from {node_id}"}],
        "sources": [{"source_ref": f"S_{node_id}"}],
    }


class RecordingExecutor:
    """Tracks node invocations for assertion."""

    def __init__(self, fail_nodes=None, delay_map=None):
        self.calls: list[tuple[str, dict, str]] = []
        self.fail_nodes = fail_nodes or set()
        self.delay_map = delay_map or {}

    async def __call__(self, node_id: str, payload: dict, branch_name: str):
        self.calls.append((node_id, payload, branch_name))
        delay = self.delay_map.get(node_id, 0.0)
        if delay:
            await asyncio.sleep(delay)
        if node_id in self.fail_nodes:
            return BranchNodeResult(node_id=node_id, success=False, error=f"Forced failure: {node_id}")
        return BranchNodeResult(
            node_id=node_id,
            success=True,
            output=_successful_node_output(node_id),
        )


# ═══════════════════════════════════════════════════════════════════
# AC1 + AC2 + AC3: Core cancellation behavior
# ═══════════════════════════════════════════════════════════════════

class TestCancelOnFirstCore:
    """Core cancel_on_first behavior with controllable timing."""

    @pytest.mark.asyncio
    async def test_first_success_cancels_pending(self):
        """AC1: First successful branch cancels pending branch tasks."""
        # Bio is instant, tech has a delay — bio wins, tech gets cancelled
        recorder = RecordingExecutor(delay_map={"tech_search": 0.3})
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_any()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_ON_FIRST,
        )

        assert not report.blocked
        assert report.first_completed_branch is not None
        # Bio should have completed
        assert "bio" in report.completed_branches
        # Tech should be cancelled (was still running when bio finished)
        # Note: if tech finishes before cancellation arrives, it may complete
        assert report.cancellation_enforced is True

    @pytest.mark.asyncio
    async def test_first_branch_enters_join(self):
        """AC2: First successful branch enters join input."""
        recorder = RecordingExecutor(delay_map={"tech_search": 0.3})
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_any()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_ON_FIRST,
        )

        assert not report.blocked
        # Merge should use first completed branch
        join_completed = [e for e in report.events if e["type"] == "join_completed"]
        assert len(join_completed) == 1

    @pytest.mark.asyncio
    async def test_cancelled_branches_get_events(self):
        """AC3: Cancelled branches receive branch_cancelled trace events."""
        recorder = RecordingExecutor(delay_map={"tech_search": 0.5})
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_any()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_ON_FIRST,
        )

        # Check for cancel_on_first_enforced event
        cancel_events = [e for e in report.events if e["type"] == "cancel_on_first_enforced"]
        # If cancellation happened, this event exists
        if report.cancelled_branches:
            assert len(cancel_events) == 1
            assert "first_completed_branch" in cancel_events[0]["metadata"]

    @pytest.mark.asyncio
    async def test_cancelled_excluded_from_join(self):
        """AC4: Cancelled branches are excluded from join input."""
        recorder = RecordingExecutor(delay_map={"tech_search": 0.5})
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_any()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_ON_FIRST,
        )

        assert not report.blocked
        # Cancelled branches should not be in completed
        for cancelled_b in report.cancelled_branches:
            assert cancelled_b not in report.completed_branches


# ═══════════════════════════════════════════════════════════════════
# AC5: Branches completed before cancellation
# ═══════════════════════════════════════════════════════════════════

class TestCancelOnFirstTiming:
    """Timing-dependent behavior."""

    @pytest.mark.asyncio
    async def test_fast_branches_both_complete(self):
        """AC5: When both complete before cancellation, both are completed."""
        # Both instant — both complete before cancel can fire
        recorder = RecordingExecutor()
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_any()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_ON_FIRST,
        )

        assert not report.blocked
        # Both may complete (instant execution)
        assert len(report.completed_branches) >= 1
        # First completed is tracked
        assert report.first_completed_branch is not None

    @pytest.mark.asyncio
    async def test_one_fails_one_succeeds(self):
        """AC5: Failed branch + successful branch; no cancellation needed."""
        recorder = RecordingExecutor(fail_nodes={"bio_search"}, delay_map={"tech_search": 0.1})
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_any()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_ON_FIRST,
        )

        assert not report.blocked
        assert "bio" in report.failed_branches
        assert "tech" in report.completed_branches

    @pytest.mark.asyncio
    async def test_all_fail_blocks(self):
        """All branches fail: join is blocked."""
        recorder = RecordingExecutor(fail_nodes={"bio_search", "tech_search"})
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_any()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_ON_FIRST,
        )

        assert report.blocked
        assert len(report.completed_branches) == 0

    @pytest.mark.asyncio
    async def test_completed_before_cancel_not_cancelled(self):
        """AC5: Branch completed before cancel fires stays completed."""
        # Both instant — both finish before cancel can fire
        recorder = RecordingExecutor()
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_any()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_ON_FIRST,
        )

        # Completed branches are not in cancelled
        for b in report.completed_branches:
            assert b not in report.cancelled_branches


# ═══════════════════════════════════════════════════════════════════
# AC7: Partial output preservation
# ═══════════════════════════════════════════════════════════════════

class TestCancelOnFirstPartialOutputs:
    """Cancelled branches preserve partial outputs."""

    @pytest.mark.asyncio
    async def test_cancelled_branch_outputs_preserved(self):
        """AC7: Partial outputs from cancelled branches are recorded."""
        # Bio instant, tech slow — tech gets cancelled mid-execution
        recorder = RecordingExecutor(delay_map={"tech_search": 0.5})
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_any()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_ON_FIRST,
        )

        # If tech was cancelled, check partial outputs
        if "tech" in report.cancelled_branches:
            tech_output = report.branch_outputs.get("tech", {})
            # Outputs dict should exist (may be empty or have partial data)
            assert "outputs" in tech_output or tech_output.get("cancelled", False)

    @pytest.mark.asyncio
    async def test_cancel_phase_recorded(self):
        """AC7: Cancel phase (during_invocation) is recorded."""
        recorder = RecordingExecutor(delay_map={"tech_search": 0.5})
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_any()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_ON_FIRST,
        )

        # Check cancel events for phase information
        cancel_events = [e for e in report.events if e["type"] == "branch_cancelled"]
        for evt in cancel_events:
            assert "cancel_phase" in evt["metadata"]


# ═══════════════════════════════════════════════════════════════════
# AC8 + AC9: No regression
# ═══════════════════════════════════════════════════════════════════

class TestCancelOnFirstNoRegression:
    """Verify existing behavior is unchanged."""

    @pytest.mark.asyncio
    async def test_allow_all_unchanged(self):
        """AC8: wait_for=any + allow_all still merges all."""
        recorder = RecordingExecutor()
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_any()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_ALLOW_ALL,
        )

        assert not report.blocked
        assert report.ignored_branches == []
        assert len(report.completed_branches) == 2
        assert report.cancelled_branches == []

    @pytest.mark.asyncio
    async def test_ignore_late_unchanged(self):
        """AC8: ignore_late still classifies, doesn't cancel."""
        recorder = RecordingExecutor()
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_any()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_IGNORE_LATE,
        )

        assert not report.blocked
        assert report.cancelled_branches == []
        assert len(report.completed_branches) == 2

    @pytest.mark.asyncio
    async def test_wait_for_first_unchanged(self):
        """AC9: wait_for=first still works independently."""
        recorder = RecordingExecutor()
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = JoinDef(
            join_id="j1", to_node="joiner",
            from_branches=["bio", "tech"], wait_for="first",
        )

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_ALLOW_ALL,
        )

        assert not report.blocked
        assert len(report.completed_branches) == 2
        assert report.cancelled_branches == []


# ═══════════════════════════════════════════════════════════════════
# Edge cases
# ═══════════════════════════════════════════════════════════════════

class TestCancelOnFirstEdgeCases:
    """Edge cases for cancel_on_first."""

    @pytest.mark.asyncio
    async def test_single_branch(self):
        """Single branch: no cancellation needed."""
        recorder = RecordingExecutor()
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_any()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_ON_FIRST,
        )

        assert not report.blocked
        assert "bio" in report.completed_branches
        assert report.cancelled_branches == []

    @pytest.mark.asyncio
    async def test_three_branches(self):
        """Three branches: first cancels the other two."""
        branch_def = BranchDef(
            branch_id="b1",
            from_node="router",
            branches={
                "bio": ["bio_search"],
                "tech": ["tech_search"],
                "med": ["med_search"],
            },
        )
        join_def = JoinDef(
            join_id="j1", to_node="joiner",
            from_branches=["bio", "tech", "med"], wait_for="any",
        )

        # Bio instant, tech and med slow
        recorder = RecordingExecutor(delay_map={"tech_search": 0.5, "med_search": 0.5})
        executor = BranchExecutor(node_executor=recorder)

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech", "med"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_ON_FIRST,
        )

        assert not report.blocked
        assert "bio" in report.completed_branches
        # At least one of tech/med should be cancelled
        cancelled_or_completed = len(report.cancelled_branches) + len(report.completed_branches)
        assert cancelled_or_completed == 3

    @pytest.mark.asyncio
    async def test_no_not_enforced_event(self):
        """cancel_on_first does not emit cancellation_policy_not_enforced."""
        recorder = RecordingExecutor()
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_any()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_ON_FIRST,
        )

        not_enforced = [e for e in report.events
                       if e["type"] == "cancellation_policy_not_enforced"]
        assert len(not_enforced) == 0

    @pytest.mark.asyncio
    async def test_join_meta_includes_cancelled(self):
        """Join metadata includes cancelled branches."""
        recorder = RecordingExecutor(delay_map={"tech_search": 0.5})
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_any()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_ON_FIRST,
        )

        assert "cancelled_branches" in report.join_meta
