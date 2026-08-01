"""Tests for wait_for=first join scheduling semantic.

AC1: wait_for=first does not wait for every selected branch before join eligibility.
AC2: First successful branch determines join input.
AC3: Later branch outputs are marked ignored for join purposes.
AC4: Trace records first_completed_branch and ignored_late_branches.
AC5: Failed first branch does not count as success; executor waits for first success or all failure.
AC6: If all branches fail, join is blocked/failed.
AC7: Existing wait_for=all and wait_for=any behavior remains unchanged.
AC8: 512 tests remain green (includes these new tests).
"""

import asyncio
import pytest

from nodechain.core.blueprint import BranchDef, JoinDef
from nodechain.runtime.branch_executor import (
    BranchExecutor, BranchNodeResult, BranchExecutionReport,
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


def _make_join_def_first():
    return JoinDef(
        join_id="j1",
        to_node="joiner",
        from_branches=["bio", "tech"],
        wait_for="first",
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
        self.delay_map = delay_map or {}  # node_id → delay seconds

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
# AC2 + AC3 + AC4: First successful branch determines join input
# ═══════════════════════════════════════════════════════════════════

class TestWaitForFirstBasic:
    """Basic wait_for=first behavior."""

    @pytest.mark.asyncio
    async def test_first_completes_join_proceeds(self):
        """AC2: First successful branch determines join input; join is not blocked."""
        recorder = RecordingExecutor()
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_first()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
        )

        assert not report.blocked
        assert report.first_completed_branch is not None
        assert report.first_completed_branch in ["bio", "tech"]

    @pytest.mark.asyncio
    async def test_later_branches_marked_ignored(self):
        """AC3: Later branch outputs are marked ignored for join purposes."""
        recorder = RecordingExecutor()
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_first()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
        )

        assert not report.blocked
        # One branch is first, the other is ignored_late
        first = report.first_completed_branch
        assert first is not None
        late = [b for b in report.completed_branches if b != first]
        assert sorted(report.ignored_branches) == sorted(late)

    @pytest.mark.asyncio
    async def test_trace_records_first_and_ignored(self):
        """AC4: Trace records first_completed_branch and ignored_late_branches."""
        recorder = RecordingExecutor()
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_first()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
        )

        # Find first_branch_selected event
        first_events = [e for e in report.events if e["type"] == "first_branch_selected"]
        assert len(first_events) == 1
        meta = first_events[0]["metadata"]
        assert "first_completed_branch" in meta
        assert "ignored_late_branches" in meta
        assert meta["first_completed_branch"] is not None

    @pytest.mark.asyncio
    async def test_merge_uses_only_first_branch(self):
        """AC2: Merged output contains only first branch's data."""
        recorder = RecordingExecutor()
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_first()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
        )

        assert not report.blocked
        # The merged output should have claims from exactly one branch
        first = report.first_completed_branch
        assert first is not None

        # Check that merge_meta shows only the first branch was used
        join_completed = [e for e in report.events if e["type"] == "join_completed"]
        assert len(join_completed) == 1
        merge_detail = join_completed[0]["metadata"]["merge_detail"]
        assert merge_detail["used_branches"] == [first]

    @pytest.mark.asyncio
    async def test_all_branches_still_executed(self):
        """AC1: All branches still run (no cancellation in v1); join is just not blocked."""
        recorder = RecordingExecutor()
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_first()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
        )

        # Both branches executed
        branch_names = {call[2] for call in recorder.calls}
        assert "bio" in branch_names
        assert "tech" in branch_names
        assert len(report.completed_branches) == 2


# ═══════════════════════════════════════════════════════════════════
# AC5: Failed first branch does not count as success
# AC6: If all branches fail, join is blocked/failed
# ═══════════════════════════════════════════════════════════════════

class TestWaitForFirstFailures:
    """Failure handling for wait_for=first."""

    @pytest.mark.asyncio
    async def test_one_branch_fails_one_succeeds(self):
        """AC5: Failed branch does not block if another succeeds."""
        recorder = RecordingExecutor(fail_nodes={"bio_search"})
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_first()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
        )

        assert not report.blocked
        assert "bio" in report.failed_branches
        assert "tech" in report.completed_branches
        assert report.first_completed_branch == "tech"

    @pytest.mark.asyncio
    async def test_all_branches_fail_blocks_join(self):
        """AC6: If all branches fail, join is blocked/failed."""
        recorder = RecordingExecutor(fail_nodes={"bio_search", "tech_search"})
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_first()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
        )

        assert report.blocked
        assert report.block_reason is not None
        assert "all branches failed" in report.block_reason
        # Verify join_blocked event
        blocked_events = [e for e in report.events if e["type"] == "join_blocked"]
        assert len(blocked_events) == 1
        assert blocked_events[0]["metadata"]["wait_for"] == "first"

    @pytest.mark.asyncio
    async def test_no_completed_means_blocked(self):
        """AC6: Zero completed branches → blocked join."""
        recorder = RecordingExecutor(fail_nodes={"bio_search", "tech_search"})
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_first()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
        )

        assert report.blocked
        assert len(report.completed_branches) == 0

    @pytest.mark.asyncio
    async def test_failed_branch_not_in_first_completed(self):
        """AC5: Failed branch is never first_completed_branch."""
        recorder = RecordingExecutor(fail_nodes={"bio_search"})
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_first()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
        )

        assert not report.blocked
        assert report.first_completed_branch != "bio"


# ═══════════════════════════════════════════════════════════════════
# AC7: Existing wait_for=all and wait_for=any unchanged
# ═══════════════════════════════════════════════════════════════════

class TestWaitForFirstNoRegression:
    """Verify wait_for=all and wait_for=any are not affected."""

    @pytest.mark.asyncio
    async def test_wait_for_all_still_blocks_on_failure(self):
        """AC7: wait_for=all still blocks when any branch fails."""
        recorder = RecordingExecutor(fail_nodes={"bio_search"})
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = JoinDef(
            join_id="j1", to_node="joiner",
            from_branches=["bio", "tech"], wait_for="all",
        )

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
        )

        assert report.blocked

    @pytest.mark.asyncio
    async def test_wait_for_any_still_proceeds_partial(self):
        """AC7: wait_for=any still proceeds with partial results."""
        recorder = RecordingExecutor(fail_nodes={"bio_search"})
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = JoinDef(
            join_id="j1", to_node="joiner",
            from_branches=["bio", "tech"], wait_for="any",
        )

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
        )

        assert not report.blocked
        assert "tech" in report.completed_branches

    @pytest.mark.asyncio
    async def test_wait_for_any_still_blocks_when_none_complete(self):
        """AC7: wait_for=any still blocks when no branches complete."""
        recorder = RecordingExecutor(fail_nodes={"bio_search", "tech_search"})
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = JoinDef(
            join_id="j1", to_node="joiner",
            from_branches=["bio", "tech"], wait_for="any",
        )

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
        )

        assert report.blocked


# ═══════════════════════════════════════════════════════════════════
# Additional edge cases
# ═══════════════════════════════════════════════════════════════════

class TestWaitForFirstEdgeCases:
    """Edge cases for wait_for=first."""

    @pytest.mark.asyncio
    async def test_single_branch(self):
        """Single branch with wait_for=first completes normally."""
        recorder = RecordingExecutor()
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_first()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio"],
            parent_output={"query": "test"},
            join_def=join_def,
        )

        assert not report.blocked
        assert report.first_completed_branch == "bio"
        assert report.ignored_branches == []

    @pytest.mark.asyncio
    async def test_single_branch_fails(self):
        """Single branch failure with wait_for=first blocks join."""
        recorder = RecordingExecutor(fail_nodes={"bio_search"})
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_first()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio"],
            parent_output={"query": "test"},
            join_def=join_def,
        )

        assert report.blocked

    @pytest.mark.asyncio
    async def test_three_branches_first_wins(self):
        """Three branches: first determines join, rest ignored."""
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
            from_branches=["bio", "tech", "med"],
            wait_for="first",
        )

        recorder = RecordingExecutor()
        executor = BranchExecutor(node_executor=recorder)

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech", "med"],
            parent_output={"query": "test"},
            join_def=join_def,
        )

        assert not report.blocked
        assert len(report.completed_branches) == 3
        assert len(report.ignored_branches) == 2

    @pytest.mark.asyncio
    async def test_join_meta_includes_wait_for_first(self):
        """Join metadata records wait_for=first."""
        recorder = RecordingExecutor()
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_first()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
        )

        assert report.join_meta["wait_for"] == "first"
        assert "first_completed_branch" in report.join_meta

    @pytest.mark.asyncio
    async def test_no_join_def_defaults_to_all(self):
        """No join_def still defaults to wait_for=all behavior."""
        recorder = RecordingExecutor(fail_nodes={"bio_search"})
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=None,
        )

        # Default is wait_for=all, so failure blocks
        assert report.blocked
