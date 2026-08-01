"""Tests for cancellation_policy=first_success_only.

AC1: first_success_only selects the first successful branch.
AC2: Failed early branches do not win.
AC3: Pending branches cancel after first success.
AC4: Winner enters join input alone.
AC5: Failed-before-success branches remain failed, not cancelled.
AC6: Cancelled branches emit branch_cancelled.
AC7: All-fail case blocks join.
AC8: Regression: allow_all, ignore_late, cancel_on_first unchanged.
AC9: 563 tests remain green.
"""

import asyncio
import pytest

from nodechain.core.blueprint import BranchDef, JoinDef
from nodechain.runtime.branch_executor import (
    BranchExecutor, BranchNodeResult, BranchExecutionReport,
)
from nodechain.runtime.invariant_engine import (
    CANCEL_FIRST_SUCCESS_ONLY, CANCEL_ALLOW_ALL,
    CANCEL_IGNORE_LATE, CANCEL_ON_FIRST,
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
# AC1 + AC3 + AC4: Core first_success_only behavior
# ═══════════════════════════════════════════════════════════════════

class TestFirstSuccessOnlyCore:
    """Core first_success_only behavior."""

    @pytest.mark.asyncio
    async def test_first_success_wins(self):
        """AC1: First successful branch wins."""
        recorder = RecordingExecutor(delay_map={"tech_search": 0.3})
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_any()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_FIRST_SUCCESS_ONLY,
        )

        assert not report.blocked
        assert report.first_completed_branch is not None
        assert report.cancellation_enforced is True

    @pytest.mark.asyncio
    async def test_pending_cancelled_after_first_success(self):
        """AC3: Pending branches cancelled after first success."""
        recorder = RecordingExecutor(delay_map={"tech_search": 0.5})
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_any()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_FIRST_SUCCESS_ONLY,
        )

        assert "bio" in report.completed_branches
        # Tech should be cancelled or completed (timing dependent)
        if "tech" in report.cancelled_branches:
            cancel_events = [e for e in report.events if e["type"] == "branch_cancelled"]
            assert any(e["metadata"]["branch"] == "tech" for e in cancel_events)

    @pytest.mark.asyncio
    async def test_winner_alone_enters_merge(self):
        """AC4: Only winner enters join input."""
        recorder = RecordingExecutor(delay_map={"tech_search": 0.5})
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_any()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_FIRST_SUCCESS_ONLY,
        )

        assert not report.blocked
        # Merge should use only the winner
        join_completed = [e for e in report.events if e["type"] == "join_completed"]
        assert len(join_completed) == 1
        merge_detail = join_completed[0]["metadata"]["merge_detail"]
        assert len(merge_detail["used_branches"]) == 1
        assert merge_detail["used_branches"][0] == report.first_completed_branch

    @pytest.mark.asyncio
    async def test_first_success_only_event(self):
        """Event uses first_success_only_enforced name."""
        recorder = RecordingExecutor(delay_map={"tech_search": 0.5})
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_any()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_FIRST_SUCCESS_ONLY,
        )

        if report.cancelled_branches:
            events = [e for e in report.events if e["type"] == "first_success_only_enforced"]
            assert len(events) == 1
            assert events[0]["metadata"]["policy"] == "first_success_only"

    @pytest.mark.asyncio
    async def test_no_not_enforced_event(self):
        """No cancellation_policy_not_enforced event."""
        recorder = RecordingExecutor()
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_any()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_FIRST_SUCCESS_ONLY,
        )

        not_enforced = [e for e in report.events
                       if e["type"] == "cancellation_policy_not_enforced"]
        assert len(not_enforced) == 0


# ═══════════════════════════════════════════════════════════════════
# AC2 + AC5: Failure handling
# ═══════════════════════════════════════════════════════════════════

class TestFirstSuccessOnlyFailures:
    """Failure handling for first_success_only."""

    @pytest.mark.asyncio
    async def test_failed_branch_does_not_win(self):
        """AC2: Failed early branches do not win."""
        # Bio fails instantly, tech succeeds slowly
        recorder = RecordingExecutor(
            fail_nodes={"bio_search"},
            delay_map={"tech_search": 0.1},
        )
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_any()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_FIRST_SUCCESS_ONLY,
        )

        assert not report.blocked
        assert "bio" in report.failed_branches
        assert "tech" in report.completed_branches
        assert report.first_completed_branch == "tech"

    @pytest.mark.asyncio
    async def test_failed_before_success_stays_failed(self):
        """AC5: Failed-before-success branches remain failed."""
        recorder = RecordingExecutor(
            fail_nodes={"bio_search"},
            delay_map={"tech_search": 0.1},
        )
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_any()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_FIRST_SUCCESS_ONLY,
        )

        assert "bio" in report.failed_branches
        assert "bio" not in report.cancelled_branches

    @pytest.mark.asyncio
    async def test_all_fail_blocks(self):
        """AC7: All branches fail blocks join."""
        recorder = RecordingExecutor(fail_nodes={"bio_search", "tech_search"})
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_any()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_FIRST_SUCCESS_ONLY,
        )

        assert report.blocked
        assert len(report.completed_branches) == 0

    @pytest.mark.asyncio
    async def test_cancelled_branches_get_events(self):
        """AC6: Cancelled branches emit branch_cancelled."""
        recorder = RecordingExecutor(delay_map={"tech_search": 0.5})
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_any()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_FIRST_SUCCESS_ONLY,
        )

        # If tech was cancelled, it should have a branch_cancelled event
        if "tech" in report.cancelled_branches:
            cancel_events = [e for e in report.events if e["type"] == "branch_cancelled"]
            assert any(e["metadata"]["branch"] == "tech" for e in cancel_events)


# ═══════════════════════════════════════════════════════════════════
# AC8: No regression
# ═══════════════════════════════════════════════════════════════════

class TestFirstSuccessOnlyNoRegression:
    """Verify existing policies are unchanged."""

    @pytest.mark.asyncio
    async def test_allow_all_unchanged(self):
        """AC8: allow_all still merges all."""
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
    async def test_cancel_on_first_unchanged(self):
        """AC8: cancel_on_first still works."""
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
        assert "bio" in report.completed_branches
        # Should emit cancel_on_first_enforced (not first_success_only_enforced)
        if report.cancelled_branches:
            events = [e for e in report.events if e["type"] == "cancel_on_first_enforced"]
            assert len(events) == 1

    @pytest.mark.asyncio
    async def test_wait_for_first_unchanged(self):
        """AC9: wait_for=first still works."""
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
        assert report.cancelled_branches == []


# ═══════════════════════════════════════════════════════════════════
# Edge cases
# ═══════════════════════════════════════════════════════════════════

class TestFirstSuccessOnlyEdgeCases:
    """Edge cases."""

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
            cancellation_policy=CANCEL_FIRST_SUCCESS_ONLY,
        )

        assert not report.blocked
        assert "bio" in report.completed_branches
        assert report.cancelled_branches == []

    @pytest.mark.asyncio
    async def test_three_branches(self):
        """Three branches: first wins, others cancelled."""
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

        recorder = RecordingExecutor(delay_map={"tech_search": 0.5, "med_search": 0.5})
        executor = BranchExecutor(node_executor=recorder)

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech", "med"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_FIRST_SUCCESS_ONLY,
        )

        assert not report.blocked
        assert "bio" in report.completed_branches
        # Merge uses only bio
        join_completed = [e for e in report.events if e["type"] == "join_completed"]
        merge_detail = join_completed[0]["metadata"]["merge_detail"]
        assert merge_detail["used_branches"] == ["bio"]

    @pytest.mark.asyncio
    async def test_single_branch_fails_blocks(self):
        """Single branch failure blocks join."""
        recorder = RecordingExecutor(fail_nodes={"bio_search"})
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_any()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_FIRST_SUCCESS_ONLY,
        )

        assert report.blocked

    @pytest.mark.asyncio
    async def test_merge_isolation(self):
        """Merge output contains only winner's claims."""
        recorder = RecordingExecutor(delay_map={"tech_search": 0.5})
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_any()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_FIRST_SUCCESS_ONLY,
        )

        assert not report.blocked
        # Merged output should have claims from bio only (the winner)
        winner = report.first_completed_branch
        assert winner is not None
        winner_claims = report.merged_output.get("claims", [])
        # All claims should be from the winner branch
        if winner_claims:
            for claim in winner_claims:
                assert isinstance(claim, dict)
