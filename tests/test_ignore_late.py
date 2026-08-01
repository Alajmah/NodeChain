"""Tests for cancellation_policy=ignore_late.

AC1: wait_for=any + ignore_late joins after first successful branch.
AC2: Join input excludes late branch outputs.
AC3: Late successful branches are recorded as ignored_late.
AC4: Already-started branch side effects remain ledgered and reconciled.
AC5: Trace records first_accepted_branch and ignored_late_branches.
AC6: wait_for=any + allow_all behavior remains unchanged.
AC7: wait_for=first behavior remains unchanged.
AC8: 529 tests remain green.
"""

import asyncio
import pytest

from nodechain.core.blueprint import BranchDef, JoinDef
from nodechain.runtime.branch_executor import (
    BranchExecutor, BranchNodeResult, BranchExecutionReport,
)
from nodechain.runtime.invariant_engine import CANCEL_IGNORE_LATE, CANCEL_ALLOW_ALL


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
# AC1 + AC2 + AC3: ignore_late basic behavior
# ═══════════════════════════════════════════════════════════════════

class TestIgnoreLateBasic:
    """Basic ignore_late behavior with wait_for=any."""

    @pytest.mark.asyncio
    async def test_joins_after_first_success(self):
        """AC1: wait_for=any + ignore_late joins after first successful branch."""
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
        assert report.cancellation_enforced is True

    @pytest.mark.asyncio
    async def test_join_input_excludes_late(self):
        """AC2: Merge uses only first accepted branch."""
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
        first = report.first_completed_branch
        assert first is not None

        # Merge should use only first branch
        join_completed = [e for e in report.events if e["type"] == "join_completed"]
        assert len(join_completed) == 1
        merge_detail = join_completed[0]["metadata"]["merge_detail"]
        assert merge_detail["used_branches"] == [first]

    @pytest.mark.asyncio
    async def test_late_branches_marked_ignored(self):
        """AC3: Late successful branches recorded as ignored_late."""
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
        first = report.first_completed_branch
        late = [b for b in report.completed_branches if b != first]
        assert sorted(report.ignored_branches) == sorted(late)

    @pytest.mark.asyncio
    async def test_all_branches_still_execute(self):
        """AC4: All branches still run to completion; side effects remain."""
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

        # Both branches executed
        branch_names = {call[2] for call in recorder.calls}
        assert "bio" in branch_names
        assert "tech" in branch_names
        assert len(report.completed_branches) == 2


# ═══════════════════════════════════════════════════════════════════
# AC5: Trace events
# ═══════════════════════════════════════════════════════════════════

class TestIgnoreLateTrace:
    """Trace event recording for ignore_late."""

    @pytest.mark.asyncio
    async def test_ignore_late_event_emitted(self):
        """AC5: Trace records ignore_late_enforced event."""
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

        events = [e for e in report.events if e["type"] == "ignore_late_enforced"]
        assert len(events) == 1
        meta = events[0]["metadata"]
        assert "first_accepted_branch" in meta
        assert "ignored_late_branches" in meta
        assert meta["cancellation_policy"] == "ignore_late"

    @pytest.mark.asyncio
    async def test_first_accepted_in_metadata(self):
        """AC5: first_accepted_branch recorded in event metadata."""
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

        events = [e for e in report.events if e["type"] == "ignore_late_enforced"]
        meta = events[0]["metadata"]
        assert meta["first_accepted_branch"] == report.first_completed_branch

    @pytest.mark.asyncio
    async def test_join_meta_includes_ignored(self):
        """Join metadata includes ignored_branches."""
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

        assert len(report.join_meta.get("ignored_branches", [])) > 0


# ═══════════════════════════════════════════════════════════════════
# Failure handling
# ═══════════════════════════════════════════════════════════════════

class TestIgnoreLateFailures:
    """Failure handling with ignore_late policy."""

    @pytest.mark.asyncio
    async def test_one_fails_one_succeeds(self):
        """Failed branch + successful branch: join succeeds on first success."""
        recorder = RecordingExecutor(fail_nodes={"bio_search"})
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
        assert "bio" in report.failed_branches
        assert "tech" in report.completed_branches
        assert report.first_completed_branch == "tech"
        # No ignored_late since only one succeeded
        assert report.ignored_branches == []

    @pytest.mark.asyncio
    async def test_all_fail_blocks_join(self):
        """All branches fail: join is blocked (same as wait_for=any)."""
        recorder = RecordingExecutor(fail_nodes={"bio_search", "tech_search"})
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

        assert report.blocked
        assert "no branches completed" in report.block_reason

    @pytest.mark.asyncio
    async def test_no_ignore_event_when_only_one_succeeds(self):
        """ignore_late event fires but with empty ignored_late_branches."""
        recorder = RecordingExecutor(fail_nodes={"bio_search"})
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

        # Event fires to record policy evaluation, but no branches were late
        events = [e for e in report.events if e["type"] == "ignore_late_enforced"]
        assert len(events) == 1
        assert events[0]["metadata"]["ignored_late_branches"] == []
        assert events[0]["metadata"]["first_accepted_branch"] == "tech"


# ═══════════════════════════════════════════════════════════════════
# AC6 + AC7: No regression
# ═══════════════════════════════════════════════════════════════════

class TestIgnoreLateNoRegression:
    """Verify existing behavior is unchanged."""

    @pytest.mark.asyncio
    async def test_allow_all_merges_all(self):
        """AC6: wait_for=any + allow_all still merges all completed branches."""
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
        # Merge should use all completed branches
        join_completed = [e for e in report.events if e["type"] == "join_completed"]
        merge_detail = join_completed[0]["metadata"]["merge_detail"]
        assert len(merge_detail["used_branches"]) == 2

    @pytest.mark.asyncio
    async def test_wait_for_first_still_works(self):
        """AC7: wait_for=first behavior unchanged."""
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
        assert len(report.ignored_branches) == 1

    @pytest.mark.asyncio
    async def test_wait_for_all_still_blocks(self):
        """AC7: wait_for=all still blocks on failure."""
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
            cancellation_policy=CANCEL_ALLOW_ALL,
        )

        assert report.blocked


# ═══════════════════════════════════════════════════════════════════
# Edge cases
# ═══════════════════════════════════════════════════════════════════

class TestIgnoreLateEdgeCases:
    """Edge cases for ignore_late."""

    @pytest.mark.asyncio
    async def test_single_branch_no_ignore(self):
        """Single branch: no late branches to ignore."""
        recorder = RecordingExecutor()
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def()
        join_def = _make_join_def_any()

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_IGNORE_LATE,
        )

        assert not report.blocked
        assert report.ignored_branches == []

    @pytest.mark.asyncio
    async def test_three_branches_two_ignored(self):
        """Three branches: first accepted, two ignored."""
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

        recorder = RecordingExecutor()
        executor = BranchExecutor(node_executor=recorder)

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech", "med"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_IGNORE_LATE,
        )

        assert not report.blocked
        assert len(report.completed_branches) == 3
        assert len(report.ignored_branches) == 2

    @pytest.mark.asyncio
    async def test_ignore_late_with_wait_for_all_no_effect(self):
        """ignore_late with wait_for=all: policy does not activate."""
        recorder = RecordingExecutor()
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
            cancellation_policy=CANCEL_IGNORE_LATE,
        )

        # wait_for=all succeeds with all branches, ignore_late doesn't activate
        assert not report.blocked
        assert len(report.completed_branches) == 2
        # No ignore_late event because wait_for=all is not in scope
        events = [e for e in report.events if e["type"] == "ignore_late_enforced"]
        assert len(events) == 0
        # Merge should use all completed branches
        join_completed = [e for e in report.events if e["type"] == "join_completed"]
        merge_detail = join_completed[0]["metadata"]["merge_detail"]
        assert len(merge_detail["used_branches"]) == 2

    @pytest.mark.asyncio
    async def test_ignore_late_not_enforced_event_absent(self):
        """When ignore_late is active, no cancellation_policy_not_enforced event."""
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

        not_enforced = [e for e in report.events
                       if e["type"] == "cancellation_policy_not_enforced"]
        assert len(not_enforced) == 0
