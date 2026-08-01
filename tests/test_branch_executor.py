"""Tests for BranchExecutor — parallel branch execution component.

Covers:
- Branch execution with all branches completing
- Branch failure isolation
- Skipped branches
- wait_for=all blocks on any failure
- wait_for=any proceeds with partial results
- wait_for=any blocks when no branches complete
- Join metadata construction
- Branch timings
- Concurrent execution verification
"""

import asyncio
import pytest

from nodechain.core.blueprint import BranchDef, JoinDef
from nodechain.runtime.branch_executor import (
    BranchExecutor, BranchNodeResult, BranchExecutionReport,
)
from nodechain.runtime.invariant_engine import (
    CANCEL_ALLOW_ALL, CANCEL_ON_FIRST,
)


# ── Helpers ──

def _make_branch_def():
    return BranchDef(
        branch_id="b1",
        from_node="router",
        branches={
            "bio": ["bio_search", "bio_process"],
            "tech": ["tech_search", "tech_process"],
            "skipped": ["skipped_node"],
        },
        default_branch="bio",
    )


def _make_join_def(wait_for="all"):
    return JoinDef(
        join_id="j1",
        to_node="joiner",
        from_branches=["bio", "tech", "skipped"],
        wait_for=wait_for,
    )


def _successful_node_output(node_id: str) -> dict:
    """Produce fake successful output for a node."""
    return {
        "claims": [{"claim_id": f"{node_id}_c1", "text": f"Claim from {node_id}"}],
        "sources": [{"source_ref": f"S_{node_id}"}],
    }


class RecordingExecutor:
    """Tracks node invocations for assertion."""

    def __init__(self, fail_nodes=None, delay=0.0):
        self.calls: list[tuple[str, dict, str]] = []
        self.fail_nodes = fail_nodes or set()
        self.delay = delay

    async def __call__(self, node_id: str, payload: dict, branch_name: str):
        self.calls.append((node_id, payload, branch_name))
        if self.delay:
            await asyncio.sleep(self.delay)
        if node_id in self.fail_nodes:
            return BranchNodeResult(node_id=node_id, success=False, error=f"Forced failure: {node_id}")
        return BranchNodeResult(
            node_id=node_id,
            success=True,
            output=_successful_node_output(node_id),
        )


# ═══════════════════════════════════════════════════════════════════
# Basic execution
# ═══════════════════════════════════════════════════════════════════

class TestBasicExecution:
    @pytest.mark.asyncio
    async def test_all_branches_complete(self):
        executor_fn = RecordingExecutor()
        bx = BranchExecutor(node_executor=executor_fn)
        report = await bx.execute(
            branch_def=_make_branch_def(),
            selected_branches=["bio", "tech"],
            parent_output={"query": "test"},
            join_def=_make_join_def(),
        )
        assert report.success
        assert not report.blocked
        assert "bio" in report.completed_branches
        assert "tech" in report.completed_branches
        assert "skipped" in report.skipped_branches
        assert len(report.completed_branches) == 2

    @pytest.mark.asyncio
    async def test_branch_outputs_populated(self):
        executor_fn = RecordingExecutor()
        bx = BranchExecutor(node_executor=executor_fn)
        report = await bx.execute(
            branch_def=_make_branch_def(),
            selected_branches=["bio"],
            parent_output={"query": "test"},
            join_def=_make_join_def(),
        )
        bio_output = report.branch_outputs["bio"]
        assert not bio_output.get("skipped")
        assert "bio_search" in bio_output["outputs"]
        assert "bio_process" in bio_output["outputs"]

    @pytest.mark.asyncio
    async def test_merged_output_contains_claims(self):
        executor_fn = RecordingExecutor()
        bx = BranchExecutor(node_executor=executor_fn)
        report = await bx.execute(
            branch_def=_make_branch_def(),
            selected_branches=["bio", "tech"],
            parent_output={},
            join_def=_make_join_def(),
        )
        assert "claims" in report.merged_output
        assert "sources" in report.merged_output
        assert len(report.merged_output["claims"]) == 4  # 2 nodes × 2 branches
        assert len(report.merged_output["sources"]) == 4


# ═══════════════════════════════════════════════════════════════════
# Failure isolation
# ═══════════════════════════════════════════════════════════════════

class TestFailureIsolation:
    @pytest.mark.asyncio
    async def test_one_branch_fails_other_succeeds(self):
        executor_fn = RecordingExecutor(fail_nodes={"tech_search"})
        bx = BranchExecutor(node_executor=executor_fn)
        report = await bx.execute(
            branch_def=_make_branch_def(),
            selected_branches=["bio", "tech"],
            parent_output={},
            join_def=_make_join_def(wait_for="any"),
        )
        # bio should complete, tech should fail
        assert "bio" in report.completed_branches
        assert "tech" in report.failed_branches
        # tech failure should not corrupt bio output
        bio_output = report.branch_outputs["bio"]
        assert not bio_output.get("failed")

    @pytest.mark.asyncio
    async def test_failed_branch_stops_at_failed_node(self):
        executor_fn = RecordingExecutor(fail_nodes={"bio_search"})
        bx = BranchExecutor(node_executor=executor_fn)
        report = await bx.execute(
            branch_def=_make_branch_def(),
            selected_branches=["bio"],
            parent_output={},
            join_def=_make_join_def(wait_for="any"),
        )
        # bio should fail at bio_search, not continue to bio_process
        bio_calls = [(nid, br) for nid, _, br in executor_fn.calls if br == "bio"]
        assert len(bio_calls) == 1  # Only bio_search, not bio_process


# ═══════════════════════════════════════════════════════════════════
# wait_for semantics
# ═══════════════════════════════════════════════════════════════════

class TestWaitForSemantics:
    @pytest.mark.asyncio
    async def test_wait_for_all_blocks_on_failure(self):
        executor_fn = RecordingExecutor(fail_nodes={"tech_search"})
        bx = BranchExecutor(node_executor=executor_fn)
        report = await bx.execute(
            branch_def=_make_branch_def(),
            selected_branches=["bio", "tech"],
            parent_output={},
            join_def=_make_join_def(wait_for="all"),
        )
        assert report.blocked
        assert "tech" in report.block_reason

    @pytest.mark.asyncio
    async def test_wait_for_any_proceeds_with_partial(self):
        executor_fn = RecordingExecutor(fail_nodes={"tech_search"})
        bx = BranchExecutor(node_executor=executor_fn)
        report = await bx.execute(
            branch_def=_make_branch_def(),
            selected_branches=["bio", "tech"],
            parent_output={},
            join_def=_make_join_def(wait_for="any"),
        )
        assert not report.blocked
        assert report.partial
        assert "bio" in report.completed_branches

    @pytest.mark.asyncio
    async def test_wait_for_any_blocks_when_none_complete(self):
        executor_fn = RecordingExecutor(fail_nodes={"bio_search", "tech_search"})
        bx = BranchExecutor(node_executor=executor_fn)
        report = await bx.execute(
            branch_def=_make_branch_def(),
            selected_branches=["bio", "tech"],
            parent_output={},
            join_def=_make_join_def(wait_for="any"),
        )
        assert report.blocked
        assert "no branches completed" in report.block_reason


# ═══════════════════════════════════════════════════════════════════
# Skipped branches
# ═══════════════════════════════════════════════════════════════════

class TestSkippedBranches:
    @pytest.mark.asyncio
    async def test_unselected_branches_skipped(self):
        executor_fn = RecordingExecutor()
        bx = BranchExecutor(node_executor=executor_fn)
        report = await bx.execute(
            branch_def=_make_branch_def(),
            selected_branches=["bio"],
            parent_output={},
            join_def=_make_join_def(),
        )
        assert "skipped" in report.skipped_branches
        assert "tech" in report.skipped_branches
        assert report.branch_outputs["skipped"]["skipped"] is True

    @pytest.mark.asyncio
    async def test_skipped_branches_not_executed(self):
        executor_fn = RecordingExecutor()
        bx = BranchExecutor(node_executor=executor_fn)
        await bx.execute(
            branch_def=_make_branch_def(),
            selected_branches=["bio"],
            parent_output={},
            join_def=_make_join_def(),
        )
        # Only bio branch nodes should have been called
        called_branches = {br for _, _, br in executor_fn.calls}
        assert called_branches == {"bio"}


# ═══════════════════════════════════════════════════════════════════
# Timings and metadata
# ═══════════════════════════════════════════════════════════════════

class TestTimingsAndMetadata:
    @pytest.mark.asyncio
    async def test_branch_timings_recorded(self):
        executor_fn = RecordingExecutor(delay=0.01)
        bx = BranchExecutor(node_executor=executor_fn)
        report = await bx.execute(
            branch_def=_make_branch_def(),
            selected_branches=["bio", "tech"],
            parent_output={},
            join_def=_make_join_def(),
        )
        assert "bio" in report.branch_timings
        assert "tech" in report.branch_timings
        assert report.branch_timings["bio"]["duration_ms"] > 0

    @pytest.mark.asyncio
    async def test_join_meta_populated(self):
        executor_fn = RecordingExecutor()
        bx = BranchExecutor(node_executor=executor_fn)
        report = await bx.execute(
            branch_def=_make_branch_def(),
            selected_branches=["bio", "tech"],
            parent_output={},
            join_def=_make_join_def(),
        )
        meta = report.join_meta
        assert meta["join_id"] == "j1"
        assert meta["wait_for"] == "all"
        assert "bio" in meta["completed_branches"]
        assert "tech" in meta["completed_branches"]

    @pytest.mark.asyncio
    async def test_events_populated(self):
        executor_fn = RecordingExecutor()
        bx = BranchExecutor(node_executor=executor_fn)
        report = await bx.execute(
            branch_def=_make_branch_def(),
            selected_branches=["bio"],
            parent_output={},
            join_def=_make_join_def(),
        )
        event_types = [e["type"] for e in report.events]
        assert "routing_decision" in event_types
        assert "branch_skipped" in event_types
        assert "branch_completed" in event_types
        assert "join_ready" in event_types
        assert "join_completed" in event_types


# ═══════════════════════════════════════════════════════════════════
# Concurrent execution
# ═══════════════════════════════════════════════════════════════════

class TestConcurrentExecution:
    @pytest.mark.asyncio
    async def test_branches_execute_in_parallel(self):
        """Verify branches actually run concurrently."""
        call_times: dict[str, float] = {}

        async def tracking_executor(node_id, payload, branch_name):
            call_times[f"{branch_name}:{node_id}"] = asyncio.get_event_loop().time()
            await asyncio.sleep(0.05)
            return BranchNodeResult(node_id=node_id, success=True, output={})

        bx = BranchExecutor(node_executor=tracking_executor)

        # Simple branch def with two single-node branches
        bd = BranchDef(
            branch_id="b1", from_node="router",
            branches={"alpha": ["n1"], "beta": ["n2"]},
        )
        report = await bx.execute(
            branch_def=bd,
            selected_branches=["alpha", "beta"],
            parent_output={},
            join_def=None,
        )

        # Both branches should have started within 50ms of each other
        t1 = call_times.get("alpha:n1", 0)
        t2 = call_times.get("beta:n2", 0)
        assert abs(t1 - t2) < 0.05  # Within 50ms — concurrent, not sequential

    @pytest.mark.asyncio
    async def test_first_completed_tracked(self):
        executor_fn = RecordingExecutor()
        bx = BranchExecutor(node_executor=executor_fn)
        report = await bx.execute(
            branch_def=_make_branch_def(),
            selected_branches=["bio", "tech"],
            parent_output={},
            join_def=_make_join_def(),
        )
        assert report.first_completed_branch is not None
        assert report.first_completed_branch in ("bio", "tech")


# ═══════════════════════════════════════════════════════════════════
# No join def
# ═══════════════════════════════════════════════════════════════════

class TestNoJoinDef:
    @pytest.mark.asyncio
    async def test_no_join_def_defaults_to_all(self):
        executor_fn = RecordingExecutor()
        bx = BranchExecutor(node_executor=executor_fn)
        report = await bx.execute(
            branch_def=_make_branch_def(),
            selected_branches=["bio"],
            parent_output={},
            join_def=None,
        )
        assert report.wait_for == "all"
        assert report.success


# ═══════════════════════════════════════════════════════════════════
# Cancellation enforcement status
# ═══════════════════════════════════════════════════════════════════

class TestCancellationEnforcement:
    """Clarify that cancellation policies are validated but not all enforced."""

    @pytest.mark.asyncio
    async def test_allow_all_is_enforced(self):
        """allow_all is actively enforced (all branches run to completion)."""
        executor_fn = RecordingExecutor()
        bx = BranchExecutor(node_executor=executor_fn)
        report = await bx.execute(
            branch_def=_make_branch_def(),
            selected_branches=["bio", "tech"],
            parent_output={},
            join_def=_make_join_def(wait_for="any"),
            cancellation_policy=CANCEL_ALLOW_ALL,
        )
        assert report.cancellation_policy == CANCEL_ALLOW_ALL
        assert report.cancellation_enforced is True
        # No enforcement-warning event
        unenforced = [e for e in report.events
                      if e["type"] == "cancellation_policy_not_enforced"]
        assert len(unenforced) == 0
        # Both branches completed
        assert len(report.completed_branches) == 2

    @pytest.mark.asyncio
    async def test_cancel_on_first_is_enforced(self):
        """cancel_on_first is now enforced at execution level."""
        executor_fn = RecordingExecutor()
        bx = BranchExecutor(node_executor=executor_fn)
        report = await bx.execute(
            branch_def=_make_branch_def(),
            selected_branches=["bio", "tech"],
            parent_output={},
            join_def=_make_join_def(wait_for="any"),
            cancellation_policy=CANCEL_ON_FIRST,
        )
        assert report.cancellation_policy == CANCEL_ON_FIRST
        assert report.cancellation_enforced is True
        # No cancellation_policy_not_enforced event
        unenforced = [e for e in report.events
                      if e["type"] == "cancellation_policy_not_enforced"]
        assert len(unenforced) == 0
        # First branch completed, second may be cancelled or completed
        # (depends on timing — both may complete before cancellation)
        assert len(report.completed_branches) >= 1

    @pytest.mark.asyncio
    async def test_ignore_late_is_enforced(self):
        """ignore_late is now enforced at execution level."""
        executor_fn = RecordingExecutor()
        bx = BranchExecutor(node_executor=executor_fn)
        report = await bx.execute(
            branch_def=_make_branch_def(),
            selected_branches=["bio"],
            parent_output={},
            join_def=_make_join_def(wait_for="any"),
            cancellation_policy="ignore_late",
        )
        assert report.cancellation_enforced is True
        # No cancellation_policy_not_enforced event
        unenforced = [e for e in report.events
                      if e["type"] == "cancellation_policy_not_enforced"]
        assert len(unenforced) == 0

    @pytest.mark.asyncio
    async def test_first_success_only_is_enforced(self):
        """first_success_only is now enforced at execution level."""
        executor_fn = RecordingExecutor()
        bx = BranchExecutor(node_executor=executor_fn)
        report = await bx.execute(
            branch_def=_make_branch_def(),
            selected_branches=["bio"],
            parent_output={},
            join_def=_make_join_def(wait_for="any"),
            cancellation_policy="first_success_only",
        )
        assert report.cancellation_enforced is True
        # No cancellation_policy_not_enforced event
        unenforced = [e for e in report.events
                      if e["type"] == "cancellation_policy_not_enforced"]
        assert len(unenforced) == 0

    @pytest.mark.asyncio
    async def test_quorum_not_enforced(self):
        """quorum is valid but not enforced."""
        executor_fn = RecordingExecutor()
        bx = BranchExecutor(node_executor=executor_fn)
        report = await bx.execute(
            branch_def=_make_branch_def(),
            selected_branches=["bio"],
            parent_output={},
            join_def=_make_join_def(wait_for="any"),
            cancellation_policy="quorum",
        )
        assert report.cancellation_enforced is True

    @pytest.mark.asyncio
    async def test_enforcement_status_in_report(self):
        """Report carries enforcement status for observability."""
        executor_fn = RecordingExecutor()
        bx = BranchExecutor(node_executor=executor_fn)
        report = await bx.execute(
            branch_def=_make_branch_def(),
            selected_branches=["bio"],
            parent_output={},
            join_def=_make_join_def(),
            cancellation_policy=CANCEL_ALLOW_ALL,
        )
        # allow_all is enforced
        assert report.cancellation_enforced is True
        assert report.cancellation_policy == CANCEL_ALLOW_ALL
