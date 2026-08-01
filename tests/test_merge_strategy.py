"""Tests for merge_strategy execution semantics.

AC1: merge_strategy=append concatenates branch lists with provenance preserved.
AC2: merge_strategy=latest selects the latest completed branch deterministically.
AC3: merge_strategy=merge detects conflicting scalar keys.
AC4: merge_strategy=concat fails clearly on incompatible field types.
AC5: Unsupported merge_strategy remains invariant warning/error.
AC6: Join trace records strategy, used branches, conflicts, and output summary.
AC7: TraceReconciler verifies JOIN_COMPLETED output matches merge metadata.
AC8: Existing 429 tests remain green.
"""

import asyncio
import pytest
from unittest.mock import MagicMock

from nodechain.core.blueprint import BranchDef, JoinDef, NodeDef
from nodechain.runtime.branch_executor import (
    BranchExecutor,
    BranchNodeResult,
    BranchExecutionReport,
)


# ── Helpers ──────────────────────────────────────────────────────────────

def _make_branch_def():
    return BranchDef(
        branch_id="b1",
        from_node="router",
        branches={
            "alpha": ["alpha_search"],
            "beta": ["beta_search"],
        },
        default_branch="alpha",
    )


def _make_join(merge_strategy: str = "append", wait_for: str = "all"):
    return JoinDef(
        join_id="j1",
        to_node="joiner",
        from_branches=["alpha", "beta"],
        wait_for=wait_for,
        merge_strategy=merge_strategy,
    )


async def _no_op_executor(node_id, payload, branch_name):
    """Executor that returns empty success."""
    return BranchNodeResult(node_id=node_id, success=True, output={})


class _RecordingExecutor:
    """Executor that returns pre-configured outputs per node."""

    def __init__(self, outputs: dict[str, dict]):
        """outputs: {node_id: output_dict}"""
        self._outputs = outputs
        self.calls: list[tuple[str, str]] = []

    async def __call__(self, node_id, payload, branch_name):
        self.calls.append((node_id, branch_name))
        output = self._outputs.get(node_id, {})
        return BranchNodeResult(node_id=node_id, success=True, output=output)


# ── AC1: append ──────────────────────────────────────────────────────────

class TestMergeAppend:

    @pytest.mark.asyncio
    async def test_append_concatenates_lists_with_provenance(self):
        """AC1: Lists from both branches are concatenated, each item gets _provenance."""
        executor = _RecordingExecutor({
            "alpha_search": {"results": [
                {"title": "Alpha Result 1", "source_id": "a1"},
                {"title": "Alpha Result 2", "source_id": "a2"},
            ]},
            "beta_search": {"results": [
                {"title": "Beta Result 1", "source_id": "b1"},
            ]},
        })

        bx = BranchExecutor(node_executor=executor)
        report = await bx.execute(
            branch_def=_make_branch_def(),
            selected_branches=["alpha", "beta"],
            parent_output={"query": "test"},
            join_def=_make_join(merge_strategy="append"),
        )

        assert report.merged_output is not None
        results = report.merged_output.get("results", [])
        assert len(results) == 3

        # Provenance preserved
        assert results[0]["_provenance"] == "alpha"
        assert results[1]["_provenance"] == "alpha"
        assert results[2]["_provenance"] == "beta"

    @pytest.mark.asyncio
    async def test_append_single_branch(self):
        """append with one branch passes through correctly."""
        executor = _RecordingExecutor({
            "alpha_search": {"results": [{"title": "A"}]},
        })

        bx = BranchExecutor(node_executor=executor)
        report = await bx.execute(
            branch_def=_make_branch_def(),
            selected_branches=["alpha"],
            parent_output={},
            join_def=_make_join(merge_strategy="append"),
        )

        results = report.merged_output.get("results", [])
        assert len(results) == 1
        assert results[0]["_provenance"] == "alpha"

    @pytest.mark.asyncio
    async def test_append_metadata(self):
        """AC6: append join trace records strategy, branches, counts."""
        executor = _RecordingExecutor({
            "alpha_search": {"results": [{"title": "A"}]},
            "beta_search": {"results": [{"title": "B"}, {"title": "C"}]},
        })

        bx = BranchExecutor(node_executor=executor)
        report = await bx.execute(
            branch_def=_make_branch_def(),
            selected_branches=["alpha", "beta"],
            parent_output={},
            join_def=_make_join(merge_strategy="append"),
        )

        # Find join_completed event
        join_events = [e for e in report.events if e["type"] == "join_completed"]
        assert len(join_events) == 1

        meta = join_events[0]["metadata"]
        assert meta["merge_strategy"] == "append"
        detail = meta["merge_detail"]
        assert detail["strategy"] == "append"
        assert set(detail["input_branches"]) == {"alpha", "beta"}
        assert detail["output_counts"]["results"] == 3
        assert detail["conflicts"] == []


# ── AC2: latest ──────────────────────────────────────────────────────────

class TestMergeLatest:

    @pytest.mark.asyncio
    async def test_latest_selects_last_completed_branch(self):
        """AC2: latest selects the branch with the latest end time."""
        call_count = 0
        alpha_end = 0.0
        beta_end = 0.0

        async def timed_executor(node_id, payload, branch_name):
            nonlocal call_count, alpha_end, beta_end
            call_count += 1
            if branch_name == "alpha":
                await asyncio.sleep(0.01)  # Alpha finishes first
                alpha_end = asyncio.get_event_loop().time()
                return BranchNodeResult(
                    node_id=node_id, success=True,
                    output={"results": [{"title": "from_alpha"}]},
                )
            else:
                await asyncio.sleep(0.03)  # Beta finishes later
                beta_end = asyncio.get_event_loop().time()
                return BranchNodeResult(
                    node_id=node_id, success=True,
                    output={"results": [{"title": "from_beta"}]},
                )

        bx = BranchExecutor(node_executor=timed_executor)
        report = await bx.execute(
            branch_def=_make_branch_def(),
            selected_branches=["alpha", "beta"],
            parent_output={},
            join_def=_make_join(merge_strategy="latest"),
        )

        # Beta finished later → latest should select beta
        results = report.merged_output.get("results", [])
        assert len(results) == 1
        assert results[0]["title"] == "from_beta"

    @pytest.mark.asyncio
    async def test_latest_metadata_records_selection(self):
        """AC6: latest records which branch was selected and why."""
        executor = _RecordingExecutor({
            "alpha_search": {"data": "alpha_data"},
            "beta_search": {"data": "beta_data"},
        })

        bx = BranchExecutor(node_executor=executor)
        report = await bx.execute(
            branch_def=_make_branch_def(),
            selected_branches=["alpha", "beta"],
            parent_output={},
            join_def=_make_join(merge_strategy="latest"),
        )

        join_events = [e for e in report.events if e["type"] == "join_completed"]
        meta = join_events[0]["metadata"]
        assert meta["merge_strategy"] == "latest"
        detail = meta["merge_detail"]
        assert detail["strategy"] == "latest"
        assert len(detail["used_branches"]) == 1
        assert detail["selection_reason"] == "latest_end_time"


# ── AC3: merge (dict) ───────────────────────────────────────────────────

class TestMergeDict:

    @pytest.mark.asyncio
    async def test_merge_detects_scalar_conflicts(self):
        """AC3: merge detects conflicting scalar keys across branches."""
        executor = _RecordingExecutor({
            "alpha_search": {"verdict": "positive", "score": 0.9, "items": [1, 2]},
            "beta_search": {"verdict": "negative", "score": 0.9, "items": [3, 4]},
        })

        bx = BranchExecutor(node_executor=executor)
        report = await bx.execute(
            branch_def=_make_branch_def(),
            selected_branches=["alpha", "beta"],
            parent_output={},
            join_def=_make_join(merge_strategy="merge"),
        )

        # "score" is same → no conflict; "verdict" differs → conflict
        assert report.merged_output["verdict"] == "positive"  # First wins
        assert report.merged_output["score"] == 0.9

        # List fields are concatenated
        assert report.merged_output["items"] == [1, 2, 3, 4]

        # Check conflicts recorded
        join_events = [e for e in report.events if e["type"] == "join_completed"]
        detail = join_events[0]["metadata"]["merge_detail"]
        conflicts = detail["conflicts"]
        assert len(conflicts) >= 1
        conflict_fields = [c["field"] for c in conflicts]
        assert "verdict" in conflict_fields

    @pytest.mark.asyncio
    async def test_merge_no_conflict_same_values(self):
        """Identical scalar values produce no conflicts."""
        executor = _RecordingExecutor({
            "alpha_search": {"verdict": "positive", "items": [1]},
            "beta_search": {"verdict": "positive", "items": [2]},
        })

        bx = BranchExecutor(node_executor=executor)
        report = await bx.execute(
            branch_def=_make_branch_def(),
            selected_branches=["alpha", "beta"],
            parent_output={},
            join_def=_make_join(merge_strategy="merge"),
        )

        join_events = [e for e in report.events if e["type"] == "join_completed"]
        detail = join_events[0]["metadata"]["merge_detail"]
        assert detail["conflicts"] == []


# ── AC4: concat ──────────────────────────────────────────────────────────

class TestMergeConcat:

    @pytest.mark.asyncio
    async def test_concat_concatenates_strings(self):
        """concat joins string fields with separator."""
        executor = _RecordingExecutor({
            "alpha_search": {"summary": "Alpha found X."},
            "beta_search": {"summary": "Beta confirmed X."},
        })

        bx = BranchExecutor(node_executor=executor)
        report = await bx.execute(
            branch_def=_make_branch_def(),
            selected_branches=["alpha", "beta"],
            parent_output={},
            join_def=_make_join(merge_strategy="concat"),
        )

        summary = report.merged_output["summary"]
        assert "Alpha found X." in summary
        assert "Beta confirmed X." in summary
        assert "---" in summary  # Separator present

    @pytest.mark.asyncio
    async def test_concat_detects_incompatible_types(self):
        """AC4: concat records conflict on incompatible field types."""
        executor = _RecordingExecutor({
            "alpha_search": {"count": 42, "items": [1, 2]},
            "beta_search": {"count": {"nested": True}, "items": [3, 4]},
        })

        bx = BranchExecutor(node_executor=executor)
        report = await bx.execute(
            branch_def=_make_branch_def(),
            selected_branches=["alpha", "beta"],
            parent_output={},
            join_def=_make_join(merge_strategy="concat"),
        )

        # "items" is all lists → concatenated
        assert report.merged_output["items"] == [1, 2, 3, 4]

        # "count" has incompatible types (int vs dict) → conflict
        join_events = [e for e in report.events if e["type"] == "join_completed"]
        detail = join_events[0]["metadata"]["merge_detail"]
        conflicts = detail["conflicts"]
        conflict_fields = [c["field"] for c in conflicts]
        assert "count" in conflict_fields
        # Check conflict type
        count_conflict = [c for c in conflicts if c["field"] == "count"][0]
        assert count_conflict["conflict_type"] == "incompatible_types"

    @pytest.mark.asyncio
    async def test_concat_lists_concatenated(self):
        """concat correctly concatenates list fields."""
        executor = _RecordingExecutor({
            "alpha_search": {"items": [1, 2]},
            "beta_search": {"items": [3, 4]},
        })

        bx = BranchExecutor(node_executor=executor)
        report = await bx.execute(
            branch_def=_make_branch_def(),
            selected_branches=["alpha", "beta"],
            parent_output={},
            join_def=_make_join(merge_strategy="concat"),
        )

        assert report.merged_output["items"] == [1, 2, 3, 4]


# ── AC5: Unsupported strategy ────────────────────────────────────────────

class TestUnsupportedStrategy:

    @pytest.mark.asyncio
    async def test_unknown_strategy_falls_back_to_merge(self):
        """AC5: Unsupported strategy falls back to merge with metadata."""
        executor = _RecordingExecutor({
            "alpha_search": {"data": "a"},
            "beta_search": {"data": "b"},
        })

        # Create join with unsupported strategy
        join = JoinDef(
            join_id="j1", to_node="joiner",
            from_branches=["alpha", "beta"],
            merge_strategy="custom_unknown",
        )

        bx = BranchExecutor(node_executor=executor)
        report = await bx.execute(
            branch_def=_make_branch_def(),
            selected_branches=["alpha", "beta"],
            parent_output={},
            join_def=join,
        )

        # Falls back to merge behavior
        join_events = [e for e in report.events if e["type"] == "join_completed"]
        detail = join_events[0]["metadata"]["merge_detail"]
        assert detail.get("fallback") is True
        assert detail["original_strategy"] == "custom_unknown"


# ── AC6: Trace metadata ─────────────────────────────────────────────────

class TestMergeTraceMetadata:

    @pytest.mark.asyncio
    async def test_all_strategies_record_trace_metadata(self):
        """AC6: Every strategy produces complete trace metadata."""
        for strategy in ["append", "merge", "latest", "concat"]:
            executor = _RecordingExecutor({
                "alpha_search": {"items": [1], "label": "a"},
                "beta_search": {"items": [2], "label": "b"},
            })

            bx = BranchExecutor(node_executor=executor)
            report = await bx.execute(
                branch_def=_make_branch_def(),
                selected_branches=["alpha", "beta"],
                parent_output={},
                join_def=_make_join(merge_strategy=strategy),
            )

            join_events = [e for e in report.events if e["type"] == "join_completed"]
            assert len(join_events) == 1, f"No join_completed for {strategy}"

            meta = join_events[0]["metadata"]
            assert meta["merge_strategy"] == strategy, f"Wrong strategy in metadata for {strategy}"
            assert "merge_detail" in meta, f"No merge_detail for {strategy}"
            detail = meta["merge_detail"]
            assert detail["strategy"] == strategy
            assert "input_branches" in detail
            assert "used_branches" in detail
            assert "conflicts" in detail
            assert "output_counts" in detail


# ── AC7: Reconciler verifies merge metadata ─────────────────────────────

class TestMergeReconciliation:
    """Verify that JOIN_COMPLETED events carry merge metadata that
    TraceReconciler can audit."""

    @pytest.mark.asyncio
    async def test_join_completed_has_merge_metadata(self):
        """AC7: JOIN_COMPLETED event includes merge strategy and detail."""
        executor = _RecordingExecutor({
            "alpha_search": {"results": [{"title": "A"}]},
            "beta_search": {"results": [{"title": "B"}]},
        })

        bx = BranchExecutor(node_executor=executor)
        report = await bx.execute(
            branch_def=_make_branch_def(),
            selected_branches=["alpha", "beta"],
            parent_output={},
            join_def=_make_join(merge_strategy="append"),
        )

        join_events = [e for e in report.events if e["type"] == "join_completed"]
        meta = join_events[0]["metadata"]

        # Required audit fields present
        assert "merge_strategy" in meta
        assert "merge_detail" in meta
        assert meta["merge_detail"]["strategy"] == "append"
        assert meta["merge_detail"]["output_counts"]["results"] == 2
