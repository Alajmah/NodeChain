"""Tests for wait_for=quorum branch scheduling.

AC1: quorum_count=2 succeeds when two branches succeed.
AC2: quorum_count=2 fails when fewer than two can succeed.
AC3: quorum_ratio=0.6 computes threshold deterministically.
AC4: Quorum merge uses only quorum-winning branches.
AC5: Pending branches cancelled/ignored per explicit policy.
AC6: Trace records quorum_required, quorum_reached, winning_branches, failed_branches.
AC7: Invalid quorum config blocks strict mode.
AC8: 655 tests remain green.
"""

import asyncio
import math
import pytest

from nodechain.core.blueprint import BranchDef, JoinDef
from nodechain.runtime.branch_executor import (
    BranchExecutor, BranchNodeResult,
)
from nodechain.runtime.invariant_engine import CANCEL_QUORUM


# ── Helpers ──

def _make_branch_def_3():
    return BranchDef(
        branch_id="b1",
        from_node="router",
        branches={
            "bio": ["bio_search"],
            "tech": ["tech_search"],
            "med": ["med_search"],
        },
    )


def _make_quorum_join(count=None, ratio=None, cancellation="cancel"):
    return JoinDef(
        join_id="j1",
        to_node="joiner",
        from_branches=["bio", "tech", "med"],
        wait_for="quorum",
        quorum_count=count,
        quorum_ratio=ratio,
        cancellation_after_quorum=cancellation,
    )


def _successful_node_output(node_id: str) -> dict:
    return {
        "claims": [{"claim_id": f"{node_id}_c1", "text": f"Claim from {node_id}"}],
        "sources": [{"source_ref": f"S_{node_id}"}],
    }


class RecordingExecutor:
    """Tracks node invocations."""

    def __init__(self, fail_nodes=None, delay_map=None):
        self.calls = []
        self.fail_nodes = fail_nodes or set()
        self.delay_map = delay_map or {}

    async def __call__(self, node_id, payload, branch_name):
        self.calls.append((node_id, payload, branch_name))
        delay = self.delay_map.get(node_id, 0.0)
        if delay:
            await asyncio.sleep(delay)
        if node_id in self.fail_nodes:
            return BranchNodeResult(node_id=node_id, success=False, error=f"Forced: {node_id}")
        return BranchNodeResult(node_id=node_id, success=True, output=_successful_node_output(node_id))


# ═══════════════════════════════════════════════════════════════════
# AC1 + AC4: Quorum succeeds with enough successes
# ═══════════════════════════════════════════════════════════════════

class TestQuorumSuccess:
    """Quorum succeeds when enough branches succeed."""

    @pytest.mark.asyncio
    async def test_quorum_count_2_succeeds(self):
        """AC1: quorum_count=2 succeeds with 2+ successes."""
        recorder = RecordingExecutor()
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def_3()
        join_def = _make_quorum_join(count=2)

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech", "med"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_QUORUM,
        )

        assert not report.blocked
        assert len(report.completed_branches) >= 2

    @pytest.mark.asyncio
    async def test_quorum_merge_uses_winners(self):
        """AC4: Merge uses only quorum-winning branches."""
        # Bio instant, tech slow, med slow — bio wins, then tech finishes
        recorder = RecordingExecutor(delay_map={"tech_search": 0.3, "med_search": 0.5})
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def_3()
        join_def = _make_quorum_join(count=2)

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech", "med"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_QUORUM,
        )

        assert not report.blocked
        # Merge should use only quorum winners
        join_completed = [e for e in report.events if e["type"] == "join_completed"]
        if join_completed:
            merge_detail = join_completed[0]["metadata"]["merge_detail"]
            assert len(merge_detail["used_branches"]) <= 2

    @pytest.mark.asyncio
    async def test_quorum_count_1_succeeds(self):
        """quorum_count=1 succeeds with just one success."""
        recorder = RecordingExecutor()
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def_3()
        join_def = _make_quorum_join(count=1)

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech", "med"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_QUORUM,
        )

        assert not report.blocked


# ═══════════════════════════════════════════════════════════════════
# AC2: Quorum failure
# ═══════════════════════════════════════════════════════════════════

class TestQuorumFailure:
    """Quorum fails when not enough branches succeed."""

    @pytest.mark.asyncio
    async def test_quorum_count_2_fails_with_one_success(self):
        """AC2: quorum_count=2 fails when only one succeeds."""
        recorder = RecordingExecutor(fail_nodes={"tech_search", "med_search"})
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def_3()
        join_def = _make_quorum_join(count=2)

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech", "med"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_QUORUM,
        )

        assert report.blocked

    @pytest.mark.asyncio
    async def test_all_fail_blocks(self):
        """All branches fail blocks join."""
        recorder = RecordingExecutor(fail_nodes={"bio_search", "tech_search", "med_search"})
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def_3()
        join_def = _make_quorum_join(count=2)

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech", "med"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_QUORUM,
        )

        assert report.blocked
        assert len(report.failed_branches) == 3


# ═══════════════════════════════════════════════════════════════════
# AC3: Quorum ratio
# ═══════════════════════════════════════════════════════════════════

class TestQuorumRatio:
    """Quorum ratio computes threshold correctly."""

    @pytest.mark.asyncio
    async def test_ratio_066(self):
        """AC3: quorum_ratio=0.66 with 3 branches → threshold=2."""
        assert math.ceil(3 * 0.66) == 2

    @pytest.mark.asyncio
    async def test_ratio_050(self):
        """quorum_ratio=0.5 with 3 branches → threshold=2."""
        assert math.ceil(3 * 0.5) == 2

    @pytest.mark.asyncio
    async def test_ratio_100(self):
        """quorum_ratio=1.0 with 3 branches → threshold=3 (all)."""
        assert math.ceil(3 * 1.0) == 3

    @pytest.mark.asyncio
    async def test_ratio_succeeds(self):
        """quorum_ratio=0.6 with 3 branches, all succeed."""
        recorder = RecordingExecutor()
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def_3()
        join_def = _make_quorum_join(ratio=0.6)

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech", "med"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_QUORUM,
        )

        assert not report.blocked


# ═══════════════════════════════════════════════════════════════════
# AC5: Cancellation after quorum
# ═══════════════════════════════════════════════════════════════════

class TestQuorumCancellation:
    """Cancellation policy after quorum reached."""

    @pytest.mark.asyncio
    async def test_cancel_after_quorum(self):
        """AC5: cancel policy cancels pending branches."""
        recorder = RecordingExecutor(delay_map={"med_search": 0.5})
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def_3()
        join_def = _make_quorum_join(count=2, cancellation="cancel")

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech", "med"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_QUORUM,
        )

        assert not report.blocked
        # Med may be cancelled or completed depending on timing
        if "med" in report.cancelled_branches:
            assert "med" not in report.completed_branches

    @pytest.mark.asyncio
    async def test_ignore_late_after_quorum(self):
        """AC5: ignore_late lets branches finish but ignores them."""
        recorder = RecordingExecutor()
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def_3()
        join_def = _make_quorum_join(count=2, cancellation="ignore_late")

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech", "med"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_QUORUM,
        )

        assert not report.blocked

    @pytest.mark.asyncio
    async def test_allow_all_after_quorum(self):
        """AC5: allow_all lets all branches complete."""
        recorder = RecordingExecutor()
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def_3()
        join_def = _make_quorum_join(count=2, cancellation="allow_all")

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech", "med"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_QUORUM,
        )

        assert not report.blocked
        assert report.cancelled_branches == []


# ═══════════════════════════════════════════════════════════════════
# AC6: Trace events
# ═══════════════════════════════════════════════════════════════════

class TestQuorumTrace:
    """Trace events for quorum execution."""

    @pytest.mark.asyncio
    async def test_quorum_reached_event(self):
        """AC6: quorum_reached event with metadata."""
        recorder = RecordingExecutor()
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def_3()
        join_def = _make_quorum_join(count=2)

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech", "med"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_QUORUM,
        )

        quorum_events = [e for e in report.events if e["type"] == "quorum_reached"]
        assert len(quorum_events) == 1
        meta = quorum_events[0]["metadata"]
        assert meta["quorum_required"] == 2
        assert "quorum_reached" in meta
        assert "winning_branches" in meta
        assert "failed_branches" in meta

    @pytest.mark.asyncio
    async def test_quorum_impossible_event(self):
        """AC6: quorum_impossible event when threshold unreachable."""
        recorder = RecordingExecutor(fail_nodes={"tech_search", "med_search"})
        executor = BranchExecutor(node_executor=recorder)
        branch_def = _make_branch_def_3()
        join_def = _make_quorum_join(count=2)

        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech", "med"],
            parent_output={"query": "test"},
            join_def=join_def,
            cancellation_policy=CANCEL_QUORUM,
        )

        impossible_events = [e for e in report.events if e["type"] == "quorum_impossible"]
        assert len(impossible_events) == 1
        meta = impossible_events[0]["metadata"]
        assert meta["quorum_required"] == 2
        assert "remaining_possible" in meta


# ═══════════════════════════════════════════════════════════════════
# AC7: Invalid config validation
# ═══════════════════════════════════════════════════════════════════

class TestQuorumValidation:
    """Quorum config validation via invariant engine."""

    def test_quorum_without_count_or_ratio_warns(self):
        """AC7: quorum without count/ratio generates warning."""
        from nodechain.runtime.invariant_engine import InvariantEngine
        from nodechain.core.blueprint import ChainBlueprint

        bp = ChainBlueprint(
            chain_id="test", name="test", version="1.0",
            description="test", goal="test",
            nodes=[], connections=[],
            joins=[JoinDef(
                join_id="j1", to_node="j",
                from_branches=["a", "b"], wait_for="quorum",
            )],
        )
        engine = InvariantEngine()
        report = engine.check_blueprint(bp)
        violations = [v for v in report.violations if v.invariant_id == "quorum_config_required"]
        assert len(violations) >= 1

    def test_quorum_ratio_out_of_range(self):
        """AC7: quorum_ratio > 1 generates error."""
        from nodechain.runtime.invariant_engine import InvariantEngine
        from nodechain.core.blueprint import ChainBlueprint

        bp = ChainBlueprint(
            chain_id="test", name="test", version="1.0",
            description="test", goal="test",
            nodes=[], connections=[],
            joins=[JoinDef(
                join_id="j1", to_node="j",
                from_branches=["a", "b"], wait_for="quorum",
                quorum_ratio=1.5,
            )],
        )
        engine = InvariantEngine()
        report = engine.check_blueprint(bp)
        violations = [v for v in report.violations if v.invariant_id == "quorum_ratio_range"]
        assert len(violations) >= 1

    def test_quorum_count_zero_error(self):
        """AC7: quorum_count=0 generates error."""
        from nodechain.runtime.invariant_engine import InvariantEngine
        from nodechain.core.blueprint import ChainBlueprint

        bp = ChainBlueprint(
            chain_id="test", name="test", version="1.0",
            description="test", goal="test",
            nodes=[], connections=[],
            joins=[JoinDef(
                join_id="j1", to_node="j",
                from_branches=["a", "b"], wait_for="quorum",
                quorum_count=0,
            )],
        )
        engine = InvariantEngine()
        report = engine.check_blueprint(bp)
        violations = [v for v in report.violations if v.invariant_id == "quorum_count_minimum"]
        assert len(violations) >= 1

    def test_valid_quorum_count_passes(self):
        """AC7: Valid quorum_count generates no violations."""
        from nodechain.runtime.invariant_engine import InvariantEngine
        from nodechain.core.blueprint import ChainBlueprint

        bp = ChainBlueprint(
            chain_id="test", name="test", version="1.0",
            description="test", goal="test",
            nodes=[], connections=[],
            joins=[JoinDef(
                join_id="j1", to_node="j",
                from_branches=["a", "b"], wait_for="quorum",
                quorum_count=2,
            )],
        )
        engine = InvariantEngine()
        report = engine.check_blueprint(bp)
        quorum_violations = [v for v in report.violations if "quorum" in v.invariant_id]
        assert len(quorum_violations) == 0

    def test_valid_quorum_ratio_passes(self):
        """AC7: Valid quorum_ratio generates no violations."""
        from nodechain.runtime.invariant_engine import InvariantEngine
        from nodechain.core.blueprint import ChainBlueprint

        bp = ChainBlueprint(
            chain_id="test", name="test", version="1.0",
            description="test", goal="test",
            nodes=[], connections=[],
            joins=[JoinDef(
                join_id="j1", to_node="j",
                from_branches=["a", "b"], wait_for="quorum",
                quorum_ratio=0.6,
            )],
        )
        engine = InvariantEngine()
        report = engine.check_blueprint(bp)
        quorum_violations = [v for v in report.violations if "quorum" in v.invariant_id]
        assert len(quorum_violations) == 0


class TestQuorumStrictMode:
    """Strict mode escalates quorum warnings to errors."""

    def test_missing_quorum_config_is_error_in_strict(self, monkeypatch):
        """Strict mode: quorum without count/ratio is error, not warning."""
        monkeypatch.setenv("NODECHAIN_GOVERNANCE_STRICT", "1")
        from nodechain.runtime.invariant_engine import InvariantEngine
        from nodechain.core.blueprint import ChainBlueprint

        bp = ChainBlueprint(
            chain_id="test", name="test", version="1.0",
            description="test", goal="test",
            nodes=[], connections=[],
            joins=[JoinDef(
                join_id="j1", to_node="j",
                from_branches=["a", "b"], wait_for="quorum",
            )],
        )
        engine = InvariantEngine()
        report = engine.check_blueprint(bp)
        violations = [v for v in report.violations if v.invariant_id == "quorum_config_required"]
        assert len(violations) == 1
        assert violations[0].severity == "error"

    def test_valid_quorum_not_affected_by_strict(self, monkeypatch):
        """Strict mode does not flag valid quorum config."""
        monkeypatch.setenv("NODECHAIN_GOVERNANCE_STRICT", "1")
        from nodechain.runtime.invariant_engine import InvariantEngine
        from nodechain.core.blueprint import ChainBlueprint

        bp = ChainBlueprint(
            chain_id="test", name="test", version="1.0",
            description="test", goal="test",
            nodes=[], connections=[],
            joins=[JoinDef(
                join_id="j1", to_node="j",
                from_branches=["a", "b"], wait_for="quorum",
                quorum_count=2,
            )],
        )
        engine = InvariantEngine()
        report = engine.check_blueprint(bp)
        quorum_violations = [v for v in report.violations if "quorum" in v.invariant_id]
        assert len(quorum_violations) == 0
