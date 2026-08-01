"""Unit tests for GraphScheduler — execution scheduling logic.

Tests the scheduler independently, without instantiating the full orchestrator.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nodechain.core.blueprint import ChainBlueprint, NodeDef, ConnectionDef, BranchDef, JoinDef, LoopDef
from nodechain.core.state import ChainState, LoopState
from nodechain.runtime.scheduler import GraphScheduler, SchedulingDecision


def _make_sequential_blueprint() -> ChainBlueprint:
    """Minimal 4-node sequential chain."""
    return ChainBlueprint(
        chain_id="test_seq_v1", name="Test Sequential", version="1.0.0", goal="Test.",
        nodes=[
            NodeDef(node_id="goal_interpreter", node_type="model", position=1),
            NodeDef(node_id="task_planner", node_type="model", position=2),
            NodeDef(node_id="response_generator", node_type="model", position=3),
            NodeDef(node_id="trace_collector", node_type="deterministic", position=4),
        ],
        connections=[
            ConnectionDef(from_node="goal_interpreter", from_port="output", to_node="task_planner", to_port="input"),
            ConnectionDef(from_node="task_planner", from_port="output", to_node="response_generator", to_port="input"),
            ConnectionDef(from_node="response_generator", from_port="output", to_node="trace_collector", to_port="input"),
        ],
    )


def _make_branch_blueprint(
    branches=None,
    default_branch=None,
    wait_for="all",
) -> ChainBlueprint:
    """Branch-join blueprint for scheduler tests."""
    if branches is None:
        branches = {"biomedical": ["biomedical_search"], "technical": ["technical_search"], "general": ["general_search"]}

    nodes = [
        NodeDef(node_id="goal_interpreter", node_type="model", position=1),
        NodeDef(node_id="domain_classifier", node_type="deterministic", position=2),
    ]
    connections = [
        ConnectionDef(from_node="goal_interpreter", from_port="output", to_node="domain_classifier", to_port="input"),
    ]
    position = 3
    for branch_name, branch_nodes in branches.items():
        for bn in branch_nodes:
            nodes.append(NodeDef(node_id=bn, node_type="deterministic", position=position))
            position += 1

    nodes.append(NodeDef(node_id="evidence_joiner", node_type="deterministic", position=position))
    position += 1
    nodes.append(NodeDef(node_id="response_generator", node_type="model", position=position))

    # Connect branch nodes to joiner
    for branch_nodes in branches.values():
        for bn in branch_nodes:
            connections.append(ConnectionDef(from_node=bn, from_port="output", to_node="evidence_joiner", to_port="input"))

    connections.append(ConnectionDef(from_node="evidence_joiner", from_port="output", to_node="response_generator", to_port="input"))

    branch_defs = [BranchDef(branch_id="domain_routing", from_node="domain_classifier", branches=branches, default_branch=default_branch)]
    join_defs = [JoinDef(join_id="evidence_merge", to_node="evidence_joiner", from_branches=list(branches.keys()), wait_for=wait_for)]

    return ChainBlueprint(
        chain_id="test_branch_v1", name="Test Branch", version="1.0.0", goal="Test.",
        nodes=nodes, connections=connections, branches=branch_defs, joins=join_defs,
    )


def _make_loop_blueprint() -> ChainBlueprint:
    """Blueprint with a bounded loop."""
    return ChainBlueprint(
        chain_id="test_loop_v1", name="Test Loop", version="1.0.0", goal="Test.",
        nodes=[
            NodeDef(node_id="goal_interpreter", node_type="model", position=1),
            NodeDef(node_id="task_planner", node_type="model", position=2),
            NodeDef(node_id="source_quality_evaluator", node_type="model", position=3),
            NodeDef(node_id="response_generator", node_type="model", position=4),
        ],
        connections=[
            ConnectionDef(from_node="goal_interpreter", from_port="output", to_node="task_planner", to_port="input"),
            ConnectionDef(from_node="task_planner", from_port="output", to_node="source_quality_evaluator", to_port="input"),
            ConnectionDef(from_node="source_quality_evaluator", from_port="output", to_node="response_generator", to_port="input"),
        ],
        loops=[
            LoopDef(
                loop_id="quality_loop",
                entry_condition="insufficient",
                exit_condition="sufficient",
                max_iterations=3,
                path=["task_planner", "source_quality_evaluator"],
            ),
        ],
    )


class TestExecutionOrder:
    """resolve_execution_order tests."""

    def test_sequential_order(self):
        """Sequential blueprint produces correct order."""
        bp = _make_sequential_blueprint()
        scheduler = GraphScheduler(bp)
        order = scheduler.resolve_execution_order()
        assert order == ["goal_interpreter", "task_planner", "response_generator", "trace_collector"]

    def test_branch_nodes_excluded_from_order(self):
        """Branch-only nodes are filtered from execution order."""
        bp = _make_branch_blueprint()
        scheduler = GraphScheduler(bp)
        order = scheduler.resolve_execution_order()
        # Branch nodes should not appear
        assert "biomedical_search" not in order
        assert "technical_search" not in order
        assert "general_search" not in order
        # Backbone nodes should appear
        assert "goal_interpreter" in order
        assert "domain_classifier" in order
        assert "evidence_joiner" in order
        assert "response_generator" in order

    def test_loop_backbone_order(self):
        """Loop blueprint produces correct backbone order."""
        bp = _make_loop_blueprint()
        scheduler = GraphScheduler(bp)
        order = scheduler.resolve_execution_order()
        assert order == ["goal_interpreter", "task_planner", "source_quality_evaluator", "response_generator"]


class TestLoopBack:
    """check_loop_back tests."""

    def test_loop_trigger_returns_loop_back(self):
        """loop_required=True returns LOOP_BACK decision."""
        bp = _make_loop_blueprint()
        scheduler = GraphScheduler(bp)
        state = ChainState(run_id="test")

        output = {"loop_required": True}
        decision = scheduler.check_loop_back("source_quality_evaluator", output, state)

        assert decision is not None
        assert decision.action == SchedulingDecision.LOOP_BACK
        assert decision.target_node == "task_planner"
        assert decision.loop_id == "quality_loop"

    def test_no_loop_trigger_returns_none(self):
        """loop_required=False returns None."""
        bp = _make_loop_blueprint()
        scheduler = GraphScheduler(bp)
        state = ChainState(run_id="test")

        output = {"loop_required": False}
        decision = scheduler.check_loop_back("source_quality_evaluator", output, state)
        assert decision is None

    def test_wrong_node_returns_none(self):
        """Loop trigger from non-loop node returns None."""
        bp = _make_loop_blueprint()
        scheduler = GraphScheduler(bp)
        state = ChainState(run_id="test")

        output = {"loop_required": True}
        decision = scheduler.check_loop_back("response_generator", output, state)
        assert decision is None

    def test_loop_iteration_increments(self):
        """Each loop trigger increments the iteration counter."""
        bp = _make_loop_blueprint()
        scheduler = GraphScheduler(bp)
        state = ChainState(run_id="test")

        output = {"loop_required": True}
        d1 = scheduler.check_loop_back("source_quality_evaluator", output, state)
        assert d1 is not None
        assert state.loop_state["quality_loop"].iteration == 1

        d2 = scheduler.check_loop_back("source_quality_evaluator", output, state)
        assert d2 is not None
        assert state.loop_state["quality_loop"].iteration == 2

    def test_loop_exhaustion_terminates(self):
        """Exceeding max_iterations returns TERMINATE."""
        bp = _make_loop_blueprint()
        scheduler = GraphScheduler(bp)
        state = ChainState(run_id="test")
        state.loop_state["quality_loop"] = LoopState(loop_id="quality_loop", iteration=3, max_iterations=3)

        output = {"loop_required": True}
        decision = scheduler.check_loop_back("source_quality_evaluator", output, state)
        assert decision is not None
        assert decision.action == SchedulingDecision.TERMINATE


class TestRebuildOrder:
    """rebuild_order_with_loop tests."""

    def test_rebuild_inserts_loop_segment(self):
        """Loop rebuild inserts loop path after current node."""
        bp = _make_loop_blueprint()
        scheduler = GraphScheduler(bp)
        order = ["goal_interpreter", "task_planner", "source_quality_evaluator", "response_generator"]

        new_order = scheduler.rebuild_order_with_loop(order, "source_quality_evaluator", "task_planner")

        # After source_quality_evaluator, task_planner..source_quality_evaluator should repeat
        assert "task_planner" in new_order
        # The loop segment should appear after the current node
        sqe_idx = new_order.index("source_quality_evaluator")
        assert new_order[sqe_idx + 1] == "task_planner"

    def test_rebuild_preserves_pre_loop_nodes(self):
        """Nodes before the loop are not duplicated."""
        bp = _make_loop_blueprint()
        scheduler = GraphScheduler(bp)
        order = ["goal_interpreter", "task_planner", "source_quality_evaluator", "response_generator"]

        new_order = scheduler.rebuild_order_with_loop(order, "source_quality_evaluator", "task_planner")

        gi_count = new_order.count("goal_interpreter")
        assert gi_count == 1  # Not duplicated


class TestBranchSelection:
    """resolve_branch_selection tests."""

    def test_explicit_selection(self):
        """Explicit selected_branches is respected."""
        bp = _make_branch_blueprint()
        scheduler = GraphScheduler(bp)

        output = {"selected_branches": ["biomedical", "technical"]}
        selected = scheduler.resolve_branch_selection(bp.branches[0], output)
        assert selected == ["biomedical", "technical"]

    def test_domain_based_selection(self):
        """Domain classification maps to branch names."""
        bp = _make_branch_blueprint()
        scheduler = GraphScheduler(bp)

        output = {"domain_classification": ["biomedical"]}
        selected = scheduler.resolve_branch_selection(bp.branches[0], output)
        assert "biomedical" in selected

    def test_default_branch_fallback(self):
        """No selection → default branch."""
        bp = _make_branch_blueprint(default_branch="general")
        scheduler = GraphScheduler(bp)

        output = {}
        selected = scheduler.resolve_branch_selection(bp.branches[0], output)
        assert selected == ["general"]

    def test_all_branches_when_no_default(self):
        """No selection and no default → all branches."""
        bp = _make_branch_blueprint()
        scheduler = GraphScheduler(bp)

        output = {}
        selected = scheduler.resolve_branch_selection(bp.branches[0], output)
        assert set(selected) == {"biomedical", "technical", "general"}

    def test_multi_domain_selects_multiple(self):
        """Multiple domain classifications select multiple branches."""
        bp = _make_branch_blueprint()
        scheduler = GraphScheduler(bp)

        output = {"domain_classification": ["biomedical", "technical"]}
        selected = scheduler.resolve_branch_selection(bp.branches[0], output)
        assert "biomedical" in selected
        assert "technical" in selected

    def test_selection_preserves_order(self):
        """Selected branches appear in stable order."""
        bp = _make_branch_blueprint()
        scheduler = GraphScheduler(bp)

        output = {"selected_branches": ["general", "biomedical"]}
        selected = scheduler.resolve_branch_selection(bp.branches[0], output)
        assert selected == ["general", "biomedical"]


class TestSkipToJoin:
    """skip_to_join tests."""

    def test_removes_branch_nodes(self):
        """Branch-only nodes are removed from order."""
        bp = _make_branch_blueprint()
        scheduler = GraphScheduler(bp)

        order = ["goal_interpreter", "domain_classifier", "biomedical_search", "technical_search", "general_search", "evidence_joiner", "response_generator"]
        branch_def = bp.branches[0]

        new_order = scheduler.skip_to_join(order, "domain_classifier", branch_def)
        assert "biomedical_search" not in new_order
        assert "technical_search" not in new_order
        assert "general_search" not in new_order
        # Backbone nodes preserved
        assert "goal_interpreter" in new_order
        assert "domain_classifier" in new_order
        assert "evidence_joiner" in new_order
        assert "response_generator" in new_order

    def test_preserves_join_node(self):
        """Join target node is preserved."""
        bp = _make_branch_blueprint()
        scheduler = GraphScheduler(bp)

        order = ["goal_interpreter", "domain_classifier", "biomedical_search", "evidence_joiner", "response_generator"]
        branch_def = bp.branches[0]

        new_order = scheduler.skip_to_join(order, "domain_classifier", branch_def)
        assert "evidence_joiner" in new_order


class TestLoopExhaustion:
    """check_loop_exhaustion tests."""

    def test_no_loop_returns_none(self):
        """Node not in any loop returns None."""
        bp = _make_loop_blueprint()
        scheduler = GraphScheduler(bp)
        state = ChainState(run_id="test")

        result = scheduler.check_loop_exhaustion("goal_interpreter", state)
        assert result is None

    def test_under_limit_returns_none(self):
        """Loop under max_iterations returns None."""
        bp = _make_loop_blueprint()
        scheduler = GraphScheduler(bp)
        state = ChainState(run_id="test")
        state.loop_state["quality_loop"] = LoopState(loop_id="quality_loop", iteration=1, max_iterations=3)

        result = scheduler.check_loop_exhaustion("task_planner", state)
        assert result is None

    def test_at_limit_returns_escalate(self):
        """Loop at max_iterations returns 'escalate'."""
        bp = _make_loop_blueprint()
        scheduler = GraphScheduler(bp)
        state = ChainState(run_id="test")
        state.loop_state["quality_loop"] = LoopState(loop_id="quality_loop", iteration=3, max_iterations=3)

        result = scheduler.check_loop_exhaustion("task_planner", state)
        assert result == "escalate"


class TestGetBranchesFrom:
    """get_branches_from tests."""

    def test_returns_branch_for_branch_node(self):
        """Branch definitions from a branching node."""
        bp = _make_branch_blueprint()
        scheduler = GraphScheduler(bp)

        branches = scheduler.get_branches_from("domain_classifier")
        assert len(branches) == 1
        assert branches[0].branch_id == "domain_routing"

    def test_returns_empty_for_non_branch_node(self):
        """No branches from a non-branching node."""
        bp = _make_branch_blueprint()
        scheduler = GraphScheduler(bp)

        branches = scheduler.get_branches_from("goal_interpreter")
        assert len(branches) == 0


# ── Review Transition Tests ────────────────────────────────────────────


class TestReviewTransitions:
    """Tests for scheduler review decision translation."""

    def _make_scheduler(self) -> GraphScheduler:
        bp = ChainBlueprint(
            chain_id="test", name="Test", version="1.0.0", goal="Test",
            nodes=[
                NodeDef(node_id="goal_interpreter", node_type="model", position=1),
                NodeDef(node_id="task_planner", node_type="model", position=2),
                NodeDef(node_id="search_tool", node_type="deterministic", position=3),
                NodeDef(node_id="risk_classifier", node_type="deterministic", position=4),
                NodeDef(node_id="response_generator", node_type="model", position=5),
            ],
            connections=[
                ConnectionDef(from_node="goal_interpreter", from_port="output", to_node="task_planner", to_port="input"),
                ConnectionDef(from_node="task_planner", from_port="output", to_node="search_tool", to_port="input"),
                ConnectionDef(from_node="search_tool", from_port="output", to_node="risk_classifier", to_port="input"),
                ConnectionDef(from_node="risk_classifier", from_port="output", to_node="response_generator", to_port="input"),
            ],
        )
        return GraphScheduler(bp)

    def test_approve_continues(self):
        scheduler = self._make_scheduler()
        order = scheduler.resolve_execution_order()
        transition = scheduler.apply_review_decision("approve", order, "risk_classifier")
        assert transition.action == "review_approve"
        assert transition.review_decision == "approve"

    def test_reject_terminates(self):
        scheduler = self._make_scheduler()
        order = scheduler.resolve_execution_order()
        transition = scheduler.apply_review_decision("reject", order, "risk_classifier")
        assert transition.action == "review_reject"
        assert transition.reason == "review_rejected"

    def test_revision_routes_to_model_node(self):
        scheduler = self._make_scheduler()
        order = scheduler.resolve_execution_order()
        transition = scheduler.apply_review_decision(
            "request_revision", order, "risk_classifier",
        )
        assert transition.action == "review_revision"
        assert transition.revision_target is not None
        # Should route to a model node before risk_classifier
        assert transition.revision_target == "task_planner"  # Closest model node before risk_classifier

    def test_revision_explicit_target(self):
        scheduler = self._make_scheduler()
        order = scheduler.resolve_execution_order()
        transition = scheduler.apply_review_decision(
            "request_revision", order, "risk_classifier",
            revision_target="goal_interpreter",
        )
        assert transition.revision_target == "goal_interpreter"

    def test_timeout_terminates(self):
        scheduler = self._make_scheduler()
        order = scheduler.resolve_execution_order()
        transition = scheduler.apply_review_decision("timeout", order, "risk_classifier")
        assert transition.action == "review_timeout"
        assert transition.reason == "review_timeout"

    def test_unknown_decision_rejects(self):
        scheduler = self._make_scheduler()
        order = scheduler.resolve_execution_order()
        transition = scheduler.apply_review_decision("telepathy", order, "risk_classifier")
        assert transition.action == "review_reject"
        assert "telepathy" in transition.reason

    def test_find_continuation_point(self):
        scheduler = self._make_scheduler()
        order = scheduler.resolve_execution_order()
        idx = scheduler.find_continuation_point(order, "risk_classifier")
        # Should be the index AFTER risk_classifier
        assert idx == order.index("risk_classifier") + 1
        assert order[idx] == "response_generator"

    def test_find_continuation_point_last_node(self):
        scheduler = self._make_scheduler()
        order = scheduler.resolve_execution_order()
        idx = scheduler.find_continuation_point(order, "response_generator")
        # Past end of order
        assert idx == len(order)
