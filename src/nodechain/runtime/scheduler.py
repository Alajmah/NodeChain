"""Graph Scheduler — execution order, loop routing, branch resolution.

Extracted from Orchestrator to separate scheduling concerns from
invocation, persistence, and trace concerns.
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from nodechain.core.blueprint import ChainBlueprint, BranchDef, LoopDef
from nodechain.core.state import ChainState, LoopState
from nodechain.runtime.loop_enforcer import LoopEnforcer, LoopEnforcementResult

if TYPE_CHECKING:
    pass


class SchedulingDecision:
    """Result of evaluating what to do next after a node completes."""

    CONTINUE = "continue"
    LOOP_BACK = "loop_back"
    SKIP_TO_JOIN = "skip_to_join"
    TERMINATE = "terminate"
    REVIEW_APPROVE = "review_approve"
    REVIEW_REJECT = "review_reject"
    REVIEW_REVISION = "review_revision"
    REVIEW_TIMEOUT = "review_timeout"

    def __init__(
        self,
        action: str,
        *,
        target_node: str | None = None,
        loop_id: str | None = None,
        branch_def: BranchDef | None = None,
        selected_branches: list[str] | None = None,
        reason: str = "",
        review_decision: str | None = None,
        revision_target: str | None = None,
    ):
        self.action = action
        self.target_node = target_node
        self.loop_id = loop_id
        self.branch_def = branch_def
        self.selected_branches = selected_branches or []
        self.reason = reason
        self.review_decision = review_decision
        self.revision_target = revision_target


class GraphScheduler:
    """Manages execution order for chain graphs.

    Responsibilities:
    - Resolve initial execution order from blueprint
    - Detect loop-back conditions in node output
    - Rebuild execution order for loop re-execution
    - Resolve branch selection from node output
    - Compute skip-to-join indices after branch execution
    - Check loop exhaustion limits

    Does NOT:
    - Invoke nodes
    - Persist state
    - Emit trace events
    - Check policies

    These remain in Orchestrator / NodeInvoker / etc.
    """

    def __init__(self, blueprint: ChainBlueprint) -> None:
        self.blueprint = blueprint
        self._loop_enforcer = LoopEnforcer(blueprint)

    def resolve_execution_order(self) -> list[str]:
        """Resolve node execution order from blueprint connections.

        For branch-join blueprints, branch nodes are excluded from the
        main execution order. They are only reached via execute_branches().
        """
        connections = self.blueprint.connections

        # Build adjacency from connections
        successors: dict[str, list[str]] = {}
        predecessors: dict[str, list[str]] = {}
        for c in connections:
            successors.setdefault(c.from_node, []).append(c.to_node)
            predecessors.setdefault(c.to_node, []).append(c.from_node)

        # Find root nodes (no predecessors)
        all_nodes = {n.node_id for n in self.blueprint.nodes}
        roots = [nid for nid in all_nodes if nid not in predecessors]

        # Topological sort via BFS
        order: list[str] = []
        visited: set[str] = set()
        queue = list(roots)

        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            order.append(current)
            for succ in successors.get(current, []):
                if succ not in visited:
                    queue.append(succ)

        # Add any nodes not reachable from roots
        for nid in all_nodes:
            if nid not in visited:
                order.append(nid)

        # Filter out branch-only nodes
        branch_node_ids: set[str] = set()
        for branch_def in self.blueprint.branches:
            for branch_name, node_ids in branch_def.branches.items():
                branch_node_ids.update(node_ids)

        order = [nid for nid in order if nid not in branch_node_ids]
        return order

    def check_loop_exhaustion(
        self, node_id: str, state: ChainState
    ) -> str | None:
        """Check if node is in a loop that has exceeded max iterations.

        Returns 'escalate' if exhausted, None otherwise.
        """
        for loop in self.blueprint.loops:
            if node_id in loop.path:
                loop_id = loop.loop_id
                if loop_id in state.loop_state:
                    ls = state.loop_state[loop_id]
                    if ls.iteration >= loop.max_iterations:
                        return "escalate"
        return None

    def check_loop_back(
        self, node_id: str, output: dict[str, Any], state: ChainState
    ) -> SchedulingDecision | None:
        """Check if a node's output triggers a loop-back.

        Returns a SchedulingDecision with LOOP_BACK action if triggered,
        or None if no loop-back is needed.
        """
        for loop in self.blueprint.loops:
            # Loop-back is triggered from the last node in the loop path
            if node_id != loop.path[-1]:
                continue

            if not output.get("loop_required", False):
                continue

            loop_id = loop.loop_id
            target_node = loop.path[0]

            # Initialize or increment loop state
            if loop_id not in state.loop_state:
                state.loop_state[loop_id] = LoopState(
                    loop_id=loop_id,
                    iteration=0,
                    max_iterations=loop.max_iterations,
                )

            ls = state.loop_state[loop_id]
            if ls.iteration >= loop.max_iterations:
                return SchedulingDecision(
                    SchedulingDecision.TERMINATE,
                    reason=f"Loop '{loop_id}' exhausted: {ls.iteration}/{loop.max_iterations}",
                )

            ls.iteration += 1
            return SchedulingDecision(
                SchedulingDecision.LOOP_BACK,
                target_node=target_node,
                loop_id=loop_id,
                reason=f"Loop '{loop_id}' iteration {ls.iteration}/{loop.max_iterations}",
            )

        return None

    def rebuild_order_with_loop(
        self, current_order: list[str], current_node: str, target_node: str
    ) -> list[str]:
        """Rebuild execution order to include nodes from target_node onwards.

        Re-inserts loop path after the current node position.
        """
        try:
            current_idx = current_order.index(current_node)
        except ValueError:
            current_idx = len(current_order) - 1

        try:
            target_idx = current_order.index(target_node)
        except ValueError:
            return current_order  # Target not in order

        # If target is ahead, normal flow — no rebuild needed
        if target_idx > current_idx:
            return current_order

        # Find loop segment
        loop_segment = current_order[target_idx: current_idx + 1]
        for loop in self.blueprint.loops:
            if target_node in loop.path:
                loop_segment = loop.path
                break

        new_order = current_order[: current_idx + 1]
        new_order.extend(loop_segment)
        new_order.extend(current_order[current_idx + 1:])
        return new_order

    def resolve_branch_selection(
        self, branch_def: BranchDef, node_output: dict[str, Any]
    ) -> list[str]:
        """Determine which branches to execute based on node output.

        Selection logic:
        1. Check output for explicit 'selected_branches'
        2. Check output for 'research_domain' or 'domain_classification'
        3. Fall back to default branch
        4. If no default, select all branches (conservative)
        """
        all_branch_names = list(branch_def.branches.keys())

        # Check explicit selection
        selected = node_output.get("selected_branches", [])
        if selected:
            return [b for b in selected if b in all_branch_names]

        # Check domain-based selection
        domain = node_output.get("research_domain", "")
        domains = node_output.get("domain_classification", [])
        if isinstance(domains, list) and domains:
            selected = []
            for d in domains:
                d_lower = str(d).lower()
                for bname in all_branch_names:
                    if bname.lower() in d_lower or d_lower in bname.lower():
                        if bname not in selected:
                            selected.append(bname)
            if selected:
                return selected
        elif domain and isinstance(domain, str):
            domain_lower = domain.lower()
            for bname in all_branch_names:
                if bname.lower() in domain_lower or domain_lower in bname.lower():
                    return [bname]

        # Fall back to default branch
        if branch_def.default_branch:
            return [branch_def.default_branch]

        # No selection and no default — execute all (conservative)
        return all_branch_names

    def skip_to_join(
        self, execution_order: list[str], from_node: str, branch_def: BranchDef
    ) -> list[str]:
        """Remove branch-only nodes from execution order, keeping join node.

        After branch execution completes, skip past the branch nodes
        to the join target node.
        """
        # Find the join node
        join_node = None
        for join_def in self.blueprint.joins:
            join_node = join_def.to_node
            break

        if not join_node or join_node not in execution_order:
            return execution_order

        # Collect all branch node IDs
        branch_node_ids: set[str] = set()
        for branch_name, node_ids in branch_def.branches.items():
            branch_node_ids.update(node_ids)

        # Remove branch nodes from order (keep everything else)
        filtered = [nid for nid in execution_order if nid not in branch_node_ids]
        return filtered

    def get_branches_from(self, node_id: str) -> list[BranchDef]:
        """Get branch definitions that originate from a node."""
        return self.blueprint.get_branches_from(node_id)

    # ── Review Transitions ──────────────────────────────────────

    def apply_review_decision(
        self,
        review_decision: str,
        execution_order: list[str],
        current_node: str,
        revision_target: str | None = None,
    ) -> SchedulingDecision:
        """Translate a review decision into a scheduling transition.

        Args:
            review_decision: "approve", "reject", "request_revision", "timeout"
            execution_order: Current execution order
            current_node: Node that triggered the review (e.g. risk_classifier)
            revision_target: Node to route back to for revision (if applicable)

        Returns:
            SchedulingDecision with the appropriate action.
        """
        if review_decision == "approve":
            return SchedulingDecision(
                SchedulingDecision.REVIEW_APPROVE,
                reason="review_approved",
                review_decision="approve",
            )

        elif review_decision == "reject":
            return SchedulingDecision(
                SchedulingDecision.REVIEW_REJECT,
                reason="review_rejected",
                review_decision="reject",
            )

        elif review_decision == "request_revision":
            # Default revision target is the first model node before the reviewer
            target = revision_target or self._default_revision_target(execution_order, current_node)
            return SchedulingDecision(
                SchedulingDecision.REVIEW_REVISION,
                target_node=target,
                reason=f"review_revision_to_{target}",
                review_decision="request_revision",
                revision_target=target,
            )

        elif review_decision == "timeout":
            return SchedulingDecision(
                SchedulingDecision.REVIEW_TIMEOUT,
                reason="review_timeout",
                review_decision="timeout",
            )

        else:
            # Unknown decision — treat as reject
            return SchedulingDecision(
                SchedulingDecision.REVIEW_REJECT,
                reason=f"unknown_review_decision:{review_decision}",
                review_decision=review_decision,
            )

    def find_continuation_point(
        self,
        execution_order: list[str],
        current_node: str,
    ) -> int:
        """Find the index to continue execution after a review approval.

        Returns the index of the node AFTER current_node in the
        execution order.
        """
        try:
            idx = execution_order.index(current_node)
        except ValueError:
            return 0
        return idx + 1

    def _default_revision_target(
        self,
        execution_order: list[str],
        current_node: str,
    ) -> str:
        """Determine the default node to route revision back to.

        Strategy: walk backwards from current_node to find the first
        model-type node in the blueprint.
        """
        try:
            current_idx = execution_order.index(current_node)
        except ValueError:
            return execution_order[0] if execution_order else current_node

        # Walk backwards to find a model node
        for i in range(current_idx - 1, -1, -1):
            nid = execution_order[i]
            for ndef in self.blueprint.nodes:
                if ndef.node_id == nid and ndef.node_type == "model":
                    return nid

        # No model node found — route to first node
        return execution_order[0] if execution_order else current_node

    # ── Loop enforcement ────────────────────────────────────────

    def get_loop_for_node(self, node_id: str) -> LoopDef | None:
        """Find the loop definition that contains this node."""
        for loop in self.blueprint.loops:
            if node_id in loop.path:
                return loop
        return None

    def check_loop_entry(
        self, node_id: str, state: ChainState, cost_usd: float = 0.0,
    ) -> LoopEnforcementResult | None:
        """Check entry_condition for a loop.

        Returns None if node is not in any loop or entry is allowed.
        Returns LoopEnforcementResult with allowed=False if entry blocked.
        """
        loop = self.get_loop_for_node(node_id)
        if loop is None:
            return None

        # Only check entry on the first node of the loop path
        if node_id != loop.path[0]:
            return None

        # Skip if loop already active (iteration > 0 means we're in the loop)
        loop_id = loop.loop_id
        if loop_id in state.loop_state and state.loop_state[loop_id].iteration > 0:
            return None

        result = self._loop_enforcer.check_entry(loop, state, cost_usd)
        return result if not result.allowed else None

    def check_loop_budget(
        self, loop_id: str, state: ChainState, cost_usd: float = 0.0,
    ) -> LoopEnforcementResult | None:
        """Check max_cost_usd for a loop.

        Returns None if within budget.
        Returns LoopEnforcementResult with allowed=False if exceeded.
        """
        loop = None
        for l in self.blueprint.loops:
            if l.loop_id == loop_id:
                loop = l
                break
        if loop is None:
            return None

        result = self._loop_enforcer.check_budget(loop, state, cost_usd)
        return result if not result.allowed else None

    def check_loop_exit(
        self, loop_id: str, state: ChainState, cost_usd: float = 0.0,
    ) -> LoopEnforcementResult | None:
        """Check exit_condition for a loop.

        Returns None if loop should continue.
        Returns LoopEnforcementResult with allowed=False if should exit.
        """
        loop = None
        for l in self.blueprint.loops:
            if l.loop_id == loop_id:
                loop = l
                break
        if loop is None:
            return None

        result = self._loop_enforcer.check_exit(loop, state, cost_usd)
        return result if not result.allowed else None

    def get_escalation_message(self, loop_id: str, reason: str) -> str | None:
        """Get escalation message for a loop policy violation."""
        for l in self.blueprint.loops:
            if l.loop_id == loop_id:
                return self._loop_enforcer.get_escalation(l, reason)
        return reason
