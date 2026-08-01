"""Branch Executor — parallel branch execution and join semantics.

Owns:
- Branch state initialization (pending/running/completed/failed/skipped)
- Parallel branch launch via asyncio.gather()
- Branch-local node execution (sequential within branch)
- Failure isolation (one branch failure doesn't corrupt others)
- wait_for semantics (all/any/first)
- Join input construction and merge
- Branch timings
- Cancellation policy evaluation

Does NOT own:
- Backbone execution (orchestrator)
- Policy gate evaluation (delegates to caller)
- State persistence (delegates to caller)
- Trace emission (returns events for caller to emit)
"""

from __future__ import annotations

import asyncio
import time as _time
from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable

from nodechain.runtime.invariant_engine import (
    CANCEL_ALLOW_ALL, CANCEL_ON_FIRST, CANCEL_IGNORE_LATE,
    CANCEL_FIRST_SUCCESS_ONLY, CANCEL_QUORUM,
)


def _truncate(value: Any, max_len: int = 200) -> Any:
    """Truncate a value for conflict metadata display."""
    if isinstance(value, str) and len(value) > max_len:
        return value[:max_len] + "..."
    if isinstance(value, list) and len(value) > 5:
        return f"[{len(value)} items]"
    if isinstance(value, dict) and len(value) > 5:
        return f"{{dict with {len(value)} keys}}"
    return value


@dataclass
class BranchNodeResult:
    """Result from executing a single node within a branch."""
    node_id: str
    success: bool
    output: dict[str, Any] | None = None
    error: str | None = None


@dataclass
class BranchResult:
    """Result from executing a single branch."""
    branch_name: str
    skipped: bool = False
    failed: bool = False
    cancelled: bool = False
    failure_reason: str | None = None
    failed_node_id: str | None = None
    cancelled_node_id: str | None = None
    cancel_phase: str | None = None  # "during_invocation" | "before_start"
    outputs: dict[str, dict[str, Any]] = field(default_factory=dict)
    duration_ms: float = 0.0
    _start_time: float = 0.0
    _end_time: float = 0.0


@dataclass
class BranchExecutionReport:
    """Full report from executing all branches and computing join."""
    # Branch classification
    selected_branches: list[str] = field(default_factory=list)
    completed_branches: list[str] = field(default_factory=list)
    failed_branches: list[str] = field(default_factory=list)
    cancelled_branches: list[str] = field(default_factory=list)
    skipped_branches: list[str] = field(default_factory=list)
    ignored_branches: list[str] = field(default_factory=list)

    # Outputs
    branch_outputs: dict[str, dict[str, Any]] = field(default_factory=dict)
    branch_timings: dict[str, dict[str, float]] = field(default_factory=dict)

    # Join
    join_id: str = "unknown"
    wait_for: str = "all"
    join_meta: dict[str, Any] = field(default_factory=dict)
    merged_output: dict[str, Any] = field(default_factory=dict)
    first_completed_branch: str | None = None

    # Status
    partial: bool = False
    blocked: bool = False
    block_reason: str | None = None

    # Cancellation
    cancellation_policy: str = CANCEL_ALLOW_ALL
    cancellation_enforced: bool = False  # True if BranchExecutor actively enforces it

    # Events to emit (caller emits these)
    events: list[dict[str, Any]] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return not self.blocked


# Type for the node execution callback
NodeExecutor = Callable[
    [str, dict[str, Any], str],  # node_id, payload, branch_name
    Awaitable[BranchNodeResult]
]


class BranchExecutor:
    """Executes branches in parallel and produces a BranchExecutionReport.

    Usage:
        executor = BranchExecutor(node_executor=my_invoke_func)
        report = await executor.execute(
            branch_def=branch_def,
            selected_branches=["bio", "tech"],
            parent_output=some_output,
            join_def=join_def,
            cancellation_policy="allow_all",
        )
    """

    def __init__(self, node_executor: NodeExecutor):
        """Initialize with a callback for executing individual nodes.

        Args:
            node_executor: Async callable(node_id, payload, branch_name) -> BranchNodeResult
        """
        self._node_executor = node_executor

    async def execute(
        self,
        branch_def: Any,  # BranchDef — avoids circular import
        selected_branches: list[str],
        parent_output: dict[str, Any],
        join_def: Any = None,  # JoinDef
        cancellation_policy: str = "allow_all",
    ) -> BranchExecutionReport:
        """Execute selected branches and produce a full report.

        The caller is responsible for:
        - Updating branch_states in ChainState
        - Persisting state
        - Emitting trace events from report.events
        """
        report = BranchExecutionReport(
            selected_branches=selected_branches,
            join_id=join_def.join_id if join_def else "unknown",
            wait_for=join_def.wait_for if join_def else "all",
            cancellation_policy=cancellation_policy,
        )

        # ── Track cancellation enforcement status ──
        # allow_all and ignore_late are enforced at execution level.
        # Other policies are validated (by InvariantEngine) but not yet
        # enforced during execution.
        if cancellation_policy == CANCEL_ALLOW_ALL:
            report.cancellation_enforced = True
        elif cancellation_policy == CANCEL_IGNORE_LATE:
            report.cancellation_enforced = True
        elif cancellation_policy in (CANCEL_ON_FIRST, CANCEL_FIRST_SUCCESS_ONLY):
            report.cancellation_enforced = True
        elif cancellation_policy in (CANCEL_QUORUM,):
            report.cancellation_enforced = True

        all_branch_names = list(branch_def.branches.keys())
        report.events.append({
            "type": "routing_decision",
            "node_id": branch_def.from_node,
            "metadata": {
                "selected": selected_branches,
                "available": all_branch_names,
                "skipped": [b for b in all_branch_names if b not in selected_branches],
            },
        })

        # ── Handle skipped branches ──
        for branch_name in all_branch_names:
            if branch_name not in selected_branches:
                report.skipped_branches.append(branch_name)
                report.branch_outputs[branch_name] = {
                    "skipped": True, "branch": branch_name,
                }
                report.events.append({
                    "type": "branch_skipped",
                    "node_id": branch_def.from_node,
                    "metadata": {"branch": branch_name},
                })

        # ── Execute selected branches concurrently ──
        selected_to_run = [b for b in all_branch_names if b in selected_branches]
        first_completed: str | None = None

        # Resolve wait_for early (needed for execution path selection)
        wait_for = join_def.wait_for if join_def else "all"

        if selected_to_run:
            # Emit branch_started events
            for bname in selected_to_run:
                report.events.append({
                    "type": "branch_started",
                    "node_id": branch_def.from_node,
                    "metadata": {
                        "branch": bname,
                        "nodes": branch_def.branches[bname],
                    },
                })

            if cancellation_policy in (CANCEL_ON_FIRST, CANCEL_FIRST_SUCCESS_ONLY):
                # cancel_on_first / first_success_only: cancel pending after first success
                first_completed = await self._execute_with_cancel_on_first(
                    branch_def, selected_to_run, parent_output, report,
                    policy_name=cancellation_policy,
                )
            elif wait_for == "quorum" and join_def:
                # Quorum: accumulate successes until threshold met
                first_completed = await self._execute_with_quorum(
                    branch_def, selected_to_run, parent_output, report, join_def,
                )
            else:
                # Default path: gather all, no cancellation
                tasks = [
                    self._run_branch(bname, branch_def.branches[bname], parent_output)
                    for bname in selected_to_run
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                for result in results:
                    if isinstance(result, Exception):
                        report.branch_outputs["unknown"] = {
                            "failed": True, "failure_reason": str(result),
                        }
                        report.failed_branches.append("unknown")
                        continue

                    br: BranchResult = result
                    first_completed = self._classify_branch_result(
                        br, branch_def, report, first_completed,
                    )

        report.first_completed_branch = first_completed

        # ── Join semantics ──

        report.partial = bool(report.failed_branches or report.cancelled_branches)

        if wait_for == "all" and report.failed_branches:
            report.blocked = True
            report.block_reason = (
                f"Join '{report.join_id}' blocked: "
                f"branches {report.failed_branches} failed with wait_for=all"
            )
            report.events.append({
                "type": "join_blocked",
                "node_id": join_def.to_node if join_def else "join",
                "metadata": {
                    "reason": report.block_reason,
                    "join_id": report.join_id,
                    "wait_for": wait_for,
                    "completed_branches": report.completed_branches,
                    "failed_branches": report.failed_branches,
                    "skipped_branches": report.skipped_branches,
                },
            })
            return report

        if wait_for == "any" and not report.completed_branches:
            report.blocked = True
            report.block_reason = (
                f"Join '{report.join_id}' blocked: "
                f"no branches completed with wait_for=any"
            )
            report.events.append({
                "type": "join_blocked",
                "node_id": join_def.to_node if join_def else "join",
                "metadata": {
                    "reason": report.block_reason,
                    "join_id": report.join_id,
                    "wait_for": wait_for,
                    "completed_branches": report.completed_branches,
                    "failed_branches": report.failed_branches,
                },
            })
            return report

        # ── Quorum blocking check ──
        if wait_for == "quorum" and join_def:
            threshold = self._compute_quorum_threshold(join_def, selected_branches)
            if len(report.completed_branches) < threshold:
                report.blocked = True
                report.block_reason = (
                    f"Join '{report.join_id}' blocked: "
                    f"quorum not met ({len(report.completed_branches)}/{threshold})"
                )
                report.events.append({
                    "type": "join_blocked",
                    "node_id": join_def.to_node if join_def else "join",
                    "metadata": {
                        "reason": report.block_reason,
                        "join_id": report.join_id,
                        "wait_for": "quorum",
                        "quorum_required": threshold,
                        "completed_branches": report.completed_branches,
                        "failed_branches": report.failed_branches,
                        "cancelled_branches": report.cancelled_branches,
                    },
                })
                return report

        # ── ignore_late policy overlay on wait_for=any ──
        # When cancellation_policy=ignore_late, join uses only the first
        # successful branch output. Later successful branches are classified
        # as ignored_late. This is result classification, not task cancellation.
        if (cancellation_policy == CANCEL_IGNORE_LATE
                and wait_for in ("any", "first")
                and report.completed_branches):
            first_branch = report.first_completed_branch
            late_branches = [
                b for b in report.completed_branches if b != first_branch
            ]
            report.ignored_branches.extend(late_branches)

            report.events.append({
                "type": "ignore_late_enforced",
                "node_id": join_def.to_node if join_def else "join",
                "metadata": {
                    "join_id": report.join_id,
                    "wait_for": wait_for,
                    "cancellation_policy": "ignore_late",
                    "first_accepted_branch": first_branch,
                    "ignored_late_branches": late_branches,
                    "failed_branches": report.failed_branches,
                },
            })

            # For merge, only use the first accepted branch
            report._first_merge_branches = [first_branch]  # type: ignore[attr-defined]

        if wait_for == "first":
            # First successful branch determines join input.
            # Later branch outputs are marked ignored_late for join purposes.
            if not report.completed_branches:
                # All branches failed — join is blocked
                report.blocked = True
                report.block_reason = (
                    f"Join '{report.join_id}' blocked: "
                    f"all branches failed with wait_for=first"
                )
                report.events.append({
                    "type": "join_blocked",
                    "node_id": join_def.to_node if join_def else "join",
                    "metadata": {
                        "reason": report.block_reason,
                        "join_id": report.join_id,
                        "wait_for": wait_for,
                        "completed_branches": report.completed_branches,
                        "failed_branches": report.failed_branches,
                    },
                })
                return report

            # Mark later branches as ignored_late
            first_branch = report.first_completed_branch
            late_branches = [
                b for b in report.completed_branches if b != first_branch
            ]
            report.ignored_branches.extend(late_branches)

            report.events.append({
                "type": "first_branch_selected",
                "node_id": join_def.to_node if join_def else "join",
                "metadata": {
                    "join_id": report.join_id,
                    "wait_for": "first",
                    "first_completed_branch": first_branch,
                    "ignored_late_branches": late_branches,
                    "failed_branches": report.failed_branches,
                },
            })

            # For merge, only use the first completed branch
            # Override completed_branches for merge step
            report._first_merge_branches = [first_branch]  # type: ignore[attr-defined]

        # ── Build join metadata ──
        report.join_meta = {
            "join_id": report.join_id,
            "wait_for": wait_for,
            "selected_branches": selected_branches,
            "completed_branches": report.completed_branches,
            "failed_branches": report.failed_branches,
            "cancelled_branches": report.cancelled_branches,
            "skipped_branches": report.skipped_branches,
            "ignored_branches": report.ignored_branches,
            "partial": report.partial,
            "branch_timings": report.branch_timings,
        }
        if first_completed:
            report.join_meta["first_completed_branch"] = first_completed

        # ── Determine join event type ──
        if report.partial and report.completed_branches:
            event_type = "join_partial"
        else:
            event_type = "join_ready"

        report.events.append({
            "type": event_type,
            "node_id": join_def.to_node if join_def else "join",
            "metadata": report.join_meta,
        })

        # ── Merge branch outputs using declared strategy ──
        merge_strategy = join_def.merge_strategy if join_def else "merge"
        # For wait_for=first, only merge the first completed branch
        merge_branches = report.completed_branches
        if hasattr(report, '_first_merge_branches'):
            merge_branches = report._first_merge_branches  # type: ignore[attr-defined]

        merged, merge_meta = self._merge_branch_outputs(
            strategy=merge_strategy,
            branch_outputs=report.branch_outputs,
            completed_branches=merge_branches,
            branch_timings=report.branch_timings,
        )

        merged["branch_outputs"] = report.branch_outputs
        report.merged_output = merged

        # Join trace metadata includes merge strategy audit
        join_completed_meta = {
            **report.join_meta,
            "merge_strategy": merge_strategy,
            "merge_detail": merge_meta,
        }

        report.events.append({
            "type": "join_completed",
            "node_id": join_def.to_node if join_def else "join",
            "metadata": join_completed_meta,
        })

        return report

    # ── Merge Strategies ────────────────────────────────────────

    def _merge_branch_outputs(
        self,
        strategy: str,
        branch_outputs: dict[str, dict[str, Any]],
        completed_branches: list[str],
        branch_timings: dict[str, dict[str, Any]],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Apply merge strategy to completed branch outputs.

        Returns:
            (merged_output, merge_metadata) — merged_output is the joined
            payload for the join node. merge_metadata records strategy,
            branches used, conflicts, and output counts for trace audit.
        """
        if strategy == "append":
            return self._merge_append(branch_outputs, completed_branches)
        elif strategy == "merge":
            return self._merge_dict(branch_outputs, completed_branches)
        elif strategy == "latest":
            return self._merge_latest(
                branch_outputs, completed_branches, branch_timings,
            )
        elif strategy == "concat":
            return self._merge_concat(branch_outputs, completed_branches)
        else:
            # Unknown strategy — fall back to merge with warning
            merged, meta = self._merge_dict(branch_outputs, completed_branches)
            meta["fallback"] = True
            meta["original_strategy"] = strategy
            return merged, meta

    def _collect_outputs(
        self,
        branch_outputs: dict[str, dict[str, Any]],
        completed_branches: list[str],
    ) -> dict[str, list[dict[str, Any]]]:
        """Collect per-node outputs from completed branches, keyed by field.

        Returns: {field_name: [(branch_name, value), ...]}
        """
        field_values: dict[str, list[tuple[str, Any]]] = {}
        for bname in completed_branches:
            bout = branch_outputs.get(bname, {})
            for nid, noutput in bout.get("outputs", {}).items():
                if not isinstance(noutput, dict):
                    continue
                for key, value in noutput.items():
                    if key not in field_values:
                        field_values[key] = []
                    field_values[key].append((bname, value))
        return field_values

    def _merge_append(
        self,
        branch_outputs: dict[str, dict[str, Any]],
        completed_branches: list[str],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """append: concatenate list outputs, preserving branch provenance.

        List fields are concatenated. Scalar fields from later branches
        overwrite earlier ones (last-writer-wins for scalars).
        Each item gets a `_provenance` field recording its branch.
        """
        field_values = self._collect_outputs(branch_outputs, completed_branches)
        merged: dict[str, Any] = {}
        output_counts: dict[str, int] = {}

        for field, entries in field_values.items():
            # Check if all values are lists
            list_entries = [(b, v) for b, v in entries if isinstance(v, list)]
            if list_entries and len(list_entries) == len(entries):
                # All values are lists — concatenate with provenance
                combined = []
                for branch_name, items in list_entries:
                    for item in items:
                        if isinstance(item, dict):
                            item = {**item, "_provenance": branch_name}
                        combined.append(item)
                merged[field] = combined
                output_counts[field] = len(combined)
            else:
                # Scalar or mixed — last writer wins
                for branch_name, value in entries:
                    merged[field] = value
                output_counts[field] = len(entries)

        meta = {
            "strategy": "append",
            "input_branches": completed_branches,
            "used_branches": completed_branches,
            "conflicts": [],
            "output_counts": output_counts,
        }
        return merged, meta

    def _merge_dict(
        self,
        branch_outputs: dict[str, dict[str, Any]],
        completed_branches: list[str],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """merge: combine branch dictionaries by key; detect scalar conflicts.

        Each output field is taken from the first branch that provides it.
        If multiple branches provide different scalar values for the same
        key, a conflict is recorded and the first branch wins.
        List fields are concatenated.
        """
        field_values = self._collect_outputs(branch_outputs, completed_branches)
        merged: dict[str, Any] = {}
        conflicts: list[dict[str, Any]] = []
        output_counts: dict[str, int] = {}

        for field, entries in field_values.items():
            if len(entries) == 1:
                # Single source — no conflict possible
                merged[field] = entries[0][1]
                output_counts[field] = (
                    len(entries[0][1]) if isinstance(entries[0][1], list) else 1
                )
                continue

            values = [v for _, v in entries]
            all_lists = all(isinstance(v, list) for v in values)

            if all_lists:
                # All list values — concatenate
                combined = []
                for branch_name, items in entries:
                    combined.extend(items)
                merged[field] = combined
                output_counts[field] = len(combined)
            else:
                # Scalar or mixed — check for conflicts
                first_branch, first_value = entries[0]
                merged[field] = first_value
                output_counts[field] = 1

                for branch_name, value in entries[1:]:
                    if value != first_value:
                        conflicts.append({
                            "field": field,
                            "conflict_type": "scalar_key_conflict",
                            "branches": [first_branch, branch_name],
                            "values": {
                                first_branch: _truncate(first_value),
                                branch_name: _truncate(value),
                            },
                        })
                        break  # One conflict per field is enough

        meta = {
            "strategy": "merge",
            "input_branches": completed_branches,
            "used_branches": completed_branches,
            "conflicts": conflicts,
            "output_counts": output_counts,
        }
        return merged, meta

    def _merge_latest(
        self,
        branch_outputs: dict[str, dict[str, Any]],
        completed_branches: list[str],
        branch_timings: dict[str, dict[str, Any]],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """latest: select output from the latest completed branch.

        Deterministic tie-breaking: latest by end_time, then alphabetical
        branch name for identical timestamps.
        """
        if not completed_branches:
            return {}, {"strategy": "latest", "used_branches": [], "conflicts": []}

        # Find latest branch by end time
        latest_branch = max(
            completed_branches,
            key=lambda b: (
                branch_timings.get(b, {}).get("end", 0),
                # Tie-break: reverse alphabetical (deterministic)
                b,
            ),
        )

        # Collect all outputs from the latest branch
        merged: dict[str, Any] = {}
        bout = branch_outputs.get(latest_branch, {})
        output_counts: dict[str, int] = {}
        for nid, noutput in bout.get("outputs", {}).items():
            if isinstance(noutput, dict):
                for key, value in noutput.items():
                    merged[key] = value
                    output_counts[key] = (
                        len(value) if isinstance(value, list) else 1
                    )

        meta = {
            "strategy": "latest",
            "input_branches": completed_branches,
            "used_branches": [latest_branch],
            "conflicts": [],
            "selection_reason": "latest_end_time",
            "output_counts": output_counts,
        }
        return merged, meta

    def _merge_concat(
        self,
        branch_outputs: dict[str, dict[str, Any]],
        completed_branches: list[str],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """concat: concatenate string/list fields; error on incompatible types.

        Only list and string fields are concatenated. If a field has
        incompatible types across branches (e.g. int + dict), the field
        is skipped and recorded as a conflict.
        """
        field_values = self._collect_outputs(branch_outputs, completed_branches)
        merged: dict[str, Any] = {}
        conflicts: list[dict[str, Any]] = []
        output_counts: dict[str, int] = {}

        for field, entries in field_values.items():
            if len(entries) == 1:
                merged[field] = entries[0][1]
                output_counts[field] = (
                    len(entries[0][1]) if isinstance(entries[0][1], (list, str)) else 1
                )
                continue

            values = [v for _, v in entries]
            types = set(type(v).__name__ for v in values)

            # All lists → concatenate
            if all(isinstance(v, list) for v in values):
                combined = []
                for v in values:
                    combined.extend(v)
                merged[field] = combined
                output_counts[field] = len(combined)

            # All strings → concatenate with separator
            elif all(isinstance(v, str) for v in values):
                merged[field] = "\n---\n".join(values)
                output_counts[field] = sum(len(v) for v in values)

            else:
                # Incompatible types — record conflict, use first value
                branch_names = [b for b, _ in entries]
                merged[field] = values[0]
                output_counts[field] = 1
                conflicts.append({
                    "field": field,
                    "conflict_type": "incompatible_types",
                    "branches": branch_names,
                    "types": {b: type(v).__name__ for b, v in entries},
                })

        meta = {
            "strategy": "concat",
            "input_branches": completed_branches,
            "used_branches": completed_branches,
            "conflicts": conflicts,
            "output_counts": output_counts,
        }
        return merged, meta

    def _classify_branch_result(
        self,
        br: BranchResult,
        branch_def: Any,
        report: BranchExecutionReport,
        first_completed: str | None,
    ) -> str | None:
        """Classify a BranchResult into the report. Returns updated first_completed."""
        report.branch_outputs[br.branch_name] = {
            "skipped": br.skipped,
            "branch": br.branch_name,
            "outputs": br.outputs,
            "failed": br.failed,
            "cancelled": br.cancelled,
            "failure_reason": br.failure_reason,
        }
        report.branch_timings[br.branch_name] = {
            "duration_ms": br.duration_ms,
            "start": getattr(br, '_start_time', 0),
            "end": getattr(br, '_end_time', 0),
        }

        if br.cancelled:
            report.cancelled_branches.append(br.branch_name)
            report.events.append({
                "type": "branch_cancelled",
                "node_id": branch_def.from_node,
                "metadata": {
                    "branch": br.branch_name,
                    "cancelled_node_id": br.cancelled_node_id,
                    "cancel_phase": br.cancel_phase,
                    "partial_outputs": list(br.outputs.keys()),
                },
            })
        elif br.skipped:
            report.skipped_branches.append(br.branch_name)
        elif br.failed:
            report.failed_branches.append(br.branch_name)
            report.events.append({
                "type": "branch_failed",
                "node_id": br.failed_node_id or branch_def.from_node,
                "metadata": {
                    "branch": br.branch_name,
                    "node": br.failed_node_id,
                    "error": br.failure_reason,
                    "failure_reason": br.failure_reason,
                },
            })
        else:
            report.completed_branches.append(br.branch_name)
            report.events.append({
                "type": "branch_completed",
                "node_id": branch_def.from_node,
                "metadata": {
                    "branch": br.branch_name,
                    "duration_ms": br.duration_ms,
                },
            })
            if first_completed is None:
                first_completed = br.branch_name

        return first_completed

    async def _execute_with_cancel_on_first(
        self,
        branch_def: Any,
        selected_to_run: list[str],
        parent_output: dict[str, Any],
        report: BranchExecutionReport,
        policy_name: str = "cancel_on_first",
    ) -> str | None:
        """Execute branches with cancel-on-first-success policy.

        Used by both cancel_on_first and first_success_only policies.

        1. Launch all branch tasks concurrently
        2. Wait for completions one at a time
        3. On first successful branch, cancel remaining tasks
        4. Classify all results (completed, failed, cancelled)
        5. Set merge isolation to first completed branch only

        Returns: first_completed branch name, or None.
        """
        first_completed: str | None = None
        cancel_triggered = False

        # Map branch name → asyncio.Task
        branch_tasks: dict[str, asyncio.Task[BranchResult]] = {}
        for bname in selected_to_run:
            task = asyncio.create_task(
                self._run_branch(bname, branch_def.branches[bname], parent_output)
            )
            branch_tasks[bname] = task

        # Process results as they complete
        pending: set[asyncio.Task[BranchResult]] = set(branch_tasks.values())
        while pending:
            done, pending = await asyncio.wait(
                pending, return_when=asyncio.FIRST_COMPLETED,
            )

            for task in done:
                # Find branch name for this task
                bname = self._task_to_branch(task, branch_tasks)

                if task.cancelled():
                    # Task was cancelled before returning
                    br = BranchResult(
                        branch_name=bname,
                        cancelled=True,
                        cancel_phase="during_invocation",
                    )
                    first_completed = self._classify_branch_result(
                        br, branch_def, report, first_completed,
                    )
                    continue

                exc = task.exception()
                if exc is not None:
                    # Task raised an exception (not CancelledError)
                    br = BranchResult(
                        branch_name=bname,
                        failed=True,
                        failure_reason=str(exc),
                    )
                    first_completed = self._classify_branch_result(
                        br, branch_def, report, first_completed,
                    )
                    continue

                br = task.result()
                first_completed = self._classify_branch_result(
                    br, branch_def, report, first_completed,
                )

                # If first success and not yet cancelled others, do it now
                if (not cancel_triggered
                        and not br.failed
                        and not br.cancelled
                        and not br.skipped):
                    cancel_triggered = True
                    # Cancel all remaining pending tasks
                    for pending_task in pending:
                        pending_task.cancel()

        # Emit cancellation summary event
        if cancel_triggered:
            report.events.append({
                "type": f"{policy_name}_enforced",
                "node_id": branch_def.from_node,
                "metadata": {
                    "policy": policy_name,
                    "first_completed_branch": first_completed,
                    "cancelled_branches": report.cancelled_branches,
                    "completed_before_cancel": [
                        b for b in report.completed_branches
                        if b != first_completed
                    ],
                },
            })

        # Merge isolation: only first completed branch enters merge
        if first_completed:
            report._first_merge_branches = [first_completed]  # type: ignore[attr-defined]

        return first_completed

    async def _execute_with_quorum(
        self,
        branch_def: Any,
        selected_to_run: list[str],
        parent_output: dict[str, Any],
        report: BranchExecutionReport,
        join_def: Any,
    ) -> str | None:
        """Execute branches with quorum policy.

        Accumulates successes until quorum threshold is met.
        Applies cancellation_after_quorum policy once quorum is reached.
        Fails early if remaining possible successes cannot reach threshold.

        Returns: first_completed branch name, or None.
        """
        first_completed: str | None = None
        quorum_met = False

        # Compute threshold from quorum_count or quorum_ratio
        threshold = self._compute_quorum_threshold(join_def, selected_to_run)
        after_quorum = join_def.cancellation_after_quorum or "cancel"

        # Map branch name → asyncio.Task
        branch_tasks: dict[str, asyncio.Task[BranchResult]] = {}
        for bname in selected_to_run:
            task = asyncio.create_task(
                self._run_branch(bname, branch_def.branches[bname], parent_output)
            )
            branch_tasks[bname] = task

        # Process results as they complete
        pending: set[asyncio.Task[BranchResult]] = set(branch_tasks.values())
        while pending:
            done, pending = await asyncio.wait(
                pending, return_when=asyncio.FIRST_COMPLETED,
            )

            for task in done:
                bname = self._task_to_branch(task, branch_tasks)

                if task.cancelled():
                    br = BranchResult(
                        branch_name=bname,
                        cancelled=True,
                        cancel_phase="during_invocation",
                    )
                    first_completed = self._classify_branch_result(
                        br, branch_def, report, first_completed,
                    )
                    continue

                exc = task.exception()
                if exc is not None:
                    br = BranchResult(
                        branch_name=bname,
                        failed=True,
                        failure_reason=str(exc),
                    )
                    first_completed = self._classify_branch_result(
                        br, branch_def, report, first_completed,
                    )
                    continue

                br = task.result()
                first_completed = self._classify_branch_result(
                    br, branch_def, report, first_completed,
                )

            # Check if quorum reached
            success_count = len(report.completed_branches)
            remaining_possible = success_count + len(pending)

            if success_count >= threshold and not quorum_met:
                quorum_met = True
                report.events.append({
                    "type": "quorum_reached",
                    "node_id": branch_def.from_node,
                    "metadata": {
                        "join_id": report.join_id,
                        "quorum_required": threshold,
                        "quorum_reached": success_count,
                        "winning_branches": list(report.completed_branches),
                        "failed_branches": list(report.failed_branches),
                        "pending_branches": [
                            self._task_to_branch(t, branch_tasks)
                            for t in pending
                        ],
                        "cancellation_policy": after_quorum,
                    },
                })

                # Apply cancellation policy
                if after_quorum == "cancel":
                    for pending_task in pending:
                        pending_task.cancel()
                elif after_quorum == "ignore_late":
                    # Let them finish but mark as ignored
                    pass  # Will classify as ignored_late after gather
                # "allow_all" lets them complete normally

            # Early failure: remaining possible successes < threshold
            if not quorum_met and remaining_possible < threshold:
                report.events.append({
                    "type": "quorum_impossible",
                    "node_id": branch_def.from_node,
                    "metadata": {
                        "join_id": report.join_id,
                        "quorum_required": threshold,
                        "successes_so_far": success_count,
                        "remaining_possible": remaining_possible,
                        "failed_branches": list(report.failed_branches),
                    },
                })
                # Cancel remaining and fail
                for pending_task in pending:
                    pending_task.cancel()
                # Process cancellations
                # (they'll be caught in next iteration of while loop)

        # Handle ignore_late after all branches complete
        if quorum_met and after_quorum == "ignore_late":
            late_branches = [
                b for b in report.completed_branches
                if b not in [report.first_completed_branch]
            ]
            # Mark late completions as ignored
            for b in list(report.completed_branches):
                if b not in [report.first_completed_branch] and len(report.completed_branches) > threshold:
                    report.ignored_branches.append(b)
            # Trim completed to quorum winners only
            winners = report.completed_branches[:threshold]
            report.completed_branches = winners
            report._first_merge_branches = winners  # type: ignore[attr-defined]
        elif quorum_met:
            # Merge only quorum winners
            winners = report.completed_branches[:threshold]
            report._first_merge_branches = winners  # type: ignore[attr-defined]

        return first_completed

    def _compute_quorum_threshold(self, join_def: Any, selected: list[str]) -> int:
        """Compute integer quorum threshold from join definition."""
        if join_def.quorum_count is not None:
            return join_def.quorum_count
        if join_def.quorum_ratio is not None:
            import math
            return math.ceil(len(selected) * join_def.quorum_ratio)
        # Default: all branches (same as wait_for=all)
        return len(selected)

    @staticmethod
    def _task_to_branch(
        task: asyncio.Task,
        branch_tasks: dict[str, asyncio.Task],
    ) -> str:
        """Reverse-lookup branch name from task."""
        for bname, t in branch_tasks.items():
            if t is task:
                return bname
        return "unknown"

    async def _run_branch(
        self,
        branch_name: str,
        branch_nodes: list[str],
        parent_output: dict[str, Any],
    ) -> BranchResult:
        """Execute a single branch's nodes sequentially.

        Handles CancelledError gracefully: records partial progress
        and marks the result as cancelled with the node that was
        interrupted.
        """
        start_time = _time.monotonic()
        payload = {**parent_output}
        result = BranchResult(branch_name=branch_name)

        for node_id in branch_nodes:
            try:
                node_result = await self._node_executor(node_id, payload, branch_name)
            except asyncio.CancelledError:
                # Branch was cancelled during node execution
                end_time = _time.monotonic()
                result.duration_ms = round((end_time - start_time) * 1000, 1)
                result._start_time = start_time
                result._end_time = end_time
                result.cancelled = True  # type: ignore[attr-defined]
                result.cancelled_node_id = node_id  # type: ignore[attr-defined]
                result.cancel_phase = "during_invocation"  # type: ignore[attr-defined]
                # Preserve outputs from already-completed nodes
                return result
            except Exception as e:
                result.failed = True
                result.failure_reason = f"Node '{node_id}' raised: {e}"
                result.failed_node_id = node_id
                break

            if not node_result.success:
                result.failed = True
                result.failure_reason = node_result.error or f"Node '{node_id}' failed"
                result.failed_node_id = node_id
                result.outputs[node_id] = {"error": node_result.error or "unknown"}
                break

            result.outputs[node_id] = node_result.output or {}
            payload = node_result.output or {}

        end_time = _time.monotonic()
        result.duration_ms = round((end_time - start_time) * 1000, 1)
        result._start_time = start_time
        result._end_time = end_time

        return result
