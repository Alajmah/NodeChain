"""Batch recovery — orchestration layer over v2.49.0 authorization (v2.50.0).

Allows operators to submit multiple recovery actions as one explicit, auditable
YAML batch. Each action inside the batch is authorized independently — a batch
is not authorized as a unit.

Non-atomic: v2.50.0 does not support rollback.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from nodechain.runtime.recovery_policy import RecoveryAction


MAX_BATCH_ACTIONS = 100  # Structural maximum; profile-specific limits enforced in BatchExecutor


@dataclass(frozen=True)
class BatchAction:
    """One action inside a recovery batch."""

    action: RecoveryAction
    run_id: str
    reason: str
    step_id: int | None = None
    new_budget: float | None = None
    instructions: str | None = None


@dataclass
class BatchSpec:
    """Parsed batch specification."""

    actions: list[BatchAction]
    batch_id: str = ""
    operator_identity: str = ""
    operator_role: str = ""
    dry_run: bool = False
    governance_profile: str = ""
    governance_profile_file: str = ""

    def __post_init__(self) -> None:
        if not self.batch_id:
            self.batch_id = f"batch-{uuid.uuid4().hex[:12]}"


def parse_batch_file(path: str) -> BatchSpec:
    """Parse and validate a YAML batch file.

    Raises ValueError on schema violations (missing/empty actions, unknown
    action types, missing run_id/reason, over-50 actions).
    """
    raw = yaml.safe_load(Path(path).read_text())
    if not isinstance(raw, dict):
        raise ValueError("batch file must be a YAML mapping")

    actions_raw = raw.get("actions")
    if actions_raw is None:
        raise ValueError("batch file is missing required 'actions' key")
    if not isinstance(actions_raw, list) or len(actions_raw) == 0:
        raise ValueError("batch 'actions' must be a non-empty list")
    if len(actions_raw) > MAX_BATCH_ACTIONS:
        raise ValueError(
            f"batch has {len(actions_raw)} actions; maximum is {MAX_BATCH_ACTIONS}"
        )

    actions: list[BatchAction] = []
    for i, entry in enumerate(actions_raw):
        if not isinstance(entry, dict):
            raise ValueError(f"action [{i}] must be a mapping")
        action_str = entry.get("action")
        if not action_str:
            raise ValueError(f"action [{i}] is missing required 'action' key")
        try:
            action = RecoveryAction(action_str)
        except ValueError:
            raise ValueError(
                f"action [{i}] has unknown action '{action_str}'; "
                f"valid actions: {', '.join(a.value for a in RecoveryAction)}"
            )
        run_id = entry.get("run_id")
        if not run_id:
            raise ValueError(f"action [{i}] ({action_str}) is missing required 'run_id'")
        reason = entry.get("reason")
        if not reason:
            raise ValueError(f"action [{i}] ({action_str}) is missing required 'reason'")
        actions.append(BatchAction(
            action=action,
            run_id=run_id,
            reason=reason,
            step_id=entry.get("step_id"),
            new_budget=entry.get("new_budget"),
            instructions=entry.get("instructions"),
        ))

    return BatchSpec(
        actions=actions,
        batch_id=raw.get("batch_id") or "",
        operator_identity=raw.get("operator_identity") or "",
        operator_role=raw.get("operator_role") or "",
        dry_run=bool(raw.get("dry_run", False)),
        governance_profile=raw.get("governance_profile") or "",
        governance_profile_file=raw.get("governance_profile_file") or "",
    )


# ── Batch result model ───────────────────────────────────────────────────────

@dataclass
class BatchActionResult:
    """Result of one action inside a batch."""

    index: int
    action: RecoveryAction
    run_id: str
    admitted: bool
    denial_type: str | None = None
    rejection_reason: str | None = None
    resulting_state: str | None = None
    status: str = "pending"  # pending, admitted, denied, executed, failed, skipped


@dataclass
class BatchSummary:
    """Summary of a batch execution."""

    batch_id: str
    operator_identity: str
    operator_role: str
    mode: str  # dry_run | execute
    total_actions: int = 0
    admitted_count: int = 0
    denied_count: int = 0
    executed_count: int = 0
    failed_count: int = 0
    skipped_count: int = 0
    results: list[BatchActionResult] = field(default_factory=list)
    overall_status: str = "pending"  # see statuses below

    # Valid overall_status values:
    #   dry_run_passed, dry_run_denied
    #   completed, completed_with_denials, completed_with_failures
    #   failed_fast


class BatchExecutor:
    """Executes a recovery batch with per-action authorization (v2.50.0).

    Each action is authorized independently through the same RecoveryService
    path used by single-action recovery. The batch is non-atomic — no rollback.
    """

    def __init__(self, service: Any) -> None:
        """service: a RecoveryService instance."""
        self.service = service

    def execute(
        self,
        spec: BatchSpec,
        *,
        dry_run: bool | None = None,
        fail_fast: bool = True,
        continue_on_error: bool = False,
        operator_identity: str | None = None,
        operator_role: str | None = None,
    ) -> BatchSummary:
        """Execute (or dry-run) a batch.

        Per-action: authorize → (dry-run: record | execute: apply) → record.
        """
        import os
        from nodechain.runtime.recovery_policy import RecoveryAction as RA

        effective_dry_run = dry_run if dry_run is not None else spec.dry_run
        effective_identity = (
            operator_identity
            or spec.operator_identity
            or os.environ.get("NODECHAIN_OPERATOR_IDENTITY", "console")
        )
        effective_role = (
            operator_role
            or spec.operator_role
            or os.environ.get("NODECHAIN_OPERATOR_ROLE", "operator")
        )
        effective_profile_name = spec.governance_profile or ""
        effective_profile_file = spec.governance_profile_file or ""
        mode = "dry_run" if effective_dry_run else "execute"

        # v2.52.0: resolve governance profile for batch-level enforcement.
        resolved_profile = None
        if effective_profile_name or effective_profile_file:
            from nodechain.runtime.governance_profiles import GovernanceProfileResolver
            try:
                resolver = GovernanceProfileResolver()
                resolved_profile = resolver.resolve(
                    explicit_profile=effective_profile_name or None,
                    explicit_profile_file=effective_profile_file or None,
                )
            except Exception:
                pass  # unknown profile — let per-action auth deny it

        # v2.52.0: enforce profile batch limits.
        max_actions = MAX_BATCH_ACTIONS
        if resolved_profile:
            max_actions = resolved_profile.batch.max_actions
            if resolved_profile.batch.enabled is False:
                summary = BatchSummary(
                    batch_id=spec.batch_id,
                    operator_identity=effective_identity,
                    operator_role=effective_role,
                    mode=mode, total_actions=len(spec.actions),
                    overall_status="failed_fast",
                )
                return summary
            if not resolved_profile.batch.allow_continue_on_error:
                continue_on_error = False
            # v2.53.0: enforce require_dry_run_before_execute
            if resolved_profile.batch.require_dry_run_before_execute and not effective_dry_run:
                summary = BatchSummary(
                    batch_id=spec.batch_id,
                    operator_identity=effective_identity,
                    operator_role=effective_role,
                    mode=mode, total_actions=len(spec.actions),
                    overall_status="failed_fast",
                )
                summary.results = [
                    BatchActionResult(index=i, action=a.action, run_id=a.run_id,
                                      admitted=False, status="denied",
                                      denial_type="batch_policy",
                                      rejection_reason=f"profile '{resolved_profile.id}' "
                                                       f"requires dry-run before execution")
                    for i, a in enumerate(spec.actions)
                ]
                summary.denied_count = len(spec.actions)
                return summary
            # Enforce profile-specific max_actions
            if len(spec.actions) > max_actions:
                summary = BatchSummary(
                    batch_id=spec.batch_id,
                    operator_identity=effective_identity,
                    operator_role=effective_role,
                    mode=mode, total_actions=len(spec.actions),
                    overall_status="failed_fast",
                )
                summary.results = [
                    BatchActionResult(index=i, action=a.action, run_id=a.run_id,
                                      admitted=False, status="denied",
                                      denial_type="batch_policy",
                                      rejection_reason=f"profile '{resolved_profile.id}' "
                                                       f"max_actions={max_actions} exceeded")
                    for i, a in enumerate(spec.actions)
                ]
                summary.denied_count = len(spec.actions)
                return summary

        summary = BatchSummary(
            batch_id=spec.batch_id,
            operator_identity=effective_identity,
            operator_role=effective_role,
            mode=mode,
            total_actions=len(spec.actions),
        )

        # continue-on-error overrides fail-fast
        stop_on_error = fail_fast and not continue_on_error

        for i, batch_action in enumerate(spec.actions):
            result = BatchActionResult(
                index=i, action=batch_action.action, run_id=batch_action.run_id,
                admitted=False, status="pending",
            )

            # v3.5.0: EXECUTE_RETRY_AUTHORIZED is excluded from batch execution
            # (locked non-goal: "no batch retry execution"). One operator
            # command → one side effect. This prevents concurrent dispatch
            # ambiguity and keeps the fenced boundary protocol under direct
            # operator control.
            if batch_action.action == RA.EXECUTE_RETRY_AUTHORIZED:
                result.status = "denied"
                result.denial_type = "batch_policy"
                result.rejection_reason = (
                    "EXECUTE_RETRY_AUTHORIZED is excluded from batch "
                    "execution (v3.5.0: one operator command → one side effect)"
                )
                summary.denied_count += 1
                summary.results.append(result)
                if stop_on_error:
                    summary.overall_status = "failed_fast"
                continue

            if summary.overall_status == "failed_fast" or any(
                r.status == "skipped" for r in summary.results if r.index < i and stop_on_error
            ):
                # This action was skipped due to earlier fail-fast
                result.status = "skipped"
                summary.skipped_count += 1
                summary.results.append(result)
                continue

            # Check if a previous action triggered fail-fast
            prior_failure = any(
                r.status in ("denied", "failed") and r.index < i
                for r in summary.results
            ) if stop_on_error else False
            if prior_failure and not any(r.status == "skipped" for r in summary.results):
                summary.overall_status = "failed_fast"

            if summary.overall_status == "failed_fast":
                result.status = "skipped"
                summary.skipped_count += 1
                summary.results.append(result)
                continue

            # Authorize the action
            if effective_dry_run:
                # Dry-run: authorize only, do not execute
                auth_result = self.service.authorize_action(
                    batch_action.run_id,
                    batch_action.action,
                    operator_identity=effective_identity,
                    operator_role=effective_role,
                    target_step_id=batch_action.step_id,
                    reason=batch_action.reason,
                    instructions=batch_action.instructions,
                    new_budget=batch_action.new_budget,
                    governance_profile=effective_profile_name or None,
                    governance_profile_file=effective_profile_file or None,
                )
            else:
                # Execute: full apply_action (authorize + delegate + audit)
                auth_result = self.service.apply_action(
                    batch_action.run_id,
                    batch_action.action,
                    operator_identity=effective_identity,
                    operator_role=effective_role,
                    target_step_id=batch_action.step_id,
                    reason=batch_action.reason,
                    instructions=batch_action.instructions,
                    new_budget=batch_action.new_budget,
                    governance_profile=effective_profile_name or None,
                    governance_profile_file=effective_profile_file or None,
                )

            if not auth_result.admitted:
                result.admitted = False
                result.status = "denied"
                result.denial_type = getattr(auth_result, "denial_type", None)
                result.rejection_reason = auth_result.rejection_reason
                summary.denied_count += 1
                summary.results.append(result)
                if stop_on_error:
                    summary.overall_status = "failed_fast"
                    # Mark remaining as skipped in subsequent iterations
                continue

            # Admitted
            result.admitted = True

            if effective_dry_run:
                result.status = "admitted"
                summary.admitted_count += 1
                summary.results.append(result)
                continue

            # Execute: the apply_action already delegated (it's not a dry-run).
            # The auth_result contains the execution result.
            result.status = "executed"
            result.resulting_state = auth_result.resulting_state
            summary.admitted_count += 1
            summary.executed_count += 1
            summary.results.append(result)

        # Determine overall status
        if not summary.results:
            summary.overall_status = "completed"
        elif effective_dry_run:
            summary.overall_status = (
                "dry_run_denied" if summary.denied_count > 0 else "dry_run_passed"
            )
        elif summary.overall_status == "failed_fast":
            pass  # already set
        elif summary.denied_count > 0 or summary.failed_count > 0:
            summary.overall_status = (
                "completed_with_failures" if summary.failed_count > 0
                else "completed_with_denials"
            )
        else:
            summary.overall_status = "completed"

        return summary
