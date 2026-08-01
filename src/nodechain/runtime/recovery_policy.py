"""OperatorActionPolicy — fail-closed authorization for recovery actions (v2.46.0).

Recovery is a high-authority surface. Every operator action is authorized
against the run's recovery state and durable facts BEFORE it is admitted.
Fail-closed: any (state, action) pair not explicitly allowed is refused.

Carry-forward constraint (Phase 2 review): before authorizing resume/retry
after crash recovery, EACH unresolved unknown side-effect row must have its own
recovery decision, matched by ``idempotency_key``. A recovery decision on the
run as a whole is NOT sufficient — that was the classifier's coarse view; the
policy must be stricter because it is the gate that actually admits the action.

The policy is pure: it takes a snapshot dict + action + optional target/override
and returns an AuthorizationResult. No I/O, no mutation.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from typing import Any

from nodechain.runtime.recovery_classifier import RecoveryState


class RecoveryAction(str, Enum):
    """The set of operator recovery actions the console can request."""

    RESUME = "resume"
    RETRY_STEP = "retry_step"
    APPROVE_REVIEW = "approve_review"
    REJECT_REVIEW = "reject_review"
    REQUEST_REVISION = "request_revision"
    ROUTE_FALLBACK = "route_fallback"
    CANCEL_RUN = "cancel_run"
    FAIL_RUN = "fail_run"
    EXPORT_REPORT = "export_report"
    APPROVE_BUDGET_INCREASE = "approve_budget_increase"  # v2.47.0
    RESOLVE_SIDE_EFFECT = "resolve_side_effect"  # v3.3.0
    EXECUTE_RETRY_AUTHORIZED = "execute_retry_authorized"  # v3.5.0


_TERMINAL_STATES = {RecoveryState.COMPLETED, RecoveryState.CANCELLED}


@dataclass(frozen=True)
class AuthorizationResult:
    """Outcome of authorizing one operator action."""

    admitted: bool
    rejection_reason: str | None = None
    denial_type: str | None = None  # rbac, policy, invalid_role, override_required, profile_constraint
    governance_profile_id: str | None = None
    governance_profile_digest: str | None = None


# v2.49.0: action-level RBAC matrix. Maps each action to the set of roles
# allowed to request it. Budget increase requires finance/admin; all other
# actions are operator-accessible.
ACTION_ALLOWED_ROLES: dict[RecoveryAction, set[str]] = {
    RecoveryAction.RESUME: {"operator", "finance", "admin"},
    RecoveryAction.RETRY_STEP: {"operator", "finance", "admin"},
    RecoveryAction.APPROVE_REVIEW: {"operator", "finance", "admin"},
    RecoveryAction.REJECT_REVIEW: {"operator", "finance", "admin"},
    RecoveryAction.REQUEST_REVISION: {"operator", "finance", "admin"},
    RecoveryAction.ROUTE_FALLBACK: {"operator", "finance", "admin"},
    RecoveryAction.CANCEL_RUN: {"operator", "finance", "admin"},
    RecoveryAction.FAIL_RUN: {"operator", "finance", "admin"},
    RecoveryAction.EXPORT_REPORT: {"operator", "finance", "admin"},
    RecoveryAction.APPROVE_BUDGET_INCREASE: {"finance", "admin"},
    RecoveryAction.RESOLVE_SIDE_EFFECT: {"operator"},  # v3.3.0: operator-only — side-effect resolution is a truth-claim about external state, distinct from flow-control recovery actions
    RecoveryAction.EXECUTE_RETRY_AUTHORIZED: {"operator"},  # v3.5.0: operator-only — retry execution is a governed side-effect operation, not a flow-control action
}

VALID_ROLES = {"operator", "finance", "admin"}


class OperatorActionPolicy:
    """Authorizes operator recovery actions against durable recovery facts.

    Pure / stateless: every decision is a function of the snapshot + action +
    optional ``target_step_id`` and ``operator_override``. Callers (RecoveryService)
    are responsible for re-reading state before authorizing — never authorize
    against a stale handle.
    """

    def authorize(
        self,
        action: RecoveryAction,
        snapshot: dict[str, Any],
        *,
        target_step_id: int | None = None,
        operator_override: bool | None = None,
        new_budget: float | None = None,
        operator_role: str | None = None,
        governance_profile: Any = None,
        reason: str | None = None,
        operator_identity: str | None = None,
    ) -> AuthorizationResult:
        # v2.49.0: RBAC checks run BEFORE action+state policy.
        # Authorization order: role validation → RBAC matrix → override → policy.

        # 1. Parse/validate role.
        if operator_role is None:
            operator_role = os.environ.get("NODECHAIN_OPERATOR_ROLE", "operator")
        if operator_role not in VALID_ROLES:
            return AuthorizationResult(
                False,
                f"invalid operator role '{operator_role}'; "
                f"allowed roles: {', '.join(sorted(VALID_ROLES))}",
                denial_type="invalid_role",
            )

        # 2. RBAC matrix check.
        allowed_roles = ACTION_ALLOWED_ROLES.get(action, set())
        if operator_role not in allowed_roles:
            return AuthorizationResult(
                False,
                f"role '{operator_role}' not authorized for {action.value}; "
                f"requires: {', '.join(sorted(allowed_roles))}",
                denial_type="rbac",
            )

        # Resolve override env.
        if operator_override is None:
            operator_override = bool(os.environ.get("NODECHAIN_OPERATOR_OVERRIDE"))

        # v2.52.0: profile-specific constraints (may be stricter, never weaker).
        profile_id = None
        profile_digest = None
        if governance_profile is not None:
            from nodechain.runtime.governance_profiles import compute_profile_digest
            profile_id = governance_profile.id
            profile_digest = compute_profile_digest(governance_profile)

            # v2.53.0: profile-level role boundary (independent of action rules)
            if operator_role not in governance_profile.roles.allowed_roles:
                return AuthorizationResult(
                    False,
                    f"profile '{profile_id}' does not allow role '{operator_role}'",
                    denial_type="profile_constraint",
                    governance_profile_id=profile_id,
                    governance_profile_digest=profile_digest,
                )

            # Profile action-role check (may restrict further)
            action_gov = governance_profile.actions.get(action.value)
            if action_gov and operator_role not in action_gov.allowed_roles:
                return AuthorizationResult(
                    False,
                    f"profile '{profile_id}' does not allow role '{operator_role}' "
                    f"for {action.value}",
                    denial_type="profile_constraint",
                    governance_profile_id=profile_id,
                    governance_profile_digest=profile_digest,
                )

            # Profile reason requirement
            if action_gov and action_gov.require_reason and not reason:
                return AuthorizationResult(
                    False,
                    f"profile '{profile_id}' requires a reason for {action.value}",
                    denial_type="profile_constraint",
                    governance_profile_id=profile_id,
                    governance_profile_digest=profile_digest,
                )

            # v2.53.0: profile require_override enforcement
            if action_gov and action_gov.require_override and not operator_override:
                return AuthorizationResult(
                    False,
                    f"profile '{profile_id}' requires NODECHAIN_OPERATOR_OVERRIDE=true "
                    f"for {action.value}",
                    denial_type="profile_constraint",
                    governance_profile_id=profile_id,
                    governance_profile_digest=profile_digest,
                )

            # v2.53.0: profile audit.require_reason_for_mutations enforcement
            if (governance_profile.audit.require_reason_for_mutations
                    and action is not RecoveryAction.EXPORT_REPORT and not reason):
                return AuthorizationResult(
                    False,
                    f"profile '{profile_id}' requires a reason for all mutations",
                    denial_type="profile_constraint",
                    governance_profile_id=profile_id,
                    governance_profile_digest=profile_digest,
                )

            # v2.53.0: profile budget enforcement for APPROVE_BUDGET_INCREASE
            if action is RecoveryAction.APPROVE_BUDGET_INCREASE and new_budget is not None:
                budget_gov = governance_profile.budget
                # Budget approve_roles (may restrict beyond global RBAC)
                if operator_role not in budget_gov.approve_roles:
                    return AuthorizationResult(
                        False,
                        f"profile '{profile_id}' budget roles for "
                        f"approve_budget_increase: {budget_gov.approve_roles}; "
                        f"role '{operator_role}' not allowed",
                        denial_type="profile_constraint",
                        governance_profile_id=profile_id,
                        governance_profile_digest=profile_digest,
                    )
                # Budget require_reason
                if budget_gov.require_reason and not reason:
                    return AuthorizationResult(
                        False,
                        f"profile '{profile_id}' requires a reason for budget increase",
                        denial_type="profile_constraint",
                        governance_profile_id=profile_id,
                        governance_profile_digest=profile_digest,
                    )
                # Budget max_new_budget_usd cap
                if budget_gov.max_new_budget_usd is not None:
                    if new_budget > budget_gov.max_new_budget_usd:
                        return AuthorizationResult(
                            False,
                            f"profile '{profile_id}' max budget cap "
                            f"${budget_gov.max_new_budget_usd} exceeded by "
                            f"${new_budget}",
                            denial_type="profile_constraint",
                            governance_profile_id=profile_id,
                            governance_profile_digest=profile_digest,
                        )
                # Budget max_increase_multiplier
                if budget_gov.max_increase_multiplier is not None:
                    previous = snapshot.get("budget_previous") or 0.0
                    if previous > 0 and new_budget > previous * budget_gov.max_increase_multiplier:
                        return AuthorizationResult(
                            False,
                            f"profile '{profile_id}' max increase multiplier "
                            f"{budget_gov.max_increase_multiplier}x exceeded: "
                            f"{new_budget} > {previous} * {budget_gov.max_increase_multiplier}",
                            denial_type="profile_constraint",
                            governance_profile_id=profile_id,
                            governance_profile_digest=profile_digest,
                        )

            # v2.52.0: profile audit governance enforcement
            if governance_profile.audit.require_operator_identity:
                identity = operator_identity or os.environ.get("NODECHAIN_OPERATOR_IDENTITY", "console")
                if identity == "console":
                    return AuthorizationResult(
                        False,
                        f"profile '{profile_id}' requires an explicit operator identity "
                        f"(not the default 'console')",
                        denial_type="profile_constraint",
                        governance_profile_id=profile_id,
                        governance_profile_digest=profile_digest,
                    )

            # v2.52.0: break-glass override enforcement
            if (governance_profile.id == "break-glass"
                    and governance_profile.override.break_glass_requires_env_override
                    and action is not RecoveryAction.EXPORT_REPORT):
                if not operator_override:
                    return AuthorizationResult(
                        False,
                        f"break-glass profile requires NODECHAIN_OPERATOR_OVERRIDE=true "
                        f"for {action.value}",
                        denial_type="profile_constraint",
                        governance_profile_id=profile_id,
                        governance_profile_digest=profile_digest,
                    )

        # 3. Override requirement: non-retryable retry needs admin + override.
        # Check this before the existing policy so the denial_type is correct.
        state = self._state(snapshot)
        if action is RecoveryAction.RETRY_STEP and state is RecoveryState.FAILED_NON_RETRYABLE:
            if not (operator_role == "admin" and operator_override):
                return AuthorizationResult(
                    False,
                    "non-retryable retry override requires role 'admin' and "
                    "NODECHAIN_OPERATOR_OVERRIDE=true",
                    denial_type="override_required",
                )

        # 4. Existing action + recovery-state policy (wrap rejections with denial_type).
        result = self._authorize_action_state(
            action, snapshot, state, target_step_id, operator_override, new_budget,
        )
        if not result.admitted and result.denial_type is None:
            result = AuthorizationResult(
                result.admitted, result.rejection_reason, denial_type="policy",
            )
        # v2.52.0: always attach profile metadata when a profile is present.
        if profile_id is not None and result.governance_profile_id is None:
            return AuthorizationResult(
                result.admitted, result.rejection_reason, result.denial_type,
                governance_profile_id=profile_id,
                governance_profile_digest=profile_digest,
            )
        return result

    def _authorize_action_state(
        self,
        action: RecoveryAction,
        snapshot: dict[str, Any],
        state: RecoveryState,
        target_step_id: int | None,
        operator_override: bool,
        new_budget: float | None,
    ) -> AuthorizationResult:
        """The existing action + recovery-state authorization logic (v2.46.0-v2.48.0).

        Extracted from authorize() so the RBAC layer can wrap its rejections
        with denial_type='policy'.
        """
        # Read-only report is always allowed, in any state.
        if action is RecoveryAction.EXPORT_REPORT:
            return AuthorizationResult(admitted=True)

        # v3.3.0: RESOLVE_SIDE_EFFECT is a ledger-layer operation, not an
        # execution-loop action. An operator may resolve an unknown side effect
        # in any non-terminal run. Evidence/key validation is enforced by the
        # StateManager facade; failures there surface through the BLOCKED path
        # in RecoveryService (auditable, fail-closed).
        if action is RecoveryAction.RESOLVE_SIDE_EFFECT:
            return AuthorizationResult(admitted=True)

        # Terminal runs refuse every mutation.
        if state in _TERMINAL_STATES:
            return AuthorizationResult(
                False, f"run is terminal ({state.value}); no recovery action applies"
            )

        # v3.5.0: EXECUTE_RETRY_AUTHORIZED is a recovery-execution operation
        # that dispatches through the SideEffectRetryCoordinator. It is admitted
        # in any non-terminal run — the coordinator validates parent status,
        # capsule availability, and adapter attestation. Failures there surface
        # through the BLOCKED path in RecoveryService (auditable, fail-closed).
        if action is RecoveryAction.EXECUTE_RETRY_AUTHORIZED:
            return AuthorizationResult(admitted=True)

        if action is RecoveryAction.RESUME:
            return self._authorize_resume(snapshot, state)
        if action is RecoveryAction.RETRY_STEP:
            return self._authorize_retry(snapshot, state, target_step_id, operator_override)
        if action in (RecoveryAction.APPROVE_REVIEW,
                      RecoveryAction.REJECT_REVIEW,
                      RecoveryAction.REQUEST_REVISION):
            return self._authorize_review(action, snapshot)
        if action is RecoveryAction.ROUTE_FALLBACK:
            return self._authorize_route_fallback(snapshot, target_step_id)
        if action is RecoveryAction.CANCEL_RUN:
            return AuthorizationResult(admitted=True)
        if action is RecoveryAction.FAIL_RUN:
            return AuthorizationResult(admitted=True)
        if action is RecoveryAction.APPROVE_BUDGET_INCREASE:
            return self._authorize_budget_increase(snapshot, new_budget)

        # Fail-closed default.
        return AuthorizationResult(False, f"no authorization rule for action {action.value}")

    def _authorize_budget_increase(
        self, snapshot: dict[str, Any], new_budget: float | None,
    ) -> AuthorizationResult:
        """Admit APPROVE_BUDGET_INCREASE for a budget-paused run (v2.47.0).

        Validation (per agreed design):
        - recovery_state must be PAUSED_FOR_BUDGET_APPROVAL
        - new_budget must be supplied
        - new_budget > previous_budget (strictly raising the ceiling)
        - new_budget > accumulated_loop_cost (can't approve below spent)

        Cost is carried (absolute ceiling), not reset — the approval records
        'raised ceiling from X to Y after Z spent', not 'erased prior spend'.
        """
        state = self._state(snapshot)
        if state is not RecoveryState.PAUSED_FOR_BUDGET_APPROVAL:
            return AuthorizationResult(
                False, f"approve_budget_increase only applies to "
                       f"PAUSED_FOR_BUDGET_APPROVAL, not {state.value}"
            )
        if new_budget is None:
            return AuthorizationResult(
                False, "approve_budget_increase requires a new_budget"
            )
        previous = snapshot.get("budget_previous") or 0.0
        if new_budget <= previous:
            return AuthorizationResult(
                False, f"new_budget {new_budget} must be strictly greater than "
                       f"previous budget {previous}"
            )
        accumulated = snapshot.get("budget_accumulated_cost") or 0.0
        if new_budget <= accumulated:
            return AuthorizationResult(
                False, f"new_budget {new_budget} must exceed accumulated loop "
                       f"cost {accumulated} (already spent)"
            )
        return AuthorizationResult(admitted=True)

    def _authorize_route_fallback(
        self, snapshot: dict[str, Any], target_step_id: int | None,
    ) -> AuthorizationResult:
        """Admit ROUTE_FALLBACK only for fallback-capable failures (#13).

        Fail-closed: requires a durable failure_type, a matching target step,
        and no prior admitted fallback for that step. Uses the
        FailureManager.OPERATOR_FALLBACK_TYPES allowlist so the policy stays in
        sync with the runtime's fallback capabilities.
        """
        from nodechain.runtime.failure_manager import FailureManager, FailureType

        if target_step_id is None:
            return AuthorizationResult(
                False, "route_fallback requires a target step_id "
                       "(step/invocation precision)"
            )
        failed_step = snapshot.get("failed_step")
        if failed_step is not None and target_step_id != failed_step:
            return AuthorizationResult(
                False, f"target step {target_step_id} does not match the durable "
                       f"failed step {failed_step}"
            )
        failure_type_str = snapshot.get("last_failure_type")
        if not failure_type_str:
            return AuthorizationResult(
                False, "route_fallback requires a durable last_failure.failure_type; "
                       "cannot classify from free-text errors"
            )
        try:
            failure_type = FailureType(failure_type_str)
        except ValueError:
            return AuthorizationResult(
                False, f"unknown failure_type '{failure_type_str}'; "
                       f"cannot determine fallback eligibility"
            )
        if not FailureManager.supports_operator_fallback(failure_type):
            return AuthorizationResult(
                False, f"failure type {failure_type.value} does not have an "
                       f"operator-callable fallback (not in OPERATOR_FALLBACK_TYPES)"
            )
        prior_attempts = snapshot.get("prior_fallback_attempts") or []
        if target_step_id in prior_attempts:
            return AuthorizationResult(
                False, f"a prior route_fallback was already admitted for step "
                       f"{target_step_id}; duplicate fallback blocked"
            )
        return AuthorizationResult(admitted=True)

    # --- per-action rules -------------------------------------------------

    def _authorize_resume(
        self, snapshot: dict[str, Any], state: RecoveryState,
    ) -> AuthorizationResult:
        # Resume is meaningful only for genuinely recoverable pauses.
        if state is RecoveryState.PAUSED_FOR_POLICY_APPROVAL:
            return AuthorizationResult(admitted=True)
        if state is RecoveryState.PAUSED_FOR_HUMAN_REVIEW:
            # Resume after review requires the review to be decided first.
            return AuthorizationResult(
                False, "review must be approved/rejected before resume "
                       "(use approve_review/reject_review)"
            )
        if state in (RecoveryState.CRASH_RECOVERABLE, RecoveryState.CRASH_NEEDS_OPERATOR):
            return self._check_unknown_effects_resolved(snapshot)

        # Fail-closed: loop exhaustion, trace incomplete, failed states, etc.
        return AuthorizationResult(
            False, f"resume not authorized for recovery state {state.value}"
        )

    def _authorize_retry(
        self, snapshot: dict[str, Any], state: RecoveryState,
        target_step_id: int | None, operator_override: bool,
    ) -> AuthorizationResult:
        if target_step_id is None:
            return AuthorizationResult(
                False, "retry requires a target step_id (step/invocation precision; "
                       "node_id alone is ambiguous for looped nodes)"
            )
        # #3: target_step_id must match the durable failed step. The policy does
        # not just check presence — `recover retry --step 999` against a run
        # whose failed step is 4 must be refused, otherwise the orchestrator
        # would resume whatever it would resume anyway (silent wrong-step retry).
        failed_step = snapshot.get("failed_step")
        if failed_step is not None and target_step_id != failed_step:
            return AuthorizationResult(
                False, f"target step {target_step_id} does not match the durable "
                       f"failed step {failed_step}; retry must target the actual failure"
            )
        if state is RecoveryState.FAILED_RETRYABLE:
            return AuthorizationResult(admitted=True)
        if state is RecoveryState.FAILED_NON_RETRYABLE:
            if operator_override:
                return AuthorizationResult(admitted=True)
            return AuthorizationResult(
                False, "failure is non-retryable; set NODECHAIN_OPERATOR_OVERRIDE "
                       "to force an operator override"
            )
        # A crash-recoverable run may retry a failed step once its unknown
        # effects are each resolved.
        if state in (RecoveryState.CRASH_RECOVERABLE, RecoveryState.CRASH_NEEDS_OPERATOR):
            effect_check = self._check_unknown_effects_resolved(snapshot)
            if not effect_check.admitted:
                return effect_check
            return AuthorizationResult(admitted=True)

        return AuthorizationResult(
            False, f"retry_step not authorized for recovery state {state.value}"
        )

    def _authorize_review(
        self, action: RecoveryAction, snapshot: dict[str, Any],
    ) -> AuthorizationResult:
        pending = snapshot.get("pending_review")
        if not pending:
            return AuthorizationResult(
                False, f"{action.value} requires a pending governed review request, "
                       "but none is present"
            )
        # The existing review system stores a committed receipt in
        # state.metadata['governed_decision_receipt'] (NOT on the pending_review
        # dict). A review with a committed receipt cannot be decided again —
        # this protects against replay of approve/reject.
        if snapshot.get("governed_decision_receipt"):
            return AuthorizationResult(
                False, "review already has a committed governed_decision_receipt; "
                       "cannot decide again"
            )
        return AuthorizationResult(admitted=True)

    # --- carry-forward: per-effect resolution -----------------------------

    def _check_unknown_effects_resolved(
        self, snapshot: dict[str, Any],
    ) -> AuthorizationResult:
        """Each unresolved unknown side-effect must have its OWN recovery
        decision, matched by idempotency_key. A decision elsewhere on the run
        does not cover it. Partial coverage blocks."""
        unknown_keys = {
            se["idempotency_key"]
            for se in snapshot.get("side_effects", [])
            if se.get("status") == "unknown" and se.get("idempotency_key")
        }
        if not unknown_keys:
            return AuthorizationResult(admitted=True)
        decided_keys = {
            d["idempotency_key"]
            for d in snapshot.get("recovery_decisions", [])
            if d.get("idempotency_key")
        }
        unresolved = sorted(unknown_keys - decided_keys)
        if unresolved:
            return AuthorizationResult(
                False,
                f"unresolved unknown side effects without a per-effect recovery "
                f"decision: {unresolved}",
            )
        return AuthorizationResult(admitted=True)

    # --- helpers ----------------------------------------------------------

    @staticmethod
    def _state(snapshot: dict[str, Any]) -> RecoveryState:
        return RecoveryState(snapshot["recovery_state"])
