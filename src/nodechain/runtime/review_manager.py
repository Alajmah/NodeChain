"""Review Manager — human review state machine and decision handling.

Owns:
- Determining whether review is needed (risk-level evaluation)
- Constructing review requests
- Persisting waiting_for_review state
- Resolving review decisions (approve/reject/revision)
- Producing structured ReviewDecision results
- Materializing governed ReviewRequest / DecisionReceipt artifacts (v2.22.0)

Does NOT own:
- Node invocation
- Scheduler transitions
- Persistence transaction internals
- Trace emission mechanics
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from nodechain.core.state import ChainState
from nodechain.core.trace import EventType, Actor, TraceEvent


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# Reason code emitted when the ReviewVerifier rejects a runtime-produced
# decision. This is a governance failure, not a reviewer rejection.
REASON_REVIEW_RECEIPT_VERIFICATION_FAILED = "review_receipt_verification_failed"


class ReviewPausedException(Exception):
    """Raised when review mode is 'pause' — chain should halt for manual resume."""
    def __init__(self, run_id: str, step_id: int) -> None:
        self.run_id = run_id
        self.step_id = step_id
        super().__init__(f"Chain paused for review at step {step_id} (run_id={run_id})")


@dataclass
class ReviewDecision:
    """Structured result from a review evaluation.

    v2.22.0: when a governed receipt is materialized, the receipt id, digest,
    and full receipt dict are attached. The scheduler-facing ``decision``
    string is unchanged — the receipt is metadata, not a new scheduler API.
    """

    decision: str  # "approve", "reject", "request_revision", "timeout"
    needs_review: bool = False
    review_request: dict[str, Any] = field(default_factory=dict)
    risk_assessment: dict[str, Any] = field(default_factory=dict)
    # Governed receipt metadata (v2.22.0). None when no receipt was materialized
    # (e.g. timeout, or verifier failure — which fails the chain instead).
    receipt_id: str | None = None
    receipt_digest: str | None = None
    decision_receipt: dict[str, Any] = field(default_factory=dict)


class ReviewManager:
    """Manages the human review lifecycle.

    State machine:
        not_required → (skipped)
        requested → waiting_for_review → approved / rejected / revision_requested
        expired → timeout (treated as reject or escalate)

    v2.22.0: when a decision resolves, a governed ReviewRequest + DecisionReceipt
    are materialized and verified through ReviewVerifier. On verifier failure the
    chain fails closed (governance failure); a valid decision produces a committed
    receipt stored in state.metadata["governed_decision_receipt"].
    """

    def __init__(
        self,
        *,
        commit_review_transition: Callable[..., None],
        add_trace_event: Callable[[TraceEvent], None],
        record_attempt: Callable[[dict], None] | None = None,
    ) -> None:
        # H0.5 (amendment 3): the transition seam owns every authoritative
        # review state change — pause, decision, and governance failure
        # commit their candidate state and asserting trace event in ONE
        # transaction, then append the event to the live trace.
        self._commit_review_transition = commit_review_transition
        self._add_trace_event = add_trace_event
        # v2.25.0: durable review decision attempt log. Optional callback; when
        # wired (by the orchestrator) every verify() attempt is persisted.
        self._record_attempt = record_attempt or (lambda a: None)
        # Single shared policy instance — reused for both policy_digest and the
        # ReviewVerifier so a future default-drift cannot cause digest mismatch.
        self._policy = _make_reviewer_policy()

    @property
    def review_mode(self) -> str:
        """Current review mode from environment."""
        return os.environ.get("NODECHAIN_REVIEW_MODE", "interactive")

    # ── Needs Review Check ──────────────────────────────────────

    def needs_review(self, risk_output: dict[str, Any]) -> bool:
        """Determine if risk classifier output requires human review.

        Returns True if:
        - Review mode is not 'disabled'
        - Risk level is HIGH
        - Risk level is MEDIUM with confidence < 0.3
        - review_required flag is True
        """
        if self.review_mode == "disabled":
            return False

        risk_level = risk_output.get("risk_level", "").upper()
        if risk_level == "HIGH":
            return True

        if risk_level == "MEDIUM":
            confidence = risk_output.get("confidence", 1.0)
            if isinstance(confidence, (int, float)) and confidence < 0.3:
                return True

        return risk_output.get("review_required", False) is True

    # ── Request Review ──────────────────────────────────────────

    async def request_review(
        self,
        risk_output: dict[str, Any],
        state: ChainState,
        chain_name: str,
        step_id: int,
    ) -> ReviewDecision:
        """Request a human review and persist waiting state.

        Returns ReviewDecision with the resolved decision.
        """
        # Build the governed review request (v2.22.0). Built before persisting so
        # pause mode can persist it alongside the legacy request.
        governed_request = self._build_governed_review_request(risk_output, state, step_id)

        # Legacy review request metadata (preserved for back-compat / inspect).
        legacy_review_request = {
            "risk_assessment": risk_output,
            "step_id": step_id,
            "node_id": "risk_classifier",
        }

        # H0.5 (amendment 3): pause transition. The waiting status, the legacy
        # and governed request metadata, and the state-asserting
        # HUMAN_REVIEW_REQUESTED event commit in ONE SQLite transaction; the
        # event is appended to the live trace only after that commit
        # succeeds. This remains the durable pause point BEFORE
        # _get_decision, so pause mode's ReviewPausedException cannot exit
        # without the waiting state and its event being durable together.
        pause_event = TraceEvent(
            run_id=state.run_id,
            chain_id=state.chain_id,
            node_id="risk_classifier",
            step_id=step_id,
            event_type=EventType.HUMAN_REVIEW_REQUESTED,
            actor=Actor.RUNTIME,
            decision="paused_for_review",
            reason_codes=["Risk classification requires human review"],
            metadata={
                "subject_type": governed_request.subject.subject_type,
                "request_id": governed_request.request_id,
                "request_digest": governed_request.compute_digest(),
            },
        )
        self._commit_review_transition(
            state,
            pause_event,
            status="waiting_for_review",
            paused_at=time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
            metadata={
                "review_request": legacy_review_request,
                "governed_review_request": governed_request.to_dict(),
            },
        )

        # Get decision from adapter (may raise ReviewPausedException in pause mode)
        decision_str = await self._get_decision(risk_output, state.outputs, chain_name)

        # In pause mode we never reach here (exception raised above). For all
        # resolved modes, H0.5 (amendment 3): the decision transition commits
        # decision-specific status, the receipt metadata proposal, and the
        # review-decision event atomically through the same transition seam.
        # Nothing mutates the accepted state before that commit: approve and
        # revision commit running; reject and timeout commit their terminal
        # failed outcome directly — no intermediate running state.
        receipt_info = self._materialize_decision_receipt(
            decision_str, governed_request, risk_output, state, step_id,
        )

        # FAIL-CLOSED GUARD (code-review fix): if _materialize_decision_receipt
        # triggered governance failure (status adopted as 'failed' by the
        # governance transition, no receipt), do NOT proceed to emit a normal
        # completion event or return the original decision_str. Return a
        # governance-failure decision instead so the orchestrator cannot
        # treat an unverifiable receipt as chain authority.
        if state.status == "failed" and receipt_info.receipt_id is None:
            return ReviewDecision(
                decision="governance_failure",
                needs_review=True,
                review_request=legacy_review_request,
                risk_assessment=risk_output,
            )

        # Decision transition — H0.5 (amendment 3): status is decision-
        # specific; the materialized receipt rides as a metadata proposal.
        event_type_map = {
            "approve": EventType.HUMAN_REVIEW_COMPLETED,
            "reject": EventType.HUMAN_REVIEW_COMPLETED,
            "request_revision": EventType.HUMAN_REVIEW_COMPLETED,
            "timeout": EventType.HUMAN_REVIEW_TIMEOUT,
        }
        decision_meta = dict(receipt_info.trace_metadata)
        decision_event = TraceEvent(
            run_id=state.run_id,
            chain_id=state.chain_id,
            node_id="risk_classifier",
            step_id=step_id,
            event_type=event_type_map.get(decision_str, EventType.HUMAN_REVIEW_COMPLETED),
            actor=Actor.HUMAN,
            decision=decision_str,
            metadata=decision_meta,
        )
        decision_status = (
            "failed" if decision_str in ("reject", "timeout") else "running"
        )
        decision_metadata = (
            {"governed_decision_receipt": receipt_info.receipt_dict}
            if receipt_info.receipt_dict else None
        )
        self._commit_review_transition(
            state, decision_event, status=decision_status, paused_at=None,
            metadata=decision_metadata,
        )

        return ReviewDecision(
            decision=decision_str,
            needs_review=True,
            review_request=legacy_review_request,
            risk_assessment=risk_output,
            receipt_id=receipt_info.receipt_id,
            receipt_digest=receipt_info.receipt_digest,
            decision_receipt=receipt_info.receipt_dict,
        )

    # ── Resume Review ───────────────────────────────────────────

    async def resolve_resume_review(
        self,
        saved: ChainState,
        chain_name: str,
    ) -> ReviewDecision:
        """Resolve a pending review decision on resume.

        Used when resuming a chain that was paused waiting for review.
        Checks metadata for pre-made decision, falls back to adapter.

        v2.22.0: reconstructs the governed ReviewRequest from persisted metadata,
        preserving the original created_at (load-bearing — compute_digest() includes
        it). The resumed decision is bound to the ORIGINAL paused request.
        """
        legacy_review_request = saved.metadata.get("review_request", {})
        risk_output = legacy_review_request.get("risk_assessment", {})

        # Check for pre-made decision
        review_decision = saved.metadata.get("review_decision")
        if not review_decision:
            review_decision = await self._get_decision(risk_output, saved.outputs, chain_name)

        # Reconstruct governed request from persisted metadata if present (v2.22.0).
        governed_request = None
        governed_dict = saved.metadata.get("governed_review_request")
        if governed_dict:
            governed_request = self._rebuild_governed_review_request(governed_dict)

        receipt_info = _ReceiptInfo()
        if governed_request is not None and review_decision != "timeout":
            receipt_info = self._materialize_decision_receipt(
                review_decision, governed_request, risk_output, saved,
                legacy_review_request.get("step_id", 0),
            )

        # FAIL-CLOSED GUARD (code-review fix B): same guard as
        # request_review — if verification failed, return governance_failure.
        if saved.status == "failed" and receipt_info.receipt_id is None:
            return ReviewDecision(
                decision="governance_failure",
                needs_review=True,
                review_request=legacy_review_request,
                risk_assessment=risk_output,
            )

        return ReviewDecision(
            decision=review_decision,
            needs_review=True,
            review_request=legacy_review_request,
            risk_assessment=risk_output,
            receipt_id=receipt_info.receipt_id,
            receipt_digest=receipt_info.receipt_digest,
            decision_receipt=receipt_info.receipt_dict,
        )

    # ── Governed receipt helpers (v2.22.0) ──────────────────────

    def _build_governed_review_request(
        self,
        risk_output: dict[str, Any],
        state: ChainState,
        step_id: int,
    ):
        """Build a governed ReviewRequest bound to this review gate invocation."""
        from nodechain.sdk.review_workbench import (
            SUBJECT_CHAIN_REVIEW, ROLE_OPERATOR, ReviewSubject, ReviewRequest,
            _sha256_dict,
        )

        subject = ReviewSubject(
            subject_type=SUBJECT_CHAIN_REVIEW,
            subject_id=f"{state.run_id}:{step_id}",
            subject_digest=_sha256_dict(risk_output),
        )
        risk_level_raw = str(risk_output.get("risk_level", "medium")).lower()
        # Map common classifier levels into the workbench risk vocabulary.
        risk_level = risk_level_raw if risk_level_raw in ("low", "medium", "high", "critical") else "medium"
        reason = self._default_rationale(risk_output, review_required=True)

        return ReviewRequest(
            request_id=f"review_{state.run_id}_{step_id}",
            subject=subject,
            reason_for_review=reason,
            required_reviewer_role=ROLE_OPERATOR,
            graph_digest=getattr(state, "execution_order_hash", "") or "",
            policy_digest=self._policy.compute_digest(),
            risk_level=risk_level,
        )

    def _rebuild_governed_review_request(self, governed_dict: dict[str, Any]):
        """Reconstruct a ReviewRequest from its persisted dict.

        created_at is passed through verbatim — compute_digest() includes it, so a
        fresh timestamp would break the request digest and fail verification.
        """
        from nodechain.sdk.review_workbench import ReviewSubject, ReviewRequest

        subj = governed_dict.get("subject", {})
        subject = ReviewSubject(
            subject_type=subj.get("subject_type", "chain_review"),
            subject_id=subj.get("subject_id", ""),
            subject_digest=subj.get("subject_digest", ""),
        )
        return ReviewRequest(
            request_id=governed_dict.get("request_id", ""),
            subject=subject,
            reason_for_review=governed_dict.get("reason_for_review", ""),
            required_reviewer_role=governed_dict.get("required_reviewer_role", "operator"),
            graph_digest=governed_dict.get("graph_digest", ""),
            policy_digest=governed_dict.get("policy_digest", ""),
            trace_event_ids=list(governed_dict.get("trace_event_ids", [])),
            created_at=governed_dict.get("created_at"),  # preserved verbatim
            risk_level=governed_dict.get("risk_level", "medium"),
            status=governed_dict.get("status", "pending"),
        )

    def _materialize_decision_receipt(
        self,
        decision_str: str,
        governed_request,
        risk_output: dict[str, Any],
        state: ChainState,
        step_id: int,
    ) -> "_ReceiptInfo":
        """Build + verify an OperatorDecision, returning receipt info.

        On verifier failure: fails closed — the governance transition commits
        failed status + reason_code + event atomically and returns an empty
        _ReceiptInfo (no receipt stored). On success: returns the receipt
        id/digest/dict + trace metadata; H0.5 leaves storing the receipt in
        state to the decision transition's metadata proposal.
        """
        from nodechain.sdk.review_workbench import (
            OperatorDecision, ReviewVerifier, chain_review_decision_type,
            ROLE_OPERATOR,
        )

        info = _ReceiptInfo()

        # Timeouts are not operator decisions — no receipt is materialized.
        if decision_str == "timeout":
            return info

        try:
            decision_type = chain_review_decision_type(decision_str)
        except ValueError:
            # Unknown outcome — cannot materialize a receipt. Fail closed.
            self._fail_closed_governance(
                state, step_id, governed_request,
                rejection_reason=f"unsupported_review_outcome:{decision_str}",
            )
            return info

        reviewer_identity = os.environ.get("NODECHAIN_REVIEWER_IDENTITY", "runtime:auto")
        rationale = self._default_rationale(risk_output, review_required=False)

        decision = OperatorDecision(
            decision_type=decision_type,
            request_id=governed_request.request_id,
            reviewer_identity=reviewer_identity,
            reviewer_role=ROLE_OPERATOR,  # authorization tied to role, not identity string
            rationale=rationale,
            request_digest=governed_request.compute_digest(),
            subject_digest=governed_request.subject.subject_digest,
            policy_digest=self._policy.compute_digest(),
        )

        result = ReviewVerifier(self._policy).verify(decision, governed_request)

        # v2.25.0: record ONE durable attempt row after verify(), before any
        # fail-closed handling — so rejected attempts persist even when the
        # chain then fails. Closes HR-046.
        self._record_review_attempt(
            decision, governed_request, result, state, step_id, reviewer_identity,
            decision_str,
        )

        if not result.admissible:
            # Governance failure — NOT a reviewer rejection. Fail closed.
            self._fail_closed_governance(
                state, step_id, governed_request,
                rejection_reason=result.rejection_reason,
                warnings=result.warnings,
            )
            return info

        receipt = result.receipt
        receipt_dict = receipt.to_dict()
        receipt_digest = receipt.compute_receipt_digest()

        # H0.5: the receipt is NOT written into the accepted state here —
        # it rides ``info.receipt_dict`` as a metadata proposal that the
        # decision transition commits (and adopts) atomically.

        info.receipt_id = receipt.receipt_id
        info.receipt_digest = receipt_digest
        info.receipt_dict = receipt_dict
        info.trace_metadata = {
            "receipt_id": receipt.receipt_id,
            "receipt_digest": receipt_digest,
            "subject_type": governed_request.subject.subject_type,
            "request_id": governed_request.request_id,
            "request_digest": governed_request.compute_digest(),
            "reviewer_identity": reviewer_identity,
        }
        return info

    def _fail_closed_governance(
        self,
        state: ChainState,
        step_id: int,
        governed_request,
        rejection_reason: str,
        warnings: list[str] | None = None,
    ) -> None:
        """Terminal governance failure (H0.5 amendment 3): atomic transition.

        The failed status, the governed_review_failure metadata, and the
        governance-failure review event commit in ONE transaction through
        the transition seam; nothing is acknowledged before that commit.
        No receipt is stored.
        """
        failure_event = TraceEvent(
            run_id=state.run_id,
            chain_id=state.chain_id,
            node_id="risk_classifier",
            step_id=step_id,
            event_type=EventType.HUMAN_REVIEW_COMPLETED,
            actor=Actor.RUNTIME,
            decision="governance_failure",
            reason_codes=[REASON_REVIEW_RECEIPT_VERIFICATION_FAILED, rejection_reason],
            metadata={
                "request_id": governed_request.request_id,
                "subject_id": governed_request.subject.subject_id,
                "request_digest": governed_request.compute_digest(),
                "rejection_reason": rejection_reason,
            },
        )
        self._commit_review_transition(
            state,
            failure_event,
            status="failed",
            metadata={
                "governed_review_failure": {
                    "reason_code": REASON_REVIEW_RECEIPT_VERIFICATION_FAILED,
                    "rejection_reason": rejection_reason,
                    "warnings": warnings or [],
                    "request_id": governed_request.request_id,
                    "subject_id": governed_request.subject.subject_id,
                    "request_digest": governed_request.compute_digest(),
                },
            },
        )

    def _record_review_attempt(
        self,
        decision,
        governed_request,
        result,
        state: ChainState,
        step_id: int,
        reviewer_identity: str,
        attempted_outcome: str,
    ) -> None:
        """Persist one durable review decision attempt row (v2.25.0).

        Records exactly once, after verify(), for admitted AND rejected attempts.
        Calls the injected record_attempt callback (wired by the orchestrator to
        StateManager.record_review_attempt). No-op if not wired.
        """
        import uuid as _uuid
        attempt = {
            "review_attempt_id": f"rda_{state.run_id}_{step_id}_{_uuid.uuid4().hex[:8]}",
            "run_id": state.run_id,
            "chain_id": state.chain_id,
            "step_id": step_id,
            "request_id": governed_request.request_id,
            "request_digest": governed_request.compute_digest(),
            "subject_type": governed_request.subject.subject_type,
            "subject_id": governed_request.subject.subject_id,
            "attempted_decision_type": decision.decision_type,
            "attempted_outcome": attempted_outcome,
            "reviewer_identity": reviewer_identity,
            "required_reviewer_role": governed_request.required_reviewer_role,
            "admitted": bool(result.admissible),
            "rejection_reason": result.rejection_reason if not result.admissible else "",
            "verifier_checks": {"warnings": list(result.warnings)},
            "policy_digest": self._policy.compute_digest(),
            "graph_digest": getattr(state, "execution_order_hash", "") or "",
            "created_at": _now_iso(),
            "retention_status": "active",
        }
        try:
            self._record_attempt(attempt)
        except Exception:
            # Never let attempt-logging crash the runtime; the audit trail is
            # best-effort relative to chain execution.
            pass

    def _default_rationale(self, risk_output: dict[str, Any], review_required: bool) -> str:
        """Build a non-empty rationale from risk signals (verifier requires >=3 chars for high risk).

        Test hook: NODECHAIN_REVIEW_RATIONALE_OVERRIDE, when set, is used verbatim
        (including empty string) — lets tests force a verifier failure to exercise
        the fail-closed path.
        """
        override = os.environ.get("NODECHAIN_REVIEW_RATIONALE_OVERRIDE")
        if override is not None:
            return override
        risk_level = str(risk_output.get("risk_level", "medium")).lower()
        factors = risk_output.get("risk_factors") or risk_output.get("uncertainty_disclosures") or []
        if isinstance(factors, list) and factors:
            return f"Runtime review gate: {risk_level} risk ({', '.join(str(f) for f in factors[:3])})"
        if review_required:
            return f"Runtime review gate: review_required=true, {risk_level} risk"
        return f"Runtime review gate: {risk_level} risk classification"

    # ── Internal ────────────────────────────────────────────────

    async def _get_decision(
        self,
        risk_output: dict[str, Any],
        chain_outputs: dict[str, Any],
        chain_name: str,
    ) -> str:
        """Get a review decision from the appropriate adapter."""
        mode = self.review_mode

        if mode in ("auto-approve", "auto-reject", "auto-revision"):
            from nodechain.adapters.auto_review_adapter import AutoReviewAdapter
            decision_map = {
                "auto-approve": "approve",
                "auto-reject": "reject",
                "auto-revision": "request_revision",
            }
            adapter = AutoReviewAdapter(decision=decision_map[mode])
            return await adapter.request_review(
                risk_assessment=risk_output,
                chain_outputs=chain_outputs,
                chain_name=chain_name,
            )

        # Pause mode — state already persisted above; raise to halt execution.
        if mode == "pause":
            raise ReviewPausedException(
                run_id=chain_outputs.get("run_id", "unknown"),
                step_id=chain_outputs.get("step_id", 0),
            )

        # Interactive mode — use HumanAdapter
        from nodechain.adapters.human_adapter import HumanAdapter
        import os
        timeout_minutes = int(os.environ.get("NODECHAIN_REVIEW_TIMEOUT_MINUTES", "30"))
        # Check for injected decision (testing/automation)
        decision_provider = os.environ.get("NODECHAIN_REVIEW_DECISION", None)
        adapter = HumanAdapter(
            timeout_minutes=timeout_minutes,
            decision_provider=decision_provider,
        )
        return await adapter.request_review(
            risk_assessment=risk_output,
            chain_outputs=chain_outputs,
            chain_name=chain_name,
        )


@dataclass
class _ReceiptInfo:
    """Internal carrier for materialized receipt artifacts."""
    receipt_id: str | None = None
    receipt_digest: str | None = None
    receipt_dict: dict[str, Any] = field(default_factory=dict)
    trace_metadata: dict[str, Any] = field(default_factory=dict)


def _make_reviewer_policy():
    """Construct the shared ReviewerPolicy used for both digest and verification."""
    from nodechain.sdk.review_workbench import ReviewerPolicy
    return ReviewerPolicy()
