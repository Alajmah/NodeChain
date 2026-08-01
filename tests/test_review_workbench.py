"""
Governed Review Workbench Tests (v2.21.3).

OR-001: A human/operator decision is admissible only if it references a
materialized review review_request, validates the bound artifacts, satisfies reviewer
authority policy, records rationale, and emits a decision receipt. No operator
decision may mutate runtime state directly.

Tests cover AC-01 through AC-15 from the v2.21.3 acceptance criteria.
"""

from __future__ import annotations

import json
import hashlib
import pytest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from click.testing import CliRunner

from nodechain.sdk.review_workbench import (
    OR_001,
    ReviewRequest,
    ReviewSubject,
    ReviewerPolicy,
    OperatorDecision,
    DecisionReceipt,
    ReviewQueue,
    ReviewVerifier,
    VerificationResult,
    REVIEW_SCHEMA_VERSION,
    # Decision types
    DECISION_APPROVE_CAPABILITY, DECISION_REJECT_CAPABILITY,
    DECISION_APPROVE_BRANCH_MERGE, DECISION_REJECT_BRANCH_MERGE,
    DECISION_APPROVE_COMPENSATION, DECISION_REJECT_COMPENSATION,
    DECISION_APPROVE_DEPLOYMENT, DECISION_REJECT_DEPLOYMENT,
    DECISION_APPROVE_REMOTE_BINDING, DECISION_REJECT_REMOTE_BINDING,
    DECISION_ACKNOWLEDGE_HEALTH,
    ALL_DECISION_TYPES,
    # Subject types
    SUBJECT_CAPABILITY, SUBJECT_BRANCH_MERGE, SUBJECT_COMPENSATION,
    SUBJECT_DEPLOYMENT, SUBJECT_REMOTE_BINDING, SUBJECT_HEALTH,
    ALL_SUBJECT_TYPES,
    # Roles
    ROLE_OPERATOR, ROLE_SECURITY_OFFICER, ROLE_RELEASE_MANAGER, ROLE_ADMIN,
    # Rejection reasons
    REJECT_NO_REQUEST, REJECT_SUBJECT_MISMATCH, REJECT_POLICY_MISMATCH,
    REJECT_UNAUTHORIZED, REJECT_MISSING_RATIONALE, REJECT_STALE,
    REJECT_DECISION_TYPE_MISMATCH,
    # Outcomes
    DECISION_APPROVE, DECISION_REJECT, DECISION_ACKNOWLEDGE,
    # Health rules
    HR_PENDING_REVIEW_TOO_OLD, HR_UNAUTHORIZED_DECISION,
    HR_STALE_DECISION, HR_REJECTED_BLOCKING,
)
from nodechain.cli.main import cli


# ── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture
def subject() -> ReviewSubject:
    return ReviewSubject(
        subject_type=SUBJECT_CAPABILITY,
        subject_id="cap_req_001",
        subject_digest="a" * 64,
        metadata={"capability": "search"},
    )


@pytest.fixture
def review_request(subject) -> ReviewRequest:
    """Fixture renamed from review_request to avoid pytest reserved word."""
    return ReviewRequest(
        request_id="req_001",
        subject=subject,
        reason_for_review="Ambiguous capability selection between two packages",
        required_reviewer_role=ROLE_SECURITY_OFFICER,
        risk_level="high",
        graph_digest="b" * 64,
        policy_digest="c" * 64,
        trace_event_ids=["e1", "e2"],
    )


@pytest.fixture
def policy() -> ReviewerPolicy:
    return ReviewerPolicy()


@pytest.fixture
def verifier(policy) -> ReviewVerifier:
    return ReviewVerifier(policy=policy)


@pytest.fixture
def valid_decision(review_request, policy) -> OperatorDecision:
    return OperatorDecision(
        decision_type=DECISION_APPROVE_CAPABILITY,
        request_id=review_request.request_id,
        reviewer_identity="alice@example.com",
        reviewer_role=ROLE_SECURITY_OFFICER,
        rationale="Package A has better certification evidence and sandbox isolation.",
        request_digest=review_request.compute_digest(),
        subject_digest=review_request.subject.subject_digest,
        policy_digest=policy.compute_digest(),
    )


# ── AC-01: ReviewRequest schema exists ──────────────────────────────────────


class TestAC01ReviewRequestSchema:
    """AC-01: ReviewRequest schema exists."""

    def test_review_request_creates(self, subject):
        req = ReviewRequest(
            request_id="r1",
            subject=subject,
            reason_for_review="test",
            required_reviewer_role=ROLE_ADMIN,
        )
        assert req.request_id == "r1"
        assert req.status == "pending"

    def test_review_request_has_all_fields(self, review_request):
        d = review_request.to_dict()
        assert "request_id" in d
        assert "subject" in d
        assert "reason_for_review" in d
        assert "required_reviewer_role" in d
        assert "graph_digest" in d
        assert "policy_digest" in d
        assert "trace_event_ids" in d
        assert "created_at" in d
        assert "request_digest" in d


# ── AC-02: ReviewRequest binds all required fields ──────────────────────────


class TestAC02RequestBinding:
    """AC-02: ReviewRequest binds all required fields."""

    def test_binds_request_id(self, review_request):
        assert review_request.request_id == "req_001"

    def test_binds_subject_type(self, review_request):
        assert review_request.subject.subject_type == SUBJECT_CAPABILITY

    def test_binds_subject_digest(self, review_request):
        assert review_request.subject.subject_digest == "a" * 64

    def test_binds_graph_digest(self, review_request):
        assert review_request.graph_digest == "b" * 64

    def test_binds_policy_digest(self, review_request):
        assert review_request.policy_digest == "c" * 64

    def test_binds_trace_events(self, review_request):
        assert review_request.trace_event_ids == ["e1", "e2"]

    def test_binds_reason(self, review_request):
        assert "Ambiguous" in review_request.reason_for_review

    def test_binds_required_role(self, review_request):
        assert review_request.required_reviewer_role == ROLE_SECURITY_OFFICER

    def test_binds_created_at(self, review_request):
        assert review_request.created_at != ""

    def test_invalid_subject_type_raises(self):
        with pytest.raises(ValueError, match="Unknown subject type"):
            ReviewSubject(
                subject_type="invalid_type",
                subject_id="x",
                subject_digest="d",
            )


# ── AC-03: ReviewerPolicy schema exists ─────────────────────────────────────


class TestAC03ReviewerPolicy:
    """AC-03: ReviewerPolicy schema exists."""

    def test_policy_creates(self):
        p = ReviewerPolicy()
        assert p.policy_id == "default"

    def test_policy_has_digest(self, policy):
        assert policy.compute_digest() != ""

    def test_policy_is_authorized(self, policy):
        assert policy.is_authorized(ROLE_ADMIN, SUBJECT_CAPABILITY)
        assert policy.is_authorized(ROLE_SECURITY_OFFICER, SUBJECT_CAPABILITY)

    def test_policy_not_authorized(self, policy):
        assert not policy.is_authorized(ROLE_OPERATOR, SUBJECT_CAPABILITY)

    def test_rationale_required_high(self, policy):
        assert policy.rationale_required("high") is True
        assert policy.rationale_required("critical") is True

    def test_rationale_not_required_low(self, policy):
        assert policy.rationale_required("low") is False


# ── AC-04: OperatorDecision schema exists ───────────────────────────────────


class TestAC04OperatorDecision:
    """AC-04: OperatorDecision schema exists."""

    def test_decision_creates(self, valid_decision):
        assert valid_decision.decision_type == DECISION_APPROVE_CAPABILITY

    def test_decision_outcome(self, valid_decision):
        assert valid_decision.outcome == DECISION_APPROVE

    def test_decision_has_digest(self, valid_decision):
        assert valid_decision.compute_digest() != ""

    def test_invalid_decision_type_raises(self):
        with pytest.raises(ValueError, match="Unknown decision type"):
            OperatorDecision(
                decision_type="invalid",
                request_id="r1",
                reviewer_identity="x",
                reviewer_role=ROLE_ADMIN,
                rationale="test",
                request_digest="d",
                subject_digest="d",
                policy_digest="d",
            )

    def test_all_decision_types_valid(self):
        for dt in ALL_DECISION_TYPES:
            d = OperatorDecision(
                decision_type=dt,
                request_id="r1",
                reviewer_identity="x",
                reviewer_role=ROLE_ADMIN,
                rationale="ok",
                request_digest="d",
                subject_digest="d",
                policy_digest="d",
            )
            assert d.outcome in (DECISION_APPROVE, DECISION_REJECT, DECISION_ACKNOWLEDGE, "request_revision")


# ── AC-05: DecisionReceipt is digest-committed ──────────────────────────────


class TestAC05DecisionReceipt:
    """AC-05: DecisionReceipt schema exists and is digest-committed."""

    def test_receipt_creates(self, valid_decision, review_request, policy):
        receipt = DecisionReceipt(
            receipt_id="rcpt_001",
            decision=valid_decision,
            request_id=review_request.request_id,
            request_digest=review_request.compute_digest(),
            subject_type=review_request.subject.subject_type,
            subject_id=review_request.subject.subject_id,
            subject_digest=review_request.subject.subject_digest,
            policy_digest=policy.compute_digest(),
        )
        receipt.commit()
        assert receipt.is_committed

    def test_receipt_digest_deterministic(self, valid_decision, review_request, policy):
        receipt = DecisionReceipt(
            receipt_id="rcpt_001",
            decision=valid_decision,
            request_id=review_request.request_id,
            request_digest=review_request.compute_digest(),
            subject_type=review_request.subject.subject_type,
            subject_id=review_request.subject.subject_id,
            subject_digest=review_request.subject.subject_digest,
            policy_digest=policy.compute_digest(),
        )
        d1 = receipt.compute_receipt_digest()
        d2 = receipt.compute_receipt_digest()
        assert d1 == d2

    def test_unsigned_receipt_not_valid(self, valid_decision, review_request, policy):
        receipt = DecisionReceipt(
            receipt_id="rcpt_001",
            decision=valid_decision,
            request_id=review_request.request_id,
            request_digest=review_request.compute_digest(),
            subject_type=review_request.subject.subject_type,
            subject_id=review_request.subject.subject_id,
            subject_digest=review_request.subject.subject_digest,
            policy_digest=policy.compute_digest(),
        )
        assert not receipt.is_committed

    def test_receipt_to_json(self, valid_decision, review_request, policy):
        receipt = DecisionReceipt(
            receipt_id="rcpt_001",
            decision=valid_decision,
            request_id=review_request.request_id,
            request_digest=review_request.compute_digest(),
            subject_type=review_request.subject.subject_type,
            subject_id=review_request.subject.subject_id,
            subject_digest=review_request.subject.subject_digest,
            policy_digest=policy.compute_digest(),
        )
        receipt.commit()
        j = json.loads(receipt.to_json())
        assert j["receipt_id"] == "rcpt_001"
        assert j["is_committed"] is True


# ── AC-06: Review queue can list pending ────────────────────────────────────


class TestAC06ReviewQueue:
    """AC-06: Review queue can list pending review requests."""

    def test_queue_starts_empty(self):
        q = ReviewQueue()
        assert q.pending_count == 0

    def test_submit_and_list(self, review_request):
        q = ReviewQueue()
        q.submit(review_request)
        assert q.pending_count == 1
        pending = q.list_pending()
        assert pending[0].request_id == "req_001"

    def test_filter_by_subject_type(self, review_request):
        q = ReviewQueue()
        q.submit(review_request)
        caps = q.list_by_subject_type(SUBJECT_CAPABILITY)
        assert len(caps) == 1
        deploys = q.list_by_subject_type(SUBJECT_DEPLOYMENT)
        assert len(deploys) == 0

    def test_filter_by_risk(self, review_request):
        q = ReviewQueue()
        q.submit(review_request)
        high = q.list_by_risk("high")
        assert len(high) == 1

    def test_duplicate_rejected(self, review_request):
        q = ReviewQueue()
        q.submit(review_request)
        with pytest.raises(ValueError, match="Duplicate"):
            q.submit(review_request)


# ── AC-07: Operator can approve/reject with rationale ───────────────────────


class TestAC07ApproveReject:
    """AC-07: Operator can approve/reject with rationale."""

    def test_approve_produces_receipt(self, verifier, valid_decision, review_request):
        result = verifier.verify(valid_decision, review_request)
        assert result.admissible
        assert result.receipt is not None
        assert result.receipt.decision.outcome == DECISION_APPROVE

    def test_reject_produces_receipt(self, review_request, policy):
        decision = OperatorDecision(
            decision_type=DECISION_REJECT_CAPABILITY,
            request_id=review_request.request_id,
            reviewer_identity="bob",
            reviewer_role=ROLE_SECURITY_OFFICER,
            rationale="Package has unresolved trust issues.",
            request_digest=review_request.compute_digest(),
            subject_digest=review_request.subject.subject_digest,
            policy_digest=policy.compute_digest(),
        )
        verifier = ReviewVerifier(policy=policy)
        result = verifier.verify(decision, review_request)
        assert result.admissible
        assert result.receipt.decision.outcome == DECISION_REJECT


# ── AC-08: Decision verifies reviewer authority ─────────────────────────────


class TestAC08ReviewerAuthority:
    """AC-08: Decision verifies reviewer authority against ReviewerPolicy."""

    def test_unauthorized_role_rejected(self, review_request, policy):
        """Operator role cannot review capability selection."""
        decision = OperatorDecision(
            decision_type=DECISION_APPROVE_CAPABILITY,
            request_id=review_request.request_id,
            reviewer_identity="charlie",
            reviewer_role=ROLE_OPERATOR,
            rationale="I approve this.",
            request_digest=review_request.compute_digest(),
            subject_digest=review_request.subject.subject_digest,
            policy_digest=policy.compute_digest(),
        )
        verifier = ReviewVerifier(policy=policy)
        result = verifier.verify(decision, review_request)
        assert not result.admissible
        assert result.rejection_reason == REJECT_UNAUTHORIZED

    def test_admin_can_review_anything(self, review_request, policy):
        decision = OperatorDecision(
            decision_type=DECISION_APPROVE_CAPABILITY,
            request_id=review_request.request_id,
            reviewer_identity="admin_user",
            reviewer_role=ROLE_ADMIN,
            rationale="Admin override with justification.",
            request_digest=review_request.compute_digest(),
            subject_digest=review_request.subject.subject_digest,
            policy_digest=policy.compute_digest(),
        )
        verifier = ReviewVerifier(policy=policy)
        result = verifier.verify(decision, review_request)
        assert result.admissible


# ── AC-09: Decision receipt references request digest ───────────────────────


class TestAC09ReceiptReferences:
    """AC-09: Decision receipt references the original ReviewRequest digest."""

    def test_receipt_has_request_digest(self, verifier, valid_decision, review_request):
        result = verifier.verify(valid_decision, review_request)
        assert result.admissible
        assert result.receipt.request_digest == review_request.compute_digest()

    def test_receipt_has_subject_digest(self, verifier, valid_decision, review_request):
        result = verifier.verify(valid_decision, review_request)
        assert result.receipt.subject_digest == review_request.subject.subject_digest

    def test_verify_receipt_against_request(self, verifier, valid_decision, review_request):
        result = verifier.verify(valid_decision, review_request)
        assert result.admissible
        assert verifier.verify_receipt(result.receipt, review_request)


# ── AC-10: Decision receipt records all fields ──────────────────────────────


class TestAC10ReceiptFields:
    """AC-10: Decision receipt records decision, reviewer, authority, rationale, timestamp."""

    def test_receipt_records_decision(self, verifier, valid_decision, review_request):
        result = verifier.verify(valid_decision, review_request)
        receipt = result.receipt
        assert receipt.decision.decision_type == DECISION_APPROVE_CAPABILITY

    def test_receipt_records_reviewer_identity(self, verifier, valid_decision, review_request):
        result = verifier.verify(valid_decision, review_request)
        assert result.receipt.decision.reviewer_identity == "alice@example.com"

    def test_receipt_records_reviewer_role(self, verifier, valid_decision, review_request):
        result = verifier.verify(valid_decision, review_request)
        assert result.receipt.decision.reviewer_role == ROLE_SECURITY_OFFICER

    def test_receipt_records_authority_source(self, verifier, valid_decision, review_request):
        result = verifier.verify(valid_decision, review_request)
        assert result.receipt.decision.authority_source == "reviewer_policy"

    def test_receipt_records_rationale_digest(self, verifier, valid_decision, review_request):
        result = verifier.verify(valid_decision, review_request)
        assert result.receipt.decision.rationale_digest != ""

    def test_receipt_records_timestamp(self, verifier, valid_decision, review_request):
        result = verifier.verify(valid_decision, review_request)
        assert result.receipt.created_at != ""

    def test_receipt_records_subject_digest(self, verifier, valid_decision, review_request):
        result = verifier.verify(valid_decision, review_request)
        assert result.receipt.subject_digest == review_request.subject.subject_digest

    def test_receipt_records_policy_digest(self, verifier, valid_decision, review_request):
        result = verifier.verify(valid_decision, review_request)
        assert result.receipt.policy_digest != ""


# ── AC-11: Verifier rejects all failure modes ───────────────────────────────


class TestAC11RejectionModes:
    """AC-11: Decision verifier rejects missing review_request, mismatched digests,
    unauthorized reviewer, missing rationale, stale request."""

    def test_reject_missing_request(self, verifier, review_request, policy):
        """Wrong request_id in decision."""
        decision = OperatorDecision(
            decision_type=DECISION_APPROVE_CAPABILITY,
            request_id="nonexistent",
            reviewer_identity="x",
            reviewer_role=ROLE_ADMIN,
            rationale="ok",
            request_digest=review_request.compute_digest(),
            subject_digest=review_request.subject.subject_digest,
            policy_digest=policy.compute_digest(),
        )
        result = verifier.verify(decision, review_request)
        assert not result.admissible
        assert result.rejection_reason == REJECT_NO_REQUEST

    def test_reject_subject_digest_mismatch(self, review_request, policy):
        decision = OperatorDecision(
            decision_type=DECISION_APPROVE_CAPABILITY,
            request_id=review_request.request_id,
            reviewer_identity="x",
            reviewer_role=ROLE_ADMIN,
            rationale="ok rationale",
            request_digest=review_request.compute_digest(),
            subject_digest="wrong_digest",
            policy_digest=policy.compute_digest(),
        )
        verifier = ReviewVerifier(policy=policy)
        result = verifier.verify(decision, review_request)
        assert not result.admissible
        assert result.rejection_reason == REJECT_SUBJECT_MISMATCH

    def test_reject_policy_digest_mismatch(self, review_request, policy):
        decision = OperatorDecision(
            decision_type=DECISION_APPROVE_CAPABILITY,
            request_id=review_request.request_id,
            reviewer_identity="x",
            reviewer_role=ROLE_ADMIN,
            rationale="ok rationale",
            request_digest=review_request.compute_digest(),
            subject_digest=review_request.subject.subject_digest,
            policy_digest="wrong_policy_digest",
        )
        verifier = ReviewVerifier(policy=policy)
        result = verifier.verify(decision, review_request)
        assert not result.admissible
        assert result.rejection_reason == REJECT_POLICY_MISMATCH

    def test_reject_missing_rationale_high_risk(self, review_request, policy):
        decision = OperatorDecision(
            decision_type=DECISION_APPROVE_CAPABILITY,
            request_id=review_request.request_id,
            reviewer_identity="x",
            reviewer_role=ROLE_SECURITY_OFFICER,
            rationale="",  # Missing!
            request_digest=review_request.compute_digest(),
            subject_digest=review_request.subject.subject_digest,
            policy_digest=policy.compute_digest(),
        )
        verifier = ReviewVerifier(policy=policy)
        result = verifier.verify(decision, review_request)
        assert not result.admissible
        assert result.rejection_reason == REJECT_MISSING_RATIONALE

    def test_reject_stale_request(self, subject, policy):
        """Request older than 72h should be rejected."""
        old_time = (datetime.now(timezone.utc) - timedelta(hours=73)).isoformat()
        old_request = ReviewRequest(
            request_id="old_req",
            subject=subject,
            reason_for_review="Old review",
            required_reviewer_role=ROLE_SECURITY_OFFICER,
            risk_level="high",
            created_at=old_time,
        )
        decision = OperatorDecision(
            decision_type=DECISION_APPROVE_CAPABILITY,
            request_id="old_req",
            reviewer_identity="x",
            reviewer_role=ROLE_SECURITY_OFFICER,
            rationale="Approving now.",
            request_digest=old_request.compute_digest(),
            subject_digest=subject.subject_digest,
            policy_digest=policy.compute_digest(),
        )
        verifier = ReviewVerifier(policy=policy)
        result = verifier.verify(decision, old_request)
        assert not result.admissible
        assert result.rejection_reason == REJECT_STALE

    def test_reject_decision_type_mismatch(self, review_request, policy):
        """Can't use a deployment decision for a capability subject."""
        decision = OperatorDecision(
            decision_type=DECISION_APPROVE_DEPLOYMENT,
            request_id=review_request.request_id,
            reviewer_identity="x",
            reviewer_role=ROLE_ADMIN,
            rationale="Wrong decision type.",
            request_digest=review_request.compute_digest(),
            subject_digest=review_request.subject.subject_digest,
            policy_digest=policy.compute_digest(),
        )
        verifier = ReviewVerifier(policy=policy)
        result = verifier.verify(decision, review_request)
        assert not result.admissible
        assert result.rejection_reason == REJECT_DECISION_TYPE_MISMATCH

    def test_reject_wrong_request_digest(self, review_request, policy):
        decision = OperatorDecision(
            decision_type=DECISION_APPROVE_CAPABILITY,
            request_id=review_request.request_id,
            reviewer_identity="x",
            reviewer_role=ROLE_SECURITY_OFFICER,
            rationale="ok rationale for this decision",
            request_digest="wrong_request_digest",
            subject_digest=review_request.subject.subject_digest,
            policy_digest=policy.compute_digest(),
        )
        verifier = ReviewVerifier(policy=policy)
        result = verifier.verify(decision, review_request)
        assert not result.admissible
        assert result.rejection_reason == REJECT_NO_REQUEST


# ── AC-12: Console can display review requests read-only ────────────────────


class TestAC12ConsoleReadOnly:
    """AC-12: Console can display review requests read-only."""

    def test_review_queue_to_dict(self, review_request):
        q = ReviewQueue()
        q.submit(review_request)
        d = q.to_dict()
        assert d["total_requests"] == 1
        assert d["pending_count"] == 1
        assert len(d["pending"]) == 1

    def test_queue_does_not_mutate_state(self, review_request):
        """The queue doesn't touch runtime state."""
        q = ReviewQueue()
        q.submit(review_request)
        # Queue has no DB, no persistence, no runtime refs
        forbidden = ["_db", "_store", "_runtime", "_persistence"]
        for attr in forbidden:
            assert not hasattr(q, attr)


# ── AC-13: Runtime may consume receipt, but decision doesn't mutate ─────────


class TestAC13NoDirectMutation:
    """AC-13: Runtime may consume a decision receipt, but the decision artifact
    itself does not directly mutate runtime state."""

    def test_decision_has_no_mutation_methods(self, valid_decision):
        forbidden = ["save", "write", "execute", "apply", "mutate", "deploy"]
        for m in forbidden:
            assert not callable(getattr(valid_decision, m, None))

    def test_verifier_has_no_mutation_methods(self, verifier):
        forbidden = ["save", "write", "execute", "apply", "mutate", "deploy"]
        for m in forbidden:
            assert not callable(getattr(verifier, m, None))

    def test_receipt_has_no_mutation_methods(self):
        """DecisionReceipt only has sign() for its own digest — no external mutation."""
        forbidden = ["save", "write", "execute", "apply_to_runtime", "deploy"]
        for m in forbidden:
            assert not hasattr(DecisionReceipt, m) or not callable(getattr(DecisionReceipt, m))


# ── AC-14: Dashboard review health rules ────────────────────────────────────


class TestAC14HealthRules:
    """AC-14: Dashboard adds review health rules HR-045 through HR-048."""

    def test_health_rule_ids_exist(self):
        assert HR_PENDING_REVIEW_TOO_OLD == "HR-045"
        assert HR_UNAUTHORIZED_DECISION == "HR-046"
        assert HR_STALE_DECISION == "HR-047"
        assert HR_REJECTED_BLOCKING == "HR-048"

    def test_queue_detects_stale(self, subject):
        q = ReviewQueue()
        old_time = (datetime.now(timezone.utc) - timedelta(hours=80)).isoformat()
        old_req = ReviewRequest(
            request_id="stale_1",
            subject=subject,
            reason_for_review="Old",
            required_reviewer_role=ROLE_ADMIN,
            created_at=old_time,
        )
        q.submit(old_req)
        stale = q.list_stale()
        assert len(stale) == 1

    def test_queue_detects_no_stale(self, review_request):
        q = ReviewQueue()
        q.submit(review_request)
        assert len(q.list_stale()) == 0


# ── AC-15: Tests cover all scenarios ────────────────────────────────────────


class TestAC15FullCoverage:
    """AC-15: Tests cover approve, reject, unauthorized, stale, digest mismatch, replay."""

    def test_all_decision_types_covered(self):
        """Every decision type is valid and maps to an outcome."""
        assert len(ALL_DECISION_TYPES) == 14  # 11 + 3 chain_review (v2.22.0)

    def test_all_subject_types_covered(self):
        assert len(ALL_SUBJECT_TYPES) == 7  # 6 + chain_review (v2.22.0)

    def test_replay_determinism(self, verifier, valid_decision, review_request):
        """Same decision + same request → same receipt digest."""
        r1 = verifier.verify(valid_decision, review_request)
        r2 = verifier.verify(valid_decision, review_request)
        assert r1.admissible and r2.admissible
        assert r1.receipt.compute_receipt_digest() == r2.receipt.compute_receipt_digest()

    def test_all_subject_decision_pairs_valid(self):
        """Each subject type maps to valid decision types."""
        for subject_type in ALL_SUBJECT_TYPES:
            decisions = _get_valid_decisions(subject_type)
            assert len(decisions) >= 1

    def test_branch_merge_approval(self):
        subject = ReviewSubject(
            subject_type=SUBJECT_BRANCH_MERGE,
            subject_id="merge_001",
            subject_digest="d" * 64,
        )
        req = ReviewRequest(
            request_id="req_merge",
            subject=subject,
            reason_for_review="High-risk branch merge",
            required_reviewer_role=ROLE_RELEASE_MANAGER,
            risk_level="high",
        )
        policy = ReviewerPolicy()
        decision = OperatorDecision(
            decision_type=DECISION_APPROVE_BRANCH_MERGE,
            request_id="req_merge",
            reviewer_identity="release_mgr",
            reviewer_role=ROLE_RELEASE_MANAGER,
            rationale="Branch passes all evaluation criteria.",
            request_digest=req.compute_digest(),
            subject_digest=subject.subject_digest,
            policy_digest=policy.compute_digest(),
        )
        verifier = ReviewVerifier(policy=policy)
        result = verifier.verify(decision, req)
        assert result.admissible

    def test_deployment_rejection(self):
        subject = ReviewSubject(
            subject_type=SUBJECT_DEPLOYMENT,
            subject_id="deploy_001",
            subject_digest="e" * 64,
        )
        req = ReviewRequest(
            request_id="req_deploy",
            subject=subject,
            reason_for_review="Deployment requires approval",
            required_reviewer_role=ROLE_RELEASE_MANAGER,
            risk_level="medium",
        )
        policy = ReviewerPolicy()
        decision = OperatorDecision(
            decision_type=DECISION_REJECT_DEPLOYMENT,
            request_id="req_deploy",
            reviewer_identity="release_mgr",
            reviewer_role=ROLE_RELEASE_MANAGER,
            rationale="Deployment fails compliance check.",
            request_digest=req.compute_digest(),
            subject_digest=subject.subject_digest,
            policy_digest=policy.compute_digest(),
        )
        verifier = ReviewVerifier(policy=policy)
        result = verifier.verify(decision, req)
        assert result.admissible
        assert result.receipt.decision.outcome == DECISION_REJECT

    def test_health_acknowledgment(self):
        subject = ReviewSubject(
            subject_type=SUBJECT_HEALTH,
            subject_id="hr_042",
            subject_digest="f" * 64,
        )
        req = ReviewRequest(
            request_id="req_health",
            subject=subject,
            reason_for_review="Branch violation detected",
            required_reviewer_role=ROLE_OPERATOR,
            risk_level="low",
        )
        policy = ReviewerPolicy()
        decision = OperatorDecision(
            decision_type=DECISION_ACKNOWLEDGE_HEALTH,
            request_id="req_health",
            reviewer_identity="ops_user",
            reviewer_role=ROLE_OPERATOR,
            rationale="Acknowledged.",
            request_digest=req.compute_digest(),
            subject_digest=subject.subject_digest,
            policy_digest=policy.compute_digest(),
        )
        verifier = ReviewVerifier(policy=policy)
        result = verifier.verify(decision, req)
        assert result.admissible
        assert result.receipt.decision.outcome == DECISION_ACKNOWLEDGE


def _get_valid_decisions(subject_type: str) -> set[str]:
    """Helper to get valid decisions for a subject type."""
    from nodechain.sdk.review_workbench import _SUBJECT_DECISION_MAP
    return _SUBJECT_DECISION_MAP.get(subject_type, frozenset())


# ── CLI Integration Tests ───────────────────────────────────────────────────


class TestCLIReview:
    """CLI review commands work correctly."""

    def test_review_group_exists(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["review", "--help"])
        assert result.exit_code == 0
        assert "submit" in result.output
        assert "decide" in result.output

    def test_review_submit(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(cli, [
            "review", "submit",
            "--request-id", "cli_req_001",
            "--subject-type", "capability_selection",
            "--subject-id", "cap_1",
            "--subject-digest", "a" * 64,
            "--reason", "CLI test review",
            "--role", "security_officer",
            "--risk", "high",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["request_id"] == "cli_req_001"
        assert data["request_digest"] != ""

    def test_review_submit_to_file(self, tmp_path):
        out = str(tmp_path / "review_request.json")
        runner = CliRunner()
        result = runner.invoke(cli, [
            "review", "submit",
            "--request-id", "file_req",
            "--subject-type", "deployment",
            "--subject-id", "dep_1",
            "--subject-digest", "b" * 64,
            "--reason", "File output test",
            "--role", "release_manager",
            "--risk", "medium",
            "--output", out,
        ])
        assert result.exit_code == 0
        assert Path(out).exists()
        data = json.loads(Path(out).read_text())
        assert data["request_id"] == "file_req"

    def test_review_decide_approve(self, tmp_path):
        """Full CLI flow: submit → decide → receipt."""
        # Step 1: Submit
        req_out = str(tmp_path / "req.json")
        runner = CliRunner()
        runner.invoke(cli, [
            "review", "submit",
            "--request-id", "flow_req",
            "--subject-type", "capability_selection",
            "--subject-id", "cap_1",
            "--subject-digest", "c" * 64,
            "--reason", "Full flow test",
            "--role", "security_officer",
            "--risk", "high",
            "--output", req_out,
        ])
        # Step 2: Decide
        result = runner.invoke(cli, [
            "review", "decide",
            "--request", req_out,
            "--decision", "approve_capability_selection",
            "--reviewer", "alice",
            "--role", "security_officer",
            "--rationale", "Package is well-certified and sandboxed.",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["decision"]["outcome"] == "approve"
        assert data["is_committed"] is True

    def test_review_decide_unauthorized(self, tmp_path):
        """Operator trying to approve capability → rejected."""
        req_out = str(tmp_path / "req.json")
        runner = CliRunner()
        runner.invoke(cli, [
            "review", "submit",
            "--request-id", "auth_req",
            "--subject-type", "capability_selection",
            "--subject-id", "cap_1",
            "--subject-digest", "d" * 64,
            "--reason", "Auth test",
            "--role", "security_officer",
            "--risk", "high",
            "--output", req_out,
        ])
        result = runner.invoke(cli, [
            "review", "decide",
            "--request", req_out,
            "--decision", "approve_capability_selection",
            "--reviewer", "ops_user",
            "--role", "operator",
            "--rationale", "Trying to approve.",
        ])
        assert result.exit_code == 10
        assert "REJECTED" in result.output


# ── OR-001 Invariant Tests ──────────────────────────────────────────────────


class TestOR001Invariant:
    """OR-001: The headline invariant is upheld."""

    def test_or_001_text(self):
        assert "materialized" in OR_001.lower()
        assert "review request" in OR_001.lower()
        assert "authority" in OR_001.lower()
        assert "rationale" in OR_001.lower()
        assert "receipt" in OR_001.lower()
        assert "mutate runtime state" in OR_001.lower()

    def test_no_direct_mutation_possible(self, verifier, valid_decision, review_request):
        """Verifying a decision and producing a receipt never mutates the request."""
        original_status = review_request.status
        original_digest = review_request.compute_digest()
        verifier.verify(valid_decision, review_request)
        assert review_request.status == original_status
        assert review_request.compute_digest() == original_digest

    def test_schema_version(self):
        assert REVIEW_SCHEMA_VERSION == "1.0.0"
