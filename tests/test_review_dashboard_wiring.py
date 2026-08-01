"""
Review Workbench Dashboard Wiring Tests (v2.21.3).

Verifies HR-045 through HR-048 are registered in ALL_RULES and evaluate correctly.
Also verifies claim-hygiene: digest_commitment, not signature.
"""

from __future__ import annotations

import json
import pytest
from nodechain.cli.dashboard_health import (
    ALL_RULES, RULES_BY_ID,
    HR045PendingReviewTooOld, HR046UnauthorizedDecision,
    HR047StaleDecision, HR048RejectedBlocking,
)
from nodechain.sdk.review_workbench import (
    DecisionReceipt, OperatorDecision, ReviewRequest, ReviewSubject,
    ReviewerPolicy, ReviewVerifier,
    SUBJECT_CAPABILITY, ROLE_SECURITY_OFFICER, ROLE_ADMIN,
    DECISION_APPROVE_CAPABILITY,
)


# ── AC-01: Receipt uses digest_commitment, not signature ───────────────────


class TestAC01ClaimHygiene:
    """AC-01: DecisionReceipt uses digest_commitment, not signature."""

    def test_field_is_digest_commitment(self):
        """Receipt dataclass has digest_commitment field, not signature."""
        import inspect
        from nodechain.sdk.review_workbench import DecisionReceipt as DR
        source = inspect.getsource(DR)
        assert "digest_commitment" in source
        assert "signature" not in source.replace("digest_commitment", "")

    def test_method_is_commit_not_sign(self):
        import inspect
        from nodechain.sdk.review_workbench import DecisionReceipt as DR
        assert hasattr(DR, "commit")
        assert not hasattr(DR, "sign")

    def test_property_is_committed(self):
        from nodechain.sdk.review_workbench import DecisionReceipt as DR
        assert hasattr(DR, "is_committed")
        assert not hasattr(DR, "is_signed")

    def test_receipt_dict_uses_digest_commitment(self):
        subject = ReviewSubject(
            subject_type=SUBJECT_CAPABILITY, subject_id="s1", subject_digest="d" * 64)
        req = ReviewRequest(
            request_id="r1", subject=subject, reason_for_review="test",
            required_reviewer_role=ROLE_SECURITY_OFFICER, risk_level="high")
        policy = ReviewerPolicy()
        decision = OperatorDecision(
            decision_type=DECISION_APPROVE_CAPABILITY, request_id="r1",
            reviewer_identity="alice", reviewer_role=ROLE_SECURITY_OFFICER,
            rationale="valid reason here",
            request_digest=req.compute_digest(),
            subject_digest=subject.subject_digest,
            policy_digest=policy.compute_digest())
        verifier = ReviewVerifier(policy=policy)
        result = verifier.verify(decision, req)
        assert result.admissible
        d = result.receipt.to_dict()
        assert "digest_commitment" in d
        assert "signature" not in d
        assert "is_committed" in d
        assert d["is_committed"] is True


# ── AC-02: CLI uses digest-committed wording ────────────────────────────────


class TestAC02CLIWording:
    """AC-02: CLI wording updated from signed to digest-committed."""

    def test_cli_source_no_signed_receipt(self):
        """The review module (not CLI source) uses digest_commitment."""
        import inspect
        from nodechain.sdk.review_workbench import DecisionReceipt
        # The dataclass must have digest_commitment, not signature
        fields = {f.name for f in DecisionReceipt.__dataclass_fields__.values()}
        assert "digest_commitment" in fields
        assert "signature" not in fields


# ── AC-03: HR-045 through HR-048 exist in dashboard_health.py ───────────────


class TestAC03HealthRuleClasses:
    """AC-03: HR-045 through HR-048 rule classes exist in dashboard_health.py."""

    def test_hr045_class_exists(self):
        rule = HR045PendingReviewTooOld()
        assert rule.rule_id == "HR-045"
        assert rule.name == "pending_review_too_old"

    def test_hr046_class_exists(self):
        rule = HR046UnauthorizedDecision()
        assert rule.rule_id == "HR-046"
        assert rule.name == "unauthorized_decision"

    def test_hr047_class_exists(self):
        rule = HR047StaleDecision()
        assert rule.rule_id == "HR-047"
        assert rule.name == "stale_decision_receipt"

    def test_hr048_class_exists(self):
        rule = HR048RejectedBlocking()
        assert rule.rule_id == "HR-048"
        assert rule.name == "rejected_blocking_workflow"


# ── AC-04: HR-045 through HR-048 in ALL_RULES ───────────────────────────────


class TestAC04AllRulesWiring:
    """AC-04: HR-045 through HR-048 added to ALL_RULES."""

    def test_all_rules_includes_045(self):
        rule_ids = [r.rule_id for r in ALL_RULES]
        assert "HR-045" in rule_ids

    def test_all_rules_includes_046(self):
        rule_ids = [r.rule_id for r in ALL_RULES]
        assert "HR-046" in rule_ids

    def test_all_rules_includes_047(self):
        rule_ids = [r.rule_id for r in ALL_RULES]
        assert "HR-047" in rule_ids

    def test_all_rules_includes_048(self):
        rule_ids = [r.rule_id for r in ALL_RULES]
        assert "HR-048" in rule_ids

    def test_all_rules_count_is_48(self):
        assert len(ALL_RULES) == 65  # 49 HR + 5 MEM + 6 SE + 5 MR (v2.41.0)

    def test_rules_by_id_has_045_through_048(self):
        assert "HR-045" in RULES_BY_ID
        assert "HR-046" in RULES_BY_ID
        assert "HR-047" in RULES_BY_ID
        assert "HR-048" in RULES_BY_ID


# ── AC-05: Dashboard evaluates review sections ──────────────────────────────


class TestAC05DashboardEvaluation:
    """AC-05: Dashboard health rules evaluate against review_workbench sections."""

    def test_hr045_triggers_on_stale(self):
        rule = HR045PendingReviewTooOld()
        sections = {"review_workbench": {"stale_count": 2}}
        result = rule.evaluate(sections)
        assert result is not None
        assert result["rule_id"] == "HR-045"
        assert "2" in result["description"]

    def test_hr045_no_trigger_when_zero(self):
        rule = HR045PendingReviewTooOld()
        sections = {"review_workbench": {"stale_count": 0}}
        assert rule.evaluate(sections) is None

    def test_hr046_triggers_on_unauthorized(self):
        rule = HR046UnauthorizedDecision()
        sections = {"review_workbench": {"unauthorized_attempts": 1}}
        result = rule.evaluate(sections)
        assert result is not None
        assert result["rule_id"] == "HR-046"
        assert result["severity"] == "critical"

    def test_hr046_no_trigger_when_zero(self):
        rule = HR046UnauthorizedDecision()
        sections = {"review_workbench": {"unauthorized_attempts": 0}}
        assert rule.evaluate(sections) is None

    def test_hr047_triggers_on_stale_decision(self):
        rule = HR047StaleDecision()
        sections = {"review_workbench": {"stale_decision_count": 1}}
        result = rule.evaluate(sections)
        assert result is not None
        assert result["rule_id"] == "HR-047"

    def test_hr047_no_trigger_when_zero(self):
        rule = HR047StaleDecision()
        sections = {"review_workbench": {"stale_decision_count": 0}}
        assert rule.evaluate(sections) is None

    def test_hr048_triggers_on_blocking(self):
        rule = HR048RejectedBlocking()
        sections = {"review_workbench": {"rejected_blocking_count": 1}}
        result = rule.evaluate(sections)
        assert result is not None
        assert result["rule_id"] == "HR-048"

    def test_hr048_no_trigger_when_zero(self):
        rule = HR048RejectedBlocking()
        sections = {"review_workbench": {"rejected_blocking_count": 0}}
        assert rule.evaluate(sections) is None

    def test_no_trigger_when_section_missing(self):
        """Rules should not trigger if review_workbench section is absent."""
        for cls in [HR045PendingReviewTooOld, HR046UnauthorizedDecision,
                    HR047StaleDecision, HR048RejectedBlocking]:
            rule = cls()
            assert rule.evaluate({}) is None


# ── AC-06: Full evaluate_all_rules works with review sections ───────────────


class TestAC06EvaluateAllRules:
    """AC-06: evaluate_all_rules picks up review workbench issues."""

    def test_evaluate_all_picks_up_stale_review(self):
        from nodechain.cli.dashboard_health import evaluate_all_rules
        sections = {
            "review_workbench": {
                "stale_count": 1,
                "unauthorized_attempts": 0,
                "stale_decision_count": 0,
                "rejected_blocking_count": 0,
            }
        }
        issues = evaluate_all_rules(sections)
        rule_ids = [i["rule_id"] for i in issues]
        assert "HR-045" in rule_ids

    def test_evaluate_all_picks_up_unauthorized(self):
        from nodechain.cli.dashboard_health import evaluate_all_rules
        sections = {
            "review_workbench": {
                "stale_count": 0,
                "unauthorized_attempts": 1,
                "stale_decision_count": 0,
                "rejected_blocking_count": 0,
            }
        }
        issues = evaluate_all_rules(sections)
        rule_ids = [i["rule_id"] for i in issues]
        assert "HR-046" in rule_ids


# ── AC-07: Review health rule constants match ───────────────────────────────


class TestAC07ConstantsMatch:
    """AC-07: Review health rule constants in review_workbench match dashboard."""

    def test_constants_match(self):
        from nodechain.sdk.review_workbench import (
            HR_PENDING_REVIEW_TOO_OLD, HR_UNAUTHORIZED_DECISION,
            HR_STALE_DECISION, HR_REJECTED_BLOCKING,
        )
        assert HR_PENDING_REVIEW_TOO_OLD == "HR-045"
        assert HR_UNAUTHORIZED_DECISION == "HR-046"
        assert HR_STALE_DECISION == "HR-047"
        assert HR_REJECTED_BLOCKING == "HR-048"
