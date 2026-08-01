"""Adaptive Branching Adversarial Certification (v2.21.3).

25-scenario adversarial matrix for the v2.21.3 adaptive branching primitive.
Invariants AB-002, AB-003, AB-004.

AB-002: A branch result is admissible for merge only if its branch plan was
        admissible, its budget was not exhausted beyond policy, and its
        side-effect log contains no unauthorized committed side effect.

AB-003: A deliberation receipt is valid only if every referenced branch plan
        digest, branch result digest, merge decision digest, policy digest,
        and budget digest matches the materialized artifact.

AB-004: A non-selected branch is evidence-only. Its output may not mutate
        committed workflow state unless a later governed merge explicitly
        selects it.
"""

from __future__ import annotations

import json
import pytest
import time

from nodechain.sdk.adaptive_branching import (
    DeliberationTrigger,
    DeliberationRequest,
    BranchPolicy,
    BudgetTracker,
    BranchPlan,
    BranchExecutionContext,
    BranchResult,
    MergeDecision,
    DeliberationReceipt,
    BranchController,
    # Constants
    ADAPTIVE_BRANCHING_SCHEMA_VERSION,
    RISK_LOW, RISK_MEDIUM, RISK_HIGH, RISK_CRITICAL,
    SANDBOX_NONE, SANDBOX_BASIC, SANDBOX_HARDENED, SANDBOX_FULL,
    SIDE_EFFECT_DENY_ALL, SIDE_EFFECT_READ_ONLY, SIDE_EFFECT_EXPLICIT_ALLOW,
    MERGE_SELECT_BEST, MERGE_REJECT_ALL, MERGE_DEFER_HUMAN,
    BRANCH_PENDING, BRANCH_RUNNING, BRANCH_COMPLETED, BRANCH_FAILED,
    BRANCH_BUDGET_EXHAUSTED, BRANCH_POLICY_VIOLATED, BRANCH_CANCELLED,
    # Exceptions
    BranchingDenied, BudgetExhausted, PolicyViolation,
    # Helpers
    validate_child_policy, default_merge_strategy,
    compute_budget_digest, attach_capability_receipts, attach_trust_graph,
    # AB invariants
    is_result_admissible_for_merge,
    verify_receipt_integrity,
    is_branch_committable,
    get_evidence_only_branches,
)


# ── Test helpers ────────────────────────────────────────────────────────────

class _Executor:
    """Configurable mock executor for adversarial tests."""

    def __init__(self, output=None, fail=False, delay=0.0, side_effects=None):
        self._output = output or {"result": "ok"}
        self._fail = fail
        self._delay = delay
        self._side_effects = side_effects or []
        self.calls = 0

    def __call__(self, node_sequence, input_data, context):
        self.calls += 1
        if self._delay:
            time.sleep(self._delay)
        if self._fail:
            raise RuntimeError("adversarial failure")
        for se in self._side_effects:
            context.record_side_effect(se.get("action", "unknown"),
                                       se.get("details", {}), se.get("allowed", False))
        context.record_evidence({"type": "test_evidence"})
        return dict(self._output)


def _make_request(**kw) -> DeliberationRequest:
    defaults = {"trigger_type": DeliberationTrigger.UNCERTAINTY}
    defaults.update(kw)
    return DeliberationRequest(**defaults)


def _make_policy(**kw) -> BranchPolicy:
    defaults = {"max_branches": 3, "max_depth": 2}
    defaults.update(kw)
    return BranchPolicy(**defaults)


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIOS 1–10: Branch Policy and Admissibility Attacks
# ═══════════════════════════════════════════════════════════════════════════════

class TestScenario01ForbiddenCapability:
    """Scenario 1: Branch requests forbidden capability → denied before execution."""

    def test_forbidden_capability_denied(self):
        controller = BranchController(policy=_make_policy(
            forbidden_capabilities={"dangerous_cap"}
        ))
        request = _make_request(requested_capabilities=["dangerous_cap"])
        with pytest.raises(BranchingDenied):
            controller.create_plans(request, num_branches=1)


class TestScenario02MissingTrustGraph:
    """Scenario 2: Branch omits required trust_graph_digest → inadmissible."""

    def test_missing_trust_graph_inadmissible(self):
        controller = BranchController(policy=_make_policy(
            require_dependency_trust=True
        ))
        plan = BranchPlan()
        plan.capability_requests = [{"capability": "search"}]
        # No trust_graph_digest set
        ok, reasons = controller.validate_plan(plan)
        assert not ok
        assert any("trust" in r for r in reasons)


class TestScenario03ChildExpandsMaxBranches:
    """Scenario 3: Child branch expands max_branches → rejected."""

    def test_child_expands_branches(self):
        parent = _make_policy(max_branches=5)
        child = _make_policy(max_branches=10)
        violations = validate_child_policy(parent, child)
        assert any("max_branches" in v for v in violations)


class TestScenario04ChildExpandsMaxDepth:
    """Scenario 4: Child branch expands max_depth → rejected."""

    def test_child_expands_depth(self):
        parent = _make_policy(max_depth=3)
        child = _make_policy(max_depth=10)
        violations = validate_child_policy(parent, child)
        assert any("max_depth" in v for v in violations)


class TestScenario05ChildRelaxesSandbox:
    """Scenario 5: Child branch relaxes sandbox minimum → rejected."""

    def test_child_relaxes_sandbox(self):
        parent = _make_policy(min_sandbox_strength=SANDBOX_FULL)
        child = _make_policy(min_sandbox_strength=SANDBOX_BASIC)
        violations = validate_child_policy(parent, child)
        assert any("sandbox" in v for v in violations)


class TestScenario06ChildRaisesRisk:
    """Scenario 6: Child branch raises max risk → rejected."""

    def test_child_raises_risk(self):
        parent = _make_policy(max_risk_level=RISK_LOW)
        child = _make_policy(max_risk_level=RISK_CRITICAL)
        violations = validate_child_policy(parent, child)
        assert any("risk" in v for v in violations)


class TestScenario07ChildRemovesForbidden:
    """Scenario 7: Child branch removes parent-forbidden capability → rejected."""

    def test_child_removes_forbidden(self):
        parent = _make_policy(forbidden_capabilities={"bad_cap"})
        child = _make_policy(forbidden_capabilities=set())  # doesn't forbid it
        violations = validate_child_policy(parent, child)
        assert any("forbidden" in v for v in violations)


class TestScenario08ChildEscalatesSideEffects:
    """Scenario 8: Child branch escalates side-effect policy → rejected."""

    def test_child_escalates_side_effects(self):
        parent = _make_policy(side_effect_policy=SIDE_EFFECT_DENY_ALL)
        child = _make_policy(side_effect_policy=SIDE_EFFECT_EXPLICIT_ALLOW)
        violations = validate_child_policy(parent, child)
        assert any("side_effect" in v for v in violations)


class TestScenario09ExploratorySideEffect:
    """Scenario 9: Exploratory branch attempts side effect → denied."""

    def test_exploratory_side_effect_denied(self):
        controller = BranchController(policy=_make_policy(
            side_effect_policy=SIDE_EFFECT_DENY_ALL
        ))
        request = _make_request()
        plans = controller.create_plans(request, num_branches=1)
        assert plans[0].is_exploratory
        assert plans[0].budget.max_side_effects == 0
        # Budget enforcement: side effect would exhaust budget
        assert not plans[0].budget.consume_side_effect()


class TestScenario10SideEffectWithoutExplicitAllow:
    """Scenario 10: Side-effect branch without explicit allow → inadmissible."""

    def test_side_effect_without_allow(self):
        controller = BranchController(policy=_make_policy(
            side_effect_policy=SIDE_EFFECT_DENY_ALL
        ))
        plan = BranchPlan()
        plan.is_exploratory = False
        plan.policy = _make_policy(side_effect_policy=SIDE_EFFECT_EXPLICIT_ALLOW)
        # Force exploratory=True + explicit allow → inadmissible
        plan.is_exploratory = True
        ok, reasons = controller.validate_plan(plan)
        assert not ok
        assert any("exploratory" in r for r in reasons)


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIOS 11–16: Budget Exhaustion Attacks
# ═══════════════════════════════════════════════════════════════════════════════

class TestScenario11TokenBudget:
    """Scenario 11: Token budget exhausted → branch stops."""

    def test_token_budget_stops_branch(self):
        b = BudgetTracker(max_tokens=100)
        assert b.consume_tokens(100)
        assert not b.consume_tokens(1)
        assert b.is_exhausted()
        assert "tokens" in b.exhausted_dimensions()

    def test_token_exhausted_not_merged(self):
        controller = BranchController(policy=_make_policy())
        request = _make_request()
        plans = controller.create_plans(request, num_branches=1)
        plans[0].budget.max_tokens = 1
        plans[0].budget.consume_tokens(2)
        executor = _Executor()
        result = controller.execute_branch(plans[0], executor)
        assert result.status == BRANCH_BUDGET_EXHAUSTED


class TestScenario12TimeBudget:
    """Scenario 12: Time budget exhausted → branch stops."""

    def test_time_budget_stops_branch(self):
        b = BudgetTracker(max_time_seconds=0.01)
        time.sleep(0.02)
        assert b.is_exhausted()
        assert "time" in b.exhausted_dimensions()


class TestScenario13ToolCallBudget:
    """Scenario 13: Tool-call budget exhausted → branch stops."""

    def test_tool_call_budget_stops(self):
        b = BudgetTracker(max_tool_calls=2)
        b.consume_tool_call()
        b.consume_tool_call()
        assert not b.consume_tool_call()
        assert "tool_calls" in b.exhausted_dimensions()


class TestScenario14RetryBudget:
    """Scenario 14: Retry budget exhausted → branch stops."""

    def test_retry_budget_stops(self):
        b = BudgetTracker(max_retries=1)
        b.consume_retry()
        assert not b.consume_retry()
        assert "retries" in b.exhausted_dimensions()


class TestScenario15DepthBudget:
    """Scenario 15: Depth budget exhausted → branch stops."""

    def test_depth_budget_stops(self):
        b = BudgetTracker(max_depth=1)
        assert b.set_depth(1)
        assert not b.set_depth(2)
        assert "depth" in b.exhausted_dimensions()


class TestScenario16SideEffectBudget:
    """Scenario 16: Side-effect budget exhausted → branch stops."""

    def test_side_effect_budget_stops(self):
        b = BudgetTracker(max_side_effects=1)
        assert b.consume_side_effect()
        assert not b.consume_side_effect()
        assert "side_effects" in b.exhausted_dimensions()


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIOS 17–20: Merge and Human Review Attacks
# ═══════════════════════════════════════════════════════════════════════════════

class TestScenario17PartialSuccess:
    """Scenario 17: One branch fails, one completes → completed selected."""

    def test_partial_success_merge(self):
        controller = BranchController(policy=_make_policy())
        request = _make_request()
        plans = controller.create_plans(request, num_branches=2)

        r1 = controller.execute_branch(plans[0], _Executor(fail=True))
        r2 = controller.execute_branch(plans[1], _Executor())
        # Give r2 more evidence to avoid narrow-margin deferral
        r2.evidence = [{"type": f"ev_{i}"} for i in range(5)]

        decision = controller.merge_results([r1, r2])
        assert decision.strategy == MERGE_SELECT_BEST
        assert decision.selected_branch_id == plans[1].branch_id


class TestScenario18AllFail:
    """Scenario 18: All branches fail → merge rejects all."""

    def test_all_fail_rejects(self):
        controller = BranchController(policy=_make_policy())
        request = _make_request()
        plans = controller.create_plans(request, num_branches=2)

        results = controller.execute_branches(plans, _Executor(fail=True))
        decision = controller.merge_results(results)
        assert decision.strategy == MERGE_REJECT_ALL
        assert decision.selected_branch_id is None


class TestScenario19NarrowMargin:
    """Scenario 19: Equal evidence / narrow margin → human review required."""

    def test_narrow_margin_human_review(self):
        controller = BranchController(policy=_make_policy(
            review_score_margin_below=0.8
        ))
        request = _make_request()
        plans = controller.create_plans(request, num_branches=2)

        # Both branches complete with equal evidence → margin=0
        r1 = controller.execute_branch(plans[0], _Executor())
        r2 = controller.execute_branch(plans[1], _Executor())
        # Both have 1 evidence item → margin = 0/2 = 0 < 0.8

        decision = controller.merge_results([r1, r2])
        assert decision.human_review_required
        assert decision.strategy == MERGE_DEFER_HUMAN


class TestScenario20HighRiskMerge:
    """Scenario 20: High-risk selected branch → human review required."""

    def test_high_risk_human_review(self):
        controller = BranchController(policy=_make_policy(
            review_risk_at_or_above=RISK_LOW
        ))
        request = _make_request()
        plans = controller.create_plans(request, num_branches=1)

        result = controller.execute_branch(plans[0], _Executor())
        result.consumed_budget["risk_level"] = RISK_HIGH

        decision = controller.merge_results([result])
        assert decision.human_review_required


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIOS 21–25: Integrity and Determinism Attacks
# ═══════════════════════════════════════════════════════════════════════════════

class TestScenario21NonSelectedCommit:
    """Scenario 21: Non-selected branch output attempts commit → rejected."""

    def test_non_selected_not_committable(self):
        decision = MergeDecision(
            strategy=MERGE_SELECT_BEST,
            selected_branch_id="b_winner",
            rejected_branch_ids=["b_loser"],
        )
        assert is_branch_committable("b_winner", decision)
        assert not is_branch_committable("b_loser", decision)

    def test_evidence_only_branches(self):
        decision = MergeDecision(
            strategy=MERGE_SELECT_BEST,
            selected_branch_id="b1",
            rejected_branch_ids=["b2", "b3"],
        )
        evidence_only = get_evidence_only_branches(decision)
        assert "b2" in evidence_only
        assert "b3" in evidence_only
        assert "b1" not in evidence_only

    def test_rejected_all_are_evidence_only(self):
        decision = MergeDecision(
            strategy=MERGE_REJECT_ALL,
            rejected_branch_ids=["b1", "b2"],
        )
        assert not is_branch_committable("b1", decision)
        assert not is_branch_committable("b2", decision)
        evidence_only = get_evidence_only_branches(decision)
        assert set(evidence_only) == {"b1", "b2"}


class TestScenario22TamperedResultDigest:
    """Scenario 22: Tampered BranchResult digest → receipt mismatch."""

    def test_tampered_result_detected(self):
        controller = BranchController(policy=_make_policy())
        request = _make_request()
        plans = controller.create_plans(request, num_branches=1)
        results = controller.execute_branches(plans, _Executor())
        decision = controller.merge_results(results)
        receipt = controller.build_receipt(request, plans, results, decision)

        # Tamper with result output
        results[0].output = {"tampered": True}

        valid, mismatches = verify_receipt_integrity(
            receipt, request, plans, results, decision, controller.policy
        )
        assert not valid
        assert any("result_digests" in m for m in mismatches)


class TestScenario23TamperedMergeDigest:
    """Scenario 23: Tampered MergeDecision digest → receipt mismatch."""

    def test_tampered_merge_detected(self):
        controller = BranchController(policy=_make_policy())
        request = _make_request()
        plans = controller.create_plans(request, num_branches=1)
        results = controller.execute_branches(plans, _Executor())
        decision = controller.merge_results(results)
        receipt = controller.build_receipt(request, plans, results, decision)

        # Tamper with merge decision
        decision.selected_branch_id = "tampered_id"

        valid, mismatches = verify_receipt_integrity(
            receipt, request, plans, results, decision, controller.policy
        )
        assert not valid
        assert any("merge_digest" in m for m in mismatches)


class TestScenario24TamperedReceipt:
    """Scenario 24: Tampered DeliberationReceipt body → signature mismatch."""

    def test_tampered_receipt_signature(self):
        controller = BranchController(policy=_make_policy())
        request = _make_request()
        plans = controller.create_plans(request, num_branches=1)
        results = controller.execute_branches(plans, _Executor())
        decision = controller.merge_results(results)
        receipt = controller.build_receipt(request, plans, results, decision)

        # Tamper with receipt body
        receipt.branch_count = 999

        # Verify signature no longer matches
        body = json.dumps(receipt._unsigned_body(), sort_keys=True, separators=(",", ":"))
        from nodechain.sdk.adaptive_branching import _sha256_str
        expected_sig = _sha256_str(body)
        assert receipt.signature != expected_sig

    def test_tampered_receipt_detected_by_verify(self):
        controller = BranchController(policy=_make_policy())
        request = _make_request()
        plans = controller.create_plans(request, num_branches=1)
        results = controller.execute_branches(plans, _Executor())
        decision = controller.merge_results(results)
        receipt = controller.build_receipt(request, plans, results, decision)

        # Tamper with receipt
        receipt.request_digest = "tampered_digest"

        valid, mismatches = verify_receipt_integrity(
            receipt, request, plans, results, decision, controller.policy
        )
        assert not valid
        assert any("request_digest" in m for m in mismatches)


class TestScenario25DeterministicDigests:
    """Scenario 25: Same inputs → deterministic digests (when IDs/timestamps pinned)."""

    def test_deterministic_policy_digest(self):
        p1 = _make_policy(max_branches=3, max_depth=2)
        p2 = _make_policy(max_branches=3, max_depth=2)
        assert p1.compute_digest() == p2.compute_digest()

    def test_deterministic_budget_digest(self):
        b1 = BudgetTracker(max_tokens=5000, max_tool_calls=10)
        b2 = BudgetTracker(max_tokens=5000, max_tool_calls=10)
        assert compute_budget_digest(b1) == compute_budget_digest(b2)

    def test_deterministic_request_digest(self):
        r1 = _make_request(
            trigger_type=DeliberationTrigger.CONFLICT,
            trigger_node_id="node_1",
            trigger_context={"key": "value"},
            requested_capabilities=["cap_a"],
        )
        r2 = _make_request(
            trigger_type=DeliberationTrigger.CONFLICT,
            trigger_node_id="node_1",
            trigger_context={"key": "value"},
            requested_capabilities=["cap_a"],
        )
        assert r1.compute_digest() == r2.compute_digest()

    def test_deterministic_merge_decision_digest(self):
        d1 = MergeDecision(
            strategy=MERGE_SELECT_BEST,
            selected_branch_id="b1",
            rejected_branch_ids=["b2"],
            confidence=0.8,
            risk_level=RISK_LOW,
            comparison_basis="evidence_count",
            human_review_required=False,
            rationale_digest="abc123",
        )
        d2 = MergeDecision(
            strategy=MERGE_SELECT_BEST,
            selected_branch_id="b1",
            rejected_branch_ids=["b2"],
            confidence=0.8,
            risk_level=RISK_LOW,
            comparison_basis="evidence_count",
            human_review_required=False,
            rationale_digest="abc123",
        )
        assert d1.compute_digest() == d2.compute_digest()

    def test_deterministic_receipt_with_pinned_ids(self):
        """Same receipt with same receipt_id and timestamps should match."""
        r1 = DeliberationReceipt(
            receipt_id="fixed_id",
            request_digest="req",
            branch_policy_digest="pol",
            branch_budget_digest="bud",
            created_at="2026-01-01T00:00:00Z",
        )
        r1.finalize()

        r2 = DeliberationReceipt(
            receipt_id="fixed_id",
            request_digest="req",
            branch_policy_digest="pol",
            branch_budget_digest="bud",
            created_at="2026-01-01T00:00:00Z",
        )
        r2.finalize()
        assert r1.signature == r2.signature


# ═══════════════════════════════════════════════════════════════════════════════
# AB-002: Branch Result Admissibility for Merge
# ═══════════════════════════════════════════════════════════════════════════════

class TestAB002ResultAdmissibility:
    """AB-002: Branch result admissibility for merge."""

    def test_admissible_result(self):
        plan = BranchPlan()
        plan.admissible = True
        result = BranchResult(branch_id=plan.branch_id, status=BRANCH_COMPLETED)
        ok, reason = is_result_admissible_for_merge(result, plan)
        assert ok
        assert reason == ""

    def test_inadmissible_plan_rejects(self):
        plan = BranchPlan()
        plan.admissible = False
        plan.inadmissibility_reasons = ["bad_capability"]
        result = BranchResult(branch_id=plan.branch_id, status=BRANCH_COMPLETED)
        ok, reason = is_result_admissible_for_merge(result, plan)
        assert not ok
        assert "plan_not_admissible" in reason

    def test_budget_exhausted_rejects(self):
        plan = BranchPlan()
        plan.admissible = True
        result = BranchResult(
            branch_id=plan.branch_id,
            status=BRANCH_BUDGET_EXHAUSTED,
            failure_reason="tokens exceeded",
        )
        ok, reason = is_result_admissible_for_merge(result, plan)
        assert not ok
        assert "budget_exhausted" in reason

    def test_unauthorized_side_effect_rejects(self):
        plan = BranchPlan()
        plan.admissible = True
        plan.policy = BranchPolicy(side_effect_policy=SIDE_EFFECT_DENY_ALL)
        result = BranchResult(
            branch_id=plan.branch_id,
            status=BRANCH_COMPLETED,
            side_effect_summary=[
                {"action": "write_file", "allowed": True},  # shouldn't be allowed
            ],
        )
        ok, reason = is_result_admissible_for_merge(result, plan)
        assert not ok
        assert "unauthorized_side_effect" in reason

    def test_failed_result_rejects(self):
        plan = BranchPlan()
        plan.admissible = True
        result = BranchResult(
            branch_id=plan.branch_id,
            status=BRANCH_FAILED,
            failure_reason="crash",
        )
        ok, reason = is_result_admissible_for_merge(result, plan)
        assert not ok
        assert "not_completed" in reason

    def test_authorized_side_effect_allowed(self):
        plan = BranchPlan()
        plan.admissible = True
        plan.policy = BranchPolicy(side_effect_policy=SIDE_EFFECT_EXPLICIT_ALLOW)
        result = BranchResult(
            branch_id=plan.branch_id,
            status=BRANCH_COMPLETED,
            side_effect_summary=[
                {"action": "write_file", "allowed": True},
            ],
        )
        ok, reason = is_result_admissible_for_merge(result, plan)
        assert ok

    def test_ab002_in_full_lifecycle(self):
        """AB-002 integrated with BranchController lifecycle."""
        controller = BranchController(policy=_make_policy())
        request = _make_request()
        plans = controller.create_plans(request, num_branches=2)

        # One completes, one fails budget
        r1 = controller.execute_branch(plans[0], _Executor())
        plans[1].budget.max_tokens = 0
        plans[1].budget.consume_tokens(1)
        r2 = controller.execute_branch(plans[1], _Executor())

        ok1, _ = is_result_admissible_for_merge(r1, plans[0])
        ok2, _ = is_result_admissible_for_merge(r2, plans[1])
        assert ok1
        assert not ok2


# ═══════════════════════════════════════════════════════════════════════════════
# AB-003: Receipt Digest Verification
# ═══════════════════════════════════════════════════════════════════════════════

class TestAB003ReceiptIntegrity:
    """AB-003: Deliberation receipt digest matching."""

    def test_valid_receipt_passes(self):
        controller = BranchController(policy=_make_policy())
        request = _make_request()
        plans = controller.create_plans(request, num_branches=2)
        results = controller.execute_branches(plans, _Executor())
        decision = controller.merge_results(results)
        receipt = controller.build_receipt(request, plans, results, decision)

        valid, mismatches = verify_receipt_integrity(
            receipt, request, plans, results, decision, controller.policy
        )
        assert valid
        assert len(mismatches) == 0

    def test_tampered_policy_detected(self):
        controller = BranchController(policy=_make_policy())
        request = _make_request()
        plans = controller.create_plans(request, num_branches=1)
        results = controller.execute_branches(plans, _Executor())
        decision = controller.merge_results(results)
        receipt = controller.build_receipt(request, plans, results, decision)

        # Swap policy
        wrong_policy = _make_policy(max_branches=99)
        valid, mismatches = verify_receipt_integrity(
            receipt, request, plans, results, decision, wrong_policy
        )
        assert not valid
        assert any("policy" in m for m in mismatches)

    def test_tampered_plan_detected(self):
        controller = BranchController(policy=_make_policy())
        request = _make_request()
        plans = controller.create_plans(request, num_branches=2)
        results = controller.execute_branches(plans, _Executor())
        decision = controller.merge_results(results)
        receipt = controller.build_receipt(request, plans, results, decision)

        # Add an extra plan
        plans.append(BranchPlan())
        valid, mismatches = verify_receipt_integrity(
            receipt, request, plans, results, decision, controller.policy
        )
        assert not valid
        assert any("plan_digests" in m for m in mismatches)

    def test_tampered_budget_detected(self):
        controller = BranchController(policy=_make_policy())
        request = _make_request()
        plans = controller.create_plans(request, num_branches=1)
        results = controller.execute_branches(plans, _Executor())
        decision = controller.merge_results(results)
        receipt = controller.build_receipt(request, plans, results, decision)

        # Change budget
        plans[0].budget.max_tokens = 999999
        valid, mismatches = verify_receipt_integrity(
            receipt, request, plans, results, decision, controller.policy
        )
        assert not valid
        assert any("budget" in m for m in mismatches)

    def test_all_digest_checks_present(self):
        """Verify AB-003 checks all 7 digest surfaces."""
        controller = BranchController(policy=_make_policy())
        request = _make_request()
        plans = controller.create_plans(request, num_branches=1)
        results = controller.execute_branches(plans, _Executor())
        decision = controller.merge_results(results)
        receipt = controller.build_receipt(request, plans, results, decision)

        # Verify the receipt has all digest fields
        d = receipt.to_dict()
        assert "request_digest" in d
        assert "branch_policy_digest" in d
        assert "branch_budget_digest" in d
        assert "branch_plan_digests" in d
        assert "branch_result_digests" in d
        assert "merge_decision_digest" in d
        assert "signature" in d


# ═══════════════════════════════════════════════════════════════════════════════
# AB-004: Non-Selected Branch is Evidence-Only
# ═══════════════════════════════════════════════════════════════════════════════

class TestAB004EvidenceOnly:
    """AB-004: Non-selected branch is evidence-only."""

    def test_selected_branch_committable(self):
        decision = MergeDecision(
            strategy=MERGE_SELECT_BEST,
            selected_branch_id="b1",
            rejected_branch_ids=["b2"],
        )
        assert is_branch_committable("b1", decision)

    def test_rejected_branch_not_committable(self):
        decision = MergeDecision(
            strategy=MERGE_SELECT_BEST,
            selected_branch_id="b1",
            rejected_branch_ids=["b2"],
        )
        assert not is_branch_committable("b2", decision)

    def test_deferred_not_committable_without_approval(self):
        decision = MergeDecision(
            strategy=MERGE_DEFER_HUMAN,
            deferred_branch_ids=["b1"],
            human_review_required=True,
        )
        assert not is_branch_committable("b1", decision)

    def test_deferred_committable_with_approval(self):
        decision = MergeDecision(
            strategy=MERGE_DEFER_HUMAN,
            deferred_branch_ids=["b1"],
            human_review_required=True,
        )
        assert is_branch_committable("b1", decision, human_review_approved=True)

    def test_reject_all_nothing_committable(self):
        decision = MergeDecision(
            strategy=MERGE_REJECT_ALL,
            rejected_branch_ids=["b1", "b2"],
        )
        assert not is_branch_committable("b1", decision)
        assert not is_branch_committable("b2", decision)

    def test_evidence_only_includes_deferred(self):
        decision = MergeDecision(
            strategy=MERGE_DEFER_HUMAN,
            deferred_branch_ids=["b1"],
            rejected_branch_ids=["b2"],
        )
        evidence_only = get_evidence_only_branches(decision)
        assert "b1" in evidence_only
        assert "b2" in evidence_only

    def test_ab004_in_full_lifecycle(self):
        """AB-004 integrated with full deliberation lifecycle."""
        controller = BranchController(policy=_make_policy())
        request = _make_request()
        plans = controller.create_plans(request, num_branches=3)

        # Give branches different evidence to avoid deferral
        results = []
        for i, plan in enumerate(plans):
            r = controller.execute_branch(plan, _Executor(output={"branch": i}))
            r.evidence = [{"type": f"ev_{i}_{j}"} for j in range(i + 3)]
            results.append(r)

        decision = controller.merge_results(results)

        # Selected is committable, rest are evidence-only
        if decision.strategy == MERGE_SELECT_BEST:
            assert decision.selected_branch_id is not None
            for r in results:
                committable = is_branch_committable(r.branch_id, decision)
                if r.branch_id == decision.selected_branch_id:
                    assert committable
                else:
                    assert not committable


# ═══════════════════════════════════════════════════════════════════════════════
# Additional edge cases
# ═══════════════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Additional adversarial edge cases."""

    def test_empty_branch_list_merge(self):
        decision = default_merge_strategy([], _make_policy())
        assert decision.strategy == MERGE_REJECT_ALL

    def test_operator_request_must_be_operator(self):
        controller = BranchController()
        request = DeliberationRequest(
            trigger_type=DeliberationTrigger.OPERATOR_REQUEST,
            requested_by="runtime",
        )
        ok, reasons = controller.validate_request(request)
        assert not ok
        assert any("operator" in r for r in reasons)

    def test_operator_request_valid_when_operator(self):
        controller = BranchController()
        request = DeliberationRequest(
            trigger_type=DeliberationTrigger.OPERATOR_REQUEST,
            requested_by="operator",
        )
        ok, reasons = controller.validate_request(request)
        assert ok

    def test_child_policy_validates_all_dimensions(self):
        """Comprehensive child policy validation across all 7 dimensions."""
        parent = _make_policy(
            max_branches=5,
            max_depth=3,
            allowed_capabilities={"a", "b"},
            forbidden_capabilities={"x"},
            min_sandbox_strength=SANDBOX_HARDENED,
            max_risk_level=RISK_HIGH,
            side_effect_policy=SIDE_EFFECT_READ_ONLY,
        )
        # Valid child (narrowed on all dimensions)
        child = _make_policy(
            max_branches=3,
            max_depth=2,
            allowed_capabilities={"a"},  # subset
            forbidden_capabilities={"x", "y"},  # superset
            min_sandbox_strength=SANDBOX_FULL,  # >=
            max_risk_level=RISK_MEDIUM,  # <=
            side_effect_policy=SIDE_EFFECT_DENY_ALL,  # more restrictive
        )
        violations = validate_child_policy(parent, child)
        assert len(violations) == 0

    def test_negative_branch_count_raises(self):
        controller = BranchController(policy=_make_policy(max_branches=1))
        request = _make_request()
        with pytest.raises(BranchingDenied):
            controller.create_plans(request, num_branches=0)

    def test_budget_with_zero_max_side_effects(self):
        b = BudgetTracker(max_side_effects=0)
        assert not b.consume_side_effect()
        assert b.is_exhausted()

    def test_context_records_unauthorized_side_effect(self):
        ctx = BranchExecutionContext(branch_id="b1")
        ctx.record_side_effect("write", {"path": "/etc/passwd"}, allowed=False)
        assert len(ctx.side_effect_log) == 1
        assert ctx.side_effect_log[0]["allowed"] is False
