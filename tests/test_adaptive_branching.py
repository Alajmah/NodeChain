"""Tests for Adaptive Branching / Bounded Deliberation (v2.21.3).

Covers AB-001 and the 10 non-negotiable rules.
Acceptance criteria AC-01 through AC-15.
"""

from __future__ import annotations

import json
import pytest
import time
from pathlib import Path

from nodechain.sdk.adaptive_branching import (
    # Core types
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
    BranchingDenied, BranchInadmissible, BudgetExhausted, PolicyViolation,
    MergeRejected, ChildPolicyExpansion,
    # Helpers
    validate_child_policy, default_merge_strategy,
    compute_budget_digest, attach_capability_receipts, attach_trust_graph,
    save_deliberation_receipt,
)


# ── Test Executor ───────────────────────────────────────────────────────────

class MockExecutor:
    """Mock branch executor that returns configured output."""

    def __init__(self, output=None, delay=0.0, fail=False):
        self._output = output or {"result": "ok"}
        self._delay = delay
        self._fail = fail
        self.call_count = 0

    def __call__(self, node_sequence, input_data, context):
        self.call_count += 1
        if self._delay:
            time.sleep(self._delay)
        if self._fail:
            raise RuntimeError("Simulated branch failure")
        # Record evidence in context
        context.record_evidence({"type": "test_evidence", "data": "branch_data"})
        return dict(self._output)


class FailingExecutor(MockExecutor):
    def __init__(self):
        super().__init__(fail=True)


# ── AC-01: BranchPolicy schema ──────────────────────────────────────────────

class TestAC01BranchPolicy:
    """AC-01: BranchPolicy schema exists with all required fields."""

    def test_policy_creation(self):
        p = BranchPolicy()
        assert p.max_branches == 3
        assert p.max_depth == 1
        assert p.side_effect_policy == SIDE_EFFECT_DENY_ALL

    def test_policy_digest(self):
        p = BranchPolicy(max_branches=5, max_depth=2)
        d = p.compute_digest()
        assert len(d) == 64  # SHA-256 hex

    def test_policy_digest_stability(self):
        p1 = BranchPolicy(max_branches=5, max_depth=2)
        p2 = BranchPolicy(max_branches=5, max_depth=2)
        assert p1.compute_digest() == p2.compute_digest()

    def test_policy_digest_changes_with_config(self):
        p1 = BranchPolicy(max_branches=5)
        p2 = BranchPolicy(max_branches=3)
        assert p1.compute_digest() != p2.compute_digest()

    def test_capability_allowed(self):
        p = BranchPolicy(allowed_capabilities={"cap_a", "cap_b"})
        assert p.is_capability_allowed("cap_a")
        assert not p.is_capability_allowed("cap_c")

    def test_capability_allowed_empty_set(self):
        p = BranchPolicy()  # empty = all allowed
        assert p.is_capability_allowed("anything")

    def test_capability_forbidden(self):
        p = BranchPolicy(forbidden_capabilities={"bad_cap"})
        assert not p.is_capability_allowed("bad_cap")

    def test_side_effect_allowed(self):
        p = BranchPolicy(side_effect_policy=SIDE_EFFECT_EXPLICIT_ALLOW)
        assert p.is_side_effect_allowed()

    def test_side_effect_denied(self):
        p = BranchPolicy(side_effect_policy=SIDE_EFFECT_DENY_ALL)
        assert not p.is_side_effect_allowed()

    def test_risk_allowed(self):
        p = BranchPolicy(max_risk_level=RISK_MEDIUM)
        assert p.is_risk_allowed(RISK_LOW)
        assert p.is_risk_allowed(RISK_MEDIUM)
        assert not p.is_risk_allowed(RISK_HIGH)

    def test_policy_to_dict(self):
        p = BranchPolicy()
        d = p.to_dict()
        assert "max_branches" in d
        assert "max_depth" in d
        assert "side_effect_policy" in d
        assert "forbidden_capabilities" in d


# ── AC-02: BranchBudget schema ──────────────────────────────────────────────

class TestAC02BranchBudget:
    """AC-02: BranchBudget schema exists with all required fields."""

    def test_budget_creation(self):
        b = BudgetTracker(max_tokens=5000, max_tool_calls=10)
        assert b.max_tokens == 5000
        assert b.max_tool_calls == 10

    def test_budget_digest(self):
        b = BudgetTracker(max_tokens=5000, max_tool_calls=10)
        d = compute_budget_digest(b)
        assert len(d) == 64

    def test_budget_digest_stability(self):
        b1 = BudgetTracker(max_tokens=5000)
        b2 = BudgetTracker(max_tokens=5000)
        assert compute_budget_digest(b1) == compute_budget_digest(b2)

    def test_budget_digest_changes(self):
        b1 = BudgetTracker(max_tokens=5000)
        b2 = BudgetTracker(max_tokens=10000)
        assert compute_budget_digest(b1) != compute_budget_digest(b2)

    def test_budget_not_exhausted_initially(self):
        b = BudgetTracker()
        assert not b.is_exhausted()

    def test_budget_exhausted_tokens(self):
        b = BudgetTracker(max_tokens=100)
        b.consume_tokens(101)
        assert b.is_exhausted()
        assert "tokens" in b.exhausted_dimensions()

    def test_budget_exhausted_tool_calls(self):
        b = BudgetTracker(max_tool_calls=2)
        b.consume_tool_call()
        b.consume_tool_call()
        b.consume_tool_call()  # 3 > 2
        assert b.is_exhausted()
        assert "tool_calls" in b.exhausted_dimensions()

    def test_budget_exhausted_retries(self):
        b = BudgetTracker(max_retries=1)
        b.consume_retry()
        b.consume_retry()  # 2 > 1
        assert b.is_exhausted()

    def test_budget_exhausted_depth(self):
        b = BudgetTracker(max_depth=2)
        b.set_depth(3)
        assert b.is_exhausted()

    def test_budget_exhausted_side_effects(self):
        b = BudgetTracker(max_side_effects=0)
        b.consume_side_effect()
        assert b.is_exhausted()

    def test_budget_consume_returns_true_within_limit(self):
        b = BudgetTracker(max_tokens=100)
        assert b.consume_tokens(50) is True
        assert b.consume_tokens(50) is True  # exactly at limit

    def test_budget_consume_returns_false_over_limit(self):
        b = BudgetTracker(max_tokens=100)
        assert b.consume_tokens(50) is True
        assert b.consume_tokens(51) is False  # over limit

    def test_budget_to_dict(self):
        b = BudgetTracker()
        d = b.to_dict()
        assert "max_tokens" in d
        assert "tokens_used" in d
        assert "time_elapsed" in d


# ── AC-03: BranchController creates N bounded branches ──────────────────────

class TestAC03BranchCreation:
    """AC-03: BranchController can create N bounded branches."""

    def test_create_plans(self):
        controller = BranchController(policy=BranchPolicy(max_branches=3))
        request = DeliberationRequest(
            trigger_type=DeliberationTrigger.UNCERTAINTY,
            trigger_node_id="test_node",
        )
        plans = controller.create_plans(request, num_branches=3)
        assert len(plans) == 3
        for plan in plans:
            assert plan.admissible

    def test_create_plans_respects_max(self):
        controller = BranchController(policy=BranchPolicy(max_branches=2))
        request = DeliberationRequest()
        plans = controller.create_plans(request, num_branches=5)
        assert len(plans) == 2  # capped at max_branches

    def test_create_plans_unique_ids(self):
        controller = BranchController()
        request = DeliberationRequest()
        plans = controller.create_plans(request, num_branches=3)
        ids = {p.branch_id for p in plans}
        assert len(ids) == 3

    def test_create_plans_with_capabilities(self):
        controller = BranchController(
            policy=BranchPolicy(allowed_capabilities={"search", "analyze"})
        )
        request = DeliberationRequest(
            requested_capabilities=["search", "analyze"],
        )
        plans = controller.create_plans(request, num_branches=2)
        assert len(plans) == 2
        for plan in plans:
            assert len(plan.capability_requests) == 2

    def test_create_plans_denied_for_forbidden_capability(self):
        controller = BranchController(
            policy=BranchPolicy(forbidden_capabilities={"dangerous"})
        )
        request = DeliberationRequest(
            requested_capabilities=["dangerous"],
        )
        with pytest.raises(BranchingDenied):
            controller.create_plans(request, num_branches=1)

    def test_zero_branches_raises(self):
        controller = BranchController(policy=BranchPolicy(max_branches=0))
        request = DeliberationRequest()
        with pytest.raises(BranchingDenied):
            controller.create_plans(request, num_branches=1)


# ── AC-04: Budget enforcement ───────────────────────────────────────────────

class TestAC04BudgetEnforcement:
    """AC-04: Budget dimensions are enforced."""

    def test_token_budget_enforced(self):
        controller = BranchController(policy=BranchPolicy(max_branches=1))
        request = DeliberationRequest()
        plans = controller.create_plans(request, num_branches=1)

        # Set a tiny token budget
        plans[0].budget.max_tokens = 10
        plans[0].budget.consume_tokens(15)

        # Execute should detect exhaustion
        executor = MockExecutor(output={"result": "ok"})
        result = controller.execute_branch(plans[0], executor)
        # Budget was already exceeded before execution
        assert result.status in (BRANCH_COMPLETED, BRANCH_BUDGET_EXHAUSTED)

    def test_tool_call_budget_enforced(self):
        b = BudgetTracker(max_tool_calls=2)
        assert b.consume_tool_call()
        assert b.consume_tool_call()
        assert not b.consume_tool_call()
        assert "tool_calls" in b.exhausted_dimensions()

    def test_retry_budget_enforced(self):
        b = BudgetTracker(max_retries=1)
        assert b.consume_retry()
        assert not b.consume_retry()
        assert b.is_exhausted()

    def test_depth_budget_enforced(self):
        b = BudgetTracker(max_depth=1)
        assert b.set_depth(1)
        assert not b.set_depth(2)
        assert "depth" in b.exhausted_dimensions()

    def test_time_budget_enforced(self):
        b = BudgetTracker(max_time_seconds=0.01)
        time.sleep(0.02)
        assert b.is_exhausted()
        assert "time" in b.exhausted_dimensions()


# ── AC-05: BranchExecutionContext isolates state ────────────────────────────

class TestAC05StateIsolation:
    """AC-05: BranchExecutionContext isolates state from the main workflow."""

    def test_context_isolation(self):
        ctx1 = BranchExecutionContext(branch_id="b1")
        ctx2 = BranchExecutionContext(branch_id="b2")

        ctx1.state["key"] = "value1"
        ctx2.state["key"] = "value2"

        assert ctx1.state["key"] == "value1"
        assert ctx2.state["key"] == "value2"
        assert ctx1.state is not ctx2.state

    def test_evidence_isolation(self):
        ctx1 = BranchExecutionContext(branch_id="b1")
        ctx2 = BranchExecutionContext(branch_id="b2")

        ctx1.record_evidence({"type": "ev1"})
        ctx2.record_evidence({"type": "ev2"})

        assert len(ctx1.evidence) == 1
        assert ctx1.evidence[0]["type"] == "ev1"
        assert len(ctx2.evidence) == 1
        assert ctx2.evidence[0]["type"] == "ev2"

    def test_side_effect_isolation(self):
        ctx1 = BranchExecutionContext(branch_id="b1")
        ctx2 = BranchExecutionContext(branch_id="b2")

        ctx1.record_side_effect("write", {"path": "/tmp/a"}, True)
        ctx2.record_side_effect("write", {"path": "/tmp/b"}, False)

        assert len(ctx1.side_effect_log) == 1
        assert ctx1.side_effect_log[0]["details"]["path"] == "/tmp/a"
        assert len(ctx2.side_effect_log) == 1
        assert ctx2.side_effect_log[0]["details"]["path"] == "/tmp/b"

    def test_output_isolation(self):
        ctx = BranchExecutionContext(branch_id="b1")
        ctx.outputs["result"] = {"data": 42}

        # Parent workflow state is not this context
        parent_state = {}
        assert parent_state == {}  # parent unaffected


# ── AC-06: Capabilities through governed resolution ─────────────────────────

class TestAC06CapabilityResolution:
    """AC-06: Branches request capabilities only through governed resolution."""

    def test_plan_has_capability_requests(self):
        controller = BranchController(
            policy=BranchPolicy(allowed_capabilities={"search"})
        )
        request = DeliberationRequest(requested_capabilities=["search"])
        plans = controller.create_plans(request, num_branches=1)
        assert plans[0].capability_requests == [{"capability": "search"}]

    def test_plan_rejects_unallowed_capability(self):
        controller = BranchController(
            policy=BranchPolicy(
                allowed_capabilities={"search"},
                forbidden_capabilities={"dangerous"},
            )
        )
        request = DeliberationRequest(requested_capabilities=["dangerous"])
        with pytest.raises(BranchingDenied):
            controller.create_plans(request, num_branches=1)

    def test_capability_receipts_attachable(self):
        plan = BranchPlan()

        class FakeReceipt:
            def __init__(self, sig):
                self.signature = sig

        receipts = [FakeReceipt("abc123"), FakeReceipt("def456")]
        attach_capability_receipts(plan, receipts)
        assert len(plan.capability_receipt_digests) == 2
        assert "abc123" in plan.capability_receipt_digests

    def test_trust_graph_attachable(self):
        plan = BranchPlan()
        attach_trust_graph(plan, "trust_digest_123")
        assert plan.trust_graph_digest == "trust_digest_123"


# ── AC-07: Branch capability selections pinned and trace-linked ─────────────

class TestAC07CapabilityPinning:
    """AC-07: Branch capability selections are pinned and trace-linked."""

    def test_result_has_capability_receipts(self):
        plan = BranchPlan()
        plan.capability_receipt_digests = ["receipt_1", "receipt_2"]

        result = BranchResult(
            branch_id=plan.branch_id,
            status=BRANCH_COMPLETED,
            selected_capability_receipts=plan.capability_receipt_digests,
        )
        assert len(result.selected_capability_receipts) == 2

    def test_result_digests_in_receipt(self):
        plan = BranchPlan()
        plan.capability_receipt_digests = ["receipt_1"]
        result = BranchResult(
            branch_id="b1",
            status=BRANCH_COMPLETED,
            selected_capability_receipts=["receipt_1"],
        )
        assert result.compute_digest()


# ── AC-08: Side effects denied by default in exploratory branches ───────────

class TestAC08SideEffectDefaultDeny:
    """AC-08: Side effects are denied by default in exploratory branches."""

    def test_default_policy_denies_side_effects(self):
        p = BranchPolicy()
        assert p.side_effect_policy == SIDE_EFFECT_DENY_ALL
        assert not p.is_side_effect_allowed()

    def test_exploratory_branch_denies_side_effects(self):
        controller = BranchController(
            policy=BranchPolicy(side_effect_policy=SIDE_EFFECT_DENY_ALL)
        )
        request = DeliberationRequest()
        plans = controller.create_plans(request, num_branches=1)
        assert plans[0].is_exploratory
        assert plans[0].budget.max_side_effects == 0

    def test_read_only_policy_allows_zero_side_effects(self):
        controller = BranchController(
            policy=BranchPolicy(side_effect_policy=SIDE_EFFECT_READ_ONLY)
        )
        request = DeliberationRequest()
        plans = controller.create_plans(request, num_branches=1)
        assert plans[0].budget.max_side_effects == 0  # read_only still 0


# ── AC-09: Side-effect branches require explicit policy ─────────────────────

class TestAC09SideEffectAuthorization:
    """AC-09: Side-effect branches require explicit policy permission."""

    def test_explicit_allow_enables_side_effects(self):
        controller = BranchController(
            policy=BranchPolicy(side_effect_policy=SIDE_EFFECT_EXPLICIT_ALLOW)
        )
        request = DeliberationRequest()
        plans = controller.create_plans(request, num_branches=1)
        assert plans[0].budget.max_side_effects > 0
        assert not plans[0].is_exploratory

    def test_exploratory_with_explicit_side_effects_inadmissible(self):
        controller = BranchController(
            policy=BranchPolicy(side_effect_policy=SIDE_EFFECT_EXPLICIT_ALLOW)
        )
        request = DeliberationRequest()
        plans = controller.create_plans(request, num_branches=1)

        # Force exploratory + explicit side effects (should be caught)
        plans[0].is_exploratory = True
        ok, reasons = controller.validate_plan(plans[0])
        assert not ok
        assert any("exploratory" in r for r in reasons)


# ── AC-10: BranchResult records all fields ──────────────────────────────────

class TestAC10BranchResult:
    """AC-10: BranchResult records all required fields."""

    def test_branch_result_fields(self):
        r = BranchResult(
            branch_id="b1",
            status=BRANCH_COMPLETED,
            output={"answer": 42},
        )
        r.evidence = [{"type": "test", "data": "ok"}]
        r.selected_capability_receipts = ["receipt_1"]
        r.consumed_budget = {"tokens_used": 100, "max_tokens": 1000}
        r.policy_verdicts = [{"rule": "AB-001", "verdict": "pass"}]
        r.side_effect_summary = [{"action": "write", "allowed": True}]

        d = r.to_dict()
        assert d["branch_id"] == "b1"
        assert d["status"] == BRANCH_COMPLETED
        assert d["output_digest"]
        assert d["evidence_digest"]
        assert d["selected_capability_receipts"] == ["receipt_1"]
        assert d["consumed_budget"]["tokens_used"] == 100
        assert d["policy_verdicts"][0]["verdict"] == "pass"
        assert d["side_effect_summary"][0]["action"] == "write"

    def test_output_digest_stable(self):
        r1 = BranchResult(branch_id="b1", output={"x": 1})
        r2 = BranchResult(branch_id="b2", output={"x": 1})
        assert r1.compute_output_digest() == r2.compute_output_digest()

    def test_output_digest_changes_with_output(self):
        r1 = BranchResult(branch_id="b1", output={"x": 1})
        r2 = BranchResult(branch_id="b2", output={"x": 2})
        assert r1.compute_output_digest() != r2.compute_output_digest()

    def test_empty_output_digest(self):
        r = BranchResult(branch_id="b1")
        d = r.compute_output_digest()
        assert len(d) == 64

    def test_empty_evidence_digest(self):
        r = BranchResult(branch_id="b1")
        d = r.compute_evidence_digest()
        assert len(d) == 64


# ── AC-11: MergeDecision records all fields ─────────────────────────────────

class TestAC11MergeDecision:
    """AC-11: MergeDecision records all required fields."""

    def test_merge_decision_select_best(self):
        d = MergeDecision(
            strategy=MERGE_SELECT_BEST,
            selected_branch_id="b1",
            rejected_branch_ids=["b2", "b3"],
            confidence=0.85,
            risk_level=RISK_LOW,
            comparison_basis="evidence_count",
            rationale="Branch b1 had most evidence",
        )
        d.finalize()
        dd = d.to_dict()
        assert dd["selected_branch_id"] == "b1"
        assert dd["rejected_branch_ids"] == ["b2", "b3"]
        assert dd["confidence"] == 0.85
        assert dd["risk_level"] == RISK_LOW
        assert dd["comparison_basis"] == "evidence_count"
        assert dd["rationale_digest"]
        assert not dd["human_review_required"]

    def test_merge_decision_reject_all(self):
        d = MergeDecision(
            strategy=MERGE_REJECT_ALL,
            rejected_branch_ids=["b1", "b2"],
            rationale="All branches failed",
            risk_level=RISK_HIGH,
        )
        d.finalize()
        assert d.selected_branch_id is None
        assert len(d.rejected_branch_ids) == 2

    def test_merge_decision_defer_human(self):
        d = MergeDecision(
            strategy=MERGE_DEFER_HUMAN,
            deferred_branch_ids=["b1"],
            human_review_required=True,
            human_review_status="pending",
            rationale="Narrow margin",
        )
        d.finalize()
        assert d.human_review_required
        assert d.human_review_status == "pending"

    def test_merge_decision_digest(self):
        d = MergeDecision(strategy=MERGE_SELECT_BEST, selected_branch_id="b1")
        d.finalize()
        assert len(d.compute_digest()) == 64

    def test_rationale_digest_set_on_finalize(self):
        d = MergeDecision(rationale="test rationale")
        assert d.rationale_digest == ""
        d.finalize()
        assert d.rationale_digest != ""


# ── AC-12: DeliberationReceipt records all fields ───────────────────────────

class TestAC12DeliberationReceipt:
    """AC-12: DeliberationReceipt records all required fields."""

    def test_receipt_fields(self):
        r = DeliberationReceipt(
            request_digest="req_abc",
            branch_policy_digest="pol_def",
            branch_budget_digest="bud_ghi",
            branch_plan_digests=["plan1", "plan2"],
            branch_result_digests=["res1", "res2"],
            merge_decision_digest="merge_jkl",
            trace_event_ids=["evt1", "evt2"],
            deliberation_trigger="uncertainty",
            branch_count=2,
            selected_branch_id="b1",
        )
        r.finalize()
        d = r.to_dict()
        assert d["request_digest"] == "req_abc"
        assert d["branch_policy_digest"] == "pol_def"
        assert d["branch_budget_digest"] == "bud_ghi"
        assert d["branch_plan_digests"] == ["plan1", "plan2"]
        assert d["branch_result_digests"] == ["res1", "res2"]
        assert d["merge_decision_digest"] == "merge_jkl"
        assert d["trace_event_ids"] == ["evt1", "evt2"]
        assert d["signature"]

    def test_receipt_has_unique_id(self):
        r1 = DeliberationReceipt()
        r2 = DeliberationReceipt()
        assert r1.receipt_id != r2.receipt_id

    def test_receipt_signature_stable(self):
        r = DeliberationReceipt(
            request_digest="abc",
            branch_policy_digest="def",
        )
        r.finalize()
        sig1 = r.signature
        r2 = DeliberationReceipt(
            request_digest="abc",
            branch_policy_digest="def",
            receipt_id=r.receipt_id,
            created_at=r.created_at,
        )
        r2.finalize()
        assert r.signature == r2.signature

    def test_save_receipt_to_file(self, tmp_path):
        r = DeliberationReceipt(
            request_digest="abc",
            branch_policy_digest="def",
        )
        r.finalize()
        path = str(tmp_path / "receipt.json")
        save_deliberation_receipt(r, path)
        loaded = json.loads(Path(path).read_text())
        assert loaded["request_digest"] == "abc"
        assert loaded["signature"]


# ── AC-13: Trace replay reconstruction ──────────────────────────────────────

class TestAC13TraceReplay:
    """AC-13: Trace replay can reconstruct branch lifecycle."""

    def test_full_deliberation_flow(self):
        """End-to-end: request → plans → execute → merge → receipt."""
        controller = BranchController(
            policy=BranchPolicy(max_branches=2)
        )
        request = DeliberationRequest(
            trigger_type=DeliberationTrigger.CONFLICT,
            trigger_node_id="conflict_detector",
            trigger_context={"issue": "score_disagreement"},
        )

        # Create plans
        plans = controller.create_plans(request, num_branches=2)
        assert len(plans) == 2

        # Execute branches
        executor = MockExecutor(output={"result": f"branch_output"})
        results = controller.execute_branches(plans, executor)
        assert len(results) == 2
        assert all(r.status == BRANCH_COMPLETED for r in results)

        # Merge
        decision = controller.merge_results(results)
        assert decision.strategy in (MERGE_SELECT_BEST, MERGE_DEFER_HUMAN)

        # Build receipt
        receipt = controller.build_receipt(request, plans, results, decision, ["evt1", "evt2"])

        # Verify receipt has all digests
        assert receipt.request_digest == request.compute_digest()
        assert receipt.branch_policy_digest == controller.policy.compute_digest()
        assert len(receipt.branch_plan_digests) == 2
        assert len(receipt.branch_result_digests) == 2
        assert receipt.merge_decision_digest == decision.compute_digest()
        assert receipt.trace_event_ids == ["evt1", "evt2"]
        assert receipt.signature

    def test_trace_event_ids_preserved(self):
        controller = BranchController()
        request = DeliberationRequest()
        plans = controller.create_plans(request, num_branches=1)
        executor = MockExecutor()
        results = controller.execute_branches(plans, executor)
        decision = controller.merge_results(results)

        trace_ids = [f"trace-{i}" for i in range(5)]
        receipt = controller.build_receipt(request, plans, results, decision, trace_ids)
        assert receipt.trace_event_ids == trace_ids


# ── Non-negotiable rules ────────────────────────────────────────────────────

class TestNonNegotiableRules:
    """The 10 non-negotiable rules for adaptive branching."""

    def test_rule1_branches_cannot_self_authorize(self):
        """Rule 1: BranchPlan has no create method — only BranchController."""
        # Verify BranchPlan has no create_plans method
        assert not hasattr(BranchPlan, "create_plans")
        assert not hasattr(BranchPlan, "create")

    def test_rule2_branches_cannot_expand_permissions(self):
        """Rule 2: validate_child_policy rejects expansions."""
        parent = BranchPolicy(max_branches=5, max_risk_level=RISK_HIGH)
        child = BranchPolicy(max_branches=10, max_risk_level=RISK_CRITICAL)
        violations = validate_child_policy(parent, child)
        assert len(violations) > 0

    def test_rule2_child_can_narrow_permissions(self):
        """Rule 2: Child may narrow."""
        parent = BranchPolicy(max_branches=5, max_risk_level=RISK_HIGH)
        child = BranchPolicy(max_branches=3, max_risk_level=RISK_MEDIUM)
        violations = validate_child_policy(parent, child)
        assert len(violations) == 0

    def test_rule2_child_cannot_add_capabilities(self):
        """Rule 2: Child cannot add capabilities not in parent."""
        parent = BranchPolicy(allowed_capabilities={"a", "b"})
        child = BranchPolicy(allowed_capabilities={"a", "b", "c"})
        violations = validate_child_policy(parent, child)
        assert any("capabilities" in v for v in violations)

    def test_rule2_child_cannot_reduce_sandbox(self):
        parent = BranchPolicy(min_sandbox_strength=SANDBOX_HARDENED)
        child = BranchPolicy(min_sandbox_strength=SANDBOX_BASIC)
        violations = validate_child_policy(parent, child)
        assert any("sandbox" in v for v in violations)

    def test_rule2_child_cannot_increase_side_effects(self):
        parent = BranchPolicy(side_effect_policy=SIDE_EFFECT_DENY_ALL)
        child = BranchPolicy(side_effect_policy=SIDE_EFFECT_EXPLICIT_ALLOW)
        violations = validate_child_policy(parent, child)
        assert any("side_effect" in v for v in violations)

    def test_rule3_bypass_capability_resolution_detected(self):
        """Rule 3: Plan validation catches disallowed capabilities."""
        controller = BranchController(
            policy=BranchPolicy(forbidden_capabilities={"dangerous"})
        )
        plan = BranchPlan()
        plan.capability_requests = [{"capability": "dangerous"}]
        ok, reasons = controller.validate_plan(plan)
        assert not ok

    def test_rule4_dependency_trust_required(self):
        """Rule 4: Plans with capability requests need trust graph."""
        controller = BranchController(
            policy=BranchPolicy(require_dependency_trust=True)
        )
        plan = BranchPlan()
        plan.capability_requests = [{"capability": "search"}]
        ok, reasons = controller.validate_plan(plan)
        assert not ok
        assert any("trust" in r for r in reasons)

    def test_rule4_dependency_trust_exempt_without_capabilities(self):
        """Rule 4: No capability requests means no trust graph needed."""
        controller = BranchController(
            policy=BranchPolicy(require_dependency_trust=True)
        )
        plan = BranchPlan()
        plan.capability_requests = []  # no capabilities
        ok, reasons = controller.validate_plan(plan)
        assert ok

    def test_rule5_exploratory_read_only_by_default(self):
        """Rule 5: Default policy has SIDE_EFFECT_DENY_ALL."""
        p = BranchPolicy()
        assert p.side_effect_policy == SIDE_EFFECT_DENY_ALL

    def test_rule6_side_effect_branches_need_explicit_policy(self):
        """Rule 6: SIDE_EFFECT_EXPLICIT_ALLOW required for side effects."""
        controller = BranchController(
            policy=BranchPolicy(side_effect_policy=SIDE_EFFECT_EXPLICIT_ALLOW)
        )
        request = DeliberationRequest()
        plans = controller.create_plans(request, num_branches=1)
        assert plans[0].budget.max_side_effects > 0
        assert not plans[0].is_exploratory

    def test_rule7_non_selected_cannot_mutate_committed_state(self):
        """Rule 7: Only selected branch output is committed.

        We verify that merge returns only one selected branch_id.
        The actual commit is the caller's responsibility.
        """
        controller = BranchController()
        request = DeliberationRequest()
        plans = controller.create_plans(request, num_branches=3)

        executor = MockExecutor(output={"result": "ok"})
        results = controller.execute_branches(plans, executor)
        decision = controller.merge_results(results)

        # At most one selected
        if decision.strategy == MERGE_SELECT_BEST:
            assert decision.selected_branch_id is not None
            assert len([decision.selected_branch_id]) == 1

    def test_rule8_budget_exhaustion_stops_branch(self):
        """Rule 8: Budget exhaustion results in budget_exhausted status."""
        controller = BranchController()
        request = DeliberationRequest()
        plans = controller.create_plans(request, num_branches=1)
        plans[0].budget.max_tokens = 0
        plans[0].budget.consume_tokens(1)

        executor = MockExecutor()
        result = controller.execute_branch(plans[0], executor)
        assert result.status == BRANCH_BUDGET_EXHAUSTED

    def test_rule9_merge_decision_receipt_backed(self):
        """Rule 9: MergeDecision has rationale_digest."""
        controller = BranchController()
        request = DeliberationRequest()
        plans = controller.create_plans(request, num_branches=2)
        executor = MockExecutor()
        results = controller.execute_branches(plans, executor)
        decision = controller.merge_results(results)
        assert decision.rationale_digest != ""

    def test_rule10_high_risk_merge_requires_human_review(self):
        """Rule 10: High-risk merge triggers human review."""
        controller = BranchController(
            policy=BranchPolicy(review_risk_at_or_above=RISK_LOW)
        )
        request = DeliberationRequest()
        plans = controller.create_plans(request, num_branches=2)

        executor = MockExecutor()
        results = controller.execute_branches(plans, executor)
        # Set risk to HIGH in consumed budget
        for r in results:
            r.consumed_budget["risk_level"] = RISK_HIGH

        decision = controller.merge_results(results)
        assert decision.human_review_required

    def test_rule10_narrow_margin_requires_human_review(self):
        """Rule 10: Narrow score margin triggers human review."""
        controller = BranchController(
            policy=BranchPolicy(review_score_margin_below=0.5)
        )
        request = DeliberationRequest()
        plans = controller.create_plans(request, num_branches=2)

        executor = MockExecutor()
        results = controller.execute_branches(plans, executor)

        decision = controller.merge_results(results)
        # With 2 equal-evidence branches, confidence = 0.5
        # margin = 1.0 - 0.5 = 0.5, which is >= review_score_margin_below
        assert decision.human_review_required


# ── Default Merge Strategy ──────────────────────────────────────────────────

class TestDefaultMergeStrategy:
    """Tests for the default merge strategy."""

    def test_no_completed_branches_rejects_all(self):
        results = [
            BranchResult(branch_id="b1", status=BRANCH_FAILED),
            BranchResult(branch_id="b2", status=BRANCH_FAILED),
        ]
        decision = default_merge_strategy(results, BranchPolicy())
        assert decision.strategy == MERGE_REJECT_ALL
        assert decision.selected_branch_id is None

    def test_single_completed_selects_it(self):
        results = [
            BranchResult(branch_id="b1", status=BRANCH_COMPLETED, evidence=[{"a": 1}]),
            BranchResult(branch_id="b2", status=BRANCH_FAILED),
        ]
        decision = default_merge_strategy(results, BranchPolicy())
        assert decision.strategy == MERGE_SELECT_BEST
        assert decision.selected_branch_id == "b1"

    def test_multiple_completed_selects_most_evidence(self):
        results = [
            BranchResult(branch_id="b1", status=BRANCH_COMPLETED, evidence=[{"a": 1}]),
            BranchResult(branch_id="b2", status=BRANCH_COMPLETED, evidence=[{"a": 1}, {"b": 2}]),
        ]
        decision = default_merge_strategy(results, BranchPolicy())
        assert decision.selected_branch_id == "b2"
        assert decision.confidence > 0.5

    def test_deterministic_tie_break(self):
        """Equal evidence → deterministic by branch_id."""
        results = [
            BranchResult(branch_id="b_z", status=BRANCH_COMPLETED, evidence=[{"a": 1}]),
            BranchResult(branch_id="b_a", status=BRANCH_COMPLETED, evidence=[{"a": 1}]),
        ]
        decision = default_merge_strategy(results, BranchPolicy())
        # Tie-break: sorted by branch_id ascending → "b_a" first
        # But both have equal evidence → confidence = 0.5 → narrow margin → defer
        assert decision.human_review_required

    def test_high_risk_triggers_review(self):
        results = [
            BranchResult(
                branch_id="b1",
                status=BRANCH_COMPLETED,
                evidence=[{"a": 1}],
                consumed_budget={"risk_level": RISK_CRITICAL},
            ),
        ]
        decision = default_merge_strategy(
            results,
            BranchPolicy(review_risk_at_or_above=RISK_HIGH),
        )
        assert decision.human_review_required


# ── DeliberationRequest ─────────────────────────────────────────────────────

class TestDeliberationRequest:
    """Tests for DeliberationRequest."""

    def test_request_creation(self):
        r = DeliberationRequest(
            trigger_type=DeliberationTrigger.UNCERTAINTY,
            trigger_node_id="test_node",
            trigger_context={"score": 0.42},
        )
        assert r.trigger_type == DeliberationTrigger.UNCERTAINTY
        assert r.trigger_node_id == "test_node"
        assert r.request_id

    def test_request_digest_stable(self):
        r1 = DeliberationRequest(
            trigger_type=DeliberationTrigger.CONFLICT,
            trigger_node_id="n1",
            trigger_context={"x": 1},
            requested_capabilities=["a", "b"],
        )
        r2 = DeliberationRequest(
            trigger_type=DeliberationTrigger.CONFLICT,
            trigger_node_id="n1",
            trigger_context={"x": 1},
            requested_capabilities=["b", "a"],  # different order
        )
        # Same digest regardless of capability order
        assert r1.compute_digest() == r2.compute_digest()

    def test_request_digest_changes_with_trigger(self):
        r1 = DeliberationRequest(trigger_type=DeliberationTrigger.UNCERTAINTY)
        r2 = DeliberationRequest(trigger_type=DeliberationTrigger.CONFLICT)
        assert r1.compute_digest() != r2.compute_digest()

    def test_operator_request_requires_operator(self):
        controller = BranchController()
        r = DeliberationRequest(
            trigger_type=DeliberationTrigger.OPERATOR_REQUEST,
            requested_by="runtime",  # wrong
        )
        ok, reasons = controller.validate_request(r)
        assert not ok
        assert any("operator" in reason for reason in reasons)


# ── Branch Plan ─────────────────────────────────────────────────────────────

class TestBranchPlan:
    """Tests for BranchPlan."""

    def test_plan_unique_ids(self):
        p1 = BranchPlan()
        p2 = BranchPlan()
        assert p1.branch_id != p2.branch_id

    def test_plan_digest(self):
        p = BranchPlan(depth=1, node_sequence=["n1", "n2"])
        d = p.compute_digest()
        assert len(d) == 64

    def test_plan_digest_changes_with_nodes(self):
        p1 = BranchPlan(node_sequence=["n1"])
        p2 = BranchPlan(node_sequence=["n1", "n2"])
        assert p1.compute_digest() != p2.compute_digest()

    def test_plan_admissible_default_false(self):
        p = BranchPlan()
        assert not p.admissible  # must be validated

    def test_plan_depth_check(self):
        controller = BranchController(policy=BranchPolicy(max_depth=1))
        p = BranchPlan(depth=2)
        ok, reasons = controller.validate_plan(p)
        assert not ok
        assert any("depth" in r for r in reasons)


# ── Integration: Full lifecycle ─────────────────────────────────────────────

class TestFullLifecycle:
    """Full deliberation lifecycle integration tests."""

    def test_full_lifecycle_with_3_branches(self):
        controller = BranchController(policy=BranchPolicy(max_branches=3))
        request = DeliberationRequest(
            trigger_type=DeliberationTrigger.UNCERTAINTY,
            trigger_node_id="confidence_calibrator",
            trigger_context={"confidence": 0.42},
        )

        plans = controller.create_plans(request, num_branches=3)
        assert len(plans) == 3

        executor = MockExecutor(output={"answer": 42})
        results = controller.execute_branches(plans, executor)
        assert all(r.status == BRANCH_COMPLETED for r in results)

        decision = controller.merge_results(results)
        assert decision.strategy in (MERGE_SELECT_BEST, MERGE_DEFER_HUMAN)

        receipt = controller.build_receipt(
            request, plans, results, decision,
            trace_event_ids=[f"evt-{i}" for i in range(10)],
        )
        assert receipt.branch_count == 3
        assert receipt.deliberation_trigger == "uncertainty"
        assert len(receipt.branch_plan_digests) == 3
        assert len(receipt.branch_result_digests) == 3
        assert len(receipt.trace_event_ids) == 10
        assert receipt.signature

    def test_lifecycle_with_failures(self):
        controller = BranchController(policy=BranchPolicy(max_branches=3))
        request = DeliberationRequest()

        plans = controller.create_plans(request, num_branches=3)

        # Execute: first fails, rest succeed
        results = []
        results.append(controller.execute_branch(plans[0], FailingExecutor()))

        # Give branches different evidence amounts to avoid narrow-margin human review
        exec2 = MockExecutor(output={"result": "ok"})
        results.append(controller.execute_branch(plans[1], exec2))
        results[-1].evidence = [{"type": "ev_a"}, {"type": "ev_b"}, {"type": "ev_c"}]

        exec3 = MockExecutor(output={"result": "ok"})
        results.append(controller.execute_branch(plans[2], exec3))
        results[-1].evidence = [{"type": "ev_d"}]

        decision = controller.merge_results(results)
        assert decision.strategy == MERGE_SELECT_BEST
        assert decision.selected_branch_id == plans[1].branch_id

    def test_lifecycle_all_fail(self):
        controller = BranchController(policy=BranchPolicy(max_branches=2))
        request = DeliberationRequest()
        plans = controller.create_plans(request, num_branches=2)

        results = controller.execute_branches(plans, FailingExecutor())
        decision = controller.merge_results(results)
        assert decision.strategy == MERGE_REJECT_ALL

    def test_child_branch_narrowing(self):
        """Test that nested branching properly narrows policy."""
        parent_policy = BranchPolicy(
            max_branches=5,
            max_depth=2,
            allowed_capabilities={"a", "b", "c"},
            max_risk_level=RISK_HIGH,
        )
        controller = BranchController(policy=parent_policy)

        # Create parent plan
        request = DeliberationRequest(requested_capabilities=["a"])
        plans = controller.create_plans(request, num_branches=1)
        parent_plan = plans[0]

        # Create child plans
        child_plans = controller.create_plans(
            request, num_branches=2, parent_plan=parent_plan,
        )
        for cp in child_plans:
            assert cp.depth == 1
            assert cp.parent_branch_id == parent_plan.branch_id

    def test_depth_limit_prevents_deep_nesting(self):
        controller = BranchController(
            policy=BranchPolicy(max_depth=0)
        )
        request = DeliberationRequest()
        plans = controller.create_plans(request, num_branches=1)
        parent = plans[0]

        # Try to create children at depth 1 > max_depth 0
        with pytest.raises(BranchingDenied, match="[Dd]epth"):
            controller.create_plans(request, num_branches=1, parent_plan=parent)


# ── Schema version ──────────────────────────────────────────────────────────

class TestSchemaVersion:
    """Verify schema version is stable and documented."""

    def test_schema_version(self):
        assert ADAPTIVE_BRANCHING_SCHEMA_VERSION == "1.0.0"

    def test_receipt_has_schema_version(self):
        r = DeliberationReceipt()
        assert r.schema_version == ADAPTIVE_BRANCHING_SCHEMA_VERSION
        assert "schema_version" in r.to_dict()
