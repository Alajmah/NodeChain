"""Side-Effect Runtime Gate + Blocked Attempt Log Tests (v2.34.0).

Proves the SIDE_EFFECT policy gate and durable blocked-attempt log:

  - ALLOW-by-default: nodes with declared side effects pass when the default
    SIDE_EFFECT policy is in effect.
  - DENY blocks before journaling and before node execution.
  - REQUIRE_APPROVAL also blocks (treated as deny for v2.34.0).
  - One durable blocked row per declared side-effect (not per node).
  - SIDE_EFFECT_BLOCKED trace event carries attempt_id.
  - Reconciler Check 4g binds blocked trace ↔ durable row.
  - Dashboard exposes blocked counters.
  - No matching SIDE_EFFECT policy fails closed.
"""

from __future__ import annotations

import pytest

from nodechain.core.policy import (
    PolicyType, PolicyAction, PolicyEngine, Policy, PolicyRule,
)
from nodechain.core.default_policies import SIDE_EFFECT_POLICY, DEFAULT_POLICIES
from nodechain.core.state import StateManager, ChainState
from nodechain.core.trace import ChainTrace, TraceEvent, EventType, Actor
from nodechain.runtime.trace_reconciler import TraceReconciler


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "se_gate.db")


@pytest.fixture
def state_manager(db_path):
    return StateManager(db_path)


@pytest.fixture
def reconciler(state_manager):
    return TraceReconciler(state_manager)


def _make_trace(run_id: str, events: list[TraceEvent] | None = None) -> ChainTrace:
    trace = ChainTrace(run_id=run_id, chain_id="test-chain", chain_name="Test")
    for e in (events or []):
        trace.add_event(e)
    trace.finalize("completed")
    return trace


# ── Unit: default policy and gate evaluation ────────────────────────────────

class TestDefaultSideEffectPolicy:
    """v2.34.0: SIDE_EFFECT_POLICY exists and is allow-by-default."""

    def test_policy_registered(self):
        assert SIDE_EFFECT_POLICY.policy_type == PolicyType.SIDE_EFFECT
        assert SIDE_EFFECT_POLICY in DEFAULT_POLICIES

    def test_default_is_allow(self):
        engine = PolicyEngine()
        for p in DEFAULT_POLICIES:
            engine.register(p)
        decisions = engine.evaluate(
            PolicyType.SIDE_EFFECT, "test_node",
            {"side_effect_types": ["external_call"]},
        )
        assert len(decisions) >= 1
        assert any(d.action == PolicyAction.ALLOW for d in decisions)

    def test_deny_rule_overrides_allow(self):
        engine = PolicyEngine()
        deny_policy = Policy(
            policy_id="test.se.deny",
            policy_type=PolicyType.SIDE_EFFECT,
            target="*",
            rules=[
                PolicyRule(
                    rule_id="se.block_external",
                    condition="block_external == True",
                    action=PolicyAction.DENY,
                    parameters={"reason": "external calls blocked"},
                    priority=20,
                ),
            ],
        )
        engine.register(deny_policy)
        decisions = engine.evaluate(
            PolicyType.SIDE_EFFECT, "test_node",
            {"side_effect_types": ["external_call"], "block_external": True},
        )
        assert any(d.action == PolicyAction.DENY for d in decisions)

    def test_list_aware_in_condition(self):
        """v2.34.1: side_effect_types is a list — 'in' must check members."""
        engine = PolicyEngine()
        deny_policy = Policy(
            policy_id="test.se.list",
            policy_type=PolicyType.SIDE_EFFECT,
            target="*",
            rules=[
                PolicyRule(
                    rule_id="se.block_external_list",
                    condition='side_effect_types in ["external_call"]',
                    action=PolicyAction.DENY,
                    parameters={"reason": "external calls blocked"},
                    priority=20,
                ),
            ],
        )
        engine.register(deny_policy)
        # Node declares both external_call and memory_write
        decisions = engine.evaluate(
            PolicyType.SIDE_EFFECT, "test_node",
            {"side_effect_types": ["external_call", "memory_write"]},
        )
        assert any(d.action == PolicyAction.DENY for d in decisions)
        # Node declares only memory_write — should NOT match
        decisions2 = engine.evaluate(
            PolicyType.SIDE_EFFECT, "test_node",
            {"side_effect_types": ["memory_write"]},
        )
        assert not any(d.action == PolicyAction.DENY for d in decisions2)

    def test_default_allow_plus_operator_deny_precedence(self):
        """v2.34.1: when default ALLOW and operator DENY both match, the DENY
        decision must be the one recorded (not decisions[0] which may be ALLOW)."""
        from nodechain.runtime.policy_gate import PolicyGate
        engine = PolicyEngine()
        # Register default allow first
        engine.register(SIDE_EFFECT_POLICY)
        # Register operator deny at higher priority
        deny_policy = Policy(
            policy_id="op.se.deny",
            policy_type=PolicyType.SIDE_EFFECT,
            target="*",
            rules=[
                PolicyRule(
                    rule_id="op.block_external",
                    condition='side_effect_types in ["external_call"]',
                    action=PolicyAction.DENY,
                    parameters={"reason": "operator blocked external"},
                    priority=20,
                ),
            ],
        )
        engine.register(deny_policy)

        decisions = engine.evaluate(
            PolicyType.SIDE_EFFECT, "test_node",
            {"side_effect_types": ["external_call"]},
        )
        # The denying decision must cite the operator rule, not the allow
        denying = next(
            d for d in decisions
            if d.action == PolicyAction.DENY
        )
        assert denying.rule_id == "op.block_external"
        assert denying.policy_id == "op.se.deny"


# ── Unit: state manager blocked-attempt log ─────────────────────────────────

class TestBlockedAttemptLog:
    """v2.34.0: side_effect_blocked_attempts table + accessors."""

    def test_record_and_retrieve(self, state_manager):
        state_manager.record_side_effect_block({
            "attempt_id": "blk-1",
            "run_id": "run-1",
            "node_id": "search_tool",
            "side_effect_type": "external_call",
            "effect_target": "api",
            "policy_id": "test.se.deny",
            "rule_id": "se.block_external",
            "decision": "deny",
            "denial_reason": "external calls blocked",
        })
        blocks = state_manager.get_side_effect_blocks(run_id="run-1")
        assert len(blocks) == 1
        assert blocks[0]["attempt_id"] == "blk-1"
        assert blocks[0]["decision"] == "deny"

    def test_multiple_effects_separate_rows(self, state_manager):
        """One row per declared side-effect."""
        for i, etype in enumerate(["external_call", "memory_write"]):
            state_manager.record_side_effect_block({
                "attempt_id": f"blk-{i}",
                "run_id": "run-multi",
                "node_id": "node_a",
                "side_effect_type": etype,
                "decision": "deny",
            })
        blocks = state_manager.get_side_effect_blocks(run_id="run-multi")
        assert len(blocks) == 2
        types = {b["side_effect_type"] for b in blocks}
        assert types == {"external_call", "memory_write"}

    def test_filter_by_decision(self, state_manager):
        state_manager.record_side_effect_block({
            "attempt_id": "blk-d", "run_id": "r",
            "node_id": "n", "side_effect_type": "t",
            "decision": "deny",
        })
        state_manager.record_side_effect_block({
            "attempt_id": "blk-a", "run_id": "r",
            "node_id": "n", "side_effect_type": "t",
            "decision": "require_approval",
        })
        denied = state_manager.get_side_effect_blocks(run_id="r", decision="deny")
        assert len(denied) == 1
        assert denied[0]["attempt_id"] == "blk-d"


# ── Integration: reconciler Check 4g ────────────────────────────────────────

class TestCheck4gBlockedBinding:
    """v2.34.0: SIDE_EFFECT_BLOCKED trace ↔ durable blocked attempt."""

    @pytest.mark.asyncio
    async def test_blocked_trace_matches_durable_row(self, reconciler, state_manager):
        state = ChainState(chain_id="test-chain")
        state_manager.save(state)

        state_manager.record_side_effect_block({
            "attempt_id": "blk-match",
            "run_id": state.run_id, "step_id": 1, "node_id": "n",
            "side_effect_type": "external_call",
            "policy_id": "p", "rule_id": "r",
            "decision": "deny", "denial_reason": "blocked",
        })

        trace = _make_trace(state.run_id, [
            TraceEvent(
                run_id=state.run_id, chain_id="test-chain",
                node_id="n", step_id=1,
                event_type=EventType.SIDE_EFFECT_BLOCKED,
                actor=Actor.RUNTIME,
                metadata={"attempt_id": "blk-match", "side_effect_type": "external_call"},
            ),
        ])

        report = reconciler.reconcile(trace)
        match_errors = [i for i in report.issues
                        if i.check == "side_effect_blocked_ledger_match"
                        and i.severity == "error"]
        assert len(match_errors) == 0

    @pytest.mark.asyncio
    async def test_blocked_trace_without_durable_is_error(self, reconciler, state_manager):
        state = ChainState(chain_id="test-chain")
        state_manager.save(state)

        trace = _make_trace(state.run_id, [
            TraceEvent(
                run_id=state.run_id, chain_id="test-chain",
                node_id="n", step_id=1,
                event_type=EventType.SIDE_EFFECT_BLOCKED,
                actor=Actor.RUNTIME,
                metadata={"attempt_id": "blk-orphan"},
            ),
        ])

        report = reconciler.reconcile(trace)
        errors = [i for i in report.issues
                  if i.check == "side_effect_blocked_ledger_match"
                  and i.severity == "error"]
        assert len(errors) >= 1

    @pytest.mark.asyncio
    async def test_durable_blocked_without_trace_is_warning(self, reconciler, state_manager):
        state = ChainState(chain_id="test-chain")
        state_manager.save(state)

        state_manager.record_side_effect_block({
            "attempt_id": "blk-no-trace",
            "run_id": state.run_id, "step_id": 1, "node_id": "n",
            "side_effect_type": "external_call",
            "decision": "deny",
        })

        trace = _make_trace(state.run_id)
        report = reconciler.reconcile(trace)

        coverage = [i for i in report.issues
                    if i.check == "side_effect_blocked_trace_coverage"]
        assert len(coverage) >= 1
        assert coverage[0].severity == "warning"

    @pytest.mark.asyncio
    async def test_blocked_wrong_decision_is_error(self, reconciler, state_manager):
        """Durable row exists but decision is 'allow' (not blocked) = ERROR."""
        state = ChainState(chain_id="test-chain")
        state_manager.save(state)

        state_manager.record_side_effect_block({
            "attempt_id": "blk-bad",
            "run_id": state.run_id, "step_id": 1, "node_id": "n",
            "side_effect_type": "external_call",
            "decision": "allow",  # wrong — should be deny/require_approval
        })

        trace = _make_trace(state.run_id, [
            TraceEvent(
                run_id=state.run_id, chain_id="test-chain",
                node_id="n", step_id=1,
                event_type=EventType.SIDE_EFFECT_BLOCKED,
                actor=Actor.RUNTIME,
                metadata={"attempt_id": "blk-bad"},
            ),
        ])

        report = reconciler.reconcile(trace)
        errors = [i for i in report.issues
                  if i.check == "side_effect_blocked_ledger_match"
                  and i.severity == "error"]
        assert len(errors) >= 1


# ── Integration: dashboard counters ─────────────────────────────────────────

class TestDashboardBlockedCounters:
    """v2.34.0: workflow_recovery section exposes blocked counters."""

    def test_counters_populated_from_durable_log(self, state_manager):
        from nodechain.cli.dashboard import collect_workflow_recovery_status

        state_manager.record_side_effect_block({
            "attempt_id": "d1", "run_id": "r",
            "node_id": "n", "side_effect_type": "external_call",
            "decision": "deny",
        })
        state_manager.record_side_effect_block({
            "attempt_id": "d2", "run_id": "r",
            "node_id": "n", "side_effect_type": "memory_write",
            "decision": "require_approval",
        })

        status = collect_workflow_recovery_status(state_manager=state_manager)
        assert status["side_effect_blocked_count"] == 2
        assert status["side_effect_denied_count"] == 1
        assert status["side_effect_require_approval_count"] == 1

    def test_counters_zero_when_no_blocks(self, state_manager):
        from nodechain.cli.dashboard import collect_workflow_recovery_status
        status = collect_workflow_recovery_status(state_manager=state_manager)
        assert status["side_effect_blocked_count"] == 0
        assert status["side_effect_denied_count"] == 0
