"""Test policy enforcement — verify policy engine gates work at runtime."""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nodechain.core.policy import (
    Policy, PolicyAction, PolicyEngine, PolicyRule, PolicyType,
)
from nodechain.core.default_policies import DEFAULT_POLICIES


class TestDefaultPolicies:
    """Verify default policies are loaded and functional."""

    def test_default_policies_loaded(self):
        engine = PolicyEngine()
        for p in DEFAULT_POLICIES:
            engine.register(p)
        assert len(engine._policies) == len(DEFAULT_POLICIES)

    def test_memory_write_blocked_low_confidence(self):
        """Low confidence should be denied by memory write policy."""
        engine = PolicyEngine()
        for p in DEFAULT_POLICIES:
            engine.register(p)

        decisions = engine.evaluate(
            PolicyType.MEMORY_WRITE,
            "memory_write_decision",
            {"confidence": 0.3, "sensitivity": "LOW", "memory_access": "write"},
        )
        deny_actions = [d for d in decisions if d.action == PolicyAction.DENY]
        assert len(deny_actions) >= 1
        assert any("confidence" in (d.parameters.get("reason", "")).lower()
                    for d in deny_actions)

    def test_memory_write_allowed_high_confidence(self):
        """High confidence with LOW sensitivity should be allowed."""
        engine = PolicyEngine()
        for p in DEFAULT_POLICIES:
            engine.register(p)

        decisions = engine.evaluate(
            PolicyType.MEMORY_WRITE,
            "memory_write_decision",
            {"confidence": 0.85, "sensitivity": "LOW", "memory_access": "write"},
        )
        deny_actions = [d for d in decisions if d.action == PolicyAction.DENY]
        assert len(deny_actions) == 0

    def test_memory_write_requires_approval_high_sensitivity(self):
        """HIGH sensitivity should require approval."""
        engine = PolicyEngine()
        for p in DEFAULT_POLICIES:
            engine.register(p)

        decisions = engine.evaluate(
            PolicyType.MEMORY_WRITE,
            "memory_write_decision",
            {"confidence": 0.9, "sensitivity": "HIGH", "memory_access": "write"},
        )
        approval = [d for d in decisions if d.action == PolicyAction.REQUIRE_APPROVAL]
        assert len(approval) >= 1

    def test_trust_level_blocks_untrusted_memory_write(self):
        """v2.44.0: Untrusted observed trust level should be denied."""
        engine = PolicyEngine()
        for p in DEFAULT_POLICIES:
            engine.register(p)

        decisions = engine.evaluate(
            PolicyType.TRUST_LEVEL,
            "memory_write_decision",
            {"observed_trust_level": "local_untrusted"},
        )
        deny_actions = [d for d in decisions if d.action == PolicyAction.DENY]
        assert len(deny_actions) >= 1

    def test_cost_limit_blocks_over_budget(self):
        """Node exceeding cost budget should be denied."""
        engine = PolicyEngine()
        for p in DEFAULT_POLICIES:
            engine.register(p)

        decisions = engine.evaluate(
            PolicyType.COST_LIMIT,
            "goal_interpreter",
            {"accumulated_cost": 2.0, "max_cost_usd": 1.0},
        )
        deny_actions = [d for d in decisions if d.action == PolicyAction.DENY]
        assert len(deny_actions) >= 1


class TestPolicyGateInOrchestrator:
    """Verify policy gate fires in real orchestrator execution."""

    def test_policy_events_emitted(self):
        """Orchestrator should emit POLICY_EVALUATED events."""
        import asyncio
        from test_runtime import load_blueprint, _create_mock_nodes
        from nodechain.runtime.orchestrator import Orchestrator
        from nodechain.core.trace import EventType

        blueprint = load_blueprint("blueprints/research_decision_v1.yaml")
        nodes = _create_mock_nodes()
        orch = Orchestrator(blueprint=blueprint, nodes=nodes)
        trace = asyncio.run(orch.run("Test policy gate"))

        assert trace.final_status == "completed"
        event_types = {e.event_type for e in trace.events}
        assert EventType.POLICY_EVALUATED in event_types

        # Count policy events
        policy_events = [e for e in trace.events if e.event_type == EventType.POLICY_EVALUATED]
        # Should have at least one policy event per node with model_required or memory_access
        assert len(policy_events) >= 1

    def test_custom_deny_policy_blocks_chain(self):
        """A custom DENY policy should block chain execution."""
        import asyncio
        from test_runtime import load_blueprint, _create_mock_nodes
        from nodechain.runtime.orchestrator import Orchestrator
        from nodechain.core.trace import EventType

        blueprint = load_blueprint("blueprints/research_decision_v1.yaml")
        nodes = _create_mock_nodes()

        # Create a policy that denies everything
        deny_all = Policy(
            policy_id="test.deny_all",
            policy_type=PolicyType.TRUST_LEVEL,
            target="*",
            description="Test: deny all nodes",
            rules=[
                PolicyRule(
                    rule_id="deny",
                    condition="always",
                    action=PolicyAction.DENY,
                    parameters={"reason": "Test deny policy"},
                    priority=100,
                ),
            ],
        )

        engine = PolicyEngine()
        engine.register(deny_all)
        orch = Orchestrator(blueprint=blueprint, nodes=nodes, policy_engine=engine)
        trace = asyncio.run(orch.run("Test deny policy"))

        assert trace.final_status == "failed"
        # Should have policy_denied in the chain failure
        failed_events = [e for e in trace.events if e.event_type == EventType.CHAIN_FAILED]
        assert any("policy_denied" in (e.decision or "") for e in failed_events)
