"""Tests for TraceEmitter — structured trace event creation.

Covers:
- Core emit
- Chain lifecycle helpers
- Node lifecycle helpers
- Policy events
- Validation events
- Branch/join helpers
- Review events
- Side-effect events
- Step tracking
"""

import pytest

from nodechain.core.trace import ChainTrace, EventType, Actor
from nodechain.runtime.trace_emitter import TraceEmitter


def _make_emitter() -> tuple[TraceEmitter, ChainTrace]:
    trace = ChainTrace(run_id="test-run", chain_id="test-chain")
    emitter = TraceEmitter(
        trace=trace, run_id="test-run", chain_id="test-chain",
        record_fn=lambda e: trace.add_event(e),
    )
    return emitter, trace


class TestCoreEmit:
    def test_basic_emit(self):
        emitter, trace = _make_emitter()
        emitter.emit(EventType.CHAIN_STARTED, decision="chain_init")
        assert len(trace.events) == 1
        assert trace.events[0].event_type == EventType.CHAIN_STARTED

    def test_emit_with_metadata(self):
        emitter, trace = _make_emitter()
        emitter.emit(
            EventType.POLICY_EVALUATED,
            node_id="search_tool",
            metadata={"policy_type": "tool_access", "allowed": True},
        )
        assert trace.events[0].metadata["policy_type"] == "tool_access"

    def test_step_id_from_counter(self):
        emitter, trace = _make_emitter()
        emitter.set_step(5)
        emitter.emit(EventType.NODE_INVOKED, node_id="a")
        assert trace.events[0].step_id == 5

    def test_step_id_override(self):
        emitter, trace = _make_emitter()
        emitter.set_step(5)
        emitter.emit(EventType.NODE_INVOKED, node_id="a", step_id=10)
        assert trace.events[0].step_id == 10

    def test_reason_codes(self):
        emitter, trace = _make_emitter()
        emitter.emit(EventType.CHAIN_FAILED, reason_codes=["timeout", "retry_exhausted"])
        assert trace.events[0].reason_codes == ["timeout", "retry_exhausted"]


class TestChainLifecycle:
    def test_chain_started(self):
        emitter, trace = _make_emitter()
        emitter.chain_started("research_chain")
        e = trace.events[0]
        assert e.event_type == EventType.CHAIN_STARTED
        assert e.metadata["chain_name"] == "research_chain"

    def test_chain_completed(self):
        emitter, trace = _make_emitter()
        emitter.chain_completed(duration_ms=1500.0, final_status="completed")
        e = trace.events[0]
        assert e.event_type == EventType.CHAIN_COMPLETED
        assert e.metadata["duration_ms"] == 1500.0

    def test_chain_failed(self):
        emitter, trace = _make_emitter()
        emitter.chain_failed("node_error", details={"node": "search"})
        e = trace.events[0]
        assert e.event_type == EventType.CHAIN_FAILED
        assert "node_error" in e.reason_codes


class TestNodeLifecycle:
    def test_node_invoked(self):
        emitter, trace = _make_emitter()
        emitter.node_invoked("goal_interpreter", step_id=1)
        e = trace.events[0]
        assert e.event_type == EventType.NODE_INVOKED
        assert e.node_id == "goal_interpreter"
        assert e.step_id == 1

    def test_node_succeeded(self):
        emitter, trace = _make_emitter()
        emitter.node_succeeded("goal_interpreter", latency_ms=150, cost_usd=0.001)
        e = trace.events[0]
        assert e.event_type == EventType.NODE_SUCCEEDED
        assert e.latency_ms == 150

    def test_node_failed(self):
        emitter, trace = _make_emitter()
        emitter.node_failed("search_tool", error="connection_timeout")
        e = trace.events[0]
        assert e.event_type == EventType.NODE_FAILED
        assert "connection_timeout" in e.reason_codes

    def test_node_skipped(self):
        emitter, trace = _make_emitter()
        emitter.node_skipped("memory_write", reason="no_new_knowledge")
        e = trace.events[0]
        assert e.event_type == EventType.NODE_SKIPPED
        assert e.metadata["reason"] == "no_new_knowledge"


class TestPolicyEvents:
    def test_policy_pass(self):
        emitter, trace = _make_emitter()
        emitter.policy_result("search_tool", "tool_access", allowed=True)
        e = trace.events[0]
        assert e.decision == "policy_pass"
        assert e.metadata["allowed"] is True

    def test_policy_deny(self):
        emitter, trace = _make_emitter()
        emitter.policy_result("search_tool", "tool_access", allowed=False, reason="not_authorized")
        e = trace.events[0]
        assert e.decision == "policy_deny"
        assert e.metadata["reason"] == "not_authorized"


class TestValidationEvents:
    def test_validation_passed(self):
        emitter, trace = _make_emitter()
        emitter.validation_passed("goal_interpreter", "schema")
        e = trace.events[0]
        assert e.event_type == EventType.VALIDATION_PASSED
        assert e.decision == "schema_valid"

    def test_validation_failed(self):
        emitter, trace = _make_emitter()
        emitter.validation_failed("goal_interpreter", ["missing_field"], "schema")
        e = trace.events[0]
        assert e.event_type == EventType.VALIDATION_FAILED
        assert "missing_field" in e.reason_codes


class TestBranchJoinEvents:
    def test_branch_started(self):
        emitter, trace = _make_emitter()
        emitter.branch_started("router", "bio", ["bio_search", "bio_process"])
        e = trace.events[0]
        assert e.event_type == EventType.BRANCH_STARTED
        assert e.metadata["branch"] == "bio"

    def test_branch_completed(self):
        emitter, trace = _make_emitter()
        emitter.branch_completed("router", "bio", duration_ms=250.0)
        assert trace.events[0].event_type == EventType.BRANCH_COMPLETED

    def test_branch_failed(self):
        emitter, trace = _make_emitter()
        emitter.branch_failed("router", "bio", error="timeout", failed_node="bio_search")
        e = trace.events[0]
        assert e.event_type == EventType.BRANCH_FAILED
        assert e.metadata["node"] == "bio_search"

    def test_join_ready(self):
        emitter, trace = _make_emitter()
        emitter.join_ready("joiner", {"completed": ["bio", "tech"]})
        assert trace.events[0].event_type == EventType.JOIN_READY

    def test_join_blocked(self):
        emitter, trace = _make_emitter()
        emitter.join_blocked("joiner", {"failed": ["bio"]})
        assert trace.events[0].event_type == EventType.JOIN_BLOCKED


class TestReviewEvents:
    def test_review_requested(self):
        emitter, trace = _make_emitter()
        emitter.review_requested("response_generator", "g1")
        e = trace.events[0]
        assert e.event_type == EventType.HUMAN_REVIEW_REQUESTED
        assert e.metadata["gate_id"] == "g1"

    def test_review_resolved(self):
        emitter, trace = _make_emitter()
        emitter.review_resolved("response_generator", "approve", "g1")
        e = trace.events[0]
        assert e.event_type == EventType.HUMAN_REVIEW_COMPLETED
        assert e.metadata["review_decision"] == "approve"


class TestSideEffectEvents:
    def test_side_effect_started(self):
        emitter, trace = _make_emitter()
        emitter.side_effect_started("search_tool", "api_call", "sem_scholar:abc123")
        e = trace.events[0]
        # v2.33.0: emits the canonical SIDE_EFFECT_STARTED event type (not
        # TOOL_CALLED), so the reconciler's Check 4b can bind it.
        assert e.event_type == EventType.SIDE_EFFECT_STARTED
        assert e.metadata["idempotency_key"] == "sem_scholar:abc123"
        assert e.metadata["effect_type"] == "api_call"

    def test_side_effect_completed(self):
        emitter, trace = _make_emitter()
        emitter.side_effect_completed("search_tool", "api_call", "sem_scholar:abc123", duration_ms=320.0)
        e = trace.events[0]
        # v2.33.0: emits the canonical SIDE_EFFECT_COMPLETED event type (not
        # TOOL_RESULT_RECEIVED), so the reconciler's Check 4a can bind it.
        assert e.event_type == EventType.SIDE_EFFECT_COMPLETED
        assert e.metadata["duration_ms"] == 320.0
        assert e.metadata["idempotency_key"] == "sem_scholar:abc123"

    def test_side_effect_failed(self):
        emitter, trace = _make_emitter()
        emitter.side_effect_failed(
            "search_tool", "api_call", "sem_scholar:abc123",
            reason="adapter_timeout",
        )
        e = trace.events[0]
        assert e.event_type == EventType.SIDE_EFFECT_FAILED
        assert e.metadata["idempotency_key"] == "sem_scholar:abc123"
        assert e.metadata["effect_type"] == "api_call"
        assert e.metadata["reason"] == "adapter_timeout"

    def test_side_effect_failed_no_reason(self):
        emitter, trace = _make_emitter()
        emitter.side_effect_failed("search_tool", "api_call", "sem_scholar:abc123")
        e = trace.events[0]
        assert e.event_type == EventType.SIDE_EFFECT_FAILED
        assert "reason" not in e.metadata


class TestContracts:
    def test_contracts_validated(self):
        emitter, trace = _make_emitter()
        emitter.contracts_validated(["goal_interpreter", "search_tool"])
        e = trace.events[0]
        assert e.event_type == EventType.CONTRACT_VALIDATED
        assert "goal_interpreter" in e.metadata["validated_nodes"]
