"""v2.27.0 — Memory Policy Runtime Gate + Write Reference Binding.

Verifies the reviewer's 5 hard sign-off requirements:
1. confidence=0.69 -> blocked with memory.block_low_confidence
2. sensitivity=HIGH -> blocked with memory.block_high_sensitivity
3. confidence=0.9 + sensitivity=LOW -> allowed with memory.allow_write
4. node no longer emits memory.confidence_threshold (old fake rule_id)
5. successful write trace contains non-empty write_ref/doc_id

Plus: the declarative PolicyEngine is the runtime authority (not hardcoded
in-node thresholds); structural validation is separate from policy decisions.
"""

from __future__ import annotations

import os
import sys
import asyncio
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nodechain.core.policy import PolicyEngine
from nodechain.core.default_policies import DEFAULT_POLICIES
from nodechain.nodes.memory_write import MemoryWriteDecisionNode
from nodechain.core.envelope import InvocationEnvelope


def _make_engine() -> PolicyEngine:
    """PolicyEngine with DEFAULT_POLICIES (incl. MEMORY_WRITE_POLICY)."""
    eng = PolicyEngine()
    for p in DEFAULT_POLICIES:
        eng.register(p)
    return eng


def _make_node(engine=None) -> MemoryWriteDecisionNode:
    return MemoryWriteDecisionNode(memory_manager=None, policy_engine=engine)


def _make_envelope(confidence: float = 0.9, recommendation: str = "Adopt RAG") -> InvocationEnvelope:
    return InvocationEnvelope(
        run_id="test-run", chain_id="test-chain", node_id="memory_write_decision",
        step_id=11,
        payload={
            "recommendation": recommendation,
            "executive_summary": "Summary of findings for memory write.",
            "confidence_statement": {"numeric": confidence, "label": "HIGH"},
        },
    )


# ── the reviewer's 5 hard requirements ────────────────────────────────────────────


class TestPolicyGateRequirements:
    """The 5 tests the review required for sign-off."""

    def test_low_confidence_blocked_with_real_rule_id(self):
        """confidence=0.69 -> blocked with memory.block_low_confidence."""
        node = _make_node(_make_engine())
        envelope = _make_envelope(confidence=0.69)
        result = asyncio.run(node.execute(envelope))
        candidates = result.output["candidates"]
        pd = candidates[0]["policy_decision"]
        assert pd["approved"] is False
        assert pd["rule_id"] == "memory.block_low_confidence"

    def test_high_sensitivity_blocked_with_real_rule_id(self):
        """sensitivity=HIGH -> blocked with memory.block_high_sensitivity."""
        node = _make_node(_make_engine())
        envelope = _make_envelope(confidence=0.9)
        result = asyncio.run(node.execute(envelope))
        candidates = result.output["candidates"]
        # The node proposes candidates with sensitivity MEDIUM by default;
        # override to HIGH via the candidate's policy context.
        # We test the _evaluate_policy directly to control sensitivity.
        pd = node._evaluate_policy(
            {"confidence": 0.9, "sensitivity": "HIGH", "content": "x", "subject": "s"},
            0.9,
        )
        assert pd["approved"] is False
        assert pd["rule_id"] == "memory.block_high_sensitivity"

    def test_high_confidence_low_sensitivity_allowed(self):
        """confidence=0.9 + sensitivity=LOW -> allowed with memory.allow_write."""
        node = _make_node(_make_engine())
        pd = node._evaluate_policy(
            {"confidence": 0.9, "sensitivity": "LOW", "content": "x", "subject": "s"},
            0.9,
        )
        assert pd["approved"] is True
        assert pd["rule_id"] == "memory.allow_write"

    def test_node_no_longer_emits_fake_rule_id(self):
        """The old fake 'memory.confidence_threshold' must never appear."""
        node = _make_node(_make_engine())
        pd = node._evaluate_policy(
            {"confidence": 0.5, "sensitivity": "LOW", "content": "x", "subject": "s"},
            0.5,
        )
        assert pd["rule_id"] != "memory.confidence_threshold"
        assert pd.get("policy_id") != "memory.confidence_threshold"
        # Also check the old fake sensitivity gate string is gone
        assert pd.get("policy_id") != "memory.sensitivity_gate"

    def test_successful_write_has_nonempty_write_ref(self):
        """A committed write must carry a non-empty write_ref."""
        node = _make_node(None)  # no manager -> fallback path
        envelope = _make_envelope(confidence=0.9)
        result = asyncio.run(node.execute(envelope))
        candidates = result.output["candidates"]
        wr = candidates[0].get("write_result", {})
        assert wr.get("committed") is True
        assert wr.get("write_ref", "") != ""


# ── Structural validation is separate from policy ────────────────────────────


class TestStructuralValidation:
    """v2.27.0: _validate_candidate checks structure only, not policy thresholds."""

    def test_low_confidence_passes_structural_validation(self):
        """Low confidence is a POLICY decision, not a structural validation.
        _validate_candidate should pass if content/subject are present, even
        if confidence is below threshold (the gate handles that)."""
        node = _make_node(None)
        vr = node._validate_candidate(
            {"confidence": 0.3, "content": "valid", "subject": "valid"}, 0.3,
        )
        assert vr["passed"] is True
        assert vr["issues"] == []

    def test_empty_content_fails_structural_validation(self):
        node = _make_node(None)
        vr = node._validate_candidate(
            {"confidence": 0.9, "content": "", "subject": "valid"}, 0.9,
        )
        assert vr["passed"] is False
        assert "Empty content" in vr["issues"]


# ── Declarative engine is the authority ──────────────────────────────────────


class TestDeclarativeAuthority:
    """When a PolicyEngine is injected, it is the single policy authority."""

    def test_engine_path_uses_policy_id_from_declarative(self):
        node = _make_node(_make_engine())
        pd = node._evaluate_policy(
            {"confidence": 0.5, "sensitivity": "LOW", "content": "x", "subject": "s"},
            0.5,
        )
        assert pd["policy_id"] == "research.memory_write.v1"

    def test_no_engine_fallback_uses_real_rule_ids(self):
        """Even without an engine, the fallback emits real rule_ids."""
        node = _make_node(None)
        pd = node._evaluate_policy(
            {"confidence": 0.5, "sensitivity": "LOW", "content": "x", "subject": "s"},
            0.5,
        )
        assert pd["approved"] is False
        assert pd["rule_id"] == "memory.block_low_confidence"
        assert pd["policy_id"] == "research.memory_write.v1"

    def test_full_node_run_with_engine_blocks_low_confidence(self):
        """End-to-end: a full node execute with the engine blocks low-confidence writes."""
        node = _make_node(_make_engine())
        envelope = _make_envelope(confidence=0.5)
        result = asyncio.run(node.execute(envelope))
        candidates = result.output["candidates"]
        pd = candidates[0]["policy_decision"]
        assert pd["approved"] is False
        assert pd["rule_id"] == "memory.block_low_confidence"
        # Blocked writes should not produce a write_result
        assert "write_result" not in candidates[0] or not candidates[0]["write_result"].get("committed")
