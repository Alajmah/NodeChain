"""Failing tests for citation/evidence gaps (v2.54.0 — drive v2.67.3 fixes).

These tests are EXPECTED TO FAIL (xfail) until v2.67.3 implements the fixes.
They document the exact gaps ChatGPT found in its audit:

1. ClaimValidatorNode._merge_validation_results drops supporting_sources
2. RiskClassifierNode zero-claim branch violates port contract
3. EvidenceSynthesizerNode marks fabricated IDs as [INVALID] instead of quarantining
"""

from __future__ import annotations

import inspect

import pytest

from nodechain.adapters.mock_model_adapter import MockModelAdapter
from nodechain.nodes.claim_validator import ClaimValidatorNode
from nodechain.nodes.risk_classifier import RiskClassifierNode
from nodechain.nodes.evidence_synthesizer import EvidenceSynthesizerNode


# --- Gap 1: ClaimValidatorNode drops supporting_sources on merge ---------------

def test_merge_preserves_supporting_sources():
    """CRITICAL: _merge_validation_results must preserve supporting_sources
    from the structural validation input. Currently it builds a new dict
    WITHOUT this field, so citations are lost before ResponseGeneratorNode."""
    node = ClaimValidatorNode(model_adapter=MockModelAdapter())
    structural = [{
        "claim_id": "c1",
        "statement": "Test claim",
        "confidence": 0.8,
        "supporting_sources": ["src_001", "src_002"],
        "contradicting_sources": ["src_003"],
        "structural_validation": {"passed": True, "issues": []},
    }]
    consistency = [{
        "claim_id": "c1",
        "internal_consistency": 0.9,
        "source_agreement": 0.85,
        "issues": [],
    }]

    merged = node._merge_validation_results(structural, consistency)

    assert len(merged) == 1
    assert merged[0]["supporting_sources"] == ["src_001", "src_002"]
    assert merged[0]["contradicting_sources"] == ["src_003"]


# --- Gap 2: RiskClassifierNode zero-claim branch violates port contract --------

def test_risk_classifier_zero_claim_preserves_guaranteed_fields():
    """CRITICAL: RiskClassifierNode declares validated_claims and sources as
    guaranteed output fields, but the zero-claim branch does not pass them
    through. This violates the port contract."""
    import asyncio
    from nodechain.core.envelope import InvocationEnvelope

    node = RiskClassifierNode(model_adapter=MockModelAdapter())

    envelope = InvocationEnvelope(
        run_id="test", chain_id="test", node_id="risk_classifier",
        step_id=1,
        payload={
            "validated_claims": [],
            "validation_summary": {"total_claims": 0},
            "sources": [{"source_id": "src_001", "title": "Test"}],
            "synthesis": {"claims": []},
        },
    )

    response = asyncio.run(node.execute(envelope))

    # The zero-claim branch must still pass through guaranteed fields
    assert "validated_claims" in response.output, \
        "RiskClassifierNode zero-claim branch must include validated_claims"
    assert "sources" in response.output, \
        "RiskClassifierNode zero-claim branch must include sources"


# --- Gap 3: EvidenceSynthesizerNode marks fabricated IDs as [INVALID] ----------

def test_fabricated_source_id_quarantines_not_soft_marks():
    """CRITICAL: EvidenceSynthesizerNode currently marks fabricated source IDs
    with "[INVALID]" suffix, allowing the claim to proceed with degraded
    citations. It should quarantine or fail the claim instead."""
    # Inspect the execute method source for the [INVALID] soft-mark pattern.
    source = inspect.getsource(EvidenceSynthesizerNode.execute)
    assert "[INVALID]" not in source, \
        "EvidenceSynthesizerNode.execute must not mark fabricated source IDs " \
        "as [INVALID]; it should quarantine or fail the claim"
