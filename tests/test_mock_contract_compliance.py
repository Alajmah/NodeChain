"""Mock Model Adapter contract compliance tests.

Verifies that MockModelAdapter payloads match the current node output contracts.
These tests exist because the mock payloads drifted from the node contracts
before v2.67.3 — evidence_synthesizer returned evidence_matrix instead of
claims/synthesis, claim_validator returned verdict/evidence_count instead of
results[], and response_generator included fields the node builds programmatically.
"""

from __future__ import annotations

import asyncio

import pytest

from nodechain.adapters.mock_model_adapter import MockModelAdapter
from nodechain.core.envelope import InvocationEnvelope
from nodechain.nodes.evidence_synthesizer import EvidenceSynthesizerNode
from nodechain.nodes.claim_validator import ClaimValidatorNode
from nodechain.nodes.risk_classifier import RiskClassifierNode
from nodechain.nodes.response_generator import ResponseGeneratorNode


# ── Test fixtures ──────────────────────────────────────────────────────────

def _make_sources(n: int = 5) -> list[dict]:
    """Create n test sources with full metadata."""
    return [
        {
            "source_id": f"src-{i}",
            "title": f"Academic Source {i}",
            "publication_date": "2024",
            "abstract": f"This is abstract text for source {i} with sufficient content for synthesis.",
            "credibility_signals": {"overall_score": 0.8},
            "citation_count": 50,
        }
        for i in range(1, n + 1)
    ]


def _make_qualified(n: int = 5) -> list[dict]:
    """Create n qualified source entries matching _make_sources."""
    return [
        {"source_ref": f"src-{i}", "quality_score": 0.8, "included": True}
        for i in range(1, n + 1)
    ]


def _make_envelope(envelope_id: str, node_id: str, step_id: int, payload: dict) -> InvocationEnvelope:
    return InvocationEnvelope(
        envelope_id=envelope_id,
        run_id="test-run",
        chain_id="test-chain",
        step_id=step_id,
        node_id=node_id,
        payload=payload,
    )


# ── Evidence Synthesizer contract ─────────────────────────────────────────

class TestEvidenceSynthesizerMockContract:
    """Mock must produce claims[] and synthesis{} matching the evidence_base contract."""

    def test_produces_claims_list(self):
        mock = MockModelAdapter()
        env = _make_envelope("e1", "evidence_synthesizer", 1, {
            "qualified_sources": _make_qualified(),
            "sources": _make_sources(),
        })
        result = asyncio.run(EvidenceSynthesizerNode(mock).execute(env))
        claims = result.output.get("claims", [])
        assert len(claims) >= 1, "Synthesizer must produce at least 1 claim"

    def test_claims_have_required_fields(self):
        mock = MockModelAdapter()
        env = _make_envelope("e2", "evidence_synthesizer", 1, {
            "qualified_sources": _make_qualified(),
            "sources": _make_sources(),
        })
        result = asyncio.run(EvidenceSynthesizerNode(mock).execute(env))
        for claim in result.output["claims"]:
            assert "claim_id" in claim
            assert "statement" in claim
            assert "supporting_sources" in claim
            assert "confidence" in claim

    def test_produces_synthesis(self):
        mock = MockModelAdapter()
        env = _make_envelope("e3", "evidence_synthesizer", 1, {
            "qualified_sources": _make_qualified(),
            "sources": _make_sources(),
        })
        result = asyncio.run(EvidenceSynthesizerNode(mock).execute(env))
        synthesis = result.output.get("synthesis", {})
        assert "summary" in synthesis
        assert "key_findings" in synthesis
        assert len(synthesis["key_findings"]) >= 1

    def test_source_ids_remapped_correctly(self):
        """Mock claims cite S1-S5 aliases, node must remap to real source IDs."""
        mock = MockModelAdapter()
        sources = _make_sources()
        env = _make_envelope("e4", "evidence_synthesizer", 1, {
            "qualified_sources": _make_qualified(),
            "sources": sources,
        })
        result = asyncio.run(EvidenceSynthesizerNode(mock).execute(env))
        real_ids = {s["source_id"] for s in sources}
        for claim in result.output["claims"]:
            for sid in claim.get("supporting_sources", []):
                assert sid in real_ids, f"Source {sid} not in real source IDs after remap"

    def test_no_fabricated_source_ids(self):
        """No claim should cite a source ID that doesn't exist."""
        mock = MockModelAdapter()
        env = _make_envelope("e5", "evidence_synthesizer", 1, {
            "qualified_sources": _make_qualified(),
            "sources": _make_sources(),
        })
        result = asyncio.run(EvidenceSynthesizerNode(mock).execute(env))
        real_ids = {s["source_id"] for s in _make_sources()}
        for claim in result.output["claims"]:
            for sid in claim.get("supporting_sources", []):
                assert sid in real_ids, f"Fabricated source ID: {sid}"
            assert claim.get("status") != "quarantined_fabricated_source", \
                "Normal mock case should not quarantine any claims"


# ── Claim Validator contract ──────────────────────────────────────────────

class TestClaimValidatorMockContract:
    """Mock must produce results[] with claim_id, status, internal_consistency."""

    def test_consistency_validation_returns_results(self):
        mock = MockModelAdapter()
        synth_env = _make_envelope("v1", "evidence_synthesizer", 1, {
            "qualified_sources": _make_qualified(),
            "sources": _make_sources(),
        })
        synth_result = asyncio.run(EvidenceSynthesizerNode(mock).execute(synth_env))

        val_env = _make_envelope("v2", "claim_validator", 2, {
            "claims": synth_result.output["claims"],
            "synthesis": synth_result.output["synthesis"],
            "sources": _make_sources(),
        })
        result = asyncio.run(ClaimValidatorNode(mock).execute(val_env))
        vc = result.output["validated_claims"]
        assert len(vc) >= 1, "Validator must produce validated claims"

    def test_validated_claims_have_status(self):
        mock = MockModelAdapter()
        synth_env = _make_envelope("v3", "evidence_synthesizer", 1, {
            "qualified_sources": _make_qualified(),
            "sources": _make_sources(),
        })
        synth_result = asyncio.run(EvidenceSynthesizerNode(mock).execute(synth_env))

        val_env = _make_envelope("v4", "claim_validator", 2, {
            "claims": synth_result.output["claims"],
            "synthesis": synth_result.output["synthesis"],
            "sources": _make_sources(),
        })
        result = asyncio.run(ClaimValidatorNode(mock).execute(val_env))
        valid_statuses = {"confirmed", "partially_confirmed", "unconfirmed", "contradicted", "insufficient_evidence"}
        for vc in result.output["validated_claims"]:
            assert vc["status"] in valid_statuses, f"Invalid status: {vc['status']}"

    def test_supporting_sources_preserved_through_merge(self):
        """v2.67.3 fix: supporting_sources must survive the merge."""
        mock = MockModelAdapter()
        synth_env = _make_envelope("v5", "evidence_synthesizer", 1, {
            "qualified_sources": _make_qualified(),
            "sources": _make_sources(),
        })
        synth_result = asyncio.run(EvidenceSynthesizerNode(mock).execute(synth_env))

        val_env = _make_envelope("v6", "claim_validator", 2, {
            "claims": synth_result.output["claims"],
            "synthesis": synth_result.output["synthesis"],
            "sources": _make_sources(),
        })
        result = asyncio.run(ClaimValidatorNode(mock).execute(val_env))
        for vc in result.output["validated_claims"]:
            assert "supporting_sources" in vc
            assert len(vc["supporting_sources"]) >= 1


# ── Risk Classifier contract ──────────────────────────────────────────────

class TestRiskClassifierMockContract:
    """Risk classifier is deterministic — no model call. Verify it handles mock-validated claims."""

    def test_produces_risk_assessment(self):
        mock = MockModelAdapter()
        synth_env = _make_envelope("r1", "evidence_synthesizer", 1, {
            "qualified_sources": _make_qualified(),
            "sources": _make_sources(),
        })
        synth_result = asyncio.run(EvidenceSynthesizerNode(mock).execute(synth_env))

        val_env = _make_envelope("r2", "claim_validator", 2, {
            "claims": synth_result.output["claims"],
            "synthesis": synth_result.output["synthesis"],
            "sources": _make_sources(),
        })
        val_result = asyncio.run(ClaimValidatorNode(mock).execute(val_env))

        risk_env = _make_envelope("r3", "risk_classifier", 3, val_result.output)
        result = asyncio.run(RiskClassifierNode(mock).execute(risk_env))

        assert result.output["risk_level"] in {"HIGH", "MEDIUM", "LOW"}
        assert "confidence" in result.output
        assert "validated_claims" in result.output
        assert "sources" in result.output

    def test_zero_claim_branch_passes_contract_fields(self):
        """v2.67.3 fix: zero-claim branch must still emit guaranteed fields."""
        mock = MockModelAdapter()
        env = _make_envelope("r4", "risk_classifier", 3, {
            "validated_claims": [],
            "validation_summary": {"total_claims": 0},
            "sources": [],
            "synthesis": {},
        })
        result = asyncio.run(RiskClassifierNode(mock).execute(env))
        assert "validated_claims" in result.output
        assert "sources" in result.output
        assert result.output["risk_level"] == "HIGH"


# ── Response Generator contract ───────────────────────────────────────────

class TestResponseGeneratorMockContract:
    """Mock must NOT include citations/uncertainty_disclosures (node builds those)."""

    def test_produces_recommendation(self):
        mock = MockModelAdapter()
        synth_env = _make_envelope("g1", "evidence_synthesizer", 1, {
            "qualified_sources": _make_qualified(),
            "sources": _make_sources(),
        })
        synth_result = asyncio.run(EvidenceSynthesizerNode(mock).execute(synth_env))
        val_env = _make_envelope("g2", "claim_validator", 2, {
            "claims": synth_result.output["claims"],
            "synthesis": synth_result.output["synthesis"],
            "sources": _make_sources(),
        })
        val_result = asyncio.run(ClaimValidatorNode(mock).execute(val_env))
        risk_env = _make_envelope("g3", "risk_classifier", 3, val_result.output)
        risk_result = asyncio.run(RiskClassifierNode(mock).execute(risk_env))

        resp_env = _make_envelope("g4", "response_generator", 4, risk_result.output)
        result = asyncio.run(ResponseGeneratorNode(mock).execute(resp_env))

        assert "recommendation" in result.output
        assert len(result.output["recommendation"]) > 10

    def test_citations_built_from_validated_claims(self):
        """Citations must come from confirmed/partially_confirmed claims, not from mock."""
        mock = MockModelAdapter()
        synth_env = _make_envelope("g5", "evidence_synthesizer", 1, {
            "qualified_sources": _make_qualified(),
            "sources": _make_sources(),
        })
        synth_result = asyncio.run(EvidenceSynthesizerNode(mock).execute(synth_env))
        val_env = _make_envelope("g6", "claim_validator", 2, {
            "claims": synth_result.output["claims"],
            "synthesis": synth_result.output["synthesis"],
            "sources": _make_sources(),
        })
        val_result = asyncio.run(ClaimValidatorNode(mock).execute(val_env))
        risk_env = _make_envelope("g7", "risk_classifier", 3, val_result.output)
        risk_result = asyncio.run(RiskClassifierNode(mock).execute(risk_env))

        resp_env = _make_envelope("g8", "response_generator", 4, risk_result.output)
        result = asyncio.run(ResponseGeneratorNode(mock).execute(resp_env))

        citations = result.output["citations"]
        real_ids = {s["source_id"] for s in _make_sources()}
        for ct in citations:
            assert ct["source_ref"] in real_ids, \
                f"Citation references unknown source: {ct['source_ref']}"

    def test_no_invalid_markers_in_output(self):
        """No [INVALID] soft-marking should survive in the final output."""
        mock = MockModelAdapter()
        synth_env = _make_envelope("g9", "evidence_synthesizer", 1, {
            "qualified_sources": _make_qualified(),
            "sources": _make_sources(),
        })
        synth_result = asyncio.run(EvidenceSynthesizerNode(mock).execute(synth_env))

        # Check no [INVALID] in any source string
        import json
        output_str = json.dumps(synth_result.output)
        assert "[INVALID]" not in output_str, "Found [INVALID] soft-marking in output"
