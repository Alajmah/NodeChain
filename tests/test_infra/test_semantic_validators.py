"""Test semantic validators — beyond-schema validation for chain outputs."""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from nodechain.validation.semantic_validators import (
    ReferentialIntegrityValidator,
    ConfidenceConsistencyValidator,
    SourceEnrichmentValidator,
    SemanticValidationPipeline,
)


class TestReferentialIntegrity:
    """Verify source references in claims resolve to actual sources."""

    def test_matching_refs_pass(self):
        """Claims with valid source references should pass."""
        claims = [
            {"claim_id": "c1", "supporting_sources": ["src-1", "src-2"]},
            {"claim_id": "c2", "supporting_sources": ["src-3"]},
        ]
        sources = [
            {"source_id": "src-1"},
            {"source_id": "src-2"},
            {"source_id": "src-3"},
        ]
        result = ReferentialIntegrityValidator().validate(claims, sources)
        assert result.valid
        assert len(result.errors) == 0

    def test_broken_refs_fail(self):
        """Claims referencing non-existent sources should fail."""
        claims = [
            {"claim_id": "c1", "supporting_sources": ["src-1", "src-999"]},
        ]
        sources = [
            {"source_id": "src-1"},
        ]
        result = ReferentialIntegrityValidator().validate(claims, sources)
        assert not result.valid
        assert any("src-999" in e for e in result.errors)

    def test_no_sources_for_claim_warns(self):
        """Claims with no supporting_sources should produce warnings."""
        claims = [
            {"claim_id": "c1", "supporting_sources": []},
        ]
        sources = [{"source_id": "src-1"}]
        result = ReferentialIntegrityValidator().validate(claims, sources)
        assert result.valid  # No errors, just warnings
        assert any("no supporting_sources" in w for w in result.warnings)

    def test_empty_claims_pass(self):
        """No claims should pass trivially."""
        result = ReferentialIntegrityValidator().validate([], [])
        assert result.valid

    def test_source_ref_field(self):
        """Should also check 'source_ref' field on sources."""
        claims = [
            {"claim_id": "c1", "supporting_sources": ["ref-1"]},
        ]
        sources = [
            {"source_ref": "ref-1"},
        ]
        result = ReferentialIntegrityValidator().validate(claims, sources)
        assert result.valid


class TestConfidenceConsistency:
    """Verify claim confidence is consistent with overall assessment."""

    def test_consistent_confidence_passes(self):
        """Claims at 80% with overall 75% should pass."""
        claims = [
            {"claim_id": "c1", "confidence": 0.8},
            {"claim_id": "c2", "confidence": 0.7},
        ]
        result = ConfidenceConsistencyValidator().validate(claims, 0.75)
        assert result.valid

    def test_mismatched_confidence_fails(self):
        """Claims averaging 90%+ with overall below 35% should fail."""
        claims = [
            {"claim_id": "c1", "confidence": 0.95},
            {"claim_id": "c2", "confidence": 0.98},
            {"claim_id": "c3", "confidence": 0.92},
        ]
        result = ConfidenceConsistencyValidator().validate(claims, 0.28)
        assert not result.valid
        assert any("mismatch" in e.lower() for e in result.errors)

    def test_all_perfect_confidence_fails(self):
        """More than 50% of claims at 100% should fail."""
        claims = [
            {"claim_id": "c1", "confidence": 1.0},
            {"claim_id": "c2", "confidence": 1.0},
            {"claim_id": "c3", "confidence": 0.7},
        ]
        result = ConfidenceConsistencyValidator().validate(claims, 0.9)
        assert not result.valid
        assert any("overconfident" in e.lower() for e in result.errors)

    def test_identical_confidence_warns(self):
        """All claims with identical confidence should warn."""
        claims = [
            {"claim_id": "c1", "confidence": 0.8},
            {"claim_id": "c2", "confidence": 0.8},
            {"claim_id": "c3", "confidence": 0.8},
        ]
        result = ConfidenceConsistencyValidator().validate(claims, 0.8)
        assert result.valid
        assert any("identical" in w.lower() for w in result.warnings)

    def test_empty_claims_pass(self):
        """No claims should pass trivially."""
        result = ConfidenceConsistencyValidator().validate([], 0.5)
        assert result.valid

    def test_this_was_phase_d_signal(self):
        """Phase D: 8 claims at 94-98% confidence, overall LOW/28%."""
        claims = [
            {"claim_id": f"c{i}", "confidence": 0.94 + i * 0.005}
            for i in range(8)
        ]
        result = ConfidenceConsistencyValidator().validate(claims, 0.28)
        assert not result.valid  # This should have caught Phase D


class TestSourceEnrichment:
    """Verify sources have meaningful content."""

    def test_enriched_sources_pass(self):
        """Sources with titles pass."""
        sources = [
            {"source_id": "s1", "title": "AI in Healthcare"},
            {"source_id": "s2", "title": "ML Diagnostics", "abstract": "A study..."},
        ]
        result = SourceEnrichmentValidator().validate(sources)
        assert result.valid

    def test_empty_sources_fail(self):
        """More than 50% empty sources should fail."""
        sources = [
            {"source_id": "s1"},
            {"source_id": "s2"},
            {"source_id": "s3", "title": "Good Source"},
        ]
        result = SourceEnrichmentValidator().validate(sources)
        assert not result.valid
        assert any("enrichment" in e.lower() for e in result.errors)

    def test_no_sources_pass(self):
        """No sources should pass trivially."""
        result = SourceEnrichmentValidator().validate([])
        assert result.valid


class TestSemanticPipeline:
    """Test the full validation pipeline."""

    def test_good_output_passes(self):
        """A well-formed chain output should pass all validators."""
        evidence = {
            "claims": [
                {"claim_id": "c1", "statement": "Test", "supporting_sources": ["src-1"], "confidence": 0.8},
            ],
            "sources": [{"source_id": "src-1", "title": "Test Paper"}],
        }
        response = {
            "confidence_statement": {"numeric": 0.75},
        }
        pipeline = SemanticValidationPipeline()
        results = pipeline.validate_chain_output(evidence, response)
        assert pipeline.all_valid(results)

    def test_phase_d_output_fails(self):
        """Phase D output (hallucinated sources, mismatched confidence) should fail."""
        evidence = {
            "claims": [
                {"claim_id": f"c{i}", "supporting_sources": ["fake-src"], "confidence": 0.95}
                for i in range(8)
            ],
            "sources": [{"source_id": "real-src"}],  # Different source
        }
        response = {
            "confidence_statement": {"numeric": 0.28},  # LOW confidence
        }
        pipeline = SemanticValidationPipeline()
        results = pipeline.validate_chain_output(evidence, response)
        assert not pipeline.all_valid(results)
        errors = pipeline.all_errors(results)
        assert len(errors) >= 1  # Should catch referential integrity at minimum
