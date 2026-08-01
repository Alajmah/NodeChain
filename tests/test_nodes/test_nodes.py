"""Tests for individual node execution."""

import pytest
import asyncio
from unittest.mock import MagicMock

from nodechain.core.envelope import compile_envelope
from nodechain.core.port import PortType
from nodechain.nodes.context_selector import ContextSelectorNode
from nodechain.nodes.source_ingestion import SourceIngestionNode
from nodechain.nodes.risk_classifier import RiskClassifierNode
from nodechain.nodes.memory_write import MemoryWriteDecisionNode


class TestContextSelectorNode:
    """Test the deterministic Context Selector Node."""

    @pytest.mark.asyncio
    async def test_produces_context_bundle(self):
        node = ContextSelectorNode()
        envelope = compile_envelope(
            run_id="test",
            chain_id="test",
            node_id="context_selector",
            step_id=1,
            payload={
                "plan_id": "plan-1",
                "tasks": [{
                    "task_id": "t1",
                    "description": "search for AI",
                    "query_terms": ["artificial intelligence", "healthcare"],
                    "priority": 1,
                }],
                "source_routing": {
                    "primary": ["semantic_scholar", "pubmed"],
                    "secondary": ["crossref"],
                    "domain_specific": {"biomedical": ["pubmed"]},
                },
            },
        )

        response = await node.execute(envelope)
        assert response.success is True
        assert response.output_type == PortType.CONTEXT_BUNDLE
        assert "search_queries" in response.output
        assert "adapter_grants" in response.output
        assert "semantic_scholar" in response.output["adapter_grants"]
        assert "pubmed" in response.output["adapter_grants"]

    @pytest.mark.asyncio
    async def test_manifest(self):
        node = ContextSelectorNode()
        assert node.manifest.node_id == "context_selector"
        assert node.manifest.node_type == "deterministic"


class TestSourceIngestionNode:
    """Test the Source Ingestion normalizer."""

    @pytest.mark.asyncio
    async def test_normalizes_semantic_scholar(self):
        node = SourceIngestionNode()
        envelope = compile_envelope(
            run_id="test",
            chain_id="test",
            node_id="source_ingestion",
            step_id=1,
            payload={
                "results": [{
                    "origin_api": "semantic_scholar",
                    "raw_data": {
                        "paperId": "abc123",
                        "title": "AI in Healthcare",
                        "abstract": "This paper discusses AI applications.",
                        "authors": [{"name": "Dr. Smith"}],
                        "year": 2024,
                        "citationCount": 50,
                        "venue": "Nature Medicine",
                        "isOpenAccess": True,
                        "openAccessPdf": {"url": "https://example.com/paper.pdf"},
                        "publicationTypes": ["JournalArticle"],
                        "fieldsOfStudy": ["Computer Science", "Medicine"],
                        "externalIds": {"DOI": "10.1234/test"},
                        "influentialCitationCount": 10,
                        "referenceCount": 30,
                    },
                    "query_used": "AI healthcare",
                    "retrieved_at": "2026-01-01T00:00:00Z",
                }],
                "total_found": 1,
                "adapters_called": ["semantic_scholar"],
                "adapters_failed": [],
            },
        )

        response = await node.execute(envelope)
        assert response.success is True
        assert response.output_type == PortType.SOURCE_SET
        assert len(response.output["sources"]) == 1
        source = response.output["sources"][0]
        assert source["title"] == "AI in Healthcare"
        assert source["origin_api"] == "semantic_scholar"
        assert source["citation_count"] == 50
        assert source["peer_reviewed"] is True
        assert "ingestion_stats" in response.output

    @pytest.mark.asyncio
    async def test_deduplicates_sources(self):
        node = SourceIngestionNode()
        envelope = compile_envelope(
            run_id="test",
            chain_id="test",
            node_id="source_ingestion",
            step_id=1,
            payload={
                "results": [
                    {
                        "origin_api": "semantic_scholar",
                        "raw_data": {"title": "Same Paper Title", "paperId": "1"},
                        "query_used": "test",
                        "retrieved_at": "2026-01-01T00:00:00Z",
                    },
                    {
                        "origin_api": "openalex",
                        "raw_data": {"title": "Same Paper Title", "id": "2"},
                        "query_used": "test",
                        "retrieved_at": "2026-01-01T00:00:00Z",
                    },
                ],
                "total_found": 2,
                "adapters_called": ["semantic_scholar", "openalex"],
            },
        )

        response = await node.execute(envelope)
        assert len(response.output["sources"]) == 1  # Deduplicated
        assert response.output["ingestion_stats"]["duplicates_removed"] == 1


class TestRiskClassifierNode:
    """Test the Risk Classifier Node."""

    @pytest.mark.asyncio
    async def test_low_risk_classification(self):
        node = RiskClassifierNode()
        envelope = compile_envelope(
            run_id="test",
            chain_id="test",
            node_id="risk_classifier",
            step_id=1,
            payload={
                "validated_claims": [
                    {"claim_id": "c1", "status": "confirmed", "adjusted_confidence": 0.9},
                    {"claim_id": "c2", "status": "confirmed", "adjusted_confidence": 0.85},
                ],
                "validation_summary": {"total_claims": 2, "confirmed": 2},
            },
        )

        response = await node.execute(envelope)
        assert response.success is True
        assert response.output["risk_level"] == "LOW"
        assert response.output["review_required"] is False

    @pytest.mark.asyncio
    async def test_high_risk_triggers_review(self):
        node = RiskClassifierNode()
        envelope = compile_envelope(
            run_id="test",
            chain_id="test",
            node_id="risk_classifier",
            step_id=1,
            payload={
                "validated_claims": [
                    {"claim_id": "c1", "status": "contradicted", "adjusted_confidence": 0.2},
                    {"claim_id": "c2", "status": "unconfirmed", "adjusted_confidence": 0.3},
                ],
                "validation_summary": {"total_claims": 2, "confirmed": 0},
            },
        )

        response = await node.execute(envelope)
        assert response.output["risk_level"] == "HIGH"
        assert response.output["review_required"] is True


class TestMemoryWriteNode:
    """Test the Memory Write Decision Node."""

    @pytest.mark.asyncio
    async def test_high_confidence_write_approved(self):
        node = MemoryWriteDecisionNode()
        envelope = compile_envelope(
            run_id="test",
            chain_id="test",
            node_id="memory_write_decision",
            step_id=1,
            payload={
                "recommendation": "AI has significant positive impact on healthcare diagnostics",
                "executive_summary": "Test summary",
                "confidence_statement": {"level": "HIGH", "numeric": 0.85},
            },
        )

        response = await node.execute(envelope)
        assert response.success is True
        assert len(response.output["candidates"]) > 0
        candidate = response.output["candidates"][0]
        assert candidate["write_result"]["committed"] is True

    @pytest.mark.asyncio
    async def test_low_confidence_write_blocked(self):
        node = MemoryWriteDecisionNode()
        envelope = compile_envelope(
            run_id="test",
            chain_id="test",
            node_id="memory_write_decision",
            step_id=1,
            payload={
                "recommendation": "Inconclusive findings",
                "executive_summary": "Low confidence results",
                "confidence_statement": {"level": "LOW", "numeric": 0.3},
            },
        )

        response = await node.execute(envelope)
        candidate = response.output["candidates"][0]
        assert candidate["confidence"] == 0.3
        # Should be blocked because below 0.7 threshold
        assert candidate["write_result"]["committed"] is False
