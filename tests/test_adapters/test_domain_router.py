"""Tests for domain router logic."""

import pytest
from nodechain.adapters.search.domain_router import detect_domain, route_to_adapters


class TestDetectDomain:
    def test_detects_biomedical_domain(self):
        result = detect_domain("cancer treatment clinical trial drug efficacy")
        assert result == "biomedical"

    def test_detects_cs_domain(self):
        result = detect_domain("machine learning neural network transformer")
        assert result == "computer_science"

    def test_detects_physics_domain(self):
        result = detect_domain("quantum mechanics particle physics entanglement")
        assert result == "physics"

    def test_detects_math_domain(self):
        result = detect_domain("topology manifold differential geometry")
        assert result == "mathematics"

    def test_default_domain(self):
        result = detect_domain("urban planning zoning regulations")
        assert result == "general"

    def test_single_query_string(self):
        result = detect_domain("drug efficacy in cancer patients")
        assert result == "biomedical"


class TestRouteToAdapters:
    def test_route_biomedical(self):
        decision = route_to_adapters("biomedical")
        assert "pubmed" in decision.primary
        assert "semantic_scholar" in decision.primary

    def test_route_cs(self):
        decision = route_to_adapters("computer_science")
        assert "arxiv" in decision.primary
        assert "semantic_scholar" in decision.primary

    def test_route_general(self):
        decision = route_to_adapters("general")
        assert "semantic_scholar" in decision.primary
        assert "openalex" in decision.primary
        assert "crossref" in decision.secondary

    def test_route_with_source_routing_override(self):
        decision = route_to_adapters(
            "biomedical",
            source_routing={
                "primary": ["pubmed"],
                "secondary": [],
                "domain_specific": {"biomedical": ["pubmed"]},
            },
        )
        assert decision.primary == ["pubmed"]
        assert "Task planner" in decision.routing_reason
