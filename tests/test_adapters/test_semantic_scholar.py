"""Tests for Semantic Scholar adapter with mocked HTTP."""

import pytest
import json
from nodechain.adapters.search.semantic_scholar import SemanticScholarAdapter
from nodechain.adapters.search.base_search import SearchQuery


class TestSemanticScholarAdapter:
    def test_build_url(self):
        adapter = SemanticScholarAdapter()
        query = SearchQuery(terms=["artificial intelligence"])
        url = adapter.build_url(query)
        assert "semanticscholar.org" in url

    def test_build_params(self):
        adapter = SemanticScholarAdapter()
        query = SearchQuery(terms=["AI", "healthcare"], max_results=5)
        params = adapter.build_params(query)
        assert params["query"] == "AI healthcare"
        assert params["limit"] == 5

    def test_normalize_response(self):
        adapter = SemanticScholarAdapter()
        raw = {
            "total": 1,
            "data": [{
                "paperId": "abc123",
                "title": "AI in Healthcare",
                "abstract": "A survey of AI applications.",
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
            }],
        }
        query = SearchQuery(terms=["AI", "healthcare"])
        results = adapter.normalize_response(raw, query)

        assert len(results) == 1
        r = results[0]
        assert r.origin_api == "semantic_scholar"
        assert r.raw_data["title"] == "AI in Healthcare"
        assert r.raw_data["citation_count"] == 50
        assert r.raw_data["external_ids"]["DOI"] == "10.1234/test"
        assert r.raw_data["venue"] == "Nature Medicine"

    def test_normalize_empty_response(self):
        adapter = SemanticScholarAdapter()
        raw = {"total": 0, "data": []}
        query = SearchQuery(terms=["xyznonexistent"])
        results = adapter.normalize_response(raw, query)
        assert len(results) == 0
