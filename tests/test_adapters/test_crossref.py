"""Tests for CrossRef adapter."""

import pytest
from nodechain.adapters.search.crossref import CrossRefAdapter
from nodechain.adapters.search.base_search import SearchQuery


SAMPLE_CROSSREF_RESPONSE = {
    "status": "ok",
    "message": {
        "total-results": 1,
        "items": [{
            "DOI": "10.5678/crossref-test",
            "title": ["Machine Learning Applications in Finance"],
            "author": [{"given": "Jane", "family": "Doe"}],
            "published-print": {"date-parts": [[2024, 6, 15]]},
            "published-online": {"date-parts": [[2024, 5, 1]]},
            "container-title": ["Journal of Financial Technology"],
            "type": "journal-article",
            "is-referenced-by-count": 25,
            "reference-count": 40,
            "subject": ["Computer Science", "Finance"],
            "license": [{"content-version": "vor", "URL": "https://creativecommons.org/licenses/by/4.0/"}],
            "link": [
                {"content-type": "application/pdf", "URL": "https://example.com/paper.pdf"}
            ],
            "abstract": "<jats:p>A study of ML in finance.</jats:p>",
        }],
    },
}


class TestCrossRefAdapter:
    def test_build_url(self):
        adapter = CrossRefAdapter()
        query = SearchQuery(terms=["machine learning"])
        url = adapter.build_url(query)
        assert "api.crossref.org" in url

    def test_build_params(self):
        adapter = CrossRefAdapter()
        query = SearchQuery(terms=["ML", "finance"], max_results=10)
        params = adapter.build_params(query)
        assert params["query"] == "ML finance"
        assert params["rows"] == 10

    def test_normalize_response(self):
        adapter = CrossRefAdapter()
        query = SearchQuery(terms=["machine learning"])
        results = adapter.normalize_response(SAMPLE_CROSSREF_RESPONSE, query)

        assert len(results) == 1
        r = results[0]
        assert r.origin_api == "crossref"
        assert r.raw_data["title"] == "Machine Learning Applications in Finance"
        assert r.raw_data["doi"] == "10.5678/crossref-test"
        assert r.raw_data["is_referenced_by_count"] == 25
        assert r.raw_data["source_type"] == "journal_article"

    def test_normalize_empty_response(self):
        adapter = CrossRefAdapter()
        raw = {"status": "ok", "message": {"total-results": 0, "items": []}}
        query = SearchQuery(terms=["nothing"])
        results = adapter.normalize_response(raw, query)
        assert len(results) == 0
