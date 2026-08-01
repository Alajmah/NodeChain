"""Tests for OpenAlex adapter."""

import pytest
from nodechain.adapters.search.openalex import OpenAlexAdapter
from nodechain.adapters.search.base_search import SearchQuery


SAMPLE_OPENLEX_RESPONSE = {
    "results": [{
        "id": "https://openalex.org/W12345",
        "title": "Climate Change Impact on Biodiversity",
        "abstract_inverted_index": {
            "Climate": [0],
            "change": [1],
            "impacts": [2],
            "biodiversity": [3],
            "worldwide": [4],
        },
        "authorships": [{
            "author": {"display_name": "Dr. Green"},
            "institutions": [{"display_name": "MIT"}],
        }],
        "publication_year": 2024,
        "publication_date": "2024-03-15",
        "doi": "https://doi.org/10.1234/climate",
        "type": "article",
        "cited_by_count": 120,
        "primary_location": {
            "source": {"display_name": "Nature Climate Change"}
        },
        "open_access": {"is_oa": True, "oa_url": "https://example.com/paper.pdf"},
        "concepts": [
            {"display_name": "Climate change", "score": 0.9},
            {"display_name": "Biodiversity", "score": 0.8},
        ],
        "topics": [{"display_name": "Ecology"}],
        "referenced_works": ["W1", "W2", "W3"],
        "language": "en",
    }],
}


class TestOpenAlexAdapter:
    def test_build_url(self):
        adapter = OpenAlexAdapter()
        query = SearchQuery(terms=["climate change"])
        url = adapter.build_url(query)
        assert "openalex.org" in url

    def test_build_params(self):
        adapter = OpenAlexAdapter()
        query = SearchQuery(terms=["climate", "biodiversity"], max_results=10)
        params = adapter.build_params(query)
        assert params["search"] == "climate biodiversity"
        assert params["per_page"] == 10

    def test_normalize_response(self):
        adapter = OpenAlexAdapter()
        query = SearchQuery(terms=["climate change"])
        results = adapter.normalize_response(SAMPLE_OPENLEX_RESPONSE, query)

        assert len(results) == 1
        r = results[0]
        assert r.origin_api == "openalex"
        assert r.raw_data["title"] == "Climate Change Impact on Biodiversity"
        assert r.raw_data["abstract"] == "Climate change impacts biodiversity worldwide"
        assert r.raw_data["cited_by_count"] == 120
        assert r.raw_data["doi"] == "10.1234/climate"

    def test_abstract_reconstruction(self):
        inverted = {"Hello": [0], "world": [1], "test": [2]}
        result = OpenAlexAdapter._reconstruct_abstract(inverted)
        assert result == "Hello world test"

    def test_abstract_reconstruction_none(self):
        result = OpenAlexAdapter._reconstruct_abstract(None)
        assert result == ""

    def test_abstract_reconstruction_empty(self):
        result = OpenAlexAdapter._reconstruct_abstract({})
        assert result == ""

    def test_abstract_reconstruction_unordered(self):
        inverted = {"world": [1], "Hello": [0], "beautiful": [2]}
        result = OpenAlexAdapter._reconstruct_abstract(inverted)
        assert result == "Hello world beautiful"
