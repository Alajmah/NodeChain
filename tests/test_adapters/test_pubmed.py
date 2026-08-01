"""Tests for PubMed adapter."""

import pytest
from nodechain.adapters.search.pubmed import PubMedAdapter
from nodechain.adapters.search.base_search import SearchQuery


SAMPLE_PUBMED_RESPONSE = {
    "esearchresult": {
        "idlist": ["12345678"],
    },
}


SAMPLE_PUBMED_SUMMARY = {
    "result": {
        "12345678": {
            "uid": "12345678",
            "title": "Efficacy of Drug X in Treating Condition Y",
            "authors": [{"name": "Dr. Lee"}, {"name": "Dr. Park"}],
            "pubdate": "2024 Jan 15",
            "source": "N Engl J Med",
            "fulljournalname": "New England Journal of Medicine",
            "volume": "390",
            "issue": "3",
            "pages": "200-210",
            "doi": "10.1056/NEJMoa123456",
            "elocationid": "doi: 10.1056/NEJMoa123456",
            "pubtype": ["Journal Article", "Clinical Trial"],
            "sortpubdate": "2024/01/15 00:00",
        },
    },
}


class TestPubMedAdapter:
    def test_build_url_search(self):
        adapter = PubMedAdapter()
        query = SearchQuery(terms=["drug efficacy"])
        url = adapter.build_url(query)
        assert "eutils.ncbi.nlm.nih.gov" in url

    def test_build_params(self):
        adapter = PubMedAdapter()
        query = SearchQuery(terms=["cancer", "treatment"], max_results=5)
        params = adapter.build_params(query)
        assert params["term"] == "cancer treatment"
        assert params["retmax"] == 5

    def test_normalize_summary(self):
        adapter = PubMedAdapter()
        query = SearchQuery(terms=["drug efficacy"])
        # PubMed normalize expects raw["articles"] as list of parsed dicts
        raw = {
            "articles": [{
                "pmid": "12345678",
                "title": "Efficacy of Drug X in Treating Condition Y",
                "authors": ["Dr. Lee", "Dr. Park"],
                "journal": "New England Journal of Medicine",
                "pub_date": "2024/01/15",
                "mesh_terms": ["Drug Therapy", "Clinical Trial"],
                "pub_types": ["Journal Article", "Clinical Trial"],
                "doi": "10.1056/NEJMoa123456",
                "keywords": ["drug efficacy"],
            }],
        }
        results = adapter.normalize_response(raw, query)

        assert len(results) == 1
        r = results[0]
        assert r.origin_api == "pubmed"
        assert r.raw_data["title"] == "Efficacy of Drug X in Treating Condition Y"
        assert r.raw_data["doi"] == "10.1056/NEJMoa123456"
        assert r.raw_data["source_type"] == "journal_article"
        assert r.raw_data["journal"] == "New England Journal of Medicine"

    def test_normalize_empty(self):
        adapter = PubMedAdapter()
        raw = {"result": {}}
        query = SearchQuery(terms=["nothing"])
        results = adapter.normalize_response(raw, query)
        assert len(results) == 0
