"""Tests for arXiv adapter with sample XML."""

import pytest
from nodechain.adapters.search.arxiv import ArxivAdapter
from nodechain.adapters.search.base_search import SearchQuery


SAMPLE_ARXIV_XML = {
    "feed": {
        "entry": [{
            "id": "http://arxiv.org/abs/2401.00001v1",
            "title": "Deep Learning for Image Recognition",
            "summary": " We propose a novel architecture. ",
            "author": [{"name": "Alice"}, {"name": "Bob"}],
            "published": "2024-01-15T00:00:00Z",
            "link": [
                {"@_href": "http://arxiv.org/pdf/2401.00001v1", "@_title": "pdf"},
                {"@_href": "http://arxiv.org/abs/2401.00001v1", "@_title": "html"},
            ],
            "category": [
                {"@_term": "cs.CV"},
                {"@_term": "cs.AI"},
            ],
            "arxiv:doi": "10.1234/arxiv.2401.00001",
        }]
    }
}


class TestArxivAdapter:
    def test_build_url(self):
        adapter = ArxivAdapter()
        query = SearchQuery(terms=["transformer", "attention"])
        url = adapter.build_url(query)
        assert "export.arxiv.org" in url

    def test_build_params(self):
        adapter = ArxivAdapter()
        query = SearchQuery(terms=["neural", "network"], max_results=5)
        params = adapter.build_params(query)
        assert "search_query" in params
        assert "all:neural" in params["search_query"]
        assert "all:network" in params["search_query"]
        assert params["max_results"] == 5

    def test_normalize_xml_data(self):
        adapter = ArxivAdapter()
        # arXiv adapter expects raw dict with 'xml_content' key
        # Since the actual parsing requires Atom XML, we test with sample XML
        sample_xml = '''<?xml version="1.0" encoding="UTF-8"?>
        <feed xmlns="http://www.w3.org/2005/Atom">
          <entry>
            <id>http://arxiv.org/abs/2401.00001v1</id>
            <title>Deep Learning for Image Recognition</title>
            <summary> We propose a novel architecture. </summary>
            <author><name>Alice</name></author>
            <published>2024-01-15T00:00:00Z</published>
            <link href="http://arxiv.org/pdf/2401.00001v1" title="pdf"/>
            <category term="cs.CV"/>
          </entry>
        </feed>'''
        raw = {"xml_content": sample_xml}
        query = SearchQuery(terms=["deep learning"])
        results = adapter.normalize_response(raw, query)

        assert len(results) == 1
        r = results[0]
        assert r.origin_api == "arxiv"
        assert r.raw_data["title"] == "Deep Learning for Image Recognition"
        assert r.raw_data["source_type"] == "preprint"
