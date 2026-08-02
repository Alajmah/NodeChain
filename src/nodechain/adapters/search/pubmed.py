"""PubMed (NCBI E-utilities) adapter — biomedical & life sciences literature."""

from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any

from nodechain.adapters.search.base_search import (
    BaseSearchAdapter,
    SearchAdapterResult,
    SearchQuery,
)


class PubMedAdapter(BaseSearchAdapter):
    """
    PubMed NCBI E-utilities adapter.
    Biomedical literature with MeSH terms, clinical trial identifiers.
    Rate limit: 3 req/sec unauthenticated, 10/sec with API key.
    """

    adapter_name = "pubmed"
    adapter_version = "1.0.0"  # v3.5.0
    base_url_search = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi"
    base_url_fetch = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/efetch.fcgi"

    def __init__(
        self,
        *,
        max_retries: int = 3,
        timeout_seconds: float = 30.0,
        backoff_min: float = 1.0,
        backoff_max: float = 10.0,
        circuit_failure_threshold: int = 5,
        circuit_cooldown_seconds: float = 60.0,
    ) -> None:
        api_key = os.environ.get("PUBMED_API_KEY", "")
        rate_limit = 10.0 if api_key else 3.0
        super().__init__(
            rate_limit_per_sec=rate_limit,
            max_retries=max_retries,
            timeout_seconds=timeout_seconds,
            backoff_min=backoff_min,
            backoff_max=backoff_max,
            circuit_failure_threshold=circuit_failure_threshold,
            circuit_cooldown_seconds=circuit_cooldown_seconds,
        )
        self._api_key = api_key

    def build_url(self, query: SearchQuery) -> str:
        # Two-step: first search, then fetch
        return self.base_url_search

    def build_params(self, query: SearchQuery) -> dict[str, Any]:
        params: dict[str, Any] = {
            "db": "pubmed",
            "term": " ".join(query.terms[:3]),
            "retmax": min(query.max_results, 50),
            "retmode": "json",
            "sort": "relevance",
        }
        if self._api_key:
            params["api_key"] = self._api_key
        return params

    def normalize_response(
        self, raw: dict[str, Any], query: SearchQuery
    ) -> list[SearchAdapterResult]:
        """Parse fetched article data."""
        articles = raw.get("articles", [])
        results: list[SearchAdapterResult] = []
        now = datetime.now(timezone.utc).isoformat()

        for article in articles:
            normalized = {
                "pmid": article.get("pmid", ""),
                "title": article.get("title", ""),
                "abstract": article.get("abstract", ""),
                "authors": article.get("authors", []),
                "journal": article.get("journal", ""),
                "publication_date": article.get("pub_date", ""),
                "mesh_terms": article.get("mesh_terms", []),
                "publication_types": article.get("pub_types", []),
                "doi": article.get("doi", ""),
                "keywords": article.get("keywords", []),
                "source_type": "journal_article",
            }

            results.append(
                SearchAdapterResult(
                    origin_api=self.adapter_name,
                    raw_data=normalized,
                    query_used=" ".join(query.terms),
                    retrieved_at=now,
                )
            )

        return results

    async def search(self, query: SearchQuery) -> list[SearchAdapterResult]:
        """
        Two-step PubMed search via shared _fetch():
        1. esearch to get PMIDs (JSON)
        2. efetch to get article details (XML)
        """
        from nodechain.adapters.search.base_search import SearchAdapterError

        await self._respect_rate_limit()

        # Step 1: Search for PMIDs
        search_params = self.build_params(query)
        query_hash = self._compute_query_hash(query)

        fetch_result = await self._fetch(
            self.base_url_search, search_params,
            response_format="json", query_hash=query_hash,
        )

        if not fetch_result.succeeded:
            raise SearchAdapterError(fetch_result.failure)

        search_data = fetch_result.data or {}
        id_list = search_data.get("esearchresult", {}).get("idlist", [])
        if not id_list:
            return []

        # Step 2: Fetch article details
        await self._respect_rate_limit()
        fetch_params: dict[str, Any] = {
            "db": "pubmed",
            "id": ",".join(id_list),
            "retmode": "xml",
            "rettype": "abstract",
        }
        if self._api_key:
            fetch_params["api_key"] = self._api_key

        fetch_result2 = await self._fetch(
            self.base_url_fetch, fetch_params,
            response_format="text", query_hash=query_hash,
        )

        if not fetch_result2.succeeded:
            raise SearchAdapterError(fetch_result2.failure)

        elapsed_ms = fetch_result.latency_ms + fetch_result2.latency_ms

        # Parse XML
        articles = self._parse_pubmed_xml(fetch_result2.text or "")
        raw = {"articles": articles}
        results = self.normalize_response(raw, query)

        return self._finalize_results(results, elapsed_ms)

    def _parse_pubmed_xml(self, xml_content: str) -> list[dict[str, Any]]:
        """Parse PubMed XML into structured article dicts."""
        articles: list[dict[str, Any]] = []

        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError:
            return []

        for article in root.findall(".//PubmedArticle"):
            medline = article.find("MedlineCitation")
            if medline is None:
                continue

            article_data = medline.find("Article")
            if article_data is None:
                continue

            # Title
            title_elem = article_data.find(".//ArticleTitle")
            title = title_elem.text if title_elem is not None else ""

            # Abstract
            abstract_parts = []
            for text in article_data.findall(".//AbstractText"):
                label = text.get("Label", "")
                content = text.text or ""
                if label:
                    abstract_parts.append(f"{label}: {content}")
                else:
                    abstract_parts.append(content)
            abstract = " ".join(abstract_parts)

            # Authors
            authors = []
            for author in article_data.findall(".//Author"):
                last = author.find("LastName")
                fore = author.find("ForeName")
                name = ""
                if fore is not None and last is not None:
                    name = f"{fore.text} {last.text}"
                elif last is not None:
                    name = last.text or ""
                if name:
                    authors.append(name)

            # Journal
            journal_elem = article_data.find(".//Journal/Title")
            journal = journal_elem.text if journal_elem is not None else ""

            # Publication date
            pub_date = medline.find(".//DateCompleted")
            date_str = ""
            if pub_date is not None:
                y = pub_date.find("Year")
                m = pub_date.find("Month")
                d = pub_date.find("Day")
                parts = []
                if y is not None:
                    parts.append(y.text or "")
                if m is not None:
                    parts.append(m.text or "")
                if d is not None:
                    parts.append(d.text or "")
                date_str = "-".join(parts)

            # MeSH terms
            mesh_terms = []
            for mesh in medline.findall(".//MeshHeading/DescriptorName"):
                if mesh.text:
                    mesh_terms.append(mesh.text)

            # Publication types
            pub_types = []
            for pt in article_data.findall(".//PublicationType"):
                if pt.text:
                    pub_types.append(pt.text)

            # PMID
            pmid_elem = medline.find("PMID")
            pmid = pmid_elem.text if pmid_elem is not None else ""

            # DOI from ArticleIdList
            doi = ""
            for aid in article.findall(".//ArticleId"):
                if aid.get("IdType") == "doi":
                    doi = aid.text or ""

            # Keywords
            keywords = []
            for kw in medline.findall(".//Keyword"):
                if kw.text:
                    keywords.append(kw.text)

            articles.append({
                "pmid": pmid,
                "title": title,
                "abstract": abstract,
                "authors": authors,
                "journal": journal,
                "pub_date": date_str,
                "mesh_terms": mesh_terms,
                "pub_types": pub_types,
                "doi": doi,
                "keywords": keywords,
            })

        return articles
