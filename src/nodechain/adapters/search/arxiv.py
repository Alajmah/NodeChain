"""arXiv API adapter — preprints for math, physics, CS, etc."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode

from nodechain.adapters.search.base_search import (
    BaseSearchAdapter,
    SearchAdapterResult,
    SearchQuery,
)


class ArxivAdapter(BaseSearchAdapter):
    """
    arXiv API adapter.
    Returns preprints with LaTeX abstracts, subject classifications.
    Rate limit: 3 req/sec recommended, no key required.
    """

    adapter_name = "arxiv"
    adapter_version = "1.0.0"  # v3.5.0
    base_url = "https://export.arxiv.org/api/query"

    # arXiv subject category mapping
    CATEGORY_MAP = {
        "computer_science": "cs.*",
        "mathematics": "math.*",
        "physics": "physics.*",
        "engineering": "eess.*",
        "biology": "q-bio.*",
        "economics": "econ.*",
        "statistics": "stat.*",
    }

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
        super().__init__(
            rate_limit_per_sec=3.0,
            max_retries=max_retries,
            timeout_seconds=timeout_seconds,
            backoff_min=backoff_min,
            backoff_max=backoff_max,
            circuit_failure_threshold=circuit_failure_threshold,
            circuit_cooldown_seconds=circuit_cooldown_seconds,
        )

    def build_url(self, query: SearchQuery) -> str:
        return self.base_url

    def build_params(self, query: SearchQuery) -> dict[str, Any]:
        search_query = " AND ".join(f"all:{term}" for term in query.terms[:3])

        # Add category filter if specified
        if "category" in query.filters:
            cat = query.filters["category"]
            search_query += f" AND cat:{cat}"

        return {
            "search_query": search_query,
            "start": 0,
            "max_results": min(query.max_results, 50),
            "sortBy": "relevance",
            "sortOrder": "descending",
        }

    def normalize_response(
        self, raw: dict[str, Any], query: SearchQuery
    ) -> list[SearchAdapterResult]:
        """Parse arXiv Atom XML response."""
        xml_content = raw.get("xml_content", "")
        if not xml_content:
            return []

        results: list[SearchAdapterResult] = []
        now = datetime.now(timezone.utc).isoformat()

        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError:
            return []

        ns = {
            "atom": "http://www.w3.org/2005/Atom",
            "arxiv": "http://arxiv.org/schemas/atom",
        }

        for entry in root.findall("atom:entry", ns):
            title = entry.find("atom:title", ns)
            summary = entry.find("atom:summary", ns)
            published = entry.find("atom:published", ns)
            link = entry.find("atom:id", ns)

            if title is None:
                continue

            authors = [
                a.find("atom:name", ns).text or ""
                for a in entry.findall("atom:author", ns)
                if a.find("atom:name", ns) is not None
            ]

            categories = [
                c.get("term", "")
                for c in entry.findall("atom:category", ns)
            ]

            # Extract DOI if available
            doi_elem = entry.find("arxiv:doi", ns)
            doi = doi_elem.text if doi_elem is not None else ""

            normalized = {
                "arxiv_id": (link.text or "").split("/")[-1] if link is not None else "",
                "title": (title.text or "").strip().replace("\n", " "),
                "abstract": (summary.text or "").strip().replace("\n", " ") if summary is not None else "",
                "authors": authors,
                "published": published.text if published is not None else "",
                "pdf_url": f"{link.text or ''}" if link is not None else "",
                "categories": categories,
                "doi": doi,
                "source_type": "preprint",
                "comment": "",
            }

            comment = entry.find("arxiv:comment", ns)
            if comment is not None and comment.text:
                normalized["comment"] = comment.text

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
        """Override to handle XML response via shared _fetch()."""
        await self._respect_rate_limit()

        url = self.build_url(query)
        params = self.build_params(query)
        query_hash = self._compute_query_hash(query)

        fetch_result = await self._fetch(
            url, params,
            response_format="text",
            query_hash=query_hash,
        )

        if not fetch_result.succeeded:
            from nodechain.adapters.search.base_search import SearchAdapterError
            raise SearchAdapterError(fetch_result.failure)

        # arXiv returns XML, pass it through for parsing
        raw = {"xml_content": fetch_result.text}
        results = self.normalize_response(raw, query)

        for r in results:
            r.adapter_latency_ms = fetch_result.latency_ms

        return results
