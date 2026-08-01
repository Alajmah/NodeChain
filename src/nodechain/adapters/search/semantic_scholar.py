"""Semantic Scholar API adapter — citation graphs, influence scores."""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from typing import Any

from nodechain.adapters.search.base_search import (
    BaseSearchAdapter,
    SearchAdapterResult,
    SearchQuery,
)


class SemanticScholarAdapter(BaseSearchAdapter):
    """
    Semantic Scholar API adapter.
    Primary source for most domains. Returns citation counts,
    influence scores, and reference graphs.
    Rate limit: 1 req/sec unauthenticated, 10/sec with key.
    """

    adapter_name = "semantic_scholar"
    adapter_version = "1.0.0"  # v3.5.0
    base_url = "https://api.semanticscholar.org/graph/v1/paper/search"

    # Fields we request from the API
    FIELDS = [
        "paperId", "title", "abstract", "authors", "year",
        "citationCount", "referenceCount", "influentialCitationCount",
        "isOpenAccess", "openAccessPdf", "venue", "publicationTypes",
        "journal", "externalIds", "fieldsOfStudy", "publicationDate",
    ]

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
        api_key = os.environ.get("SEMANTIC_SCHOLAR_API_KEY", "")
        rate_limit = 10.0 if api_key else 0.5
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
        return self.base_url

    def build_params(self, query: SearchQuery) -> dict[str, Any]:
        params: dict[str, Any] = {
            "query": " ".join(query.terms[:2]),
            "limit": min(query.max_results, 100),
            "fields": ",".join(self.FIELDS),
        }

        # Apply year filter if specified
        if "year_from" in query.filters:
            params["year"] = f"{query.filters['year_from']}-{query.filters.get('year_to', '')}"

        return params

    def normalize_response(
        self, raw: dict[str, Any], query: SearchQuery
    ) -> list[SearchAdapterResult]:
        papers = raw.get("data", [])
        results: list[SearchAdapterResult] = []
        now = datetime.now(timezone.utc).isoformat()

        for paper in papers:
            if not paper.get("title"):
                continue

            normalized = {
                "paper_id": paper.get("paperId", ""),
                "title": paper.get("title", ""),
                "abstract": paper.get("abstract", ""),
                "authors": [
                    a.get("name", "") for a in paper.get("authors", [])
                ],
                "year": paper.get("year"),
                "publication_date": paper.get("publicationDate"),
                "venue": paper.get("venue", ""),
                "citation_count": paper.get("citationCount", 0),
                "reference_count": paper.get("referenceCount", 0),
                "influential_citation_count": paper.get(
                    "influentialCitationCount", 0
                ),
                "open_access": paper.get("isOpenAccess", False),
                "pdf_url": (
                    paper.get("openAccessPdf", {}).get("url", "")
                    if paper.get("openAccessPdf")
                    else ""
                ),
                "publication_types": paper.get("publicationTypes", []),
                "fields_of_study": paper.get("fieldsOfStudy", []),
                "external_ids": paper.get("externalIds", {}),
                "journal": paper.get("journal", {}),
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
