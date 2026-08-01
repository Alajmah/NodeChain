"""OpenAlex API adapter — open scholarly metadata and citation graphs."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from nodechain.adapters.search.base_search import (
    BaseSearchAdapter,
    SearchAdapterResult,
    SearchQuery,
)


class OpenAlexAdapter(BaseSearchAdapter):
    """
    OpenAlex API adapter.
    Broad scholarly metadata, concept tags, institutional affiliations.
    Rate limit: 10 req/sec, polite pool with email header.
    """

    adapter_name = "openalex"
    adapter_version = "1.0.0"  # v3.5.0
    base_url = "https://api.openalex.org/works"

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
        email = os.environ.get("OPENALEX_EMAIL", "")
        api_key = os.environ.get("OPENALEX_API_KEY", "")
        super().__init__(
            rate_limit_per_sec=10.0,
            max_retries=max_retries,
            timeout_seconds=timeout_seconds,
            backoff_min=backoff_min,
            backoff_max=backoff_max,
            circuit_failure_threshold=circuit_failure_threshold,
            circuit_cooldown_seconds=circuit_cooldown_seconds,
        )
        self._email = email
        self._api_key = api_key

    def build_url(self, query: SearchQuery) -> str:
        return self.base_url

    def build_params(self, query: SearchQuery) -> dict[str, Any]:
        params: dict[str, Any] = {
            "search": " ".join(query.terms[:3]),
            "per_page": min(query.max_results, 50),
            "sort": "relevance_score:desc",
        }

        if self._email:
            params["mailto"] = self._email

        # API key for premium pool access (higher rate limits, avoids 503)
        if self._api_key:
            params["api_key"] = self._api_key

        # Year filter
        if "year_from" in query.filters:
            year_from = query.filters["year_from"]
            year_to = query.filters.get("year_to", "")
            params["filter"] = f"publication_year:{year_from}-{year_to}"

        return params

    def normalize_response(
        self, raw: dict[str, Any], query: SearchQuery
    ) -> list[SearchAdapterResult]:
        works = raw.get("results", [])
        results: list[SearchAdapterResult] = []
        now = datetime.now(timezone.utc).isoformat()

        for work in works:
            # Extract author names
            authorships = work.get("authorships", [])
            authors = []
            institutions = []
            for auth in authorships:
                author = auth.get("author", {})
                authors.append(author.get("display_name", ""))
                for inst in auth.get("institutions", []):
                    institutions.append(inst.get("display_name", ""))

            # Extract concepts (topics)
            concepts = work.get("concepts", [])
            concept_scores = {
                c.get("display_name", ""): c.get("score", 0)
                for c in concepts
            }

            # Extract DOI
            doi = work.get("doi", "") or ""
            if doi.startswith("https://doi.org/"):
                doi = doi.replace("https://doi.org/", "")

            # Determine source type
            source_type = work.get("type", "article")
            type_map = {
                "article": "journal_article",
                "preprint": "preprint",
                "conference-paper": "conference",
                "review": "review",
                "book-chapter": "book",
            }

            # Reconstruct abstract from inverted index
            abstract = self._reconstruct_abstract(
                work.get("abstract_inverted_index")
            )

            normalized = {
                "openalex_id": work.get("id", ""),
                "title": work.get("title", ""),
                "abstract": abstract,
                "authors": authors,
                "institutions": institutions,
                "publication_year": work.get("publication_year"),
                "publication_date": work.get("publication_date", ""),
                "doi": doi,
                "source_type": type_map.get(source_type, "other"),
                "cited_by_count": work.get("cited_by_count", 0),
                "venue": ((work.get("primary_location") or {}).get("source") or {}).get("display_name", ""),
                "is_oa": (work.get("open_access") or {}).get("is_oa", False),
                "oa_url": (work.get("open_access") or {}).get("oa_url", ""),
                "concepts": concept_scores,
                "topics": [
                    t.get("display_name", "")
                    for t in work.get("topics", [])
                ],
                "referenced_works_count": len(work.get("referenced_works", [])),
                "language": work.get("language", ""),
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

    @staticmethod
    def _reconstruct_abstract(inverted_index: dict[str, list[int]] | None) -> str:
        """Reconstruct abstract text from OpenAlex inverted index.
        OpenAlex returns: {"word": [position1, position2, ...], ...}
        We sort by position and join.
        """
        if not inverted_index:
            return ""

        # Build position → word mapping
        position_map: dict[int, str] = {}
        for word, positions in inverted_index.items():
            for pos in positions:
                position_map[pos] = word

        if not position_map:
            return ""

        # Sort by position and join
        sorted_words = [
            position_map[i]
            for i in sorted(position_map.keys())
        ]
        return " ".join(sorted_words)
