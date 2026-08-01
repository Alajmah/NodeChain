"""CrossRef API adapter — DOI metadata retrieval and publisher info."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from nodechain.adapters.search.base_search import (
    BaseSearchAdapter,
    SearchAdapterResult,
    SearchQuery,
)


class CrossRefAdapter(BaseSearchAdapter):
    """
    CrossRef API adapter.
    DOI-based metadata, publisher info, journal impact, license type.
    Polite pool with User-Agent and email header.
    """

    adapter_name = "crossref"
    adapter_version = "1.0.0"  # v3.5.0
    base_url = "https://api.crossref.org/works"

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
        email = os.environ.get("CROSSREF_EMAIL", "")
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

    def build_url(self, query: SearchQuery) -> str:
        return self.base_url

    def build_params(self, query: SearchQuery) -> dict[str, Any]:
        params: dict[str, Any] = {
            "query": " ".join(query.terms),
            "rows": min(query.max_results, 50),
            "sort": "relevance",
        }

        # Year filter
        if "year_from" in query.filters:
            params["filter"] = (
                f"from-pub-date:{query.filters['year_from']}"
            )
            if "year_to" in query.filters:
                params["filter"] += f",until-pub-date:{query.filters['year_to']}"

        return params

    def _get_headers(self) -> dict[str, str]:
        headers = {
            "User-Agent": "NodeChain/0.1.0 (https://github.com/Alajmah/NodeChain)",
        }
        if self._email:
            headers["User-Agent"] += f" mailto:{self._email}"
        return headers

    def normalize_response(
        self, raw: dict[str, Any], query: SearchQuery
    ) -> list[SearchAdapterResult]:
        items = raw.get("message", {}).get("items", [])
        results: list[SearchAdapterResult] = []
        now = datetime.now(timezone.utc).isoformat()

        for item in items:
            # Extract authors
            authors = []
            for author in item.get("author", []):
                given = author.get("given", "")
                family = author.get("family", "")
                authors.append(f"{given} {family}".strip())

            # Extract title
            titles = item.get("title", [])
            title = titles[0] if titles else ""

            if not title:
                continue

            # Extract DOI
            doi = item.get("DOI", "")

            # Determine source type
            source_type = item.get("type", "journal-article")
            type_map = {
                "journal-article": "journal_article",
                "proceedings-article": "conference",
                "book-chapter": "book",
                "preprint": "preprint",
                "review": "review",
                "dissertation": "thesis",
            }

            # Extract publisher and journal
            container_titles = item.get("container-title", [])
            venue = container_titles[0] if container_titles else ""
            publisher = item.get("publisher", "")

            # Extract license info
            licenses = item.get("license", [])
            license_types = [lic.get("content-version", "") for lic in licenses]

            # Check for retraction
            assertions = item.get("assertion", [])
            is_retracted = any(
                a.get("name") == "retraction" for a in assertions
            )
            # Also check update policy
            update_policy = item.get("update-policy", "")
            if "retraction" in update_policy.lower():
                is_retracted = True

            # Extract ISSN for journal identification
            issns = item.get("ISSN", [])

            normalized = {
                "doi": doi,
                "title": title,
                "authors": authors,
                "publisher": publisher,
                "venue": venue,
                "issns": issns,
                "publication_date": item.get("published", {}).get("date-parts", [[]])[0],
                "source_type": type_map.get(source_type, "other"),
                "is_referenced_by_count": item.get("is-referenced-by-count", 0),
                "references_count": item.get("references-count", 0),
                "license_types": license_types,
                "is_retracted": is_retracted,
                "abstract": item.get("abstract", ""),
                "subject": item.get("subject", []),
                "url": item.get("URL", ""),
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
