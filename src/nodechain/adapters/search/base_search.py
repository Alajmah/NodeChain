"""Base search adapter interface for academic API adapters.

v2.57.0: adds shared _fetch() helper with built-in retry/backoff,
circuit breaker integration, and failure taxonomy.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Literal

import httpx
from pydantic import BaseModel

from nodechain.adapters.search.failure_types import (
    AdapterFailure,
    SearchFetchResult,
    SearchFailureType,
    classify_exception,
    classify_http_status,
)
from nodechain.adapters.search.circuit_breaker import CircuitBreaker
from nodechain.core.provenance import (
    CURRENT_PROVENANCE_VERSION,
    ProvenanceError,
    ProvenanceFailureCode,
)

logger = logging.getLogger(__name__)


class SearchQuery(BaseModel):
    """Normalized search query passed to all adapters."""

    terms: list[str]
    max_results: int = 10
    filters: dict[str, Any] = {}


class SearchAdapterResult(BaseModel):
    """Normalized result from a single search adapter.

    provenance_version is stamped centrally by BaseSearchAdapter.search()
    and must never be set by individual adapters.
    """

    origin_api: str
    raw_data: dict[str, Any]
    query_used: str
    retrieved_at: str
    adapter_latency_ms: int = 0
    provenance_version: int | None = None  # stamped by search(), not by adapters


class BaseSearchAdapter(ABC):
    """
    Abstract base for all academic search adapters.
    Each adapter translates SearchQuery → API call → normalized raw results.

    v2.57.0: all HTTP calls go through _fetch() which provides retry/backoff,
    failure classification, and circuit breaker integration.

    v3.5.0: adapter_version + adapter_id for retry-authorized execution
    (INV-019). Adapters declare a semantic version for semver range matching
    in the recovery allowlist.
    """

    adapter_name: str = "base"
    adapter_version: str = "1.0.0"  # v3.5.0: semver for retry attestation
    base_url: str = ""

    def __init__(
        self,
        rate_limit_per_sec: float = 1.0,
        max_retries: int = 3,
        timeout_seconds: float = 30.0,
        backoff_min: float = 1.0,
        backoff_max: float = 10.0,
        circuit_failure_threshold: int = 5,
        circuit_cooldown_seconds: float = 60.0,
    ) -> None:
        self._rate_limit = rate_limit_per_sec
        self._last_request_time: float = 0.0
        self._max_retries = max_retries
        self._timeout_seconds = timeout_seconds
        self._backoff_min = backoff_min
        self._backoff_max = backoff_max
        self._circuit = CircuitBreaker(
            adapter_name=self.adapter_name,
            failure_threshold=circuit_failure_threshold,
            cooldown_seconds=circuit_cooldown_seconds,
        )

    @abstractmethod
    def build_url(self, query: SearchQuery) -> str:
        """Build the request URL for this adapter's API."""
        ...

    @abstractmethod
    def build_params(self, query: SearchQuery) -> dict[str, Any]:
        """Build query parameters for this adapter's API."""
        ...

    @abstractmethod
    def normalize_response(
        self, raw: dict[str, Any], query: SearchQuery
    ) -> list[SearchAdapterResult]:
        """Normalize raw API response into SearchAdapterResult list."""
        ...

    # ── Shared fetch helper (v2.57.0) ───────────────────────────────

    async def _fetch(
        self,
        url: str,
        params: dict[str, Any] | None = None,
        *,
        headers: dict[str, str] | None = None,
        response_format: Literal["json", "text"] = "json",
        query_hash: str = "",
    ) -> SearchFetchResult:
        """Shared HTTP fetch with retry, backoff, and circuit breaker.

        All adapter HTTP calls should route through this method to get
        consistent retry behavior and failure classification.

        Args:
            url: Request URL
            params: Query parameters
            headers: Optional request headers (e.g. CrossRef User-Agent)
            response_format: "json" for most adapters, "text" for arXiv XML
            query_hash: Stable hash of the query for failure provenance

        Returns:
            SearchFetchResult with data/text on success or failure on error.
        """
        # Circuit breaker check
        if not self._circuit.allow_request():
            return SearchFetchResult(
                failure=AdapterFailure(
                    adapter=self.adapter_name,
                    failure_type=SearchFailureType.CIRCUIT_OPEN,
                    query_hash=query_hash,
                    message=f"Circuit breaker open for {self.adapter_name}",
                ),
            )

        last_failure: AdapterFailure | None = None
        total_attempts = 0

        for attempt in range(1, self._max_retries + 1):
            total_attempts = attempt
            start = time.time()

            try:
                async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
                    response = await client.get(url, params=params, headers=headers)

                elapsed_ms = int((time.time() - start) * 1000)

                # Check HTTP status
                status_failure_type = classify_http_status(response.status_code)
                if status_failure_type is not None:
                    # HTTP error — check if retryable
                    ft = status_failure_type
                    failure = AdapterFailure(
                        adapter=self.adapter_name,
                        failure_type=ft,
                        attempts=attempt,
                        status_code=response.status_code,
                        latency_ms=elapsed_ms,
                        query_hash=query_hash,
                        message=f"HTTP {response.status_code}",
                    )
                    last_failure = failure

                    # Only 429 and 5xx are retryable; 4xx (except 429) are deterministic
                    is_retryable = (
                        ft == SearchFailureType.RATE_LIMIT
                        or (ft == SearchFailureType.HTTP_ERROR and response.status_code >= 500)
                    )
                    if not is_retryable:
                        # Non-retryable HTTP error (4xx except 429)
                        self._circuit.record_failure(ft)
                        return SearchFetchResult(failure=failure, latency_ms=elapsed_ms, attempts=attempt)

                    # Retryable — fall through to backoff
                    logger.warning(
                        "Adapter %s attempt %d: HTTP %d (retryable)",
                        self.adapter_name, attempt, response.status_code,
                    )
                else:
                    # Success — parse response
                    if response_format == "json":
                        try:
                            data = response.json()
                        except Exception as e:
                            elapsed_ms = int((time.time() - start) * 1000)
                            failure = AdapterFailure(
                                adapter=self.adapter_name,
                                failure_type=SearchFailureType.MALFORMED_PAYLOAD,
                                attempts=attempt,
                                latency_ms=elapsed_ms,
                                query_hash=query_hash,
                                message=f"JSON parse error: {e}",
                                exception_class=type(e).__name__,
                            )
                            # Malformed payload is non-retryable — don't record
                            # as circuit success (it's not a successful fetch)
                            # and don't trip the breaker (server responded OK)
                            return SearchFetchResult(failure=failure, latency_ms=elapsed_ms, attempts=attempt)
                    else:
                        data = {"xml_content": response.text, "text_content": response.text}

                    elapsed_ms = int((time.time() - start) * 1000)
                    self._circuit.record_success()
                    return SearchFetchResult(
                        data=data if response_format == "json" else None,
                        text=response.text if response_format == "text" else None,
                        latency_ms=elapsed_ms,
                        attempts=attempt,
                    )

            except httpx.TimeoutException as e:
                elapsed_ms = int((time.time() - start) * 1000)
                last_failure = AdapterFailure(
                    adapter=self.adapter_name,
                    failure_type=SearchFailureType.TIMEOUT,
                    attempts=attempt,
                    latency_ms=elapsed_ms,
                    query_hash=query_hash,
                    message=f"Request timed out after {self._timeout_seconds}s",
                    exception_class=type(e).__name__,
                )
                logger.warning("Adapter %s attempt %d: timeout", self.adapter_name, attempt)

            except (httpx.ConnectError, httpx.ReadError, httpx.NetworkError) as e:
                elapsed_ms = int((time.time() - start) * 1000)
                last_failure = AdapterFailure(
                    adapter=self.adapter_name,
                    failure_type=SearchFailureType.TIMEOUT,
                    attempts=attempt,
                    latency_ms=elapsed_ms,
                    query_hash=query_hash,
                    message=f"Network error: {e}",
                    exception_class=type(e).__name__,
                )
                logger.warning("Adapter %s attempt %d: network error: %s", self.adapter_name, attempt, e)

            except Exception as e:
                elapsed_ms = int((time.time() - start) * 1000)
                ft = classify_exception(e, self.adapter_name)
                last_failure = AdapterFailure(
                    adapter=self.adapter_name,
                    failure_type=ft,
                    attempts=attempt,
                    latency_ms=elapsed_ms,
                    query_hash=query_hash,
                    message=str(e),
                    exception_class=type(e).__name__,
                )
                # Non-retryable — stop immediately
                if ft not in (
                    SearchFailureType.TIMEOUT,
                    SearchFailureType.RATE_LIMIT,
                    SearchFailureType.HTTP_ERROR,
                ):
                    self._circuit.record_failure(ft)
                    return SearchFetchResult(failure=last_failure, latency_ms=elapsed_ms, attempts=attempt)
                logger.warning("Adapter %s attempt %d: %s: %s", self.adapter_name, attempt, ft.value, e)

            # Backoff before retry (with jitter)
            if attempt < self._max_retries:
                import random
                backoff = min(
                    self._backoff_min * (2 ** (attempt - 1)),
                    self._backoff_max,
                )
                backoff += random.uniform(0, backoff * 0.1)  # jitter
                await asyncio.sleep(backoff)

        # All retries exhausted
        if last_failure:
            self._circuit.record_failure(last_failure.failure_type)
        return SearchFetchResult(
            failure=last_failure,
            latency_ms=last_failure.latency_ms if last_failure else 0,
            attempts=total_attempts,
        )

    def _compute_query_hash(self, query: SearchQuery) -> str:
        """Compute a stable hash of the query for failure provenance."""
        payload = json.dumps(
            {"terms": sorted(query.terms), "max": query.max_results, "filters": query.filters},
            sort_keys=True, default=str,
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    @property
    def circuit_state(self) -> dict[str, Any]:
        """Expose circuit breaker state for reporting."""
        return self._circuit.to_dict()

    async def search(self, query: SearchQuery) -> list[SearchAdapterResult]:
        """Execute a search through this adapter using the shared _fetch().

        This is the single authoritative current-version stamping boundary.
        After normalize_response, every result is stamped with
        CURRENT_PROVENANCE_VERSION. Adapters must not set it themselves.
        """
        await self._respect_rate_limit()

        url = self.build_url(query)
        params = self.build_params(query)
        query_hash = self._compute_query_hash(query)

        # Allow adapters to provide headers (e.g. CrossRef User-Agent)
        headers = self._get_headers() if hasattr(self, "_get_headers") else None

        fetch_result = await self._fetch(
            url, params, headers=headers,
            response_format="json", query_hash=query_hash,
        )

        if not fetch_result.succeeded:
            # Raise with structured failure info for SearchToolNode to catch
            failure = fetch_result.failure
            raise SearchAdapterError(failure)

        start = time.time()
        results = self.normalize_response(fetch_result.data or {}, query)
        elapsed_ms = int((time.time() - start) * 1000) + fetch_result.latency_ms

        return self._finalize_results(results, elapsed_ms)

    def _finalize_results(
        self, results: list[SearchAdapterResult], elapsed_ms: int
    ) -> list[SearchAdapterResult]:
        """Shared finalization: stamp latency + provenance version.

        Rejects ANY adapter-supplied provenance version (including 1).
        The version is exclusively set by this central boundary.
        Called by base search(), arXiv search(), and PubMed search().
        """
        for r in results:
            r.adapter_latency_ms = elapsed_ms
            # Reject ANY adapter-supplied version, including explicit None
            if "provenance_version" in r.model_fields_set:
                raise ProvenanceError(
                    ProvenanceFailureCode.PROVENANCE_VERSION_CONFLICT,
                    f"adapter {self.adapter_name} supplied provenance_version="
                    f"{r.provenance_version}; version must not be set by adapters",
                )
            # Reject adapter-supplied reserved provenance fields
            if "provenance_entries" in r.raw_data:
                raise ProvenanceError(
                    ProvenanceFailureCode.PROVENANCE_VERSION_CONFLICT,
                    f"adapter {self.adapter_name} supplied reserved "
                    f"raw_data.provenance_entries",
                )
            if "_dedup_origins" in r.raw_data:
                raise ProvenanceError(
                    ProvenanceFailureCode.PROVENANCE_VERSION_CONFLICT,
                    f"adapter {self.adapter_name} supplied reserved "
                    f"raw_data._dedup_origins",
                )
            # Central authoritative stamping
            r.provenance_version = CURRENT_PROVENANCE_VERSION

        return results

    async def _respect_rate_limit(self) -> None:
        """Enforce rate limit between requests (async-safe)."""
        now = time.time()
        min_interval = 1.0 / self._rate_limit
        elapsed = now - self._last_request_time
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        self._last_request_time = time.time()


class SearchAdapterError(Exception):
    """Exception carrying structured failure info from the adapter layer."""

    def __init__(self, failure: AdapterFailure) -> None:
        self.failure = failure
        super().__init__(failure.message)
