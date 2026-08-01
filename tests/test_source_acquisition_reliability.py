"""Source Acquisition Reliability tests (v2.67.3).

Tests the failure taxonomy, retry/backoff, circuit breaker, and deduplication
using fake adapters — no real network calls. These are the release-gate tests
for source acquisition reliability.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from nodechain.adapters.search.base_search import (
    BaseSearchAdapter, SearchQuery, SearchAdapterResult, SearchAdapterError,
)
from nodechain.adapters.search.failure_types import (
    AdapterFailure, SearchFailureType, SearchFetchResult,
    classify_exception, classify_http_status,
    RETRYABLE_FAILURE_TYPES, NON_RETRYABLE_FAILURE_TYPES,
)
from nodechain.adapters.search.circuit_breaker import CircuitBreaker
from nodechain.nodes.search_tool import (
    _deduplicate_results, _normalize_doi, _normalize_title, _get_dedup_key,
)


# ── Failure taxonomy ──────────────────────────────────────────────────────

class TestFailureTaxonomy:
    def test_all_failure_types_defined(self):
        expected = {
            "timeout", "rate_limit", "http_error", "schema_drift",
            "empty_result", "malformed_payload", "circuit_open", "unknown",
        }
        actual = {ft.value for ft in SearchFailureType}
        assert actual == expected

    def test_classify_timeout_exception(self):
        exc = httpx.ReadTimeout("timed out")
        ft = classify_exception(exc, "test")
        assert ft == SearchFailureType.TIMEOUT

    def test_classify_connect_error(self):
        exc = httpx.ConnectError("connection refused")
        ft = classify_exception(exc, "test")
        assert ft == SearchFailureType.TIMEOUT

    def test_classify_key_error_as_schema_drift(self):
        exc = KeyError("missing_field")
        ft = classify_exception(exc, "test")
        assert ft == SearchFailureType.SCHEMA_DRIFT

    def test_classify_json_error_as_malformed(self):
        exc = ValueError("Invalid JSON")
        ft = classify_exception(exc, "test")
        assert ft == SearchFailureType.MALFORMED_PAYLOAD

    def test_classify_http_status_429(self):
        assert classify_http_status(429) == SearchFailureType.RATE_LIMIT

    def test_classify_http_status_500(self):
        assert classify_http_status(500) == SearchFailureType.HTTP_ERROR

    def test_classify_http_status_404(self):
        assert classify_http_status(404) == SearchFailureType.HTTP_ERROR

    def test_classify_http_status_200_none(self):
        assert classify_http_status(200) is None

    def test_retryable_types_correct(self):
        assert SearchFailureType.TIMEOUT in RETRYABLE_FAILURE_TYPES
        assert SearchFailureType.RATE_LIMIT in RETRYABLE_FAILURE_TYPES

    def test_non_retryable_types_correct(self):
        assert SearchFailureType.SCHEMA_DRIFT in NON_RETRYABLE_FAILURE_TYPES
        assert SearchFailureType.CIRCUIT_OPEN in NON_RETRYABLE_FAILURE_TYPES

    def test_adapter_failure_derives_retryable(self):
        f = AdapterFailure(
            adapter="test", failure_type=SearchFailureType.TIMEOUT,
        )
        assert f.retryable is True

        f2 = AdapterFailure(
            adapter="test", failure_type=SearchFailureType.SCHEMA_DRIFT,
        )
        assert f2.retryable is False

    def test_adapter_failure_has_timestamp(self):
        f = AdapterFailure(
            adapter="test", failure_type=SearchFailureType.UNKNOWN,
        )
        assert f.timestamp  # non-empty


# ── Circuit breaker ───────────────────────────────────────────────────────

class TestCircuitBreaker:
    def test_starts_closed(self):
        cb = CircuitBreaker("test")
        assert cb.state == "closed"
        assert not cb.is_open
        assert cb.allow_request()

    def test_trips_after_threshold(self):
        cb = CircuitBreaker("test", failure_threshold=3, cooldown_seconds=60)
        cb.record_failure(SearchFailureType.TIMEOUT)
        cb.record_failure(SearchFailureType.TIMEOUT)
        assert cb.state == "closed"  # Not yet
        cb.record_failure(SearchFailureType.TIMEOUT)
        assert cb.state == "open"
        assert cb.is_open
        assert not cb.allow_request()

    def test_non_retryable_doesnt_trip(self):
        cb = CircuitBreaker("test", failure_threshold=2, cooldown_seconds=60)
        cb.record_failure(SearchFailureType.SCHEMA_DRIFT)
        cb.record_failure(SearchFailureType.SCHEMA_DRIFT)
        assert cb.state == "closed"  # Non-retryable doesn't trip

    def test_success_resets(self):
        cb = CircuitBreaker("test", failure_threshold=3, cooldown_seconds=60)
        cb.record_failure(SearchFailureType.TIMEOUT)
        cb.record_failure(SearchFailureType.TIMEOUT)
        cb.record_success()
        assert cb._consecutive_failures == 0
        assert cb.state == "closed"

    def test_half_open_after_cooldown(self):
        cb = CircuitBreaker("test", failure_threshold=1, cooldown_seconds=0.1)
        cb.record_failure(SearchFailureType.TIMEOUT)
        assert cb.state == "open"
        import time
        time.sleep(0.15)
        assert cb.state == "half_open"
        assert cb.allow_request()

    def test_half_open_failure_reopens(self):
        cb = CircuitBreaker("test", failure_threshold=1, cooldown_seconds=0.1)
        cb.record_failure(SearchFailureType.TIMEOUT)
        import time
        time.sleep(0.15)
        assert cb.state == "half_open"
        cb.record_failure(SearchFailureType.TIMEOUT)
        assert cb.state == "open"

    def test_half_open_success_closes(self):
        cb = CircuitBreaker("test", failure_threshold=1, cooldown_seconds=0.1)
        cb.record_failure(SearchFailureType.TIMEOUT)
        import time
        time.sleep(0.15)
        assert cb.state == "half_open"
        cb.record_success()
        assert cb.state == "closed"


# ── Deduplication ─────────────────────────────────────────────────────────

class TestDeduplication:
    def test_dedup_by_doi(self):
        results = [
            {"origin_api": "semantic_scholar", "raw_data": {"doi": "10.1000/test", "title": "A"}},
            {"origin_api": "crossref", "raw_data": {"doi": "10.1000/test", "title": "A duplicate"}},
        ]
        deduped = _deduplicate_results(results)
        assert len(deduped) == 1
        assert len(deduped[0]["raw_data"]["_dedup_origins"]) == 2

    def test_dedup_by_normalized_doi(self):
        results = [
            {"origin_api": "crossref", "raw_data": {"doi": "https://doi.org/10.1000/test"}},
            {"origin_api": "openalex", "raw_data": {"doi": "10.1000/TEST"}},
        ]
        deduped = _deduplicate_results(results)
        assert len(deduped) == 1

    def test_dedup_by_title_fallback(self):
        results = [
            {"origin_api": "arxiv", "raw_data": {"title": "Machine Learning Approaches"}},
            {"origin_api": "semantic_scholar", "raw_data": {"title": "machine learning approaches"}},
        ]
        deduped = _deduplicate_results(results)
        assert len(deduped) == 1

    def test_dedup_by_external_id(self):
        results = [
            {"origin_api": "arxiv", "raw_data": {"arxiv_id": "2401.12345", "title": "X"}},
            {"origin_api": "semantic_scholar", "raw_data": {"arxiv_id": "2401.12345", "title": "X duplicate"}},
        ]
        deduped = _deduplicate_results(results)
        assert len(deduped) == 1

    def test_no_dedup_for_different_results(self):
        results = [
            {"origin_api": "a", "raw_data": {"doi": "10.1000/a", "title": "A"}},
            {"origin_api": "b", "raw_data": {"doi": "10.1000/b", "title": "B"}},
        ]
        deduped = _deduplicate_results(results)
        assert len(deduped) == 2

    def test_no_key_kept_separately(self):
        results = [
            {"origin_api": "a", "raw_data": {}},
            {"origin_api": "b", "raw_data": {}},
        ]
        deduped = _deduplicate_results(results)
        assert len(deduped) == 2

    def test_normalize_doi_strips_prefix(self):
        assert _normalize_doi("https://doi.org/10.1000/test") == "10.1000/test"
        assert _normalize_doi("DOI:10.1000/TEST") == "10.1000/test"

    def test_normalize_title_collapses_whitespace(self):
        assert _normalize_title("  Machine   Learning  ") == "machine learning"


# ── _fetch with retry (using fake HTTP responses) ─────────────────────────

class TestFetchRetry:
    """Test that _fetch retries transient failures and not deterministic ones."""

    def _make_test_adapter(self, **kwargs):
        """Create a minimal concrete adapter for testing _fetch."""
        class TestAdapter(BaseSearchAdapter):
            adapter_name = "test"

            def build_url(self, query): return "http://test/api"
            def build_params(self, query): return {}
            def normalize_response(self, raw, query): return []

        return TestAdapter(
            max_retries=kwargs.get("max_retries", 3),
            timeout_seconds=kwargs.get("timeout_seconds", 5.0),
            backoff_min=kwargs.get("backoff_min", 0.01),  # Fast for tests
            backoff_max=kwargs.get("backoff_max", 0.05),
            circuit_failure_threshold=kwargs.get("circuit_failure_threshold", 10),
            circuit_cooldown_seconds=kwargs.get("circuit_cooldown_seconds", 60),
        )

    @patch("httpx.AsyncClient")
    def test_successful_fetch_returns_data(self, mock_client_cls):
        adapter = self._make_test_adapter()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": "test"}

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value = mock_client

        result = asyncio.run(adapter._fetch("http://test", {}, response_format="json"))
        assert result.succeeded
        assert result.data == {"data": "test"}

    @patch("httpx.AsyncClient")
    def test_retries_on_500_then_succeeds(self, mock_client_cls):
        adapter = self._make_test_adapter(max_retries=3)
        fail_response = MagicMock()
        fail_response.status_code = 500
        success_response = MagicMock()
        success_response.status_code = 200
        success_response.json.return_value = {"ok": True}

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(side_effect=[fail_response, success_response])
        mock_client_cls.return_value = mock_client

        result = asyncio.run(adapter._fetch("http://test", {}, response_format="json"))
        assert result.succeeded
        assert result.attempts == 2

    @patch("httpx.AsyncClient")
    def test_retries_on_timeout_then_succeeds(self, mock_client_cls):
        adapter = self._make_test_adapter(max_retries=3)
        success_response = MagicMock()
        success_response.status_code = 200
        success_response.json.return_value = {"ok": True}

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(side_effect=[
            httpx.ReadTimeout("timeout"),
            success_response,
        ])
        mock_client_cls.return_value = mock_client

        result = asyncio.run(adapter._fetch("http://test", {}, response_format="json"))
        assert result.succeeded
        assert result.attempts == 2

    @patch("httpx.AsyncClient")
    def test_does_not_retry_404(self, mock_client_cls):
        adapter = self._make_test_adapter(max_retries=3)
        fail_response = MagicMock()
        fail_response.status_code = 404

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=fail_response)
        mock_client_cls.return_value = mock_client

        result = asyncio.run(adapter._fetch("http://test", {}, response_format="json"))
        assert not result.succeeded
        assert result.attempts == 1  # No retry
        assert result.failure.failure_type == SearchFailureType.HTTP_ERROR

    @patch("httpx.AsyncClient")
    def test_all_retries_exhausted(self, mock_client_cls):
        adapter = self._make_test_adapter(max_retries=2)
        fail_response = MagicMock()
        fail_response.status_code = 500

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=fail_response)
        mock_client_cls.return_value = mock_client

        result = asyncio.run(adapter._fetch("http://test", {}, response_format="json"))
        assert not result.succeeded
        assert result.attempts == 2
        assert result.failure.failure_type == SearchFailureType.HTTP_ERROR

    @patch("httpx.AsyncClient")
    def test_rate_limit_is_retryable(self, mock_client_cls):
        adapter = self._make_test_adapter(max_retries=3)
        rate_limit_resp = MagicMock()
        rate_limit_resp.status_code = 429
        success_response = MagicMock()
        success_response.status_code = 200
        success_response.json.return_value = {"ok": True}

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(side_effect=[rate_limit_resp, success_response])
        mock_client_cls.return_value = mock_client

        result = asyncio.run(adapter._fetch("http://test", {}, response_format="json"))
        assert result.succeeded
        assert result.attempts == 2

    @patch("httpx.AsyncClient")
    def test_circuit_open_blocks_request(self, mock_client_cls):
        adapter = self._make_test_adapter(circuit_failure_threshold=1)
        # Trip the circuit
        adapter._circuit.record_failure(SearchFailureType.TIMEOUT)
        assert adapter._circuit.is_open

        result = asyncio.run(adapter._fetch("http://test", {}, response_format="json"))
        assert not result.succeeded
        assert result.failure.failure_type == SearchFailureType.CIRCUIT_OPEN

    @patch("httpx.AsyncClient")
    def test_text_format_for_arxiv(self, mock_client_cls):
        adapter = self._make_test_adapter()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<xml>test</xml>"

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value = mock_client

        result = asyncio.run(adapter._fetch("http://test", {}, response_format="text"))
        assert result.succeeded
        assert result.text == "<xml>test</xml>"
