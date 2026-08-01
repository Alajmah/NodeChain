"""Search adapter fallback resilience tests (v2.67.3).

Tests that the search tool:
1. Uses ALL granted adapters when planner gives no target adapters
2. Continues when some adapters fail
3. Performs zero-results rescue with untried granted adapters
4. Never calls ungranted adapters
5. Includes rescue metadata in output
"""

from __future__ import annotations

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from nodechain.core.envelope import InvocationEnvelope, Context, Capabilities
from nodechain.nodes.search_tool import SearchToolNode, _get_adapter
from nodechain.adapters.search.base_search import SearchAdapterResult, SearchAdapterError
from nodechain.adapters.search.failure_types import AdapterFailure, SearchFailureType


def _make_envelope(
    payload: dict,
    allowed_adapters: list[str],
    adapter_grants: list[str] | None = None,
) -> InvocationEnvelope:
    """Build an envelope with capabilities granting specific adapters."""
    return InvocationEnvelope(
        envelope_id="test",
        run_id="test",
        chain_id="test",
        node_id="search_tool",
        step_id=4,
        payload=payload,
        context=Context(chain_state={}),
        capabilities=Capabilities(
            allowed_adapters=allowed_adapters,
            can_call_tools=True,
        ),
    )


def _mock_adapter(name: str, results: list[dict] | None = None):
    """Create a mock adapter that returns given results or raises."""
    adapter = MagicMock()
    if results is not None:
        mock_results = []
        for r in results:
            mock_results.append(SearchAdapterResult(
                origin_api=name,
                raw_data=r,
                query_used="test query",
                retrieved_at="2026-07-01T00:00:00Z",
            ))
        adapter.search = AsyncMock(return_value=mock_results)
    else:
        failure = AdapterFailure(
            failure_type=SearchFailureType.HTTP_ERROR,
            message=f"{name} unavailable",
            adapter=name,
            retryable=True,
            attempts=3,
            status_code=503,
        )
        adapter.search = AsyncMock(side_effect=SearchAdapterError(failure))
    return adapter


class TestSearchFallbackUsesAllGrantedAdapters:
    """When planner gives no target adapters, ALL granted adapters are tried."""

    def test_no_target_adapters_tries_all_granted(self):
        """cap_adapters[:2] bug would only try 2; fix should try all."""
        payload = {
            "search_queries": [],
            "adapter_grants": [],  # No explicit grants
            "research_goal": {"primary_question": "test query"},
        }
        envelope = _make_envelope(
            payload,
            allowed_adapters=["semantic_scholar", "arxiv", "openalex", "crossref", "pubmed"],
        )

        node = SearchToolNode(allow_unguarded=True)

        # Mock all adapters to return results
        with patch("nodechain.nodes.search_tool._get_adapter") as mock_get:
            def fake_get(name):
                return _mock_adapter(name, [{"source_id": f"src-{name}", "title": f"Test {name}", "doi": f"10.1/{name}"}])
            mock_get.side_effect = fake_get

            response = asyncio.run(node.execute(envelope))

        adapters_called = set(response.output["adapters_called"])
        assert len(adapters_called) == 5, f"Expected 5 adapters called, got {adapters_called}"


class TestSearchContinuesOnAdapterFailure:
    """Some adapters failing doesn't prevent others from running."""

    def test_first_two_fail_third_succeeds(self):
        """Even if first adapters fail, remaining adapters still execute."""
        payload = {
            "search_queries": [{
                "terms": ["RAG hallucinations"],
                "target_adapters": ["semantic_scholar", "arxiv", "crossref"],
                "max_results": 5,
                "filters": {},
            }],
            "adapter_grants": ["semantic_scholar", "arxiv", "crossref"],
        }
        envelope = _make_envelope(
            payload,
            allowed_adapters=["semantic_scholar", "arxiv", "crossref"],
        )

        node = SearchToolNode(allow_unguarded=True)

        with patch("nodechain.nodes.search_tool._get_adapter") as mock_get:
            def fake_get(name):
                if name in ("semantic_scholar", "arxiv"):
                    return _mock_adapter(name, None)  # Fails
                return _mock_adapter(name, [{"source_id": f"src-{name}", "title": f"Test {name}", "doi": f"10.1/{name}"}])
            mock_get.side_effect = fake_get

            response = asyncio.run(node.execute(envelope))

        assert response.output["total_found"] > 0, "Should have results from crossref"
        assert "crossref" in response.output["adapters_called"]
        assert len(response.output["adapters_failed"]) == 2


class TestZeroResultsRescue:
    """When all explicit adapters return zero, rescue tries untried granted adapters."""

    def test_explicit_targets_fail_rescue_tries_others(self):
        payload = {
            "search_queries": [{
                "terms": ["RAG hallucinations"],
                "target_adapters": ["semantic_scholar", "openalex"],
                "max_results": 5,
                "filters": {},
            }],
            "adapter_grants": ["semantic_scholar", "openalex"],
        }
        envelope = _make_envelope(
            payload,
            allowed_adapters=["semantic_scholar", "openalex", "arxiv", "crossref", "pubmed"],
        )

        node = SearchToolNode(allow_unguarded=True)

        with patch("nodechain.nodes.search_tool._get_adapter") as mock_get:
            def fake_get(name):
                if name in ("semantic_scholar", "openalex"):
                    return _mock_adapter(name, None)  # Fails
                return _mock_adapter(name, [{"source_id": f"src-{name}", "title": f"Rescue {name}", "doi": f"10.2/{name}"}])
            mock_get.side_effect = fake_get

            response = asyncio.run(node.execute(envelope))

        assert response.output["total_found"] > 0, "Rescue should have found results"
        assert len(response.output.get("rescue_attempted", [])) > 0, "Rescue metadata should be present"
        # Rescue adapters should include arxiv/crossref/pubmed
        rescue = set(response.output.get("rescue_attempted", []))
        assert rescue & {"arxiv", "crossref", "pubmed"}, f"Rescue should include untried adapters, got {rescue}"


class TestUngrantedAdaptersNeverCalled:
    """Adapters not in allowed_adapters are never called, even during rescue."""

    def test_ungranted_not_called_during_rescue(self):
        payload = {
            "search_queries": [{
                "terms": ["RAG hallucinations"],
                "target_adapters": ["semantic_scholar"],
                "max_results": 5,
                "filters": {},
            }],
            "adapter_grants": ["semantic_scholar"],
        }
        # Only grant semantic_scholar and arxiv
        envelope = _make_envelope(
            payload,
            allowed_adapters=["semantic_scholar", "arxiv"],
        )

        node = SearchToolNode(allow_unguarded=True)

        called_adapters = set()
        with patch("nodechain.nodes.search_tool._get_adapter") as mock_get:
            def fake_get(name):
                called_adapters.add(name)
                if name == "semantic_scholar":
                    return _mock_adapter(name, None)  # Fails
                return _mock_adapter(name, [{"source_id": f"src-{name}", "title": f"Test {name}", "doi": f"10.3/{name}"}])
            mock_get.side_effect = fake_get

            response = asyncio.run(node.execute(envelope))

        # Only granted adapters should have been called
        assert called_adapters <= {"semantic_scholar", "arxiv"}, f"Ungranted adapters called: {called_adapters - {'semantic_scholar', 'arxiv'}}"


class TestRescueMetadata:
    """Output includes rescue metadata when rescue was performed."""

    def test_output_has_rescue_attempted_key(self):
        payload = {
            "search_queries": [{
                "terms": ["test"],
                "target_adapters": ["semantic_scholar"],
                "max_results": 5,
                "filters": {},
            }],
            "adapter_grants": ["semantic_scholar"],
        }
        envelope = _make_enapter_with_adapters(payload, ["semantic_scholar", "arxiv"])

        node = SearchToolNode(allow_unguarded=True)

        with patch("nodechain.nodes.search_tool._get_adapter") as mock_get:
            def fake_get(name):
                if name == "semantic_scholar":
                    return _mock_adapter(name, None)
                return _mock_adapter(name, [{"source_id": f"src-{name}", "title": f"Test", "doi": f"10.4/{name}"}])
            mock_get.side_effect = fake_get

            response = asyncio.run(node.execute(envelope))

        assert "rescue_attempted" in response.output
        assert len(response.output["rescue_attempted"]) > 0


def _make_enapter_with_adapters(payload, adapters):
    """Helper for TestRescueMetadata."""
    return InvocationEnvelope(
        envelope_id="test",
        run_id="test",
        chain_id="test",
        node_id="search_tool",
        step_id=4,
        payload=payload,
        context=Context(chain_state={}),
        capabilities=Capabilities(allowed_adapters=adapters, can_call_tools=True),
    )
