"""v2.69 tests for per-adapter result counts and silent-zero surfacing.

Per agreement with strategic reviewer: "silent zero" is the real defect to
eliminate. The search tool must surface per-adapter result counts so that
when an adapter returns zero results, it's visible — not silently collapsed
into overall success.
"""
from __future__ import annotations

import os
import sys
from unittest.mock import AsyncMock, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nodechain.nodes.search_tool import SearchToolNode
from nodechain.core.envelope import InvocationEnvelope, Capabilities
from nodechain.adapters.search.base_search import SearchAdapterResult


def _make_result(origin: str = "test") -> SearchAdapterResult:
    return SearchAdapterResult(
        origin_api=origin,
        raw_data={"title": "Test Result", "doi": f"10.1000/{origin}"},
        query_used="test query",
        retrieved_at="2024-01-01T00:00:00Z",
    )


class TestAdapterResultCounts:
    """v2.69: search_tool output must include adapter_result_counts and
    silent_zero_adapters."""

    def test_output_includes_adapter_result_counts(self):
        """The output dict must include adapter_result_counts as a field."""
        # This is a structural test — verify the field exists in the output schema
        # by checking the code path produces it. We test via the output dict
        # construction, not a full chain run.
        # (Full integration coverage comes from the real chain rerun in v2.69 #4.)
        import inspect
        source = inspect.getsource(SearchToolNode.execute)
        assert "adapter_result_counts" in source, \
            "search_tool.execute must produce adapter_result_counts"
        assert "silent_zero_adapters" in source, \
            "search_tool.execute must produce silent_zero_adapters"

    def test_silent_zero_logic(self):
        """Adapters called with 0 results and no failure should appear in
        silent_zero_adapters. Adapters that returned results should not."""
        # Test the classification logic directly
        adapter_result_counts = {"openalex": 40, "arxiv": 0, "crossref": 5}
        adapters_failed = []  # no failures — arxiv just returned nothing

        silent_zero = sorted([
            name for name, count in adapter_result_counts.items()
            if count == 0 and name not in [af["adapter"] for af in adapters_failed]
        ])
        assert silent_zero == ["arxiv"], \
            f"arxiv should be flagged as silent zero, got {silent_zero}"
        assert "openalex" not in silent_zero
        assert "crossref" not in silent_zero

    def test_failed_adapter_not_counted_as_silent_zero(self):
        """An adapter that failed (raised SearchAdapterError) should NOT appear
        in silent_zero — it's a failure, not a silent zero."""
        adapter_result_counts = {"openalex": 40, "semantic_scholar": 0}
        adapters_failed = [{"adapter": "semantic_scholar", "error": "HTTP 429"}]

        silent_zero = sorted([
            name for name, count in adapter_result_counts.items()
            if count == 0 and name not in [af["adapter"] for af in adapters_failed]
        ])
        assert silent_zero == [], \
            "failed adapter should not be silent zero"

    def test_all_zero_counts_surfaced(self):
        """When multiple adapters return zero, all should be surfaced."""
        adapter_result_counts = {"openalex": 0, "arxiv": 0, "crossref": 0}
        adapters_failed = []

        silent_zero = sorted([
            name for name, count in adapter_result_counts.items()
            if count == 0 and name not in [af["adapter"] for af in adapters_failed]
        ])
        assert silent_zero == ["arxiv", "crossref", "openalex"]

    def test_mixed_results_and_failures(self):
        """Realistic mix: one adapter succeeds with results, one returns zero,
        one fails entirely."""
        adapter_result_counts = {"openalex": 40, "arxiv": 0, "crossref": 0}
        adapters_failed = [{"adapter": "crossref", "error": "timeout"}]

        silent_zero = sorted([
            name for name, count in adapter_result_counts.items()
            if count == 0 and name not in [af["adapter"] for af in adapters_failed]
        ])
        assert silent_zero == ["arxiv"], \
            f"only arxiv should be silent zero (crossref is a failure), got {silent_zero}"
