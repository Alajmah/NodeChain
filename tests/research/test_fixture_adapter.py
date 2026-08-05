"""Fixture adapter unit tests: sealed corpus, zero-network, post-dispatch faults.

These tests prove the adapter's core invariants in isolation (without the
orchestrator or guard):

* zero-network (structural + runtime socket guard)
* deterministic results from a sealed corpus
* corpus immutability (both original-argument and retained-representation)
* corpus digest stability and integrity verification
* only post-dispatch fault modes (fail_before_dispatch is rejected)
* provenance stamping through the central _finalize_results boundary
"""

from __future__ import annotations

import asyncio
import socket
from types import MappingProxyType

import pytest

from nodechain.adapters.search.base_search import (
    ProvenanceError,
    SearchAdapterError,
    SearchQuery,
)
from nodechain.adapters.search.fixture import (
    FixtureCorpusError,
    FixtureSearchAdapter,
)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _run(coro):
    return asyncio.run(coro)


def _simple_corpus() -> dict:
    return {
        "async rust": {
            "results": [
                {
                    "origin_api": "fixture",
                    "raw_data": {"title": "Sealed Paper A"},
                    "query_used": "async rust",
                },
                {
                    "origin_api": "fixture",
                    "raw_data": {"title": "Sealed Paper B"},
                    "query_used": "async rust",
                },
            ]
        }
    }


# --------------------------------------------------------------------------- #
# Zero-network (structural)
# --------------------------------------------------------------------------- #


def test_search_never_calls_build_url_or_build_params_or_normalize() -> None:
    """Structural proof: the sealed search() path bypasses all network-facing
    methods. They must raise if ever called."""
    adapter = FixtureSearchAdapter(_simple_corpus())
    q = SearchQuery(terms=["async", "rust"])
    with pytest.raises(FixtureCorpusError):
        adapter.build_url(q)
    with pytest.raises(FixtureCorpusError):
        adapter.build_params(q)
    with pytest.raises(FixtureCorpusError):
        adapter.normalize_response({}, q)


def test_zero_network_runtime_socket_guard() -> None:
    """Runtime proof: with socket.create_connection guarded, search still
    succeeds because no outbound connection is attempted."""
    orig = socket.create_connection
    socket.create_connection = lambda *a, **kw: (_ for _ in ()).throw(
        RuntimeError("NETWORK ATTEMPT")
    )
    try:
        adapter = FixtureSearchAdapter(_simple_corpus())
        results = _run(adapter.search(SearchQuery(terms=["async", "rust"])))
        assert len(results) == 2
    finally:
        socket.create_connection = orig


def test_base_url_is_empty() -> None:
    """The adapter declares no network endpoint."""
    assert FixtureSearchAdapter.base_url == ""


# --------------------------------------------------------------------------- #
# Determinism
# --------------------------------------------------------------------------- #


def test_deterministic_results() -> None:
    adapter = FixtureSearchAdapter(_simple_corpus())
    q = SearchQuery(terms=["async", "rust"])
    r1 = _run(adapter.search(q))
    r2 = _run(adapter.search(q))
    assert len(r1) == len(r2) == 2
    assert r1[0].raw_data["title"] == r2[0].raw_data["title"]


def test_unknown_query_returns_empty() -> None:
    adapter = FixtureSearchAdapter(_simple_corpus())
    r = _run(adapter.search(SearchQuery(terms=["quantum", "gravity"])))
    assert r == []


def test_max_results_truncation() -> None:
    adapter = FixtureSearchAdapter(_simple_corpus())
    r = _run(adapter.search(SearchQuery(terms=["async", "rust"], max_results=1)))
    assert len(r) == 1


def test_provenance_version_centrally_stamped() -> None:
    """Results are stamped by _finalize_results, not by the adapter."""
    adapter = FixtureSearchAdapter(_simple_corpus())
    r = _run(adapter.search(SearchQuery(terms=["async", "rust"])))
    for item in r:
        assert item.provenance_version is not None
        assert item.provenance_version > 0


# --------------------------------------------------------------------------- #
# Corpus sealing / immutability
# --------------------------------------------------------------------------- #


def test_original_argument_mutation_does_not_leak() -> None:
    """Mutating the dict passed to the constructor after construction does not
    affect the adapter's results."""
    original = _simple_corpus()
    adapter = FixtureSearchAdapter(original)
    original["async rust"]["results"].append({"injected": True})
    original["new_key"] = {"results": []}
    r = _run(adapter.search(SearchQuery(terms=["async", "rust"])))
    assert len(r) == 2  # original count, mutation did not leak


def test_retained_representation_is_immutable() -> None:
    """The adapter's retained corpus has no mutable surface."""
    adapter = FixtureSearchAdapter(_simple_corpus())
    # Top-level corpus is MappingProxyType.
    assert isinstance(adapter._corpus, MappingProxyType)
    with pytest.raises(TypeError):
        adapter._corpus["new"] = ()
    # Inner entry is MappingProxyType.
    inner = adapter._corpus["async rust"]
    assert isinstance(inner, MappingProxyType)
    with pytest.raises(TypeError):
        inner["new_key"] = "x"
    # Results are a tuple (immutable).
    assert isinstance(inner["results"], tuple)


def test_corpus_digest_is_stable_and_order_independent() -> None:
    a1 = FixtureSearchAdapter({"a": {"results": []}, "b": {"results": []}})
    a2 = FixtureSearchAdapter({"b": {"results": []}, "a": {"results": []}})
    assert a1.corpus_digest == a2.corpus_digest
    assert len(a1.corpus_digest) == 64  # SHA-256 hex


def test_corpus_size() -> None:
    adapter = FixtureSearchAdapter({"a": {"results": []}, "b": {"results": []}})
    assert adapter.corpus_size == 2


# --------------------------------------------------------------------------- #
# Fault modes (post-dispatch only)
# --------------------------------------------------------------------------- #


def test_fail_before_dispatch_is_rejected() -> None:
    """fail_before_dispatch is not a valid adapter fault — it belongs in the
    runner's lane-admission layer."""
    adapter = FixtureSearchAdapter({"x": {"_fault": "fail_before_dispatch"}})
    with pytest.raises(FixtureCorpusError, match="unknown fault type"):
        _run(adapter.search(SearchQuery(terms=["x"])))


def test_timeout_after_dispatch_fault() -> None:
    adapter = FixtureSearchAdapter({"x": {"_fault": "timeout_after_dispatch"}})
    with pytest.raises(SearchAdapterError) as exc_info:
        _run(adapter.search(SearchQuery(terms=["x"])))
    assert exc_info.value.failure.failure_type.value == "timeout"


def test_malformed_provenance_fault() -> None:
    adapter = FixtureSearchAdapter(
        {"x": {"_fault": "malformed_provenance",
                "results": [{"origin_api": "fixture", "raw_data": {}}]}}
    )
    with pytest.raises(ProvenanceError):
        _run(adapter.search(SearchQuery(terms=["x"])))


def test_partial_result_set_fault() -> None:
    """partial_result_set returns results (explicitly incomplete) rather than
    raising — the node records a partially-successful lane."""
    adapter = FixtureSearchAdapter(
        {"x": {"_fault": "partial_result_set",
                "results": [{"origin_api": "fixture", "raw_data": {"partial": True}}]}}
    )
    r = _run(adapter.search(SearchQuery(terms=["x"])))
    assert len(r) == 1


def test_invocation_count_increments() -> None:
    adapter = FixtureSearchAdapter(_simple_corpus())
    assert adapter.invocation_count == 0
    _run(adapter.search(SearchQuery(terms=["async", "rust"])))
    assert adapter.invocation_count == 1
    _run(adapter.search(SearchQuery(terms=["async", "rust"])))
    assert adapter.invocation_count == 2


def test_corpus_result_must_not_set_provenance_version() -> None:
    """A corpus entry that pre-sets provenance_version is rejected at build
    time (not via the central boundary)."""
    adapter = FixtureSearchAdapter(
        {"x": {"results": [
            {"origin_api": "fixture", "raw_data": {}, "provenance_version": 1}
        ]}}
    )
    with pytest.raises(FixtureCorpusError, match="provenance_version"):
        _run(adapter.search(SearchQuery(terms=["x"])))
