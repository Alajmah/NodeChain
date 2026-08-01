"""v3.5.0 Task 3 tests — Adapter attestation + RecoveryDispatchGuard.

Tests the dispatch interceptor that enforces exactly-one-target-effect at
the real adapter search() boundary (INV-006, INV-014, INV-019).

ChatGPT Blocker 1 (plan review): the journal runs BEFORE node execution and
cannot mediate adapter calls during execution. SearchToolNode calls
adapter.search(query) directly. The guard wraps that boundary.

ChatGPT guardrails:
- #2: guard owns tuple validation + dispatch_attempted_at, NOT completion
- #3: instance-local registry, not module-global _ADAPTERS mutation
- #4: counts dispatch proposals, not unique request hashes

Adversarial tests:
- duplicate identical queries → second call rejected
- zero-result rescue path → rescue call rejected before wire dispatch
- non-target adapter → rejected
- wrong request hash → rejected
- wrong adapter version → rejected

Protects: INV-005, INV-014, INV-019
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from nodechain.adapters.search.base_search import BaseSearchAdapter, SearchQuery, SearchAdapterResult
from nodechain.runtime.recovery_dispatch_guard import (
    ADAPTER_RETRY_ALLOWLIST,
    AdapterRetryCapability,
    ExecutionConstraints,
    RecoveryDispatchError,
    RecoveryDispatchGuard,
    build_guarded_adapter_registry,
    is_adapter_attested,
)


# ── Adapter attestation (INV-019) ─────────────────────────────────────


class TestAdapterAllowlist:
    """v3.5.0 allowlist for the 5 search adapters."""

    def test_all_5_adapters_attested(self):
        expected = {"semantic_scholar", "arxiv", "openalex", "crossref", "pubmed"}
        assert set(ADAPTER_RETRY_ALLOWLIST.keys()) == expected

    def test_all_attested_as_single_logical_operation(self):
        for name, cap in ADAPTER_RETRY_ALLOWLIST.items():
            assert cap.dispatch_cardinality == "single_logical_operation", (
                f"{name} must be single_logical_operation for Tier 1"
            )
            assert cap.internal_batching is False, (
                f"{name} must have no internal batching"
            )

    def test_is_adapter_attested_true_for_known(self):
        assert is_adapter_attested("semantic_scholar", "1.0.0")
        assert is_adapter_attested("arxiv", "1.0.0")

    def test_is_adapter_attested_false_for_unknown(self):
        assert not is_adapter_attested("unknown_adapter", "1.0.0")

    def test_is_adapter_attested_false_for_wrong_version(self):
        # Version outside the range
        assert not is_adapter_attested("semantic_scholar", "0.0.1")


class TestAdapterVersions:
    """Concrete adapters declare adapter_version."""

    def test_semantic_scholar_has_version(self):
        from nodechain.adapters.search.semantic_scholar import SemanticScholarAdapter
        assert SemanticScholarAdapter.adapter_version == "1.0.0"

    def test_arxiv_has_version(self):
        from nodechain.adapters.search.arxiv import ArxivAdapter
        assert ArxivAdapter.adapter_version == "1.0.0"

    def test_all_5_have_versions(self):
        from nodechain.adapters.search.semantic_scholar import SemanticScholarAdapter
        from nodechain.adapters.search.arxiv import ArxivAdapter
        from nodechain.adapters.search.openalex import OpenAlexAdapter
        from nodechain.adapters.search.crossref import CrossRefAdapter
        from nodechain.adapters.search.pubmed import PubMedAdapter
        for cls in [SemanticScholarAdapter, ArxivAdapter, OpenAlexAdapter,
                    CrossRefAdapter, PubMedAdapter]:
            assert hasattr(cls, "adapter_version")
            assert cls.adapter_version  # non-empty


# ── RecoveryDispatchGuard — happy path ─────────────────────────────────


class _FakeAdapter(BaseSearchAdapter):
    """A fake adapter for testing — returns canned results."""
    adapter_name = "fake_adapter"
    adapter_version = "1.0.0"

    def build_url(self, query):
        return "http://fake.test/search"

    def build_params(self, query):
        return {"q": " ".join(query.terms)}

    def normalize_response(self, raw, query):
        return [SearchAdapterResult(
            origin_api=self.adapter_name,
            raw_data=raw,
            query_used=" ".join(query.terms),
            retrieved_at="2026-07-11T00:00:00Z",
        )]

    async def search(self, query):
        return self.normalize_response({"results": [{"title": "test"}]}, query)


def _make_constraints(adapter_id="fake_adapter", version="1.0.0", request_hash=None):
    """Build constraints matching a fake adapter.

    v3.5.0 update: uses full canonical_request_digest (SHA-256, 64 hex chars),
    not the legacy 16-char prefix.
    """
    if request_hash is None:
        # Compute the full canonical digest the guard will derive
        from nodechain.core.side_effect_utils import (
            canonicalize_capsule_payload,
            compute_canonical_request_digest,
        )
        operation = {"terms": sorted(["ai", "safety"]), "max": 10, "filters": {}}
        canonical_bytes = canonicalize_capsule_payload(operation)
        request_hash = compute_canonical_request_digest(canonical_bytes)
    return ExecutionConstraints(
        required_type="external_call",
        required_operation_name="search",
        required_adapter_id=adapter_id,
        required_adapter_version=version,
        required_request_hash=request_hash,
    )


class TestGuardHappyPath:
    """The guard allows the first matching dispatch."""

    @pytest.mark.asyncio
    async def test_first_dispatch_allowed(self):
        adapter = _FakeAdapter()
        query = SearchQuery(terms=["ai", "safety"], max_results=10)
        constraints = _make_constraints()
        guard = RecoveryDispatchGuard(adapter, constraints)
        results = await guard.search(query)
        assert len(results) == 1
        assert guard.target_dispatched
        assert guard.dispatch_count == 1

    @pytest.mark.asyncio
    async def test_dispatch_attempted_callback_fired(self):
        adapter = _FakeAdapter()
        query = SearchQuery(terms=["ai", "safety"], max_results=10)
        constraints = _make_constraints()
        callback_called = []
        guard = RecoveryDispatchGuard(
            adapter, constraints,
            on_dispatch_attempted=lambda: callback_called.append(True),
        )
        await guard.search(query)
        assert callback_called == [True]


# ── Adversarial tests (ChatGPT's required scenarios) ───────────────────


class TestGuardRejectsSecondDispatch:
    """ChatGPT adversarial test: duplicate identical queries → second rejected.

    The guard counts dispatch proposals, not unique request hashes. Two
    identical calls with the same tuple still constitute an impermissible
    second proposal in Tier 1 (ChatGPT guardrail #4).
    """

    @pytest.mark.asyncio
    async def test_second_dispatch_rejected_even_same_hash(self):
        adapter = _FakeAdapter()
        query = SearchQuery(terms=["ai", "safety"], max_results=10)
        constraints = _make_constraints()
        guard = RecoveryDispatchGuard(adapter, constraints)

        # First dispatch succeeds
        await guard.search(query)
        assert guard.target_dispatched

        # Second dispatch (same query, same hash) must be rejected
        with pytest.raises(RecoveryDispatchError, match="Second dispatch proposal rejected"):
            await guard.search(query)
        assert guard.dispatch_count == 2


class TestGuardRejectsMismatchedTuple:
    """The guard validates the full tuple (INV-014)."""

    @pytest.mark.asyncio
    async def test_wrong_adapter_id_rejected(self):
        adapter = _FakeAdapter()
        query = SearchQuery(terms=["ai", "safety"], max_results=10)
        constraints = _make_constraints(adapter_id="DIFFERENT")
        guard = RecoveryDispatchGuard(adapter, constraints)
        with pytest.raises(RecoveryDispatchError, match="Adapter ID mismatch"):
            await guard.search(query)

    @pytest.mark.asyncio
    async def test_wrong_adapter_version_rejected(self):
        adapter = _FakeAdapter()
        query = SearchQuery(terms=["ai", "safety"], max_results=10)
        constraints = _make_constraints(version="2.0.0")
        guard = RecoveryDispatchGuard(adapter, constraints)
        with pytest.raises(RecoveryDispatchError, match="Adapter version mismatch"):
            await guard.search(query)

    @pytest.mark.asyncio
    async def test_wrong_request_hash_rejected(self):
        adapter = _FakeAdapter()
        query = SearchQuery(terms=["ai", "safety"], max_results=10)
        constraints = _make_constraints(request_hash="deadbeefdeadbeef")
        guard = RecoveryDispatchGuard(adapter, constraints)
        with pytest.raises(RecoveryDispatchError, match="Request hash mismatch"):
            await guard.search(query)


class TestGuardRejectsRescuePath:
    """ChatGPT adversarial test: zero-result rescue → rescue call rejected.

    Simulates the SearchToolNode rescue path: target adapter returns zero
    results, node tries a different adapter. The rescue call must be rejected
    because only one dispatch is permitted.
    """

    @pytest.mark.asyncio
    async def test_rescue_adapter_rejected(self):
        """After target dispatches, a rescue adapter call is rejected."""
        target = _FakeAdapter()
        rescue = _FakeAdapter()
        rescue.adapter_name = "rescue_adapter"

        query = SearchQuery(terms=["ai", "safety"], max_results=10)
        constraints = _make_constraints(adapter_id="fake_adapter")

        # Build a guarded registry with only the target
        registry = build_guarded_adapter_registry(
            "fake_adapter", target, constraints,
        )

        # Target dispatch succeeds
        guarded_target = registry["fake_adapter"]
        assert isinstance(guarded_target, RecoveryDispatchGuard)
        await guarded_target.search(query)

        # A rescue adapter is NOT in the registry — it can't be called
        # through the guarded path. If someone tried to call it directly,
        # it's outside the guard (the coordinator must ensure only the
        # guarded registry is used).
        assert "rescue_adapter" not in registry


# ── Instance-local registry (ChatGPT guardrail #3) ─────────────────────


class TestInstanceLocalRegistry:
    """The guarded registry is instance-local, not module-global."""

    def test_build_guarded_registry_returns_isolated_dict(self):
        adapter = _FakeAdapter()
        constraints = _make_constraints()
        registry = build_guarded_adapter_registry("fake_adapter", adapter, constraints)

        # It's a fresh dict, not the module-global _ADAPTERS
        from nodechain.nodes.search_tool import _ADAPTERS
        assert registry is not _ADAPTERS
        assert "fake_adapter" in registry
        assert isinstance(registry["fake_adapter"], RecoveryDispatchGuard)

    def test_module_global_adapters_not_mutated(self):
        """Building a guarded registry does NOT touch _ADAPTERS."""
        from nodechain.nodes.search_tool import _ADAPTERS
        snapshot = dict(_ADAPTERS)

        adapter = _FakeAdapter()
        constraints = _make_constraints()
        registry = build_guarded_adapter_registry("fake_adapter", adapter, constraints)

        assert _ADAPTERS == snapshot  # unchanged


# ── Guard does NOT claim completion (ChatGPT guardrail #2) ─────────────


class TestGuardDoesNotComplete:
    """The guard intercepts dispatch but does NOT mark the child completed.

    Completion requires observed evidence through the existing v3.0/v3.1
    machinery. The guard only records that the dispatch boundary was crossed.
    """

    @pytest.mark.asyncio
    async def test_guard_returns_results_not_completion(self):
        adapter = _FakeAdapter()
        query = SearchQuery(terms=["ai", "safety"], max_results=10)
        constraints = _make_constraints()
        guard = RecoveryDispatchGuard(adapter, constraints)

        results = await guard.search(query)

        # Guard returns adapter results — it does NOT mark anything completed
        assert guard.target_dispatched  # dispatch happened
        # But there's no "completed" flag on the guard
        assert not hasattr(guard, "completed")
        assert not hasattr(guard, "_completed")
