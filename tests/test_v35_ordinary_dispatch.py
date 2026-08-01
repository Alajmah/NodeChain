"""v3.5.0 Task 3b tests — OrdinaryDispatchGuard: closes the rescue/fallback gap.

ChatGPT T3 STOP: "Every journaled side effect has a capsule" does NOT prove
"Every adapter dispatch has a matching capsule." The ordinary search node can
call adapter.search() directly (rescue path, fallback queries) without a
matching operation-specific capsule.

These tests prove the OrdinaryDispatchGuard closes that gap:

- ordinary zero-result rescue without capsule → blocked
- ordinary generated fallback without capsule → blocked
- ordinary duplicate identical query → second blocked
- ordinary dispatch with valid capsule → allowed
- trusted adapter identity enforced (spoofed adapter rejected)

Protects: INV-004 (capsule-before-wire), ChatGPT T3 gate condition.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any

import pytest

from nodechain.adapters.search.base_search import (
    BaseSearchAdapter, SearchQuery, SearchAdapterResult,
)
from nodechain.runtime.recovery_dispatch_guard import (
    OrdinaryDispatchGuard,
    OrdinaryDispatchError,
    is_trusted_adapter,
    build_ordinary_guarded_registry,
    TRUSTED_ADAPTER_CLASSES,
)
from nodechain.core.side_effect_utils import (
    canonicalize_capsule_payload,
    compute_canonical_request_digest,
)


class _FakeAdapter(BaseSearchAdapter):
    """A fake adapter for testing."""
    adapter_name = "fake_adapter"
    adapter_version = "1.0.0"
    _search_call_count = 0

    def build_url(self, query): return "http://fake.test"
    def build_params(self, query): return {}
    def normalize_response(self, raw, query):
        return [SearchAdapterResult(
            origin_api=self.adapter_name, raw_data=raw,
            query_used=" ".join(query.terms), retrieved_at="2026-07-11T00:00:00Z",
        )]

    async def search(self, query):
        type(self)._search_call_count += 1
        return self.normalize_response({"results": [{"title": "test"}]}, query)


class _SpoofedAdapter(BaseSearchAdapter):
    """Claims to be 'arxiv' but is a different implementation."""
    adapter_name = "arxiv"
    adapter_version = "1.0.0"

    def build_url(self, query): return "http://evil.test"
    def build_params(self, query): return {}
    def normalize_response(self, raw, query): return []

    async def search(self, query): return []


def _make_validator(valid_digests: set[str]) -> Any:
    """Build a capsule validator that returns True for digests in the set."""
    def validator(run_id: str, adapter_name: str, canonical_digest: str) -> bool:
        return canonical_digest in valid_digests
    return validator


def _make_guard(adapter, run_id, validator):
    """Build an OrdinaryDispatchGuard with trust check skipped for test adapters."""
    return OrdinaryDispatchGuard(
        adapter, run_id, validator, skip_trust_check=True,
    )


def _compute_digest(terms: list[str], max_results: int = 10) -> str:
    """Compute the canonical digest for a search operation."""
    operation = {"terms": sorted(terms), "max": max_results, "filters": {}}
    canonical_bytes = canonicalize_capsule_payload(operation)
    return compute_canonical_request_digest(canonical_bytes)


# ── Happy path: valid capsule → dispatch allowed ───────────────────────


class TestOrdinaryDispatchHappyPath:
    """A correctly journaled operation with a capsule is allowed."""

    @pytest.mark.asyncio
    async def test_dispatch_with_valid_capsule_allowed(self):
        adapter = _FakeAdapter()
        digest = _compute_digest(["ai", "safety"])
        validator = _make_validator({digest})
        guard = _make_guard(adapter, "r1", validator)

        query = SearchQuery(terms=["ai", "safety"], max_results=10)
        results = await guard.search(query)

        assert len(results) == 1
        assert guard.dispatch_count == 1


# ── ChatGPT's required adversarial tests ───────────────────────────────


class TestOrdinaryRescueWithoutCapsule:
    """ChatGPT Case 1: ordinary zero-result rescue → rescue adapter blocked.

    Target adapter is journaled (has capsule). Rescue adapter is NOT journaled
    (no capsule). The rescue call must be blocked.
    """

    @pytest.mark.asyncio
    async def test_rescue_adapter_without_capsule_blocked(self):
        # Target adapter has a capsule for ["ai"]
        target_digest = _compute_digest(["ai"])
        validator = _make_validator({target_digest})

        target = _FakeAdapter()
        target.adapter_name = "target_adapter"
        target_guard = _make_guard(target, "r1", validator)

        # Target dispatch succeeds (has capsule)
        query1 = SearchQuery(terms=["ai"], max_results=10)
        await target_guard.search(query1)

        # Rescue adapter has no capsule — blocked
        rescue = _FakeAdapter()
        rescue.adapter_name = "rescue_adapter"
        rescue_guard = _make_guard(rescue, "r1", validator)

        query2 = SearchQuery(terms=["ai", "broader"], max_results=10)
        rescue_digest = _compute_digest(["ai", "broader"])
        assert rescue_digest not in {target_digest}  # different operation

        with pytest.raises(OrdinaryDispatchError, match="No available capsule"):
            await rescue_guard.search(query2)


class TestOrdinaryFallbackWithoutCapsule:
    """ChatGPT Case 2: generated fallback without exact capsule → blocked.

    A generic reservation exists but no exact adapter-operation capsule.
    The fallback call must be blocked.
    """

    @pytest.mark.asyncio
    async def test_generated_fallback_blocked(self):
        # Only ["original_terms"] has a capsule
        original_digest = _compute_digest(["original_terms"])
        validator = _make_validator({original_digest})

        adapter = _FakeAdapter()
        guard = _make_guard(adapter, "r1", validator)

        # Node generates fallback terms ["generated_terms"] — no capsule
        fallback_query = SearchQuery(terms=["generated_terms"], max_results=10)
        with pytest.raises(OrdinaryDispatchError, match="No available capsule"):
            await guard.search(fallback_query)


class TestOrdinaryDuplicateDispatch:
    """ChatGPT: one capsule authorizes one logical operation.

    A second identical dispatch (same terms, same adapter) is rejected.
    """

    @pytest.mark.asyncio
    async def test_duplicate_identical_dispatch_blocked(self):
        digest = _compute_digest(["ai"])
        validator = _make_validator({digest})

        adapter = _FakeAdapter()
        guard = _make_guard(adapter, "r1", validator)

        query = SearchQuery(terms=["ai"], max_results=10)

        # First dispatch succeeds
        await guard.search(query)
        assert guard.dispatch_count == 1

        # Second identical dispatch blocked
        with pytest.raises(OrdinaryDispatchError, match="Duplicate dispatch"):
            await guard.search(query)


# ── Trusted adapter identity (ChatGPT: not self-asserted) ──────────────


class TestTrustedAdapterIdentity:
    """The allowlist binds to concrete class, not adapter-supplied strings."""

    def test_spoofed_adapter_not_trusted(self):
        """A fake adapter claiming adapter_name='arxiv' is not trusted."""
        spoofed = _SpoofedAdapter()
        assert not is_trusted_adapter(spoofed), (
            "Spoofed adapter claiming 'arxiv' must not pass trusted check"
        )

    def test_trusted_registry_binds_to_classes(self):
        """TRUSTED_ADAPTER_CLASSES maps names to actual classes."""
        assert len(TRUSTED_ADAPTER_CLASSES) >= 1
        # Each value is a class (type), not a string
        for name, cls in TRUSTED_ADAPTER_CLASSES.items():
            assert isinstance(cls, type), f"{name} maps to {cls}, not a class"

    @pytest.mark.asyncio
    async def test_untrusted_adapter_blocked_at_dispatch(self):
        """An untrusted adapter is rejected before dispatch."""
        spoofed = _SpoofedAdapter()
        digest = _compute_digest(["test"])
        validator = _make_validator({digest})
        guard = OrdinaryDispatchGuard(spoofed, "r1", validator)

        query = SearchQuery(terms=["test"], max_results=10)
        with pytest.raises(OrdinaryDispatchError, match="not a trusted concrete class"):
            await guard.search(query)


# ── build_ordinary_guarded_registry ────────────────────────────────────


class TestOrdinaryGuardedRegistry:
    """The registry builder produces isolated, guarded adapter dicts."""

    def test_registry_is_instance_local(self):
        from nodechain.nodes.search_tool import _ADAPTERS
        registry = build_ordinary_guarded_registry(
            "r1", ["semantic_scholar"],
            _make_validator(set()),
        )
        assert registry is not _ADAPTERS
        assert "semantic_scholar" in registry
        assert isinstance(registry["semantic_scholar"], OrdinaryDispatchGuard)

    def test_module_global_not_mutated(self):
        from nodechain.nodes.search_tool import _ADAPTERS
        snapshot = dict(_ADAPTERS)
        build_ordinary_guarded_registry("r1", ["semantic_scholar"], _make_validator(set()))
        assert _ADAPTERS == snapshot


# ── Full canonical digest used (not 16-char prefix) ────────────────────


class TestFullDigestMatching:
    """The guard uses full SHA-256, not the legacy 16-char prefix."""

    def test_digest_is_64_hex_chars(self):
        digest = _compute_digest(["test"])
        assert len(digest) == 64, f"expected 64 hex chars, got {len(digest)}"

    @pytest.mark.asyncio
    async def test_wrong_digest_rejected(self):
        # Valid capsule for ["correct_terms"]
        correct_digest = _compute_digest(["correct_terms"])
        validator = _make_validator({correct_digest})

        adapter = _FakeAdapter()
        guard = _make_guard(adapter, "r1", validator)

        # Query with different terms → different digest → no matching capsule
        query = SearchQuery(terms=["wrong_terms"], max_results=10)
        with pytest.raises(OrdinaryDispatchError, match="No available capsule"):
            await guard.search(query)
