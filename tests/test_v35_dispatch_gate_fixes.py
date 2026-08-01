"""v3.5.0 T3c/d/e tests — ChatGPT's three narrow STOP conditions.

1. adapter_resolver mandatory: production path cannot construct unguarded search
2. type() is instead of isinstance: subclass rejection
3. dispatch-integrity exceptions escape SearchToolNode.execute()

These close ChatGPT's narrow STOP gate before T4.
"""
from __future__ import annotations

import asyncio
import pytest

from nodechain.adapters.search.base_search import (
    BaseSearchAdapter, SearchQuery, SearchAdapterResult,
)
from nodechain.nodes.search_tool import SearchToolNode
from nodechain.runtime.recovery_dispatch_guard import (
    OrdinaryDispatchGuard,
    OrdinaryDispatchError,
    RecoveryDispatchError,
    is_trusted_adapter,
    TRUSTED_ADAPTER_CLASSES,
)


# ── Fix 1: adapter_resolver mandatory ─────────────────────────────────


class TestResolverMandatory:
    """Production path cannot construct an unguarded search."""

    def test_no_resolver_no_unguarded_raises(self):
        """Without resolver and allow_unguarded=False, resolution fails closed."""
        node = SearchToolNode(allow_unguarded=False)
        with pytest.raises(RuntimeError, match="no adapter_resolver"):
            node._resolve_adapter("semantic_scholar")

    def test_resolver_lookup_miss_returns_none(self):
        """Resolver miss does NOT fall back to _ADAPTERS."""
        node = SearchToolNode(
            adapter_resolver={"only_this": "fake"},
            allow_unguarded=False,
        )
        # Lookup for an adapter NOT in the resolver → None, not _ADAPTERS fallback
        result = node._resolve_adapter("semantic_scholar")
        assert result is None

    def test_resolver_provides_adapter(self):
        """Resolver provides the guarded adapter when present."""
        fake = object()
        node = SearchToolNode(adapter_resolver={"semantic_scholar": fake})
        assert node._resolve_adapter("semantic_scholar") is fake


# ── Fix 2: type() is (reject subclasses) ──────────────────────────────


class TestSubclassRejection:
    """is_trusted_adapter uses type() is, not isinstance — rejects subclasses."""

    def test_exact_class_accepted(self):
        """The exact trusted class passes."""
        if "arxiv" in TRUSTED_ADAPTER_CLASSES:
            from nodechain.adapters.search.arxiv import ArxivAdapter
            adapter = ArxivAdapter()
            assert is_trusted_adapter(adapter)

    def test_subclass_rejected(self):
        """A subclass of a trusted adapter is rejected.

        ChatGPT: isinstance() accepts arbitrary subclasses that can override
        search() to batch or fan out. type() is rejects them.
        """
        if "arxiv" in TRUSTED_ADAPTER_CLASSES:
            from nodechain.adapters.search.arxiv import ArxivAdapter

            class BatchingArxivAdapter(ArxivAdapter):
                """A malicious subclass that batches multiple wire operations."""
                async def search(self, query):
                    # Would make multiple calls — not singleton
                    return []

            spoofed = BatchingArxivAdapter()
            assert not is_trusted_adapter(spoofed), (
                "Subclass of trusted adapter must be rejected (type() is check)"
            )


# ── Fix 3: dispatch-integrity exceptions escape node ──────────────────


class _RejectingGuard:
    """A fake adapter that raises OrdinaryDispatchError."""
    adapter_name = "fake"
    adapter_version = "1.0.0"

    async def search(self, query):
        raise OrdinaryDispatchError(
            "No available capsule for fake",
            rejection_type="no_matching_capsule",
        )


class TestExceptionsEscapeNode:
    """Dispatch-integrity exceptions must NOT be swallowed by SearchToolNode."""

    @pytest.mark.asyncio
    async def test_ordinary_dispatch_error_propagates(self):
        """OrdinaryDispatchError leaves execute() instead of becoming adapters_failed."""
        node = SearchToolNode(
            adapter_resolver={"semantic_scholar": _RejectingGuard()},
            allow_unguarded=False,
        )
        envelope = _make_search_envelope(
            adapter_grants=["semantic_scholar"],
            search_queries=[{
                "terms": ["ai"],
                "target_adapters": ["semantic_scholar"],
                "max_results": 5, "filters": {},
            }],
        )
        with pytest.raises(OrdinaryDispatchError):
            await node.execute(envelope)

    @pytest.mark.asyncio
    async def test_recovery_dispatch_error_propagates(self):
        """RecoveryDispatchError leaves execute() for coordinator classification."""

        class _RecoveryRejectingGuard:
            adapter_name = "fake"
            adapter_version = "1.0.0"
            async def search(self, query):
                raise RecoveryDispatchError(
                    "Second dispatch rejected",
                    rejection_type="duplicate_dispatch",
                )

        node = SearchToolNode(
            adapter_resolver={"semantic_scholar": _RecoveryRejectingGuard()},
            allow_unguarded=False,
        )
        envelope = _make_search_envelope(
            adapter_grants=["semantic_scholar"],
            search_queries=[{
                "terms": ["ai"],
                "target_adapters": ["semantic_scholar"],
                "max_results": 5, "filters": {},
            }],
        )
        with pytest.raises(RecoveryDispatchError):
            await node.execute(envelope)


# ── Helpers ───────────────────────────────────────────────────────────


def _make_search_envelope(
    adapter_grants: list[str],
    search_queries: list[dict],
):
    """Build a minimal InvocationEnvelope for SearchToolNode."""
    from nodechain.core.envelope import InvocationEnvelope, Capabilities, Context

    payload = {
        "search_queries": search_queries,
        "adapter_grants": adapter_grants,
    }
    return InvocationEnvelope(
        payload=payload,
        run_id="r1",
        chain_id="c1",
        node_id="search_tool",
        step_id=1,
        context=Context(
            chain_state={"outputs": {}},
            step=1,
            session_memory=[],
        ),
        capabilities=Capabilities(
            allowed_adapters=adapter_grants,
            allowed_tools=[],
            side_effect_completed_keys=[],
            side_effect_status_map={},
        ),
    )
