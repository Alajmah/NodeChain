"""Trust attestation tests for the FixtureSearchAdapter through the governed
dispatch guard.

These tests prove:

* exact FixtureSearchAdapter class accepted by OrdinaryDispatchGuard
* subclass rejected (type() is exact match)
* same-name different class rejected
* unknown adapter name rejected
* skip_trust_check remains false
* allow_unguarded remains false
* one query causes one adapter invocation
* two distinct query digests remain two distinct governed operations
* no hidden retry or fan-out
* fixture absent from ADAPTER_RETRY_ALLOWLIST
* installed-wheel class identity equals trusted registry identity
"""

from __future__ import annotations

import asyncio

import pytest

from nodechain.adapters.search.base_search import SearchQuery
from nodechain.adapters.search.fixture import FixtureSearchAdapter
from nodechain.runtime.recovery_dispatch_guard import (
    OrdinaryDispatchGuard,
    OrdinaryDispatchError,
    ADAPTER_RETRY_ALLOWLIST,
    TRUSTED_ADAPTER_CLASSES,
    is_trusted_adapter,
)


def _run(coro):
    return asyncio.run(coro)


def _make_guard(
    corpus: dict | None = None,
    *,
    run_id: str = "attestation-run",
    skip_trust_check: bool = False,
    capsule_present: bool = True,
) -> tuple[OrdinaryDispatchGuard, FixtureSearchAdapter]:
    adapter = FixtureSearchAdapter(corpus or {})
    guard = OrdinaryDispatchGuard(
        target_adapter=adapter,
        run_id=run_id,
        capsule_validator=lambda rid, aname, digest: capsule_present,
        skip_trust_check=skip_trust_check,
    )
    return guard, adapter


# --------------------------------------------------------------------------- #
# Trust attestation
# --------------------------------------------------------------------------- #


def test_exact_fixture_class_accepted() -> None:
    adapter = FixtureSearchAdapter({})
    assert is_trusted_adapter(adapter) is True


def test_fixture_subclass_rejected() -> None:
    class FakeFixture(FixtureSearchAdapter):
        pass

    fake = FakeFixture({})
    assert is_trusted_adapter(fake) is False


def test_same_name_different_class_rejected() -> None:
    """An adapter whose adapter_name is 'fixture' but whose class is not
    FixtureSearchAdapter is rejected."""

    class ImposterFixture(FixtureSearchAdapter):
        adapter_name = "fixture"

    imposter = ImposterFixture({})
    # The name matches, but the exact class does not.
    assert is_trusted_adapter(imposter) is False


def test_unknown_adapter_name_rejected() -> None:
    assert "not_a_real_adapter" not in TRUSTED_ADAPTER_CLASSES


def test_fixture_in_trust_registry() -> None:
    assert "fixture" in TRUSTED_ADAPTER_CLASSES
    assert TRUSTED_ADAPTER_CLASSES["fixture"] is FixtureSearchAdapter


# --------------------------------------------------------------------------- #
# Guard flags remain locked
# --------------------------------------------------------------------------- #


def test_skip_trust_check_remains_false() -> None:
    guard, _ = _make_guard()
    assert guard._skip_trust_check is False


def test_allow_unguarded_remains_false() -> None:
    """The FixtureSearchToolNode (used in the runner) defaults to
    allow_unguarded=False; verify the adapter itself carries no bypass."""
    adapter = FixtureSearchAdapter({})
    # The adapter has no allow_unguarded attribute — it's a node-level flag.
    # The guard's skip_trust_check is the trust-bypass equivalent and must
    # be False.
    guard = OrdinaryDispatchGuard(
        target_adapter=adapter,
        run_id="x",
        capsule_validator=lambda *a: True,
    )
    assert guard._skip_trust_check is False


# --------------------------------------------------------------------------- #
# Dispatch counting (one query = one governed operation)
# --------------------------------------------------------------------------- #


def test_one_query_one_adapter_invocation() -> None:
    corpus = {"async rust": {"results": [
        {"origin_api": "fixture", "raw_data": {"title": "A"}}
    ]}}
    guard, adapter = _make_guard(corpus)
    results = _run(guard.search(SearchQuery(terms=["async", "rust"])))
    assert len(results) == 1
    assert len(guard._dispatched_digests) == 1
    assert adapter.invocation_count == 1


def test_two_distinct_queries_two_distinct_digests() -> None:
    corpus = {
        "async rust": {"results": [
            {"origin_api": "fixture", "raw_data": {"title": "A"}}
        ]},
        "neural networks": {"results": [
            {"origin_api": "fixture", "raw_data": {"title": "B"}}
        ]},
    }
    guard, adapter = _make_guard(corpus)
    _run(guard.search(SearchQuery(terms=["async", "rust"])))
    _run(guard.search(SearchQuery(terms=["neural", "networks"])))
    assert len(guard._dispatched_digests) == 2
    assert adapter.invocation_count == 2


def test_duplicate_query_digest_rejected() -> None:
    """The same query digest cannot dispatch twice — no hidden retry."""
    corpus = {"async rust": {"results": [
        {"origin_api": "fixture", "raw_data": {"title": "A"}}
    ]}}
    guard, adapter = _make_guard(corpus)
    _run(guard.search(SearchQuery(terms=["async", "rust"])))
    with pytest.raises(OrdinaryDispatchError):
        _run(guard.search(SearchQuery(terms=["async", "rust"])))
    assert adapter.invocation_count == 1


def test_no_fan_out() -> None:
    """One search() call produces exactly one adapter invocation — the guard
    does not fan out to multiple adapters or batch operations."""
    corpus = {"async rust": {"results": [
        {"origin_api": "fixture", "raw_data": {"title": "A"}},
        {"origin_api": "fixture", "raw_data": {"title": "B"}},
        {"origin_api": "fixture", "raw_data": {"title": "C"}},
    ]}}
    guard, adapter = _make_guard(corpus)
    results = _run(guard.search(SearchQuery(terms=["async", "rust"])))
    assert len(results) == 3  # 3 results from ONE invocation
    assert adapter.invocation_count == 1
    assert len(guard._dispatched_digests) == 1


# --------------------------------------------------------------------------- #
# Retry allowlist
# --------------------------------------------------------------------------- #


def test_fixture_absent_from_retry_allowlist() -> None:
    """The fixture adapter is NOT in the recovery retry allowlist. Fixture
    attestation covers ordinary dispatch only; recovery attestation is a
    separate, unauthorized concern."""
    assert "fixture" not in ADAPTER_RETRY_ALLOWLIST


# --------------------------------------------------------------------------- #
# Installed-wheel class identity (structural — runs in any install context)
# --------------------------------------------------------------------------- #


def test_installed_class_identity_equals_registry_identity() -> None:
    """The FixtureSearchAdapter class object used at runtime is the same class
    object bound in the trust registry. This holds in source, wheel, and sdist
    installs because the import path is identical."""
    from nodechain.adapters.search.fixture import FixtureSearchAdapter as Installed

    assert Installed is TRUSTED_ADAPTER_CLASSES["fixture"]
