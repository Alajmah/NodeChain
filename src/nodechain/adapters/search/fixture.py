"""Sealed fixture search adapter for governed research workspace runs.

The FixtureSearchAdapter is a deterministic, zero-network adapter that serves
results from an immutable sealed corpus. It is the only adapter permitted in
the Phase 5 research workspace contract.

Design contract
---------------
* **Zero network**: ``search()`` is overridden entirely; it never calls
  ``_fetch()``, ``build_url()``, or ``build_params()``. No socket is opened.
* **Deterministic**: the same corpus + query always produces the same results.
* **Sealed (immutable representation)**: the corpus is converted to a deeply
  immutable structure (``MappingProxyType`` / tuples / frozen records) at
  construction, and a canonical digest is retained as independent evidence.
  Mutation through either the original constructor argument or the
  adapter-retained representation is impossible (the former is detached via
  deep copy; the latter has no mutable surface). The digest is recomputed
  before every search and mismatch rejects before result production.
* **Provenance-faithful**: results pass through ``_finalize_results()`` so the
  central provenance stamping boundary applies identically to live adapters.
* **Fault-injection capable**: the corpus may carry per-scenario fault
  directives. Because ``OrdinaryDispatchGuard.search()`` validates trust and
  capsule state, records the operation digest, and only then delegates to the
  adapter, any fault raised inside this adapter is *post-dispatch*. Therefore
  ``fail_before_dispatch`` is NOT implemented here — it belongs in the
  WorkspaceRunner's lane-admission layer (before the guard is invoked). The
  adapter implements only post-dispatch faults: ``timeout_after_dispatch``,
  ``malformed_provenance``, ``partial_result_set``.
"""

from __future__ import annotations

import copy
import hashlib
import json
import time
from types import MappingProxyType
from typing import Any

from nodechain.adapters.search.base_search import (
    BaseSearchAdapter,
    ProvenanceError,
    ProvenanceFailureCode,
    SearchAdapterError,
    SearchAdapterResult,
    SearchQuery,
)
from nodechain.adapters.search.failure_types import (
    AdapterFailure,
    SearchFailureType,
)


# --------------------------------------------------------------------------- #
# Corpus types
# --------------------------------------------------------------------------- #


#: Per-scenario fault directives supported by the adapter. All are
#: *post-dispatch* faults — they fire after OrdinaryDispatchGuard has recorded
#: the operation. ``fail_before_dispatch`` is intentionally absent; it is
#: implemented in the WorkspaceRunner's lane-admission layer.
_FAULT_TYPES: frozenset[str] = frozenset(
    {
        "timeout_after_dispatch",
        "malformed_provenance",
        "partial_result_set",
    }
)


class FixtureCorpusError(Exception):
    """Raised when a sealed fixture corpus is malformed or mutated."""


# --------------------------------------------------------------------------- #
# Immutable corpus representation
# --------------------------------------------------------------------------- #


def _freeze(obj: Any) -> Any:
    """Recursively convert ``obj`` into a deeply immutable representation.

    dict → MappingProxyType (read-only view over a frozen dict)
    list → tuple
    set  → frozenset
    scalars (str/int/float/bool/None) → unchanged
    """
    if isinstance(obj, dict):
        return MappingProxyType({k: _freeze(v) for k, v in obj.items()})
    if isinstance(obj, (list, tuple)):
        return tuple(_freeze(v) for v in obj)
    if isinstance(obj, set):
        return frozenset(_freeze(v) for v in obj)
    return obj


def _compute_corpus_digest(corpus: Any) -> str:
    """Compute a canonical SHA-256 digest of the corpus.

    The corpus is serialized with sorted keys and compact separators so the
    digest is stable regardless of dict insertion order.
    """
    def _to_serializable(o: Any) -> Any:
        if isinstance(o, MappingProxyType):
            return {k: _to_serializable(v) for k, v in o.items()}
        if isinstance(o, tuple):
            return [_to_serializable(v) for v in o]
        if isinstance(o, frozenset):
            return sorted(_to_serializable(v) for v in o)
        return o

    payload = json.dumps(
        _to_serializable(corpus),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# FixtureSearchAdapter
# --------------------------------------------------------------------------- #


class FixtureSearchAdapter(BaseSearchAdapter):
    """Sealed, deterministic, zero-network search adapter.

    The corpus is a mapping of deterministic query-key → entry. A query-key
    is the lowercased, sorted, space-joined query terms. An entry is either a
    list of result dicts or a dict with ``results`` (list) and optional
    ``_fault``. Each result dict has the shape accepted by
    ``SearchAdapterResult`` minus the centrally-stamped fields.

    The corpus is stored as a deeply immutable structure (MappingProxyType /
    tuples) and a canonical digest is retained. The digest is recomputed
    before every search; any discrepancy (indicating internal corruption)
    causes immediate rejection.
    """

    adapter_name = "fixture"
    adapter_version = "1.0.0"
    base_url = ""  # no network endpoint — sealed

    def __init__(
        self,
        corpus: dict[str, Any] | None = None,
        *,
        default_max_results: int = 10,
    ) -> None:
        # Do NOT call BaseSearchAdapter.__init__ with network-oriented
        # circuit-breaker defaults that imply wire activity. We pass benign
        # values; the circuit breaker is never tripped because search() never
        # calls _fetch().
        super().__init__(
            rate_limit_per_sec=0.0,
            max_retries=0,
            timeout_seconds=0.0,
            backoff_min=0.0,
            backoff_max=0.0,
            circuit_failure_threshold=0,
            circuit_cooldown_seconds=0.0,
        )
        if corpus is None:
            corpus = {}
        # Deep-copy the input to detach from the caller's object, then freeze
        # into an immutable representation that has no mutable surface.
        self._corpus: MappingProxyType = _freeze(copy.deepcopy(corpus))
        self._default_max_results = default_max_results
        self._corpus_digest: str = _compute_corpus_digest(self._corpus)
        self._invocation_count = 0

    # ------------------------------------------------------------------ #
    # Sealed-corpus access
    # ------------------------------------------------------------------ #

    @property
    def corpus_digest(self) -> str:
        """Canonical SHA-256 digest of the sealed corpus (computed once at
        construction; recomputed internally before each search)."""
        return self._corpus_digest

    @property
    def corpus_size(self) -> int:
        """Number of distinct query-keys in the sealed corpus."""
        return len(self._corpus)

    @staticmethod
    def _query_key(query: SearchQuery) -> str:
        return " ".join(sorted(t.lower() for t in query.terms if isinstance(t, str)))

    def _verify_corpus_integrity(self) -> None:
        """Recompute the corpus digest and reject on mismatch. This catches
        any internal corruption (the immutable representation has no mutable
        surface, so a mismatch would indicate memory corruption or a
        qualification defect)."""
        current = _compute_corpus_digest(self._corpus)
        if current != self._corpus_digest:
            raise FixtureCorpusError(
                f"sealed corpus digest mismatch: expected {self._corpus_digest}, "
                f"recomputed {current}"
            )

    def _lookup(self, query: SearchQuery) -> Any:
        self._verify_corpus_integrity()
        key = self._query_key(query)
        entry = self._corpus.get(key)
        if entry is None:
            return ()
        return entry  # already immutable (tuple / MappingProxyType)

    # ------------------------------------------------------------------ #
    # Abstract-method stubs (never called — search() is fully overridden)
    # ------------------------------------------------------------------ #

    def build_url(self, query: SearchQuery) -> str:  # pragma: no cover
        raise FixtureCorpusError(
            "FixtureSearchAdapter does not build URLs — search() is sealed"
        )

    def build_params(self, query: SearchQuery) -> dict[str, Any]:  # pragma: no cover
        raise FixtureCorpusError(
            "FixtureSearchAdapter does not build params — search() is sealed"
        )

    def normalize_response(
        self, raw: dict[str, Any], query: SearchQuery
    ) -> list[SearchAdapterResult]:  # pragma: no cover
        raise FixtureCorpusError(
            "FixtureSearchAdapter does not normalize HTTP responses — "
            "search() is sealed"
        )

    # ------------------------------------------------------------------ #
    # Sealed search — the authoritative zero-network path
    # ------------------------------------------------------------------ #

    async def search(self, query: SearchQuery) -> list[SearchAdapterResult]:
        """Serve deterministic results from the sealed corpus.

        Never opens a socket. Never calls ``_fetch()``, ``build_url()``, or
        ``build_params()``. Honors post-dispatch fault directives in the corpus
        entry. Delegates provenance stamping to ``_finalize_results()`` so the
        central boundary applies identically.

        Note: ``fail_before_dispatch`` is NOT a valid fault here. The
        OrdinaryDispatchGuard records the dispatch digest *before* delegating
        to this method, so any fault raised here is post-dispatch by
        definition. ``fail_before_dispatch`` is implemented in the
        WorkspaceRunner's lane-admission layer.
        """
        self._verify_corpus_integrity()
        self._invocation_count += 1
        start = time.time()

        entry = self._lookup(query)

        # ── Fault injection (post-dispatch only) ───────────────────── #
        if isinstance(entry, MappingProxyType) and "_fault" in entry:
            fault = entry["_fault"]
            if fault not in _FAULT_TYPES:
                raise FixtureCorpusError(
                    f"unknown fault type in fixture corpus: {fault!r}"
                )
            if fault == "timeout_after_dispatch":
                # dispatch occurred; outcome unknown.
                raise SearchAdapterError(
                    AdapterFailure(
                        adapter=self.adapter_name,
                        failure_type=SearchFailureType.TIMEOUT,
                        retryable=False,
                        message="timeout_after_dispatch: injected fault "
                        "(dispatch occurred, outcome unknown)",
                    )
                )
            if fault == "malformed_provenance":
                # Return results with a forbidden adapter-supplied
                # provenance_version that BYPASSES _finalize_results() so the
                # malformed result crosses the adapter boundary. The node's
                # FPV1 validation (SearchToolNode.validate_live_result) then
                # rejects it. The clean path still goes through
                # _finalize_results() for central stamping.
                raw_results = self._build_results(
                    entry.get("results", ()), query
                )
                # Stamp with an invalid version directly — do NOT call
                # _finalize_results (which would catch this and raise).
                elapsed_ms = int((time.time() - start) * 1000)
                for r in raw_results:
                    r.adapter_latency_ms = elapsed_ms
                    r.provenance_version = 999  # forbidden version
                return raw_results
            if fault == "partial_result_set":
                # dispatch succeeded; explicitly incomplete set. Return the
                # partial results with structural incompleteness metadata
                # embedded in each result's raw_data so downstream nodes can
                # classify the partial outcome.
                raw_results = self._build_results(
                    entry.get("results", ()), query
                )
                total_available = entry.get("total_available", 0)
                unavailable_ids = list(entry.get("unavailable_source_ids", ()))
                incompleteness_reason = entry.get(
                    "incompleteness_reason", "partial_result_set_fault"
                )
                for r in raw_results:
                    r.raw_data["_partial"] = True
                    r.raw_data["_total_available"] = total_available
                    r.raw_data["_returned_count"] = len(raw_results)
                    r.raw_data["_unavailable_source_ids"] = unavailable_ids
                    r.raw_data["_incompleteness_reason"] = incompleteness_reason
                return self._finalize_results(
                    raw_results, int((time.time() - start) * 1000)
                )

        # ── Clean deterministic path ───────────────────────────────── #
        if isinstance(entry, MappingProxyType):
            results_data = entry.get("results", ())
        elif isinstance(entry, tuple):
            results_data = entry
        else:
            results_data = ()

        max_results = query.max_results or self._default_max_results
        results_data = results_data[:max_results]
        raw_results = self._build_results(results_data, query)
        return self._finalize_results(
            raw_results, int((time.time() - start) * 1000)
        )

    def _build_results(
        self, results_data: tuple[Any, ...], query: SearchQuery
    ) -> list[SearchAdapterResult]:
        """Convert immutable raw corpus entries into SearchAdapterResult
        objects.

        Each entry is a MappingProxyType. The entry may either:
        - have a nested ``raw_data`` key (legacy format), or
        - have source fields at the top level (expanded format from
          corpus_to_fixture_map: origin_api, source_id, source_hash, title,
          authors, abstract, doi, etc.)

        In the expanded format, ALL fields except origin_api, query_used,
        and retrieved_at become the ``raw_data`` dict, preserving the source
        content for downstream ingestion.
        """
        out: list[SearchAdapterResult] = []
        query_str = " ".join(query.terms)
        # Fields that are NOT part of raw_data (they map to SearchAdapterResult
        # top-level fields).
        _TOP_LEVEL = {"origin_api", "query_used", "retrieved_at",
                       "adapter_latency_ms", "provenance_version"}
        for item in results_data:
            if not isinstance(item, MappingProxyType):
                raise FixtureCorpusError(
                    f"fixture result entry is not a mapping: {type(item).__name__}"
                )
            if "provenance_version" in item:
                raise FixtureCorpusError(
                    "fixture corpus result must not set provenance_version"
                )
            # If the item has a nested raw_data key, use it (legacy format).
            if "raw_data" in item:
                raw_data = dict(item["raw_data"])
            else:
                # Expanded format: all non-top-level fields become raw_data.
                raw_data = {
                    k: v for k, v in item.items() if k not in _TOP_LEVEL
                }
            raw_data = _unfreeze(raw_data)
            out.append(
                SearchAdapterResult(
                    origin_api=item.get("origin_api", "fixture"),
                    raw_data=raw_data,
                    query_used=item.get("query_used", query_str),
                    retrieved_at=item.get(
                        "retrieved_at", "2026-01-01T00:00:00Z"
                    ),
                    adapter_latency_ms=item.get("adapter_latency_ms", 0),
                )
            )
        return out

    # ------------------------------------------------------------------ #
    # Introspection (for attestation tests)
    # ------------------------------------------------------------------ #

    @property
    def invocation_count(self) -> int:
        """Number of times ``search()`` has been called on this instance."""
        return self._invocation_count


def _unfreeze(obj: Any) -> Any:
    """Recursively convert immutable types back to mutable JSON types."""
    if isinstance(obj, MappingProxyType):
        return {k: _unfreeze(v) for k, v in obj.items()}
    if isinstance(obj, tuple):
        return [_unfreeze(v) for v in obj]
    if isinstance(obj, frozenset):
        return sorted(_unfreeze(v) for v in obj)
    return obj
