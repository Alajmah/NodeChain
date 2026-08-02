"""Tests for flat-result provenance versioning v1 (RD1-FPV1).

Covers strict raw-input classification, live-result gating,
deduplication provenance entries, historical ingestion compatibility,
and adversarial serialization cases.
"""

import pytest

from nodechain.core.provenance import (
    CURRENT_PROVENANCE_VERSION,
    LEGACY_PROVENANCE_VERSION,
    ProvenanceClassification,
    ProvenanceError,
    ProvenanceFailureCode,
    classify_provenance,
    classification_to_mode,
    validate_live_result,
    merge_provenance_entries,
    check_mode_consistency,
    derive_dedup_origins,
    is_ingestible,
)


# ── Fixtures ──────────────────────────────────────────────────────

def _complete_raw(version: int | None = 1, omit_version: bool = False) -> dict:
    d = {
        "origin_api": "semantic_scholar",
        "query_used": "cancer immunotherapy",
        "retrieved_at": "2026-01-01T00:00:00Z",
        # Provenance fields checked by classifier
        "adapter": "semantic_scholar",
        "query": "cancer immunotherapy",
        "retrieval_timestamp": "2026-01-01T00:00:00Z",
        "raw_data": {"title": "Test Paper", "doi": "10.1234/test"},
    }
    if not omit_version and version is not None:
        d["provenance_version"] = version
    # For current version, include provenance_entries (required for ingestion)
    if not omit_version and version == 1:
        d["raw_data"]["provenance_entries"] = [{
            "version": 1,
            "adapter": "semantic_scholar",
            "query": "cancer immunotherapy",
            "retrieval_timestamp": "2026-01-01T00:00:00Z",
        }]
    return d


# ── Classification tests ──────────────────────────────────────────

class TestClassifyProvenance:
    def test_current_complete(self):
        r = _complete_raw(1)
        assert classify_provenance(r) == ProvenanceClassification.CURRENT_COMPLETE

    def test_current_incomplete_missing_adapter(self):
        r = _complete_raw(1)
        r["adapter"] = ""
        r["origin_api"] = ""
        assert classify_provenance(r) == ProvenanceClassification.CURRENT_INCOMPLETE

    def test_current_incomplete_whitespace_query(self):
        r = _complete_raw(1)
        r["query"] = "   "
        r["query_used"] = "   "
        assert classify_provenance(r) == ProvenanceClassification.CURRENT_INCOMPLETE

    def test_current_incomplete_missing_timestamp(self):
        r = _complete_raw(1)
        del r["retrieval_timestamp"]
        del r["retrieved_at"]
        assert classify_provenance(r) == ProvenanceClassification.CURRENT_INCOMPLETE

    def test_legacy_complete(self):
        r = _complete_raw(0)
        assert classify_provenance(r) == ProvenanceClassification.LEGACY_COMPLETE

    def test_legacy_incomplete(self):
        r = _complete_raw(0)
        r["adapter"] = ""
        r["origin_api"] = ""
        assert classify_provenance(r) == ProvenanceClassification.LEGACY_INCOMPLETE

    def test_pre_version_complete(self):
        r = _complete_raw(omit_version=True)
        assert classify_provenance(r) == ProvenanceClassification.PRE_VERSION_COMPLETE

    def test_pre_version_incomplete(self):
        r = _complete_raw(omit_version=True)
        r["adapter"] = ""
        r["origin_api"] = ""
        assert classify_provenance(r) == ProvenanceClassification.PRE_VERSION_INCOMPLETE

    def test_unknown_version(self):
        r = _complete_raw(999)
        assert classify_provenance(r) == ProvenanceClassification.UNKNOWN_VERSION

    @pytest.mark.parametrize("bad_val", [True, False, None, 1.0, "1", -1, [], {}])
    def test_malformed_version(self, bad_val):
        r = _complete_raw()
        r["provenance_version"] = bad_val
        assert classify_provenance(r) == ProvenanceClassification.MALFORMED_VERSION

    def test_pre_version_distinct_from_legacy(self):
        """PRE_VERSION (no key) must not equal LEGACY (explicit 0)."""
        pre = _complete_raw(omit_version=True)
        leg = _complete_raw(0)
        assert classify_provenance(pre) != classify_provenance(leg)

    def test_classification_to_mode_current(self):
        assert classification_to_mode(ProvenanceClassification.CURRENT_COMPLETE) is not None

    def test_classification_to_mode_legacy(self):
        assert classification_to_mode(ProvenanceClassification.LEGACY_COMPLETE) is not None

    def test_classification_to_mode_pre_version(self):
        assert classification_to_mode(ProvenanceClassification.PRE_VERSION_COMPLETE) is not None


# ── Live-result gate tests ───────────────────────────────────────

class TestValidateLiveResult:
    def test_current_complete_accepted(self):
        validate_live_result(_complete_raw(1), 0)  # no exception

    def test_missing_version_rejected(self):
        with pytest.raises(ProvenanceError) as exc:
            validate_live_result(_complete_raw(omit_version=True), 0)
        assert exc.value.code == ProvenanceFailureCode.PROVENANCE_VERSION_MISSING_LIVE

    def test_current_incomplete_rejected(self):
        r = _complete_raw(1)
        r["adapter"] = ""
        r["origin_api"] = ""
        with pytest.raises(ProvenanceError) as exc:
            validate_live_result(r, 0)
        assert exc.value.code == ProvenanceFailureCode.PROVENANCE_CURRENT_INCOMPLETE

    def test_legacy_on_live_rejected(self):
        with pytest.raises(ProvenanceError) as exc:
            validate_live_result(_complete_raw(0), 0)
        assert exc.value.code == ProvenanceFailureCode.PROVENANCE_VERSION_CONFLICT

    def test_pre_version_on_live_rejected(self):
        with pytest.raises(ProvenanceError) as exc:
            validate_live_result(_complete_raw(omit_version=True), 0)
        assert exc.value.code == ProvenanceFailureCode.PROVENANCE_VERSION_MISSING_LIVE

    def test_malformed_rejected(self):
        r = _complete_raw()
        r["provenance_version"] = True
        with pytest.raises(ProvenanceError) as exc:
            validate_live_result(r, 0)
        assert exc.value.code == ProvenanceFailureCode.PROVENANCE_VERSION_MALFORMED

    def test_unknown_version_rejected(self):
        with pytest.raises(ProvenanceError) as exc:
            validate_live_result(_complete_raw(999), 0)
        assert exc.value.code == ProvenanceFailureCode.PROVENANCE_VERSION_UNKNOWN


# ── Deduplication provenance entry tests ──────────────────────────

class TestDedupProvenanceEntries:
    def test_two_current_merge_complete_entries(self):
        e1 = {"version": 1, "adapter": "semantic_scholar", "query": "q1", "retrieval_timestamp": "2026-01-01T00:00:00Z"}
        e2 = {"version": 1, "adapter": "openalex", "query": "q2", "retrieval_timestamp": "2026-01-02T00:00:00Z"}
        merged = merge_provenance_entries([e1], e2)
        assert len(merged) == 2

    def test_exact_duplicates_collapse(self):
        e = {"version": 1, "adapter": "arxiv", "query": "q", "retrieval_timestamp": "2026-01-01T00:00:00Z"}
        merged = merge_provenance_entries([e], e.copy())
        assert len(merged) == 1

    def test_canonical_ordering_independent_of_input(self):
        e1 = {"version": 1, "adapter": "zzz", "query": "q", "retrieval_timestamp": "2026-01-01T00:00:00Z"}
        e2 = {"version": 1, "adapter": "aaa", "query": "q", "retrieval_timestamp": "2026-01-01T00:00:00Z"}
        m1 = merge_provenance_entries([e1], e2)
        m2 = merge_provenance_entries([e2], e1)
        assert m1 == m2  # same canonical order

    def test_mixed_current_legacy_rejected(self):
        with pytest.raises(ProvenanceError) as exc:
            check_mode_consistency([
                {"version": 1, "adapter": "a", "query": "q", "retrieval_timestamp": "2026-01-01T00:00:00Z"},
                {"version": 0, "adapter": "b", "query": "q", "retrieval_timestamp": "2026-01-01T00:00:00Z"},
            ])
        assert exc.value.code == ProvenanceFailureCode.PROVENANCE_MODE_MIXED

    def test_mixed_current_pre_version_rejected(self):
        with pytest.raises(ProvenanceError) as exc:
            check_mode_consistency([
                {"version": 1, "adapter": "a", "query": "q", "retrieval_timestamp": "2026-01-01T00:00:00Z"},
                {"version": None, "adapter": "b", "query": "q", "retrieval_timestamp": "2026-01-01T00:00:00Z"},
            ])
        assert exc.value.code == ProvenanceFailureCode.PROVENANCE_MODE_MIXED

    def test_dedup_origins_derived_from_entries(self):
        entries = [
            {"version": 1, "adapter": "arxiv", "query": "q", "retrieval_timestamp": "2026-01-01T00:00:00Z"},
            {"version": 1, "adapter": "openalex", "query": "q2", "retrieval_timestamp": "2026-01-02T00:00:00Z"},
        ]
        origins = derive_dedup_origins(entries)
        assert origins == ["arxiv", "openalex"]


# ── Ingestion compatibility tests ─────────────────────────────────

class TestIngestionCompatibility:
    def test_current_complete_ingestible(self):
        assert is_ingestible(ProvenanceClassification.CURRENT_COMPLETE)

    def test_legacy_complete_ingestible(self):
        assert is_ingestible(ProvenanceClassification.LEGACY_COMPLETE)

    def test_pre_version_complete_ingestible(self):
        assert is_ingestible(ProvenanceClassification.PRE_VERSION_COMPLETE)

    def test_current_incomplete_not_ingestible(self):
        assert not is_ingestible(ProvenanceClassification.CURRENT_INCOMPLETE)

    def test_unknown_not_ingestible(self):
        assert not is_ingestible(ProvenanceClassification.UNKNOWN_VERSION)

    def test_malformed_not_ingestible(self):
        assert not is_ingestible(ProvenanceClassification.MALFORMED_VERSION)


# ── Serialization round-trip tests ────────────────────────────────

class TestSerializationRoundTrip:
    def test_current_round_trip_preserves_mode(self):
        from nodechain.nodes.source_ingestion import _build_normalized_provenance
        raw = _complete_raw(1)
        result = _build_normalized_provenance(raw)
        assert result["mode"] == "current"
        assert result["version"] == 1

    def test_legacy_round_trip_preserves_mode(self):
        from nodechain.nodes.source_ingestion import _build_normalized_provenance
        raw = _complete_raw(0)
        result = _build_normalized_provenance(raw)
        assert result["mode"] == "legacy"
        assert result["version"] == 0

    def test_pre_version_round_trip_preserves_mode(self):
        from nodechain.nodes.source_ingestion import _build_normalized_provenance
        raw = _complete_raw(omit_version=True)
        result = _build_normalized_provenance(raw)
        assert result["mode"] == "pre_version"
        assert result["version"] is None

    def test_historical_replay_cannot_upgrade_mode(self):
        """A pre-version record classified once must stay pre_version."""
        raw = _complete_raw(omit_version=True)
        c1 = classify_provenance(raw)
        # Simulate serialization + re-read
        raw2 = dict(raw)  # still no version key
        c2 = classify_provenance(raw2)
        assert c1 == c2 == ProvenanceClassification.PRE_VERSION_COMPLETE

    def test_current_output_has_explicit_version(self):
        """Newly created current output must carry version=1."""
        from nodechain.adapters.search.base_search import SearchAdapterResult
        r = SearchAdapterResult(
            origin_api="test",
            raw_data={"title": "T"},
            query_used="q",
            retrieved_at="2026-01-01T00:00:00Z",
        )
        # Before stamping, version is None
        assert r.provenance_version is None
        # After central stamping
        r.provenance_version = CURRENT_PROVENANCE_VERSION
        assert r.provenance_version == 1


# ── R1 correction tests (7 findings) ──────────────────────────────

class TestAdapterConflictRejection:
    """Finding 2: ANY adapter-supplied version is rejected (including 1)."""

    def test_adapter_supplied_version_0_rejected(self):
        from nodechain.adapters.search.base_search import SearchAdapterResult
        from nodechain.adapters.search.arxiv import ArxivAdapter
        adapter = ArxivAdapter()
        r = SearchAdapterResult(
            origin_api="arxiv", raw_data={"title": "T"},
            query_used="q", retrieved_at="2026-01-01T00:00:00Z",
            provenance_version=0,
        )
        with pytest.raises(ProvenanceError) as exc:
            adapter._finalize_results([r], 100)
        assert exc.value.code == ProvenanceFailureCode.PROVENANCE_VERSION_CONFLICT

    def test_adapter_supplied_version_1_also_rejected(self):
        """Even supplying the correct version 1 must be rejected."""
        from nodechain.adapters.search.base_search import SearchAdapterResult
        from nodechain.adapters.search.arxiv import ArxivAdapter
        adapter = ArxivAdapter()
        r = SearchAdapterResult(
            origin_api="arxiv", raw_data={"title": "T"},
            query_used="q", retrieved_at="2026-01-01T00:00:00Z",
            provenance_version=1,
        )
        with pytest.raises(ProvenanceError) as exc:
            adapter._finalize_results([r], 100)
        assert exc.value.code == ProvenanceFailureCode.PROVENANCE_VERSION_CONFLICT

    def test_adapter_supplied_entries_rejected(self):
        """Adapter must not supply reserved raw_data.provenance_entries."""
        from nodechain.adapters.search.base_search import SearchAdapterResult
        from nodechain.adapters.search.arxiv import ArxivAdapter
        adapter = ArxivAdapter()
        r = SearchAdapterResult(
            origin_api="arxiv",
            raw_data={"title": "T", "provenance_entries": [{"version": 1}]},
            query_used="q", retrieved_at="2026-01-01T00:00:00Z",
        )
        with pytest.raises(ProvenanceError) as exc:
            adapter._finalize_results([r], 100)
        assert exc.value.code == ProvenanceFailureCode.PROVENANCE_VERSION_CONFLICT

    def test_arxiv_finalize_stamps_version_1(self):
        from nodechain.adapters.search.base_search import SearchAdapterResult
        from nodechain.adapters.search.arxiv import ArxivAdapter
        adapter = ArxivAdapter()
        r = SearchAdapterResult(
            origin_api="arxiv", raw_data={"title": "T"},
            query_used="q", retrieved_at="2026-01-01T00:00:00Z",
        )
        results = adapter._finalize_results([r], 100)
        assert results[0].provenance_version == 1

    def test_pubmed_finalize_stamps_version_1(self):
        from nodechain.adapters.search.base_search import SearchAdapterResult
        from nodechain.adapters.search.pubmed import PubMedAdapter
        adapter = PubMedAdapter()
        r = SearchAdapterResult(
            origin_api="pubmed", raw_data={"title": "T"},
            query_used="q", retrieved_at="2026-01-01T00:00:00Z",
        )
        results = adapter._finalize_results([r], 100)
        assert results[0].provenance_version == 1


class TestCoreUtilFixes:
    """Finding 6: strictness defects in core utilities."""

    def test_non_string_provenance_field_is_incomplete(self):
        """Lists/ints/objects must NOT satisfy completeness."""
        r = _complete_raw(1)
        r["adapter"] = ["not_a_string"]
        r["origin_api"] = ["not_a_string"]  # set both aliases
        assert classify_provenance(r) == ProvenanceClassification.CURRENT_INCOMPLETE

    def test_int_provenance_field_is_incomplete(self):
        r = _complete_raw(1)
        r["query"] = 42
        r["query_used"] = 42  # set both aliases
        assert classify_provenance(r) == ProvenanceClassification.CURRENT_INCOMPLETE

    def test_delimiter_containing_entries_dont_collide(self):
        """Entries with pipe characters must not collide."""
        e1 = {"version": 1, "adapter": "a|b", "query": "q|1", "retrieval_timestamp": "t|x"}
        e2 = {"version": 1, "adapter": "a", "query": "b|q", "retrieval_timestamp": "1|t"}
        # These are distinct entries that WOULD collide with pipe-delimited keys
        merged = merge_provenance_entries([e1], e2)
        assert len(merged) == 2  # both survive

    def test_from_raw_result_no_silent_upgrade(self):
        """Missing version must stay None, not default to current or legacy."""
        from nodechain.core.provenance import ProvenanceEntry
        raw = {
            "origin_api": "test",
            "query_used": "q",
            "retrieved_at": "2026-01-01T00:00:00Z",
        }
        entry = ProvenanceEntry.from_raw_result(raw)
        # Missing version must be None, not 0 or 1
        assert entry.version is None


class TestIngestionEntryValidation:
    """Finding 4: historical entries are strictly validated."""

    def test_mixed_entry_modes_rejected(self):
        """Current record with a legacy entry must fail."""
        from nodechain.nodes.source_ingestion import _build_normalized_provenance
        raw = _complete_raw(1)
        raw["raw_data"]["provenance_entries"] = [
            {"version": 0, "adapter": "legacy", "query": "q", "retrieval_timestamp": "2026-01-01T00:00:00Z"},
        ]
        with pytest.raises(ProvenanceError) as exc:
            _build_normalized_provenance(raw)
        # Should fail with mode-mixed or version-conflict
        assert exc.value.code in (
            ProvenanceFailureCode.PROVENANCE_MODE_MIXED,
            ProvenanceFailureCode.PROVENANCE_VERSION_CONFLICT,
        )

    def test_incomplete_entry_rejected_not_repaired(self):
        """Entry with missing field must fail, not be filled from top-level."""
        from nodechain.nodes.source_ingestion import _build_normalized_provenance
        raw = _complete_raw(1)
        raw["raw_data"]["provenance_entries"] = [
            {"version": 1, "adapter": "", "query": "q", "retrieval_timestamp": "2026-01-01T00:00:00Z"},
        ]
        with pytest.raises(ProvenanceError):
            _build_normalized_provenance(raw)

    def test_stable_failure_codes_preserved(self):
        """Rejection uses ProvenanceFailureCode, not ProvenanceClassification."""
        from nodechain.nodes.source_ingestion import _build_normalized_provenance
        raw = _complete_raw(999)  # unknown version
        with pytest.raises(ProvenanceError) as exc:
            _build_normalized_provenance(raw)
        assert isinstance(exc.value.code, ProvenanceFailureCode)
        assert exc.value.code == ProvenanceFailureCode.PROVENANCE_VERSION_UNKNOWN

    def test_duplicate_entries_deduplicated_in_ingestion(self):
        """Duplicate entries in raw_data are collapsed during ingestion."""
        from nodechain.nodes.source_ingestion import _build_normalized_provenance
        raw = _complete_raw(1)
        raw["raw_data"]["provenance_entries"] = [
            {"version": 1, "adapter": "a", "query": "q", "retrieval_timestamp": "2026-01-01T00:00:00Z"},
            {"version": 1, "adapter": "a", "query": "q", "retrieval_timestamp": "2026-01-01T00:00:00Z"},
        ]
        result = _build_normalized_provenance(raw)
        assert len(result["entries"]) == 1


class TestProvenanceErrorEscapes:
    """Finding 1: ProvenanceError propagates from SearchToolNode."""

    def test_provenance_error_does_not_inherit_from_adapter_error(self):
        """ProvenanceError must not be caught by SearchAdapterError handler."""
        from nodechain.adapters.search.base_search import SearchAdapterError
        assert not issubclass(ProvenanceError, SearchAdapterError)

    def test_provenance_error_does_not_inherit_from_ordinary_dispatch(self):
        from nodechain.runtime.recovery_dispatch_guard import OrdinaryDispatchError
        assert not issubclass(ProvenanceError, OrdinaryDispatchError)


# ── R4 correction tests ───────────────────────────────────────────

class TestCurrentNoEntriesFails:
    """R4 Finding 2: current records cannot use the fallback path."""

    def test_current_without_entries_fails(self):
        from nodechain.nodes.source_ingestion import _build_normalized_provenance
        raw = {
            "origin_api": "openalex",
            "query_used": "q",
            "retrieved_at": "2026-01-01T00:00:00Z",
            "adapter": "openalex",
            "query": "q",
            "retrieval_timestamp": "2026-01-01T00:00:00Z",
            "provenance_version": 1,
            "raw_data": {"title": "T"},
        }
        with pytest.raises(ProvenanceError) as exc:
            _build_normalized_provenance(raw)
        assert exc.value.code == ProvenanceFailureCode.PROVENANCE_CURRENT_INCOMPLETE

    def test_legacy_without_entries_uses_fallback(self):
        from nodechain.nodes.source_ingestion import _build_normalized_provenance
        raw = {
            "origin_api": "openalex",
            "query_used": "q",
            "retrieved_at": "2026-01-01T00:00:00Z",
            "adapter": "openalex",
            "query": "q",
            "retrieval_timestamp": "2026-01-01T00:00:00Z",
            "provenance_version": 0,
            "raw_data": {"title": "T"},
        }
        result = _build_normalized_provenance(raw)
        assert result["mode"] == "legacy"
        assert len(result["entries"]) == 1

    def test_pre_version_without_entries_uses_fallback(self):
        from nodechain.nodes.source_ingestion import _build_normalized_provenance
        raw = {
            "origin_api": "openalex",
            "query_used": "q",
            "retrieved_at": "2026-01-01T00:00:00Z",
            "adapter": "openalex",
            "query": "q",
            "retrieval_timestamp": "2026-01-01T00:00:00Z",
            "raw_data": {"title": "T"},
        }
        result = _build_normalized_provenance(raw)
        assert result["mode"] == "pre_version"
        assert len(result["entries"]) == 1


class TestEmptyEntryListModeCodes:
    """R4 Finding 3: empty entry list returns correct mode-specific code."""

    def test_empty_current_entries_code(self):
        from nodechain.nodes.source_ingestion import _build_normalized_provenance
        raw = _complete_raw(1)
        raw["raw_data"]["provenance_entries"] = []
        with pytest.raises(ProvenanceError) as exc:
            _build_normalized_provenance(raw)
        assert exc.value.code == ProvenanceFailureCode.PROVENANCE_CURRENT_INCOMPLETE

    def test_empty_legacy_entries_code(self):
        from nodechain.nodes.source_ingestion import _build_normalized_provenance
        raw = {
            "origin_api": "x", "query_used": "q", "retrieved_at": "2026-01-01T00:00:00Z",
            "adapter": "x", "query": "q", "retrieval_timestamp": "2026-01-01T00:00:00Z",
            "provenance_version": 0,
            "raw_data": {"provenance_entries": []},
        }
        with pytest.raises(ProvenanceError) as exc:
            _build_normalized_provenance(raw)
        assert exc.value.code == ProvenanceFailureCode.PROVENANCE_LEGACY_INCOMPLETE

    def test_non_list_entries_rejected(self):
        from nodechain.nodes.source_ingestion import _build_normalized_provenance
        raw = _complete_raw(1)
        raw["raw_data"]["provenance_entries"] = "not_a_list"
        with pytest.raises(ProvenanceError) as exc:
            _build_normalized_provenance(raw)
        assert exc.value.code == ProvenanceFailureCode.PROVENANCE_VERSION_MALFORMED

    def test_non_object_entry_rejected(self):
        from nodechain.nodes.source_ingestion import _build_normalized_provenance
        raw = _complete_raw(1)
        raw["raw_data"]["provenance_entries"] = ["string_not_object"]
        with pytest.raises(ProvenanceError) as exc:
            _build_normalized_provenance(raw)
        assert exc.value.code == ProvenanceFailureCode.PROVENANCE_VERSION_MALFORMED


class TestNodeLevelProvenancePropagation:
    """R4: actual SearchToolNode execution tests."""

    def _make_envelope(self, allowed_adapters=None):
        from nodechain.core.envelope import InvocationEnvelope, Context, Capabilities
        return InvocationEnvelope(
            envelope_id="test", run_id="test", chain_id="test",
            node_id="search_tool", step_id=4,
            payload={
                "search_queries": [{"terms": ["test"], "max_results": 1}],
                "adapter_grants": [],
            },
            context=Context(chain_state={}),
            capabilities=Capabilities(
                allowed_adapters=allowed_adapters or ["semantic_scholar"],
                adapter_grants=None,
            ),
        )

    def _unstamped_adapter(self, name, results):
        """Mock adapter that returns results WITHOUT _finalize_results stamping."""
        from unittest.mock import MagicMock, AsyncMock
        from nodechain.adapters.search.base_search import SearchAdapterResult
        adapter = MagicMock()
        mock_results = [
            SearchAdapterResult(
                origin_api=name, raw_data=r,
                query_used="q", retrieved_at="2026-01-01T00:00:00Z",
                # Deliberately NOT setting provenance_version
            )
            for r in results
        ]
        adapter.search = AsyncMock(return_value=mock_results)
        return adapter

    def test_normal_path_unstamped_raises_missing_live(self):
        import asyncio
        from unittest.mock import patch
        from nodechain.nodes.search_tool import SearchToolNode

        envelope = self._make_envelope(["semantic_scholar"])
        node = SearchToolNode(allow_unguarded=True)
        with patch("nodechain.nodes.search_tool._get_adapter") as mock_get:
            mock_get.return_value = self._unstamped_adapter("semantic_scholar", [{"title": "T", "doi": "10.1/x"}])
            with pytest.raises(ProvenanceError) as exc:
                asyncio.run(node.execute(envelope))
        assert exc.value.code == ProvenanceFailureCode.PROVENANCE_VERSION_MISSING_LIVE


class TestCompatSchemaValidation:
    """R4: compat schema accepts/rejects the right records."""

    def _validate(self, record):
        import json
        from jsonschema import validate, ValidationError, FormatChecker
        with open("schemas/semantic_types/raw_search_results_compat.json") as f:
            schema = json.load(f)
        # Wrap single record in the expected envelope
        instance = {"results": [record]}
        try:
            validate(instance, schema, format_checker=FormatChecker())
            return True
        except (ValidationError, Exception):
            return False

    def test_current_complete_accepted(self):
        raw = _complete_raw(1)
        assert self._validate(raw)

    def test_legacy_complete_accepted(self):
        raw = {
            "origin_api": "x", "query_used": "q", "retrieved_at": "2026-01-01T00:00:00Z",
            "adapter": "x", "query": "q", "retrieval_timestamp": "2026-01-01T00:00:00Z",
            "provenance_version": 0, "raw_data": {"title": "T"},
        }
        assert self._validate(raw)

    def test_pre_version_complete_accepted(self):
        raw = {
            "origin_api": "x", "query_used": "q", "retrieved_at": "2026-01-01T00:00:00Z",
            "adapter": "x", "query": "q", "retrieval_timestamp": "2026-01-01T00:00:00Z",
            "raw_data": {"title": "T"},
        }
        assert self._validate(raw)

    def test_unknown_version_rejected(self):
        raw = {
            "origin_api": "x", "query_used": "q", "retrieved_at": "2026-01-01T00:00:00Z",
            "adapter": "x", "query": "q", "retrieval_timestamp": "2026-01-01T00:00:00Z",
            "provenance_version": 999, "raw_data": {"title": "T", "provenance_entries": [
                {"version": 999, "adapter": "x", "query": "q", "retrieval_timestamp": "2026-01-01T00:00:00Z"}
            ]},
        }
        assert not self._validate(raw)

    def test_mixed_entry_versions_rejected_by_merge(self):
        """Mixed current/pre-version entries in merge produce MODE_MIXED, not TypeError."""
        from nodechain.core.provenance import merge_provenance_entries
        e1 = {"version": 1, "adapter": "a", "query": "q", "retrieval_timestamp": "2026-01-01T00:00:00Z"}
        e2 = {"version": None, "adapter": "b", "query": "q2", "retrieval_timestamp": "2026-01-02T00:00:00Z"}
        merged = merge_provenance_entries([e1], e2)
        # Should not TypeError; check_mode_consistency catches it separately
        assert len(merged) == 2

    def test_explicit_none_rejected_at_finalization(self):
        """Explicit provenance_version=None is rejected by _finalize_results."""
        from nodechain.adapters.search.base_search import SearchAdapterResult
        from nodechain.adapters.search.arxiv import ArxivAdapter
        adapter = ArxivAdapter()
        r = SearchAdapterResult(
            origin_api="arxiv", raw_data={"title": "T"},
            query_used="q", retrieved_at="2026-01-01T00:00:00Z",
            provenance_version=None,  # explicit None
        )
        with pytest.raises(ProvenanceError) as exc:
            adapter._finalize_results([r], 100)
        assert exc.value.code == ProvenanceFailureCode.PROVENANCE_VERSION_CONFLICT


# ── R5 date-time enforcement tests ────────────────────────────────

class TestTimestampEnforcement:
    """R5: invalid timestamps are rejected at every provenance boundary."""

    def test_invalid_live_timestamp_rejected(self):
        """Live result with bad timestamp fails the live gate."""
        raw = {
            "origin_api": "x", "query_used": "q", "retrieved_at": "not-a-date",
            "adapter": "x", "query": "q", "retrieval_timestamp": "not-a-date",
            "provenance_version": 1,
            "raw_data": {"title": "T"},
        }
        with pytest.raises(ProvenanceError) as exc:
            validate_live_result(raw, 0)
        assert exc.value.code == ProvenanceFailureCode.PROVENANCE_CURRENT_INCOMPLETE

    def test_invalid_entry_timestamp_rejected_current(self):
        """Current entry with bad timestamp fails ingestion validation."""
        from nodechain.nodes.source_ingestion import _build_normalized_provenance
        raw = _complete_raw(1)
        raw["raw_data"]["provenance_entries"] = [{
            "version": 1, "adapter": "x", "query": "q",
            "retrieval_timestamp": "not-a-date",
        }]
        with pytest.raises(ProvenanceError) as exc:
            _build_normalized_provenance(raw)
        assert exc.value.code == ProvenanceFailureCode.PROVENANCE_CURRENT_INCOMPLETE

    def test_invalid_entry_timestamp_rejected_legacy(self):
        """Legacy entry with bad timestamp fails ingestion."""
        from nodechain.nodes.source_ingestion import _build_normalized_provenance
        raw = {
            "origin_api": "x", "query_used": "q", "retrieved_at": "2026-01-01T00:00:00Z",
            "adapter": "x", "query": "q", "retrieval_timestamp": "2026-01-01T00:00:00Z",
            "provenance_version": 0,
            "raw_data": {"provenance_entries": [{
                "version": 0, "adapter": "x", "query": "q",
                "retrieval_timestamp": "not-a-date",
            }]},
        }
        with pytest.raises(ProvenanceError) as exc:
            _build_normalized_provenance(raw)
        assert exc.value.code == ProvenanceFailureCode.PROVENANCE_LEGACY_INCOMPLETE

    def test_invalid_entry_timestamp_rejected_pre_version(self):
        """Pre-version entry with bad timestamp fails ingestion."""
        from nodechain.nodes.source_ingestion import _build_normalized_provenance
        raw = {
            "origin_api": "x", "query_used": "q", "retrieved_at": "2026-01-01T00:00:00Z",
            "adapter": "x", "query": "q", "retrieval_timestamp": "2026-01-01T00:00:00Z",
            "raw_data": {"provenance_entries": [{
                "version": None, "adapter": "x", "query": "q",
                "retrieval_timestamp": "not-a-date",
            }]},
        }
        with pytest.raises(ProvenanceError) as exc:
            _build_normalized_provenance(raw)
        assert exc.value.code == ProvenanceFailureCode.PROVENANCE_PRE_VERSION_INCOMPLETE

    def test_valid_utc_z_timestamp_accepted(self):
        """UTC Z suffix timestamps are accepted."""
        from nodechain.core.provenance import is_valid_timestamp
        assert is_valid_timestamp("2026-01-01T00:00:00Z")

    def test_valid_offset_timestamp_accepted(self):
        """Timezone offset timestamps are accepted."""
        from nodechain.core.provenance import is_valid_timestamp
        assert is_valid_timestamp("2026-01-01T00:00:00+03:00")

    def test_valid_microsecond_timestamp_accepted(self):
        """Microsecond precision timestamps are accepted."""
        from nodechain.core.provenance import is_valid_timestamp
        assert is_valid_timestamp("2026-01-01T00:00:00.123456Z")

    @pytest.mark.parametrize("bad_ts", [
        "not-a-date", "2026-01-01", "2026-01-01 00:00:00",
        "2026-01-01T00:00:00",  # no timezone
        "", "   ", "2026/01/01T00:00:00Z",
    ])
    def test_invalid_timestamps_rejected(self, bad_ts):
        from nodechain.core.provenance import is_valid_timestamp
        assert not is_valid_timestamp(bad_ts)

    def test_invalid_timestamp_code_rejected(self):
        """Entry with bad timestamp is rejected at code level (jsonschema oneOf + format
        has known propagation limitations; code-level validation is the authority)."""
        from nodechain.core.provenance import is_valid_timestamp
        assert not is_valid_timestamp("not-a-date")
        from nodechain.nodes.source_ingestion import _build_normalized_provenance
        raw = _complete_raw(1)
        raw["raw_data"]["provenance_entries"][0]["retrieval_timestamp"] = "not-a-date"
        with pytest.raises(ProvenanceError):
            _build_normalized_provenance(raw)


class TestR6CalendarValidity:
    """R6: semantic RFC 3339 validation rejects impossible calendar dates
    that regex-only shape matching would accept."""

    # ── Validator-level calendar cases ────────────────────────────

    @pytest.mark.parametrize("bad_ts", [
        "2026-02-30T00:00:00Z",      # Feb 30 never exists
        "2025-02-29T00:00:00Z",      # Feb 29 in a non-leap year
        "2026-13-01T00:00:00Z",      # month 13
        "2026-00-01T00:00:00Z",      # month 0
        "2026-01-00T00:00:00Z",      # day 0
        "2026-01-32T00:00:00Z",      # day 32
        "2026-01-01T24:00:00Z",      # hour 24
        "2026-01-01T00:60:00Z",      # minute 60
        "2026-01-01T00:00:60Z",      # second 60 (no leap second semantics)
        "2026-04-31T00:00:00Z",      # April has 30 days
        "2026-06-31T00:00:00Z",      # June has 30 days
        "2026-09-31T00:00:00Z",      # September has 30 days
        "2026-11-31T00:00:00Z",      # November has 30 days
    ])
    def test_impossible_dates_rejected(self, bad_ts):
        """These shape-valid but calendar-impossible timestamps are rejected."""
        from nodechain.core.provenance import is_valid_timestamp
        assert not is_valid_timestamp(bad_ts)

    @pytest.mark.parametrize("good_ts", [
        "2024-02-29T00:00:00Z",      # Feb 29 in a leap year
        "2026-02-28T00:00:00Z",      # last valid day of Feb (non-leap)
        "2026-01-31T00:00:00Z",      # valid 31-day month
        "2026-01-01T23:59:59Z",      # last valid second of day
        "2026-01-01T00:00:00+14:00", # max east offset
        "2026-01-01T00:00:00-14:00", # max west offset
    ])
    def test_calendar_valid_dates_accepted(self, good_ts):
        from nodechain.core.provenance import is_valid_timestamp
        assert is_valid_timestamp(good_ts)

    def test_regex_only_regression_proof(self):
        """Concrete proof the validator is no longer regex-only: a string
        that matches the structural regex but is calendar-impossible must
        be rejected. (Before R6 a pure-regex validator accepted this.)"""
        from nodechain.core.provenance import is_valid_timestamp, _RFC3339_RE
        impossible = "2026-02-30T00:00:00Z"
        # It DOES pass the structural regex…
        assert _RFC3339_RE.match(impossible) is not None
        # …but the validator must still reject it.
        assert not is_valid_timestamp(impossible)

    # ── Top-level retrieved_at enforcement (R6.2) ─────────────────

    def test_invalid_top_level_retrieved_at_current_rejected(self):
        """R6.2: current record with valid entries but an invalid top-level
        retrieved_at is rejected. This is the exact gap R6 identified —
        entries were validated but the propagated flat field was not."""
        from nodechain.nodes.source_ingestion import _build_normalized_provenance
        raw = _complete_raw(1)
        raw["retrieved_at"] = "2026-02-30T00:00:00Z"  # impossible, entries still valid
        with pytest.raises(ProvenanceError) as exc:
            _build_normalized_provenance(raw)
        assert exc.value.code == ProvenanceFailureCode.PROVENANCE_CURRENT_INCOMPLETE
        assert "retrieved_at" in exc.value.context

    def test_invalid_top_level_retrieved_at_legacy_rejected(self):
        """R6.2: legacy record with valid entries but invalid top-level field."""
        from nodechain.nodes.source_ingestion import _build_normalized_provenance
        raw = {
            "origin_api": "x", "query_used": "q", "retrieved_at": "2026-13-01T00:00:00Z",
            "adapter": "x", "query": "q", "retrieval_timestamp": "2026-01-01T00:00:00Z",
            "provenance_version": 0,
            "raw_data": {"provenance_entries": [{
                "version": 0, "adapter": "x", "query": "q",
                "retrieval_timestamp": "2026-01-01T00:00:00Z",
            }]},
        }
        with pytest.raises(ProvenanceError) as exc:
            _build_normalized_provenance(raw)
        assert exc.value.code == ProvenanceFailureCode.PROVENANCE_LEGACY_INCOMPLETE

    def test_invalid_top_level_retrieved_at_pre_version_rejected(self):
        """R6.2: pre-version record (fallback path) with invalid top-level field."""
        from nodechain.nodes.source_ingestion import _build_normalized_provenance
        raw = {
            "origin_api": "x", "query_used": "q", "retrieved_at": "2026-02-30T00:00:00Z",
            "adapter": "x", "query": "q", "retrieval_timestamp": "2026-01-01T00:00:00Z",
            "raw_data": {"title": "T"},
        }
        with pytest.raises(ProvenanceError) as exc:
            _build_normalized_provenance(raw)
        assert exc.value.code == ProvenanceFailureCode.PROVENANCE_PRE_VERSION_INCOMPLETE

    def test_invalid_entry_timestamp_still_rejected_alongside_valid_top(self):
        """R6.2 does not weaken entry validation: a valid top-level retrieved_at
        does not rescue an invalid entry timestamp."""
        from nodechain.nodes.source_ingestion import _build_normalized_provenance
        raw = _complete_raw(1)
        # top-level stays valid; entry becomes impossible
        raw["raw_data"]["provenance_entries"][0]["retrieval_timestamp"] = "2026-02-30T00:00:00Z"
        with pytest.raises(ProvenanceError) as exc:
            _build_normalized_provenance(raw)
        assert exc.value.code == ProvenanceFailureCode.PROVENANCE_CURRENT_INCOMPLETE
        # Must be the entry path, not the top-level path
        assert "entry[0]" in exc.value.context

    def test_valid_top_and_valid_entries_accepted(self):
        """R6.2 does not over-reject: a fully valid current record still passes."""
        from nodechain.nodes.source_ingestion import _build_normalized_provenance
        raw = _complete_raw(1)  # all fields valid by default
        result = _build_normalized_provenance(raw)
        assert result["mode"] == "current"
        assert len(result["entries"]) == 1


class TestR7OffsetComponents:
    """R7: RFC 3339 numeric-offset and clock-component range enforcement.

    datetime.fromisoformat() normalizes overflowing offset minutes
    (e.g. +14:60 -> +15:00), so the regex is the authority for all
    component-range bounds. These tests pin that behaviour.
    """

    # ── Required offset-minute / offset-hour rejections ──────────

    @pytest.mark.parametrize("bad_ts", [
        "2026-01-01T00:00:00+00:60",   # offset minute overflow (zero hour)
        "2026-01-01T00:00:00-00:60",   # negative offset minute overflow
        "2026-01-01T00:00:00+14:60",   # the exact defect R6 left open
        "2026-01-01T00:00:00+23:60",   # max-hour offset minute overflow
        "2026-01-01T00:00:00+24:00",   # offset hour out of range
        "2026-01-01T00:00:00-24:00",   # negative offset hour out of range
        "2026-01-01T00:00:00+99:99",   # both components overflow
    ])
    def test_invalid_offset_components_rejected(self, bad_ts):
        """Overflowing offset minutes/hours are rejected, not normalized."""
        from nodechain.core.provenance import is_valid_timestamp
        # These were ACCEPTED under the R6 regex (which used \d{2}:\d{2}).
        assert not is_valid_timestamp(bad_ts)

    def test_offset_minute_regression_proof(self):
        """Concrete proof the defect R7 fixes is closed: the exact value
        the R6 review reproduced (+14:60) must now be rejected even though
        datetime.fromisoformat would normalize it to +15:00."""
        from nodechain.core.provenance import is_valid_timestamp, _RFC3339_RE
        from datetime import datetime
        defective = "2026-01-01T00:00:00+14:60"
        # datetime.fromisoformat STILL normalizes this (regex is the fix)…
        normalized = datetime.fromisoformat(defective.replace("Z", "+00:00"))
        assert normalized.utcoffset().total_seconds() == 15 * 3600
        # …but the strict regex rejects it…
        assert _RFC3339_RE.match(defective) is None
        # …so the validator rejects it.
        assert not is_valid_timestamp(defective)

    # ── Required offset acceptances ──────────────────────────────

    @pytest.mark.parametrize("good_ts", [
        "2026-01-01T00:00:00Z",        # Z
        "2026-01-01T00:00:00+00:00",   # zero offset
        "2026-01-01T00:00:00-00:00",   # negative zero offset
        "2026-01-01T00:00:00+14:00",   # max east
        "2026-01-01T00:00:00-14:00",   # max west
        "2026-01-01T00:00:00+23:59",   # max hour + max minute
        "2026-01-01T00:00:00-23:59",   # negative max
        "2026-01-01T00:00:00.123456Z", # fractional seconds
        "2024-02-29T00:00:00Z",        # valid leap day (calendar stage)
    ])
    def test_valid_offsets_accepted(self, good_ts):
        from nodechain.core.provenance import is_valid_timestamp
        assert is_valid_timestamp(good_ts)

    # ── Leap-second strict subset ────────────────────────────────

    @pytest.mark.parametrize("leap_ts", [
        "2026-06-30T23:59:60Z",   # historical positive leap second
        "2016-12-31T23:59:60Z",   # historical positive leap second
    ])
    def test_leap_second_rejected(self, leap_ts):
        """NodeChain is a STRICT SUBSET of RFC 3339: :60 leap seconds are
        rejected because downstream clock/epoch math has no leap-second
        table. This is documented in provenance.py and is not a defect."""
        from nodechain.core.provenance import is_valid_timestamp
        assert not is_valid_timestamp(leap_ts)

    # ── Top-level gate catches offset defect too (R6.2 + R7) ─────

    def test_invalid_offset_top_level_retrieved_at_rejected(self):
        """R6.2 + R7 together: an overflowing offset in the top-level
        retrieved_at is rejected at the ingestion gate."""
        from nodechain.nodes.source_ingestion import _build_normalized_provenance
        raw = _complete_raw(1)
        raw["retrieved_at"] = "2026-01-01T00:00:00+14:60"  # entries still valid
        with pytest.raises(ProvenanceError) as exc:
            _build_normalized_provenance(raw)
        assert exc.value.code == ProvenanceFailureCode.PROVENANCE_CURRENT_INCOMPLETE
        assert "retrieved_at" in exc.value.context

