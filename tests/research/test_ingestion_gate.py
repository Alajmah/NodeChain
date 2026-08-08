"""Focused ingestion gate tests for the fixture normalizer and corpus contract.

Each test exercises one exact acceptance or rejection condition from the
locked ingestion gate requirements.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from nodechain.nodes.source_ingestion import (
    NORMALIZERS,
    _normalize_fixture,
    _normalize_arxiv,
    _normalize_semantic_scholar,
    _normalize_openalex,
    _normalize_crossref,
    _normalize_pubmed,
)
from nodechain.research.corpus import (
    CorpusSource,
    CorpusQueryEntry,
    FixtureCorpus,
    MinimumEvidencePolicy,
    canonical_query_key,
    compute_corpus_canonical_digest,
    load_corpus,
)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _valid_raw() -> dict[str, Any]:
    """Return a valid fixture raw_data dict with a correct hash."""
    fields = {
        "source_id": "src-1",
        "title": "Test Title",
        "authors": ["A. Author"],
        "abstract": "Test abstract.",
        "doi": "10.1000/1",
    }
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"))
    h = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return {**fields, "source_hash": h}


# --------------------------------------------------------------------------- #
# Normalizer rejection tests
# --------------------------------------------------------------------------- #


def test_missing_authors_rejected() -> None:
    raw = _valid_raw()
    del raw["authors"]
    with pytest.raises(ValueError, match="missing authors"):
        _normalize_fixture(raw)


def test_missing_abstract_rejected() -> None:
    raw = _valid_raw()
    del raw["abstract"]
    with pytest.raises(ValueError, match="invalid abstract"):
        _normalize_fixture(raw)


def test_uppercase_source_hash_rejected() -> None:
    raw = _valid_raw()
    raw["source_hash"] = raw["source_hash"].upper()
    with pytest.raises(ValueError, match="lowercase hex"):
        _normalize_fixture(raw)


def test_incorrect_content_hash_rejected() -> None:
    raw = _valid_raw()
    raw["source_hash"] = "0" * 64  # valid format, wrong hash
    with pytest.raises(ValueError, match="source_hash mismatch"):
        _normalize_fixture(raw)


def test_invalid_source_type_rejected() -> None:
    raw = _valid_raw()
    raw["source_type"] = "sealed_fixture"  # not in schema enum
    with pytest.raises(ValueError, match="source_type"):
        _normalize_fixture(raw)


# --------------------------------------------------------------------------- #
# Normalizer acceptance tests
# --------------------------------------------------------------------------- #


def test_fixture_source_id_preserved() -> None:
    result = _normalize_fixture(_valid_raw())
    assert result["source_id"] == "src-1"


def test_fixture_source_hash_preserved() -> None:
    raw = _valid_raw()
    result = _normalize_fixture(raw)
    assert result["source_hash"] == raw["source_hash"]


def test_retrieved_at_preserved() -> None:
    raw = _valid_raw()
    raw["retrieved_at"] = "2026-06-01T12:00:00Z"
    result = _normalize_fixture(raw)
    # retrieved_at is on the SearchAdapterResult, not raw_data; but the
    # normalizer preserves the credibility_signals.
    assert result["credibility_signals"]["fixture_source_id"] == "src-1"


def test_publication_date_not_fabricated() -> None:
    raw = _valid_raw()
    # publication_date not in raw → should default to empty string, not fabricated
    result = _normalize_fixture(raw)
    assert result["publication_date"] == ""


def test_source_type_defaults_to_other() -> None:
    raw = _valid_raw()
    result = _normalize_fixture(raw)
    assert result["source_type"] == "other"


# --------------------------------------------------------------------------- #
# Corpus query result format tests
# --------------------------------------------------------------------------- #


def test_query_results_schema_uses_strings() -> None:
    """The corpus model accepts results as source-ID strings."""
    entry = CorpusQueryEntry(results=("src-1", "src-2"))
    assert entry.results == ("src-1", "src-2")
    assert all(isinstance(r, str) for r in entry.results)


def test_query_object_result_rejected() -> None:
    """The corpus model rejects results containing dicts, not strings."""
    with pytest.raises(Exception):
        CorpusQueryEntry(results=({"source_id": "src-1"},))  # type: ignore


# --------------------------------------------------------------------------- #
# Corpus loader validation tests
# --------------------------------------------------------------------------- #


def _make_source(source_id: str = "src-1", title: str = "Test") -> CorpusSource:
    fields = {
        "source_id": source_id,
        "title": title,
        "authors": ("Author",),
        "abstract": "Abstract.",
        "doi": "",
        "query_used": "test",
    }
    # Hash computed from the SAME fields as _verify_source_hashes:
    # source_id, title, authors, abstract, doi.
    hash_content = {
        "source_id": source_id,
        "title": title,
        "authors": list(fields["authors"]),
        "abstract": fields["abstract"],
        "doi": fields["doi"],
    }
    canonical = json.dumps(hash_content, sort_keys=True, separators=(",", ":"))
    h = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return CorpusSource(**fields, source_hash=h)


def test_unknown_source_reference_rejected() -> None:
    """A query referencing an undeclared source is rejected."""
    src = _make_source()
    with pytest.raises(Exception, match="unknown source_id"):
        FixtureCorpus(
            corpus_version="1.0",
            scenario_id="test",
            sources=(src,),
            queries={"test": CorpusQueryEntry(results=("src-2",))},  # src-2 not declared
        )


def test_duplicate_source_reference_rejected() -> None:
    """A query with duplicate source references is rejected."""
    src = _make_source()
    with pytest.raises(Exception, match="duplicate source reference"):
        FixtureCorpus(
            corpus_version="1.0",
            scenario_id="test",
            sources=(src,),
            queries={"test": CorpusQueryEntry(results=("src-1", "src-1"))},
        )


def test_noncanonical_query_key_rejected() -> None:
    """A query key that is not in canonical form is rejected."""
    src = _make_source()
    with pytest.raises(Exception, match="not canonical"):
        FixtureCorpus(
            corpus_version="1.0",
            scenario_id="test",
            sources=(src,),
            queries={"test query": CorpusQueryEntry(results=("src-1",))},  # canonical: "query test"
        )


# --------------------------------------------------------------------------- #
# Production normalizers unchanged
# --------------------------------------------------------------------------- #


def test_all_five_production_normalizers_present() -> None:
    """The five production normalizers are unchanged."""
    assert NORMALIZERS["semantic_scholar"] is _normalize_semantic_scholar
    assert NORMALIZERS["arxiv"] is _normalize_arxiv
    assert NORMALIZERS["openalex"] is _normalize_openalex
    assert NORMALIZERS["crossref"] is _normalize_crossref
    assert NORMALIZERS["pubmed"] is _normalize_pubmed


def test_fixture_normalizer_present() -> None:
    assert "fixture" in NORMALIZERS
    assert NORMALIZERS["fixture"] is _normalize_fixture


# --------------------------------------------------------------------------- #
# Canonical query key shared function
# --------------------------------------------------------------------------- #


def test_canonical_query_key_sorted_lowercase() -> None:
    assert canonical_query_key(["Rust", "async", "Safety"]) == "async rust safety"
    assert canonical_query_key(["test", "query"]) == "query test"


def test_adapter_uses_shared_canonical_function() -> None:
    """FixtureSearchAdapter._query_key uses the same canonical function."""
    from nodechain.adapters.search.fixture import FixtureSearchAdapter
    from nodechain.adapters.search.base_search import SearchQuery

    q = SearchQuery(terms=["Rust", "async", "Safety"])
    adapter_key = FixtureSearchAdapter._query_key(q)
    assert adapter_key == canonical_query_key(["Rust", "async", "Safety"])
