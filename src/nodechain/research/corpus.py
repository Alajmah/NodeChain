"""Sealed fixture-corpus contract and loader for governed research runs.

The corpus is the deterministic input substrate for a sealed research run.
It provides:

* corpus version
* scenario identifiers
* stable source identifiers
* source-content SHA-256 values
* deterministic query mappings (query-key → fixture results)
* retrieval metadata
* minimum-evidence policy
* fault-injection configuration

Authoring format: YAML (human-readable). The loader uses ``yaml.safe_load``,
rejects unknown fields via a strict pydantic model, normalizes the content to
canonical JSON, and records the canonical digest before execution.

The canonical digest is the SHA-256 of the canonical-JSON serialization of
the normalized corpus (sorted keys, compact separators). It is stable across
dict insertion order and is recorded as ``input_digest`` on the run manifest.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from typing import Literal


# --------------------------------------------------------------------------- #
# Canonical query key (shared with FixtureSearchAdapter)
# --------------------------------------------------------------------------- #


def canonical_query_key(terms: list[str]) -> str:
    """Compute the canonical query key: lowercase, trimmed, single-space
    separated, sorted tokens.

    This MUST match FixtureSearchAdapter._query_key() exactly. Both use this
    shared function so they cannot drift.
    """
    return " ".join(sorted(t.lower().strip() for t in terms if isinstance(t, str) and t.strip()))


# --------------------------------------------------------------------------- #
# Corpus models (strict — extra='forbid')
# --------------------------------------------------------------------------- #


class CorpusSource(BaseModel):
    """A single source in the sealed corpus."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_id: str
    origin_api: Literal["fixture"] = "fixture"
    query_used: str
    retrieved_at: str = "2026-01-01T00:00:00Z"
    title: str = ""
    doi: str | None = None
    authors: tuple[str, ...] = ()
    abstract: str = ""
    source_hash: str  # SHA-256 of source content


class CorpusQueryEntry(BaseModel):
    """A deterministic query mapping: query-key → source references + fault.

    Each result references exactly one declared source by ID. The
    corpus_to_fixture_map() expands these references from the authoritative
    sources collection.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    results: tuple[str, ...] = ()  # source IDs referencing declared CorpusSource entries
    fault: str | None = Field(default=None, alias="_fault")
    # partial_result_set structural metadata (used when fault == partial_result_set)
    total_available: int | None = None
    unavailable_source_ids: tuple[str, ...] = ()
    incompleteness_reason: str | None = None

    @model_validator(mode="after")
    def _validate_fault(self) -> "CorpusQueryEntry":
        if self.fault is not None:
            allowed = {
                "timeout_after_dispatch",
                "malformed_provenance",
                "partial_result_set",
            }
            if self.fault not in allowed:
                raise ValueError(
                    f"corpus fault must be one of {sorted(allowed)}, "
                    f"got {self.fault!r}"
                )
        return self


class MinimumEvidencePolicy(BaseModel):
    """Policy governing minimum evidence thresholds for a sealed run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    min_sources: int = 1
    min_evidence_per_claim: int = 1
    min_confidence: float = 0.0


class FaultInjectionConfig(BaseModel):
    """Configuration for fault-injection lanes in a sealed run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    # Lane-level fail_before_dispatch: scenario_id → True
    # Implemented in the WorkspaceRunner's lane-admission layer, NOT in the
    # adapter.
    fail_before_dispatch_lanes: tuple[str, ...] = ()


class FixtureCorpus(BaseModel):
    """The sealed fixture corpus contract."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    corpus_version: str
    scenario_id: str
    description: str = ""
    sources: tuple[CorpusSource, ...] = ()
    # query_key → entry. The key is the lowercased, sorted, space-joined terms.
    queries: dict[str, CorpusQueryEntry] = Field(default_factory=dict)
    minimum_evidence: MinimumEvidencePolicy = Field(
        default_factory=MinimumEvidencePolicy
    )
    fault_injection: FaultInjectionConfig = Field(
        default_factory=FaultInjectionConfig
    )

    @field_validator("corpus_version", "scenario_id")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("must be non-empty")
        return v

    @model_validator(mode="after")
    def _source_hashes_are_sha256(self) -> "FixtureCorpus":
        for src in self.sources:
            if len(src.source_hash) != 64:
                raise ValueError(
                    f"source {src.source_id} source_hash must be SHA-256 (64 hex chars)"
                )
            try:
                int(src.source_hash, 16)
            except ValueError as exc:
                raise ValueError(
                    f"source {src.source_id} source_hash must be hex"
                ) from exc
        return self

    @model_validator(mode="after")
    def _validate_source_references(self) -> "FixtureCorpus":
        """Enforce that query results reference declared sources, source IDs
        are unique, and no duplicate references within a query."""
        source_ids = [s.source_id for s in self.sources]
        # Source IDs must be unique.
        if len(source_ids) != len(set(source_ids)):
            seen: set[str] = set()
            for sid in source_ids:
                if sid in seen:
                    raise ValueError(f"duplicate source_id: {sid}")
                seen.add(sid)
        declared = set(source_ids)
        for query_key, entry in self.queries.items():
            seen_in_query: set[str] = set()
            for ref in entry.results:
                if ref not in declared:
                    raise ValueError(
                        f"query {query_key!r} references unknown source_id {ref!r}"
                    )
                if ref in seen_in_query:
                    raise ValueError(
                        f"query {query_key!r} has duplicate source reference {ref!r}"
                    )
                seen_in_query.add(ref)
            # unavailable_source_ids must also reference declared sources
            for sid in entry.unavailable_source_ids:
                if sid not in declared:
                    raise ValueError(
                        f"query {query_key!r} unavailable_source_ids references "
                        f"unknown source_id {sid!r}"
                    )
        return self

    @model_validator(mode="after")
    def _verify_source_hashes(self) -> "FixtureCorpus":
        """Verify each source_hash equals the SHA-256 of the canonical source
        content (title, authors, abstract, doi)."""
        import hashlib

        for src in self.sources:
            content_fields = {
                "source_id": src.source_id,
                "title": src.title,
                "authors": list(src.authors),
                "abstract": src.abstract,
                "doi": src.doi or "",
            }
            canonical = json.dumps(
                content_fields, sort_keys=True, separators=(",", ":")
            )
            expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            if src.source_hash != expected:
                raise ValueError(
                    f"source {src.source_id} source_hash mismatch: "
                    f"expected {expected}, got {src.source_hash}"
                )
        return self

    @model_validator(mode="after")
    def _validate_canonical_query_keys(self) -> "FixtureCorpus":
        """Reject query keys that are not in canonical form (lowercase, trimmed,
        single-space separated, sorted tokens). Noncanonical keys caused the
        capsule digest mismatch — this validator prevents recurrence."""
        for query_key in self.queries:
            # The canonical form is computed from the key split on whitespace.
            tokens = query_key.split()
            expected_key = canonical_query_key(tokens)
            if query_key != expected_key:
                raise ValueError(
                    f"query key {query_key!r} is not canonical; "
                    f"expected {expected_key!r}"
                )
        return self


# --------------------------------------------------------------------------- #
# Canonical digest
# --------------------------------------------------------------------------- #


def _to_serializable(obj: Any) -> Any:
    """Recursively convert pydantic models / tuples to JSON-native types."""
    if isinstance(obj, BaseModel):
        return _to_serializable(obj.model_dump(mode="json", by_alias=True))
    if isinstance(obj, dict):
        return {k: _to_serializable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_serializable(v) for v in obj]
    return obj


def compute_corpus_canonical_digest(corpus: FixtureCorpus | dict[str, Any]) -> str:
    """Compute the canonical SHA-256 digest of a corpus.

    The corpus is serialized with sorted keys and compact separators so the
    digest is stable regardless of dict insertion order.
    """
    if isinstance(corpus, FixtureCorpus):
        data = _to_serializable(corpus)
    else:
        data = _to_serializable(dict(corpus))
    payload = json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Loader
# --------------------------------------------------------------------------- #


class CorpusLoaderError(Exception):
    """Raised when a fixture corpus cannot be loaded or validated."""


def load_corpus(path: str | Path) -> FixtureCorpus:
    """Load and validate a fixture corpus from a YAML file.

    Uses ``yaml.safe_load`` (never ``yaml.load``). Unknown fields are rejected
    by the strict pydantic model. Returns the validated, frozen corpus.

    Raises :class:`CorpusLoaderError` on any read, parse, or validation error.
    """
    path = Path(path)
    if not path.exists():
        raise CorpusLoaderError(f"corpus file not found: {path}")
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CorpusLoaderError(f"cannot read corpus file {path}: {exc}") from exc
    try:
        raw_doc = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise CorpusLoaderError(f"YAML parse error in {path}: {exc}") from exc
    if raw_doc is None:
        raise CorpusLoaderError(f"corpus file is empty: {path}")
    if not isinstance(raw_doc, dict):
        raise CorpusLoaderError(
            f"corpus root must be a mapping, got {type(raw_doc).__name__}"
        )
    try:
        return FixtureCorpus(**raw_doc)
    except Exception as exc:
        raise CorpusLoaderError(
            f"corpus validation failed for {path}: {exc}"
        ) from exc


def corpus_to_fixture_map(corpus: FixtureCorpus) -> dict[str, Any]:
    """Convert a validated FixtureCorpus into the dict format expected by
    FixtureSearchAdapter.

    Each query's source-ID references are expanded from the authoritative
    ``sources`` collection into full adapter ``raw_data`` dicts, including
    source_id, source_hash, title, authors, abstract, doi, publication_date.
    There is one authoritative source-content copy (the ``sources``
    collection); query results reference it by ID and are expanded here.
    """
    # Build authoritative source lookup.
    sources_by_id: dict[str, CorpusSource] = {s.source_id: s for s in corpus.sources}

    out: dict[str, Any] = {}
    for key, entry in corpus.queries.items():
        entry_dict: dict[str, Any] = {}

        # Expand source-ID references into full raw_data dicts.
        expanded_results: list[dict[str, Any]] = []
        for source_id in entry.results:
            src = sources_by_id[source_id]
            expanded_results.append({
                "origin_api": "fixture",
                "source_id": src.source_id,
                "source_hash": src.source_hash,
                "title": src.title,
                "authors": list(src.authors),
                "abstract": src.abstract,
                "doi": src.doi or "",
                "retrieved_at": src.retrieved_at,
                "publication_date": "",  # not fabricated — separate from retrieval
                "query_used": key,
            })
        entry_dict["results"] = expanded_results

        if entry.fault:
            entry_dict["_fault"] = entry.fault
        if entry.total_available is not None:
            entry_dict["total_available"] = entry.total_available
        if entry.unavailable_source_ids:
            entry_dict["unavailable_source_ids"] = list(entry.unavailable_source_ids)
        if entry.incompleteness_reason:
            entry_dict["incompleteness_reason"] = entry.incompleteness_reason
        out[key] = entry_dict
    return out
