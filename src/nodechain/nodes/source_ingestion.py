"""Node 5: Source Ingestion — normalize 5 API schemas into unified SourceRecord."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import (
    EntryContract, ExitContract, NodeContract, Requirements,
)
from nodechain.core.manifest import NodeManifest
from nodechain.core.port import PortType
from nodechain.core.provenance import (
    CURRENT_PROVENANCE_VERSION,
    LEGACY_PROVENANCE_VERSION,
    ProvenanceClassification,
    ProvenanceError,
    ProvenanceFailureCode,
    ProvenanceMode,
    _is_strict_int,
    classify_for_ingestion,
    classification_to_mode,
    is_ingestible,
    is_valid_timestamp,
)
from nodechain.nodes.base_node import BaseNode


def _validate_entry_strict(
    entry: dict[str, Any],
    expected_version: int | None,
    context: str,
) -> None:
    """Strictly validate a single provenance entry.

    Uses the correct failure code for the entry's expected mode.
    """
    # Determine incomplete failure code based on expected version
    if expected_version == CURRENT_PROVENANCE_VERSION:
        incomplete_code = ProvenanceFailureCode.PROVENANCE_CURRENT_INCOMPLETE
    elif expected_version == LEGACY_PROVENANCE_VERSION:
        incomplete_code = ProvenanceFailureCode.PROVENANCE_LEGACY_INCOMPLETE
    else:
        incomplete_code = ProvenanceFailureCode.PROVENANCE_PRE_VERSION_INCOMPLETE

    # Check required fields are non-blank strings
    for f in ("adapter", "query", "retrieval_timestamp"):
        val = entry.get(f)
        if not isinstance(val, str) or val.strip() == "":
            raise ProvenanceError(
                incomplete_code,
                f"{context}: entry field '{f}' missing or non-string",
            )

    # Validate timestamp is RFC 3339 date-time
    if not is_valid_timestamp(entry.get("retrieval_timestamp", "")):
        raise ProvenanceError(
            incomplete_code,
            f"{context}: invalid retrieval_timestamp {entry.get('retrieval_timestamp')!r}",
        )

    # Check version matches expected
    ev = entry.get("version")
    if expected_version is None:
        # Pre-version: entry version must be None
        if ev is not None:
            raise ProvenanceError(
                ProvenanceFailureCode.PROVENANCE_VERSION_CONFLICT,
                f"{context}: pre-version record with entry version {ev}",
            )
    else:
        if not _is_strict_int(ev):
            raise ProvenanceError(
                ProvenanceFailureCode.PROVENANCE_VERSION_MALFORMED,
                f"{context}: entry version not a strict int: {ev!r}",
            )
        if ev != expected_version:
            raise ProvenanceError(
                ProvenanceFailureCode.PROVENANCE_MODE_MIXED,
                f"{context}: entry version {ev} != expected {expected_version}",
            )


def _build_normalized_provenance(raw: dict[str, Any]) -> dict[str, Any]:
    """Build normalized provenance from a raw search result.

    Applies compatibility decoding on the raw dictionary before any
    Pydantic defaults. Validates all authoritative entries strictly.
    """
    c = classify_for_ingestion(raw)
    if not is_ingestible(c):
        # Map classification to correct failure code
        if c == ProvenanceClassification.MALFORMED_VERSION:
            code = ProvenanceFailureCode.PROVENANCE_VERSION_MALFORMED
        elif c == ProvenanceClassification.UNKNOWN_VERSION:
            code = ProvenanceFailureCode.PROVENANCE_VERSION_UNKNOWN
        elif c == ProvenanceClassification.CURRENT_INCOMPLETE:
            code = ProvenanceFailureCode.PROVENANCE_CURRENT_INCOMPLETE
        elif c == ProvenanceClassification.LEGACY_INCOMPLETE:
            code = ProvenanceFailureCode.PROVENANCE_LEGACY_INCOMPLETE
        elif c == ProvenanceClassification.PRE_VERSION_INCOMPLETE:
            code = ProvenanceFailureCode.PROVENANCE_PRE_VERSION_INCOMPLETE
        else:
            code = ProvenanceFailureCode.PROVENANCE_VERSION_MALFORMED
        raise ProvenanceError(code, f"ingestion rejected: {c.value}")

    mode = classification_to_mode(c)

    if c in (ProvenanceClassification.CURRENT_COMPLETE,):
        norm_version = CURRENT_PROVENANCE_VERSION
    elif c == ProvenanceClassification.LEGACY_COMPLETE:
        norm_version = LEGACY_PROVENANCE_VERSION
    else:
        norm_version = None  # pre_version

    # Determine incomplete failure code based on expected version
    if norm_version == CURRENT_PROVENANCE_VERSION:
        incomplete_code = ProvenanceFailureCode.PROVENANCE_CURRENT_INCOMPLETE
    elif norm_version == LEGACY_PROVENANCE_VERSION:
        incomplete_code = ProvenanceFailureCode.PROVENANCE_LEGACY_INCOMPLETE
    else:
        incomplete_code = ProvenanceFailureCode.PROVENANCE_PRE_VERSION_INCOMPLETE

    # R6: Validate the top-level retrieved_at for EVERY ingestible record.
    # The flat retrieved_at is propagated to the output (retrieval_timestamp)
    # regardless of whether provenance_entries are present, so it must be a
    # semantically valid RFC 3339 timestamp here — including for records that
    # already carry validated entries.
    retrieved_at = raw.get("retrieved_at", "")
    if not is_valid_timestamp(retrieved_at):
        raise ProvenanceError(
            incomplete_code,
            f"invalid top-level retrieved_at: {retrieved_at!r}",
        )

    # Build and validate entries
    entries: list[dict[str, Any]] = []
    raw_data = raw.get("raw_data", {})
    entries_key_present = "provenance_entries" in raw_data
    raw_entries = raw_data.get("provenance_entries")

    if entries_key_present:
        # Key is present — must be non-empty list of objects
        if not isinstance(raw_entries, list):
            raise ProvenanceError(
                ProvenanceFailureCode.PROVENANCE_VERSION_MALFORMED,
                f"provenance_entries is not a list: {type(raw_entries).__name__}",
            )
        if len(raw_entries) == 0:
            raise ProvenanceError(
                incomplete_code,
                "provenance_entries is explicitly empty",
            )
        for i, e in enumerate(raw_entries):
            if not isinstance(e, dict):
                raise ProvenanceError(
                    ProvenanceFailureCode.PROVENANCE_VERSION_MALFORMED,
                    f"entry[{i}] is not an object",
                )
            _validate_entry_strict(e, norm_version, f"entry[{i}]")
            entries.append({
                "version": e["version"],
                "adapter": e["adapter"],
                "query": e["query"],
                "retrieval_timestamp": e["retrieval_timestamp"],
            })
    elif c == ProvenanceClassification.CURRENT_COMPLETE:
        # Current version MUST have provenance_entries — no fallback allowed
        raise ProvenanceError(
            ProvenanceFailureCode.PROVENANCE_CURRENT_INCOMPLETE,
            "current record missing provenance_entries (no fallback for current)",
        )
    else:
        # Legacy or pre-version: bounded flat-field fallback may synthesize
        entry = {
            "version": norm_version,
            "adapter": raw.get("origin_api", ""),
            "query": raw.get("query_used", ""),
            "retrieval_timestamp": raw.get("retrieved_at", ""),
        }
        _validate_entry_strict(entry, norm_version, "top-level")
        entries.append(entry)

    # Deduplicate and sort canonically
    seen_keys: set[tuple] = set()
    deduped: list[dict[str, Any]] = []
    for e in entries:
        key = (e["version"], e["adapter"], e["query"], e["retrieval_timestamp"])
        if key not in seen_keys:
            seen_keys.add(key)
            deduped.append(e)
    entries = sorted(deduped, key=lambda e: (
        e.get("version") if e.get("version") is not None else -1,
        e.get("adapter", ""),
        e.get("query", ""),
        e.get("retrieval_timestamp", ""),
    ))

    return {
        "mode": mode.value,
        "version": norm_version,
        "entries": entries,
        # Backward-compatible flat fields
        "adapter": raw.get("origin_api", ""),
        "query": raw.get("query_used", ""),
        "retrieval_timestamp": raw.get("retrieved_at", ""),
    }


SOURCE_INGESTION_CONTRACT = NodeContract(
    contract_id="research.source-ingestion.v1",
    node_id="source_ingestion",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.RAW_SEARCH_RESULTS,
        schema_ref="nodechain://schemas/semantic_types/raw_search_results_compat",
        required_fields=["results"],
    ),
    exit=ExitContract(
        output_type=PortType.SOURCE_SET,
        schema_ref="nodechain://schemas/semantic_types/source_set",
        guaranteed_fields=["sources", "ingestion_stats"],
    ),
    requirements=Requirements(
        model_required=False,
    ),
)


def _normalize_semantic_scholar(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize Semantic Scholar result.
    Handles both adapter-normalized (snake_case) and raw API (camelCase) fields.
    """
    # Support both camelCase from raw API and snake_case from adapter
    ext_ids = raw.get("external_ids", {})
    doi = ext_ids.get("DOI", "") if isinstance(ext_ids, dict) else ""
    pub_types = raw.get("publication_types") or raw.get("publicationTypes") or []
    source_type = "journal_article"
    if "Review" in pub_types or "review" in str(pub_types).lower():
        source_type = "review"
    elif "Conference" in pub_types or "conference" in str(pub_types).lower():
        source_type = "conference"

    # Authors can be list of strings or list of dicts with 'name'
    raw_authors = raw.get("authors", [])
    authors = []
    for a in raw_authors:
        if isinstance(a, str):
            authors.append(a)
        elif isinstance(a, dict):
            authors.append(a.get("name", ""))

    citation_count = raw.get("citation_count", raw.get("citationCount", 0))
    influential = raw.get("influential_citation_count", raw.get("influentialCitationCount", 0))
    reference_count = raw.get("reference_count", raw.get("referenceCount", 0))
    open_access = raw.get("open_access", raw.get("isOpenAccess", False))
    pdf_data = raw.get("openAccessPdf") or {}
    pdf_url = pdf_data.get("url", "") if isinstance(pdf_data, dict) else raw.get("pdf_url", "")
    fields = raw.get("fields_of_study", raw.get("fieldsOfStudy", []))
    pub_date = raw.get("publication_date", raw.get("publicationDate", "")) or str(raw.get("year", ""))

    return {
        "title": raw.get("title", ""),
        "authors": authors,
        "publication_date": str(pub_date),
        "doi": doi,
        "abstract": raw.get("abstract", ""),
        "source_type": source_type,
        "peer_reviewed": source_type == "journal_article",
        "citation_count": citation_count,
        "venue": raw.get("venue", ""),
        "subject_areas": fields if isinstance(fields, list) else [],
        "open_access": bool(open_access),
        "pdf_url": pdf_url,
        "credibility_signals": {
            "influential_citation_count": influential,
            "reference_count": reference_count,
        },
    }


def _normalize_arxiv(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize arXiv result."""
    return {
        "title": raw.get("title", ""),
        "authors": raw.get("authors", []),
        "publication_date": raw.get("published", ""),
        "doi": raw.get("doi", ""),
        "abstract": raw.get("abstract", ""),
        "source_type": "preprint",
        "peer_reviewed": False,
        "citation_count": 0,
        "venue": "arXiv",
        "subject_areas": raw.get("categories", []),
        "open_access": True,
        "pdf_url": raw.get("pdf_url", ""),
        "credibility_signals": {
            "arxiv_id": raw.get("arxiv_id", ""),
            "comment": raw.get("comment", ""),
        },
    }


def _normalize_openalex(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize OpenAlex result."""
    return {
        "title": raw.get("title", ""),
        "authors": raw.get("authors", []),
        "publication_date": raw.get("publication_date", ""),
        "doi": raw.get("doi", ""),
        "abstract": raw.get("abstract", ""),  # OpenAlex adapter already reconstructs from inverted index
        "source_type": raw.get("source_type", "other"),
        "peer_reviewed": raw.get("source_type") == "journal_article",
        "citation_count": raw.get("cited_by_count", 0),
        "venue": raw.get("venue", ""),
        "subject_areas": list(raw.get("concepts", {}).keys()),
        "open_access": raw.get("is_oa", False),
        "pdf_url": raw.get("oa_url", ""),
        "credibility_signals": {
            "concepts": raw.get("concepts", {}),
            "topics": raw.get("topics", []),
            "institutions": raw.get("institutions", []),
            "referenced_works_count": raw.get("referenced_works_count", 0),
        },
    }


def _normalize_crossref(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize CrossRef result."""
    pub_date = raw.get("publication_date", [])
    date_str = "-".join(str(p) for p in pub_date) if pub_date else ""

    return {
        "title": raw.get("title", ""),
        "authors": raw.get("authors", []),
        "publication_date": date_str,
        "doi": raw.get("doi", ""),
        "abstract": raw.get("abstract", ""),
        "source_type": raw.get("source_type", "other"),
        "peer_reviewed": raw.get("source_type") == "journal_article",
        "citation_count": raw.get("is_referenced_by_count", 0),
        "venue": raw.get("venue", ""),
        "subject_areas": raw.get("subject", []),
        "open_access": bool(raw.get("license_types")),
        "pdf_url": "",
        "credibility_signals": {
            "publisher": raw.get("publisher", ""),
            "is_retracted": raw.get("is_retracted", False),
            "issns": raw.get("issns", []),
            "references_count": raw.get("references_count", 0),
        },
    }


def _normalize_pubmed(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize PubMed result."""
    return {
        "title": raw.get("title", ""),
        "authors": raw.get("authors", []),
        "publication_date": raw.get("pub_date", ""),
        "doi": raw.get("doi", ""),
        "abstract": raw.get("abstract", ""),
        "source_type": "journal_article",
        "peer_reviewed": True,
        "citation_count": 0,
        "venue": raw.get("journal", ""),
        "subject_areas": raw.get("mesh_terms", []),
        "open_access": False,
        "pdf_url": "",
        "credibility_signals": {
            "pmid": raw.get("pmid", ""),
            "mesh_terms": raw.get("mesh_terms", []),
            "pub_types": raw.get("pub_types", []),
            "keywords": raw.get("keywords", []),
        },
    }


def _normalize_fixture(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize a sealed-fixture result.

    Fixture results carry the exact sealed-corpus identifiers (source_id,
    source_hash) plus the content fields (title, authors, abstract, doi).
    This normalizer preserves those identifiers so the ingested source record
    is traceable to the declared corpus source.

    Required fields: source_id, source_hash, title, authors, abstract.
    Fail closed if any is missing or has the wrong type — do not invent
    identifiers, hashes, or content.
    """
    source_id = raw.get("source_id", "")
    source_hash = raw.get("source_hash", "")
    title = raw.get("title", "")
    authors = raw.get("authors")
    abstract = raw.get("abstract")

    # Validate required fields exist.
    if not source_id or not isinstance(source_id, str):
        raise ValueError("fixture result missing or invalid source_id")
    if not source_hash or not isinstance(source_hash, str):
        raise ValueError("fixture result missing or invalid source_hash")
    if not title or not isinstance(title, str):
        raise ValueError("fixture result missing or invalid title")
    if authors is None:
        raise ValueError("fixture result missing authors")
    # Accept both list and tuple (the corpus model stores tuple[str,...]).
    if isinstance(authors, (list, tuple)):
        authors = list(authors)
    if not isinstance(authors, list) or not all(isinstance(a, str) for a in authors):
        raise ValueError(
            f"fixture result invalid authors (expected list[str])"
        )
    if abstract is None or not isinstance(abstract, str):
        raise ValueError(
            f"fixture result missing or invalid abstract (expected str)"
        )

    # Validate source_hash is exactly lowercase [0-9a-f]{64}.
    import re
    if not re.match(r'^[0-9a-f]{64}$', source_hash):
        raise ValueError(
            f"fixture source_hash must be exactly 64 lowercase hex chars, "
            f"got {source_hash[:20]}..."
        )

    # Recompute the canonical content hash and reject mismatch.
    import hashlib as _hl
    import json as _json
    content_fields = {
        "source_id": source_id,
        "title": title,
        "authors": list(authors),
        "abstract": abstract,
        "doi": raw.get("doi", "") or "",
    }
    canonical = _json.dumps(content_fields, sort_keys=True, separators=(",", ":"))
    expected_hash = _hl.sha256(canonical.encode("utf-8")).hexdigest()
    if source_hash != expected_hash:
        raise ValueError(
            f"fixture source_hash mismatch: expected {expected_hash}, "
            f"got {source_hash}"
        )

    # Validate optional field types if supplied.
    source_type = raw.get("source_type", "other")
    valid_source_types = {"journal_article", "preprint", "conference", "review", "book", "thesis", "other"}
    if source_type not in valid_source_types:
        raise ValueError(
            f"fixture source_type {source_type!r} not in {sorted(valid_source_types)}"
        )

    return {
        "source_id": source_id,
        "source_hash": source_hash,
        "title": title,
        "authors": list(authors),
        "publication_date": raw.get("publication_date", ""),
        "doi": raw.get("doi", ""),
        "abstract": abstract,
        "source_type": source_type,
        "peer_reviewed": raw.get("peer_reviewed", False),
        "citation_count": raw.get("citation_count", 0),
        "venue": raw.get("venue", "Sealed Fixture Corpus"),
        "subject_areas": raw.get("subject_areas", []),
        "open_access": raw.get("open_access", True),
        "pdf_url": raw.get("pdf_url", ""),
        "credibility_signals": raw.get("credibility_signals", {
            "fixture_source_id": source_id,
            "fixture_source_hash": source_hash,
        }),
    }


NORMALIZERS = {
    "semantic_scholar": _normalize_semantic_scholar,
    "arxiv": _normalize_arxiv,
    "openalex": _normalize_openalex,
    "crossref": _normalize_crossref,
    "pubmed": _normalize_pubmed,
    "fixture": _normalize_fixture,
}


class SourceIngestionNode(BaseNode):
    """
    Node 5: Data transformer. Normalizes all API schemas into
    unified SourceRecord without losing origin-specific signals.
    """

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="source_ingestion",
            node_type="deterministic",
            name="Source Ingestion",
            description="Normalizes multi-API search results into unified SourceRecord schema.",
            contract=SOURCE_INGESTION_CONTRACT,
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        raw_results = envelope.payload.get("results", [])
        sources: list[dict[str, Any]] = []
        seen_titles: set[str] = set()
        by_origin: dict[str, int] = {}

        for raw in raw_results:
            # FPV1: validate provenance BEFORE any content-quality filtering
            provenance = _build_normalized_provenance(raw)

            origin = raw.get("origin_api", "")
            raw_data = raw.get("raw_data", {})

            normalizer = NORMALIZERS.get(origin)
            if normalizer is None:
                continue

            normalized = normalizer(raw_data)
            title = (normalized.get("title", "") or "").strip().lower()

            if not title:
                continue  # Skip sources with no title

            # Deduplicate by title
            title_hash = hashlib.md5(title.encode()).hexdigest()
            if title_hash in seen_titles:
                continue
            seen_titles.add(title_hash)

            source_record = {
                "source_id": str(uuid.uuid4()),
                "origin_api": origin,
                **normalized,
                "provenance": provenance,
            }

            sources.append(source_record)
            by_origin[origin] = by_origin.get(origin, 0) + 1

        # Normalize None values to empty strings for schema compliance
        for s in sources:
            if s.get("abstract") is None:
                s["abstract"] = ""
                s["abstract_available"] = False
            else:
                s["abstract_available"] = bool(s.get("abstract"))

        output = {
            "sources": sources,
            "ingestion_stats": {
                "total_raw": len(raw_results),
                "total_normalized": len(sources),
                "duplicates_removed": len(raw_results) - len(sources),
                "by_origin": by_origin,
            },
        }

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="source_ingestion",
            step_id=envelope.step_id,
            output=output,
            output_type=PortType.SOURCE_SET,
        )
