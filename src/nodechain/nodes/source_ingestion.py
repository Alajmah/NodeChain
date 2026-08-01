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
from nodechain.nodes.base_node import BaseNode


SOURCE_INGESTION_CONTRACT = NodeContract(
    contract_id="research.source-ingestion.v1",
    node_id="source_ingestion",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.RAW_SEARCH_RESULTS,
        schema_ref="nodechain://schemas/semantic_types/raw_search_results",
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


NORMALIZERS = {
    "semantic_scholar": _normalize_semantic_scholar,
    "arxiv": _normalize_arxiv,
    "openalex": _normalize_openalex,
    "crossref": _normalize_crossref,
    "pubmed": _normalize_pubmed,
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
                "provenance": {
                    "adapter": origin,
                    "query": raw.get("query_used", ""),
                    "retrieval_timestamp": raw.get("retrieved_at", ""),
                },
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
