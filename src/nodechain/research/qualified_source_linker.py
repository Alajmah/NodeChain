"""Qualified Source Linker — deterministic node between quality evaluation
and evidence synthesis.

Receives two authoritative inputs:
1. quality_decision (from source_quality_evaluator): quality judgments
2. ingested_source_set (from source_ingestion): source artifacts with hashes

For every included qualified source, resolves the source_id to the ingested
source record and propagates source_hash and artifact_ref. Unknown IDs,
missing hashes, and mismatches fail closed with explicit reason codes.

Excluded sources are separated and not sent to evidence synthesis.
"""

from __future__ import annotations

from typing import Any

from nodechain.core.contract import (
    EntryContract,
    ExitContract,
    NodeContract,
    Requirements,
    SideEffect,
)
from nodechain.core.envelope import EnvelopeResponse, InvocationEnvelope
from nodechain.core.manifest import NodeManifest
from nodechain.core.port import PortType
from nodechain.nodes.base_node import BaseNode


class QualifiedSourceLinkageError(Exception):
    """Raised when a qualified source cannot be linked to an ingested artifact."""

    def __init__(self, reason_code: str, source_id: str, detail: str = "") -> None:
        self.reason_code = reason_code
        self.source_id = source_id
        super().__init__(f"{reason_code}: {source_id} — {detail}")


QUALIFIED_SOURCE_LINKER_CONTRACT = NodeContract(
    contract_id="research.qualified-source-linker.v1",
    node_id="qualified_source_linker",
    version="1.0.0",
    entry=EntryContract(
        input_type="qualified_source_set",
        schema_ref="nodechain://schemas/semantic_types/source_set",
        required_fields=["qualified_sources", "sources"],
    ),
    exit=ExitContract(
        output_type="qualified_source_set",
        schema_ref="nodechain://schemas/semantic_types/source_set",
        guaranteed_fields=["linked_sources", "qualified_sources", "quality_summary", "loop_required"],
    ),
    side_effects=[],
    requirements=Requirements(
        model_required=False,
        tools_required=[],
        adapters_required=[],
    ),
)


class QualifiedSourceLinkerNode(BaseNode):
    """Deterministically binds qualified sources to ingested artifacts.

    The linker reads quality decisions (qualified_sources) and ingested
    source records (sources) from its payload. For every included source,
    it resolves the source_id to the ingested artifact, propagates
    source_hash and artifact_ref, and fails closed on errors.

    Excluded sources are separated into excluded_sources and do not reach
    evidence synthesis.
    """

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="qualified_source_linker",
            node_type="deterministic",
            name="Qualified Source Linker",
            description=(
                "Deterministically binds qualified sources to ingested "
                "artifacts by propagating source_hash and artifact_ref. "
                "Fails closed on unknown, missing, or mismatched sources."
            ),
            contract=QUALIFIED_SOURCE_LINKER_CONTRACT,
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        payload = envelope.payload or {}

        # Read quality decisions and ingested sources from the payload.
        # The quality evaluator passes through 'sources' from ingestion,
        # so both are available in the same payload.
        qualified_sources = payload.get("qualified_sources", [])
        sources = payload.get("sources", [])
        quality_summary = payload.get("quality_summary", "")
        loop_required = payload.get("loop_required", False)

        # Build ingested source lookup by source_id. Reject duplicates.
        ingested_by_id: dict[str, dict[str, Any]] = {}
        for s in sources:
            sid = s.get("source_id", "")
            if not sid:
                continue
            if sid in ingested_by_id:
                raise QualifiedSourceLinkageError(
                    "DUPLICATE_INGESTED_SOURCE_ID",
                    sid,
                    f"ingested source {sid} appears more than once",
                )
            ingested_by_id[sid] = s

        # Reject duplicate qualified source IDs.
        seen_qualified: set[str] = set()

        # Link each qualified source.
        linked_sources: list[dict[str, Any]] = []
        excluded_sources: list[dict[str, Any]] = []

        for q in qualified_sources:
            included = q.get("included", True)
            if not included:
                excluded_sources.append(q)
                continue

            sid = q.get("source_id", "")
            if not sid:
                raise QualifiedSourceLinkageError(
                    "QUALIFIED_SOURCE_MISSING_ID",
                    "",
                    "qualified source has no source_id",
                )

            if sid in seen_qualified:
                raise QualifiedSourceLinkageError(
                    "DUPLICATE_QUALIFIED_SOURCE_ID",
                    sid,
                    f"qualified source {sid} appears more than once",
                )
            seen_qualified.add(sid)

            ingested = ingested_by_id.get(sid)
            if ingested is None:
                raise QualifiedSourceLinkageError(
                    "QUALIFIED_SOURCE_NOT_INGESTED",
                    sid,
                    f"source {sid} not found in ingested source set",
                )

            source_hash = ingested.get("source_hash", "")
            if not source_hash:
                raise QualifiedSourceLinkageError(
                    "INGESTED_SOURCE_HASH_MISSING",
                    sid,
                    f"ingested source {sid} has no source_hash",
                )

            artifact_ref = ingested.get("artifact_ref", "")
            if not artifact_ref:
                raise QualifiedSourceLinkageError(
                    "INGESTED_SOURCE_REF_MISSING",
                    sid,
                    f"ingested source {sid} has no artifact_ref",
                )

            # Validate artifact_ref matches expected format.
            expected_ref = f"ingested:{sid}:{source_hash}"
            if artifact_ref != expected_ref:
                raise QualifiedSourceLinkageError(
                    "INGESTED_SOURCE_REF_MISMATCH",
                    sid,
                    f"artifact_ref {artifact_ref} != expected {expected_ref}",
                )

            # Propagate artifact identity deterministically from ingestion.
            # source_ref is set to source_id for synthesizer citation matching
            # (the synthesizer matches source_ref against source_id).
            # artifact_ref carries the full immutable reference.
            linked = {
                **q,
                "source_ref": sid,
                "artifact_ref": artifact_ref,
                "source_hash": source_hash,
            }
            linked_sources.append(linked)

        # Build the output: only linked sources reach downstream nodes.
        # The 'sources' field carries ONLY the linked set so the synthesizer
        # cannot fall back to raw unqualified sources.
        linked_source_records = []
        for linked in linked_sources:
            sid = linked["source_id"]
            ingested = ingested_by_id[sid]
            linked_source_records.append({
                **ingested,
                "source_ref": sid,
                "artifact_ref": linked["artifact_ref"],
                "source_hash": linked["source_hash"],
                "quality_score": linked.get("quality_score", 0.0),
                "included": True,
            })

        output = {
            "linked_sources": linked_sources,
            "excluded_sources": excluded_sources,
            "qualified_sources": linked_sources,  # backwards compat for synthesizer
            "quality_summary": quality_summary,
            "loop_required": loop_required,
            "sources": linked_source_records,  # ONLY linked — no raw passthrough
            "linkage_verified": True,
        }

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="qualified_source_linker",
            step_id=envelope.step_id,
            output=output,
            output_type="qualified_source_set",
            success=True,
        )
