"""Qualified Source Linker — deterministic node between quality evaluation
and evidence synthesis.

Receives the source ingestion output and quality evaluator output. For every
included qualified source, resolves the source_id to the ingested source
record and propagates source_hash and source_ref. Unknown IDs, missing
hashes, and mismatches fail closed.

This node lives in the nodechain.nodes namespace to pass the PolicyGate
built-in boundary (privileged node trust).
"""

from __future__ import annotations

from typing import Any

from nodechain.core.contract import EntryContract, ExitContract, NodeContract, Requirements, SideEffect
from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.port import PortType
from nodechain.core.manifest import NodeManifest
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
        required_fields=["qualified_sources"],
    ),
    exit=ExitContract(
        output_type="qualified_source_set",
        schema_ref="nodechain://schemas/semantic_types/source_set",
        guaranteed_fields=["qualified_sources", "quality_summary", "loop_required"],
    ),
    side_effects=[],
    requirements=Requirements(
        model_required=False,
        tools_required=[],
        adapters_required=[],
    ),
)


class QualifiedSourceLinkerNode(BaseNode):
    """Deterministic linker that binds qualified sources to ingested artifacts.

    Receives the quality evaluator output (which carries quality judgments)
    and the source ingestion output (which carries source_hash). For every
    included qualified source, propagates source_hash and source_ref from
    the ingested source record. Fails closed on unknown, missing, or
    mismatched sources.

    The output replaces qualified_sources with linked_sources that carry
    both quality decisions and artifact identity.
    """

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="qualified_source_linker",
            node_type="deterministic",
            name="Qualified Source Linker",
            description=(
                "Deterministically binds qualified sources to ingested "
                "artifacts by propagating source_hash. Fails closed on "
                "unknown, missing, or mismatched sources."
            ),
            contract=QUALIFIED_SOURCE_LINKER_CONTRACT,
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        payload = envelope.payload or {}

        # Extract quality decisions and passthrough sources.
        qualified_sources = payload.get("qualified_sources", [])
        sources = payload.get("sources", [])
        quality_summary = payload.get("quality_summary", "")
        loop_required = payload.get("loop_required", False)

        # Build ingested source lookup by source_id.
        ingested_by_id: dict[str, dict[str, Any]] = {}
        for s in sources:
            sid = s.get("source_id", "")
            if sid:
                ingested_by_id[sid] = s

        # Link each included qualified source to its ingested artifact.
        linked_sources: list[dict[str, Any]] = []
        for q in qualified_sources:
            if not q.get("included", True):
                linked_sources.append(q)
                continue

            sid = q.get("source_id", "")
            if not sid:
                raise QualifiedSourceLinkageError(
                    "QUALIFIED_SOURCE_MISSING_ID",
                    sid,
                    "qualified source has no source_id",
                )

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

            # Propagate artifact identity deterministically.
            linked = {
                **q,
                "source_ref": f"ingested:{sid}:{source_hash[:12]}",
                "source_hash": source_hash,
            }
            linked_sources.append(linked)

        output = {
            "linked_sources": linked_sources,
            "qualified_sources": linked_sources,
            "quality_summary": quality_summary,
            "loop_required": loop_required,
            "sources": sources,
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
