"""Node 7: Evidence Synthesizer - synthesize evidence from qualified sources."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

import json
from typing import Any

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import (
    EntryContract, ExitContract, NodeContract, Requirements, ModelRequirements,
)
from nodechain.core.manifest import NodeManifest
from nodechain.core.port import PortType
from nodechain.nodes.base_node import BaseNode


EVIDENCE_SYNTHESIZER_CONTRACT = NodeContract(
    contract_id="research.evidence-synthesizer.v1",
    node_id="evidence_synthesizer",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.QUALIFIED_SOURCE_SET,
        schema_ref="nodechain://schemas/semantic_types/qualified_source_set",
        required_fields=["qualified_sources", "quality_summary"],
    ),
    exit=ExitContract(
        output_type=PortType.EVIDENCE_BASE,
        schema_ref="nodechain://schemas/semantic_types/evidence_base",
        guaranteed_fields=["claims", "synthesis"],
    ),
    requirements=Requirements(
        model_required=True,
        model_capabilities=["structured_output", "reasoning", "deep_analysis"],
        memory_access="read",
        model_requirements=ModelRequirements(
            structured_output_required=True,
            min_output_tokens=4096,
            json_schema_adherence="required",
        ),
    ),
)

SYNTHESIZER_SYSTEM_PROMPT = """You are an Evidence Synthesizer. Given a set of qualified academic sources, synthesize the evidence into claims and a coherent analysis.

For each distinct finding or claim:
1. claim_id: Unique identifier
2. statement: The claim in clear language
3. supporting_sources: Source IDs that support this claim
4. contradicting_sources: Source IDs that contradict this claim
5. confidence: 0.0-1.0 how well-supported this claim is
   CRITICAL: Very few claims deserve 0.9+. Most research claims should be 0.4-0.7.
   (0.8-1.0 = multiple independent peer-reviewed studies directly confirm; 0.5-0.7 = limited or mixed support from 1-2 studies; 0.1-0.4 = weak, indirect, or contradicted)
6. support_strength: "direct" (source explicitly states the claim), "indirect" (source implies it), or "weak" (source loosely relates)
7. source_agreement: "consistent" (sources agree), "mixed" (sources disagree), or "contradicted" (sources contradict)
8. uncertainty: Any caveats or limitations
9. domain: The academic domain this claim belongs to

Then provide a synthesis:
- summary: Overall summary of findings
- key_findings: List of the most important findings
- areas_of_agreement: Where sources agree
- areas_of_disagreement: Where sources disagree
- gaps_identified: What the evidence does NOT cover
- temporal_analysis: How findings have evolved over time

Be thorough, precise, and honest about uncertainty. Every claim must trace back to specific sources."""

OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "claims": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "claim_id": {"type": "string"},
                    "statement": {"type": "string"},
                    "supporting_sources": {"type": "array", "items": {"type": "string"}},
                    "contradicting_sources": {"type": "array", "items": {"type": "string"}},
                    "confidence": {"type": "number"},
                    "support_strength": {"type": "string", "enum": ["direct", "indirect", "weak"]},
                    "source_agreement": {"type": "string", "enum": ["consistent", "mixed", "contradicted"]},
                    "uncertainty": {"type": "string"},
                    "domain": {"type": "string"},
                },
            },
        },
        "synthesis": {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "key_findings": {"type": "array", "items": {"type": "string"}},
                "areas_of_agreement": {"type": "array", "items": {"type": "string"}},
                "areas_of_disagreement": {"type": "array", "items": {"type": "string"}},
                "gaps_identified": {"type": "array", "items": {"type": "string"}},
                "temporal_analysis": {"type": "string"},
            },
        },
    },
    "required": ["claims", "synthesis"],
}


class EvidenceSynthesizerNode(BaseNode):
    """
    Node 7: Deep reasoning node that synthesizes evidence from qualified sources.
    First session memory read. Produces claims with citations.
    """

    def __init__(self, model_adapter: Any) -> None:
        self._model = model_adapter

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="evidence_synthesizer",
            node_type="model",
            name="Evidence Synthesizer",
            description="Synthesizes qualified sources into evidence claims and analysis.",
            contract=EVIDENCE_SYNTHESIZER_CONTRACT,
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        qualified = envelope.payload.get("qualified_sources", [])
        all_sources = envelope.payload.get("sources", [])

        # Build enriched source content for synthesis.
        # Strategy: use all_sources directly since they have full metadata.
        # qualified_sources may have source_ref values that don't match source_id UUIDs.
        # If qualified list is usable (has matching refs), enrich from it.
        # Otherwise, just use all_sources directly.
        sources_for_model = []

        # Check if qualified sources have usable refs that match all_sources
        if qualified and all_sources:
            src_ids = {s.get("source_id", "") for s in all_sources if s}
            qs_refs = {q.get("source_ref", "") for q in qualified if isinstance(q, dict)}
            has_matches = bool(src_ids & qs_refs)
        else:
            has_matches = False

        if has_matches and qualified:
            # Cross-reference path: qualified refs match source IDs
            source_map = {s.get("source_id", ""): s for s in all_sources if s}
            for qs in qualified:
                if qs is None or not isinstance(qs, dict):
                    continue
                if not qs.get("included", True):
                    continue
                ref = qs.get("source_ref", "") or qs.get("source_id", "")
                full = source_map.get(ref, {}) or {}
                sources_for_model.append({
                    "source_ref": ref,
                    "quality_score": qs.get("quality_score", 0),
                    "title": full.get("title", ""),
                    "authors": full.get("authors", []) or [],
                    "venue": full.get("venue", "") or "",
                    "year": full.get("publication_date", "") or "",
                    "citation_count": full.get("citation_count", 0) or 0,
                    "abstract": (full.get("abstract", "") or "")[:500],
                })
        elif all_sources:
            # Direct path: use all_sources as-is (no cross-ref needed)
            for s in all_sources:
                if s is None:
                    continue
                sources_for_model.append({
                    "source_ref": s.get("source_id", ""),
                    "quality_score": s.get("credibility_signals", {}).get("overall_score", 0.5) if isinstance(s.get("credibility_signals"), dict) else 0.5,
                    "title": s.get("title", "") or "",
                    "authors": s.get("authors", []) or [],
                    "venue": s.get("venue", "") or "",
                    "year": s.get("publication_date", "") or s.get("year", "") or "",
                    "citation_count": s.get("citation_count", 0) or 0,
                    "abstract": (s.get("abstract", "") or "")[:500],
                })
        elif qualified:
            # Only qualified available (no all_sources pass-through)
            for qs in qualified:
                if qs is None or not isinstance(qs, dict):
                    continue
                if not qs.get("included", True):
                    continue
                sources_for_model.append({
                    "source_ref": qs.get("source_ref", ""),
                    "quality_score": qs.get("quality_score", 0),
                    "title": qs.get("title", "") or "",
                    "authors": qs.get("authors", []) or [],
                    "venue": qs.get("venue", "") or "",
                    "year": qs.get("year", "") or "",
                    "citation_count": qs.get("citation_count", 0) or 0,
                    "abstract": (qs.get("abstract", "") or "")[:500],
                })

        # Get session memory if available
        memory_context = ""
        if envelope.context and envelope.context.session_memory:
            memory_items = [
                f"- {m.get('subject', '')}: {m.get('content', '')}"
                for m in envelope.context.session_memory
            ]
            memory_context = f"\n\nPrevious research memory:\n{chr(10).join(memory_items)}"

        # Limit to sources with actual content (to fit context)
        # Sort by quality_score (descending) before truncating to top-8
        # This ensures the highest-quality, most-relevant sources reach the model
        sources_with_abstracts = [s for s in sources_for_model if s.get("abstract")]
        sources_with_abstracts.sort(key=lambda s: s.get("quality_score", 0), reverse=True)
        sources_with_content = sources_with_abstracts[:8]
        if not sources_with_content:
            sources_with_content = sources_for_model[:5]
        
        # Ultimate fallback: if still no sources, use raw qualified_sources data
        if not sources_with_content and qualified:
            for qs in qualified[:5]:
                if qs and isinstance(qs, dict):
                    sources_with_content.append({
                        "source_ref": str(qs.get("source_ref", "")),
                        "quality_score": qs.get("quality_score", 0.5),
                        "title": str(qs.get("title", "")),
                        "authors": [],
                        "venue": str(qs.get("venue", "")),
                        "year": "",
                        "citation_count": 0,
                        "abstract": str(qs.get("abstract", ""))[:500],
                    })

        # Early exit: if no sources to synthesize, return empty result
        if not sources_with_content:
            return EnvelopeResponse(
                request_envelope_id=envelope.envelope_id,
                run_id=envelope.run_id,
                chain_id=envelope.chain_id,
                node_id="evidence_synthesizer",
                step_id=envelope.step_id,
                output={
                    "claims": [],
                    "synthesis": {"summary": "No sources were provided for synthesis.", "key_findings": [], "areas_of_agreement": [], "areas_of_disagreement": []},
                    "source_count": 0,
                    "memory_context_used": bool(memory_context),
                    "sources": all_sources,
                },
                output_type=PortType.EVIDENCE_BASE,
            )

        # ── Source alias system ──────────────────────────────────────
        # Replace UUIDs with short aliases (S1, S2, ...) for the model.
        # Remap back to real IDs after model output.
        alias_map: dict[str, str] = {}   # alias -> real source_ref
        reverse_map: dict[str, str] = {}  # real source_ref -> alias
        aliased_sources: list[dict] = []
        for i, s in enumerate(sources_with_content, start=1):
            alias = f"S{i}"
            real_ref = s.get("source_ref", "")
            alias_map[alias] = real_ref
            reverse_map[real_ref] = alias
            aliased = {**s, "source_ref": alias}
            aliased_sources.append(aliased)

        allowed_ids = set(alias_map.keys())

        response = self._model.complete(
            system_prompt=SYNTHESIZER_SYSTEM_PROMPT,
            user_message=(
                f"Synthesize evidence from these {len(aliased_sources)} sources. "
                f"Extract specific verifiable claims with citations.\n\n"
                f"IMPORTANT: You MUST cite sources using ONLY these IDs: {sorted(allowed_ids)}. "
                f"Do NOT invent or modify source IDs.\n\n"
                f"{json.dumps(aliased_sources, indent=2)}"
                f"{memory_context}"
            ),
            output_schema=OUTPUT_SCHEMA,
            temperature=0.3,
            max_tokens=10240,
        )

        # Instrumentation: log model call details for diagnostics
        logger.info(
            "Evidence Synthesizer model call: "
            "input_tokens=%d output_tokens=%d stop_reason=%s raw_bytes=%d latency_ms=%d",
            response.usage.get("input_tokens", 0),
            response.usage.get("output_tokens", 0),
            response.stop_reason,
            response.raw_output_size,
            response.latency_ms,
        )

        output = response.structured_output or {}
        if not output:
            try:
                output = json.loads(response.content)
            except json.JSONDecodeError:
                output = {
                    "claims": [],
                    "synthesis": {
                        "summary": "Unable to synthesize evidence due to processing error.",
                        "key_findings": [],
                        "areas_of_agreement": [],
                        "areas_of_disagreement": [],
                    },
                }

        # ── Remap source aliases back to real IDs ──────────────────
        for claim in output.get("claims", []):
            # Remap supporting_sources
            remapped_supporting = []
            for sid in claim.get("supporting_sources", []):
                if sid in alias_map:
                    # Alias already — remap to real
                    remapped_supporting.append(alias_map[sid])
                elif sid in reverse_map:
                    # Already a real ID — keep it
                    remapped_supporting.append(sid)
                else:
                    # Fabricated ID — quarantine the claim by downgrading
                    claim["status"] = "quarantined_fabricated_source"
                    claim["quarantine_reason"] = f"cites fabricated source ID: {sid}"
                    logger.warning("Claim %s quarantined: cites fabricated source ID: %s",
                                   claim.get("claim_id", "?"), sid)
                    # Drop the fabricated reference rather than soft-marking it
            claim["supporting_sources"] = remapped_supporting

            # Remap contradicting_sources
            remapped_contra = []
            for sid in claim.get("contradicting_sources", []):
                if sid in alias_map:
                    remapped_contra.append(alias_map[sid])
                elif sid in reverse_map:
                    remapped_contra.append(sid)
                else:
                    # Fabricated contradicting source — quarantine the claim
                    claim["status"] = "quarantined_fabricated_source"
                    claim["quarantine_reason"] = f"cites fabricated contradicting source ID: {sid}"
                    logger.warning("Claim %s quarantined: cites fabricated contradicting source ID: %s",
                                   claim.get("claim_id", "?"), sid)
            claim["contradicting_sources"] = remapped_contra

        output["source_count"] = len([q for q in qualified if q.get("included", True)])
        output["memory_context_used"] = bool(memory_context)

        # Pass through sources for downstream nodes
        output["sources"] = envelope.payload.get("sources", [])

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="evidence_synthesizer",
            step_id=envelope.step_id,
            output=output,
            output_type=PortType.EVIDENCE_BASE,
            cost_usd=response.cost_usd,
            latency_ms=response.latency_ms,
        )
