"""Node 6: Source Quality Evaluator — structured credibility scoring + loop trigger."""

from __future__ import annotations

import json
from typing import Any

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import (
    EntryContract, ExitContract, NodeContract, Requirements,
)
from nodechain.core.manifest import NodeManifest
from nodechain.core.port import PortType
from nodechain.nodes.base_node import BaseNode


SOURCE_QUALITY_CONTRACT = NodeContract(
    contract_id="research.source-quality.v1",
    node_id="source_quality_evaluator",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.SOURCE_SET,
        schema_ref="nodechain://schemas/semantic_types/source_set",
        required_fields=["sources"],
    ),
    exit=ExitContract(
        output_type=PortType.QUALIFIED_SOURCE_SET,
        schema_ref="nodechain://schemas/semantic_types/qualified_source_set",
        guaranteed_fields=["qualified_sources", "quality_summary", "loop_required", "sources"],
        possible_fields=["loop_reason", "revised_queries"],
    ),
    requirements=Requirements(
        model_required=True,
        model_capabilities=["structured_output", "evaluation"],
    ),
)

QUALITY_SYSTEM_PROMPT = """You are a Source Quality Evaluator. Given a set of academic sources with structured metadata, evaluate each source's quality and determine if the collection is sufficient.

For each source, score based on these signals:
- peer_reviewed: Boolean — establishes credibility baseline
- citation_count: Number — field recognition signal
- publication_date: Recency — freshness signal
- retraction_status: Boolean — hard disqualifier
- source_type: preprint vs published — uncertainty signal
- venue_quality: Where published — venue quality signal
- cross_source_corroboration: Same finding across databases

Scoring:
- quality_score: 0.0-1.0 overall quality
- signals: Structured breakdown of each signal
- included: Whether to include in evidence synthesis

Then evaluate the collection:
- domain_coverage: Is coverage strong, adequate, or weak?
- loop_required: Should the chain search again with revised queries?
- revised_queries: If looping, suggest better search terms

Only set loop_required=true if the collection genuinely lacks sufficient quality sources.

Set loop_required=true if ANY of these conditions hold:
- Fewer than 3 sources have quality_score >= 0.5
- Average quality score across all sources is below 0.3
- No peer-reviewed sources are present
- All sources are from a single API (no corroboration)
- Fewer than 5 sources total were evaluated
- Domain coverage is "limited" or "weak"""""

OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "qualified_sources": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "source_ref": {"type": "string"},
                    "quality_score": {"type": "number"},
                    "signals": {"type": "object"},
                    "included": {"type": "boolean"},
                    "exclusion_reason": {"type": "string"},
                },
            },
        },
        "quality_summary": {"type": "object"},
        "loop_required": {"type": "boolean"},
        "loop_reason": {"type": "string"},
        "revised_queries": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["qualified_sources", "quality_summary", "loop_required"],
}


def _sources_have_title(sources: list[dict[str, Any]], source_ref: str) -> bool:
    """v2.68: Minimal citation-grounding check for
    source_quality_policy.single_adapter_acceptance.v1.

    Confirms the referenced source has a stable id AND a non-empty title —
    the minimum metadata needed to ground a citation. Used by the
    single-adapter acceptance policy to ensure every accepted source is
    citation-groundable, not just present.
    """
    for s in sources:
        if s.get("source_id") == source_ref:
            return bool(s.get("title"))
    return False


class SourceQualityEvaluatorNode(BaseNode):
    """
    Node 6: Evaluates source quality using structured credibility signals.
    First loop trigger. Can cause the chain to re-search with revised queries.
    """

    def __init__(self, model_adapter: Any) -> None:
        self._model = model_adapter

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="source_quality_evaluator",
            node_type="model",
            name="Source Quality Evaluator",
            description="Evaluates source quality with structured credibility signals and triggers loop if insufficient.",
            contract=SOURCE_QUALITY_CONTRACT,
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        sources = envelope.payload.get("sources", [])

        # Quick deterministic pre-filter: remove retracted sources
        pre_filtered = []
        for s in sources:
            signals = s.get("credibility_signals", {})
            if signals.get("is_retracted", False):
                continue
            pre_filtered.append(s)

        # Model-backed quality evaluation
        # Truncate to fit model context (max 10 sources, minimal fields).
        # v2.68 fix: sort by citation_count (desc) BEFORE truncating so the
        # highest-signal sources reach the model. Previously this took the first
        # 10 in insertion order, which on a multi-API batch could be all preprints
        # from one adapter (e.g. arXiv), causing the model to see a uniformly weak
        # set, score everything 0.35, and trigger an unrecoverable corroboration
        # loop. Sorting by citation count naturally surfaces peer-reviewed,
        # well-cited sources first. Ties broken by peer_reviewed (True first).
        sources_to_evaluate = sorted(
            pre_filtered,
            key=lambda s: (
                1 if s.get("peer_reviewed", False) else 0,
                s.get("citation_count", 0) or 0,
            ),
            reverse=True,
        )[:10]
        sources_summary = []
        for s in sources_to_evaluate:
            signals = s.get("credibility_signals", {})
            sources_summary.append({
                "source_id": s.get("source_id", ""),
                "title": s.get("title", "")[:80],
                "origin_api": s.get("origin_api", ""),
                "peer_reviewed": s.get("peer_reviewed", False),
                "citation_count": s.get("citation_count", 0),
                "source_type": s.get("source_type", ""),
                "venue": (s.get("venue", "") or "")[:40],
            })

        # If too many for context, just do deterministic scoring
        if len(sources_summary) == 0:
            return self._deterministic_quality(pre_filtered, envelope)

        response = self._model.complete(
            system_prompt=QUALITY_SYSTEM_PROMPT,
            user_message=f"Evaluate these {len(sources_summary)} academic sources:\n\n{json.dumps(sources_summary, indent=2)}",
            output_schema=OUTPUT_SCHEMA,
            temperature=0.2,
            max_tokens=4096,
        )

        output = response.structured_output or {}
        if not output:
            try:
                output = json.loads(response.content)
            except json.JSONDecodeError:
                output = self._deterministic_quality_output(pre_filtered)

        # Ensure pass-through of sources for downstream nodes
        output["sources"] = pre_filtered

        # Ensure quality_summary exists (model may omit it)
        if "quality_summary" not in output or not isinstance(output.get("quality_summary"), dict):
            output["quality_summary"] = {
                "total_evaluated": len(pre_filtered),
                "total_passed": len([q for q in output.get("qualified_sources", []) if q.get("included", True)]),
                "average_score": 0.5,
                "domain_coverage": "adequate" if len(pre_filtered) >= 5 else "limited",
            }

        # Deterministic loop trigger: override model if evidence is clearly insufficient
        output = self._apply_deterministic_loop_trigger(output, pre_filtered)

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="source_quality_evaluator",
            step_id=envelope.step_id,
            output=output,
            output_type=PortType.QUALIFIED_SOURCE_SET,
            cost_usd=response.cost_usd,
            latency_ms=response.latency_ms,
        )

    def _deterministic_quality(
        self, sources: list[dict[str, Any]], envelope: InvocationEnvelope
    ) -> EnvelopeResponse:
        """Fallback: deterministic quality scoring without model call."""
        from nodechain.core.envelope import EnvelopeResponse
        import time

        output = self._deterministic_quality_output(sources)
        # Apply deterministic loop trigger to the fallback output too
        output = self._apply_deterministic_loop_trigger(output, sources)
        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="source_quality_evaluator",
            step_id=envelope.step_id,
            output=output,
            output_type=PortType.QUALIFIED_SOURCE_SET,
            cost_usd=0.0,
            latency_ms=0,
        )

    @staticmethod
    def _deterministic_quality_output(sources: list[dict[str, Any]]) -> dict[str, Any]:
        """Generate deterministic quality scores based on signals."""
        qualified = []
        scores = []
        for s in sources:
            score = 0.5  # Base
            if s.get("peer_reviewed"):
                score += 0.2
            citations = s.get("citation_count", 0) or 0
            if citations > 50:
                score += 0.15
            elif citations > 10:
                score += 0.1
            if s.get("open_access"):
                score += 0.05
            score = min(score, 1.0)
            scores.append(score)
            q_entry = {
                "source_ref": s.get("source_id", ""),
                "quality_score": score,
                "signals": {
                    "peer_reviewed": s.get("peer_reviewed", False),
                    "citation_count": citations,
                    "open_access": s.get("open_access", False),
                },
                "included": score >= 0.4,
                # Carry forward source content for downstream nodes
                "title": s.get("title", ""),
                "authors": s.get("authors", []),
                "venue": s.get("venue", ""),
                "year": s.get("publication_date", "")[:4] if s.get("publication_date") else "",
                "abstract": s.get("abstract", ""),
                "doi": s.get("doi", ""),
                "citation_count": citations,
                "peer_reviewed": s.get("peer_reviewed", False),
            }
            qualified.append(q_entry)

        avg_score = sum(scores) / len(scores) if scores else 0.0
        return {
            "qualified_sources": qualified,
            "quality_summary": {
                "total_evaluated": len(sources),
                "total_passed": sum(1 for q in qualified if q["included"]),
                "average_score": round(avg_score, 2),
                "domain_coverage": "adequate" if len(sources) >= 5 else "limited",
            },
            "loop_required": False,
            "sources": sources,
        }

    @staticmethod
    def _apply_deterministic_loop_trigger(
        output: dict[str, Any], sources: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Apply deterministic loop trigger logic after model evaluation.

        This overrides the model's loop_required decision when evidence
        is clearly insufficient based on measurable criteria.
        """
        qualified = output.get("qualified_sources", [])
        quality_summary = output.get("quality_summary", {})

        total_evaluated = quality_summary.get("total_evaluated", len(sources))
        qualified_count = sum(1 for q in qualified if q.get("included", True))
        avg_score = quality_summary.get("average_score", 0.5)
        domain_coverage = quality_summary.get("domain_coverage", "adequate")

        # Check for peer-reviewed sources
        has_peer_reviewed = any(
            q.get("signals", {}).get("peer_reviewed", False)
            for q in qualified
        )

        # Check for source diversity (not all from single API)
        apis = set()
        for s in sources:
            api = s.get("origin_api", s.get("provenance", {}).get("adapter", ""))
            if api:
                apis.add(api)
        single_api = len(apis) <= 1 and total_evaluated > 0

        # ── v2.68: source_quality_policy.single_adapter_acceptance.v1 ──────
        # Governance-sensitive rule (per agreement with strategic reviewer):
        # a single-API result is acceptable (no loop trigger) only when the
        # sources themselves are objectively high-quality. The original rule
        # fired unconditionally on any single-API result, which forced the chain
        # to loop against adapters that had genuinely returned nothing on the
        # first pass. Looping cannot make a silent adapter respond.
        #
        # This is an EXPLICIT POLICY, not a hidden override. The decision and
        # its reason codes are surfaced in the output and trace.
        policy_id = "source_quality_policy.single_adapter_acceptance.v1"
        single_adapter_reason_codes: list[str] = []
        single_api_acceptable = False
        if single_api:
            thresholds_met = []
            if qualified_count >= 3:
                thresholds_met.append("qualified_source_threshold_met")
            if has_peer_reviewed:
                thresholds_met.append("peer_reviewed_requirement_met")
            if avg_score >= 0.4:
                thresholds_met.append("average_quality_threshold_met")
            # Citation-groundable: every included source has a stable source_id
            # AND a non-empty title (minimal citation metadata).
            citation_groundable = all(
                q.get("source_ref") and _sources_have_title(sources, q.get("source_ref", ""))
                for q in qualified
                if q.get("included", True)
            )
            if citation_groundable:
                thresholds_met.append("citation_grounding_available")

            if len(thresholds_met) == 4:
                single_api_acceptable = True
                single_adapter_reason_codes = (
                    ["single_adapter_mode"] + thresholds_met
                )

        # Deterministic triggers
        reasons = []
        # Skip deterministic loop trigger when no sources were evaluated
        # (empty pipeline — looping won't help)
        if total_evaluated == 0:
            output["loop_required"] = False
            output["loop_reason"] = "No sources to evaluate — skipping loop trigger"
            return output

        if total_evaluated < 3:
            reasons.append(f"Only {total_evaluated} sources evaluated (need >= 3)")
        if qualified_count < 3 and total_evaluated >= 3:
            reasons.append(f"Only {qualified_count}/{total_evaluated} sources qualified")
        if avg_score < 0.3:
            reasons.append(f"Average quality score {avg_score:.2f} is below 0.3")
        if not has_peer_reviewed and total_evaluated > 0:
            reasons.append("No peer-reviewed sources found")
        if single_api and total_evaluated > 0 and not single_api_acceptable:
            reasons.append(f"All sources from single API ({apis}) — no corroboration")
        if domain_coverage in ("limited", "weak"):
            reasons.append(f"Domain coverage is '{domain_coverage}'")

        if reasons:
            output["loop_required"] = True
            output["loop_reason"] = "Deterministic trigger: " + "; ".join(reasons)
            # Generate revised queries for the next loop iteration
            if not output.get("revised_queries"):
                output["revised_queries"] = ["broader AI healthcare research", "systematic review AI medicine"]
        else:
            # No deterministic reasons fire — override a model "loop_required: True"
            # that was set on weak grounds (e.g. single-API but high-quality).
            # The override is justified ONLY by stricter deterministic evidence
            # criteria, never subjective convenience. Surface the policy and
            # reason codes explicitly.
            if output.get("loop_required") is True:
                output["loop_required"] = False
                if single_api_acceptable:
                    single_adapter_reason_codes.append(
                        "model_loop_flag_overridden_by_policy"
                    )
                    output["loop_reason"] = (
                        f"Policy {policy_id}: model requested loop but evidence "
                        f"satisfies single-adapter acceptance thresholds "
                        f"(qualified_count={qualified_count}, peer_reviewed="
                        f"{has_peer_reviewed}, avg_score={avg_score:.2f})."
                    )
                    output["policy_decision"] = {
                        "policy_id": policy_id,
                        "decision": "allow_single_adapter_acceptance",
                        "reason_codes": single_adapter_reason_codes,
                    }
                else:
                    output["loop_reason"] = (
                        "Deterministic override: model requested loop but evidence "
                        f"is sufficient (qualified_count={qualified_count}, "
                        f"peer_reviewed={has_peer_reviewed}, "
                        f"avg_score={avg_score:.2f})."
                    )
            # Ensure loop_required is explicitly set even when the model didn't
            # provide one (e.g. deterministic-only evaluation paths).
            if "loop_required" not in output:
                output["loop_required"] = False

        return output
