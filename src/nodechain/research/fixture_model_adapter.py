"""Deterministic model adapter for sealed fixture-corpus research runs.

The FixtureModelAdapter produces structured responses wired to the sealed
corpus, ensuring the full chain executes deterministically with fixture
adapter grants. It is the Phase 5 sealed-run equivalent of the production
MockModelAdapter — zero-network, deterministic, and corpus-aware.

Response selection is driven by ``output_schema`` (the schema the calling
node passes), not by prompt wording alone. The adapter populates both
``ModelResponse.structured_output`` and canonical JSON ``content``.

For evidence synthesis, the adapter extracts aliased source IDs (``S1``,
``S2``, ...) from the node's prompt text and cites them in claims. The node
remaps aliases back to real source IDs after the model response.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

from nodechain.adapters.model_adapter import ModelResponse


class FixtureModelAdapter:
    """Deterministic, corpus-aware model adapter for sealed research runs.

    Returns structured responses matching the expected node output schemas.
    No LLM calls, no network, fully deterministic. All search routing targets
    the ``"fixture"`` adapter.
    """

    def __init__(
        self,
        latency_ms: int = 0,
        *,
        search_terms: list[str] | None = None,
        claim_confidence: float = 0.75,
        scenario_kind: str = "stable_literature",
    ) -> None:
        self.model = "fixture-mock"
        self.default_max_tokens = 4096
        self._latency_ms = latency_ms
        self._search_terms = search_terms or []
        self._claim_confidence = claim_confidence
        self._scenario_kind = scenario_kind

    # ------------------------------------------------------------------ #
    # Source extraction from prompt text
    # ------------------------------------------------------------------ #

    @staticmethod
    def _extract_aliased_sources(text: str) -> list[dict[str, Any]]:
        """Extract aliased source dicts (with source_ref=S1, S2, ...) from
        a node prompt that embeds sources as JSON."""
        # Find all '[' positions and try to parse a JSON array from each
        idx = 0
        while True:
            pos = text.find('[', idx)
            if pos == -1:
                break
            depth = 0
            for end in range(pos, len(text)):
                if text[end] == '[':
                    depth += 1
                elif text[end] == ']':
                    depth -= 1
                    if depth == 0:
                        candidate_str = text[pos:end + 1]
                        try:
                            candidate = json.loads(candidate_str)
                            if (isinstance(candidate, list)
                                    and len(candidate) > 0
                                    and all(isinstance(x, dict) for x in candidate)
                                    and any("source_ref" in x or "source_id" in x for x in candidate)):
                                return candidate
                        except (json.JSONDecodeError, ValueError):
                            pass
                        break
            idx = pos + 1
        return []

    @staticmethod
    def _extract_claims_from_text(text: str) -> list[dict[str, Any]]:
        """Extract claims from a claim_validator prompt."""
        idx = 0
        while True:
            pos = text.find('[', idx)
            if pos == -1:
                return []
            depth = 0
            for end in range(pos, len(text)):
                if text[end] == '[':
                    depth += 1
                elif text[end] == ']':
                    depth -= 1
                    if depth == 0:
                        try:
                            candidate = json.loads(text[pos:end + 1])
                            if (isinstance(candidate, list)
                                    and len(candidate) > 0
                                    and all(isinstance(x, dict) for x in candidate)
                                    and any("claim_id" in x for x in candidate)):
                                return candidate
                        except (json.JSONDecodeError, ValueError):
                            pass
                        break
            idx = pos + 1

    # ------------------------------------------------------------------ #
    # Main completion method
    # ------------------------------------------------------------------ #

    def complete(
        self,
        system_prompt: str,
        user_message: str,
        max_tokens: int | None = None,
        temperature: float = 0.3,
        output_schema: dict[str, Any] | None = None,
        task_type: str = "auto",
    ) -> ModelResponse:
        """Return a deterministic fixture-aware response."""
        time.sleep(self._latency_ms / 1000.0)

        lower = (system_prompt + " " + user_message).lower()
        schema_props = (output_schema or {}).get("properties", {})
        schema_keys = set(schema_props.keys())

        # ── Evidence synthesizer (output_schema has 'claims' + 'synthesis') ──
        if "claims" in schema_keys and "synthesis" in schema_keys:
            return self._synthesizer_response(user_message)

        # ── Claim validator (output_schema has 'results' with claim_id) ──
        if "results" in schema_keys:
            results_item = schema_props.get("results", {})
            item_props = results_item.get("properties", results_item.get("items", {}).get("properties", {}))
            if "claim_id" in item_props and "internal_consistency" in item_props:
                return self._validator_response(user_message)

        # ── Source quality evaluator (output_schema has 'qualified_sources') ──
        if "qualified_sources" in schema_keys:
            return self._quality_evaluator_response(user_message)

        # ── Node-identity fallback (prompt-wording based) ──
        if "goal_interpreter" in lower or "goal interpreter" in lower:
            content = json.dumps({
                "primary_question": user_message.strip(),
                "research_goal": {
                    "primary_question": user_message.strip(),
                    "focus_areas": [],
                },
                "query": user_message.strip(),
            })
        elif "task_planner" in lower or "task planner" in lower:
            terms = self._search_terms or [user_message.strip()]
            content = json.dumps({
                "tasks": [
                    {
                        "task_id": 1,
                        "description": " ".join(terms),
                        "source_types": ["academic"],
                        "query_terms": terms,
                    }
                ],
                "source_routing": {
                    "primary": ["fixture"],
                    "secondary": [],
                    "domain_specific": {},
                },
                "search_queries": [
                    {
                        "query": " ".join(terms),
                        "terms": terms,
                    }
                ],
            })
        elif "source_quality" in lower or "quality_evaluator" in lower:
            sources = self._extract_aliased_sources(user_message)
            qualified = [
                {
                    "source_id": s.get("source_id", s.get("source_ref", "")),
                    "quality_score": 0.8,
                    "peer_reviewed": s.get("peer_reviewed", False),
                    "citation_count": s.get("citation_count", 0),
                    "included": True,
                }
                for s in sources if isinstance(s, dict)
            ]
            content = json.dumps({
                "qualified_sources": qualified,
                "quality_scores": {q["source_id"]: q["quality_score"] for q in qualified},
            })
        elif "risk_classifier" in lower or "risk classifier" in lower:
            content = json.dumps({
                "risk_level": "HIGH",
                "confidence": 0.0,
                "review_required": True,
                "reasoning": "Sealed corpus run — review required by policy.",
            })
        elif "response_generator" in lower or "response generator" in lower:
            # H1.4: emit the Response Generator's declared output schema so
            # sealed fixture runs preserve the same final-response evidence
            # shape live runs produce. Deterministic sealed-corpus content —
            # no second generation pass.
            content = json.dumps({
                "recommendation": (
                    "Sealed corpus run completed. See evidence summary."
                ),
                "executive_summary": (
                    "The sealed fixture corpus run produced a deterministic "
                    "evidence base; see key findings."
                ),
                "key_findings": [
                    "Sealed corpus run completed with deterministic evidence.",
                ],
                "confidence_statement": {
                    "level": "low",
                    "numeric": 0.4,
                    "explanation": "Results based on sealed fixture corpus.",
                },
                "alternative_perspectives": [],
                "methodology_notes": (
                    "Governed execution over the sealed fixture corpus "
                    "(deterministic qualification profile)."
                ),
            })
        else:
            content = json.dumps({"result": user_message.strip()})

        return ModelResponse(
            content=content,
            model=self.model,
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    # ------------------------------------------------------------------ #
    # Quality evaluator response
    # ------------------------------------------------------------------ #

    def _quality_evaluator_response(self, user_message: str) -> ModelResponse:
        """Produce source quality evaluator output with qualified sources.

        Each qualified source is deterministically enriched with source_ref
        and source_hash from the actual ingested source data (extracted from
        the node's prompt text). The hash is NOT fabricated by the model —
        it is propagated from the ingested source record.
        """
        sources = self._extract_aliased_sources(user_message)
        qualified = []
        for s in sources:
            if not isinstance(s, dict):
                continue
            sid = s.get("source_id", s.get("source_ref", ""))
            if not sid:
                continue
            q = {
                "source_id": sid,
                "quality_score": 0.8,
                "included": True,
                "peer_reviewed": s.get("peer_reviewed", False),
                "citation_count": s.get("citation_count", 0),
            }
            qualified.append(q)
        output = {
            "qualified_sources": qualified,
            "quality_summary": f"Evaluated {len(qualified)} sources.",
            "loop_required": False,
        }
        content = json.dumps(output)
        return ModelResponse(
            content=content,
            structured_output=output,
            model=self.model,
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    # ------------------------------------------------------------------ #
    # Synthesizer response
    # ------------------------------------------------------------------ #

    def _synthesizer_response(self, user_message: str) -> ModelResponse:
        """Produce evidence synthesizer output citing aliased sources.

        For conflicting_evidence scenarios, produces a claim with genuinely
        contradictory supporting/contradicting sources and mixed agreement.
        """
        sources = self._extract_aliased_sources(user_message)
        aliases = [
            s.get("source_ref", s.get("source_id", ""))
            for s in sources if isinstance(s, dict)
        ]

        claims: list[dict[str, Any]] = []
        synthesis: dict[str, Any] = {
            "summary": "No sources were provided for synthesis.",
            "key_findings": [],
            "areas_of_agreement": [],
            "areas_of_disagreement": [],
            "gaps_identified": [],
            "temporal_analysis": "",
        }

        if aliases:
            if self._scenario_kind == "conflicting_evidence" and len(aliases) >= 2:
                # Genuinely contradictory evidence: first source supports,
                # second source contradicts.
                claims = [{
                    "claim_id": "cl-1",
                    "statement": "Sources disagree on the research question.",
                    "supporting_sources": [aliases[0]],
                    "contradicting_sources": [aliases[1]],
                    "confidence": 0.2,
                    "support_strength": "weak",
                    "source_agreement": "contradicted",
                    "uncertainty": "Sources provide contradictory evidence.",
                    "domain": "sealed_research",
                }]
                synthesis = {
                    "summary": f"Conflicting evidence from {len(aliases)} sealed sources.",
                    "key_findings": ["Sources disagree on the primary claim."],
                    "areas_of_agreement": [],
                    "areas_of_disagreement": ["Sources contradict on the research question."],
                    "gaps_identified": ["Conflict unresolved in sealed corpus."],
                    "temporal_analysis": "Sources are contemporary but contradictory.",
                }
            else:
                # Stable literature: all sources support.
                claims = [{
                    "claim_id": "cl-1",
                    "statement": "Sealed corpus evidence supports the research question.",
                    "supporting_sources": aliases,
                    "contradicting_sources": [],
                    "confidence": self._claim_confidence,
                    "support_strength": "direct",
                    "source_agreement": "consistent",
                    "uncertainty": "Limited to sealed fixture corpus scope.",
                    "domain": "sealed_research",
                }]
                synthesis = {
                    "summary": f"Synthesized evidence from {len(aliases)} sealed sources.",
                    "key_findings": ["Fixture sources are consistent with the research question."],
                    "areas_of_agreement": ["All sources support the primary claim."],
                    "areas_of_disagreement": [],
                    "gaps_identified": ["Sealed corpus scope is limited."],
                    "temporal_analysis": "Sources are contemporary.",
                }

        output = {"claims": claims, "synthesis": synthesis}
        content = json.dumps(output)
        return ModelResponse(
            content=content,
            structured_output=output,
            model=self.model,
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    # ------------------------------------------------------------------ #
    # Validator response
    # ------------------------------------------------------------------ #

    def _validator_response(self, user_message: str) -> ModelResponse:
        """Produce claim validator output."""
        claims = self._extract_claims_from_text(user_message)
        results = [
            {
                "claim_id": c.get("claim_id", ""),
                "internal_consistency": 0.8,
                "source_agreement": 0.8,
                "status": "confirmed",
                "issues": [],
            }
            for c in claims if isinstance(c, dict) and c.get("claim_id")
        ]
        output = {"results": results}
        content = json.dumps(output)
        return ModelResponse(
            content=content,
            structured_output=output,
            model=self.model,
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )
