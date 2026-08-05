"""Deterministic model adapter for sealed fixture-corpus research runs.

The FixtureModelAdapter produces structured responses wired to the sealed
corpus, ensuring the full chain executes deterministically with fixture
adapter grants. It is the Phase 5 sealed-run equivalent of the production
MockModelAdapter — zero-network, deterministic, and corpus-aware.

Each node receives a response matching its expected output schema, with
``source_routing.primary = ["fixture"]`` so the context_selector produces
``adapter_grants = ["fixture"]`` and ``target_adapters = ["fixture"]``.
"""

from __future__ import annotations

import json
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
    ) -> None:
        self.model = "fixture-mock"
        self.default_max_tokens = 4096
        self._latency_ms = latency_ms
        # When provided, these terms are used as search query terms instead
        # of the raw question, so the context_selector produces queries that
        # match corpus keys.
        self._search_terms = search_terms or []

    @staticmethod
    def _extract_sources_from_text(text: str) -> list[dict[str, Any]]:
        """Extract source dicts from a node prompt that embeds sources as JSON.

        Nodes pass sources as ``json.dumps(aliased_sources)`` inside a
        formatted prompt string. This helper finds JSON arrays containing
        source_id keys by scanning for '[' positions and attempting to parse.
        """
        # Find all '[' positions and try to parse a JSON array from each
        idx = 0
        while True:
            pos = text.find('[', idx)
            if pos == -1:
                break
            # Try to find the matching ']' by scanning forward
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
                                    and any("source_id" in x for x in candidate)):
                                return candidate
                        except (json.JSONDecodeError, ValueError):
                            pass
                        break
            idx = pos + 1
        return []

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

        # Route based on which node is calling (identified by prompt content).
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
                        "query": user_message.strip(),
                        "terms": [user_message.strip()],
                    }
                ],
            })
        elif "source_quality" in lower or "quality_evaluator" in lower:
            # Derive qualified sources from the input sources embedded in the
            # node's prompt text.
            sources = self._extract_sources_from_text(user_message)
            qualified = [
                {
                    "source_id": s.get("source_id", ""),
                    "quality_score": 0.8,
                    "peer_reviewed": s.get("peer_reviewed", False),
                    "citation_count": s.get("citation_count", 0),
                }
                for s in sources if isinstance(s, dict) and s.get("source_id")
            ]
            content = json.dumps({
                "qualified_sources": qualified,
                "quality_scores": {q["source_id"]: q["quality_score"] for q in qualified},
            })
        elif "evidence_synthesizer" in lower or "evidence synthesizer" in lower:
            # Derive evidence and claims from the input sources embedded in the
            # node's prompt text.
            sources = self._extract_sources_from_text(user_message)
            source_ids = [s.get("source_id", "") for s in sources if isinstance(s, dict) and s.get("source_id")]
            # Produce one claim supported by all sources.
            claims = []
            if source_ids:
                claims = [{
                    "claim_id": "cl-1",
                    "statement": "Sealed corpus evidence supports the research question.",
                    "status": "supported",
                    "supporting_evidence_ids": ["ev-1"],
                    "contradicting_evidence_ids": [],
                    "citation_ids": [],
                    "confidence": 0.7,
                }]
            evidence = []
            if source_ids:
                evidence = [{
                    "evidence_id": "ev-1",
                    "source_ids": source_ids,
                    "extracted_text": "Evidence derived from sealed fixture corpus sources.",
                    "evidence_type": "synthesis",
                    "confidence": 0.7,
                }]
            content = json.dumps({
                "claims": claims,
                "evidence": evidence,
                "evidence_summary": f"Synthesized {len(evidence)} evidence from {len(source_ids)} sources.",
                "executive_answer": "Sealed corpus evidence available." if source_ids else "No evidence synthesized.",
            })
        elif "claim_validator" in lower or "claim validator" in lower:
            # Derive validated claims from the input claims.
            import json as _json
            try:
                input_data = _json.loads(user_message) if user_message.strip() else {}
            except Exception:
                input_data = {}
            claims = input_data.get("claims", []) if isinstance(input_data, dict) else []
            validated = [
                {
                    "claim_id": c.get("claim_id", ""),
                    "validation_status": "validated",
                    "supporting_evidence_ids": c.get("supporting_evidence_ids", []),
                }
                for c in claims if isinstance(c, dict) and c.get("claim_id")
            ]
            content = json.dumps({
                "validated_claims": validated,
                "validation_summary": f"Validated {len(validated)} claim(s).",
            })
        elif "risk_classifier" in lower or "risk classifier" in lower:
            content = json.dumps({
                "risk_level": "HIGH",
                "confidence": 0.0,
                "review_required": True,
                "reasoning": "Sealed corpus run — review required by policy.",
            })
        elif "response_generator" in lower or "response generator" in lower:
            content = json.dumps({
                "answer": "Sealed corpus run completed. See evidence summary.",
                "confidence": "low",
                "caveats": ["Results based on sealed fixture corpus."],
            })
        else:
            # Default: pass-through JSON
            content = json.dumps({"result": user_message.strip()})

        return ModelResponse(
            content=content,
            model=self.model,
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )
