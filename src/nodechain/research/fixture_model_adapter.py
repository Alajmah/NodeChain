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
            # Use corpus-matched search terms if provided, otherwise extract
            # from the question.
            terms = self._search_terms or [user_message.strip()]
            content = json.dumps({
                "tasks": [
                    {
                        "task_id": 1,
                        "description": " ".join(terms),
                        "source_types": ["academic"],
                        "search_terms": terms,
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
            content = json.dumps({
                "qualified_sources": [],
                "quality_scores": {},
            })
        elif "evidence_synthesizer" in lower or "evidence synthesizer" in lower:
            content = json.dumps({
                "claims": [],
                "evidence_summary": "No evidence synthesized from sealed corpus.",
                "executive_answer": "Insufficient evidence in the sealed corpus.",
            })
        elif "claim_validator" in lower or "claim validator" in lower:
            content = json.dumps({
                "validated_claims": [],
                "validation_summary": "No claims to validate.",
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
