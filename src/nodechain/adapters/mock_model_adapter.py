"""Mock Model Adapter — deterministic responses for testing and demos.

Returns structured, predictable outputs without any LLM calls.
Used by --provider mock for reproducible CLI demos.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

from nodechain.adapters.model_adapter import ModelResponse


# Deterministic responses keyed by task pattern
_MOCK_RESPONSES: dict[str, dict[str, Any]] = {
    "goal_interpreter": {
        "normalized_goal": "Evaluate the feasibility of adopting retrieval-augmented generation for policy question-answering",
        "research_scope": {
            "domains": ["NLP", "information_retrieval", "policy_analysis"],
            "time_constraint": "comprehensive",
            "depth": "deep",
        },
        "clarifications_needed": [],
        "confidence": 0.92,
    },
    "task_planner": {
        "plan": [
            {"task_id": 1, "description": "Search for RAG literature", "source_types": ["academic"]},
            {"task_id": 2, "description": "Find policy QA benchmarks", "source_types": ["academic", "government"]},
            {"task_id": 3, "description": "Evaluate RAG vs fine-tuning", "source_types": ["academic"]},
        ],
        "search_queries": [
            {"query": "retrieval augmented generation policy QA", "adapters": ["semantic_scholar", "arxiv"]},
            {"query": "RAG vs fine-tuning comparison", "adapters": ["semantic_scholar"]},
        ],
        "estimated_complexity": "medium",
    },
    "source_quality_evaluator": {
        "quality_scores": [{"source": "mock_source_1", "score": 0.85, "reason": "Peer-reviewed"}, {"source": "mock_source_2", "score": 0.80, "reason": "High citation count"}, {"source": "mock_source_3", "score": 0.75, "reason": "Recent publication"}],
        "filtered_sources": [],
        "loop_required": False,
        "assessment": "Sufficient evidence found. No additional search needed.",
        "qualified_sources": [
            {"source_id": "S1", "title": "RAG for Policy QA", "quality_score": 0.85, "included": True, "signals": {"peer_reviewed": True, "citation_count": 50}},
            {"source_id": "S2", "title": "Retrieval-Augmented Generation Survey", "quality_score": 0.80, "included": True, "signals": {"peer_reviewed": True, "citation_count": 120}},
            {"source_id": "S3", "title": "Hallucination Reduction via RAG", "quality_score": 0.75, "included": True, "signals": {"peer_reviewed": True, "citation_count": 30}},
            {"source_id": "S4", "title": "RAG Implementation Patterns", "quality_score": 0.70, "included": True, "signals": {"peer_reviewed": False, "citation_count": 10}},
            {"source_id": "S5", "title": "Cost Analysis of RAG vs Fine-tuning", "quality_score": 0.78, "included": True, "signals": {"peer_reviewed": True, "citation_count": 25}}
        ],
        "quality_summary": {
            "total_evaluated": 5,
            "total_passed": 5,
            "average_score": 0.78,
            "domain_coverage": "strong"
        },
    },
    "evidence_synthesizer": {
        "claims": [
            {
                "claim_id": "C1",
                "statement": "RAG improves factual accuracy in knowledge-intensive NLP tasks",
                "supporting_sources": ["S1", "S2", "S3", "S4", "S5"],
                "contradicting_sources": [],
                "confidence": 0.85,
                "support_strength": "direct",
                "source_agreement": "consistent",
                "uncertainty": "Based on 5 sources with consistent findings across academic literature",
                "domain": "NLP",
            },
            {
                "claim_id": "C2",
                "statement": "RAG reduces hallucination by 40-60% compared to vanilla generation",
                "supporting_sources": ["S1", "S2", "S3"],
                "contradicting_sources": [],
                "confidence": 0.80,
                "support_strength": "direct",
                "source_agreement": "consistent",
                "uncertainty": "Exact reduction varies by task and domain",
                "domain": "NLP",
            },
            {
                "claim_id": "C3",
                "statement": "RAG is cost-effective compared to fine-tuning for policy QA",
                "supporting_sources": ["S4", "S5"],
                "contradicting_sources": [],
                "confidence": 0.65,
                "support_strength": "indirect",
                "source_agreement": "mixed",
                "uncertainty": "Limited cost-comparison data; operational costs may vary",
                "domain": "information_retrieval",
            },
        ],
        "synthesis": {
            "summary": "RAG offers significant accuracy improvements (15-30%) over baseline approaches for policy question-answering, with strong evidence for hallucination reduction and moderate evidence for cost-effectiveness.",
            "key_findings": [
                "RAG significantly reduces hallucination in generative QA",
                "Policy-specific benchmarks show 15-30% accuracy improvement",
                "Implementation cost is moderate; operational cost is lower than fine-tuning",
            ],
            "areas_of_agreement": [
                "RAG improves factual accuracy across multiple studies",
                "Hallucination reduction is consistently observed",
            ],
            "areas_of_disagreement": [
                "Exact cost savings vary between studies",
            ],
            "gaps_identified": [
                "Long-term maintenance costs of RAG infrastructure are not well-documented",
                "Policy domain specificity may require additional evaluation",
            ],
            "temporal_analysis": "Evidence has strengthened from 2020 to 2024 as RAG adoption increased.",
        },
    },
    "claim_validator": {
        "results": [
            {
                "claim_id": "C1",
                "internal_consistency": 0.90,
                "source_agreement": 0.85,
                "status": "confirmed",
                "issues": [],
            },
            {
                "claim_id": "C2",
                "internal_consistency": 0.85,
                "source_agreement": 0.80,
                "status": "confirmed",
                "issues": [],
            },
            {
                "claim_id": "C3",
                "internal_consistency": 0.65,
                "source_agreement": 0.60,
                "status": "partially_confirmed",
                "issues": ["Limited source coverage for cost comparison"],
            },
        ],
    },
    "risk_classifier": {
        "risk_level": "medium",
        "risk_factors": [
            {"factor": "Implementation complexity", "severity": "medium", "mitigation": "Phased rollout"},
            {"factor": "Data freshness dependency", "severity": "low", "mitigation": "Automated index updates"},
        ],
        "recommendation": "proceed_with_caution",
        "confidence": 0.80,
    },
    "response_generator": {
        "recommendation": "Proceed with a phased adoption of RAG for policy QA, starting with a pilot on non-critical policy domains.",
        "executive_summary": "Based on analysis of academic literature and benchmarks, retrieval-augmented generation (RAG) offers significant accuracy improvements (15-30%) over baseline approaches for policy question-answering. The evidence strongly supports adoption with appropriate safeguards.",
        "key_findings": [
            "RAG reduces hallucination by 40-60% compared to vanilla generation",
            "Policy-specific benchmarks show consistent accuracy gains",
            "Implementation complexity is moderate; operational costs are favorable vs fine-tuning",
            "Data freshness is a manageable risk with automated index updates",
        ],
        "confidence_statement": {"level": "HIGH", "numeric": 0.85, "explanation": "Strong multi-source evidence with consistent findings across academic literature."},
        "alternative_perspectives": [
            "Fine-tuning may be preferable for highly specialized domains with stable knowledge",
            "Hybrid approaches combining RAG with fine-tuning could offer additional gains",
        ],
        "methodology_notes": "Research conducted using automated academic search across multiple databases with two-pass claim validation.",
    },
    "memory_write": {
        "should_write": True,
        "memory_entries": [
            {"key": "rag_policy_qa_evaluation", "value": "RAG recommended for policy QA with HIGH confidence (0.85)"},
        ],
        "dedup_decision": {"is_duplicate": False, "reason": "New topic evaluation"},
    },
    "default": {
        "status": "completed",
        "confidence": 0.75,
        "summary": "Mock response for demo purposes.",
    },
}


class MockModelAdapter:
    """Deterministic mock adapter for testing and demos.

    Returns structured responses matching the expected node output schemas.
    No LLM calls, no network, fully deterministic.
    """

    def __init__(self, latency_ms: int = 10) -> None:
        self.model = "mock"
        self.default_max_tokens = 4096
        self._latency_ms = latency_ms

    def complete(
        self,
        system_prompt: str,
        user_message: str,
        max_tokens: int | None = None,
        temperature: float = 0.3,
        output_schema: dict[str, Any] | None = None,
        task_type: str = "auto",
    ) -> ModelResponse:
        """Return a deterministic mock response."""
        time.sleep(self._latency_ms / 1000.0)

        # Match response to task type from system prompt or task_type param
        response_key = "default"
        lower_prompt = (system_prompt + " " + user_message).lower()

        # Try exact node ID match first (most reliable)
        for key in _MOCK_RESPONSES:
            if key in lower_prompt or key == task_type:
                response_key = key
                break

        # Fallback: match partial keys
        if response_key == "default":
            aliases = {
                "source quality evaluator": "source_quality_evaluator",
                "source_quality": "source_quality_evaluator",
                "quality_evaluator": "source_quality_evaluator",
                "quality evaluator": "source_quality_evaluator",
                "goal interpreter": "goal_interpreter",
                "task planner": "task_planner",
                "context selector": "context_selector",
                "search tool": "search_tool",
                "evidence synthesizer": "evidence_synthesizer",
                "claim validator": "claim_validator",
                "consistency validator": "claim_validator",
                "risk classifier": "risk_classifier",
                "response generator": "response_generator",
                "memory write": "memory_write",
            }
            for alias, full_key in aliases.items():
                if alias in lower_prompt and full_key in _MOCK_RESPONSES:
                    response_key = full_key
                    break

        import copy
        response_data = copy.deepcopy(_MOCK_RESPONSES[response_key])

        # Adapt evidence_synthesizer claims to the actual source IDs provided.
        # The synthesizer prompt lists allowed IDs like: ['S1', 'S2', 'S3'].
        # Cap supporting_sources to only reference IDs that exist.
        if response_key == "evidence_synthesizer":
            import re
            # Extract allowed source IDs from the prompt
            id_match = re.findall(r"S\d+", user_message)
            available_ids = sorted(set(id_match), key=lambda x: int(x[1:]))
            if available_ids:
                for claim in response_data.get("claims", []):
                    # Cap supporting_sources to available IDs (max 5)
                    capped = [sid for sid in claim.get("supporting_sources", [])
                              if sid in available_ids]
                    if not capped:
                        # All original IDs were beyond range — use first available
                        capped = available_ids[:min(2, len(available_ids))]
                    claim["supporting_sources"] = capped
                    # Cap contradicting_sources too
                    capped_contra = [sid for sid in claim.get("contradicting_sources", [])
                                     if sid in available_ids]
                    claim["contradicting_sources"] = capped_contra

        # Override risk level if env var is set (for pause/resume demo)
        if response_key == "risk_classifier":
            risk_override = os.environ.get("NODECHAIN_MOCK_RISK_LEVEL", "")
            if risk_override:
                response_data["risk_level"] = risk_override.lower()
                if risk_override.lower() == "high":
                    response_data["review_required"] = True
                    response_data["recommendation"] = "requires_human_review"

        content = json.dumps(response_data, indent=2)

        return ModelResponse(
            content=content,
            structured_output=response_data,
            model="mock",
            usage={"prompt_tokens": 100, "completion_tokens": 200, "total_tokens": 300},
            cost_usd=0.0,
            latency_ms=self._latency_ms,
            stop_reason="stop",
            raw_output_size=len(content.encode()),
        )

    def get_loaded_models(self) -> list[str]:
        """Return mock model list."""
        return ["mock"]
