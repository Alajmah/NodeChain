"""Research Evaluation Runner — deterministic chain execution for quality measurement.

Executes the research_decision_v1 chain through MockModelAdapter and captures
per-node outputs for metric computation. This is the real eval runner that
v2.56.0 adds — replacing the structural-only `_run_default_case()` for
research quality evaluation.

Key properties:
- Fully deterministic (no network, no LLM)
- Captures every node's output contract fields
- Produces a machine-readable report suitable for release gating
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from nodechain.adapters.mock_model_adapter import MockModelAdapter
from nodechain.core.blueprint import load_blueprint
from nodechain.core.envelope import InvocationEnvelope
from nodechain.nodes.evidence_synthesizer import EvidenceSynthesizerNode
from nodechain.nodes.claim_validator import ClaimValidatorNode
from nodechain.nodes.risk_classifier import RiskClassifierNode
from nodechain.nodes.response_generator import ResponseGeneratorNode

logger = logging.getLogger(__name__)


# ── Research chain node IDs ────────────────────────────────────────────────

RESEARCH_NODES = [
    "goal_interpreter",
    "task_planner",
    "context_selector",
    "search_tool",
    "source_ingestion",
    "source_quality_evaluator",
    "evidence_synthesizer",
    "claim_validator",
    "risk_classifier",
    "response_generator",
    "memory_write_decision",
    "trace_collector",
]


def _make_test_sources(n: int = 5) -> list[dict[str, Any]]:
    """Create deterministic test sources for mock eval."""
    return [
        {
            "source_id": f"src-{i}",
            "title": f"Academic Source {i}: Research Findings",
            "authors": [f"Author {i}"],
            "publication_date": "2024",
            "abstract": f"This source provides evidence about retrieval-augmented generation and its impact on accuracy. Abstract {i}.",
            "credibility_signals": {"overall_score": 0.8},
            "citation_count": 50,
            "doi": f"10.1000/test{i}",
        }
        for i in range(1, n + 1)
    ]


def _make_test_qualified(n: int = 5) -> list[dict[str, Any]]:
    """Create deterministic qualified sources."""
    return [
        {
            "source_ref": f"src-{i}",
            "quality_score": 0.8,
            "included": True,
            "signals": {"peer_reviewed": True, "citation_count": 50},
        }
        for i in range(1, n + 1)
    ]


class ResearchEvalCase:
    """A single deterministic eval case for the research chain."""

    def __init__(
        self,
        case_id: str,
        description: str,
        source_count: int = 5,
        include_qualified: bool = True,
        empty_evidence: bool = False,
        expected_risk_level: str | None = None,
        expect_citations: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.case_id = case_id
        self.description = description
        self.source_count = source_count
        self.include_qualified = include_qualified
        self.empty_evidence = empty_evidence
        self.expected_risk_level = expected_risk_level
        self.expect_citations = expect_citations
        self.metadata = metadata or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "description": self.description,
            "source_count": self.source_count,
            "empty_evidence": self.empty_evidence,
            "expected_risk_level": self.expected_risk_level,
            "expect_citations": self.expect_citations,
        }


def run_research_eval_case(case: ResearchEvalCase) -> dict[str, Any]:
    """Execute a single research eval case through the mock-driven chain.

    Runs evidence_synthesizer → claim_validator → risk_classifier → response_generator
    using MockModelAdapter. Returns per-node outputs and computed metrics.

    This is deliberately not the full orchestrator (which needs LIM/search adapters).
    It executes the 4 research-quality-critical nodes deterministically.
    """
    mock = MockModelAdapter()
    run_id = f"eval-{case.case_id}-{uuid.uuid4().hex[:8]}"
    chain_id = "research_decision_v1"
    node_outputs: dict[str, dict[str, Any]] = {}

    if case.empty_evidence:
        sources: list[dict] = []
        qualified: list[dict] = []
    else:
        sources = _make_test_sources(case.source_count)
        qualified = _make_test_qualified(case.source_count) if case.include_qualified else []

    errors: list[str] = []

    try:
        # ── Node 7: Evidence Synthesizer ───────────────────────────────
        synth_env = InvocationEnvelope(
            envelope_id=f"{run_id}-e1", run_id=run_id, chain_id=chain_id,
            step_id=1, node_id="evidence_synthesizer",
            payload={"qualified_sources": qualified, "sources": sources},
        )
        synth = EvidenceSynthesizerNode(mock)
        synth_resp = asyncio.run(synth.execute(synth_env))
        node_outputs["evidence_synthesizer"] = synth_resp.output

        # ── Node 8: Claim Validator ────────────────────────────────────
        val_env = InvocationEnvelope(
            envelope_id=f"{run_id}-e2", run_id=run_id, chain_id=chain_id,
            step_id=2, node_id="claim_validator",
            payload={
                "claims": synth_resp.output.get("claims", []),
                "synthesis": synth_resp.output.get("synthesis", {}),
                "sources": sources,
            },
        )
        validator = ClaimValidatorNode(mock)
        val_resp = asyncio.run(validator.execute(val_env))
        node_outputs["claim_validator"] = val_resp.output

        # ── Node 9: Risk Classifier ────────────────────────────────────
        risk_env = InvocationEnvelope(
            envelope_id=f"{run_id}-e3", run_id=run_id, chain_id=chain_id,
            step_id=3, node_id="risk_classifier",
            payload=val_resp.output,
        )
        risk = RiskClassifierNode(mock)
        risk_resp = asyncio.run(risk.execute(risk_env))
        node_outputs["risk_classifier"] = risk_resp.output

        # ── Node 10: Response Generator ────────────────────────────────
        resp_env = InvocationEnvelope(
            envelope_id=f"{run_id}-e4", run_id=run_id, chain_id=chain_id,
            step_id=4, node_id="response_generator",
            payload=risk_resp.output,
        )
        gen = ResponseGeneratorNode(mock)
        gen_resp = asyncio.run(gen.execute(resp_env))
        node_outputs["response_generator"] = gen_resp.output

    except Exception as e:
        errors.append(f"Chain execution error: {e}")
        logger.exception("Research eval case %s failed", case.case_id)

    return {
        "case_id": case.case_id,
        "description": case.description,
        "node_outputs": node_outputs,
        "errors": errors,
        "run_id": run_id,
    }


# ── Golden corpus ──────────────────────────────────────────────────────────

def get_golden_corpus() -> list[ResearchEvalCase]:
    """Return the standard golden corpus for research evaluation.

    These cases cover the critical quality paths:
    - Normal supported answer with citations
    - Zero evidence path (no sources)
    - Mixed evidence (fewer sources)
    - Low-source-count edge case
    """
    return [
        ResearchEvalCase(
            case_id="golden-001-normal-supported",
            description="Normal case: 5 qualified sources, should produce confirmed claims with valid citations",
            source_count=5,
            include_qualified=True,
            expected_risk_level="LOW",
            expect_citations=True,
        ),
        ResearchEvalCase(
            case_id="golden-002-zero-evidence",
            description="Zero evidence: no sources provided, should produce HIGH risk, no citations",
            source_count=0,
            empty_evidence=True,
            expected_risk_level="HIGH",
            expect_citations=False,
        ),
        ResearchEvalCase(
            case_id="golden-003-mixed-evidence",
            description="Mixed evidence: 3 sources, should produce partially confirmed claims",
            source_count=3,
            include_qualified=True,
            expected_risk_level="LOW",
            expect_citations=True,
        ),
        ResearchEvalCase(
            case_id="golden-004-minimal-evidence",
            description="Minimal evidence: 2 sources, should still produce valid claims",
            source_count=2,
            include_qualified=True,
            expect_citations=True,
        ),
        ResearchEvalCase(
            case_id="golden-005-no-qualified-pass-through",
            description="No qualified list but sources present: should use direct source path",
            source_count=5,
            include_qualified=False,
            expect_citations=True,
        ),
    ]
