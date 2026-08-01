"""Node 1: Goal Interpreter — parse raw query into normalized research goal."""

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


GOAL_INTERPRETER_CONTRACT = NodeContract(
    contract_id="research.goal-interpreter.v1",
    node_id="goal_interpreter",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.RAW_QUERY,
        schema_ref="nodechain://schemas/semantic_types/raw_user_query",
        required_fields=["query"],
    ),
    exit=ExitContract(
        output_type=PortType.RESEARCH_GOAL,
        schema_ref="nodechain://schemas/semantic_types/normalized_research_goal",
        guaranteed_fields=[
            "primary_question", "research_domain", "success_criteria",
            "domain_classification", "depth_required",
        ],
    ),
    requirements=Requirements(
        model_required=True,
        model_capabilities=["structured_output", "reasoning"],
    ),
)

GOAL_INTERPRETER_SYSTEM_PROMPT = """You are a Research Goal Interpreter. Your job is to take a raw user query and normalize it into a structured research goal.

Analyze the query and produce:
1. primary_question: The core question being asked
2. sub_questions: Breakdown into searchable sub-questions
3. research_domain: The primary academic domain (biomedical, computer_science, mathematics, physics, social_sciences, engineering, general)
4. domain_classification: Confidence scores for each relevant domain
5. success_criteria: What would constitute a complete answer
6. constraints: Any constraints mentioned or implied
7. time_sensitivity: How time-sensitive the information is
8. depth_required: How deep the research needs to go

Be precise. Extract the actual research intent, not just keywords."""

OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "primary_question": {"type": "string"},
        "sub_questions": {"type": "array", "items": {"type": "string"}},
        "research_domain": {"type": "string"},
        "domain_classification": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string"},
                    "confidence": {"type": "number"},
                },
            },
        },
        "success_criteria": {"type": "array", "items": {"type": "string"}},
        "constraints": {"type": "array", "items": {"type": "string"}},
        "time_sensitivity": {"type": "string"},
        "depth_required": {"type": "string"},
    },
    "required": ["primary_question", "research_domain", "success_criteria"],
}


class GoalInterpreterNode(BaseNode):
    """
    Node 1: Takes raw user query, produces normalized research goal.
    First model call through the runtime.
    """

    def __init__(self, model_adapter: Any) -> None:
        self._model = model_adapter

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="goal_interpreter",
            node_type="model",
            name="Goal Interpreter",
            description="Parses raw user query into a normalized research goal with domain classification.",
            contract=GOAL_INTERPRETER_CONTRACT,
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        query = envelope.payload.get("query", "")

        response = self._model.complete(
            system_prompt=GOAL_INTERPRETER_SYSTEM_PROMPT,
            user_message=f"Analyze this research query:\n\n{query}",
            output_schema=OUTPUT_SCHEMA,
            temperature=0.2,
        )

        output = response.structured_output or {}
        if not output:
            # Fallback: try to parse content as JSON
            try:
                output = json.loads(response.content)
            except json.JSONDecodeError:
                output = {
                    "primary_question": query,
                    "research_domain": "general",
                    "success_criteria": ["Provide relevant information"],
                    "domain_classification": [],
                    "depth_required": "moderate",
                }

        # Normalize field names (local models may use different names)
        output = self._normalize_output(output, query)

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="goal_interpreter",
            step_id=envelope.step_id,
            output=output,
            output_type=PortType.RESEARCH_GOAL,
            cost_usd=response.cost_usd,
            latency_ms=response.latency_ms,
        )

    @staticmethod
    def _normalize_output(output: dict[str, Any], query: str) -> dict[str, Any]:
        """Normalize model output to match expected schema fields."""
        # Map alternate field names from local models
        if "primary_question" not in output:
            output["primary_question"] = output.get("question", output.get("query", query))

        if "research_domain" not in output:
            domain = output.get("domain", output.get("research_area", "general"))
            output["research_domain"] = domain

        if "success_criteria" not in output:
            criteria = output.get("criteria", output.get("objectives", []))
            if isinstance(criteria, str):
                criteria = [criteria]
            if not criteria:
                criteria = ["Provide relevant information"]
            output["success_criteria"] = criteria

        if "sub_questions" not in output:
            subs = output.get("sub_question", output.get("subquestions", []))
            if isinstance(subs, str):
                subs = [subs]
            output["sub_questions"] = subs if isinstance(subs, list) else []

        if "domain_classification" not in output:
            # Build from key_terms or research_domain if available
            key_terms = output.get("key_terms", [])
            domain = output.get("research_domain", "general")
            classifications = []
            if key_terms:
                for term in key_terms[:5]:
                    classifications.append({"domain": term, "confidence": 0.7})
            else:
                classifications.append({"domain": domain, "confidence": 0.8})
            output["domain_classification"] = classifications

        if "depth_required" not in output:
            output["depth_required"] = output.get("depth", "moderate")

        if "time_sensitivity" not in output:
            output["time_sensitivity"] = output.get("urgency", "normal")

        if "constraints" not in output:
            output["constraints"] = output.get("limitations", [])

        return output
