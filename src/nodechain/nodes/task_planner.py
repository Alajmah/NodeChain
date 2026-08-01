"""Node 2: Task Planner — decompose research goal into task plan with source routing."""

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


TASK_PLANNER_CONTRACT = NodeContract(
    contract_id="research.task-planner.v1",
    node_id="task_planner",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.RESEARCH_GOAL,
        schema_ref="nodechain://schemas/semantic_types/normalized_research_goal",
        required_fields=["primary_question", "research_domain"],
    ),
    exit=ExitContract(
        output_type=PortType.TASK_PLAN,
        schema_ref="nodechain://schemas/semantic_types/task_plan",
        guaranteed_fields=["plan_id", "tasks", "source_routing"],
    ),
    requirements=Requirements(
        model_required=True,
        model_capabilities=["structured_output", "planning"],
    ),
)

TASK_PLANNER_SYSTEM_PROMPT = """You are a Research Task Planner. Given a normalized research goal, create a structured task plan for gathering evidence.

For each task, specify:
1. task_id: Unique identifier
2. description: What this task searches for
3. query_terms: Specific search terms to use
4. priority: Task importance (1=highest)
5. target_domains: Which academic domains to search

Also specify source_routing:
- primary: Main academic APIs to search (semantic_scholar, arxiv, openalex, crossref, pubmed)
- secondary: Backup APIs if primary returns insufficient results
- domain_specific: APIs specific to the research domain

Choose APIs wisely:
- semantic_scholar: Best for citation graphs, influence scores
- arxiv: Best for preprints in CS, math, physics
- openalex: Broad coverage, concept tags, institutional data
- crossref: DOI resolution, publisher metadata, retraction status
- pubmed: Biomedical and life sciences only

Available APIs: semantic_scholar, arxiv, openalex, crossref, pubmed"""

OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "tasks": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "task_id": {"type": "string"},
                    "description": {"type": "string"},
                    "query_terms": {"type": "array", "items": {"type": "string"}},
                    "priority": {"type": "integer"},
                    "target_domains": {"type": "array", "items": {"type": "string"}},
                },
            },
        },
        "source_routing": {
            "type": "object",
            "properties": {
                "primary": {"type": "array", "items": {"type": "string"}},
                "secondary": {"type": "array", "items": {"type": "string"}},
                "domain_specific": {"type": "object"},
            },
        },
        "estimated_complexity": {"type": "string"},
    },
    "required": ["tasks", "source_routing"],
}


class TaskPlannerNode(BaseNode):
    """
    Node 2: Decomposes research goal into tasks with source routing.
    First multi-output node. Validates task plan schema.
    """

    def __init__(self, model_adapter: Any) -> None:
        self._model = model_adapter

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="task_planner",
            node_type="model",
            name="Task Planner",
            description="Decomposes research goal into a structured task plan with source routing.",
            contract=TASK_PLANNER_CONTRACT,
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        import uuid

        research_goal = envelope.payload

        response = self._model.complete(
            system_prompt=TASK_PLANNER_SYSTEM_PROMPT,
            user_message=f"Create a task plan for this research goal:\n\n{json.dumps(research_goal, indent=2)}",
            output_schema=OUTPUT_SCHEMA,
            temperature=0.3,
        )

        output = response.structured_output or {}
        if not output:
            try:
                output = json.loads(response.content)
            except json.JSONDecodeError:
                output = {
                    "tasks": [{
                        "task_id": "task_1",
                        "description": research_goal.get("primary_question", ""),
                        "query_terms": research_goal.get("primary_question", "").split(),
                        "priority": 1,
                        "target_domains": [research_goal.get("research_domain", "general")],
                    }],
                    "source_routing": {
                        "primary": ["semantic_scholar", "openalex"],
                        "secondary": ["crossref"],
                        "domain_specific": {},
                    },
                }

        output["plan_id"] = str(uuid.uuid4())

        # Ensure source_routing has the required structure
        if "source_routing" not in output:
            output["source_routing"] = {
                "primary": ["semantic_scholar", "openalex"],
                "secondary": ["crossref"],
            }

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="task_planner",
            step_id=envelope.step_id,
            output=output,
            output_type=PortType.TASK_PLAN,
            cost_usd=response.cost_usd,
            latency_ms=response.latency_ms,
        )
