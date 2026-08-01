"""Node 1: Code Review Request — parse a review request into a structured goal.

v2.71 Code Review Assistant: the entry point. Takes a raw query like
"Review commit abc123 for correctness, security, and style" and produces
a structured CodeReviewGoal with target_commit, review_focus, and file_scope.
"""
from __future__ import annotations

import logging
from typing import Any

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import (
    EntryContract, ExitContract, NodeContract, Requirements,
)
from nodechain.core.manifest import NodeManifest
from nodechain.core.port import PortType
from nodechain.nodes.base_node import BaseNode

logger = logging.getLogger(__name__)

CODE_REVIEW_REQUEST_CONTRACT = NodeContract(
    contract_id="codereview.request.v1",
    node_id="code_review_request",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.RAW_QUERY,
        schema_ref="nodechain://schemas/semantic_types/raw_user_query",
        required_fields=["query"],
    ),
    exit=ExitContract(
        output_type=PortType.CODE_REVIEW_GOAL,
        schema_ref="nodechain://schemas/semantic_types/code_review_goal",
        guaranteed_fields=["target_commit", "review_focus", "file_scope"],
    ),
    requirements=Requirements(
        model_required=True,
        model_capabilities=["structured_output"],
    ),
)

REQUEST_SYSTEM_PROMPT = """You are a Code Review Request Parser. Given a user's review request, produce a structured CodeReviewGoal.

Extract:
1. target_commit: The commit hash, branch name, or "HEAD" to review. Default: "HEAD".
2. review_focus: What to review — "correctness", "security", "style", "performance", or "all". Default: "all".
3. file_scope: Which files — "changed" (only files in the commit diff), "all" (entire repo), or a list of specific paths. Default: "changed".
4. review_context: Any additional context the user provided.

Be precise. If the user doesn't specify, use the defaults above."""

REQUEST_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "target_commit": {"type": "string"},
        "review_focus": {"type": "string", "enum": ["correctness", "security", "style", "performance", "all"]},
        "file_scope": {"type": "string", "enum": ["changed", "all"]},
        "review_context": {"type": "string"},
    },
    "required": ["target_commit", "review_focus", "file_scope"],
}


class CodeReviewRequestNode(BaseNode):
    """Node 1: Parse a review request into a structured CodeReviewGoal."""

    def __init__(self, model_adapter: Any) -> None:
        self._model = model_adapter

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="code_review_request",
            node_type="model",
            name="Code Review Request Parser",
            description="Parses a code review request into a structured goal with target, focus, and scope.",
            contract=CODE_REVIEW_REQUEST_CONTRACT,
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        query = envelope.payload.get("query", "")

        response = self._model.complete(
            system_prompt=REQUEST_SYSTEM_PROMPT,
            user_message=f"Parse this review request:\n\n{query}",
            output_schema=REQUEST_OUTPUT_SCHEMA,
            temperature=0.2,
            max_tokens=2048,
        )

        output = response.structured_output or {}
        if not output:
            import json
            try:
                output = json.loads(response.content)
            except Exception:
                output = {
                    "target_commit": "HEAD",
                    "review_focus": "all",
                    "file_scope": "changed",
                    "review_context": query,
                }

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="code_review_request",
            step_id=envelope.step_id,
            output=output,
            output_type=PortType.CODE_REVIEW_GOAL,
            cost_usd=response.cost_usd,
            latency_ms=response.latency_ms,
        )
