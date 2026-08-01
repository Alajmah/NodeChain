"""Node 6: Patch Generator — generate unified-diff patches as artifacts.

v2.72 Code Review patch proposal path. Generates patch proposals from review
findings. Each proposal is a typed-port artifact (NOT a side effect). The
generator has NO file access and NO write permissions — it only produces
proposal objects.

Per ChatGPT v2.72 design (conversation 6a4adfe1):
  patch_proposal = typed artifact / port output, not side effect.
  The generator must_not: read files, write files, execute code, claim tests passed.
"""
from __future__ import annotations

import json
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

PATCH_GENERATOR_CONTRACT = NodeContract(
    contract_id="codereview.patch-generator.v1",
    node_id="patch_generator",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.FINAL_REVIEW,
        schema_ref="nodechain://schemas/semantic_types/final_review",
        required_fields=["findings"],
    ),
    exit=ExitContract(
        output_type=PortType.PATCH_PROPOSALS,
        schema_ref="nodechain://schemas/semantic_types/patch_proposals",
        guaranteed_fields=["patch_proposals"],
    ),
    requirements=Requirements(
        model_required=True,
        model_capabilities=["structured_output", "code_generation"],
    ),
)

GENERATOR_SYSTEM_PROMPT = """You are a Patch Generator. Given code review findings with file provenance, generate unified-diff patches as proposal artifacts.

For each finding that has a clear, safe fix:
1. proposal_id: Unique identifier (P1, P2, ...)
2. finding_id: The finding this patch addresses
3. target_file: The file to patch
4. unified_diff: A standard unified diff that can be applied with `patch` or `git apply`
5. rationale: Why this fix addresses the finding
6. expected_effect: What the fix does behaviorally
7. limitations: What the fix does NOT do (e.g., "does not fix the underlying design issue")
8. tests_not_run: Always true — patches are proposed, not tested in this release

Only generate patches for findings with clear, safe fixes. Do NOT generate patches for:
- Findings marked "speculative"
- Findings where the fix would require architectural changes
- Findings where you are not confident in the correct fix

It is better to propose zero patches than to propose a risky or incorrect patch."""

GENERATOR_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "patch_proposals": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "proposal_id": {"type": "string"},
                    "finding_id": {"type": "string"},
                    "target_file": {"type": "string"},
                    "unified_diff": {"type": "string"},
                    "rationale": {"type": "string"},
                    "expected_effect": {"type": "string"},
                    "limitations": {"type": "string"},
                    "tests_not_run": {"type": "boolean"},
                },
                "required": ["proposal_id", "finding_id", "target_file", "unified_diff"],
            },
        },
    },
    "required": ["patch_proposals"],
}


class PatchGeneratorNode(BaseNode):
    """Node 6: Generate patch proposals from review findings.

    Model-backed, creative, untrusted. Produces artifacts only — no file access,
    no writes, no execution. The proposals must be validated by patch_validator
    before they can be considered actionable.
    """

    def __init__(self, model_adapter: Any) -> None:
        self._model = model_adapter

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="patch_generator",
            node_type="model",
            name="Patch Generator",
            description="Generates unified-diff patch proposals from review findings. Artifacts only, no file access.",
            contract=PATCH_GENERATOR_CONTRACT,
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        review = envelope.payload
        findings = review.get("findings", [])
        recommendation = review.get("recommendation", "")
        executive_summary = review.get("executive_summary", "")

        # Only generate patches for findings worth fixing
        fixable_findings = [
            f for f in findings
            if f.get("severity") in ("blocker", "warning")
            and f.get("status") != "speculative"
        ]

        if not fixable_findings:
            return EnvelopeResponse(
                request_envelope_id=envelope.envelope_id,
                run_id=envelope.run_id,
                chain_id=envelope.chain_id,
                node_id="patch_generator",
                step_id=envelope.step_id,
                output={"patch_proposals": [], "reason": "No fixable findings to patch."},
                output_type=PortType.PATCH_PROPOSALS,
            )

        findings_context = json.dumps(fixable_findings, indent=2)

        response = self._model.complete(
            system_prompt=GENERATOR_SYSTEM_PROMPT,
            user_message=(
                f"Review summary: {executive_summary}\n"
                f"Recommendation: {recommendation}\n\n"
                f"Findings to patch:\n{findings_context}\n\n"
                f"Generate patch proposals for findings with clear, safe fixes."
            ),
            output_schema=GENERATOR_OUTPUT_SCHEMA,
            temperature=0.2,
            max_tokens=8192,
        )

        output = response.structured_output or {}
        if not output:
            try:
                output = json.loads(response.content)
            except Exception:
                output = {"patch_proposals": []}

        # Ensure tests_not_run is always true on every proposal
        for p in output.get("patch_proposals", []):
            p["tests_not_run"] = True

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="patch_generator",
            step_id=envelope.step_id,
            output=output,
            output_type=PortType.PATCH_PROPOSALS,
            cost_usd=response.cost_usd,
            latency_ms=response.latency_ms,
        )
