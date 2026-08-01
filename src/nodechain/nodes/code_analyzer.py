"""Node 3: Code Analyzer — model-backed analysis of code artifacts.

v2.71 Code Review Assistant: analyzes the code artifacts and produces
structured findings with file/line provenance. Each finding cites the
exact file_path and line range where the issue was found.
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

CODE_ANALYZER_CONTRACT = NodeContract(
    contract_id="codereview.analyzer.v1",
    node_id="code_analyzer",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.CODE_ARTIFACTS,
        schema_ref="nodechain://schemas/semantic_types/code_artifacts",
        required_fields=["files"],
    ),
    exit=ExitContract(
        output_type=PortType.REVIEW_FINDINGS,
        schema_ref="nodechain://schemas/semantic_types/review_findings",
        guaranteed_fields=["findings"],
    ),
    requirements=Requirements(
        model_required=True,
        model_capabilities=["structured_output", "reasoning", "code_analysis"],
    ),
)

ANALYZER_SYSTEM_PROMPT = """You are a Code Analyzer. Given code artifacts (file contents + diff hunks), produce structured review findings.

For each issue found:
1. finding_id: Unique identifier (F1, F2, ...)
2. file_path: The file where the issue was found
3. line_range: "start-end" line numbers (approximate from the diff hunk context)
4. severity: "blocker", "warning", or "info"
5. category: "correctness", "security", "style", "performance", or "architecture"
6. evidence: The specific code snippet or pattern that triggered the finding
7. recommendation: What to do about it
8. confidence: 0.0-1.0 how certain you are this is a real issue

Be precise. Cite exact file paths and line numbers. Do NOT invent issues. If the code is clean, return an empty findings array. It is better to find zero issues than to hallucinate false positives."""

ANALYZER_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string"},
                    "file_path": {"type": "string"},
                    "line_range": {"type": "string"},
                    "severity": {"type": "string", "enum": ["blocker", "warning", "info"]},
                    "category": {"type": "string", "enum": ["correctness", "security", "style", "performance", "architecture"]},
                    "evidence": {"type": "string"},
                    "recommendation": {"type": "string"},
                    "confidence": {"type": "number"},
                },
            },
        },
    },
    "required": ["findings"],
}


class CodeAnalyzerNode(BaseNode):
    """Node 3: Analyze code artifacts and produce structured findings."""

    def __init__(self, model_adapter: Any) -> None:
        self._model = model_adapter

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="code_analyzer",
            node_type="model",
            name="Code Analyzer",
            description="Analyzes code artifacts for correctness, security, style, and performance issues.",
            contract=CODE_ANALYZER_CONTRACT,
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        artifacts = envelope.payload
        files = artifacts.get("files", [])
        diff_hunks = artifacts.get("diff", [])
        review_focus = artifacts.get("review_focus", "all")

        # Build the code context for the model.
        # v2.71 fix: truncate at line boundary (not mid-token) and give more
        # context (4000 chars per file). The original 2000-char cap cut
        # mid-line, causing the model to see "broken" code and flag false
        # syntax errors (e.g. `required_fields: li` instead of `list[str]`).
        code_context = "Code Artifacts:\n\n"
        for f in files[:10]:  # cap at 10 files for context management
            code_context += f"--- {f['file_path']} ---\n"
            content = f.get("content", "")
            max_per_file = 4000
            if len(content) > max_per_file:
                cut = content[:max_per_file].rfind("\n")
                if cut > 0:
                    content = content[:cut]
                else:
                    content = content[:max_per_file]
            code_context += content
            code_context += "\n\n"
        if diff_hunks:
            code_context += "Diff Hunks:\n\n"
            for h in diff_hunks[:20]:
                hunk_content = h.get("content", "")
                max_hunk = 800
                if len(hunk_content) > max_hunk:
                    cut = hunk_content[:max_hunk].rfind("\n")
                    if cut > 0:
                        hunk_content = hunk_content[:cut]
                code_context += f"[{h['file_path']} lines {h.get('new_start','?')}+]\n"
                code_context += hunk_content
                code_context += "\n"

        response = self._model.complete(
            system_prompt=ANALYZER_SYSTEM_PROMPT,
            user_message=(
                f"Review focus: {review_focus}\n\n"
                f"Analyze the following code for issues:\n\n{code_context}"
            ),
            output_schema=ANALYZER_OUTPUT_SCHEMA,
            temperature=0.2,
            max_tokens=8192,
        )

        output = response.structured_output or {}
        if not output:
            try:
                output = json.loads(response.content)
            except Exception:
                output = {"findings": []}

        output["source_artifacts"] = {
            "files_analyzed": len(files),
            "diff_hunks_analyzed": len(diff_hunks),
        }

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="code_analyzer",
            step_id=envelope.step_id,
            output=output,
            output_type=PortType.REVIEW_FINDINGS,
            cost_usd=response.cost_usd,
            latency_ms=response.latency_ms,
        )
