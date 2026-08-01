"""Node 8: Patch Risk Classifier — deterministic LOW/MEDIUM/HIGH risk per patch.

v2.72 Code Review patch proposal path. Classifies each validated patch's risk
based on file path, diff content, and the finding it addresses. No model call.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import (
    EntryContract, ExitContract, NodeContract, Requirements,
)
from nodechain.core.manifest import NodeManifest
from nodechain.core.port import PortType
from nodechain.nodes.base_node import BaseNode

logger = logging.getLogger(__name__)

PATCH_RISK_CONTRACT = NodeContract(
    contract_id="codereview.patch-risk.v1",
    node_id="patch_risk_classifier",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.VALIDATED_PATCHES,
        schema_ref="nodechain://schemas/semantic_types/validated_patches",
        required_fields=["validated_patches"],
    ),
    exit=ExitContract(
        output_type=PortType.CLASSIFIED_PATCHES,
        schema_ref="nodechain://schemas/semantic_types/classified_patches",
        guaranteed_fields=["classified_patches", "risk_summary"],
    ),
    requirements=Requirements(model_required=False),
)

# File path patterns that indicate HIGH risk
HIGH_RISK_PATTERNS = [
    r"(?:auth|security|credential|password|token|secret)",
    r"(?:policy|governance)",
    r"(?:orchestrator|runtime.*state)",
    r"(?:filesystem.*write|file.*write)",
    r"(?:network|http|request)",
    r"(?:concurr|thread|async.*lock|mutex)",
    r"(?:migration|schema.*change)",
    r"(?:dependenc|requirement|setup\.py|pyproject)",
    r"(?:docker|ci|github.*action|workflow)",
    r"(?:api.*surface|public.*interface)",
]

# Patterns that indicate LOW risk
LOW_RISK_PATTERNS = [
    r"(?:comment|docstring|documentation)",
    r"(?:test|fixture|mock)",
    r"(?:typo|naming|rename.*variable)",
    r"(?:dead.*code|unused|remove.*import)",
    r"(?:print|debug|logging.*level)",
]


class PatchRiskClassifierNode(BaseNode):
    """Node 8: Classify validated patches as LOW/MEDIUM/HIGH risk.

    Deterministic rules per ChatGPT v2.72 design:
    - LOW: comments, docs, tests, dead-code removal, typo/naming, no behavior change
    - MEDIUM: localized logic change, error-handling fix, small control-flow
    - HIGH: auth/security, policy/governance, orchestrator, filesystem writes,
            credentials, network, concurrency, migrations, dependencies, API changes
    """

    def __init__(self, model_adapter: Any = None) -> None:
        self._model = model_adapter  # unused — deterministic only

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="patch_risk_classifier",
            node_type="deterministic",
            name="Patch Risk Classifier",
            description="Classifies patch risk as LOW/MEDIUM/HIGH using deterministic rules.",
            contract=PATCH_RISK_CONTRACT,
        )

    @staticmethod
    def _classify_risk(patch: dict) -> tuple[str, list[str]]:
        """Return (risk_level, reasons) for a validated patch."""
        target_file = patch.get("target_file", "").lower()
        diff_text = patch.get("unified_diff", "").lower()
        reasons: list[str] = []

        # Check HIGH risk patterns
        for pattern in HIGH_RISK_PATTERNS:
            if re.search(pattern, target_file) or re.search(pattern, diff_text):
                return "HIGH", [f"matches high-risk pattern: {pattern}"]

        # Check LOW risk patterns
        is_low = False
        for pattern in LOW_RISK_PATTERNS:
            if re.search(pattern, target_file) or re.search(pattern, diff_text):
                is_low = True
                reasons.append(f"matches low-risk pattern: {pattern}")
                break

        # Count diff lines for blast radius
        added_lines = sum(1 for l in diff_text.split("\n") if l.startswith("+") and not l.startswith("+++"))
        removed_lines = sum(1 for l in diff_text.split("\n") if l.startswith("-") and not l.startswith("---"))
        total_change = added_lines + removed_lines

        if total_change > 30:
            return "HIGH", [f"large blast radius: {total_change} lines changed"]
        elif total_change > 10:
            reasons.append(f"moderate change: {total_change} lines")
            return "MEDIUM", reasons if reasons else ["moderate change size"]
        elif is_low:
            return "LOW", reasons
        else:
            return "MEDIUM", reasons if reasons else [f"small localized change ({total_change} lines)"]

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        data = envelope.payload
        validated = [p for p in data.get("validated_patches", []) if p.get("status") == "validated"]

        classified = []
        risk_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}

        for patch in validated:
            risk_level, reasons = self._classify_risk(patch)
            risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
            classified.append({
                **patch,
                "risk_level": risk_level,
                "risk_reasons": reasons,
            })

        output = {
            "classified_patches": classified,
            "risk_summary": {
                "total_validated": len(classified),
                "by_risk": risk_counts,
                "high_risk_count": risk_counts.get("HIGH", 0),
            },
        }

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="patch_risk_classifier",
            step_id=envelope.step_id,
            output=output,
            output_type=PortType.CLASSIFIED_PATCHES,
        )
