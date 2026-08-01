"""Node 9: Patch Report Assembler — assemble the final patch report.

v2.72 Code Review patch proposal path. Deterministic — assembles validated
and classified outputs into the final report. Does NOT invent new patch
content, does NOT generate prose via model, does NOT apply patches.

Per ChatGPT v2.72 design: "assembles validated/classified outputs; should
not invent new patch content." The trace truth rule requires the report to
explicitly state what was and was NOT done.
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

PATCH_REPORT_CONTRACT = NodeContract(
    contract_id="codereview.patch-report.v1",
    node_id="patch_report_assembler",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.CLASSIFIED_PATCHES,
        schema_ref="nodechain://schemas/semantic_types/classified_patches",
        required_fields=["classified_patches"],
    ),
    exit=ExitContract(
        output_type=PortType.FINAL_PATCH_REPORT,
        schema_ref="nodechain://schemas/semantic_types/final_patch_report",
        guaranteed_fields=["patches", "governance_status", "proposed_only"],
    ),
    requirements=Requirements(model_required=False),
)


class PatchReportAssemblerNode(BaseNode):
    """Node 9: Assemble the final patch report from classified patches.

    Deterministic — assembles, does not invent. Every patch is marked
    proposed_only. The governance status explicitly states what was NOT done
    per the trace truth rule.
    """

    def __init__(self, model_adapter: Any = None) -> None:
        self._model = model_adapter  # unused

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="patch_report_assembler",
            node_type="deterministic",
            name="Patch Report Assembler",
            description="Assembles the final patch report. Proposed-only, never applied.",
            contract=PATCH_REPORT_CONTRACT,
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        data = envelope.payload
        classified = data.get("classified_patches", [])
        risk_summary = data.get("risk_summary", {})

        # Build the patch list for the report
        patches = []
        for p in classified:
            patches.append({
                "proposal_id": p.get("proposal_id"),
                "finding_id": p.get("finding_id"),
                "target_file": p.get("target_file"),
                "risk_level": p.get("risk_level"),
                "risk_reasons": p.get("risk_reasons", []),
                "rationale": p.get("rationale", ""),
                "unified_diff": p.get("unified_diff", ""),
                "status": "proposed_only",
            })

        output = {
            "patches": patches,
            "patch_count": len(patches),
            "risk_summary": risk_summary,
            "proposed_only": True,
            "governance_status": {
                "patch_proposed": len(patches) > 0,
                "patch_validated_in_temp_workspace": True,
                "patch_applied_to_real_repo": False,
                "tests_run": False,
                "commit_created": False,
                "push_performed": False,
                "repo_working_tree_unchanged": True,
            },
            "report_note": (
                "All patches are proposed-only artifacts. No patch has been applied "
                "to the real repository. No tests were run. No commits were created. "
                "No pushes were performed. The repository working tree is unchanged."
            ),
        }

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="patch_report_assembler",
            step_id=envelope.step_id,
            output=output,
            output_type=PortType.FINAL_PATCH_REPORT,
        )
