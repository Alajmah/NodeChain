"""Node 4: Finding Classifier — confirm/speculate + deduplicate findings.

v2.71 Code Review Assistant: hybrid node (deterministic dedup + model
classification). Distinguishes confirmed issues from speculative concerns.
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

FINDING_CLASSIFIER_CONTRACT = NodeContract(
    contract_id="codereview.classifier.v1",
    node_id="finding_classifier",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.REVIEW_FINDINGS,
        schema_ref="nodechain://schemas/semantic_types/review_findings",
        required_fields=["findings"],
    ),
    exit=ExitContract(
        output_type=PortType.CLASSIFIED_FINDINGS,
        schema_ref="nodechain://schemas/semantic_types/classified_findings",
        guaranteed_fields=["classified_findings", "summary"],
    ),
    requirements=Requirements(
        model_required=False,  # deterministic in v2.71 MVP
    ),
)


class FindingClassifierNode(BaseNode):
    """Node 4: Classify findings as confirmed/speculative, deduplicate, assign severity.

    v2.71 uses deterministic rules (no model call):
    - confidence >= 0.7 → "confirmed"
    - confidence < 0.7 → "speculative"
    - Findings with the same file_path + category + overlapping line_range → deduped
    """

    def __init__(self, model_adapter: Any = None) -> None:
        self._model = model_adapter  # unused in v2.71 MVP; reserved for v2.72

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="finding_classifier",
            node_type="deterministic",
            name="Finding Classifier",
            description="Classifies findings as confirmed/speculative and deduplicates overlapping issues.",
            contract=FINDING_CLASSIFIER_CONTRACT,
        )

    @staticmethod
    def _parse_line_range(line_range: str) -> tuple[int, int]:
        """Parse 'start-end' or 'start' into (start, end)."""
        try:
            if "-" in line_range:
                parts = line_range.split("-")
                return int(parts[0]), int(parts[1])
            return int(line_range), int(line_range)
        except (ValueError, IndexError):
            return 0, 0

    @staticmethod
    def _ranges_overlap(a: tuple[int, int], b: tuple[int, int]) -> bool:
        return a[0] <= b[1] and b[0] <= a[1]

    def _deduplicate(self, findings: list[dict]) -> list[dict]:
        """Deduplicate findings with same file_path + category + overlapping lines."""
        if not findings:
            return []
        seen: list[dict] = []
        for f in findings:
            f_range = self._parse_line_range(f.get("line_range", "0"))
            is_dup = False
            for s in seen:
                if (s.get("file_path") == f.get("file_path")
                    and s.get("category") == f.get("category")
                    and self._ranges_overlap(
                        self._parse_line_range(s.get("line_range", "0")), f_range
                    )):
                    # Merge: keep the higher-confidence one
                    if f.get("confidence", 0) > s.get("confidence", 0):
                        s.update(f)
                    is_dup = True
                    break
            if not is_dup:
                seen.append(dict(f))
        return seen

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        findings_data = envelope.payload
        findings = findings_data.get("findings", [])

        # Deduplicate
        deduped = self._deduplicate(findings)

        # Classify each finding
        classified = []
        for f in deduped:
            confidence = f.get("confidence", 0.5)
            f["status"] = "confirmed" if confidence >= 0.7 else "speculative"
            classified.append(f)

        # Build summary
        by_severity = {"blocker": 0, "warning": 0, "info": 0}
        by_status = {"confirmed": 0, "speculative": 0}
        for f in classified:
            sev = f.get("severity", "info")
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_status[f["status"]] = by_status.get(f["status"], 0) + 1

        output = {
            "classified_findings": classified,
            "summary": {
                "total_findings": len(classified),
                "by_severity": by_severity,
                "by_status": by_status,
                "blocker_count": by_severity.get("blocker", 0),
            },
        }

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="finding_classifier",
            step_id=envelope.step_id,
            output=output,
            output_type=PortType.CLASSIFIED_FINDINGS,
        )
