"""Node 11: Test Result Classifier — deterministic verdict from exit code.

v2.73: Classifies each patch's test outcome into governance semantics.
NEVER model-judged — verdict comes from objective execution facts (exit code,
timeout, patch-apply status, output truncation). Per ChatGPT v2.73 design:
"A model can later summarize failure logs, but it should not decide whether
tests passed."
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

TEST_RESULT_CLASSIFIER_CONTRACT = NodeContract(
    contract_id="codereview.test-classifier.v1",
    node_id="test_result_classifier",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.SANDBOX_TEST_RESULTS,
        schema_ref="nodechain://schemas/semantic_types/sandbox_test_results",
        required_fields=["test_records"],
    ),
    exit=ExitContract(
        output_type=PortType.CLASSIFIED_TEST_RESULTS,
        schema_ref="nodechain://schemas/semantic_types/classified_test_results",
        guaranteed_fields=["verdicts", "classification_summary"],
    ),
    requirements=Requirements(model_required=False),
)


class TestResultClassifierNode(BaseNode):
    """Node 11: Classify test results deterministically.

    Verdict mapping (from ChatGPT v2.73 design):
      patch_apply_status=failed     → verdict=not_run, reason=patch_apply_failed
      test_status=passed            → verdict=pass, recommendation=accept_patch
      test_status=failed            → verdict=fail, recommendation=reject_patch
      test_status=timeout           → verdict=timeout, recommendation=needs_manual_review
      test_status=execution_error   → verdict=error, recommendation=needs_manual_review
      test_status=not_run           → verdict=not_run, reason=test_not_run
      output_truncated=True         → add reason_code=output_truncated
    """

    def __init__(self, model_adapter: Any = None) -> None:
        self._model = model_adapter  # unused — deterministic only

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="test_result_classifier",
            node_type="deterministic",
            name="Test Result Classifier",
            description="Classifies sandbox test results into governance verdicts. Deterministic, never model-judged.",
            contract=TEST_RESULT_CLASSIFIER_CONTRACT,
        )

    @staticmethod
    def _classify(record: dict) -> dict:
        """Produce a deterministic verdict from objective execution facts."""
        patch_id = record.get("patch_id", "?")
        patch_apply = record.get("patch_apply_status", "unknown")
        test_status = record.get("test_status", "unknown")
        output_truncated = record.get("output_truncated", False)
        exit_code = record.get("process_exit_code")

        verdict = "error"
        reason_codes: list[str] = []
        recommendation = "needs_manual_review"
        confidence = "deterministic"

        # TRACE TRUTH: patch apply failure means test was NOT RUN, not FAILED
        if patch_apply in ("failed", "workspace_export_failed"):
            verdict = "not_run"
            reason_codes.append(f"patch_apply_{patch_apply}")
            recommendation = "reject_patch"
        elif test_status == "passed":
            verdict = "pass"
            reason_codes.append("pytest_exit_code_0")
            recommendation = "accept_patch"
        elif test_status == "failed":
            verdict = "fail"
            reason_codes.append(f"pytest_exit_code_{exit_code}")
            recommendation = "reject_patch"
        elif test_status == "timeout":
            verdict = "timeout"
            reason_codes.append(f"process_timeout_after_{record.get('duration_ms', 0)}ms")
            recommendation = "needs_manual_review"
        elif test_status == "execution_error":
            verdict = "error"
            reason_codes.append("process_execution_failed")
            recommendation = "needs_manual_review"
        elif test_status == "not_run":
            verdict = "not_run"
            reason_codes.append("test_not_run")
            recommendation = "needs_manual_review"

        if output_truncated:
            reason_codes.append("output_truncated")

        return {
            "patch_id": patch_id,
            "verdict": verdict,
            "reason_codes": reason_codes,
            "evidence_refs": {
                "patch_apply_status": patch_apply,
                "test_status": test_status,
                "exit_code": exit_code,
                "duration_ms": record.get("duration_ms", 0),
                "stdout_available": bool(record.get("stdout_preview")),
                "stderr_available": bool(record.get("stderr_preview")),
            },
            "confidence": confidence,
            "recommendation": recommendation,
        }

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        data = envelope.payload
        records = data.get("test_records", [])
        exec_summary = data.get("execution_summary", {})

        verdicts = [self._classify(r) for r in records]

        verdict_counts = {}
        rec_counts = {}
        for v in verdicts:
            verdict_counts[v["verdict"]] = verdict_counts.get(v["verdict"], 0) + 1
            rec_counts[v["recommendation"]] = rec_counts.get(v["recommendation"], 0) + 1

        output = {
            "verdicts": verdicts,
            "classification_summary": {
                "total_verdicts": len(verdicts),
                "by_verdict": verdict_counts,
                "by_recommendation": rec_counts,
                "deterministic": True,
                "repo_unchanged": exec_summary.get("repo_git_status_unchanged", False),
            },
        }

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="test_result_classifier",
            step_id=envelope.step_id,
            output=output,
            output_type=PortType.CLASSIFIED_TEST_RESULTS,
        )
