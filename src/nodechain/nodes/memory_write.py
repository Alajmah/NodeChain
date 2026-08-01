"""Node 11: Memory Write Decision — governed memory write with 5-stage flow."""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Any

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import (
    EntryContract, ExitContract, NodeContract, Requirements,
    SideEffect,
)
from nodechain.core.manifest import NodeManifest
from nodechain.core.policy import PolicyEngine, PolicyType, PolicyAction
from nodechain.core.port import PortType
from nodechain.nodes.base_node import BaseNode
from nodechain.memory.manager import MemoryManager


MEMORY_WRITE_CONTRACT = NodeContract(
    contract_id="research.memory-write.v1",
    node_id="memory_write_decision",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.FINAL_RESPONSE,
        schema_ref="nodechain://schemas/semantic_types/final_response",
        required_fields=["recommendation", "confidence_statement"],
    ),
    exit=ExitContract(
        output_type=PortType.MEMORY_WRITE_DECISION,
        schema_ref="nodechain://schemas/semantic_types/memory_write_decision",
        guaranteed_fields=["candidates"],
    ),
    side_effects=[
        SideEffect(effect_type="memory_write", target="memory_store"),
    ],
    requirements=Requirements(
        memory_access="write",
    ),
)

# Write guard rules (enforced by runtime, not bypassable by node)
MIN_CONFIDENCE_THRESHOLD = 0.7
DUPLICATE_WINDOW_HOURS = 24


class MemoryWriteDecisionNode(BaseNode):
    """
    Node 11: Proposes and governs memory writes.
    Implements the full 5-stage write flow:
    1. Proposal — evaluate response, propose write candidates
    2. Policy — evaluate candidates for scope, sensitivity, permission
    3. Validation — check correctness, confidence threshold, source attribution
    4. Commit — write approved candidates to memory store
    5. Trace — record decision, candidate, policy result, write reference
    """

    def __init__(
        self,
        memory_manager: MemoryManager | None = None,
        policy_engine: PolicyEngine | None = None,
        record_memory_decision: Any = None,
    ) -> None:
        self._memory_manager = memory_manager
        # v2.27.0: declarative policy engine is the runtime authority for
        # memory write allow/block. When injected, _evaluate_policy delegates
        # to engine.evaluate(MEMORY_ACCESS) with the candidate's context.
        self._policy_engine = policy_engine
        # v2.28.0: durable memory decision log. Optional callback; when wired
        # (by run.py) every candidate decision (allow/deny/skip/error) is persisted.
        self._record_memory_decision = record_memory_decision or (lambda d: None)

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="memory_write_decision",
            node_type="deterministic",
            name="Memory Write Decision",
            description="Governs memory writes through 5-stage proposal-policy-validation-commit-trace flow.",
            contract=MEMORY_WRITE_CONTRACT,
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        response_data = envelope.payload
        confidence = response_data.get("confidence_statement", {}).get("numeric", 0.0)
        recommendation = response_data.get("recommendation", "")

        # Stage 1: Proposal — propose memory write candidates
        candidates = self._propose_candidates(response_data, envelope)

        # Stage 2: Policy — evaluate each candidate
        for candidate in candidates:
            candidate["policy_decision"] = self._evaluate_policy(candidate, confidence)

        # Stage 3: Validation — check correctness and thresholds
        for candidate in candidates:
            candidate["validation_result"] = self._validate_candidate(
                candidate, confidence
            )

        # Stage 4: Commit — write approved candidates to memory store
        for candidate in candidates:
            policy_ok = candidate.get("policy_decision", {}).get("approved", False)
            validation_ok = candidate.get("validation_result", {}).get("passed", False)

            if policy_ok and validation_ok:
                if self._memory_manager:
                    # Actual persistence through MemoryManager
                    write_result = await self._memory_manager.commit_write_candidate(candidate)
                    candidate["write_result"] = write_result
                else:
                    candidate["write_result"] = {
                        "committed": True,
                        "write_ref": str(uuid.uuid4()),
                        "note": "no_memory_manager_connected",
                    }
            else:
                reasons = []
                if not policy_ok:
                    reasons.append(candidate.get("policy_decision", {}).get("reason", "policy_denied"))
                if not validation_ok:
                    reasons.extend(candidate.get("validation_result", {}).get("issues", []))
                candidate["write_result"] = {
                    "committed": False,
                    "blocked_reason": "; ".join(reasons),
                }

        # Stage 5: Record durable memory decision for each candidate (v2.28.0).
        # Every candidate — allowed OR blocked — leaves a durable audit row.
        # Callback failure is non-fatal but visible (Correction A).
        log_errors = []
        for candidate in candidates:
            try:
                self._record_durable_decision(candidate, envelope)
            except Exception as exc:
                log_errors.append(str(exc))

        # Stage 6: Trace record is embedded in the output for the orchestrator to emit
        output = {"candidates": candidates}
        if log_errors:
            output["memory_decision_log_error"] = log_errors

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="memory_write_decision",
            step_id=envelope.step_id,
            output=output,
            output_type=PortType.MEMORY_WRITE_DECISION,
        )

    def _propose_candidates(
        self, response_data: dict[str, Any], envelope: InvocationEnvelope
    ) -> list[dict[str, Any]]:
        """Stage 1: Propose write candidates from the response."""
        candidates = []
        now = datetime.now(timezone.utc).isoformat()

        # Propose a single candidate: the key recommendation
        recommendation = response_data.get("recommendation", "")
        confidence = response_data.get("confidence_statement", {}).get("numeric", 0.0)

        # Get source IDs from chain state
        chain_state = envelope.context.chain_state if envelope.context else {}
        outputs = chain_state.get("outputs", {})
        sources = outputs.get("source_ingestion", {}).get("sources", [])
        source_ids = [s.get("source_id", "") for s in sources]

        if recommendation:
            candidates.append({
                "memory_id": str(uuid.uuid4()),
                "scope": "task_memory",
                "subject": response_data.get("executive_summary", "")[:100],
                "content": recommendation,
                "confidence": confidence,
                "sensitivity": "MEDIUM" if confidence < 0.8 else "LOW",
                "retention_policy": "session",
                "provenance": {
                    "chain_id": envelope.chain_id,
                    "run_id": envelope.run_id,
                    "source_ids": source_ids[:10],
                    "generation_timestamp": now,
                },
                "owner": "chain_operator",
            })

        return candidates

    def _evaluate_policy(
        self, candidate: dict[str, Any], response_confidence: float
    ) -> dict[str, Any]:
        """Stage 2: Policy evaluation.

        v2.27.0: when a declarative PolicyEngine is injected, this delegates to
        engine.evaluate(MEMORY_ACCESS) with the candidate's confidence and
        sensitivity — making MEMORY_WRITE_POLICY the runtime authority. The
        declarative rule_ids (memory.block_low_confidence,
        memory.block_high_sensitivity, memory.allow_write) are surfaced.

        When no engine is injected (legacy/tests), the same thresholds are
        evaluated directly but now emit the REAL declarative rule_ids (not the
        old fake 'memory.confidence_threshold' strings).
        """
        confidence = candidate.get("confidence", 0)
        sensitivity = candidate.get("sensitivity", "MEDIUM")

        # Declarative path: the PolicyEngine is the authority.
        if self._policy_engine is not None:
            context = {
                "confidence": confidence,
                "sensitivity": sensitivity,
                "node_id": "memory_write_decision",
            }
            decisions = self._policy_engine.evaluate(
                PolicyType.MEMORY_WRITE, "memory_write_decision", context,
            )
            # v2.31.0: MEMORY_WRITE type now isolates write policies from read
            # policies. The old policy_id filter workaround (v2.27.0) is removed.
            for dec in decisions:
                if dec.action == PolicyAction.DENY:
                    return {
                        "approved": False,
                        "reason": f"Denied by policy rule {dec.rule_id}",
                        "policy_id": dec.policy_id,
                        "rule_id": dec.rule_id,
                    }
                if dec.action == PolicyAction.REQUIRE_APPROVAL:
                    return {
                        "approved": False,
                        "reason": f"Rule {dec.rule_id} requires explicit approval",
                        "policy_id": dec.policy_id,
                        "rule_id": dec.rule_id,
                    }
            # No deny/approval decision -> allow
            if decisions:
                dec = decisions[0]
                return {
                    "approved": True,
                    "reason": f"Allowed by policy rule {dec.rule_id}",
                    "policy_id": dec.policy_id,
                    "rule_id": dec.rule_id,
                }
            # No matching policy at all — fail closed (no implicit allow).
            return {
                "approved": False,
                "reason": "No matching memory write policy evaluated",
                "policy_id": "memory.no_match",
                "rule_id": "memory.no_match",
            }

        # Fallback path (no engine injected). code-review fix:
        # In production (not under pytest), fail closed when no policy engine
        # is injected — the node must not govern itself outside the runtime path.
        # Under pytest (NODECHAIN_TEST_MODE=1), the fallback threshold checks
        # remain available for legacy tests that don't inject an engine.
        if not os.environ.get("NODECHAIN_TEST_MODE"):
            return {
                "approved": False,
                "reason": "No declarative PolicyEngine injected — memory write governance unavailable",
                "policy_id": "memory.no_engine",
                "rule_id": "memory.no_engine_injected",
            }
        # Test-mode fallback: direct threshold checks using REAL rule_ids.
        if confidence < MIN_CONFIDENCE_THRESHOLD:
            return {
                "approved": False,
                "reason": f"Confidence {confidence} below threshold {MIN_CONFIDENCE_THRESHOLD}",
                "policy_id": "research.memory_write.v1",
                "rule_id": "memory.block_low_confidence",
            }
        if sensitivity == "HIGH":
            return {
                "approved": False,
                "reason": "HIGH sensitivity content requires explicit policy permission",
                "policy_id": "research.memory_write.v1",
                "rule_id": "memory.block_high_sensitivity",
            }
        return {
            "approved": True,
            "reason": "Passed policy checks",
            "policy_id": "research.memory_write.v1",
            "rule_id": "memory.allow_write",
        }

    def _validate_candidate(
        self, candidate: dict[str, Any], response_confidence: float
    ) -> dict[str, Any]:
        """Stage 3: Structural validation (NOT policy thresholds).

        v2.27.0: per governance correction, confidence threshold is a POLICY
        decision (handled by _evaluate_policy / the gate), not a structural
        validation. This method now checks only structural field correctness.
        """
        issues = []

        # Check content is not empty
        if not (candidate.get("content") or "").strip():
            issues.append("Empty content")

        # Check subject is not empty
        if not (candidate.get("subject") or "").strip():
            issues.append("Empty subject")

        # Note: source attribution is a soft requirement in v1
        # (chain state may not be available in all execution contexts)

        return {
            "passed": len(issues) == 0,
            "issues": issues,
        }

    def _record_durable_decision(self, candidate: dict[str, Any], envelope: InvocationEnvelope) -> None:
        """Record one durable memory decision row for a candidate (v2.28.0).

        Classifies the outcome: allow / deny / skip / error. Blocked candidates
        are recorded too — the core value of the durable decision log.
        Uses canonical dict digests (Correction B).
        """
        import hashlib
        import json
        from datetime import datetime, timezone

        def _sha256_dict(data: dict) -> str:
            return hashlib.sha256(
                json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()

        pd = candidate.get("policy_decision", {})
        vr = candidate.get("validation_result", {})
        wr = candidate.get("write_result", {})
        policy_ok = pd.get("approved", False)
        validation_ok = vr.get("passed", False)
        committed = wr.get("committed", False)

        # Classify the decision.
        if policy_ok and validation_ok and committed:
            decision = "allow"
            reason_code = ""
        elif not policy_ok:
            decision = "deny"
            reason_code = pd.get("rule_id", "policy_denied")
        elif not validation_ok:
            decision = "skip"
            reason_code = "; ".join(vr.get("issues", ["validation_failed"]))
        else:
            # policy allowed + validation passed but commit failed
            decision = "error"
            reason_code = wr.get("error", wr.get("blocked_reason", "commit_failed"))

        subject = candidate.get("subject", "")
        content = candidate.get("content", "")
        confidence = candidate.get("confidence", 0.0)
        sensitivity = candidate.get("sensitivity", "MEDIUM")
        provenance = candidate.get("provenance", {})
        # Strip volatile fields from provenance for a stable candidate_digest.
        stable_provenance = {
            k: v for k, v in provenance.items()
            if k != "generation_timestamp"
        }

        subject_digest = _sha256_dict({"subject": subject})
        candidate_digest = _sha256_dict({
            "subject": subject,
            "content": content,
            "confidence": confidence,
            "sensitivity": sensitivity,
            "provenance": stable_provenance,
        })

        decision_row = {
            "memory_decision_id": f"md_{envelope.run_id}_{envelope.step_id}_{candidate.get('memory_id', '')[:8]}",
            "run_id": envelope.run_id,
            "chain_id": envelope.chain_id,
            "step_id": envelope.step_id,
            "node_id": "memory_write_decision",
            "candidate_id": candidate.get("memory_id", ""),
            "subject": subject,
            "subject_digest": subject_digest,
            "candidate_digest": candidate_digest,
            "confidence": confidence,
            "sensitivity": sensitivity,
            "policy_id": pd.get("policy_id", ""),
            "rule_id": pd.get("rule_id", ""),
            "decision": decision,
            "reason_code": reason_code,
            "write_ref": wr.get("write_ref", "") if committed else "",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "retention_status": "active",
        }
        # v2.29.0: stash the digest + decision on the candidate dict so the
        # orchestrator can enrich trace metadata. The node is the digest
        # authority (it canonicalizes + strips volatile provenance fields).
        candidate["candidate_digest"] = candidate_digest
        candidate["governed_decision"] = decision
        self._record_memory_decision(decision_row)
