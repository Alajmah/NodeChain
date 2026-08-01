"""Memory Write Flow — 5-stage governed write pipeline."""

from __future__ import annotations

from typing import Any

MIN_CONFIDENCE_THRESHOLD = 0.7


class WriteFlow:
    """
    The 5-stage memory write flow, extracted for independent testability.

    Stages:
      1. Proposal — extract candidates from chain output
      2. Policy — evaluate write policy against each candidate
      3. Validation — check content, subject, confidence
      4. Commit — persist to memory store (delegated to MemoryManager)
      5. Trace — record write decision in trace
    """

    def propose_candidates(
        self,
        response_data: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Stage 1: Extract write candidates from response data."""
        candidates = []

        recommendation = response_data.get("recommendation", "")
        executive_summary = response_data.get("executive_summary", "")
        confidence = (
            response_data.get("confidence_statement", {}).get("numeric", 0.0)
        )

        if recommendation:
            candidates.append({
                "memory_type": "session_knowledge",
                "subject": response_data.get("query", "research_result"),
                "content": recommendation,
                "confidence": confidence,
                "provenance": {
                    "source_count": len(
                        response_data.get("source_references", [])
                    ),
                    "chain_id": response_data.get("chain_id", ""),
                    "run_id": response_data.get("run_id", ""),
                },
            })

        if executive_summary and executive_summary != recommendation:
            candidates.append({
                "memory_type": "session_summary",
                "subject": f"summary:{response_data.get('query', 'research')}",
                "content": executive_summary,
                "confidence": confidence,
                "provenance": {
                    "source_count": len(
                        response_data.get("source_references", [])
                    ),
                    "chain_id": response_data.get("chain_id", ""),
                    "run_id": response_data.get("run_id", ""),
                },
            })

        return candidates

    def evaluate_policy(
        self, candidate: dict[str, Any]
    ) -> dict[str, Any]:
        """Stage 2: Policy gate — should this candidate be written?"""
        confidence = candidate.get("confidence", 0.0)

        reasons: list[str] = []
        allowed = True

        if confidence < MIN_CONFIDENCE_THRESHOLD:
            reasons.append(
                f"Confidence {confidence:.2f} below threshold {MIN_CONFIDENCE_THRESHOLD}"
            )
            allowed = False

        content = candidate.get("content", "") or ""
        if len(content.strip()) < 10:
            reasons.append("Content too short for meaningful memory")
            allowed = False

        return {
            "allowed": allowed,
            "reasons": reasons,
            "threshold": MIN_CONFIDENCE_THRESHOLD,
        }

    def validate_candidate(
        self, candidate: dict[str, Any]
    ) -> dict[str, Any]:
        """Stage 3: Validation — check structural requirements."""
        issues: list[str] = []

        if not (candidate.get("content") or "").strip():
            issues.append("Empty content")

        if not (candidate.get("subject") or "").strip():
            issues.append("Empty subject")

        if candidate.get("confidence", 0) < MIN_CONFIDENCE_THRESHOLD:
            issues.append(
                f"Confidence {candidate.get('confidence', 0)} below write threshold"
            )

        return {
            "passed": len(issues) == 0,
            "issues": issues,
        }

    async def execute_flow(
        self,
        response_data: dict[str, Any],
        commit_fn=None,
    ) -> dict[str, Any]:
        """
        Execute all 5 stages for a response. Returns full write decision.
        commit_fn: async callable(candidate) -> {"committed": bool, ...}
        """
        # Stage 1: Propose
        candidates = self.propose_candidates(response_data)

        results = []
        for candidate in candidates:
            # Stage 2: Policy
            policy_result = self.evaluate_policy(candidate)
            if not policy_result["allowed"]:
                results.append({
                    "subject": candidate.get("subject", ""),
                    "confidence": candidate.get("confidence", 0),
                    "write_result": {
                        "committed": False,
                        "reason": "policy_rejected",
                        "details": policy_result["reasons"],
                    },
                })
                continue

            # Stage 3: Validation
            validation = self.validate_candidate(candidate)
            if not validation["passed"]:
                results.append({
                    "subject": candidate.get("subject", ""),
                    "confidence": candidate.get("confidence", 0),
                    "write_result": {
                        "committed": False,
                        "reason": "validation_failed",
                        "details": validation["issues"],
                    },
                })
                continue

            # Stage 4: Commit (delegated)
            write_result = {"committed": False, "reason": "no_commit_fn"}
            if commit_fn:
                write_result = await commit_fn(candidate)

            # Stage 5: Trace record (returned as part of results)
            results.append({
                "subject": candidate.get("subject", ""),
                "confidence": candidate.get("confidence", 0),
                "write_result": write_result,
            })

        return {
            "candidates": results,
            "total_proposed": len(candidates),
            "total_committed": sum(
                1 for r in results if r["write_result"].get("committed")
            ),
        }
