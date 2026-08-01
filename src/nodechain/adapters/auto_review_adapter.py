"""Auto Review Adapter — non-interactive review for testing and automation."""

from __future__ import annotations

from typing import Any


class AutoReviewAdapter:
    """
    Non-interactive review adapter for testing and automation.
    Always returns a pre-configured decision.
    Records all review requests for verification.
    """

    def __init__(self, decision: str = "approve"):
        """
        Args:
            decision: One of 'approve', 'reject', 'request_revision', 'timeout'.
        """
        self.decision = decision
        self.review_log: list[dict[str, Any]] = []

    async def request_review(
        self,
        risk_assessment: dict[str, Any],
        chain_outputs: dict[str, Any],
        chain_name: str = "NodeChain",
    ) -> str:
        """Record the review request and return the pre-configured decision."""
        self.review_log.append({
            "risk_assessment": risk_assessment,
            "chain_outputs": {
                k: type(v).__name__ for k, v in chain_outputs.items()
            },
            "chain_name": chain_name,
        })
        return self.decision
