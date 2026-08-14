"""Test human review gate — verify review triggers and completes correctly."""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


class TestHumanReviewGate:
    """Verify the human review gate triggers and handles decisions."""

    def _make_review_manager(self):
        from nodechain.runtime.review_manager import ReviewManager

        def stub_transition(s, e, *, status, paused_at=None, metadata=None):
            s.status = status
            s.paused_at = paused_at
            if metadata:
                s.metadata = {**(s.metadata or {}), **metadata}

        return ReviewManager(
            commit_review_transition=stub_transition,
            add_trace_event=lambda e: None,
        )

    def test_high_risk_triggers_review(self):
        """HIGH risk should trigger human review."""
        rm = self._make_review_manager()
        result = rm.needs_review({"risk_level": "HIGH", "review_required": False})
        assert result is True

    def test_medium_risk_low_confidence_triggers_review(self):
        """MEDIUM risk with low confidence should trigger review."""
        rm = self._make_review_manager()
        result = rm.needs_review({"risk_level": "MEDIUM", "confidence": 0.2, "review_required": False})
        assert result is True

    def test_low_risk_no_review(self):
        """LOW risk should NOT trigger review."""
        rm = self._make_review_manager()
        result = rm.needs_review({"risk_level": "LOW", "confidence": 0.8, "review_required": False})
        assert result is False

    def test_explicit_review_required_overrides(self):
        """review_required=True should trigger even for LOW risk."""
        rm = self._make_review_manager()
        result = rm.needs_review({"risk_level": "LOW", "confidence": 0.9, "review_required": True})
        assert result is True

    def test_disabled_mode_never_triggers(self):
        """NODECHAIN_REVIEW_MODE=disabled should never trigger review."""
        rm = self._make_review_manager()
        os.environ["NODECHAIN_REVIEW_MODE"] = "disabled"
        try:
            result = rm.needs_review({"risk_level": "HIGH", "review_required": True})
            assert result is False
        finally:
            del os.environ["NODECHAIN_REVIEW_MODE"]


class TestAutoReviewAdapter:
    """Test the non-interactive review adapter."""

    @pytest.mark.asyncio
    async def test_auto_approve(self):
        from nodechain.adapters.auto_review_adapter import AutoReviewAdapter
        adapter = AutoReviewAdapter(decision="approve")
        result = await adapter.request_review(
            risk_assessment={"risk_level": "HIGH"},
            chain_outputs={},
            chain_name="Test",
        )
        assert result == "approve"
        assert len(adapter.review_log) == 1

    @pytest.mark.asyncio
    async def test_auto_reject(self):
        from nodechain.adapters.auto_review_adapter import AutoReviewAdapter
        adapter = AutoReviewAdapter(decision="reject")
        result = await adapter.request_review(
            risk_assessment={"risk_level": "HIGH"},
            chain_outputs={},
        )
        assert result == "reject"

    @pytest.mark.asyncio
    async def test_review_log_records_payload(self):
        from nodechain.adapters.auto_review_adapter import AutoReviewAdapter
        adapter = AutoReviewAdapter(decision="approve")
        await adapter.request_review(
            risk_assessment={"risk_level": "HIGH", "confidence": 0.3},
            chain_outputs={"evidence": dict},
        )
        assert adapter.review_log[0]["risk_assessment"]["risk_level"] == "HIGH"


class TestReviewInOrchestrator:
    """Verify the orchestrator correctly handles review in a chain run."""

    def test_auto_approve_chain_completes(self):
        """Chain with HIGH risk and auto-approve should complete."""
        from test_runtime import load_blueprint, _create_mock_nodes, MockNode
        from nodechain.runtime.orchestrator import Orchestrator
        from nodechain.core.port import PortType
        from nodechain.core.trace import EventType
        from nodechain.core.envelope import EnvelopeResponse

        blueprint = load_blueprint("blueprints/research_decision_v1.yaml")
        nodes = _create_mock_nodes()

        # Override risk_classifier to return HIGH risk
        class HighRiskClassifier(MockNode):
            async def execute(self, envelope):
                return EnvelopeResponse(
                    request_envelope_id=envelope.envelope_id,
                    run_id=envelope.run_id,
                    chain_id=envelope.chain_id,
                    node_id="risk_classifier",
                    step_id=envelope.step_id,
                    output={
                        "risk_level": "HIGH",
                        "confidence": 0.3,
                        "review_required": True,
                        "uncertainty_disclosures": [],
                        "risk_factors": ["test high risk"],
                    },
                    output_type=PortType.RISK_ASSESSMENT,
                )

        nodes["risk_classifier"] = HighRiskClassifier("risk_classifier", PortType.VALIDATED_EVIDENCE, PortType.RISK_ASSESSMENT)

        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-approve"
        try:
            orch = Orchestrator(blueprint=blueprint, nodes=nodes)
            import asyncio
            trace = asyncio.run(orch.run("Test HIGH risk query"))

            assert trace.final_status == "completed"
            event_types = {e.event_type for e in trace.events}
            assert EventType.HUMAN_REVIEW_REQUESTED in event_types
            assert EventType.HUMAN_REVIEW_COMPLETED in event_types
        finally:
            del os.environ["NODECHAIN_REVIEW_MODE"]

    def test_auto_reject_chain_fails(self):
        """Chain with HIGH risk and auto-reject should fail."""
        from test_runtime import load_blueprint, _create_mock_nodes, MockNode
        from nodechain.runtime.orchestrator import Orchestrator
        from nodechain.core.port import PortType
        from nodechain.core.trace import EventType
        from nodechain.core.envelope import EnvelopeResponse

        blueprint = load_blueprint("blueprints/research_decision_v1.yaml")
        nodes = _create_mock_nodes()

        class HighRiskClassifier(MockNode):
            async def execute(self, envelope):
                return EnvelopeResponse(
                    request_envelope_id=envelope.envelope_id,
                    run_id=envelope.run_id,
                    chain_id=envelope.chain_id,
                    node_id="risk_classifier",
                    step_id=envelope.step_id,
                    output={
                        "risk_level": "HIGH",
                        "confidence": 0.2,
                        "review_required": True,
                        "uncertainty_disclosures": [],
                        "risk_factors": ["test rejection"],
                    },
                    output_type=PortType.RISK_ASSESSMENT,
                )

        nodes["risk_classifier"] = HighRiskClassifier("risk_classifier", PortType.VALIDATED_EVIDENCE, PortType.RISK_ASSESSMENT)

        os.environ["NODECHAIN_REVIEW_MODE"] = "auto-reject"
        try:
            orch = Orchestrator(blueprint=blueprint, nodes=nodes)
            import asyncio
            trace = asyncio.run(orch.run("Test rejection query"))

            assert trace.final_status == "failed"
            event_types = {e.event_type for e in trace.events}
            assert EventType.HUMAN_REVIEW_REQUESTED in event_types
            assert EventType.HUMAN_REVIEW_COMPLETED in event_types
            # Verify reject is recorded
            review_events = [e for e in trace.events if e.event_type == EventType.HUMAN_REVIEW_COMPLETED]
            assert any(e.decision == "reject" for e in review_events)
        finally:
            del os.environ["NODECHAIN_REVIEW_MODE"]
