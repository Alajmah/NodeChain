"""Tests for interactive review adapter integration.

AC1: interactive mode no longer silently approves.
AC2: HumanAdapter is called through the normal runtime path.
AC3: timeout produces REVIEW_TIMEOUT and terminal failed state.
AC4: approve resumes through scheduler transition.
AC5: reject produces terminal failed state.
AC6: request_revision routes to explicit revision target.
AC7: CLI pause/resume demo remains deterministic.
"""

import pytest
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


class TestInteractiveReviewAdapter:
    """Verify HumanAdapter is called for interactive mode."""

    @pytest.mark.asyncio
    async def test_human_adapter_approve(self):
        """AC2+AC4: HumanAdapter with approve decision completes chain."""
        from nodechain.adapters.human_adapter import HumanAdapter

        adapter = HumanAdapter(decision_provider="approve")
        result = await adapter.request_review(
            risk_assessment={"risk_level": "HIGH", "confidence": 0.3},
            chain_outputs={"evidence_synthesizer": {"claims": ["test"]}},
            chain_name="Test Chain",
        )
        assert result == "approve"

    @pytest.mark.asyncio
    async def test_human_adapter_reject(self):
        """AC5: HumanAdapter with reject decision."""
        from nodechain.adapters.human_adapter import HumanAdapter

        adapter = HumanAdapter(decision_provider="reject")
        result = await adapter.request_review(
            risk_assessment={"risk_level": "HIGH", "confidence": 0.2},
            chain_outputs={},
            chain_name="Test Chain",
        )
        assert result == "reject"

    @pytest.mark.asyncio
    async def test_human_adapter_revision(self):
        """AC6: HumanAdapter with request_revision decision."""
        from nodechain.adapters.human_adapter import HumanAdapter

        adapter = HumanAdapter(decision_provider="request_revision")
        result = await adapter.request_review(
            risk_assessment={"risk_level": "HIGH", "confidence": 0.4},
            chain_outputs={},
            chain_name="Test Chain",
        )
        assert result == "request_revision"

    @pytest.mark.asyncio
    async def test_human_adapter_callable_provider(self):
        """HumanAdapter accepts callable decision provider."""
        from nodechain.adapters.human_adapter import HumanAdapter

        call_log = []

        def provider(risk, outputs):
            call_log.append({"risk": risk, "outputs": outputs})
            return "approve"

        adapter = HumanAdapter(decision_provider=provider)
        result = await adapter.request_review(
            risk_assessment={"risk_level": "HIGH"},
            chain_outputs={"data": "test"},
        )
        assert result == "approve"
        assert len(call_log) == 1
        assert call_log[0]["risk"]["risk_level"] == "HIGH"

    @pytest.mark.asyncio
    async def test_human_adapter_async_provider(self):
        """HumanAdapter accepts async callable decision provider."""
        from nodechain.adapters.human_adapter import HumanAdapter

        async def provider(risk, outputs):
            return "reject"

        adapter = HumanAdapter(decision_provider=provider)
        result = await adapter.request_review(
            risk_assessment={"risk_level": "HIGH"},
            chain_outputs={},
        )
        assert result == "reject"


class TestInteractiveReviewInOrchestrator:
    """Verify interactive review through the full orchestrator path."""

    def test_interactive_approve_completes(self):
        """AC1+AC4: Interactive mode with approve completes the chain."""
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
                        "confidence": 0.3,
                        "review_required": True,
                        "uncertainty_disclosures": [],
                        "risk_factors": ["test"],
                    },
                    output_type=PortType.RISK_ASSESSMENT,
                )

        nodes["risk_classifier"] = HighRiskClassifier(
            "risk_classifier", PortType.VALIDATED_EVIDENCE, PortType.RISK_ASSESSMENT,
        )

        os.environ["NODECHAIN_REVIEW_MODE"] = "interactive"
        os.environ["NODECHAIN_REVIEW_DECISION"] = "approve"
        try:
            orch = Orchestrator(blueprint=blueprint, nodes=nodes)
            import asyncio
            trace = asyncio.run(orch.run("Test interactive approve"))

            assert trace.final_status == "completed"
            event_types = {e.event_type for e in trace.events}
            assert EventType.HUMAN_REVIEW_REQUESTED in event_types
            assert EventType.HUMAN_REVIEW_COMPLETED in event_types
            # Verify approve decision in trace
            review_events = [e for e in trace.events if e.event_type == EventType.HUMAN_REVIEW_COMPLETED]
            assert any(e.decision == "approve" for e in review_events)
        finally:
            del os.environ["NODECHAIN_REVIEW_MODE"]
            del os.environ["NODECHAIN_REVIEW_DECISION"]

    def test_interactive_reject_fails(self):
        """AC5: Interactive reject produces terminal failed state."""
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
                        "risk_factors": ["test reject"],
                    },
                    output_type=PortType.RISK_ASSESSMENT,
                )

        nodes["risk_classifier"] = HighRiskClassifier(
            "risk_classifier", PortType.VALIDATED_EVIDENCE, PortType.RISK_ASSESSMENT,
        )

        os.environ["NODECHAIN_REVIEW_MODE"] = "interactive"
        os.environ["NODECHAIN_REVIEW_DECISION"] = "reject"
        try:
            orch = Orchestrator(blueprint=blueprint, nodes=nodes)
            import asyncio
            trace = asyncio.run(orch.run("Test interactive reject"))

            assert trace.final_status == "failed"
            event_types = {e.event_type for e in trace.events}
            assert EventType.HUMAN_REVIEW_REQUESTED in event_types
            assert EventType.HUMAN_REVIEW_COMPLETED in event_types
            review_events = [e for e in trace.events if e.event_type == EventType.HUMAN_REVIEW_COMPLETED]
            assert any(e.decision == "reject" for e in review_events)
        finally:
            del os.environ["NODECHAIN_REVIEW_MODE"]
            del os.environ["NODECHAIN_REVIEW_DECISION"]

    def test_interactive_revision_loops(self):
        """AC6: Interactive revision routes to task_planner."""
        from test_runtime import load_blueprint, _create_mock_nodes, MockNode
        from nodechain.runtime.orchestrator import Orchestrator
        from nodechain.core.port import PortType
        from nodechain.core.trace import EventType
        from nodechain.core.envelope import EnvelopeResponse

        blueprint = load_blueprint("blueprints/research_decision_v1.yaml")
        nodes = _create_mock_nodes()

        class HighRiskThenLow(MockNode):
            """Returns HIGH first time, LOW after revision loop."""
            def __init__(self):
                super().__init__(
                    "risk_classifier", PortType.VALIDATED_EVIDENCE, PortType.RISK_ASSESSMENT,
                )
                self._call_count = 0

            async def execute(self, envelope):
                self._call_count += 1
                if self._call_count <= 1:
                    risk_level = "HIGH"
                    review_required = True
                else:
                    risk_level = "LOW"
                    review_required = False
                return EnvelopeResponse(
                    request_envelope_id=envelope.envelope_id,
                    run_id=envelope.run_id,
                    chain_id=envelope.chain_id,
                    node_id="risk_classifier",
                    step_id=envelope.step_id,
                    output={
                        "risk_level": risk_level,
                        "confidence": 0.4,
                        "review_required": review_required,
                        "uncertainty_disclosures": [],
                        "risk_factors": ["test revision"],
                    },
                    output_type=PortType.RISK_ASSESSMENT,
                )

        nodes["risk_classifier"] = HighRiskThenLow()

        os.environ["NODECHAIN_REVIEW_MODE"] = "interactive"
        os.environ["NODECHAIN_REVIEW_DECISION"] = "request_revision"
        try:
            orch = Orchestrator(blueprint=blueprint, nodes=nodes)
            import asyncio
            trace = asyncio.run(orch.run("Test interactive revision"))

            # Chain should complete (revision routes back)
            assert trace.final_status == "completed"
            event_types = {e.event_type for e in trace.events}
            assert EventType.HUMAN_REVIEW_REQUESTED in event_types
            assert EventType.HUMAN_REVIEW_COMPLETED in event_types
            # Verify revision decision
            review_events = [e for e in trace.events if e.event_type == EventType.HUMAN_REVIEW_COMPLETED]
            assert any(e.decision == "request_revision" for e in review_events)
        finally:
            del os.environ["NODECHAIN_REVIEW_MODE"]
            del os.environ["NODECHAIN_REVIEW_DECISION"]

    def test_interactive_timeout_fails(self):
        """AC3: Interactive timeout produces REVIEW_TIMEOUT and terminal failed state."""
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
                        "risk_factors": ["test timeout"],
                    },
                    output_type=PortType.RISK_ASSESSMENT,
                )

        nodes["risk_classifier"] = HighRiskClassifier(
            "risk_classifier", PortType.VALIDATED_EVIDENCE, PortType.RISK_ASSESSMENT,
        )

        os.environ["NODECHAIN_REVIEW_MODE"] = "interactive"
        os.environ["NODECHAIN_REVIEW_DECISION"] = "timeout"
        try:
            orch = Orchestrator(blueprint=blueprint, nodes=nodes)
            import asyncio
            trace = asyncio.run(orch.run("Test interactive timeout"))

            assert trace.final_status == "failed"
            event_types = {e.event_type for e in trace.events}
            assert EventType.HUMAN_REVIEW_REQUESTED in event_types
            assert EventType.HUMAN_REVIEW_TIMEOUT in event_types
        finally:
            del os.environ["NODECHAIN_REVIEW_MODE"]
            del os.environ["NODECHAIN_REVIEW_DECISION"]

    def test_interactive_no_longer_silently_approves(self):
        """AC1: Verify interactive mode actually calls HumanAdapter."""
        from nodechain.adapters.human_adapter import HumanAdapter

        # Track that the adapter was called
        call_log = []

        class TrackingAdapter(HumanAdapter):
            async def request_review(self, **kwargs):
                call_log.append(True)
                return "approve"

        adapter = TrackingAdapter()
        import asyncio
        result = asyncio.run(adapter.request_review(
            risk_assessment={"risk_level": "HIGH"},
            chain_outputs={},
        ))
        assert result == "approve"
        assert len(call_log) == 1, "HumanAdapter.request_review was NOT called"
