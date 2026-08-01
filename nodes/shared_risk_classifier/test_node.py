"""Test for Shared Risk Classifier node."""
import asyncio
from nodechain.core.envelope import InvocationEnvelope
from nodes.shared_risk_classifier.implementation import SharedRiskClassifierNode


def test_high_risk_classification():
    node = SharedRiskClassifierNode()
    env = InvocationEnvelope(
        envelope_id="t1", run_id="t", chain_id="t", step_id=1, node_id="shared_risk_classifier",
        payload={
            "domain": "research",
            "subject": "test",
            "severity_signals": [{"level": "high"}, {"level": "high"}],
            "confidence_signals": [{"score": 0.3}],
            "uncertainty_factors": ["a", "b", "c"],
            "evidence_refs": [],
        },
    )
    result = asyncio.run(node.execute(env))
    assert result.output["risk_level"] == "HIGH"
    assert result.output["review_required"] is True


def test_low_risk_classification():
    node = SharedRiskClassifierNode()
    env = InvocationEnvelope(
        envelope_id="t2", run_id="t", chain_id="t", step_id=1, node_id="shared_risk_classifier",
        payload={
            "domain": "incident_response",
            "subject": "minor alert",
            "severity_signals": [{"level": "low"}],
            "confidence_signals": [{"score": 0.9}],
            "uncertainty_factors": [],
            "evidence_refs": ["src-1"],
        },
    )
    result = asyncio.run(node.execute(env))
    assert result.output["risk_level"] == "LOW"
    assert result.output["review_required"] is False


def test_domain_neutral():
    """Same node works for different domains."""
    node = SharedRiskClassifierNode()
    for domain in ["research", "incident_response", "security_audit", "fact_check"]:
        env = InvocationEnvelope(
            envelope_id=f"d-{domain}", run_id="t", chain_id="t", step_id=1, node_id="shared_risk_classifier",
            payload={
                "domain": domain,
                "subject": "test",
                "severity_signals": [{"level": "medium"}],
                "confidence_signals": [{"score": 0.6}],
                "uncertainty_factors": [],
                "evidence_refs": ["ref-1"],
            },
        )
        result = asyncio.run(node.execute(env))
        assert "risk_level" in result.output
        assert result.output["domain"] == domain
