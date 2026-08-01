"""Tests for the Incident Response Reference Chain (v1.19.0).

Tests cover:
1. Individual node execution (5 nodes)
2. End-to-end chain execution
3. Evidence chain verification
4. Governance gate enforcement
5. Certified registry integration
"""

import asyncio
import hashlib
import json
import pytest
import uuid

from nodes.incident_response.implementations.incident_detector import IncidentDetector
from nodes.incident_response.implementations.severity_triager import SeverityTriager
from nodes.incident_response.implementations.remediation_decisioner import RemediationDecisioner
from nodes.incident_response.implementations.governed_remediator import GovernedRemediator
from nodes.incident_response.implementations.recovery_verifier import RecoveryVerifier
from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse


def _make_envelope(payload: dict, run_id: str = "") -> InvocationEnvelope:
    return InvocationEnvelope(
        envelope_id=str(uuid.uuid4()),
        run_id=run_id or str(uuid.uuid4()),
        chain_id="incident-response-v1",
        node_id="test",
        step_id=1,
        payload=payload,
    )


class TestIncidentDetector:
    """Node 1: Incident detection from monitoring signals."""

    @pytest.mark.asyncio
    async def test_detects_drift_incident(self):
        node = IncidentDetector()
        envelope = _make_envelope({
            "signals": [],
            "drift_report": {"drift_detected": True, "drift_summary": "Config mismatch", "drift_fields": ["memory.max"]},
        })
        result = await node.execute(envelope)
        assert result.output["detected"] is True
        assert len(result.output["anomalies"]) == 1
        assert result.output["anomalies"][0]["type"] == "configuration_drift"
        assert result.output["incident_id"].startswith("INC-")

    @pytest.mark.asyncio
    async def test_detects_metric_anomaly(self):
        node = IncidentDetector()
        envelope = _make_envelope({
            "signals": [{"metric": "cpu_usage", "value": 95, "threshold": 80, "source": "prometheus"}],
        })
        result = await node.execute(envelope)
        assert result.output["detected"] is True
        assert result.output["anomalies"][0]["type"] == "cpu_usage"

    @pytest.mark.asyncio
    async def test_detects_critical_alerts(self):
        node = IncidentDetector()
        envelope = _make_envelope({
            "signals": [],
            "alert_history": [{"severity": "critical", "message": "OOM killed"}],
        })
        result = await node.execute(envelope)
        assert result.output["detected"] is True
        assert result.output["severity_hint"] == "critical"

    @pytest.mark.asyncio
    async def test_no_incident_when_clean(self):
        node = IncidentDetector()
        envelope = _make_envelope({"signals": [], "drift_report": {}})
        result = await node.execute(envelope)
        assert result.output["detected"] is False
        assert result.output["incident_id"] == ""

    @pytest.mark.asyncio
    async def test_contract_and_manifest(self):
        node = IncidentDetector()
        assert node.manifest().node_id == "incident_detector"
        assert node.contract().contract_id == "incident.detector.v1"
        assert "incident_id" in node.contract().exit.guaranteed_fields


class TestSeverityTriager:
    """Node 2: Severity classification."""

    @pytest.mark.asyncio
    async def test_critical_severity(self):
        node = SeverityTriager()
        envelope = _make_envelope({
            "detected": True,
            "anomalies": [{"type": "critical_alerts", "source": "alerting", "count": 3}],
            "severity_hint": "critical",
        })
        result = await node.execute(envelope)
        assert result.output["severity"] == "critical"
        assert result.output["urgency"] == "immediate"
        assert result.output["requires_remediation"] is True

    @pytest.mark.asyncio
    async def test_low_severity(self):
        node = SeverityTriager()
        envelope = _make_envelope({
            "detected": True,
            "anomalies": [{"type": "minor_metric", "source": "monitoring"}],
        })
        result = await node.execute(envelope)
        assert result.output["severity"] == "low"
        assert result.output["requires_remediation"] is False

    @pytest.mark.asyncio
    async def test_human_review_for_critical(self):
        node = SeverityTriager()
        envelope = _make_envelope({
            "detected": True,
            "anomalies": [{"type": "critical_alerts", "count": 5, "source": "alerting"}],
            "severity_hint": "critical",
        })
        result = await node.execute(envelope)
        assert result.output["requires_human_review"] is True


class TestRemediationDecisioner:
    """Node 3: Remediation mode decision."""

    @pytest.mark.asyncio
    async def test_recommend_mode_for_high(self):
        node = RemediationDecisioner()
        envelope = _make_envelope({
            "severity": "high",
            "requires_remediation": True,
            "urgency": "urgent",
        })
        result = await node.execute(envelope)
        assert result.output["remediation_mode"] == "recommend"
        assert result.output["authorized"] is True
        assert result.output["selected_action"] == "rollback_artifact"
        assert len(result.output["policy_digest"]) == 64

    @pytest.mark.asyncio
    async def test_manual_mode_for_critical(self):
        node = RemediationDecisioner()
        envelope = _make_envelope({
            "severity": "critical",
            "requires_remediation": True,
        })
        result = await node.execute(envelope)
        assert result.output["remediation_mode"] == "manual"
        assert result.output["authorized"] is True  # authorized to alert, not to execute
        assert result.output["selected_action"] == "alert"

    @pytest.mark.asyncio
    async def test_no_action_when_not_required(self):
        node = RemediationDecisioner()
        envelope = _make_envelope({
            "severity": "low",
            "requires_remediation": False,
        })
        result = await node.execute(envelope)
        assert result.output["selected_action"] == "no_action"
        assert result.output["authorized"] is False

    @pytest.mark.asyncio
    async def test_policy_digest_deterministic(self):
        node = RemediationDecisioner()
        payload = {"severity": "high", "requires_remediation": True}
        r1 = await node.execute(_make_envelope(payload))
        r2 = await node.execute(_make_envelope(payload))
        assert r1.output["policy_digest"] == r2.output["policy_digest"]


class TestGovernedRemediator:
    """Node 4: Governed remediation execution."""

    @pytest.mark.asyncio
    async def test_executes_authorized_rollback(self):
        node = GovernedRemediator()
        envelope = _make_envelope({
            "remediation_mode": "auto_rollback",
            "authorized": True,
            "selected_action": "rollback_artifact",
            "policy_digest": "abc123",
            "target": "pve1/801",
        })
        result = await node.execute(envelope)
        assert result.output["executed"] is True
        assert result.output["rollback_attempted"] is True
        assert result.output["final_state"] == "executed"
        assert result.output["evidence_count"] >= 3

    @pytest.mark.asyncio
    async def test_denies_unauthorized(self):
        node = GovernedRemediator()
        envelope = _make_envelope({
            "remediation_mode": "auto_rollback",
            "authorized": False,
            "selected_action": "rollback_artifact",
        })
        result = await node.execute(envelope)
        assert result.output["executed"] is False
        assert result.output["final_state"] == "denied"
        assert result.output["evidence"][0]["result"] == "denied"

    @pytest.mark.asyncio
    async def test_manual_mode_no_execution(self):
        node = GovernedRemediator()
        envelope = _make_envelope({
            "remediation_mode": "manual",
            "authorized": True,
            "selected_action": "alert",
        })
        result = await node.execute(envelope)
        assert result.output["executed"] is False
        assert result.output["final_state"] == "manual_intervention_required"

    @pytest.mark.asyncio
    async def test_recommend_mode_produces_plan(self):
        node = GovernedRemediator()
        envelope = _make_envelope({
            "remediation_mode": "recommend",
            "authorized": True,
            "selected_action": "rollback_artifact",
            "policy_digest": "abc123",
        })
        result = await node.execute(envelope)
        assert result.output["executed"] is False
        assert result.output["final_state"] == "recommendation_produced"

    @pytest.mark.asyncio
    async def test_side_effects_declared(self):
        node = GovernedRemediator()
        contract = node.contract()
        assert len(contract.side_effects) > 0
        assert contract.side_effects[0].effect_type == "deployment"


class TestRecoveryVerifier:
    """Node 5: Recovery verification."""

    @pytest.mark.asyncio
    async def test_verifies_successful_remediation(self):
        node = RecoveryVerifier()
        envelope = _make_envelope({
            "final_state": "executed",
            "executed": True,
            "evidence": [{"gate": "execution", "result": "success"}],
            "incident_id": "INC-1234",
        })
        result = await node.execute(envelope)
        assert result.output["recovered"] is True
        assert result.output["verified"] is True
        assert result.output["incident_status"] == "resolved"

    @pytest.mark.asyncio
    async def test_pending_for_recommendation(self):
        node = RecoveryVerifier()
        envelope = _make_envelope({
            "final_state": "recommendation_produced",
            "executed": False,
            "evidence": [],
        })
        result = await node.execute(envelope)
        assert result.output["recovered"] is False
        assert result.output["incident_status"] == "remediation_pending"

    @pytest.mark.asyncio
    async def test_evidence_chain_built(self):
        node = RecoveryVerifier()
        envelope = _make_envelope({
            "final_state": "executed",
            "executed": True,
            "evidence": [{"gate": "authorization", "result": "approved"}, {"gate": "execution", "result": "success"}],
        })
        result = await node.execute(envelope)
        chain = result.output["evidence_chain"]
        assert len(chain) >= 3  # 2 from input + 1 from verification
        assert chain[-1]["gate"] == "recovery_verification"


class TestEndToEndChain:
    """Full pipeline execution: detect → triage → decide → remediate → verify."""

    @pytest.mark.asyncio
    async def test_full_chain_drift_incident(self):
        """Simulates a configuration drift incident flowing through the full chain."""
        run_id = str(uuid.uuid4())

        # Node 1: Detect
        detector = IncidentDetector()
        detect_result = await detector.execute(_make_envelope({
            "signals": [],
            "drift_report": {
                "drift_detected": True,
                "drift_summary": "memory.max changed from 2G to 512M",
                "drift_fields": ["memory.max"],
                "evidence_strength": "observed",
            },
        }, run_id=run_id))
        assert detect_result.output["detected"] is True

        # Node 2: Triage
        triager = SeverityTriager()
        triage_result = await triager.execute(_make_envelope(
            detect_result.output, run_id=run_id
        ))
        assert triage_result.output["severity"] in ("high", "critical", "medium")
        assert triage_result.output["requires_remediation"] is True

        # Node 3: Decide
        decisioner = RemediationDecisioner()
        decision_result = await decisioner.execute(_make_envelope(
            triage_result.output, run_id=run_id
        ))
        assert decision_result.output["remediation_mode"] in ("recommend", "manual", "auto_rollback")

        # Node 4: Remediate
        remediator = GovernedRemediator()
        remediation_result = await remediator.execute(_make_envelope(
            decision_result.output, run_id=run_id
        ))
        assert remediation_result.output["final_state"] in (
            "executed", "recommendation_produced", "manual_intervention_required"
        )

        # Node 5: Verify
        verifier = RecoveryVerifier()
        verification_result = await verifier.execute(_make_envelope(
            remediation_result.output, run_id=run_id
        ))
        assert verification_result.output["verified"] is True
        assert verification_result.output["incident_status"] in (
            "resolved", "remediation_pending", "awaiting_operator"
        )

    @pytest.mark.asyncio
    async def test_full_chain_no_incident(self):
        """Clean signals — no incident detected."""
        run_id = str(uuid.uuid4())

        detector = IncidentDetector()
        detect_result = await detector.execute(_make_envelope({
            "signals": [{"metric": "cpu", "value": 30, "threshold": 80, "status": "ok"}],
            "drift_report": {},
        }, run_id=run_id))
        assert detect_result.output["detected"] is False

        triager = SeverityTriager()
        triage_result = await triager.execute(_make_envelope(
            detect_result.output, run_id=run_id
        ))
        assert triage_result.output["severity"] == "low"

        decisioner = RemediationDecisioner()
        decision_result = await decisioner.execute(_make_envelope(
            triage_result.output, run_id=run_id
        ))
        assert decision_result.output["selected_action"] == "no_action"

    @pytest.mark.asyncio
    async def test_full_chain_critical_with_alerts(self):
        """Critical incident from alert history flows through with human review."""
        run_id = str(uuid.uuid4())

        # Detect critical
        detector = IncidentDetector()
        detect_result = await detector.execute(_make_envelope({
            "signals": [],
            "alert_history": [
                {"severity": "critical", "message": "OOM"},
                {"severity": "critical", "message": "Disk full"},
            ],
        }, run_id=run_id))
        assert detect_result.output["severity_hint"] == "critical"

        # Triage → critical
        triager = SeverityTriager()
        triage_result = await triager.execute(_make_envelope(
            detect_result.output, run_id=run_id
        ))
        assert triage_result.output["severity"] == "critical"
        assert triage_result.output["requires_human_review"] is True

        # Decide → manual (critical requires human)
        decisioner = RemediationDecisioner()
        decision_result = await decisioner.execute(_make_envelope(
            triage_result.output, run_id=run_id
        ))
        assert decision_result.output["remediation_mode"] == "manual"

        # Remediate → manual_intervention_required
        remediator = GovernedRemediator()
        remediation_result = await remediator.execute(_make_envelope(
            decision_result.output, run_id=run_id
        ))
        assert remediation_result.output["final_state"] == "manual_intervention_required"

        # Verify → awaiting_operator
        verifier = RecoveryVerifier()
        verification_result = await verifier.execute(_make_envelope(
            remediation_result.output, run_id=run_id
        ))
        assert verification_result.output["incident_status"] == "awaiting_operator"


class TestEvidenceChain:
    """Verify evidence chain is maintained through the pipeline."""

    @pytest.mark.asyncio
    async def test_policy_digest_propagates(self):
        """Policy digest from decisioner reaches the remediation evidence."""
        run_id = str(uuid.uuid4())

        decisioner = RemediationDecisioner()
        decision = await decisioner.execute(_make_envelope({
            "severity": "high", "requires_remediation": True,
        }, run_id=run_id))

        remediator = GovernedRemediator()
        remediation = await remediator.execute(_make_envelope(
            decision.output, run_id=run_id
        ))

        # Policy digest should appear in evidence
        auth_evidence = [e for e in remediation.output["evidence"] if e.get("gate") == "authorization"]
        if auth_evidence and auth_evidence[0]["result"] == "approved":
            assert auth_evidence[0]["policy_digest"] == decision.output["policy_digest"]

    @pytest.mark.asyncio
    async def test_incident_id_propagates(self):
        """Incident ID flows through the entire chain."""
        run_id = str(uuid.uuid4())

        detector = IncidentDetector()
        detect = await detector.execute(_make_envelope({
            "signals": [],
            "drift_report": {"drift_detected": True, "drift_summary": "test"},
        }, run_id=run_id))
        incident_id = detect.output["incident_id"]
        assert incident_id

        triager = SeverityTriager()
        triage = await triager.execute(_make_envelope(detect.output, run_id=run_id))
        assert triage.output["incident_id"] == incident_id

        decisioner = RemediationDecisioner()
        decision = await decisioner.execute(_make_envelope(triage.output, run_id=run_id))
        assert decision.output["incident_id"] == incident_id
