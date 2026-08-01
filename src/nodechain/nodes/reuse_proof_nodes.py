"""Reuse Proof domain adapter and entry nodes (v2.62.0).

These nodes are domain-specific: they produce canonical RISK_CONTEXT
output that the shared_risk_classifier can consume. The shared nodes
themselves remain domain-neutral and unchanged.
"""

from __future__ import annotations

from typing import Any

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import (
    EntryContract, ExitContract, NodeContract, Requirements,
)
from nodechain.core.manifest import NodeManifest
from nodechain.core.port import PortType
from nodechain.nodes.base_node import BaseNode


# ── Fact Check domain ─────────────────────────────────────────────────────

class FactCheckEntryNode(BaseNode):
    """Entry node for fact-checking proof chain. Produces raw fact-check data."""

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="fact_checker",
            node_type="deterministic",
            name="Fact Checker (Proof)",
            description="Produces fact-check findings for risk assessment.",
            contract=NodeContract(
                contract_id="proof.fact-checker.v1",
                node_id="fact_checker",
                version="1.0.0",
                entry=EntryContract(input_type=PortType.RAW_QUERY, schema_ref='nodechain://schemas/dynamic'),
                exit=ExitContract(output_type="fact_check_result", schema_ref='nodechain://schemas/dynamic'),
            ),
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id, chain_id=envelope.chain_id,
            node_id="fact_checker", step_id=envelope.step_id,
            output={
                "domain": "fact_check",
                "claims_checked": 3,
                "verified": 2,
                "disputed": 1,
                "confidence_per_claim": [0.9, 0.8, 0.3],
            },
            output_type="fact_check_result",
        )


class FactCheckRiskAdapterNode(BaseNode):
    """Adapts fact-check results into canonical RISK_CONTEXT."""

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="risk_context_adapter",
            node_type="deterministic",
            name="Fact Check Risk Adapter",
            description="Normalizes fact-check output into RISK_CONTEXT.",
            contract=NodeContract(
                contract_id="proof.fact-check-adapter.v1",
                node_id="risk_context_adapter",
                version="1.0.0",
                entry=EntryContract(input_type="fact_check_result", schema_ref='nodechain://schemas/dynamic'),
                exit=ExitContract(output_type=PortType.RISK_CONTEXT, schema_ref='nodechain://schemas/dynamic', guaranteed_fields=["domain", "subject", "severity_signals"]),
            ),
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        data = envelope.payload
        disputed = data.get("disputed", 0)
        confidence = data.get("confidence_per_claim", [0.5])
        mean_conf = sum(confidence) / len(confidence) if confidence else 0.5

        risk_context = {
            "domain": "fact_check",
            "subject": "fact verification",
            "severity_signals": [
                {"level": "high", "source": "disputed_claim"} for _ in range(disputed)
            ],
            "confidence_signals": [{"score": c} for c in confidence],
            "uncertainty_factors": ["source reliability"] if disputed > 0 else [],
            "evidence_refs": [f"claim-{i}" for i in range(data.get("claims_checked", 0))],
        }

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id, chain_id=envelope.chain_id,
            node_id="risk_context_adapter", step_id=envelope.step_id,
            output=risk_context,
            output_type=PortType.RISK_CONTEXT,
        )


# ── Incident Response domain ──────────────────────────────────────────────

class IncidentEntryNode(BaseNode):
    """Entry node for incident response proof chain."""

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="incident_triager",
            node_type="deterministic",
            name="Incident Triager (Proof)",
            description="Produces incident triage data for risk assessment.",
            contract=NodeContract(
                contract_id="proof.incident-triager.v1",
                node_id="incident_triager",
                version="1.0.0",
                entry=EntryContract(input_type=PortType.RAW_QUERY, schema_ref='nodechain://schemas/dynamic'),
                exit=ExitContract(output_type="incident_triage_result", schema_ref='nodechain://schemas/dynamic'),
            ),
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id, chain_id=envelope.chain_id,
            node_id="incident_triager", step_id=envelope.step_id,
            output={
                "domain": "incident_response",
                "severity": "medium",
                "affected_systems": 2,
                "contains_successful": False,
            },
            output_type="incident_triage_result",
        )


class IncidentRiskAdapterNode(BaseNode):
    """Adapts incident triage into canonical RISK_CONTEXT."""

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="incident_risk_adapter",
            node_type="deterministic",
            name="Incident Risk Adapter",
            description="Normalizes incident triage into RISK_CONTEXT.",
            contract=NodeContract(
                contract_id="proof.incident-adapter.v1",
                node_id="incident_risk_adapter",
                version="1.0.0",
                entry=EntryContract(input_type="incident_triage_result", schema_ref='nodechain://schemas/dynamic'),
                exit=ExitContract(output_type=PortType.RISK_CONTEXT, schema_ref='nodechain://schemas/dynamic', guaranteed_fields=["domain", "subject", "severity_signals"]),
            ),
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        data = envelope.payload
        severity = data.get("severity", "low")
        affected = data.get("affected_systems", 0)

        level_map = {"critical": "high", "high": "high", "medium": "medium", "low": "low"}
        severity_level = level_map.get(severity, "low")

        risk_context = {
            "domain": "incident_response",
            "subject": "incident triage",
            "severity_signals": [{"level": severity_level, "source": "triage"}],
            "confidence_signals": [{"score": 0.7}],
            "uncertainty_factors": ["blast radius unknown"] if affected > 1 else [],
            "evidence_refs": [f"system-{i}" for i in range(affected)],
        }

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id, chain_id=envelope.chain_id,
            node_id="incident_risk_adapter", step_id=envelope.step_id,
            output=risk_context,
            output_type=PortType.RISK_CONTEXT,
        )


# ── Security Audit domain ─────────────────────────────────────────────────

class AuditEntryNode(BaseNode):
    """Entry node for security audit proof chain."""

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="audit_scanner",
            node_type="deterministic",
            name="Audit Scanner (Proof)",
            description="Produces security audit findings for risk assessment.",
            contract=NodeContract(
                contract_id="proof.audit-scanner.v1",
                node_id="audit_scanner",
                version="1.0.0",
                entry=EntryContract(input_type=PortType.RAW_QUERY, schema_ref='nodechain://schemas/dynamic'),
                exit=ExitContract(output_type="audit_scan_result", schema_ref='nodechain://schemas/dynamic'),
            ),
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id, chain_id=envelope.chain_id,
            node_id="audit_scanner", step_id=envelope.step_id,
            output={
                "domain": "security_audit",
                "findings_total": 5,
                "findings_high": 1,
                "findings_medium": 2,
                "findings_low": 2,
            },
            output_type="audit_scan_result",
        )


class AuditRiskAdapterNode(BaseNode):
    """Adapts security audit findings into canonical RISK_CONTEXT."""

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="audit_risk_adapter",
            node_type="deterministic",
            name="Audit Risk Adapter",
            description="Normalizes audit findings into RISK_CONTEXT.",
            contract=NodeContract(
                contract_id="proof.audit-adapter.v1",
                node_id="audit_risk_adapter",
                version="1.0.0",
                entry=EntryContract(input_type="audit_scan_result", schema_ref='nodechain://schemas/dynamic'),
                exit=ExitContract(output_type=PortType.RISK_CONTEXT, schema_ref='nodechain://schemas/dynamic', guaranteed_fields=["domain", "subject", "severity_signals"]),
            ),
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        data = envelope.payload
        high = data.get("findings_high", 0)
        medium = data.get("findings_medium", 0)

        severity_signals = []
        for _ in range(high):
            severity_signals.append({"level": "high", "source": "audit_finding"})
        for _ in range(medium):
            severity_signals.append({"level": "medium", "source": "audit_finding"})

        risk_context = {
            "domain": "security_audit",
            "subject": "security posture",
            "severity_signals": severity_signals,
            "confidence_signals": [{"score": 0.8}],
            "uncertainty_factors": [],
            "evidence_refs": [f"finding-{i}" for i in range(data.get("findings_total", 0))],
        }

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id, chain_id=envelope.chain_id,
            node_id="audit_risk_adapter", step_id=envelope.step_id,
            output=risk_context,
            output_type=PortType.RISK_CONTEXT,
        )


# ── Trace input adapter (converts risk assessment + run info to TRACE_INPUT) ──

class TraceInputAdapterNode(BaseNode):
    """Converts risk assessment output + run info into TRACE_INPUT for shared trace collector."""

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="trace_input_adapter",
            node_type="deterministic",
            name="Trace Input Adapter",
            description="Normalizes risk assessment into TRACE_INPUT.",
            contract=NodeContract(
                contract_id="proof.trace-input-adapter.v1",
                node_id="trace_input_adapter",
                version="1.0.0",
                entry=EntryContract(input_type=PortType.RISK_ASSESSMENT, schema_ref='nodechain://schemas/dynamic'),
                exit=ExitContract(output_type=PortType.TRACE_INPUT, schema_ref='nodechain://schemas/dynamic', guaranteed_fields=["run_id"]),
            ),
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        risk = envelope.payload
        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id, chain_id=envelope.chain_id,
            node_id="trace_input_adapter", step_id=envelope.step_id,
            output={
                "run_id": envelope.run_id,
                "chain_id": envelope.chain_id,
                "nodes_executed": ["entry", "adapter", "shared_risk_classifier"],
                "total_cost": 0.0,
                "total_duration_ms": 100,
                "final_status": "completed",
                "errors": [],
                "risk_level": risk.get("risk_level", "unknown"),
            },
            output_type=PortType.TRACE_INPUT,
        )
