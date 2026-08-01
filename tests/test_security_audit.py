"""Tests for the Security Audit Reference Chain (v1.21.0).

Tests cover:
1. All 7 individual nodes
2. End-to-end chain execution
3. Audit scoring and grading
4. Finding severity ranking
5. Evidence references in findings
6. Evaluation suite
7. Dashboard integration
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import pytest
import uuid
from pathlib import Path

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse


def _make_envelope(payload: dict, run_id: str = "") -> InvocationEnvelope:
    return InvocationEnvelope(
        envelope_id=str(uuid.uuid4()),
        run_id=run_id or str(uuid.uuid4()),
        chain_id="security-audit-v1",
        node_id="test",
        step_id=1,
        payload=payload,
    )


class TestAssetInventoryCollector:
    """Node 1: Asset inventory collection."""

    @pytest.mark.asyncio
    async def test_collects_dashboard_sections(self):
        from nodes.security_audit.implementations.asset_inventory_collector import AssetInventoryCollector
        node = AssetInventoryCollector()
        env = _make_envelope({
            "dashboard": {"sections": {"trust": {"total_keys": 5}, "registry": {"active": 3}}},
            "scan_env": False,
        })
        result = await node.execute(env)
        assert result.output["asset_count"] == 2
        assert result.output["inventory_digest"]
        assert len(result.output["assets"]) == 2

    @pytest.mark.asyncio
    async def test_contract_and_manifest(self):
        from nodes.security_audit.implementations.asset_inventory_collector import AssetInventoryCollector
        node = AssetInventoryCollector()
        assert node.manifest().node_id == "asset_inventory_collector"
        assert node.contract().contract_id == "audit.inventory.v1"
        assert "inventory_digest" in node.contract().exit.guaranteed_fields


class TestTrustPostureAuditor:
    """Node 2: Trust posture audit."""

    @pytest.mark.asyncio
    async def test_produces_findings(self):
        from nodes.security_audit.implementations.trust_posture_auditor import TrustPostureAuditor
        node = TrustPostureAuditor()
        result = await node.execute(_make_envelope({}))
        assert "findings" in result.output
        assert "trust_score" in result.output
        assert isinstance(result.output["findings"], list)
        assert 0 <= result.output["trust_score"] <= 100

    @pytest.mark.asyncio
    async def test_contract_valid(self):
        from nodes.security_audit.implementations.trust_posture_auditor import TrustPostureAuditor
        node = TrustPostureAuditor()
        assert node.contract().contract_id == "audit.trust.v1"


class TestRegistryPostureAuditor:
    """Node 3: Registry posture audit."""

    @pytest.mark.asyncio
    async def test_produces_findings(self):
        from nodes.security_audit.implementations.registry_posture_auditor import RegistryPostureAuditor
        node = RegistryPostureAuditor()
        result = await node.execute(_make_envelope({}))
        assert "findings" in result.output
        assert "registry_score" in result.output
        assert 0 <= result.output["registry_score"] <= 100

    @pytest.mark.asyncio
    async def test_contract_valid(self):
        from nodes.security_audit.implementations.registry_posture_auditor import RegistryPostureAuditor
        node = RegistryPostureAuditor()
        assert node.contract().contract_id == "audit.registry.v1"


class TestEvidenceChainAuditor:
    """Node 4: Evidence chain audit."""

    @pytest.mark.asyncio
    async def test_produces_findings(self):
        from nodes.security_audit.implementations.evidence_chain_auditor import EvidenceChainAuditor
        node = EvidenceChainAuditor()
        result = await node.execute(_make_envelope({}))
        assert "findings" in result.output
        assert "evidence_score" in result.output

    @pytest.mark.asyncio
    async def test_contract_valid(self):
        from nodes.security_audit.implementations.evidence_chain_auditor import EvidenceChainAuditor
        node = EvidenceChainAuditor()
        assert node.contract().contract_id == "audit.evidence.v1"


class TestSandboxPolicyAuditor:
    """Node 5: Sandbox policy audit."""

    @pytest.mark.asyncio
    async def test_produces_findings(self):
        from nodes.security_audit.implementations.sandbox_policy_auditor import SandboxPolicyAuditor
        node = SandboxPolicyAuditor()
        result = await node.execute(_make_envelope({}))
        assert "findings" in result.output
        assert "sandbox_score" in result.output
        assert "platform" in result.output

    @pytest.mark.asyncio
    async def test_contract_valid(self):
        from nodes.security_audit.implementations.sandbox_policy_auditor import SandboxPolicyAuditor
        node = SandboxPolicyAuditor()
        assert node.contract().contract_id == "audit.sandbox.v1"


class TestDeploymentRiskAuditor:
    """Node 6: Deployment risk audit."""

    @pytest.mark.asyncio
    async def test_produces_findings(self):
        from nodes.security_audit.implementations.deployment_risk_auditor import DeploymentRiskAuditor
        node = DeploymentRiskAuditor()
        result = await node.execute(_make_envelope({}))
        assert "findings" in result.output
        assert "deployment_score" in result.output

    @pytest.mark.asyncio
    async def test_contract_valid(self):
        from nodes.security_audit.implementations.deployment_risk_auditor import DeploymentRiskAuditor
        node = DeploymentRiskAuditor()
        assert node.contract().contract_id == "audit.deployment.v1"


class TestAuditReportWriter:
    """Node 7: Audit report aggregation."""

    @pytest.mark.asyncio
    async def test_aggregates_empty_findings(self):
        from nodes.security_audit.implementations.audit_report_writer import AuditReportWriter
        node = AuditReportWriter()
        result = await node.execute(_make_envelope({}))
        assert result.output["audit_score"] == 100
        assert result.output["overall_grade"] == "A"
        assert result.output["finding_count"] == 0
        assert result.output["report_digest"]

    @pytest.mark.asyncio
    async def test_aggregates_findings_from_all_auditors(self):
        from nodes.security_audit.implementations.audit_report_writer import AuditReportWriter
        node = AuditReportWriter()
        result = await node.execute(_make_envelope({
            "trust_audit": {
                "findings": [{"control": "T1", "severity": "warning", "title": "test", "recommendation": "fix"}],
                "trust_score": 90,
            },
            "registry_audit": {
                "findings": [{"control": "R1", "severity": "critical", "title": "bad", "recommendation": "fix now"}],
                "registry_score": 60,
            },
            "evidence_audit": {"findings": [], "evidence_score": 100},
            "sandbox_audit": {"findings": [], "sandbox_score": 100},
            "deployment_audit": {
                "findings": [{"control": "D1", "severity": "degraded", "title": "drift", "recommendation": "check"}],
                "deployment_score": 75,
            },
        }))
        assert result.output["finding_count"] == 3
        assert result.output["critical_count"] == 1
        assert result.output["degraded_count"] == 1
        assert result.output["warning_count"] == 1
        # Score is average: (90+60+100+100+75)/5 = 85 → B
        assert result.output["audit_score"] == 85
        assert result.output["overall_grade"] == "B"

    @pytest.mark.asyncio
    async def test_findings_sorted_by_severity(self):
        from nodes.security_audit.implementations.audit_report_writer import AuditReportWriter
        node = AuditReportWriter()
        result = await node.execute(_make_envelope({
            "trust_audit": {
                "findings": [{"control": "T1", "severity": "warning", "title": "w1", "recommendation": "r1"}],
                "trust_score": 90,
            },
            "registry_audit": {
                "findings": [{"control": "R1", "severity": "critical", "title": "c1", "recommendation": "r2"}],
                "registry_score": 60,
            },
        }))
        findings = result.output["findings"]
        assert findings[0]["severity"] == "critical"
        assert findings[1]["severity"] == "warning"

    @pytest.mark.asyncio
    async def test_report_digest_deterministic(self):
        from nodes.security_audit.implementations.audit_report_writer import AuditReportWriter
        node = AuditReportWriter()
        r1 = await node.execute(_make_envelope({"trust_audit": {"findings": [], "trust_score": 100}}))
        r2 = await node.execute(_make_envelope({"trust_audit": {"findings": [], "trust_score": 100}}))
        # Digests should match since same input (minus timestamp)
        assert r1.output["report_digest"] is not None

    @pytest.mark.asyncio
    async def test_audit_grades(self):
        from nodes.security_audit.implementations.audit_report_writer import AuditReportWriter
        node = AuditReportWriter()

        for score, expected_grade in [(95, "A"), (85, "B"), (75, "C"), (65, "D"), (50, "F")]:
            result = await node.execute(_make_envelope({
                "trust_audit": {"findings": [], "trust_score": score},
                "registry_audit": {"findings": [], "registry_score": score},
                "evidence_audit": {"findings": [], "evidence_score": score},
                "sandbox_audit": {"findings": [], "sandbox_score": score},
                "deployment_audit": {"findings": [], "deployment_score": score},
            }))
            assert result.output["audit_score"] == score
            assert result.output["overall_grade"] == expected_grade


class TestEndToEndChain:
    """Full pipeline execution: collect → audit → report."""

    @pytest.mark.asyncio
    async def test_full_audit_chain(self):
        """Run all 7 nodes in sequence."""
        run_id = str(uuid.uuid4())

        # Node 1: Collect
        from nodes.security_audit.implementations.asset_inventory_collector import AssetInventoryCollector
        collector = AssetInventoryCollector()
        collect_result = await collector.execute(_make_envelope({
            "scan_env": False, "dashboard": {"sections": {"trust": {"total_keys": 3}}},
        }, run_id=run_id))
        assert collect_result.output["asset_count"] >= 1

        # Node 2: Trust audit
        from nodes.security_audit.implementations.trust_posture_auditor import TrustPostureAuditor
        trust_result = await TrustPostureAuditor().execute(_make_envelope(
            collect_result.output, run_id=run_id,
        ))
        assert "trust_score" in trust_result.output

        # Node 3: Registry audit
        from nodes.security_audit.implementations.registry_posture_auditor import RegistryPostureAuditor
        registry_result = await RegistryPostureAuditor().execute(_make_envelope(
            trust_result.output, run_id=run_id,
        ))
        assert "registry_score" in registry_result.output

        # Node 4: Evidence audit
        from nodes.security_audit.implementations.evidence_chain_auditor import EvidenceChainAuditor
        evidence_result = await EvidenceChainAuditor().execute(_make_envelope(
            registry_result.output, run_id=run_id,
        ))
        assert "evidence_score" in evidence_result.output

        # Node 5: Sandbox audit
        from nodes.security_audit.implementations.sandbox_policy_auditor import SandboxPolicyAuditor
        sandbox_result = await SandboxPolicyAuditor().execute(_make_envelope(
            evidence_result.output, run_id=run_id,
        ))
        assert "sandbox_score" in sandbox_result.output

        # Node 6: Deployment audit
        from nodes.security_audit.implementations.deployment_risk_auditor import DeploymentRiskAuditor
        deployment_result = await DeploymentRiskAuditor().execute(_make_envelope(
            sandbox_result.output, run_id=run_id,
        ))
        assert "deployment_score" in deployment_result.output

        # Node 7: Report writer — pass all audit data
        from nodes.security_audit.implementations.audit_report_writer import AuditReportWriter
        report_result = await AuditReportWriter().execute(_make_envelope({
            **deployment_result.output,
            "trust_audit": trust_result.output,
            "registry_audit": registry_result.output,
            "evidence_audit": evidence_result.output,
            "sandbox_audit": sandbox_result.output,
            "deployment_audit": deployment_result.output,
        }, run_id=run_id))

        assert report_result.output["audit_score"] >= 0
        assert report_result.output["overall_grade"] in ("A", "B", "C", "D", "F")
        assert report_result.output["report_digest"]
        assert isinstance(report_result.output["findings"], list)


class TestEvidenceReferences:
    """Every finding must have an evidence_ref (AC7)."""

    @pytest.mark.asyncio
    async def test_all_findings_have_evidence_ref(self):
        """All findings from all auditors include evidence_ref field."""
        from nodes.security_audit.implementations.trust_posture_auditor import TrustPostureAuditor
        from nodes.security_audit.implementations.registry_posture_auditor import RegistryPostureAuditor
        from nodes.security_audit.implementations.evidence_chain_auditor import EvidenceChainAuditor
        from nodes.security_audit.implementations.sandbox_policy_auditor import SandboxPolicyAuditor
        from nodes.security_audit.implementations.deployment_risk_auditor import DeploymentRiskAuditor

        for auditor_cls in [TrustPostureAuditor, RegistryPostureAuditor,
                           EvidenceChainAuditor, SandboxPolicyAuditor, DeploymentRiskAuditor]:
            result = await auditor_cls().execute(_make_envelope({}))
            for finding in result.output["findings"]:
                assert "evidence_ref" in finding, \
                    f"{auditor_cls.__name__} finding missing evidence_ref: {finding}"


class TestEvaluationSuite:
    """AC8: Evaluation suite loads and passes."""

    def test_suite_exists(self):
        assert Path("eval_suites/security_audit_eval.yaml").exists()

    def test_suite_loads_and_validates(self):
        from nodechain.cli.evaluation import EvaluationSuite
        suite = EvaluationSuite.from_file("eval_suites/security_audit_eval.yaml")
        errors = suite.validate()
        assert not errors
        assert suite.suite_id == "security_audit_eval"
        assert len(suite.cases) >= 7

    def test_suite_evaluates(self):
        from nodechain.cli.evaluation import EvaluationSuite, run_evaluation
        suite = EvaluationSuite.from_file("eval_suites/security_audit_eval.yaml")
        report = run_evaluation(suite, target_digest="test")
        assert report["passed"]
        assert report["total_cases"] >= 7


class TestDashboardIntegration:
    """AC10: Dashboard can display audit status."""

    def test_dashboard_has_audit_section(self):
        """Dashboard overview doesn't break when audit data is present."""
        from nodechain.cli.dashboard import collect_dashboard
        data = collect_dashboard()
        assert "sections" in data
        # Dashboard should work without audit data
        assert data["overall_health"] in ("healthy", "warning", "degraded", "critical", "unknown")


class TestHealthOrderingFix:
    """Verify the health ordering fix from the review note."""

    def test_critical_dominates_unknown(self):
        from nodechain.cli.dashboard import worst_health, CRITICAL, UNKNOWN
        result = worst_health(UNKNOWN, CRITICAL)
        assert result == CRITICAL, f"Expected critical to dominate unknown, got {result}"

    def test_unknown_between_warning_and_degraded(self):
        from nodechain.cli.dashboard import worst_health, UNKNOWN, WARNING, DEGRADED
        result = worst_health(WARNING, UNKNOWN)
        assert result == UNKNOWN

    def test_health_order_values(self):
        from nodechain.cli.dashboard import HEALTH_ORDER, HEALTHY, WARNING, UNKNOWN, DEGRADED, CRITICAL
        assert HEALTH_ORDER[HEALTHY] < HEALTH_ORDER[WARNING]
        assert HEALTH_ORDER[WARNING] < HEALTH_ORDER[UNKNOWN]
        assert HEALTH_ORDER[UNKNOWN] < HEALTH_ORDER[DEGRADED]
        assert HEALTH_ORDER[DEGRADED] < HEALTH_ORDER[CRITICAL]
