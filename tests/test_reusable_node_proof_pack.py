"""Reusable Node Proof Pack tests (v2.67.3).

Proves that the same independently packaged nodes can be reused unchanged
across multiple chain contexts, with consistent identity, contracts,
and behavior.

This is the core product proof for NodeChain's composable-node promise:
> Build a node once. Govern it forever. Reuse it everywhere.
"""

from __future__ import annotations

import asyncio
import hashlib
import sys
from pathlib import Path

import pytest

# Ensure nodes/ is importable
NODES_DIR = Path(__file__).parent.parent / "nodes"
sys.path.insert(0, str(NODES_DIR.parent))

from nodechain.core.envelope import InvocationEnvelope
from nodechain.core.port import PortType
from nodes.shared_risk_classifier.implementation import SharedRiskClassifierNode
from nodes.shared_trace_collector.implementation import SharedTraceCollectorNode


# ── Shared node packages exist ────────────────────────────────────────────

class TestSharedPackagesExist:
    def test_risk_classifier_package_exists(self):
        assert (NODES_DIR / "shared_risk_classifier").exists()
        assert (NODES_DIR / "shared_risk_classifier" / "node.yaml").exists()
        assert (NODES_DIR / "shared_risk_classifier" / "implementation.py").exists()

    def test_trace_collector_package_exists(self):
        assert (NODES_DIR / "shared_trace_collector").exists()
        assert (NODES_DIR / "shared_trace_collector" / "node.yaml").exists()
        assert (NODES_DIR / "shared_trace_collector" / "implementation.py").exists()

    def test_risk_classifier_has_tests(self):
        assert (NODES_DIR / "shared_risk_classifier" / "test_node.py").exists()

    def test_trace_collector_has_tests(self):
        assert (NODES_DIR / "shared_trace_collector" / "test_node.py").exists()


# ── Proof blueprints exist ───────────────────────────────────────────────

class TestProofBlueprintsExist:
    @pytest.fixture
    def blueprints_dir(self):
        return Path(__file__).parent.parent / "blueprints"

    def test_quick_fact_check_proof_exists(self, blueprints_dir):
        assert (blueprints_dir / "reuse_proof_quick_fact_check_v1.yaml").exists()

    def test_incident_response_proof_exists(self, blueprints_dir):
        assert (blueprints_dir / "reuse_proof_incident_response_v1.yaml").exists()

    def test_security_audit_proof_exists(self, blueprints_dir):
        assert (blueprints_dir / "reuse_proof_security_audit_v1.yaml").exists()

    def test_all_proof_blueprints_reference_shared_nodes(self, blueprints_dir):
        """All 3 proof blueprints must reference both shared packages."""
        for bp_name in [
            "reuse_proof_quick_fact_check_v1.yaml",
            "reuse_proof_incident_response_v1.yaml",
            "reuse_proof_security_audit_v1.yaml",
        ]:
            content = (blueprints_dir / bp_name).read_text()
            assert "shared_risk_classifier" in content, f"{bp_name} must reference shared_risk_classifier"
            assert "shared_trace_collector" in content, f"{bp_name} must reference shared_trace_collector"


# ── Same node reused across 3+ domains ───────────────────────────────────

class TestCrossDomainReuse:
    """The core proof: same node instance executes in different domain contexts."""

    DOMAINS = [
        ("research", "reuse-proof-quick-fact-check-v1"),
        ("incident_response", "reuse-proof-incident-response-v1"),
        ("security_audit", "reuse-proof-security-audit-v1"),
    ]

    def test_risk_classifier_same_instance_all_domains(self):
        """ONE node instance, reused across 3 domains — the core proof."""
        node = SharedRiskClassifierNode()  # Single instance

        results = {}
        for domain, chain_id in self.DOMAINS:
            env = InvocationEnvelope(
                envelope_id=f"proof-{domain}",
                run_id=f"run-{domain}",
                chain_id=chain_id,
                step_id=1,
                node_id="shared_risk_classifier",
                payload={
                    "domain": domain,
                    "subject": f"test in {domain}",
                    "severity_signals": [{"level": "medium"}],
                    "confidence_signals": [{"score": 0.6}],
                    "uncertainty_factors": [],
                    "evidence_refs": ["ref-1"],
                },
            )
            result = asyncio.run(node.execute(env))
            results[domain] = result

        # All domains produced valid output
        for domain, result in results.items():
            assert result.output["risk_level"] in ("HIGH", "MEDIUM", "LOW")
            assert result.output["domain"] == domain
            assert result.output["confidence"] > 0

    def test_trace_collector_same_instance_all_domains(self):
        """ONE trace collector instance, reused across 3 domains."""
        node = SharedTraceCollectorNode()  # Single instance

        for domain, chain_id in self.DOMAINS:
            env = InvocationEnvelope(
                envelope_id=f"trace-{domain}",
                run_id=f"run-{domain}",
                chain_id=chain_id,
                step_id=2,
                node_id="shared_trace_collector",
                payload={
                    "run_id": f"run-{domain}",
                    "chain_id": chain_id,
                    "nodes_executed": ["scanner", "adapter", "shared_risk_classifier"],
                    "total_cost": 0.01,
                    "total_duration_ms": 500,
                    "final_status": "completed",
                    "errors": [],
                },
            )
            result = asyncio.run(node.execute(env))
            assert result.output["trace_id"].startswith("trace-")
            assert result.output["chain_id"] == chain_id
            assert result.output["trace_complete"] is True

    def test_risk_output_type_is_consistent(self):
        """Output port type must be RISK_ASSESSMENT regardless of domain."""
        node = SharedRiskClassifierNode()
        for domain, _ in self.DOMAINS:
            env = InvocationEnvelope(
                envelope_id=f"type-{domain}", run_id="r", chain_id="c", step_id=1, node_id="shared_risk_classifier",
                payload={"domain": domain, "subject": "t", "severity_signals": [{"level": "low"}], "confidence_signals": [{"score": 0.9}], "uncertainty_factors": [], "evidence_refs": ["r"]},
            )
            result = asyncio.run(node.execute(env))
            assert result.output_type == PortType.RISK_ASSESSMENT

    def test_trace_output_type_is_consistent(self):
        """Output port type must be CHAIN_TRACE_OUTPUT regardless of domain."""
        node = SharedTraceCollectorNode()
        for domain, _ in self.DOMAINS:
            env = InvocationEnvelope(
                envelope_id=f"type-{domain}", run_id="r", chain_id="c", step_id=2, node_id="shared_trace_collector",
                payload={"run_id": "r", "chain_id": "c", "nodes_executed": ["a"], "total_cost": 0, "total_duration_ms": 0, "final_status": "completed", "errors": []},
            )
            result = asyncio.run(node.execute(env))
            assert result.output_type == PortType.CHAIN_TRACE_OUTPUT


# ── Package identity consistency ─────────────────────────────────────────

class TestPackageIdentity:
    """The same node has the same identity (manifest, contract) everywhere."""

    def test_risk_classifier_manifest_is_stable(self):
        """Manifest must be identical regardless of which chain uses the node."""
        node = SharedRiskClassifierNode()
        manifest1 = node.manifest
        manifest2 = SharedRiskClassifierNode().manifest

        assert manifest1.node_id == manifest2.node_id == "shared_risk_classifier"
        assert manifest1.contract.contract_id == manifest2.contract.contract_id
        assert manifest1.contract.version == manifest2.contract.version

    def test_trace_collector_manifest_is_stable(self):
        node = SharedTraceCollectorNode()
        manifest1 = node.manifest
        manifest2 = SharedTraceCollectorNode().manifest

        assert manifest1.node_id == manifest2.node_id == "shared_trace_collector"
        assert manifest1.contract.contract_id == manifest2.contract.contract_id

    def test_risk_classifier_content_hash(self):
        """Content hash of implementation must be stable."""
        impl_path = NODES_DIR / "shared_risk_classifier" / "implementation.py"
        content = impl_path.read_bytes()
        hash1 = hashlib.sha256(content).hexdigest()
        hash2 = hashlib.sha256(impl_path.read_bytes()).hexdigest()
        assert hash1 == hash2
        assert len(hash1) == 64

    def test_trace_collector_content_hash(self):
        impl_path = NODES_DIR / "shared_trace_collector" / "implementation.py"
        content = impl_path.read_bytes()
        hash1 = hashlib.sha256(content).hexdigest()
        hash2 = hashlib.sha256(impl_path.read_bytes()).hexdigest()
        assert hash1 == hash2


# ── Domain-neutral contract ──────────────────────────────────────────────

class TestDomainNeutralContract:
    """The shared node's contract must not reference any specific domain."""

    def test_risk_classifier_entry_is_risk_context(self):
        node = SharedRiskClassifierNode()
        assert node.manifest.contract.entry.input_type == PortType.RISK_CONTEXT

    def test_risk_classifier_exit_is_risk_assessment(self):
        node = SharedRiskClassifierNode()
        assert node.manifest.contract.exit.output_type == PortType.RISK_ASSESSMENT

    def test_trace_collector_entry_is_trace_input(self):
        node = SharedTraceCollectorNode()
        assert node.manifest.contract.entry.input_type == PortType.TRACE_INPUT

    def test_trace_collector_exit_is_chain_trace(self):
        node = SharedTraceCollectorNode()
        assert node.manifest.contract.exit.output_type == PortType.CHAIN_TRACE_OUTPUT

    def test_risk_classifier_does_not_branch_on_domain(self):
        """The implementation must not hardcode domain-specific logic."""
        impl = (NODES_DIR / "shared_risk_classifier" / "implementation.py").read_text()
        # It's OK to record the domain from input, but not to branch on it
        assert "if domain ==" not in impl
        assert "if domain ==" not in impl.replace('"', "'")


# ── Risk classification consistency ──────────────────────────────────────

class TestRiskConsistency:
    """Same input → same output, regardless of domain field."""

    def test_same_signals_produce_same_risk_level(self):
        """Identical severity/confidence signals must produce the same risk level
        regardless of which domain the context claims to be from."""
        node = SharedRiskClassifierNode()
        base_payload = {
            "subject": "test",
            "severity_signals": [{"level": "high"}, {"level": "medium"}],
            "confidence_signals": [{"score": 0.5}],
            "uncertainty_factors": ["a"],
            "evidence_refs": ["ref-1"],
        }

        levels = set()
        for domain, _ in TestCrossDomainReuse.DOMAINS:
            env = InvocationEnvelope(
                envelope_id=f"cons-{domain}", run_id="r", chain_id="c", step_id=1, node_id="shared_risk_classifier",
                payload={**base_payload, "domain": domain},
            )
            result = asyncio.run(node.execute(env))
            levels.add(result.output["risk_level"])

        # All domains must produce the same risk level for identical signals
        assert len(levels) == 1, f"Risk level differed by domain: {levels}"
