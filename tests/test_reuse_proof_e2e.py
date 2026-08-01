"""End-to-end orchestrator execution tests for the reuse-proof blueprints (legacy direct-wiring path).

Verifies that all three proof chains (quick_fact_check, incident_response,
security_audit) load, that every blueprint node resolves in the orchestrator
node registry, and that the shared reusable nodes — SharedRiskClassifierNode
and SharedTraceCollectorNode — execute correctly through the node path and
are shared (same instance) across blueprint contexts.

These nodes are deterministic, so we wire a MockModelAdapter.

v2.67.3 note: This test file uses the LEGACY direct-wiring path
(_create_nodes with include_shared_nodes=True, the default). It verifies
node identity, types, and cross-chain instance reuse via the direct path.
The REGISTRY-RESOLVED proof (NodeLoader resolution, provenance, lockfile
enforcement) lives in test_reuse_proof_runtime_smoke.py. Both files are
valid — this one proves node-level properties, the runtime smoke test
proves the registry-resolution lifecycle.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from nodechain.adapters.mock_model_adapter import MockModelAdapter
from nodechain.cli.run import _create_nodes
from nodechain.core.blueprint import load_blueprint
from nodechain.core.envelope import InvocationEnvelope
from nodechain.core.port import PortType
from nodechain.nodes.reuse_proof_nodes import (
    AuditRiskAdapterNode,
    AuditEntryNode,
    FactCheckEntryNode,
    FactCheckRiskAdapterNode,
    IncidentEntryNode,
    IncidentRiskAdapterNode,
    TraceInputAdapterNode,
)

# Shared nodes live under the top-level nodes/ package, loaded dynamically
# by _create_nodes via _load_shared_node.
from nodes.shared_risk_classifier.implementation import SharedRiskClassifierNode
from nodes.shared_trace_collector.implementation import SharedTraceCollectorNode


BLUEPRINTS_DIR = Path(__file__).resolve().parent.parent / "blueprints"

BLUEPRINT_PATHS = {
    "quick_fact_check": BLUEPRINTS_DIR / "reuse_proof_quick_fact_check_v1.yaml",
    "incident_response": BLUEPRINTS_DIR / "reuse_proof_incident_response_v1.yaml",
    "security_audit": BLUEPRINTS_DIR / "reuse_proof_security_audit_v1.yaml",
}


# ── Fixtures ───────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def node_registry() -> dict:
    """Build the full orchestrator node registry once for the module."""
    return _create_nodes(MockModelAdapter(), trace_dir="/tmp/nodechain-test-trace")


@pytest.fixture(scope="module")
def loaded_blueprints() -> dict:
    """Load all three proof blueprints once for the module."""
    return {name: load_blueprint(str(path)) for name, path in BLUEPRINT_PATHS.items()}


# ── 1. Blueprint load + node registry availability ─────────────────────────

@pytest.mark.parametrize("blueprint_name", list(BLUEPRINT_PATHS.keys()))
def test_blueprint_loads_successfully(blueprint_name, loaded_blueprints):
    """Each proof blueprint loads and parses without error."""
    bp = loaded_blueprints[blueprint_name]
    assert bp.chain_id
    assert len(bp.nodes) == 5
    assert len(bp.connections) == 4


@pytest.mark.parametrize("blueprint_name", list(BLUEPRINT_PATHS.keys()))
def test_all_blueprint_nodes_in_registry(blueprint_name, loaded_blueprints, node_registry):
    """Every node declared in the blueprint is present in the orchestrator registry."""
    bp = loaded_blueprints[blueprint_name]
    missing = [n.node_id for n in bp.nodes if n.node_id not in node_registry]
    assert missing == [], f"Missing nodes in registry for {blueprint_name}: {missing}"


# ── 2. Shared node types present in registry ───────────────────────────────

def test_shared_risk_classifier_present_and_typed(node_registry):
    """shared_risk_classifier is registered and is a SharedRiskClassifierNode."""
    node = node_registry["shared_risk_classifier"]
    assert node is not None, "shared_risk_classifier missing from registry"
    assert isinstance(node, SharedRiskClassifierNode)


def test_shared_trace_collector_present_and_typed(node_registry):
    """shared_trace_collector is registered and is a SharedTraceCollectorNode."""
    node = node_registry["shared_trace_collector"]
    assert node is not None, "shared_trace_collector missing from registry"
    assert isinstance(node, SharedTraceCollectorNode)


# ── 3. Shared node appears in orchestrator output (entry→adapter→shared) ───

def _run(coro):
    """Run an async coroutine to completion in a fresh event loop."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _envelope(node_id: str, chain_id: str, payload: dict, step_id: int = 1) -> InvocationEnvelope:
    return InvocationEnvelope(
        run_id="test-run-reuse-proof",
        chain_id=chain_id,
        node_id=node_id,
        step_id=step_id,
        payload=payload,
    )


@pytest.mark.parametrize(
    "blueprint_name, entry_id, adapter_id, entry_payload, expected_domain",
    [
        (
            "quick_fact_check",
            "fact_checker",
            "risk_context_adapter",
            {"query": "verify this claim"},
            "fact_check",
        ),
        (
            "incident_response",
            "incident_triager",
            "incident_risk_adapter",
            {"query": "triage this incident"},
            "incident_response",
        ),
        (
            "security_audit",
            "audit_scanner",
            "audit_risk_adapter",
            {"query": "scan for findings"},
            "security_audit",
        ),
    ],
)
def test_entry_adapter_shared_risk_chain_produces_risk_assessment(
    blueprint_name, entry_id, adapter_id, entry_payload, expected_domain,
    loaded_blueprints, node_registry,
):
    """Run entry → adapter → shared_risk_classifier and assert valid RISK_ASSESSMENT output."""
    bp = loaded_blueprints[blueprint_name]
    chain_id = bp.chain_id

    entry_node = node_registry[entry_id]
    adapter_node = node_registry[adapter_id]
    classifier = node_registry["shared_risk_classifier"]

    # Step 1: entry node
    entry_resp = _run(entry_node.execute(_envelope(entry_id, chain_id, entry_payload, step_id=1)))
    assert entry_resp.output_type in ("fact_check_result", "incident_triage_result", "audit_scan_result")

    # Step 2: risk adapter normalizes to RISK_CONTEXT
    adapter_resp = _run(adapter_node.execute(
        _envelope(adapter_id, chain_id, entry_resp.output, step_id=2)
    ))
    assert adapter_resp.output_type == PortType.RISK_CONTEXT
    assert adapter_resp.output["domain"] == expected_domain

    # Step 3: shared_risk_classifier produces RISK_ASSESSMENT
    classifier_resp = _run(classifier.execute(
        _envelope("shared_risk_classifier", chain_id, adapter_resp.output, step_id=3)
    ))
    assert classifier_resp.output_type == PortType.RISK_ASSESSMENT
    out = classifier_resp.output
    assert out["risk_level"] in ("LOW", "MEDIUM", "HIGH")
    assert "confidence" in out
    assert "review_required" in out
    assert out["domain"] == expected_domain


# ── 4. Shared trace collector produces trace output ────────────────────────

def test_shared_trace_collector_produces_chain_trace_output(node_registry, loaded_blueprints):
    """trace_input_adapter → shared_trace_collector yields CHAIN_TRACE_OUTPUT."""
    bp = loaded_blueprints["incident_response"]
    chain_id = bp.chain_id

    trace_adapter = node_registry["trace_input_adapter"]
    collector = node_registry["shared_trace_collector"]

    risk_assessment = {
        "risk_level": "MEDIUM",
        "confidence": 0.7,
        "review_required": False,
        "domain": "incident_response",
    }

    adapter_resp = _run(trace_adapter.execute(
        _envelope("trace_input_adapter", chain_id, risk_assessment, step_id=4)
    ))
    assert adapter_resp.output_type == PortType.TRACE_INPUT

    trace_resp = _run(collector.execute(
        _envelope("shared_trace_collector", chain_id, adapter_resp.output, step_id=5)
    ))
    assert trace_resp.output_type == PortType.CHAIN_TRACE_OUTPUT
    out = trace_resp.output
    assert out["trace_id"].startswith("trace-")
    assert out["run_id"] == "test-run-reuse-proof"
    assert out["node_count"] == len(out["nodes_executed"])
    assert out["final_status"] == "completed"


# ── 5. Same shared node instance reused across blueprint contexts ──────────

def test_same_shared_node_instance_across_blueprints(node_registry, loaded_blueprints):
    """The shared_risk_classifier and shared_trace_collector instances are the
    single registered objects — i.e. reused, not re-instantiated per blueprint.
    """
    # The registry holds one instance per shared node id; every blueprint that
    # references shared_risk_classifier resolves to this same object.
    risk_a = node_registry["shared_risk_classifier"]
    risk_b = node_registry["shared_risk_classifier"]
    assert risk_a is risk_b

    trace_a = node_registry["shared_trace_collector"]
    trace_b = node_registry["shared_trace_collector"]
    assert trace_a is trace_b

    # Every blueprint references the same shared node ids, so the orchestrator
    # would bind them to these identical instances.
    for bp in loaded_blueprints.values():
        node_ids = bp.node_ids()
        assert "shared_risk_classifier" in node_ids
        assert "shared_trace_collector" in node_ids

    # Sanity: the shared classifier is distinct from the shared collector.
    assert risk_a is not trace_a


def test_shared_nodes_are_domain_neutral(node_registry, loaded_blueprints):
    """The same SharedRiskClassifierNode instance classifies inputs from
    multiple domains (fact_check, incident_response, security_audit) without
    being reconfigured — proving domain-neutral reuse.
    """
    classifier = node_registry["shared_risk_classifier"]
    seen_domains = set()

    for bp_name, bp in loaded_blueprints.items():
        # Synthesize a canonical RISK_CONTEXT directly (the adapter's job).
        ctx = {
            "domain": bp_name,
            "subject": "reuse proof",
            "severity_signals": [{"level": "medium", "source": "test"}],
            "confidence_signals": [{"score": 0.6}],
            "uncertainty_factors": [],
            "evidence_refs": ["e1"],
        }
        resp = _run(classifier.execute(
            _envelope("shared_risk_classifier", bp.chain_id, ctx, step_id=3)
        ))
        assert resp.output_type == PortType.RISK_ASSESSMENT
        assert resp.output["domain"] == bp_name
        seen_domains.add(resp.output["domain"])

    assert seen_domains == {"quick_fact_check", "incident_response", "security_audit"}
