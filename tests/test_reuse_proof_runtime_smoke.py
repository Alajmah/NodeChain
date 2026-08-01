"""Registry-Resolved Reuse Proof tests (v2.67.3).

Proves that shared nodes execute through the REAL orchestrator.run() path
after being resolved from the local registry — NOT wired directly into
_create_nodes(). This closes the reviewer objection:

  "The runtime proof is real, but the shared nodes are still wired directly
  into code rather than proven through the registry lifecycle."

Proof progression:
  v2.61.0: Direct shared-node proof
  v2.62.0: Orchestrator-registry integrated proof
  v2.67.3: Full orchestrator.run() persistence/trace proof
  v2.67.3: Registry-resolved proof — NodeLoader resolves shared nodes (this release)

> Build a node once. Govern it forever. Reuse it everywhere.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from nodechain.adapters.mock_model_adapter import MockModelAdapter
from nodechain.core.blueprint import load_blueprint
from nodechain.core.state import StateManager
from nodechain.runtime.orchestrator import Orchestrator


PROOF_BLUEPRINTS = [
    "blueprints/reuse_proof_quick_fact_check_v1.yaml",
    "blueprints/reuse_proof_incident_response_v1.yaml",
    "blueprints/reuse_proof_security_audit_v1.yaml",
]

SHARED_NODE_IDS = ["shared_risk_classifier", "shared_trace_collector"]


def _get_nodes_registry_resolved() -> dict:
    """Build the node map the registry-resolved way.

    Shared nodes are EXCLUDED from built-ins and resolved through NodeLoader,
    exactly as run_chain(registry_resolved=True) does. This is the v2.67.3
    proof path — no direct _load_shared_node() wiring.
    """
    from nodechain.cli.run import _create_nodes
    from nodechain.sdk.loader import NodeLoader

    # Built-ins WITHOUT shared nodes (the exclusion proof)
    nodes = _create_nodes(
        MockModelAdapter(), trace_dir="data/traces",
        include_shared_nodes=False,
    )
    # Resolve shared nodes from the local registry (the resolution proof)
    loader = NodeLoader()
    for nid in SHARED_NODE_IDS:
        nodes[nid] = loader.load(nid)
    return nodes


def _run_blueprint(blueprint_path: str, db_path: str, trace_dir: str):
    """Run a blueprint through the real orchestrator and return (trace, state)."""
    blueprint = load_blueprint(blueprint_path)
    nodes = _get_nodes_registry_resolved()

    # Filter nodes to only those in the blueprint
    blueprint_node_ids = [n.node_id for n in blueprint.nodes]
    chain_nodes = {nid: nodes[nid] for nid in blueprint_node_ids if nid in nodes}

    sm = StateManager(db_path=db_path)

    orchestrator = Orchestrator(
        blueprint=blueprint,
        nodes=chain_nodes,
        state_manager=sm,
    )

    trace = asyncio.run(orchestrator.run("reuse proof test query"))
    return trace, sm


@pytest.fixture
def temp_env(tmp_path):
    """Create temp paths for db and trace output."""
    db = str(tmp_path / "test_reuse.db")
    trace_dir = str(tmp_path / "traces")
    Path(trace_dir).mkdir(parents=True, exist_ok=True)
    return db, trace_dir


# ── Proof 1: Exclusion — shared nodes absent from built-ins ───────────────

class TestSharedNodeExclusion:
    """In registry-resolved mode, shared nodes must NOT be in _create_nodes()."""

    def test_shared_nodes_absent_when_excluded(self):
        """include_shared_nodes=False must omit both shared node IDs."""
        from nodechain.cli.run import _create_nodes
        nodes = _create_nodes(
            MockModelAdapter(), trace_dir="data/traces",
            include_shared_nodes=False,
        )
        assert "shared_risk_classifier" not in nodes, \
            "shared_risk_classifier must be absent when include_shared_nodes=False"
        assert "shared_trace_collector" not in nodes, \
            "shared_trace_collector must be absent when include_shared_nodes=False"

    def test_shared_nodes_present_by_default(self):
        """Default behavior (include_shared_nodes=True) still wires them."""
        from nodechain.cli.run import _create_nodes
        nodes = _create_nodes(MockModelAdapter(), trace_dir="data/traces")
        assert "shared_risk_classifier" in nodes
        assert "shared_trace_collector" in nodes

    def test_non_shared_nodes_preserved_when_excluded(self):
        """Excluding shared nodes must not remove other built-ins."""
        from nodechain.cli.run import _create_nodes
        nodes = _create_nodes(
            MockModelAdapter(), trace_dir="data/traces",
            include_shared_nodes=False,
        )
        assert "goal_interpreter" in nodes
        assert "fact_checker" in nodes
        assert "trace_input_adapter" in nodes


# ── Proof 2: Resolution — NodeLoader resolves shared nodes ────────────────

class TestRegistryResolution:
    """NodeLoader.load() must resolve both shared nodes from the local registry."""

    @pytest.mark.parametrize("node_id", SHARED_NODE_IDS)
    def test_node_loads_from_registry(self, node_id):
        from nodechain.sdk.loader import NodeLoader
        loader = NodeLoader()
        node = loader.load(node_id)
        assert node is not None, f"{node_id} must resolve from registry"

    def test_all_proof_blueprint_nodes_resolvable(self):
        """Every node in every proof blueprint resolves via the registry-resolved path."""
        for bp_path in PROOF_BLUEPRINTS:
            bp = load_blueprint(bp_path)
            nodes = _get_nodes_registry_resolved()
            for node_def in bp.nodes:
                assert node_def.node_id in nodes, \
                    f"Node '{node_def.node_id}' not resolvable for {bp_path}"


# ── Proof 3: Provenance — registry-loaded instances carry local_registry origin ─

class TestRegistryProvenance:
    """Registry-resolved nodes must carry local_registry provenance."""

    @pytest.mark.parametrize("node_id", SHARED_NODE_IDS)
    def test_node_origin_is_local_registry(self, node_id):
        from nodechain.sdk.loader import NodeLoader
        loader = NodeLoader()
        node = loader.load(node_id)
        assert getattr(node, "_node_origin", None) == "local_registry", \
            f"{node_id} must have _node_origin='local_registry'"

    @pytest.mark.parametrize("node_id", SHARED_NODE_IDS)
    def test_node_has_package_root(self, node_id):
        from nodechain.sdk.loader import NodeLoader
        loader = NodeLoader()
        node = loader.load(node_id)
        assert getattr(node, "_package_root", None), \
            f"{node_id} must have _package_root set"

    @pytest.mark.parametrize("node_id", SHARED_NODE_IDS)
    def test_node_has_module_path(self, node_id):
        from nodechain.sdk.loader import NodeLoader
        loader = NodeLoader()
        node = loader.load(node_id)
        assert getattr(node, "_module_path", None), \
            f"{node_id} must have _module_path set"


# ── Proof 4: Locking — content_digest pins the package identity ──────────

class TestPackageDigestLocking:
    """The full content_digest pins shared node identity for enforcement."""

    @pytest.mark.parametrize("node_id", SHARED_NODE_IDS)
    def test_content_digest_is_full_length(self, node_id):
        """content_digest must be the full 64-char SHA-256 (not truncated)."""
        from nodechain.registry.local_registry import RegistryIndex
        reg = RegistryIndex()
        reg.scan()
        pkg = reg.get_package(node_id)
        assert pkg is not None
        digest = pkg.content_digest()
        assert digest is not None
        assert len(digest) == 64, \
            f"{node_id} content_digest must be 64 chars (full SHA-256), got {len(digest)}"

    @pytest.mark.parametrize("node_id", SHARED_NODE_IDS)
    def test_content_hash_is_shorter_than_digest(self, node_id):
        """content_hash (display) must be shorter than content_digest (enforcement)."""
        from nodechain.registry.local_registry import RegistryIndex
        reg = RegistryIndex()
        reg.scan()
        pkg = reg.get_package(node_id)
        assert pkg is not None
        assert len(pkg.content_hash()) < len(pkg.content_digest()), \
            f"{node_id}: content_hash must be shorter than content_digest"

    def test_same_digest_across_all_three_contexts(self):
        """The same content_digest appears for each shared node across all
        three proof blueprints — proving package identity is stable."""
        from nodechain.registry.local_registry import RegistryIndex
        reg = RegistryIndex()
        reg.scan()

        digests_by_node: dict[str, list[str]] = {nid: [] for nid in SHARED_NODE_IDS}
        for bp_path in PROOF_BLUEPRINTS:
            bp = load_blueprint(bp_path)
            for node_def in bp.nodes:
                if node_def.node_id in SHARED_NODE_IDS:
                    pkg = reg.get_package(node_def.node_id)
                    digests_by_node[node_def.node_id].append(pkg.content_digest())

        for nid, digests in digests_by_node.items():
            assert len(digests) == 3, f"{nid}: expected 3 contexts, got {len(digests)}"
            assert len(set(digests)) == 1, \
                f"{nid}: content_digest must be identical across all 3 contexts, got {set(digests)}"


# ── Proof 5: Runtime — orchestrator.run() completes with registry-resolved nodes ─

class TestFullRuntimeExecution:
    """The core proof: run each blueprint through orchestrator.run() with
    registry-resolved shared nodes and verify persisted state + trace."""

    @pytest.mark.parametrize("blueprint_path", PROOF_BLUEPRINTS)
    def test_orchestrator_run_succeeds(self, blueprint_path, temp_env):
        """Run completes through the real orchestrator."""
        db, trace_dir = temp_env
        trace, sm = _run_blueprint(blueprint_path, db, trace_dir)
        assert trace is not None
        assert trace.final_status == "completed"

    @pytest.mark.parametrize("blueprint_path", PROOF_BLUEPRINTS)
    def test_shared_risk_classifier_in_state(self, blueprint_path, temp_env):
        """Persisted state contains shared_risk_classifier output."""
        db, trace_dir = temp_env
        trace, sm = _run_blueprint(blueprint_path, db, trace_dir)

        state = sm.load(trace.run_id)
        assert state is not None, "Persisted state must exist after orchestrator.run()"
        assert state.outputs, "State outputs must not be empty"
        assert "shared_risk_classifier" in state.outputs, \
            "shared_risk_classifier must be in persisted state outputs"
        output = state.outputs["shared_risk_classifier"]
        assert isinstance(output, dict), "Output must be a dict"
        assert "risk_level" in output, "risk_level must be in shared_risk_classifier output"

    @pytest.mark.parametrize("blueprint_path", PROOF_BLUEPRINTS)
    def test_shared_trace_collector_in_state(self, blueprint_path, temp_env):
        """Persisted state contains shared_trace_collector output."""
        db, trace_dir = temp_env
        trace, sm = _run_blueprint(blueprint_path, db, trace_dir)

        state = sm.load(trace.run_id)
        assert state is not None, "Persisted state must exist"
        assert state.outputs, "State outputs must not be empty"
        assert "shared_trace_collector" in state.outputs, \
            "shared_trace_collector must be in persisted state outputs"
        output = state.outputs["shared_trace_collector"]
        assert isinstance(output, dict), "Output must be a dict"
        assert "trace_id" in output, "trace_id must be in shared_trace_collector output"

    @pytest.mark.parametrize("blueprint_path", PROOF_BLUEPRINTS)
    def test_trace_contains_shared_node_events(self, blueprint_path, temp_env):
        """Trace events explicitly include both shared nodes."""
        db, trace_dir = temp_env
        trace, sm = _run_blueprint(blueprint_path, db, trace_dir)

        all_event_str = json.dumps(
            [e.model_dump() if hasattr(e, "model_dump") else str(e) for e in trace.events],
            default=str,
        )
        assert "shared_risk_classifier" in all_event_str, \
            "Trace must explicitly reference shared_risk_classifier"
        assert "shared_trace_collector" in all_event_str, \
            "Trace must explicitly reference shared_trace_collector"


# ── Blueprint loading + structure ─────────────────────────────────────────

class TestBlueprintLoading:
    """All proof blueprints must load with the expected 5-node structure."""

    @pytest.mark.parametrize("blueprint_path", PROOF_BLUEPRINTS)
    def test_blueprint_loads(self, blueprint_path):
        bp = load_blueprint(blueprint_path)
        assert bp is not None
        assert len(bp.nodes) == 5

    @pytest.mark.parametrize("blueprint_path", PROOF_BLUEPRINTS)
    def test_shared_nodes_in_blueprint(self, blueprint_path):
        bp = load_blueprint(blueprint_path)
        node_ids = [n.node_id for n in bp.nodes]
        assert "shared_risk_classifier" in node_ids
        assert "shared_trace_collector" in node_ids
