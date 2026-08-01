# Reusable Node Proof Pack (v2.61.0)

**Purpose:** Concrete proof that NodeChain's composable-node promise works:
the same independently packaged node can be reused unchanged across multiple
autonomous-system chains with consistent identity, contracts, and behavior.

> **Build a node once. Govern it forever. Reuse it everywhere.**

---

## What is proved

Two shared node packages are reused across three different chain contexts:

| Shared Node | Package Location | Port Type (Entry → Exit) |
|---|---|---|
| **Shared Risk Classifier** | `nodes/shared_risk_classifier/` | `RISK_CONTEXT` → `RISK_ASSESSMENT` |
| **Shared Trace Collector** | `nodes/shared_trace_collector/` | `TRACE_INPUT` → `CHAIN_TRACE_OUTPUT` |

These nodes are reused in:

| Proof Blueprint | Domain | Shared Nodes Used |
|---|---|---|
| `blueprints/reuse_proof_quick_fact_check_v1.yaml` | Fact checking | Risk Classifier + Trace Collector |
| `blueprints/reuse_proof_incident_response_v1.yaml` | Incident response | Risk Classifier + Trace Collector |
| `blueprints/reuse_proof_security_audit_v1.yaml` | Security audit | Risk Classifier + Trace Collector |

---

## How to verify the proof

### 1. Inspect the shared packages

```bash
# Verify package structure
ls nodes/shared_risk_classifier/
ls nodes/shared_trace_collector/

# Read the manifests
cat nodes/shared_risk_classifier/node.yaml
cat nodes/shared_trace_collector/node.yaml
```

### 2. Run the proof tests

```bash
python -m pytest tests/test_reusable_node_proof_pack.py -v
```

The tests verify:
- **Package existence**: both shared packages exist with manifests, implementations, and tests
- **Blueprint references**: all 3 proof blueprints reference both shared packages
- **Cross-domain reuse**: the SAME node instance executes in 3 different domain contexts
- **Output type consistency**: port types are identical regardless of domain
- **Package identity stability**: manifest, contract, and content hash are stable
- **Domain-neutral contract**: entry/exit types are canonical, not domain-specific
- **Risk consistency**: identical input signals produce identical risk levels across domains

### 3. Inspect the blueprints

```bash
cat blueprints/reuse_proof_quick_fact_check_v1.yaml
cat blueprints/reuse_proof_incident_response_v1.yaml
cat blueprints/reuse_proof_security_audit_v1.yaml
```

Each blueprint shows:
- A domain-specific entry node (fact checker, incident triager, audit scanner)
- A domain adapter that normalizes output into `RISK_CONTEXT`
- The **same** `shared_risk_classifier` node (unchanged)
- The **same** `shared_trace_collector` node (unchanged)

### 4. Run the shared node tests

```bash
cd nodes/shared_risk_classifier && python -m pytest test_node.py -v
cd nodes/shared_trace_collector && python -m pytest test_node.py -v
```

---

## Architecture: Adapters, Not Custom Copies

The shared nodes are domain-neutral. They do not branch on domain type.
Instead, each chain includes a **domain adapter** that normalizes its
domain-specific output into the canonical `RISK_CONTEXT`:

```
Domain-specific node output
        ↓
Domain adapter / normalizer
        ↓
Canonical RISK_CONTEXT
        ↓
shared_risk_classifier (unchanged)
        ↓
RISK_ASSESSMENT
```

Examples:
- **Research**: claim validation → evidence risk adapter → `RISK_CONTEXT`
- **Incident response**: triage severity → incident risk adapter → `RISK_CONTEXT`
- **Security audit**: audit findings → audit risk adapter → `RISK_CONTEXT`

This means the shared node never needs to know about specific domains.

---

## Canonical Port Types (v2.61.0)

Two new port types enable cross-domain reuse:

| Port Type | Purpose |
|---|---|
| `RISK_CONTEXT` | Canonical input for domain-neutral risk classification |
| `TRACE_INPUT` | Canonical input for domain-neutral trace collection |

These join the existing 13 research-chain port types in `src/nodechain/core/port.py`.

---

## What this proves

1. **The same node package** (same manifest, same contract, same content hash) is reused across 3 chains
2. **The node is domain-neutral** — it does not contain domain-specific logic
3. **Output is consistent** — identical inputs produce identical risk levels regardless of domain
4. **Port types are canonical** — `RISK_CONTEXT` and `RISK_ASSESSMENT` work across all domains
5. **Existing chains are not destabilized** — proof blueprints are separate variants

This is Level 2 proof from VISION.md: **cross-chain reuse with shared packaged nodes**.

---

## v2.64.0 — Registry-Resolved Reuse Proof

v2.61.0–v2.63.x proved runtime reuse: the same shared nodes execute across 3 chains. But the shared nodes were wired directly into `_create_nodes()` — a reviewer could object: *"the nodes are loaded from code, not from the registry."*

v2.64.0 closes that objection. In registry-resolved mode, shared nodes are:
1. **Excluded** from built-ins (`_create_nodes(include_shared_nodes=False)`)
2. **Resolved** by `NodeLoader.load()` from the local `RegistryIndex`
3. **Provenanced** — resolved instances carry `_node_origin="local_registry"`, `_package_root`, `_module_path`
4. **Locked** — the lockfile pins each package with a full 64-char `content_digest`
5. **Enforced** — tampered/missing/mismatched digests deny execution (fail-closed)

### How to verify the registry-resolved proof

```bash
# 1. Run the registry-resolved proof tests (35 tests, 5 independent facts)
python -m pytest tests/test_reuse_proof_runtime_smoke.py -v

# 2. Run the lockfile enforcement tests (11 tests, 7 denial conditions)
python -m pytest tests/test_registry_lockfile_enforcement.py -v

# 3. Generate the lockfile (required for --registry-resolved; gitignored because
#    paths are machine-specific)
nodechain registry lock

# 4. Run a chain with registry-resolved mode via CLI
nodechain run --blueprint blueprints/reuse_proof_quick_fact_check_v1.yaml \
  --registry-resolved "test query"
```

### How to prove shared nodes come from the registry (not `_create_nodes()`)

```python
from nodechain.cli.run import _create_nodes
from nodechain.adapters.mock_model_adapter import MockModelAdapter
from nodechain.sdk.loader import NodeLoader

# Exclusion: shared nodes absent when include_shared_nodes=False
nodes = _create_nodes(MockModelAdapter(), trace_dir="data/traces", include_shared_nodes=False)
assert "shared_risk_classifier" not in nodes  # ← excluded

# Resolution: NodeLoader resolves it from the registry
loader = NodeLoader()
node = loader.load("shared_risk_classifier")
assert getattr(node, "_node_origin") == "local_registry"  # ← registry provenance
```

### How to inspect the lockfile

```bash
# The lockfile pins package identity, version, and full content_digest.
# Generate it first (it's gitignored — paths are machine-specific):
nodechain registry lock

# Then inspect:
cat registry.lock.json | jq '.packages[] | {node_id, version, content_digest}'
```

### How to trigger a lockfile mismatch denial

```bash
# Tamper a content_digest in registry.lock.json, then:
nodechain run --blueprint blueprints/reuse_proof_quick_fact_check_v1.yaml \
  --registry-resolved "test query"
# → execution denied with "content_digest mismatch" error
```

### What this proves

The reusable nodes are no longer merely importable code or hardwired runtime entries. They are **registry-resolved governed packages**: admitted by the local registry, resolved by NodeLoader, pinned by lockfile digest, and executed by `Orchestrator.run()`.

> v2.64.0 proves local/private runtime registry resolution. Certified registry distribution remains a separate lifecycle proof.
