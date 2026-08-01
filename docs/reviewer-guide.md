# NodeChain Reviewer Guide

**Purpose:** A practical inspection recipe for anyone reviewing NodeChain —
whether for adoption, contribution, security assessment, or competitive
analysis. This guide tells you *what to look at* and *what each area proves*.

For the strategic vision, read [VISION.md](../VISION.md) first.

---

## Quick Start (15 minutes)

1. Read [VISION.md](../VISION.md) — the product thesis and current state
2. Read [README.md](../README.md) — quick start and command matrix
3. Run a mock chain:
   ```bash
   NODECHAIN_PROVIDER=mock nodechain run "test query" --provider mock
   ```
4. Inspect the result:
   ```bash
   nodechain inspect <run-id>
   nodechain recover evidence <run-id>
   ```

---

## How to Verify the Composable-Node Claim

NodeChain's central promise is that autonomous capabilities are built as
reusable, governed Harness Nodes. Here's how to verify that:

### 1. Inspect the node contracts

```bash
# View what a node declares: entry/exit ports, requirements, side effects
nodechain node validate nodes/echo_node
nodechain node check-compat --blueprint blueprints/research_decision_v1.yaml
```

The contract model enforces:
- **Typed ports** — nodes connect only where port types match
- **Required fields** — entry contracts specify what inputs are mandatory
- **Guaranteed fields** — exit contracts specify what outputs are promised
- **Declared requirements** — model, tools, memory, trust level
- **Declared side effects** — what the node writes, idempotency, retryability

### 2. Inspect the typed port system

Look at `src/nodechain/core/port.py` — 13 semantic port types form a typed
data flow from raw query through research, evidence, validation, risk,
response, memory, and trace.

### 3. Inspect multiple chains

NodeChain is not one-chain-only. Inspect:

| Blueprint | What it proves |
|---|---|
| `blueprints/research_decision_v1.yaml` | 12-node research assistant with full governance |
| `blueprints/incident_response_v1.yaml` | Incident response chain with detection → triage → remediation |
| `blueprints/security_audit_v1.yaml` | Security audit chain across 7 auditing nodes |
| `blueprints/composition_cross_domain_v1.yaml` | Cross-domain composition — nodes from different chains in one blueprint |
| `blueprints/branch_demo_v1.yaml` | Branch and quorum fork demonstration |
| `blueprints/domain_routed_evidence_v1.yaml` | Domain-routed search and evidence gathering |

### 4. Inspect packaged nodes

External node packages exist under `nodes/`:

```
nodes/echo_node/         — minimal example node
nodes/future_node/       — forward-looking capability demo
nodes/incident_response/ — incident response node set
nodes/sandbox_test_node/ — sandbox testing node
nodes/security_audit/    — security audit node set
nodes/text_transforms/   — text transformation utilities
```

Each package has its own manifest, contract, implementation, and tests.

---

## How to Verify the Package Lifecycle

The full create → package → publish → install → deprecate lifecycle is
implemented. See [node-package-walkthrough.md](node-package-walkthrough.md)
for the complete command path.

Quick verification:

```bash
# Create a new node from template
nodechain node create --name my_node

# Validate it
nodechain node validate nodes/my_node

# Test it
nodechain node test nodes/my_node

# Publish to local registry
nodechain registry publish nodes/my_node

# List registered packages
nodechain registry list

# Inspect a package
nodechain registry inspect my_node

# Lock dependencies
nodechain registry lock

# Deprecate
nodechain registry deprecate my_node

# Revoke
nodechain registry revoke my_node
```

---

## How to Verify Runtime Governance

### Policy gates

Before every node execution, the runtime checks:
- Tool access permissions
- Adapter access (search APIs)
- Memory read/write/create permissions
- Side-effect completion/idempotency
- Trust level requirements
- Cost budget enforcement

Inspect: `src/nodechain/runtime/policy_gate.py`

### Governance profiles

```bash
# View the full action matrix, budgets, overrides, and audit settings
nodechain recover profiles show team-default
nodechain recover profiles show regulated
nodechain recover profiles show break-glass
```

### Recovery system

```bash
# List runs with recovery states
nodechain recover list

# Inspect a run's recovery snapshot
nodechain recover inspect <run-id>

# Preview an action (dry-run, no mutation)
nodechain recover preview <run-id> resume --role operator

# View the operator dashboard
nodechain recover dashboard
```

---

## How to Verify Trace Truth and Evidence

### Trace as execution law

Every node invocation produces pre/post/output trace events. The trace
reconciler verifies trace events match persisted state.

```bash
nodechain trace <run-id>
nodechain reconcile <run-id>
```

### Evidence provenance

The research chain produces traceable evidence:
- Sources ingested with metadata
- Claims cite source IDs (fabricated IDs quarantined)
- Validated claims carry status (confirmed/partially/unconfirmed/contradicted)
- Citations resolve to real sources

```bash
nodechain recover evidence <run-id>
```

### Evaluation

```bash
# Run the deterministic research evaluation harness
NODECHAIN_PROVIDER=mock nodechain eval research
```

---

## How to Verify the Local API Server

```bash
# Start the API server (requires token)
export NODECHAIN_API_TOKEN=$(python -c "import secrets; print(secrets.token_hex(32))")
nodechain api serve

# In another terminal:
curl -H "Authorization: Bearer $NODECHAIN_API_TOKEN" http://127.0.0.1:8765/api/v1/health
curl -H "Authorization: Bearer $NODECHAIN_API_TOKEN" http://127.0.0.1:8765/api/v1/profiles
curl -H "Authorization: Bearer $NODECHAIN_API_TOKEN" http://127.0.0.1:8765/api/v1/dashboard
```

---

## What is Mature vs Not Mature

### Mature and tested

- Runtime execution kernel with governance, state, and trace
- Contract/typed-port composition model
- Policy gates (tools, memory, side effects, trust, cost)
- Recovery system with RBAC and governance profiles
- Persistence with atomic commit boundaries
- Research evaluation harness with quality metrics
- Source acquisition with retry, circuit breaker, and failure taxonomy
- CLI operator workbench with preview, evidence, and dashboard
- Local API server with auth and OpenAPI

### Needs strengthening

- Cross-chain packaged reuse proof (same node reused across multiple chains)
- Documentation alignment across all surfaces
- Node package walkthrough needs real end-to-end examples
- Registry/trust story needs a concise narrative
- API mutation endpoints (deferred to later release)
- Visual proof surface (trace/evidence viewer)

---

## Test Coverage

```bash
# Run the full test suite (may take several minutes)
make ci-blocking

# Or run specific shards
make ci-fast          # fast unit + governance tests
make ci-recovery      # orchestrator + recovery tests
make ci-trust         # trust collector tests
```

Key test files to inspect:
- `tests/test_release_truth.py` — version consistency across all surfaces
- `tests/test_citation_gaps.py` — citation integrity
- `tests/test_research_eval_harness.py` — research quality metrics
- `tests/test_source_acquisition_reliability.py` — adapter resilience
- `tests/test_operator_workbench.py` — CLI operator commands
- `tests/test_local_api_server.py` — API server endpoints
- `tests/test_docs_vision_links.py` — documentation drift guardrails
- `tests/invariants/` — authorization, audit, state transition, budget, batch, governance invariants
