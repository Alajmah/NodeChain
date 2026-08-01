# Node Package Walkthrough

**Purpose:** A concrete, command-by-command walkthrough of the Harness Node
lifecycle — from creation to deprecation. This is the practical proof of
NodeChain's core promise:

> **Build a node once. Govern it forever. Reuse it everywhere.**

---

## Prerequisites

```bash
# NodeChain must be installed and on PATH
nodechain --version

# Verify the node and registry command groups exist
nodechain node --help
nodechain registry --help
```

---

## Step 1: Create a Node

Create a new node package from the built-in template:

```bash
nodechain node create --name my_evaluator
```

This generates a node package directory with:
- `manifest.yaml` — node identity, type, contract reference
- `contract.yaml` — entry/exit ports, required fields, side effects
- `implementation.py` — the node's Python class
- `test_node.py` — package-local tests
- `README.md` — node documentation

### Node types

Nodes can be:
- **deterministic** — pure logic, no model needed (e.g., Risk Classifier)
- **model** — requires an LLM call (e.g., Evidence Synthesizer)
- **hybrid** — combines deterministic rules with model calls (e.g., Claim Validator)
- **tool** — wraps an external tool or API (e.g., Search Tool)

---

## Step 2: Define the Contract

Edit `contract.yaml` to declare:

```yaml
entry:
  input_type: "evidence_base"
  required_fields: ["claims", "synthesis"]

exit:
  output_type: "validated_evidence"
  guaranteed_fields: ["validated_claims", "validation_summary"]

requirements:
  model_required: true
  model_capabilities: ["structured_output", "reasoning", "validation"]
  memory_access: "read"

side_effects: []
```

The contract is the compatibility boundary. Two nodes can connect only if
the upstream node's exit `output_type` matches the downstream node's entry
`input_type`.

---

## Step 3: Validate the Package

```bash
nodechain node validate nodes/my_evaluator
```

This checks:
- Manifest is well-formed
- Contract declares entry/exit ports
- Required fields are specified
- Implementation file exists and is importable

---

## Step 4: Test the Node

```bash
nodechain node test nodes/my_evaluator
```

Runs the package-local tests defined in `test_node.py`. These should cover:
- Input/output schema compliance
- Guaranteed fields are present in output
- Side effects behave correctly
- Error handling for malformed inputs

---

## Step 5: Check Compatibility

Before using the node in a chain, verify it can connect:

```bash
nodechain node check-compat --blueprint blueprints/research_decision_v1.yaml
```

This validates that all nodes in the blueprint have compatible port types
and that the connection graph is sound.

---

## Step 6: Publish to the Registry

```bash
nodechain registry publish nodes/my_evaluator
```

This:
- Computes a content hash for integrity
- Records capabilities (network, filesystem, memory, subprocess)
- Assigns a policy status (allowed/denied)
- Stores the package in the local registry

---

## Step 7: Inspect the Registered Package

```bash
nodechain registry inspect my_evaluator
nodechain registry list
```

The registry entry shows:
- `node_id`, `name`, `version`
- `content_hash` (integrity verification)
- `capabilities` (what the node can access)
- `policy_status` (whether it's allowed to run)
- `nodechain_min_version` (compatibility floor)

---

## Step 8: Lock Dependencies

```bash
nodechain registry lock
```

Generates `registry.lock.json` — a pinned record of exact package versions,
content hashes, and policy states. This prevents supply-chain drift:
the same lockfile guarantees the same node versions across environments.

---

## Step 9: Execute in a Chain

Add the node to a blueprint:

```yaml
nodes:
  - node_id: my_evaluator
    node_type: hybrid
    # ... connection to upstream/downstream nodes
```

Then run the chain:

```bash
nodechain run "your research question" -b blueprints/your_chain.yaml
```

During execution, the runtime:
1. Validates the node's contract against its connections
2. Checks policy gates (tools, memory, side effects, trust, cost)
3. Invokes the node with an InvocationEnvelope
4. Records pre/post/output trace events
5. Commits state atomically

---

## Step 10: Inspect Trace and Evidence

After execution:

```bash
# View the run's trace
nodechain trace <run-id>

# Inspect the recovery snapshot
nodechain recover inspect <run-id>

# Browse evidence and citations
nodechain recover evidence <run-id>

# Reconcile trace against persisted state
nodechain reconcile <run-id>
```

---

## Step 11: Deprecate or Revoke

When a node is no longer needed or has been superseded:

```bash
# Mark as deprecated (soft removal — existing lockfiles still work)
nodechain registry deprecate my_evaluator

# Revoke entirely (hard removal — future installs blocked)
nodechain registry revoke my_evaluator
```

---

## Step 12: Upgrade

To publish a new version:

```bash
# Update the implementation
# Bump the version in manifest.yaml
# Re-validate and test
nodechain node validate nodes/my_evaluator
nodechain node test nodes/my_evaluator

# Publish the new version
nodechain registry publish nodes/my_evaluator
```

The registry maintains version history. Previous versions remain available
for chains that pin to them via lockfile.

---

## Trust and Supply Chain

The SDK includes additional supply-chain modules:

```bash
# Certified registry operations
nodechain registry certified-list
nodechain registry certified-inspect <node_id>
nodechain registry certified-verify <node_id>

# Dependency resolution
nodechain registry resolve <node_id>
nodechain registry resolve-deps <node_id>

# Remote registry (v2.0.0+)
nodechain registry install-remote <url>
nodechain registry remote-build
nodechain registry serve

# Federation (v2.5.0+)
nodechain registry federation --help

# Reputation (v2.6.0+)
nodechain registry reputation --help
```

---

## Existing Node Packages

The repository includes real packaged node sets:

| Package | Location | Purpose |
|---|---|---|
| `echo_node` | `nodes/echo_node/` | Minimal example — echoes input |
| `future_node` | `nodes/future_node/` | Forward-looking capability demo |
| `incident_response` | `nodes/incident_response/` | Incident response node set |
| `sandbox_test_node` | `nodes/sandbox_test_node/` | Sandbox testing |
| `security_audit` | `nodes/security_audit/` | Security audit node set |
| `text_transforms` | `nodes/text_transforms/` | Text transformation utilities |

These demonstrate that nodes can be packaged, distributed, and installed
separately from the core runtime — the first step toward cross-chain reuse.
