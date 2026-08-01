# 5-Minute Local Proof

This quickstart demonstrates NodeChain's core value — **bounded nodes, runtime
execution, contract validation, trace output, and inspectability** — in under
five minutes with **zero external API keys** and **no model service running**.

Everything runs locally using NodeChain's deterministic `mock` model provider.

---

## Prerequisites

- Python 3.11+ (`python --version`)
- Git (`git --version`)
- This repo cloned

## Step 1: Install (30 seconds)

```bash
pip install -e ".[dev]"
```

This installs NodeChain in editable mode with all dev dependencies.

Verify the install:

```bash
python scripts/validate_schemas.py
```

Expected output:

```
[OK] All 20 schemas are valid JSON Schema (Draft 2020-12)
```

## Step 2: Run a chain (10 seconds)

Run the echo demo — the simplest possible NodeChain chain (1 node, 1 contract,
typed ports, full governance):

```bash
nodechain run "hello nodechain" -b blueprints/echo_demo_v1.yaml --provider mock
```

What happens:
- NodeChain loads the blueprint and registers 33 built-in nodes.
- The orchestrator validates all contracts (input/output types, side-effect
  declarations, trust levels).
- The `echo_node` executes inside a governed invocation envelope.
- A complete trace is saved to `data/traces/<run_id>.json`.

Expected output:

```
Chain complete!

Trace:
  Run ID: <a UUID>
  Status: completed
  Events: 8
  Cost: $0.0000
  Duration: ~3s

  Trace saved: data/traces/<run_id>.json
```

**Copy the Run ID** from the output — you'll use it in the next steps.

## Step 3: Inspect the trace (5 seconds)

View the trace as a formatted table:

```bash
nodechain trace <run_id>
```

Replace `<run_id>` with the UUID from Step 2. You'll see every event in
execution order: contract validation, node invocation, node success, output
validation, chain completion. Each event records its actor, decision, and
metadata.

This is NodeChain's **inspectability** value: every step is traced, and the
trace is the authoritative execution record — not a log, not a side effect.

## Step 4: Verify the trace (5 seconds)

Run the trace through 7 automated consistency checks:

```bash
nodechain trace-replay run --trace data/traces/<run_id>.json
```

Expected output:

```
Trace replay passed
  Events:  8
  Checks:  7
    step_order: 8 steps checked
    node_invocation_order: 8 node invocations, 2 unique nodes
    contract_validity: contracts valid
    port_validity: ports valid
    policy_verdicts: all policies passed
    state_transitions: transitions valid
    digest_references: digests valid
```

This proves the trace is **verifiable**, not just human-readable. The replay
report carries a SHA-256 digest — it's a cryptographically checkable artifact.

## Step 5: Try a richer chain (optional, 30 seconds)

### Multi-hop data flow

```bash
nodechain run "abc" -b blueprints/multi_node_demo_v1.yaml --provider mock
```

Two deterministic nodes (`uppercase_node` → `reverse_node`) prove multi-hop
data flow through typed ports.

### Branch/join with quorum

```bash
nodechain run "branch demo" -b blueprints/branch_demo_v1.yaml --provider mock
```

Seven nodes fork into three parallel branches and join via quorum — the
headline graph-runtime feature, all on mock.

### Shared/reusable nodes

```bash
nodechain run "quick fact check" -b blueprints/reuse_proof_quick_fact_check_v1.yaml --provider mock
```

Five nodes including shared registry-resolved nodes (`shared_risk_classifier`,
`shared_trace_collector`) prove node reusability across chain contexts.

---

## What you've proven

In under five minutes, you demonstrated:

| Capability | How you saw it |
|---|---|
| **Bounded nodes** | Every node has a contract (input type, output type, declared side effects) |
| **Runtime execution** | The orchestrator executes nodes through invocation envelopes |
| **Contract validation** | "All contracts validated" before any node runs |
| **Trace output** | Complete execution trace saved to `data/traces/<run_id>.json` |
| **Inspectability** | `nodechain trace` shows every event; `trace-replay` verifies consistency |
| **Zero external dependencies** | Everything ran on the deterministic mock provider |

## Next steps

- Read `VISION.md` for the full platform thesis.
- Explore `blueprints/` — each YAML is a runnable chain.
- Read `docs/native_sandbox_test_runner.md` for the governed sandbox execution
  surface (the Code Review chain with real patch testing).
- Check `docs/ci.md` for verification and CI conventions.

## Troubleshooting

**"command not found: nodechain"** — make sure you ran `pip install -e ".[dev]"`
and your Python Scripts directory is on PATH.

**ChromaDB warning** — harmless. ChromaDB is optional; if it's not running,
memory features are simply unavailable and the chain proceeds normally.

**Trace file not found** — the Run ID in the output is also the filename:
`data/traces/<run_id>.json`. Make sure you're in the repo root.
