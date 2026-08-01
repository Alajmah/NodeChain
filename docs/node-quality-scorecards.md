# Node Quality Scorecards (v2.65.0)

Node-level quality evaluation for registry-resolved deterministic nodes.

## Purpose

v2.64.x proved that shared nodes are registry-resolved governed packages.
v2.65.0 proves that those packages have **measurable node-level quality**:
reproducibility, correctness, schema compliance, cost compliance, latency,
and rule branch coverage.

> Build a node once. Govern it forever. Reuse it everywhere.

---

## Profiles

Two scorecard profiles are planned:

| Profile | Status | Target Nodes | Correctness Model |
|---------|--------|-------------|-------------------|
| **deterministic** | ✅ v2.65.0 | `shared_risk_classifier`, `shared_trace_collector` | Exact match (golden I/O) |
| **model_backed** | ❌ deferred | Harness nodes (`evidence_synthesizer`, etc.) | Fuzzy match + tolerance bands |

v2.65.0 implements the deterministic profile only. Model-backed scorecards
require a different correctness model (fuzzy matching, nondeterminism
controls) and are deferred to a future release.

---

## Metrics (deterministic profile)

| Metric | Range | Target | What it measures |
|--------|-------|--------|-----------------|
| `reproducibility` | 0–1 | 1.0 | Same input produces identical canonical output across N runs (volatile fields stripped) |
| `exact_match_correctness` | 0–1 | 1.0 | Expected output is a subset of actual (classification correctness) |
| `schema_compliance` | 0–1 | 1.0 | All `NodeContract.guaranteed_fields` present in output |
| `cost_compliance` | 0–1 | 1.0 | `model_required=false` nodes report `cost_usd == 0.0` |
| `latency_ms_p95` | ms | <500 | P95 latency across all case runs (warn >100ms, fail >500ms) |
| `rule_branch_coverage` | 0–1 | 1.0 | Both factor triggers AND outcome rules fired as expected |

### Volatile field handling

Some fields are inherently non-deterministic (e.g. `trace_id` is uuid-derived).
The scorecard handles this via `ignored_fields` — these fields are stripped
before reproducibility and exact-match comparisons. For `shared_trace_collector`,
`trace_id` is ignored.

### Report digest stability

The `report_digest` is a SHA-256 over **quality fields only** — it excludes
all timing fields (`latencies_ms`, `latency_ms_mean`, `latency_ms_max`,
`latency_ms_p95`, `generated_at`). This makes the digest deterministic across
separate runs of the same node, even though latency varies.

---

## Branch coverage

Branch coverage uses namespaced identifiers covering both factor triggers
and outcome rules:

**Risk classifier branches:**
```
risk_factor.high_severity_signals
risk_factor.high_uncertainty_count
risk_factor.low_confidence
risk_factor.no_evidence_refs
level.high_via_two_factors
level.high_via_two_high_severity
level.medium_via_one_factor
level.medium_via_confidence_below_0_5
level.low_baseline
```

**Trace collector branches:**
```
trace.trace_complete_true
trace.trace_complete_false
trace.error_count
```

---

## How to run

```bash
# Evaluate a single shared node
nodechain eval node-scorecard --node shared_risk_classifier

# Evaluate all shared deterministic nodes
nodechain eval node-scorecard --all-shared

# Output JSON to file
nodechain eval node-scorecard --all-shared --output scorecard.json

# Print JSON to stdout
nodechain eval node-scorecard --node shared_risk_classifier --json
```

---

## Report format

```json
{
  "report_type": "node_quality_scorecard",
  "target_type": "node",
  "node_id": "shared_risk_classifier",
  "node_version": "1.0.0",
  "node_origin": "local_registry",
  "content_digest": "...64-char SHA-256...",
  "profile": "deterministic",
  "metrics": {
    "reproducibility": 1.0,
    "exact_match_correctness": 1.0,
    "schema_compliance": 1.0,
    "cost_compliance": 1.0,
    "latency_ms_p95": 0.0,
    "latency_ms_mean": 0.5,
    "rule_branch_coverage": 1.0
  },
  "thresholds": {
    "reproducibility": 1.0,
    "exact_match_correctness": 1.0,
    "schema_compliance": 1.0,
    "cost_compliance": 1.0,
    "rule_branch_coverage": 1.0,
    "latency_ms_p95": 500.0
  },
  "cases": [
    {
      "case_id": "rc-low-baseline",
      "passed": true,
      "reproducible": true,
      "exact_match": true,
      "branches_expected": ["level.low_baseline"],
      "branches_fired": ["level.low_baseline"],
      "branches_covered": true,
      "latencies_ms": [0.0, 0.0, 0.0],
      "latency_ms_mean": 0.0,
      "latency_ms_max": 0.0
    }
  ],
  "passed": true,
  "report_digest": "...64-char SHA-256 (quality fields only)..."
}
```

---

## Architecture

```
CLI / helper layer:
  resolve node via NodeLoader (registry path, provenance)
  collect content_digest from registry package
  select golden cases for the node

scorecard runner (pure):
  takes node_instance directly
  invokes through NodeInvoker (real latency measurement)
  runs each case replay_count=3 times
  computes 6 metrics
  emits report with stable digest
```

---

## Deferred

- Model-backed node scorecards (fuzzy correctness, tolerance bands)
- Cross-chain scorecard aggregation (v2.67.3 dashboard)
- Trend tracking over time
- Automated golden-case generation
