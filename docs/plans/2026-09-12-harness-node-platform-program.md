# Harness Node Platform Program — Post-Benchmark Plan

**Status:** FROZEN FOR SEQUENCING  
**Date:** 2026-09-12  
**Base:** `master@5d54190c87136ff217b0d2f4899d6a04ea1b486a`

## Decision

NodeChain will be developed primarily as a **governed reusable-capability platform built around Harness Nodes**.

The Governed Research Workspace remains a flagship reference application, live integration proof, and product-proof surface. Research-product feature parity is not the platform objective.

The next major proof question is:

> Can one governed capability be built once and reused across materially different autonomous systems while preserving identity, contracts, typed semantics, authority, side-effect truth, trust, evaluation, recovery, and evidence?

## Evidence basis

The completed Runtime / Framework benchmark showed NodeChain's strongest architectural center is governed execution assurance: durable state, recovery, operator authority, explicit side-effect semantics, trust, fail-closed execution, and inspectable evidence.

The completed Research Product benchmark showed a different result: the tested Research Workspace was not yet competitive as a completed research-answer product. All six live NodeChain tasks reached governed terminal failure before producing substantive research answers because evidence acquisition was repeatedly throttled while inference remained healthy.

The second result is a product-delivery failure, not a failure of the Harness Node/runtime thesis. It requires the flagship reference application to become reliable enough to complete its user outcome, but it does not justify optimizing the platform around research-market feature parity.

## Selected sequence

```text
P0  Current-truth rebaseline
        ↓
P1  Execution-Truth Integrity
        ↓
P2  Harness Node Reuse Proof
        ├── Research / decision work
        ├── Software engineering
        └── Approval-gated operations
        ↓
P3  Reference-product reliability
        ↓
P4  Node SDK + portable evaluation + private registry
        ↓
P5  Workspace / Studio productization
        ↓
P6  Enterprise platform expansion
```

P0–P3 are the selected near-term program. P4–P6 remain contingent on preceding evidence.

# P0 — Current-truth rebaseline

Restore the repository's documentation-authority invariant before new implementation work.

Required outcomes:

- pin `BASELINE.md` and `ARCHITECTURE.md` to current master;
- remove stale README/current-truth language for already-closed defects;
- reconcile `ROADMAP.md` so completed H1.1–H1.4 work is not presented as future work;
- classify Research Workspace explicitly as the flagship reference application rather than the definition of NodeChain;
- record the completed benchmark program as evidence without automatically promoting findings into implementation requirements;
- retain `v3.6.0` as release truth until a later release action changes it.

P0 is documentation-only. P1 does not start until P0 closes or is explicitly waived.

# P1 — Execution-Truth Integrity

Make NodeChain's strongest platform claim literal at the remaining external-effect and durable-mutation boundaries.

The required invariant is:

> Runtime evidence distinguishes admission/reservation, actual dispatch, response observation, terminal effect state, and recovery without inferring one from another.

P1 has three bounded targets.

### P1.1 Side-effect dispatch truth

A pre-wire denial must not be recorded as actual dispatch. The accepted model must distinguish at least planned/admitted state from a proved dispatch attempt, then preserve completed/failed/unknown terminal semantics.

Acceptance includes pre-dispatch denial, guard denial, deterministic post-dispatch failure, post-dispatch uncertainty, successful completion, idempotent duplicate completion, conflicting completion rejection, and fresh-process reconciliation.

### P1.2 Provider/wire retry ownership

A logical NodeChain effect must not contain unreconstructable hidden provider attempts.

Select and prove one model:

- runtime-visible physical attempts beneath the logical operation; or
- a single-attempt adapter boundary with retry ownership at a governed coordinator/runtime authority.

The exact physical-attempt count and retry authority must be reconstructable.

### P1.3 Durable-memory admission

Supported production durable memory writes must require governed admission. A lower-level mutation API must not bypass a rejected WriteFlow decision. Admission and durable mutation must be linked in evidence.

P1 explicitly excludes research UX, arbitrary replay/fork, coworker delegation, distributed workflow infrastructure, visual builders, and general refactoring.

# P2 — Harness Node Reuse Proof

Demonstrate reuse of the **same packaged governed capability** across at least three materially different autonomous systems:

1. Research / decision work.
2. Software engineering.
3. Approval-gated operations or incident response.

A node qualifies as genuinely reusable only if the proof preserves:

- identical package/content digest;
- node and contract identity/version;
- unchanged typed entry/exit semantics;
- application-specific capability grants and policy without node-code modification;
- unchanged declared side effects;
- the P1 execution-truth model;
- trust identity separate from invocation permission;
- stable trace/evidence semantics;
- evaluation bound to the same package/version/digest;
- fresh-process durability in at least one reference application;
- no product-specific weaker runtime or hidden governance bypass.

The deliverable is a versioned Harness Node Reuse Evidence Bundle containing package identity, contracts, blueprints, policy/capability differences, run IDs, effect/recovery evidence where applicable, node evaluation evidence, cross-application equivalence results, and explicit negative cases.

# P3 — Reference-product reliability

Research Workspace must become reliable enough to serve as a credible end-to-end platform proof, not a category-leading research product.

The reliability study must cover provider rate limits/health, provider backoff signals, global and per-provider budgets, retry ownership consistent with P1, failover without request storms, sufficient-evidence thresholds, degraded completion from an adequate provider subset, explicit failure when evidence is insufficient, and keyed versus anonymous provider configurations.

Qualification scenarios must include persistent 429, timeout, zero results, partial provider outage, governed recovery, successful degraded completion with disclosure, insufficient-evidence refusal, and at least one live substantive cited report.

# P4 and later

P4 begins only after P2 proves governed reuse. It productizes node authoring, portable evaluation/evidence, package/sign/attest lifecycle, private registry reuse, and compatibility/deprecation/revocation.

Workspace UI, Blueprint Studio, managed execution, multi-tenancy, distributed workers, and enterprise control-plane work remain later outcomes.

## Explicitly deferred comparator parity

Absent a new forcing function, do not promote:

- arbitrary checkpoint replay/fork/state editing;
- hierarchical manager/coworker delegation abstractions;
- broad distributed workflow infrastructure;
- research-product feature parity;
- managed multi-tenant execution.

## Program invariants

1. Runtime remains execution authority.
2. Trace/evidence never claim behavior that did not occur.
3. Product surfaces do not create parallel truth stores.
4. Trust identity remains separate from invocation authority.
5. Side-effect uncertainty is preserved rather than rewritten.
6. Stronger required controls fail closed rather than silently degrade.
7. Reference applications receive no hidden governance exemptions.
8. Benchmark findings are evidence; implementation requires a selected objective.
9. Acceptance criteria freeze before substantive implementation.
10. Closure evidence names the exact code and environment it proves.

## Immediate next action

The next repository change is **P0 only**. P0 must not contain P1 production code.

After P0 closes, P1 begins with a design/characterization packet freezing the authoritative dispatch boundary, side-effect vocabulary/compatibility mapping, retry ownership, memory-admission authority, adversarial acceptance tests, and migration rules.

## First major program milestone

The program reaches its first strategic proof when NodeChain can show, with pinned evidence:

> The same governed Harness Node package was reused across materially different autonomous systems, under different invocation policies, while its contract, trust, effect, recovery, evaluation, and evidence semantics remained intact and every application executed through the same runtime truth.
