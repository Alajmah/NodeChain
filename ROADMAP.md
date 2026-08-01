# NodeChain Development Roadmap

This roadmap tracks version-by-version development from v2.22.0 onward.
It is maintained collaboratively with strategic review as strategic reviewer.
Each version closes one runtime promise end-to-end: runtime behavior,
durable record, trace, reconciler, dashboard, and tests.

**Current HEAD:** See `git log --oneline -1`
**strategic review conversation:** `6a36016a-695c-83eb-b2f9-d657652e135b`

---

## Canonical Vertical Labels

Each vertical closes one governance surface end-to-end:

1. **Review Governance** ✅
2. **Memory Write Governance** ✅
3. **Side-Effect Enforcement** ✅
4. **Memory Read Governance** (v2.40.0–v2.41.0)
5. **Tool / Adapter Governance** (v2.42.0–v2.43.0)
6. **Package Trust / Registry Governance** (v2.44.0–v2.45.0)
7. **Operator Control Plane** (v2.46.0–v2.47.0)
8. **Evaluation / Assurance** (v2.48.0–v2.49.0)
9. **Productization** (v2.50.0–v2.52.0)

---

## Completed Verticals

### Review Governance (v2.22.0–v2.26.0, cleanup through v2.31.2) ✅

Governed DecisionReceipt materialization, digest-committed receipts,
ReviewVerifier 9-check pipeline, durable review_decision_attempts log,
audit triangle in TraceReconciler (trace ↔ receipt ↔ attempt log),
fail-closed on both request_review and resolve_resume_review paths.

### Memory Write Governance + Policy Type Split (v2.27.0–v2.31.2) ✅

Declarative PolicyEngine as runtime authority, durable memory_decisions
table, canonical candidate_digest, MEM-001..005 dashboard health rules,
MEMORY_WRITE/MEMORY_READ policy type split.

Memory-write governance is complete. MEMORY_READ exists as a policy type,
but runtime read gating, durable read decisions, reconciler checks, and
dashboard exposure audit are still forward work (v2.40.0–v2.41.0).

### Side-Effect Enforcement (v2.33.0–v2.39.0) ✅

Full side-effect governance vertical:
- Lifecycle trace/ledger (started/completed/failed/unknown)
- Runtime policy gate (PolicyType.SIDE_EFFECT)
- Blocked attempt durable log
- Declared-vs-observed enforcement (canonical taxonomy, CONTRACT_VIOLATION)
- Reconciler strong binding (composite identity fields)
- Governance dashboard (SE-001..006 health rules)
- Idempotency/dedup hardening (collision detection, terminal dedup)
- Recovery decision log + transition guard

**Closing invariant:** A side effect must have one stable identity across
planning, execution, completion, recovery, trace, ledger, reconciler, and dashboard.

| Version | Feature | HEAD |
|---|---|---|
| v2.33.0–v2.33.1 | Trace/Ledger Lifecycle | `84cd1963` |
| v2.34.0–v2.34.1 | Runtime Gate + Blocked Attempt Log | `5ca67d2c` |
| v2.35.0–v2.35.4 | Declared-vs-Observed Enforcement | `c5662d21` |
| v2.36.0 | Reconciler Strong Binding | `a1675ba6` |
| v2.37.0 | Governance Dashboard (SE-001..006) | `65cc5271` |
| v2.38.0–v2.38.1 | Idempotency/Dedup Hardening | `1fa42036` |
| v2.39.0 | Recovery Decision Log + Transition Guard | `96bb5ff4` |

---

## Forward Roadmap

### Phase 2 — Close Memory Read Governance

#### v2.40.0 — Memory Read Policy Runtime Gate

**Goal:** make memory reads governed like memory writes.

No durable memory, retrieved context, or memory-derived summary may be
exposed to a node unless a MEMORY_READ policy decision explicitly allows
it before retrieval or exposure.

Core work:
1. Add runtime gate before memory/context retrieval and before envelope/context exposure
2. Evaluate MEMORY_READ policy with node_id, purpose, query type, sensitivity, budget
3. Emit MEMORY_READ_REQUESTED / ALLOWED / DENIED events
4. Record durable memory_read_decisions
5. Block context exposure when denied — denied memory must not appear in
   invocation envelope, node context, trace-visible node input, or
   downstream synthesized context
6. Add reconciler check: memory read trace ↔ durable decision

Acceptance criteria:
- No node receives durable memory/context unless a MEMORY_READ policy decision allowed it
- A denied memory read must not appear in the invocation envelope, node context, trace-visible node input, or downstream synthesized context
- Denied memory reads produce durable decision + trace
- Reconciler detects memory read without decision

#### v2.41.0 — Memory Read Dashboard + Exposure Audit

**Goal:** expose memory-read governance health.

Dashboard fields:
- memory_read_requested_count
- memory_read_allowed_count
- memory_read_denied_count
- memory_read_without_decision_count
- memory_read_policy_mismatch_count
- nodes_with_memory_exposure

Completes the memory governance vertical:
write policy → write decision log → write reconciler → write dashboard →
read policy → read decision log → read reconciler → read dashboard

---

### Phase 3 — Tool and Adapter Governance

#### v2.42.0 — Tool Access Runtime Gate Generalization

**Goal:** replace hardcoded tool assumptions with manifest/contract-driven tool grants.

Core work:
1. Tool access determined from node contract / manifest
2. Runtime checks requested tool against declared tool grants
3. Durable tool access decision log
4. Trace events for TOOL_ACCESS_ALLOWED / TOOL_ACCESS_DENIED
5. Reconciler detects tool call without grant

Acceptance criteria:
- A node cannot call a tool merely because of its node_id
- A node must have an explicit contract/manifest grant

#### v2.43.0 — Adapter Grant Enforcement

**Goal:** enforce protocol/model/API adapter permissions as runtime gates.

Core work:
1. Model adapter grants
2. Search/API adapter grants
3. Memory adapter grants
4. External service grants
5. Adapter-level policy checks
6. Reconciler verifies adapter call against granted adapter

---

### Phase 4 — Package Trust and Supply-Chain Boundary

#### v2.44.0 — Node Package Trust Runtime Enforcement

**Goal:** prevent untrusted or unsigned nodes from executing privileged capabilities.

Core work:
1. Package identity
2. Package digest
3. Trust level
4. Signature or local trust marker
5. Runtime enforcement before invocation
6. Trace + durable trust decision

Acceptance criteria:
- Untrusted package cannot request privileged tool/memory/side-effect capability
- Trust decision is visible in trace and reconciler

#### v2.45.0 — Registry Admission Policy

**Goal:** make the node registry a governance boundary.

Core work:
1. Validate node manifests at registration
2. Reject invalid side-effect/tool/memory declarations
3. Record registry admission decisions
4. Add registry health dashboard

---

### Phase 5 — Human/Operator Control Plane

#### v2.46.0 — Operator Recovery Console

**Goal:** make review, unknown side effects, blocked side effects, and failed policy gates visible and actionable.

Core work:
1. List paused/recovery-required runs
2. Show unknown side effects
3. Show blocked side-effect attempts
4. Show review receipts
5. Show memory/tool policy denials
6. Allow operator decision records

#### v2.47.0 — Operator Recovery Actions

**Goal:** use the durable recovery decision model from v2.39.0 to let
operators safely resolve, retry, abandon, or verify uncertain side-effect
states from the control plane.

Core work:
1. Mark unknown side effect as externally verified completed
2. Mark unknown side effect as safe to retry
3. Mark run as unrecoverable
4. Emit durable recovery decision receipt (uses v2.39.0 model)
5. Reconciler verifies recovery receipt

Split across versions:
- v2.39.0 = durable recovery model + legality (done)
- v2.46.0 = recovery visibility console
- v2.47.0 = operator action execution using that model

---

### Phase 6 — Evaluation and Assurance

#### v2.48.0 — Chain Evaluation Harness

**Goal:** evaluate complete autonomous chains, not only unit behavior.

Core work:
1. Golden chain scenarios
2. Expected trace invariants
3. Expected policy decisions
4. Expected memory decisions
5. Expected side-effect ledger states
6. Regression reports

Becomes the quality gate for NodeChain itself.

#### v2.49.0 — Runtime Invariant Engine Hardening

**Goal:** make invariants first-class runtime/reconciler checks.

Core work:
1. Promote important reconciler checks into named invariants
2. Severity levels: info/warning/error/fatal
3. Versioned invariant sets
4. Invariant result dashboard
5. CI integration

---

### Phase 7 — Productization Layer

#### v2.50.0 — Developer SDK Stabilization

**Goal:** make NodeChain usable by external builders.

Core work:
1. Stable node authoring API
2. Manifest authoring helpers
3. Contract validation CLI
4. Local chain runner
5. Example node packages
6. Documentation for reusable blocks

#### v2.51.0 — Chain Builder Primitives

**Goal:** expose the Lego promise.

Core work:
1. Reusable node library
2. Chain blueprint templates
3. Typed-port compatibility checks
4. Visual or CLI chain inspection
5. Registry search

#### v2.52.0 — Product Shell / Managed Runtime

**Goal:** package NodeChain as a usable platform.

Core work:
1. Run dashboard
2. Trace browser
3. Governance dashboard
4. Node registry UI
5. Chain execution UI
6. Operator review/recovery UI

---

## Standing Conventions

- Each version: plan → review sign-off → implement → test → verify → commit → push → report → code-review re-review
- Full test suite must pass (5352+ passed, 2 pre-existing DB-leak failures acceptable)
- Version-guard tests (~32 files) batch-updated on each version bump
- CHANGELOG.md entry per version
- strategic reviews actual code on GitHub, not just reports
- Side-effect transitions follow the legal transition graph (see state.py LEGAL_TRANSITIONS)
