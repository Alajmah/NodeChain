# Side-Effect Completion Design Study

**Status:** Design artifact (v2.99). No implementation in this release.
**Supersedes:** Nothing. Documents the gap surfaced by v2.97 characterization.
**Target implementation:** v3.0.0 (if this design converges).

---

## 1. Current behavior (frozen by v2.97)

NodeChain's side-effect journaling lifecycle currently works as follows:

```
planned → started → (completion never wired in mock chain)
```

### What exists
- **`record_side_effect`** (`core/state.py`): inserts a ledger row with
  `status="started"` (via `_journal_one` in `SideEffectJournalMixin`).
- **`update_side_effect_status`** (`SideEffectLedgerStore`): transitions
  ledger status (planned→started→completed→failed→unknown).
- **`TraceEmitter.side_effect_started()`**: emits `SIDE_EFFECT_STARTED`.
- **`TraceEmitter.side_effect_completed()`**: defined in `trace_emitter.py`
  but has **zero callers** in the entire `src/` tree.
- **`validate_side_effect_transition`**: enforces the legal transition graph
  (planned→started, started→completed/failed/unknown, etc.).

### What does NOT happen
- No code path marks side effects "completed" after a node succeeds.
- No code path marks side effects "failed" if a node fails.
- The mock chain leaves all declared side effects at status "started"
  indefinitely (until resume reconciliation marks them "unknown").

### Why this matters
Side effects are one of NodeChain's core governance boundaries. The current
state means:
- The ledger does not distinguish "started and succeeded" from "started and
  crashed" — both appear as "started" until a resume marks them "unknown".
- The trace does not contain `SIDE_EFFECT_COMPLETED` events.
- Resume/recovery cannot determine whether a started side effect actually
  completed without external verification.

This was characterized (not hidden) in v2.97's test suite.

---

## 2. Design invariant

```
Completed side effects require observed evidence.
The runtime must not silently infer completion for external actions.
```

"Node succeeded" and "external effect completed" are separate facts. A node
can produce a valid output while an external side effect:
- Partially failed (network timeout after partial write)
- Was skipped (caching layer returned, no external call made)
- Was retried (first attempt failed, second succeeded)
- Completed with different observed metadata (different response hash)

Therefore, the runtime cannot infer side-effect completion from node success
alone. Completion must be explicitly reported.

---

## 3. Completion authority models

### Model A: Orchestrator inference (REJECTED)

```
Node succeeds → declared side effects marked completed.
```

**Rejected.** Violates the invariant. "Node succeeded" ≠ "external effect
completed." This model would make the ledger claim things that may not be true.

### Model B: Adapter/executor-reported completion (PREFERRED for external effects)

```
Adapter or command runner explicitly reports observed completion.
Runtime records it in the ledger.
```

**How it would work:**
- After a node executes, the adapter/executor path inspects what actually
  happened externally.
- For each declared side effect, the adapter reports:
  - `completed` (with `response_hash` and optionally `external_reference`)
  - `failed` (with error reason)
  - `skipped` (with reason — e.g., cache hit)
- The runtime calls `update_side_effect_status` with the reported status.

**Why preferred:** It matches the actual execution boundary. The adapter IS
the component that knows whether the external call succeeded. It doesn't
require the node to understand ledger semantics.

**Limitation:** Requires adapter-level reporting infrastructure that doesn't
exist yet. Each adapter type (search, memory, code_execution) would need a
completion-reporting path.

### Model C: Node-output-reported completion (COMPLEMENTARY)

```
Node output includes side_effect_records.
Runtime validates them against declared/planned effects.
```

**How it would work:**
- A node's `execute()` may include `side_effect_records` in its output:
  ```json
  {
    "side_effect_records": [
      {
        "idempotency_key": "search:semantic_scholar:abc123",
        "status": "completed",
        "response_hash": "def456"
      }
    ]
  }
  ```
- The runtime (via `_emit_node_detail_events` or a dedicated path) validates
  each record:
  - Key must match a declared/planned side effect
  - Unknown keys are rejected (undeclared completion)
  - Missing declared effects are left as "started" (not inferred)
- Validated records drive `update_side_effect_status` calls.

**Why complementary:** Some nodes naturally know their side-effect outcomes
(e.g., `sandbox_test_runner` knows whether pytest passed). Model C lets them
report it without requiring adapter-level instrumentation.

**Limitation:** Requires node cooperation — nodes that don't report are left
at "started" (which is the honest current behavior).

### Recommended approach: B + C hybrid

- **Model B** for adapter-driven side effects (search, external API calls):
  the adapter path reports completion after the external call returns.
- **Model C** for node-driven side effects (code execution, memory writes):
  the node's output includes side-effect completion records.
- **Model A** is never used for external effects. It may be acceptable for
  purely deterministic internal effects (e.g., memory writes that the runtime
  itself performs), but this is a narrow exception, not the general rule.

---

## 4. Ledger transition rules (existing + proposed)

### Current legal transitions (`SideEffectLedgerStore.LEGAL_TRANSITIONS`)
```
planned → started, completed, failed
started → completed, failed, unknown
unknown → completed, failed, retry_authorized
completed → (terminal)
failed → (terminal)
retry_authorized → started
```

### Proposed additions (for v3.0 implementation)
```
started → skipped (new: effect was not performed, e.g., cache hit)
planned → skipped (new: effect was never needed)
```

### Resume behavior (existing, unchanged)
- `started` effects on resume → `unknown` (crash window — may or may not have completed)
- `planned` effects on resume → stay `planned` (safe to re-execute)
- `unknown` effects require explicit recovery decision (completed/failed/retry_authorized)

---

## 5. Trace requirements

### Current events
- `SIDE_EFFECT_STARTED` — emitted by `_journal_one` when a row transitions to "started"

### Missing events (proposed for v3.0)
- `SIDE_EFFECT_COMPLETED` — emitted when a side effect transitions to "completed"
  via observed evidence (not inference)
- `SIDE_EFFECT_FAILED` — emitted when a side effect transitions to "failed"
- `SIDE_EFFECT_UNKNOWN` — NOT emitted on resume (deliberately — the ledger is
  source of truth, not the trace; this is existing behavior from v2.33.0)
- `SIDE_EFFECT_SKIPPED` — if the "skipped" status is added

### Ordering invariants
```
SIDE_EFFECT_STARTED → before NODE_INVOKED (current behavior — pre-invocation journaling)
SIDE_EFFECT_COMPLETED → after NODE_SUCCEEDED (completion requires post-execution evidence)
SIDE_EFFECT_FAILED → after NODE_FAILED or after adapter reports failure
```

The `SIDE_EFFECT_COMPLETED` emitter already exists in `trace_emitter.py` —
it just has zero callers. Implementation means wiring it.

---

## 6. Acceptance criteria for a future implementation release

```
1. At least one completion model is implemented (B or C or both).
2. SIDE_EFFECT_COMPLETED events appear in trace for completed effects.
3. The ledger status "completed" requires observed evidence — not node success alone.
4. The v2.97 characterization tests are updated (the "started not completed"
   assertions flip to "completed" for effects that now have completion paths).
5. Resume behavior unchanged: unknown transition for started-but-not-completed.
6. Trace ordering: SIDE_EFFECT_COMPLETED after NODE_SUCCEEDED.
7. No inference shortcut: nodes/adapters that don't report completion leave
   effects at "started" — the honest state.
```

---

## 7. Non-goals

```
- No hostile-code containment claim
- No Docker backend
- No change to current runtime behavior in v2.99
- No change to policy blocking semantics
- No change to resume/recovery semantics
- No change to the planned→started→(unknown) lifecycle for unreported effects
```

---

## 8. Implementation sketch (for v3.0, not v2.99)

The most likely first implementation path:

1. **In `_emit_node_detail_events` (or a new completion method):** after
   `_journal_one` post-call processing, check if the node's output includes
   `side_effect_records` (Model C). If so, validate and update status.

2. **In adapter call paths:** after a search adapter returns, report
   completion with the response hash (Model B). This requires adding a
   reporting hook to the adapter call path.

3. **Wire `TraceEmitter.side_effect_completed()`:** the emitter exists. It
   needs callers in the completion path.

4. **Update v2.97 tests:** the "started not completed" assertions become
   "completed when reported" — but ONLY for effects that have a reporting
   path. Effects without reporting stay "started."

The critical design constraint: **the absence of a completion report must
leave the effect at "started," not infer "completed."** This preserves
NodeChain's trace-truth model: the ledger records what was observed, not
what was assumed.

---

## v3.0.0 — Implementation Status

**Implemented:** Model C (node-output-reported observed completion), first path.

- Nodes may include `output["side_effect_records"]`: a list of completion
  records, each with `side_effect_key`, `side_effect_type`, `status`,
  `observed_by`, `observed_at`, `response_hash`, and optional `evidence`.
- `SideEffectJournalController.complete_reported_side_effects(node_id, envelope, output)`
  validates each record against the started/planned ledger and, for valid
  records, transitions the ledger to `completed` (persisting `response_hash`)
  and emits `SIDE_EFFECT_COMPLETED`.
- The canonical mock `search_tool` now reports observed completion for its
  `semantic_scholar` external_call, closing the v2.97-characterized gap.
- New helper `make_canonical_search_key(adapter_name, request_hash)` in
  `nodechain.core.side_effect_utils` — single source of truth for the
  `search:<adapter>:<hash>` key format.

**Validation rules (v3.0):**

1. `side_effect_key` exactly matches a `started` ledger row for the current run.
2. `side_effect_type` matches the canonical type (e.g. `external_call`).
3. `status == "completed"`.
4. `observed_by` is an accepted authority (`node` in v3.0; `adapter`/`executor` deferred to v3.1).
5. `response_hash` is non-empty.
6. `observed_at` is non-empty.
7. The record is nested under `output["side_effect_records"]` and is itself a dict (malformed ⇒ fail closed).

Idempotency: same key + `completed` + same `response_hash` ⇒ safe replay (`True`); different `response_hash` ⇒ `CONTRACT_VIOLATION` (`False`).

Invalid/unmatched/malformed reports emit `CONTRACT_VIOLATION` (`decision="invalid_completion_report"`)
and fail the chain via the existing soft-fail path. No new exception or event
type was introduced.

**Not implemented in v3.0:**
- Model B (adapter/executor-reported completion via `BaseSearchAdapter`).
- memory_write / code_execution / external_write completion paths.
- A dedicated `SIDE_EFFECT_REJECTED` event type (uses `CONTRACT_VIOLATION`).
- Completion wiring on the `resume()` path (the `run()` seam only, in v3.0).

**Guardrail preserved:**
```
Completed means observed.
Node success does not imply side-effect completion.
No completion report ⇒ the side effect remains started.
```

---

## v3.1.0 — Resume-Path Implementation Status

**Implemented:** resume-path observed side-effect completion for freshly
re-executed nodes (Case A1). The `resume()` post-call seam now calls
`SideEffectJournalController.complete_reported_side_effects(node_id, envelope, response.output)`,
mirroring v3.0's `run()` wiring. For a node whose side-effect key is genuinely
new (the crash happened before it ever journaled), the effect is journaled
`started` and completed exactly like the run path.

**Not implemented in v3.1 (the crash-window limitation):**

Crash-window `unknown` effects (Case A2: journaled `started` in the crashed
run, marked `unknown` by `_reconcile_side_effects_on_resume`) are NOT
completable by the resume path. The v3.0 validation rule rejects completion of
non-`started` effects (`reason="completion_requires_started_status"`), and the
store layer independently requires a `verified_completed` recovery-decision
record for `unknown → completed` — and **no production code path writes
recovery decisions today**. Resolving crash-window `unknown` effects is a
recovery-governance design problem, deferred to v3.2.

**Scope statement:**

v3.1 wires observed side-effect completion into the normal resume re-execution
path. It does not resolve crash-window unknown effects; those remain blocked
on a recovery-decision design.
