# Recovery-Decision Authority for Crash-Window Unknown Side Effects

## v3.3 Design Study — Updated

**Status:** implemented in v3.3.0. The design study graduated to a release — see the "v3.3.0 Implementation Status" section at the end of this document.
**Prerequisite:** v3.2.0 fixed retry-recovery truth, so failure-manager recovery signals are now trustworthy.
**Code verification (2026-07-09):** the store's semantic-binding gate (`stores.py:349-386`) and ledger UPDATE (`stores.py:388`) already share one connection inside `update_side_effect_status`; `record_recovery_decision` (`stores.py:751-779`) opens a SEPARATE connection and uses `INSERT OR REPLACE` with `decision_id` defaulting to `""`. Both facts motivate the atomic-method requirement and the decision_id audit rules below. Implementation-readiness gate cleared.

## Thesis

Crash-window `unknown` side effects are visible but not actionable. Current surfaces can show that intervention is needed, but no production path converts an `unknown` side effect into an explicit recovery decision. The existing write machinery is present but unwired: `record_recovery_decision` exists, the store-layer semantic-binding gate exists, but there are no production callers; the operator recovery surface also has no side-effect-resolution action.

v3.3 should close this gap narrowly:

```text
Wire the operator recovery surface to resolve unknown side effects through a governed RESOLVE_SIDE_EFFECT action.
```

v3.3 should **not** add autonomous recovery, skipped-node re-execution, validator relaxation, or a new `waived` ledger status.

## Corrected core invariant

```text
Completed means observed.
Failed means externally failed, did not occur, or was closed as unrecoverable with reason.
Retry-authorized means an operator has authorized a future retry, but no retry has happened yet.
Unknown means the runtime lost certainty and no authority has resolved it.
```

Do **not** describe all outcomes as terminal. Only `completed` and `failed` are terminal. `retry_authorized` is non-terminal.

## Authority model

Only the governed runtime may mutate a side-effect ledger row out of `unknown`.

The actor may be an operator, but the operator does not directly edit the ledger. The operator submits a recovery action; the runtime authorizes it, validates it, records the decision, performs the gated transition, traces it, and records the operator action.

Initial v3.3 authority:

```text
operator → allowed
policy_engine → deferred
automated reconciliation agent → deferred
node → not authority
adapter → evidence provider only, not authority
```

This follows NodeChain's runtime-authority model: policies and runtime determine what actually executes, and trace is the historical record.

## Recovery action

Add:

```text
RecoveryAction.RESOLVE_SIDE_EFFECT
```

RBAC:

```text
allowed role: operator
```

This joins the existing operator recovery boundary:

```text
authorize → delegate → emit/trace → record operator action
```

## Resolution mapping

```text
verified_completed
  → ledger status: completed
  → meaning: operator confirms the external side effect occurred
  → evidence required: external_reference OR response_hash
  → reason_code: side_effect_completed_verified

verified_failed
  → ledger status: failed
  → meaning: evidence shows the effect failed or did not occur
  → evidence required: reason
  → optional: external_reference
  → reason_code: side_effect_failed_verified

mark_unrecoverable
  → ledger status: failed
  → meaning: operator cannot prove the outcome and closes it as unrecoverable
  → evidence required: reason
  → reason_code: side_effect_unrecoverable_operator_closed

safe_to_retry
  → ledger status: retry_authorized
  → meaning: operator authorizes a future retry
  → evidence required: reason
  → reason_code: side_effect_retry_authorized
```

`mark_unrecoverable` maps to `failed` because the current store has no `waived` status. The distinction must be preserved in the decision record and reason code. Reports and dashboards must not collapse `verified_failed` and `mark_unrecoverable` into the same human meaning.

## Rejected: `waived` status in v3.3

Do not add:

```text
unknown → waived
```

A real `waived` status would require a broader ledger redesign: new status, legal transitions, reconciler behavior, dashboard semantics, inspect/report rendering, and policy meaning. v3.3 should not take that on.

For now:

```text
operator gives up / cannot prove outcome → mark_unrecoverable → failed + reason_code
```

## Skipped-node recovery

Skipped nodes should **not** re-enter the normal node execution seam.

The resume skip is load-bearing for idempotency. Re-running a completed node can re-fire the side effect. v3.3 must not punch a hole through resume scheduling just to reach the post-call completion seam.

Correct seam:

```text
ledger recovery seam, not node post-call seam
```

Flow:

```text
resume / inspect / recovery classifier detects unknown side effect
→ operator lists unknown side effects
→ operator submits RESOLVE_SIDE_EFFECT
→ runtime writes recovery decision + transitions ledger atomically
→ unknown becomes completed | failed | retry_authorized
→ no node invocation occurs
→ no post-call completion report is accepted from a skipped node
```

For `safe_to_retry`, v3.3 only records:

```text
unknown → retry_authorized
```

It does **not** perform the retry. Actual re-execution after `retry_authorized` is a later scheduler design.

## Production caller location

The production caller belongs behind the governed recovery service boundary:

```text
RecoveryService._delegate_action
```

Updated call chain:

```text
operator CLI/API
  → RecoveryService.apply_action(
        run_id,
        RecoveryAction.RESOLVE_SIDE_EFFECT,
        side_effect_key=...,
        decision=...,
        reason=...,
        external_reference=...,
        response_hash=...
    )
    → OperatorActionPolicy.authorize(...)
    → RecoveryService._delegate_action(...)
      → StateManager.resolve_side_effect_recovery_decision(...)
        → DecisionLogStore.resolve_side_effect_recovery_decision_transactional(...)
          → validate decision_id
          → validate target side effect exists and status == unknown
          → validate decision value and evidence
          → write recovery decision
          → update side-effect status through semantic-binding gate
          → commit transaction
    → emit existing recovery action trace/event surface
    → record operator action ledger row
```

Do **not** call `record_recovery_decision(...)` and `update_side_effect_status(...)` as two independent production writes.

## Atomicity requirement

This is mandatory.

```text
The recovery decision write and side-effect status transition must be atomic.
```

Required behavior:

```text
If the ledger transition fails, no recovery decision may remain that makes the run appear recoverable.
```

Design requirement:

```text
StateManager.resolve_side_effect_recovery_decision(...)
```

or an equivalent transactional store method must perform both operations in one transaction.

This avoids the dangerous partial state:

```text
decision exists
ledger still unknown
classifier thinks recovery exists
run is still unresolved
```

**Implementation note (verified against store):** the semantic-binding gate (`stores.py:349-386`) and the ledger UPDATE (`stores.py:388-395`) already run on the same `conn` inside `update_side_effect_status`. The atomic method should open one connection, INSERT the recovery decision, then run the gate + UPDATE in the same transaction scope — the gate's SELECT will find the freshly-inserted row. Use a plain `INSERT` (not `INSERT OR REPLACE`) so a duplicate `decision_id` raises `sqlite3.IntegrityError`, which the caller translates to `DUPLICATE_RECOVERY_DECISION`. This lets the PRIMARY KEY constraint enforce uniqueness atomically (no TOCTOU race from pre-checking existence).

## Decision ID and audit behavior

Production code must generate a unique decision ID.

Rules:

```text
- decision_id must be UUID-like or otherwise globally unique enough for the store.
- empty decision_id is rejected before store write.
- duplicate decision_id is rejected; it must not silently overwrite.
- production path must not rely on INSERT OR REPLACE semantics.
```

If the underlying store still uses `INSERT OR REPLACE` (`stores.py:760`), v3.3 must protect the production path with caller/store validation so an existing decision is never overwritten silently.

## Trace vocabulary decision

For v3.3, choose the narrow path:

```text
No new SIDE_EFFECT_RESOLVED event type.
```

Use existing surfaces:

```text
RECOVERY_ACTION_ALLOWED
operator-action ledger row
recovery-decision record
side-effect ledger transition
reconciler checks over the persisted ledger
```

Only add a dedicated `SIDE_EFFECT_RESOLVED` event later if the reconciler cannot validate operator-resolved unknowns cleanly without it.

## CLI surface

Add:

```bash
nodechain recover list-unknown --run-id <run_id>
```

and:

```bash
nodechain recover resolve-side-effect \
  --run-id <run_id> \
  --side-effect-key <key> \
  --decision verified_completed|verified_failed|mark_unrecoverable|safe_to_retry \
  --reason "<reason>" \
  [--external-reference "<reference>"] \
  [--response-hash "<hash>"]
```

Validation rules:

```text
verified_completed:
  requires external_reference OR response_hash

verified_failed:
  requires reason
  external_reference optional

mark_unrecoverable:
  requires reason

safe_to_retry:
  requires reason
```

Clean errors required:

```text
SIDE_EFFECT_NOT_FOUND
SIDE_EFFECT_NOT_UNKNOWN
SIDE_EFFECT_ALREADY_RESOLVED
INVALID_RECOVERY_DECISION
MISSING_REQUIRED_EVIDENCE
UNAUTHORIZED_RECOVERY_ACTION
DUPLICATE_RECOVERY_DECISION
```

No raw store-layer exception should leak to the operator.

## Non-goals

```text
- No autonomous unknown-effect resolution.
- No automated reconciliation agent.
- No new waived status.
- No skipped-node re-execution.
- No retry execution after safe_to_retry.
- No run()/resume() execution-flow change.
- No observed-completion validator relaxation.
- No unknown→completed through output["side_effect_records"].
- No Model B adapter-reported completion.
- No new broad trace vocabulary unless inspection proves it necessary.
```

## Acceptance criteria for v3.3 implementation

```text
1. Operator can list unknown side effects for a run.
2. Operator can resolve unknown → completed through verified_completed.
3. Operator can resolve unknown → failed through verified_failed.
4. Operator can resolve unknown → failed through mark_unrecoverable, with a distinct reason_code.
5. Operator can resolve unknown → retry_authorized through safe_to_retry.
6. safe_to_retry does not re-execute the node.
7. verified_completed without external_reference or response_hash is rejected.
8. Non-operator role cannot resolve side effects.
9. Missing side_effect_key is rejected cleanly.
10. Unknown side effect not found is rejected cleanly.
11. Already resolved side effect is rejected cleanly.
12. Empty decision_id is impossible or rejected.
13. Duplicate decision_id cannot overwrite an existing decision.
14. Decision write + ledger transition are atomic.
15. If ledger transition fails, no recovery decision remains.
16. Operator action is authorized, traced, and recorded.
17. Recovery decision is durably recorded.
18. Ledger transition uses the existing semantic-binding gate.
19. Resolved effects no longer appear as unresolved unknowns in dashboard/inspect/reconciler surfaces.
20. Existing SE-R3/R4/R5 reconciler checks remain green for resolved effects.
21. No run()/resume() node execution-flow change.
22. No change to observed side-effect completion validation.
23. Existing v3.0–v3.2 tests remain green.
24. Linux `.28` full suite green before merge/tag.
```

## Recommended release framing

```text
v3.3.0 — Operator Side-Effect Recovery Decisions
```

Release wording:

```text
v3.3.0 wires governed operator resolution for crash-window unknown side effects. Operators can list unknown effects and resolve them through explicit recovery decisions that atomically record authority and transition the side-effect ledger. v3.3 does not add automated recovery, skipped-node re-execution, validator relaxation, or a waived status.
```

## Roadmap after v3.3

```text
v3.4 candidate A:
  Automated unknown-effect reconciliation probe
  - actor="automated:<name>"
  - separate trust/evidence model
  - writes the same recovery-decision records

v3.4 candidate B:
  retry_authorized execution design
  - scheduler semantics for re-running after operator authorization
  - idempotency controls
  - resume interaction
```

## Implementation readiness

This design is ready to become an implementation plan once the code inspection confirms one point:

```text
Can the store support an atomic decision+transition method cleanly without destabilizing existing recovery-decision tests?
```

**Answer (verified 2026-07-09):** yes. The gate + UPDATE already share one connection inside `update_side_effect_status` (`stores.py:315-395`); inserting the decision row into that scope is additive. Existing recovery-decision tests (`test_side_effect_recovery_decisions.py`, `test_side_effect_transition_guard.py`) call the two methods independently and are unaffected because the new atomic method is net-new, not a replacement.

If yes, v3.3 can proceed as an implementation release. If not, v3.3 should first ship the atomic store method and tests as the narrow foundation, then wire CLI/operator resolution in v3.3.1.

---

## v3.3.0 — Implementation Status

**Implemented:** governed operator resolution for crash-window unknown side effects.

- `SideEffectLedgerStore.resolve_side_effect_recovery_decision_transactional` — atomic decision INSERT + gate + ledger UPDATE in one transaction (plain INSERT, PK-enforced uniqueness).
- `StateManager.resolve_side_effect_recovery_decision` — validated facade (decision→status mapping, evidence requirements, UUID decision_id, status==unknown pre-check, clean errors).
- `RecoveryAction.RESOLVE_SIDE_EFFECT` — governed recovery boundary (authorize → delegate → emit → record); **RBAC: operator only** (side-effect resolution is a truth-claim about external state, distinct from flow-control recovery actions; finance/admin rejected for this action specifically); ledger-layer delegation (no orchestrator re-execution).
- CLI: `nodechain recover list-unknown --run-id` + `nodechain recover resolve-side-effect --run-id --side-effect-key --decision --reason [--external-reference] [--response-hash]`.
- Recovery classifier flips `CRASH_NEEDS_OPERATOR → CRASH_RECOVERABLE` on resolution; SE-R3/R4/R5 reconciler invariants hold.

**Decision→status mapping implemented:** `verified_completed → completed` (requires external_reference OR response_hash); `verified_failed → failed`; `mark_unrecoverable → failed` (distinct reason_code); `safe_to_retry → retry_authorized`.

**Not implemented (deferred, as designed):**
- Autonomous/automated recovery (v3.4 candidate A).
- `retry_authorized` re-execution scheduler (v3.4 candidate B).
- `waived` status (`mark_unrecoverable` maps to `failed` + reason_code).
- Skipped-node re-execution (resolution is ledger-layer, out-of-band).
- Model B adapter-reported completion.
- New trace event type (uses existing `RECOVERY_ACTION_ALLOWED`).
