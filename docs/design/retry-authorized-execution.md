# Retry-Authorized Execution Semantics
## v3.4 Design Study

**Status:** design study (no implementation in this release).
**Date:** 2026-07-09.
**Prerequisite:** v3.3.0 introduced `safe_to_retry → retry_authorized` as a governed operator recovery decision, but deliberately did not execute the retry. v3.4 defines what it means to execute after that state.

---

## Thesis

v3.3 made `retry_authorized` a real recovery state with zero production callers for its execution. v3.4 must define what it means to execute after that state without violating the side-effect discipline v3.0–v3.3 established.

Core invariant:

```text
retry_authorized permits a future attempt.
It does not erase the unknown attempt.
It does not imply the original side effect failed.
It does not allow blind re-execution.
```

NodeChain's runtime owns state transitions, retries, failures, policy enforcement, trace emission, pause/resume, and completion/failure decisions; side effects must be declared and trace-relevant decisions recorded. v3.4 therefore cannot be "just re-run the skipped node."

## Grounding (verified against v3.3.0 code)

Three facts shape this design:

1. **`LEGAL_TRANSITIONS` permits `retry_authorized → {started}`** (`stores.py:208`, `state.py:931`). The store currently allows this transition, but v3.4's lineage model does NOT use it on the original side-effect row. The original row remains `retry_authorized` as the historical record of the operator's `safe_to_retry` decision. A retry execution allocates a NEW child retry-attempt key, which enters the normal side-effect lifecycle as `planned → started → completed | failed | unknown`. The existing `retry_authorized → started` transition is rejected for v3.4's lineage model unless a later design explicitly chooses same-row retry execution.

2. **`retry_authorized → started` has zero production callers.** Defined in the transition graph but nothing transitions it. This is the gap v3.4 closes — but via a child attempt row, not by transitioning the original.

3. **`_journal_one` (`side_effect_journal.py:226-238) only re-starts `planned` rows.** If a retry re-executes the node with the *same* side-effect key, `_journal_one` finds the existing `retry_authorized` row, the `if existing["status"] == "planned"` branch is False, and it returns True leaving the row stuck at `retry_authorized`. **Therefore the retry attempt MUST use a new key** — not just for lineage cleanliness, but because the existing journaling machinery cannot unstick a `retry_authorized` row by key reuse. This makes the new-child-attempt model a requirement, not a preference.

4. **Ordinary `RETRY_STEP` (the existing recovery action) calls `orchestrator.resume(run_id)`** (`cli/recover.py:113`) — it operates at the step/invocation level, knows nothing about side-effect keys, and goes through the normal resume path (which skips completed nodes). It is a different operation from executing a `retry_authorized` side effect. v3.4 keeps them distinct.

---

## Design questions

### Q1. Who can trigger execution after `retry_authorized`?

**Recommendation: operator only in v3.4.**

`safe_to_retry` was an operator truth-authority decision in v3.3. The actual execution after that decision is a separate authority class: it can create a second external side effect. Keep it narrow:

```text
operator → allowed
policy_engine → deferred
automated scheduler → deferred
node → not authority
adapter → evidence/idempotency provider only
```

Suggested action: `RecoveryAction.EXECUTE_RETRY_AUTHORIZED` (preferred over `RETRY_AUTHORIZED_STEP` — makes the distinction from ordinary `RETRY_STEP` explicit). RBAC: `{"operator"}` — matching v3.3's `RESOLVE_SIDE_EFFECT` precedent (operator-only for side-effect truth authority).

### Q2. Does execution re-run the original node, a recovery node, or a specialized replay path?

**Recommendation: specialized recovery replay path, not normal resume and not ordinary retry.**

Do not punch through the normal resume skip rule (it's load-bearing for idempotency — re-running a completed node re-fires side effects). Instead, v3.4 defines a separate controlled execution seam:

```text
operator action
→ authorize EXECUTE_RETRY_AUTHORIZED
→ validate side_effect status == retry_authorized
→ build a recovery invocation envelope
→ execute the same node implementation under recovery metadata
→ require fresh pre-call side-effect journaling with a NEW attempt key
→ require normal observed-completion reporting (output["side_effect_records"])
→ reconcile old retry_authorized effect and new attempt separately
```

The original crash-window effect remains `retry_authorized` (history preserved); the new retry attempt has its own side-effect record with its own lifecycle (`started → completed | failed | unknown`).

### Q3. How does the scheduler avoid duplicate side effects?

**This is the central v3.4 question, and grounding fact #3 makes the answer non-optional.**

Retry execution is allowed only when the original side effect is `retry_authorized` AND the retry attempt has a distinct attempt identity (new key). Do NOT mutate the original key.

Proposed key shape:
```text
<original_side_effect_key>::retry::<attempt_number_or_uuid>
```
Or a canonical helper:
```text
make_retry_side_effect_key(original_key, recovery_decision_id, attempt_number)
```

The original record remains:
```text
status: retry_authorized
decision: safe_to_retry
```

The retry attempt is a NEW child row that enters the normal side-effect lifecycle from the beginning:
```text
(nonexistent) → planned → started → completed | failed | unknown
```

Do not mark the original `retry_authorized` record as `completed` merely because the retry completed — that would rewrite history. The original records "an attempt was authorized"; the retry records "the authorized attempt was executed and observed." These are two separate historical facts that need separate identities:
```text
Fact 1: original side effect became unknown, then safe_to_retry was authorized.
Fact 2: a later retry attempt executed and produced its own result.
```

### Q4. What evidence or idempotency key is required before retry?

Minimum v3.4 evidence standard:
```text
- original side effect status == retry_authorized
- recovery decision exists with decision == safe_to_retry
- actor == operator
- reason is present
- retry policy allows a retry for this side-effect type
- retry attempt has a unique attempt key
```

For external mutation / high-impact actions, require an idempotency control before execution:
```text
- idempotency_key, or
- adapter-level safe retry declaration, or
- explicit operator override with reason
```

For read-only external calls (e.g. `external_call` search), lighter rules are acceptable, but still need trace and attempt identity.

### Q5. How are retry execution attempts traced and reconciled?

**Recommendation: no new broad trace vocabulary unless inspection proves existing events cannot express it.**

Use existing surfaces first:
```text
RECOVERY_ACTION_ALLOWED
operator-action ledger row
side-effect journal planned/started/completed events for the retry attempt
node_invoked / node_succeeded / node_failed
reconciler checks over original + retry attempt rows
```

If design inspection shows ambiguity, add ONE narrow event: `SIDE_EFFECT_RETRY_EXECUTED`. But default to no new event in the first design pass.

---

## Proposed model

### State model (lineage, not a new table at first)

```text
original_side_effect_key   → remains retry_authorized
retry_attempt_key          → new, its own lifecycle
recovery_decision_id       → links the two
retry_authorized_by        → operator who said safe_to_retry
retry_executed_by          → operator who triggered EXECUTE_RETRY_AUTHORIZED
retry_execution_timestamp
```

Key design point: **lineage**. The retry attempt points back to the original `retry_authorized` effect; the original is not overwritten.

### Transition model

Two separate rows, two separate lifecycles, linked by lineage — NOT one row transitioning through `retry_authorized → started`.

**Original side-effect row** (the crash-window effect, v3.3):
```text
unknown → retry_authorized          (v3.3, via safe_to_retry decision)
                                      ...and stays retry_authorized. Terminal for this row.
```

**Retry attempt row** (the child, v3.4):
```text
(nonexistent) → planned → started → completed | failed | unknown
```

The child enters the normal lifecycle from `planned` — it does NOT pass through `retry_authorized` (that status belongs to the original authorization, not the attempt). The child's lineage metadata (`recovery_decision_id`, `original_side_effect_key`) ties it back to the authorization without duplicating the authorization state onto the attempt.

The store currently permits `retry_authorized → started` (`LEGAL_TRANSITIONS`), but v3.4's lineage model does NOT use that transition on the original row. It is rejected unless a later design explicitly chooses same-row retry execution.

Rejected:
```text
same-key retry execution           (collapses two historical facts into one row)
original retry_authorized → completed  (rewrites history — retry must be observed, not inferred)
original retry_authorized → failed     (same — must be observed)
original retry_authorized → started    (v3.4 uses a child attempt, not same-row transition)
original retry_authorized → unknown    (nonsensical)
retry_executed status              (no such status; child uses the normal lifecycle)
normal resume skip bypass          (breaks idempotency)
same side-effect key reused        (grounding fact #3: _journal_one cannot unstick it)
automatic retry without operator   (violates operator-authority)
```

### Execution seam

Recommended: a `SideEffectRetryCoordinator` (or a `RecoveryService._delegate_action` branch for `EXECUTE_RETRY_AUTHORIZED`, matching v3.3's pattern of extending RecoveryService rather than adding new controllers). Responsibilities:

```text
- validate retry_authorized state
- validate safe_to_retry decision
- validate actor/RBAC
- allocate retry attempt identity (new key)
- compile recovery invocation envelope
- invoke node through existing runtime node-invocation machinery
- journal retry attempt side effects separately (new key)
- route result through existing observed-completion validation (v3.0/v3.1)
- emit/record recovery action and attempt lineage
```

Do NOT put this directly in `resume()`. Resume is about restoring chain progress; retry-authorized execution is an explicit recovery operation.

---

## Non-goals (v3.4)

```text
- No automated unknown-effect reconciliation.
- No automated retry scheduler.
- No adapter-reported completion Model B.
- No validator relaxation.
- No reuse of the original side-effect key for retry.
- No mutation of the original retry_authorized row (it stays retry_authorized; the retry is a child attempt).
- No mutation of retry_authorized → completed based on retry success.
- No broad waived-status redesign.
- No general workflow retry rewrite.
- No new retry_executed status (the child attempt uses the normal planned → started → completed|failed|unknown lifecycle).
```

---

## Design-study tasks

```text
1. Inventory current statuses and transitions (DONE in grounding above):
   - LEGAL_TRANSITIONS: retry_authorized → {started} exists, zero callers
   - retry_authorized references: dashboard count, reconciler terminal check, store gate

2. Inspect ordinary RETRY_STEP (DONE in grounding above):
   - calls orchestrator.resume(run_id); step-level; no side-effect-key awareness
   - distinct from EXECUTE_RETRY_AUTHORIZED; keep separate

3. Characterize retry_authorized today (DONE in grounding above):
   - safe_to_retry records retry_authorized (v3.3)
   - no production code executes it
   - _journal_one cannot unstick it by key reuse (grounding fact #3)

4. Design retry attempt identity: key format, parent/child relationship, attempt numbering, duplicate prevention

5. Design execution seam: SideEffectRetryCoordinator vs RecoveryService delegate;
   how to invoke a node without breaking resume skip; envelope + trace continuity

6. Design idempotency policy by side-effect class: read-only, external writes, high-impact

7. Write docs/design/retry-authorized-execution.md (this document, refined)

8. Add characterization tests only:
   - retry_authorized does not execute today
   - ordinary resume does not execute retry_authorized
   - ordinary completion validation does not treat retry_authorized as completed
   - retry_authorized requires a safe_to_retry decision
   - no retry attempt lineage exists today
   - _journal_one cannot unstick a retry_authorized row by key reuse (grounding fact #3)
```

## Acceptance criteria for the design study

```text
1. The authority model for executing retry_authorized is explicit.
2. The execution seam is separate from normal resume.
3. Retry attempt identity and lineage are specified.
4. The original retry_authorized record is not overwritten.
5. Idempotency requirements are specified by side-effect class.
6. The relationship to ordinary RETRY_STEP is decided.
7. Trace/reconciler expectations are specified.
8. No automated retry execution is introduced.
9. No observed-completion validator relaxation is proposed.
10. No implementation starts until the design answers Q1–Q5.
```

## Recommendation

Start v3.4 as a design/characterization release. The likely implementation release after the study should be narrow:

```text
v3.4.0 — Retry-Authorized Attempt Lineage
```

Do not implement full retry execution first. The safer first implementation is lineage + coordinator skeleton + characterization. Actual execution can follow once the side-effect retry attempt model is proven.

---

## v3.5.0 Implementation Status

**Status:** implemented and tested (2026-07-14).

The v3.4 design study is now fully implemented in v3.5.0 across nine tasks
(T1–T9). All 22 invariants (INV-001 through INV-022) are enforced and tested.
See `CHANGELOG.md` `[3.5.0]` for the full change list and `invariants/v3.5.md`
for the invariant definitions.

### Design questions — resolved

| Question | v3.4 recommendation | v3.5.0 implementation |
|---|---|---|
| Q1: Who triggers execution? | Operator only | `EXECUTE_RETRY_AUTHORIZED` action, RBAC `{"operator"}` |
| Q2: Re-run original node? | Specialized recovery replay path | `SideEffectRetryCoordinator` distinct from resume + RETRY_STEP |
| Q3: Duplicate side effects? | New child key, original immutable | `make_retry_side_effect_key` (deterministic UUIDv5), parent permanently immutable (INV-003) |
| Q4: Evidence/idempotency? | Capsule + decision binding | Proactive replay capsule (INV-004), decision binding validation |
| Q5: Trace/reconcile? | Existing surfaces + SE-R6 | `classify_retry_lineages()` projection, SE-R6a–SE-R6g checks |

### Tasks completed

- **T1:** Schema migrations, legacy classification, dead-transition removal.
- **T2:** Capsule system (KEK→DEK→capsule), atomic `started` + capsule persistence.
- **T3:** Adapter identity + `RecoveryDispatchGuard` at the real `search()` boundary.
- **T4:** Coordinator + envelope + deterministic lineage + fencing.
- **T5:** Parent immutability + recovery-only CAS repair + batch exclusion.
- **T6:** RecoveryService wiring + `EXECUTE_RETRY_AUTHORIZED` delegation.
- **T7:** Lineage projection + boundary-aware classifier + reconciler SE-R6.
- **T8:** CLI `execute-retry-authorized` command + three-truth rendering.
- **T9:** Metrics (15-metric vocabulary, three producers) + deletion/purge gate
  (INV-016: lineage-closure-gated, atomic purge, key tombstone, resurrection
  prevention).

