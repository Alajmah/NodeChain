# NodeChain Architecture Report — v1.3.1

> **HISTORICAL DOCUMENT** — This report covers NodeChain v0.1.0 through v1.3.1.
> The current version is v3.5.1. For the full product vision, see
> **[VISION.md](VISION.md)**. For current capabilities, see README.md,
> CHANGELOG.md, and docs/ci.md. This document is retained for historical
> reference but does not reflect the current architecture.

**Date**: 13 June 2026, 11:52 PM GMT+3
**Tag**: `v0.1.0-milestone-1` through `v1.3.1-cgroup-runtime-integration`
**Tests**: 1429/1429 Windows (11 skipped), 1427/1427 Linux (13 skipped)

---

## System Description

NodeChain is a contract-validated, crash-consistent, governed graph runtime
with allocator-backed invocation identity, canonical operation-level side-effect
journaling, durable cost accounting, complete all/any/first/quorum branch
scheduling, enforced branch cancellation/result policies, enforced loop
entry/exit/budget controls, real human-review pause/resume and interactive
review, merge semantics, ledger-backed trace reconciliation, and a script-safe
developer CLI.

---

## Source Map

```
Category              Files    Lines
─────────────────────────────────────
Runtime (15)             15    5,600
Nodes (19)               19    3,362
Core (9)                  9    2,030
Validation (4)            4    1,134
Adapters (8)              8    1,085
Memory (3)                3      505
CLI (7)                   7      650
─────────────────────────────────────
Source                  115   15,036
Tests                   45   11,200
Schemas (JSON)          20      —
Blueprints (YAML)        3      —
─────────────────────────────────────
Total                   183   26,236
```

---

## Runtime Component Map

Runtime consists of 15 modules: the orchestrator and 13 focused control-plane
components plus `__init__.py` and `loop_enforcer.py`.

```
Component               Lines  Tests  Responsibility
──────────────────────────────────────────────────────────────
Orchestrator            1,800      —  Coordination, state lifecycle, cost hierarchy
StepAllocator              93     11  Async-locked step identity
GraphScheduler            389     31  Execution order, loop routing, review transitions
BranchExecutor            850     35  Parallel branches + merge + quorum + cancel
LoopEnforcer              185     45  Declarative loop condition evaluation
NodeInvoker               127      —  Node execution boundary
PolicyGate                191     17  Authorization
PersistenceCoordinator    207     18  Transaction / recovery
ReviewManager             208     17  Human review lifecycle
TraceReconciler           321     20  Audit integrity (hard errors)
TraceEmitter              277     26  Structured trace creation
ValidationPipeline        218      —  Schema + semantic + calibration
InvariantEngine           530     56  Structural / governance legality + quorum validation
FailureManager            282     13  Failure classification
```

---

## Branch Scheduling Matrix

### wait_for Modes

```
Mode        Threshold           On Failure              Merge Scope
──────────────────────────────────────────────────────────────────────
all         All must succeed    Any fail -> block       All completed
any         >= 1 must succeed   All fail -> block       All completed
first       First success       All fail -> block       First only
quorum      count or ratio      < threshold -> block    Quorum winners only
```

### cancellation_policy (General)

```
Policy                Mechanism              After Success
──────────────────────────────────────────────────────────────────
allow_all             asyncio.gather         All branches merge
ignore_late           asyncio.gather         Late outputs excluded
cancel_on_first       task.cancel()          Pending cancelled
first_success_only    task.cancel()          Pending cancelled + merge isolation
```

### cancellation_after_quorum (Quorum-specific)

```
Policy          Mechanism                         After Quorum
──────────────────────────────────────────────────────────────────
cancel          task.cancel() on pending          Pending cancelled
ignore_late     Let finish, mark ignored          Late excluded from merge
allow_all       Let finish normally               All merge
```

### Quorum Configuration

```yaml
joins:
  - join_id: j1
    to_node: joiner
    from_branches: [bio, tech, med]
    wait_for: quorum
    quorum_count: 2                   # absolute: need 2 successes
    # OR
    quorum_ratio: 0.6                 # ratio: ceil(3 * 0.6) = 2
    cancellation_after_quorum: cancel  # cancel | ignore_late | allow_all
```

### Quorum Validation

```
Violation                Severity     Condition
─────────────────────────────────────────────────────────
quorum_config_required   warning*     wait_for=quorum without count or ratio
quorum_ratio_range       error        quorum_ratio not in (0, 1]
quorum_count_minimum     error        quorum_count < 1

* = error in strict mode (NODECHAIN_GOVERNANCE_STRICT=1)
```

### Trace Events

```
Event                 Metadata
──────────────────────────────────────────────────────────────────
quorum_reached        quorum_required, quorum_reached, winning_branches,
                      failed_branches, pending_branches, cancellation_policy

quorum_impossible     quorum_required, successes_so_far, remaining_possible,
                      failed_branches
```

---

## Loop Enforcement Matrix

```
Enforcement Point    Source                    Strict Mode
──────────────────────────────────────────────────────────────────
entry_condition      LoopEnforcer (regex)      Parseable required
exit_condition       LoopEnforcer (regex)      Parseable required
max_iterations       Blueprint field            Always enforced
max_cost_usd        invocation_ledger primary  Always enforced
                     trace_events fallback
```

### Cost Source Hierarchy

```
Priority:
  1. invocation_ledger (durable, per-invocation cost_usd)
     — used when ledger has invocation rows for loop nodes
     — even when total is 0.0 (real zero-cost runs)
  2. trace_events (fallback, audit surface)
     — used when no ledger rows exist yet

Metadata in LOOP_BLOCKED / LOOP_EXITED:
  cost_source: "invocation_ledger" | "trace_events"
```

### Condition Syntax

```
Format: variable operator value
  variable: [a-zA-Z_][a-zA-Z0-9_]*
  operator: ==, !=, <, >, <=, >=
  value:    numeric or quoted string

Examples:
  source_count >= 3
  confidence > 0.7
  quality_score >= 0.5

Prose conditions: advisory in non-strict, hard error in strict.
```

---

## Merge Strategies

```
Strategy    List Fields              Scalar Fields          Conflicts
─────────────────────────────────────────────────────────────────────
append      Concat + _provenance     Last-writer-wins       None
merge       Concat                   First-writer-wins      scalar_key_conflict
latest      Take latest branch       Same                   None
concat      Concat lists/strings     Concat strings         incompatible_types
```

---

## Review Transitions

```
Decision          Scheduler Action     Runtime Behavior
──────────────────────────────────────────────────────────
approve           REVIEW_APPROVE       Continue from next node
reject            REVIEW_REJECT        Terminal failed state
request_revision  REVIEW_REVISION      Route to revision target
timeout           REVIEW_TIMEOUT       Terminal failed state
```

### Review Modes

```
Mode            Behavior
──────────────────────────────────────────────────────────
interactive     HumanAdapter prompts via CLI stdin
auto-approve    Silently approve all reviews
auto-reject     Silently reject all reviews
auto-revision   Silently request revision
disabled        Skip review gate entirely
pause           Raise ReviewPausedException, exit code 11
```

---

## Enforcement Surface

```
Semantic                        Prevention              Detection
──────────────────────────────────────────────────────────────────
Step identity under concurrency  StepAllocator           TraceReconciler
Durable state consistency       Atomic transaction       State <-> ledger check
Durable cost accounting         invocation_ledger       cost_source metadata
Parallel branch execution       BranchExecutor           BranchExecutionReport
Quorum threshold enforcement    BranchExecutor           quorum_reached/impossible events
Branch cancellation             task.cancel()            cancel_phase events
Merge strategy execution        BranchExecutor           InvariantEngine
Join fan-in/fan-out types       PortCompatibility        Orchestrator validation
Required field coverage         PortCompatibility        Orchestrator validation
Schema ref match                PortCompatibility        Orchestrator (strict)
Port type compatibility         PortCompatibility        Orchestrator validation
Policy authorization            PolicyGate               Policy trace events
Governance coverage             InvariantEngine          Strict mode blocking
Side-effect gating              Ledger + Capabilities    Side-effect ledger
Side-effect identity            Operation-level keys     Pre/post-call closure
Confidence integrity            ConfidenceCalibrator     Calibration metadata
Source attribution              Source aliases           SourceRef validator
Human review gate               ReviewManager            Scheduler transitions
Interactive review              HumanAdapter             decision_provider
Review resume                   GraphScheduler           Trace continuity
Loop bounds                     LoopEnforcer             LoopState tracking
Loop budget                     invocation_ledger        cost_source metadata
Strict loop conditions          LoopEnforcer             ConditionEvaluationError
Trace completeness              TraceEmitter             TraceReconciler
```

---

## Persistence Surfaces

```
Table                Purpose                       Key
────────────────────────────────────────────────────────────
chain_states         Materialized state snapshot     run_id
state_events         Append-only event log           (run_id, seq)
invocation_ledger    Idempotency + cost tracking     (run_id, step_id)
                                                   + cost_usd column
side_effect_ledger   External action lifecycle        (run_id, idempotency_key)
```

---

## Blueprint Catalog

```
Blueprint                       Nodes  Branches  Joins  Loops
─────────────────────────────────────────────────────────────
research_decision_v1.yaml         12         0      0     1
quick_fact_check_v1.yaml           5         0      0     0
domain_routed_evidence_v1.yaml     9         1      1     0
```

---

## Event Taxonomy

```
30+ trace event types:
  CHAIN_STARTED / COMPLETED / FAILED
  NODE_INVOKED / SUCCEEDED / FAILED / SKIPPED
  BRANCH_STARTED / COMPLETED / FAILED / CANCELLED / IGNORED
  BRANCH_FIRST_SELECTED
  JOIN_READY / BLOCKED / PARTIAL / COMPLETED
  POLICY_EVALUATED
  CONTRACT_VALIDATED
  VALIDATION_PASSED / FAILED
  MODEL_CALLED
  SIDE_EFFECT_STARTED / COMPLETED / FAILED
  REVIEW_REQUESTED / RESOLVED
  ROUTING_DECISION
  LOOP_BLOCKED
  quorum_reached / quorum_impossible
  cancellation_policy_not_enforced
  ignore_late_enforced
  branch_cancelled
  first_success_only_enforced
```

---

## Environment Configuration

```
Variable                       Purpose
──────────────────────────────────────────────────────────────
NODECHAIN_PROVIDER             Model adapter: lim, mock, custom
NODECHAIN_MODEL                Model name passed to adapter
NODECHAIN_REVIEW_MODE          interactive, auto-approve, auto-reject, auto-revision,
                               disabled, pause
NODECHAIN_REVIEW_DECISION      Inject decision for testing/automation
NODECHAIN_REVIEW_TIMEOUT_MIN   HumanAdapter timeout (default 30)
NODECHAIN_GOVERNANCE_STRICT    1 = warnings become errors, unparseable loops fail
NODECHAIN_STRICT_SCHEMA        1 = strict schema validation
NODECHAIN_MOCK_RISK_LEVEL      Override mock risk_classifier output
CHROMA_HOST                    ChromaDB host (default localhost)
CHROMA_PORT                    ChromaDB port (default 8000)
PYTHONIOENCODING               utf-8 required on Windows for Rich CLI output
```

---

## CLI Surface

```
Command                  Description
────────────────────────────────────────────────────────────────────────
nodechain run QUERY      Execute the Research & Decision Assistant chain
  --strict                Enable strict governance (warnings -> errors)
  --review-mode MODE      Set review gate: interactive|auto-approve|...
  --provider PROVIDER     Model provider: lim|mock|custom
  -b, --blueprint PATH    Path to chain blueprint YAML
  -m, --model MODEL       Model name for LLM calls
  --json                  Output results as JSON

nodechain inspect RUN_ID Show detailed state for a saved run
  --db PATH               Path to chain state database

nodechain reconcile RUN_ID
                        Cross-check trace against persistent state
  --db PATH               Path to chain state database
  -t, --trace-dir DIR     Directory for trace files

nodechain resume RUN_ID  Resume a paused or failed chain run
  --db PATH               Path to chain state database
  -b, --blueprint PATH    Blueprint for orchestrator reconstruction
  -t, --trace-dir DIR     Directory for trace output
  --review-mode MODE      Override review mode for resumed run

nodechain report RUN_ID  Generate comprehensive run report
  --db PATH               Path to chain state database
  -t, --trace-dir DIR     Directory for trace files
  -o, --output FILE       Save report as JSON

nodechain trace FILE     View a chain trace in readable format
```

### Exit Codes

```
Code  Meaning
─────────────────────────────────────
  0   Success
  1   Reconciliation errors found
  2   Run not found
  3   Recovery required
 10   Validation error
 11   Paused (waiting for review)
 12   Chain execution failed
 13   Run not resumable
 14   Resume failed
```

---

## Trust Model

### Enforcement Layers

```text
Python-level (all platforms):
  Layer 1: Package Policy        (load boundary)
  Layer 2: Import Enforcement     (import hooks + preloaded denylist)
  Layer 3: Filesystem Policy      (open, pathlib, os.open/stat/listdir/mutation)
  Layer 4: Subprocess Policy      (Popen, run, call, async, os.system/popen)
  Layer 5: Network Policy         (socket, DNS, SSL, urllib, http.client)

OS-level (Linux):
  Layer 6: Seccomp Syscall Filter (20 dangerous syscalls denied in child)
          Applied BEFORE untrusted module import.

Isolation:
  Layer 7: Process Isolation      (subprocess execution for untrusted)

Governance:
  Layer 8: Trust Invariants       (7 structured compliance codes, INV-001..007)
  Layer 9: CI Gates               (--trust-check, exit code 15)
```

### Enforcement Bootstrap Order (Child Subprocess)

```text
Phase 1:  Import trusted SDK + create event loop
Phase 1b: Apply seccomp filter (Linux only, if available)
Phase 1c: Activate ALL Python enforcement (import + fs + subprocess + network)
Phase 2:  Import untrusted node module (UNDER seccomp + Python enforcement)
Phase 3:  Execute node
Phase 4:  Report + deactivate enforcement
```

The untrusted node module is NOT imported until ALL enforcement layers
are active. Import enforcement uses `allow_preloaded=True` so trusted
framework dependencies (pydantic, yaml) already in `sys.modules` are
allowed, but sensitive modules (ctypes, runpy, multiprocessing) are
always blocked by the preloaded denylist.

### Trust Invariant Codes

```text
INV-001  untrusted        → requires isolation_mode=subprocess
INV-002  untrusted        → requires child_policy_enforced=true
INV-003  subprocess       → requires env_filtered=true
INV-004  subprocess       → requires temp_dir_isolated=true
INV-005  locked mode      → requires lockfile_verified=true
INV-006  required profile → must be used (no downgrade)
INV-007  os_profile+Linux → requires syscall_filtering_enforced=true
INV-008  os_profile       → requires at least one OS enforcement capability
```

See [docs/frozen-surfaces.md](docs/frozen-surfaces.md) for the complete table.

### Sandbox Capability Layers (Distinguished)

```text
Resource limits (RLIMIT):
  Linux:   enforced — CPU, memory, file size, processes
  Windows: Job Objects — CPU, memory
  macOS:   detection only

Seccomp syscall filtering:
  Linux:   enforced when os_profile + seccomp available
           20 dangerous syscalls denied (fork, clone, ptrace, mount, etc.)
  Windows: not available
  macOS:   not available

Cgroups v2 (validated v1.3.1):
  Linux:   per-invocation child cgroup with accounting
           memory.peak, cpu.stat, pids.peak read after execution
           optional limits: memory.max, pids.max, cpu.max
  Windows: not available
  macOS:   not available

Namespaces (planned):
  Linux:   not yet implemented

AppArmor (planned):
  Linux:   not yet implemented
```

### Honest Boundaries

NodeChain operates at multiple enforcement levels:

**What NodeChain provides:**
- seccomp-based syscall filtering on Linux (proven by blocked-syscall tests)
- RLIMIT resource limits on Linux
- cgroup v2 per-invocation resource accounting on Linux (v1.3.1)
- Job Objects resource limits on Windows
- Python API interception on all platforms
- Process isolation for untrusted nodes

**What NodeChain does NOT provide:**
- Namespace-based filesystem isolation (planned)
- AppArmor security profiles (planned)
- Native extension / ctypes isolation (ctypes is in preloaded denylist)
- Protection against threads that bypass contextvars
- Protection against already-captured module references

For adversarial or completely untrusted code, use OS-level isolation
(containers, VMs) in addition to NodeChain's trust runtime.

---

*Updated for v1.2.5 — 13 June 2026*

```
File                                          Tests
──────────────────────────────────────────────────────
test_runtime.py                                 44
test_branch_executor.py                         22
test_branch_join.py                             33
test_invariant_engine.py                        56
test_scheduler.py                               31
test_durable_state.py                           45
test_durable_cost.py                            11
test_persistence.py                             18
test_step_allocator.py                          11
test_branch_step_race.py                        11
test_merge_strategy.py                          13
test_trace_reconciler.py                        15
test_trace_emitter.py                           26
test_review_resume.py                            9
test_interactive_review.py                      10
test_wait_for_first.py                          17
test_ignore_late.py                             17
test_cancel_on_first.py                         17
test_first_success_only.py                      17
test_quorum.py                                  19
test_loop_enforcement.py                        34
test_loop_consolidation.py                      11
test_strict_loop_conditions.py                  19
test_port_compatibility.py                      18
test_human_review.py                             6
test_review_manager.py                          17
test_policy_gate.py                             17
test_side_effect_journal.py                      7
test_side_effect_lifecycle.py                   10
test_composability.py                            6
test_contracts.py                                9
test_loop_trigger.py                             5
test_nodes/test_nodes.py                        17
test_adapters/*                                 15
test_infra/*                                    14
──────────────────────────────────────────────────────
TOTAL                                          674
```

---

*Updated for v1.0.0 — 13 June 2026*
