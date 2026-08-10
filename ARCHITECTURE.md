# NodeChain Current Architecture

**Document class:** Descriptive architecture  
**Baseline date:** 2026-08-10  
**Baseline SHA:** `af1943c24a58d80ae048b9b9d50842cf0e0b27d1`  
**Released version at baseline:** `v3.6.0`  
**Current-state summary:** [BASELINE.md](BASELINE.md)

This document describes the architecture that actually exists in the development baseline, including important alternate paths and known authority seams. It is not the normative System Specification and it does not hide compatibility or direct-execution paths that are narrower than the primary governed runtime.

The previous root architecture report described v0.1.0–v1.3.1 and was explicitly historical. That report remains available in git/release history; this root document now describes the current implementation.

---

## 1. Architectural thesis

NodeChain is built around one central idea:

> Autonomous work should execute through reusable capability units whose contracts, permissions, external effects, evidence, recovery, and quality are part of the execution model.

The primary architecture is therefore not simply a graph scheduler. It is a layered governed runtime:

```text
User / Operator / Product Surface
                ↓
CLI · Local API · Workspace · SDK
                ↓
Composition and Admission
blueprints · manifests · contracts · typed ports · trust/package identity
                ↓
Governed Runtime
Orchestrator · scheduler · policy · validation · state · trace · side effects · recovery
                ↓
Invocation / Execution Boundaries
NodeInvoker · model/search/human/memory adapters · subprocess/sandbox/supervised execution
                ↓
Durable Evidence
state events · invocation ledger · side-effect ledger · decisions · trace · bundles · eval reports
```

---

## 2. Core composition primitives

### InvocationEnvelope / EnvelopeResponse

The universal node-call boundary. Runtime context, capability grants, run/chain/node/step identity, and payload travel through the envelope rather than through arbitrary shared state.

### NodeManifest and NodeContract

Describe node identity, version, type, entry/exit requirements, typed ports, side effects, and capability requirements. Contract preflight occurs before normal chain execution.

### Typed ports

Connections are semantic, not merely positional. Port/schema compatibility is validated so a graph cannot be treated as valid solely because two functions happen to accept dictionaries.

### ChainBlueprint

Declarative graph definition including ordered nodes, connections, branches, joins, loops, gates, invariants, and configuration.

### Harness Node

The reusable capability unit. A node may be built-in or packaged; trust and packaging affect admission/execution policy but do not replace the node's contract.

---

## 3. Primary governed runtime

The canonical runtime composition root is `src/nodechain/runtime/orchestrator.py`.

A simplified normal-run flow is:

```text
run(query)
  ↓
mark running / emit chain start
  ↓
contract preflight
  ↓
blueprint + governance invariant checks
  ↓
scheduler determines next node
  ↓
allocate invocation identity / step
  ↓
policy gate
  ↓
compile InvocationEnvelope
  ↓
pre-call side-effect journaling
  ↓
invoke node
  ↓
classify failure / recover if needed
  ↓
validate output
  ↓
persist invocation/state evidence
  ↓
emit node/detail events
  ↓
complete observed side effects
  ↓
branch / loop / review routing
  ↓
next node or terminalize
```

The resume path reconstructs durable state and continues through corresponding scheduling, policy, invocation, validation, side-effect, review, and persistence behavior.

### Extracted runtime controllers

The orchestrator remains large but important responsibilities already have named boundaries, including:

- contract preflight controller;
- node output validation controller;
- policy gate controller;
- side-effect journal controller;
- scheduler / branch executor / loop enforcer;
- failure manager;
- review manager;
- trace emitter and reconciler;
- persistence coordinator / StateManager stores;
- step allocator.

The architectural goal is not decomposition for its own sake. Extraction is valuable when it creates one explicit authority or a testable behavioral seam.

---

## 4. Scheduling, branches, loops, and review

The runtime supports ordered node execution plus non-linear control flow.

### Branch/join behavior

Supported wait conditions include:

- `all`
- `any`
- `first`
- `quorum`

Result/cancellation policies include allow-all, ignore-late, cancel-on-first, first-success-only, and quorum-specific post-threshold behavior.

### Loops

Loops are bounded by declared iteration limits and may include cost limits and declarative entry/exit conditions. The runtime must never rely on an unbounded natural-language loop instruction as its only safety bound.

### Human review

Risk/review routing can pause a run and later resume it from durable state. Review decisions and recovery actions are expected to be durable evidence, not ephemeral UI clicks.

---

## 5. Policy and capability governance

Policy is evaluated as part of execution, not as a post-run report.

Important policy surfaces include:

- input/output validation;
- tool access;
- adapter access;
- model access;
- memory read/write;
- side effects;
- cost/rate/timeout;
- retry/fallback;
- trust level;
- sensitivity/retention/audit.

A node's manifest/contract describes requirements; the policy engine and runtime decide whether those requirements are admissible in the current execution context.

Package trust, signature validity, registry status, and certification are inputs to governance. None of them independently imply execution permission.

---

## 6. State and persistence

NodeChain uses SQLite-backed durable state and multiple append-only or lifecycle ledgers/stores.

Important persistent concepts include:

- chain state snapshots/materialized state;
- state event log;
- invocation ledger;
- decision/action records;
- side-effect ledger;
- recovery records;
- replay capsules and retry lineage;
- trace persistence/evidence;
- product-specific workspace records and bundles.

### Current authority seam

The primary runtime still directly mutates some `ChainState` fields before or around persistence calls. This is not automatically incorrect—transactions need in-memory preparation—but it means the codebase does not yet have one explicit state-transition coordinator through which every authoritative transition passes.

The desired invariant is:

> An in-memory calculation may be provisional; a transition is authoritative only after the declared durable boundary accepts it.

This is tracked in `ROADMAP.md` Horizon 0 rather than hidden behind a claim that in-memory and durable state are literally identical at every instant.

---

## 7. Trace architecture

Trace events encode runtime execution, decisions, failures, policy, side effects, review, branches/loops, recovery, and terminal status.

The trace truth rule is:

> No event may claim execution or recovery that did not actually occur.

Runtime facts must come from runtime boundaries. Fixture configuration, intended behavior, or later inspection cannot be used to fabricate an execution event after the fact.

### TraceEmitter and reconciliation

The primary architecture uses a trace emitter plus reconciliation/inspection surfaces. Durable evidence should bind to stable event identities so state/ledger/evidence projections can point back to proving events.

### Current authority seam

At the baseline SHA, at least one resume validation branch still calls `self.trace.add_event(...)` directly for a validation-failure event. Therefore the repository is not yet at the literal end state of “every authoritative event enters through one durability-aware emission API.”

That remaining seam is tracked explicitly in Horizon 0.

---

## 8. Side-effect lifecycle and recovery

External action truth is tracked independently from whether a node invocation as a whole succeeded.

The core lifecycle is:

```text
planned
  ↓
started
  ↓
completed | failed | unknown
```

`unknown` represents the crash/uncertainty window where NodeChain cannot safely infer whether an external effect happened.

Recovery evolved to preserve that uncertainty rather than erase it:

```text
unknown original attempt
  ↓
operator recovery decision
  ↓
safe_to_retry / retry_authorized
  ↓
governed child retry attempt
  ↓
normal planned → started → terminal lifecycle
```

The original unknown/retry-authorized history remains immutable. Recovery creates lineage rather than rewriting the past.

Replay capsules, adapter attestation, fencing/claims, dispatch-attempt boundaries, and recovery execution actions support this governed retry model.

---

## 9. Node invocation and execution isolation

`runtime/node_invoker.py` is the normal node-call boundary used by the orchestrator.

For in-process paths it executes nodes with the applicable Python-level enforcement contexts. For isolated non-built-in nodes it delegates to `SubprocessRunner`.

### Trust levels

The codebase distinguishes at least:

- `built_in`
- `local_trusted`
- `local_untrusted`
- `remote_untrusted`

Trust level affects execution/isolation requirements but does not supersede policy.

### Python-level enforcement

The trust runtime includes import, filesystem, subprocess, and network enforcement hooks for applicable non-built-in execution.

### Windows isolation path

Windows uses process/subprocess containment mechanisms appropriate to that platform, including bounded process execution and Job Object support in relevant paths. Windows is not claimed to provide Linux namespace/seccomp/cgroup equivalence.

---

## 10. Supervised Linux execution and the T3 boundary

NodeChain contains a hardened supervised Linux execution substrate developed through v3.5.1.

Relevant modules include:

- `runtime/supervised_argv.py`
- `runtime/supervised_exec_session.py`
- `runtime/exec_supervisor.py`
- `runtime/exec_protocol.py`
- `runtime/async_fd_transport.py`
- `runtime/pid_namespace_topology.py`
- supporting streaming/containment helpers.

Important design properties include:

- external launcher / namespace-init / bootstrap topology;
- PID namespace identity proof;
- exact `PTRACE_EVENT_EXEC` as workload-start authority;
- event-loop-owned protocol transport;
- bounded stdout/stderr/config/payload ownership;
- deterministic terminal cleanup;
- namespace-init reaping;
- independent host process-group containment.

### The current integration boundary

The generic path is:

```text
Orchestrator
  ↓
NodeInvoker
  ↓
SubprocessRunner.run_isolated()
```

On POSIX, `SubprocessRunner.run_isolated()` currently contains an explicit T3.0 fence for `local_untrusted` / `remote_untrusted` and returns `supervised_backend_required` before workload spawn.

Therefore:

```text
supervised Linux substrate: implemented
ordinary POSIX untrusted-node routing into it: not yet integrated
legacy weaker POSIX fallback: deliberately disabled
```

Documentation and deployment profiles must preserve this distinction.

---

## 11. Registry, package, and trust architecture

NodeChain includes a broad reusable-node supply-chain layer:

```text
node/package source
  ↓
manifest + contract + capabilities
  ↓
content digest / signature / publisher identity
  ↓
registry admission
  ↓
lock / dependency / compatibility resolution
  ↓
certification / evaluation metadata
  ↓
install / consumption policy
  ↓
runtime trust + capability admission
```

Remote-registry rules deliberately separate concepts that are often conflated:

- remote install does not imply execution permission;
- publisher signature does not imply safety;
- registry signature does not imply publisher trust;
- digest match does not imply certification;
- certification does not bypass sandboxing;
- `remote_untrusted` does not self-upgrade to `local_trusted`.

This is a substantial platform capability, but the current implementation is still primarily a developer/operator substrate rather than a polished enterprise registry service.

---

## 12. Research architecture

### 12.1 General Research & Decision Assistant

The main blueprint contains twelve nodes:

```text
goal_interpreter
→ task_planner
→ context_selector
→ search_tool
→ source_ingestion
→ source_quality_evaluator
→ evidence_synthesizer
→ claim_validator
→ risk_classifier
→ response_generator
→ memory_write_decision
→ trace_collector
```

It is designed around live/general research adapters and normal runtime memory/trace semantics.

### 12.2 Governed Research Workspace

The post-v3.6 Workspace runner constructs a separate linear product-proof blueprint:

```text
goal_interpreter
→ task_planner
→ context_selector
→ fixture search_tool
→ source_ingestion
→ source_quality_evaluator
→ qualified_source_linker
→ evidence_synthesizer
→ claim_validator
→ risk_classifier
→ response_generator
```

The sealed corpus is loaded and canonically digested. The fixture adapter is wrapped by the ordinary dispatch guard. Fault injection is divided between lane admission (pre-dispatch) and adapter behavior (post-dispatch), allowing runtime evidence to distinguish:

- `LANE_ADMISSION_REJECTED`
- `SEARCH_TIMEOUT_AFTER_DISPATCH`
- `SEARCH_PROVENANCE_MALFORMED`
- `SEARCH_PARTIAL_RESULT_SET`

Fault records are projected from recognized trace events rather than from fixture declarations.

`QualifiedSourceLinker` binds qualified source decisions to actual ingested source identity/hash evidence before synthesis consumes them.

Terminal output is finalized into `ResearchWorkspaceBundleV1`, whose member documents and manifest are integrity checked by the corresponding bundle reader.

### Current CLI seam

The library provides `WorkspaceRunner.from_descriptor()` for fresh reconstruction and restores the descriptor used by terminal finalization. The current `nodechain research review` CLI manually constructs a runner rather than using that classmethod, so the descriptor-dependent terminal finalization branch is not guaranteed on that specific CLI reconstruction path. This is a bounded Horizon 0 integration correction.

---

## 13. Evaluation architecture

NodeChain evaluation has multiple evidence classes.

### Structural/generic evaluation

The generic evaluation system can validate suite/case structure, expected properties, thresholds, signatures, certification lifecycle, and custom runner results.

The default runner is structural; default metric values are not evidence that the full governed runtime executed.

### Research quality evaluation

`runtime/research_eval_runner.py` directly executes the synthesis → claim validation → risk → response segment under `MockModelAdapter` for deterministic quality measurement.

It explicitly does not execute the complete orchestrator.

### Desired consolidation

When an evaluation claim depends on policy, trace, side effects, review, recovery, persistence, or containment, the evaluator should consume evidence from the complete governed runtime. Direct-node evaluation remains useful for local node quality and deterministic regression.

---

## 14. Operator surfaces

The repository exposes several operator/developer interfaces:

- Click-based CLI and command groups;
- run/inspect/reconcile/resume/report/trace flows;
- recovery console/actions;
- trust, registry, evaluation, evidence, release/deployment operations;
- dashboard/health surfaces;
- governed review workbench;
- Research Workspace commands;
- FastAPI local read-only operator API with bearer-token protection.

The CLI `--help` output is the authoritative current command inventory. Documentation should avoid volatile command-count claims unless generated from the executable surface.

---

## 15. Known alternate or narrower execution paths

The repository contains utilities that must not be confused with the primary governed runtime.

### `runtime/chain_orchestrator.py`

A multi-chain composition utility includes `execute_sub_chain()`, which builds an envelope and directly calls `node.execute()` with a comment that full chain execution should use the Orchestrator.

This is a real parallel execution seam. It should either delegate governed execution or remain explicitly classified as a narrow/non-production utility.

### `runtime/research_eval_runner.py`

Directly invokes selected research nodes for deterministic evaluation. Useful, but not full runtime execution.

### Sandbox/native command runners

Some sandbox/native command-runner paths have their own qualification evidence. A green result for one runner/profile is not automatically evidence for the generic Harness Node invocation path.

---

## 16. Deployment profiles

Architecture claims must name the execution profile.

| Profile | Intended role | Baseline claim |
|---|---|---|
| Local trusted development | SDK/CLI/runtime development and trusted-node execution | Supported |
| GitHub-hosted CI | Cross-platform regression, packaging, publication-tree, non-privileged behavior | Supported; not privileged Linux containment proof |
| Privileged Linux verification | Native/supervised containment qualification on a capability-qualified host | Supported as a qualification profile |
| Generic POSIX untrusted Harness Node execution | Ordinary `NodeInvoker` untrusted path | Fail-closed pending T3 routing |
| Windows control-plane/development | CLI/SDK/general runtime behavior without Linux-equivalent containment claims | Supported within platform-specific limits |
| Managed multi-tenant service | Enterprise hosted execution | Not implemented |

See `docs/linux-deployment.md` for operational details.

---

## 17. Architectural debt that matters

The important remaining architecture work is authority-related, not aesthetic:

1. join generic POSIX untrusted node invocation to the supervised backend;
2. remove/classify direct node execution outside the primary orchestrator;
3. route all authoritative trace events through one durable emission boundary;
4. make the state-transition durability boundary explicit and singular;
5. connect runtime-level evaluation claims to complete governed execution;
6. preserve one source of truth while productizing Workspace/enterprise surfaces.

Large files may be refactored when that work creates a stable authority or testability boundary. File size alone is not an architectural invariant.

---

## 18. Historical architecture

Older architecture reports remain valuable historical evidence for the system's evolution. They should be read against their release/tag, not used to infer current implementation status.

For current truth use this document plus `BASELINE.md`. For intended platform semantics use the NodeChain System Specification.
