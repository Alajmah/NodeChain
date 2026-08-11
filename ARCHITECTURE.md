# NodeChain Current Architecture

**Document class:** Descriptive architecture  
**Baseline date:** 2026-08-11  
**Implementation code baseline:** `989b21fe1d61332f3848474fdfd3e0d9ca1aaf5c`  
**Released version at baseline:** `v3.6.0`  
**Current-state summary:** [BASELINE.md](BASELINE.md)  
**Strategic source:** [VISION.md](VISION.md)

The current version is v3.6.0. The pinned implementation baseline also contains post-release development work, which is described separately in `BASELINE.md` rather than back-projected into the v3.6.0 release record.

This document describes the architecture that actually exists in the pinned implementation baseline, including important alternate paths and known authority seams. Documentation-only commits may follow the implementation SHA without changing these code facts.

The previous root architecture report described v0.1.0–v1.3.1 and was explicitly historical. That report remains available through git/release history. The root architecture document now describes the current code. For product thesis and long-term direction, use `VISION.md`.

---

## 1. Architectural thesis

NodeChain is built around one central idea:

> Autonomous work should execute through reusable capability units whose contracts, permissions, external effects, evidence, recovery, and quality are part of the execution model.

The primary architecture is a layered governed runtime:

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

The universal node-call boundary. Runtime context, capability grants, run/chain/node/step identity, and payload travel through the envelope instead of relying on arbitrary shared process state.

### NodeManifest and NodeContract

Describe node identity, version, type, entry/exit requirements, typed ports, side effects, and capability requirements. Contract preflight occurs before normal governed execution.

### Typed ports

Connections are semantic, not merely positional. Port/schema compatibility is validated so a graph cannot be considered safe just because adjacent Python functions both accept dictionaries.

### ChainBlueprint

Declarative graph definition including nodes, connections, branches, joins, loops, gates, invariants, and configuration.

### Harness Node

The reusable capability unit. A node may be built-in or packaged; trust and packaging affect admission/execution requirements but do not replace the node's contract.

---

## 3. Primary governed runtime

The canonical execution composition root is `src/nodechain/runtime/orchestrator.py`.

A simplified normal-run flow is:

```text
run(query)
  ↓
chain start
  ↓
contract preflight
  ↓
blueprint + governance invariant checks
  ↓
scheduler selects next node
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

The resume path reconstructs durable state and continues through corresponding scheduling, policy, invocation, validation, side-effect, review, recovery, and persistence behavior.

Important runtime responsibilities already have named boundaries/controllers, including:

- contract preflight;
- node-output validation;
- policy gating;
- side-effect journaling;
- scheduler / branch executor / loop enforcer;
- failure manager;
- review manager;
- trace emitter and reconciler;
- persistence coordinator / StateManager stores;
- step allocator.

The architectural goal is not decomposition for its own sake. Extraction is useful when it produces one explicit authority or a testable behavioral seam.

---

## 4. Scheduling, branches, loops, and review

The runtime supports ordered execution plus non-linear control flow.

### Branch/join behavior

Supported wait conditions include `all`, `any`, `first`, and `quorum`. Result/cancellation behavior includes allow-all, ignore-late, cancel-on-first, first-success-only, and quorum-specific post-threshold policies.

### Loops

Loops are bounded by declared iteration limits and may include cost limits and declarative entry/exit conditions. Natural-language intent is not accepted as the only execution bound.

### Human review

Risk/review routing can pause a run and later resume it from durable state. Review decisions and recovery actions are durable evidence, not merely UI state.

---

## 5. Policy and capability governance

Policy is evaluated as part of execution rather than added only as a post-run report.

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

A manifest/contract declares requirements. Policy and runtime context decide whether those requirements are admissible for a particular invocation.

Package trust, signature validity, registry status, and certification are governance inputs. None independently grants execution permission.

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

### Current state-authority seam

The primary runtime still directly mutates some `ChainState` fields before or around persistence calls. That is not automatically incorrect—transactions require provisional in-memory preparation—but the codebase does not yet express every authoritative transition through one named transition coordinator.

The intended invariant is:

> An in-memory calculation may be provisional; a transition becomes authoritative only when its declared durable boundary accepts it.

This is tracked in `ROADMAP.md` Horizon 0.

---

## 7. Trace architecture

Trace events encode runtime execution, decisions, failures, policy, side effects, review, branches/loops, recovery, and terminal status.

The trace truth rule is:

> No event may claim execution or recovery that did not actually occur.

Runtime facts must come from runtime boundaries. Fixture configuration, expected behavior, or later inference cannot be used to fabricate a proving event.

### Current trace-authority seam

The primary architecture uses a trace emitter plus reconciliation/inspection surfaces, but at the pinned implementation baseline at least one resume validation branch still calls `self.trace.add_event(...)` directly for a validation-failure event. The repository is therefore not yet at the literal end state where every authoritative event passes through one durability-aware emission API.

That remaining seam is tracked in Horizon 0.

---

## 8. Side-effect lifecycle and recovery

External action truth is tracked separately from node success.

```text
planned
  ↓
started
  ↓
completed | failed | unknown
```

`unknown` represents the crash/uncertainty window where NodeChain cannot safely infer whether an external action occurred.

Recovery preserves that uncertainty:

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

The original history remains immutable. Replay capsules, adapter attestation, fencing/claims, dispatch-attempt boundaries, and recovery execution actions create explicit retry lineage rather than rewriting the past.

---

## 9. Trust Model and node invocation

`runtime/node_invoker.py` is the normal node-call boundary used by the orchestrator.

For in-process paths it executes nodes with applicable Python-level enforcement contexts. For isolated non-built-in nodes it delegates to `SubprocessRunner`.

Trust levels include:

- `built_in`
- `local_trusted`
- `local_untrusted`
- `remote_untrusted`

Trust identity affects required execution controls but does not supersede policy.

The Python-level trust runtime includes import, filesystem, subprocess, and network enforcement hooks for applicable paths.

Windows uses platform-appropriate process controls, including bounded subprocess handling and Job Objects in relevant execution paths. Windows is not claimed to provide Linux namespace/seccomp/cgroup equivalence.

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

Important properties include:

- external launcher / namespace-init / bootstrap topology;
- PID namespace identity proof;
- exact `PTRACE_EVENT_EXEC` as workload-start authority;
- event-loop-owned protocol transport;
- bounded config/stdout/stderr/payload ownership;
- deterministic terminal cleanup;
- namespace-init reaping;
- independent host process-group containment.

### Current generic integration boundary

The ordinary isolated-node route is:

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

NodeChain includes a reusable-node supply-chain layer:

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

Remote-registry rules intentionally separate concepts that are often conflated:

- remote install does not imply execution permission;
- publisher signature does not imply safety;
- registry signature does not imply publisher trust;
- digest match does not imply certification;
- certification does not bypass sandboxing;
- `remote_untrusted` does not self-upgrade to `local_trusted`.

The substrate is substantial, but the current product is still primarily developer/operator oriented rather than a managed enterprise registry service.

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

It is designed around the normal runtime and general/live academic search adapters.

### 12.2 Governed Research Workspace

The post-v3.6 product-proof runner constructs a separate linear path:

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

The sealed corpus is canonically digested. The fixture adapter is wrapped by the ordinary dispatch guard. Runtime evidence distinguishes the accepted stable fault codes:

- `LANE_ADMISSION_REJECTED`
- `SEARCH_TIMEOUT_AFTER_DISPATCH`
- `SEARCH_PROVENANCE_MALFORMED`
- `SEARCH_PARTIAL_RESULT_SET`

Fault records are projections of recognized trace evidence rather than fixture declarations.

`QualifiedSourceLinker` binds qualification decisions to actual ingested source identity/hash evidence before synthesis consumes the set.

Terminal output is finalized into `ResearchWorkspaceBundleV1`, whose members and manifest are integrity-checked by the bundle reader.

The `nodechain research review` command reconstructs the runner through `WorkspaceRunner.from_descriptor(desc)`, which restores `_run_descriptor`, so terminal `resume()` executes C5 bundle finalization on the fresh-process CLI review path.

---

## 13. Evaluation architecture

NodeChain evaluation has multiple evidence classes.

### Structural/generic evaluation

The generic evaluation system supports suite/case structure, expected properties, thresholds, signatures, certification lifecycle, and custom runners. Its default runner is structural; default metric values are not proof that the full governed runtime executed.

### Research quality evaluation

`runtime/research_eval_runner.py` directly executes the synthesis → claim validation → risk → response segment under `MockModelAdapter` for deterministic quality measurement. It explicitly does not execute the complete orchestrator.

### Desired consolidation

When an evaluation claim depends on policy, trace, side effects, review, recovery, persistence, or containment, the evaluator should consume evidence from complete governed execution. Direct-node evaluation remains useful for node-quality regression.

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

The executable CLI `--help` tree is the authoritative current command inventory. Hand-maintained global command counts are intentionally avoided.

---

## 15. Known alternate or narrower execution paths

### `runtime/chain_orchestrator.py`

H0.3 retired the legacy composition executor. The module previously hosted `execute_sub_chain()`, which constructed an envelope and directly called `node.execute()` outside the canonical `Orchestrator`. All execution surfaces now fail closed with `governed_composition_backend_required` and no `BaseNode.execute()` call expression remains in the module (AST-guarded by `tests/research/test_compose_execution_fails_closed.py`). Pure composition-plan data utilities (`SubChainSpec`, `CompositionPlan`, `SubChainResult`, topological ordering, digest, aggregation) are retained for plan validation. `nodechain compose validate` remains a supported read-only surface; `nodechain compose --plan` exits before any registry/package loading.

Governed multi-chain composition — when it becomes a real product requirement — must be designed around a canonical child `Orchestrator` rather than retrofitting this legacy module.

### `runtime/research_eval_runner.py`

Directly invokes selected research nodes for deterministic evaluation. Useful, but not full-runtime execution.

### Sandbox/native command runners

Some native/sandbox command-runner paths have their own qualification evidence. A green result for one runner/profile is not automatically evidence for the generic Harness Node invocation path.

---

## 16. Deployment profiles

| Profile | Intended role | Baseline claim |
|---|---|---|
| Local trusted development | SDK/CLI/runtime development and trusted-node execution | Supported |
| GitHub-hosted CI | Cross-platform regression, packaging, Publication Tree, non-privileged behavior | Supported; not privileged Linux containment proof |
| Privileged Linux verification | Native/supervised containment qualification on a capability-qualified host | Supported as a qualification profile |
| Generic POSIX untrusted Harness Node execution | Ordinary `NodeInvoker` untrusted path | Fail-closed pending T3 routing |
| Windows control-plane/development | CLI/SDK/general runtime behavior without Linux-equivalent containment claims | Supported within platform limits |
| Managed multi-tenant service | Enterprise hosted execution | Not implemented |

See `docs/linux-deployment.md` for operational detail.

---

## 17. Historical trust/sandbox compatibility lineage

The current architecture supersedes the historical root report as a current-state document, but some historical security terms remain compatibility/test anchors. They are recorded here explicitly without turning them into claims about every current execution path.

### Historical enforcement ordering

The v1 sandbox lineage documented child bootstrap ordering approximately as:

```text
Phase 1:  import trusted SDK/bootstrap dependencies
Phase 1b: Apply seccomp filter where the historical profile required it
Phase 1c: activate Python-level import/filesystem/subprocess/network enforcement
Phase 2:  import the untrusted node implementation under enforcement
Phase 3:  execute the node
Phase 4:  report/deactivate
```

Later native/supervised designs changed important process and containment boundaries; the current T3 status is documented above.

### Historical layer labels

Compatibility documentation used the following layer labels:

- **Layer 6 — Seccomp syscall filtering** on qualified Linux paths;
- **Layer 7 — Process isolation**;
- **Layer 8 — Trust invariants**;
- **Layer 9 — CI/trust gates**.

The broader sandbox lineage also includes **Resource limits**, **Namespaces**, **Cgroups**, Python-level API enforcement, and historical discussion of **AppArmor** as an unimplemented/planned outer control. These terms describe the evolution of the sandbox architecture; present-tense support claims must still name the actual execution path/profile.

### Historical invariant identifiers

The v1 trust-surface contract includes at least:

```text
INV-001
INV-002
INV-003
INV-004
INV-005
INV-006
INV-007
```

Later releases added more invariant identifiers. Exact current meanings live in the corresponding invariant/trust implementation and compatibility documents.

---

## 18. Honest Boundaries

NodeChain **does NOT** claim that every execution helper is equivalent to the primary governed Orchestrator, that every evaluation runs through the full runtime, or that a green hosted CI run proves privileged Linux containment.

It also does NOT claim universal hostile-code security, Windows equivalence to Linux namespace/seccomp/cgroup semantics, generic POSIX untrusted Harness Node execution before T3 routing closes, managed multi-tenant service operation, or visual-builder productization.

These boundaries are deliberate current-state claims, not permanent architectural limits.

---

## 19. Architectural debt that matters

The important remaining architecture work is authority-related rather than aesthetic:

1. join generic POSIX untrusted-node invocation to the supervised backend;
2. remove/classify direct node execution outside the primary orchestrator;
3. route all authoritative trace events through one durable emission boundary;
4. make the state-transition durability boundary explicit and singular;
5. connect runtime-level evaluation claims to complete governed execution;
6. preserve one source of truth while productizing Workspace/enterprise surfaces.

Large files may be refactored when that work creates a stable authority or testability boundary. File size alone is not an architectural invariant.

---

## 20. Historical architecture

Older architecture reports remain valuable historical evidence for the system's evolution. They should be read against their release/tag, not used to infer current implementation status.

For current truth use this document plus `BASELINE.md`. For strategic direction use `VISION.md`. For intended platform semantics use the NodeChain System Specification.
