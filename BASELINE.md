# NodeChain Current Baseline

**Document class:** Descriptive baseline  
**Status:** Active development truth  
**Baseline date:** 2026-08-14  
**Released version:** `v3.6.0`  
**Implementation code baseline:** `70c8921da34ed1db86233942b70fe597318b3f5b` (the `master` code state at the H0.5 authoritative state-transition boundary)  
**Supersedes for current-state claims:** implementation/status sections in older README, VISION, ROADMAP, and architecture snapshots

This document answers one question: **what does the NodeChain codebase actually contain and support at the pinned implementation baseline?** Documentation-only commits may follow this SHA without changing the implementation facts recorded here.

It is descriptive, not normative. The NodeChain System Specification defines intended platform semantics; `VISION.md` defines strategic direction; `CHANGELOG.md` and `docs/releases/` record released history. When a descriptive claim conflicts with code at the pinned implementation SHA, the code is authoritative and this file must be corrected.

---

## 1. Release baseline vs implementation baseline

NodeChain has two legitimate anchors and they must not be conflated.

| Anchor | Value | Meaning |
|---|---|---|
| Released product baseline | `v3.6.0` | Latest packaged/released version represented by `pyproject.toml` and `nodechain.__version__` |
| Implementation code baseline | `70c8921da34ed1db86233942b70fe597318b3f5b` | `master` code state at the H0.5 authoritative state-transition boundary; includes post-v3.6 work merged through PR #22 |

The implementation baseline includes the `ResearchWorkspaceBundleV1` contract and the governed Research Workspace runner. Those capabilities are **post-v3.6 development state**, not retroactively part of the v3.6.0 release.

---

## 2. What NodeChain is today

NodeChain is an advanced local governed execution platform for autonomous AI systems built from reusable Harness Nodes. The implemented platform includes:

- typed invocation envelopes, contracts, ports, manifests, and declarative blueprints;
- a durable `Orchestrator` with scheduling, policy gates, validation, state persistence, trace emission, review, recovery, loop/branch control, and side-effect journaling;
- governed side-effect lifecycle and operator-authorized retry execution;
- node/package trust, registry, lockfile, signing, certification, and remote-registry mechanisms;
- model, academic-search, human-review, memory, and execution adapters;
- CLI operator surfaces, dashboards, recovery tooling, evidence tooling, and a local authenticated read-only API;
- evaluation, scorecard, evidence, trace-replay, and certification infrastructure;
- a proven Research & Decision Assistant domain and a proven Code Review domain;
- a post-v3.6 governed Research Workspace development surface that produces a terminal integrity-checked research evidence bundle.

NodeChain is **not** a hosted SaaS, distributed worker fabric, multi-tenant enterprise service, or visual builder at this baseline.

---

## 3. The two research execution surfaces

The repository now contains two materially different research paths. Documentation must distinguish them.

### 3.1 Research & Decision Assistant

The general `blueprints/research_decision_v1.yaml` chain is the original twelve-node research path:

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

It is designed for the normal runtime and the five academic search adapters: Semantic Scholar, arXiv, OpenAlex, CrossRef, and PubMed. It includes bounded source-quality looping, review routing, governed memory write behavior, and complete runtime trace/state surfaces.

### 3.2 Governed Research Workspace

The implementation-baseline Research Workspace is a separate product-proof path built around a sealed fixture corpus:

```text
goal_interpreter
→ task_planner
→ context_selector
→ fixture search
→ source_ingestion
→ source_quality_evaluator
→ qualified_source_linker
→ evidence_synthesizer
→ claim_validator
→ risk_classifier
→ response_generator
→ terminal ResearchWorkspaceBundleV1
```

Key properties implemented in PR #12 and PR #13:

- sealed deterministic corpus and zero-network fixture adapter;
- guarded search dispatch through `OrdinaryDispatchGuard`;
- runtime-derived stable search fault reason codes;
- trace-derived durable fault records;
- explicit qualified-source identity/hash linking before synthesis;
- durable pause/review/resume and fresh reconstruction support;
- atomic write-once operational evidence;
- terminal `ResearchWorkspaceBundleV1` finalization and integrity reading;
- KEK material excluded from the terminal bundle.

This workspace is currently a **governed deterministic product-proof substrate**, not a claim that the sealed fixture path is itself the live-search production product.

---

## 4. Research Workspace CLI finalization

The fresh-process review command reconstructs the runner through the descriptor-aware authority. `nodechain research review` calls `WorkspaceRunner.from_descriptor(desc)`, which restores `_run_descriptor`, so terminal `WorkspaceRunner.resume()` executes the C5 terminal bundle-finalization branch on the CLI path.

CLI-level regression proof in `tests/research/test_cli_review_finalization.py` covers approve, reject, revise, injected finalization failure, and identity stability across reconstruction (implementation pin `f197ecbe4a9ae617ac419342676fd8a89a511f01`).

This was a bounded integration defect corrected in H0.1; it is not a reason to invalidate the accepted WP 5.1/WP 5.2 substrate.

---

## 5. Runtime execution authority

### 5.1 Canonical governed path

The primary execution authority is `src/nodechain/runtime/orchestrator.py`. It coordinates contract preflight, scheduling, policy, invocation, persistence, validation, trace, side effects, failure handling, review, resume, and terminalization.

Several responsibilities have been extracted behind named controllers, including contract preflight, node-output validation, policy gating, and side-effect journaling. The orchestrator remains the composition root and lifecycle authority.

### 5.2 Remaining parallel/bypass seams

The codebase still contains execution or state/trace paths that are not yet reduced to one singular authority:

- `runtime/chain_orchestrator.py` previously contained a lightweight composition executor that directly called `node.execute()` outside the full `Orchestrator`; H0.3 retired that path — the execution surfaces (`execute_sub_chain`, `orchestrate_composition`, `SubChainStep.execute`) now fail closed with `governed_composition_backend_required`, and `nodechain compose --plan` exits before any registry/package loading. Pure composition-plan data utilities (`SubChainSpec`, `CompositionPlan`, `SubChainResult`, topological ordering, digest, aggregation) remain; `compose validate` remains a supported read-only surface;
- live `ChainTrace` appends now route through one singular authority (`_record_trace_event`); the orchestrator no longer contains direct `self.trace.add_event(...)` calls outside that boundary (AST-guarded); authoritative durable trace rows — including operator/recovery events — carry first-class `trace_event_id` and participate in one `get_trace_events()` projection;
- authoritative `ChainState` transitions now follow one accepted-state rule (H0.5): a candidate copy is constructed (`ChainState.transition_candidate()`), committed durably, and only then adopted; a failed commit leaves the accepted state untouched with no revision consumed. Invocation transitions (output, completed-step, cursor, branch state) and state-asserting lifecycle transitions (start, completion, failure, review pause/decision) commit through `PersistenceCoordinator` primitives; lifecycle state and their asserting trace events commit in one SQLite transaction. Review decisions are outcome-specific (reject/timeout commit failed directly); recovery terminal actions are candidate-safe and adopt the committed revision;
- the research evaluation runner directly executes quality-critical nodes rather than executing the complete governed runtime.

These are current architectural seams. They are not evidence that the primary runtime is absent; they are the remaining work required to make the “one execution / one trace / one authoritative state-transition path” claim literal throughout the repository.

---

## 6. Untrusted execution baseline

The repository contains a hardened supervised POSIX execution substrate and a separate ordinary node-isolation integration path. They are not yet fully joined.

### Supervised execution substrate

`runtime/supervised_argv.py`, the supervisor/session modules, PID-namespace topology logic, ptrace `PTRACE_EVENT_EXEC` authority, bounded asynchronous I/O, namespace cleanup, and host process-group containment implement the hardened Linux execution substrate developed through v3.5.1.

### Ordinary NodeInvoker path

`NodeInvoker` sends isolated non-built-in nodes through `SubprocessRunner.run_isolated()`.

At this baseline, `SubprocessRunner.run_isolated()` contains an explicit T3.0 safety fence: on POSIX, `local_untrusted` and `remote_untrusted` requests return `supervised_backend_required` before workload spawn. The legacy POSIX path is deliberately disabled until supervised routing/result mapping is integrated.

Therefore the truthful claim is:

> The supervised Linux execution substrate exists and is heavily qualified, while ordinary POSIX untrusted-node invocation is currently fail-closed pending T3 integration into the generic `SubprocessRunner` / `NodeInvoker` path.

No documentation should describe the generic POSIX untrusted-node path as silently falling back to a weaker sandbox.

---

## 7. Evaluation baseline

Evaluation infrastructure is substantial but must be described in layers.

- Evaluation suites, lifecycle, thresholds, report signing, certification, scorecards, and evidence tooling exist.
- The default evaluation case runner is structural unless a custom runtime runner is supplied.
- `runtime/research_eval_runner.py` executes four research-quality-critical nodes directly under `MockModelAdapter`; it explicitly is not the full orchestrator.

**Baseline claim:** NodeChain has mature evaluation infrastructure and deterministic quality evaluation paths, but a single end-to-end evaluation path that always evaluates the complete governed runtime is not yet the universal evaluation authority.

---

## 8. CI and release assurance baseline

Public CI is GitHub-hosted. The workflow in `.github/workflows/ci.yml` defines ten CI jobs, and `.github/workflows/publication-tree.yml` adds Ubuntu and Windows publication-tree jobs. Branch protection currently uses twelve required check contexts.

`slow-shard-2` is capability-sensitive and uses job-level `continue-on-error: true`; it is therefore not equivalent to privileged native-containment qualification.

`Makefile` is useful for local iteration but is not currently exact hosted-CI parity: for example, its `ci-lint` target still invokes Ruff with `--exit-zero`, while hosted CI makes the Ruff scan blocking, and the `ci-blocking` target does not reproduce the complete hosted required-check set.

For exact verification semantics, see `docs/ci.md`.

---

## 9. Current product/readiness matrix

| Surface | Baseline status | What can be claimed now | Boundary |
|---|---|---|---|
| Core governed runtime | Mature | Durable governed graph execution with contracts, policy, trace, state, review, recovery, loops/branches | Some parallel/bypass authority seams remain |
| Side-effect discipline | Mature | Planned/started/terminal lifecycle, unknown-state recovery, operator-authorized retry execution | Continue preserving trace/ledger truth |
| Harness Node SDK | Substantial | Package, validate, trust, lock, resolve, publish/install, compatibility and reusable-node mechanics | Ecosystem UX not complete |
| Registry/trust | Substantial | Local/certified/remote registry mechanics, signatures, trust and consumption policies | Not yet an enterprise registry service product |
| Research & Decision Assistant | Proven reference domain | General governed 12-node research chain and prior real-model/baseline evidence | Model-family breadth and live product UX remain separate questions |
| Code Review | Proven second domain | Governed read/review, patch-proposal and bounded test-execution patterns | Not a hosted developer product |
| Governed Research Workspace | Product-proof backend + CLI | Sealed deterministic governed run, fault truth, review/resume, qualified sources, terminal bundle, descriptor-aware CLI review finalization | Live-search productization not yet closed |
| Evaluation | Substantial | Suites, metrics, signing/certification, deterministic research-quality eval | Complete governed-runtime evaluation is not yet universal |
| Local API | Available | Authenticated local read-only operator API | Not a remote multi-tenant API service |
| Hosted SaaS | Not available | — | Future |
| Multi-tenant enterprise control plane | Not available | — | Future |
| Visual builder | Not available | Blueprint/YAML/CLI composition exists | Future |

---

## 10. Mapping to the normative System Specification

The System Specification remains the normative architecture target. The implementation should be mapped to it rather than rewriting the specification to match every temporary code seam.

| System Specification phase | Implementation-baseline assessment |
|---|---|
| 1. Formal Foundation | Mature / substantially implemented |
| 2. NodeChain Kernel | Mature operational core; singular-authority cleanup remains |
| 3. Harness Node SDK | Substantial / operational |
| 4. Control Plane | Substantial / operational |
| 5. Execution Fabric | Partial; strong adapters and sandbox substrate, but not the complete intended execution fabric |
| 6. Memory & Validation | Substantial |
| 7. Reference Autonomous Chains | Partial but proven across research and code-review domains |
| 8. Registry & Evaluation | Registry substantial; evaluation substantial but full governed-runtime evaluation not universal |
| 9. Builder Experience | Partial; rich CLI/dashboard/API, no cohesive Workspace/Blueprint Studio product yet |
| 10. Visual Builder & Ecosystem | Future |

The original Research & Decision Assistant Reference Implementation should be treated as a historical normative reference for that chain, not as a complete description of the current repository.

---

## 11. What NodeChain does not claim at this baseline

NodeChain does not currently claim:

- managed cloud/SaaS operation;
- distributed worker execution;
- general multi-tenant isolation and RBAC across organizations;
- generic POSIX untrusted-node execution through the ordinary `NodeInvoker` path until T3 routing is closed;
- universal Linux compatibility for privileged supervised containment;
- Windows equivalence to Linux namespace/seccomp/PID-containment primitives;
- complete hostile-code security proof;
- a universal full-orchestrator evaluation path;
- a visual drag-and-drop builder;
- that post-v3.6 Research Workspace work shipped in v3.6.0.

---

## 12. Documentation authority map

| Document | Class | Answers |
|---|---|---|
| `BASELINE.md` | Descriptive | What is true in the pinned current implementation code? |
| `VISION.md` | Strategic | Why does NodeChain exist and what is it becoming? |
| NodeChain System Specification | Normative | What must the complete platform mean? |
| Reference Implementation | Historical normative reference | What did the original Research & Decision Assistant design require? |
| `ARCHITECTURE.md` | Descriptive architecture | How is the current code arranged, including known alternate paths? |
| `ROADMAP.md` | Future work | What remains after this baseline? |
| `CHANGELOG.md` | Release history | What changed in released lines and future release-preparation records? |
| `docs/ci.md` | Operational contract | What evidence do CI and release gates provide? |
| `docs/releases/*` | Release record | What was true for a specific immutable release? |

See `docs/documentation-authority.md` for the update rules that keep these classes separate.

---

## 13. Baseline correction queue

The following are the concrete corrections discovered or reaffirmed by the rebaseline. They are inputs to `ROADMAP.md`, not hidden caveats:

1. ~~Correct `nodechain research review` to reconstruct through the descriptor-aware path so terminal C5 bundle finalization is guaranteed on the CLI path.~~ **Closed in H0.1 (implementation pin `f197ecbe4a9ae617ac419342676fd8a89a511f01`).**
2. Complete T3 routing/result mapping from ordinary POSIX untrusted-node invocation into the supervised backend, or retain the explicit fail-closed boundary until it is complete.
3. ~~Retire or govern the lightweight `chain_orchestrator.py` direct-execution path.~~ **Closed in H0.3 (implementation pin `989b21fe1d61332f3848474fdfd3e0d9ca1aaf5c`).** Legacy composition execution is fail-closed; no `BaseNode.execute()` call remains in the module (AST-guarded).
4. ~~Route every accepted runtime trace event through one durable emission authority.~~ **Closed in H0.4 (implementation pin `b89c9dd7ba2890d4fa66f89b2b682f036446a591`).** One live `ChainTrace` append authority (`_record_trace_event`, durable-first, same object); first-class `trace_event_id` for authoritative durable trace rows including operator/recovery events; one `get_trace_events()` projection; AST guard enforces exactly one `.add_event()` call in all of `src/nodechain/`.
5. ~~Consolidate authoritative state transitions behind one durability-before-acknowledgement boundary.~~ **Closed in H0.5 (implementation pin `70c8921da34ed1db86233942b70fe597318b3f5b`).** Accepted-state rule: candidate copy → durable commit → adopt; failed commits leave the accepted state untouched with no revision consumed; lifecycle state and asserting trace events commit in one transaction.
6. Connect evaluation to the complete governed runtime where the evaluation claim requires runtime-level evidence.
7. Keep deployment-profile documentation explicit about which execution path and host capability profile is being claimed.

The roadmap must not reopen already-proven features merely because stronger or broader variants are possible. New work should close one of these concrete boundaries or advance a separately stated product outcome.
