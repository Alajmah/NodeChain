# NodeChain Current Baseline

**Document class:** Descriptive baseline  
**Status:** Active development truth  
**Baseline date:** 2026-08-18  
**Released version:** `v3.6.0`  
**Implementation code baseline:** `78f98252173eb38d4284ed92f0fd3343c5c5ce21` (the `master` state at the H0.6 deployment-profile closure — implementation squash `068120f6` plus the canonical deployment-profile documentation; Horizon 0 is closed)  
**Supersedes for current-state claims:** implementation/status sections in older README, VISION, ROADMAP, and architecture snapshots

This document answers one question: **what does the NodeChain codebase actually contain and support at the pinned implementation baseline?** Documentation-only commits may follow this SHA without changing the implementation facts recorded here.

It is descriptive, not normative. The NodeChain System Specification defines intended platform semantics; `VISION.md` defines strategic direction; `CHANGELOG.md` and `docs/releases/` record released history. When a descriptive claim conflicts with code at the pinned implementation SHA, the code is authoritative and this file must be corrected.

---

## 1. Release baseline vs implementation baseline

NodeChain has two legitimate anchors and they must not be conflated.

| Anchor | Value | Meaning |
|---|---|---|
| Released product baseline | `v3.6.0` | Latest packaged/released version represented by `pyproject.toml` and `nodechain.__version__` |
| Implementation code baseline | `78f98252173eb38d4284ed92f0fd3343c5c5ce21` | `master` state at the H0.6 deployment-profile closure (implementation squash `068120f6` of PR #25 + the canonical deployment-profile documentation of PR #27); Horizon 0 closed |

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
- authoritative/accepted `ChainState` transition boundaries use candidate → durable commit → adopt (H0.5): a candidate copy is constructed (`ChainState.transition_candidate()`), committed durably, and only then adopted; a failed commit leaves the accepted state untouched with no revision consumed. Invocation transitions (output, completed-step, cursor, branch state), state-asserting lifecycle transitions (start, completion, failure, review pause/decision), and resume control-marker removals commit through `PersistenceCoordinator` primitives; lifecycle state and their asserting trace events commit in one SQLite transaction. Review decisions are outcome-specific (reject/timeout commit failed directly); recovery terminal actions are candidate-safe and adopt the committed revision. Scheduler-local provisional preparation is not itself an authoritative transition;
- the research evaluation runner directly executes quality-critical nodes rather than executing the complete governed runtime.

These are current architectural seams. They are not evidence that the primary runtime is absent; they are the remaining work required to make the “one execution / one trace / one authoritative state-transition path” claim literal throughout the repository.

---

## 6. Untrusted execution baseline

The hardened supervised POSIX execution substrate and the ordinary node-isolation integration path are JOINED: H0.2 (T3) routes ordinary POSIX untrusted invocation through the supervised backend as the single spawn/lifecycle authority.

### Supervised execution substrate

`runtime/supervised_argv.py`, the supervisor/session modules, PID-namespace topology logic, ptrace `PTRACE_EVENT_EXEC` authority, bounded asynchronous I/O, namespace cleanup, and host process-group containment implement the hardened Linux execution substrate developed through v3.5.1.

### Ordinary NodeInvoker path (H0.2 routing)

`NodeInvoker` sends isolated non-built-in nodes through `SubprocessRunner.run_isolated()`. On POSIX, `local_untrusted` and `remote_untrusted` requests route through `_run_supervised_untrusted()` into the supervised stack; the legacy POSIX spawn body is unreachable for untrusted trust levels, and there is no try-supervised-except-legacy fallback under any condition. The frozen outcome matrix maps supervisor truth into the compatibility result shape (not-started vs started-failed, timeout, output-cap, SIGSYS/seccomp-kill classification, cleanup-dominates), and the `supervised_execution` evidence projection rides both success and failure.

Containment and startup boundaries qualified at this baseline:

- mount confinement binds the package at `/package` and every runtime extra mount read-only (`MS_REMOUNT|MS_BIND|MS_RDONLY`), with `/tmp` writable; any required read-only remount that cannot be established fails closed before workload start;
- a durable capability boundary removes the boundary-undoing capabilities (including `CAP_SYS_CHROOT` and `CAP_SYS_ADMIN`) from all five relevant sets (effective, permitted, inheritable, ambient, bounding) before `enforcement_verified`, verified by read-back and proven against deliberately seeded ambient/inheritable capabilities;
- every Python launch boundary is trust-rooted: the workload interpreter runs `python -I -c` (no cwd/user-site on `sys.path`, `PYTHON*` ignored), the child script imports the SDK from the resolved trusted installation (never the caller cwd), and the supervisor and bootstrap launch with `-P`;
- requested seccomp is really enforced when a filter binding is present (available → enforced → verified → exec-confirmed chain, kernel SIGSYS denial proof); without a binding the run fails closed before start;
- on hosts without the privileges the topology needs (hosted CI), the route fails closed before workload start (`process_started=False`) — that is the design truth, never a weaker fallback.

Deployment-profile truth is now canonical in `docs/deployment-profiles.md` (the six-profile matrix with dispositions and the evidence ledger): editable/source-backed installations and custom-prefix interpreter layouts are unsupported under mount confinement and fail closed; the host `package_root` pathname is visible to the trusted child context as information only; non-Linux `WNOWAIT` kernel profiles are unqualified; requested cgroups are refused before start.

Therefore the truthful claim is:

> One governed supervised backend owns ordinary POSIX untrusted-node execution, with read-only bind confinement, a verified five-set capability boundary, and trust-rooted interpreter startup. Enforcement requires a privileged Linux host; everywhere else the path fails closed before workload start.

No documentation should describe the generic POSIX untrusted-node path as silently falling back to a weaker sandbox.

---


## 6a. Research Workspace object model (H1.1)

`nodechain.research.workspace.open_workspace()` projects the authoritative runtime/evidence records of a workspace's selected run into a frozen, versioned `ResearchWorkspaceSnapshot`. The Workspace is a read-only projection — it creates no competing runtime state, performs no lifecycle mutation, and performs no persistence write. Every concept from the H1.1 roadmap contract is represented: objective, plan, runs, sources, qualified sources, evidence, claims, citations, uncertainties, faults, recovery, review decisions, trace, and terminal verified bundles (integrity-verified through `BundleReader` only). Three statuses are explicitly separated: `execution_status` (runtime truth), `research_outcome` (product/evidence outcome), and `bundle_status` (absent/verified/invalid). Each section carries its availability state so absence is never fabricated.

## 6b. Research operator CLI surface (H1.2)

The operator experience is a read-side CLI on top of the H1.1 snapshot: `nodechain research open` (workspace overview), `runs` (listing with persistence time `updated_at`), `inspect` (per-section drill-down with availability states and the governed recovery handoff), `verify` (terminal-bundle integrity through `BundleReader`, including the verified document inventory), `compare` (side-by-side run comparison), and `export` (verified-bundle copy — directory or `.zip` — never regeneration). Every command supports `--json`; `research run` accepts an additive `--workspace DIR` so creation and observation target the same workspace root.

All observation commands are runtime-state read-only through `StateManager(read_only=True)`: the DB-hash invariant proves zero persistence writes across `open`, `runs`, `inspect`, `verify`, and `compare`. `research export` has exactly one side effect — the explicitly requested output artifact. `research verify` exits nonzero on an invalid bundle in both human and `--json` modes. `inspect`'s recovery handoff resolves the descriptor's `db_path` and routes to the existing governed recovery console (`nodechain recover inspect` / `list-unknown`); it invents no recovery action and has no placeholder fallback. API/UI product surfaces that consume the `--json` contract remain future work (Roadmap H1.6).

## 6c. Live source acquisition profile (H1.3)

The Research Workspace has exactly two acquisition profiles: `fixture` (the default, sealed-corpus deterministic path) and `live` (the existing governed academic adapters: Semantic Scholar, arXiv, OpenAlex, CrossRef, PubMed). `nodechain research run --profile live` selects live acquisition; combination rules fail closed (`fixture` requires `--corpus`, `live` rejects it) with no silent fallback in either direction.

Live composition reuses the ordinary execution spine: the production `SearchToolNode`, the existing guarded adapter registry (`OrdinaryDispatchGuard` with capsule-before-wire), and the existing production model-provider resolution factored into `resolve_production_model_adapter` (the same authority as the ordinary run path). The runner and CLI hold no direct adapter or network path.

Every ingested live source carries a NodeChain-computed content identity: `source_hash` is the SHA-256 of canonical normalized content (origin, title, authors, DOI, abstract, publication metadata, source type, venue, retained origin-specific signals — excluding volatile acquisition metadata such as the retrieval timestamp), and `artifact_ref` is `ingested:<source_id>:<source_hash>`. Authoritative `query_used`/`retrieved_at` propagate from acquisition provenance into the persisted record; the `QualifiedSourceLinker`'s fail-closed binding is unchanged. Thus the same content fetched later hashes identically while changed content changes the hash.

Descriptors are versioned: legacy documents without `descriptor_version` remain V1 fixture descriptors whose stored raw-document digest is their identity (loading never recomputes it under V2 defaults); new runs write V2 acquisition-aware descriptors carrying the profile, a launch-intent `input_digest` (brief/profile/adapters/provenance version/non-secret model identity — never a source snapshot or replay digest), the allowed adapter set, and resolved non-secret model identity. Credentials are never persisted.

Terminal live bundles remain BundleV1: `provider_mode="live"`, `fixture_corpus_version` null (non-empty is enforced exactly for fixture runs by model and schema), and `replay_eligible=false` unconditionally. Adapter coverage, used adapters, retrieval timestamps, hashes, and artifact refs derive from actual records rather than hardcoding. The reproducibility claim is artifact-bounded: NodeChain proves exactly which content and provenance a run used, and does not claim a later network query returns the same sources. The Workspace projection exposes `acquisition_profile` and `reproducibility_mode` (`deterministic_fixture` / `artifact_bounded_live`) on the snapshot and every run summary, so no live run can be presented as a deterministic fixture run. Fault truth is unchanged: records project only from actual trace events.

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
- universal Linux compatibility for privileged supervised containment (unprivileged hosts fail closed before workload start, by design);
- editable/source-backed installations or custom-prefix interpreter layouts under mount confinement (disposition recorded in `docs/deployment-profiles.md`);
- cgroup accounting or limits on the supervised route (requested cgroups are refused before start);
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
2. ~~Complete T3 routing/result mapping from ordinary POSIX untrusted-node invocation into the supervised backend, or retain the explicit fail-closed boundary until it is complete.~~ **Closed in H0.2 (implementation pin `068120f6a46797182d33e100b5dadfc8ccc77b4f`).** One supervised backend owns ordinary POSIX untrusted-node execution with truthful result mapping; no legacy fallback exists under any condition. Read-only bind mounts (`/package` + runtime extras, `/tmp` writable), a verified five-set capability boundary before `enforcement_verified`, real requested-seccomp enforcement with SIGSYS denial proof, and trust-rooted interpreter startup (`-I` child, trusted-installation import root, `-P` supervisor/bootstrap) are all adversarially proven on privileged Linux; unprivileged hosts fail closed before workload start.
3. ~~Retire or govern the lightweight `chain_orchestrator.py` direct-execution path.~~ **Closed in H0.3 (implementation pin `989b21fe1d61332f3848474fdfd3e0d9ca1aaf5c`).** Legacy composition execution is fail-closed; no `BaseNode.execute()` call remains in the module (AST-guarded).
4. ~~Route every accepted runtime trace event through one durable emission authority.~~ **Closed in H0.4 (implementation pin `b89c9dd7ba2890d4fa66f89b2b682f036446a591`).** One live `ChainTrace` append authority (`_record_trace_event`, durable-first, same object); first-class `trace_event_id` for authoritative durable trace rows including operator/recovery events; one `get_trace_events()` projection; AST guard enforces exactly one `.add_event()` call in all of `src/nodechain/`.
5. ~~Consolidate authoritative state transitions behind one durability-before-acknowledgement boundary.~~ **Closed in H0.5 (implementation pin `71afaef186dca695770c73f212a7f198e97dac2b`).** Authoritative/accepted `ChainState` transition boundaries use candidate copy → durable commit → adopt; failed commits leave the accepted state untouched with no revision consumed; lifecycle state and asserting trace events commit in one transaction; resume control-marker removals are candidate-owned. Scheduler-local provisional preparation is not itself an authoritative transition.
6. Connect evaluation to the complete governed runtime where the evaluation claim requires runtime-level evidence.
7. ~~Keep deployment-profile documentation explicit about which execution path and host capability profile is being claimed.~~ **Closed in H0.6 (truth pin `78f98252173eb38d4284ed92f0fd3343c5c5ce21`).** The canonical six-profile matrix with dispositions and the evidence ledger is `docs/deployment-profiles.md`; every current descriptive document links to it rather than maintaining competing detail, and the claim-audit gate holds at zero contradictory deployment claims.

The roadmap must not reopen already-proven features merely because stronger or broader variants are possible. New work should close one of these concrete boundaries or advance a separately stated product outcome.
