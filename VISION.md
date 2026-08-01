# NodeChain Vision: Auditable Autonomous Systems from Governed Reusable Nodes

> **Build a node once. Govern it forever. Reuse it everywhere.**

**Status:** Canonical strategic document
**Current version:** v3.5.1
**Last updated:** 2026-07-14

This document is the single source of truth for what NodeChain is, why it
exists, what it has built, and where it is going. It exists because the
codebase has grown to a scale where individual files and changelogs no
longer convey the full picture.

For the historical architecture report (v0.1.0–v1.3.1), see
[ARCHITECTURE.md](ARCHITECTURE.md). For current implementation details, see
[README.md](README.md), [CHANGELOG.md](CHANGELOG.md), and the source map
in this document.

---

## 1. Executive Thesis

NodeChain exists to produce **auditable autonomous systems**, not just
automations.

A NodeChain system does not merely call an AI agent and return an answer.
It runs a governed lifecycle:

```
goal interpretation → planning → context control → tool selection →
memory access → validation → review gates → policy-controlled execution →
trace recording → evaluation → improvement
```

The platform mechanism that makes this possible is the Harness Node model:
autonomous capabilities are built as reusable, contract-bound nodes with
typed ports, declared permissions, declared side effects, trust identity,
trace behavior, and measurable quality.

In short:

**NodeChain builds autonomous AI systems from reusable governed nodes, so
useful AI work can be composed, audited, recovered, evaluated, and reused.**

---

## 2. The Product Thesis

The output is not:

```
AI agent completes task
```

The output is:

```
AI system interprets goal
plans work
selects tools
controls context
uses memory safely
validates claims and actions
routes through review when needed
executes under policy
records trace
supports evaluation
improves over time
```

That is the defensible difference. NodeChain's competitors help you build
agents that *do things*. NodeChain helps you build autonomous systems you can
*prove did things safely, for the right reasons, within approved boundaries,
with a complete audit trail*.

---

## 3. Who NodeChain Is For

| Audience | Why they need NodeChain |
|----------|------------------------|
| **Compliance-sensitive teams** (healthcare, finance, government, aviation) | Must prove what the system was allowed to see, why it acted, what it changed, what was blocked, and how recovery was handled |
| **Platform engineers** building internal AI tooling | Need reusable governed components with admission, enforcement, and quality measurement — not copy-pasted logic |
| **Researchers** who need validated, cited outputs | Want outputs that document their own confidence, flag uncertainties, and prove citations are real |
| **Operators** who must intervene when autonomous systems fail | Need recovery consoles, per-action authorization, and durable audit trails |

---

## 4. What NodeChain Can Become

Five core products, layered from foundation to ecosystem:

### A. NodeChain Runtime
A durable runtime for autonomous AI systems. Produces executable chains,
invocation envelopes, durable state, trace records, and runtime policy
enforcement. This is the foundation — without it, NodeChain is only a
design language.

### B. Harness Node SDK
A developer kit for building reusable capability blocks. Produces node
templates, manifest generators, contract validators, local runners, and
package builders. Preserves the composable-node promise: build blocks
once, validate, package, and reuse across chains.

### C. Private Node Registry
A controlled catalog of reusable Harness Nodes. Produces internal node
libraries, versioned dependencies, trust metadata, certification workflows,
and blueprint sharing. This is one of the clearest enterprise products
because companies want reusable AI capabilities without every team
inventing unsafe agents.

### D. Chain Blueprint Studio
A developer/operator interface for designing autonomous chains. Produces
blueprint editors, contract graph viewers, risk/budget/memory overlays,
and validation reports. Can start as CLI/YAML/dashboard before becoming
visual — the runtime and contracts remain the execution authority.

### E. Trace and Evaluation Console
An observability and quality layer for autonomous systems. Produces chain
traces, node traces, policy traces, cost/latency reports, regression
evaluations, and failure analysis. Commercially strong because most
companies deploying agents eventually ask: "What happened, why did it
happen, who approved it, what did it cost, and can we reproduce it?"

---

## 5. The Composable Node Promise

This is the central architectural thesis.

A Harness Node is not just a function or a step in a pipeline. It is:

```
Harness Node =
    reusable capability
    + manifest (identity, version, type)
    + contract (entry/exit schema, required fields, side effects)
    + typed ports (semantic input/output types)
    + declared requirements (model, tools, adapters, memory, trust)
    + declared side effects (idempotent, retryable, governed)
    + policy surface (what this node may do at runtime)
    + trust identity (signed, verified, trust-rated)
    + validation (input/output schema enforcement)
    + trace behavior (pre/post/output events recorded)
    + evaluation hooks (quality measured per execution)
    + packaging lifecycle (create → package → publish → install → reuse)
```

The promise:

> A team builds a node once — for example, a Claim Validator that checks
> evidence consistency. They package it, sign it, and register it. Then any
> autonomous chain that needs claim validation can install that node,
> compatibility-check it against its blueprint, execute it under the chain's
> governance profile, trace its behavior, and evaluate its quality — all
> without touching the node's implementation.

---

## 6. Reference Autonomous Chains

The reference implementation already defines the first serious chain: a
**Research and Decision Assistant** using twelve nodes. That pattern can
become a family of production chains:

| Chain | What it proves | Why governance matters | Status |
|-------|---------------|----------------------|--------|
| **Research & Decision Assistant** | Planning, search, synthesis, validation, risk, memory, trace | Cited recommendations need source quality, claim validation, and confidence disclosure | Reference chain (12 nodes); Stage 1 proven end-to-end on GLM-4.6 (v2.68, 9 validated claims, 0 fabricated); baseline comparison passed 7/7 gates (v2.70) |
| **Email Triage Assistant** | Controlled external action | Email sending is a high-risk side effect — approval gates and permission model are critical | Conceptual |
| **Code Review Assistant** | Developer value | Linting, security, architecture review as separate governed nodes | Conceptual |
| **Customer Support Assistant** | Enterprise workflow value | Memory governance matters — support systems can leak or store sensitive information | Conceptual |
| **Procurement Assistant** | Approval-gated autonomy | External actions, vendor contact, purchase recommendations all benefit from policy-gated execution | Conceptual |
| **Incident Response Assistant** | Bounded tool access and side-effect control | Requires strict tool access, side-effect discipline, and trace completeness for post-incident review | Conceptual |

---

## 7. Node Library Vision

NodeChain can produce reusable building-block libraries across four families:

**Core reasoning nodes:** Goal Interpreter, Task Planner, Router, Evidence
Synthesizer, Response Generator, Risk Classifier.

**Tool and adapter nodes:** Web Search, Document Search, Email Draft,
Calendar Draft, Ticketing Adapter (Jira/Linear/Zendesk), Database Query,
Code Execution (sandboxed).

**Validation nodes:** Schema Validator, Source Validator, Claim Validator,
Permission Validator, Side-Effect Validator, Memory Validator, Final
Response Validator.

**Governance nodes:** Policy Evaluator, Human Review, Budget Controller,
Context Exposure Controller, Tool Exposure Controller, Memory Exposure
Controller.

These libraries are where NodeChain transitions from "a platform with one
chain" to "an ecosystem of reusable governed components." The v2.61–v2.66
proof chain (shared nodes, registry resolution, quality scorecards) was the
first mechanical proof that this ecosystem model works.

---

## 8. Industry Product Directions

These are product directions, not committed products. They show where the
reference chain pattern can go vertically.

| Industry | Possible products | Why NodeChain fits |
|----------|------------------|-------------------|
| **Legal** | Legal Research Chain, Contract Review, Discovery Triage, Compliance Monitor | Traceability, citation discipline, review gates, controlled memory |
| **Finance & Investment** | Market Research, Credit Memos, Due Diligence, Portfolio Risk Monitor | Policy enforcement, source validation, disclaimers, human review |
| **Healthcare Operations** | Clinical Admin, Literature Review, Patient Triage, Compliance Docs | Governance useful but requires strict privacy, validation, and regulatory controls |
| **Enterprise Knowledge** | Knowledge Assistant, Meeting-to-Action, Policy Assistant, Project Synthesizer | Benefits from memory, retrieval, validation, and trace without dangerous external actions — best early market |
| **Software Engineering** | Code Review, Migration, Debugging, Architecture Review, Documentation | Engineering teams naturally understand contracts, traces, and reusable nodes |

---

## 9. Current Implementation State

*Snapshot — v2.67.3. 476 Python files (171 src, 275 tests), ~6,000 test
functions, 16 blueprints, 8 node packages, 13+2 typed ports, self-hosted
CI on Proxmox CT 801.*

### Proof chain (v2.63–v2.66)

| Release | What was proven |
|---------|----------------|
| v2.63.2–v2.63.3 | Master green and CI live on self-hosted CT 801 runner |
| v2.64.0–v2.64.1 | Shared nodes are registry-resolved governed packages with lockfile enforcement |
| v2.65.0–v2.65.1 | Those packages have measurable node-level quality (reproducibility, correctness, branch coverage) |
| v2.66.0–v2.66.1 | Both proofs are operator-visible in the dashboard (reuse + scorecards sections) |

### What exists

| Area | What exists | Count |
|------|------------|-------|
| Blueprints | Research & Decision Assistant, Incident Response, Security Audit, Cross-Domain Composition, Quick Fact Check, reuse-proof chains, demos | 16 |
| Harness Nodes | 12-node reference chain + branch variants + shared reusable nodes + domain adapters | 22+ |
| Typed Ports | RAW_QUERY through CHAIN_TRACE_OUTPUT + RISK_CONTEXT + TRACE_INPUT | 13+2 |
| Node Packages | echo_node, shared_risk_classifier, shared_trace_collector, incident_response, security_audit, text_transforms | 8 |
| Node Package SDK | Packaging, trust, compatibility, lockfile, registry, supply-chain attestation, federation, discovery | 43 modules |
| Runtime | Orchestrator, scheduler, policy gate, node invoker, subprocess runner, recovery, evaluation, scorecards | 26+ modules |
| Registry | Publish, install, inspect, lock, verify, resolve, certified lifecycle, federation | — |
| Evaluation | 7 eval suites, research eval harness (6 metrics), node quality scorecards (6 metrics) | — |
| Search Adapters | Semantic Scholar, arXiv, OpenAlex, CrossRef, PubMed with circuit breaker + retry | 5 |
| Operator CLI | ~181 commands across 20+ groups including dashboard, recovery, registry, eval, evidence | 31 modules |
| Local API | FastAPI read-only operator API with auth, OpenAPI, dry-run preview | 10 modules |
| CI | Self-hosted on CT 801 (Proxmox LXC, Ubuntu 24.04), 8 blocking Linux jobs + 1 Windows | 10 jobs |

---

## 10. Platform Architecture

### Layer map

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Operator Experience                          │
│  CLI workbench · Dashboard · Recovery Console · Local API           │
├─────────────────────────────────────────────────────────────────────┤
│                    Trace & Evaluation Layer                          │
│  Trace truth · Evidence · Scorecards · Eval suites · Health rules   │
├─────────────────────────────────────────────────────────────────────┤
│                  Registry & Trust Layer                              │
│  Admission · Packages · Lockfile · Trust levels · Supply chain      │
├─────────────────────────────────────────────────────────────────────┤
│                    Runtime Governance Layer                          │
│  Policy gate · Invariants · Budget · Review · Side effects · Sandbox│
├─────────────────────────────────────────────────────────────────────┤
│                    Execution Kernel                                  │
│  Orchestrator · Scheduler · Node invoker · State · Recovery         │
├─────────────────────────────────────────────────────────────────────┤
│                    Composition Primitives                            │
│  Contracts · Typed ports · Envelopes · Blueprints · Manifests       │
└─────────────────────────────────────────────────────────────────────┘
```

### Core primitives

- **InvocationEnvelope / EnvelopeResponse** — the universal execution boundary. No node sees raw input; no node returns raw output.
- **NodeContract** — entry/exit specification validated at load time, not invocation time.
- **Typed Ports** — semantic types constraining which nodes can connect.
- **ChainBlueprint** — declarative YAML chain definition (nodes, connections, loops, branches, gates, invariants).
- **StateManager** — SQLite-backed durable state with atomic commit boundaries.
- **Trace** — 80+ event types forming the authoritative execution record.

### Runtime governance

- **PolicyGate** — 20 policy types (tool, model, memory, side-effect, cost, rate limit), evaluated before invocation.
- **InvariantEngine** — structural invariants checked at load and runtime.
- **NodeInvoker** — clean invocation boundary; subprocess isolation for untrusted nodes with optional seccomp, cgroups, namespace confinement.
- **Recovery** — per-action authorization for budget increases, route fallbacks, retries, and human review.

---

## 11. Competitive Position

NodeChain does not compete by being a faster agent framework, a broader
integration marketplace, or a better observability dashboard. It competes
by making autonomous capabilities **reusable, governed, auditable, and
portable across chains**.

| Category | Market strength | NodeChain distinction |
|----------|----------------|----------------------|
| Agent frameworks (LangGraph, OpenAI Agents SDK, AutoGen) | Fast construction, tool calling, handoffs, sessions, tracing | Governed reusable nodes with contracts, typed ports, and policy built into the block — not bolted on |
| Workflow automation (n8n) | Visual workflows, integrations | Autonomous-node governance, trace truth, side-effect discipline |
| Durable execution (Temporal) | Industrial resumability, event history | AI-native policy, memory governance, evidence provenance, node contracts |
| Observability (LangSmith, Phoenix) | Traces, evals, datasets | Governance and reuse are part of execution, not monitoring after the fact |

**NodeChain's distinct claim:** reusable **governed autonomous-system
nodes** — where governance, trust, trace, evaluation, and recovery are
native properties of the node itself, not external tooling applied around it.

---

## 12. Engineering Maintainability Boundary

NodeChain has reached a level of runtime maturity where several core files
have grown large enough to create maintainability risk:

| File | Size | Risk level | Why |
|------|------|-----------|-----|
| `orchestrator.py` | 143KB | Actively concerning | Combines run, resume, failure, side-effect journaling, state transitions |
| `state.py` | 81KB | Hidden danger | 40+ methods accumulating unrelated persistence responsibilities |
| `trace_reconciler.py` | 92KB | High but contained | Post-execution diagnostic, not execution-path-critical |
| `cli/main.py` | 263KB | Ugly but safe | CLI command splitting is mechanical and low behavioral risk |
| `dashboard_health.py` | 92KB | Large but modular | 39 rule classes naturally extractable |

This is not currently treated as a product blocker because the test suite
is green and the next priority is proving a real end-to-end product run.
However, large-file decomposition is a Stage 1/Stage 2 engineering
readiness task.

**The rule:**
- Prove the product path first
- Record which large files are touched during real execution debugging
- Extract only stable seams after the real run
- Preserve behavior through characterization tests before structural refactors

---

## 13. What NodeChain Is Not Yet

Honest readiness boundaries — distinguishing what exists, what is partial,
and what is conceptual:

| Surface | Status today | Possible stage | Current claim | Not claiming yet |
|---------|-------------|----------------|---------------|-----------------|
| Hosted SaaS | Not available | Stage 3 | Local runtime + API server | Managed cloud platform |
| Visual Builder | Not available | Stage 3 | Blueprint-driven composition | Drag-and-drop product |
| Private Registry | Partially implemented | Stage 2/3 | Local registry mechanics exist | Enterprise registry product |
| Certified Node Program | Early infrastructure | Stage 3 | Trust/eval/attestation primitives | Public certification marketplace |
| Industry Products | Conceptual | Stage 2/3 | Reference-chain patterns exist | Production vertical solutions |
| Real chain execution | Stage 1 proven (v2.68) + baseline (v2.70) | Stage 2 | 12-node research chain proven on GLM-4.6; 7/7 baseline gates vs flat agent; value proposition = verifiable governance, not better prose | Proven across multiple model families |
| Second domain | Stage 2 proven (v2.71) | Stage 2 | Code Review chain (5 nodes): file-access governance, artifact provenance, read-only enforcement | Third domain chain |
| Patch proposal governance | Stage 2 proven (v2.72) | Stage 2 | Patch proposals as typed-port artifacts, validated in temp workspace, risk-classified; repo never modified | — |
| Governed test execution | Stage 2 proven (v2.73) | Stage 2 | Patches tested in isolated temp workspaces (tracked-file export, bounded pytest); code_execution as declared side effect | Container/OS isolation; arbitrary command profiles |
| External validation | None | Stage 1/2 | Internally tested only | Independently reviewed |

These are boundaries, not permanent limitations. They define what the
project is ready for today and what requires further maturation.

---

## 14. Roadmap

### Product Staging

**Stage 1 — Product Proof** ✅

Prove the Research & Decision Assistant works end-to-end with real model
and search adapters. Produce a real cited research artifact with complete
governance evidence. Compare against a simpler baseline. This is the gate
between platform and product.

Completed in v2.68–v2.70:
- v2.68: 12-node chain ran end-to-end (9 claims, 0 fabricated, model requirements traced)
- v2.69: Citation surface + adapter reliability (8 citations, arXiv+OpenAlex both contributing)
- v2.70: Baseline comparison — 7/7 gates passed, value = verifiable governance not better prose

**Stage 2 — Repeatable Use Cases** ✅

After the reference chain is proven, build additional chains. Each proves a
different governance property. Extend to patch proposal and governed execution.

Completed in v2.71–v2.73:
- v2.71: Code Review chain (5 nodes) — file-access governance, artifact provenance, read-only enforcement
- v2.72: Patch proposal path (4 nodes) — patches as typed-port artifacts, temp-workspace validation, risk classification
- v2.73: Governed test execution (2 nodes) — bounded pytest in isolated temp workspaces, code_execution as declared side effect

Stage 2 proved the governed-node model generalizes across two domains (research
+ code review) and three governance surfaces (citation/search, file/tool access,
code execution). The Code Review chain is 10 nodes total and demonstrates the
full arc: review → propose → validate → test → classify → report.

**Stage 3 — Commercial Platform**

Private Node Registry, Blueprint Marketplace, Visual Builder, Compliance
Console, Certified Node Program, Managed NodeChain Cloud.

### Next Release Targets

```
v2.68  Real Research & Decision Assistant run ✅
v2.69  Citation surface + source acquisition reliability ✅
v2.70  Baseline comparison harness (governance vs flat agent) ✅
v2.71  Code Review Assistant: read-only governed review ✅
v2.72  Code Review Assistant: governed patch proposal path ✅
v2.73  Code Review Assistant: governed temp-workspace test execution ✅
v2.74  Orchestrator decomposition: NodeEventEmitter extraction ✅
v2.75  Orchestrator decomposition: side-effect journaling extraction ✅
v2.76  Native OS-sandboxed test runner execution (close the routing gap) ✅
v2.77  Privileged Linux native sandbox verification harness ✅
v2.78  Child-applied seccomp for native command runner ✅
v2.79  Operator surface cleanup: CLI characterization + Click relocation wave 1 ✅
v2.80  CLI relocation wave 2 (eval, graph, console) ✅
v2.81  StateManager characterization harness ✅
v2.82  StateManager store extraction phase 1 (EventLogStore, InvocationLedgerStore) ✅
v2.83  StateManager store extraction phase 2 (SideEffectLedgerStore, DecisionLogStore) ✅
v2.84  Verification ergonomics: Windows suite sharding + release gate clarity ✅
v2.85  Five-minute local proof quickstart ✅
v2.86  CLI relocation wave 3 (inspect, report, trace, trace-replay, compose) ✅
v2.87  External verification pack (reviewer-facing docs + claims/evidence + smoke) ✅
v2.88  External verification runner + evidence bundle ✅
v2.89  Optional sandbox verification evidence profile ✅
v2.90  Release evidence index + verification dashboard ✅
v2.91  Orchestrator characterization harness ✅
v2.92  Orchestrator extraction phase 1: contract preflight controller ✅
v2.93  Orchestrator extraction phase 2: node output validation controller ✅
v2.94  Orchestrator validation failure characterization ✅
v2.95  Orchestrator policy gate characterization ✅
v2.96  Orchestrator extraction phase 3: policy gate controller ✅
v2.97  Orchestrator side-effect journaling characterization ✅
v2.98  Orchestrator extraction phase 4: side-effect journal controller ✅
v2.99  Side-effect completion design study ✅
v3.0   Observed side-effect completion path (if design converges), branch/loop/review characterization, or Docker
v3.1   Side-effect completion (observed-completion model) ✅
v3.2   Side-effect recovery decisions ✅
v3.3   Safe-to-retry recovery state ✅
v3.4   Retry-authorized execution design study + characterization ✅
v3.5   Governed retry-authorized side-effect execution ✅
```

### Shipped history

```
v2.60  Vision alignment + documentation truth — shipped
v2.61  Reusable Node Proof Pack — direct shared-node proof — shipped
v2.62  End-to-end reuse execution proof — shipped
v2.63  Full reuse runtime proof + CI migration (CT 801) — shipped
v2.64  Registry-resolved reuse proof — shipped
v2.65  Deterministic node quality scorecards — shipped
v2.66  Operator evidence/reuse dashboard — shipped
```

### Roadmap principles

1. Every feature must serve node reuse, trace truth, recovery, or policy.
2. No more broad platform features until one real use case works end-to-end.
3. Evaluation must measure reusable node quality across chains.
4. Visual tooling should start with trace/reuse inspection, not workflow building.

---

## 15. External Reviewer Guide

If you are reviewing NodeChain, inspect these areas **in this order**:

1. **Run a real chain** — `nodechain run "your research question"` with real adapters. Judge the output as a product artifact.
2. **Read the trace** — `nodechain trace <run_id>`. Verify every decision is auditable.
3. **Check the dashboard** — `nodechain dashboard`. See governance health at a glance.
4. **Inspect the proof chain** — `nodechain dashboard reuse` and `nodechain dashboard scorecards`. Verify registry-resolved packages with quality evidence.
5. **Read VISION.md** (this document) — the full product thesis and current state.
6. **Browse blueprints/** — multiple chains exist; NodeChain is not one-chain-only.
7. **Browse nodes/** — independently packaged node sets; reuse has started.
8. **Read src/nodechain/core/** — contracts, typed ports, manifests, state, trace.
9. **Read src/nodechain/runtime/** — orchestrator, policy gate, recovery, evaluation.
10. **Check tests/** — ~6,000 tests across 275 files, invariant tests, adversarial tests.

---

## 16. Maturity, Risks, and Open Gaps

### What is mature

- Runtime execution kernel with governance, state, and trace
- Contract/typed-port composition model
- Policy gates (tools, memory, side effects, trust, cost, code execution)
- Recovery system with per-action authorization
- Persistence with atomic commit boundaries
- Test discipline (~6,131 tests across 90+ files, invariant tests, self-hosted CI)
- Research evaluation harness with quality metrics
- Node quality scorecards with reproducibility and branch coverage
- Source acquisition with retry, circuit breaker, and failure taxonomy
- CLI operator workbench with dashboard, recovery, and local API
- Two proven domain chains: Research & Decision Assistant (12 nodes) + Code Review Assistant (10 nodes)
- Baseline comparison proof: governance > flat agent on verifiable auditability
- Patch proposal governance: typed-port artifacts, temp-workspace validation, risk classification
- Governed code execution: bounded pytest in isolated temp workspaces, code_execution as declared side effect

### What needs strengthening

- **Real end-to-end chain execution — Stage 1 proven (v2.68).** A real Research
  and Decision Assistant chain completed end-to-end with 12/12 nodes, validated
  claims, trace-visible source-quality policy decisions, and zero fabricated
  citations. Stage 1 proven with capable structured-output model: GLM-4.6. The
  original Gemma 4 12B failure was not re-instrumented before tag. The
  context-overflow hypothesis was falsified by code inspection and replay, and
  the successful GLM-4.6 run is sufficient to prove the architecture under a
  capable structured-output model, not yet to prove model-agnostic robustness.
- **Baseline comparison** — compare NodeChain output against a simpler agent approach to validate the governance overhead is justified (v2.69)
- **External validation** — independent installation and review beyond internal tests
- **Code maintainability** — several core files need decomposition (see §12)
- **Quickstart / setup flow** — no "get running in 5 minutes" path exists yet
- **Performance and cost data** — no data on real chain latency or cost

### Risks

- **Scope pressure** — the project covers many subsystems; focus must stay on proving the product
- **Platform vs product** — the governance infrastructure is deep; it must translate to user-visible value
- **Competitive narrowing** — agent frameworks are maturing rapidly; governance depth must be felt, not just claimed

---

## 17. Glossary

| Term | Definition |
|------|-----------|
| **Harness Node** | A reusable autonomous-system capability unit with manifest, contract, typed ports, declared requirements, side effects, policy surface, trust identity, trace behavior, and packaging lifecycle |
| **Auditable Autonomous System** | An AI system whose full governed lifecycle — goal, plan, tools, memory, validation, review, policy, trace, evaluation — is recorded and reproducible |
| **Node Contract** | Formal entry/exit specification: input/output port types, schema references, required fields, guaranteed fields, declared requirements, declared side effects |
| **Typed Port** | A semantic port type (e.g., EVIDENCE_BASE, RISK_ASSESSMENT) that constrains which nodes can connect to which |
| **Blueprint** | A chain definition file specifying ordered nodes, connections, branch policies, loop controls, and review gates |
| **Chain** | A running instance of a blueprint — an autonomous system assembled from governed nodes |
| **Node Package** | A distributable unit containing a node's manifest, contract, implementation, tests, and metadata |
| **Registry** | A system for publishing, installing, verifying, locking, and revoking node packages with trust and policy enforcement |
| **Lockfile** | A pinned record of exact package versions, content digests, and policy states for a given chain |
| **Trust Status** | The trust level assigned to a node package, determining whether the runtime will execute it |
| **Policy Gate** | The runtime checkpoint that verifies tool, adapter, memory, side-effect, trust, and cost permissions before node invocation |
| **Side Effect** | A declared external action a node performs (e.g., API call, memory write, file write) — governed, idempotent, retryable |
| **Trace Truth** | The principle that the execution trace is the authoritative record — executed, skipped, simulated, and partial steps are distinguished |
| **Content Digest** | Full-length deterministic SHA-256 over package files, used for fail-closed lockfile enforcement |
| **Recovery Action** | A governed operator action (resume, retry, approve, cancel, etc.) performed on a paused or failed chain |
| **Composable Governed Node** | The core product primitive: an autonomous capability that can be built once, packaged, trusted, and composed into any governed chain |
