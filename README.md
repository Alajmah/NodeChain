# NodeChain

**Governed autonomous systems from reusable Harness Nodes**

> **Build a node once. Govern it forever. Reuse it everywhere.**

NodeChain is a local-first platform for building autonomous AI systems from composable, contract-bound, policy-governed, traceable nodes. It focuses on the part that becomes difficult after an agent demo works: proving what ran, what it was allowed to do, what external effects occurred, how failures were recovered, what evidence supported the result, and whether the same governed capability can be reused safely elsewhere.

## Start with the right document

NodeChain now separates strategy, current implementation truth, architecture, roadmap, release history, and compatibility surfaces.

| Document | Purpose |
|---|---|
| **[BASELINE.md](BASELINE.md)** | Canonical description of what the pinned implementation code actually supports |
| **[VISION.md](VISION.md)** | Product thesis and strategic direction |
| **[ARCHITECTURE.md](ARCHITECTURE.md)** | Current implementation architecture, including known alternate paths and boundaries |
| **[ROADMAP.md](ROADMAP.md)** | Future work only — no shipped-release backlog |
| **[CHANGELOG.md](CHANGELOG.md)** | Released change history; development truth remains in `BASELINE.md` until release preparation |
| **[docs/current-public-surfaces.md](docs/current-public-surfaces.md)** | Current compatibility/public-surface map |
| **[docs/ci.md](docs/ci.md)** | Hosted CI and qualification contract |
| **[docs/documentation-authority.md](docs/documentation-authority.md)** | Rules that keep normative, descriptive, strategic, historical, and evidence documents separate |

### Release vs implementation baseline

- **Released version:** `v3.6.0`
- **Implementation code baseline traced for this rebaseline:** `af1943c24a58d80ae048b9b9d50842cf0e0b27d1`

That SHA is the `master` code state examined before this documentation-only wave. The implementation baseline includes the post-v3.6 `ResearchWorkspaceBundleV1` contract and governed Research Workspace merged in PR #12 and PR #13. Those features are not retroactively part of the v3.6.0 release. Documentation-only commits may follow the pinned implementation SHA without changing the implementation facts.

---

## What NodeChain provides

The implemented platform includes:

- **Governed graph execution** — blueprints, typed ports, contracts, invocation envelopes, scheduling, branches, loops, review gates, validation, persistence, and trace;
- **Policy-controlled capabilities** — model, tool/adapter, memory, trust, cost, timeout, retry, fallback, and side-effect controls;
- **Side-effect truth and recovery** — operation identity, `planned → started → completed | failed | unknown`, operator recovery decisions, and governed retry-authorized execution;
- **Reusable Harness Nodes** — package manifests, compatibility checks, lockfiles, registry resolution, trust metadata, signing/certification, and remote-registry mechanics;
- **Operator tooling** — CLI, inspection, reconciliation, recovery, evidence, dashboards, release assurance, and a token-protected local read-only API;
- **Evaluation infrastructure** — suites, metrics, scorecards, report signing, certification, and deterministic research-quality evaluation;
- **Execution isolation substrate** — Python-level enforcement, sandbox/native execution components, and hardened supervised Linux execution primitives;
- **Proven application domains** — Research & Decision Assistant and Code Review, plus the post-v3.6 governed Research Workspace product-proof backend.

NodeChain is not yet a managed SaaS, a distributed worker fabric, a general multi-tenant enterprise service, or a visual drag-and-drop builder.

---

## Quick start: general governed runtime

```bash
# Install for development
python -m pip install -e ".[dev]"

# Deterministic run — no external model/API required
nodechain run "Should we adopt RAG for policy QA?" \
  --provider mock \
  --review-mode auto-approve \
  --strict \
  --json data/demo_run.json

# Inspect durable state
nodechain inspect <run_id>

# Reconcile durable state and trace
nodechain reconcile <run_id>

# Generate a run report
nodechain report <run_id> --output data/report.json

# View a trace
nodechain trace data/traces/<run_id>.json
```

Use `nodechain --help` and the command-group `--help` output as the authoritative live CLI inventory. This README intentionally avoids hard-coded command counts because the CLI surface changes more frequently than the product thesis.

---

## Two research paths — do not confuse them

### 1. Research & Decision Assistant

`blueprints/research_decision_v1.yaml` is the general twelve-node research chain:

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

Its search tool is designed around five academic adapters:

- Semantic Scholar
- arXiv
- OpenAlex
- CrossRef
- PubMed

The chain includes source-quality looping, risk/review routing, governed memory decisions, and complete runtime state/trace surfaces.

### 2. Governed Research Workspace — post-v3.6 implementation baseline

The post-v3.6 Research Workspace is a deterministic product-proof surface using a sealed fixture corpus and a terminal integrity-checked evidence bundle. It adds an explicit `qualified_source_linker` between source qualification and synthesis.

A development fixture run can be exercised with:

```bash
nodechain research run tests/fixtures/research/brief_basic.yaml \
  --corpus tests/fixtures/research/corpus_basic.yaml
```

The workspace proves a different set of properties from the live academic-search chain: sealed source identity, zero-network fixture execution, guarded dispatch, trace-derived fault truth, qualified-source hash continuity, durable review/resume evidence, and terminal `ResearchWorkspaceBundleV1` finalization.

**Current implementation-boundary note:** the `nodechain research review` CLI reconstructs the runner differently from the descriptor-aware library path. The terminal bundle-finalization branch depends on the descriptor being restored, so the CLI review/resume wiring requires a bounded correction before that command is claimed as authoritative end-to-end bundle production. See [BASELINE.md](BASELINE.md#4-known-research-workspace-integration-gap).

---

## Runtime architecture

The primary governed execution path is:

```text
CLI / API / composition root
        ↓
Orchestrator
  ├─ contract preflight
  ├─ scheduler / branches / loops
  ├─ policy gate
  ├─ invocation envelope + NodeInvoker
  ├─ side-effect journal
  ├─ validation
  ├─ persistence
  ├─ trace emission / reconciliation
  ├─ failure manager / recovery
  └─ human review / resume
        ↓
models · search adapters · memory · execution adapters · nodes
```

The repository also contains narrower direct-execution utilities and historical/compatibility paths. They are documented explicitly in [ARCHITECTURE.md](ARCHITECTURE.md) rather than being silently presented as equivalent to the main governed runtime.

---

## Trust and untrusted execution

NodeChain distinguishes trust identity from execution permission. Package signatures, registry trust, certification, and digest matches do not automatically authorize a node to execute privileged behavior.

At the pinned implementation baseline:

- built-in and trusted paths can execute through the ordinary runtime according to policy;
- the hardened supervised Linux execution substrate exists;
- **ordinary POSIX `local_untrusted` / `remote_untrusted` node invocation is deliberately fail-closed in `SubprocessRunner.run_isolated()` pending T3 supervised routing into the generic `NodeInvoker` path**;
- Windows does not claim equivalence to Linux PID namespaces, seccomp, procfs isolation, or cgroup semantics.

### Historical seccomp compatibility anchor

**Seccomp Enforcement (v1.2.2+)** introduced seccomp syscall filtering into NodeChain's Linux sandbox lineage. Later releases added namespace, cgroup, native-runner, and supervised-execution mechanisms. Current execution-path claims are narrower than that historical milestone and are documented in `BASELINE.md` and `docs/linux-deployment.md`.

The historical trust-invariant lineage includes `INV-006` and `INV-007`. These identifiers remain compatibility/documentation anchors; the current enforcement model contains additional invariants and profile-specific behavior.

NodeChain **does NOT provide** universal hostile-code containment merely because seccomp syscall filtering or another individual primitive is available. Security claims require the actual execution path, host profile, and proving runtime evidence.

See [docs/linux-deployment.md](docs/linux-deployment.md) and [BASELINE.md](BASELINE.md#6-untrusted-execution-baseline) before making deployment or containment claims.

---

## Evaluation

NodeChain contains substantial evaluation and certification machinery, but not every evaluation route is a complete runtime execution.

- generic evaluation suites can use structural/default evaluation or custom runners;
- research-quality evaluation directly exercises the synthesis/validation/risk/response segment deterministically;
- full governed-runtime evidence should be required whenever a claim depends on policy, recovery, side-effect, trace, or persistence behavior.

The roadmap includes consolidation of runtime-level evaluation authority rather than relabeling direct-node evaluation as full-runtime proof.

---

## Local API

A token-protected local read-only operator API is available:

```bash
export NODECHAIN_API_TOKEN="<strong-random-token>"
nodechain api serve --host 127.0.0.1 --port 8765
```

The API is a local operator/control-plane surface. It is not a hosted multi-tenant service.

---

## Verification

Hosted GitHub Actions are the public repository qualification surface. Current branch protection requires the CI job set plus Ubuntu and Windows Publication Tree checks.

```bash
# Useful local iteration targets
make ci-fast
make ci-recovery
make ci-trust

# Direct full local suite when the host/time budget allows
python -m pytest tests/ -q --tb=short
```

Do not assume `make ci` is bit-for-bit identical to hosted CI. The current Makefile still differs from hosted blocking semantics in several places; [docs/ci.md](docs/ci.md) records the exact discrepancy and the authoritative hosted checks.

Native Linux containment evidence has additional host-capability requirements and is not proven merely because GitHub-hosted CI is green.

---

## Core principles

- **Trace truth** — the trace must describe what actually occurred, not what configuration implied should occur.
- **Durability before authoritative acknowledgement** — persistent state, decisions, and side-effect truth must survive interruption at their declared boundaries.
- **Contracted composition** — nodes communicate through declared envelopes, ports, schemas, and requirements.
- **Fail closed** — unavailable trust or containment prerequisites must not silently weaken the execution boundary.
- **Side-effect identity** — external actions keep stable operation identity across attempt, completion, failure, unknown state, recovery, and retry lineage.
- **Governed reuse** — reusable nodes retain policy, trust, side-effect, trace, and evaluation semantics across chains.
- **Evidence over configuration** — execution, recovery, provenance, and containment claims require proving runtime evidence.

---

## Documentation status

Older documents and release-specific files are intentionally preserved where they are historical evidence. A historical document is not automatically a current architecture description. `docs/frozen-surfaces.md` remains a historical v1 compatibility contract; use [docs/current-public-surfaces.md](docs/current-public-surfaces.md) for the current surface map.

For the exact implementation-state boundary, start with **[BASELINE.md](BASELINE.md)**.
