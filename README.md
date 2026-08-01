# NodeChain

**Autonomous AI systems from composable Harness Nodes**

> **Build a node once. Govern it forever. Reuse it everywhere.**

NodeChain is a platform for building autonomous AI systems from reusable "Harness Nodes" — composable, contract-bound, policy-governed, memory-aware, traceable units connected through typed ports.

📖 **[VISION.md](VISION.md)** — the canonical strategic document: what NodeChain is, what exists today, how the pieces fit, and where it's going.

## Research & Decision Assistant

The first production-grade chain. Given a complex research question, it:

1. **Parses** the query into a normalized research goal
2. **Plans** search tasks with domain-aware source routing
3. **Searches** 5 academic APIs (Semantic Scholar, arXiv, OpenAlex, CrossRef, PubMed)
4. **Ingests** and normalizes results into unified source records
5. **Evaluates** source quality using structured credibility signals
6. **Synthesizes** evidence into claims with citations
7. **Validates** claims through two-pass structural + consistency checks
8. **Classifies** risk and confidence levels
9. **Generates** a cited recommendation with confidence statement
10. **Decides** whether to write to governed memory
11. **Collects** a complete, auditable chain trace

All 12 nodes execute through a typed-port runtime with contract validation, bounded loops, a real human review gate, and governed memory writes.

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Run with mock provider (deterministic, no LLM/API needed)
nodechain run "Should we adopt RAG for policy QA?" \
  --provider mock --review-mode auto-approve --strict \
  --json data/demo_run.json

# Inspect the saved state
nodechain inspect <run_id>

# Reconcile trace against ledger
nodechain reconcile <run_id>

# Generate comprehensive report (with branch summary)
nodechain report <run_id> --output data/report.json

# View trace events
nodechain trace data/traces/<run_id>.json

# Run tests
pytest tests/ -v

# Validate all schemas
python scripts/validate_schemas.py
```

For a full walkthrough:
```bash
bash examples/demo_milestone_1.sh      # Linux/macOS
examples\demo_milestone_1.bat           # Windows
```

### Pause/Resume Demo (Human Review)

```bash
# Run with pause mode -- chain halts at review gate
NODECHAIN_MOCK_RISK_LEVEL=high nodechain run "high-risk query" \
  --provider mock --review-mode pause --json data/pause.json

# Inspect the paused state
nodechain inspect <run_id>      # shows "WAITING FOR REVIEW"

# Resume with approval
nodechain resume <run_id> --review-mode auto-approve

# Reconcile the resumed run
nodechain reconcile <run_id>    # clean
```

## CLI Command Matrix

NodeChain exposes **21 top-level commands** with **57 total commands**
(including subcommands) across six platform spines.

### Runtime Commands

| Command | Description |
|---------|-------------|
| `run` | Execute a chain blueprint |
| `inspect` | Show detailed state for a saved chain run |
| `reconcile` | Reconcile trace vs ledger audit |
| `resume` | Resume a paused or failed chain run |
| `report` | Generate a comprehensive run report |
| `trace` | View a chain trace in readable format |
| `trust` | Inspect trust enforcement for a run |

### Trust & Signing Commands

| Command | Description |
|---------|-------------|
| `audit-bundle` | Generate or verify a portable sandbox audit bundle |
| `attest` | Generate or verify a deployment attestation |
| `deploy-receipt create` | Create a deployment receipt from a gate evaluation |
| `deploy-receipt verify` | Verify a deployment receipt |
| `trust-store add-key` | Add a trusted public key (with purpose constraint) |
| `trust-store list` | List all trusted keys in the trust store |
| `trust-store migrate` | Migrate legacy keys with explicit purposes |
| `trust-store remove-key` | Remove a trusted key from the trust store |
| `trust-store snapshot` | Create a signed snapshot of the trust store |
| `trust-store verify` | Validate trust store integrity |
| `trust-store verify-snapshot` | Verify a trust store snapshot |
| `assurance` | Verify the entire assurance chain in one command |

### Registry & Node Commands

| Command | Description |
|---------|-------------|
| `registry list` | List all registered node packages |
| `registry inspect` | Show detailed info about a registered node |
| `registry lock` | Generate a registry lockfile |
| `registry verify` | Verify registry against lockfile |
| `registry publish` | Publish a certified package to the certified registry |
| `registry install` | Install a certified package (consumption gate enforced) |
| `registry resolve` | Resolve a package from the certified registry |
| `registry certified-list` | List certified registry entries |
| `registry certified-inspect` | Inspect a certified registry entry |
| `registry certified-verify` | Verify a certified registry entry |
| `registry deprecate` | Deprecate a registry entry |
| `registry revoke` | Revoke a registry entry |
| `node create` | Create a new node package from a template |
| `node validate` | Validate a node package at the given path |
| `node test` | Run package-local tests for a node package |
| `node check-compat` | Check node compatibility with a blueprint |

### Deployment & Operations Commands

| Command | Description |
|---------|-------------|
| `deploy` | Deploy via an adapter or verify a deployment |
| `release-history list` | List releases in the release history |
| `release-history verify` | Verify release retention and integrity |
| `release-history latest-known-good` | Show the latest known-good release |
| `release-history snapshot` | Create a signed release history snapshot |
| `release-history verify-snapshot` | Verify a release history snapshot |
| `drift check` | Check for deployment drift |
| `drift policy` | Drift policy management (sign, verify, register) |
| `drift remediate` | Perform governed drift remediation |

### Evaluation & Certification Commands

| Command | Description |
|---------|-------------|
| `eval run` | Run an evaluation suite |
| `eval sign` | Sign an evaluation report |
| `eval verify` | Verify a signed evaluation report |
| `eval suite` | Evaluation suite management (sign, verify, register) |
| `eval certify` | Create a certification from an evaluation report |
| `eval certification` | Certification management (sign, verify, revoke, inspect) |

### Explainability Commands

| Command | Description |
|---------|-------------|
| `evidence index` | Build an evidence index from source artifacts |
| `evidence query` | Query the evidence index with filters |
| `evidence timeline` | Build a chronological evidence timeline |
| `evidence sign` | Sign an evidence report |
| `evidence verify` | Verify a signed evidence report |
| `trace-replay run` | Replay a trace with 7-point verification |

### Configuration Commands

| Command | Description |
|---------|-------------|
| `presets` | List available policy presets |

### Exit Codes

| Code | Constant | Meaning |
|------|----------|---------|
| 0 | `EXIT_OK` | Success |
| 1 | `EXIT_RECONCILE_ERRORS` | Reconciliation errors / lockfile drift |
| 2 | `EXIT_NOT_FOUND` | Run not found |
| 3 | `EXIT_RECONCILE_RECOVERY` | Recovery required (side effects in unknown state) |
| 10 | `EXIT_RUN_VALIDATION` | Validation/governance failure |
| 11 | `EXIT_RUN_PAUSED` | Paused (review gate) |
| 12 | `EXIT_RUN_FAILED` | Chain execution failed |
| 13 | `EXIT_RESUME_NOT_RESUMABLE` | Not resumable |
| 14 | `EXIT_RESUME_FAILED` | Resume failed |
| 15 | `EXIT_TRUST_VIOLATION` | Trust invariant violation (strict mode) |

## Branch Scheduling

NodeChain supports four branch scheduling modes with configurable result policies:

### wait_for Modes

| Mode | Threshold | On Failure | Merge Scope |
|------|-----------|------------|-------------|
| `all` | All must succeed | Any fail -> block | All completed |
| `any` | >= 1 must succeed | All fail -> block | All completed |
| `first` | First success | All fail -> block | First only |
| `quorum` | count or ratio | < threshold -> block | Quorum winners only |

### Branch Policies

| Policy | Mechanism | After Success |
|--------|-----------|---------------|
| `allow_all` | asyncio.gather | All branches merge |
| `ignore_late` | asyncio.gather | Late outputs excluded |
| `cancel_on_first` | task.cancel() | Pending cancelled |
| `first_success_only` | task.cancel() | Cancelled + merge isolation |

### Post-Quorum Behavior

| Policy | Mechanism | After Quorum |
|--------|-----------|---------------|
| `cancel` | task.cancel() | Pending cancelled |
| `ignore_late` | Let finish, mark ignored | Late excluded from merge |
| `allow_all` | Let finish normally | All merge |

### Example (Quorum)

```yaml
joins:
  - join_id: evidence_join
    to_node: evidence_joiner
    from_branches: [bio, tech, med]
    wait_for: quorum
    quorum_count: 2
    cancellation_after_quorum: cancel
    merge_strategy: merge
```

## Loop Controls

| Control | Source | Strict Mode |
|---------|--------|-------------|
| `max_iterations` | Blueprint field | Always enforced |
| `entry_condition` | Declarative (regex) | Parseable required |
| `exit_condition` | Declarative (regex) | Parseable required |
| `max_cost_usd` | invocation_ledger (primary), trace_events (fallback) | Always enforced |

## Architecture

```
Query -> Goal Interpreter -> Task Planner -> Context Selector -> Search Tool
    -> Source Ingestion -> Quality Evaluator -> Evidence Synthesizer
    -> Claim Validator -> Risk Classifier -> Response Generator
    -> Memory Write -> Trace Collector -> Complete Trace
```

### 12 Harness Nodes

| # | Node | Type | Purpose |
|---|------|------|---------|
| 1 | Goal Interpreter | Model | Parse raw query -> research goal |
| 2 | Task Planner | Model | Decompose -> task plan + source routing |
| 3 | Context Selector | Deterministic | Per-node access grants |
| 4 | Search Tool | Tool | Multi-source domain-routed search |
| 5 | Source Ingestion | Deterministic | Normalize 5 API schemas |
| 6 | Source Quality Evaluator | Model | Structured credibility scoring |
| 7 | Evidence Synthesizer | Model | Deep reasoning + citation tracking |
| 8 | Claim Validator | Hybrid | Two-pass validation |
| 9 | Risk / Confidence | Hybrid | Scoring + review routing |
| 10 | Response Generator | Model | Cited recommendation |
| 11 | Memory Write | Deterministic | 5-stage governed write |
| 12 | Trace Collector | Deterministic | Complete audit trail |

### 5 Academic Search APIs

| API | Coverage | Key Signals |
|-----|----------|-------------|
| Semantic Scholar | Broad | Citation graphs, influence scores |
| arXiv | Math, Physics, CS | Preprints, LaTeX abstracts |
| OpenAlex | Broad | Concept tags, institutional data |
| CrossRef | DOI-based | Publisher metadata, retraction status |
| PubMed | Biomedical | MeSH terms, clinical trial IDs |

All free, no API keys required for basic access.

## Project Structure

```
src/nodechain/
  core/          # Platform primitives (envelope, contract, port, blueprint, state, policy, trace)
  runtime/       # 15 extracted components (orchestrator, scheduler, branch_executor, etc.)
  adapters/      # Model adapter + 5 search adapters + domain router + human adapter + ChromaDB
  memory/        # Governed memory subsystem (manager, write flow, dedup)
  validation/    # Schema validation + semantic validators + confidence calibration + port compatibility
  nodes/         # All 12 harness nodes + branch support nodes
  cli/           # 6 command-line interface modules

schemas/           # All JSON schemas (the runtime's law)
blueprints/        # 4 chain definitions (YAML)
ARCHITECTURE.md    # Full architecture report
examples/          # Demo scripts (golden path + CLI verification)
tests/             # 1230 tests across 65+ files
```

## Positioning

**NodeChain is:**
- A local developer/operator runtime for governed graph execution
- A contract-validated, crash-consistent execution engine
- A platform for building autonomous AI systems from composable nodes
- Testable end-to-end with deterministic mock providers
- Script-safe with structured exit codes for pipeline automation

**NodeChain is not yet:**
- A hosted platform or cloud service
- A distributed worker system
- Production-deployed (still in development)

**NodeChain now includes (v2.21.3):**
- Remote package install with governed trust protocol (v2.12–v2.13)
- Reference remote registry server (v2.14)
- Registry lifecycle governance with signer rotation (v2.15)
- Dependency graph trust resolution with DT-001 (v2.16)
- Capability resolution and governed node selection (v2.17)

## Key Principles

- **Contract validation at load time** — incompatible nodes caught before execution
- **Schema validation at runtime** — payloads checked against JSON Schema (strict mode via env var)
- **Typed ports** — every connection carries a semantic type with schema
- **Bounded loops** — max iterations + cost caps + declarative entry/exit + escalation paths
- **Durable cost accounting** — invocation ledger primary, trace events fallback
- **Complete branch scheduling** — all/any/first/quorum with 4 result policies
- **Human review gate** — real CLI pause/resume with 30-min timeout + interactive mode
- **8-type failure handling** — per-failure-type recovery strategies
- **Governed memory** — 5-stage write flow with policy, validation, and trace
- **Side-effect journaling** — operation-level identity with pre/post lifecycle
- **Trace truth rule** — no event claims execution unless it actually occurred
- **Port isolation** — nodes receive data through declared ports, not chain state peeking
- **Context integrity (v2.71)** — context truncation must preserve semantic unit boundaries (line boundaries for code, sentence/paragraph for text, record boundaries for structured data). A model can be wrong because the governed context substrate is wrong, not because the prompt is wrong.
- **Script-safe CLI** — structured exit codes for pipeline automation

## Tech Stack

- **Python 3.11+** with Pydantic v2
- **LIM (Local Inference Manager)** — default provider, connects to LM Studio via Tailscale VPN
- **OpenAI-compatible** — any provider supporting the OpenAI chat completions API
- **Mock** — zero-dependency adapter for testing and development
- **httpx** — async HTTP for all academic APIs
- **ChromaDB** — local vector store for documents + memory
- **SQLite** — chain state persistence (4 surfaces)
- **Docker Compose** — ChromaDB service
- **Rich** — formatted CLI output

## Test Coverage

```
1230 tests across 65+ test files:
  Runtime core:
    orchestrator, scheduler, invariant engine, branch executor,
    trace emitter, trace reconciler, step allocator, persistence,
    policy gate, review manager, failure manager, loop enforcer
  Branch scheduling:
    branch-join, wait_for=first, ignore_late, cancel_on_first,
    first_success_only, quorum, merge strategy
  Trust & sandbox:
    import/filesystem/subprocess/network enforcement,
    process isolation, child policy, environment minimization,
    cwd/temp isolation, trust summary, trust invariants, trust CI gates
  Package & registry:
    SDK, capabilities, lockfile, multi-node packages,
    registry-loaded, mixed-origin, policy enforcement
  Release gates:
    release guard, RC1 smoke tests, hardening tests,
    consolidation tests, sandbox demo
  Nodes + adapters:
    all 12 nodes, 5 academic search APIs, domain router
  Infrastructure:
    schema validation, semantic validators, memory flow,
    trace completeness, dedup, side-effect lifecycle
```

## Trust Model

NodeChain enforces a multi-layer trust runtime that controls what
third-party node packages can do at runtime.

### Trust Levels

| Level | Execution | Enforcement |
|-------|-----------|-------------|
| `built_in` | In-process | No restrictions |
| `local_trusted` | In-process | Import/filesystem/subprocess/network hooks active |
| `local_untrusted` | Subprocess-isolated | Full child-side enforcement + env filtering + cwd/temp isolation |
| `remote_untrusted` | Subprocess-isolated | Same as `local_untrusted` |

### Enforcement Surfaces

```text
Python-level (all platforms):
  1. Package Policy        (load boundary)
  2. Import Enforcement     (import hooks + preloaded denylist)
  3. Filesystem Policy      (open, pathlib, os.open/stat/listdir/mutation)
  4. Subprocess Policy      (Popen, run, call, async, os.system/popen)
  5. Network Policy         (socket, DNS, SSL, urllib, http.client)

Linux-only:
  6. Seccomp Syscall Filter (20 dangerous syscalls denied in child)
     Applied before untrusted module import.
     Denies: fork, vfork, clone, ptrace, mount, reboot,
             kexec_load, init_module, bpf, unshare, setns, etc.
```

All Python-level enforcers use contextvars for concurrency safety.

### Trust Invariants

Strict mode enforces seven structured compliance codes:

```text
INV-001  untrusted        → requires isolation_mode=subprocess
INV-002  untrusted        → requires child_policy_enforced=true
INV-003  subprocess       → requires env_filtered=true
INV-004  subprocess       → requires temp_dir_isolated=true
INV-005  locked mode      → requires lockfile_verified=true
INV-006  required profile → must be used (no downgrade)
INV-007  os_profile+Linux → requires syscall_filtering_enforced=true
INV-008  os_profile       → requires at least one OS enforcement capability
INV-009  cgroup limits     → must be enforced when requested
```

### Cgroup v2 Per-Invocation Resource Accounting (v1.3.1)

On Linux with cgroup v2, NodeChain creates a child cgroup per node
invocation, moves the subprocess into it, reads resource accounting after
execution, and cleans up. This provides per-node resource visibility:

- `memory.peak` — peak memory usage of the node subprocess
- `cpu.stat` — CPU time consumed
- `pids.peak` — maximum process/thread count

`cgroup_accounting_scope` distinguishes `"invocation"` (per-node) from
`"parent"` (container-level).

### Linux Seccomp Enforcement (v1.2.2+)

On Linux with seccomp available (libseccomp + pyseccomp), NodeChain applies
a seccomp profile to the child subprocess before importing the untrusted
node module. The profile denies 20 dangerous syscalls:

```text
Process creation:  fork, vfork, clone, clone3
Kernel modules:    init_module, finit_module, delete_module
Privilege:         ptrace, mount, umount2, reboot
Namespaces:        unshare, setns
Kernel attack:     bpf, perf_event_open, userfaultfd
Memory policy:     mbind, migrate_pages, move_pages
Boot:              kexec_load
```

**Bootstrap ordering** (child subprocess):

```text
Phase 1:  Import trusted SDK + create event loop
Phase 1b: Apply seccomp filter (Linux)
Phase 1c: Activate ALL Python enforcement (import+fs+subproc+net)
Phase 2:  Import untrusted node module (UNDER all enforcement)
Phase 3:  Execute node
Phase 4:  Report + deactivate
```

Seccomp is automatically enabled on Linux when the sandbox profile is
`os_profile`. It is reported in `TrustSummary` as:
`seccomp_enforced`, `seccomp_profile_name`, `syscall_filtering_enforced`.

### CLI Trust Commands

```bash
nodechain run --locked --strict --trust-check   # pre+post trust gates
nodechain run --sandbox-profile os_profile      # require OS sandbox
nodechain trust <run_id> --strict                # audit trust posture
nodechain reconcile <run_id>                     # cross-check trace
nodechain registry lock                          # generate lockfile
nodechain registry verify                        # verify provenance
```

### Honest Boundaries

NodeChain's sandbox operates at multiple levels:

```text
Layer 1 (strongest):  seccomp syscall filtering (Linux only)
Layer 2:              filesystem/subprocess/network Python enforcers
Layer 3:              import enforcement with preloaded denylist
```

What NodeChain provides:
- seccomp-based syscall filtering on Linux (20 dangerous syscalls denied)
- RLIMIT resource limits on Linux (CPU, memory, file size, processes)
- cgroup v2 per-invocation resource accounting and limit enforcement (Linux)
- Job Objects resource limits on Windows
- Python API interception on all platforms
- Process isolation for untrusted nodes
- Policy presets for operator-level sandbox posture selection

What NodeChain does NOT provide:
- Namespace-based filesystem isolation (planned)
- AppArmor security profiles (planned)
- Native extension / ctypes isolation (ctypes is in preloaded denylist)
- Protection against threads that bypass contextvars
- Protection against already-captured module references

For adversarial or completely untrusted code, use OS-level isolation
(containers, VMs) in addition to NodeChain's trust runtime.

### Policy Presets (v1.3.8+)

Operators select a sandbox posture via `--policy-preset`:

```bash
# Minimal: subprocess isolation only
nodechain run --blueprint my_chain.yaml --policy-preset minimal

# Standard: subprocess + seccomp syscall filtering (Linux)
nodechain run --blueprint my_chain.yaml --policy-preset standard_untrusted

# Production: subprocess + seccomp + cgroup limits (512MB, 50 pids, 2 CPU)
nodechain run --blueprint my_chain.yaml --policy-preset production_untrusted --strict --trust-check

# Hardened: production + network namespace + mount confinement (chroot)
nodechain run --blueprint my_chain.yaml --policy-preset hardened_untrusted --strict --trust-check
```

Blueprints can declare a preset:

```yaml
policy_preset: production_untrusted
```

CLI `--policy-preset` overrides blueprint declaration. Resolution order:
CLI → blueprint → default (none).

| Preset | Isolation | Seccomp | Cgroup Limits | Net NS | Mount Conf |
|--------|-----------|---------|---------------|--------|------------|
| `minimal` | subprocess | no | no | no | no |
| `standard_untrusted` | subprocess + os_profile | yes (Linux) | no | no | no |
| `production_untrusted` | subprocess + os_profile | yes (Linux) | 512MB / 50 pids / 2 CPU | yes | no |
| `hardened_untrusted` | subprocess + os_profile | yes (Linux) | 512MB / 50 pids / 2 CPU | yes | yes (chroot) |

## Status

**v3.5.1 — PID-Namespace Supervised Execution Hardening**

Native asynchronous supervised-protocol ownership with exact
`PTRACE_EVENT_EXEC` workload-start authority, launcher/namespace-init
topology, bootstrap PID-namespace verification, and namespace-wide
terminal cleanup. Qualified Linux only; fails closed elsewhere.
See [CHANGELOG.md](CHANGELOG.md) for details.

**v3.5.0 — Governed Retry-Authorized Side-Effect Execution**

Stage 1 + Stage 2 proven. Two domain chains, six releases, 6,131 tests.

- **Research & Decision Assistant** (12 nodes): search → synthesis → validation → cited output
- **Code Review Assistant** (10 nodes): review → patch proposal → sandbox test → classification
- **Baseline comparison**: 7/7 gates — governance > flat agent on verifiable auditability
- **Patch governance**: proposals as typed-port artifacts, temp-workspace validation, risk classification
- **Governed execution**: bounded pytest in isolated temp workspaces, code_execution as declared side effect

Contract-validated, crash-consistent, governed local trust platform
with durable execution, complete branch/loop semantics, local SDK/registry,
package policy, lockfile provenance, Python-level API sandboxing,
process-isolated untrusted execution, child-side enforcement, trust
invariant reconciliation, CI-scriptable trust gates, frozen v1 public
surfaces, granular OS sandbox capability reporting, **Linux seccomp
syscall filtering**, **validated Linux cgroup v2 per-invocation
resource accounting and limit enforcement**, **behavioral pressure
evidence for memory, CPU, and PID controls**, and **operator-facing
policy presets**.

Proven on Proxmox CT 801 (Ubuntu 24.04, cgroup v2):
- Per-invocation child cgroup created, process moved, accounting read, cleaned up
- memory_peak: 18.1 MB, cpu_usage: 0.255s, pids_peak: 1 for echo node
- Platform-neutral INV-008: at least one OS capability required for os_profile
syscall filtering** for untrusted child execution.

All v1.0.0 public surfaces remain frozen. See [docs/frozen-surfaces.md](docs/frozen-surfaces.md).

1435/1435 tests passing (Windows). 1433/1433 (Linux). 7+ blueprints. 5 registry packages.
49 git tags (v0.1.0 through v1.3.3).

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full component map.
