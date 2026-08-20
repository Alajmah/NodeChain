# Changelog

All notable changes to NodeChain are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Fixed

- **H0.1 — Research Workspace CLI descriptor/finalization correction.**
  `nodechain research review` reconstructed `WorkspaceRunner` manually on the
  fresh-process resume path, leaving `runner._run_descriptor` unset. Terminal
  `resume()` finalizes the bundle only when `_run_descriptor` is present, so
  CLI review/resume silently skipped terminal C5 bundle finalization. The
  command now reconstructs through `WorkspaceRunner.from_descriptor(desc)`.
  CLI-level regression proof added in
  `tests/research/test_cli_review_finalization.py` (approve, reject, revise,
  injected finalization failure, identity stability). No change to WP 5.1/WP
  5.2 bundle semantics, resume(), finalize_bundle(), or C5 terminal-status
  classification.

### Changed

- **H0.3 — Legacy composition execution is now fail-closed.**
  `runtime/chain_orchestrator.py` previously hosted a lightweight composition
  executor (`execute_sub_chain`, `orchestrate_composition`) that constructed
  its own `InvocationEnvelope` and called `await node.execute(envelope)`
  directly, bypassing the canonical `Orchestrator` and every governed
  authority (policy, trust admission, side-effect journal, invocation ledger,
  durable state, trace, recovery, review, validation, containment). All three
  execution surfaces now fail closed with stable reason
  `governed_composition_backend_required`:
  `execute_sub_chain()` and `orchestrate_composition()` raise
  `GovernedCompositionRequired`; `SubChainStep.execute()` returns an
  unsuccessful `EnvelopeResponse` before registry access. No `BaseNode.execute()`
  call expression remains in the module (AST-guarded). `nodechain compose --plan`
  exits 10 (`EXIT_VALIDATION`) before any registry/package loading;
  `nodechain compose --plan --json` emits a parseable JSON error object.
  `nodechain compose validate --plan` remains a supported read-only surface.
  Pure composition-plan data utilities (`SubChainSpec`, `CompositionPlan`,
  `SubChainResult`, topological ordering, digest, aggregation) are retained.
  Adversarial proof in
  `tests/research/test_compose_execution_fails_closed.py` (sentinel node,
  registry/package monkeypatching, AST guard, JSON parseability, positive
  validate proof). Governed multi-chain composition is deferred to a
  post-Horizon-0 design.

- **H0.4 — Singular durable trace-emission authority.**
  The orchestrator previously had 11 bypass sites that appended trace events
  directly to `ChainTrace` (in-memory only, no durability), and the existing
  `_emit()` constructed two separate objects with no shared identity. H0.4
  establishes `_record_trace_event(event)` as the ONLY production method
  allowed to call `ChainTrace.add_event()`. Durable append happens first
  (via `persistence.append_trace_event`, carrying the event's own `event_id`
  and timestamp); the in-memory append happens second with the exact same
  `TraceEvent` object. All 11 former bypass sites (node lifecycle, chain
  lifecycle, validation events, ReviewManager callback, both controllers)
  route through `_emit()` or `_record_trace_event`. `TraceEmitter` and
  `ContractPreflightController` require the injected authority at
  construction — no in-memory-only fallback. `RecoveryService` operator
  and audit trace events are durable trace producers outside the live-trace
  boundary: they write through `append_trace_event()` or the atomic
  `save_with_event()` path (for terminal CANCEL_RUN / FAIL_RUN), carry
  first-class `trace_event_id`, and participate in the same
  `get_trace_events()` projection. Schema: `state_events` gains
  `trace_event_id TEXT NULL` + partial unique index. AST guard enforces
  exactly one `.add_event()` call in all of `src/nodechain/`. Adversarial
  proof: 13 cases in `tests/research/test_singular_trace_authority.py` plus
  1 AST-guard test in `tests/research/test_trace_authority_guard.py`
  (14 total). No change to replay, state-transition semantics, or
  `save_with_invocation`.

- **H0.5 — Authoritative state-transition boundary.**
  Authoritative `ChainState` transitions previously mutated the accepted
  live state before (or without) their owning commit: invocation outputs,
  cursors, and branch state were written pre-commit; terminal completion
  was acknowledged by a durable `CHAIN_COMPLETED` event before its state
  committed (a failed save could then produce durable COMPLETED and FAILED
  events for one run); `_fail_chain` never persisted the failed status;
  review transitions mutated loaded state before snapshot; and failed
  commits consumed revisions on the live object. H0.5 establishes one
  accepted-state rule: construct a candidate copy
  (`ChainState.transition_candidate()`), durably commit, then adopt and
  acknowledge; a failed commit leaves the accepted state untouched with
  no revision consumed. Invocation transitions (output, completed-step,
  cursor, branch state) are proposals owned by
  `PersistenceCoordinator.commit_invocation_success`; state-asserting
  lifecycle transitions (chain start, terminal completion, runtime
  failure, review pause/decision) commit their candidate state and
  authoritative trace row in ONE SQLite transaction
  (`StateManager.save_with_trace_event`), so a completion-commit failure
  can no longer durably produce `CHAIN_COMPLETED` and the contradictory
  COMPLETED-then-FAILED pair is unproducible. Review decisions are
  outcome-specific: approve/revision commit running; reject/timeout
  commit their terminal failed outcome directly with the decision event;
  the governed decision receipt rides as a committed metadata proposal.
  Recovery CANCEL/FAIL remain their existing operator-transition authority
  while becoming candidate-safe and adopting the committed revision.
  Budget pause/approve and route fallback are candidate-safe checkpoints.
  `_record_trace_event` gains an already-durable mode for lifecycle
  events; the H0.4 singular `ChainTrace.add_event()` authority and AST
  guard are unchanged. The review-resume delegation re-entry is retired
  (it rebuilt the live trace and discarded the acknowledged decision
  event); the `pending_review_event` deferral is retired with it.
  Adversarial proof: 21 tests in
  `tests/research/test_state_transition_authority.py` (candidate
  isolation; checkpoint/invocation/lifecycle/branch failure semantics;
  reject never passing through running; failed review commit preserving
  waiting state; recovery revision adoption). Resume control-marker
  removals (`review_revision_target`, `pending_loop_back`) are likewise
  candidate-owned: a failed commit leaves the marker accepted in live,
  durable, and fresh-process state with no revision consumed. The rule
  applies to authoritative/accepted transition boundaries; scheduler-local
  provisional preparation is not itself an authoritative transition. No
  H0.4 trace redesign, no RecoveryService redesign, no replay.

- **H1.2 — Research operator experience.**
  Adds the read-side operator CLI on top of the H1.1
  ResearchWorkspaceSnapshot: `research open` (workspace overview),
  `research runs` (listing), `research inspect` (per-section drill-down
  with availability states and the governed recovery handoff),
  `research verify` (terminal-bundle integrity through BundleReader),
  `research compare` (side-by-side run comparison), and `research
  export` (verified-bundle copy; never regenerates). Every new command
  supports `--json`. `research run` gains an additive `--workspace DIR`
  option making workspace creation/targeting coherent (first run into
  DIR creates the workspace; subsequent open/runs/inspect observe the
  same root through the existing WorkspaceRunner composition path).
  All new commands are read-only through StateManager(read_only=True)
  — the DB-hash invariant proves zero persistence writes across all
  observation commands. Existing `research run` and `research review`
  authority paths remain unchanged and backward compatible. H1.2 is
  scoped as CLI operator experience + stable machine-readable JSON
  contract; API/UI product surfaces consume this contract in a
  successor outcome.

- **H1.1 — Workspace object model.**
  Introduces `nodechain.research.workspace` with a frozen,
  versioned `ResearchWorkspaceSnapshot` — the stable user/product model
  for a research workspace. `open_workspace(workspace_dir, run_id=None)`
  discovers all runs under a workspace root, selects one (explicitly or
  deterministically by the most recently created descriptor), and
  projects the authoritative runtime/evidence records into an immutable
  snapshot. The Workspace is a projection, not a truth store: it never
  executes nodes, transitions ChainState, writes trace, resolves
  recovery, or maintains a competing lifecycle. Every roadmap concept is
  represented: objective (from the verified RunDescriptor), plan,
  runs (all discoverable run summaries), sources, qualified sources
  (with source_id/hash/artifact_ref preserved exactly), evidence,
  claims, citations, uncertainties, faults (from immutable fault
  records), recovery (side-effect ledger + durable recovery decisions),
  review decisions (runtime attempts + CLI submissions + resume
  outcomes), trace (via StateManager.get_trace_events), and terminal
  verified bundles (via BundleReader integrity verification only).
  Three explicitly separated statuses replace any single overloaded
  `status` field: `execution_status` (runtime ChainState status),
  `research_outcome` (product/evidence outcome from the verified
  bundle), and `bundle_status` (absent/verified/invalid). Each major
  section carries its availability state — `not_available`,
  `live_partial`, `live_current`, `terminal_verified` — so absence is
  never fabricated as empty completed data. Read-side helpers added to
  `run_descriptor.py`: `list_run_ids()`, `list_run_descriptors()`,
  `list_review_records()`, `list_outcome_records()`. Adversarial test
  matrix (A–J) covers empty workspace, descriptor-only run, active-run
  projection, paused-for-review (corpus-dependent), fault preservation,
  qualified-source linkage, verified terminal bundle, tampered-bundle
  rejection, multi-run visibility with deterministic selection, and the
  read-only invariant (no runtime revision, trace, DB row, descriptor,
  fault record, or bundle mutation across repeated projections).

- **H0.6 — Deployment profile truth.**
  Establishes `docs/deployment-profiles.md` as the canonical
  deployment-profile authority: the six-profile matrix (trusted local
  development, GitHub-hosted CI, privileged Linux verification, generic
  POSIX untrusted execution, Windows control-plane, and the future
  managed/delegated profile recorded as not implemented), each with
  intended use, host prerequisites, execution backend, enforced
  controls, failure behavior, qualification evidence, and hard
  not-claimed limits. The load-bearing distinction is recorded once:
  trust identity says what the workload is; the deployment profile
  decides whether a qualified backend exists to execute it. Deferred
  H0.2 deployment truths receive explicit dispositions —
  editable/source-backed installs and custom-prefix interpreter
  layouts are unsupported under mount confinement and fail closed;
  requested cgroups are refused before start; `WNOWAIT` is qualified
  only on the Linux family the suites run on; the host `package_root`
  pathname is informational in the trusted child context; missing
  privileges or a missing seccomp binding fail closed before workload
  start; Windows containment is documented as unavailable rather than
  equivalent. The pre-H0.2 T3-fence story is retired from
  `README.md`, `docs/linux-deployment.md` (rewritten as the Linux
  operational appendix around the now-active supervised route), and
  `docs/ci.md`; stale implementation-baseline pins in those three
  documents are advanced to the H0.2 implementation squash. The
  external-verification native-sandbox containment sentence now names
  the four proven v2.78 primitives (mount confinement, network
  namespace, PID/procfs isolation, seccomp) instead of implying
  cgroup enforcement the displayed evidence does not identify.
  ARCHITECTURE/BASELINE/public-surfaces/documentation-authority link
  to the canonical matrix rather than maintaining competing detail.
  Documentation only — no runtime change; H0.2 sealed evidence is
  reused unchanged per the frozen H0.6 plan.

- **H0.6 closure — Horizon 0 CLOSED.** Pins the H0.6 truth baseline
  to `78f98252173eb38d4284ed92f0fd3343c5c5ce21` (the deployment-profile
  closure squash), closes correction-queue item 7, advances the
  descriptive document pins, and records Horizon 0 closed in
  `ROADMAP.md`: H0.1 Research CLI authority, H0.3 singular execution
  authority, H0.4 singular trace authority, H0.5 authoritative
  state-transition boundary, H0.2 POSIX supervised untrusted routing,
  and H0.6 deployment profile truth are all sealed. Post-merge
  qualification of the H0.6 truth squash: CI 10/10 and Publication
  Tree 2/2 on `78f9825`. Horizon 1 begins with the Workspace object
  model.

- **H0.2 — Supervised untrusted execution routing (T3).**
  Ordinary POSIX `local_untrusted` / `remote_untrusted` invocation now
  routes through the supervised backend as the single spawn/lifecycle
  authority: the legacy POSIX spawn body is unreachable for untrusted
  trust levels and no try-supervised-except-legacy fallback exists
  under any condition. The frozen outcome matrix maps supervisor truth
  into the compatibility shape (parent/setup failures -1;
  supervisor-existed-but-unconfirmed 126; not-started vs started-failed
  discrimination; timeout; output-cap; SIGSYS→seccomp-kill exit -31;
  cleanup-dominates), with the `supervised_execution` evidence
  projection on success AND failure. Containment boundaries qualified:
  read-only bind mounts (`/package` and all runtime extras via
  `MS_REMOUNT|MS_BIND|MS_RDONLY`, `/tmp` writable, fail-closed on any
  refused remount); a durable five-set capability boundary (bounding
  drops while `CAP_SETPCAP` is effective, ambient clear, empty
  effective/permitted/inheritable via libcap, read-back verification of
  every dangerous bit across all five sets before
  `enforcement_verified`, proven against deliberately seeded
  ambient+inheritable `CAP_SYS_CHROOT`/`CAP_SYS_ADMIN`); trust-rooted
  interpreter startup (workload `python -I -c`; child SDK imports from
  the resolved trusted installation, never the caller cwd; supervisor
  `python -P -m`; bootstrap `python -P -c`; adversarial fake-cwd
  package proof); real requested-seccomp enforcement when a filter
  binding exists (available→enforced→verified→exec-confirmed chain;
  kernel SIGSYS denial via a denied `os.fork` workload; binding
  preloaded before the confinement chroot because
  `ctypes.util.find_library` cannot resolve inside it); workload
  equivalence preserved (nested module paths under an ancestor package
  root, module-outside-root fails closed in the parent,
  TEMP/TMP/TMPDIR advertise the workload-visible `/tmp`, trusted
  seccomp flags projected into `EnvelopeResponse.metadata`). The
  supervisor's metadata-reader probe distinguishes ptrace stops from
  terminal child death (si_code-based), and the bootstrap blocks
  SIGCHLD noise (seccomp-binding import vforks) with the original mask
  restored before workload exec. On hosts without the privileges the
  topology needs, the route fails closed before workload start —
  hosted CI asserts that truth. Adversarial proofs on privileged
  Linux include the classic double-chroot escape (kernel-denied with
  and without optional seccomp), the sacrificial two-stage
  confinement→capdrop→exec→`chroot` EPERM probe, adversarial
  `sitecustomize`/PYTHONPATH startup hooks (inert), and the fake
  `nodechain` package in the parent cwd (never imported).
  Qualification at merge: privileged structural set 374 passed /
  72 skipped / 0 failed; Windows full suite 7438 passed / 0 failed;
  exact-head CI 10/10 and Publication Tree 2/2 at both the PR head
  (`18dc2a7058db19a98831e239715ac3026f49e973`) and the master squash
  SHA (`068120f6a46797182d33e100b5dadfc8ccc77b4f`). Deployment-profile
  truths deferred to H0.6: editable/source-backed installs and
  custom-prefix interpreter layouts fail closed under mount
  confinement; no cgroup support on the supervised route (requested
  cgroups are refused before start with `supervised_cgroup_unsupported`).

## [3.6.0] — First Public-Era Release

**Release type:** feature + governance (minor).

v3.6.0 is the first release produced entirely from the clean public
canonical history. It introduces flat-result provenance versioning,
establishes the public development governance model, and hardens the
hosted CI pipeline.

### Added

- Flat-result provenance versioning v1 (PR #3): explicit versioned
  provenance contract for search-result payloads, with compatibility
  handling for version 0 and pre-version payloads, strict RFC 3339
  timestamp validation, and adversarial regression tests.
- Public development governance documents (PR #4): solo-maintainer
  operating policy, release checklist, and emergency admin bypass
  procedure.
- Runtime JSON schemas are included in the wheel under
  `nodechain/schemas/`. `SchemaValidator` supports both installed-package
  and source-tree layouts. Publication Tree validates schema availability
  from the installed wheel.

### Changed

- Eliminated 16 Ruff F821 undefined-name findings across 8 files
  (PR #6), including two genuine runtime bugs (AuthorizationResult
  and Panel imports).
- Made Ruff lint a blocking gate (PR #7): removed `--exit-zero`,
  renamed step from advisory to blocking.
- Refreshed pinned GitHub Actions to checkout v7.0.1 and
  setup-python v7.0.0 (PR #9), resolving Node.js 20 runtime
  deprecation warnings.

### Governance and release assurance

- Public repository transition from contaminated private history
  through clean tree-only republication.
- Branch protection: PR required, 12 hosted checks enforced, linear
  history, no force pushes, no branch deletion.
- Windows test timeout increased to 90 minutes (PRs #5, #8) to
  accommodate hosted-runner performance variability.
- Twelve required status checks registered in branch protection (P2-G1).

### Compatibility and boundaries

- Current-version provenance payloads (version 1) require complete
  provenance fields; incomplete current-version records fail closed.
- Legacy (version 0) and pre-version payloads remain supported
  through the compatibility schema.
- `O_BINARY` correction for Windows/MSVC text-mode corruption of
  cryptographic key material (F2, F3).
- CI-H1 loader-environment correction for relocated Python builds
  (PR #1): `LD_LIBRARY_PATH` preserved across `execve` boundaries.

### PR arc

| PR | Description |
|----|-------------|
| #1 | CI-H1: preserve loader environment across execve |
| #2 | Public-CI portability: advisory lint, UTF-8 encoding fixes |
| #3 | FPV1: flat-result provenance versioning v1 |
| #4 | Public development governance |
| #5 | Windows timeout 45 → 60 |
| #6 | F821 baseline cleanup |
| #7 | Blocking Ruff gate |
| #8 | Windows timeout 60 → 90 |
| #9 | Node 24 pinned Actions refresh |

### Known boundaries

- Windows hosted-runner test duration varies (25–60+ minutes);
  sharding is deferred.
- `slow-shard-2` contains capability-sensitive native-security tests
  that may skip on hosted runners lacking specific kernel features.
- The Governed Research Workspace product proof is not shipped in
  this release.

---

## [3.5.1] — PID-Namespace Supervised Execution Hardening

**Release type:** production hardening (patch).

v3.5.1 hardens the sandbox execution path with ownership-complete native
asynchronous supervised execution. It does not introduce a new product surface
or change any public API. All supervised-execution production code lives behind
the existing identity-gated untrusted-node boundary.

### Process topology

The supervised path is built on a strict three-process topology. The
NodeChain parent spawns an external launcher **S**; **S** unshares a PID
namespace and forks the namespace-init **I**; **I** forks the bootstrap
**B**; **B** verifies the namespace and execves the workload in place.

```
NodeChain parent
└── S — external launcher; host session/process-group leader
    ├── unshare(CLONE_NEWPID)
    ├── fork I
    ├── validate I identity and topology proof
    └── send exact release token
        └── I — namespace PID 1; tracer and namespace reaper
            └── B — bootstrap; namespace PID > 1, parent PID 1
                ├── verify namespace identity
                ├── PTRACE_TRACEME
                └── execve workload in place
```

**S never enters the namespace** and never execves the workload. **I** is the
first process forked inside the new namespace and becomes namespace PID 1.
**B** is namespace PID > 1 with parent PID 1, and is the only process that
calls `execve` on the workload.

### What changed

**R3 — native asynchronous lifecycle ownership.**
The supervised execution session is owned by an event-loop-bound lifecycle
module (`supervised_exec_session`). It owns the supervisor process handle,
the protocol transport (one event-loop-owned FD reader), the stored PGID
(never rediscovered), the config/stdout/stderr tasks, and absolute execution
and cleanup deadlines. Natural protocol drain precedes forced stop; cleanup
deadlines are monotonic boundaries with reserved TERM and KILL windows.

**R3 — exact `PTRACE_EVENT_EXEC` workload-start authority.**
B calls `PTRACE_TRACEME` and later execves the workload in place. I arms
`PTRACE_O_TRACEEXEC` and observes `PTRACE_EVENT_EXEC`. That exact event is the
sole workload-start authority. Pre-exec primitives are bootstrap events, not
workload-start. If B dies before `PTRACE_EVENT_EXEC`, the workload is reported
as not started regardless of any other signal.

**S3.2 Task 2 — PID-namespace topology primitive and proof.**
A standalone module (`pid_namespace_topology`) provides the typed
`PidNamespaceTopologyProof`, the `CLONE_NEWPID` unshare primitive, and
fail-closed `/proc` readers. The proof encodes the exact relationships:
launcher PID namespace != child PID namespace, launcher
`pid_for_children` == child PID namespace, launcher PGID == launcher host
PID (session-leader invariant), and init PGID == launcher PGID (shared host
process group). Malformed, missing, or inconsistent `/proc` evidence raises
a typed exception — no `None` fallback, no cached identity.

**S3.2 Task 3 — S/I split and identity-gated release.**
S is spawned by the NodeChain parent with `start_new_session=True`. S calls
`unshare_pid_namespace()`, forks exactly one child I (which becomes namespace
PID 1), reads I's private identity, calls `build_topology_proof()`, then
releases I through an exact gate token. I does not enter `supervisor_main`
until the gate is opened. This split keeps S outside the child PID namespace
and establishes I as namespace PID 1, tracer, and reaper. The exact release
gate prevents I from entering `supervisor_main` until S has accepted I's
identity and topology proof. B is forked and may exec the workload only
after that release.

**S3.2 Task 4 — B namespace verification before `PTRACE_TRACEME`.**
Before calling `PTRACE_TRACEME`, B verifies `getpid() > 1`,
`getppid() == 1`, and that `/proc/self/ns/pid` matches the namespace
identity accepted by S's topology proof. Any ambiguous or out-of-contract
status causes bootstrap to fail closed with a typed reason, before any
ptrace call. Only after verification does B call `PTRACE_TRACEME` and
later `execve` the workload.

**S3.2 Task 5 — I-owned namespace-wide cleanup with `ECHILD` proof.**
Terminal cleanup runs inside I (namespace PID 1). I performs a bounded
namespace-wide `kill(-1, …)` sequence (CONT → TERM → KILL with reserved
reap windows between) and reaps children. I reports cleanup success only
after `ECHILD` — `waitpid(-1, WNOHANG)` raises `ChildProcessError`,
proving no descendant of any depth remains to be reaped by the namespace
init. Before any `kill(-1, …)`, I verifies its own identity:
`getpid() == 1`, `getppid() == 0`, and `/proc/self/ns/pid` matching the
accepted proof. If the guard fails, no namespace-wide signal is sent and
cleanup returns `False`.

**R3 — independent host process-group containment.**
The NodeChain parent separately owns host process-group containment. After
I's terminal proof, the parent probes the stored supervisor PGID with
`os.killpg(pgid, 0)`; `ESRCH` (the group does not exist) is the quiescence
proof. This authority is independent of I's namespace cleanup success — a
leaked supervisor-side PGID is detected even when the namespace reports
empty.

**Identity-gated release.**
The supervised path is reachable only through the identity-gated
untrusted-node boundary. No public API exposes supervised execution.

**H2 integration, end-to-end, and adversarial verification.**
A 12-case production-path matrix exercises protocol failure, output
limit, timeout, surviving descendants, SIGTERM-ignoring descendants,
SIGSTOP descendants, and double-fork orphans. The H2 stress campaign
(295 runs) repeatedly exercised each descendant and terminal-cleanup
class. H2 acceptance closes the supervised-execution hardening story
within the scope of the qualified Linux environment.

**Qualified Linux capability requirements.**
The supervised path requires a host with PID namespaces,
`/proc` topology inspection, `ptrace TRACEEXEC`, `seccomp`,
process-group signaling, and root (or equivalent) capabilities to
unshare a PID namespace and ptrace a child.

**Fail-closed behavior when required capabilities are unavailable.**
Outside the qualified Linux environment, the supervised path fails
closed. It does not silently degrade to a less-contained fallback.

### What this release does NOT claim

- It does not claim universal Linux compatibility. The supervised path
  is qualified only on Linux hosts that meet the capability list above.
- It does not claim complete hostile-code containment. It claims that
  the supervised protocol is ownership-complete within the qualified
  environment.
- It does not claim bare-metal verification until Task 3 supplies that
  evidence.

### Test surface

- Targeted supervised-execution gate (307 cases).
- 12-case production-path end-to-end matrix.
- H2 integration and stress evidence.
- Characterization locks for the R3 invariants.

---

## [3.5.0] — Governed Retry-Authorized Side-Effect Execution

**Release type:** production feature (major).

v3.5.0 implements governed retry-authorized side-effect execution. An operator
who previously issued `safe_to_retry` (v3.3) can now execute that retry through
`EXECUTE_RETRY_AUTHORIZED`, producing a child attempt that enters the normal
side-effect lifecycle (`planned → started → completed | failed | unknown`). The
original `retry_authorized` row remains immutable history.

### What changed

**Schema + migration (T1):**
- Lineage columns on `side_effect_ledger` (`parent_side_effect_key`,
  `root_side_effect_key`, `retry_ordinal`, `recovery_decision_id`,
  `capsule_id`, `capsule_status`, `execution_claim_id`,
  `dispatch_attempted_at`, `claim_acquired_at`, `claim_expires_at`).
- New tables: `side_effect_replay_capsules`, `recovery_execution_actions`,
  `run_encryption_keys`.
- `retry_authorized → started` removed from `LEGAL_TRANSITIONS` (INV-008).
- Legacy rows classified `capsule_status = 'legacy_unavailable'`.

**Capsule system (T2):**
- KEK → per-run DEK → capsule encryption hierarchy (AES-256-GCM).
- Proactive capsule persistence at `started` time via one authoritative
  store operation (`start_side_effect_with_capsule`).
- Capsule retention tied to lineage closure (INV-016).

**Adapter identity + dispatch interceptor (T3):**
- `RecoveryDispatchGuard` wraps the actual adapter at the `search()`
  boundary — NOT a pre-call journal gate.
- Fresh adapter instances from trusted class registry (no global cache).

**Coordinator + envelope + lineage (T4):**
- `SideEffectRetryCoordinator` owns the full T6 execution protocol.
- Deterministic child keys (`make_retry_side_effect_key`).
- Fencing tokens + heartbeat for exclusive dispatch ownership.

**RecoveryService + parent immutability (T5):**
- `EXECUTE_RETRY_AUTHORIZED` recovery action + RBAC.
- Transactional parent-lineage guard (parent permanently immutable).
- Recovery-only CAS repair for expired children.
- Batch exclusion (EXECUTE_RETRY_AUTHORIZED rejected by batch).

**RecoveryService wiring (T6):**
- `RecoveryService.apply_action()` delegates to the coordinator.
- Governance profile wiring.
- Pre-durable action path (child + action row allocated BEFORE dispatch).

**Lineage projection + classifier + reconciler (T7):**
- `classify_retry_lineages()` per-parent projection.
- Boundary-aware classifier (dispatch boundary is the truth divider).
- Reconciler SE-R6 checks for retry-authorized lineage integrity.

**CLI composition + three-truth rendering (T8):**
- `recover execute-retry-authorized` Click command.
- Three-truth outcome rendering: node invocation, side-effect status,
  operator action outcome, dispatch occurrence, chain status.

**Metrics + deletion/purge gate (T9):**
- DB-backed recovery metrics (15-metric vocabulary, three producers).
- `RunDeletionService`: three independent gates (existence, terminal status,
  lineage closure), `BEGIN IMMEDIATE` locked recheck, atomic 16-table purge,
  key invalidation (X'' soft tombstone), global `run_purge_audit` tombstone.
- Post-purge metric resurrection prevention.
- Dashboard recovery-metrics collector + full rendering wiring.
- `trace_errors` projected into snapshot and rendered in `recover inspect`
  (red section) and `recover list` (Trace Health column).

### What did NOT change

- No autonomous retry scheduling.
- No policy-engine-triggered execution.
- No general `RETRY_STEP` redesign.
- No normal resume bypass.
- No arbitrary whole-node replay.
- No multiple children from one decision.
- No downstream chain routing from retry children.
- No validator relaxation.
- No capsule backfill for legacy rows.
- No batch retry execution.

### Tests

- 58 T9 tests (metrics + deletion gate).
- 235 v3.5 cluster tests (T6–T9 + recovery + dashboard).
- Characterization tests (`test_retry_authorized_characterization.py`) verify
  v3.4 behavior is intentionally changed (e.g., `retry_authorized → started`
  now rejected).

---

## [3.4.0] — Retry-Authorized Execution Design + Characterization

**Release type:** design study + characterization (no production behavior change).

v3.4.0 freezes the design truth for retry-authorized execution and characterizes
the current gap. v3.3 introduced `safe_to_retry → retry_authorized` as a
recorded-but-unexecutable state; v3.4 defines how an authorized retry should
execute (two-row lineage model) and locks the current behavior with tests so
the v3.5 implementation cannot silently change it.

**What changed**
- New design study: `docs/design/retry-authorized-execution.md`. Defines the
  two-row lineage model: the original side-effect row stays `retry_authorized`
  (historical record of the operator's authorization); a retry execution
  allocates a NEW child attempt key that enters the normal lifecycle
  (`planned → started → completed | failed | unknown`). The existing
  `retry_authorized → started` store transition is rejected for the original row.
- New characterization: `tests/test_retry_authorized_characterization.py`
  (6 tests) proving retry_authorized is authorization-only (not execution),
  resume does not transition it, RETRY_STEP is side-effect-unaware,
  `_journal_one` cannot unstick it, no child lineage exists today, and it is
  not treated as completed.

**What did NOT change**
- No production behavior change. No `EXECUTE_RETRY_AUTHORIZED` implementation.
- No run()/resume() control-flow change.
- No observed-completion validator change.
- No new trace event type.

**Tests**
- New: `tests/test_retry_authorized_characterization.py` (6 characterization tests).

**Version bump:** 3.3.0 → 3.4.0.

## [3.3.0] — Operator Side-Effect Recovery Decisions

**Release type:** governed operator resolution for crash-window unknown side effects.

v3.3.0 wires governed operator resolution for crash-window `unknown` side
effects. Operators can list unknown effects (`recover list-unknown`) and
resolve them (`recover resolve-side-effect`) through explicit recovery
decisions that atomically record authority and transition the side-effect
ledger. This closes the gap surfaced in v3.1: crash-window `unknown` effects
were visible but not actionable — the write machinery existed but had no
production caller, and the operator surface had no side-effect-resolution action.

**What changed**
- `SideEffectLedgerStore.resolve_side_effect_recovery_decision_transactional` —
  a new atomic store method that records a recovery decision AND transitions
  the ledger out of `unknown` in ONE transaction (plain INSERT, not
  INSERT OR REPLACE; PRIMARY KEY enforces decision_id uniqueness). Avoids the
  dangerous partial state where a decision exists but the ledger stays unknown.
- `StateManager.resolve_side_effect_recovery_decision` — validated facade:
  maps decision values to target statuses, enforces evidence requirements
  (`verified_completed` requires external_reference OR response_hash; others
  require reason), generates a UUID decision_id, pre-checks status==unknown
  for clean errors, delegates to the atomic store method. Existing
  `record_recovery_decision` and `update_side_effect_status` preserved unchanged.
- `RecoveryAction.RESOLVE_SIDE_EFFECT` — joins the governed recovery boundary
  (authorize → delegate → emit → record). RBAC: **operator only**. Side-effect
  resolution is a truth-claim about external state, distinct from flow-control
  recovery actions (resume/retry/cancel); finance/admin are rejected for this
  action specifically. The delegate calls the StateManager facade directly
  (ledger-layer, no orchestrator re-execution).
- CLI: `nodechain recover list-unknown --run-id` and
  `nodechain recover resolve-side-effect --run-id --side-effect-key --decision
  --reason [--external-reference] [--response-hash]`.
- The recovery classifier flips from `CRASH_NEEDS_OPERATOR` to
  `CRASH_RECOVERABLE` once an unknown effect is resolved; SE-R3/R4/R5
  reconciler invariants hold against the resolved ledger.

**What did NOT change**
- No autonomous/automated recovery (operator authority only).
- No `waived` status (`mark_unrecoverable` maps to `failed` + distinct reason).
- No skipped-node re-execution (resolution is ledger-layer, out-of-band).
- No retry execution after `safe_to_retry` (records `retry_authorized` only).
- No run()/resume() control-flow change.
- No observed-completion validator relaxation.
- No unknown→completed via `output["side_effect_records"]`.
- No Model B adapter-reported completion.
- No new trace event type (uses existing `RECOVERY_ACTION_ALLOWED`).

**Tests**
- New: `tests/test_side_effect_recovery_decisions.py` (atomic store method,
  9 tests), `tests/test_recovery_side_effect_resolution.py` (governed
  RecoveryService path, 9 tests), `tests/test_recover_cli_side_effect.py`
  (CLI, 5 tests), `tests/test_recovery_surface_verification.py` (surface +
  reconciler invariants, 6 tests).
- Updated: `tests/test_operator_action_policy.py` (enum count 10→11).
- Green: store, state-manager, recovery-service, route-fallback, orchestrator,
  durable-state, completion suites.

**Version bump:** 3.2.0 → 3.3.0.

## [3.2.0] — Retry Recovery Success Invariant

**Release type:** runtime correctness fix (retry-recovery contract violation).

v3.2.0 enforces the retry-recovery success invariant: a recovery result may
advance execution only when (1) `recovered=True` and the response is present
and `response.success=True`, OR (2) `recovered=True` and the action is an
intentional skip/continue action explicitly allowlisted by the orchestrator
(`_SKIP_CONTINUE_ACTIONS`). All other `recovered=True` shapes fail the chain
rather than feed garbage output downstream.

Previously, four retry handlers (`_handle_unknown`, `_handle_schema_failure`,
`_handle_model_timeout`, `_handle_search_unavailable`) returned
`recovered=True` with the retry response unconditionally — feeding a failed
retry's output downstream as if the node had succeeded.

**What changed**
- Four retry handlers now gate `recovered=True` on `response.success`. A failed
  retry returns `recovered=False` with action `*_retry_failed`
  (`schema_failure_retry_failed`, `model_timeout_retry_failed`,
  `search_unavailable_retry_failed`, `unknown_retry_failed`).
- Orchestrator `run()` and `resume()` now re-check the recovery response
  (defense-in-depth, independent of the handler fixes): `recovered=True` is
  authoritative only with a valid successful response. Both invalid shapes —
  missing response AND failed response — fail the chain. The two intentional
  skip-continue actions (`skip_memory_write_policy_rejection`,
  `trace_fallback_stderr`) are exempt for the missing-response case only; the
  failed-response guard is unconditional.

**What did NOT change**
- No side-effect validator relaxation.
- No unknown side-effect recovery authority.
- No operator RecoveryAction for side effects.
- No Model B adapter-reported completion.

**Tests**
- Updated: `tests/test_infra/test_failure_manager.py` (characterization flipped
  to fixed behavior + positive controls; 4 handlers).
- New: `tests/test_retry_recovery_invariant.py` (orchestrator defense-in-depth:
  run/resume refuse invalid recovery responses; skip-continue exemption regression).
- Green: orchestrator, durable-state, validation, completion suites.

**Version bump:** 3.1.0 → 3.2.0.

## [3.1.0] — Resume-Path Observed Side-Effect Completion

**Release type:** narrow symmetry fix (resume path mirrors run path).

v3.1.0 wires observed side-effect completion into the orchestrator's `resume()`
post-call seam, mirroring v3.0's `run()` wiring. For freshly re-executed nodes
whose side-effect key is genuinely new (the crash happened before they
journaled), completion works exactly like the run path.

**What changed**
- `resume()` post-call seam now calls
  `complete_reported_side_effects(node_id, envelope, response.output)`,
  identical to `run()` (orchestrator.py ~line 1050).
- No validator changes, no new event types, no new exception types.

**What did NOT change (the crash-window limitation)**
- Crash-window `unknown` effects are NOT completable by the resume path.
  `_reconcile_side_effects_on_resume` marks crashed `started` effects `unknown`,
  and the v3.0 validation rule rejects completion of non-`started` effects.
  Completing an `unknown` effect requires a recovery-decision write path that
  does not exist in production today. This is deferred to v3.2.
- No Model B adapter-reported completion.
- No memory_write / code_execution / external-write completion.

**Tests**
- New: `tests/test_resume_side_effect_completion.py` (5 tests: resume-path
  completion for fresh keys, absent/invalid/no-inference, unknown-effect
  characterization).
- Green: v3.0 completion suite unchanged (23 tests).

**Version bump:** 3.0.0 → 3.1.0.

---

## [3.0.0] — Observed Side-Effect Completion (Model C, first path)

**Release type:** narrow behavior implementation (first behavior change in the
2.9x→3.x transition; prior 2.9x releases were characterization or
behavior-preserving extraction).

v3.0.0 implements the first observed side-effect completion path: nodes may
report completion records in `output["side_effect_records"]`, and the runtime
validates each record against the planned/started ledger before marking it
`completed`. This closes the gap characterized in v2.97 (side effects stayed
`started` because no caller wired the completion emitter).

**What changed**
- `SideEffectJournalController.complete_reported_side_effects(node_id, envelope, output)`
  validates node-reported completion records and transitions matching ledger
  rows to `completed` (persisting `response_hash`), emitting
  `SIDE_EFFECT_COMPLETED` only for validated observed reports.
- `SideEffectJournalMixin._complete_reported_side_effect` holds the validation
  logic: key match, canonical-type match, status, accepted authority
  (`node`), non-empty `response_hash` and `observed_at`, idempotent same-hash
  replay, conflict on different-hash replay.
- New helper `make_canonical_search_key(adapter_name, request_hash)` in
  `nodechain.core.side_effect_utils` — single source of truth for the
  `search:<adapter>:<hash>` key format.
- The canonical mock `search_tool` now reports observed completion for its
  `semantic_scholar` external_call.

**What did NOT change**
- No completion is inferred from node success.
- No adapter-level (Model B) completion reporting.
- No memory_write / code_execution / external_write completion paths.
- Resume-path completion reporting is NOT wired. v3.0 wires the `run()` post-call
  seam only; the separate `_emit_node_detail_events` call site in `resume()`
  (orchestrator.py) is unchanged, so a resumed run that reports
  `output["side_effect_records"]` would have those records ignored. Resume-path
  completion remains deferred.
- No policy, sandbox, recovery, or Docker behavior changes.
- No new exception types; no new trace event types (invalid reports reuse the
  existing `CONTRACT_VIOLATION` soft-fail path).

**Scope statement**

v3.0 implements observed side-effect completion for the normal run path only.
Resume-path completion reporting remains deferred.

**Tests**
- New: `tests/test_observed_side_effect_completion.py` (23 focused tests:
  canonical key, validation, controller, end-to-end, legacy/absent-report,
  invalid-report, canonical-mock-reports).
- Updated: `tests/test_side_effect_journaling_characterization.py` (5 assertions
  narrowed: search path now reaches `completed`; memory_write stays `started`).
- Green: orchestrator, validation-failure, policy-gate, state-manager
  characterization suites (105 passed in the affected-area sweep).

**Version bump:** 2.99.0 → 3.0.0.

---

## [2.99.0] — Side-Effect Completion Design Study

Design-only release. Adds a design artifact documenting the side-effect
completion gap surfaced by v2.97 characterization. **No production behavior
changes, no new powers, no implementation.**

### Added
- `docs/design/side-effect-completion.md` — design study covering:
  - Current behavior (started-not-completed, frozen by v2.97)
  - Design invariant: "completed requires observed evidence, not inference"
  - Three completion authority models (A: inference — rejected; B: adapter-
    reported — preferred for external; C: node-output-reported — complementary)
  - Recommended B+C hybrid approach
  - Ledger transition rules (existing + proposed "skipped" status)
  - Trace requirements (SIDE_EFFECT_COMPLETED exists but has zero callers)
  - Acceptance criteria for a future v3.0 implementation
  - Implementation sketch with the critical constraint: "absence of a
    completion report leaves the effect at 'started,' not infer 'completed'"

### Not changed
- No production code changes. No runtime behavior changes.
- v2.97 characterization (started-not-completed) remains the frozen truth.

### Changed
- Version bump 2.98.0 → 2.99.0.

---

## [2.98.0] — Orchestrator Extraction Phase 4: Side-Effect Journal Controller

Behavior-preserving extraction. Wraps the pre-invocation side-effect journaling
call behind `SideEffectJournalController`, providing a named controller entry
point consistent with the other three orchestrator controllers. **Zero behavior
change.** All characterization tests pass unchanged.

### Extracted
- `src/nodechain/runtime/side_effect_journal_controller.py` — new module with
  `SideEffectJournalController`:
  - `journal_planned_side_effects(node_id, envelope)` → delegates to
    SideEffectJournalMixin._journal_planned_side_effects
  - Wraps the mixin (which Orchestrator inherits from) to provide a named
    controller consistent with ContractPreflightController /
    NodeOutputValidationController / PolicyGateController
- Orchestrator instantiates the controller in `__init__` and delegates both
  call sites (run() + resume()) from `self._journal_planned_side_effects(...)`
  to `self._side_effect_journal.journal_planned_side_effects(...)`.

### Not extracted (stays on Orchestrator / mixin)
- Side-effect completion (unimplemented — no callers wire it)
- Resume reconciliation (_reconcile_side_effects_on_resume)
- Policy blocking semantics
- Node invocation, execution loop, failure management

### Not changed
- v2.97 (17), v2.91 (20), v2.94 (11), v2.95 (10) characterization tests pass UNCHANGED.
- No side-effect key/request_hash/type/lifecycle drift.
- SIDE_EFFECT_STARTED remains before NODE_INVOKED.
- Mock-chain side effects remain started, not completed.

### Changed
- Version bump 2.97.0 → 2.98.0.

---

## [2.97.0] — Orchestrator Side-Effect Journaling Characterization

Characterization-only release. Adds 17 focused tests freezing the side-effect
journaling lifecycle through the orchestrator-integrated path. **Zero production
behavior changes.** Fills the safety net before any future
SideEffectJournalController extraction.

### Added
- `tests/test_side_effect_journaling_characterization.py` (17 tests):
  - Declared lifecycle: side effects journaled with search:adapter:hash key,
    canonical type, valid step_id, non-empty request_hash
  - Memory write: memory_write_decision journals with expected key prefix/type
  - Failure path: trace returned (not exception); side effects remain in ledger
  - Trace ordering: SIDE_EFFECT_STARTED before NODE_INVOKED (actual behavior);
    CHAIN_COMPLETED last event
  - Resume visibility: started effects queryable; completed effects absent in
    mock (documents actual behavior — real adapters must wire completion)

### Key findings documented in tests (not bugs — actual behavior frozen)
- Side effects stay "started" (not "completed") in the mock chain — the
  completion path (`side_effect_completed` emitter) is defined but has zero
  callers. Real adapters must wire this. This is characterized, not fixed.
- SIDE_EFFECT_STARTED is emitted BEFORE NODE_INVOKED (journaling happens
  pre-invocation at orchestrator line 400).

### Changed
- Version bump 2.96.0 → 2.97.0.

---

## [2.96.0] — Orchestrator Extraction Phase 3: Policy Gate Controller

Behavior-preserving extraction. Moves the ~400-line policy gate logic behind
`PolicyGateController`, while Orchestrator remains the public facade.
**Zero behavior change.** All characterization tests pass unchanged.

### Extracted
- `src/nodechain/runtime/policy_gate_controller.py` — new module (484 lines)
  with `PolicyGateController`:
  - Provenance normalization (derives _module_path)
  - POLICY_EVALUATED trace events for each evaluated policy
  - PACKAGE_TRUST, TOOL_ACCESS, ADAPTER_ACCESS, MEMORY_READ durable decisions
  - SIDE_EFFECT_BLOCKED on denial
  - Returns denial reason string or None
- Orchestrator instantiates the controller in `__init__` and delegates
  `_check_policy_gate()` as a thin delegator.
- orchestrator.py: 2,450 → 2,077 lines (373-line reduction).

### Not extracted (stays on Orchestrator)
- `run()` execution loop, node invocation, output validation
- Side-effect journaling, branch/loop/review routing
- Chain failure finalization

### Not changed
- v2.91 (20), v2.94 (11), v2.95 (10) characterization tests pass UNCHANGED.
- No policy rules, default policy behavior, fail-closed semantics, trace
  ordering, or durable-decision recording changes.

### Changed
- Version bump 2.95.0 → 2.96.0.

---

## [2.95.0] — Orchestrator Policy Gate Characterization

Characterization-only release. Adds 10 focused tests for policy-gate behavior
before any future PolicyGateController extraction. **Zero production behavior changes.**

### Added
- `tests/test_policy_gate_characterization.py` (10 tests):
  - Allow: default policies complete chain; policy events emitted on allow
  - Deny: deny-all returns failed trace; deny-all never raises exception
  - Ordering: POLICY_EVALUATED before CHAIN_FAILED; denied node does not succeed
  - Targeted deny: denying one node prevents downstream invocation
  - Tool access: deny-tools policy blocks chain through orchestrator path
  - Trace recording: deny produces policy events; allow produces policy events

### Changed
- Version bump 2.94.0 → 2.95.0.

---

## [2.94.0] — Orchestrator Validation Failure Characterization

Characterization-only release. Adds 11 focused tests around output-validation
failure behavior that the v2.91 broad characterization didn't exercise.
**Zero production behavior changes.** Fills the gap flagged in v2.93.

### Added
- `tests/test_validation_failure_characterization.py` (11 tests):
  - Invalid output returns ChainTrace, not exception
  - Node exception returns failed trace, never propagates
  - Failure prevents downstream node invocation
  - Event ordering: chain_started first, chain_completed/failed last,
    node_invoked before node_succeeded
  - All-contracts-validated before any node invocation
  - Validation/succeeded sequence preserved on happy path
  - Trace finalization: trace_complete flag, non-negative duration

### Changed
- Version bump 2.93.0 → 2.94.0.

---

## [2.93.0] — Orchestrator Extraction Phase 2: Node Output Validation Controller

Behavior-preserving extraction. Moves post-invocation output validation
(schema + semantic) behind a dedicated controller, while Orchestrator remains
the public facade. **Zero behavior change.** v2.91 characterization tests pass
unchanged.

### Extracted
- `src/nodechain/runtime/node_output_validation_controller.py` — new module with
  `NodeOutputValidationController`:
  - `validate_schema(...)` — validates output against exit contract schema,
    emits VALIDATION_PASSED / VALIDATION_FAILED, returns ValidationResult
  - `run_semantic_validations(...)` — runs semantic validators, can calibrate
    output, emit semantic events, returns SemanticValidationOutcome
- Orchestrator instantiates the controller in `__init__` and delegates. Control-
  flow decisions (`_fail_chain`, `return`) stay in `run()`.
- The old `_run_semantic_validations` method removed from Orchestrator (fully
  extracted). Net: orchestrator.py reduced by ~41 lines.

### Not extracted (stays on Orchestrator)
- `run()` execution loop, node invocation, policy gate, side-effect journaling
- Control-flow branching on validation results
- Loop-back, branch/join routing

### Not changed
- No trace event ordering drift. No runtime/recovery/policy/sandbox/trace changes.
- v2.91 characterization tests (20) pass UNCHANGED.

### Changed
- Version bump 2.92.0 → 2.93.0.

---

## [2.92.0] — Orchestrator Extraction Phase 1: Contract Preflight Controller

Behavior-preserving extraction. Moves contract validation logic behind a
dedicated controller class, while Orchestrator remains the public facade.
**Zero behavior change.** v2.91 characterization tests pass unchanged.

### Extracted
- `src/nodechain/runtime/contract_preflight_controller.py` — new module with
  `ContractPreflightController`:
  - Validates backbone connections via ContractRegistry
  - Validates port compatibility (including branches and joins)
  - Emits CONTRACT_VALIDATED trace events on validation failures
  - Returns list of issue strings (empty = all valid)
- Orchestrator instantiates the controller in `__init__` and delegates
  `validate_contracts()`. Public method signature unchanged.

### Not extracted (stays on Orchestrator)
- `run()` execution loop, node invocation, policy gate, side-effect journaling
- `_emit_all_contracts_validated` (success event stays in NodeEventEmitterMixin)
- Per-node `_emit_contract_validated` (already in NodeEventEmitterMixin from v2.74)

### Not changed
- No trace event ordering drift. No runtime/recovery/policy/sandbox/trace changes.
- v2.91 characterization tests (20) pass UNCHANGED.

### Changed
- Version bump 2.91.0 → 2.92.0.

---

## [2.91.0] — Orchestrator Characterization Harness

Characterization-only release. Freezes the orchestrator's observable runtime
behavior with 20 tests before any future extraction. **Zero production behavior
changes.** This is the safety net for future orchestrator decomposition.

### Added
- `tests/test_orchestrator_characterization.py` (20 tests):
  - Contract validation: returns empty list on valid chain, returns list type
  - Chain execution lifecycle: returns ChainTrace, completes with "completed",
    emits chain_started + chain_completed, trace finalized with status
  - Contract validation ordering: all_contracts_validated before first node_invoked
  - Node execution sequencing: invoked/succeeded counts match, invoked precedes
    succeeded per node pair
  - Trace event coverage: required event types present, non-zero events,
    trace_complete flag
  - Policy gate behavior: mock nodes pass default policies, policy events emitted
  - State persistence: chain_state + invocation_ledger populated after run
  - Validation failure behavior: failed chain returns trace (never raises)
  - Output inspection: state.outputs populated, run_id is valid UUID

All tests use deterministic mock 12-node chain + temp StateManager (tmp_path).
No production code changes.

### Changed
- Version bump 2.90.0 → 2.91.0.

---

## [2.90.0] — Release Evidence Index + Verification Dashboard

Consolidates all evidence-producing paths (v2.85–v2.89) into one discoverable
reference for operators and reviewers. **No runtime authority changes, no new powers.**

### Added
- `docs/release-evidence.md` — one-stop evidence index with:
  - 10-row evidence path table (claim, command, artifact, platform, status)
  - Claims vs evidence mapping (11 proven claims with their evidence sources)
  - What this does NOT prove (6 open questions with status + reasoning)
  - Precise verification-language guidance
  - Regenerate-all-evidence command summary
  - Related document reference table
- `tests/test_release_evidence_links.py` (5 tests) — prevents doc rot by checking
  all referenced docs, scripts, and tests exist; required structural sections present

### Not changed
- No runtime, StateManager, policy, recovery, sandbox, trace, or CLI changes.

### Changed
- Version bump 2.89.0 → 2.90.0.

---

## [2.89.0] — Optional Sandbox Verification Evidence Profile

Makes the sandbox enforcement arc (v2.76–v2.78) evidence collectible via a
dedicated runner. Separate from the default external verifier — this profile
requires Linux + root and probes host capabilities before attempting enforcement.

### Added
- `scripts/run_sandbox_verification.py` — probes host capabilities (OS, uid,
  seccomp bindings, native_sandbox_supported), then either:
  - **Eligible host (Linux + root + flag):** runs 4 enforcement tests and emits
    `sandbox-evidence.json` + `sandbox-evidence.md` with mount confinement,
    network namespace, PID/procfs, and seccomp SIGSYS canary evidence
  - **Ineligible host:** emits explicit "unsupported on this host" evidence with
    precise reason (NOT a failure — exit 0)
- `docs/external-verification.md` updated to reference the optional sandbox runner

### Verification results
- Windows: explicit unsupported-skip (exit 0, not a failure)
- `.28` Linux as root: enforcement verified (4/4 passed, SIGSYS canary included)

### Not changed
- Default external verification runner unchanged and green
- No runtime, sandbox, StateManager, CLI, or trace changes
- No Docker backend

### Changed
- Version bump 2.88.0 → 2.89.0.

---

## [2.88.0] — External Verification Runner + Evidence Bundle

Makes the v2.87 verification pack executable and collectible. One command runs
the full reviewer proof path and emits a compact evidence bundle. **No runtime
authority changes, no new powers.**

### Added
- `scripts/run_external_verification.py` — runs 6 verification steps in ~25s:
  1. Schema validation
  2. Quickstart echo demo (with --provider mock)
  3. Trace existence check
  4. Trace replay consistency verification (7 checks)
  5. Quickstart smoke tests (5 tests)
  6. Doc-link + CLI characterization tests (14 tests)
- Emits two evidence artifacts:
  - `evidence.json` — machine-readable (metadata, step results, run_id, trace path)
  - `evidence.md` — human-readable summary table
- `docs/external-verification.md` updated to reference the runner as the fastest path

### What the runner does NOT do
- Does not run the full test suite (use `pytest -q` or `run_full_suite_sharded.py`)
- Does not run native sandbox enforcement (requires Linux + root)
- Does not require external API keys
- Does not claim to be a full release gate

### Not changed
- No runtime, StateManager, policy, recovery, sandbox, trace, or CLI changes.

### Changed
- Version bump 2.87.0 → 2.88.0.

---

## [2.87.0] — External Verification Pack

A documentation/adoption release. Adds a reviewer-facing verification bundle
that lets an outside reviewer understand, run, verify, and judge NodeChain
without project history. **No runtime authority changes, no new powers.**

### Added
- `docs/external-verification.md` — reviewer-facing document with:
  - Claims vs evidence table (8 proven claims with evidence paths)
  - What this does NOT prove (5 open questions with status + reasoning)
  - Exact verification commands (install, schema validation, quickstart run,
    trace inspection, trace replay, targeted tests, full suite, sharded suite)
  - Document reference table linking all verification-related docs
  - Precise verification-language guidance
- `tests/test_external_verification_links.py` (6 tests) — validates the doc
  doesn't rot: all referenced docs, scripts, tests, and blueprints exist; the
  doc contains required structural sections (Claims vs Evidence, What this does
  NOT prove, Verification commands, Verification language)

### Not changed
- No runtime, StateManager, policy, recovery, sandbox, trace, or CLI changes.
- No new product surface.

### Changed
- Version bump 2.86.0 → 2.87.0.

---

## [2.86.0] — CLI Relocation Wave 3

Continues the operator-surface decomposition arc. 5 more read-oriented commands
relocated into `cli/commands/`. **No new powers; no behavior changes.**

### Relocated (zero behavior change)
- `inspect` (standalone) → `cli/commands/inspect.py` — read-only state inspection
- `report` (standalone) → `cli/commands/report.py` — read-only report generation
- `trace` (standalone) → `cli/commands/trace.py` — trace viewing
- `trace-replay` group (1 subcommand: run) → `cli/commands/trace_replay.py` — trace verification
- `compose` group (1 subcommand: validate) → `cli/commands/compose.py` — blueprint validation

All read/inspection/validation oriented — no mutation surfaces. Lazy imports
preserved. `test_cli_import_is_lightweight` remains a hard gate.

### Changed
- `main.py`: 4,500 → 4,325 lines (175 relocated). Cumulative across v2.79–v2.86:
  6,068 → 4,325 (1,743 lines relocated across 12 groups/commands).
- No source-text test fixes needed this wave.
- Version bump 2.85.0 → 2.86.0.

### Not changed
- No runtime, StateManager, policy, recovery, sandbox, trace, or persistence
  semantics change. No commands added, removed, or renamed.

---

## [2.85.0] — Five-Minute Local Proof Quickstart

A usability release. Adds a documented, runnable local proof that demonstrates
NodeChain's core value in under five minutes with zero external API keys.
**No runtime authority changes, no new powers.**

### Added
- `docs/5-minute-local-proof.md` — step-by-step quickstart with exact copy-paste
  commands: install → validate schemas → run echo demo → inspect trace →
  trace-replay verification → optional richer chains (branch/join, multi-hop,
  shared nodes). All run on the deterministic mock provider.
- `tests/test_quickstart_smoke.py` (5 tests) — validates the documented command
  sequence end-to-end so it doesn't rot: validate_schemas, echo demo run, trace
  inspection, trace-replay verification, optional blueprint existence.

### What the quickstart proves
A new user can demonstrate in 5 minutes:
- Bounded nodes (contracts, typed ports, side-effect declarations)
- Runtime execution (orchestrator + invocation envelopes)
- Contract validation ("All contracts validated" before any node runs)
- Trace output (complete execution record saved to `data/traces/<run_id>.json`)
- Inspectability (`nodechain trace` + `trace-replay` 7 consistency checks)
- Zero external dependencies (deterministic mock provider, no API keys, no model service)

### Not changed
- No runtime, StateManager, policy, recovery, sandbox, trace, or CLI behavior changes.
- No new runtime authority.

### Changed
- Version bump 2.84.0 → 2.85.0.

---

## [2.84.0] — Verification Ergonomics: Windows Suite Sharding + Release Gate Clarity

Verification-infrastructure cleanup. **No production code changes, no new powers.**
Fixes the Windows full-suite tool-ceiling problem by adding a sharded runner
and documenting the three verification tiers.

### Added
- `scripts/run_full_suite_sharded.py` — runs all 264 test files in N shards,
  aggregates results into a combined summary (passed/skipped/failed/elapsed
  per shard). Exits non-zero on any failure. Default 6 shards.
- `docs/ci.md` verification-tier documentation:
  - Tier 1: full-suite single-run (strongest, authoritative on .28)
  - Tier 2: sharded full-suite (strong, use when single-run hits ceilings)
  - Tier 3: targeted affected-area (iteration aid, not a release gate alone)
  - Reconciliation note: sharded totals may differ ~100-120 from single-run
    due to pytest collection-order effects (expected, not a bug)

### Fixed
- Release-gate language accuracy: distinguish "full-suite green" from
  "targeted affected-area green" from "tool-ceiling timeout" — the accurate
  phrasing per ChatGPT's v2.83 caveat.

### Not changed
- No production code behavior changes.
- No test semantics changes.
- No runtime/state/policy/recovery/sandbox/trace/persistence changes.

### Changed
- Version bump 2.83.0 → 2.84.0.

---

## [2.83.0] — StateManager Store Extraction Phase 2

Behavior-preserving extraction. Moves the side-effect ledger and all decision
log persistence behind dedicated store classes. StateManager remains the public
facade. **Zero behavior change.** v2.81 characterization tests pass unchanged.

### Extracted
- `SideEffectLedgerStore` (7 methods + LEGAL_TRANSITIONS): record_side_effect,
  update_side_effect_status (incl. cross-table recovery-decision read),
  get_side_effects, get_side_effect_by_key, is_side_effect_completed,
  get_side_effects_by_status, validate_side_effect_transition
- `DecisionLogStore` (20 methods across 10 decision tables): operator actions,
  review attempts, memory decisions, side-effect blocks, recovery decisions,
  memory-read decisions, tool access, adapter access, package trust,
  registry admission (each with record + get pair)

### Not extracted (stays on StateManager)
- save/load/delete, save_with_invocation/save_with_event (atomic transactions)
- replay_state, list_all_runs, list_all_review_states, _init_db
- PersistenceCoordinator composition (load_for_recovery)

### Not changed
- No schema changes. No table/column renames. No behavior changes.
- v2.81 characterization tests (24) pass UNCHANGED.
- 4 stores now extracted total (EventLog, InvocationLedger, SideEffectLedger,
  DecisionLog). StateManager retains chain-state materialization + atomic
  transactions + recovery composition.

### Changed
- Version bump 2.82.0 → 2.83.0.

---

## [2.82.0] — StateManager Store Extraction Phase 1

Behavior-preserving extraction. Moves the event-log and invocation-ledger
persistence methods behind dedicated store classes, while StateManager remains
the public facade. **Zero behavior change.** v2.81 characterization tests pass
unchanged.

### Extracted
- `src/nodechain/core/stores.py` — new module with:
  - `EventLogStore`: `append_event`, `get_events` (state_events table)
  - `InvocationLedgerStore`: `record_invocation`, `is_step_completed`,
    `is_node_completed`, `get_completed_steps`, `get_invocation_cost`
    (invocation_ledger table)
- StateManager instantiates both stores in `__init__` and delegates. Public
  method signatures on StateManager are unchanged — callers see no difference.

### Not extracted (stays on StateManager)
- `save_with_invocation` / `save_with_event`: atomic multi-table transactions
  (chain_states + invocation_ledger + state_events). These are the core write
  boundary; splitting them across stores would break transactional integrity.
- `save` / `load` / `delete`: chain_states materialized snapshot.
- Side-effect ledger and all decision logs: future extraction phases.
- `_init_db`: schema creation stays centralized.

### Not changed (strict extraction boundary)
- No schema changes. No table/column renames. No behavior changes.
- No recovery/reconciler/policy/side-effect/trace semantics change.
- v2.81 characterization tests (24 tests) pass UNCHANGED.

### Changed
- Version bump 2.81.0 → 2.82.0.

---

## [2.81.0] — StateManager Characterization Harness

A characterization-only release. Freezes the StateManager persistence surface
with 24 tests covering table presence, column contracts, chain-state lifecycle,
invocation ledger, side-effect ledger, decision durability, resume/recovery
read paths, and event-log ordering. **No production behavior changes.** This
is the safety net that makes future store extraction possible without audit drift.

### Added
- `tests/test_state_manager_characterization.py` (24 tests):
  - Schema initialization: all 14 required tables present + key column checks
  - Chain state lifecycle: save/load round-trip, revision increment, nonexistent-run handling
  - Invocation ledger: step/node recording, step-completion check, cost tracking
  - Side-effect ledger: default planned status, started/completed transitions, idempotency
  - Side-effect recovery: started/planned effects visible by status (resume path)
  - Decision durability: operator actions, review attempts, memory decisions, tool access decisions
  - Resume reads latest materialized state (load_for_recovery composition)
  - Event log: append + get_events, ordering by seq

### Not changed (strict characterization boundary)
- No StateManager extraction, splitting, renaming, or schema changes.
- No runtime/recovery/policy/side-effect/reconciler/trace semantics change.
- All tests use isolated temp SQLite databases; no developer-machine state dependency.

### Changed
- Version bump 2.80.0 → 2.81.0.

---

## [2.80.0] — CLI Relocation Wave 2

Continues the operator-surface decomposition arc from v2.79. Another bounded
cluster of read-oriented Click declaration groups relocated into `cli/commands/`.
No new powers; no runtime/state/policy/recovery/sandbox/trace/persistence changes.

### Relocated (zero behavior change)
- `eval` group (8 direct subcommands + 2 nested subgroups: `certification` 4 cmds,
  `suite` 6 cmds) → `cli/commands/eval.py`
- `graph` group (export, verify) → `cli/commands/graph.py`
- `console` group (open, serve) → `cli/commands/console.py`

All implementation logic stays in sibling `cli/*.py` modules. Lazy imports
preserved. `test_cli_import_is_lightweight` remains a hard gate.

### Fixed
- `tests/test_console_hardening.py`: source-text helper updated to read from
  `cli/commands/console.py` (the code it checks moved; behavior unchanged).
- VISION.md roadmap corrected: v2.80/v2.81/v2.82 are now three separate releases
  (CLI wave 2 / StateManager characterization / Docker-or-quickstart decision),
  not two combined.

### Changed
- `main.py`: 5,460 → 4,500 lines (960 lines of Click declarations moved out).
  Cumulative with v2.79: 6,068 → 4,500 (1,568 lines relocated across both waves).
- 7 groups now relocated total (evidence, release_history, audit_bundle, dashboard,
  eval, graph, console). Remaining groups relocate in future waves.
- Version bump 2.79.0 → 2.80.0.

### Not changed (strict refactor boundary)
- No runtime, StateManager, Orchestrator, policy, recovery, registry-admission,
  sandbox, trace, or persistence semantics change.
- No commands added, removed, or renamed.

---

## [2.79.0] — Operator Surface Cleanup: CLI Characterization + Click Relocation Wave 1

A refactor/cleanup release with **no new powers**. Fixes two confirmed
truth/portability issues, freezes the CLI command surface with characterization
tests, and relocates a small read-oriented Click declaration cluster into
`cli/commands/`. Does not change runtime, state, recovery, policy,
registry-admission, sandbox, trace, or persistence semantics.

### Fixed
- `scripts/validate_schemas.py`: UnicodeEncodeError on default Windows stdout
  (✅/❌ glyphs crashed the script on cp1252). Replaced with ASCII-safe
  `[OK]`/`[ERROR]` output.
- `VISION.md` L168: stale "mock-tested, not yet run end-to-end" research-chain
  status cell corrected to reflect the v2.68 GLM-4.6 end-to-end success.

### Added
- `tests/test_cli_characterization.py` (8 tests): CLI command inventory, Click
  parameter signatures (via metadata, not raw help text), selected normalized
  help snapshots, exit codes, unknown-command behavior, and import-is-lightweight
  (hard gate: relocated modules must preserve lazy imports).
- `src/nodechain/cli/commands/` subpackage with `register(cli)` pattern for
  relocated Click declaration modules.

### Changed (relocation — zero behavior change)
- Click declarations for 4 read-oriented groups relocated from `main.py` to
  `cli/commands/`: `evidence` (5 commands), `release_history` (5 commands),
  `audit_bundle` (standalone), `dashboard` (11 commands).
- `main.py`: 6,068 → 5,460 lines (608 lines of Click declarations moved out).
  The relocation pattern is proven; remaining groups relocate in v2.80.
- All implementation logic stays in sibling `cli/*.py` modules unchanged.
  Relocated modules use the same lazy-import pattern as the original handlers.
- 6 source-text checks in `test_audit_bundle.py` updated to point at the new
  `cli/commands/audit_bundle.py` location (the code they check moved; the
  behavior they verify is unchanged).

### Not changed (strict refactor boundary)
- No runtime, StateManager, Orchestrator, policy, recovery, registry-admission,
  sandbox, trace, or persistence semantics change.
- No commands added, removed, or renamed.
- local_subprocess and native_os_sandbox backends unchanged.

### Changed
- Version bump 2.78.0 → 2.79.0.

---

## [2.78.0] — Child-Applied Seccomp for Native Command Runner

Closes the v2.77 seccomp deferral. seccomp is now enforced through the
integrated v2.76 command-runner path via a child-applied filter that survives
`execve` — the same Linux mechanism runc uses to confine containers.

### The redesign
The v2.76/v2.77 model applied seccomp to the *spawner* before `subprocess.run`,
which was incompatible with the deny-list (fork/vfork/clone/clone3 are denied,
but `subprocess.run` needs fork). v2.78 moves seccomp to the *child*: the
bootstrap does namespace/chroot setup, applies the filter to itself, then
`os.execve`s the workload in place. The filter survives `execve` (Linux
guarantee: seccomp filters attach to the process, not the binary), so the
workload runs confined without the spawner needing fork-denied syscalls.

### Proven (child-observed, all four primitives now green)
- ✅ Mount confinement — child reads `/workspace/sentinel.txt` from inside chroot
- ✅ Network namespace — host positive-control + sandbox block
- ✅ PID namespace + procfs isolation
- ✅ **Seccomp** — child applies filter; fork canary workload is killed by SIGSYS
  (signal 31), classified by the parent as `seccomp_sigsys_kill`

### Metadata model (distinguishes states, per ChatGPT review)
```json
{
  "seccomp_requested": true,
  "seccomp_apply_mode": "child_pre_exec",
  "seccomp_applied": true,
  "seccomp_observed_by_workload": true,
  "seccomp_canary_blocked": true,
  "seccomp_verified": true
}
```
Ordinary workloads (no probe) report `seccomp_applied: true` without claiming
workload-level verification — `applied` is not `verified`, preserving trace truth.

### Changed
- `native_sandbox_exec.py` rewritten to the execve model: parent owns result
  assembly (exit code, stdout, stderr, timeout); child does setup + seccomp +
  in-place execve (terminal). Setup metadata flows through a parent-created
  pipe FD (passed via `pass_fds`), not stdout.
- `enable_seccomp` re-enabled for the native path (was disabled in v2.77).
- The two v2.77 seccomp `xfail` tests rewritten as positive assertions (no
  xfail markers); both pass on `.28` as root.
- Exit-code classifier recognizes SIGSYS in both forms (`-31` and `128+31=159`).
- Version bump 2.77.0 → 2.78.0.

### Relationship to #2
Contributes direct evidence against two of #2's review questions:
- **Q1: "Can Python-level hooks be bypassed via C extensions, ctypes, or direct syscalls?"** — seccomp is the syscall-level backstop; the canary proves it's active inside the workload boundary.
- **Q3: "Does process isolation properly confine untrusted nodes?"** — the child-applied model proves confinement at the correct execution layer.

Closes #30. #2 remains open (broader review scope).

### Non-goals (unchanged from v2.77)
No Docker, no unprivileged userns, no local_subprocess changes, no broad policy refactors. GHA-native execution still not claimed (runner is non-root); unprivileged production deployment still not proven.

---

## [2.77.0] — Privileged Linux Native Sandbox Verification Harness

Proves the integrated v2.76 `native_os_sandbox` command-runner path enforces
confinement under the privileged Linux execution profile, with child-observed
evidence. This retires most of the v2.76 caveat ("path is wired but not yet
proven enforcing").

### Added
- `tests/test_native_sandbox_enforcement.py` — integrated-chain enforcement
  tests gated by the three-tier `native_sandbox` marker
- `@pytest.mark.native_sandbox` marker + three-tier conftest gate
  (default-host skip / privileged-root enforces / misconfigured-runner hard-fail)
- `scripts/run_native_sandbox_verification.sh` — release-evidence path with
  fail-closed preconditions (root, Linux, seccomp bindings, host network
  reachability, no-skips)
- `docs/native_sandbox_verification.md` — repeatable procedure + honest scope
- `apply_mount_confinement` `extra_mounts` keyword (backward-compatible) —
  bind-mounts `/usr`, `/lib`, `/lib64`, and the venv so the argv binary
  (python interpreter) is reachable inside the chroot

### Proven (child-observed, not metadata-only)
- Mount confinement: confined child reads `/workspace/sentinel.txt`; metadata
  reports `mount_confinement_enforced=True`
- Network namespace: host positive-control reaches `1.1.1.1:53`; sandboxed
  child cannot; metadata reports `network_namespace_enforced=True`
- PID namespace + procfs isolation: enforced

### Named limitation: seccomp deferred to v2.78
Seccomp syscall filtering is **intentionally deferred**. The existing seccomp
profile denies `fork`/`vfork`/`clone`/`clone3` — correct for in-process node
execution, but incompatible with the subprocess-based command runner (the
spawner requires fork before the workload can run). v2.77 disables seccomp at
the source (`enable_seccomp: False`) and xfails the seccomp tests with a
precise reason. The **child-applied seccomp redesign** (parent spawns
unconfined, child self-applies the profile before the workload) is tracked for
v2.78. This is the honest position — claiming seccomp enforced when it was
silently disabled would violate the trace-truth rule.

### Operational caveat
The native_os_sandbox backend requires privileges (`CAP_SYS_ADMIN`,
`CAP_SYS_CHROOT`) that ordinary non-root CI users and production service users
do not have. v2.77 verifies enforcement under the privileged profile as root on
the designated Linux host. GHA-native non-root execution and unprivileged
production deployment are NOT claimed.

### Changed
- `native_sandbox_exec.py`: pre-chroot trusted imports (seccomp/namespace
  modules now imported before chroot, surviving in sys.modules); `enable_seccomp`
  disabled for v2.77 with documented deferral
- Version bump 2.76.0 → 2.77.0

### Compatibility
- Existing local temp-workspace behavior remains the default
- No Docker, no chain topology changes, no side-effect taxonomy changes
- Suite stays green-with-skips on non-Linux / non-runner hosts

---

## [2.76.0] — Native OS-Sandboxed Test Runner Execution

Routes governed patch-test execution through NodeChain's existing native OS
sandbox stack. This closes the routing gap between `sandbox_test_runner` and
the already-built namespace / seccomp / cgroup / mount-confinement machinery —
it does **not** add Docker and does **not** claim complete hostile-code
containment.

### Added
- `src/nodechain/runtime/sandbox_command_runner.py` — backend-selected command
  execution seam with `local_subprocess` (default) and `native_os_sandbox`
  (opt-in) backends
- `src/nodechain/runtime/native_sandbox_exec.py` — Linux enforcement path that
  mirrors the validated child bootstrap (PID/network/mount namespace, mount
  confinement, seccomp) for arbitrary argv execution
- `BaseNode.sandbox_backend` property reading `NODECHAIN_SANDBOX_BACKEND`
  (mirrors the `NODECHAIN_SANDBOX_PROFILE` precedent)
- `workspace_src` keyword to `apply_mount_confinement` — bind-mounts the
  patched temp workspace at `/workspace` inside the confined child (before
  chroot); backward-compatible
- `sandbox_event_log` guaranteed output field on `sandbox_test_runner`
- `NodeEventEmitterMixin._emit_sandbox_event_log` — consumes the structured
  log and emits the v2.73 sandbox/code-execution `EventType` constants (these
  constants existed but were previously unemitted)
- `docs/native_sandbox_test_runner.md`
- `tests/test_native_sandbox_test_runner.py` (21 tests; Linux-only adversarial
  network-blocking test skips elsewhere)

### Changed
- `sandbox_test_runner._run_pytest()` now delegates to `SandboxCommandRunner`;
  `execute()` retains full control of git-status integrity, patch apply/not_run
  truth, workspace lifecycle, cleanup, and classification
- `ENV_ALLOWLIST` moved to `sandbox_command_runner.py` (single owner),
  re-exported from `sandbox_test_runner` for backward compatibility

### Security posture
- Native backend reuses existing namespace, mount-confinement, seccomp,
  cgroup, timeout, output-cap, and Python-enforcer machinery
- Fails closed when native sandboxing is explicitly requested but unavailable
  (no silent fallback to local subprocess)
- Enforcement strength varies by host capability (strongest on Linux)

### Compatibility
- Existing local temp-workspace pytest execution remains the default
- No Docker backend, no side-effect taxonomy changes, no chain topology changes

### Changed
- Version bump 2.75.0 → 2.76.0.

---

## [2.75.0] — Orchestrator Decomposition: Side-Effect Journaling Extraction

Continues the targeted runtime decomposition started in v2.74.0. Zero
behavioral change — pure structural refactor with the full test suite as
characterization tests.

### Extracted
- `src/nodechain/runtime/side_effect_journal.py` (SideEffectJournalMixin)
- 6 methods moved: `_journal_planned_side_effects`,
  `_journal_search_operations`, `_assert_declared_side_effect`, `_journal_one`,
  `_reconcile_side_effects_on_resume`, `_get_declared_se_types`
- Covers pre-call side-effect journaling, per-adapter search operation
  journaling, declared-vs-observed enforcement, single-entry ledger writes,
  canonical declared-type lookup, and resume reconciliation for the crash
  window (started-but-not-completed effects)
- Orchestrator now inherits both mixins
  (`NodeEventEmitterMixin`, `SideEffectJournalMixin`); all self. references
  work unchanged. MRO verified conflict-free.
- `_node_has_contract` intentionally remains on Orchestrator (general helper
  used beyond side-effect journaling)

### Impact
- orchestrator.py: 2772 → 2521 lines (251 lines removed, 9% reduction)
- Side-effect governance now has a dedicated runtime seam, preparing the
  codebase for future container-isolation work
- 6,138 tests pass — zero behavioral change verified

### Changed
- Version bump 2.74.0 → 2.75.0.

---

## [2.74.0] — Orchestrator Decomposition: Node Event Emitter Extraction

First targeted decomposition of orchestrator.py per VISION.md §12. Zero
behavioral change — pure structural refactor with full test suite as
characterization tests.

### Extracted
- `src/nodechain/runtime/node_event_emitter.py` (NodeEventEmitterMixin)
- 4 methods moved: `_emit_all_contracts_validated`, `_emit_contract_validated`,
  `_emit_model_requirements_evaluation`, `_emit_node_detail_events`
- Includes the ROUTING_DECISION emissions for source_quality_evaluator and
  risk_classifier, and the v2.68 model_requirements evaluation hook
- Orchestrator now inherits the mixin — all self. references work unchanged

### Impact
- orchestrator.py: 3246 → 2772 lines (474 lines removed, 15% reduction)
- All 6,131 tests pass — zero behavioral change verified

### Changed
- Version bump 2.73.0 → 2.74.0.

---

## [2.73.0] — Governed Temp-Workspace Test Execution

Stage 2 crosses the final boundary: from governed proposal to governed
**execution** of change. Validated patches are applied in isolated temp
workspaces (tracked-file export), pytest runs with a bounded command profile,
results are captured, and workspaces are cleaned up. The real repo is never
modified.

**Security claim precision (per strategic review):** this is governed,
bounded, temp-workspace execution — NOT a full hostile-code sandbox. Temp
directory protects the real repo from mutation but does not fully isolate the
host (tests can read host files, open sockets). Container/OS isolation is a
future release.

### New nodes (2)
- sandbox_test_runner: tracked-file export → apply patch → run pytest (bounded) → capture results → cleanup
- test_result_classifier: deterministic verdict from exit code (pass/fail/timeout/error/not_run)

### Governance surfaces (new in v2.73)
- `code_execution` declared as BOTH side effect AND capability (per strategic review)
- Command profile: pytest only, shell=False, bounded timeout (120s), output cap (50KB)
- Env allowlist: explicit set, no secrets
- Tracked-file workspace export (git archive — excludes .git, .env, caches, untracked)
- Per-patch isolation: separate workspace + verdict per patch
- Cleanup: always, failures traced not swallowed
- Trace truth: patch_apply_failed → test_not_run (NOT test_failed)

### Side-effect taxonomy expanded
- `code_execution`: new canonical SideEffectType
- `sandbox_file_write`: new canonical SideEffectType
- Total canonical types: 5 (was 3)

### Real run (commit c227874e)
- 10/10 nodes completed, 68 trace events
- 0 patches reached sandbox (validator correctly rejected malformed patch — governance working)
- `repo_git_status_unchanged: True`
- 11/12 gates pass (gate 10 = per-patch isolation vacuously true with 0 patches)

### Added
- 2 new node modules: sandbox_test_runner.py, test_result_classifier.py
- 3 new port types: SANDBOX_TEST_RESULTS, CLASSIFIED_TEST_RESULTS, FINAL_TEST_REPORT
- 16 new trace event types (workspace lifecycle, patch apply, command auth, execution, cleanup, classification)
- blueprints/code_review_full_v1.yaml (10-node chain)
- tests/test_sandbox_execution.py (18 tests)
- SideEffectType expanded (code_execution, sandbox_file_write)
- 32 total nodes registered (was 30)

### Changed
- Version bump 2.72.0 → 2.73.0.

---

## [2.72.0] — Code Review Assistant: Governed Patch Proposal Path

Stage 2 crosses the next boundary: from governed observation (v2.71) to
**governed proposal of change**. Patches can be proposed, validated, traced,
and exported as artifacts — but never applied to the real repository.

### New chain extension: patch proposal path (4 new nodes)

```
[v2.71 review] → report_generator
                       │
[v2.72 proposal]      ▼
                 patch_generator → patch_validator → patch_risk_classifier → patch_report_assembler
```

**Governance properties proven:**
- Patch proposals are typed-port artifacts, NOT side effects (per strategic review)
- Patch validator writes ONLY to a temp workspace — never the real repo
- Real repo working tree is byte-for-byte unchanged after validation
- No tests run, no commits, no pushes, no code execution
- Risk classifier assigns deterministic LOW/MEDIUM/HIGH per patch
- Report explicitly states what was NOT done (trace truth rule)

### Real run (commit c227874e)
- 9/9 nodes completed, 59 trace events
- 1 patch proposed, 1 rejected (git apply --check caught anchor mismatch — governance working correctly)
- 10/10 acceptance gates pass
- `repo_working_tree_unchanged: True` verified

### Design decisions (per ChatGPT v2.72 design study, conversation 6a4adfe1)
- `patch_proposal` is NOT a SideEffectType — it's a typed-port artifact
- `file_read` is a governed capability, not a side effect (two-axis model)
- `sandbox_file_write` is the only new effect class (temp workspace only)
- `code_execution` deferred to v2.73
- Node rename: `patch_report_assembler` (not `final_report_with_patches`) — assembles, doesn't invent

### Added
- 4 new node modules: patch_generator.py, patch_validator.py, patch_risk_classifier.py, patch_report_assembler.py
- 4 new port types: PATCH_PROPOSALS, VALIDATED_PATCHES, CLASSIFIED_PATCHES, FINAL_PATCH_REPORT
- 6 new trace event types: PATCH_PROPOSED, PATCH_VALIDATION_STARTED/PASSED/FAILED, PATCH_RISK_CLASSIFIED, REPO_WRITE_BLOCKED
- blueprints/code_review_with_patches_v1.yaml (9-node chain)
- tests/test_patch_proposal_governance.py (15 tests: repo-mutation prevention, path safety, risk classification, trace truth)
- 30 total nodes registered (was 26)

### Changed
- Version bump 2.71.0 → 2.72.0.

---

## [2.71.0] — Code Review Assistant: Read-Only Governed Review Path

Stage 2's second proof: the governed-chain model generalizes beyond the
Research & Decision Assistant to a completely different governance surface
(file/tool access on developer artifacts).

### New chain: Code Review Assistant (5 nodes)

```
code_review_request → file_reader → code_analyzer → finding_classifier → review_report_generator
```

**Governance properties proven (distinct from the research chain):**
- File-access governance: file_reader reads ONLY paths matching allowed_paths
- Read-only enforcement: no writes, no patches, no commits
- Tool access governance: uses `git` as a declared read-only tool
- Artifact provenance: every finding cites file_path + line_range

### Real run (review target: commit c227874e; release commit: db6dcdd0)
- 5/5 nodes completed, 38 trace events
- 2 findings: 1 blocker (dead-code function `_validate_model_requirements`), 1 warning (silent exception swallow)
- Recommendation: request_changes
- All 7 acceptance gates pass

### Truncation fix
- File content truncated at line boundary (not mid-token), preventing false-positive syntax errors
- file_reader: 5000→12000 char limit, line-boundary cut
- code_analyzer: 2000→4000 char per-file limit, line-boundary cut

### Added
- 5 new node modules: code_review_request.py, file_reader.py, code_analyzer.py, finding_classifier.py, review_report_generator.py
- 5 new port types: CODE_REVIEW_GOAL, CODE_ARTIFACTS, REVIEW_FINDINGS, CLASSIFIED_FINDINGS, FINAL_REVIEW
- blueprints/code_review_v1.yaml
- tests/test_code_review_chain.py (11 tests: governance, classification, port-chain, blueprint structure)
- Nodes wired into orchestrator's node registry (26 total nodes)

### Changed
- Version bump 2.70.0 → 2.71.0.

---

## [2.70.0] — Research Baseline Comparison Harness

Proves the governed-chain value proposition: NodeChain is structurally better
than a flat agent on the same question and same frozen source set — not at
writing prose, but at verifiable governance.

### The experiment
Same research question, same 10 frozen sources (hash `b9fc69a56`), same model
(GLM-4.6). NodeChain's v2.69 output vs a flat LLM agent with no governance
infrastructure (one call, no validators, no trace, no claim validator, no risk
classifier).

### Results — 7/7 acceptance gates pass

| Dimension | NodeChain | Baseline (flat agent) |
|---|---|---|
| Fabricated citations | 0 (verified through alias-map + claim validator + traceable evidence chain) | 0 (self-asserted, no validation) — raw tie; NodeChain strictly better on citation auditability and validation provenance |
| Structured claims | 9 (all with supporting_sources) | 0 (free text) |
| Validated claims | 9 (passed claim validator) | 0 (no validator exists) |
| Reviewer-facing citations | 8 (structured list) | 0 (short refs in prose) |
| Confidence calibration | MEDIUM (0.55) + uncertainty disclosure | "high" (self-asserted) |
| Execution trace | 133 events, 12 nodes | none |

The baseline produced genuinely good prose. NodeChain's advantage is structural:
verifiable citation integrity, calibrated confidence, structured claim lineage,
and an auditable execution record. A flat agent cannot match these without
becoming a chain — which is the value proposition.

### Added
- `scripts/baseline_comparison.py` — fair comparison harness (baseline agent
  path + automated 7-point gate scorer)
- `data/v2.70_baseline/frozen_comparison_fixture.json` — frozen source set,
  question, NodeChain result, source_set_hash for reproducibility
- `tests/test_baseline_comparison.py` — 8 tests (fixture integrity, scorer
  correctness, harness reproducibility)

### Changed
- Version bump 2.69.0 → 2.70.0.

---

## [2.69.0] — Citation Surface and Source Acquisition Reliability

Closes the two known-limitation gaps from v2.68: reviewer-facing citation
aggregation and per-adapter result visibility. Both fixes verified on a real
chain rerun (run ID df0ab40f, 12/12 nodes, 9/9 claims validated, 0 fabricated
citations, arXiv + OpenAlex both contributing 50 results each).

### Fixed
- **Citation aggregation root cause:** `response_generator.citations` was empty
  because a status filter (`"confirmed"` / `"partially_confirmed"`) excluded
  every claim in the v2.68 run (all were `"unconfirmed"`). Now aggregates
  citations from any validated claim with `supporting_sources`, regardless of
  confidence status. The per-claim `status` is preserved in each citation entry
  for honesty. Deduplicates by `source_ref`.
- **arXiv zero-result diagnosis:** tested in isolation with both short terms
  and the exact v2.68 long-phrase query terms — both return results. The v2.68
  zero was transient (rate-limit/burst behavior during a 4-query batch against
  arXiv's 3-req/sec limit). No code fix needed.

### Added
- **`adapter_result_counts`** in `search_tool` output: per-adapter tally of
  results returned. Makes every adapter's contribution (or lack thereof)
  visible at the output level.
- **`silent_zero_adapters`** in `search_tool` output: adapters that were called,
  returned zero results, and recorded no failure. These are distinguished from
  failed adapters (which raised `SearchAdapterError`). Per agreement with
  strategic reviewer: "silent zero" is the real defect to eliminate — empty
  adapter results must never be silently collapsed into overall success.

### Tests
- `tests/test_citation_aggregation.py` — 5 tests (unconfirmed-claims-produce-
  citations, deduplication, mixed statuses, empty-claims, fabricated-ref-
  exclusion)
- `tests/test_adapter_result_counts.py` — 5 tests (output structure, silent-zero
  logic, failed-adapter distinction, all-zero, mixed results + failures)
- Full suite: 6079 passed, 78 skipped, 0 failed

### Real-chain acceptance run
- Run ID: `df0ab40f-05f7-46f7-a3ee-a0cd4dd5cdc8` (artifact ID, not a commit)
- 12/12 nodes completed
- `response_generator.citations`: 8 (was 0 in v2.68)
- `adapter_result_counts`: `{arxiv: 50, openalex: 50}`
- `silent_zero_adapters`: `[]`
- 9 synthesizer claims, 9 validated, 0 fabricated citations

### Changed
- Version bump 2.68.0 → 2.69.0.

---

## [2.68.0] — Model Requirements Traceability + First Real End-to-End Chain Run

The product gate is cleared. A real Research & Decision Assistant chain completed
end-to-end (12/12 nodes) with a capable structured-output model, producing a cited
recommendation with validated claims. This release also makes explicit the
model-output floor that was implicit during the July 1 diagnostic run, and ships
four bug fixes the real run surfaced between the search layer and the synthesizer.

### Real chain run (the proof)
- **Status:** completed, 12/12 nodes (GLM-4.6 via OpenAI-compatible endpoint)
- **Synthesizer:** 8 claims, 14 valid citations, 0 fabricated, 0 empty support
- **Claim Validator:** 8 validated claims
- **Response:** cited recommendation, MEDIUM confidence (0.55) with explicit
  uncertainty disclosure ("evidence_quality: few_confirmed_claims")
- **Trace:** `model_requirements_evaluated` event fired on the synthesizer as
  designed; source-quality policy decision trace-visible

### Added — model capability requirements (v2.68 core change)
- `ModelRequirements` value object on `node.contract.requirements`: three fields
  — `structured_output_required`, `min_output_tokens`, `json_schema_adherence`.
  Born from the v2.68 diagnostic: the Evidence Synthesizer produced 0 claims on
  Gemma 4 12B because the model could not produce structured JSON; the
  requirement was implicit. v2.68 makes it explicit and traceable.
- New `EventType.MODEL_REQUIREMENTS_EVALUATED` trace event, emitted by the
  orchestrator after every model-backed node invocation. Fields: `node_id`,
  `contract_id`, `model_selected`, `requirements`, `evaluation_status`
  (`satisfied` / `unsatisfied` / `unknown` / `not_applicable`), `known_capabilities`,
  `unknown_reasons`, `enforcement_mode`.
- **v2.68 enforcement posture:** declare, evaluate what is known, trace, warn on
  unknown. Does NOT block the run. Hard enforcement + capability profile
  registry deferred to v2.69.
- Wired onto `nodechain.research.evidence-synthesizer.v1`. Other model-backed
  nodes get it in later releases — broad retrofit is out of v2.68 scope.

### Added — source_quality_policy.single_adapter_acceptance.v1
- Single-adapter source sets are accepted **only when** ≥3 qualified sources,
  ≥1 peer-reviewed source, average quality ≥0.4, and citation-groundable
  metadata (stable `source_id` + non-empty `title`) are present. The policy
  surfaces `policy_decision` metadata with reason codes, including
  `model_loop_flag_overridden_by_policy`.
- Replaces the previous unconditional corroboration rule, which forced the chain
  to loop against adapters that had genuinely returned nothing on the first pass.
  Looping cannot make a silent adapter respond.
- New helper `_sources_have_title(sources, source_ref)` for the
  citation-grounding check.

### Fixed — chain bugs surfaced by the real run
- **`context_selector.py`: search query adapter targeting** — search queries
  were only targeting `source_routing.primary`, silently dropping `secondary`
  and `domain_specific`. Adapters the planner routed to were granted but never
  invoked. Fix: `target_adapters = primary + secondary + flattened(domain_specific)`.
- **`source_quality.py`: deterministic source ordering** — evaluator truncated
  to `pre_filtered[:10]` by insertion order, which on multi-API batches was all
  arXiv preprints (no citations, not peer-reviewed). Fix: sort by
  `citation_count` desc + `peer_reviewed` first before truncating.
- **`orchestrator.py`: v2.68 hook error path** — the `MODEL_REQUIREMENTS_EVALUATED`
  hook called `self._log()` which does not exist on `Orchestrator`. Hook threw
  on the synthesizer's first run. Fix: removed the log calls; the trace event
  IS the warning.

### Tests
- `tests/test_model_requirements.py` — 6 tests (declaration, parse/serialize,
  legacy-compat, validation, trace-event type, unknown-does-not-raise)
- `tests/test_single_adapter_policy.py` — 6 tests (1 positive, 5 negative
  covering every threshold violation + model-loop-override-without-thresholds)
- 227 tests in the broader regression set (quality + loop + contract +
  single_adapter): all pass, 0 regressions

### Known limitations
- arXiv returned zero results in the validated real-chain run; tracked for v2.69
  adapter reliability work.
- Top-level `response_generator.citations` may be empty even when claim-level
  `supporting_sources` are valid and traceable; reviewer-facing citation
  aggregation is deferred to v2.69.
- The `total_evaluated` field name varies between runs; cosmetic normalization
  deferred.

### Diagnostic note (Gemma 4 12B failure)
The original July 1 v2.68 diagnostic run failed at the Evidence Synthesizer
(0 claims from 56 sources), with a hypothesized cause of context-window overflow
from 56 abstracts. That hypothesis was falsified: code inspection showed the
synthesizer already caps at top-8 sources with 500-char abstracts (~2K input
tokens), nowhere near Gemma's context limit. A replay harness
(`scripts/replay_synthesizer.py`) was built and run against the frozen
QualifiedSourceSet; GLM-4.6 produced 7 valid cited claims on the first attempt.
The conclusion is that the failure was Gemma-specific, not architectural. The
Gemma failure was not re-instrumented before tag — the context-overflow
hypothesis was falsified by code inspection + replay, and the GLM-4.6 success is
sufficient to prove the architecture under a capable structured-output model
(not yet model-agnostic robustness).

### Changed
- Version bump 2.67.3 → 2.68.0.

---

## [2.67.3] — OpenAlex Auth and Abstract Preservation

Two correctness bugs discovered during Phase 4 real-chain runs. These affect the normal product path, not just degraded conditions.

### Fixed
- **OpenAlex adapter ignored API key:** The `.env` file has `OPENALEX_API_KEY` but the adapter only read `OPENALEX_EMAIL`. Without the key, OpenAlex returns 503 (premium pool required). With the key, it returns 200 with relevant results and abstracts. Adapter now reads `OPENALEX_API_KEY` and passes it as `params["api_key"]`.
- **Source ingestion destroyed OpenAlex abstracts:** `source_ingestion.py` hardcoded `"abstract": ""` for OpenAlex sources with the comment "too complex to reconstruct here" — but the OpenAlex adapter already reconstructs abstracts from the inverted index. The ingestion normalizer was throwing away abstracts the adapter had already built. Fixed: now uses `raw.get("abstract", "")`.
- **OpenAlex null-safety:** `primary_location.source` can be None in OpenAlex API responses, causing `AttributeError` during normalization. Fixed with null-safe nested access.

### Context
These bugs meant that even when OpenAlex returned relevant RAG/hallucination papers with full abstracts, NodeChain (1) couldn't authenticate to get them and (2) would discard the abstracts during ingestion. The synthesizer then received title-only sources and could not produce claims.

### Changed
- Version bump 2.67.2 → 2.67.3.

## [2.67.2] — Search Adapter Fallback Resilience

Search adapter fallback was arbitrarily limited to the first 2 granted adapters, causing the chain to fail when those 2 happened to be unavailable (rate-limited or down). This was discovered during the Phase 4 re-run attempt where Semantic Scholar (429) and OpenAlex (503) both failed while arXiv, CrossRef, and PubMed were available but never called.

### Fixed
- **Fallback uses all granted adapters:** `search_tool.py` no longer truncates to `cap_adapters[:2]`. When the planner gives no target adapters, ALL policy-granted adapters are tried.
- **Zero-results rescue:** When the planner explicitly routes to specific adapters but all return zero results, a rescue pass tries all granted adapters not already attempted. Failed adapters are not retried (the adapter layer already handles retries).
- **Rescue metadata in output:** `rescue_attempted` field added to search output for observability.

### Added
- **`tests/test_search_fallback_resilience.py`:** 5 tests covering:
  1. No target adapters → all granted adapters attempted
  2. First two fail, later succeeds → search succeeds
  3. Explicit targets return zero → rescue tries untried granted adapters
  4. Ungranted adapters never called, even during rescue
  5. Output includes rescue metadata

### Changed
- Version bump 2.67.1 → 2.67.2.

### Context
This is the second pre-v2.68 plumbing fix. The Phase 4 chain re-run hit this bug when Semantic Scholar and OpenAlex were both unavailable simultaneously. The fix ensures the system tries all available adapters rather than silently failing on the first two.

## [2.67.1] — Real Adapter and Trace Wiring Fixes

Preconditions for v2.68 real chain execution. These fixes were discovered during the first real end-to-end chain run (diagnostic, not released as v2.68 — see `docs/runs/v2.68-first-real-run-diagnostic.md`).

### Fixed
- **Adapter routing:** `run.py` was routing `openai_compatible` provider through `LIMModelAdapter` (expects LIM API format) instead of `ModelAdapter` (proper OpenAI-compatible support). Now uses `ModelAdapter(provider="openai_compatible")`.
- **Env var alignment:** reads `OPENAI_BASE_URL` first (what `.env` uses), falls back to `NODECHAIN_BASE_URL`, then `LIM_BASE_URL`.
- **Trace collector wiring:** orchestrator's `_build_context()` now injects `self.trace.model_dump()` into context specifically for the trace_collector node. The collector verifies the truth rule and reports event count. No longer writes the trace file itself (that's `run.py`'s job after chain completion).
- **CLI trace viewer:** `nodechain trace <run_id>` now resolves `<run_id>.json` in `--trace-dir` (default: `data/traces/`) instead of treating the run ID as a literal file path. Added `--trace-dir` option.

### Added
- **`docs/runs/v2.68-first-real-run-diagnostic.md`:** forensic report documenting the first real 12-node chain run. Records configuration, node-by-node status, search adapter results, evidence synthesizer failure analysis, governance behavior assessment, what the run proves, and what it does not yet prove.

### Context
The first real chain run (run ID `62008aa6-...`) proved the governance machinery works under real conditions: all 12 nodes executed, 56 real academic sources were found, the risk classifier correctly identified HIGH risk, the response generator chose honest failure over hallucination, and memory writes were correctly blocked. The evidence synthesizer produced zero claims — a diagnostic issue to be resolved before v2.68.0.

### Changed
- Version bump 2.67.0 → 2.67.1.

## [2.67.0] — Vision Alignment: Auditable Autonomous Systems

Rebases VISION.md from an internal platform-proof document into a product-strategy document. The product vision — "auditable autonomous systems, not just automations" — becomes the dominant framing, with composable governed nodes as the mechanism.

### Changed
- **VISION.md fully restructured** (17 sections, replacing the prior 18):
  - New executive thesis: "auditable autonomous systems, not just automations" layered on top of the platform thesis (governance-first composable nodes)
  - New product thesis section: the governed lifecycle (goal → plan → context → tools → memory → validation → review → policy → trace → evaluation → improvement)
  - New "What NodeChain Can Become" section: 5 core products (Runtime, SDK, Registry, Blueprint Studio, Trace Console)
  - New "Reference Autonomous Chains" section: 6 chains (Research, Email, Code Review, Support, Procurement, Incident Response) with governance rationale and status
  - New "Node Library Vision" section: 4 node families (reasoning, tool/adapter, validation, governance)
  - New "Industry Product Directions" section: Legal, Finance, Healthcare, Enterprise, Engineering
  - New "Engineering Maintainability Boundary" section: honest risk ranking of large files with the principle "prove the product path first, then decompose observed hot paths"
  - Replaced "What NodeChain Is Not Yet" with a readiness-boundary table (status today / possible stage / current claim / not claiming yet)
  - Replaced shipped v2.60-v2.66 roadmap with commercial staging (Stage 1/2/3) + next release targets (v2.68 = real chain run)
  - Updated "Current Implementation State" to v2.67.0 with accurate counts
  - Updated external reviewer guide: "run a real chain first, then inspect internals"
  - Updated competitive position: sharpened around governed reuse + auditability as native primitives

### Strategic shift
v2.63–v2.66 proved the platform is internally coherent (registry-resolved packages, quality scorecards, operator dashboard). v2.67.0 reframes the vision to answer the next question: does a governed autonomous chain produce useful work under real conditions? That question defines v2.68.

### Version bump 2.66.1 → 2.67.0

## [2.66.1] — Operator Evidence Dashboard (review hotfix)

Addresses three issues ChatGPT found in the v2.66.0 review: a crash bug, a staleness gap, and an overall-health visibility gap. Plus CLI subcommand tests that would have caught the crash.

### Fixed
- **Crash bug (blocking)**: `nodechain dashboard scorecards` without `--refresh` raised `UnboundLocalError` because `refresh_error` was only defined inside the `if refresh:` block. Now initialized to `None` before the branch.
- **nodechain_version staleness**: `is_scorecard_cache_stale()` now compares the cached `nodechain_version` against the live runtime version. Previously a v2.65.1 cache would not be detected as stale under v2.66.0.
- **Overall health visibility**: `collect_dashboard()` now adds reuse/scorecard health issues to the `issues` list. Previously a non-healthy reuse or scorecard section could be hidden by the `if not issues: overall = HEALTHY` override.

### Added
- **CLI subcommand tests** (4 tests): `dashboard scorecards` (no refresh), `dashboard scorecards --json`, `dashboard reuse`, `dashboard reuse --json`. These would have caught the crash bug before release.

### Changed
- Version bump 2.66.0 → 2.66.1.

## [2.66.0] — Operator Evidence / Reuse Dashboard

Extends the existing `nodechain dashboard` with two new sections that make the v2.64-v2.65 proofs operator-visible in one place: registry-resolved reuse proof status and cached deterministic node quality scorecards.

### Added
- **`nodechain dashboard reuse`** — shows shared node provenance (registry origin, package root, content_digest), lockfile status (exists, entries valid, digest match), and health (HEALTHY/WARNING/DEGRADED based on resolution + lockfile proof).
- **`nodechain dashboard scorecards`** — shows cached deterministic node quality scorecard results (pass/fail, all 6 metrics, staleness state). Cache-backed by default (does NOT run evaluations).
- **`nodechain dashboard scorecards --refresh`** — runs scorecards for all shared nodes via the shared library (no subprocess), writes cache atomically, then renders. On refresh failure: shows old cache as stale with refresh_error, or shows "refresh_failed" state if no cache.
- **Scorecard cache infrastructure** in `node_quality_scorecard.py`:
  - `get_shared_registry_node_ids()` — centralized target discovery (single source of truth)
  - `write_scorecard_cache()` — atomic aggregate cache writer with envelope format
  - `load_scorecard_cache()` — pure loader (read + validate, no side effects)
  - `is_scorecard_cache_stale()` — separate staleness check (digest/version comparison)
- **Two new dashboard sections** registered in both `collect_dashboard()` and `collect_dashboard_v2()` aggregators.
- **`tests/test_dashboard_reuse_scorecards.py`** — 24 tests across 7 test classes.

### Key design decisions (agreed with ChatGPT)
- **Extend existing dashboard**, not new command — reuse `collect_dashboard`/`render_dashboard`/section subcommands.
- **Cache-by-default** — dashboard is inspection, not evaluation runner. `--refresh` calls shared library directly.
- **Pure loader** — `load_scorecard_cache()` reads/validates only; staleness is separate.
- **Missing vs invalid vs stale** — distinct operator states: missing→UNKNOWN, invalid→DEGRADED, stale→WARNING.
- **Non-silent refresh failure** — old cache shown as stale with error, not silently overwritten.
- **Centralized target discovery** — `get_shared_registry_node_ids()` used everywhere to prevent drift.
- **Lockfile mismatch is DEGRADED** (failed proof), missing lockfile is WARNING (absence of enforcement).

### Changed
- `eval node-scorecard --all-shared` now uses `get_shared_registry_node_ids()` (was hardcoded).
- Version bump 2.65.1 → 2.66.0.

### Deferred
Web dashboard, daemon, database migration, trend tracking, time series, remote registry, certified registry, model-backed scorecards.

## [2.65.1] — Node Quality Scorecards (review cleanup)

Addresses two observations ChatGPT flagged in the v2.65.0 review.

### Fixed
- **`run_registry_node_scorecard(registry=...)` now respects injected registry**: The function was constructing a fresh `NodeLoader` even when a pre-scanned registry was provided, ignoring the `registry` parameter for node resolution. Restructured so the provided registry is used for the package lookup (`content_digest`), while the node instance is always resolved via `NodeLoader` for provenance stamping.
- **Created `docs/node-quality-scorecards.md`**: The planned documentation file was missing from the v2.65.0 commit. Added with full explanation of profiles, metrics, branch coverage, report format, architecture, and CLI usage.

### Changed
- Version bump 2.65.0 → 2.65.1.

## [2.65.0] — Deterministic Node Quality Scorecards

Introduces node-level quality evaluation for registry-resolved deterministic nodes. Closes the gap: v2.64.x proved shared nodes are registry-resolved packages; v2.65.0 proves those packages have measurable node-level quality.

### Added
- **`src/nodechain/runtime/node_quality_scorecard.py`** — deterministic node quality evaluation module with:
  - `NodeScorecardCase` / `NodeScorecardReport` data models
  - `run_node_scorecard(node_instance, cases, contract)` — pure runner, invokes through `NodeInvoker` for real latency measurement
  - `run_registry_node_scorecard(node_id)` — convenience helper, resolves via NodeLoader with provenance
  - `get_shared_node_golden_cases()` — 12 golden I/O cases (8 for risk classifier, 4 for trace collector) covering ALL branches
- **Six deterministic metrics:**
  1. `reproducibility` — run same case 3x, compare canonical JSON with ignored volatile fields stripped. Target: 1.0
  2. `exact_match_correctness` — expected output is a subset of actual (classification correctness, extra self-reported fields allowed). Target: 1.0
  3. `schema_compliance` — from `NodeContract.guaranteed_fields`. Target: 1.0
  4. `cost_compliance` — `model_required=false` nodes must report `cost_usd == 0.0`. Target: 1.0
  5. `latency_ms_p95` + `latency_ms_mean` — measured via NodeInvoker. Warn >100ms, hard-fail >500ms. Per-case: `latencies_ms` array + mean + max.
  6. `rule_branch_coverage` — covers both factor triggers AND outcome rules (namespaced: `risk_factor.*`, `level.*`, `trace.*`). Target: 1.0
- **`report_digest`** — stable SHA-256 over quality fields only (excludes volatile timing fields), deterministic across separate runs.
- **CLI:** `nodechain eval node-scorecard --node shared_risk_classifier` / `--all-shared` with `--output` and `--json`.
- **`tests/test_node_quality_scorecard.py`** — 53 tests across 8 test classes.

### Key design decisions (agreed with ChatGPT)
- **Deterministic-only profile** for v2.65.0; model-backed scorecards deferred (need fuzzy correctness, tolerance bands).
- **`NodeInvoker.invoke()`** used for invocation (real latency_ms measurement, not direct `node.execute()`).
- **`report_digest` excludes timing fields** so it's stable across runs (latency varies).
- **`expected_branches`** covers both factor triggers and outcome rules, not just `risk_factors`.
- **Volatile field handling:** `trace_id` (uuid-derived) is ignored for `shared_trace_collector` reproducibility.

### Verified
- Both shared nodes pass all 6 metrics at target values.
- 53 scorecard tests pass.
- CT 801 CI verifies the release.

### Deferred
- Model-backed node scorecards (fuzzy correctness, tolerance bands, nondeterminism controls)
- Cross-chain scorecard aggregation (v2.66.0 dashboard)
- Trend tracking, automated golden-case generation

## [2.64.1] — Registry-Resolved Reuse Proof (review cleanup)

Addresses two cleanup issues ChatGPT flagged in the v2.64.0 review. Neither invalidates the core proof; both matter for external reviewer credibility.

### Fixed
- **Lockfile docs accuracy**: `registry.lock.json` is correctly gitignored (paths are machine-specific), but the docs instructed reviewers to inspect it without first explaining generation. Updated `docs/reusable-node-proof-pack.md` to instruct `nodechain registry lock` before `--registry-resolved` and before inspecting the lockfile.
- **`test_reuse_proof_e2e.py` honest labeling**: the v2.64.0 CHANGELOG claimed this file was rewritten; it was not (it still uses the direct-wiring path, which is valid for node identity/type testing). Relabeled as a legacy direct-wiring test with a clear docstring explaining the division of labor: this file proves node-level properties, `test_reuse_proof_runtime_smoke.py` proves the registry-resolution lifecycle.

### Changed
- Version bump 2.64.0 → 2.64.1.

## [2.64.0] — Registry-Resolved Reuse Proof

Closes the reviewer objection: *"The runtime proof is real, but the shared nodes are still wired directly into code rather than proven through the registry lifecycle."* Shared nodes now resolve through the local registry with full provenance, lockfile enforcement, and tamper denial.

### The proof (5 independent facts)
1. **Exclusion**: `_create_nodes(include_shared_nodes=False)` omits shared nodes — they are NOT in built-ins
2. **Resolution**: `NodeLoader.load()` resolves both shared nodes from the local `RegistryIndex`
3. **Provenance**: resolved instances carry `_node_origin="local_registry"`, `_package_root`, `_module_path`
4. **Locking**: lockfile pins `content_digest` (full 64-char SHA-256); tampered/missing/mismatched digests deny execution
5. **Runtime**: all 3 proof blueprints complete via `Orchestrator.run()` with registry-resolved nodes

### Added
- **`NodePackage.content_digest()`**: full-length deterministic SHA-256 with path + length-prefixed framing (stronger than the 16-char display `content_hash`). Used for all fail-closed integrity checks.
- **`enforce_lockfile_for_nodes()`**: fail-closed lockfile enforcement for specific resolved nodes. Denies on: lockfile missing, entry missing, version mismatch, origin mismatch, digest missing, digest mismatch, package not admitted.
- **`_create_nodes(include_shared_nodes=True)`**: gates shared node direct-wiring so registry-resolved mode can exclude them.
- **`run_chain(registry_resolved, enforce_lockfile, lockfile_path)`**: when registry-resolved, shared nodes must resolve via `NodeLoader(state_manager=sm)` (shared StateManager for audit coherence).
- **`nodechain run --registry-resolved`**: CLI flag enabling registry-resolved mode with explicit output and lockfile enforcement.
- **`tests/test_reuse_proof_runtime_smoke.py`** rewritten: 35 tests proving all 5 facts above.
- **`tests/test_reuse_proof_e2e.py`** relabeled as legacy direct-wiring test (proves node identity/types/cross-chain instance reuse via the direct path; registry-resolved proof is in the runtime smoke test).
- **`tests/test_registry_lockfile_enforcement.py`** (new): 11 tests covering all 7 denial conditions + digest length guards.

### Fixed
- **Shared node manifests were not registry-admissible**: `nodes/shared_risk_classifier/node.yaml` and `nodes/shared_trace_collector/node.yaml` were missing `contract_id` and `version` fields, causing `NodePackage.from_yaml()` to reject them (`parse_error`). This is why v2.62-v2.63 used the `_load_shared_node()` bypass — the registry path never actually worked. Added `contract_id` + `version` to both manifests; they now admit and resolve correctly.

### Changed
- `generate_lockfile()` now records `content_digest` alongside `content_hash` in each lockfile entry.
- `registry.lock.json` regenerated: now locks 3 packages (echo_node + both shared nodes) with full digests.
- Version bump 2.63.3 → 2.64.0.

### Deferred (agreed with ChatGPT)
Certified registry publish/install (distribution proof, separate lifecycle); separate manifest/contract/implementation digests (v2.64.1 if needed); resume.py/recover.py NodeLoader fallback; remote registry distribution.

> v2.64.0 proves local/private runtime registry resolution. Certified registry distribution remains a separate lifecycle proof.

## [2.63.3] — Self-Hosted CI Migration

Migrates all Linux CI jobs from GitHub-hosted `ubuntu-latest` to the CT 801 self-hosted runner (Proxmox LXC, Ubuntu 24.04). This restores green CI after the GitHub Actions runner-allocation block that affected the private repo since v2.61.0.

### Changed
- **`.github/workflows/ci.yml`**: All 9 Linux jobs moved to a self-hosted runner — lint, unit-fast, orchestrator-recovery, trust-collector, slow-shard-1/2/3, cli-smoke, package-build.
- **`windows-tests`**: Remains on GitHub-hosted `windows-latest`. This is the one remaining billed job — an explicit tradeoff, since a Linux LXC runner cannot service Windows jobs and dropping Windows coverage to reach zero hosted minutes would be the wrong tradeoff.
- **`docs/ci.md`**: Added "Self-hosted Linux runner" section documenting the runner labels, non-root `gha-runner` execution identity, workspace isolation (`/opt/actions-runner/_work`, not the admin clone), and the Windows exception.

### Runner (CT 801) — operational context
- Non-root user `gha-runner` (uid 1000, no sudo)
- Systemd service, auto-starts on boot, survives reboot (verified)
- Own clean workspace at `/opt/actions-runner/_work/nodechain/nodechain`
- Smoke canary passed twice (pre- and post-reboot)
- Admin clone at `/opt/nodechain-test` untouched

### Release sequencing
```
v2.63.2 = master made green and runner-ready
v2.63.3 = CI moved onto CT 801 and verified        ← this release
v2.64.0 = Registry-Resolved Reuse Proof (developed with working CI)
```

This is a governance/CI release, not a feature release. No product/runtime changes.

## [2.63.2] — CI Migration Readiness Patch

Closes two issues that the downed GitHub Actions CI had been hiding since v2.60.0, surfaced by running the full suite on the Proxmox CT 801 runner candidate. Master is now green and migration-ready for the self-hosted runner bring-up.

### Fixed
- **Doc-drift test (real failure)**: `test_seccomp_consolidation.py::test_readme_status_is_v1_12_5` asserted `"v2.31.0" in README.md`, but the v2.60.0 "Documentation Truth" rewrite dropped that anchor. Re-anchored as `test_readme_documents_seccomp_milestone_version`, verifying the README's actual `"Seccomp Enforcement (v1.2.2+)"` section — the truthful milestone-of-record.
- **LXC seccomp e2e tests (environmental failure)**: `test_preset_e2e.py` gated the two seccomp-preset e2e tests on `platform.system() != "Linux"` only. LXC containers report as Linux yet cannot apply seccomp-bpf, so both failed on Proxmox CT 801 with `seccomp_enforced != True`. Replaced the OS-only gate with a capability gate that reuses the runtime's own `SeccompBackend().available` detector, so the test's notion of "can enforce seccomp" matches production truth. The tests still run and assert enforcement on bare-metal Linux or a capable VM.

### Changed
- Version bump 2.63.1 → 2.63.2 across `__init__.py`, `pyproject.toml`, `test_release_guard.py`, and 38 version-asserting test files, plus README/VISION/ARCHITECTURE/ci.md current-version anchors.

### Context
These are the two known-red items that must not be the first signal from the new self-hosted runner. The seccomp tests skip honestly on environments that cannot enforce the capability; the doc-truth test now asserts what the README actually documents.

## [2.63.1] — Reuse Proof Assertion Hardening

Tightens the runtime proof tests from permissive to strict. Fixes the contract validation gap that was masked by lenient assertions.

### Fixed
- **Adapter exit contracts**: Added `guaranteed_fields` to all domain adapter exit contracts (`risk_context_adapter`, `incident_risk_adapter`, `audit_risk_adapter`, `trace_input_adapter`). Without guaranteed fields, the orchestrator's contract validator rejected the connection because downstream required fields weren't declared.
- **Runtime status assertion**: Changed from accepting `"completed"/"failed"/"paused"` to requiring `"completed"` only.
- **Persisted state assertions**: Changed from conditional (`if state and state.outputs`) to mandatory (`assert state is not None`, `assert state.outputs`). Now verifies `risk_level` in shared_risk_classifier output and `trace_id` in shared_trace_collector output.
- **Trace assertions**: Changed from permissive (`len(events) > 0`) to explicit (`"shared_risk_classifier" in trace`, `"shared_trace_collector" in trace`).
- **Docstring typo**: Fixed v2.62/v2.63 progression listing.

## [2.63.0] — Full Reuse Runtime Proof

Closes the final gap in the reusable-node proof: shared nodes now execute through the real `Orchestrator.run()` path, producing persisted state and trace events across three domain contexts.

### Added
- **23 full runtime proof tests** (`tests/test_reuse_proof_runtime_smoke.py`): Blueprint loading and contract validation (9 tests), full `Orchestrator.run()` execution with persisted state verification (12 tests — shared risk classifier output in state, shared trace collector output in state, trace events reference shared nodes), instance reuse across runs (2 tests).

### Proof progression complete
```
v2.61.0: Direct shared-node proof (same node, 3 domains)
v2.62.0: Orchestrator-registry integrated proof (blueprints, connections, registry)
v2.63.0: Full orchestrator.run() persistence/trace proof (REAL runtime execution)
```

### CI note
GitHub Actions runner allocation was unavailable for v2.62.0–v2.63.0 commits (runner_id=0, no steps executed). All tests verified locally (79 tests pass). Treated as infrastructure failure, not code failure.

## [2.62.0] — End-to-End Reuse Execution Proof

Upgrades the reusable-node proof from direct node invocation (Level 2A) to orchestrator-integrated execution. Shared nodes now execute through the full node registry, are referenced by orchestrator-compatible blueprints, and produce traceable output across three domain contexts.

### Added
- **Domain adapter and entry nodes** (`src/nodechain/nodes/reuse_proof_nodes.py`): 7 deterministic nodes for fact-checking, incident response, and security audit domains. Each domain has an entry node (produces domain-specific data) and an adapter node (normalizes into canonical RISK_CONTEXT). Plus a trace input adapter.
- **Orchestrator-compatible proof blueprints**: All 3 proof blueprints rewritten with proper positions, connections, port types, and shared node config blocks.
- **Shared node wiring**: `shared_risk_classifier` and `shared_trace_collector` are now registered in `_create_nodes()` via dynamic loading from `nodes/` packages.
- **14 end-to-end execution tests** (`tests/test_reuse_proof_e2e.py`): blueprint loading, node registry resolution, shared node type verification, cross-domain execution path (entry → adapter → shared classifier → trace), trace output verification, instance reuse across blueprints.

### Changed
- `_create_nodes()` now includes shared reusable nodes and domain adapter nodes alongside the 12 built-in research chain nodes.
- Proof blueprints use proper orchestrator format (positions, connections, config blocks) instead of the simplified `next:` format.

## [2.61.0] — Reusable Node Proof Pack

Proves that the same independently packaged node can be reused unchanged across multiple autonomous-system chains. The first concrete proof of NodeChain's composable-node promise: build a node once, govern it forever, reuse it everywhere.

### Added
- **Shared Risk Classifier** (`nodes/shared_risk_classifier/`): domain-neutral risk classifier accepting canonical `RISK_CONTEXT` and producing `RISK_ASSESSMENT`. Uses severity signals, confidence signals, uncertainty factors, and evidence refs. Deterministic, no model required.
- **Shared Trace Collector** (`nodes/shared_trace_collector/`): domain-neutral trace collector accepting `TRACE_INPUT` and producing `CHAIN_TRACE_OUTPUT`. Universal terminal node for all chain types.
- **Canonical port types**: `RISK_CONTEXT` and `TRACE_INPUT` added to `PortType` for cross-domain composition.
- **3 proof blueprints**: `reuse_proof_quick_fact_check_v1.yaml`, `reuse_proof_incident_response_v1.yaml`, `reuse_proof_security_audit_v1.yaml` — each uses the same shared nodes unchanged in a different domain.
- **22 proof tests** (`tests/test_reusable_node_proof_pack.py`): package existence, blueprint references, cross-domain reuse (same instance in 3 domains), output type consistency, package identity stability (manifest, contract, content hash), domain-neutral contract verification, risk classification consistency.
- **Reviewer docs** (`docs/reusable-node-proof-pack.md`): how to verify the proof, adapter architecture explanation, canonical port type reference.

### Design decisions
- **Adapters, not custom copies**: domain-specific nodes normalize their output into `RISK_CONTEXT` via adapters. The shared node never branches on domain.
- **Proof blueprints as variants**: existing production blueprints are not destabilized. Proof blueprints are separate `reuse_proof_*` variants.
- **Domain-neutral contracts**: shared nodes use canonical port types, not domain-specific ones.

## [2.60.0] — Vision Alignment / Documentation Truth

Makes the repository internally consistent with the new VISION.md framing: composable governed nodes as the central product thesis. A consolidation release — no new product surface, only documentation, walkthroughs, drift guardrails, and API hardening.

### Added
- **VISION.md** — canonical strategic document (18 sections) defining NodeChain as a governance-first platform for composable governed Harness Nodes. Includes product thesis, factual inventory, layer map, node lifecycle, proof of reuse, competitive position, roadmap principles, reviewer guide, and glossary.
- **`docs/reviewer-guide.md`** — practical inspection recipe for external reviewers: what to inspect first, how to verify the composable-node claim, which blueprints show reuse, which commands prove package lifecycle.
- **`docs/node-package-walkthrough.md`** — concrete command path showing the full node lifecycle: create → validate → test → publish → install → lock → check-compat → execute → inspect → deprecate.
- **`tests/test_docs_vision_links.py`** — documentation drift guardrails: verifies README links to VISION.md, ARCHITECTURE declares itself historical, VISION.md contains the slogan, no trademarked term, includes current version.

### Changed
- **API host-binding warning**: non-localhost binds now print a visible security warning (not a hard block).
- **CLI smoke coverage**: `api --help` and `api serve --help` now covered by CLI smoke tests.
- README.md links to VISION.md at the top with the project slogan.
- ARCHITECTURE.md explicitly references VISION.md as the strategic source of truth and declares itself historical.

## [2.59.0] — Local API Server

Turns the CLI Operator Workbench into a stable local operator API without changing execution semantics. Exposes run status, evidence, recovery preview, and governance profiles through localhost-only, token-protected, schema-validated endpoints backed by the same policy and audit primitives as the CLI.

### Added
- **FastAPI + uvicorn** as core dependencies for the local API server.
- **`src/nodechain/api/` package**: app factory (`create_app`), token auth middleware, Pydantic DTOs, service adapters, and route modules (health, runs, profiles, dashboard).
- **`nodechain api serve` CLI command**: starts uvicorn on localhost:8765 by default. Requires `NODECHAIN_API_TOKEN` env var — refuses to start without it.
- **Read-only API endpoints**:
  - `GET /api/v1/health` — server health and version
  - `GET /api/v1/runs` — list all runs
  - `GET /api/v1/runs/{run_id}` — recovery snapshot
  - `GET /api/v1/runs/{run_id}/evidence` — evidence and citations
  - `GET /api/v1/runs/{run_id}/report` — recovery report
  - `GET /api/v1/profiles` — list governance profiles
  - `GET /api/v1/profiles/{profile_id}` — full governance detail with action matrix
  - `GET /api/v1/dashboard` — dashboard summary (backlog by state)
- **`POST /api/v1/runs/{run_id}/preview`**: dry-run authorization preview. Uses `RecoveryService.authorize_action()` — same path as CLI. Returns `mutated: false` to make read-only contract visible. Zero state mutation.
- **Bearer token auth**: all `/api/v1/*` endpoints require `Authorization: Bearer <NODECHAIN_API_TOKEN>`. `/docs` and `/openapi.json` protected by default; expose with `NODECHAIN_API_EXPOSE_DOCS=1`.
- **Stable error model**: `{"error": {"code", "message", "details"}}` shape with codes: unauthorized, forbidden, run_not_found, profile_not_found, invalid_action, internal_error.
- **OpenAPI schema**: auto-generated by FastAPI, available at `/openapi.json` and `/docs` when exposed.
- **23 deterministic TestClient tests**: auth (required, wrong token, correct), health, runs (empty, with data, not found, evidence, report), profiles (list, detail, action matrix, not found), dashboard (empty, with data), preview (resume, budget denied, invalid action, not found, no-mutation invariant), OpenAPI schema, docs UI.

### Changed
- `pyproject.toml`: added `fastapi>=0.110` and `uvicorn>=0.29` as core dependencies.
- CLI surface: added `api` command group to frozen CLI snapshots.

### Cut to v2.60.0
- Mutation endpoints (resume/retry/approve/cancel via API)
- Multi-user auth, token rotation, scopes
- Web UI / browser dashboard
- Streaming, websockets, background workers

## [2.58.0] — CLI Operator Workbench

Makes NodeChain operable as a local product, not only a CLI runtime. Adds operator-facing commands for governance visibility, dry-run action preview, evidence browsing, and a unified dashboard — all read-only, all CLI-based.

### Added
- **`recover profiles show` full governance display**: action matrix table (action × role × allowed/denied), per-action requirements (reason/override), budget governance (caps, multipliers, approve roles), override governance (admin/env requirements), audit governance (identity, reason, digest), and batch governance (limits, dry-run, continue-on-error). Supports `--file` for custom profiles.
- **`recover preview`**: dry-run authorization for any governed recovery action. Uses the exact same `RecoveryService.authorize_action()` path as real actions — no duplicated policy logic. Shows allowed/denied, role, profile, denial type, and reason. Zero state mutation.
- **`recover evidence RUN_ID`**: dedicated evidence browser showing sources, claims, validation summary, risk classification, and final recommendation. Supports `--json` for machine-readable output. No raw SQLite/JSON access needed.
- **`recover inspect` evidence section**: now includes a compact evidence/citation summary showing citations, validated claims with status/confidence, and quarantined claims. Degrades gracefully for runs without evidence data.
- **`recover dashboard`**: Rich CLI dashboard showing recovery backlog by state and recent denied actions. All data derived from persisted state — read-only, no synthetic health.
- **16 operator workbench tests**: profiles show, preview, evidence, dashboard, inspect.

### Changed
- `recover profiles show` signature: added `--file` option for custom profile display.
- `recover_inspect` now calls `_render_evidence_summary()` after the snapshot.

### Cut to v2.59.0
- Local API server (auth, OpenAPI, request validation, API contract tests)
- Web UI / browser dashboard
- Persistent operator cache management

## [2.57.0] — Source Acquisition Reliability

Makes external research collection resilient, observable, and quality-aware. All adapter HTTP paths now route through a shared fetch helper with retry/backoff, failure taxonomy, and circuit breaker.

### Added
- **Failure taxonomy** (`src/nodechain/adapters/search/failure_types.py`): `SearchFailureType` enum (timeout, rate_limit, http_error, schema_drift, empty_result, malformed_payload, circuit_open, unknown). `AdapterFailure` model with structured fields (adapter, type, retryable, attempts, status_code, latency, query_hash, exception_class, timestamp). `classify_exception()` and `classify_http_status()` classifiers.
- **Circuit breaker** (`src/nodechain/adapters/search/circuit_breaker.py`): per-adapter breaker with CLOSED/OPEN/HALF_OPEN states. Trips after N consecutive retryable failures, cooldown period, half-open probe on next request.
- **Shared `_fetch()` helper** in `BaseSearchAdapter`: tenacity-free retry with exponential backoff + jitter. Supports JSON and text response formats. Configurable per adapter: `max_retries`, `timeout_seconds`, `backoff_min`, `backoff_max`. Retries only transient failures (timeout, 429, 5xx); does not retry 4xx (except 429), schema drift, or malformed payloads.
- **Structured SearchToolNode output**: `adapters_failed[]` now includes `failure_type`, `retryable`, `attempts`, `status_code`. Added aggregate counters: `failures_by_type`, `retry_attempts_total`, `adapters_circuit_open`.
- **Deduplication improvement**: results now deduplicate by DOI (normalized) → external stable ID (paperId/arxiv_id/openalex_id/pmid) → normalized title → source_id fallback. Provenance preserved via `_dedup_origins` list.
- **36 deterministic tests** (`tests/test_source_acquisition_reliability.py`): failure taxonomy classification, circuit breaker state transitions, deduplication by DOI/title/ID, retry behavior (timeout, 429, 500, 404, exhausted retries, circuit-open blocking).

### Changed
- `BaseSearchAdapter.search()` now routes through `_fetch()` instead of direct `httpx.get()`. Raises `SearchAdapterError` carrying structured `AdapterFailure` on failure.
- `ArxivAdapter.search()` now uses `_fetch(response_format="text")` instead of its own `httpx.get()`.
- `PubMedAdapter.search()` now uses `_fetch()` for both esearch (JSON) and efetch (XML) steps.
- `SearchToolNode` catches `SearchAdapterError` separately from generic exceptions, preserving structured failure data.
- All adapters now accept circuit breaker configuration in their constructors.

### Cut to v2.58.0
- Persistent source-query cache with provenance (storage/product surface)
- Source diversity/reranking before synthesis (quality-of-synthesis concern)

## [2.56.0] — Research Evaluation Harness

Turns "the assistant seems good" into measurable, release-gated quality. Adds a deterministic chain-eval runner that executes the research_decision_v1 research-quality slice (evidence_synthesizer → claim_validator → risk_classifier → response_generator) through MockModelAdapter, computes quality metrics, and enforces release-gate thresholds.

### Added
- **Research eval runner** (`src/nodechain/runtime/research_eval_runner.py`): deterministic chain execution that runs evidence_synthesizer → claim_validator → risk_classifier → response_generator via MockModelAdapter. Captures per-node outputs for metric computation.
- **Research eval metrics** (`src/nodechain/runtime/research_eval_metrics.py`): computes citation_validity, claim_support_rate, fabrication_rate, schema_compliance, confidence_calibration, and trace_completeness from node outputs. Includes invariant checks (no [INVALID], citations resolve to real sources, quarantined claims have reasons) and threshold enforcement (schema_compliance=1.0, citation_validity≥0.95, fabrication_rate=0.0, trace_completeness=1.0).
- **Golden corpus**: 5 deterministic cases covering normal-supported, zero-evidence, mixed-evidence, minimal-evidence, and no-qualified-pass-through paths.
- **CLI command** `nodechain eval research`: runs the full golden corpus, produces a machine-readable report with digest, exits non-zero on any failure.
- **Mock contract compliance tests** (`tests/test_mock_contract_compliance.py`): 13 tests verifying mock payloads match current node output contracts.
- **Eval harness tests** (`tests/test_research_eval_harness.py`): 25 tests covering chain execution, metric computation, invariants, thresholds, and the full golden corpus run.

### Changed
- **MockModelAdapter refresh**: evidence_synthesizer payload now emits `claims[]`/`synthesis{}` (was `evidence_matrix`/`key_findings`). claim_validator emits `results[]` with `claim_id`/`internal_consistency`/`source_agreement`/`status` (was `validated_claims` with `verdict`/`evidence_count`). response_generator no longer includes citations/uncertainty_disclosures (node builds those programmatically).
- **Mock alias**: added `"consistency validator"` → `claim_validator` alias to match ClaimValidatorNode's system prompt ("Claim Consistency Validator").
- **Mock source adaptation**: evidence_synthesizer response now caps `supporting_sources` to only reference source IDs that exist in the input, preventing false fabrication quarantine on reduced-source cases.

## [2.55.0] — Citation Closure & Evidence Integrity

Every final recommendation must be traceably grounded in validated sources, or explicitly fail closed. Fixes the 3 citation-integrity gaps found in ChatGPT's v2.54.0 audit.

### Fixed
- **ClaimValidatorNode** (`_merge_validation_results`): now preserves `supporting_sources` and `contradicting_sources` through the merge. Previously these fields were dropped, causing citations to disappear before ResponseGeneratorNode.
- **RiskClassifierNode** (zero-claim branch): now passes through `validated_claims`, `sources`, and `synthesis` as guaranteed output fields. Previously the zero-claim branch violated the port contract by omitting them.
- **EvidenceSynthesizerNode**: fabricated source IDs are now quarantined (claim status set to `quarantined_fabricated_source` with a quarantine reason) instead of soft-marked with `[INVALID]` suffix. Fabricated references are dropped rather than propagated.

### Changed
- Citation gap xfail tests (from v2.54.0) are now normal passing tests — the gaps are fixed.

## [2.54.1] — v2.54.0 Review Fixes

Addresses ChatGPT's 3 blockers from v2.54.0 review.

### Fixed
- `ARCHITECTURE.md` current version updated from v2.53.0 to v2.54.1
- Release-truth guard now checks ARCHITECTURE.md version consistency
- `make ci` restructured: `ci-core` (fast+recovery+trust), `ci-blocking` (all required checks), `ci` = `ci-blocking`
- Added `ci-shard-1` and `ci-shard-3` Makefile targets
- Citation gap xfail tests rewritten: now fail for the actual semantic gap (not fixture/API mismatches)
- `docs/ci.md`: lint job documented as py_compile blocking + Ruff advisory

## [2.54.0] — Release Truth & Citation Closure Prep

Makes repository truth, release truth, and operator truth agree. Adds failing tests documenting the citation-integrity gaps that v2.55.0 will fix.

### Fixed
- **README.md status**: updated from stale v2.31.0 to v2.54.0
- **ARCHITECTURE.md**: updated from stale v2.17.2 to v2.54.0 with pointer to current docs
- **docs/ci.md**: updated from stale v2.51.0 to v2.54.0
- **Makefile**: `make ci` now documents full CI surface; added `make ci-lint`, `make ci-smoke`, `make ci-package` targets

### Added
- **Release-truth guard test** (`tests/test_release_truth.py`): verifies `nodechain.__version__`, `pyproject.toml`, `docs/ci.md`, `README.md`, and `CHANGELOG.md` all agree. Prevents future version drift.
- **Citation gap tests** (`tests/test_citation_gaps.py`): 3 failing tests documenting:
  1. `ClaimValidatorNode._merge_validation_results` drops `supporting_sources` (citations lost)
  2. `RiskClassifierNode` zero-claim branch violates port contract (missing guaranteed output fields)
  3. `EvidenceSynthesizerNode` marks fabricated source IDs as `[INVALID]` instead of quarantining

These failing tests drive v2.55.0 implementation.

## [2.53.0] — Governance Profile Enforcement Completeness

Enforces all previously-inert governance profile fields. No governance field is decorative.

### Changed
- `require_override`: blocks action if `NODECHAIN_OPERATOR_OVERRIDE` not set (per-action)
- `audit.require_reason_for_mutations`: requires reason for all non-export actions
- `budget.approve_roles`: restricts budget approval beyond global RBAC (profile-specific)
- `budget.max_new_budget_usd`: rejects absolute budget cap exceedance
- `budget.max_increase_multiplier`: rejects excessive multiplier-based budget jumps
- `batch.require_dry_run_before_execute`: profile with this flag refuses non-dry-run batch execution

### Fixed
- Invalid profile resolution now produces a governed denial (`denial_type=governance_profile`) instead of a runtime exception
- BatchExecutor catches profile-resolution failures deterministically

### Added
- `tests/invariants/test_no_inert_fields.py`: 6 tests proving each governance field affects authorization behavior
- Ruff lint (E9, F63, F7, F82) added to CI lint job alongside py_compile

## [2.52.0] — Operator Governance Profiles

Adds named governance profiles for operator recovery workflows. Profiles make the v2.49–v2.51 recovery authorization system configurable and auditable without weakening hard security invariants.

### Added
- Built-in profiles: `solo-dev`, `team-default` (default, preserves v2.51.0 behavior), `regulated`, `break-glass`.
- Profile resolver: CLI > environment > config > default (`team-default`).
- Profile-aware `OperatorActionPolicy`: profiles may make recovery stricter but cannot weaken hard floors.
- Profile-aware batch recovery limits (max_actions, continue-on-error per profile).
- Profile audit metadata: profile id, digest, source recorded in `operator_action_log`.
- CLI: `--profile` / `--profile-file` flags on all mutation commands; `nodechain recover profiles list/show/validate` inspection commands.
- `GovernanceProfile` Pydantic model with submodels for roles, actions, budget, batch, audit, override.

### Security
- Profiles may make recovery stricter but cannot weaken hard floors.
- `operator` can never approve budget increases in any profile.
- Non-retryable retry still requires admin + explicit override in any profile.
- Terminal states remain immutable across all profiles.
- Invalid/unsafe profiles fail closed at validation time.

## [2.51.0] — Recovery Semantics Hardening / Invariant Tests

Adds invariant-level tests across recovery state transitions, operator authorization, audit completeness, budget resume semantics, and batch execution behavior. These tests verify system-level contracts across the recovery subsystem rather than isolated component behavior. No new runtime/test dependency introduced.

### Added
- **`tests/invariants/` package** with 27 named invariant tests across 5 files:
  - `test_authorization_invariants.py`: invalid roles fail closed (parametrized over 5 roles × all actions), operator can never increase budget, two-key override matrix (parametrized 4 cases)
  - `test_audit_invariants.py`: admitted action has exactly one action log row, denied action still audited, operator events never carry Actor.NODE, every action has a trace event
  - `test_state_transition_invariants.py`: FAILED_RETRYABLE/FAILED_NON_RETRYABLE require durable last_failure (protects the wiring bug), terminal states refuse all mutations (parametrized over 5 actions × 2 terminal states)
  - `test_budget_invariants.py`: approved budget must exceed previous + accumulated cost, carry semantics preserved after approval
  - `test_batch_invariants.py`: dry-run never mutates state, fail-fast skips after first denial, result count == total actions

## [2.50.0] — Batch Recovery Operations

Allows operators to submit multiple recovery actions as one explicit, auditable YAML batch. Each action is authorized independently through the same v2.49.0 RBAC + policy path — a batch is not authorized as a unit.

### Added
- **YAML batch input**: `nodechain recover batch --file recovery.yaml` with schema validation (max 50 actions, required fields, unknown-action rejection).
- **Dry-run mode**: `--dry-run` plans the batch (authorizes each action) without mutating state. Reports admitted/denied/skipped per action.
- **Fail-fast (default)**: stops after first denial/failure, marks remaining as skipped.
- **Continue-on-error**: `--continue-on-error` processes all actions independently regardless of denials.
- **Per-action RBAC**: each action goes through the full RBAC matrix + recovery-state policy independently. Budget increase denied for operator even inside a batch.
- **Batch result model**: `BatchSummary` with admitted/denied/executed/skipped counts + overall status.
- **`RecoveryService.authorize_action()`**: authorization-only path (no execution) for batch dry-run planning.
- **Non-atomic**: documented — v2.50.0 does not support rollback.

## [2.49.0] — Recovery Authorization / RBAC

Adds role-based authorization for recovery actions using operator, finance, and admin roles. Budget increase approval is now restricted to finance/admin users, non-retryable retry override now requires both admin role and explicit override flag, invalid roles fail closed, and audit decisions now include denial_type and decision_reason for allow/deny traceability.

### Added
- **Three roles**: `operator` (default), `finance`, `admin`. Source: `--role` flag (on all recover action commands) > `NODECHAIN_OPERATOR_ROLE` env > `operator`.
- **Declarative action-role matrix** (`ACTION_ALLOWED_ROLES`): budget approval = finance/admin only; all other actions = operator-accessible.
- **Two-key override**: non-retryable retry requires admin role AND `NODECHAIN_OPERATOR_OVERRIDE=true` (was: any role + override env).
- **`denial_type`** on `AuthorizationResult`: `rbac`, `invalid_role`, `override_required`, `policy`, `None` (admitted).
- **`--role` flag** on all 8 recover action commands (resume, retry, approve, revise, cancel, fail, fallback, budget).

### Security
- OLD: any identity + `NODECHAIN_OPERATOR_OVERRIDE=true` could trigger non-retryable retry override.
- NEW: admin role + `NODECHAIN_OPERATOR_OVERRIDE=true` required. Operator/finance + override = denied with `denial_type=override_required`.

## [2.48.0] — Independent Verification Pipeline

v2.48.0 introduces the project's first working GitHub Actions verification pipeline for master and pull requests. The release adds sharded CI jobs for fast tests, recovery/orchestrator coverage, trust collector coverage, slow suites, CLI smoke tests, Windows checks, and package builds. It also adds local Makefile parity commands, documents the CI contract, and introduces regression tests for two previously discovered wiring bugs: trust key counting and orchestrator `last_failure` persistence. Loop payload construction tests were hardened to assert actual `_build_loop_payload` semantics for `context_selector`, `task_planner`, default, and missing-output cases.

### Fixed
- **CI workflow branch trigger**: was `main` (never triggered) → fixed to `master`. This was why GitHub status was always empty.
- **Version snapshot drift**: ~30 test files hardcoded `__version__ == "2.45.5"` — CI caught this; all updated to `2.47.0`.

### Added
- GitHub Actions CI: 8 sharded jobs (lint, unit-fast, orchestrator-recovery, trust-collector, slow-shard-1/2/3, windows, cli-smoke, package-build).
- Makefile: `make ci`, `make ci-fast`, `make ci-recovery`, `make ci-trust` for local/CI parity.
- `docs/ci.md`: CI contract documentation (jobs, blocking status, slow-test policy, version-snapshot convention).
- Regression tests: `collect_trust_status` reads `keys` not `entries`; orchestrator persists `last_failure`.
- Hardened `_build_loop_payload` tests: semantic assertions for context_selector, task_planner, default, and missing-outputs cases.

## [2.47.0] — Budget Approval Pause State

### Changed
- **Budget-exceeded runs now pause instead of failing.** When a loop's cost budget is exceeded, the orchestrator sets `status="paused_for_budget"` (was: immediate `_fail_chain` → `status="failed"`). The run awaits operator budget-increase approval rather than terminating.

### Added
- **`PAUSED_FOR_BUDGET_APPROVAL` is now reachable.** The recovery classifier maps `paused_for_budget` status to this state (was: enum-only, nothing classified to it).
- **`APPROVE_BUDGET_INCREASE` recovery action.** A distinct operator action with its own policy gate and audit trail. Validation: `new_budget > previous_budget`, `new_budget > accumulated_loop_cost`. Cost is **carried** (absolute ceiling, not reset) — the approval records "raised ceiling from X to Y after Z spent."
- **`nodechain recover budget <run> --new-budget <N>`** CLI command.
- **Budget audit fields:** `previous_budget`, `new_budget`, `accumulated_cost_at_pause`, `remaining_budget_after_approval`, recorded in state metadata + operator_action_log.

### Fixed (follow-ups from v2.46.0)
- **#12:** HR-045/HR-046 dashboard baseline test failures (DB isolation + frozen-surface section-count correction).
- **#15:** Dashboard collector existence semantics — `collect_trust_status`/`collect_registry_status`/`collect_recovery_status` now distinguish absent/synthesized from present-but-noncompliant. Plus `collect_trust_status` field-name bug (`entries` → `keys`).
- **#13:** `ROUTE_FALLBACK` delegation — real operator-callable fallback through `FailureManager.route_fallback` (allowlist: `SEARCH_API_UNAVAILABLE`). Plus latent bug: orchestrator never persisted `last_failure` metadata, so `FAILED_RETRYABLE`/`FAILED_NON_RETRYABLE` classification was unreachable.

## [2.46.0] — Operator Recovery Console

### Added
- **Operator Recovery Console:** the first operator-facing recovery surface for interrupted, paused, failed, or review-blocked NodeChain runs. Turns recovery from an internal runtime capability into an explicit governed operator workflow. Thin read + policy + audit layer over existing runtime primitives — owns no execution loop and never bypasses runtime governance.
- **Five accepted phases:** read surface → operator trace discipline → governed action boundary → CLI actions + orchestrator delegation → dashboard visibility.
- **New `nodechain recover` commands:** `list`, `inspect`, `trace`, `resume`, `retry`, `approve`, `revise`, `cancel`, `fail`, `report`.
- **Derived recovery state:** `recovery_classifier.classify()` derives one of 11 operator-facing recovery states from durable facts; never persisted on `ChainState` (prevents drift).
- **Governed action boundary:** `RecoveryService.apply_action()` is the only place an operator action mutates anything — re-read state → `OperatorActionPolicy.authorize()` (fail-closed) → emit `Actor.OPERATOR` trace events → record `operator_action_log` admission row → delegate.
- **Operator trace discipline:** 13 new `EventType` values + `Actor.OPERATOR` (distinct from `NODE`/`RUNTIME`/`HUMAN`) so operator actions are never recorded as node execution.
- **Admission ledger:** `operator_action_log` records every attempt (admitted AND blocked) with `trace_event_id` binding to the authoritative Chain Trace. Not a competing execution record.
- **Per-effect crash recovery authorization:** resume/retry after crash recovery require EACH unresolved unknown side-effect to have its own recovery decision (matched by `idempotency_key`), not any run-level decision.
- **Step-precise retry:** `recover retry --step <step_id>` validates against the durable failed step; never retries by `node_id` alone (looped-node safe).
- **Atomic terminal actions:** `StateManager.save_with_event()` writes state + outcome event in one SQLite transaction (no crash window).
- **HR-049 `operator_recovery_backlog`:** dashboard health rule firing on non-terminal recovery-state runs, wired into the versioned `collect_dashboard_v2()` health path.

### Known Limitations
- **`ROUTE_FALLBACK` stubbed/refused:** the enum value exists and the policy admits it only for fallback-capable failures, but delegation returns "not implemented" (FailureManager fallbacks are hardcoded per-failure-type) rather than silently no-op'ing. Real delegation is a follow-up.
- **`PAUSED_FOR_BUDGET_APPROVAL` enum-only:** budget-exceeded failures currently fail the chain immediately; there is no true pause-for-budget runtime state yet. The classifier maps these to `FAILED_NON_RETRYABLE`.
- **2 pre-existing test failures:** `test_review_dashboard_closure` HR-045/HR-046 fail at baseline `master 634cd4e5`, unrelated to recovery. Carry forward.
- **No independent CI green status:** GitHub CI is not configured for this branch; all verification was local.
- **Slow runtime/integration files excluded from final aggregate run:** 37 files (sandbox/checkpoint/proxmox/namespace/live-dashboard-builds) were excluded from the final aggregate local run due to execution-window limits. Every test that completed passed; zero new failures.

## [2.45.5] — Admission Durability Failure Visibility

### Fixed
- **Durable write failure always visible in-memory:** when durable recording fails for an allow, the failure decision (`admission.durable_write_failed`) is added to `_admission_decisions` in-memory **unconditionally** — even if the durable write for the failure itself also fails. This guarantees health visibility.
- **collect_health() surfaces durable failures:** new fields `durable_write_failures` (count) and `durable_write_failed_node_ids` (list) in health report.

## [2.45.4] — Registry Admission Failure-State Consistency

### Fixed
- **In-memory admission ledger consistency:** `_record_admission()` now writes to durable storage FIRST, then adds to `_admission_decisions` only on success. If durable write fails, the original allow decision is never visible in the in-memory ledger.
- **Failure decision recorded in-memory:** when durable write fails for an allow, the failure decision (`rule_id="admission.durable_write_failed"`) is recorded via `_record_admission(fail_decision)` so `_admission_decisions` and `collect_health()` see a deny, not an allow.
- **No inconsistent state:** `_admission_decisions` never contains an allow for a package that isn't loadable.

## [2.45.3] — Registry Admission Durability Fail-Closed

### Fixed
- **Default StateManager in RegistryIndex:** when `state_manager=None`, `RegistryIndex` now creates a default `StateManager()` internally. Admission is always durable.
- **Fail-closed durable recording:** `_record_admission()` returns `bool`. `scan()` only inserts into `_packages` when durable recording succeeded. If the durable write fails, the package is denied with `rule_id="admission.durable_write_failed"`.
- **No more swallowed durable errors:** the `except Exception: pass` in `_record_admission()` is replaced with a return value that callers must check.

## [2.45.2] — Registry Admission Durability + Policy Enforcement Correctness

### Fixed
- **NodeLoader default durable path:** `NodeLoader.__init__()` now creates a default `StateManager` and passes it to `RegistryIndex`, so the normal loader path always records durable admission decisions.
- **BLOCK enum fix:** `PolicyDecision.BLOCK.value` is `"block"` (lowercase). Fixed comparison from `== "BLOCK"` to `== PolicyDecision.BLOCK`.
- **Path conversion:** `package_path` passed as `Path(pkg.path)`, not raw string.
- **Fail-closed for privileged:** enforcer errors on privileged packages now deny admission (was silently passed).

## [2.45.1] — Durable Registry Admission + Policy Coverage

### Fixed
- **Durable admission recording:** RegistryIndex now accepts `state_manager` parameter. Every admission decision (allow + deny + parse error) is recorded via `_record_admission()` → `StateManager.record_registry_admission()`.
- **PackagePolicyEnforcer wired into admission:** `_admit_package()` now calls `enforce_package()` and denies on BLOCK decisions.
- **Lockfile drift in health:** `collect_health()` now includes `lockfile_valid`, `lockfile_mismatches`, `lockfile_missing`, `lockfile_extra`.
- **Parse-error keying:** denied parse errors use `f"parse_error:{path}"` as key (not colliding `"unknown"`).

## [2.45.0] — Registry Admission Policy

The registry is now an admission boundary. scan() discovers candidates, evaluates admission, and only admitted packages enter the loadable index.

### Added
- **`AdmissionDecision` model** (local_registry.py): structured allow/deny with admission_id, node_id, package_digest, origin, manifest_hash, contract_hash, declared_privileged, reason, rule_id.
- **`_admit_package()` admission function**: validates structural integrity (manifest, contract, implementation file), checks duplicate node_id, version compatibility, and derives package digest.
- **Two-surface registry**: `_discovered` (all scanned), `_packages` (admitted only), `_denied` (denied decisions). `get_package()` returns only admitted packages.
- **`registry_admission_decisions` table** (state.py): 16-field durable admission ledger.
- **`collect_health()` on RegistryIndex**: surfaces total_discovered/admitted/denied, parse_errors, missing_digest, privileged_declarations, latest_admissions.
- **NodeLoader provenance handoff**: sets `_node_origin`, `_trust_level`, `_module_path`, `_package_root` on loaded node instances from registry admission metadata.

### Changed
- `RegistryIndex.scan()` now evaluates admission before indexing. Parse failures produce deny decisions (was silently swallowed).
- Lockfile generation only includes admitted packages.
- `get_package()`, `list_packages()`, `search()`, `resolve_blueprint_contracts()` only see admitted packages.

### Tests
- `test_registry_admission.py` (10 tests): AdmissionDecision model, admission boundary (scan/discover/deny/load), durable decisions, health report.

## [2.44.4] — Explicit Built-in Provenance Boundary

### Fixed
- **Known built-in check:** privileged nodes claiming `built_in` trust via inherited BaseNode defaults are now verified by module namespace. Only nodes under `nodechain.nodes.*` are treated as proven built-in. Arbitrary BaseNode subclasses from other modules get `observed_trust_level = "unknown"` and `origin = "unknown"` → denied by package-trust gate.

### Tests (4 new)
- `test_arbitrary_subclass_inherited_defaults_denied`: custom BaseNode subclass with tools_required and no provenance → denied (observed_trust_level = "unknown")
- `test_actual_built_in_node_allowed`: real SearchToolNode under nodechain.nodes.* → allowed
- `test_local_trusted_loader_set_allowed`: loader-set local_trusted → allowed
- `test_local_untrusted_loader_set_denied`: loader-set local_untrusted → denied

## [2.44.3] — Package Trust Step-Exact Binding

### Fixed
- **Emitter step sync:** orchestrator now calls `self.emitter.set_step(self._step)` before policy gate, so SIDE_EFFECT_STARTED events carry the correct step_id (was step 0 from uninitialized emitter). Root cause of the step mismatch between trust decisions and side-effect events.
- **PT-1 step-exact:** privileged event matched by `(node_id, step_id)` against `allow_by_node_step`. No more node-level matching.
- **PT-4 step-exact:** denied package matched by `(node_id, step_id)` against `deny_by_node_step`. No more node-level de-poisoning.
- **PT-3 step_id check:** durable row `step_id` must match trace event `step_id`.
- **PT-3 is_privileged check:** trace `is_privileged` must match durable row.
- **PT-3 missing metadata = ERROR:** if trace event lacks `origin`, `observed_trust_level`, or `package_digest`, emits `package_trust_metadata_missing` (was silently ignored).

## [2.44.2] — Package Trust Invocation Binding Exactness

### Fixed
- **PT-1 no node_has_any exception:** privileged event without durable allow is always ERROR when trust decisions exist for the run. Previously skipped if the node had no trust row at all.
- **PT-4 deny de-poisoning:** a node with both allow and deny decisions (different invocations) no longer poisons allowed invocations. `deny_by_node` is reduced by `allow_by_node`.
- **PT-3 full metadata binding:** PACKAGE_TRUST_ALLOWED/DENIED trace events now verified against durable row on `origin`, `observed_trust_level`, and `package_digest` (in addition to polarity and node_id).
- **Provenance normalization:** module_path derived via `inspect.getfile()` before digest computation.

## [2.44.1] — Package Trust Reconciler + Provenance Exactness

### Added
- **Reconciler PT-1/2/3/4** (`_check_package_trust_binding`):
  - PT-1: privileged runtime event (TOOL_ACCESS_ALLOWED, ADAPTER_ACCESS_ALLOWED, MEMORY_*, SIDE_EFFECT_*, MODEL_CALLED) without durable package-trust allow = ERROR
  - PT-2: PACKAGE_TRUST_ALLOWED/DENIED trace decision_id missing durable row = ERROR
  - PT-3: trace node_id, step_id, decision polarity must match durable row = ERROR
  - PT-4: denied package with privileged runtime event for same node+step = ERROR

### Fixed
- **Provenance normalization:** removed silent `_trust_level = "built_in"` and `_node_origin = "built_in"` assignment for missing attrs. Class defaults from `BaseNode` remain, but the orchestrator no longer overrides empty values — loader-set values are preserved, and truly unknown nodes keep their class-level defaults (which ARE `built_in` but represent the actual BaseNode contract, not an override).

## [2.44.0] — Node Package Trust Runtime Enforcement

Package trust is now runtime-derived, fail-closed, and runs as the FIRST gate for privileged nodes.

### Added
- **`is_privileged_node()` helper** (contract.py): a node is privileged if it declares tools, adapters, memory access, side effects, or model access.
- **`package_trust_decisions` table** (state.py): 19 fields binding run+step+node+package identity+digest+origin+observed/required trust+decision.
- **EventType.PACKAGE_TRUST_ALLOWED / PACKAGE_TRUST_DENIED**: trace events binding to durable decision_id.
- **PolicyGate section 0 (package trust)**: runs BEFORE all other gates. Uses `BaseNode._trust_level` (observed) not `Requirements.trust_level` (self-declared). Fail-closed when no decision. Only for privileged nodes.
- **Orchestrator normalization**: normalizes `_node_origin`, `_trust_level`, `_module_path` before policy evaluation. Derives package_digest from module_path SHA-256.
- **Durable decision recording** in `_check_policy_gate`: one row per privileged invocation, with trust_source classification.

### Changed
- **TRUST_LEVEL_POLICY rewritten**: uses `observed_trust_level in [built_in, local_trusted]` for allow, `[local_untrusted, remote_untrusted, unknown]` for deny. Old self-declared vocabulary (`untrusted, sandbox`) removed.
- **PolicyGate trust gate moved to position 0** (was section 4, last gate — now first).
- **PolicyGate fail-closed**: no trust decision → deny for privileged nodes (was fail-open).

### Design principle
- Trust is runtime-derived from `BaseNode._trust_level` (set by loader/runtime), NOT from `Requirements.trust_level` (self-declared by contract).
- A node declaring `trust_level="trusted"` in its contract does NOT get trusted status. The runtime determines trust from origin, loader resolution, or explicit built-in normalization.
- Built-in nodes: `_trust_level = "built_in"` → explicit allow with `trust_source = built_in_default`.
- Unknown/untrusted: deny before any capability gate runs.

### Tests
- `test_package_trust.py` (12 tests): is_privileged helper, policy vocabulary, self-declared ignored, gate evaluation (built-in allowed, untrusted denied, non-privileged skipped, fail-closed), durable decisions.

## [2.43.3] — Adapter Trace Polarity Binding

### Fixed
- **AA-3 polarity verification:** `allow_decision_ids` must reference durable `decision="allow"` rows; `deny_decision_ids` must reference `decision="deny"` rows. Was: membership-only check (any decision row would pass).
- **AA-3 identity verification:** each decision_id's durable row must match the trace event's `node_id` and `step_id`. Was: not checked.
- New checks: `adapter_access_polarity_mismatch` (ERROR), `adapter_access_identity_mismatch` (ERROR).

## [2.43.2] — Adapter Reconciler Binding Exactness

### Fixed
- **Exact reconciler binding:** TOOL_CALLED adapter traces now matched against durable allow by `(node_id, step_id, adapter_name)`, not just adapter name. Cross-node/cross-step reuse of a valid allow is now detected.
- **Always-ERROR severity:** TOOL_CALLED without durable allow is ERROR unconditionally (was WARNING when table empty).
- **Split decision_ids:** ADAPTER_ACCESS_ALLOWED carries `allow_decision_ids` + `deny_decision_ids`; DENIED carries the same split. No more ambiguous single `decision_ids` list mixing allow and deny rows.

## [2.43.1] — Adapter Grant Semantics + Reconciler Binding

### Fixed
- **Subset grant semantics:** `adapters_required` now means "supported adapters" (not "all must be granted"). A node declaring 5 adapters with only 3 granted is ALLOWED. Only 0 granted = DENIED. Policy uses `has_no_granted_adapters` instead of `has_ungranted_adapters`.
- **BranchSearchNode contract:** now declares `tools_required=["search"]` + `adapters_required=[5 backends]`. Hardcoded fallback `["semantic_scholar"]` replaced with capabilities-derived fallback.
- **Empty-declaration sanitizer:** nodes with no `adapters_required` get `allowed_adapters=[]` (don't inherit config).
- **Reconciler AA-1/AA-2/AA-3:** TOOL_CALLED with adapter but no durable allow = ERROR (WARNING when no decisions exist at all). Denied adapter + TOOL_CALLED = ERROR. Trace decision_id missing durable row = ERROR.

## [2.43.0] — Adapter Grant Enforcement

True tool/adapter separation: `tools_required` is a capability class, `adapters_required` is specific backend identity.

### Added
- **`Requirements.adapters_required`**: specific backend/adapter grants (e.g. `["semantic_scholar", "arxiv", ...]`), separate from `tools_required` (capability class, e.g. `["search"]`).
- **`Capabilities.allowed_adapters`**: sanitized adapter grants (declared ∩ runtime config).
- **`PolicyType.ADAPTER_ACCESS`**: separate from TOOL_ACCESS.
- **`ADAPTER_ACCESS_POLICY`**: target `"*"`, deny-first when ungranted adapters exist, allow when all granted.
- **`adapter_access_decisions` table** (14 fields, 3 indexes): one row per adapter.
- **EventType.ADAPTER_ACCESS_ALLOWED / ADAPTER_ACCESS_DENIED**: trace events with `decision_ids` bound to durable rows.
- **PolicyGate ADAPTER_ACCESS section**: triggers on `req.adapters_required`, fail-closed, computed context (`adapters_required`, `allowed_adapters`, `ungranted_adapters`, `has_ungranted_adapters`).
- **Capabilities sanitizer**: `allowed_adapters` = declared ∩ runtime config.

### Changed
- **SearchToolNode contract**: `tools_required=["search"]` (was adapter names), `adapters_required=["semantic_scholar", ...]`.
- **search_tool.py enforcement**: upper-bound now from `allowed_adapters` (not `allowed_tools`). Hardcoded fallback `["semantic_scholar", "pubmed"]` removed — adapters only from `allowed_adapters`.
- **Blueprints**: `allowed_tools: [search]` + `allowed_adapters: [5 backends]`.
- **PolicyGate `_build_context`**: now includes `allowed_adapters` from capabilities.

### Design distinction
- `tools_required` = capability class ("can this node use search?")
- `adapters_required` = backend identity ("can this node use arxiv specifically?")
- `allowed_tools` ≠ `allowed_adapters` — a tool grant does not imply adapter access.

## [2.42.1] — Tool Access Gate Runtime Binding Fix

### Fixed
- **SearchToolNode contract now declares `tools_required`:** the real search tool contract had no tool declaration, so the new gate never triggered for it. Now declares all 5 adapters.
- **Unconditional capability upper-bound:** `search_tool.py` now enforces `allowed_tools` intersection unconditionally. Empty `allowed_tools` = no adapters callable (was skipped when empty).
- **Trace decision binding:** TOOL_ACCESS_ALLOWED/DENIED trace events now reference durable `decision_ids` (list matching the tool_access_decisions rows), not random UUIDs.

### Tests (4 new, 14 total)
- `test_search_tool_contract_has_tools_required`: contract declares tool grants
- `test_search_tool_enters_tool_access_gate`: real SearchToolNode enters gate
- `test_empty_capabilities_blocks_all_adapters`: empty allowed_tools = no calls
- `test_allowed_trace_has_decision_ids`: trace references durable decision IDs

## [2.42.0] — Tool Access Runtime Gate Generalization

Replaces hardcoded `node_id == "search_tool"` with contract-driven `Requirements.tools_required` gate.

### Changed
- **PolicyGate tool access trigger:** now fires on `req.tools_required` (any node), not `node_id == "search_tool"`.
- **TOOL_ACCESS_POLICY target:** `"search_tool"` → `"*"`.
- **TOOL_ACCESS_POLICY rules:** dead `always/ALLOW` → deny-first when ungranted tools exist (`has_ungranted_tools == True` at priority 20), then allow when all granted (`tools_required_count > 0` at priority 10).
- **Fail-closed:** no TOOL_ACCESS policy decision → deny.
- **Capabilities sanitizer:** `allowed_tools` is now `declared ∩ runtime`, not raw config.
- **Payload adapter_grants upper-bound:** `search_tool.py` intersects payload grants with `capabilities.allowed_tools`.

### Added
- **`tool_access_decisions` table** (12 fields, 3 indexes): one row per declared tool.
- **EventType.TOOL_ACCESS_ALLOWED / TOOL_ACCESS_DENIED.**
- **Computed context fields** for policy: `tools_required`, `allowed_tools`, `ungranted_tools`, `ungranted_tool_count`, `has_ungranted_tools`.
- **Durable decision recording** in `_check_policy_gate`: one row per tool per invocation.
- **Trace emission** with decision_id, tools, policy_id, rule_id.

### Tests
- `test_tool_access_gate.py` (10 tests): policy fix, gate trigger (tools_required/no-tools/fail-closed), durable decisions (CRUD + one-per-tool), capabilities sanitizer.

## [2.41.3] — Memory Read Exposure Run Binding

### Fixed
- **Run ID binding:** exposure events now verified against durable decision `run_id`. Cross-run reuse of a valid allow → mismatch.

### Tests (1 new, 17 total)
- test_allow_in_run_a_but_exposed_in_run_b

## [2.41.2] — Memory Read Exposure Binding Exactness

### Fixed
- **Identity binding:** exposure events now verified against durable decision node_id AND step_id, not just decision_id existence.

### Tests (2 new, 16 total)
- test_allow_for_node_a_but_exposed_by_node_b
- test_allow_for_step_1_but_exposed_at_step_2

## [2.41.1] — Memory Read Dashboard Event Parsing + Audit Exactness

All notable changes to NodeChain are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

---

## [2.41.1] — Memory Read Dashboard Event Parsing + Audit Exactness

### Fixed
- **Payload parsing:** `collect_memory_read_status` now parses `_emit`-shaped payloads where `decision_id`/`node_id` are nested under `payload["metadata"]`, not at top level.
- **Missing decision_id:** exposure events with no `decision_id` are now counted as `without_decision` (was silently dropped).
- **Policy mismatch wiring:** `memory_read_policy_mismatch_count` now detects exposure events whose `decision_id` references a durable **deny** decision (was always 0).
- **MR-005 real signal:** collector now emits `lookup_failed=True` when `memory_read_decisions` or `state_events` lookup fails.

### Tests (4 new, 14 total)
- All exposure tests use `_emit`-shaped payloads (`{"decision":..., "metadata":{...}}`)
- `test_exposed_without_any_decision_id`: exposure with no decision_id → without_decision
- `test_exposed_with_deny_decision_is_mismatch`: deny decision + exposure → mismatch
- `test_mr005_fires_on_real_collector_failure`: broken db_path → lookup_failed → MR-005

## [2.41.0] — Memory Read Dashboard + Exposure Audit

Completes the memory governance vertical: write policy → write log → write reconciler → write dashboard → read policy → read log → read reconciler → **read dashboard**.

### Added
- **`EventType.MEMORY_READ_EXPOSED`**: fires only when memory is actually exposed in context (not just authorized with empty memory). Distinguishes authorization from exposure.
- **`collect_memory_read_status()`** (dashboard.py): live counters from `memory_read_decisions` table + `state_events`. Fields: requested/allowed/denied/without_decision/mismatch counts, nodes_with_memory_exposure, exposed_node_count, decision_count. All from real durable data — no stubs.
- **MR-001..005 health rules** (dashboard_health.py):
  - MR-001: denied reads > 0 → WARNING
  - MR-002: exposure without durable decision → CRITICAL
  - MR-003: policy mismatch → CRITICAL
  - MR-004: exposure detected → WARNING
  - MR-005: decision log lookup failed → DEGRADED (conservative — only on explicit failure)
- ALL_RULES: 59 → 64 (48 HR + 5 MEM + 6 SE + 5 MR).
- `memory_read` section wired into `collect_dashboard_v2()`.

### Design distinction
- `requested` = allowed + denied decisions (policy evaluated)
- `allowed` = durable allow decision exists
- `denied` = durable deny decision exists
- `exposed` = MEMORY_READ_EXPOSED event (actual context content, not just auth)
- `without_decision` = exposure event without matching durable allow

### Tests
- `test_memory_read_dashboard.py` (10 tests): live decision counts, exposure from events, without-decision detection, MR-001..005 trigger/no-trigger, clean environment healthy, zero-data stays healthy.

## [2.40.4] — SE Dashboard Collector Exactness (Gate 3 fix 3)

### Fixed
- **SE-005 real failure signaling:** `_count_side_effects_by_status` returns `(counts, lookup_failed)` tuple. Collector sets `ledger_lookup_failed=True` on real failure.
- **SE-006 key-level matching:** `_count_unreconciled_completed()` matches idempotency_keys, not aggregate subtraction. Catches false-negative (equal counts, different keys).

### Tests (2 new)
- `test_se006_false_negative_regression`: unmatched trace key + unrelated ledger key → detected
- `test_se005_fires_on_real_ledger_failure`: broken db_path → SE-005 triggers

## [2.40.3] — Dashboard Wiring + Version Continuity (audit Gate 3 fix 2)

### Fixed
- **Version regression:** package version was incorrectly set to 2.37.1 during the audit patch sequence, creating release-history ambiguity. Restored to 2.40.3 (continuing the audit line from 2.40.2).
- **SE-003/SE-006 not dashboard-wired:** `collect_workflow_recovery_status` accepted trace-sourced parameters but `collect_dashboard_v2` never passed real values. Now `_count_events_by_type` helper reads CONTRACT_VIOLATION and SIDE_EFFECT_COMPLETED events directly from the events table when state_manager is available. SE-003 counts contract violations; SE-006 approximates unreconciled completions (trace completed events minus ledger completed rows).

### Tests
- `test_se_dashboard_live.py` updated: tests proving collect_workflow_recovery_status returns nonzero counts from real state_manager data (not just injected parameters).

## [2.37.1] — Side-Effect Dashboard Counter Completion (audit Gate 3 fix)

### Fixed
- **SE-005 `ledger_lookup_failed` signal:** collector now emits `ledger_lookup_failed=True` when the side-effect ledger lookup raises an exception (was only flipping `available=False` without the flag).
- **SE-003 `undeclared_side_effect_count`:** was hardcoded stub=0. Now accepted as a parameter (`contract_violation_count`) on `collect_workflow_recovery_status`. SE-003 evaluates the counter directly without gating on `enabled` (trace-sourced counters are available even without a DB).
- **SE-006 `unreconciled_completed_count`:** was hardcoded stub=0. Now accepted as a parameter on `collect_workflow_recovery_status`. SE-006 evaluates without `enabled` gate (same rationale).

### Architecture
- Ledger-sourced counters (SE-001/002/004) require `enabled=True` (real DB access).
- Trace-sourced counters (SE-003/006) fire from caller-provided values without DB dependency.
- Callers with trace/reconciler data pass real counts; callers without pass 0 (honest).

### Tests
- `test_se_dashboard_live.py` (6 tests): SE-003/005/006 trigger from nonzero signals, don't trigger from zero.

## [2.39.2] — Recovery Decision Semantic Binding (audit Gate 1 audit fix 2)

### Fixed
- **Recovery decision was existence-only, not semantic:** `update_side_effect_status` now checks that the recovery decision type matches the target transition:
  - unknown→completed requires `verified_completed`
  - unknown→failed requires `verified_failed` or `mark_unrecoverable`
  - unknown→retry_authorized requires `safe_to_retry`
- **Duplicate validation removed:** the transition guard and recovery check were duplicated before and after terminal dedup. Now single pass: terminal dedup (same-status only) → transition guard → recovery semantic check → write.
- **failed→failed explicitly blocked:** failed is terminal; same-status replay was undefined. Now raises `SideEffectTransitionError`.

### Tests (7 new, 24 total)
- Mismatch negatives: safe_to_retry ≠ completed, verified_completed ≠ retry, verified_failed ≠ completed, verified_completed ≠ failed
- Correct pairings: mark_unrecoverable → failed passes
- operator_acknowledged alone does not authorize terminal transition
- failed→failed raises

## [2.39.1] — Runtime Transition Guard (audit Gate 1 audit fix)

### Fixed
- **Transition validator was not enforced at write time:** `update_side_effect_status` now calls `validate_side_effect_transition` BEFORE the terminal dedup check. Illegal transitions (completed→started, failed→completed, planned→unknown, unknown→started) raise `SideEffectTransitionError` at write time, not just post-hoc via reconciler.
- **Unknown→terminal requires recovery decision:** `update_side_effect_status` now checks for a matching `side_effect_recovery_decisions` row when transitioning from `unknown` to `completed`/`failed`/`retry_authorized`. No recovery decision → `SideEffectTransitionError`.
- **Terminal dedup scoped to same-status:** the completed-row dedup check now only fires when `ex_status == "completed" and status == "completed"` (same-status replay), not when transitioning to a different status.

### Added
- `SideEffectTransitionError` exception class.

### Tests
- `test_side_effect_transition_guard.py` (17 tests): illegal transitions blocked (planned→unknown, completed→started, failed→completed, unknown→started), unknown→terminal without recovery raises, unknown→terminal with recovery passes (completed/failed/retry), legal transitions pass, terminal dedup preserved, missing row no-op.

## [2.40.2] — Memory Read Exposure Binding + Test Completion

### Added
- **`Context.memory_read_decision_id`**: when memory is exposed to a node, the Context now carries the durable decision_id that authorized the exposure. Empty string = no memory exposed (sanitized). This binds decision ↔ actual context exposure for the v2.41.0 exposure audit.

### Tests
- `test_no_policy_fails_closed`: declared read node with no MEMORY_READ policy → denied
- `test_step_scoped_allow_expires`: second invocation at different step → no inherited allow
- `test_memory_receiving_node_marked_derived`: any node with allow → output marked memory-derived
- `test_downstream_node_without_allow_gets_stripped_output`: memory-derived output stripped from downstream without allow
- `test_denied_node_context_has_no_decision_id`: denied node → empty decision_id in context

## [2.40.1] — Memory Read Gate Hardening (code-review re-audit)

### Fixed
- **Fail-closed on missing MEMORY_READ decision:** if no policy decision returned for a declared read node, was treated as allowed. Now denied (same pattern as SIDE_EFFECT gate).
- **Decision-scoped allow binding:** `_memory_read_allows` changed from `set[str]` (node_id only) to `dict[(step_id, node_id), decision_id]`. One allow no longer authorizes retries/loops/branches without a fresh decision.
- **Branch step allocation order:** branch executor now allocates step BEFORE policy gate (was reversed), so memory-read decisions get the correct step_id.
- **Broader memory-derived lineage:** any node that received allowed memory now has its output marked memory-derived (was evidence_synthesizer only). Downstream nodes without allow get all memory-derived outputs stripped.

## [2.40.0] — Memory Read Policy Runtime Gate

Two-layer gate: authorization (PolicyGate MEMORY_READ) + enforcement (_build_context sanitizer).

### Fixed
- **MEMORY_READ_POLICY condition bug:** checked `"memory_access in [readonly, write]"` but actual values are `read`/`write`/`read_write`. `"readonly"` doesn't exist, so ALLOW never matched. Fixed to `"memory_access in [read, write, read_write]"`.
- **MEMORY_READ was dead code:** PolicyGate never evaluated MEMORY_READ (only MEMORY_WRITE). Now evaluated for nodes declaring `memory_access in ("read", "read_write")`.

### Added
- **PolicyGate MEMORY_READ branch** (policy_gate.py): evaluates PolicyType.MEMORY_READ for declared read nodes. Structured evaluation data (policy_type, memory_access, decision, rule_ids, policy_ids). DENY blocks node before invocation. Uses deny-preferred selector.
- **memory_read_decisions table** (state.py): durable decision log with 19 fields (decision_id, run_id, step_id, node_id, actor, policy_id, rule_id, decision, purpose, source, query_digest, memory_namespace, requested/exposed_item_count, exposed_to_node, reason_codes, created_at, metadata_json, retention_status). Three indexes.
- **EventType.MEMORY_READ_ALLOWED / MEMORY_READ_DENIED** (trace.py): pre-exposure gate events (not post-hoc observation).
- **_build_context sanitizer** (orchestrator.py): strips session_memory and memory-derived outputs from Context unless an allow decision exists for the node. Undeclared nodes get no memory by default. `_memory_read_allows` set tracks allowed nodes; `_memory_derived_outputs` set tracks lineage.
- **Memory-derived output lineage** (orchestrator.py): evidence_synthesizer output marked as memory-derived; downstream nodes without allow get it stripped from chain_state.
- **Reconciler MR-1/MR-2/MR-3** (trace_reconciler.py): MEMORY_READ_ALLOWED without durable decision = ERROR; denied but exposed = ERROR; durable allow without trace = WARNING.

### Replaced
- Evidence synthesizer post-hoc MEMORY_READ_REQUESTED emission (buggy: emitted REQUESTED twice) replaced with memory-derived lineage tracking.

### Tests
- `test_memory_read_gate.py` (12 tests): policy condition fix, allow/deny matching, durable decision CRUD, reconciler MR-1/MR-2/MR-3, context sanitizer (undeclared stripped, allowed exposed).

## [2.39.0] — Side-Effect Recovery Decision Log + Transition Guard

### Added
- **`side_effect_recovery_decisions` table** (state.py): durable record of operator/runtime decisions resolving unknown side effects. Fields: decision_id, run_id, idempotency_key, node_id, step_id, side_effect_type, prior_status, decision, actor, reason, external_reference, created_at, metadata_json.
- **Allowed decisions:** verified_completed, verified_failed, safe_to_retry, do_not_retry, mark_unrecoverable, operator_acknowledged.
- **`validate_side_effect_transition()`** (state.py): explicit legal-transition graph. Terminal states (completed/failed) cannot transition out. Unknown→terminal requires recovery decision. Retry_authorized→started is the retry path.
- **`record_recovery_decision()` / `get_recovery_decisions()`** (state.py): durable CRUD for recovery decisions.
- **Reconciler SE-R1..R5 checks** (trace_reconciler.py):
  - SE-R3: illegal status transition detected (status not in legal set)
  - SE-R4: recovery decision references missing ledger row = ERROR
  - SE-R5: recovery decision conflicts with terminal ledger state = ERROR
- **Dashboard counters** (collect_workflow_recovery_status): recovery_decision_count, unresolved_unknown_count, retry_authorized_count, unrecoverable_side_effect_count.

### Legal transition graph
```
planned → started → completed/failed/unknown
unknown → completed/failed/retry_authorized (requires recovery decision)
retry_authorized → started
completed/failed → terminal (no transitions)
```

### Tests
- `test_side_effect_recovery.py` (new): recovery decision CRUD, transition validation (legal/illegal), reconciler SE-R3/R4/R5.

## [2.38.1] — Collision Detection + Terminal Dedup (acceptance criteria 2-3)

### Added
- **`SideEffectCollisionError`** exception: raised by `record_side_effect` when a row with the same `(run_id, idempotency_key)` already exists but the new record claims a different `node_id`, `side_effect_type`, or `request_hash`. Same key + different identity = identity corruption, not idempotency.
- **`SideEffectIntegrityError`** exception: raised by `update_side_effect_status` when a row is already `completed` but the new `response_hash`/`external_reference` differs from the stored value. Same completed key + different response = integrity violation.

### Changed
- `record_side_effect`: replaced `INSERT OR IGNORE` with explicit collision check. Same identity → safe replay (no-op). Different identity → `SideEffectCollisionError`.
- `update_side_effect_status`: added terminal dedup check before UPDATE. Same response → safe no-op. Different response → `SideEffectIntegrityError`.

### Tests
- `test_side_effect_collision.py` (new): 10 tests covering collision (node/type/request_hash mismatch), safe replay, terminal dedup (same/different response, external_reference, missing response).

### Acceptance criteria now met
- ✅ Criterion 2: Same idempotency_key with different request_hash is detected
- ✅ Criterion 3: Same completed key with different response_hash is detected

## [2.38.0] — Side-Effect Idempotency/Dedup Hardening

### Added
- **`compute_side_effect_request_hash()`** in new `side_effect_utils.py` — single canonical function for request_hash derivation across all side-effect lifecycle paths. Takes `side_effect_type`, `node_id`, and either an `operation` dict (preferred) or `payload` (fallback). 16-char hex.
- **`compute_side_effect_response_hash()`** — canonical response hash from results list or external_reference passthrough.
- `_journal_one` now accepts optional `operation` param so search pre-call and post-call paths use the same operation dict for request_hash.
- Dashboard counters: `idempotency_collision_count`, `duplicate_completed_count`, `request_hash_mismatch_count`, `response_hash_mismatch_count` (stubs for v2.38.0).

### Fixed
- **Request hash derivation drift (v2.36.0 debt):** pre-call journaling used full-payload hash while post-call used `{terms, max, filters}` operation hash — producing different digests for the same side effect. Now both paths use the canonical function with the same `operation` dict.
- **Memory-write had no request_hash:** now computes from `{subject, content}` via the canonical function.
- **SE-005 counter_source** renamed from `workflow_recovery.enabled` to `workflow_recovery.ledger_lookup_failed` (matches actual firing condition).
- Reconciler `request_hash` mismatch upgraded from WARNING to ERROR (derivation is now canonical).

### Changed
- Search pre-call (`_journal_search_operations`), search completion, and search failure paths all use `compute_side_effect_request_hash` with the same operation dict.
- `_journal_one` forwards `operation` to the canonical hash when provided by the caller.

### What was NOT done
- Collision detection in `record_side_effect` (INSERT OR IGNORE still silently ignores duplicates). This is a state.py change that needs careful migration — deferred to a follow-up.
- Terminal dedup in `update_side_effect_status`. Same reason.
- SE-003/SE-006 wiring from real signals (still stubs).

## [2.37.0] — Side-Effect Governance Dashboard

### Added
- **SE-001..006 health rules** — new side-effect governance namespace in `ALL_RULES`:
  - SE-001: unknown side effects > 0 → WARNING
  - SE-002: failed side effects > 0 → DEGRADED
  - SE-003: undeclared side effects > 0 → CRITICAL
  - SE-004: blocked side effects > 0 → WARNING
  - SE-005: side-effect ledger unavailable → DEGRADED
  - SE-006: completed trace without ledger row > 0 → CRITICAL
- Each SE rule declares `counter_source` explicitly (per code review requirement: no hidden/global counters).
- `undeclared_side_effect_count` and `unreconciled_completed_count` fields added to `collect_workflow_recovery_status()` (stub=0 for v2.37.0; wired when trace/reconciler data is available).
- ALL_RULES bumped from 53 → 59 (48 HR + 5 MEM + 6 SE).

### Fixed
- **HR-022 field mismatch:** read nonexistent `unresolved_count` (defaulted to 1). Now reads `unknown_side_effect_count` — the actual intervention source.

### Kept stable
- HR-023 (FailedCheckpointRestore) and HR-024 (ResumedChainChangedContext) remain registered but dormant (hardcoded stubs). Not deleted — rule IDs stay stable for forward compatibility.
- No API version bump. Ruleset version change only. `DASHBOARD_API_VERSION` stays "1.0.0".

## [2.36.0] — Side-Effect Reconciler Strong Binding

### Added
- **Widened TraceEmitter signatures:** `side_effect_started` now accepts `request_hash`; `side_effect_completed` accepts `request_hash`, `response_hash`, `external_reference`; `side_effect_failed` accepts `request_hash`. Orchestrator forwards these from ledger writes to trace metadata.
- **`_strong_bind()` helper** in TraceReconciler: compares trace event against ledger row on `node_id`, `step_id`, `side_effect_type` (canonicalized), `request_hash`, and `response_hash`/`external_reference`. Mismatch on identity fields = ERROR. Response hash mismatch = ERROR when both present, silent when absent on one side.

### Changed
- **Check 4a (completed):** now calls `_strong_bind()` after key+status match passes. Binds node_id, step_id, side_effect_type, request_hash, response_hash.
- **Check 4b (started):** same strong binding.
- **Check 4f (failed):** same strong binding (was deferred from v2.33.0; now implemented).
- Orchestrator forwards `request_hash` to `SIDE_EFFECT_STARTED`, `request_hash`+`response_hash` to `SIDE_EFFECT_COMPLETED` (search path), `external_reference` to `SIDE_EFFECT_COMPLETED` (memory-write path).

### Binding matrix
```
STARTED:   idempotency_key + node_id + step_id + side_effect_type + request_hash
COMPLETED: idempotency_key + node_id + step_id + side_effect_type + request_hash + response_hash/external_reference
FAILED:    idempotency_key + node_id + step_id + side_effect_type + request_hash
BLOCKED:   attempt_id + decision (4g strengthening deferred to v2.37.0)
```

## [2.35.4] — Enforcement Correctness (code-review re-audit)

### Fixed
- **Search completed path returned `self.trace` (truthy) instead of `False`:** caller checked `if not _emit_node_detail_events(...)` but ChainTrace is truthy, so violation didn't propagate. Now returns `False`.
- **Declaration guards suppressed enforcement:** search/memory-write recording was gated on declaration membership, skipping enforcement for undeclared nodes. Now detects observed behavior first, then asserts.
- **Mock nodes updated:** MockNode accepts `side_effects`; search_tool and memory_write_decision mocks declare their effects.

## [2.35.3] — Violation Propagation to Chain Failure (code-review re-audit)

### Fixed
- **Pre-call violation didn't abort invocation:** `_journal_planned_side_effects` returned None; the main loop still called `_invoke_node`. Now returns bool — callers `_fail_chain("undeclared_side_effect")` and return before invocation.
- **Post-call violation didn't propagate:** `_emit_node_detail_events` returned None; `return self.trace` inside it only exited the helper. Now returns bool — callers check and `_fail_chain` on False.

## [2.35.2 — Declared-vs-Observed Enforcement Complete (code-review re-audit)

### Fixed
- **Search completed path bypassed assertion:** `_emit_node_detail_events` recorded `external_call` completed rows and emitted `SIDE_EFFECT_COMPLETED` without calling `_assert_declared_side_effect`. Now asserts before any ledger/trace write; aborts on None (`return self.trace`).
- **Search failed path bypassed assertion:** same fix for the adapter-failure branch.
- **Memory-write completion path bypassed assertion:** `record_side_effect`/`update_side_effect_status` for committed writes and the reservation close now assert `memory_write` is declared first.
- **CONTRACT_VIOLATION now stops execution:** all three paths return `self.trace` on assertion failure, ending the run — not just emitting and continuing.

## [2.35.1] — Declared-vs-Observed Enforcement Wired (code-review re-audit)

### Fixed
- **Runtime enforcement not wired into write paths:** `_assert_declared_side_effect()` existed but `_journal_one()` didn't call it. Now called before every ledger record/update and trace emission. Aborts the write on None return (CONTRACT_VIOLATION already emitted).
- **No-declaration backward-compat escape:** nodes with contracts but zero side-effect declarations were allowed to produce canonical side effects. Now fail closed — `node_declares_no_side_effects` reason. Manifest-level unknowns remain warning-only.
- **PolicyGate context used raw strings:** `side_effect_types` built from `se.effect_type` directly, not normalized. Now normalizes to canonical so policy rules match legacy declarations.
- **Check 4h incomplete:** audited ledger rows only, not trace events. Now checks SIDE_EFFECT_STARTED/COMPLETED/FAILED metadata too. Also distinguishes "contract available but declares nothing" (ERROR) from "contract unavailable" (WARNING).

### Tests
- Updated `test_node_without_declarations` → `test_known_node_with_empty_declarations_fails_closed`

## [2.35.0] — Declared-vs-Observed Side-Effect Enforcement

### Added
- **Canonical SideEffectType enum** (3 types): `external_call`, `memory_write`, `memory_read`. `tool_invocation` intentionally excluded (ambiguous — deferred to a future tool/capability model).
- **`normalize_side_effect_type()`** in contract.py: maps 8 legacy strings (external_api_read, api_call, search, external_read, external_write, etc.) → 3 canonical types. Unknown strings return None.
- **`EventType.CONTRACT_VIOLATION`**: dedicated event for undeclared observed side effects. Keeps `SIDE_EFFECT_BLOCKED` clean (policy gate block vs contract violation).
- **`_assert_declared_side_effect()`** in orchestrator: central helper that normalizes observed type, compares against node's declared types, and emits CONTRACT_VIOLATION + fails closed on mismatch. Nodes without declarations allow canonical types (warning territory for backward compat).
- **`_get_declared_se_types()`** in orchestrator: reads node contract, returns canonical declared types.
- **Check 4h** in TraceReconciler (`side_effect_declared_type_match`): ledger side-effect type must be declared by node contract (after canonicalization). Mismatch = ERROR. Contract unavailable = WARNING.

### Changed
- Orchestrator search-adapter path now records `external_call` (canonical), not `external_api_read`.
- `_journal_one()` normalizes effect_type before recording/emitting.
- Invariant engine replaces stale `("api_call", "search", "external_read", "external_write")` set with canonical normalization.
- TraceReconciler gains `set_nodes()` for wiring the node registry (Check 4h).

### Tests
- `test_side_effect_taxonomy.py` (new): canonical enum, parametrized normalization, orchestrator canonical writes, _assert_declared_side_effect (declared/undeclared/unrecognized/no-declarations), Check 4h (mismatch/unavailable).

### Non-goals (deferred)
- DB migration of historical rows (normalize at read time only)
- tool_invocation canonicalization (future tool/capability model)
- workflow_recovery SideEffectContract unification (separate model)
- Strong reconciler binding (v2.36.0)

## [2.34.1] — Side-Effect Gate Correctness (code-review re-audit)

### Fixed
- **Policy `in` condition not list-aware:** `side_effect_types` is a list, but the evaluator stringified it via `str(actual) in values`. A rule like `side_effect_types in ["external_call"]` wouldn't match a node declaring `["external_call", "memory_write"]`. Now checks if ANY list member is in values.
- **Blocked row cited wrong policy/rule:** `PolicyGate` stored `decisions[0]` (possibly a lower-priority ALLOW), not the actual DENY/REQUIRE_APPROVAL decision. Now binds to the denying decision.

### Tests
- `test_list_aware_in_condition`: verifies list-member matching (match + non-match)
- `test_default_allow_plus_operator_deny_precedence`: verifies the denying decision cites the operator rule, not the default allow

## [2.34.0] — Side-Effect Runtime Gate + Blocked Attempt Log

### Added
- **SIDE_EFFECT runtime gate** in `PolicyGate.check()`: evaluates `PolicyType.SIDE_EFFECT` for nodes with declared side effects. ALLOW-by-default (`SIDE_EFFECT_POLICY` in `DEFAULT_POLICIES`); operators install DENY/REQUIRE_APPROVAL rules to block. No matching SIDE_EFFECT decision fails closed. Gate placement is before `_journal_planned_side_effects`, so denials short-circuit before any side-effect intent is journaled or the node executes.
- **`side_effect_blocked_attempts` table** in `state.py`: one durable row per declared side-effect (not per node). Records `attempt_id`, `run_id`, `node_id`, `side_effect_type`, `effect_target`, `policy_id`, `rule_id`, `decision`, `denial_reason`. Five indexes (run_id, node_id, decision, rule_id, retention_status).
- **`EventType.SIDE_EFFECT_BLOCKED`**: dedicated lifecycle event (not reused from POLICY_EVALUATED). Emitted per durable blocked row with `attempt_id` as the binding key.
- **Check 4g** in `TraceReconciler`: `SIDE_EFFECT_BLOCKED` trace must match a durable `side_effect_blocked_attempts` row by `attempt_id`. Missing row = ERROR; decision not deny/require_approval = ERROR; durable row without trace = WARNING. Strong binding deferred to v2.36.0.
- **Structured SIDE_EFFECT evaluation data** in `PolicyCheckResult.evaluated_policies`: carries `policy_type`, `policy_id`, `rule_id`, `actions`, `side_effect_types` so the orchestrator can identify side-effect denials without string parsing.
- **Dashboard counters** in `collect_workflow_recovery_status()`: `side_effect_blocked_count`, `side_effect_denied_count`, `side_effect_require_approval_count`. No new health rule (full SE-001..006 dashboard deferred to v2.37.0).

### Methods
- `StateManager.record_side_effect_block(attempt: dict)` — INSERT OR REPLACE
- `StateManager.get_side_effect_blocks(*, run_id, decision, rule_id)` — filtered query

### Tests
- `test_side_effect_runtime_gate.py` (new): default policy registration, deny-rule override, blocked-attempt log CRUD, multiple-effects-separate-rows, Check 4g binding (match/missing/coverage/wrong-decision), dashboard counters.

### Non-goals (deferred)
- Declaration enforcement (undeclared side effects) — v2.35.0
- Strong reconciler binding (request_hash/response_hash) — v2.36.0
- Full SE-001..006 dashboard health rules — v2.37.0
- Idempotency/dedup hardening — v2.38.0

## [2.33.1] — Side-Effect Lifecycle Coverage (code-review re-audit)

### Fixed
- **`SIDE_EFFECT_STARTED` not emitted from production journaling:** `_journal_one()` recorded ledger rows to `started` without calling `side_effect_started()`. Now emits for both the new→started record and the planned→started update, so the trace surface mirrors the ledger for the `planned → started` transition.
- **Memory-write reservation row completed without trace coverage:** closing the node-level reservation to `completed` (on a successful write) did not emit `SIDE_EFFECT_COMPLETED`, which would trigger a reconciler Check 4c coverage warning. Now emits the completion event for the reservation key.

### Tests
- Added production-orchestrator test proving `_journal_one()` emits `SIDE_EFFECT_STARTED`.

## [2.33.0] — Side-Effect Trace/Ledger Lifecycle

### Fixed
- **TraceEmitter side-effect helpers emitted wrong EventType:** `side_effect_started()` emitted `TOOL_CALLED` and `side_effect_completed()` emitted `TOOL_RESULT_RECEIVED`, making them invisible to the reconciler's side-effect checks (which match on the `SIDE_EFFECT_*` substring). Both now emit their canonical `EventType.SIDE_EFFECT_STARTED` / `SIDE_EFFECT_COMPLETED`.
- **Dead `SIDE_EFFECT_FAILED`:** the enum value existed in `trace.py` but was never emitted by any code path. Added `TraceEmitter.side_effect_failed()` helper and wired it to the orchestrator's adapter-failure path.
- **Fake completion on crash recovery:** `_reconcile_side_effects_on_resume()` marked started effects as `unknown` in the ledger (correct) but also emitted a fake `SIDE_EFFECT_COMPLETED` with `decision="side_effect_marked_unknown"`, polluting the reconciler's completed bucket. The unknown transition now emits **no** trace event — the ledger `unknown` status is the sole source of truth, and Check 4d warns from ledger state directly.

### Added
- **Check 4f — SIDE_EFFECT_FAILED lifecycle binding** in `TraceReconciler`: a `SIDE_EFFECT_FAILED` trace event must match a ledger row with `status="failed"` (missing/mismatch = ERROR). Ledger failed without trace = WARNING (failure may be recovery-only). Strong binding (request_hash/response_hash) deferred to v2.36.0.
- **`workflow_recovery` dashboard section** in `collect_dashboard_v2()`: populates `unknown_side_effect_count`, `started/completed/failed/planned` counts, and `enabled` from the durable `side_effect_ledger`. Activates HR-022..025 (previously always short-circuited on `enabled=False` because the section was never collected).
- **`side_effect_failed()` helper** on `TraceEmitter` with `reason` metadata.
- Orchestrator now emits `SIDE_EFFECT_COMPLETED` on search-adapter success and memory-write commit, and `SIDE_EFFECT_FAILED` on adapter failure — so the trace surface mirrors the ledger transitions honestly.

### Tests
- `test_side_effect_trace_lifecycle.py` (new): proves the transition table — started→completed, started→failed (with Check 4f binding), started→unknown (no fake completion, recovery warning from ledger), emitter/reconciler integration.
- `test_trace_emitter.py`: updated assertions from `TOOL_CALLED`/`TOOL_RESULT_RECEIVED` to `SIDE_EFFECT_STARTED`/`SIDE_EFFECT_COMPLETED`; added `side_effect_failed` tests.

### Non-goals (deferred to v2.34.0+)
- No `PolicyType.SIDE_EFFECT` runtime gate.
- No blocked-attempt durable log.
- No declaration enforcement.
- Memory-write-blocked ledger rows remain at `started` (known false-positive source for `unknown` on resume) — documented as v2.34.0 target.
- No idempotency-key derivation changes, no strong reconciler binding.

## [2.31.0] — Memory Policy Type Split

### Fixed
- **Latent policy classification bug:** `MEMORY_WRITE_POLICY` and `MEMORY_READ_POLICY` both used `PolicyType.MEMORY_ACCESS`, so the read policy's `deny_read` rule would fire for write nodes. Fixed by splitting into distinct types.

### Changed
- Added `PolicyType.MEMORY_WRITE` and `PolicyType.MEMORY_READ` to the enum. `MEMORY_ACCESS` retained as deprecated (distinct legacy value, not an alias).
- `MEMORY_WRITE_POLICY.policy_type` → `MEMORY_WRITE`. `MEMORY_READ_POLICY.policy_type` → `MEMORY_READ`.
- `PolicyGate` write-node check now evaluates `MEMORY_WRITE` (not `MEMORY_ACCESS`).
- Removed the `policy_id == "research.memory_write.v1"` filter workaround from `memory_write.py` (no longer needed — the type split isolates write policies natively).
- `test_policy_gate.py` updated: `MEMORY_ACCESS` → `MEMORY_WRITE` in 3 evaluation calls.

### Non-goals (deferred)
- No read-gate activation (v2.32.0 — needs contract fixtures, denied-read trace behavior, tests).
- No new memory dashboard counters, no dedup cleanup, no memory_decisions table changes.
- No broader policy engine redesign.

## [2.30.0] — Memory Governance Dashboard

### Added
- New `collect_memory_status(state_manager=None)` in dashboard.py — derives 9 counters from the durable `memory_decisions` table: total, allowed, denied, skipped, errors, denied_low_confidence, denied_high_sensitivity, committed_writes, uncommitted_allowed.
- New `memory` section in `collect_dashboard_v2` (8 sections total, was 7).
- 5 new health rules: MEM-001 (errors → DEGRADED), MEM-002 (uncommitted allowed → CRITICAL), MEM-003 (high-sensitivity denied → WARNING), MEM-004 (decision log unavailable → DEGRADED), MEM-005 (ChromaDB health → never fires, unavailable).
- ChromaDB health excluded from dashboard (network dependency — `chromadb_health_available=False`, `chromadb_health_source="excluded_network_dependency"`). Per code review: don't risk dashboard hangs.

### Changed
- `ALL_RULES` now has 53 rules (48 HR + 5 MEM). 27 test files updated with new count.

### Non-goals (deferred)
- No `PolicyType.MEMORY_READ` split (v2.31.0).
- No ChromaDB record reconciliation.
- No dedup cleanup.

## [2.29.0] — Memory Decision Reconciler

### Added
- New `_check_memory_decision_binding` reconciler method (Check 5c, sibling to the review receipt/attempt bindings). Binds `MEMORY_WRITE_ALLOWED`/`MEMORY_WRITE_BLOCKED` trace events to durable `memory_decisions` rows via `candidate_digest`.
- Enriched memory trace metadata: ALLOWED/BLOCKED events now carry `candidate_id`, `candidate_digest`, `policy_id`, `rule_id`, `decision` (read from the candidate dict, which the node now stashes).
- Node stashes `candidate_digest` + `governed_decision` on the candidate dict — the node is the digest authority (canonicalizes + strips volatile provenance).
- Binding direction: durable row is canonical governance artifact; trace is audit projection. Reconciler verifies trace did not drift.
- New checks: `memory_decision_log_missing`, `memory_decision_type_mismatch`, `memory_decision_allow_missing_write_ref`, `memory_decision_blocked_has_write_ref`, `memory_write_ref_mismatch`, `memory_rule_id_mismatch`, `memory_decision_duplicate` (warning), `memory_decision_duplicate_conflict` (error).
- Targeted regression tests for checks 8-10: low-confidence → `memory.block_low_confidence`, high-sensitivity → `memory.block_high_sensitivity`, structural skip → `decision=skip`.

### Non-goals (deferred)
- No memory dashboard section/health rules (v2.30.0).
- No `PolicyType.MEMORY_READ` split (v2.31.0).
- No ChromaDB-backed record reconciliation (trace ↔ SQLite only).
- No dedup cleanup.

## [2.28.0] — Durable Memory Decision Log

### Added
- New `memory_decisions` SQLite table — one row per memory write candidate decision (allow/deny/skip/error), mirroring `review_decision_attempts`. Blocked candidates leave a durable row even when no Chroma write occurs.
- `StateManager.record_memory_decision(decision)` and `StateManager.get_memory_decisions(run_id=, decision=, rule_id=)`.
- `MemoryWriteDecisionNode` records one decision row per candidate (Stage 5) via an optional `record_memory_decision` callback (wired by `run.py` to `StateManager.record_memory_decision`).
- Decision classification: `allow` (policy ok + validation ok + committed), `deny` (policy denied), `skip` (structural validation failed), `error` (policy ok + validation ok but commit failed).
- Canonical digests: `subject_digest = sha256_dict({"subject": subject})`, `candidate_digest = sha256_dict({subject, content, confidence, sensitivity, provenance})` — provenance stripped of volatile `generation_timestamp` for stability.
- Non-fatal-visible callback failure: if `record_memory_decision` raises, the node completes normally and surfaces `memory_decision_log_error` in its output (Correction A).

### Non-goals (deferred)
- No memory decision reconciler (v2.29.0).
- No memory dashboard section/health rules (v2.30.0).
- No `PolicyType.MEMORY_READ` split (v2.31.0).
- No dedup cleanup.

## [2.27.0] — Memory Policy Runtime Gate + Write Reference Binding

### Fixed
- **Memory policy gate was a structural no-op.** The declarative `MEMORY_WRITE_POLICY` existed and was wired into `PolicyGate`, but the evaluation context never included `confidence`/`sensitivity`, so `memory.block_low_confidence` and `memory.block_high_sensitivity` always short-circuited. Only `memory.allow_write` (condition `always`) ever matched — every memory write was allowed by the gate. Actual blocking happened in a duplicated, hardcoded in-node `_evaluate_policy` that emitted fake `policy_id` strings (`memory.confidence_threshold`) that didn't match the declarative `rule_id`s.
- **`write_ref`/`doc_id` binding was always empty.** The orchestrator read `write_result.get("write_ref")` for trace metadata and the side-effect ledger's `external_reference`, but `ChromaAdapter.write_memory` returned `doc_id` only. The durable ChromaDB identifier never reached the trace. Fixed: adapter now returns `write_ref` (aliased to `doc_id`).

### Changed
- `MemoryWriteDecisionNode` now accepts an optional `policy_engine: PolicyEngine`. When injected (wired in `run.py`), `_evaluate_policy` delegates to `engine.evaluate(MEMORY_ACCESS)` with the candidate's confidence and sensitivity — making the declarative `MEMORY_WRITE_POLICY` the runtime authority.
- The node emits REAL declarative rule_ids (`memory.block_low_confidence`, `memory.block_high_sensitivity`, `memory.allow_write`) from the gate result, not the old fake strings.
- `_validate_candidate` now checks structural fields only (empty content/subject). The confidence threshold is a POLICY decision handled by the gate, not a structural validation.
- Fallback path (no engine injected) also emits real rule_ids.
- Filters engine decisions to `research.memory_write.v1` policy_id to avoid a latent classification bug where `MEMORY_READ_POLICY` shares the `MEMORY_ACCESS` type.

### Non-goals (deferred)
- No durable memory-decision log (like review_decision_attempts).
- No memory dashboard section or health rules.
- No reconciler memory-write binding.
- No dedup cleanup (existing_id/window_hours bugs).
- No `PolicyType.MEMORY_READ` / `MEMORY_RETENTION` activation.

## [2.26.0] — Reconciler Review Attempt Binding

### Added
- New `_check_review_attempt_binding` reconciler method (sibling to the v2.23.0 receipt binding) forming the **audit triangle**: trace ↔ receipt ↔ attempt log.
- Admitted attempts bound against BOTH the `HUMAN_REVIEW_COMPLETED` trace metadata AND `state.metadata["governed_decision_receipt"]` (request_id, request_digest, subject_type, subject_id, attempted_outcome, reviewer_identity).
- Governance-failure path: exactly one non-admitted attempt required; 0 or >1 → error; rejection_reason mismatch → error.
- Duplicate admitted attempts: warning if equivalent (same binding fields), error if conflicting (`review_attempt_duplicate_conflict`).
- New checks: `review_attempt_log_missing`, `review_attempt_request_digest_mismatch`, `review_attempt_subject_type_unexpected` (warning), `review_attempt_duplicate_admitted` (warning), `review_attempt_duplicate_conflict` (error), `review_attempt_duplicate_failure` (error), `review_attempt_rejection_mismatch`, `review_attempt_outcome_receipt_mismatch`, `review_attempt_subject_id_mismatch`, `review_attempt_reviewer_identity_mismatch`.
- reviewer_identity binding: fails only on explicit disagreement where both sides provide a value (legacy surfaces lacking it don't fail solely for absence).

### Changed
- Two v2.23.0 receipt-binding tests updated: `_produce_real_receipt` now wires `record_attempt` (matching the real orchestrator); the governance-failure test records a non-admitted attempt (audit triangle complete).

### Non-goals (deferred)
- No full Durable ReviewQueue, no claiming/locking, no replay engine, no retention purge, no reviewer assignment, no multi-gate receipt-history model, no dashboard expansion.

## [2.25.0] — Durable Review Decision Attempt Log

### Added
- New `review_decision_attempts` SQLite table — one row per `ReviewVerifier.verify()` call (admitted OR rejected), closing the HR-046 gap. Columns: review_attempt_id, run_id, chain_id, step_id, request_id, request_digest, subject_type, subject_id, attempted_decision_type, attempted_outcome, reviewer_identity, required_reviewer_role, admitted, rejection_reason, verifier_checks (JSON `{"warnings": [...]}`), policy_digest, graph_digest, created_at, retention_status (`active`, forward-compatible — no purge enforcement this version).
- `StateManager.record_review_attempt(attempt)` and `StateManager.get_review_attempts(run_id=, admitted=, rejection_reason=)`.
- `ReviewManager` records exactly one attempt row after `verify()`, before fail-closed handling — so rejected attempts persist even when the chain then fails. Wired via an optional `record_attempt` callback (orchestrator passes `state_manager.record_review_attempt`).
- HR-046 (`unauthorized_attempts`) now derives from the attempt log. Counts ONLY authorization/admissibility rejections (`reject_unauthorized_reviewer`, `reject_decision_type_not_valid_for_subject`, `reject_subject_type_mismatch`, `reject_no_review_request`) — NOT digest/rationale/staleness failures. `unauthorized_attempts_available` is now `True` when a state_manager is wired.

### Changed
- HR-046 now fires from real unauthorized attempt data instead of being permanently unavailable.
- Two v2.24.0 tests updated: unauthorized_attempts is now available (True) but 0 when no unauthorized attempts exist (previously asserted unavailable=False).

### Non-goals (deferred)
- No queue claiming/locking, no reviewer assignment, no multi-pending scheduler, no replay engine, no retention purge job, no new reviewer roles.
- No replacement of the `state.metadata` pause/resume path.
- Reconciler attempt-log consistency check deferred.

## [2.24.0] — Dashboard Live Data

### Added
- `collect_review_workbench_status` now derives three of its four review-health counters from durable chain state (no longer hardcoded zeros):
  - `stale_count` (HR-045) — runs paused `waiting_for_review` whose governed request is older than 72h.
  - `rejected_blocking_count` (HR-048) — terminal runs with a committed `reject` receipt blocking the workflow.
  - `stale_decision_count` (HR-047) — receipts whose governed request was already >72h old at decision time (strict, decision-timestamp-based definition using `receipt.created_at == decision.decided_at`).
- `StateManager.list_all_review_states()` — scoped scan of `chain_states` returning only runs carrying governed-review metadata (`governed_review_request`, `governed_decision_receipt`, or `governed_review_failure`). Intentionally not a generic list-all-runs method.
- `collect_dashboard_v2` now wires a `StateManager` (same DB resolution as inspect/reconcile) into the review collector, gated on the DB file existing to preserve deterministic-output guarantees.
- `unauthorized_attempts_available` / `unauthorized_attempts_source` fields surface honestly that HR-046 is not derivable from current durable state (receipts only record admitted decisions).

### Changed
- HR-045, HR-047, HR-048 now fire from real runtime-derived data instead of always-zero inputs.
- Legacy `review_queue` parameter still honored (back-compat); both sources merged with max() semantics.

### Non-goals (deferred)
- `unauthorized_attempts` (HR-046) stays 0 / unavailable until a durable review-decision attempt log exists (planned v2.25.0).
- No Durable ReviewQueue lifecycle (identity, replay, retention).
- No new reviewer role.

## [2.23.0] — Reconciler Receipt Binding

### Added
- TraceReconciler now binds `HUMAN_REVIEW_COMPLETED` trace events to the persisted governed `DecisionReceipt` via a new `_check_review_receipt_binding` check (replaces the prior presence-only Check 5).
- Recomputes the persisted receipt digest (not just string equality) to detect post-commit tampering with the receipt fields.
- Cross-binds the receipt's `request_digest` against the original `governed_review_request` (recomputed with the original `created_at`) when that request is persisted.
- Governance-failure events (`decision='governance_failure'`) reconcile as failure-path-valid when no receipt is committed, and as an error when a receipt is incorrectly present.
- New checks: `review_receipt_id_mismatch`, `review_receipt_digest_mismatch`, `review_receipt_digest_tamper`, `review_request_id_mismatch`, `review_request_digest_mismatch`, `review_request_digest_request_mismatch`, `review_receipt_metadata_missing`, `review_receipt_state_missing`, `review_receipt_not_committed`, `review_subject_type_mismatch` (warning), `review_subject_type_unexpected` (warning), `governance_failure_with_receipt`.

### Changed
- Hoisted the materialized-state load to the top of `reconcile()` so the receipt-binding check reads `ChainState.metadata` independent of the Check 9 `completed_steps` branch. Behavior-preserving refactor; Check 9 reuses the same variable.

### Non-goals (deferred)
- No Durable ReviewQueue.
- No dashboard live-data changes.
- No new reviewer role.
- No runtime decision-materialization changes.
- No multi-gate receipt history model beyond what trace events already expose.

## [2.22.1] — Test Fixture Date-Rollover Fix

### Fixed
- Replaced hardcoded `issued_at`/`expires_at` dates in `tests/test_repo_audit_hardening.py` with relative-to-now timestamps via `_relative_metadata_dates()` helper. The prior fixture expired at `2026-06-20T00:00:00Z`, turning the suite red every day from that date forward. The new helper issues metadata 5 minutes in the past (inside the 24h freshness window) with a 1-day-forward expiry, so it never rolls over again.

### No functional changes
- This is a test-only patch. No runtime, SDK, CLI, or schema changes. The v2.22.0 review-receipt feature boundary is untouched.

## [2.22.0] — Review Receipt Runtime Consumption

### Added
- Added `chain_review` as a governed review subject for runtime risk-classifier review gates.
- Added chain-review decision constants for approve, reject, and revision requests.
- Added `chain_review_decision_type()` helper for mapping runtime review outcomes to governed decision types.
- Runtime review gates now materialize `ReviewRequest`, `OperatorDecision`, and digest-committed `DecisionReceipt` artifacts.
- Decision receipts are stored in `ChainState.metadata["governed_decision_receipt"]`.
- Paused review states persist `ChainState.metadata["governed_review_request"]` for resume-safe digest binding (preserves original `created_at`).
- Human-review trace events now include decision receipt references in metadata (`receipt_id`, `receipt_digest`, `request_id`, `request_digest`, `subject_type`, `reviewer_identity`).
- Verifier failure fails closed: `state.status="failed"`, `reason_code="review_receipt_verification_failed"`, no receipt stored, downstream blocked.
- `NODECHAIN_REVIEWER_IDENTITY` env var (default `runtime:auto`) for auto-mode reviewer identity.
- `NODECHAIN_REVIEW_RATIONALE_OVERRIDE` env var (test hook for exercising the fail-closed path).
- 27 new tests in `tests/test_review_receipt_runtime.py`.

### Changed
- `ReviewDecision` now carries optional receipt metadata (`receipt_id`, `receipt_digest`, `decision_receipt`) while preserving the existing scheduler decision string.
- Resume review resolution now binds resumed decisions to the original persisted governed review request (digest-stable across pause/resume).
- `DEFAULT_ROLE_AUTHORITY[ROLE_OPERATOR]` now includes `SUBJECT_CHAIN_REVIEW` (authorization tied to role, not identity string).
- `ReviewQueue.record_decision` now handles the `request_revision` outcome (status `revision_requested`).

### Non-goals (deferred to future versions)
- No durable `ReviewQueue` runtime persistence (queue identity, replay, retention).
- No dashboard live-data changes (`collect_review_workbench_status` counters unchanged).
- No trace reconciler receipt-binding enforcement.
- No new reviewer role (`ROLE_CHAIN_OPERATOR`); blueprint `chain_operator` maps to `ROLE_OPERATOR`.

## [2.21.3] — 2026-06-20

### Review Dashboard Collection Actual Closure

  - collect_dashboard_v2() now includes review_workbench section
  - This is the actual collector used by the CLI (`nodechain dashboard`)
  - HR-045 through HR-048 auto-trigger from collect_dashboard_v2() data
  - 22 actual closure tests targeting collect_dashboard_v2() directly
  - verify_receipt() wording remains digest commitment / committed

## [2.21.2] — 2026-06-20

### Review Dashboard Collection Closure

  - Added collect_review_workbench_status() to dashboard.py
  - collect_dashboard() now includes review_workbench section
  - HR-045 through HR-048 trigger automatically from collected dashboard data
  - Cleaned remaining "signed/signature" wording in verify_receipt()
  - 14 collection closure tests

## [2.21.1] — 2026-06-20

### Review Workbench Claim-Hygiene and Dashboard Wiring

  Claim hygiene:
    - Renamed DecisionReceipt.signature → digest_commitment
    - Renamed sign() → commit()
    - Renamed is_signed → is_committed
    - Updated all tests to use digest-committed terminology

  Dashboard wiring:
    - Added HR-045 (pending_review_too_old) to dashboard_health.py
    - Added HR-046 (unauthorized_decision) to dashboard_health.py
    - Added HR-047 (stale_decision_receipt) to dashboard_health.py
    - Added HR-048 (rejected_blocking_workflow) to dashboard_health.py
    - ALL_RULES now has 48 rules
    - Review health rules evaluate against review_workbench dashboard sections

  28 wiring + claim-hygiene tests

## [2.21.0] — 2026-06-20

### Governed Human Review / Operator Decision Workbench

  New module: `src/nodechain/sdk/review_workbench.py` (~700 lines)

  OR-001:
    A human/operator decision is admissible only if it references a materialized
    review request, validates the bound artifacts, satisfies reviewer authority
    policy, records rationale, and emits a decision receipt. No operator decision
    may mutate runtime state directly.

  Core primitives:
    ReviewRequest, ReviewSubject, ReviewerPolicy, OperatorDecision,
    DecisionReceipt, ReviewQueue, ReviewVerifier

  11 decision types: approve/reject for capability, branch merge, compensation,
    deployment, remote binding; acknowledge health finding

  9 verification checks: request match, request digest, subject digest,
    policy digest, decision type match, reviewer authority, rationale for
    high-risk, staleness, role hierarchy

  Dashboard health rules HR-045 through HR-048

  CLI: nodechain review submit, nodechain review decide

  15 acceptance criteria — 77 tests

## [2.20.1] — 2026-06-19

### Governance Console HTML / Serving Hardening

  CONSOLE-001: All graph-derived values escaped before HTML insertion.
    - Added _esc() helper using html.escape() with quote=True
    - Applied to labels, metadata, warnings, rejection reasons, branch IDs,
      receipt IDs, severity names, digest strings, source artifacts
    - 5 XSS payloads tested: <script>, img onerror, svg onload, iframe, SQL injection

  CONSOLE-002: console serve binds to 127.0.0.1 by default.
    - Added --host option (default: 127.0.0.1)
    - Added --allow-remote-console flag for non-localhost binding
    - Rejects unsafe host binding without explicit flag
    - Added Content-Security-Policy header (script-src 'none', style-src 'unsafe-inline')

  10 acceptance criteria (AC-01 through AC-10) — 62 hardening tests

## [2.20.0] — 2026-06-19

### Operator-Facing Ecosystem Governance Console

  New module: `src/nodechain/sdk/governance_console.py` (~900 lines)

  OC-001:
    The governance console is a read-only operator surface over materialized
    NodeChain artifacts. It must not invent trust, mutate runtime state, or
    make policy decisions outside existing governance primitives.

  6 core surfaces:
    1. Graph viewer — renders graph JSON from v2.19.x
    2. Package inspector — identity, registry, publisher, lifecycle, cert
    3. Capability inspector — selected vs rejected candidates
    4. Branch inspector — plans, budgets, results, merge, human review
    5. Health console — HR-001 through HR-044 by severity
    6. Receipt explorer — digests, links, provenance

  CLI commands:
    nodechain console open --graph graph.json [--mode terminal|json|html]
      [--section summary|warnings|health|capabilities|branches|receipts|all]
      [--inspect node_id] [--nodes type_group]
    nodechain console serve --graph graph.json [--port 8700]

  3 output modes: terminal, JSON, HTML (from same graph JSON)
  15 acceptance criteria (AC-01 through AC-15) — 65 tests

## [2.19.2] — 2026-06-19

### Graph Verify Full Parity

  graph verify now supports the same 8-flag artifact set as graph export:
    --lockfile, --capability-receipt, --deliberation-receipt,
    --branch-plans, --branch-results, --merge-decision,
    --health-sections, --trace-events

  CLI export and verify now accept identical inputs.

## [2.19.1] — 2026-06-19

### Graph Explorer Completeness / CLI Parity

  CLI now exposes all SDK materialization paths.

  New flags on `nodechain graph export`:
    --health-sections     Dashboard health sections (HR-001–HR-044)
    --trace-events        Trace events (ordered execution graph)
    --branch-plans        Branch plans for deliberation graph
    --branch-results      Branch results for deliberation graph
    --merge-decision      Merge decision for deliberation graph

  `nodechain graph verify` now supports the same artifact set:
    --lockfile, --capability-receipt, --deliberation-receipt,
    --health-sections, --trace-events

  Deliberation graph CLI now renders full adaptive-branch view:
    receipt + plans + results + merge decision + human review gate.

  25 CLI parity tests covering AC-01 through AC-08.

## [2.19.0] — 2026-06-19

### Visual Trust Graph / Capability Graph Explorer

  NodeChain can now render a verifiable governance graph showing how
  packages, dependencies, capabilities, adaptive branches, merge
  decisions, receipts, trace events, and health rules relate — without
  inventing trust relationships not backed by runtime evidence.

  Central invariant VG-001: Every visual graph edge and node must be
  backed by a materialized runtime, trust, capability, dependency,
  branch, receipt, or dashboard artifact. The graph explorer must not
  invent inferred trust relationships.

  New module: src/nodechain/sdk/visual_graph.py
    - GraphNode, GraphEdge, TrustGraphView data model
    - GraphExporter with 5 materialization paths:
      build_from_lockfile()
      build_from_capability_receipt()
      build_from_deliberation_receipt()
      build_from_health_sections()
      build_from_trace_events()
    - JSON and Mermaid export formats
    - Deterministic graph digest
    - Missing artifact warnings (VG-001)
    - merge_graphs() for multi-source views

  CLI commands:
    nodechain graph export --lockfile --capability-receipt --deliberation-receipt
    nodechain graph verify --lockfile

  6 graph views: package trust, dependency, capability selection,
  adaptive branching, receipt chain, health overlay.

  53 tests covering 15 acceptance criteria + VG-001.

## [2.18.1] — 2026-06-19

### Adaptive Branching Adversarial and Budget Certification

  25-scenario adversarial matrix covering branch policy attacks,
  budget exhaustion attacks, merge/human-review attacks, and integrity/
  determinism attacks.

  New invariants:
    AB-002: A branch result is admissible for merge only if its branch plan
            was admissible, its budget was not exhausted beyond policy, and
            its side-effect log contains no unauthorized committed side effect.
    AB-003: A deliberation receipt is valid only if every referenced branch
            plan digest, branch result digest, merge decision digest, policy
            digest, and budget digest matches the materialized artifact.
    AB-004: A non-selected branch is evidence-only. Its output may not mutate
            committed workflow state unless a later governed merge explicitly
            selects it.

  New functions:
    is_result_admissible_for_merge() — AB-002 enforcement
    verify_receipt_integrity() — AB-003 enforcement (7 digest checks)
    is_branch_committable() — AB-004 enforcement
    get_evidence_only_branches() — AB-004 helper

  Claim hygiene: DeliberationReceipt is digest-committed, not signed.

  59 adversarial tests. Linux: full suite passed.

## [2.18.0] — 2026-06-19

### Adaptive Branching / Bounded Deliberation

  NodeChain can now branch under uncertainty, compare bounded
  alternatives, and merge a selected path while preserving policy,
  budget, sandbox, capability, dependency-trust, trace, evidence, and
  human-review controls.

  Central invariant AB-001: Adaptive branching may only create branches
  whose policies, budgets, capability requests, package selections,
  dependency graphs, sandbox profiles, and side-effect permissions are
  admissible before execution.

  10 non-negotiable rules:
    1. Branches cannot self-authorize.
    2. Branches cannot expand parent permissions.
    3. Branches cannot bypass capability resolution.
    4. Branches cannot bypass dependency trust resolution.
    5. Exploratory branches are read-only by default.
    6. Side-effect branches require explicit policy authorization.
    7. Non-selected branches cannot mutate committed state.
    8. Budget exhaustion must stop the branch.
    9. Merge decisions must be receipt-backed.
    10. High-risk, irreversible, or ambiguous merge decisions require human review.

  New module: src/nodechain/sdk/adaptive_branching.py
    - DeliberationRequest, DeliberationTrigger
    - BranchPolicy (with child-narrowing validation)
    - BudgetTracker (tokens, time, tool calls, retries, depth, side effects)
    - BranchPlan (admissibility-validated)
    - BranchExecutionContext (isolated state)
    - BranchResult (output, evidence, capability receipts, budget, verdicts)
    - MergeDecision (select/reject/defer with rationale_digest)
    - DeliberationReceipt (full audit trail with signature)
    - BranchController (single authority for plan creation and execution)
    - default_merge_strategy (evidence-based, deterministic tie-breaking)
    - validate_child_policy (Rule 2 enforcement)

  Dashboard health rules HR-040 through HR-044:
    HR-040: Active deliberation
    HR-041: Exhausted branch budget
    HR-042: Branch policy violation
    HR-043: Unresolved merge
    HR-044: Human review pending

  103 tests covering 15 acceptance criteria + 10 non-negotiable rules.

## [2.17.4] — 2026-06-19

### Trust Digest Closure

  TRUST-004: fail_closed_empty_trust is now included in
  TrustAwareResolver._compute_policy_digest(). Two policies that differ
  only in this flag now produce different resolver_policy_digests,
  ensuring lockfiles and receipts are bound to the correct admission
  semantics.

  3 new tests: digest changes with flag, same flag produces same digest,
  graph digest reflects flag.

  Loop-back cursor regression tests confirmed at:
    TestRuntime001LoopBackCursor.test_rebuild_order_with_loop_returns_correct_index
    TestRuntime001LoopBackCursor.test_loop_target_at_correct_position

## [2.17.3] — 2026-06-19

### Repo Audit Hardening: Signature Semantics, CLI Trust Check, and Docs Alignment

  Addresses all 7 findings from the v2.17.2 repo audit.

  CLI-001: Fixed --trust-check `_json` bug
    - Changed `_json.load(f)` to `json.load(f)`
    - In strict mode, trust-check exceptions now fail closed (exit 15)
    - In non-strict mode, exceptions emit a warning instead of silent pass

  TRUST-001/002: Signature terminology clarification
    - Added SIGNATURE_PROTOCOL_NOTE constant to registry_trust.py
    - Updated module docstrings: "signed" → "digest-committed" where
      no asymmetric crypto occurs
    - Added verify_digest_integrity() method to SignedRegistryMetadata
    - Evaluator now rejects metadata with mismatched digest (Check 1c)
    - get_signed_metadata() now includes metadata_digest and signature fields
    - All "signature" fields documented as SHA-256 digest commitments in
      reference implementation; production should use RSA-PSS-SHA256 or Ed25519

  TRUST-003: Fail-closed empty trust sets
    - Added fail_closed_empty_trust parameter to TrustAwareResolver
    - When True, empty trusted_registries/trusted_publishers reject all
    - Default False preserves dev/test backward compatibility

  DOC-001: README and ARCHITECTURE alignment
    - README updated: removed "local-only" and "not a public node registry"
    - README now lists v2.12–v2.17 remote capabilities
    - ARCHITECTURE.md marked as HISTORICAL with v2.17.2 context note

  DOC-002: governed_install docstring fixed
    - Removed INSERT OR IGNORE framing from recovery comment
    - Updated to reference RI-001 identity verification

  RUNTIME-001: Loop-back cursor regression tests
    - Added tests for rebuild_order_with_loop with repeated node IDs
    - Verifies target node is findable at correct position after rebuild

  18 audit hardening tests. Linux: full suite passed.

## [2.17.2] — 2026-06-19

### CR-002 Strict Mode: require_governed_evidence

  CR-002 is now absolute by default, not conditional on wiring.

  New policy field: require_governed_evidence (default=True)

  When True (production default):
    - Candidates without governed evidence for scores, trust, risk, and
      certification are rejected with REJECT_UNVERIFIED_SCORE.
    - This applies whether or not an EvidenceProvider is configured.
    - Without an EvidenceProvider: ALL candidates are rejected.
    - With an EvidenceProvider: only candidates with returned evidence pass.

  When False (development/testing only):
    - Self-claimed offer fields are accepted as before.
    - Evidence provider still overrides when available.

  Updated tests: all capability tests now supply governed evidence via
  MockEvidenceProvider. 5 new tests verify strict default behavior.

  100 total capability tests (66 resolver + 34 adversarial). Linux: full suite passed.

## [2.17.1] — 2026-06-19

### Capability Resolver Adversarial Certification

  20-scenario adversarial test matrix proving the capability resolver
  under hostile offers, false self-claims, selection drift attacks,
  and policy edge cases.

  New invariants:
    CR-002: Capability scores must be derived from trusted registry,
    certification, evaluation, and policy evidence. A candidate package
    may advertise capability, but it must not be the authority for its
    own score, trust level, or certification.

    CR-003: A selected capability resolution is stable until explicitly
    re-resolved. Newly discovered candidates must not silently replace
    a pinned selection.

  New resolver capabilities:
    - EvidenceProvider protocol + GovernedEvidence dataclass
    - Evidence overrides self-claimed scores, trust, risk, certification
    - No evidence → REJECT_UNVERIFIED_SCORE
    - re_resolve() for governed re-resolution with drift warning
    - is_selection_stable() to check pin stability

  20 scenarios:
    1.  Wrong input contract → rejected
    2.  Wrong output contract → rejected
    3.  DT-001 failed → rejected before scoring
    4.  Excellent score but policy denial → score ignored
    5.  Forbidden secondary capability → rejected
    6.  Weaker sandbox than policy → rejected
    7.  Risk exceeds max_risk → rejected
    8.  Deprecated with allow_deprecated=false → rejected
    9.  Deprecated with allow_deprecated=true → selectable
    10. High-risk → human review required
    11. External publisher → human review required
    12. Narrow score margin → human review required
    13. Exact score tie → deterministic tie-break
    14. Preferred publisher cannot override hard filter
    15. Lockfile drift after selection
    16. Package revoked after selection → re-resolution rejects
    17. Better candidate appears → no silent switch
    18. False evaluation score → CR-002 evidence rejection
    19. Explain mode → rejected candidates preserved
    20. Determinism → same inputs produce same receipt

  29 adversarial tests. Linux: full suite passed.

## [2.17.0] — 2026-06-19

### Capability Resolution and Governed Node Selection

  Given multiple nodes that claim the same capability, NodeChain can now
  discover eligible implementations, reject unsafe ones, select the best
  admissible one, and prove why it chose it.

  New module: src/nodechain/sdk/capability_resolver.py

  Core primitives:
    - CapabilityRequest: A chain asks for a capability, not a specific package
    - CapabilityOffer: A package advertises what it can provide
    - CapabilityResolutionPolicy: Policy-owned scoring weights and hard requirements
    - CapabilitySelectionReceipt: Evidence trail for selection decisions
    - CapabilityPin: Version-pinned capability resolution for blueprint embedding
    - CandidateScore: Per-dimension scoring breakdown

  CR-001: Capability selection is admissible only among candidates whose
  complete package graph has already passed dependency trust resolution.
  Scoring never overrides policy denial.

  10 non-negotiable rules:
    1.  Nodes may advertise capabilities
    2.  Nodes may not select themselves
    3.  Capability selection is performed by the resolver
    4.  Hard policy filters run before scoring
    5.  A higher score cannot override a policy denial
    6.  Every candidate graph must pass DT-001
    7.  Selection must be deterministic under the same inputs
    8.  Human review required for high-risk or ambiguous selections
    9.  The chosen package must be version-pinned
    10. Selection receipt must include rejected candidates and reasons

  Hard filters:
    contract mismatch, revoked, deprecated disallowed, uncertified,
    untrusted registry, unapproved publisher, forbidden capability,
    sandbox downgrade, risk too high, DT-001 failed

  Scoring dimensions (policy-owned):
    contract_fit (35), evaluation_score (25), certification_recency (15),
    trust_level (10), risk (10), latency_cost (5)

  Deterministic tie-breaking:
    preferred publisher > preferred package > certification recency >
    evaluation score > trust level > lower risk > stable identity ordering

  Human review triggers:
    high-risk node, external publisher, narrow score margin

  5 dashboard health rules: HR-035 through HR-039
    HR-035: unresolved capability request
    HR-036: ambiguous selection
    HR-037: high-risk selected node
    HR-038: selected deprecated node
    HR-039: selection drift

  66 tests covering 13 acceptance criteria + CR-001/CR-003/CR-009.

## [2.16.1] — 2026-06-19

### Dependency Resolver Adversarial Certification

  20-scenario adversarial test matrix proving the trust-aware dependency
  resolver under hostile dependency graphs, transitive attacks, and
  policy edge cases.

  Resolver enhancements:
    - Cycle detection with path tracking (resolving_stack)
    - Explain mode: rejected candidates and reasons preserved in receipt
    - Cross-registry ambiguity: fail closed unless registry explicitly trusted

  20 scenarios:
    1.  Direct revoked dependency → graph rejected
    2.  Transitive revoked dependency → graph rejected
    3.  Direct uncertified when cert required → rejected
    4.  Transitive uncertified → rejected
    5.  Forbidden capability (direct) → rejected
    6.  Forbidden capability (transitive) → rejected
    7.  Sandbox downgrade → rejected
    8.  Version conflict between branches
    9.  Dependency cycle → rejected with cycle path
    10. Cross-registry ambiguity → fail closed unless trusted
    11. Deprecated dependency → policy-controlled
    12. Lockfile drift after metadata update
    13. Publisher revoked after lockfile → re-resolution rejects
    14. Registry signer rotated → continuity verified
    15. Same version different artifact → lockfile drift
    16. Deep dependency graph → deterministic digest
    17. Diamond dependency → one resolved identity
    18. Capability aggregation → accurate union
    19. Sandbox aggregation → no node below required
    20. Explain mode → rejected candidates preserved in receipt

  25 adversarial tests. Linux: full suite passed.

## [2.16.0] — 2026-06-19

### Remote Dependency Resolution and Transitive Trust

  A remote package is admissible only if every dependency in its resolved
  graph is version-compatible, identity-verified, non-revoked, publisher-
  authorized, certified, policy-admissible, and sandbox-compatible.

  DT-001 (critical invariant):
    A package graph is admissible only if every reachable dependency is
    individually trusted, policy-admissible, lifecycle-valid, certification-
    valid, and sandbox-compatible. Trust does not flow transitively from
    the root package.

  New module: src/nodechain/sdk/trust_resolver.py
    - ResolvedTrustGraph: complete graph with trust verdicts per node
    - ResolvedTrustNode: per-package lifecycle, policy, trust verdict
    - TrustGraphEdge: dependency edges with constraints
    - TrustLockfile: binds all fields, detects drift
    - TrustResolutionReceipt: signed resolution record
    - TrustAwareResolver: policy-driven graph resolution

  Resolver checks (10 hard rules):
    1. Revoked dependency blocks graph
    2. Uncertified dependency blocks when certification required
    3. Forbidden capability blocks graph
    4. Sandbox downgrade blocks graph
    5. Untrusted registry blocks graph
    6. Unapproved publisher blocks graph
    7. Deprecated dependency is policy-controlled
    8. Resolution is deterministic
    9. Lockfile binds exact versions and digests
    10. Trust does not flow transitively (DT-001)

  Aggregate computation:
    - Combined capabilities (union of all nodes)
    - Strongest sandbox profile (max of all nodes)

  Deprecated policy modes:
    allow_with_warning | deny | allow_only_if_pinned

  Dashboard health rules (4 new):
    HR-031: revoked transitive dependency (CRITICAL)
    HR-032: deprecated transitive dependency (WARNING)
    HR-033: lockfile drift (DEGRADED)
    HR-034: unresolved dependency conflict (DEGRADED)

  41 tests. Linux: full suite passed.

## [2.15.1] — 2026-06-19

### Registry Lifecycle Adversarial Certification

  12-scenario certification proving lifecycle governance under adversarial
  timing, stale metadata, concurrent authority changes, and hostile-network
  conditions.

  New invariant LG-011:
    Once a client has accepted a valid signer-rotation record for a registry,
    the superseded signer must not authorize metadata generations >= the
    rotation generation unless explicitly retained by an overlap policy.

  New trust verdict: superseded_signer

  Trust store additions:
    record_signer_supersession() — records rotation in client trust store
    is_signer_superseded() — checks if signer was rotated out
    get_supersession_generation() — gets generation at which signer was superseded

  12 adversarial scenarios:
    1.  Old signer after rotation → rejected for newer gen (LG-011)
    2.  Overlap window → both signers accepted if policy permits
    3.  Unlinked signer change → fail closed
    4.  Rotation chain A → B → C → transitive continuity verified
    5.  Rotation replay → no rollback
    6.  Publisher revocation + publish → rejected
    7.  Revoked package installed → evidence preserved, lifecycle revoked
    8.  Revoked package re-publish → rejected
    9.  Deprecation after pinning → policy-controlled
    10. Emergency revocation → signed receipt, generation advanced
    11. Concurrent transitions → atomic, one legal final state
    12. Rotation during install → completes against verified gen or fails closed

  25 adversarial tests + 7 LG-011 direct tests. Linux: full suite passed.

## [2.15.0] — 2026-06-19

### Registry Lifecycle Governance

  Governs all registry lifecycle transitions: publish, deprecate, revoke,
  signer rotation, and publisher authority changes.

  New module: src/nodechain/sdk/registry_lifecycle.py
    - LifecycleGovernor: governs all transitions with authorization
    - TransitionLog: append-only log with integrity verification
    - LifecycleTransition: per-transition record with digest
    - LifecycleReceipt: signed receipt per transition
    - KeyContinuityRecord: signer rotation history

  10 lifecycle invariants (LG-001 through LG-010):
    LG-001: Signer rotation preserves registry_id continuity
    LG-002: Only the current signer can authorize rotation
    LG-003: All transitions produce signed receipts
    LG-004: Lifecycle transitions advance generation
    LG-005: Revoked packages are terminal (cannot transition)
    LG-006: Deprecated packages can only transition to revoked
    LG-007: Publisher authority changes authorized by current signer
    LG-008: Transition log is append-only
    LG-009: Signer rotation emits key-continuity receipt
    LG-010: Publisher revocation does not revoke published packages

  Lifecycle state machine:
    active → deprecated (one-way)
    active → revoked (terminal)
    deprecated → revoked (terminal)
    revoked → (terminal, no transitions)

  Signer rotation:
    Old signer authorizes rotation to new key
    registry_id preserved (identity continuity)
    Key continuity chain tracks all rotations
    Post-rotation operations require new signer

  Publisher authority governance:
    Add: authorize new publisher with optional package scope
    Revoke: remove publisher authorization
    Published packages remain immutable (LG-010)

  51 tests.

## [2.14.1] — 2026-06-19

### Client–Server Hostile-Network Integration Certification

  16-scenario integration test matrix verifying the complete protocol
  under adversarial transport and server behavior.

  New file: tests/test_hostile_network_cert.py

  16 scenarios:
    1.  Valid server → install succeeds
    2.  Unapproved registry signer → client rejects
    3.  Unauthorized publisher → server rejects
    4.  Expired metadata → strict client rejects
    5.  Generation rollback → client rejects
    6.  Equivocation → client detects and fails closed
    7.  Changed artifact under same version → server rejects RR-001
    8.  Changed publisher under same version → server rejects
    9.  Changed certification under same version → server rejects
    10. Revoked package → excluded from active index, re-publish rejected
    11. Deprecated package → lifecycle changed, immutable identity preserved
    12. Mirror same canonical identity → accepted, provenance recorded
    13. Endpoint identity drift → endpoint-drift failure
    14. Redirect to disallowed scheme → detected
    15. TLS validation failure → strict mode enforced
    16. Crash during install phases → governed recovery

  Semantic correction (v2.14.0 review):
    Split immutable release identity from mutable lifecycle state.
    RR-001 now compares 8 immutable fields (not 9). Lifecycle
    (active/deprecated/revoked) is mutable metadata that changes
    through authorized signed registry transitions, NOT part of
    immutable release identity.

    Immutable (8 fields): package_id, version, artifact_digest,
      manifest_digest, publisher_fingerprint, publisher_id,
      certification_digest, sandbox_profile
    Mutable: lifecycle, revoked_at, deprecated_at, revocation_reason

  Trust role separation verified:
    Registry signing authority ≠ publisher authorization.
    Trusted registry signer does not automatically make publishers trusted.
    Publisher signature does not replace registry metadata trust.

  77 tests (33 hostile-network + 44 reference server). Linux: full suite passed.

## [2.14.0] — 2026-06-19

### Reference Remote Registry Server

  A stateful reference implementation proving the server side of the
  Remote Registry Trust Protocol. Not a marketplace — a protocol proof.

  New module: src/nodechain/sdk/reference_registry_server.py
    - RegistryState: persistent state (id, signer, generation, packages)
    - PublisherAuthorization: approved publisher records (fail closed)
    - ImmutablePackageRecord: 9-field identity, RR-001 enforcement
    - PublicationReceipt: signed receipt per successful publish
    - ReferenceRegistryServer: full publish/read/revoke/deprecate API

  Publish flow:
    1. Artifact size check (50 MB limit)
    2. Publisher authorization (fail closed)
    3. Artifact digest computation (SHA-256)
    4. RR-001 immutability check (9-field identity comparison)
    5. Content-addressed artifact storage (dedup by digest)
    6. Atomic generation advancement
    7. Publication receipt emission

  RR-001 (core invariant):
    A package version is immutable. Once package_id + version is published,
    any later publication must have the same complete identity or be
    rejected as a conflict.

  Lifecycle states: active → deprecated, active → revoked
  Revoked packages excluded from active package index digest.
  Generation advances on publish, revoke, and deprecate.

  v2.13.0 compatibility:
    Server metadata (get_signed_metadata) produces v2.13.0-compatible
    SignedRegistryMetadata with generation, issued_at, expires_at,
    and package_index_digest. Client trust evaluator can verify it.

  44 tests.

## [2.13.0] — 2026-06-19

### Remote Registry Trust Protocol v1

  Establishes trust in remote registry metadata through signed metadata
  with freshness, generation, and expiry.

  New module: src/nodechain/sdk/registry_trust.py
    - SignedRegistryMetadata v1: registry_id, signer_fingerprint,
      issued_at, expires_at, generation, package_index_digest
    - RegistryTrustStore: persistent trust state with approved signers,
      accepted metadata records, endpoint identity mappings
    - RegistryTrustEvaluator: 5-check trust evaluation protocol
    - TransportProvenance: forensic transport detail (URL, redirects)

  Trust protocol (5 checks):
    1. Signer approval: registry_id must be bound to approved signer fingerprint
    2. Freshness: reject expired metadata in strict mode, reject stale
    3. Rollback prevention: reject generation < highest accepted
    4. Equivocation detection: same identity + generation, different digest
    5. Endpoint identity drift: same endpoint, different registry identity

  Invariants:
    Empty allowlist fails closed (no signer approved = not trusted)
    Canonical identity = registry_id + signer_fingerprint (not URL)
    Transport URL is forensic provenance, not trust identity

  Dashboard health rules (5 new):
    HR-026: remote install conflict
    HR-027: registry metadata expired or stale
    HR-028: registry equivocation or rollback (CRITICAL)
    HR-029: endpoint identity drift
    HR-030: unapproved registry signer

  42 tests.

## [2.12.1] — 2026-06-19

### Remote Install Identity and Registry Metadata Integrity

  RI-001: A remote install may be treated as idempotently registered only
  when the existing local registry entry exactly matches the verified
  remote package identity and provenance.

  INSERT OR IGNORE is insufficient — it can silently leave an old entry
  in place while the installer concludes success. Registration now
  requires exact-identity comparison across 9 fields:
    package_id, package_version, artifact_digest, manifest_digest,
    publisher_fingerprint, registry_fingerprint, registry_id,
    certification_digest, trust_level

  New: install_conflict terminal phase for identity mismatches.
  New: InstallConflictError with diagnostic mismatch list.
  New: compare_registry_identity() and verify_registration_idempotency().
  New: compute_canonical_install_key() using registry_id + signer fingerprint
    instead of transport URL. Mirrors, redirects, and trailing-slash
    variants produce the same canonical identity.

  Invariant: The canonical identity is the durable trust identity.
  The transport URL is ephemeral.

  30 tests.

## [2.12.0] — 2026-06-19

### Governed Remote Installation

  Makes remote package installation a checkpoint-governed operation.
  Installation inherits the recovery discipline established in v2.10-v2.11:
  durable idempotency keys, phase tracking, and crash-safe recovery.

  New module: src/nodechain/sdk/governed_install.py
    - InstallJournal: durable journal of install operations
    - InstallOperation: tracks install through 7 phases
    - InstallRecoveryManager: reconciles interrupted installs
    - GovernedInstallReceipt: enhanced receipt with idempotency key
    - compute_install_key(): deterministic idempotency key
    - classify_install_recovery(): safe recovery action per phase

  Install phases (crash-safe at every boundary):
    pending → downloading → downloaded → extracting
            → extracted → registering → committed

  Recovery rules:
    committed:            skip (already done)
    pending/downloading:  safe to restart
    downloaded:           resume at extraction
    extracting:           re-extract from verified artifact
    extracted:            resume at registration
    registering:          re-register (INSERT OR IGNORE)

  Idempotency: same package + version + digest = same install key.
  A different digest for the same version is a conflict, not a retry.

  Installation is itself a side-effect-governed operation with
  idempotent_with_key contract. A crash during download, extraction,
  or local registration follows the same recovery discipline.

  46 tests.

## [2.11.2] — 2026-06-19

### Side-Effect Recovery Semantic Corrections

  Two semantic refinements that tighten the recovery model:

  Fix 1: planned actions are 'eligible for execution', not 'skip'.
    A planned action was never dispatched. On resume it should be
    eligible for normal execution when the workflow reaches that point.
    New ELIGIBLE recovery action and eligible_keys list.

  Fix 2: compensatable actions require authorization, not automatic.
    A compensating action is itself a side effect. The contract tells
    NodeChain that an undo path exists; policy and authorization decide
    whether that path may execute.
    PROPOSE_COMPENSATION replaces COMPENSATE.
    authorization_required + human_approval_required flags on decision.

  Invariant:
    A recovery contract describes available recovery behavior.
    Policy and authorization decide whether that behavior may execute.

  3 tests (on top of 31 from v2.11.1).

## [2.11.1] — 2026-06-19

### Side-Effect Recovery Semantics

  Make exactly-once claims conditional on an explicit, verifiable idempotency
  contract with the external action target.

  A started action may have reached an external system before crash.
  Re-executing it is safe only when the contract guarantees idempotency.

  New: SideEffectContract / IdempotencyContract metadata
    Every action-capable side effect must declare one of:
      idempotent_with_key  → retry with same key
      externally_queryable → query target before retry
      compensatable        → operator-approved compensation path
      non_idempotent       → needs_intervention
      unknown              → needs_intervention

  New: classify_started_effect()
    Determines safe recovery action based on contract type.

  New: SideEffectRecoveryDecision
    Per-action recovery decision with contract verification.

  Enhanced: ActionDeduplicationResult
    Now includes retried_keys, queried_keys, compensated_keys,
    and full recovery_decisions list.

  Enhanced: WorkflowRecoveryManager.recover()
    Started effects are classified by idempotency contract.
    No contract → defaults to unknown → needs_intervention.

  Dashboard health rule:
    HR-025: unresolved side-effect ambiguity

  31 tests.

## [2.11.0] — 2026-06-19

### Checkpointed Workflow Recovery Integration

  Graduate from subsystem hardening to workflow-level recovery assurance.
  Proves that a composed multi-node, side-effect-aware workflow can crash,
  restart, reconcile its checkpoint journal, restore only verified state,
  and continue without duplicating governed actions.

  New module: `src/nodechain/sdk/workflow_recovery.py`
    - WorkflowEnvironmentBinding: 7-field execution environment capture
    - WorkflowCheckpointBinder: capture + verify + diff bindings
    - WorkflowRecoveryReceipt: full recovery provenance with action dedup
    - WorkflowRecoveryManager: 7-step recovery protocol
    - ActionDeduplicationResult: completed/skipped/unknown classification

  Environment binding fields (resume rejected on mismatch):
    - blueprint_revision
    - execution_order_hash
    - package_versions
    - policy_profile_digest
    - trust_store_digest
    - registry_resolution_digest
    - certification_state_digest

  Dashboard health rules:
    - HR-022: unresolved recovery intervention
    - HR-023: failed checkpoint restore
    - HR-024: resumed chain with changed trust/policy context

  10 acceptance criteria verified. 30 tests.

## [2.10.10] — 2026-06-19

### Checkpoint Crash Matrix Certification

  CP-026: Chain save atomicity invariant documented and regression-tested.
    chain.save() delegates to atomic_write_json() (temp + fsync + os.replace
    + dir fsync). checkpoint_prepared → aborted reconciliation is safe
    because chain persistence cannot expose a partially committed checkpoint.

  Crash injection at 10 durable boundaries:
    1. After journal.prepare()           → safe abort
    2. After manifest retain()            → needs intervention
    3. After checkpoint_prepared          → committed if in chain, else aborted
    4. During chain.save()                → aborted (atomicity prevents partial)
    5. After chain_committed marking      → committed
    6. During mark_committed()            → committed (idempotent)
    7. Concurrent journal mutation        → serialized by lock
    8. Corrupt/truncated journal           → CheckpointError fail-closed
    9. Manifest unavailable at reconcile  → needs intervention
    10. Chain checkpoint, journal absent  → committed via reconciliation

  Negative assertions:
    - Never silently lost
    - Never silently duplicated
    - Never incorrectly included in later snapshot lineage

  27 certification tests.

## [2.10.9] — 2026-06-19

### Checkpoint Journal Commit Ordering and Store-Aware Reconciliation

  CP-022: Checkpoint identity persisted before chain save.
    New checkpoint_prepared intermediate state.
    mark_checkpoint_prepared() records checkpoint_id and checkpoint_digest
    BEFORE chain.save(), enabling reconciliation to identify
    already-committed checkpoints after crash.

  CP-023: Store-aware reconciliation.
    reconcile() accepts store parameter, checks manifest existence.
    prepared + manifest in store = needs intervention (crash after retain).
    prepared + manifest absent = safe to abort.

  CP-024: Aborted manifests excluded from snapshots.
    _get_aborted_manifest_exclusions() returns journal aborted digests.
    create_checkpoint() filters them from artifact_digests.

  CP-025: Journal locking.
    CheckpointJournal has own lock for all mutations.

  18 tests across 4 findings.

## [2.10.8] — 2026-06-19

### Checkpoint Journal Integrity and Crash Reconciliation

  CP-019: Journal records actual manifest digest.
    - Expected manifest digest computed before retention.
    - mark_manifest_retained() verifies actual matches expected.
    - Journal links operations to their retained artifacts.

  CP-020: Corrupt journal fails closed.
    - _load() raises CheckpointError on corrupt JSON or missing fields.
    - Only missing file = legitimate empty journal.
    - Each operation validated for required fields.

  CP-021: Crash reconciliation implemented.
    - New chain_committed intermediate state.
    - checkpoint_id and checkpoint_digest recorded before chain save.
    - reconcile() deterministically resolves nonterminal operations:
      prepared -> aborted, chain_committed -> committed.
    - manifest_retained without chain match -> needs intervention.

  18 tests across 3 findings.

## [2.10.7] — 2026-06-19

### Checkpoint Commit Journal and Recovery Semantics

  CP-018: Failed checkpoint creation after manifest retention
  is journaled and recoverable.
    - New CheckpointJournal: prepare → manifest_retained → committed/aborted.
    - create_checkpoint() wraps post-manifest operations in try/except,
      marking aborted with reason on failure.
    - Recovery report surfaces uncommitted and aborted operations.
    - Journal-manifest digests are recoverable, not silently orphaned.
    - Journal is atomically written and survives crashes.

  16 tests across 1 finding.

## [2.10.6] — 2026-06-19

### Checkpoint Commit Atomicity and Genesis Resolver Binding

  CP-016: Failed checkpoint creation leaves no retained evidence.
    - Manifest retention moved inside the chain lock.
    - All preconditions (keypair check, signer authorization,
      chain validation) pass before manifest is retained.
    - Failed checkpoint creation leaves no orphaned manifest artifacts.

  CP-017: Strict creation requires resolver consistency for genesis.
    - Genesis checkpoint creation now verifies resolver can resolve
      the signer fingerprint.
    - Authorized signer not in resolver → CheckpointError.
    - Creation cannot produce a checkpoint that strict verification
      would later reject.

  16 tests across 2 findings.

## [2.10.5] — 2026-06-18

### Checkpoint Policy Completion and Creation-Gate Enforcement

  CP-014: Strict recovery verification is fail-closed.
    - generate_recovery_report() under strict profiles with missing
      chain, resolver, or key returns invalid + checkpoint_indeterminate.
    - New RecoveryReport field: checkpoint_indeterminate.
    - Storage integrity alone is never valid under strict policy.

  CP-015: Checkpoint creation is policy-governed.
    - create_checkpoint() accepts profile and signer_resolver params.
    - Strict profiles require authorized signer fingerprint.
    - Private/public key correspondence verified before signing.
    - Existing chain verified under profile-aware resolution.

  18 tests across 2 findings.

## [2.10.4] — 2026-06-18

### Checkpoint Signer Policy Enforcement

  CP-012: Signer authorization is now enforced by all verification APIs.
    - verify_checkpoint(), verify_checkpoint_chain(),
      generate_recovery_report(), and detect_rollback() accept
      optional profile and signer_resolver parameters.
    - resolve_verification_key() is the new gate: under strict profiles,
      the caller-supplied key is ignored and the resolver-provided key
      is used instead.
    - Missing profile/resolver in strict mode → denied or indeterminate.

  CP-013: Resolver provides keys, not authorization.
    - check_checkpoint_signer_policy() no longer accepts resolver
      membership as authorization.
    - Signer must be in profile.trusted_checkpoint_signers.
    - Resolver only resolves the authorized fingerprint to its key.
    - Fingerprint binding (resolver key → checkpoint signer_fingerprint)
      enforced before signature check.

  19 enforcement tests + 3 backwards-compat tests.

## [2.10.3] — 2026-06-18

### Checkpoint Signer Authorization

  CP-010: create_checkpoint() verifies the existing chain's signatures,
    continuity, and sequence before extending it. Cannot extend
    an already-invalid chain.

  CP-011: Manifest self-consistency: artifact_count must equal
    len(artifact_digests), no duplicate digests, all digests
    must be valid 64-char SHA-256 hex.

  CP-012: Organization-authorized checkpoint signing.
    - CheckpointSignerResolver maps fingerprints to public keys.
    - check_checkpoint_signer_policy() enforces org policy.
    - New profile fields: trusted_checkpoint_signers,
      require_checkpoint_signer_authorization, allow_any_checkpoint_signer.
    - strict_enterprise and airgapped_high_assurance require authorization.
    - Empty allowlist fails closed unless allow_any_checkpoint_signer=True.
    - Cryptographically valid signer ≠ organization-authorized signer.

  17 tests across 3 findings.

## [2.10.2] — 2026-06-18

### Checkpoint Semantic Binding and Verified Lineage

  CP-006: Manifest artifact is parsed as RetentionManifest and its internal
    fields (index_digest, artifact_count, policy_profile_digest) are cross-
    checked against checkpoint fields. Snapshot artifacts are verified from
    the manifest's artifact_digests list, not from the live index.

  CP-007: Incompatible lineage detection. A local chain at equal-or-higher
    sequence that does not contain the external anchor digest is treated as
    incompatible lineage and fails closed. No fallback to manifest-artifact
    existence check.

  CP-008: detect_rollback() verifies the entire local chain before using it
    for lineage comparison. Broken signatures, predecessor links, or sequence
    discontinuities are detected before the rollback decision.

  CP-009: External anchor signature and signer identity are mandatory.
    Without a public key, detect_rollback() returns indeterminate.
    Unverified anchors cannot influence a trust conclusion.

  14 semantic and lineage tests across 4 findings.

## [2.10.1] — 2026-06-18

### Anchored Checkpoint Verification and Adversarial Hardening

  CP-001: External anchor model for rollback detection. Local chain
    truncation is only detectable with a verified external checkpoint.
  CP-002: Unconditional signer-fingerprint binding. verify_checkpoint_signature()
    derives fingerprint from supplied key and compares to checkpoint.signer_fingerprint
    before signature check. No longer conditional on optional parameter.
  CP-003: Descendant-based rollback detection. Normal forward progress
    (external anchor is ancestor of local chain head) is NOT rollback.
    Chain truncation below external anchor IS rollback.
  CP-004: Chain writer serialization. CheckpointChain has its own lock.
    create_checkpoint holds chain lock for sequence determination + append.
  CP-005: Retained manifest artifact. manifest_digest now refers to a
    content-addressed RetentionManifest stored in the retention store.
    No longer duplicates the index-entry digest.

  19 adversarial tests across 9 ACs.

## [2.10.0] — 2026-06-18

### Signed Evidence Checkpoints and Recovery Verification

Converts the retention layer from locally consistent storage into a
reviewable evidence-history subsystem.

  - `EvidenceCheckpoint`: signed snapshot of retention state at a point in time.
  - `CheckpointChain`: append-only chain with continuity enforcement.
  - `verify_checkpoint()`: 7-point verification (digest, signature, fingerprint,
    manifest match, artifact availability, artifact digests, index integrity).
  - `verify_checkpoint_chain()`: chain continuity, monotonic sequence, signature.
  - `generate_recovery_report()`: orphans, missing, corrupted, broken chain,
    rollback detection against externally retained checkpoints.
  - `detect_rollback()`: whole-store rollback detection.
  - RSA-PSS-SHA256 signing over checkpoint_digest.
  - New CLI: `nodechain checkpoint` (create, verify, chain, recovery).
  - New evidence types (3), transparency events (4), health rule HR-021.

30 tests across 7 categories.

## [2.9.3] — 2026-06-18

### Retention Adversarial Suite and Write-Path Fail-Closed

  RET-004: Write-path fail-closed. _update_index_locked() and retain()
    now verify the existing index BEFORE mutation. A tampered index
    causes RetentionError without writing artifacts or healing the index.

  RET-005: Directory fsync after atomic replace for crash-durability.
    atomic_write() now calls _fsync_dir() on the parent directory after
    os.replace(). Best-effort (no-op on Windows NTFS).

  34 adversarial tests across 14 ACs covering:
    AC-01: Index tampering before retain
    AC-02: Missing schema_version before retain
    AC-03: Missing entries before retain
    AC-04: Blank index_digest before retain
    AC-05: Retain-GC concurrency safety
    AC-06: Concurrent retain operations
    AC-07: Crash after object write before index update
    AC-08: Partial write / corrupt JSON detection
    AC-09: Locked verification between verifier and writer
    AC-10: Empty valid index
    AC-11: Empty invalid index (missing digest)
    AC-12: Symlink and path traversal rejection
    AC-13: Missing/orphan/digest-mismatched object detection
    AC-14: GC refusal on every index-integrity error type

## [2.9.2] — 2026-06-18

### Retention Index Digest Fail-Closed

  1. If index.json exists, schema_version, entries, and index_digest are mandatory.
  2. Missing/blank index_digest causes RetentionError.
  3. Empty entries still require: SHA-256(canonical({})) == stored index_digest.
  4. No index file = legitimate empty state (not an error).
  5. GC acquires lock FIRST, then calls load_index() inside lock,
     scans from that verified snapshot.
  6. verify_integrity() and find_orphaned()/find_missing() use the
     verified index snapshot, not unchecked loads.

7 new tests covering all v2.9.2 fail-closed scenarios.

## [2.9.1] — 2026-06-18

### Retention Transaction and GC Safety Hardening

Three code fixes:

  RET-001: Truncated/empty index now invalidates integrity and blocks GC.
    - load_index() always verifies digest, even for empty indexes
    - Missing 'entries' field is an error, not silently normalized
    - Orphans make verify_integrity() report valid=False
    - collect_orphans() verifies index before proceeding; refuses on failure
    - collect_orphans() holds the store lock during the entire operation

  RET-002: Index update now happens inside the store lock in retain().
    - No gap between artifact write and index entry
    - Windows locking upgraded from advisory to msvcrt.locking (real lock)
    - GC holds lock for entire scan+delete operation

  RET-003: Digest scope documented as consistency, not tamper resistance.
    - Tests confirm that an attacker who recomputes the digest is not caught
    - Stronger protection requires signed manifests or append-only checkpoints

19 tests across 3 findings.

## [2.9.0] — 2026-06-18

### Artifact Retention and Evidence Index Protection

Evidence index is derived from retained artifacts.
Retained artifacts are not trusted merely because an index mentions them.

New module: src/nodechain/sdk/artifact_retention.py
  - ContentAddressedStore: artifacts stored at artifacts/<sha256[:2]>/<digest>
  - Atomic writes (temp file + fsync + atomic replace)
  - Writer serialization (file locking)
  - Evidence index with canonical digest (verified on read)
  - Receipt integrity (digest recomputed on load)
  - Artifact integrity (digest recomputed on read)
  - Orphaned/missing artifact detection
  - Retention manifest with digest root
  - Safe garbage collection (never deletes referenced objects)
  - Path safety (rejects traversal, symlinks, device files)
  - Full integrity verification

New CLI: nodechain retention
  - retain, verify, manifest, gc, list

New transparency events: artifact_retained, artifact_orphan_collected,
  evidence_index_verified, evidence_index_mismatch
New evidence types: retention_manifest, garbage_collection_receipt
New health rule: HR-020 (evidence_index_issues)

New org profile fields: require_evidence_index_verification,
  artifact_retention_policy_id

strict_enterprise: require_evidence_index_verification=True
airgapped_high_assurance: require_evidence_index_verification=True

31 tests across 12 acceptance criteria.

## [2.8.2] — 2026-06-18

### Attestation Issuer Key Binding

Cryptographically binds the issuer fingerprint to the verification key.

The invariant now enforced:
  attestation.issuer_fingerprint
  = fingerprint(verification_public_key)
  = profile-authorized issuer fingerprint

New function: derive_fingerprint(public_key_pem) — SHA-256(DER SubjectPublicKeyInfo)[:32]
New class: AttestationIssuerResolver — maps issuer fingerprints to public key PEMs

Updated verify_attestation():
  - Accepts optional issuer_resolver parameter
  - When a public key is used for verification, derives its fingerprint
  - Compares derived fingerprint to attestation.issuer_fingerprint
  - Fingerprint mismatch fails closed before signature check

Updated AttestationVerifyResult:
  - issuer_key_fingerprint_match (bool)
  - derived_fingerprint (str)

The distinction now enforced:
  signature from arbitrary key ≠ signature from the claimed issuer's key

24 tests across 10 acceptance criteria.

## [2.8.1] — 2026-06-18

### Supply Chain Attestation Adversarial Test Suite

47 adversarial tests across 20 acceptance criteria.

Code fix: Same empty-allowlist pattern as discovery v2.7.3 — when
`require_attestation_signature=True`, an empty `trusted_attestation_issuers`
list now fails closed instead of silently allowing any issuer.

New profile field: `allow_any_attestation_issuer` (default False).
Explicit opt-in for issuer-wide trust. When True, the allowlist check is
skipped but signature verification still runs.

The distinction now enforced:
  cryptographically valid issuer ≠ issuer authorized by this organization

## [2.8.0] — 2026-06-18

### Supply Chain Attestations

Attestation is evidence.
Attestation is not automatic trust.

NON-NEGOTIABLE RULES:
  A valid attestation must NEVER:
    - Automatically upgrade a package's trust level
    - Bypass certification requirements
    - Bypass sandbox requirements
    - Override a federation conflict

New module: src/nodechain/sdk/supply_chain_attestation.py
  - SupplyChainAttestation: binds artifact digest to package identity,
    build/provenance subject, and issuer identity
  - AttestationVerifyResult: multi-check verification result
  - AttestationReceipt: evidence receipt with policy-profile digest binding
  - AttestationStore: file-backed persistence with artifact/package lookup
  - verify_attestation(): digest + signature + issuer + artifact + expiry
  - check_attestation_policy(): org profile gate (level, issuer, signature)
  - create_attestation(): factory with optional RSA-PSS-SHA256 signing
  - SLSA-like levels: none < source < build < provenance

New CLI: nodechain supply-chain
  - create, verify, list, inspect

New transparency events: attestation_seen, attestation_verified,
  attestation_rejected
New evidence types: supply_chain_attestation, attestation_receipt
New health rule: HR-019 (attestation_issues)

New org profile fields: require_supply_chain_attestations,
  minimum_attestation_level, trusted_attestation_issuers,
  require_attestation_signature

strict_enterprise: minimum_attestation_level=build, require_signature
airgapped_high_assurance: minimum_attestation_level=provenance

49 tests across 17 acceptance criteria.

## [2.7.3] — 2026-06-18

### Discovery Signer Allowlist Fail-Closed

Fixes the ambiguity in v2.7.2 where an empty `trusted_discovery_signers`
list silently allowed any resolver-known signer when
`require_discovery_signature_verification=True`.

Now when `require_discovery_signature_verification=True`:
  - `trusted_discovery_signers` must be non-empty (unless explicitly overridden)
  - The index signer fingerprint must appear in that list
  - The resolver must provide the mapped public key
  - RSA-PSS-SHA256 verification must succeed
  - Otherwise deny

New profile field: `allow_any_resolver_discovery_signer` (default False)
  Explicit opt-in for resolver-wide trust. When True, the allowlist
  check is skipped but crypto verification still runs.

The distinction now enforced:
  cryptographically valid signer ≠ signer authorized by this organization

23 tests across 8 acceptance criteria.

## [2.7.2] — 2026-06-18

### Discovery Signature Policy Binding

Binds cryptographic signature verification into strict policy enforcement.

`require_signed_discovery_index` now has two enforcement tiers:
  1. `require_signed_discovery_index=True` — signature fields must be present
  2. `require_discovery_signature_verification=True` — signature must
     cryptographically verify via RSA-PSS-SHA256 against a resolved public key

New profile fields:
  - trusted_discovery_signers: fingerprints authorized to sign discovery indexes
  - require_discovery_signature_verification: bool, enforces crypto verification

New class: DiscoverySignerResolver
  Maps signer fingerprints to public key PEMs.
  Strict profiles require this to be provided.

Updated check_discovery_policy():
  - Accepts optional signer_resolver parameter
  - When require_discovery_signature_verification=True:
    * Signer must be in trusted_discovery_signers
    * Resolver must provide the public key
    * Signature must cryptographically verify
  - When only require_signed_discovery_index=True:
    * Field presence is sufficient (backward compatible)

Updated DiscoveryIndexReceipt:
  - signature_present (bool)
  - signature_verified (bool, was already present)
  - verifier_key_digest (str, SHA-256 of verifying public key)

strict_enterprise and airgapped_high_assurance now set
require_discovery_signature_verification=True.

28 tests across 10 acceptance criteria.

## [2.7.1] — 2026-06-18

### Discovery Adversarial Test Suite

34 adversarial tests across 20 acceptance criteria.

Code enhancement: Added verify_discovery_signature() for cryptographic
RSA-PSS-SHA256 verification of discovery index signatures. The previous
field-present check is now supplemented with full crypto verification
when a public key is provided.

## [2.7.0] — 2026-06-18

### Public Discovery and Marketplace Integration

Discovery adds reachability. Discovery does not add trust.

NON-NEGOTIABLE RULES:
  Marketplace listing is not certification.
  Discovery index signature is not package trust.
  Registry reachability is not registry eligibility.
  Popularity is not reputation.
  Reputation is not trust.

New module: src/nodechain/sdk/discovery.py
  - PublicDiscoveryIndex, MarketplaceRegistryListing
  - DiscoveryIndexReceipt, MarketplaceRegistryAddReceipt
  - fetch_discovery_index() with size/format/digest verification
  - check_discovery_policy() — org profile controls discovery
  - check_registry_add_policy() — marketplace add is opt-in
  - add_registry_from_discovery() — adds as disabled FederatedRegistryConfig
  - search_discovery_index() — query/category/package search
  - verify_discovery_index() — integrity check
  - DiscoveryStore with file persistence

New CLI: nodechain marketplace
  - discover, search, inspect, add-registry, verify

New transparency events: discovery_index_seen, registry_discovered,
  registry_added_from_discovery
New evidence types: discovery_index_receipt,
  marketplace_registry_add_receipt
New health rule: HR-018 (discovery_issues)

New org profile fields: allow_public_discovery,
  allowed_discovery_sources, require_signed_discovery_index,
  maximum_discovery_index_age, allow_marketplace_registry_add

Discovery never writes active federation config automatically.
Discovered registries are disabled by default.

49 tests covering all 12 ACs.

## [2.6.2] — 2026-06-18

### Reputation Profile Persistence and Digest Binding

Fixes OrganizationTrustPolicyProfile serialization gap.

OrganizationTrustPolicyProfile.to_dict() and from_dict() now include
use_registry_reputation and minimum_registry_grade. compute_digest()
now binds reputation controls. Profile receipts and active-profile
digest drift detection (HR-015) cover reputation policy fields.

18 tests across 8 acceptance criteria.

## [2.6.1] — 2026-06-17

### Reputation Adversarial Test Suite

32 adversarial tests across 20 acceptance criteria.

Two code-level findings hardened:

REP-FINDING-001: Added score_digest to RegistryHealthScore.
  score_digest covers registry_id, score, grade, last_checked, components,
  evidence_digest, transparency_log_digest. verify_health_score() now
  recomputes score_digest and fails on mismatch. The old no-op comparison
  `score.evidence_digest != score.evidence_digest` is eliminated.

REP-FINDING-002: filter_by_reputation() is now opt-in via org profile.
  Added use_registry_reputation (bool, default False) and
  minimum_registry_grade (str, default "C") to OrganizationTrustPolicyProfile.
  filter_by_reputation() returns all candidates unchanged unless the active
  org profile has use_registry_reputation=True. strict_enterprise enables
  reputation filtering (min C); airgapped_high_assurance enables (min B).

## [2.6.0] — 2026-06-17

### Registry Reputation and Health Scoring

Local scoring signal for remote registries. Reputation informs selection
but does not create trust.

NON-NEGOTIABLE RULE:
    Reputation informs selection.
    Reputation does not create trust.

Resolver order remains:
    hard verification gates
    → organization policy
    → conflict detection
    → reputation as optional ranking/filter
    → deterministic selection

New module: src/nodechain/sdk/reputation.py
  - RegistryHealthScore model (registry_id, score, grade, last_checked,
    components, evidence_digest, transparency_log_digest)
  - 8 score components: availability, metadata_freshness,
    signature_validity, transparency_consistency, conflict_history,
    revocation_responsiveness, install_success_rate, policy_compliance
    (latency optional)
  - Every component explainable: value, weight, reason, evidence_reference
  - ScoringInputs with compute_digest() for tamper detection
  - score_registry() produces explainable RegistryHealthScore
  - should_deny_by_reputation() — F always denies, D denies under strict
  - filter_by_reputation() — subordinate to hard gates
  - verify_health_score() — integrity check
  - ReputationStore with file persistence
  - generate_reputation_report() — aggregate summary

New CLI: nodechain registry reputation
  - score, show, verify, refresh

New transparency event: reputation_score_computed
New evidence types: registry_health_score_receipt,
  registry_reputation_report
New health rule: HR-017 (registry_reputation)

51 tests covering all 10 ACs.

## [2.5.1] — 2026-06-17

### Multi-Registry Federation Adversarial Test Suite

37 adversarial tests across 20 acceptance criteria.

Code fix: Separated certification from signing in federation resolver.
metadata_signed ≠ certified. FederationCandidate now has separate
`certified` field. Strict enterprise correctly rejects signed-but-uncertified.

Added FederationConfigError for safe corrupt-config handling.
Added compute_digest() to FederationConfigStore.

## [2.5.0] — 2026-06-17

### Multi-Registry Federation

Allows resolution of packages across multiple remote registries while
maintaining the non-negotiable rule:

    A registry is not trusted because it is reachable.
    A registry is eligible only if the active organization profile allows it.

New module: src/nodechain/sdk/federation.py
  - FederatedRegistryConfig (registry_id, base_url, trust_level,
    allowed_publishers, allowed_packages, priority, enabled,
    required_signer_fingerprint)
  - FederationConfigStore (add, remove, get, enabled_registries)
  - FederationCandidate and FederationResolveResult
  - resolve_federated_package() with 5-phase selection pipeline:
    discover → verify config → apply policy → detect conflicts → select winner
  - verify_federation() configuration integrity check

New CLI: nodechain registry federation
  - list, add, remove, verify, resolve

New transparency events: registry_selected, registry_conflict,
  federated_package_resolved
New evidence type: federated_resolution_receipt
New health rule: HR-016 (federation_issues)

43 tests covering all 10 ACs.

## [2.4.1] — 2026-06-17

### Organization Trust Policy Adversarial Test Suite

61 adversarial tests across 18 acceptance criteria:
  AC1:  Profile tampering (5 parametrized + 2)
  AC2:  Receipt tampering (3)
  AC3:  Policy downgrade requires receipt (2)
  AC4:  Stale profile detection (2)
  AC5:  Direct-call bypass prevention (4)
  AC6:  Key-purpose confusion (3)
  AC7:  Remote install denial even with valid signatures (3)
  AC8:  Certification denial (3)
  AC9:  Transparency denial (2)
  AC10: Dependency denial (2)
  AC11: Lockfile requirement (4)
  AC12: Sandbox downgrade (5)
  AC13: Deployment denial (2)
  AC14: Eval-suite spoofing (4)
  AC15: Profile diff correctness (3)
  AC16: Dashboard HR-015 (5)
  AC17: Concurrent profile apply (2)
  AC18: Runtime path integration (5)

Added check_lockfile() and check_key_purposes() enforcement methods.

## [2.4.0] — 2026-06-17

### Organization Trust Policy Profiles

Named, enforceable trust policies that consolidate scattered governance
flags into a single declarative profile.

NON-NEGOTIABLE RULE: profile declared ≠ profile enforced.
The profile must become an input to enforcement decisions.

New module: src/nodechain/sdk/org_policy.py
  - OrganizationTrustPolicyProfile model with 12 enforcement surfaces
  - 4 built-in profiles:
      permissive_local: Maximum flexibility for local development
      standard_team: Balanced with signing + transparency requirements
      strict_enterprise: Signed + certified + production sandbox
      airgapped_high_assurance: No remote, no deployment, hardened sandbox
  - PolicyProfileReceipt with digest binding
  - apply_profile() / get_active_profile() / get_active_profile_receipt()
  - diff_profiles() for field-by-field comparison
  - validate_profile() for consistency checks
  - Per-field enforcement check methods

New CLI: nodechain policy profiles
  - list: Show built-in and active profiles
  - show <name>: Display profile details
  - validate <name>: Check profile consistency
  - apply <name>: Activate as organization policy
  - diff <a> <b>: Compare two profiles

New evidence type: policy_profile_receipt
New health rule: HR-015 (policy_drift)

## [2.3.1] — 2026-06-17

### Transparency Log Adversarial Test Suite

47 adversarial tests across 15 acceptance criteria covering:
  - Field tampering (5 parametrized)
  - Entry deletion (4)
  - Forged insertion (3)
  - Duplicate sequence (2)
  - Sequence gaps (2)
  - Wrong previous_entry_digest (2)
  - Wrong entry_digest (2)
  - Invalid event types (5 parametrized)
  - Corrupt JSON (5 — garbage, truncated, wrong type, CLI, empty)
  - Empty log health (3)
  - Cross-state mismatch detection (3 — AC11/12/13)
  - Concurrent append safety (3)
  - Chain recomputation (3)
  - Cross-layer integrity (3)

Enhanced HR-014 health rule to detect:
  - Remote installs without transparency entries
  - Dependency resolutions without transparency entries
  - Revoked packages without revocation entries

Added TransparencyLogError for safe corrupt-JSON handling.

Windows: 3306 passed, 57 skipped

## [2.3.0] — 2026-06-17

### Remote Registry Transparency Log

Append-only, tamper-evident log of remote registry interactions.
Chained SHA-256 digests make any modification to historical entries
instantly detectable.

NON-NEGOTIABLE RULE: Logged does not mean trusted.
Trust still comes from signatures, digests, certification, and policy.
The log adds historical accountability, replay evidence, tamper detection,
and registry behavior auditability.

New module: src/nodechain/sdk/transparency_log.py
  - TransparencyLogEntry with chained digests
  - TransparencyLog (append-only)
  - TransparencyLogVerifyResult
  - 7 event types (registry_metadata_seen, package_metadata_seen, etc.)
  - File-based persistence with atomic writes
  - append_event() convenience
  - verify_transparency_log()

New CLI: nodechain registry transparency
  - verify: Check chain integrity
  - show: Query entries (by package, digest, event type, last N)
  - append: Manual event logging

New evidence types: transparency_log, transparency_entry
New health rule: HR-014 (transparency_log_broken)

## [2.2.1] — 2026-06-17

### Dependency Confusion / Graph Attack Test Suite

Hardens the dependency resolver with two code-level fixes plus
comprehensive adversarial tests.

Code fixes:
- **DEP-FINDING-001**: Cycles now fail closed in strict mode (default).
  `DependencyCycleError` raised. Non-strict mode (strict=False) produces
  warnings for diagnostic use.
- **DEP-FINDING-002**: Sandbox downgrade check is now graph-wide.
  Compares every child against `max(parent_floor, remote_untrusted_floor)`
  instead of only root→child edges. Transitive dependencies can no longer
  introduce weaker sandbox profiles.

29 adversarial tests covering all 14 acceptance criteria:
  AC1: Cycle strict (4 tests)
  AC2: Diamond resolution (2 tests)
  AC3: Version conflict (1 test)
  AC4: Dependency substitution (1 test)
  AC5: Publisher mismatch (1 test)
  AC6: Capability escalation (1 test)
  AC7: Sandbox downgrade graph-wide (3 tests)
  AC8: Revoked dependency (1 test)
  AC9: Expired certification (1 test)
  AC10: Lockfile tampering (2 tests)
  AC11: Deterministic digest (2 tests)
  AC12: Optional vs required (3 tests)
  AC13: Lockfile re-resolution (3 tests)
  + Dependency confusion attacks (4 tests)

Windows: 3223 passed, 57 skipped

## [2.2.0] — 2026-06-17

### Remote Dependency Resolution and Transitive Trust

Resolves remote package dependencies with strict independent verification.
Every dependency must independently pass the full verification pipeline.

New module: `src/nodechain/sdk/dependency_resolver.py`
- **RemoteDependencySpec**: Single dependency requirement with bounds
- **DependencyGraphNode**: Resolved node in the graph
- **RemoteDependencyGraph**: Resolved graph with deterministic digest
- **RemoteDependencyLockfile**: Locked graph for reproducible installs
- **DependencyResolutionReceipt**: Evidence with per-package receipts
- **resolve_dependencies()**: Recursive resolver with cycle/conflict detection
- **verify_dependency_graph()**: Per-node verification
- **verify_dependency_bounds()**: Publisher, capability, sandbox bounds
- **resolve_and_verify()**: Full pipeline (resolve → verify → lockfile → receipt)

New CLI command:
- `nodechain registry resolve-deps --package-id <id> --version <ver> --remote <url>`

Transitive trust rule (non-negotiable):
- Root package trust does NOT transfer to dependencies
- Every dependency must independently verify
- Every dependency remains separately revocable
- No dependency execution during install

New evidence type: `dependency_resolution_receipt`

44 tests covering all 10 acceptance criteria + 12 negative scenarios.

Windows: 3194 passed, 57 skipped

## [2.1.0] — 2026-06-17

### Remote Registry Server Reference Implementation

Minimal signed HTTP server that serves protocol v1 endpoints.

New module: `src/nodechain/sdk/remote_registry_server.py`
- **ThreadedHTTPServer** with stdlib http.server (no external deps)
- **Registry builder**: scans package directories, creates signed metadata
- **Package metadata builder**: creates signed metadata from artifacts
- **Strict mode**: rejects unsigned metadata (default: strict)
- **Path safety**: rejects traversal, absolute paths, unknown endpoints

New CLI commands:
- `nodechain registry serve --root <dir> --host <addr> --port <port>`
- `nodechain registry remote-build --root <dir> --sign <key>`

Key design: The server serves signed metadata and artifacts. The client
verifies everything. The server is not trusted merely because it served
the bytes.

39 tests covering all 11 acceptance criteria:
- Protocol v1 endpoints (well-known, package metadata, artifact)
- Read-only server (rejects POST)
- Refuses: traversal, unknown packages, unknown versions, strict unsigned
- Registry and package metadata signing with RSA-PSS-SHA256
- End-to-end: build → serve → install → verify → receipt → evidence
- Negative: 404, 500, malformed JSON, path traversal, content types
- Concurrent requests

Windows: 3150 passed, 57 skipped

## [2.0.1] — 2026-06-17

### Remote Registry Adversarial Test Suite

Comprehensive attack surface testing using reusable adversarial fixtures.

New files:
- `tests/adversarial_fixtures.py` — Reusable malicious fixture library
- `tests/test_adversarial_remote.py` — 46 adversarial tests

Attack categories tested:
- **R1 Registry attacks** (6): Tampered metadata, protocol downgrade, stale metadata, wrong fingerprint, server errors, invalid JSON
- **P1 Package attacks** (6): Substitution, version rollback, missing certification, forged capabilities, size lies, cross-package confusion
- **A1 Archive attacks** (12): Path traversal (Unix/Windows/backslash), absolute paths, symlink escape, executable hooks, deeply nested paths, zip bombs, too many files, hidden scripts, hardlink escape, extraction escape
- **N1 Network attacks** (4): Timeout, partial download, corrupted response, TLS rejection
- **T1 Trust boundary attacks** (4): Sandbox downgrade, capability escalation, trust upgrade, certification bypass
- **I1 Integration attacks** (6): End-to-end install with adversarial inputs
- **Edge cases** (6): Empty artifact, huge ID, unicode, special chars, concurrent fetches, retry exhaustion

Windows: 3111 passed, 57 skipped

## [2.0.0] — 2026-06-17

### Remote Registry Foundation

**Major version bump** — transitions NodeChain from local-only trust to
network package distribution.

New module: `src/nodechain/sdk/remote_registry.py`
- **Protocol v1** with three endpoints:
  - `/.well-known/nodechain-registry.json` (registry discovery)
  - `/packages/{id}/versions/{ver}.json` (package metadata)
  - `/packages/{id}/versions/{ver}/artifact` (package download)
- **RemoteRegistryClient**: HTTP client with timeout, retry, size limits, TLS enforcement
- **RemoteRegistryMetadata**: Frozen registry discovery document with digest verification
- **RemotePackageMetadata**: Frozen package metadata with digest verification
- **RemoteInstallReceipt**: Immutable install record with full verification trail
- **Verification pipeline**: 8-point check (digests, protocol, size, archive safety, keys)
- **Safe extraction**: Reuses v1.22.1 archive safety (path traversal, symlinks, size)
- **Local registry bridge**: Remote packages get `origin=remote`, `trust_level=remote_untrusted`
- **Evidence integration**: Install receipts indexed in evidence chain
- **Trust store extension**: `remote_registry_signing`, `remote_package_publishing` purposes
- **New CLI command**: `nodechain registry install-remote <id> --version <ver> --remote <url>`

Security rules (non-negotiable):
- Remote install never implies execution permission
- Publisher signature never implies package safety
- Registry signature never implies publisher trust
- remote_untrusted never upgrades automatically

## [1.22.1] — 2026-06-17

### Remote Registry Readiness

Hardens the local platform before the v2.0.0 major-version jump to
remote registry. Freezes schemas, adds archive safety validation,
makes trust-level mapping explicit, and documents the remote registry
threat model.

New module: `src/nodechain/sdk/remote_readiness.py`
- Frozen package manifest schema v1.0.0 (7 required fields)
- Frozen registry entry schema v1.0.0 (7 required fields)
- Explicit trust-level mapping: built_in → local_trusted → local_untrusted → remote_untrusted
- Trust-to-sandbox mapping: remote_untrusted → hardened_untrusted (Linux) / production_untrusted (other)
- Trust level upgrade prevention (no automatic privilege escalation)
- Archive safety: path traversal blocked, absolute paths blocked, symlink escape blocked
- Archive limits: max 500 files, max 50MB, path length max 255
- safe_extract() with per-member path validation
- 10 documented remote registry threats with mitigations
- `get_remote_registry_readiness()` assessment function

New health rule: HR-013 (remote_registry_unready)
Warns when platform has issues that would compromise remote registry trust.

36 tests covering all 9 acceptance criteria.

Windows: 3015 passed, 57 skipped

## [1.22.0] — 2026-06-17

### Multi-Chain Orchestrator

Chain-of-chains composition: a meta-orchestrator that invokes multiple
sub-chains, manages dependencies between them, and aggregates results.

New module: `src/nodechain/runtime/chain_orchestrator.py`
- `CompositionPlan`: YAML-loadable plan with sub-chains and dependencies
- `SubChainSpec`: per-chain config (inputs, depends_on, failure_mode)
- `orchestrate_composition()`: executes chains in topological order
- `SubChainStep`: composable node that invokes a composition plan
- Topological sort with cycle detection
- 4 aggregation strategies: merge_all, last_only, collect_list, scored_best
- 3 failure modes: propagate, skip, default
- SHA-256 plan digest for trace lineage

New CLI: `nodechain compose`
- `--plan <path>`: execute a composition plan
- `compose validate --plan <path>`: validate without executing
- `--json` output

New blueprint: `blueprints/composition_cross_domain_v1.yaml`
- Composes incident response + security audit (4 sub-chains)

CLI surface: 23 top-level commands (additive `compose` group)

Windows: 2979 passed, 57 skipped

## [1.21.0] — 2026-06-17

### Security Audit Reference Chain

New 7-node security audit pipeline that assesses platform posture across
trust, registry, evidence, sandbox, and deployment domains.

New package: `nodes/security_audit/`
- AssetInventoryCollector: collects all platform assets
- TrustPostureAuditor: audits trust store (unsigned snapshots, legacy keys)
- RegistryPostureAuditor: audits registry (revoked, denied, uncertified)
- EvidenceChainAuditor: audits evidence chains (broken, empty, replay)
- SandboxPolicyAuditor: audits sandbox (seccomp, import hooks, presets)
- DeploymentRiskAuditor: audits operations (drift, failed remediations)
- AuditReportWriter: aggregates findings, computes score and grade

Blueprint: `blueprints/security_audit_v1.yaml`
Eval suite: `eval_suites/security_audit_eval.yaml` (7 cases)
Tests: 26 tests covering all nodes, e2e chain, evidence refs, grading

Audit report features:
- Per-domain scores (0-100)
- Overall grade (A/B/C/D/F)
- Severity-ranked findings (critical > degraded > warning)
- Evidence references on every finding
- SHA-256 report digest
- Recommendations for each finding

Health model fix: `critical` now correctly dominates `unknown` in
`HEALTH_ORDER` (review note from v1.20.1)

Windows: 2947 passed, 57 skipped

## [1.20.1] — 2026-06-17

### Dashboard Health Rules and JSON API Stability

Formalizes health detection into a structured rule engine with stable
JSON API for programmatic consumption.

New module: `src/nodechain/cli/dashboard_health.py`
- 12 health rules (HR-001 through HR-012) with IDs, severities,
  descriptions, and recommendations
- Versioned JSON API (`api_version: 1.0.0`)
- Rule summary with triggered/untriggered status per rule
- `compute_health_from_issues()` computes overall health from triggered rules

New CLI subcommand: `nodechain dashboard rules`
- Lists all 12 rules with triggered status
- `--json` output with structured rule summary

Updated: `nodechain dashboard health` now uses the rule engine
- JSON output includes `api_version`, `rule_summary`, `issue_count`

Rules implemented:
  HR-001: Unsigned trust store snapshot (warning)
  HR-002: Legacy trust keys without purpose (warning)
  HR-003: Revoked registry entries present (warning)
  HR-004: Denied registry entries present (degraded)
  HR-005: Expired certifications (degraded)
  HR-006: Denied certifications (degraded)
  HR-007: Failed evaluation reports (warning)
  HR-008: Broken evidence chains (warning)
  HR-009: Unresolved drift without remediation (warning)
  HR-010: Failed remediation receipts (degraded)
  HR-011: Paused human reviews (warning)
  HR-012: Failed trace replays (warning)

35 tests covering rule evaluation, JSON API stability, and detection scenarios.

Windows: 2921 passed, 57 skipped

## [1.20.0] — 2026-06-17

### Operator Dashboard

Unified read-only operational view across all six platform spines.

New CLI command: `nodechain dashboard` with subcommands:
- `dashboard` (default overview)
- `dashboard runs` — runtime status
- `dashboard trust` — trust store status
- `dashboard registry` — certified registry status
- `dashboard evidence` — evidence index status
- `dashboard deployments` — release history
- `dashboard drift` — drift detection
- `dashboard evaluations` — evaluation/certification
- `dashboard health` — overall health and issues

Features:
- `--json` output for every view
- `--watch` flag for live terminal refresh
- Health model: healthy / warning / degraded / critical / unknown
- Detects: unsigned trust snapshots, revoked registry entries,
  expired certifications, failed evaluations, broken evidence chains,
  unresolved drift, failed remediations, paused human reviews
- Read-only by default — never mutates state

52 tests covering all 10 acceptance criteria.

CLI surface: 22 top-level commands (additive `dashboard` group)

Windows: 2886 passed, 57 skipped

## [1.19.1] — 2026-06-17

### Certified Incident Chain Assurance

Proves the incident-response chain is not just composed, but
**certified-registry-composed end to end**.

The chain now flows through the full certified ecosystem:

    package → registry entry → certification → eval report → suite → trace

New evaluation suite: `eval_suites/incident_response_eval.yaml`
- 5 structural cases verifying contract validity for all 5 nodes
- 5 metrics: correctness, contract_validity, governance_enforcement,
  evidence_chain_integrity, recovery_verification

New tests: `tests/test_incident_chain_assurance.py` (23 tests)
- AC1: Registry resolution with certified_only policy (3 tests)
- AC2: Trace field propagation — 5 registry evidence fields (2 tests)
- AC3: Evaluation suite loads, validates, and passes (3 tests)
- AC4: Signed local certification creation and verification (3 tests)
- AC5: Evidence chain reconstruction — all links connected (2 tests)
- AC6: Critical incident path — governance enforcement (4 tests)
- AC7: CLI smoke — all command help surfaces (6 tests)

Platform change: Added `package` to valid TARGET_TYPES in EvaluationSuite
(additive, does not affect existing types).

Windows: 2834 passed, 57 skipped

## [1.19.0] — 2026-06-17

### Incident Response Reference Chain

New multi-node package demonstrating the full certified ecosystem:
detect → triage → decide → remediate → verify.

New package: `nodes/incident_response/`
- 5 nodes: IncidentDetector, SeverityTriager, RemediationDecisioner,
  GovernedRemediator, RecoveryVerifier
- Each node has contracts, manifests, and capability declarations
- Blueprint: `blueprints/incident_response_v1.yaml`
- 25 tests covering individual nodes, end-to-end execution, evidence
  chain propagation, and governance gate enforcement

The chain exercises:
- Configuration drift as an incident trigger
- Severity-based remediation mode selection (manual/recommend/auto_rollback)
- Authorization gates preventing unauthorized execution
- Evidence chain with policy digest propagation
- Recovery verification closing the incident loop
- Critical incidents requiring human review (governance gate)

This is the first reference chain designed for certified registry
publishing — each node is independently testable and certifiable.

Windows: 2811 passed, 57 skipped

## [1.18.5] — 2026-06-17

### Enforcement Internals Review

Focused review of 5 security-critical enforcement paths. One real bypass
vector found and fixed.

Security findings:

- FINDING-002 (FIXED): `importlib.import_module()` bypassed the import
  enforcer because it calls `_bootstrap._gcd_import()` directly, not
  `builtins.__import__`. A sandboxed node could import denied modules
  via `importlib.import_module('subprocess')`. Fixed by patching
  `importlib.import_module` separately with its own enforcement wrapper.
  4 new tests verify the fix.

- FINDING-003 (DOCUMENTED): Digest comparisons use `==` instead of
  `hmac.compare_digest()`. This is acceptable for a local trust platform
  (no network-exposed comparison oracle), but documented as a known
  limitation. Defense-in-depth improvement for future.

Review areas passed without findings:
- Trust store signature verification: RSA-PSS-SHA256, canonical JSON,
  proper field stripping, purpose enforcement
- Registry consumption gate: 7-point check, revoked always rejected,
  certified_only properly enforced
- Deployment adapter: shlex.quote in shell mode, argv mode with shell=False
- Drift remediation: proper mode hierarchy, auto-downgrade without manifest

Windows: 2781 passed, 57 skipped
Linux:   2822 passed, 16 skipped, 0 failed

## [1.18.4] — 2026-06-17

### External Code Review Findings

Bug fixes from external code review:

- DOC-FINDING-001 (FIXED): README CLI command matrix was stale, listing only
  6 early commands instead of the full surface. Rewritten with all 21
  top-level commands and 57 total commands organized by platform spine.

- CLI-BUG-001 (FIXED): `evidence` and `trace-replay` command groups were
  defined with `@click.group()` but never registered on the `cli` object.
  They were unreachable from the command line. Fixed by using `@cli.group()`
  instead of `@click.group()`.

- BLOCKER-001 (RESOLVED in v1.18.3): Version mismatch — tag v1.18.3 was
  created but code reported version 1.18.2. Now all version surfaces report
  1.18.4 consistently.

Frozen surface tests updated to include `evidence` and `trace-replay`
commands in the expected command set.

Windows: 2777 passed, 57 skipped

## [1.18.3] — 2026-06-17

### External Code Review Hardening

Verification milestone — hardens the codebase for external review and publishes
a clean private repository. No new runtime features.

Secret scan and sanitization:
- gitleaks scan: 0 real secrets (3 test-fixture false positives allowlisted)
- All infrastructure identifiers sanitized to RFC 5737 documentation range
- Clean git history (single commit, no historical secret exposure)
- `.gitleaksignore` for test-fixture false positives

Security review findings:
- FINDING-001 (FIXED): Shell mode deployment adapter did not `shlex.quote()`
  interpolated values before template substitution. Now all values are
  shell-escaped.
- No eval/exec/pickle/marshal in code paths
- `shell=True` only in governed deployment adapter path
- `os.system` patched by subprocess enforcer

Repository publication:
- GitHub repository: https://github.com/Alajmah/NodeChain
- Clean single-commit history (no binary artifacts in history)
- 347 tracked files, 0 secrets, 0 __pycache__, 0 data artifacts
- 6 GitHub issues created for security review tracking (#1–#6)

CI infrastructure:
- `.github/workflows/ci.yml` with 5 jobs:
  - windows-tests, linux-unit-tests, linux-privileged-tests
  - cli-smoke, package-build
- Capability-aware test matrix split
- Proxmox tests mocked by default

Verification:
- `pip install -e .` succeeds
- `nodechain --version` works
- `python -m build --wheel` succeeds
- Windows: 2777 passed, 57 skipped
- Linux: 2818 passed, 16 skipped

## [1.18.2] — 2026-06-17

### Public Repository Readiness and Code Review

Verification milestone — prepares the codebase for private GitHub repository
publication. No new features. Focus on secret scrubbing, documentation,
CI, and security posture.

Changes:
- Added comprehensive `.gitignore` (Python, secrets, data, pycache)
- Removed all tracked `.pyc` files (281 files)
- Removed all tracked `data/` runtime files (80 files)
- Removed tracked `.env` file
- Sanitized `.env.example` with placeholder values
- Added `SECURITY.md` with supported versions, secret handling, trust boundary,
  sandbox limitations, and responsible disclosure
- Added `THREAT_MODEL.md` with threat actors, trust model assumptions,
  sandbox assumptions, registry trust assumptions, and deployment risks
- Added `LICENSE` (MIT)
- Added `data/.gitkeep` to preserve directory structure
- Added GitHub Actions CI workflow (`.github/workflows/ci.yml`) with:
  - Windows tests
  - Linux unit tests
  - Linux privileged tests (sandbox/cgroup/namespace)
  - CLI smoke tests
  - Package build verification
- CI test matrix is split by capability requirements
- Proxmox tests are mocked by default (no real credentials in CI)

## [1.18.1] — 2026-06-17

### Certified Registry Consumption

Makes the registry an execution gate. NodeChain refuses to install, load,
or execute registry packages unless their registry entry, certification
chain, package digest, lifecycle state, and capability policy are acceptable.

New CLI commands:
  nodechain registry install --package-id <id> [--version] [--certified-only]
  nodechain registry resolve --package-id <id> [--version] [--certified-only]

New classes:
  ConsumptionPolicy — configurable consumption gate
  ResolutionResult — structured resolution outcome with 7 checks

Consumption policy options:
  certified_only:          Require active certification
  trusted_publisher_only:  Require trust-store-verified publisher
  minimum_certification_level: Minimum certification strength
  allowed_capabilities:    Capability allowlist
  allowed_sandbox_profile: Sandbox profile constraint
  allowed_policy_preset:   Policy preset constraint
  require_active_only:     Reject deprecated entries

Resolution checks (7-point):
  1. Entry exists in registry
  2. Registry status acceptable
  3. Certification status = certified
  4. Package digest present
  5. Publisher trusted
  6. Capabilities allowed
  7. Sandbox profile matches

Trace evidence fields:
  registry_entry_digest, certification_digest, publisher_fingerprint,
  registry_resolution_status, registry_policy_verdict

Evidence chain:
  runtime trace → registry entry → certification → evaluation report → suite

New module: cli/registry_consumption.py

## [1.18.0] — 2026-06-17

### Certified Registry Publishing

Turns certified targets into reusable registry entries. A package that
has been signed, evaluated by a trusted active suite, and certified by
an authorized certifier can be published to the local registry for
discovery and reuse.

This is where NodeChain stops being only a runtime and becomes a platform
for teams.

New trust store purpose (11th):
  registry_publishing

New CLI commands:
  nodechain registry publish --package <pkg> --certification <cert.json>
  nodechain registry certified-list [--active-only]
  nodechain registry certified-inspect --entry-id <id>
  nodechain registry certified-verify --entry-id <id> [--pubkey] [--trust-store]
  nodechain registry deprecate --entry-id <id> [--reason]
  nodechain registry revoke --entry-id <id> [--reason]

Registry entry includes:
  entry_id, package_id, package_version, package_digest, manifest_digest,
  lockfile_digest, certification_digest, eval_report_digest, suite_digest,
  certification_status, publisher_fingerprint, published_at,
  registry_status (active|deprecated|revoked), entry_digest,
  registry_signature, capabilities, trust_level

Publish checks (5):
  1. Package manifest present
  2. Package digest computable
  3. Certification status = certified
  4. Certification signature valid (if required)
  5. Target digest matches package digest

Verify (7-point):
  1. Entry has signature
  2. entry_digest matches content
  3. Signature cryptographically valid
  4. Publisher in trust store
  5. Publisher has registry_publishing purpose
  6. Certification status is certified
  7. Registry status is active

Registry index has:
  registry_id, schema_version, entries_digest, updated_at, audit_log

Evidence index supports registry entries (12th evidence type).

New module: cli/certified_registry.py
New constant: REGISTRY_ENTRY_STATUSES
New env var: NODECHAIN_CERTIFIED_REGISTRY

## [1.17.0] — 2026-06-17

### Trace Replay and Evidence Query

Makes the entire evidence graph queryable, replayable, and explainable.
Operators can now index all NodeChain artifacts, query across them with
rich filters, reconstruct operational timelines, and replay traces with
consistency verification.

New trust store purpose (10th):
  evidence_report_signing

New CLI commands:
  nodechain evidence index --input <dir-or-file> --output evidence_index.json
  nodechain evidence query --index evidence_index.json --filter key=value
  nodechain evidence timeline --index evidence_index.json --target <ref>
  nodechain evidence sign --report report.json --key key.pem
  nodechain evidence verify --report report.json [--pubkey] [--trust-store]
  nodechain trace-replay run --trace trace.json [--strict]

Evidence types indexed (11):
  trace, audit_bundle, attestation, verifier_profile, gate_receipt,
  deployment_receipt, release_history_snapshot, drift_report,
  remediation_receipt, evaluation_report, certification

Query filters (12):
  run_id, target_digest, target_type, artifact_digest, policy_digest,
  suite_digest, certification_status, final_deployment_state,
  drift_detected, remediation_status, signer_fingerprint, artifact_type

Trace replay verifies (7 checks):
  1. Step order consistency
  2. Node invocation order
  3. Contract validity
  4. Port validity
  5. Policy verdicts
  6. State transitions
  7. Digest references

Evidence reports (index, timeline, replay) can be signed with RSA-PSS-SHA256.

New modules:
  cli/evidence.py — indexing, querying, timeline, signing
  cli/trace_replay.py — trace replay with 7-point verification

New constants:
  EVIDENCE_TYPES (11 types)
  QUERY_FILTERS (12 filters)
  TIMELINE_ORDER (phase ordering)

## [1.16.3] — 2026-06-17

### Evaluation Certification

Completes the evaluation governance arc: a target that passes a trusted
active evaluation suite under strict thresholds can receive a signed,
revocable certification artifact verified through the trust store.

This is the bridge between evaluation and ecosystem trust:
  package → sign → evaluate → certify → publish → reuse

New trust store purpose (9th):
  certification_signing

New CLI commands:
  nodechain eval certify --report eval_report.json
  nodechain eval certification sign --certification cert.json --key certifier.pem
  nodechain eval certification verify --certification cert.json [--pubkey] [--trust-store]
  nodechain eval certification revoke --certification cert.json [--reason]
  nodechain eval certification inspect --certification cert.json

Certification checks (create):
  1. Evaluation report passed=true
  2. Report signature valid (if required)
  3. Suite signature valid (if required)
  4. Suite validity window acceptable (if strict)
  5. Target digest present

Certification verify (8-point):
  1. Signature present
  2. certification_digest matches content
  3. Signature cryptographically valid
  4. Certifier in trust store
  5. Certifier has certification_signing purpose
  6. eval_report_digest present
  7. suite_digest present
  8. Status certified and within validity window

Certification artifact fields:
  certification_id, target_type, target_ref, target_digest,
  suite_id, suite_version, suite_digest, eval_report_digest,
  certifier_fingerprint, certification_status (certified|denied|revoked),
  valid_from, valid_until, issued_at, errors, certification_digest,
  certification_signature, certification_signature_algorithm

New module: cli/certification.py
New constant: CERTIFICATION_STATUSES = frozenset({certified, denied, revoked})

## [1.16.2] — 2026-06-16

### Evaluation Suite Lifecycle

Adds lifecycle management to evaluation suites, mirroring drift policy
lifecycle. Suites now have validity windows, status tracking, supersession,
and a local registry.

New lifecycle fields:
  valid_from — ISO timestamp when suite becomes active
  valid_until — ISO timestamp when suite expires
  supersedes_suite_digest — digest of the suite this one replaces
  suite_status — active | deprecated | revoked

New CLI commands:
  nodechain eval suite register --suite suite.yaml
  nodechain eval suite list [--active-only]
  nodechain eval suite revoke --digest <sha256> [--reason "..."]
  nodechain eval suite verify-registry --digest <sha256>

Strict/active-required mode rejects:
  - Expired suites (valid_until in the past)
  - Not-yet-valid suites (valid_from in the future)
  - Revoked suites
  - Deprecated suites
  - Unknown status

Evaluation report records:
  suite_validity_status (valid|invalid:<reason>|not_checked)
  suite_registry_digest

New module: cli/eval_suite_registry.py
New constant: SUITE_STATUSES = frozenset({active, deprecated, revoked})

## [1.16.1] — 2026-06-16

### Evaluation Suite Trust

Makes evaluation suites signed, trust-store-verified artifacts. A suite that
defines what "good" means is a policy-like authority and should be governed.

New trust store purpose (8th):
  evaluation_suite_signing

New CLI commands:
  nodechain eval suite sign --suite suite.yaml --key key.pem
  nodechain eval suite verify --suite signed.json [--pubkey pub.pem] [--trust-store ts.json]

New CLI flag:
  nodechain eval run --require-suite-signature --trust-store ts.json

Suite signature verification (5-point):
  1. Suite has signature field
  2. suite_digest matches content
  3. Signature is cryptographically valid
  4. Signer is in trust store
  5. Signer has evaluation_suite_signing purpose

Evaluation report records:
  suite_signature_status (valid|invalid|unsigned|signed_unverified)
  suite_signer_fingerprint
  suite_signer_trusted
  suite_trust_verified

New functions:
  sign_evaluation_suite()
  verify_evaluation_suite_signature()

## [1.16.0] — 2026-06-16

### Evaluation Runner

Introduces structured evaluation of nodes, chains, policies, adapters, traces,
and deployment/remediation outcomes. Turns NodeChain from a runtime platform
into something measurable, comparable, and certifiable.

New module:
  src/nodechain/cli/evaluation.py

New CLI commands:
  nodechain eval run --suite suite.yaml [--output report.json] [--strict]
  nodechain eval sign --report report.json --key key.pem
  nodechain eval verify --report signed.json [--pubkey pub.pem] [--trust-store ts.json]

New trust store purpose (7th):
  evaluation_report_signing

New classes:
  EvaluationCase — single evaluation case
  EvaluationSuite — collection of cases with metrics and thresholds
  CaseResult — result of running a case

Built-in metrics (9):
  correctness, schema_validity, contract_validity,
  invariant_compliance, policy_compliance, trace_completeness,
  cost, latency, deterministic_replay_match

Target types (7):
  node, chain, policy, adapter, trace, deployment, remediation

Evaluation report records:
  eval_id, suite_digest, target_digest, case_results, metric_results,
  passed, failed_cases, threshold_failures, started_at, finished_at,
  nodechain_version, report_digest

Strict mode fails on:
  suite malformed, target missing, required artifact missing,
  threshold failed, invariant failed

5 real evaluation suites:
  eval_suites/sandbox_hardening_eval.yaml
  eval_suites/trust_chain_eval.yaml
  eval_suites/proxmox_deployment_eval.yaml
  eval_suites/drift_remediation_eval.yaml
  eval_suites/reference_chain_eval.yaml

## [1.15.0] — 2026-06-16

### Drift Remediation

Completes the operational loop: deploy → verify → monitor drift → decide →
remediate → record. When drift is detected, NodeChain can now perform a
governed remediation decision under signed policy.

New module:
  src/nodechain/cli/drift_remediation.py

New CLI command:
  nodechain drift remediate --target pve1/801
    [--policy remediation_policy.json] [--drift-report report.json]
    [--release-history rh.json] [--release-history-snapshot snap.json]
    [--sign --key key.pem] [--output receipt.json] [--strict]

New classes:
  RemediationPolicy — governs remediation decisions

Remediation modes:
  manual      — operator decides, produce alert
  recommend   — produce remediation plan, do not mutate target
  auto_rollback — execute governed rollback to latest known-good

Remediation policy fields:
  remediation_mode, allowed_remediation_actions,
  require_signed_drift_policy, require_signed_drift_report,
  require_release_history_snapshot, require_latest_known_good,
  require_previous_assurance_chain, target

Remediation receipt records:
  remediation_id, drift_report_digest, remediation_policy_digest,
  remediation_mode, selected_action, selected_release_id,
  selected_artifact_digest, rollback_attempted, rollback_result,
  final_state, denial_reason, receipt_digest

Final states:
  no_remediation_needed, drift_detected, recommendation_produced,
  rolled_back, denied, failed, manual_intervention_required

Strict mode fails on:
  Unsigned drift report when required
  Drift policy invalid/revoked/expired
  Latest known-good unavailable
  Release-history snapshot invalid
  Previous assurance chain invalid
  Rollback not authorized by policy
  Rollback verification fails

Exit codes:
  0 = completed or no remediation needed
  10 = invalid/incomplete
  15 = drift detected but remediation denied/failed under strict policy

## [1.14.3] — 2026-06-16

### Drift Policy Lifecycle

Adds lifecycle management to drift policies — validity windows, status
management, and a local policy registry for tracking active/revoked policies.

New policy fields:
  policy_id, policy_version, valid_from, valid_until,
  supersedes_policy_digest, policy_status (active|deprecated|revoked)

Lifecycle validation:
  DriftPolicy.check_validity() — checks time window and status
  Strict mode rejects expired, revoked, deprecated, not-yet-valid policies

Local policy registry:
  data/drift_policy_registry.json
  nodechain drift policy register --policy policy.json
  nodechain drift policy list
  nodechain drift policy revoke --policy-id ID
  nodechain drift policy verify-registry --policy-id ID [--policy-digest DIGEST]

Registry features:
  Atomic writes with entries_digest
  Registration tracking with timestamp
  Revocation (status → revoked)
  Digest-based verification

Drift report records:
  policy_id, policy_version, policy_status,
  policy_validity_status, policy_validity_detail

Backward compatibility:
  Unsigned/default policy allowed outside strict mode
  Policies without lifecycle fields default to active/unlimited

New module:
  src/nodechain/cli/drift_policy_registry.py

New env var:
  NODECHAIN_DRIFT_POLICY_REGISTRY (default: data/drift_policy_registry.json)

## [1.14.2] — 2026-06-16

### Drift Policy Trust

Makes drift policies trusted artifacts. A policy that decides drift/no-drift
outcomes should be signed and verified against the trust store.

New trust store purpose:
  drift_policy_signing (6th purpose)

New CLI commands:
  nodechain drift policy sign --policy policy.json --key key.pem
  nodechain drift policy verify --policy signed_policy.json [--pubkey pub.pem] [--trust-store ts.json]

New CLI flag:
  nodechain drift check --policy signed_policy.json --require-policy-signature --trust-store ts.json

Policy signature verification checks:
  1. Policy has signature field
  2. policy_digest matches content
  3. Signature is cryptographically valid
  4. Signer is in trust store (if trust_store given)
  5. Signer has drift_policy_signing purpose

Strict mode fails if:
  Policy unsigned when signature required
  Signer not trusted
  Signer lacks drift_policy_signing purpose
  Policy signature invalid
  Policy digest mismatch

Drift report records:
  policy_signature_status (valid|invalid|unsigned|signed_unverified)
  policy_signer_fingerprint
  policy_signer_trusted

Default unsigned policy remains allowed in non-strict compatibility mode.

New functions:
  sign_drift_policy()
  verify_drift_policy_signature()

## [1.14.1] — 2026-06-16

### Drift Policy and Evidence Strength

Enhances drift detection with policy-aware, evidence-strength-aware
per-field evaluation. Not all evidence is equally strong — this version
makes that explicit.

New class:
  DriftPolicy — loads from JSON, governs field evaluation

New constants:
  EVIDENCE_STRENGTH_LEVELS = (unavailable, inferred, observed, verified)

Policy fields:
  required_fields — must be present and match
  advisory_fields — produce warnings on mismatch
  ignored_fields — excluded from checking
  acceptable_drift — field→list of acceptable observed values
  evidence_strength_required — field→minimum strength
  strict_mode — required failures become hard errors

Per-field evaluation records:
  evidence_source — how the value was obtained
  evidence_strength — observed|verified|inferred|unavailable
  comparison_status — match|mismatch|skipped|unavailable|acceptable_drift

Strict mode failures:
  required field unavailable
  required field evidence strength below minimum
  required field mismatch
  required field expected value missing

Drift report additions:
  field_details, required_field_failures, advisory_field_warnings,
  evidence_strength_summary, policy_digest, policy_strict_mode

New CLI flag:
  nodechain drift check --policy drift_policy.json [--strict]

New functions:
  classify_evidence_strength()
  DriftPolicy.from_dict/from_file/to_dict/digest

## [1.14.0] — 2026-06-16

### Deployment Drift Detection

Introduces drift detection — verifying what is actually deployed on a target
matches what should be deployed according to release history.

New module:
  src/nodechain/cli/drift_detection.py

New CLI command:
  nodechain drift check --target pve1/801 [--release-id ID]
    [--observed-artifact DIGEST] [--observed-service-state STATE]
    [--sign --key key.pem] [--output report.json] [--strict]

Drift check compares:
  artifact_digest — Expected artifact vs observed
  final_path — Expected path vs observed
  service_state — Expected state vs observed
  target_identity — Expected target vs observed
  policy_digest — Expected policy vs observed
  deployment_receipt_digest — Expected receipt vs observed

Drift result records:
  drift_detected, drift_fields, expected_values, observed_values,
  checked_at, target, release_id, evidence_source, report_id

Drift report:
  Can be signed with RSA-PSS-SHA256
  Includes report_digest for integrity

Strict mode exit codes:
  0 = no drift detected
  10 = check invalid or incomplete
  15 = drift detected

## [1.13.8] — 2026-06-16

### Release History Signed Snapshots

Completes parity with the trust-store hardening model. Release history
snapshots can be created, signed, and verified — freezing the known-good
release set used for rollback decisions.

New CLI commands:
  nodechain release-history snapshot --output snap.json [--sign --key key.pem]
  nodechain release-history verify-snapshot --snapshot snap.json [--pubkey pub.pem]

Snapshot includes:
  schema_version (1)
  release_history_id
  entries_digest
  audit_log_digest
  release_count
  target_summary
  latest_known_good_summary
  created_at
  snapshot_digest (SHA-256)
  snapshot_signature (RSA-PSS-SHA256, if signed)

Snapshot verification checks:
  schema_version
  snapshot_digest
  release_history_id
  entries_digest
  audit_log_digest
  signature validity
  live history comparison (optional)

New manifest fields:
  require_release_history_snapshot
  release_history_snapshot_path

New CLI flag:
  --require-release-history-snapshot

Rollback receipt records:
  release_history_snapshot_digest
  release_history_snapshot_signature_status
  release_history_snapshot_verified

Strict rollback refuses when snapshot is invalid (failure_mode=release_history_snapshot_invalid).

## [1.13.7] — 2026-06-16

### Release History Integrity

Hardens release_history.json as an operational authority with schema
metadata, entries digest, audit logging, and comprehensive verification.

New metadata fields in release_history.json:
  schema_version (2.0)
  release_history_id (unique UUID per history)
  updated_at (last modification timestamp)
  entries_digest (SHA-256 of canonical release entries)

New audit log (data/release_history_audit.jsonl):
  record_release — New release recorded
  update_release — Release updated
  remove_release — Release removed
  retention_verified — Retention check performed
  rollback_resolved — Rollback resolved from history

Each audit event records:
  timestamp, action, release_id, target, artifact_digest,
  final_deployment_state, activation_verified, actor

New CLI flag:
  nodechain release-history verify --integrity

Full integrity check validates:
  - Schema version present
  - No duplicate release IDs
  - No duplicate deployment receipt digests
  - All digests are valid hex SHA-256
  - entries_digest matches computed value
  - Referenced files exist

Strict rollback refuses malformed release history when
require_retention_verification=true.

## [1.13.6] — 2026-06-16

### Release History and Retention

Adds a persistent release history index that tracks every deployment,
enables rollback-by-release-id resolution, and verifies that referenced
artifacts are retained and intact.

New module:
  src/nodechain/cli/release_history.py

New classes:
  ReleaseRecord — Single release entry with 16 fields
  ReleaseHistory — Persistent index at data/release_history.json

Release record fields:
  release_id, artifact_digest, deployment_receipt_digest,
  attestation_digest, audit_bundle_digest, verifier_profile_digest,
  gate_receipt_digest, final_deployment_state, activation_verified,
  created_at, target, deployment_receipt_path, attestation_path,
  audit_bundle_path, verifier_profile_path, gate_receipt_path, artifact_path

Rollback resolution modes (resolve_release_by):
  release_id — Resolve specific release by ID
  artifact_digest — Find release by artifact digest
  latest_known_good — Find latest applied+verified release for target

Retention verification checks:
  - Referenced files exist
  - Referenced digests match
  - Release state is applied
  - activation_verified=true
  - Assurance chain available if required

New manifest fields:
  resolve_release_by, resolve_release_id,
  release_history_path, require_retention_verification

New CLI commands:
  nodechain release-history list [--target T] [--limit N]
  nodechain release-history verify [--release-id ID] [--require-chain]
  nodechain release-history latest-known-good [--target T]

Strict mode fails when:
  - Release history missing
  - latest_known_good unavailable
  - Referenced artifact/bundle/receipt missing
  - Digest mismatch
  - Retained chain incomplete

## [1.13.5] — 2026-06-16

### Rollback Full Chain Verification

Makes "known-good" depend on the same assurance chain as the current
deployment, not only a prior receipt's fields. When
`require_previous_assurance_chain=true`, rollback verifies the full
prior assurance chain:

```text
provenance → receipt type → attestation → verifier profile → audit bundle
```

New manifest fields:
  require_previous_assurance_chain (default False)
  previous_attestation — Prior attestation data (dict)
  previous_verifier_profile — Prior verifier profile (dict)
  previous_gate_receipt — Prior gate receipt (dict)
  previous_audit_bundle_digest — Expected audit bundle SHA-256
  previous_receipt_signature_required (default False)
  previous_attestation_signature_required (default False)
  previous_verifier_profile_trust_required (default False)

New CLI flag:
  --require-previous-assurance-chain

Chain verification steps (8-point check):
  1. Provenance passed (v1.13.4)
  2. Prior receipt is a deployment_system_receipt
  3. Prior receipt is signed (if required)
  4. Prior attestation is present and deploy_allowed
  5. Prior attestation is signed (if required)
  6. Prior verifier profile is trusted (if required)
  7. Prior audit bundle digest matches (if provided)
  8. Prior gate receipt deploy_allowed (if provided)

New receipt fields:
  previous_assurance_chain_verified
  previous_chain_verification_status (chain_verified/not_checked/
    provenance_failed/receipt_not_deployment_system/receipt_unsigned/
    attestation_missing/attestation_non_compliant/attestation_unsigned/
    verifier_profile_untrusted/audit_bundle_mismatch/gate_receipt_denied)
  previous_release_identity

Strict mode fails when:
  - Previous receipt is unsigned (signatures required)
  - Prior assurance chain invalid
  - Prior verifier profile untrusted
  - Prior attestation non-compliant
  - Prior receipt not deployment_system_receipt
  - Prior final_deployment_state != applied
  - Prior activation_verified != true

## [1.13.4] — 2026-06-16

### Rollback Provenance

Turns rollback from "restore configured previous artifact" into
"restore verified known-good release" by linking rollback targets to
prior verified deployment receipts.

New manifest fields:
  previous_deployment_receipt — Prior deployment receipt data (dict)
  previous_deployment_receipt_digest — SHA-256 of prior receipt for integrity
  previous_attestation_digest — SHA-256 of prior attestation
  require_previous_receipt_verified (default True)

Provenance verification checks:
  1. Prior receipt data is provided
  2. Receipt digest matches previous_deployment_receipt_digest
  3. Prior receipt shows final_deployment_state=applied
  4. Prior receipt shows activation_verified=true
  5. Prior receipt artifact_digest matches rollback target digest

New receipt fields:
  previous_deployment_receipt_digest
  previous_release_verified
  rollback_to_known_good
  rollback_provenance_status (verified/not_checked/receipt_missing/
    receipt_invalid/digest_mismatch/release_not_applied/
    activation_not_verified)

Strict mode fails when:
  - Previous receipt missing
  - Previous receipt invalid (digest mismatch)
  - Previous artifact digest mismatch
  - Previous release was not applied
  - Previous activation was not verified

## [1.13.3] — 2026-06-16

### Proxmox Rollback Policy

Adds the `rollback_artifact` action and automatic rollback on apply
failure, completing the operational safety story:

```text
upload → promote → apply → rollback if needed
```

New action:
  rollback_artifact — Revert to previous artifact version

New manifest fields:
  previous_artifact_digest — Digest of artifact to roll back to
  rollback_target_path — Path for rolled-back artifact
  rollback_timeout_seconds (default 120)
  require_rollback_verification (default True)
  rollback_on_apply_failure (default False)

Automatic rollback:
  When rollback_on_apply_failure=true and previous_artifact_digest is
  set, apply failures automatically trigger rollback. The receipt
  records both the apply failure and the rollback result.

New receipt fields:
  rollback_attempted, rollback_started_at, rollback_finished_at
  rollback_status (succeeded/failed/verification_failed/not_attempted)
  rollback_artifact_digest, rollback_verified
  final_deployment_state (applied/rolled_back/failed/unknown)
  rollback_triggered_by (explicit/apply_failure)

Strict mode fails when:
  - Previous artifact digest missing
  - Rollback API action fails
  - Rollback task returns error
  - Rollback verification fails (service state mismatch)
  - Final state is unknown

## [1.13.2] — 2026-06-16

### Proxmox Apply Artifact

Adds the `apply_artifact` action, completing the three-stage deployment
pipeline:

```text
upload_artifact → stage artifact
promote_artifact → move to final location
apply_artifact → activate artifact
```

New action:
  apply_artifact — Activate promoted artifact via API POST

New manifest fields:
  api_apply_action — Custom API endpoint for apply
  allowed_apply_targets — Restrict which targets can be activated
  require_promoted_artifact (default True)
  expected_service_state (default 'running')
  apply_timeout_seconds (default 120)
  rollback_policy (default 'manual')

New receipt fields:
  apply_started_at, apply_finished_at, apply_status
  promoted_artifact_digest, activated_artifact_digest
  service_pre_state, service_post_state
  activation_verified

Apply only runs when:
  - Promoted artifact digest matches expected
  - final_path is allowed
  - Adapter manifest is signed and trusted

Strict mode fails when:
  - Promoted artifact missing or unverifiable
  - Digest mismatch
  - Apply API action fails
  - Service state mismatch
  - Activation unverifiable when required

Transport: proxmox_command_shape=api (explicit HTTP)

## [1.13.1] — 2026-06-16

### Proxmox Artifact Staging Integrity

Separates artifact staging from finalization with an explicit
`promote_artifact` action. The three-stage pipeline is now clear:

```text
upload_artifact → stage artifact to staging directory
promote_artifact → move staged artifact to final location
apply_artifact → activate artifact (future)
```

New action:
  promote_artifact — Move staged artifact to final_path

New artifact action matrix:
  ARTIFACT_ACTION_MATRIX documents upload → promote → apply stages

New manifest fields:
  require_signed_manifest_for_promotion (default True)
  staging_digest_verification_required (default True)
  final_digest_verification_required (default True)

New receipt fields:
  staging_path
  final_path
  staging_digest
  final_digest
  promotion_performed
  promotion_started_at
  promotion_finished_at

Strict mode fails when:
  staging_directory not configured
  final_path not in allowed_remote_paths
  staged artifact cannot be verified
  final path already exists and overwrite_policy=reject
  promotion API call fails
  final digest mismatch

## [1.13.0] — 2026-06-16

### Proxmox API Artifact Deployment

Adds the `upload_artifact` action to the Proxmox API adapter, enabling
controlled artifact staging via the HTTP API with full digest
verification, size enforcement, path allowlisting, and overwrite policy.

New action:
  upload_artifact — POST /storage/{storage}/upload

New manifest fields:
  artifact_digest_required (default True)
  remote_digest_verification_required (default True)
  max_artifact_size_bytes (0 = unlimited)
  overwrite_policy ('reject' default, 'allow', 'overwrite')
  staging_directory
  final_path
  remote_storage (default 'local')
  artifact_local_path

New receipt fields:
  artifact_digest, local_artifact_digest
  artifact_size_bytes
  remote_path, remote_artifact_digest
  remote_digest_matched
  transfer_started_at, transfer_finished_at
  overwrite_performed, staging_used
  failure_mode (for rejection diagnostics)

Transport: proxmox_command_shape=api (HTTP multipart upload)

## [1.12.7] — 2026-06-16

### Proxmox API Lifecycle Consolidation

Consolidates the five lifecycle actions into a single normalized profile
with an evidence matrix, safe boot ID storage, dry-run policy checks,
and comprehensive negative smoke tests.

New constants:
- `PROXMOX_API_LIFECYCLE_MATRIX`: Per-action evidence requirements
- `LIFECYCLE_RECEIPT_FIELDS`: Canonical receipt field set

New manifest fields:
- `hash_boot_ids`: Hash boot IDs in receipts by default (default: true)
- `allow_raw_boot_ids`: Allow raw boot IDs when explicitly configured

New CLI flag:
- `--dry-run-policy-check`: Validate manifest, action, secret, TLS, and
  target policy without performing any mutation

Safe boot ID storage:
- Boot IDs hashed via SHA-256 by default
- Raw boot IDs require explicit `allow_raw_boot_ids=true`
- Receipts record `boot_id_hashed` field for auditability

## [1.12.6] — 2026-06-16

### Proxmox Reboot Boot-ID Proof

Upgrades reboot evidence from uptime-only to real boot identity
verification via QEMU guest agent. The adapter now reads
`/proc/sys/kernel/random/boot_id` from the guest to prove a reboot
actually occurred, with uptime-reset as a configurable fallback.

New manifest fields:
- `boot_evidence_source`: `uptime` (default), `guest_agent`, or `auto`
- `allow_uptime_only_fallback`: When `require_boot_id_change=true` and
  boot ID is unavailable, controls whether uptime evidence is accepted

New receipt fields:
- `boot_evidence_source`: Which evidence source was used
- `pre_boot_id`: Boot identifier before reboot
- `post_boot_id`: Boot identifier after reboot
- `boot_id_changed`: Whether boot ID actually changed
- `uptime_fallback_used`: Whether uptime was used as fallback evidence

Strict mode fails when:
- `require_boot_id_change=true` and boot ID unavailable and
  `allow_uptime_only_fallback=false`
- Boot ID available but unchanged

## [1.12.5] — 2026-06-15

### Proxmox API Reboot Evidence

Adds the `reboot` action with boot-evidence verification. Since reboot
has `running → running` state, uptime reset detection provides the
additional evidence needed to prove the reboot actually occurred.

Also tightens reject_noop semantics: when target is already in desired
state and no-op is not allowed, the adapter now rejects before executing
an unnecessary mutation.

New action:
  `reboot` — POST /status/reboot returns UPID task

New manifest fields:
  `require_boot_id_change` — require proof of boot identity change
  `require_uptime_reset` — require uptime reset evidence
  `reboot_timeout_seconds` — timeout for reboot task (default: 300)

New receipt fields:
  `pre_uptime_seconds` — uptime before reboot
  `post_uptime_seconds` — uptime after reboot
  `boot_identity_changed` — boot evidence shows a reboot occurred
  `uptime_reset_detected` — uptime was reset (post < pre)

Reboot evidence logic:
  Uptime is captured before and after the reboot task.
  If post_uptime < pre_uptime, a reset is detected.
  When require_boot_id_change=true, boot_identity_changed must be true.
  When require_uptime_reset=true, uptime_reset_detected must be true.

reject_noop hardening:
  When target already in expected_post_state + idempotency_policy=reject_noop:
    → deployment is rejected before executing unnecessary mutation
    → effective_action='rejected', task_exitstatus='REJECTED_NOOP'

## [1.12.4] — 2026-06-15

### Proxmox API Idempotent Actions

Adds the `stop` action and idempotency/no-op semantics for API mutations.
When a target is already in the desired post-state, the adapter can either
reject the action (default) or emit a no-op result based on policy.

New action:
  `stop` — POST /status/stop returns UPID task

New manifest fields:
  `idempotency_policy` — 'reject_noop' (default) or 'allow_noop'
  `allow_noop_if_already_desired` — skip mutation if target already in state

No-op behavior:
  If target pre-state == expected_post_state:
    allow_noop → accepted with no_op=true, effective_action=noop
    reject_noop → proceeds with mutation (likely fails pre-state check)

Receipt records:
  `requested_action` — the action from the manifest
  `effective_action` — actual action taken (action | noop)
  `no_op` — whether a no-op shortcut was taken
  `idempotency_policy` — policy that was in effect

Strict mode fails if:
  - Action outside allowlist
  - Pre-state mismatch
  - Post-state mismatch
  - Task failure
  - Timeout
  - No-op not allowed (reject_noop)

## [1.12.3] — 2026-06-15

### Proxmox API Task Polling

Upgrades from single post-state check to proper UPID-based task endpoint
polling with configurable intervals and max attempts.

New manifest fields:
  `task_poll_interval_seconds` — poll interval (default: 1.0)
  `task_max_polls` — maximum poll attempts (default: 10)
  `require_task_success` — require task exitstatus=OK (default: true)

New receipt fields:
  `task_poll_count` — number of polls performed
  `task_duration_ms` — task execution duration in milliseconds
  `task_api_status` — Proxmox task status (stopped/running/unknown)
  `task_success` — task completed with OK exitstatus
  `task_log_digest` — SHA-256 digest of task log (optional)

Separation of concerns:
  `task_success` — did the Proxmox task complete successfully?
  `state_transition_verified` — did the VM/CT reach expected state?
  These are tracked independently; overall success requires both.

Strict mode fails if:
  - Task endpoint unavailable
  - Task times out (exceeds task_max_polls)
  - Task exitstatus is not OK (when require_task_success=true)
  - Post-state mismatch (when expected_post_state set)

## [1.12.2] — 2026-06-15

### Proxmox API Task Actions

Adds the first controlled API mutation action: `start`. The adapter now
handles Proxmox UPID/task responses with pre-state verification, post-state
confirmation, and state-transition evidence in receipts.

New action:
  `start` — POST /status/start returns UPID task

New manifest fields:
  `allowed_api_actions` — restrict which API actions are permitted
  `require_confirmed_target_status` — verify state before mutation
  `expected_pre_state` — required state before action (e.g., 'stopped')
  `expected_post_state` — expected state after action (e.g., 'running')
  `task_timeout_seconds` — timeout for task completion (default: 120)

Receipt records:
  `proxmox_task_upid` — Proxmox task identifier
  `task_started_at` — when the POST was issued
  `task_finished_at` — when post-state was checked
  `task_exitstatus` — 'OK' or 'FAILED'
  `pre_state` — observed state before mutation
  `post_state` — observed state after mutation
  `state_transition_verified` — pre→post transition matches expectations

Strict mode fails if:
  - Action outside allowed_api_actions
  - Pre-state does not match expected_pre_state
  - Task returns no UPID
  - Post-state does not match expected_post_state

## [1.12.1] — 2026-06-15

### Secret Reference Policy

Adds secret-source policy enforcement for the Proxmox API adapter,
controlling which secret references can be resolved for deployment
operations.

New manifest fields:
  `allowed_secret_ref_prefixes` — restrict secret ref format
  `allowed_env_vars` — allowlist specific environment variables
  `allowed_secret_files` — allowlist specific file paths
  `require_secret_ref` — require a secret ref to be set
  `forbid_inline_secrets` — reject inline/plaintext secrets (default: true)

Verification fails if:
  - token_secret_ref is missing (when require_secret_ref=true)
  - token_secret_ref is inline/plaintext (when forbid_inline_secrets=true)
  - env var is not in allowed_env_vars
  - file path is not in allowed_secret_files
  - file permissions are too broad (world-readable/group-writable)
  - secret source cannot be resolved in strict mode

Receipt records:
  `token_secret_ref_type` — env | file | inline | empty
  `secret_source_allowed` — source passed policy checks
  `secret_resolved` — secret value was found
  `secret_value_serialized` — always false
  `token_secret_ref_redacted` — redacted reference for audit

Redaction:
  env:  first 4 chars of var name + ***
  file: sha256 hash of path (first 12 chars)
  inline: ***REDACTED***

## [1.12.0] — 2026-06-15

### Proxmox API Adapter

Adds `ProxmoxApiAdapter` implementing `DeploymentAdapter` with HTTP API
backend, complementing the existing SSH adapter. The API adapter provides
cleaner identity and policy semantics using Proxmox API tokens (PVEAPIToken)
with TLS verification.

New manifest fields:
  `api_base_url` — Proxmox API base URL
  `token_id` — API token identifier (e.g., user@pam!token)
  `token_secret_ref` — Secret reference: env:VAR, file:/path, or inline
  `verify_tls` — Verify TLS certificate (default: true)
  `ca_bundle_path` — Custom CA bundle for TLS verification
  `allow_insecure_tls` — Explicitly allow insecure TLS in strict mode

New API actions:
  `validate_target` — Check VM/CT exists via API
  `get_status` — Retrieve VM/CT status via API

New receipt fields:
  `proxmox_command_shape=api`
  `api_endpoint_identity` — Full API URL called
  `tls_verified` — TLS certificate verification result
  `response_status_code` — HTTP status code

Strict mode fails if:
  - TLS disabled without allow_insecure_tls
  - Action outside PROXMOX_API_ACTIONS allowlist
  - Node or VMID outside manifest allowlist
  - API returns non-success status
  - Token reference missing

Secret handling:
  Token secrets are resolved at runtime from env/file references.
  Secrets are never written to receipts, traces, audit bundles, or logs.
  Receipt records only that a token was used, not its value.

Shared receipt model:
  SSH and API adapters produce the same receipt structure.
  `proxmox_command_shape` distinguishes the execution path.

## [1.11.2] — 2026-06-15

### Proxmox Evidence and Negative Smokes

Adds enforcement for host fingerprint verification and enhanced receipt
fields, plus comprehensive negative smoke tests proving all policy
violations actually fail.

Enhanced receipt fields:
  `host_key_pin_checked` — fingerprint pinning was attempted
  `host_key_pin_matched` — observed host key matches pinned fingerprint
  `remote_hash_verified` — artifact hash verification was performed
  `remote_hash_matched` — remote hash matched expected value
  `proxmox_command_shape` — ssh | api
  `shell_used` — always false for Proxmox argv-only execution

Host key enforcement (v1.11.2):
  SSH stderr "Host key verification failed" sets host_key_verified=false
  Fingerprint mismatch sets host_key_pin_matched=false
  Strict mode rejects on pin mismatch

Negative smoke tests (v1.11.2):
  - Host fingerprint mismatch fails
  - known_hosts mismatch fails
  - root without allow_root fails
  - VMID outside allowlist fails
  - node outside allowlist fails
  - action outside allowlist fails
  - remote artifact hash mismatch fails
  - execute_deploy proves shell_used=false

## [1.11.1] — 2026-06-15

### Proxmox Adapter Hardening

Hardens the Proxmox SSH deployment adapter with host key verification,
dedicated deploy identity enforcement, manifest allowlists, and remote
artifact hash verification.

SSH host key verification/pinning:
  `strict_host_key_checking` (default: true)
  `known_hosts_path` — explicit known_hosts file
  `proxmox_host_fingerprint` — expected host fingerprint

Dedicated deploy identity:
  `proxmox_user` must be explicit in strict mode
  `root` user allowed only with `allow_root=true`

New manifest fields:
  `allowed_vmid_list` — restrict VMIDs
  `allowed_node_list` — restrict Proxmox nodes
  `allowed_remote_paths` — restrict remote paths
  `deploy_timeout_seconds` — override deploy timeout
  `require_artifact_hash_verification` — verify remote hash after upload

New receipt fields:
  `ssh_user`, `host_key_verified`, `root_user_used`
  `sudo_used`, `ssh_host_fingerprint`

Strict mode fails if:
  - Host key is unverified
  - Root user used without allow_root
  - VMID/node outside manifest allowlist
  - Action outside manifest allowlist

## [1.11.0] — 2026-06-15

### Proxmox Deployment Adapter

Moves from local/dry-run deployment into a real deployment backend.
The ProxmoxAdapter performs narrow, governed actions against a Proxmox VE
cluster via SSH.

New adapter:
  `ProxmoxAdapter` — implements DeploymentAdapter

New manifest fields:
  `proxmox_node` — target Proxmox node name
  `target_vmid` — CT or VM ID
  `allowed_actions` — narrow action allowlist

Supported actions:
  `validate_target` — check CT/VM exists and is running
  `upload_artifact` — upload artifact to CT (configured)
  `execute_deploy` — execute fixed deploy command inside CT via `pct exec`

New receipt fields:
  `proxmox_node`, `vmid`, `proxmox_action`, `api_endpoint`

Environment variables:
  `NODECHAIN_PROXMOX_HOST` — Proxmox host for SSH
  `NODECHAIN_PROXMOX_USER` — SSH user (default: root)

Manifest must be signed and purpose-authorized (v1.10.3–v1.10.7 chain).
Strict mode fails if Proxmox action is rejected or incomplete.

Windows tests skip Proxmox integration cleanly.

## [1.10.7] — 2026-06-14

### Trust Store Signed Snapshots

Adds the ability to freeze and attest the trust root state used by CI.
Snapshots capture the complete trust store state at a point in time and
can be cryptographically signed.

New CLI commands:
  `trust-store snapshot --output snapshot.json [--sign --key admin.pem]`
  `trust-store verify-snapshot snapshot.json [--pubkey pub.pem] [--check-live]`

New deploy flag:
  `--require-trust-store-snapshot snapshot.json`

Snapshot fields:
  schema_version, type, trust_store_id, entries_digest,
  audit_log_digest, key_count, purposes_summary,
  created_at, snapshot_digest
  Optional: snapshot_signature, snapshot_signature_algorithm,
            snapshot_signer_fingerprint

Snapshot verification checks:
  - Schema version
  - snapshot_digest integrity (tamper detection)
  - Signature validity (if signed)
  - Live store match (if --check-live)

New receipt fields (v1.10.7):
  trust_store_snapshot_digest
  trust_store_snapshot_signature_status

## [1.10.6] — 2026-06-14

### Trust Store Integrity and Audit

Hardens the trust store itself with integrity metadata, atomic writes,
audit logging, and a verification command.

Trust store metadata:
  `trust_store_id`: UUID generated on creation
  `updated_at`: ISO 8601 timestamp of last write
  `entries_digest`: SHA-256 of canonical key entries

Atomic writes:
  All writes go through temp file + rename for crash consistency.

Audit log (v1.10.6):
  Records all trust store mutations:
    add_key, remove_key, migrate_key

  Each event records:
    timestamp, action, key_id, fingerprint,
    purposes_before, purposes_after

New command:
  `nodechain trust-store verify [--strict]`

  Validates:
    - Schema version
    - Duplicate key IDs
    - Duplicate fingerprints
    - Invalid purposes
    - Malformed PEM keys
    - entries_digest integrity

Strict mode enforcement:
  Strict mode now also refuses malformed or unverifiable trust stores.

## [1.10.5] — 2026-06-14

### Strict Trust Store Mode

Adds `--strict-trust-store` mode that rejects legacy keys (those without
explicit `allowed_purposes`). Legacy keys are accepted in standard mode
but clearly marked in listing output.

New CLI:
  `nodechain trust-store migrate [--purpose ...]`
  Adds explicit purposes to legacy keys.

  `--strict-trust-store` on `deploy` command.

New functions:
  `is_legacy_key(info)` — detect keys without allowed_purposes
  `migrate_legacy_keys(purposes)` — add purposes to legacy keys
  `check_purpose(strict=True)` — strict mode rejects legacy keys
  `is_trusted_fingerprint(strict=True)` — strict mode rejects legacy keys

CLI list output:
  Legacy keys marked with (LEGACY: no explicit purposes)

New receipt fields (v1.10.5):
  `trust_store_mode` — strict | standard
  `signer_required_purpose` — adapter_manifest_signing
  `signer_allowed_purposes` — list of purposes from key entry
  `purpose_authorized` — bool

## [1.10.4] — 2026-06-14

### Trust Store Key Purposes

Adds purpose constraints to trust store keys, preventing privilege creep
where any trusted key becomes implicitly trusted for all artifact types.

New purpose constants:
  `VALID_PURPOSES`: verifier_profile_signing, adapter_manifest_signing,
                    audit_bundle_signing, attestation_signing, receipt_signing
  `ALL_PURPOSES`: sorted list of all valid purposes

New functions:
  `check_purpose(fingerprint, purpose)` — check key has required purpose
  `add_key()` now accepts `purposes` parameter
  `is_trusted_fingerprint()` now accepts optional `purpose` parameter

CLI updates:
  `trust-store add-key --purpose <p>` (repeatable)
  `trust-store list` shows purposes per key

Purpose enforcement:
  Verifier profile sig: requires verifier_profile_signing
  Adapter manifest sig: requires adapter_manifest_signing

Verification fails if:
  - Key exists but lacks required purpose
  - Unknown purpose specified

Backward compatibility:
  Old keys without `allowed_purposes` field load with all purposes
  and emit no error (silent migration)

## [1.10.3] — 2026-06-14

### Adapter Manifest Trust

Makes adapter manifests trusted policy artifacts with RSA-PSS signing
and trust store integration. Manifests are no longer just hashed config
files — they are signed policy documents verifiable against the local
trust store.

New functions:
  `sign_manifest(manifest_path, private_key_path)` — RSA-PSS-SHA256
  `verify_manifest_signature(manifest_dict, public_key_pem)`

New CLI flag:
  `--require-adapter-manifest-signature`

Trust store integration:
  Manifest signer keys stored via `nodechain trust-store add-key`
  Verification checks fingerprint against trust store

Deployment fails if:
  - Manifest unsigned when --require-adapter-manifest-signature is set
  - Manifest signer not in trust store
  - Manifest signature invalid

New receipt fields:
  `adapter_manifest_signature_status` (valid/invalid/none/untrusted_signer)
  `adapter_manifest_signer_fingerprint`
  `adapter_manifest_signer_trusted`

## [1.10.2] — 2026-06-14

### Argv Deployment Adapter

Moves deployment adapter execution from shell to safe argv-based process
execution, eliminating command injection risk.

New manifest fields:
```json
{
  "execution_mode": "argv",
  "allow_shell": false,
  "argv_template": ["deploy-tool", "--target", "{target}", "--artifact", "{artifact_digest}"],
  "allowed_executables": ["deploy-tool", "echo"]
}
```

Argv execution:
  - Uses `subprocess.run(argv_list, shell=False)`
  - No shell interpolation possible
  - Template vars resolved before execution
  - Empty executable detected
  - Executable allowlist enforcement

Shell mode now requires explicit `allow_shell: true`.
Default `allow_shell: false` blocks shell templates.

New receipt fields:
  `execution_mode` (argv | shell)
  `shell_used` (true/false)
  `argv_template_digest`
  `resolved_argv_digest`

Validation fails if:
  - `execution_mode=shell` and `allow_shell=false`
  - argv contains unresolved placeholders
  - argv[0] (executable) is empty
  - executable not in allowlist

## [1.10.1] — 2026-06-14

### Deployment Adapter Policy

Hardens the deployment adapter layer with manifests, command templates,
and safety checks to prevent it from becoming the weakest link.

New `AdapterManifest` class:
```json
{
  "schema_version": "1",
  "type": "adapter_manifest",
  "adapter_id": "prod-lxc-shell",
  "adapter_type": "local_shell",
  "allowed_targets": ["prod-lxc-801"],
  "required_policy_digest": "abc123...",
  "allowed_artifact_digest_patterns": ["*"]
  "command_template": "echo deploy {target} {artifact_digest}",
  "environment_policy": "filtered",
  "working_directory_policy": "inherit",
  "timeout_seconds": 30
}
```

Local shell now uses fixed command templates with safe placeholders
(`{target}`, `{artifact_digest}`, `{policy_digest}`) instead of arbitrary
shell input.

Unsafe interpolation detection:
  - Command substitution `$()`, backticks
  - Variable expansion `${}`
  - Chaining `;`, `&&`, `||`
  - Pipes `|`, redirects `<>`
  - Unknown template variables

New receipt fields:
  `adapter_manifest_digest`
  `command_template_digest`
  `execution_exit_code`
  `stdout_digest`
  `stderr_digest`
  `command_executed`

New CLI option: `--manifest manifest.json`

Validation fails if:
  - Target not in allowed_targets
  - Policy digest mismatch
  - Artifact digest not allowed
  - Command template missing
  - Unsafe interpolation detected

## [1.10.0] — 2026-06-14

### Deployment System Receipt

Binds the NodeChain deploy gate receipt to a real deployment system action
via deployment adapters. Proves not just that the gate allowed deployment,
but that a deployment system accepted/applied it.

New `deploy` CLI command:
```text
nodechain deploy --receipt gate_receipt.json --adapter dry-run --output deploy.json
nodechain deploy --receipt gate.json --adapter dry-run --sign key.pem
nodechain deploy --verify deploy.json --pubkey pub.pem
nodechain deploy --verify deploy.json --strict --gate-receipt gate.json
```

Deployment adapter interface (`DeploymentAdapter`):
```python
class DryRunAdapter(DeploymentAdapter):
    system_name = "dry_run"
    def deploy(self, target, artifact_digest, ...) -> dict

class LocalShellAdapter(DeploymentAdapter):
    system_name = "local_shell"
    # Runs NODECHAIN_DEPLOY_COMMAND or 'echo deploy'
```

Deployment-system receipt includes:
  schema_version, type, deployment_receipt_id (UUID)
  gate_receipt_id, deployment_system, target
  artifact_digest, policy_digest
  deploy_status (accepted/rejected/failed)
  deployer_identity, deploy_detail
  deploy_started_at, deploy_finished_at
  assurance_receipt_id, assurance_receipt_digest
  receipt_digest (SHA-256 tamper detection)
  Optional: receipt_signature (RSA-PSS-SHA256)

Verification distinguishes:
  gate_receipt — NodeChain gate evaluated and allowed/denied
  deployment_system_receipt — deployment system accepted/applied

Strict mode fails if deploy_status != "accepted".

## [1.9.1] — 2026-06-14

### Assurance Chain Verifier

Verifies the entire evidence chain in one command, cross-checking digests
between artifacts and verifying all signatures.

New command:
```text
nodechain assurance verify \
  --bundle audit.zip \
  --attestation attestation.json \
  --profile verifier_profile.json \
  --receipt receipt.json \
  --pubkey public.pem \
  --require-signatures \
  --strict \
  --trust-store
```

Cross-artifact digest checks:
  receipt → attestation digest
  receipt → verifier profile digest
  attestation → audit bundle hash

Signature checks:
  audit bundle signature
  attestation signature
  verifier profile signature (trust store)
  receipt signature

Single final verdict:
  assurance_chain_valid: true/false
  deploy_allowed: true/false
  denial_reason

Exit codes:
  0  = valid, deploy allowed chain
  10 = invalid chain
  15 = valid chain but strict deploy denied

## [1.9.0] — 2026-06-14

### Deployment Receipt

Records that a deployment gate evaluated a specific attestation under a
specific verifier profile and either accepted or rejected the deployment.

New `deploy-receipt` CLI command group:
```text
nodechain deploy-receipt create \
    --attestation attestation.json \
    --profile verifier_profile.json \
    --output receipt.json

nodechain deploy-receipt create \
    --attestation attestation.json \
    --sign deploy-gate_private.pem \
    --output receipt.json

nodechain deploy-receipt verify receipt.json \
    --pubkey deploy-gate_public.pem
```

Receipt includes:
  schema_version, receipt_id (UUID), type
  attestation_digest, verifier_profile_digest
  profile_signer_fingerprint, attestation_signer_fingerprint
  deploy_allowed, denial_reason
  target, artifact_digest, lockfile_digest, policy_digest
  receipt_digest (SHA-256 content hash)
  verified_at, verifier_nodechain_version
  Optional: receipt_signature (RSA-PSS-SHA256)

Verification fails if:
  - Receipt signature invalid
  - Attestation digest mismatch
  - Profile digest mismatch
  - deploy_allowed=false under --strict (exit 15)
  - Receipt schema version unsupported
  - Receipt digest mismatch (tamper detection)

Exit codes:
  0  = valid receipt
  10 = invalid receipt
  15 = strict deny

## [1.8.3] — 2026-06-14

### Verifier Profile Trust Store

Local trust store for verifier profile signing keys, enabling profile-signature
enforcement for CI deploy gates.

New `trust-store` CLI command group:
```text
nodechain trust-store add-key profile-signer public.pem
nodechain trust-store list
nodechain trust-store remove-key profile-signer
```

New attest flag:
```text
nodechain attest --verify attestation.json \
    --profile verifier_profile.json \
    --require-profile-signature
```

Verification fails if:
- Profile is unsigned when `--require-profile-signature` is set
- Profile signer fingerprint not in trust store
- Profile signature is invalid

Verification output includes:
- `profile_digest`
- `profile_signature_status` (valid/invalid/missing/untrusted_signer)
- `profile_signer_fingerprint`
- `profile_signer_trusted`

Trust store format:
```json
{
  "schema_version": "1",
  "type": "trust_store",
  "keys": {
    "profile-signer": {
      "fingerprint": "abc123...",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----...",
      "added_at": "2026-06-14T..."
    }
  }
}
```

Trust store location: `data/trust_store.json` (or `$NODECHAIN_TRUST_STORE`).

## [1.8.2] — 2026-06-14

### Attestation Verifier Profile

Consolidates all CI expectation flags into a versioned verifier profile.

New verifier profile file:
```json
{
  "schema_version": "1",
  "type": "verifier_profile",
  "require_signature": true,
  "strict_mode": true,
  "trusted_signer_fingerprints": ["abc123..."],
  "expected_policy_digest": "def456...",
  "expected_target": "prod-lxc-801",
  "expected_artifact_digest": "ghi789...",
  "expected_lockfile_digest": "jkl012...",
  "allowed_attestation_schema_versions": ["1"]
}
```

Usage:
```text
nodechain attest --verify attestation.json --profile verifier_profile.json
```

Profile includes:
- `trusted_signer_fingerprints` — whitelist of allowed signers
- `allowed_attestation_schema_versions` — accepted schema versions
- All expectation fields from v1.8.1 as profile fields
- `profile_digest` — SHA-256 of profile (shown in output)

Verification fails if:
- Signer fingerprint not in trusted list
- Attestation schema version not in allowed versions
- Any expectation mismatch

## [1.8.1] — 2026-06-14

### Attestation Policy Binding

Explicit policy document binding and CI expectation checks.

New attestation fields:
- `policy_id` — policy identifier
- `policy_version` — policy version
- `policy_digest` — SHA-256 of policy identity
- `deploy_allowed` — boolean deploy/deny decision
- `denial_reason` — explanation when deploy not allowed

New verification options:
```text
--expect-artifact-digest <sha256>
--expect-lockfile-digest <sha256>
--expect-policy-digest <sha256>
--expect-target <target>
```

Each expectation mismatch produces a stable error and fails verification.

Strict mode now also requires:
- Policy binding present (`policy_id`)
- `deploy_allowed` is true

## [1.8.0] — 2026-06-14

### Deployment Attestation

Binds a signed audit bundle to a specific deployment artifact, environment,
policy preset, and runtime decision.

New commands:
```text
nodechain attest <run_id> --bundle audit.zip --output attestation.json
nodechain attest <run_id> --bundle a.zip --sign private.pem
nodechain attest --verify attestation.json --pubkey public.pem
nodechain attest --verify a.json --pubkey pub.pem --require-signature --strict
```

Attestation includes:
- `run_id` — chain run identifier
- `audit_bundle_sha256` — hash of the source bundle
- `bundle_signature_status` — signed/unsigned
- `signer_key_fingerprint` — signer identity
- `active_preset` — policy preset used
- `trust_verdict` — compliant / compliant_with_warnings / non_compliant
- `deployment_target` — target identifier
- `artifact_digest` — package/artifact SHA-256
- `lockfile_digest` — registry lockfile hash
- `platform` — deployment platform summary
- `git` — commit/tag/branch info
- `schema_version` — attestation format version

Verification fails if:
- Audit bundle hash does not match expected bundle
- Signer key does not match expected key
- Trust verdict is non-compliant under `--strict`
- Artifact digest differs from expected
- Attestation signature is invalid

CI mode: `--require-signature --strict` enforces both signature and compliance.

## [1.7.1] — 2026-06-14

### Audit Key Identity and Policy

Enhanced key identity metadata and CI signature enforcement.

New `bundle_meta.json` fields:
- `signature_algorithm`: RSA-PSS-SHA256
- `signature_created_at`: ISO 8601 timestamp
- `signer_key_fingerprint`: SHA-256 of public key DER

New `--require-signature` flag:
```text
nodechain audit-bundle x --verify bundle.zip --pubkey public.pem --require-signature
```
Fails if:
- Bundle is not signed
- Signature is missing when `--pubkey` provided
- No `--pubkey` provided (can't verify)
- Signature verification fails

SUMMARY.md now includes Bundle Integrity section with:
- Signature status (unsigned / signed / signing_failed)
- Bundle SHA-256 hash
- Signer fingerprint when signed
- Manifest entry count

## [1.7.0] — 2026-06-14

### Signed Audit Bundles

Cryptographic signatures for audit bundles using RSA-PSS with SHA-256.

New commands:
```text
nodechain audit-bundle x --generate-keys ~/.nodechain/keys
nodechain audit-bundle <run_id> --sign private.pem --output bundle.zip
nodechain audit-bundle x --verify bundle.zip --pubkey public.pem
```

Signature covers:
- `audit_bundle_schema_version`
- `run_id`
- `generated_at`
- file manifest (all paths, SHA-256 hashes, sizes)

Key features:
- RSA 3072-bit key pairs (PEM/PKCS8)
- RSA-PSS with SHA-256 and MGF1
- Signer fingerprint (SHA-256 of public key DER)
- `bundle_meta.json` records signature, algorithm, fingerprint
- `--verify` with `--pubkey` validates signature
- Unsigned bundles still verify (non-signature mode)
- Wrong public key → verification fails
- Modified manifest → verification fails

Dependency: `cryptography>=42.0` added to pyproject.toml

## [1.6.2] — 2026-06-14

### Audit Bundle Integrity

Content integrity via SHA-256 file manifests inside the bundle.

Changes:
- `bundle_meta.json` now includes a `files` manifest with SHA-256 and size
  for every bundle file.
- `--verify` checks all hashes against the manifest.
- Verification fails if any file content is modified (hash mismatch).
- Verification fails if any unexpected file is added not in the manifest.
- Top-level bundle SHA-256 emitted after generation.
- `SUMMARY.md` includes bundle hash.

This makes the bundle tamper-evident: any modification to any file inside
the ZIP is detected during verification.

## [1.6.1] — 2026-06-14

### Audit Bundle Schema Versioning

Every JSON file in the audit bundle now carries a `schema_version` stamp.
The bundle itself carries `audit_bundle_schema_version` in `bundle_meta.json`.

New verification command:
```text
nodechain audit-bundle <run_id> --verify bundle.zip
```

Verifies:
- All required files present
- Every JSON file has `schema_version`
- `bundle_meta.json` has `audit_bundle_schema_version`
- `SUMMARY.md` has `Compliance Status` section

Exits 10 on invalid bundles, 0 on valid.

Enhanced `SUMMARY.md`:
- Overall compliance status (COMPLIANT / NON-COMPLIANT / WITH WARNINGS)
- Active preset
- Required layers count
- Enforced layers count
- Failed invariants count

`bundle_meta.json` now includes:
- `audit_bundle_schema_version`
- `nodechain_version`
- `git_tag`
- `git_commit`
- `generated_at`
- `run_id`

## [1.6.0] — 2026-06-14

### Sandbox Audit Bundle

Portable evidence artifact for operators, auditors, and CI.

New command:
```text
nodechain audit-bundle <run_id> --output bundle.zip
nodechain audit-bundle <run_id> --strict  # CI mode, exit 15 on violations
```

Bundle contents (ZIP):
- `SUMMARY.md` — human-readable audit report
- `bundle_meta.json` — version, git info, platform
- `report.json` — full run report
- `trust_summary.json` — trust summary with all nodes
- `invariants.json` — INV-001..013 results
- `lockfile.json` — lockfile verification
- `sandbox_capabilities.json` — platform sandbox detection
- `namespace_detection.json` — namespace capabilities
- `preset.json` — active preset configuration
- `enforcement_layers.json` — required/enforced/advisory/unavailable/skipped
- `trace.json` — execution trace
- `platform.json` — OS/kernel/Python/container info

Enforcement layers are classified:
- **Required**: layers the preset declares
- **Enforced**: layers actually active
- **Advisory**: RLIMIT / Job Objects (reported, not blocking)
- **Unavailable**: layers not supported on this platform
- **Skipped**: optional layers not enabled

CI mode: `--strict` exits 15 if trust violations exist.

## [1.5.2] — 2026-06-14

### Hardened Sandbox Profile Consolidation

Full consolidation of the hardened sandbox profile: positive smoke,
negative smoke per kernel layer, and unified documentation.

Changes:

1. **Positive CLI smoke**: `hardened_untrusted --strict --trust-check`
   exits 0 with all enforcement layers proven.

2. **Negative smoke per required kernel layer**: Each invariant
   (INV-007 seccomp, INV-009 cgroup, INV-011 netns, INV-012 mount
   confinement, INV-013 pidns) independently fires exit 15 when
   required but not enforced.

3. **Hardened Sandbox Profile table**: Single table in docs showing
   every enforcement layer, its status (required/advisory/optional),
   platform, and governing invariant.

4. **`nodechain presets` enhanced**: Shows hardening layers per preset.

5. **CLI consistency**: report/trust/inspect show same posture.

## [1.5.1] — 2026-06-14

### PID Namespace Procfs Consolidation

Consolidation pass for PID namespace: procfs remount prototype,
honest /proc visibility reporting, PID 1 behavior documentation,
and CLI reporting.

Changes:

1. **Procfs remount prototype**: `remount_procfs_for_pid_namespace()`
   remounts /proc inside the PID namespace so only namespace-local
   PIDs are visible. Optional via `enable_procfs_isolation`.

2. **TrustSummary distinguishes**: `pid_namespace_enforced` (PID
   namespace active, child is PID 1) vs `procfs_namespace_view_enforced`
   (/proc remounted, only local PIDs visible).

3. **PolicyPreset**: `procfs_isolation_required` field. Wired so that
   `pid_namespace_required=True` presets also enable procfs isolation.

4. **CLI**: trust/report/inspect show procfs_isolated and procfs_error.

5. **Documentation**: PID namespace behavior, /proc visibility, PID 1
   signal handling and zombie reaping, compatibility notes.

## [1.5.0] — 2026-06-14

### PID Namespace Isolation

The next kernel boundary: PID namespace isolation via two-stage fork.

When `enable_pid_namespace=True`, the child bootstrap performs:
1. `unshare(CLONE_NEWPID)` — marks new PID namespace
2. `fork()` — child is PID 1 in the new namespace
3. Parent waits, exits with child's status
4. Child continues with all other enforcement phases

The child process sees itself with a namespace-local PID (typically 1).
Host processes are not directly visible as PID numbers (though `/proc`
remains the host's procfs unless combined with mount namespace/chroot).

Key design: PID namespace unshare+fork happens as **Phase 0**, before
seccomp (which blocks fork) and before all other phases.

Changes:

1. **`apply_pid_namespace_two_stage()`**: unshare + fork protocol with
   `_PID_NS_SUCCESS`/`_PID_NS_SKIP`/`_PID_NS_FAIL` return codes.

2. **SubprocessRunner**: `enable_pid_namespace` parameter.
   Child bootstrap Phase 0 before all other phases.

3. **NodeTrustRecord**: `pid_namespace_requested`,
   `pid_namespace_enforced`, `pid_namespace_error`, `pid_namespace_mode`.

4. **SandboxCapabilities**: `pid_namespace_enforced`.

5. **INV-013**: `pid_namespace_required_but_not_enforced` — fires as
   error when required but not enforced. Strict mode → exit 15.

6. **hardened_untrusted preset**: `pid_namespace_required=True`.

7. **CLI**: trust/report/inspect show PID namespace fields.

## [1.4.7] — 2026-06-14

### Hardened Preset Compatibility

Compatibility and consolidation pass for the `hardened_untrusted` preset.
Tests that chroot-based mount confinement works with real node patterns:
pure Python, package resources, stdlib imports, host path blocking, and
import enforcement.

Changes:

1. **Chroot compatibility matrix** (5 scenarios, proven on CT 801):
   - Pure Python node: echo executes correctly under chroot
   - Package resource: data file in package dir accessible via /package bind mount
   - Stdlib imports: json, math, re, collections all work
   - Host path access: /etc/passwd blocked (FileNotFoundError)
   - Forbidden import: ctypes blocked by import enforcer

2. **CLI smoke proven**: `nodechain run --policy-preset hardened_untrusted
   --strict --trust-check` exits 0 on Linux.

3. **Blueprint-declared preset**: `hardened_untrusted_demo_v1.yaml`
   with `policy_preset: hardened_untrusted`.

4. **Docs**: Linux deployment guide updated with chroot compatibility
   notes, packaging guidance, and known limitations.

## [1.4.6] — 2026-06-14

### Mount Confinement Policy Completion

Governance and policy wiring for mount namespace chroot-based
filesystem confinement. Brings mount confinement to the same
governance level as network namespace, seccomp, and cgroups.

Changes:

1. **INV-012 strict**: Upgraded from advisory to capability-specific
   error. Fires when `mount_confinement_requested=true` but
   `mount_confinement_enforced=false`. Strict mode → exit 15.

2. **hardened_untrusted preset**: New policy preset = production_untrusted
   + mount confinement. Does NOT replace production_untrusted —
   production_untrusted remains broadly usable while hardened_untrusted
   is for nodes known to be chroot-compatible.

3. **NodeTrustRecord**: `mount_confinement_requested` field added.

4. **CLI views**: report/trust/inspect show mount confinement fields
   (mnt_conf_req, mnt_conf_enf, temp_root_created, allowed_mounts).

5. **PolicyPreset**: `mount_confinement_required` field wired into
   `to_runner_kwargs()` → `enable_mount_confinement=True`.

## [1.4.5] — 2026-06-14

### Mount Namespace Temp-Root Confinement

Filesystem confinement via mount namespace + chroot.

When `enable_mount_confinement=True`, the child process gets:
1. New mount namespace (CLONE_NEWNS)
2. Private mount propagation (MS_PRIVATE|MS_REC)
3. Per-invocation temp root
4. Bind-mounted package root → `/package`
5. Bind-mounted temp dir → `/tmp`
6. chroot to temp root

The child can only access `/package` and `/tmp`. Host paths like
`/etc/passwd` return `FileNotFoundError` — kernel-level filesystem
isolation.

Key distinction:
- `mount_namespace_enforced`: child has separate mount namespace
- `mount_confinement_enforced`: child filesystem view is restricted
  to only allowed mounts

Changes:

1. **`apply_mount_confinement()`**: unshare + private propagation +
   bind mounts + chroot.

2. **SubprocessRunner**: `enable_mount_confinement` parameter.
   Child bootstrap Phase 1b applies confinement before node import.

3. **Module path update**: After chroot, module path becomes
   `/package/<filename>` (bind-mounted path).

4. **NodeTrustRecord**: `mount_confinement_enforced`,
   `mount_confinement_error`, `temp_root_created`, `allowed_mounts`.

5. **INV-012**: `required_mount_confinement_must_be_enforced`
   (advisory — not required by any preset yet).

6. **Proven on CT 801**: echo node executes under chroot, host paths
   blocked, output correct.

## [1.4.4] — 2026-06-14

### Mount Namespace Reporting

Operator-visible mount namespace status across all CLI views.

Key changes:

1. **`report` CLI**: Shows mount_namespace_enforced state in namespace panel.

2. **`trust` CLI**: Per-node mount namespace fields (mnt_ns_requested,
   mnt_ns_enforced, mnt_ns_error).

3. **`inspect` CLI**: Shows mount_namespace_enforced in namespace panel.

4. **docs/frozen-surfaces.md**: Mount namespace fields documented
   additively for both NodeTrustRecord and SandboxCapabilities.

5. **docs/linux-deployment.md**: Mount namespace prototype documented
   in capability matrix and namespace behavior section. CLONE_NEWNS +
   private propagation proven; temp-root/pivot_root noted as not
   implemented.

## [1.4.3] — 2026-06-14

### Mount Namespace Prototype

First mount namespace isolation: `CLONE_NEWNS` + private mount propagation.

Scope is intentionally narrow: unshare mount namespace and make mounts
private. No `pivot_root`, bind mounts, or read-only rootfs yet.

Key changes:

1. **`apply_mount_namespace()`**: Unshares `CLONE_NEWNS`, then makes all
   mounts private (`MS_PRIVATE|MS_REC`). Mount events in child do not
   propagate to parent and vice versa.

2. **SubprocessRunner**: `enable_mount_namespace` parameter. When True,
   child bootstrap Phase 1a creates mount namespace before node import.

3. **RunnerConfig**: Carries `enable_mount_namespace` through the
   explicit config path.

4. **NodeTrustRecord**: `mount_namespace_requested`,
   `mount_namespace_enforced`, `mount_namespace_error` fields.

5. **SandboxCapabilities**: `mount_namespace_enforced` field.

6. **INV-011**: Extended to check mount namespace. If
   `mount_namespace_required=true` but not enforced, INV-011 fires.

7. **PolicyPreset**: `mount_namespace_required` field (False for all
   existing presets — this is a prototype, not required yet).

8. **Child bootstrap ordering**: mount ns after network ns, before seccomp.

No existing presets require mount namespace. Strict mode only hard-fails
if mount namespace is explicitly required (not for any current preset).

## [1.4.2] — 2026-06-14

### Namespace Reporting and Detection Consolidation

Human-readable reporting + complete namespace detection.

Key changes:

1. **`report` CLI**: Namespace status panel showing namespace_mode,
   already_nested, available namespace types, network_namespace_required.

2. **`trust` CLI**: Per-node namespace fields (net_ns_requested,
   net_ns_enforced, net_ns_error, namespace_mode).

3. **`inspect` CLI**: Namespace detection panel with mode, nested,
   available types.

4. **All 6 namespace types detected**: mount, pid, network, user,
   uts, ipc — each independently probed via subprocess `unshare`.

5. **Detection distinguishes**: available, already_nested,
   creation_allowed, enforced — clear state model.

6. **docs/frozen-surfaces.md**: INV-011 + namespace fields documented
   as additive v1.x surfaces.

7. **docs/linux-deployment.md**: Proxmox CT namespace behavior,
   updated capability matrix, strict mode INV-011 documentation.

## [1.4.1] — 2026-06-14

### Network Namespace Policy Completion

Makes namespace enforcement as auditable and strict as seccomp/cgroups.

Key changes:

1. **INV-011 capability-specific**: When a preset declares
   `network_namespace_required=True` but the child reports
   `network_namespace_enforced=false`, INV-011 fires as a **hard error**.
   No longer advisory.

2. **Strict mode hard-fails**: INV-011 is now severity=error by default.
   If namespace creation fails while the preset requires it, strict mode
   produces exit code 15 (trust violation).

3. **NodeTrustRecord fields added**: `network_namespace_requested`,
   `network_namespace_error` for full auditability.

4. **TrustSummary reports**: namespace_available, namespace_mode,
   already_nested, network_namespace_requested, network_namespace_enforced,
   network_namespace_error.

5. **Negative test**: Simulated namespace failure produces INV-011
   violation.

6. **Physical isolation test**: Socket connection attempt fails under
   network namespace even without Python network hooks.

7. **docs/frozen-surfaces.md updated**: INV-011, namespace fields,
   v1.4.0/1.4.1 entries.

## [1.4.0] — 2026-06-14

### Linux Namespace Confinement

First namespace enforcement layer: network namespace isolation.

When `production_untrusted` preset is active, the child process gets
a new network namespace with no interfaces, making network access
impossible at the kernel level.

This is the strongest enforcement layer:
```text
Layer 1 (strongest):  network namespace isolation (v1.4.0) + seccomp
Layer 2:              cgroup v2 resource limits
Layer 3:              filesystem/subprocess/network Python enforcers
Layer 4:              import enforcement with preloaded denylist
```

Key changes:

1. **`sdk/namespace_profile.py`**: NamespaceCapabilities detection,
   `apply_network_namespace()`, per-type namespace availability.
   Proven on Proxmox CT 801: all 6 namespace types creatable.

2. **Network namespace enforcement**: `os.unshare(CLONE_NEWNET)` in
   child bootstrap Phase 1a. Child gets new netns with only `lo`
   (down). Socket connections fail with OSError.

3. **PolicyPreset integration**: `production_untrusted` now declares
   `network_namespace_required=True`. RunnerConfig passes
   `enable_network_namespace` through the call chain.

4. **SandboxCapabilities**: 9 namespace fields (namespace_available,
   namespace_mode, already_nested, mount/pid/network/user namespace
   availability, network_namespace_enforced).

5. **NodeTrustRecord**: 3 namespace fields (namespace_available,
   network_namespace_enforced, namespace_mode).

6. **INV-011**: `required_namespace_confinement_must_be_enforced`
   (advisory for os_profile nodes).

## [1.3.9] — 2026-06-14

### Resource Governance Consolidation

Final consolidation of the v1.3 resource-governance line.

#### RunnerConfig refactor

1. **`RunnerConfig` class**: Explicit configuration object replacing
   hidden env-var coupling. Created from `PolicyPreset` via
   `RunnerConfig.from_preset()` or manually.

2. **Explicit config flow**: CLI → `RunnerConfig` → `run_chain()` →
   `Orchestrator(runner_config=...)` → `NodeInvoker(runner_config=...)` →
   `get_subprocess_runner(config=...)` → `SubprocessRunner`.

3. **Env vars as external inputs only**: `NODECHAIN_POLICY_PRESET`
   remains as CLI input and backward-compatible fallback in
   `get_subprocess_runner(config=None)`. The internal transport is now
   explicit config objects.

4. **Human-readable report**: `nodechain report` now displays a
   Policy Preset & Enforcement panel showing preset, source, sandbox
   profile, seccomp status, and cgroup limits.

#### v1.3.0 → v1.3.8 progression

| Version | Focus |
|---------|-------|
| v1.3.0  | Cgroup v2 detection + accounting |
| v1.3.1  | Per-invocation cgroup lifecycle (INV-008 fix) |
| v1.3.2  | Cgroup limit enforcement (INV-009) |
| v1.3.3  | Behavioral pressure evidence + policy presets |
| v1.3.4  | Pressure proof with explicit assertions |
| v1.3.5  | Preset productization (INV-010) |
| v1.3.6  | Preset drives actual runner config |
| v1.3.7  | All 3 presets proven e2e |
| v1.3.8  | Full CLI smoke proven |
| v1.3.9  | RunnerConfig refactor + consolidation |

## [1.3.8] — 2026-06-14

### Policy Preset Release Smoke

Full CLI smoke and display polish completing the v1.3 preset line.

Key changes:

1. **Full CLI smoke proven on Linux**: `nodechain run --blueprint
   production_untrusted_demo_v1.yaml --strict --trust-check` completes
   successfully (exit 0). Tests the full path: CLI resolver →
   orchestrator → invoker → SubprocessRunner → seccomp → cgroup →
   TrustSummary → trust-check exit code.

2. **CLI override smoke**: `--policy-preset minimal` overrides blueprint
   `production_untrusted` deterministically.

3. **inspect CLI preset display**: Shows Policy Preset, Preset Source,
   Sandbox Profile in a dedicated panel.

4. **Demo blueprint fixed**: Single-node echo chain compatible with
   subprocess isolation, no model adapter required.

5. **Operator recipe**: README documents preset usage with examples.

## [1.3.7] — 2026-06-14

### Policy Preset E2E Completion

End-to-end proof for all three presets with real enforcement evidence.

Key changes:

1. **standard_untrusted e2e proven on Linux**: `seccomp_enforced=true`,
   `syscall_filtering_enforced=true`, `seccomp_profile_name=nodechain_default`.

2. **production_untrusted e2e proven on Linux**: seccomp + cgroup limits
   all enforced in a single invocation (512MB, 50 pids, 200000 cpu quota).

3. **Blueprint-declared preset**: resolver sets env vars from blueprint
   `policy_preset` field without manual pre-setting.

4. **CLI override determinism**: `--policy-preset` overrides blueprint
   declaration. No preset when neither declares one.

5. **TrustSummary evidence**: reports actual enforced capabilities
   per node (seccomp, cgroup, memory, pids, cpu).

## [1.3.6] — 2026-06-14

### Policy Preset Runtime Wiring

Presets now drive actual subprocess runner configuration.

Key changes:

1. **`get_subprocess_runner()` reads preset**: When
   `NODECHAIN_POLICY_PRESET` is set, the factory calls
   `preset.to_runner_kwargs()` to configure cgroup limits, pids max,
   and cpu quota.

2. **End-to-end enforcement**: `--policy-preset production_untrusted`
   now produces: `enable_cgroup=True`, `cgroup_memory_max_mb=512`,
   `cgroup_pids_max=50`, `cgroup_cpu_max_quota=200000`.

3. **Demo blueprint**: `blueprints/production_untrusted_demo_v1.yaml`
   with `policy_preset: production_untrusted`.

4. **CLI display**: `trust` command shows `Policy preset`, `Preset source`,
   cgroup limit fields. `report` JSON includes preset info.

5. **Invariant layer compares evidence**: INV-010 checks actual
   `NodeTrustRecord` evidence (seccomp_enforced, cgroup_limits_enforced)
   against preset requirements, not just declared config.

## [1.3.5] — 2026-06-14

### Policy Preset Productization

Operator-facing policy presets with CLI integration, blueprint declaration,
and deterministic resolution order.

Key changes:

1. **CLI `--policy-preset`**: `minimal|standard_untrusted|production_untrusted`
   via `nodechain run --policy-preset production_untrusted`

2. **Blueprint declaration**: `policy_preset` field in chain_blueprint.yaml/json

3. **Deterministic resolution**: CLI override → blueprint → default (none)

4. **`presets` CLI command**: `nodechain presets` lists all available presets

5. **TrustSummary**: reports `policy_preset`, `preset_source`

6. **INV-010**: `preset_requirements_must_be_satisfied` — checks that the
   declared preset's seccomp/cgroup requirements are met by the runtime.

7. **`production_untrusted`** requires: os_profile, seccomp, cgroup limits
   **`standard_untrusted`** requires: os_profile, seccomp
   **`minimal`**: current behavior (subprocess isolation only)

8. **Strict mode enforces declared requirements, never invents them.**

9. **frozen-surfaces.md**: INV-010, NODECHAIN_POLICY_PRESET/SOURCE env vars,
   policy preset table, pressure evidence fields documented.

## [1.3.4] — 2026-06-14

### Cgroup Pressure Proof

Explicit kernel-outcome assertions for cgroup limit enforcement.

Key changes:

1. **OOM test strengthened**: uses unreclaimable anonymous memory
   (mmap with page-touching) to create real OOM pressure. Test
   accepts either oom_kill (child killed) or max > 0 (reclamation).

2. **CPU throttling asserted**: `nr_throttled > 0` or
   `throttled_usec > 0` now explicitly asserted, not just field presence.

3. **TrustSummary pressure evidence** (6 new fields):
   - `memory_events_max`, `memory_events_oom`, `memory_events_oom_kill`
   - `cpu_nr_throttled`, `cpu_throttled_usec`
   - `pids_limit_denied`

4. **CgroupAccounting fields**: `oom_events`, `oom_kill_events` parsed
   from `memory.events`.

5. **memory.events counters**: parsed and available in accounting output.

## [1.3.3] — 2026-06-14

### Cgroup Limit Behavior Under Pressure

Proves runtime behavior when child processes hit cgroup limits.

Key changes:

1. **Memory OOM behavior**: child exceeding memory.max is killed by
   the kernel. Test proves OOM kill + cgroup cleanup.

2. **pids.max behavior**: child forking beyond pids.max has fork
   denied. Test proves fork failure + cleanup.

3. **CPU throttling evidence**: CPU-bound child under tight quota shows
   throttling counters (nr_throttled, throttled_usec) in cpu.stat.

4. **Cleanup after kernel kill**: explicit test verifies cgroup directory
   removed after kernel-killed child.

5. **CgroupAccounting extended**: cpu_nr_periods, cpu_nr_throttled,
   cpu_throttled_usec, oom_events, oom_kill_events from cpu.stat and
   memory.events.

6. **NodeTrustRecord extended**: cgroup_oom_kill_observed,
   cgroup_cpu_throttling_observed, cgroup_pids_limit_observed.

7. **Policy presets**: production_untrusted, standard_untrusted, minimal.
   Presets declare requirements — strict mode enforces declared
   requirements but does not auto-create resource policy.

## [1.3.2] — 2026-06-14

### Cgroup Limit Enforcement

Per-invocation cgroup resource limits (memory.max, pids.max, cpu.max)
applied to child cgroups with enforcement reporting.

Key changes:

1. **SubprocessRunner applies limits**: `cgroup_memory_max_mb`,
   `cgroup_pids_max`, `cgroup_cpu_max_quota` parameters write to the
   invocation cgroup via CgroupLimits.

2. **Limit enforcement tracking**: `cgroup_limits_requested` and
   `cgroup_limits_enforced` reported per invocation. `_finalize_cgroup()`
   reports all six limit fields: requested, enforced, memory_max_mb,
   pids_max, cpu_max_quota, accounting_scope.

3. **INV-009**: `required_cgroup_limits_must_be_enforced` — fires when
   cgroup limits are requested but not enforced.

4. **NodeTrustRecord extended**: `cgroup_limits_requested`,
   `cgroup_memory_max_mb`, `cgroup_pids_max`, `cgroup_cpu_max_quota`.

5. **NodeInvoker propagation**: All limit fields propagated to response
   metadata.

6. **Killed-child cleanup test**: Timeout path cgroup removal verified.

7. **Doc fixes**: ARCHITECTURE.md metadata updated to v1.3.x;
   linux-deployment.md duplicate validation lines collapsed.

## [1.3.1] — 2026-06-13

### Per-invocation Cgroup Runtime Integration

Child cgroup lifecycle for per-node resource accounting on Linux.

Key changes:

1. **INV-008 fixed** — changed from `required_resource_accounting_must_be_available`
   (cgroup-specific, Linux-only) to `required_os_capability_must_be_available`
   (platform-neutral). Fires only when NO OS enforcement capability exists.
   RLIMIT alone satisfies it on Linux; Job Objects alone on Windows.

2. **Explicit capability requirements** — `required_os_capabilities` field on
   NodeTrustRecord: `["cgroup_accounting"]`, `["seccomp"]`, `["job_object"]`, etc.

3. **Per-invocation child cgroups** — SubprocessRunner creates a child cgroup
   per node invocation, moves the child process into it, reads accounting after
   execution, and cleans up on all exit paths (success, failure, timeout).

4. **Cgroup accounting scope** — `cgroup_accounting_scope` field distinguishes
   `"parent"` (container-level) from `"invocation"` (per-node).

5. **NodeInvoker propagation** — cgroup_accounting, cgroup_path,
   cgroup_accounting_scope propagated to response metadata.

6. **NodeTrustRecord extended** — `cgroup_limits_enforced`,
   `cgroup_accounting_scope`, `required_os_capabilities`.

## [1.3.0] — 2026-06-13

### Cgroup v2 Resource Accounting

Real cgroup v2 detection, accounting, and limit reporting on Linux.

Key changes:

1. **CgroupProfile module** (`sdk/cgroup_profile.py`): Detects cgroup v2,
   reads resource accounting (memory.current/peak, cpu.stat usage, pids),
   reports capabilities independently (available/accounting_readable/
   limits_writable/accounting_only).

2. **Honest Proxmox LXC reporting**: Distinguishes:
   - detected (cgroup v2 filesystem exists)
   - accounting readable (can read memory/cpu/pid stats)
   - limits writable (can create child cgroups and write limits)
   - accounting_only (read-only delegation)

3. **SandboxCapabilities extended**: cgroup_available, cgroup_version,
   cgroup_accounting_readable, cgroup_limits_writable, cgroup_accounting_only.

4. **NodeTrustRecord extended**: Same 5 cgroup fields.

5. **INV-008**: `required_resource_accounting_must_be_available` — fires
   when os_profile is required but cgroup is unavailable.

6. **CLI report**: sandbox_status includes cgroup capability info.

7. **LinuxBackend.get_capabilities()**: Propagates cgroup detection.

## [1.2.6] — 2026-06-13

### Linux Seccomp Consolidation

Documentation consolidation for the seccomp milestone series (v1.2.2–v1.2.5).

Key updates:

1. **README** — Trust Model section now documents 7 enforcement surfaces
   including Linux seccomp. Honest Boundaries rewritten to distinguish
   what NodeChain provides vs what is planned. INV-001..007 documented.
   Status updated to v1.2.5.

2. **ARCHITECTURE.md** — Enforcement layers updated to 9 layers.
   Bootstrap order documented (Phase 1 through Phase 4). Sandbox
   capability layers distinguished (resource limits vs seccomp vs
   namespaces vs cgroups vs AppArmor). INV-001..007 table.

3. **docs/linux-deployment.md** — Validation results updated with
   v1.2.5 evidence: seccomp_enforced=True, syscall_filtering=True,
   1379 Linux tests.

4. **docs/frozen-surfaces.md** — INV-006 and INV-007 added.

5. **CLI trust output** — Seccomp fields shown in node trust records.

## [1.2.5] — 2026-06-13

### Seccomp Productization

CLI and policy layer now auto-enable seccomp on Linux.

Key changes:

1. **BaseNode.isolation_config** — Auto-enables seccomp on Linux for
   untrusted nodes. Orchestrator reads node._trust_level and passes
   isolation_config to NodeInvoker.

2. **allow_preloaded denylist** — Sensitive modules (ctypes, runpy,
   multiprocessing, code, pdb) are ALWAYS blocked to untrusted nodes,
   even when allow_preloaded=True and they are in sys.modules.

3. **Blocked-syscall kill test** — Proves fork() is denied in a child
   process with seccomp active. Test runs entirely in a subprocess
   so seccomp never contaminates the pytest process.

4. **Orchestrator wiring** — _invoke_node passes trust_level and
   isolation_config to NodeInvoker.invoke().

## [1.2.4] — 2026-06-13

### Seccomp Policy Completion — Import Enforcement Ordering Fixed

Import enforcement is now active BEFORE the untrusted node module is imported.
The `_loading_trusted_deps` global flag has been replaced with a per-enforcer
`allow_preloaded` parameter. In the subprocess child, import enforcement
activates in Phase 1c with `allow_preloaded=True` — trusted framework
dependencies already in `sys.modules` bypass the policy, but NEW imports
of dangerous modules not in `sys.modules` are still blocked.

Bootstrap ordering is now:
  Phase 1:  Import trusted SDK + create event loop
  Phase 1b: Apply seccomp filter (Linux)
  Phase 1c: Activate ALL enforcement (import + fs + subprocess + network)
  Phase 2:  Import untrusted node module (under ALL enforcement)
  Phase 3:  Execute node
  Phase 4:  Report + deactivate

There is no longer a separate Phase 2b — import enforcement is NOT deferred.

## [1.2.3] — 2026-06-13

### Seccomp Runtime Integration

Real seccomp enforcement integrated into NodeInvoker child execution path.
Safe bootstrap ordering: node module imported after seccomp + OS enforcement.

## [1.2.2] — 2026-06-13

### Seccomp Backend Validation

Seccomp enforcement proven on real Linux. SeccompBackend.apply_profile() fixed
for pyseccomp API. enable_seccomp flag added to SubprocessRunner.

## [1.2.1] — 2026-06-13

### Linux Proxmox Baseline

Deployment tooling and validation scripts for real Linux VM execution.

New files:
- `scripts/setup_linux.sh`: automated VM setup (Python, venv, seccomp detection)
- `scripts/validate_linux.sh`: full validation suite with honest capability report
- `docs/linux-deployment.md`: Proxmox VM guide, Docker, systemd, seccomp instructions
- `Dockerfile`: updated for production (Python 3.11, libseccomp, healthcheck, labels)

The user must create the VM on Proxmox and run the scripts. This tag prepares
the tooling — actual Linux validation happens on the VM.

**1353 tests, 3 skipped.**

---

## [1.2.1] — 2026-06-13

### Linux Proxmox Baseline — VALIDATED

Proxmox LXC container created and NodeChain validated on real Linux.

Container details:
- Proxmox CT 801, hostname `nodechain`, IP 192.0.2.100
- Ubuntu 24.04 LTS, Python 3.12.3, kernel 6.8.12-13-pve
- libseccomp-dev + pyseccomp installed
- nesting=1, keyctl=1 features enabled

Validation results on Linux:
- 1345 passed, 11 skipped, 0 failed
- `resource_limits_enforced: True` (RLIMIT real on Linux)
- `seccomp_available: True` (pyseccomp detected)
- `seccomp_enforced: False` (detection only, not auto-enforced)
- All CLI commands pass: run --locked --strict --trust-check, trust, report, reconcile

Fix: LinuxBackend.get_capabilities() now propagates seccomp_available from
the SeccompBackend instead of hardcoding False.

New files:
- `scripts/setup_linux.sh`: automated VM setup
- `scripts/validate_linux.sh`: full validation suite
- `docs/linux-deployment.md`: Proxmox deployment guide
- `Dockerfile`: production-ready container image

**1353 tests (Windows), 1345 tests (Linux), 3/11 skipped respectively.**

---

## [1.2.0] — 2026-06-13

### Linux Seccomp Profile

Optional syscall filtering for Linux untrusted node execution.

New features:
- `SeccompProfile`: declarative deny-list with 20 dangerous syscalls
  (fork, clone, ptrace, mount, reboot, kexec, init_module, unshare, bpf, etc.)
- `SeccompBackend`: detects `seccomp`/`pyseccomp` Python library on Linux
- `SandboxCapabilities` extended: `seccomp_available`, `seccomp_enforced`, `seccomp_profile_name`
- `INV-007`: `required_sandbox_capability_must_be_enforced` — fires when OS profile claimed but backend empty/none
- 29 seccomp profile tests + 1 Linux-only skip
- Clean behavior on non-Linux (detection only, no crash)

**1323 tests, 3 skipped.**

---

## [1.1.1] — 2026-06-13

### OS Profile Reporting Hardening

Granular capability reporting so claims match what is actually enforced.

New features:
- `SandboxCapabilities` dataclass with 9 independently-verifiable fields
- Each backend reports `get_capabilities()` with honest enforcement status
- `resource_limits_enforced` separated from `syscall_filtering_enforced`
- macOS explicitly reports `detection_only=True`
- Windows reports `job_object_enforced=True` when available
- Linux reports `resource_limits_enforced=True` but does NOT claim seccomp/namespaces/cgroups
- `SandboxResult.capabilities` field included in all resolver results
- `describe()` includes `granular_capabilities` dict
- 29 reporting hardening tests

**1294 tests, 2 skipped.**

---

## [1.1.0] — 2026-06-13

### OS Sandbox Profiles

Additive layer on top of v1.0.0. No breaking changes.

New features:
- `SandboxProfile` model: `none`, `python_hooks`, `subprocess_isolated`, `os_profile`
- `SandboxProfileResolver` with fallback logic and strict-mode enforcement
- Platform-specific backends: Linux (RLIMIT), Windows (Job Objects via ctypes), macOS (detection only)
- `ResourceLimits` model: CPU time, memory, output size, wall timeout, temp storage, process count
- `INV-006`: `required_sandbox_profile_must_be_used` — fires when required profile is downgraded
- `--sandbox-profile` CLI flag on `run` command
- `NodeTrustRecord` extended with `sandbox_profile_required`, `sandbox_profile_used`, `os_sandbox_enforced`, `fallback_used`, `sandbox_backend`
- `NODECHAIN_SANDBOX_PROFILE` environment variable
- 30 OS sandbox tests + 1 platform-conditional skip

**1265 tests, 2 skipped.**

---

## [1.0.0] — 2026-06-13

### Stable Release

Frozen public surface contract (`docs/frozen-surfaces.md`):
- CLI: 9 top-level commands, all flags documented
- Exit codes: 10 codes (0, 1, 2, 3, 10, 11, 12, 13, 14, 15)
- Trust invariants: INV-001 through INV-005
- Trust levels: built_in, local_trusted, local_untrusted, remote_untrusted
- Blueprint schema v1, package manifest schema v1
- 11 environment variables documented
- Migration notes from v0.x

Release hardening (40 tests):
- All CLI commands verified against known-good fixtures
- frozen-surfaces.md verified against actual CLI help and schemas
- README boundaries honest: local platform, Python-level sandbox, not OS/kernel
- Architecture document covers all subsystems

**1230 tests, 1 skipped (symlink on Windows).**

---

## [1.0.0-rc1] — 2026-06-13

### Release Candidate

All public surfaces frozen:
- CLI surface frozen and verified
- Package manifest schema v1 frozen
- Blueprint schema v1 frozen
- Trust invariant codes frozen (INV-001..005)
- Exit-code table frozen
- Canonical architecture document with trust model and honest boundaries

31 release smoke tests across 9 verification classes.

**1190 tests.**

---

## [0.9.0] — 2026-06-13

### Governed Local Trust Platform

Consolidation milestone. Six tasks:
1. Exit-code audit: all `sys.exit(1)` replaced with structured constants
2. Trust demo scripts (`demo_trust.sh` / `.bat`)
3. README Trust Model section with honest boundaries
4. README exit-code table with all 10 codes
5. Version bumped to 0.9.0 everywhere
6. 13 consolidation tests

**1159 tests.**

---

## [0.8.2] — 2026-06-13

### Trust CI and Run Gates

- `--trust-check` flag on `run` command: post-execution trust validation
- `--strict` + `--trust-check` exits 15 on violations
- `EXIT_TRUST_VIOLATION = 15` added to exit codes
- All exit codes distinct and stable
- 14 CI gate tests

**1146 tests.**

---

## [0.8.1] — 2026-06-13

### Trust Invariant Enforcement

Five structured invariant codes:
- `INV-001`: untrusted requires `isolation_mode=subprocess`
- `INV-002`: untrusted requires `child_policy_enforced=true`
- `INV-003`: subprocess requires `env_filtered=true`
- `INV-004`: subprocess requires `temp_dir_isolated=true`
- `INV-005`: locked mode requires `lockfile_verified=true`

`TrustViolation` dataclass with code, severity, node_id, invariant, expected, actual.
`is_compliant` delegates to `validate_invariants(strict=False)`.
`nodechain trust --strict` exits nonzero on error violations.

**1132 tests.**

---

## [0.8.0] — 2026-06-13

### Trust Runtime Consolidation

- `TrustSummary` model with per-node records (15 fields)
- `is_compliant` property checking untrusted nodes have subprocess isolation
- Trust summary in report CLI
- Reconciler trust check (advisory)
- CLI `trust` command
- 17 consolidation tests

**1114 tests.**

---

## [0.7.0]–[0.7.3] — 2026-06-12/13

### Process-Isolated Node Execution

- `SubprocessRunner`: nodes execute in isolated OS subprocess
- `InvocationEnvelope` serialized as JSON over stdin/stdout
- Timeout (30s), output-size limit (10MB), memory limit (512MB)
- Child policy enforcement: all four enforcers installed in child before execution
- Bootstrap ordering: import → event loop → enforce → execute → report
- Environment filtering strips secrets (API_KEY, SECRET, TOKEN, etc.)
- Per-invocation temp directory with cleanup on all exit paths
- `close_fds=True` to prevent fd leakage

**1097 tests at v0.7.3.**

---

## [0.6.0] — 2026-06-12

### Python-Level Sandbox

Release version guard (6 checks). CLI version dynamic from `__version__`.
Unified `sandbox_status` in report. `sandbox_test_node` demo node. `sandbox_demo_v1` blueprint.

**1057 tests.**

---

## [0.5.0]–[0.5.10] — 2026-06-12

### Package Trust and Runtime Interception

- `TrustLevel` enum, `ExecutionPolicy` per level
- `ImportEnforcer`: hooks `__import__` via contextvars
- `FilesystemEnforcer`: hooks `builtins.open`, `pathlib.Path.open`, `os.open/stat/listdir/mutation`
- `SubprocessEnforcer`: intercepts Popen/run/call/async/os.system/popen
- `NetworkEnforcer`: intercepts socket/DNS/SSL/urllib/http.client
- `NodeInvoker` quadruple enforcement: import + filesystem + subprocess + network
- Path traversal blocked, symlink escape blocked

**1047 tests at v0.5.10.**

---

## [0.4.0] — 2026-06-12

### Local Extensibility Platform

Consolidation of SDK, registry, templates, compatibility checker.

**858 tests.**

---

## [0.3.0]–[0.3.8] — 2026-06-12

### SDK and Local Registry

- `NodePackage`, `RegistryIndex`, CLI commands
- `MultiNodePackage` (`package.yaml` format)
- `PackageCapabilities`, `PackageDependencies`, `NodeEntrypoint`
- `PackagePolicyEnforcer` with version gate
- Registry lockfile: `generate_lockfile()` / `verify_lockfile()` with SHA-256 content hash
- Provenance hardening: content hash covers all files

**858 tests at v0.3.8.**

---

## [0.2.0] — 2026-06-12

### Developer/Operator Runtime

- StepAllocator + InvocationIdentity for concurrency-safe execution identity
- GraphScheduler, BranchExecutor, NodeInvoker, PolicyGate, PersistenceCoordinator
- ReviewManager, TraceReconciler, ValidationPipeline, InvariantEngine
- FailureManager, TraceEmitter
- Parallel branches (asyncio.gather), merge strategies
- Loop enforcement (entry/exit/budget)
- Durable cost accounting via invocation ledger
- Quorum branch scheduling
- Interactive review, pause/resume
- CLI: run, inspect, reconcile, resume, report, trace
- Structured exit codes

**676 tests.**

---

## [0.1.0] — 2026-06-12

### Governed Runtime Kernel

- 12 Harness Nodes (goal interpreter → response generator)
- 5 academic search adapters (Semantic Scholar, arXiv, OpenAlex, CrossRef, PubMed)
- Domain router, model adapter (LIM)
- Runtime orchestrator with blueprint-driven execution
- Contract validation, policy gate, invariant engine
- Schema/semantic/confidence validation
- Trace emission + reconciliation
- Human review workflow
- Side-effect journaling

**481 tests.**

