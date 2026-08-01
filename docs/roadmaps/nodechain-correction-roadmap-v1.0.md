# NodeChain Correction Roadmap v1.0 — Frozen

**Canonical pre-history-decision planning base:** `bceba2aa3fa0c520820c7252ae9609b6c31f0f67`
**Status:** Phase 0 blocked — pending C0 security classification, history decision, and Linux containment rebaseline/repair.
**Relationship:** Dependency gate for the NodeChain Master Roadmap v1.0. Phase 1 production implementation and release depend on Phase 0 exit; user research, workflow validation, Workspace design, prototype testing, and product-evidence collection may continue in parallel, provided they do not introduce new substrate or production execution paths.

---

## 1. Purpose

This roadmap defines **what must be corrected, consolidated, removed, qualified, and documented** before NodeChain's foundation is coherent enough to support production work. It is the concrete content of Master Roadmap Phase 0.

It does not introduce product features. It does not advance capabilities. Every item here exists because the substrate currently violates one of: the singular-runtime-truth rule (Master Rule 4), the no-silent-weakening rule (Master Rule 9), or a Phase 0 required outcome that verification showed unmet.

---

## 2. Governing evidence (verified)

| Finding | Source | Status |
|---|---|---|
| At the prior base `42fb701b`, 16 containment tests failed on the privileged CT 801 suite (root) | Privileged pytest run, fresh GitHub clone @ `42fb701b` | Verified; **current count at `bceba2aa` not yet rebaselined** |
| Root cause hypothesis: cgroup-v2 false-negative (host has cgroup2fs; runtime reports "container without cgroup v2") | `stat -fc %T /sys/fs/cgroup` = `cgroup2fs` on CT 801; runtime emits `containment_unavailable` | Verified environment; **hypothesis to be confirmed at rebaseline** |
| Rule 4 breaks at 3 seams: `chain_orchestrator.py` ghost path, trace dual-write, direct state mutation | Source-read at `chain_orchestrator.py:1,268`, `research_eval_runner.py:122`, orchestrator direct `self.trace` appends | Verified |
| `.ouroboros/state.db` (159MB current) reachable in history from all 4 active branches + signed `v3.5.0` tag | Corrected all-ref reachability procedure; introducing commit `8e34269e` | Verified; **multi-version classification pending** |
| Two large modules under correction pressure: `exec_supervisor.py`, `orchestrator.py` (`run()`, `resume()`) | `wc -l`, git trajectory | Verified |
| Windows unqualified (CI `continue-on-error`, no namespace/seccomp analog, no `docs/windows-*`) | `.github/workflows/ci.yml:218-229`, source inspection | Verified |

---

## 3. C0 gates (blocking — must close before Phase 0 exit)

C0 items are security-class. **C0.1 must precede C0.2. C0.3 may execute in parallel. All three block Phase 0 exit, but they do not prevent independent workstreams from being implemented and accepted.** Otherwise repository-history analysis could unnecessarily stall the most important runtime correction.

### C0.1 — Classify every historical `state.db` blob

**Why blocking:** A 159MB SQLite database is reachable in git history from every active branch and the signed `v3.5.0` tag. The file was modified across history, so the current local copy may not contain data that existed in earlier committed versions. Until every historical version is classified, the statement "no secret in history" cannot be made (Master Rule 9).

**Procedure (no values printed):**
1. Inventory all unique historical blob SHAs for `.ouroboros/state.db` across every reachable ref.
2. Extract each unique blob into an offline, access-controlled temporary directory.
3. Verify each extracted object's SHA.
4. Inspect schema, tables, row counts, column categories, and secret-pattern findings without printing values.
5. Report the data categories found in each unique version (or prove versions differ only in non-sensitive structural/generated data).
6. Securely remove temporary extracted copies after the report is accepted.
7. Use the preserved local database only as an additional current-state sample.

**Exit:** A classification report covering **the historical object set** — every unique blob — with per-version data-category verdict. Final verdict: the historical set is **sensitive** or **non-sensitive**.

### C0.2 — Decide whether history rewriting is required

**Why blocking:** Depends on C0.1. If any historical version is sensitive, rewrite is mandatory regardless of cost. If all versions are non-sensitive, the cost (4-branch rewrite, v3.5.0 re-sign, mass re-clone, planning-base re-pin) may exceed benefit.

**Governing inventory (corrected, verified):** The blob set is reachable from:
- `master`, `review/v3.5.1-t1-supervised-argv`, `fix/v3.5.1-production-hardening`, `study/v3.5-retry-authorized-execution`
- All `origin/*` mirrors of the above
- Signed annotated tag `v3.5.0` (signature will break on rewrite)
- 258 other tags (v1.18.3 → v3.4.0) are unaffected

**Sensitive-data response:** If C0.1 identifies actionable sensitive content, the applicable incident response must begin before the history rewrite. This includes credential revocation or rotation, access and exposure assessment, and notification or legal handling where applicable. History rewriting removes the material from the canonical repository history; it is not evidence that prior clones, caches, mirrors, or downloaded copies no longer contain it.

**Rewrite execution policy (outcome frozen, command not):**

If rewriting is required, execute it only from an offline, verified mirror backup under a separately approved runbook. The runbook must rewrite every affected branch and tag identified by the final reachability inventory, including the signed `v3.5.0` tag, without rewriting unaffected refs unnecessarily.

The provisional implementation mechanism is `git filter-repo` with `.ouroboros/state.db` excluded. The exact ref scope and command are determined from the mirror's final ref inventory immediately before execution.

**Mandatory post-rewrite proofs:**

- `git rev-list --objects --all` no longer exposes any historical `state.db` blob.
- Every intended branch and tag points to its expected rewritten equivalent.
- Unaffected tags retain their original object identities.
- `v3.5.0` is recreated and re-signed, or explicitly replaced under a documented release-integrity decision.
- A fresh clone does not download or expose the removed database objects.

This roadmap does not authorize the rewrite itself. It authorizes creation and approval of the runbook after C0.1.

**Exit:** A documented decision with rationale. If rewrite: executed per the approved runbook with mirror backup, v3.5.0 re-sign, and re-clone instructions; all post-rewrite proofs satisfied. If no rewrite: explicit acceptance that historical `state.db` versions remain in history with recorded justification.

**Stability note:** Until C0.2 closes, no branch SHA, tag SHA, or roadmap base may be treated as stable. `bceba2aa` is the pre-history-decision planning base only.

### C0.3 — Rebaseline and close CT 801 containment failures

**Why blocking:** NodeChain's headline property is governed containment. On the privileged CT 801 qualification profile, containment did not engage at `42fb701b`: the runtime reported cgroup v2 as unavailable on a host that exposed cgroup v2. A capability-detection defect is the leading hypothesis, to be confirmed through the current-SHA rebaseline and diagnosis. Phase 0 outcome #1 (production path for untrusted workloads) and #6 (qualified Linux behavior) are both unmet.

**Evidence statement (corrected):**

> At `42fb701b`, the privileged CT 801 suite produced 16 failures. The exact current failure inventory at `bceba2aa` has not yet been captured. C0.3 begins by reproducing the complete suite from a fresh GitHub clone at the current planning SHA and recording the new baseline.

Do not assume the current total is still 16. Preserve the original result as historical evidence, but re-run before planning individual repairs. The FD endpoint-policy test was corrected at `5ef742e` (now in `bceba2aa`), so at least that one failure is already resolved.

**Procedure:**
1. From a fresh GitHub clone at `bceba2aa`, run the full supervised-exec/sandbox/PID-namespace family on the privileged CT 801 profile as root with `NODECHAIN_NATIVE_RUNNER=1`. Record the new failure inventory.
2. Locate the cgroup-v2 detection function (the probe that returns "container without cgroup v2").
3. Diagnose why it mis-detects on a host where `stat -fc %T /sys/fs/cgroup` = `cgroup2fs` and `cgroup.controllers` exists.
4. Repair the probe.
5. Re-run and characterize remaining failures (the CWD cluster likely shares the root cause; mock-drift ones are independent).

**Exit:** The supervised-exec/sandbox/PID-namespace family passes on the privileged CT 801 profile. Skips on non-Linux hosts remain correctly labeled as skips, not passes (change-control rule 6).

---

## 4. Phase 0 workstreams

Each workstream maps to a Phase 0 required outcome. Order reflects dependency, not priority. All may proceed in parallel with C0 where they don't depend on a C0 outcome.

### WS-1 — One governed untrusted-execution backend (Phase 0 outcomes #1, #4)

The goal is one execution authority, not deletion of every existing facade.

- `SubprocessRunner` may remain as a public compatibility facade, but it must delegate untrusted Linux execution to the supervised backend and contain no independent weaker implementation.
- `chain_orchestrator.py` may remain only as a thin adapter over the governed orchestrator. It must not directly call arbitrary `node.execute()` outside policy, journaling, trace, and state authorities.
- Silent fallback to an unsupervised implementation is forbidden.
- Trusted local utilities must be explicitly classified and must not be callable through the untrusted-execution contract.
- Finish **T3** (SubprocessRunner routing + result mapping through supervised exec).

**Exit criterion:** Exactly one governed backend owns untrusted execution. Any remaining modules are adapters or explicitly trusted utilities, not parallel authorities.

### WS-2 — One durable trace-emission authority (Master Rule 4)

**Exit criterion:** All trace events pass through one emission authority. Each accepted event has one stable event identity, is durably appended before acknowledgement, and is projected into live views from the same logical record. The live trace can be rebuilt from durable evidence, and no direct append path bypasses durability.

Concretely: kill the 7 direct `self.trace.add_event` calls in orchestrator (incl. `resume()` path at line 1083) that bypass `TraceEmitter` and never reach the durable log; route `RecoveryService` operator/outcome events (`recovery_service.py:690, 728`) through the same emitter so they enter the live `ChainTrace` from the same durable record.

### WS-3 — One authoritative state-transition coordinator (Master Rule 4)

**Exit criterion:** Every authoritative chain-state transition passes through one transition coordinator. A transition is durably committed before it is treated as successful. After interruption, recovery reconstructs the last accepted state deterministically. Ephemeral calculations may remain in memory but cannot become authoritative state through direct field mutation.

Concretely: replace direct `ChainState` field mutation (`orchestrator.py:216, 507, 743, 1095, 1707`) with transition-coordinator calls. The previous "in-memory == durable at all times" framing is rejected as impossible — transactions legitimately have transient in-memory projections while being prepared; the actual requirement is durability-before-acknowledgement.

### WS-4 — Gate-relevant responsibility extraction

**Scope:** Only extractions that close a named authority or testability gap. General code cleanup, method-size reduction, naming, and stylistic decomposition are deferred unless directly required by another Phase 0 gate.

For `exec_supervisor.py`, extract only stable responsibilities needed by the correction:
- environment and containment capability detection
- protocol types, framing, and validation
- bootstrap construction
- PID-namespace launch supervision
- lifecycle/result mapping

For `orchestrator.py`, extract only:
- trace-emission authority (closes WS-2)
- state-transition coordination (closes WS-3)
- side-effect lifecycle coordination
- recovery/resume coordination

**Exit when:**
- each ownership boundary has an explicit interface
- critical behavior can be tested without whole-module patching
- extraction introduces no semantic changes
- production and regression behavior remains green

The line-count threshold is removed. It is not an architectural invariant and would incentivize mechanical extraction, keeping Phase 0 open indefinitely.

### WS-5 — Deployment profiles documented (Phase 0 outcome #5)

Produce `docs/deployment-profiles/` documenting supported vs unsupported profiles. Currently zero-progress. Must cover: local, containerized, delegated Linux service. Windows profile is defined per WS-7.

### WS-6 — Preserve existing invariants (verify remains done)

Confirm these remain unbroken by any WS-1–WS-5 change:
- Side-effect/recovery model (22 invariants, `invariants/v3.5.md`)
- No false containment claims (commit `230a398e` hygiene maintained)
- Correction decisions recorded (git history discipline)

### WS-7 — Windows qualified for a limited role; Linux containment delegated

**Frozen decision:** Windows is qualified as a development, SDK, CLI, control-plane, and orchestration client profile. Local Linux-equivalent containment of untrusted workloads is not supported on Windows. Untrusted execution must be delegated to a qualified Linux execution service or fail closed.

This avoids starting a speculative Windows containment program during Phase 0.

The Windows test matrix must prove:
- public API compatibility
- blueprint and contract validation
- policy behavior
- orchestration behavior that does not require Linux primitives
- correct delegation or fail-closed behavior for untrusted execution
- no claim of namespace, seccomp, procfs, or cgroup equivalence

### WS-8 — Qualification, integration, and release closure

Required outcomes:

1. After C0.2 closes, establish and record the stable post-history-decision development base. All subsequent Phase 0 work must descend from that base.
2. After C0.3 and WS-1 through WS-7 are complete, freeze one release-candidate SHA and run the full qualification matrix from a fresh GitHub clone at that exact SHA.
3. Capture complete terminal summaries for: focused correction suites; privileged Linux containment suites; broad Linux regression; defined Windows profile; documentation and packaging checks.
4. Confirm all capability-relevant skips are justified and do not satisfy qualification gates.
5. Integrate the corrected branch into `master`.
6. Prove the accepted release commit is reachable from the default branch.
7. Synchronize roadmap, architecture, deployment-profile, and version documentation.
8. Create and verify the intended release tag.
9. Archive or clearly mark superseded correction branches.
10. Confirm a clean GitHub clone reproduces the tagged release.
11. Prove that GitHub is the canonical source of truth:
    - the accepted release commit is reachable from the default branch;
    - the release tag resolves to the accepted release commit;
    - the canonical local checkout is 0 ahead / 0 behind its upstream;
    - the canonical working tree is clean except for documented ignored machine-local material;
    - a fresh clone requires no untracked source, test, fixture, migration, or specification file to reproduce the qualified result.

**Phase 0 must not close while its accepted implementation lives only on a long-running review branch.** This closes the divergence dynamic verified in the git trajectory (master previously 159 commits behind review branch).

**WS-8 exit condition:** No production or documentation change may enter the release candidate after qualification begins without invalidating the qualification and restarting the affected gates. This prevents qualifying one SHA and tagging another.

---

## 5. Phase 0 exit criteria

Phase 0 closes **only when all** are met. "Code exists" is not sufficient (Master Rule 8).

```text
C0.1  Every unique historical state.db blob classified
C0.2  History decision executed or explicitly accepted
C0.3  Current canonical SHA rebaselined and CT 801 containment suite green

WS-1  One governed untrusted-execution backend
WS-2  One durable trace-emission authority
WS-3  One authoritative state-transition coordinator
WS-4  Only gate-relevant responsibility extraction completed
WS-5  Deployment profiles documented
WS-6  Existing side-effect, recovery, and claim invariants preserved
WS-7  Windows qualified for a limited role and Linux containment explicitly delegated
WS-8  Correction integrated into the GitHub default branch, fully qualified,
      documented, tagged, and reproducible from GitHub alone
```

**Fence condition:** Phase 0 has no calendar date until C0.1–C0.3 close and capacity is known (Master Rule 10). The change-control rules below are the forcing function that prevents the gate from expanding to fill available effort.

---

## 6. Phase 0 change-control rules

1. Every task must identify the exact exit gate it closes.
2. A new gate requires a reproducible defect, documented impact, and explicit roadmap amendment.
3. Accepted T1 and T2 slices are not reopened without new contradictory evidence.
4. Refactoring cannot be introduced solely for stylistic or speculative maintainability reasons.
5. Security qualification occurs only against named deployment profiles.
6. Skipped tests never prove the skipped capability.
7. Once every frozen exit condition is satisfied, Phase 0 closes; discretionary hardening is deferred.
8. Product-substrate expansion remains prohibited unless required by a frozen Phase 0 gate.

---

## 7. Phase 0 evidence contract

Phase 0 defines what must be true; this section defines what constitutes acceptable proof. This is necessary because the project has repeatedly had correct implementation claims paired with incomplete or host-inapplicable test evidence.

Every gate closure must record:

```text
Gate identifier:
Status:
Canonical base SHA:
Candidate SHA:
Deployment profile:
Host or runner class:
Exact test or verification commands:
Passed:
Failed:
Skipped:
Expected skips:
Unexpected skips:
Evidence artifact:
Known limitations:
Reviewer:
Verdict:
```

**Rules:**

1. A result without the exact tested SHA is not qualification evidence.
2. A partial or truncated test run cannot close a gate.
3. User-reported manual output must be labeled manual evidence.
4. GitHub Actions evidence must identify the run and job.
5. Privileged containment evidence must identify the qualified deployment profile.
6. Skips must be enumerated and justified.
7. Screenshots, snippets, or selected passing tests cannot substitute for the complete terminal summary.
8. A gate is closed only by an explicit accepted verdict linked to its evidence.

---

## 8. What is explicitly NOT in this roadmap

- Workspace / UI work (Phase 1)
- Reference chain productization (Phase 1 — chain is real; surface + users are Phase 1)
- New platform primitives
- Eval runner runtime wiring (Phase 4)
- General god-object cleanup or stylistic refactor (deferred — WS-4 is gate-bounded only)
- Windows local containment (descoped per WS-7)
- Any feature framed as "progress" against the master roadmap

---

## 9. Resolved open decisions

- **C0.1 authority:** Classify against an offline local mirror containing all unique historical database blobs. The preserved working database alone is not authoritative for historical classification.
- **Windows:** Adopt the development/control-plane profile; explicitly descope local untrusted containment for this release.
- **WS-4:** Bounded responsibility extraction inside Phase 0; general god-object cleanup and method-length threshold removed.
- **`chain_orchestrator.py`:** First identify supported production callers. No supported caller → deprecate and remove. Supported caller → convert to thin governed-orchestrator adapter. Direct raw execution is not an acceptable retained option.

---

## 10. Stability statement

Until C0.2 closes:
- `bceba2aa` is the **pre-history-decision planning base**, not an immutable release anchor.
- No tag, branch SHA, or roadmap anchor is final.
- This roadmap itself may need re-basing if history is rewritten.

After C0.2 closes and any required rewrite completes, record the stable post-history-decision development base for the remaining Phase 0 work. It does not become the Phase 1 or release base until C0.3 and WS-1 through WS-7 close and WS-8 qualifies, integrates, and tags the release-candidate SHA.

---

## Appendix — Approved frozen decisions

The following are approved without further revision:

- `bceba2aa` is the **pre-history-decision planning base**, not an immutable release anchor.
- C0.1 precedes C0.2; C0.3 proceeds independently.
- C0.1 classifies every unique historical database blob.
- The current containment baseline must be recaptured at the current canonical SHA.
- T1 and T2 remain accepted unless new contradictory evidence appears.
- `SubprocessRunner` and `chain_orchestrator.py` may remain only as governed adapters, never as parallel authorities.
- Trace acceptance requires durable append before acknowledgement and one emission authority.
- State acceptance requires one durable transition coordinator.
- WS-4 remains limited to gate-closing responsibility extraction.
- Windows is a development/control-plane client profile; local Linux-equivalent containment is explicitly unsupported.
- Product discovery may proceed in parallel, but it cannot add production substrate.
- Phase 0 closes immediately when the frozen gates are satisfied; discretionary hardening is deferred.
