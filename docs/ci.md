# NodeChain CI and Qualification Contract

**Document class:** Operational / descriptive  
**Baseline date:** 2026-08-18  
**Implementation code baseline:** `78f98252173eb38d4284ed92f0fd3343c5c5ce21`  
**Canonical profile authority:** [docs/deployment-profiles.md](deployment-profiles.md)  
**Authoritative configuration:** `.github/workflows/ci.yml`, `.github/workflows/publication-tree.yml`, and branch protection

The version is currently `3.6.0`. Post-v3.6 development state is described separately in `BASELINE.md`; this version statement tracks the installed/released package version used by the release-truth guards.

This document explains what the public hosted CI proves and, equally important, what it does **not** prove.

---

## 1. Public CI is GitHub-hosted

The public repository uses GitHub-hosted runners rather than the historical self-hosted CT 801 runner for ordinary protected-branch qualification.

Current runner families:

- Linux: `ubuntu-24.04`
- Windows: `windows-2022`
- Python used by the workflows: 3.12
- pinned official actions: `actions/checkout` v7.0.1 commit and `actions/setup-python` v7.0.0 commit

Every hosted run starts from a fresh runner image and installs the repository dependencies for that job.

Historical CT 801 / privileged Linux evidence remains useful for the execution paths it actually exercised, but it is not the current public CI execution environment.

---

## 2. CI workflow job set

`.github/workflows/ci.yml` currently defines these jobs:

| Job | Runner | Timeout | Purpose | Workflow behavior |
|---|---|---:|---|---|
| `lint` | Ubuntu | 10 min | `py_compile` + Ruff syntax/undefined-name blocking scan | Blocking in workflow |
| `unit-fast` | Ubuntu | 30 min | Broad fast unit/governance suite excluding named slow/capability files | Blocking |
| `orchestrator-recovery` | Ubuntu | 20 min | Orchestrator, recovery, review, budget, operator action coverage | Blocking |
| `trust-collector` | Ubuntu | 20 min | Trust, registry, collector and dashboard semantics | Blocking |
| `slow-shard-1` | Ubuntu | 25 min | Checkpoint, loop, evidence and branch-race integration | Blocking |
| `slow-shard-2` | Ubuntu | 25 min | Sandbox, namespace and security tests | **Job-level tolerant** (`continue-on-error: true`) |
| `slow-shard-3` | Ubuntu | 25 min | Proxmox adapter, network and recovery integration | Blocking |
| `windows-tests` | Windows | 90 min | Cross-platform test surface excluding Linux-native files | Blocking |
| `cli-smoke` | Ubuntu | 15 min | Installed CLI command smoke surface | Blocking |
| `package-build` | Ubuntu | 15 min | Build wheel | Blocking |

The workflow triggers on pushes to `master` and pull requests targeting `master`.

---

## 3. Publication Tree

`.github/workflows/publication-tree.yml` runs a two-OS matrix:

```text
publication tree (ubuntu-24.04)
publication tree (windows-2022)
```

The workflow verifies, among other things:

- clean/publication tree guard;
- publication-guard tests;
- wheel and sdist build;
- exactly one wheel and one sdist;
- installation of the wheel into an empty virtual environment;
- version/CLI smoke;
- source ↔ wheel ↔ sdist runtime schema-set parity;
- installed-wheel schema loading outside the checkout.

This is the authoritative packaging/publication portability gate, not merely a unit-test shard.

---

## 4. Required branch checks

At this baseline, branch protection expects the ten CI job contexts plus the two Publication Tree matrix contexts.

The exact current required set is:

```text
lint
unit-fast
orchestrator-recovery
trust-collector
slow-shard-1
slow-shard-2
slow-shard-3
windows-tests
cli-smoke
package-build
publication tree (ubuntu-24.04)
publication tree (windows-2022)
```

Do not encode “10/10 + 2/2” as the governance contract in multiple documents. Job counts are descriptive and may change. The contract is: **all branch-protection-required hosted checks for the candidate SHA must satisfy branch protection before normal merge/release progression.**

`docs/governance/release-checklist.md` and the public-development policy refer back to this document/workflow rather than maintaining an independent count.

---

## 5. `slow-shard-2` evidence semantics

`slow-shard-2` is special.

It includes capability-sensitive sandbox/security tests but the job itself has:

```yaml
continue-on-error: true
```

Therefore a required `slow-shard-2` check does **not** mean the hosted runner proved all privileged native-containment behavior. The workflow intentionally tolerates capability-related job failure on hosts that cannot provide the required kernel/privilege environment.

Consequences:

- branch protection requires the check context to complete as configured;
- hosted CI remains useful for portable security regressions and explicit skips;
- privileged namespace/seccomp/cgroup/supervised-execution qualification requires a separately named capable Linux profile and evidence run;
- no release document should translate a green hosted `slow-shard-2` context into “privileged Linux containment proven.”

---

## 6. Verification evidence classes

NodeChain uses several different evidence strengths. They should not be collapsed into one “tests passed” statement.

### A. Hosted protected-branch qualification

The full required GitHub check set for the exact candidate SHA.

Use for:

- ordinary merge/release governance;
- cross-platform regression;
- package/publication proof;
- public reproducibility.

### B. Full local suite

A single local pytest invocation that collects/runs the repository test tree in that environment.

Useful for broad regression confidence, but its evidentiary value depends on the host and enabled capabilities.

### C. Sharded local suite

All intended test files executed through multiple invocations. Useful when host/time constraints make a single invocation impractical.

Sharded pass totals may not equal one-shot collection totals if collection behavior depends on cross-file context. Record file coverage and shard results rather than asserting numerical identity.

### D. Targeted affected-area suite

A bounded set of tests for the changed behavior. Appropriate for iteration and acceptance of a narrow change, but not by itself equivalent to full release qualification.

### E. Capability-qualified native/security suite

Runs on an explicitly qualified Linux host/profile with the privileges/kernel features needed by the path under test.

Use for claims about:

- PID namespaces;
- seccomp;
- procfs namespace views;
- cgroup containment;
- ptrace/supervised execution;
- privileged mount/network isolation.

The evidence must name the exact code SHA and host profile.

---

## 7. Local Makefile: useful, not exact hosted parity

Older documentation claimed the `Makefile` mirrored CI exactly. That is not true at this baseline.

Two concrete differences are visible in the current files:

### Ruff behavior differs

Hosted CI runs:

```bash
ruff check src/nodechain/ --select E9,F63,F7,F82 --no-cache
```

and treats failure as blocking.

The current `Makefile` `ci-lint` target still includes:

```bash
--exit-zero
```

so `make ci-lint` does not reproduce the hosted lint gate.

### `make ci-blocking` is not the full protected check set

The current target runs local lint/fast/recovery/trust/shard-1/shard-3/smoke/package targets. It does not itself reproduce:

- `slow-shard-2` as configured by hosted CI;
- `windows-tests`;
- Ubuntu + Windows Publication Tree.

Therefore:

> **Use Make targets for local iteration. Use the hosted required checks as the authoritative public merge/release qualification surface.**

A future tooling correction may restore closer parity; until then the documentation must not claim parity that the commands do not provide.

---

## 8. Useful local commands

```bash
python -m pip install -e ".[dev]"

make ci-fast
make ci-recovery
make ci-trust
make ci-shard-1
make ci-shard-3

# Direct blocking-equivalent Ruff invocation
python -m py_compile $(find src/nodechain -name '*.py')
ruff check src/nodechain/ --select E9,F63,F7,F82 --no-cache

# Broad local suite
python -m pytest tests/ -q --tb=short
```

On Windows, use the platform-appropriate shell/commands rather than the POSIX `find` example.

---

## 9. Version/package qualification

The released version at this baseline is `3.6.0`, and both `pyproject.toml` and `nodechain.__version__` report that version.

Publication Tree additionally hard-checks the installed package version and schema availability.

The development branch may contain post-release features while the package version remains the last released version. This is expected and is why `BASELINE.md` distinguishes released and development state.

Do not label a post-v3.6 development feature “shipped in v3.6.0” merely because it exists on `master` while the version metadata remains `3.6.0`.

---

## 10. Release qualification rule

For an ordinary public release:

1. release candidate PR is scoped and reviewed;
2. every branch-protection-required hosted check for the exact head SHA satisfies protection;
3. the PR is squash-merged according to governance policy;
4. push-triggered checks on the resulting `master` release commit complete as required;
5. package artifacts are rebuilt/verified from the accepted release commit;
6. wheel/sdist installation, version and schema/package proofs pass;
7. checksums and release provenance are retained;
8. tag/release points to the verified release commit.

If the release makes a native-containment claim beyond hosted capabilities, the applicable capability-qualified evidence must also be attached to that exact release candidate/release commit according to its qualification plan.

---

## 11. What hosted CI does not prove

A fully green protected check set does not by itself prove:

- privileged enforcement of the supervised route on arbitrary deployment hosts (the supervised backend owns the generic POSIX untrusted route at this baseline, but hosted CI runners cannot provide its privileges — those runs assert the fail-closed truth only; see the canonical profile matrix);
- privileged Linux namespace/seccomp/cgroup/ptrace behavior on every deployment host;
- production service SLOs or scale;
- multi-tenant isolation;
- real-model quality;
- live-network source reliability;
- security against kernel/container escape or arbitrary hostile code.

Those require separate execution/product evidence.

---

## 12. Documentation update rule

When `.github/workflows/ci.yml`, Publication Tree, or branch-protection requirements change:

- update this document from the actual workflow/configuration;
- update governance docs to reference the authoritative set rather than duplicating counts;
- update `BASELINE.md` only if the change materially alters the project's verification/readiness claim.
