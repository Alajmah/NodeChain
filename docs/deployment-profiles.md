# NodeChain Deployment Profiles — Canonical Truth

**Document class:** Descriptive deployment authority  
**Baseline date:** 2026-08-18  
**Implementation code baseline:** `78f98252173eb38d4284ed92f0fd3343c5c5ce21` (the H0.6 truth squash; evidence rows below still name the SHAs they were actually produced at)  
**Current released version:** `v3.6.0`  
**Current-state summary:** [BASELINE.md](../BASELINE.md)

This document answers one question:

> Given this host, installation layout, trust level, execution path, and requested controls, what can NodeChain actually execute, what enforcement can it prove, how does it fail, and what evidence supports the claim?

Every deployment or containment claim anywhere in this repository must agree with this matrix. `docs/linux-deployment.md` is the Linux operational appendix; `docs/ci.md` is the hosted-evidence contract; `BASELINE.md` is the implementation-truth anchor above both.

---

## 1. The governing equation

A valid deployment claim is:

```text
execution path
+ deployment profile
+ trust identity
+ host prerequisites
+ requested controls
+ observed enforcement
+ workload-start truth
+ cleanup truth
+ evidence class
= valid deployment claim
```

A green check, a passing suite, or a historical sandbox proof from one profile never becomes a claim about another profile. Evidence must name the exact code SHA and the host profile it ran on.

## 2. Trust identity is not deployment profile

`local_untrusted` says what the workload **is**. The deployment profile decides whether a qualified backend exists on that host to execute it. The same untrusted node runs under full supervised containment on one host and fails closed before workload start on another; the trust identity is identical in both cases.

```text
local_untrusted / remote_untrusted
        ↓
POSIX NodeInvoker route
        ↓
one supervised backend
        ↓
qualified privileged Linux → may execute with observed controls
unqualified / insufficient host → fails closed before workload start
requested cgroup → explicit supervised-cgroup refusal
        ↓
NO legacy fallback
```

---

## 3. The canonical matrix

Fields follow the frozen H0.6 model. "Not claimed" is a hard limit, not a TODO.

### Profile 1 — Trusted local development

| Field | Value |
|---|---|
| Profile ID | `trusted-local-development` |
| Intended use | SDK, CLI, blueprints, tests, trusted/built-in node development |
| Platform/host | Any supported dev host (Linux, macOS class, Windows) |
| Installation assumptions | Any, including editable/source checkouts |
| Runtime entry point | CLI / SDK / Orchestrator → NodeInvoker |
| Trust levels | `built_in`, `local_trusted` |
| Execution backend | Ordinary in-process / legacy subprocess path for trusted levels |
| Host prerequisites | None beyond running Python |
| Requested controls | Policy presets for trusted levels |
| Enforced controls | Python policy layer (import/filesystem/subprocess/network) |
| Workload-start truth | Starts per policy |
| Failure behavior | Ordinary policy/exception failures |
| Fallback behavior | n/a (no hostile workload) |
| Qualification evidence | Hosted CI cross-platform suites at the pinned SHA |
| Not claimed | **Any hostile-workload containment.** Running untrusted nodes in this profile proves nothing about isolation |

### Profile 2 — GitHub-hosted CI

| Field | Value |
|---|---|
| Profile ID | `github-hosted-ci` |
| Intended use | Portable regression, packaging, Publication Tree, cross-platform behavior |
| Platform/host | GitHub-hosted `ubuntu-24.04` / `windows-2022` runners, unprivileged |
| Installation assumptions | Wheel install from source at the exact SHA |
| Runtime entry point | Test suites, CLI smoke, package build |
| Trust levels | All, as test subjects |
| Execution backend | For untrusted-path tests: the supervised route, which **fails closed here by design** |
| Host prerequisites | None privileged |
| Requested controls | Whatever the tests request |
| Enforced controls | None that require privileges; capability-sensitive jobs are `continue-on-error` non-evidence |
| Workload-start truth | Unprivileged-container assertions: `process_started=false` pre-start |
| Failure behavior | The frozen fail-closed family (bootstrap/refusal) — asserted as the expected truth |
| Fallback behavior | None — asserted |
| Qualification evidence | Exact-head required checks (10 CI contexts) + Publication Tree (2 contexts) at the pinned SHA |
| Not claimed | **Privileged Linux containment.** A green hosted check set never proves namespace/seccomp/capability enforcement |

### Profile 3 — Privileged Linux containment verification

| Field | Value |
|---|---|
| Profile ID | `privileged-linux-verification` |
| Intended use | Qualification of the real supervised containment stack |
| Platform/host | Linux with CAP_SYS_ADMIN-class privileges (e.g. `--privileged` container, suitably configured VM/LXC) |
| Installation assumptions | Non-editable wheel/venv install of the trusted runtime under a qualified interpreter layout |
| Runtime entry point | Direct qualification suites against the supervised stack |
| Trust levels | `local_untrusted` / `remote_untrusted` as adversarial subjects |
| Execution backend | The supervised stack (supervisor launcher + trusted bootstrap + workload) |
| Host prerequisites | PID namespaces, `/proc` inspection, ptrace `PTRACE_O_TRACEEXEC`, seccomp (when requested), capabilities for namespace/mount operations |
| Requested controls | Network/mount namespaces, mount confinement, procfs isolation, seccomp |
| Enforced controls | All requested controls with trusted evidence: read-only bind mounts (`/package` + runtime extras, `/tmp` writable), the five-set capability boundary, real seccomp filter with SIGSYS denial |
| Workload-start truth | Starts, with `enforcement_verified` → exec-confirmed authority |
| Failure behavior | Any control that cannot be enforced → `enforcement_failed`, exit 126 family, workload never starts |
| Fallback behavior | **None under any condition** |
| Qualification evidence | The sealed H0.2 privileged record at `068120f6`: 374 passed / 72 skipped / 0 failed, including double-chroot escape denial, seeded-capability proofs, SIGSYS denial, startup-injection proofs |
| Not claimed | Kernel-escape formal proof; universal host compatibility; cgroup enforcement |

### Profile 4 — Generic POSIX untrusted Harness Node execution

| Field | Value |
|---|---|
| Profile ID | `generic-posix-untrusted` |
| Intended use | Ordinary production invocation of untrusted Harness Nodes |
| Platform/host | POSIX; execution requires a Profile-3-class qualified Linux host |
| Installation assumptions | Trusted runtime installed under a qualified layout; node package on disk |
| Runtime entry point | Orchestrator → NodeInvoker → `SubprocessRunner.run_isolated()` |
| Trust levels | `local_untrusted`, `remote_untrusted` |
| Execution backend | One supervised backend (H0.2 joined route); the legacy POSIX spawn body is unreachable and no try-supervised-except-legacy fallback exists |
| Host prerequisites | Same as Profile 3 when containment/seccomp are requested |
| Requested controls | Containment config incl. optional seccomp; cgroup requests refused pre-start (`supervised_cgroup_unsupported`) |
| Enforced controls | On a qualified host: Profile-3 evidence, projected truthfully (`supervised_execution` evidence on success and failure) |
| Workload-start truth | Qualified host → starts with enforcement evidence; insufficient host → `process_started=false` before workload start |
| Failure behavior | The frozen outcome-matrix families (setup −1 / bootstrap 126 / started-failed / timeout / SIGSYS −31 / cleanup-dominates) |
| Fallback behavior | **None under any condition** |
| Qualification evidence | H0.2 sealed record at `068120f6` (privileged Linux) + hosted CI fail-closed assertions (both truths) |
| Not claimed | Execution without host prerequisites; editable/custom-prefix layouts under confinement (see §4); cgroups |

### Profile 5 — Windows control-plane / development

| Field | Value |
|---|---|
| Profile ID | `windows-control-plane` |
| Intended use | CLI/SDK/control-plane development and trusted execution on Windows |
| Platform/host | Windows |
| Installation assumptions | Standard Python install |
| Runtime entry point | CLI / SDK / tests |
| Trust levels | `built_in`, `local_trusted` for execution; untrusted levels exercise the control-plane result shapes only |
| Execution backend | Ordinary trusted paths; POSIX-only supervised containment is not emulated |
| Host prerequisites | None privileged |
| Requested controls | n/a |
| Enforced controls | Python policy layer; no OS containment |
| Workload-start truth | Trusted workloads start per policy |
| Failure behavior | POSIX-only containment is documented as unavailable, not silently degraded |
| Fallback behavior | n/a |
| Qualification evidence | Windows suite at the pinned SHA (7438 passed / 0 failed) |
| Not claimed | **Any Linux-equivalent namespace, seccomp, procfs, capability, or cgroup enforcement** |

### Profile 6 — Managed / delegated execution (future)

| Field | Value |
|---|---|
| Profile ID | `managed-delegated-execution` |
| Intended use | Future hosted/worker execution service |
| Platform/host | n/a |
| Runtime entry point | n/a |
| Execution backend | Not implemented |
| Qualification evidence | Negative qualification only (below) |
| Not claimed | Everything: managed service, distributed worker fabric, multi-tenant isolation, SLOs |

Negative qualification record:

```text
managed service implemented: no
distributed worker fabric: no
multi-tenant execution qualification: no
```

---

## 4. Deferred-truth dispositions (H0.6.2)

Each known limitation is disposed as supported / qualified / fail-closed / not claimed. None is implemented around; each fails closed where it applies.

| Item | Supported? | Qualified? | Fail-closed? | Not claimed |
|---|---|---|---|---|
| Editable / source-backed installs under mount confinement | No | No | Yes — workload import fails closed inside the chroot (the editable path points outside the bind set) | Deployment compatibility |
| Custom interpreter prefixes (e.g. conda-style paths outside `/usr`, `/venv`, `/.venv`) under confinement | No | No | Yes — the interpreter binary is absent from the bind set; exec fails closed | Arbitrary `sys.executable` locations under confinement |
| Supervised cgroup request | No (refused) | n/a | Yes — refused in the parent before any start, `supervised_cgroup_unsupported`, exit 126 | cgroup accounting/limits on the supervised route |
| `WNOWAIT` portability | Linux only | Qualified on the Linux family the suites run on (GitHub-hosted Ubuntu + qualification containers) | Probe errors fail closed | Universal POSIX `waitid` semantics |
| Host `package_root` pathname in the trusted child context | Present | Documented | n/a — informational; the workload never receives the config, and under confinement the host path is unreachable | Containment-escape relevance (knowing the string grants no access) |
| Insufficient Linux privileges | n/a | n/a | Yes — pre-workload-start refusal (`process_started=false`) with the explicit fail-closed family | Weaker fallback execution |
| Seccomp binding unavailable | n/a | n/a | Yes — requested seccomp fails closed; absence is never enforced=false-and-run | Enforcement without a filter library |
| Windows containment | No | No | Documented as unavailable | Linux-equivalent enforcement |

---

## 5. Evidence ledger

| Evidence | SHA | Profile | Class |
|---|---|---|---|
| Exact-head hosted CI 10/10 (PR head `18dc2a7` and master `068120f6`) | see CHANGELOG H0.2 | Profile 2 | Hosted cross-platform |
| Publication Tree 2/2 (same SHAs) | see CHANGELOG H0.2 | Profile 2 | Packaging/schema |
| Privileged supervised set 374/72/0 incl. adversarial security proofs | `068120f6` | Profiles 3–4 | Capability-qualified |
| Windows full suite 7438/0 | `068120f6` | Profile 5 | Cross-platform |
| Historical native-sandbox evidence (v2.76/v2.78) | historical docs | native-sandbox runner path only | Historical, profile-bound |

Historical sandbox evidence stays bound to the execution path it actually tested (the native sandbox runner). It is never generalized to the generic route.

## 6. Related documents

- [BASELINE.md](../BASELINE.md) — implementation truth anchor.
- [docs/linux-deployment.md](linux-deployment.md) — Linux operational appendix.
- [docs/ci.md](ci.md) — hosted-evidence contract.
- [ARCHITECTURE.md](../ARCHITECTURE.md) §16 links here for the deployment-profile summary.
