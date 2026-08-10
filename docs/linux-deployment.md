# NodeChain Linux Deployment Profiles

**Document class:** Descriptive deployment profile  
**Baseline date:** 2026-08-10  
**Baseline SHA:** `af1943c24a58d80ae048b9b9d50842cf0e0b27d1`  
**Current released version:** `v3.6.0`

This document replaces the older “production Linux deployment” narrative with profile-specific claims that match the current code.

The most important distinction is:

> **NodeChain has a hardened supervised Linux execution substrate, but the ordinary `NodeInvoker → SubprocessRunner` POSIX untrusted-node path is currently fail-closed pending T3 integration into that substrate.**

Do not treat historical sandbox evidence as proof that every current untrusted Harness Node invocation uses the same backend.

---

## 1. Deployment/qualification profile matrix

| Profile | Intended use | Baseline status | Untrusted execution claim |
|---|---|---|---|
| Trusted local Linux development | SDK, CLI, blueprints, trusted/built-in nodes, tests | Supported | Does not require generic untrusted execution |
| GitHub-hosted Ubuntu CI | Portable regression, packaging, ordinary integration | Supported | Not privileged containment qualification |
| Privileged Linux verification host | Native/supervised sandbox and containment evidence | Supported as a qualification profile when prerequisites exist | Specific tested execution path only |
| Generic POSIX untrusted Harness Node invocation | Normal `NodeInvoker` isolated-node path | **Fail-closed pending T3** | Returns `supervised_backend_required` before workload spawn |
| Future delegated Linux execution service | Production untrusted workload service | Not yet a qualified product profile | Must use one governed supervised backend |
| Windows development/control plane | Cross-platform SDK/CLI/control behavior | Separate platform profile | No Linux-equivalent namespace/seccomp/cgroup claim |

---

## 2. Trusted local Linux development

For ordinary source development and trusted/built-in execution:

```bash
git clone <repository-url> nodechain
cd nodechain
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

nodechain --version
nodechain --help

nodechain run "test query" \
  --provider mock \
  --review-mode auto-approve
```

This profile is appropriate for:

- blueprint/contract development;
- built-in and explicitly trusted node work;
- CLI/operator workflows;
- deterministic mock runs;
- non-privileged unit/integration tests.

It should not be used to claim privileged containment merely because the host is Linux.

---

## 3. Current generic untrusted-node boundary

The normal isolated-node call chain is:

```text
Orchestrator
  ↓
NodeInvoker
  ↓
SubprocessRunner.run_isolated()
```

At the current baseline, `SubprocessRunner.run_isolated()` begins with an explicit T3.0 safety fence for POSIX `local_untrusted` and `remote_untrusted` nodes.

The method returns a failure result containing:

```text
supervised_backend_required
```

before creating the workload process.

The reason is recorded directly in code: the legacy POSIX runner path is not permitted to proceed until supervised routing/result mapping is integrated. A weaker fallback must not silently execute an untrusted workload.

### Operational consequence

A deployment that requires ordinary untrusted Harness Nodes on POSIX is **not yet complete** simply by installing NodeChain v3.6/current master. It needs the T3 integration/qualification outcome from `ROADMAP.md` or must remain fail-closed.

---

## 4. Supervised Linux execution substrate

Separately from the generic NodeInvoker integration, NodeChain contains the hardened supervised execution stack developed through v3.5.1.

Important modules include:

```text
supervised_argv.py
supervised_exec_session.py
exec_supervisor.py
exec_protocol.py
async_fd_transport.py
pid_namespace_topology.py
streaming_output.py and supporting helpers
```

The design includes:

- external supervisor launcher;
- PID-namespace init/reaper;
- verified bootstrap identity;
- exact `PTRACE_EVENT_EXEC` workload-start authority;
- bounded asynchronous config/stdout/stderr/protocol/payload ownership;
- monotonic execution/cleanup deadlines;
- namespace-wide cleanup and reaping;
- independent host process-group containment.

This is the intended substrate for the generic POSIX untrusted-node routing work.

---

## 5. Privileged Linux qualification prerequisites

Security/containment evidence for the supervised/native paths may require host capabilities such as:

- Linux PID namespaces;
- `/proc` namespace/topology inspection;
- ptrace / `PTRACE_O_TRACEEXEC` support;
- seccomp support;
- process-group signaling;
- cgroup v2 where the tested path depends on it;
- privileges/capabilities sufficient to create the required namespaces and perform the tested operations.

A host without those prerequisites must not silently be reported as having equivalent containment.

Capability detection and fail-closed behavior are part of the security contract.

---

## 6. Historical native sandbox evidence

NodeChain has historical privileged-Linux verification for the native command-runner path, including child-observed proofs for:

- mount confinement;
- network namespace isolation;
- PID namespace/procfs isolation;
- child-applied seccomp surviving `execve`.

See `docs/native_sandbox_verification.md` for the historical evidence class and exact path it exercised.

That evidence is valuable, but its scope is specific:

```text
SandboxCommandRunner/native command path
≠ automatically the same as
NodeInvoker → SubprocessRunner generic Harness Node path
```

The T3 fence exists precisely because those integration boundaries must be proven rather than inferred.

---

## 7. GitHub-hosted Linux CI

Public CI uses GitHub-hosted `ubuntu-24.04` runners.

This profile is authoritative for:

- portable unit/integration regression;
- CLI and package behavior;
- ordinary Linux compatibility;
- Publication Tree packaging/schema proof.

It is **not** the authoritative environment for privileged PID-namespace/seccomp/ptrace/cgroup containment claims.

The capability-sensitive `slow-shard-2` job uses `continue-on-error: true`; see `docs/ci.md` for exact evidence semantics.

---

## 8. cgroup, namespace, and seccomp documentation rule

The repository contains several generations of sandbox implementation and evidence. Avoid global statements such as “NodeChain uses cgroups/seccomp/namespaces for every untrusted node.”

Instead state:

```text
execution path
+ requested profile
+ host capabilities
+ actual runtime evidence
= valid containment claim
```

For each run/profile, distinguish:

- capability available;
- capability requested;
- capability actually enforced;
- workload actually started;
- terminal cleanup result;
- fallback/fail-closed behavior.

---

## 9. Docker/container use

Containerizing the NodeChain process can be useful for packaging and service isolation, but a generic Docker deployment does not automatically satisfy NodeChain's internal untrusted-execution claims.

Container runtimes vary in their ability to provide nested namespaces, ptrace, cgroup delegation, mount operations, and seccomp configuration.

Use containers as an **outer deployment boundary** where appropriate, but qualify the inner NodeChain execution path separately.

Example for trusted/mock experimentation:

```bash
docker build -t nodechain .
docker run --rm nodechain run "test query" \
  --blueprint blueprints/echo_demo_v1.yaml \
  --provider mock
```

Do not relabel this example as a generic untrusted-workload production profile without the required containment qualification.

---

## 10. Production service guidance at this baseline

### Trusted/internal workload service

A controlled Linux service account may run NodeChain for built-in/trusted workflows, subject to normal OS hardening, secrets management, filesystem permissions, network policy, and the NodeChain policy/trust model.

### Untrusted Harness Node service

Do not enable a weaker legacy POSIX path to bypass `supervised_backend_required`.

The production direction is:

```text
ordinary governed node invocation
        ↓
identity/trust/policy admission
        ↓
one supervised Linux backend
        ↓
truthful result + containment evidence
        ↓
normal trace/state/side-effect/recovery authority
```

Until T3 closes and the integrated path is qualified, the generic untrusted-node profile remains fail-closed.

---

## 11. Windows relationship

Windows is a separate platform profile for NodeChain development, CLI, package validation, and applicable runtime behavior.

NodeChain does not claim Windows implements Linux-equivalent:

- PID namespaces;
- seccomp syscall filters;
- `/proc` namespace views;
- cgroup v2 semantics.

Windows process/Job Object controls should be documented and qualified as Windows controls rather than described as equivalent Linux mechanisms.

---

## 12. Evidence to retain for a qualified Linux deployment

For a deployment that makes containment claims, retain at least:

- exact NodeChain commit/tag;
- OS/kernel version;
- virtualization/container profile;
- effective uid/capabilities relevant to namespace/ptrace operations;
- cgroup/filesystem capability facts where applicable;
- seccomp availability;
- test/qualification command;
- full pass/fail/skip summary;
- explicit reason for capability-related skips;
- runtime containment metadata/protocol evidence required by the tested path.

A green summary without proof that the intended capability path actually executed is insufficient.

---

## 13. Related documents

- `BASELINE.md` — current implementation truth
- `ARCHITECTURE.md` — current execution architecture
- `ROADMAP.md` — T3 and authority-closure outcomes
- `docs/ci.md` — hosted qualification semantics
- `docs/native_sandbox_verification.md` — historical native command-runner verification evidence
- `CHANGELOG.md` — v3.5.1 supervised execution release history
