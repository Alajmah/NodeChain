# NodeChain Linux Deployment Profiles

**Document class:** Descriptive deployment profile (operational appendix)  
**Baseline date:** 2026-08-18  
**Implementation code baseline:** `068120f6a46797182d33e100b5dadfc8ccc77b4f`  
**Current released version:** `v3.6.0`  
**Canonical profile authority:** [docs/deployment-profiles.md](deployment-profiles.md)

This document is the Linux operational appendix to the canonical deployment-profile matrix. Profile definitions, evidence classes, and not-claimed limits live there; this page carries Linux-specific operational detail.

The most important distinction is:

> **One supervised backend owns ordinary POSIX untrusted-node execution (H0.2 sealed). On a qualified privileged Linux host it executes with observed containment evidence; on any host lacking the required privileges or kernel features it fails closed before workload start. No weaker legacy path exists.**

Do not treat historical sandbox evidence as proof that every current untrusted Harness Node invocation uses the same backend — evidence is profile-bound.

---

## 1. Deployment/qualification profile matrix

The canonical matrix with full field detail lives in [docs/deployment-profiles.md](deployment-profiles.md). Summary:

| Profile | Intended use | Baseline status | Untrusted execution claim |
|---|---|---|---|
| Trusted local Linux development | SDK, CLI, blueprints, trusted/built-in nodes, tests | Supported | Does not require generic untrusted execution |
| GitHub-hosted Ubuntu CI | Portable regression, packaging, ordinary integration | Supported | Not privileged containment qualification |
| Privileged Linux verification host | Native/supervised sandbox and containment evidence | Supported as a qualification profile when prerequisites exist | Specific tested execution path only |
| Generic POSIX untrusted Harness Node invocation | Normal `NodeInvoker` isolated-node path | **Routed through the supervised backend** (H0.2 sealed) | Executes with enforcement evidence on a qualified privileged Linux host; fails closed before workload start elsewhere |
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

## 3. Generic untrusted-node routing (H0.2 sealed)

The normal isolated-node call chain is:

```text
Orchestrator
  ↓
NodeInvoker
  ↓
SubprocessRunner.run_isolated()
  ↓
_run_supervised_untrusted() → the supervised backend
```

At the pinned implementation baseline, POSIX `local_untrusted` and `remote_untrusted` requests route through the supervised backend, which owns the entire spawn/lifecycle: PID-namespace topology, requested namespaces, read-only mount confinement, the five-set capability boundary, requested seccomp, and ptrace exec authority. The former T3.0 safety fence was replaced by this routing branch as the final production edit of H0.2.

The result mapping preserves supervisor truth in the compatibility shape, and the `supervised_execution` evidence projection rides both success and failure. There is no try-supervised-except-legacy fallback under any condition: the legacy POSIX spawn body is unreachable for untrusted trust levels.

### Operational consequence

A deployment running ordinary untrusted Harness Nodes on POSIX needs a host that satisfies the supervised prerequisites (section 5) and a qualified installation layout (see the canonical matrix). On any other host the invocation fails closed before workload start with `process_started=false` — an explicit refusal, never a weaker fallback.

### Qualified containment boundaries at this baseline

- mount confinement binds `/package` and every runtime extra mount read-only, with `/tmp` writable; a refused read-only remount fails containment closed before workload start;
- a verified capability boundary removes the boundary-undoing capabilities (including `CAP_SYS_CHROOT` and `CAP_SYS_ADMIN`) from all five relevant capability sets before `enforcement_verified`;
- every Python launch is trust-rooted (`-I` workload, trusted-installation import root, `-P` supervisor/bootstrap);
- requested seccomp is really enforced when a filter binding is present, with kernel SIGSYS denial proof; without a binding the run fails closed;
- requested cgroup accounting/limits are refused in the parent before any start (`supervised_cgroup_unsupported`).

---

## 4. Supervised Linux execution substrate

The supervised execution stack below is the active substrate of the generic route above — developed and hardened through v3.5.1, joined to the ordinary path by H0.2.

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

This is the active substrate of the generic POSIX untrusted-node routing (H0.2 sealed).

---

## 5. Privileged Linux qualification prerequisites

Security/containment evidence for supervised/native paths may require host capabilities such as:

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

### Historical capability-field anchors

Earlier Linux sandbox qualification reports used fields such as:

| Field | Historical evidence meaning |
|---|---|
| `resource_limits_enforced` | RLIMIT/resource controls were applied in the path being reported |
| `syscall_filtering_enforced` | syscall filtering was actually active in the qualified child/workload path |
| `seccomp_enforced` | the named seccomp profile was applied in that path |
| `network_namespace_enforced` | the qualified child observed the requested network namespace |
| `pid_namespace_enforced` | the qualified child executed in the requested PID namespace path |
| `procfs_namespace_view_enforced` | the qualified path established the intended namespace-local procfs view |

Earlier qualified reports included values such as:

```text
seccomp_enforced: True
syscall_filtering_enforced: True
```

These names remain useful evidence/compatibility anchors. Their presence in a historical report does **not** mean every current execution path emits `True`; current claims must bind them to the actual runner/profile that produced the evidence.

### Seccomp tooling for historical/qualification profiles

Some historical Linux qualification paths used the system development package plus Python seccomp bindings:

```bash
sudo apt-get install -y libseccomp-dev
pip install seccomp
```

A successful import/install is only a prerequisite. It is not proof that a particular workload crossed the seccomp-enforced execution boundary.

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

- `namespace_available` — capability is available on the host;
- capability requested;
- capability actually enforced;
- `mount_namespace_enforced` — the qualified child observed mount namespace isolation in the tested path;
- workload actually started;
- terminal cleanup result;
- fallback/fail-closed behavior.

### Mount namespace prototype and root filesystem hardening

Earlier qualification work included a **Mount Namespace Prototype** that demonstrated:

- mount namespace creation via `CLONE_NEWNS` and isolation;
- `pivot_root` or read-only rootfs as a root-filesystem hardening primitive;
- verification that the workload could not escape the mount namespace;
- `mount_namespace_enforced` evidence from the qualified child in that path.

These prototypes remain documented evidence of what the supervised substrate is designed to enforce. The generic POSIX untrusted-node path now routes through the supervised substrate (H0.2); the prototypes' own evidence stays bound to the runs that produced it.

### Namespace Behavior on Proxmox LXC

Historical qualification on Proxmox LXC hosts recorded specific namespace behavior:

- `mount_namespace_enforced` in the LXC qualification path;
- `namespace_available` detection for mount/PID/network on LXC hosts;
- `namespace_mode` reporting for each namespace type tested;
- `already_nested` detection when the host environment was itself already inside a container or namespace;
- observed differences between full-VM and LXC nesting behavior.

Proxmox LXC evidence remains valid for the hosts it was collected on. New qualification hosts must re-establish enforcement evidence rather than inheriting the historical claim.

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

## 10. Proxmox, full VM, and LXC qualification guidance

NodeChain has historical qualification evidence from Proxmox environments, including LXC-based verification hosts. That history is useful evidence for those exact hosts, but virtualization type changes containment semantics and must be recorded with each new qualification.

For a clean Linux containment qualification profile, a **full VM** is generally easier to reason about than nested **LXC**, because a VM owns a complete guest-kernel environment while LXC shares the host kernel and can introduce namespace, cgroup-delegation, seccomp, and capability constraints.

A reasonable fresh qualification host is an Ubuntu 24.04 LTS VM or another explicitly supported Linux distribution with the required kernel capabilities. An LXC host can still be used when its nesting/privilege configuration is deliberate and the evidence records those facts.

Do not infer “full VM stronger than LXC” as a proof of a particular NodeChain control: the NodeChain path must still emit/retain its own enforcement evidence.

---

## 11. Production service guidance at this baseline

### Trusted/internal workload service

A controlled Linux service account may run NodeChain for built-in/trusted workflows, subject to normal OS hardening, secrets management, filesystem permissions, network policy, and the NodeChain policy/trust model.

A minimal **systemd** example for a trusted/internal service profile might look like:

```ini
[Unit]
Description=NodeChain trusted internal service
After=network.target

[Service]
Type=simple
User=nodechain
WorkingDirectory=/opt/nodechain
Environment=NODECHAIN_PROVIDER=mock
ExecStart=/opt/nodechain/.venv/bin/nodechain api serve --host 127.0.0.1 --port 8765
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

This service example is an outer process-management recipe. It does not enable the generic POSIX untrusted Harness Node path or prove containment.

### Untrusted Harness Node service

There is no weaker legacy POSIX path: the supervised route is the only backend, and the legacy spawn body is unreachable for untrusted trust levels.

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

## 12. Windows relationship

Windows is a separate platform profile for NodeChain development, CLI, package validation, and applicable runtime behavior.

NodeChain does not claim Windows implements Linux-equivalent:

- PID namespaces;
- seccomp syscall filters;
- `/proc` namespace views;
- cgroup v2 semantics.

Windows process/Job Object controls should be documented and qualified as Windows controls rather than described as equivalent Linux mechanisms.

---

## 13. Evidence to retain for a qualified Linux deployment

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

## 14. Historical PID Namespace / procfs compatibility anchors

Older v1.x sandbox documentation and characterization tests use a compact enforcement vocabulary that remains part of the historical compatibility record. The terms below describe those earlier qualified paths; they do not override the current T3 fail-closed boundary for generic POSIX untrusted Harness Nodes.

### Historical enforcement hierarchy

The earlier Linux sandbox model can be read as a layered defense-in-depth stack:

```text
Layer 1 — process isolation and bounded child lifecycle
Layer 2 — Python-level import/filesystem/subprocess/network enforcement
Layer 3 — resource limits and cgroup controls where requested/available
Layer 4 — namespace isolation (network, mount, PID Namespace and procfs view)
Layer 5 — seccomp syscall filtering on qualified Linux paths
```

These layers were cumulative evidence surfaces, not interchangeable guarantees. A later/current path must still prove which layers actually executed.

### PID Namespace behavior

In the historical v1.5 PID Namespace path, the namespace child was designed to become **PID 1** inside the newly created PID namespace. That role matters because PID 1 has namespace-init responsibilities and different signal/reaping behavior from an ordinary process.

The later v3.5.1 supervised design made the topology more explicit: the namespace init owns descendant reaping while the bootstrap/workload has a distinct verified identity. Current supervised claims should therefore use the v3.5.1 topology/evidence rather than infer behavior from the older shorthand alone.

### procfs remount / namespace view

The historical procfs integration paired PID namespace creation with a **procfs remount** so `/proc` could reflect namespace-local process identity rather than the host process view. Evidence fields/documentation used names such as:

```text
procfs_namespace_view_enforced
```

Again, this is a compatibility/evidence anchor for the path that implemented it. A current deployment must prove the actual `/proc`/namespace topology of the runner being qualified.

---

## 15. Hardened Sandbox Profile — historical compatibility table

The `hardened_untrusted` profile and its invariant names remain part of NodeChain's compatibility/documentation lineage. This table records the historical intent of the profile; it does **not** override the current T3 fence for generic POSIX `local_untrusted` / `remote_untrusted` Harness Nodes.

| Layer / invariant | Historical requirement | Required in hardened profile? |
|---|---|---|
| `INV-001` | Untrusted execution requires process/subprocess isolation | Required |
| `INV-002` | Untrusted execution requires child policy enforcement | Required |
| `INV-003` | Isolated subprocess execution requires filtered environment | Required |
| `INV-004` | Isolated subprocess execution requires temp/CWD isolation | Required |
| `INV-005` | Locked execution requires lockfile verification | Required when locked |
| `INV-006` | Required sandbox profile must be the profile actually used | Required |
| `INV-007` | Required sandbox capability, historically including seccomp in Linux `os_profile`, must be enforced | Required |
| `INV-009` | Requested cgroup limits must be enforced | Required |
| `INV-011` | Required network namespace must be enforced | Required |
| `INV-012` | Required mount confinement must be enforced | Required |
| `INV-013` | Required PID namespace must be enforced | Required |

The current implementation and host evidence remain authoritative for whether each capability is actually reachable and enforced in a given execution path.

---

## 16. Related documents

- `BASELINE.md` — current implementation truth
- `ARCHITECTURE.md` — current execution architecture
- `ROADMAP.md` — T3 and authority-closure outcomes
- `docs/ci.md` — hosted qualification semantics
- `docs/native_sandbox_verification.md` — historical native command-runner verification evidence
- `CHANGELOG.md` — v3.5.1 supervised execution release history
