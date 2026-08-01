# Native Sandbox Test Runner (v2.76)

## What this release does

v2.99.0 **routes the Code Review chain's pytest execution through NodeChain's
existing native OS sandbox stack**, closing the routing gap between
`sandbox_test_runner` and the already-built namespace / seccomp / cgroup /
mount-confinement machinery.

It does **not** add Docker. It does **not** redesign patch governance.

## The gap v2.76 closes

Before v2.76, `sandbox_test_runner._run_pytest()` ran pytest directly via
`subprocess.run(..., shell=False)` in the temp workspace. The broader runtime
already had native isolation machinery (`RunnerConfig` exposes cgroup,
namespace, mount-confinement, PID/procfs, timeout, output, and memory
controls; the child bootstrap already sequences PID namespace, network
namespace, mount namespace, chroot-style mount confinement, seccomp, and
Python enforcers). The gap was **command execution**, not sandbox capability.

v2.76 adds a dedicated command-execution seam (`SandboxCommandRunner`) that
reuses those primitives without polluting the node-module-oriented
`SubprocessRunner`.

## Backends

```text
local_subprocess      # default — existing v2.73/v2.75 behavior, unchanged
native_os_sandbox     # opt-in — reuses native OS sandbox primitives
```

Selection:

```bash
NODECHAIN_SANDBOX_BACKEND=local_subprocess     # default
NODECHAIN_SANDBOX_BACKEND=native_os_sandbox    # opt-in
```

The variable is read through `BaseNode.sandbox_backend`, mirroring the
existing `NODECHAIN_SANDBOX_PROFILE` precedent.

## Fail-closed behavior

If `native_os_sandbox` is explicitly requested but the host cannot enforce it
(non-Linux, or required primitives unavailable), the backend **fails closed**:

```text
process_started = False
exit_code_interpretation = "error"
reason = "native_sandbox_unavailable"
```

There is **no silent fallback** to `local_subprocess`. An explicit native
request that cannot be honored is an error, not a quiet downgrade.

## What the native path isolates

The native backend reuses the existing validated primitives:

- **Network namespace** (`CLONE_NEWNET`) — outbound network blocked
- **Mount namespace + confinement** (`CLONE_NEWNS` + chroot) — filesystem
  restricted to `/package`, `/tmp`, and the patched workspace at `/workspace`
- **PID namespace** (two-stage fork) — process visibility restricted
- **Seccomp filter** — 22 dangerous syscalls denied
- **Cgroups** — memory / CPU / PID limits
- **Python enforcers** — import / filesystem / subprocess / network policy

The patched temp workspace is bind-mounted into the confined child at
`/workspace` (via the v2.76 `workspace_src` extension to
`apply_mount_confinement`), and pytest runs with `cwd=/workspace`,
`PYTHONPATH=/workspace/src`.

## What this does NOT guarantee

This release **does not claim complete hostile-code containment**.

- Native enforcement strength **varies by host capability**. The strongest
  primitives (namespaces, seccomp, cgroups) are Linux syscalls. On Windows
  the runtime falls back to Job Objects; on macOS to detection-only.
- The native sandbox is a strong practical boundary, not a formal security
  proof against kernel exploits or a compromised host.
- The local backend (`local_subprocess`) provides governed temp-workspace
  isolation only — it does not isolate the host from the test process beyond
  the bounded command profile, env allowlist, and git-status integrity guard.

## Trace events

v2.76 newly wires the v2.73 `EventType` constants (workspace creation, patch
apply, command authorization, code execution, output capping, cleanup,
classification) into an actual emission layer. The node produces a structured
`sandbox_event_log`; `NodeEventEmitterMixin` consumes it and emits the real
trace events. The node never writes trace events directly — the runtime
retains trace authority.

## Adversarial validation

A Linux-gated adversarial test (`TestNativeNetworkBlocking`) proves the
native network namespace blocks outbound connections through the test-runner
path. It is skipped on non-Linux hosts, matching the convention used by the
existing native-sandbox test suite.

## Roadmap

```text
v2.99.0 — Native OS-Sandboxed Test Runner Execution (this release)
v2.99.0 — Docker backend only if justified as defense-in-depth / packaging
v2.99.0 — Quickstart flow or trace primitive extraction
```
