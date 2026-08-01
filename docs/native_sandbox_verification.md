# Native Sandbox Verification (v2.78)

## What is proven (v2.78 — all four primitives)

v2.78 verifies the **integrated v2.76 native_os_sandbox command-runner path**
enforces all four primitives under the **privileged Linux execution profile**
the current implementation requires. Proofs are **child-observed** (the confined
process itself demonstrates the confinement), not metadata-only.

Proven primitives (through `SandboxCommandRunner("native_os_sandbox").run_command(...)`
→ `native_sandbox_exec.run_isolated` → child bootstrap → in-place `os.execve`):

- **Mount confinement** — child reads `/workspace/sentinel.txt` from inside the
  chroot; metadata reports `mount_confinement_enforced=True`.
- **Network namespace** — host positive-control reaches the target
  (`1.1.1.1:53` by default); the sandboxed child cannot reach the same target;
  metadata reports `network_namespace_enforced=True`.
- **PID namespace + procfs isolation** — enforced; metadata clean.
- **Seccomp** (v2.78, was deferred in v2.77) — the child applies the syscall
  filter to itself after namespace/chroot setup, then `os.execve`s the workload
  in place. The filter survives `execve` (Linux guarantee). A fork canary
  workload is killed by SIGSYS (signal 31), proving the filter is active inside
  the workload boundary.

## What is NOT proven (named limitations, not buried caveats)

### ~~Seccomp syscall filtering — deferred to v2.78~~ (CLOSED in v2.78)

v2.77 deferred seccomp because the existing deny-list (fork/vfork/clone/clone3)
was incompatible with the spawner-applied model. **v2.78 closes this** via the
child-applied seccomp redesign: the child applies the filter to itself after
setup, then `os.execve`s the workload. The filter survives `execve`, so the
workload runs confined. The fork canary workload is killed by SIGSYS, proving
enforcement inside the workload boundary. See CHANGELOG v2.99.0 for details.

### GHA-native execution — not claimed

The self-hosted GitHub Actions runner (`gha-runner`, uid 1000) cannot perform
the namespace/chroot operations the native path requires. Enforcement
verification therefore runs as **root on the designated Linux host**, not
inside the GHA job context.

### 3. Unprivileged / production deployment — not proven

The current native_os_sandbox backend requires privileges (`CAP_SYS_ADMIN`,
`CAP_SYS_CHROOT`) that ordinary non-root CI users and many production service
users do not have. v2.77 verifies enforcement under the privileged profile, but
does NOT prove that `sandbox_test_runner` can run from an unprivileged
deployment account. Unprivileged-native execution (likely via user namespaces
with `--user --map-root-user` and a bootstrap adaptation) is a production-
readiness requirement before relying on this backend in non-root service
deployments.

### 4. Not a security proof

v2.77 is enforcement verification of an existing code path against a real Linux
kernel, not a formal security-boundary proof. It does not claim kernel-exploit
resistance, container-escape resistance, compromised-daemon resistance, or
complete hostile-code containment.

## How to run the verification (repeatable procedure)

On the designated Linux verification host, as root:

```bash
# One-time setup:
apt install -y python3-seccomp python3-venv git
# (NodeChain itself: see docs/native_sandbox_test_runner.md or your team's
#  checkout procedure — the repo is private; a git bundle transfer or a
#  token-authenticated clone both work.)
python3 -m venv --system-site-packages .venv
. .venv/bin/activate
pip install -e ".[dev]"

# Each verification run:
scripts/run_native_sandbox_verification.sh
```

The script fail-closes on every precondition (flag, root, Linux, seccomp
bindings, host network reachability, zero/skipped tests). A green-looking run
that verified nothing is impossible.

Expected result:

```
2 passed, 2 xfailed
```

The 2 xfails are the seccomp tests (see "Seccomp deferred" above). Under v2.78
they become 4 passed.

## Host profile (verified, not inferred)

```
host:           the designated Linux verification host
virt:           LXC container (Proxmox 6.8 kernel in the v2.77 reference host)
os:             Ubuntu 24.04 LTS
privileges:     root (uid 0) — REQUIRED
unshare:        --mount --pid --fork, --net, --user variants all OK as root
libseccomp-dev: present
seccomp py:     python3-seccomp (apt), visible via venv --system-site-packages
cgroups:        cgroup2fs (v2)
```

Enforcement strength varies by host capability. The reference host is an LXC
container; if a future verification host is bare metal or a full VM, re-run the
procedure and record the new profile.
