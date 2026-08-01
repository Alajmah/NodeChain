# NodeChain Linux Deployment — Proxmox Baseline

This guide covers deploying NodeChain on a Linux VM (Proxmox or bare metal)
for production use and Linux sandbox validation.

## Quick Start

### Option A: Fresh VM Setup

```bash
# 1. Create an Ubuntu Server LTS VM on Proxmox (full VM, not LXC)
# 2. SSH into the VM
# 3. Clone and setup:
git clone <repo-url> /opt/nodechain
cd /opt/nodechain
bash scripts/setup_linux.sh

# 4. Validate:
bash scripts/validate_linux.sh
```

### Option B: Docker

```bash
docker build -t nodechain .
docker run --rm nodechain run "test query" \
    --blueprint blueprints/echo_demo_v1.yaml \
    --provider mock
```

### Option C: Docker Compose (with ChromaDB)

```bash
docker-compose up -d
docker-compose exec nodechain run "test query" --provider mock
```

---

## Linux Sandbox Capability Matrix

When running on Linux, NodeChain reports these capabilities honestly:

| Capability | Status | Mechanism |
|-----------|--------|-----------|
| `resource_limits_enforced` | ✅ Real | RLIMIT_CPU, RLIMIT_AS, RLIMIT_FSIZE |
| `syscall_filtering_enforced` | ⚠️ Optional | seccomp (requires `pip install seccomp` + `libseccomp-dev`) |
| `namespace_available` | ✅ Real (v1.4.0) | `unshare()` detection via `/proc/self/ns/` |
| `network_namespace_enforced` | ✅ Real (v1.4.0) | `os.unshare(CLONE_NEWNET)` in child bootstrap |
| `namespace_mode` | ✅ Real (v1.4.0) | `none` \| `detected` \| `nested` \| `created` |
| `cgroup_accounting_readable` | ✅ Real | cgroup v2: memory, cpu, pids accounting |
| `cgroup_limits_writable` | ✅ Real | cgroup v2: memory.max, pids.max, cpu.max |
| `cgroup_accounting_scope` | ✅ `invocation` | Per-node child cgroup with lifecycle |
| `job_object_enforced` | N/A | Windows only |
| `apparmor_profile_used` | ❌ Not implemented | Planned |
| `mount_namespace_enforced` | ✅ Prototype (v1.4.3) | `unshare(CLONE_NEWNS)` + `MS_PRIVATE\|MS_REC` |
| `pid_namespace_enforced` | ✅ v1.5.0 | `unshare(CLONE_NEWPID)` + fork, child is PID 1 |
| `procfs_namespace_view_enforced` | ✅ Prototype (v1.5.1) | /proc remounted for namespace-local PIDs |

### Namespace Behavior on Proxmox LXC

Proxmox CT 801 (with `nesting=1`, `keyctl=1`) supports all 6 namespace types.
The container itself runs inside its own mount/pid/net namespaces (`already_nested=true`).
Child processes can create additional namespaces via `unshare()`, including network
namespaces that isolate the child from all network interfaces.

Network namespace enforcement (`production_untrusted` preset):
- `os.unshare(CLONE_NEWNET)` runs in child bootstrap Phase 1a
- Child gets new network namespace with only `lo` (down)
- Socket connections fail with `OSError` — kernel-level isolation
- INV-011 fires as error if namespace creation fails when required

Mount namespace prototype (v1.4.3, not required by any preset):
- `unshare(CLONE_NEWNS)` creates new mount namespace in child
- `MS_PRIVATE|MS_REC` makes mount propagation private
- Child mount namespace inode differs from parent
- No `pivot_root`, bind mounts, or read-only rootfs yet
- Available via `enable_mount_namespace=True` on RunnerConfig/SubprocessRunner
- Composes with network namespace (both can be active simultaneously)

### Enabling Seccomp

```bash
# Install system dependency
sudo apt-get install -y libseccomp-dev

# Install Python bindings
pip install seccomp

# Verify
python -c "from nodechain.sdk.seccomp_profile import detect_seccomp; b = detect_seccomp(); print(f'Available: {b.available}')"
```

---

## Proxmox VM Recommendations

| Setting | Value |
|---------|-------|
| Type | Full VM (not LXC) |
| OS | Ubuntu Server 22.04 LTS or 24.04 LTS |
| CPU | 2+ cores |
| Memory | 4 GB minimum (8 GB for GPU model inference) |
| Disk | 20 GB |
| Network | Bridge or NAT |

### Why full VM, not LXC?

LXC containers share the host kernel and have nesting constraints around:
- seccomp (filter inheritance)
- namespaces (already nested)
- cgroups (delegation complexity)
- AppArmor (profile composition)

A full VM gives clean evidence for all sandbox mechanisms.

---

## Validation

After setup, run the validation script:

```bash
bash scripts/validate_linux.sh
```

- Full test suite results (should be 1420+ passed, ~13 skipped)
- Linux sandbox capability report
- CLI command verification
- Honest assessment of what is enforced vs not implemented

### Expected Results on Proxmox LXC with seccomp + cgroup (v1.3.1)
```text
Passed:  1427
Skipped: 13 (Windows-only + platform-specific)
Failed:  0

Sandbox capability report:
  resource_limits_enforced:    True     (RLIMIT -- real on Linux)
  seccomp_available:           True     (pyseccomp detected)
  seccomp_enforced:            True     (applied in child subprocess)
  seccomp_profile_name:        nodechain_default
  syscall_filtering_enforced:  True     (20 dangerous syscalls denied)
  cgroup_available:            True     (cgroup v2 detected)
  cgroup_version:              v2
  cgroup_accounting_readable:  True     (memory, cpu, pids accounting)
  cgroup_limits_writable:      True     (can create child cgroups)
  cgroup_accounting_scope:     invocation  (per-node child cgroup)

Per-invocation evidence (echo node):
  cgroup_path:                 /sys/fs/cgroup/nodechain_echo_xxxxxx
  memory_peak_bytes:           18,137,088 (17.3 MB)
  cpu_usage_usec:              255,001    (0.255 seconds)
  pids_peak:                   1
  cgroup cleaned up:           True       (removed after execution)
```

The seccomp profile denies: fork, vfork, clone, clone3, ptrace, mount,
umount2, reboot, kexec_load, init_module, finit_module, delete_module,
setns, unshare, perf_event_open, bpf, userfaultfd, mbind, migrate_pages,
move_pages.

### Expected Results without seccomp library

```text
Passed:  1379
Skipped: 13 (Linux seccomp tests)
Failed:  0

seccomp_available:  False
seccomp_enforced:   False
```

---

## Production Deployment

### systemd Service

```ini
# /etc/systemd/system/nodechain.service
[Unit]
Description=NodeChain Governed Local Trust Platform
After=network.target

[Service]
Type=simple
User=nodechain
WorkingDirectory=/opt/nodechain
Environment=NODECHAIN_PROVIDER=lim
Environment=LIM_BASE_URL=http://localhost:8766
ExecStart=/opt/nodechain/.venv/bin/python -m nodechain.cli.main run --provider mock
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### Running with Real LLM (LIM)

```bash
# Start LIM on the GPU machine
# Point NodeChain at LIM
export NODECHAIN_PROVIDER=lim
export LIM_BASE_URL=http://gpu-machine:8766
export NODECHAIN_MODEL=gemma-4-12b

# Run with full trust gates
nodechain run "research query" \
    --blueprint blueprints/research_decision_v1.yaml \
    --locked --strict --trust-check
```

---

## Hardened Untrusted Preset (v1.4.5–v1.4.7)

### Hardened Sandbox Profile (v1.5.2)

The complete hardened sandbox profile, showing every enforcement layer:

| Layer | Enforcement | Required? | Platform | Invariant |
|-------|-------------|-----------|----------|----------|
| Subprocess isolation | Separate OS process | ✅ Required | All | INV-001 |
| Child policy enforcement | Import/fs/subprocess/net hooks | ✅ Required | All | INV-002 |
| Environment filtering | Sensitive env vars stripped | ✅ Required | All | INV-003 |
| Temp directory isolation | Per-invocation temp dir | ✅ Required | All | INV-004 |
| Lockfile verification | Content hash verified | If locked | All | INV-005 |
| Sandbox profile used | os_profile enforced | ✅ Required | All | INV-006 |
| Sandbox capability enforced | Seccomp/namespace/cgroup | ✅ Required | Linux | INV-007 |
| OS capability available | At least one OS enforcement | ✅ Required | Linux | INV-008 |
| Cgroup limits enforced | memory/PID/CPU limits | ✅ Required | Linux | INV-009 |
| Preset requirements satisfied | All declared requirements | ✅ Required | All | INV-010 |
| Network namespace enforced | No network interfaces | ✅ Required | Linux | INV-011 |
| Mount confinement enforced | chroot: /package + /tmp only | ✅ Required | Linux | INV-012 |
| PID namespace enforced | Child is PID 1 | ✅ Required | Linux | INV-013 |
| Seccomp syscall filtering | 20 dangerous syscalls blocked | ✅ Required | Linux | INV-007 |
| Cgroup resource accounting | Per-invocation accounting | ✅ Required | Linux | INV-008 |
| RLIMIT | File/CPU/open-files limits | Advisory | All | — |
| Procfs remount | Namespace-local /proc | Optional | Linux | — |
| Python API enforcement | Import/fs/subprocess/net | ✅ Required | All | INV-002 |

**Legend**: Required = enforced by strict mode (exit 15). Advisory = reported but not blocking. Optional = available via RunnerConfig.

The `hardened_untrusted` preset provides the strongest local sandbox:

```text
subprocess isolation
+ seccomp syscall filtering (20 dangerous syscalls)
+ cgroup v2 limits (512MB memory / 50 PIDs / 2 CPUs)
+ network namespace isolation (no network interfaces)
+ mount namespace creation + private propagation
+ chroot-based filesystem confinement (temp root)
+ strict trust invariants (INV-001 through INV-012)
+ trust-check required
```

### Usage

```bash
# CLI override
nodechain run "query" \
    --blueprint blueprints/hardened_untrusted_demo_v1.yaml \
    --trust-check --strict

# Or via env var
export NODECHAIN_POLICY_PRESET=hardened_untrusted
nodechain run "query" --blueprint blueprints/echo_demo_v1.yaml
```

### Chroot Compatibility Matrix

Under chroot, the child process can only access:
- `/package/` — node implementation directory (bind-mounted)
- `/tmp/` — invocation temp directory (bind-mounted)

Host paths like `/etc/passwd` return `FileNotFoundError`.

| Node Pattern | Status | Notes |
|---|---|---|
| Pure Python (echo) | ✅ Proven | No external dependencies |
| Package resource (data file) | ✅ Proven | File in package dir accessible via /package |
| Stdlib imports (json, math, re) | ✅ Proven | Pre-loaded in sys.modules |
| Host path access (/etc/passwd) | ✅ Blocked | FileNotFoundError at kernel level |
| Forbidden import (ctypes) | ✅ Blocked | Import enforcer defense-in-depth |

### Known Limitations

Not yet broadly proven under chroot:
- **Native extensions** (`.so` files) — may fail if they depend on
  shared libraries outside the chroot
- **Dynamic shared libraries** — chroot restricts library search path
- **Model/data files** outside package directory — only `/package/`
  and `/tmp/` are accessible
- **Runtime plugin loading** — dynamic imports from non-package paths
  will fail

### Packaging Chroot-Compatible Nodes

To ensure your node works under `hardened_untrusted`:

1. **Pure Python preferred** — avoid native extensions
2. **Bundle data files in the package directory** — they'll be at
   `/package/` under chroot
3. **Use stdlib modules** — they're pre-loaded before chroot
4. **Avoid runtime path discovery** — `__file__` resolves to
   `/package/<filename>` under chroot
5. **Test with hardened_untrusted** — `nodechain run ... --policy-preset
   hardened_untrusted --trust-check`

### Preset Comparison

| Feature | production_untrusted | hardened_untrusted |
|---|---|---|
| Subprocess isolation | ✅ | ✅ |
| Seccomp | ✅ | ✅ |
| Cgroup limits | ✅ | ✅ |
| Trust check | ✅ | ✅ |
| Network namespace | ✅ | ✅ |
| Mount namespace | ✅ | ✅ |
| **Mount confinement (chroot)** | ❌ | **✅** |
| **PID namespace** | ❌ | **✅** |

---

## PID Namespace Isolation (v1.5.0–v1.5.1)

The `hardened_untrusted` preset includes PID namespace isolation.

### How it works

```text
1. unshare(CLONE_NEWPID)  — marks new PID namespace
2. fork()                  — child is PID 1 in new namespace
3. Parent waits, exits with child's status
4. Child continues with all enforcement phases
```

The child process observes itself as PID 1 in the new namespace.

### /proc Visibility

**Without procfs remount** (v1.5.0):
- Host /proc remains visible (same procfs mount)
- Child's own PID is 1 in the new namespace
- Host PIDs are NOT in the child's PID namespace — cannot send signals
  to host processes from child
- Host PID entries are still visible in /proc

**With procfs remount** (v1.5.1, optional):
- /proc is remounted for the PID namespace
- Only namespace-local PIDs visible in /proc
- `procfs_namespace_view_enforced=true`
- Requires `enable_procfs_isolation=True`

### PID 1 Behavior

A process running as PID 1 has special kernel behavior:

- **Signal handling**: PID 1 does not receive default-action signals
  (SIGTERM, SIGINT) unless explicitly handled. This means the child
  won't be killed by signals that would normally terminate a process.
  The timeout mechanism in SubprocessRunner uses SIGKILL which bypasses
  this protection.

- **Zombie reaping**: PID 1 is responsible for reaping orphaned
  children. If a grandchild process exits, PID 1 must call waitpid()
  to prevent zombies. Under seccomp + cgroup limits, the child
  typically cannot spawn subprocesses, so this is a theoretical
  concern. The runtime does not install a zombie reaper.

- **Shutdown**: When the node execution completes, the child exits
  normally. The parent process (pre-fork) relays the exit status.

### Enforcement Layer Hierarchy (Corrected)

```text
Layer 1 — Kernel isolation:
  Network namespace     — no network interfaces
  Mount namespace       — separate mount tree
  Mount confinement     — chroot: /package + /tmp only
  PID namespace         — child is PID 1, separate PID space

Layer 2 — Kernel syscall filtering:
  Seccomp               — 20 dangerous syscalls blocked

Layer 3 — Kernel resource governance:
  Cgroup v2             — memory/PID/CPU limits per invocation
  RLIMIT                — file size, CPU time, open files

Layer 4 — Python/API enforcement:
  Import enforcer       — blocks dangerous module imports
  Filesystem enforcer   — blocks file I/O outside policy
  Subprocess enforcer   — blocks process spawning
  Network enforcer      — blocks network at socket level

Layer 5 — Governance:
  13 trust invariants   — INV-001 through INV-013
  4 policy presets      — minimal → standard → production → hardened
  CI trust gates        — exit code 15 on trust violation
```
