# NodeChain CI Contract (v3.6.0)

This document defines how NodeChain is verified in CI and how to reproduce
CI runs locally.

## Verification tiers (v3.6.0)

Three tiers of verification are used, each with a distinct evidentiary value:

```text
1. Full-suite green (strongest)
   All tests collected and run in a single pytest invocation.
   .28 Linux: ~5.5 min — the authoritative release gate.
   Windows: ~10 min — may exceed local tool ceilings; use sharded path if needed.

2. Sharded full-suite green (strong)
   All test files run in N shards via scripts/run_full_suite_sharded.py.
   Per-shard results aggregated into a combined summary.
   Sharded totals may differ slightly from single-run due to pytest collection-
   order effects (some tests are collected only in cross-file fixture context).
   Use when the single-run path hits a time/tool ceiling.

3. Targeted affected-area green (weakest, but useful for iteration)
   A curated set of test files covering the specific code changed.
   Not a release gate alone — must be combined with tier 1 or 2 before tagging.
```

## Windows sharded suite (v3.6.0)

When the Windows full suite exceeds available time/tool ceilings, use:

```bash
python scripts/run_full_suite_sharded.py --shards 6
```

This runs 264 test files in 6 sequential shards (~10 min total wall time),
aggregates the results, and exits non-zero on any failure. Each shard is
small enough to complete within a single tool invocation if needed.

**Reconciliation note:** sharded totals (sum of per-shard results) may be
~100-120 tests fewer than a single-run collection due to pytest collection-
order effects. This is expected — the shards verify every test file runs
green; the count difference is a collection artifact, not a missing-test bug.

## GitHub-hosted runners

All CI jobs run on **GitHub-hosted runners**. Linux jobs use `ubuntu-24.04`;
Windows jobs use `windows-2022`. Each job receives a fresh VM with no shared
state. This model is portable, free for public repositories, and avoids the
security risks of attaching self-hosted runners to a public repository.

Pinned official actions run on the **Node 24** runtime:
`actions/checkout@v7.0.1` and `actions/setup-python@v7.0.0`.

## GitHub Actions workflow

Location: `.github/workflows/ci.yml`

Triggers: `push` to `master`, all `pull_request`.

### Jobs

| Job | Runner | Timeout | Purpose | Blocking |
|-----|--------|---------|---------|----------|
| `lint` | `ubuntu-24.04` | 10 min | py_compile all source + Ruff (E9,F63,F7,F82) | ✅ |
| `unit-fast` | `ubuntu-24.04` | 30 min | Fast unit + governance tests (excludes slow files) | ✅ |
| `orchestrator-recovery` | `ubuntu-24.04` | 20 min | Orchestrator + recovery console + budget tests | ✅ |
| `trust-collector` | `ubuntu-24.04` | 20 min | Trust + registry + dashboard + collector semantics | ✅ |
| `slow-shard-1` | `ubuntu-24.04` | 25 min | Checkpoint + loop + evidence | ✅ |
| `slow-shard-2` | `ubuntu-24.04` | 25 min | Sandbox + namespace + security (native capability; `continue-on-error` internally, tolerated on hosted) | ✅ (required) |
| `slow-shard-3` | `ubuntu-24.04` | 25 min | Proxmox adapter + network + integration | ✅ |
| `windows-tests` | `windows-2022` | 90 min | Cross-platform fast tests | ✅ |
| `cli-smoke` | `ubuntu-24.04` | 15 min | CLI command surface (includes `recover`) | ✅ |
| `package-build` | `ubuntu-24.04` | 15 min | `python -m build --wheel` | ✅ |

### slow-shard-2 tolerance

`slow-shard-2` retains `continue-on-error: true` in the workflow because it
exercises kernel-level sandbox features (seccomp, cgroups, mount namespaces)
that require privileges unavailable on standard hosted runners. The job is
nonetheless a **required** branch-protection check: capability-sensitive tests
that genuinely cannot run on hosted infrastructure produce explicit reasoned
skips, not silent disappearance, so the job remains a meaningful gate.

## Local verification (Makefile)

The `Makefile` mirrors the CI jobs so "verified locally" = "verified in CI":

```bash
make install          # pip install -e ".[dev]"
make ci-core          # ci-fast + ci-recovery + ci-trust in sequence
make ci-blocking      # all blocking CI jobs (lint + fast + recovery + trust + shards + smoke + package)
make ci               # alias for ci-blocking (full blocking CI surface)
make ci-fast          # fast unit + governance tests (excludes slow files)
make ci-recovery      # orchestrator + recovery + budget tests
make ci-trust         # trust + registry + dashboard tests
```

## Slow-test policy

The following test files are excluded from `unit-fast` and run in dedicated
shards or with `continue-on-error`:

**Sandbox/security (need kernel privileges):**
```
test_seccomp_*, test_cgroup_*, test_pid_namespace*, test_mount_confinement*,
test_namespace_*, test_subprocess_*, test_sandbox_demo, test_cwd_temp_isolation,
test_hostile_network_cert, test_adversarial_remote, test_network_hardening,
test_preset_e2e, test_preset_wiring
```

**Slow integration (exceed timeout in fast job):**
```
test_checkpoint_*, test_dashboard_health, test_dashboard_live_data,
test_memory_dashboard, test_graph_cli_parity, test_chain_orchestrator,
test_evaluation_suite_lifecycle, test_workflow_recovery_integration
```

## Required checks (branch protection)

Branch protection is technically enforced on `master` with strict status checks
and `enforce_admins: true`. The repository is public; required approvals are
`0` for the solo maintainer. The following **12** checks are required:

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

## Version snapshot tests

NodeChain has ~30 test files that assert `nodechain.__version__ == "X.Y.Z"`.
When bumping the version (in `__init__.py` + `pyproject.toml`), update these
snapshots or CI will fail. The version is currently `3.6.0`.

## Branch protection status

This repository is **public**. Branch protection is technically enforced via a
GitHub ruleset with strict required status checks and `enforce_admins: true`.
Public repositories on GitHub Free do offer branch protection, so no paid plan
is required for enforcement.

**Operating state (v3.6.0):**

- Strict required checks: enabled (the 12 checks listed above).
- Required approvals: `0` (solo maintainer).
- `enforce_admins`: true.
- `windows-tests`: required (90-minute timeout), blocking.
- Publication Tree (Ubuntu and Windows): required, blocking.
- Ruff: blocking (`E9,F63,F7,F82`), no `--exit-zero`.
- GitHub Actions runtime: Node 24 for the pinned official actions
  (`checkout@v7.0.1`, `setup-python@v7.0.0`).

**Project policy** (still applies alongside technical enforcement):

- Pull requests and master pushes must have green blocking CI before release.
- No direct master commits except emergency recovery.
- Every feature/change should go through a PR where possible.
- Release tags must only be created from a green master commit.
- `slow-shard-2` is required at the branch-protection level but tolerates
  capability-sensitive sandbox tests internally via `continue-on-error`, since
  those tests require kernel privileges unavailable on standard GitHub-hosted
  runners.
