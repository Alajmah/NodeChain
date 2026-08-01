# NodeChain CI Contract (v3.5.1)

This document defines how NodeChain is verified in CI and how to reproduce
CI runs locally.

## Verification tiers (v3.5.1)

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

## Windows sharded suite (v3.5.1)

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

## GitHub Actions workflow

Location: `.github/workflows/ci.yml`

Triggers: `push` to `master`, all `pull_request`.

### Jobs

| Job | Runner | Purpose | Blocking |
|-----|--------|---------|----------|
| `lint` | `ubuntu-24.04` | py_compile all source + Ruff (syntax errors) | ✅ |
| `unit-fast` | `ubuntu-24.04` | Fast unit + governance tests (excludes slow files) | ✅ |
| `orchestrator-recovery` | `ubuntu-24.04` | Orchestrator + recovery console + budget tests | ✅ |
| `trust-collector` | `ubuntu-24.04` | Trust + registry + dashboard + collector semantics | ✅ |
| `slow-shard-1` | `ubuntu-24.04` | Checkpoint + loop + evidence | ✅ |
| `slow-shard-2` | `ubuntu-24.04` | Sandbox + namespace + security (native capability; may skip on hosted) | `continue-on-error` |
| `slow-shard-3` | `ubuntu-24.04` | Proxmox adapter + network + integration | ✅ |
| `windows-tests` | `windows-2022` | Cross-platform fast tests | `continue-on-error` |
| `cli-smoke` | `ubuntu-24.04` | CLI command surface (includes `recover`) | ✅ |
| `package-build` | `ubuntu-24.04` | `python -m build --wheel` | ✅ |

### Non-blocking jobs

`slow-shard-2` and `windows-tests` have `continue-on-error: true` because they
test kernel-level sandbox features (seccomp, cgroups, mount namespaces) that
require privileges or platform features unavailable on standard hosted runners.
Their results are visible but don't block merge. Tests that genuinely cannot
run on hosted infrastructure produce explicit reasoned skips, not silent
disappearance.

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

Once the workflow is consistently green on `master`, enable branch protection
requiring these checks:

```text
lint
unit-fast
orchestrator-recovery
trust-collector
slow-shard-1
slow-shard-3
cli-smoke
package-build
```

## Version snapshot tests

NodeChain has ~30 test files that assert `nodechain.__version__ == "X.Y.Z"`.
When bumping the version (in `__init__.py` + `pyproject.toml`), update these
snapshots or CI will fail. The version is currently `3.5.1`.

## Branch protection status

This repository is private and currently hosted under a GitHub plan where
branch protection/ruleset enforcement is not available for private organization
repositories.

Until the repository is moved to a GitHub Team or Enterprise organization
account, CI is advisory rather than technically enforced by GitHub.

**Project policy** (procedural governance until technical enforcement is available):

- Pull requests and master pushes must have green blocking CI before release.
- No direct master commits except emergency recovery.
- Every feature/change should go through a PR where possible.
- Release tags must only be created from a green master commit.
- The following jobs are treated as required by project policy:
  - `lint`
  - `unit-fast`
  - `orchestrator-recovery`
  - `trust-collector`
  - `slow-shard-1`
  - `slow-shard-3`
  - `cli-smoke`
  - `package-build`
- `slow-shard-2` and `windows-tests` are advisory because they include
  environment/platform-incompatible sandbox tests that require kernel
  privileges unavailable on standard GitHub-hosted runners.
