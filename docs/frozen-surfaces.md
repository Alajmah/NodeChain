# NodeChain v1.0.0-rc1 — Frozen Surface Contract

This document defines the public API surfaces frozen for the v1.0.0 release
candidate. Changes to any surface listed here require a version bump per
[semver](https://semver.org/) rules.

---

## 1. CLI Surface (Frozen)

Top-level commands (8):

| Command | Description | Since |
|---------|-------------|-------|
| `run` | Execute a chain from a blueprint | v0.1.0 |
| `inspect` | Show detailed state for a run | v0.1.0 |
| `reconcile` | Cross-check trace against persistent state | v0.1.0 |
| `resume` | Resume a paused or failed run | v0.1.0 |
| `report` | Generate comprehensive run report | v0.1.0 |
| `trace` | View a chain trace | v0.1.0 |
| `trust` | Inspect trust enforcement for a run | v0.8.0 |
| `trust-store` | Manage trusted profile signing keys | v1.8.3 |
| `deploy-receipt` | Create/verify deployment receipts | v1.9.0 |
| `assurance` | Verify entire evidence chain | v1.9.1 |
| `deploy` | Deploy via adapter / verify deployment receipt | v1.10.0 |
| `release-history` | List/verify release history and retention | v1.13.6 |
| `drift` | Deployment drift detection | v1.14.0 |
| `presets` | List available policy presets | v1.3.5 |
| `audit-bundle` | Generate portable evidence bundle | v1.6.0 |
| `attest` | Generate or verify deployment attestation | v1.8.0 |
| `registry` | Node registry operations (subgroup) | v0.3.0 |
| `node` | Node package operations (subgroup) | v0.3.0 |
| `eval` | Evaluation suite operations (subgroup) | v1.16.0 |
| `evidence` | Evidence index operations (subgroup) | v1.17.0 |
| `trace-replay` | Trace replay verification | v1.17.0 |
| `dashboard` | Operator dashboard (subgroup) | v1.20.0 |

Registry subcommands: `list`, `inspect`, `lock`, `verify`
Node subcommands: `validate`, `test`, `create`, `check-compat`

### Run Command Flags (Frozen)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--blueprint` / `-b` | string | `blueprints/research_decision_v1.yaml` | Blueprint path |
| `--trace-dir` / `-t` | string | `data/traces` | Trace output directory |
| `--model` / `-m` | string | None | Model override |
| `--strict` | flag | False | Strict governance mode |
| `--review-mode` | choice | None | Review gate mode |
| `--provider` | choice | None | Model provider |
| `--json` | string | None | Write run metadata JSON |
| `--locked` | flag | False | Verify lockfile before execution |
| `--trust-check` | flag | False | Post-run trust validation |

### Trust Command Flags (Frozen)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--strict` | flag | False | Exit nonzero on violations |
| `--db` | string | `data/chain_state.db` | Database path |

---

## 2. Exit Code Table (Frozen)

| Code | Constant | Meaning | Since |
|------|----------|---------|-------|
| 0 | `EXIT_OK` | Success | v0.1.0 |
| 1 | `EXIT_RECONCILE_ERRORS` | Reconciliation errors / lockfile drift | v0.1.0 |
| 2 | `EXIT_NOT_FOUND` | Run/file not found | v0.1.0 |
| 3 | `EXIT_RECONCILE_RECOVERY` | Recovery required | v0.1.0 |
| 10 | `EXIT_RUN_VALIDATION` | Validation/governance failure | v0.1.0 |
| 11 | `EXIT_RUN_PAUSED` | Paused for review | v0.2.0 |
| 12 | `EXIT_RUN_FAILED` | Execution failed | v0.1.0 |
| 13 | `EXIT_RESUME_NOT_RESUMABLE` | Not resumable | v0.2.0 |
| 14 | `EXIT_RESUME_FAILED` | Resume failed | v0.2.0 |
| 15 | `EXIT_TRUST_VIOLATION` | Trust invariant violation | v0.8.2 |

---

## 3. Trust Invariant Codes (Frozen)

INV-001 through INV-005 are frozen since v1.0.0. INV-006 and INV-007 are
additive v1.x entries — backward compatible, no existing code breaks.

| Code | Invariant | Severity | Since |
|------|-----------|----------|-------|
| `INV-001` | `untrusted_requires_subprocess_isolation` | error | v0.8.1 |
| `INV-002` | `untrusted_requires_child_policy` | error | v0.8.1 |
| `INV-003` | `subprocess_requires_env_filtered` | error | v0.8.1 |
| `INV-004` | `subprocess_requires_temp_isolated` | error | v0.8.1 |
| `INV-005` | `locked_requires_lockfile_verified` | error | v0.8.1 |
| `INV-006` | `required_sandbox_profile_must_be_used` | error | v1.1.0 (additive) |
| `INV-007` | `required_sandbox_capability_must_be_enforced` | error | v1.2.0 (additive) |
| `INV-008` | `required_os_capability_must_be_available` | error | v1.3.0 (additive) |
| `INV-009` | `required_cgroup_limits_must_be_enforced` | error | v1.3.2 (additive) |
| `INV-010` | `preset_requirements_must_be_satisfied` | error | v1.3.5 (additive) |
| `INV-011` | `network_namespace_required_but_not_enforced` | error | v1.4.0 (additive, v1.4.1 strict) |
| `INV-012` | `mount_confinement_required_but_not_enforced` | error | v1.4.5 (additive, v1.4.6 strict) |
| `INV-013` | `pid_namespace_required_but_not_enforced` | error | v1.5.0 (additive) |

---

## 4. Trust Levels (Frozen)

| Level | Execution | Enforcement | Since |
|-------|-----------|-------------|-------|
| `built_in` | In-process | No restrictions | v0.5.0 |
| `local_trusted` | In-process | Python API hooks active | v0.5.0 |
| `local_untrusted` | Subprocess-isolated | Full child-side enforcement | v0.5.0 |
| `remote_untrusted` | Subprocess-isolated | Same as `local_untrusted` | v0.5.0 |

---

## 5. Blueprint Schema (Frozen: v1)

Key fields:

```yaml
name: string          # Blueprint name (required)
version: string       # Blueprint version (required)
nodes:                # Node list (required)
  - node_id: string
    type: string
    config: object
edges:                # Edge list (required)
  - from: string
    to: string
    from_port: string
    to_port: string
branches:             # Branch definitions (optional)
  - branch_id: string
    branches:
      - node_id: string
    wait_for: enum    # all|any|first|quorum
    join: string
    merge_strategy: enum  # append|merge|latest|concat
    cancellation_policy: enum  # ignore_late|cancel_on_first|first_success_only
loops:                 # Loop definitions (optional)
  - loop_id: string
    nodes: [string]
    entry_condition: string
    exit_condition: string
    max_iterations: int
```

---

## 6. Package Manifest Schema (Frozen: v1)

Single-node (`node.yaml`):

```yaml
node_id: string
version: string       # semver
description: string
entrypoint: string    # Python module path
contract:
  inputs: [port_def]
  outputs: [port_def]
  side_effects: [side_effect_def]
  requirements: [string]
trust_level: enum     # built_in|local_trusted|local_untrusted|remote_untrusted
```

Multi-node (`package.yaml`):

```yaml
package_id: string
version: string
nodes:
  - node_id: string
    version: string
    entrypoint: string
    contract: {...}
    trust_level: enum
capabilities: [string]
dependencies: [string]
```

---

## 7. Environment Variables (Frozen)

| Variable | Values | Description |
|----------|--------|-------------|
| `NODECHAIN_SANDBOX_PROFILE` | string | Override sandbox profile (v1.1.0) |
| `NODECHAIN_POLICY_PRESET` | string | Policy preset name (v1.3.5) |
| `NODECHAIN_POLICY_PRESET_SOURCE` | string | Preset source: cli/blueprint (v1.3.5) |
| `NODECHAIN_PROVIDER` | `lim`/`mock`/`custom` | Model adapter selection |
| `NODECHAIN_MODEL` | string | Model name override |
| `NODECHAIN_REVIEW_MODE` | `interactive`/`auto-approve`/`auto-reject`/`auto-revision`/`disabled`/`pause` | Review gate mode |
| `NODECHAIN_REVIEW_DECISION` | string | Injected review decision |
| `NODECHAIN_GOVERNANCE_STRICT` | `1` | Enable strict governance |
| `NODECHAIN_DEV_MODE` | `1` | Allow skip_policy bypass in strict |
| `NODECHAIN_MOCK_RISK_LEVEL` | string | Override mock risk classifier |
| `LIM_BASE_URL` | URL | LIM endpoint |
| `NODECHAIN_BASE_URL` | URL | Custom provider endpoint |
| `CHROMA_HOST` | string | ChromaDB host |
| `CHROMA_PORT` | string | ChromaDB port |

---

## 8. Policy Presets (Additive: v1.3.5)

Presets declare resource policy requirements. Strict mode enforces declared
requirements but does not invent them.

| Preset | Sandbox | Seccomp | Cgroup Limits | Trust Check | Net NS | Mount Conf | PID NS |
|--------|---------|--------|---------------|-------------|--------|------------|--------|
| `minimal` | subprocess_isolated | no | no | no | no | no | no |
| `standard_untrusted` | os_profile | yes | no | no | no | no | no |
| `production_untrusted` | os_profile | yes | yes (512MB/50pids/2cpu) | yes | yes | no | no |
| `hardened_untrusted` | os_profile | yes | yes (512MB/50pids/2cpu) | yes | yes | yes | yes |

**Resolution order**: CLI `--policy-preset` → blueprint `policy_preset` → default (none).

**NodeTrustRecord pressure evidence fields** (v1.3.4 additive, non-frozen):
`memory_events_max`, `memory_events_oom`, `memory_events_oom_kill`,
`cpu_nr_throttled`, `cpu_throttled_usec`, `pids_limit_denied`.

**NodeTrustRecord namespace fields** (v1.4.0–v1.4.6 additive, non-frozen):
`network_namespace_requested`, `network_namespace_enforced`,
`network_namespace_error`, `namespace_mode`,
`mount_namespace_requested`, `mount_namespace_enforced`,
`mount_namespace_error`,
`mount_confinement_requested`, `mount_confinement_enforced`,
`mount_confinement_error`, `temp_root_created`, `allowed_mounts`.

**NodeTrustRecord PID namespace fields** (v1.5.0 additive, non-frozen):
`pid_namespace_requested`, `pid_namespace_enforced`,
`pid_namespace_error`, `pid_namespace_mode`.

**NodeTrustRecord procfs fields** (v1.5.1 additive, non-frozen):
`procfs_namespace_view_enforced`, `procfs_error`.

**NodeTrustRecord namespace fields** (v1.4.0-v1.4.3 additive, non-frozen):
`namespace_available`, `network_namespace_enforced`, `network_namespace_requested`,
`network_namespace_error`, `namespace_mode`,
`mount_namespace_requested`, `mount_namespace_enforced`, `mount_namespace_error`.

**SandboxCapabilities namespace fields** (v1.4.0-v1.4.3 additive, non-frozen):
`namespace_available`, `namespace_mode`, `already_nested`,
`mount_namespace_available`, `pid_namespace_available`,
`network_namespace_available`, `network_namespace_enforced`,
`user_namespace_available`, `mount_namespace_enforced`.

---

## Migration Notes

### v0.x → v1.0.0

- `sys.exit(1)` calls replaced with structured exit codes (code 1 retained for lockfile drift)
- `is_compliant` now delegates to `validate_invariants(strict=False)`
- Trust reconciler check remains advisory in normal mode, error in strict mode
- Lockfile format unchanged (`registry.lock.json`)
- Blueprint format unchanged — all existing blueprints are compatible

No breaking changes from v0.9.0 to v1.0.0-rc1.
