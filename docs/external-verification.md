# External Verification Pack

**For outside reviewers.** This document explains how to verify NodeChain's core
claims independently, without project history or internal knowledge.

**Fastest path:** run `python scripts/run_external_verification.py` — one command
that runs the full reviewer proof path and emits a JSON + Markdown evidence bundle
in ~25 seconds.

**Optional sandbox evidence:** on a designated Linux host with root access, run
`NODECHAIN_NATIVE_RUNNER=1 python scripts/run_sandbox_verification.py` to produce
sandbox enforcement evidence (mount, network, seccomp, SIGSYS canary). On
unsupported hosts, the script produces an explicit capability-skip result
(NOT a failure).

Start here: [5-Minute Local Proof](5-minute-local-proof.md) — the manual version
of the same path, with explanations.

---

## What NodeChain claims

NodeChain is a runtime for autonomous chains with contracts, policies, memory
control, validation, traceability, and evaluation as native platform concerns.

The claims below are **provable by running the commands in this document**.
Each claim has a corresponding evidence path.

## Claims vs Evidence

| Claim | Evidence | How to verify |
|---|---|---|
| Contracts are validated before any node executes | Quickstart run output shows "All contracts validated" before "Chain complete" | Step 1 below |
| Every node execution produces a trace event | `nodechain trace <run_id>` shows events in execution order | Step 2 below |
| Traces are verifiable, not just human-readable | `nodechain trace-replay run` passes 7 automated consistency checks | Step 3 below |
| The default proof requires zero external dependencies | Everything runs on `--provider mock` (deterministic, no network) | Step 1 below |
| Persistence behavior is characterized and protected | 24 StateManager characterization tests freeze table/column/write contracts | Step 4 below |
| Sandbox enforcement is verified on Linux | 4 enforcement tests (mount, network, seccomp, SIGSYS canary) pass on designated Linux host as root | See `docs/native_sandbox_verification.md` |
| The test suite is comprehensive | 6,200+ tests across 264 files | Step 4 below |
| CLI command surface is frozen against drift | 8 characterization tests (inventory, Click param signatures, help, exit codes) | Step 4 below |

## What this does NOT prove

| Open question | Status | Why it's open |
|---|---|---|
| Complete hostile-code containment | Not claimed | The native sandbox enforces mount-confinement/network-namespace/PID-procfs/seccomp isolation (the four proven v2.78 primitives), but this is not a formal kernel-escape proof |
| Unprivileged production deployment | Not proven | The native sandbox backend requires root; unprivileged userns support is future work |
| Docker backend | Not shipped | No concrete blocker justifies Docker over the native path yet |
| GHA-native sandbox enforcement | Not claimed | The self-hosted runner is non-root and cannot execute namespace/chroot operations |
| Cross-platform enforcement parity | Not claimed | Enforcement strength varies by host capability (strongest on Linux) |

---

## Verification commands

### Prerequisites

- Python 3.11+
- Git
- This repo cloned
- On Linux for full-suite verification: the designated verification host with root access (for sandbox enforcement tests)

### Install

```bash
pip install -e ".[dev]"
```

### Step 1: Run the local proof (no API keys)

```bash
# Validate schemas
python scripts/validate_schemas.py

# Run the echo demo (deterministic, zero external dependencies)
nodechain run "hello nodechain" -b blueprints/echo_demo_v1.yaml --provider mock
```

Expected: "All contracts validated" → "Chain complete!" → trace saved.

See: [5-Minute Local Proof](5-minute-local-proof.md) for the full path including
trace inspection and replay verification.

### Step 2: Inspect the trace

```bash
# Replace <run_id> with the UUID from Step 1
nodechain trace <run_id>
```

Expected: a formatted table showing every event (contract validation, node
invocation, node success, output validation, chain completion).

### Step 3: Verify the trace

```bash
nodechain trace-replay run --trace data/traces/<run_id>.json
```

Expected: 7 consistency checks pass (step order, node invocation order,
contract validity, port validity, policy verdicts, state transitions,
digest references).

### Step 4: Run the test suite

**Linux full suite** (authoritative release gate):

```bash
python -m pytest -q
```

Expected: 6,200+ passed, ~33 skipped, 0 failed. Completes in ~5.5 minutes.

**Windows sharded suite** (when single-run exceeds time ceilings):

```bash
python scripts/run_full_suite_sharded.py --shards 6
```

Expected: all shards green, aggregated summary shows 0 failures. See
[CI documentation](ci.md) for verification-tier details.

**Targeted verification** (iteration aid, not a release gate alone):

```bash
# Quickstart smoke + CLI characterization + release guard
python -m pytest tests/test_quickstart_smoke.py tests/test_cli_characterization.py tests/test_release_guard.py -v

# StateManager characterization (persistence safety net)
python -m pytest tests/test_state_manager_characterization.py -v

# Native sandbox enforcement (Linux + root only)
NODECHAIN_NATIVE_RUNNER=1 python -m pytest tests/test_native_sandbox_enforcement.py -v
```

### Step 5: Verify sandbox enforcement (Linux + root only)

On the designated Linux verification host as root:

```bash
NODECHAIN_NATIVE_RUNNER=1 python -m pytest tests/test_native_sandbox_enforcement.py -v
```

Expected: 4 passed (mount sentinel, network block, seccomp metadata, SIGSYS
canary), 0 failed. See [Native Sandbox Verification](native_sandbox_verification.md)
for the full enforcement contract and limitations.

---

## Document references

| Document | What it covers |
|---|---|
| [5-Minute Local Proof](5-minute-local-proof.md) | Quickstart: install → run → inspect → verify |
| [CI Contract](ci.md) | Verification tiers (full-suite, sharded, targeted), runner setup |
| [Native Sandbox Verification](native_sandbox_verification.md) | Privileged Linux enforcement: mount, network, seccomp, SIGSYS |
| [Native Sandbox Test Runner](native_sandbox_test_runner.md) | The sandbox_test_runner node and the SandboxCommandRunner seam |
| [VISION.md](../VISION.md) | Platform thesis, roadmap, and what NodeChain is/is-not-yet |

## Verification language

When reporting verification status, use precise language:

```text
"Linux full suite green"           — single-run, all tests collected and passed
"Windows sharded suite green"      — sharded run, all shards passed
"Windows targeted green"           — affected-area subset only (iteration aid)
"Windows single-run exceeds ceiling" — the honest statement for timeouts
```

Do not conflate targeted verification with full-suite verification.
