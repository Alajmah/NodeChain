# Release Evidence Index

One-stop reference for all NodeChain evidence-producing paths. Each row links a
claim to the artifact that proves it, the command that regenerates it, and the
platform it requires.

For the narrative quickstart, see [5-Minute Local Proof](5-minute-local-proof.md).
For the full reviewer guide, see [External Verification Pack](external-verification.md).

---

## Evidence Paths

| # | Evidence | Command | Artifact(s) | Platform | Status |
|---|----------|---------|-------------|----------|--------|
| 1 | Default local proof (contracts, trace, replay, zero deps) | `python scripts/run_external_verification.py` | `data/verification_evidence/evidence.json` + `.md` | Any (Python 3.11+) | Proven |
| 2 | Optional sandbox enforcement (mount, network, seccomp, SIGSYS) | `NODECHAIN_NATIVE_RUNNER=1 python scripts/run_sandbox_verification.py` | `data/verification_evidence/sandbox-evidence.json` + `.md` | Linux + root | Optional / unsupported-skip on other hosts |
| 3 | Full test suite (release gate) | `python -m pytest -q` | (stdout) | Linux | Proven (~5.5 min) |
| 4 | Full test suite, sharded (Windows when single-run exceeds ceiling) | `python scripts/run_full_suite_sharded.py --shards 6` | (stdout) | Any | Available |
| 5 | Schema validation | `python scripts/validate_schemas.py` | (stdout) | Any | Proven |
| 6 | Trace replay consistency (7 checks) | `nodechain trace-replay run --trace <trace_path>` | (stdout) | Any | Proven |
| 7 | Quickstart smoke tests | `python -m pytest tests/test_quickstart_smoke.py -v` | (stdout) | Any | Proven |
| 8 | StateManager characterization (24 tests) | `python -m pytest tests/test_state_manager_characterization.py -v` | (stdout) | Any | Proven |
| 9 | CLI characterization (8 tests) | `python -m pytest tests/test_cli_characterization.py -v` | (stdout) | Any | Proven |
| 10 | Doc-link verification (6 tests) | `python -m pytest tests/test_external_verification_links.py -v` | (stdout) | Any | Proven |

## Claims vs Evidence

| Claim | Evidence path | Proven? |
|---|---|---|
| Contracts validated before execution | #1 (quickstart output) | Yes |
| Trace artifact produced for every run | #1, #7 | Yes |
| Traces are verifiable (7 consistency checks) | #1, #6 | Yes |
| Default proof requires zero external dependencies | #1 | Yes |
| Persistence behavior is frozen by characterization | #8 | Yes |
| CLI command surface is frozen by characterization | #9 | Yes |
| Sandbox enforces mount confinement (child-observed) | #2 | Yes (Linux + root only) |
| Sandbox enforces network namespace isolation | #2 | Yes (Linux + root only) |
| Sandbox enforces PID/procfs isolation | #2 | Yes (Linux + root only) |
| Sandbox enforces seccomp (SIGSYS canary) | #2 | Yes (Linux + root only) |
| Full test suite passes | #3 | Yes (Linux) |

## What this does NOT prove

| Open question | Status | Why |
|---|---|---|
| Complete hostile-code containment | Not claimed | Sandbox enforces isolation but is not a kernel-escape proof |
| Unprivileged production deployment | Not proven | Native backend requires root; userns support is future work |
| Docker backend | Not shipped | No concrete blocker justifies Docker over native path yet |
| GHA-native sandbox enforcement | Not claimed | Self-hosted runner is non-root, cannot execute namespace ops |
| Cross-platform enforcement parity | Not claimed | Enforcement strength varies by host (strongest on Linux) |
| Windows full-suite single-run | Not verified | Exceeds local tool ceiling; sharded path (#4) is the Windows gate |

## Verification language

When reporting evidence status, use precise language:

```
"Linux full suite green"                — single-run, all tests passed
"Linux sandbox enforcement verified"    — eligible root host, 4/4 enforcement passed
"Windows external verifier green"       — default reviewer path, all 6 steps passed
"Windows targeted verification green"   — affected-area subset only (iteration aid)
"Windows sharded suite green"           — sharded run, all shards passed
"Unsupported-skip (sandbox)"            — host cannot execute; NOT a failure
"Windows single-run exceeds ceiling"    — honest statement for timeouts
```

Do not conflate targeted verification with full-suite verification. Do not
conflate unsupported-skip with enforcement proof.

## Regenerating all evidence

```bash
# Default local proof (any host, ~25s)
python scripts/run_external_verification.py

# Optional sandbox enforcement (Linux + root, ~2s)
NODECHAIN_NATIVE_RUNNER=1 python scripts/run_sandbox_verification.py

# Full test suite (Linux, ~5.5 min)
python -m pytest -q

# Sharded full suite (Windows or any host, ~10 min)
python scripts/run_full_suite_sharded.py --shards 6
```

## Related documents

| Document | What it covers |
|---|---|
| [External Verification Pack](external-verification.md) | Reviewer-facing guide: claims, commands, caveats |
| [5-Minute Local Proof](5-minute-local-proof.md) | Quickstart: install → run → inspect → verify |
| [CI Contract](ci.md) | Verification tiers, runner setup, Windows sharding |
| [Native Sandbox Verification](native_sandbox_verification.md) | Privileged enforcement contract + limitations |
| [Native Sandbox Test Runner](native_sandbox_test_runner.md) | SandboxCommandRunner seam + backend selection |
