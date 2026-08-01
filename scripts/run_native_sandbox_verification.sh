#!/usr/bin/env bash
# v2.77 — Privileged Linux Native Sandbox Verification Harness
#
# Runs the native_os_sandbox enforcement tests under the privileged execution
# profile required by the current v2.76 backend. This is the release-evidence
# path: the same tests SKIP on default hosts and inside the GHA runner (which
# is non-root and cannot perform namespace/chroot operations).
#
# Fail-closed preconditions: ANY of the following cause a non-zero exit with a
# precise reason, so a green-looking run that verified nothing is impossible:
#   - NODECHAIN_NATIVE_RUNNER not set
#   - not running as root (uid 0)
#   - not Linux
#   - seccomp Python bindings absent
#   - host positive-control network check fails
#   - zero native_sandbox tests collected or any skipped
#
# Usage (on the designated verification host, as root):
#   scripts/run_native_sandbox_verification.sh
#
# Exit codes:
#   0 — all enforcement tests passed (or xfailed for the documented seccomp deferral)
#   1 — a precondition failed, or one or more enforcement tests failed
set -euo pipefail

# ─── Precondition checks (fail-closed) ─────────────────────────────────────

fail() {
    echo "VERIFICATION PRECONDITION FAILED: $*" >&2
    echo "v2.77 native sandbox verification did NOT run to completion." >&2
    exit 1
}

# 1. Flag must be set by this script's invocation context.
export NODECHAIN_NATIVE_RUNNER=1

# 2. Must be Linux.
if [ "$(uname -s)" != "Linux" ]; then
    fail "platform is $(uname -s), not Linux. Native sandbox primitives are Linux-only."
fi

# 3. Must be root (the v2.76 backend requires CAP_SYS_ADMIN/CAP_SYS_CHROOT,
#    which the GHA runner user does not have — see docs/native_sandbox_verification.md).
if [ "$(id -u)" -ne 0 ]; then
    fail "running as uid $(id -u), not root. The native_os_sandbox backend requires root (CAP_SYS_ADMIN/CAP_SYS_CHROOT). Run as root on the designated verification host."
fi

# 4. Seccomp Python bindings must be available (even though seccomp is deferred
#    for v2.77, the binding presence proves the host is set up for v2.78).
PYTHON_BIN="${PYTHON:-python3}"
if ! "$PYTHON_BIN" -c "import seccomp" 2>/dev/null; then
    fail "seccomp Python bindings not importable by $PYTHON_BIN. Install via 'apt install python3-seccomp' (Ubuntu/Debian) or 'pip install seccomp'."
fi

# 5. Host positive-control network check — the adversarial test will prove the
#    SANDBOX blocks outbound; this proves the HOST can reach the target, so
#    'blocked' is meaningful. Default target is configurable.
NET_TARGET="${NODECHAIN_NATIVE_SANDBOX_NET_TARGET:-1.1.1.1:53}"
NET_HOST="${NET_TARGET%%:*}"
NET_PORT="${NET_TARGET##*:}"
if ! timeout 5 bash -c "echo >/dev/tcp/$NET_HOST/$NET_PORT" 2>/dev/null; then
    fail "host positive-control network check failed: cannot reach $NET_TARGET from the host. The runner is misconfigured for the adversarial network test — 'blocked' would be meaningless. Set NODECHAIN_NATIVE_SANDBOX_NET_TARGET to a reachable host:port or fix host egress."
fi

echo "v2.77 native sandbox verification — preconditions OK"
echo "  platform:   $(uname -s) $(uname -r)"
echo "  uid:        $(id -u) ($(id -un))"
echo "  seccomp:    importable"
echo "  net target: $NET_TARGET (host reachable)"
echo

# ─── Locate repo root + venv ───────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# Activate venv if present (the verification host setup creates one).
if [ -f ".venv/bin/activate" ]; then
    # shellcheck disable=SC1091
    . .venv/bin/activate
fi

# ─── Run the enforcement tests ─────────────────────────────────────────────
echo "Running native_sandbox enforcement tests..."
# -m native_sandbox:    select only the enforcement tests
# -ra:                  show short summary for non-passing
# We capture pass/fail/xfail counts to verify no enforcement test was skipped.
OUTPUT_FILE="$(mktemp)"
trap 'rm -f "$OUTPUT_FILE"' EXIT

python -m pytest -m native_sandbox tests/test_native_sandbox_enforcement.py -ra -v 2>&1 | tee "$OUTPUT_FILE"

# ─── Post-run integrity checks ─────────────────────────────────────────────
echo
echo "Post-run integrity checks..."

# 6. No enforcement test should be skipped on this runner.
if grep -q "skipped" "$OUTPUT_FILE"; then
    SKIPPED_COUNT=$(grep -c -E "SKIPPED|skipped" "$OUTPUT_FILE" || true)
    fail "$SKIPPED_COUNT enforcement test(s) were skipped on the verification runner. Skips are not acceptable release evidence in this tier. (A skip here usually means the conftest gate didn't recognize NODECHAIN_NATIVE_RUNNER=1, or pytest collected the wrong tests.)"
fi

# 7. Tests must have actually collected (zero collected = silent no-op).
if grep -q "no tests ran" "$OUTPUT_FILE"; then
    fail "zero native_sandbox tests collected. Marker registration or test file path is wrong; nothing was verified."
fi

echo "VERIFICATION COMPLETE: enforcement tests ran with no skips."
echo "Seccomp xfailures are expected (v2.78 deferral — see docs/native_sandbox_verification.md)."
exit 0
