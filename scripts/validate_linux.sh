#!/usr/bin/env bash
#
# NodeChain Linux Validation Script — Proxmox Baseline
#
# Runs the full test suite on Linux and captures:
# - Test pass/fail/skip counts
# - Linux sandbox capability report
# - Previously-skipped Linux test results
# - CLI command verification
#
# Usage:
#   bash scripts/validate_linux.sh [--json report.json]
#
set -uo pipefail

JSON_OUTPUT="${1:-}"

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

# Activate venv if present
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
fi

export NODECHAIN_PROVIDER=mock
export NODECHAIN_MOCK_RISK_LEVEL=low
export PYTHONIOENCODING=utf-8

echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  NodeChain Linux Validation — Proxmox Baseline"
echo "  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "══════════════════════════════════════════════════════════════"
echo ""

# ── 1. Platform Report ────────────────────────────────────────────
echo "[1/5] Platform capability report..."
echo ""

python3 -c "
from nodechain.sdk.os_sandbox import detect_backend, Platform
from nodechain.sdk.seccomp_profile import detect_seccomp
import json, sys, os

backend = detect_backend()
caps = backend.get_capabilities()
seccomp = detect_seccomp()

report = {
    'platform': {
        'system': os.uname().sysname if hasattr(os, 'uname') else 'unknown',
        'release': os.uname().release if hasattr(os, 'uname') else 'unknown',
        'machine': os.uname().machine if hasattr(os, 'uname') else 'unknown',
    },
    'sandbox_backend': backend.describe(),
    'sandbox_capabilities': caps.to_dict(),
    'seccomp': seccomp.describe(),
}

print(json.dumps(report, indent=2))
" 2>&1

echo ""

# ── 2. Full test suite ────────────────────────────────────────────
echo "[2/5] Running full test suite..."
echo ""

TEST_OUTPUT=$(python3 -m pytest tests/ -q --tb=short 2>&1)
TEST_EXIT=$?
echo "$TEST_OUTPUT" | tail -5

# Extract counts
PASSED=$(echo "$TEST_OUTPUT" | grep -oP '\d+(?= passed)' || echo "0")
SKIPPED=$(echo "$TEST_OUTPUT" | grep -oP '\d+(?= skipped)' || echo "0")
FAILED=$(echo "$TEST_OUTPUT" | grep -oP '\d+(?= failed)' || echo "0")

echo ""
echo "  Passed:  $PASSED"
echo "  Skipped: $SKIPPED"
echo "  Failed:  $FAILED"

# ── 3. Linux-specific sandbox tests ───────────────────────────────
echo ""
echo "[3/5] Linux sandbox tests..."
echo ""

SANDBOX_OUTPUT=$(python3 -m pytest tests/test_os_sandbox.py tests/test_os_sandbox_reporting.py tests/test_seccomp_profile.py -v --tb=short 2>&1)
echo "$SANDBOX_OUTPUT" | grep -E "PASSED|FAILED|SKIPPED" | tail -20

echo ""

# ── 4. CLI verification ───────────────────────────────────────────
echo "[4/5] CLI verification..."
echo ""

python3 -c "
import os, json, tempfile
from click.testing import CliRunner
from nodechain.cli.main import cli

runner = CliRunner()
results = {}

# Run echo demo
r = runner.invoke(cli, ['run', 'baseline test',
    '--blueprint', 'blueprints/echo_demo_v1.yaml',
    '--provider', 'mock',
    '--json', 'data/linux_baseline.json'])
results['run'] = {'exit_code': r.exit_code}

# Trust check
if os.path.exists('data/linux_baseline.json'):
    data = json.load(open('data/linux_baseline.json'))
    run_id = data.get('run_id', '')
    if run_id:
        r = runner.invoke(cli, ['trust', run_id, '--strict'])
        results['trust_strict'] = {'exit_code': r.exit_code}

        r = runner.invoke(cli, ['report', run_id])
        results['report'] = {'exit_code': r.exit_code}

        r = runner.invoke(cli, ['reconcile', run_id])
        results['reconcile'] = {'exit_code': r.exit_code}

# Registry
r = runner.invoke(cli, ['registry', 'list'])
results['registry_list'] = {'exit_code': r.exit_code}

r = runner.invoke(cli, ['registry', 'lock'])
results['registry_lock'] = {'exit_code': r.exit_code}

r = runner.invoke(cli, ['registry', 'verify'])
results['registry_verify'] = {'exit_code': r.exit_code}

for cmd, info in results.items():
    status = 'PASS' if info['exit_code'] == 0 else f'EXIT({info[\"exit_code\"]})'
    print(f'  {cmd:20s} {status}')
" 2>&1

echo ""

# ── 5. Summary ────────────────────────────────────────────────────
echo "[5/5] Validation summary..."
echo ""

python3 -c "
from nodechain.sdk.os_sandbox import detect_backend
from nodechain.sdk.seccomp_profile import detect_seccomp

backend = detect_backend()
caps = backend.get_capabilities()
seccomp = detect_seccomp()

print('Sandbox capability report:')
print(f'  resource_limits_enforced:    {caps.resource_limits_enforced}')
print(f'  syscall_filtering_enforced:  {caps.syscall_filtering_enforced}')
print(f'  namespace_enforced:          {caps.namespace_enforced}')
print(f'  cgroup_enforced:             {caps.cgroup_enforced}')
print(f'  seccomp_available:           {caps.seccomp_available}')
print(f'  seccomp_enforced:            {caps.seccomp_enforced}')
print(f'  detection_only:              {caps.detection_only}')
print()
print('Honest assessment:')
if caps.resource_limits_enforced:
    print('  [REAL] Resource limits enforced via RLIMIT')
else:
    print('  [MISSING] Resource limits not enforced')
if caps.syscall_filtering_enforced:
    print('  [REAL] Syscall filtering enforced via seccomp')
else:
    print('  [NOT IMPLEMENTED] Syscall filtering not enforced (v1.2.x)')
if caps.namespace_enforced:
    print('  [REAL] Namespace isolation enforced')
else:
    print('  [NOT IMPLEMENTED] Namespace isolation not enforced (v1.2.x)')
if caps.cgroup_enforced:
    print('  [REAL] Cgroup v2 resource accounting')
else:
    print('  [NOT IMPLEMENTED] Cgroup enforcement not implemented (v1.2.x)')
" 2>&1

# ── JSON output ───────────────────────────────────────────────────
if [ -n "$JSON_OUTPUT" ]; then
    python3 -c "
import json, sys

report = {
    'test_passed': $PASSED,
    'test_skipped': $SKIPPED,
    'test_failed': $FAILED,
    'test_exit_code': $TEST_EXIT,
}
json.dump(report, open('$JSON_OUTPUT', 'w'), indent=2)
print(f'Report written to $JSON_OUTPUT')
" 2>&1
fi

echo ""
echo "══════════════════════════════════════════════════════════════"
if [ "$FAILED" -eq 0 ]; then
    echo "  ✅ Linux baseline PASSED ($PASSED tests, $SKIPPED skipped)"
else
    echo "  ❌ Linux baseline FAILED ($FAILED failures)"
fi
echo "══════════════════════════════════════════════════════════════"
