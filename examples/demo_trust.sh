#!/usr/bin/env bash
# Trust Runtime Demo — runs the full trust lifecycle
# Usage: ./demo_trust.sh [blueprint] [query]
# Requires: NODECHAIN_PROVIDER=mock (no LLM/API needed)

set -e

BLUEPRINT="${1:-blueprints/echo_demo_v1.yaml}"
QUERY="${2:-Trust runtime verification query}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

export NODECHAIN_PROVIDER=mock
export NODECHAIN_MOCK_RISK_LEVEL=low
export PYTHONIOENCODING=utf-8

echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  NodeChain Trust Runtime Demo"
echo "  v0.9.0-governed-local-trust-platform"
echo "══════════════════════════════════════════════════════════════"
echo ""

# ── Step 1: Generate lockfile ──
echo "[1/5] Generating registry lockfile..."
nodechain registry lock || true
echo ""

# ── Step 2: Verify lockfile ──
echo "[2/5] Verifying lockfile..."
nodechain registry verify || true
echo ""

# ── Step 3: Run chain with trust check ──
echo "[3/5] Running chain (--locked --strict --trust-check)..."
nodechain run "$QUERY" \
    --blueprint "$BLUEPRINT" \
    --locked \
    --strict \
    --trust-check \
    --json data/trust_demo_run.json \
    || RUN_EXIT=$?
RUN_EXIT=${RUN_EXIT:-0}
echo ""

# ── Step 4: Trust report ──
if [ -f data/trust_demo_run.json ]; then
    RUN_ID=$(python -c "import json; print(json.load(open('data/trust_demo_run.json'))['run_id'])" 2>/dev/null || echo "")
    if [ -n "$RUN_ID" ]; then
        echo "[4/5] Trust inspection for run $RUN_ID..."
        nodechain trust "$RUN_ID" --strict || true
        echo ""
        echo "[5/5] Full report..."
        nodechain report "$RUN_ID" || true
    else
        echo "[4/5] (skipped — no run_id found)"
        echo "[5/5] (skipped)"
    fi
else
    echo "[4/5] (skipped — run did not produce output)"
    echo "[5/5] (skipped)"
fi

echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  Trust Runtime Demo complete"
echo "  Run exit code: $RUN_EXIT"
echo "  Exit codes: 0=ok 2=not_found 3=recovery 10=validation"
echo "              11=paused 12=failed 13=not_resumable"
echo "              14=resume_failed 15=trust_violation"
echo "══════════════════════════════════════════════════════════════"
