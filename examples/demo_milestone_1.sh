#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# NodeChain Milestone 1 -- Golden Path Demo
#
# Deterministic mock execution. No LLM or external API required.
# Run from project root:  bash examples/demo_milestone_1.sh
# ═══════════════════════════════════════════════════════════════════════

set -euo pipefail
export PYTHONIOENCODING=utf-8

echo "================================================================"
echo "  NodeChain Milestone 1 -- Golden Path Demo (mock provider)"
echo "================================================================"
echo ""

# ── Part A: Normal execution ──────────────────────────────────────
echo "== Part A: Normal execution (auto-approve) =="
echo ""

NODECHAIN_PROVIDER=mock \
NODECHAIN_REVIEW_MODE=auto-approve \
NODECHAIN_GOVERNANCE_STRICT=1 \
python -m nodechain.cli.main run \
    "Should we adopt retrieval-augmented generation for policy QA?" \
    --provider mock \
    --review-mode auto-approve \
    --strict \
    --json data/demo_run.json

RUN_ID=$(python -c "import json; print(json.load(open('data/demo_run.json'))['run_id'])")
echo ""
echo "  Captured run_id: $RUN_ID"
echo ""

# ── Inspect the saved state ────────────────────────────────────────
echo ">> Inspecting saved state..."
echo ""
python -m nodechain.cli.main inspect "$RUN_ID"
echo ""

# ── Reconcile trace against ledger ────────────────────────────────
echo ">> Reconciling trace against ledger..."
echo ""
python -m nodechain.cli.main reconcile "$RUN_ID"
echo ""

# ── Generate comprehensive report ─────────────────────────────────
echo ">> Generating comprehensive report..."
echo ""
python -m nodechain.cli.main report "$RUN_ID" --output data/demo_report.json
echo ""

# ── Part B: Pause/Resume (human review) ──────────────────────────
echo ""
echo "================================================================"
echo "  Part B: Human Review Pause/Resume"
echo "================================================================"
echo ""

# ── Run with pause mode (triggers review, saves state) ────────────
echo ">> Running chain with review pause..."
echo ""

NODECHAIN_PROVIDER=mock \
NODECHAIN_REVIEW_MODE=pause \
NODECHAIN_MOCK_RISK_LEVEL=high \
python -m nodechain.cli.main run \
    "Evaluate the risk of deploying untested ML models in production" \
    --provider mock \
    --review-mode pause \
    --json data/demo_pause.json

PAUSE_ID=$(python -c "import json; print(json.load(open('data/demo_pause.json'))['run_id'])")
echo ""
echo "  Chain paused. Run ID: $PAUSE_ID"
echo ""

# ── Inspect the paused state ──────────────────────────────────────
echo ">> Inspecting paused state..."
echo ""
python -m nodechain.cli.main inspect "$PAUSE_ID"
echo ""

# ── Resume with auto-approve ──────────────────────────────────────
echo ">> Resuming with auto-approve..."
echo ""
NODECHAIN_REVIEW_MODE=auto-approve \
NODECHAIN_MOCK_RISK_LEVEL=high \
python -m nodechain.cli.main resume "$PAUSE_ID" --review-mode auto-approve
echo ""

# ── Reconcile after resume ────────────────────────────────────────
echo ">> Reconciling resumed run..."
echo ""
python -m nodechain.cli.main reconcile "$PAUSE_ID"
echo ""

# ── Summary ───────────────────────────────────────────────────────
echo "================================================================"
echo "  Demo complete. Artifacts:"
echo "    data/demo_run.json      -- normal run metadata"
echo "    data/demo_pause.json    -- paused run metadata"
echo "    data/demo_report.json   -- comprehensive report"
echo "    data/chain_state.db     -- persistent state"
echo "================================================================"
echo ""

# ── Side-effect lifecycle assertion ───────────────────────────────
echo ">> Verifying side-effect lifecycle..."
python -c "
from nodechain.core.state import StateManager
import json

sm = StateManager(db_path='data/chain_state.db')
with open('data/demo_run.json') as f:
    d = json.load(f)
run_id = d['run_id']

effects = sm.get_side_effects(run_id)
started = [e for e in effects if e['status'] == 'started']
unknown = [e for e in effects if e['status'] == 'unknown']

if started:
    print(f'FAIL: {len(started)} side-effect rows still started after successful run')
    for e in started:
        print(f'  {e[\"idempotency_key\"]}')
    exit(1)
elif unknown:
    print(f'WARN: {len(unknown)} unknown side effects (expected only after crash)')
else:
    print(f'PASS: All {len(effects)} side-effect rows in terminal state (completed/failed)')
"
