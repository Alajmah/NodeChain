@echo off
REM ═══════════════════════════════════════════════════════════════════════
REM NodeChain Milestone 1 - Golden Path Demo (Windows)
REM
REM Deterministic mock execution. No LLM or external API required.
REM Run from project root:  examples\demo_milestone_1.bat
REM ═══════════════════════════════════════════════════════════════════════

echo ================================================================
echo   NodeChain Milestone 1 - Golden Path Demo (mock provider)
echo ================================================================
echo.

REM -- Step 1: Run the chain with mock provider --
echo [Step 1] Running chain with mock provider...
echo.

set PYTHONIOENCODING=utf-8
set NODECHAIN_PROVIDER=mock
set NODECHAIN_REVIEW_MODE=auto-approve
set NODECHAIN_GOVERNANCE_STRICT=1

python -m nodechain.cli.main run "Should we adopt retrieval-augmented generation for policy QA?" --provider mock --review-mode auto-approve --strict --json data\demo_run.json

REM Extract run_id from JSON output
for /f "tokens=*" %%i in ('python -c "import json; print(json.load(open('data/demo_run.json'))['run_id'])"') do set RUN_ID=%%i

echo.
echo   Captured run_id: %RUN_ID%
echo.

REM -- Step 2: Inspect the saved state --
echo [Step 2] Inspecting saved state...
echo.
python -m nodechain.cli.main inspect %RUN_ID%
echo.

REM -- Step 3: Reconcile trace against ledger --
echo [Step 3] Reconciling trace against ledger...
echo.
python -m nodechain.cli.main reconcile %RUN_ID%
echo.

REM -- Step 4: Generate comprehensive report --
echo [Step 4] Generating comprehensive report...
echo.
python -m nodechain.cli.main report %RUN_ID% --output data\demo_report.json
echo.

REM -- Step 5: View the trace --
echo [Step 5] Viewing trace events...
echo.
python -m nodechain.cli.main trace "data\traces\%RUN_ID%.json"
echo.

echo ================================================================
echo   Demo complete. Artifacts:
echo     data\demo_run.json      - run metadata
echo     data\demo_report.json   - comprehensive report
echo     data\traces\%RUN_ID%.json - full trace
echo     data\chain_state.db     - persistent state
echo ================================================================
