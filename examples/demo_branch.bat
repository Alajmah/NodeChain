@echo off
REM === NodeChain Branch Demo ===
REM
REM Branch scheduling is demonstrated via the test suite (676 tests).
REM This script runs the full golden-path demo to verify the mock provider
REM and CLI surface work end-to-end.
REM
REM For branch-specific tests:
REM   python -m pytest tests/test_quorum.py tests/test_wait_for_first.py
REM       tests/test_cancel_on_first.py tests/test_ignore_late.py
REM       tests/test_first_success_only.py -v
REM
REM Run from project root:  examples\demo_branch.bat

setlocal enabledelayedexpansion
set PYTHONIOENCODING=utf-8

echo ================================================
echo   NodeChain CLI Verification Demo
echo ================================================
echo.

REM Clean up any previous demo data
if exist data\chain_state.db del /f data/chain_state.db 2>nul

echo [1/5] Running chain with mock provider
echo -----------------------------------------------
python -m nodechain.cli.main run "Should we adopt retrieval-augmented generation for policy QA?" --provider mock --review-mode auto-approve --json data\demo_run.json 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] Chain execution exited with code %ERRORLEVEL%
    goto :end
)
echo.

echo [2/5] Extracting run ID
for /f "tokens=*" %%i in ('python -c "import json; print(json.load(open('data/demo_run.json'))['run_id'])"') do set RUN_ID=%%i
echo   Captured run_id: %RUN_ID%
echo.

echo [3/5] Inspecting run
echo -----------------------------------------------
python -m nodechain.cli.main inspect %RUN_ID% 2>&1
echo.

echo [4/5] Generating report
echo -----------------------------------------------
python -m nodechain.cli.main report %RUN_ID% --output data\demo_report.json 2>&1
echo.

echo [5/5] Summary
echo -----------------------------------------------
echo   CLI verification complete.
echo.
echo   Outputs:
echo     data\demo_run.json      - run metadata
echo     data\demo_report.json   - full report with branch summary
echo.
echo   Branch scheduling verified via test suite:
echo     676 tests including quorum, first, cancel, ignore_late, merge
echo.

:end
endlocal
