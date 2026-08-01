@echo off
REM Trust Runtime Demo - runs the full trust lifecycle
REM Usage: demo_trust.bat [blueprint] [query]
REM Requires: NODECHAIN_PROVIDER=mock (no LLM/API needed)

setlocal enabledelayedexpansion

set BLUEPRINT=%1
if "%BLUEPRINT%"=="" set BLUEPRINT=blueprints\echo_demo_v1.yaml
set QUERY=%2
if "%QUERY%"=="" set QUERY=Trust runtime verification query

set NODECHAIN_PROVIDER=mock
set NODECHAIN_MOCK_RISK_LEVEL=low
set PYTHONIOENCODING=utf-8

echo.
echo ════════════════════════════════════════════════════════════════
echo   NodeChain Trust Runtime Demo
echo   v0.9.0-governed-local-trust-platform
echo ════════════════════════════════════════════════════════════════
echo.

echo [1/5] Generating registry lockfile...
nodechain registry lock 2>nul
echo.

echo [2/5] Verifying lockfile...
nodechain registry verify 2>nul
echo.

echo [3/5] Running chain --locked --strict --trust-check...
nodechain run "%QUERY%" --blueprint "%BLUEPRINT%" --locked --strict --trust-check --json data\trust_demo_run.json
set RUN_EXIT=!ERRORLEVEL!
echo.

if exist data\trust_demo_run.json (
    echo [4/5] Trust inspection...
    for /f "delims=" %%i in ('python -c "import json; print(json.load(open('data/trust_demo_run.json'))['run_id'])" 2^>nul') do set RUN_ID=%%i
    if defined RUN_ID (
        nodechain trust "!RUN_ID!" --strict 2>nul
        echo.
        echo [5/5] Full report...
        nodechain report "!RUN_ID!" 2>nul
    )
) else (
    echo [4/5] skipped - no run output
    echo [5/5] skipped
)

echo.
echo ════════════════════════════════════════════════════════════════
echo   Trust Runtime Demo complete (exit: !RUN_EXIT!)
echo   Exit codes: 0=ok 2=not_found 3=recovery 10=validation
echo               11=paused 12=failed 13=not_resumable
echo               14=resume_failed 15=trust_violation
echo ════════════════════════════════════════════════════════════════
endlocal
