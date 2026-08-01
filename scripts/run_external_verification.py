#!/usr/bin/env python3
"""v2.88 — External Verification Runner + Evidence Bundle.

Runs the core reviewer proof path and emits a compact, collectible evidence
bundle. One command that an outside reviewer can execute on a fresh clone to
produce machine-readable (JSON) and human-readable (Markdown) evidence.

What it runs:
  1. Schema validation (scripts/validate_schemas.py)
  2. Five-minute quickstart (echo demo with --provider mock)
  3. Trace existence check
  4. Trace replay consistency check
  5. Quickstart smoke tests (tests/test_quickstart_smoke.py)
  6. Selected verification/doc-link tests

What it does NOT run:
  - The full test suite (use scripts/run_full_suite_sharded.py or pytest -q)
  - Native sandbox enforcement (requires Linux + root; see docs/native_sandbox_verification.md)
  - Anything requiring external API keys

Usage:
    python scripts/run_external_verification.py
    python scripts/run_external_verification.py --output-dir my-evidence/

Outputs:
    <output-dir>/evidence.json    — machine-readable evidence bundle
    <output-dir>/evidence.md      — human-readable summary

Exit code:
    0 — all steps passed
    1 — one or more steps failed
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _git_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=str(REPO_ROOT), stderr=subprocess.DEVNULL, text=True,
        ).strip()[:12]
    except Exception:
        return "unknown"


def _git_branch() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=str(REPO_ROOT), stderr=subprocess.DEVNULL, text=True,
        ).strip()
    except Exception:
        return "unknown"


def _run_step(name: str, cmd: list[str], env: dict | None = None, timeout: int = 120) -> dict:
    """Run one verification step. Returns result dict."""
    merged_env = {**os.environ, **(env or {})}
    t0 = time.time()
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            cwd=str(REPO_ROOT), env=merged_env, timeout=timeout,
        )
        elapsed = round(time.time() - t0, 1)
        return {
            "name": name,
            "command": " ".join(cmd),
            "exit_code": result.returncode,
            "passed": result.returncode == 0,
            "elapsed_s": elapsed,
            "stdout_tail": "\n".join(result.stdout.splitlines()[-5:]) if result.stdout else "",
            "stderr_tail": "\n".join(result.stderr.splitlines()[-3:]) if result.stderr else "",
        }
    except subprocess.TimeoutExpired:
        elapsed = round(time.time() - t0, 1)
        return {
            "name": name,
            "command": " ".join(cmd),
            "exit_code": -1,
            "passed": False,
            "elapsed_s": elapsed,
            "stdout_tail": "",
            "stderr_tail": f"TIMEOUT after {timeout}s",
        }


def _run_quickstart() -> dict:
    """Run the echo demo and capture the run_id for subsequent steps."""
    env = {"NODECHAIN_PROVIDER": "mock"}
    t0 = time.time()
    result = subprocess.run(
        [sys.executable, "-m", "nodechain.cli.main", "run",
         "hello nodechain", "-b", "blueprints/echo_demo_v1.yaml",
         "--provider", "mock"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
        env={**os.environ, **env}, timeout=60,
    )
    elapsed = round(time.time() - t0, 1)

    run_id = None
    trace_path = None
    if result.returncode == 0:
        m = re.search(r"Run ID:\s*([a-f0-9-]+)", result.stdout)
        if m:
            run_id = m.group(1)
            trace_path = str(REPO_ROOT / "data" / "traces" / f"{run_id}.json")

    return {
        "name": "quickstart_echo_demo",
        "command": "nodechain run 'hello nodechain' -b blueprints/echo_demo_v1.yaml --provider mock",
        "exit_code": result.returncode,
        "passed": result.returncode == 0 and run_id is not None,
        "elapsed_s": elapsed,
        "run_id": run_id,
        "trace_path": trace_path,
        "stdout_tail": "\n".join(result.stdout.splitlines()[-5:]) if result.stdout else "",
        "stderr_tail": "\n".join(result.stderr.splitlines()[-3:]) if result.stderr else "",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run external verification path and emit evidence bundle")
    parser.add_argument("--output-dir", default="data/verification_evidence",
                        help="Directory for evidence artifacts (default: data/verification_evidence)")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Metadata
    meta = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "git_commit": _git_commit(),
        "git_branch": _git_branch(),
        "version": "unknown",
        "platform": platform.system(),
        "platform_release": platform.release(),
        "python_version": sys.version.split()[0],
    }
    try:
        import nodechain
        meta["version"] = nodechain.__version__
    except Exception:
        pass

    print(f"External Verification Runner")
    print(f"  NodeChain {meta['version']} ({meta['git_commit']} on {meta['git_branch']})")
    print(f"  {meta['platform']} {meta['platform_release']}, Python {meta['python_version']}")
    print(f"  Output: {output_dir}/")
    print()

    steps = []

    # Step 1: Schema validation
    print("[1/6] Schema validation...")
    s = _run_step("schema_validation",
                  [sys.executable, "scripts/validate_schemas.py"], timeout=30)
    steps.append(s)
    print(f"      {'PASS' if s['passed'] else 'FAIL'} ({s['elapsed_s']}s)")

    # Step 2: Quickstart echo demo
    print("[2/6] Quickstart echo demo...")
    s = _run_quickstart()
    steps.append(s)
    run_id = s.get("run_id")
    trace_path = s.get("trace_path")
    print(f"      {'PASS' if s['passed'] else 'FAIL'} ({s['elapsed_s']}s)")
    if run_id:
        print(f"      run_id={run_id}")

    # Step 3: Trace existence
    print("[3/6] Trace existence check...")
    trace_exists = trace_path is not None and Path(trace_path).exists()
    s_trace = {
        "name": "trace_exists",
        "command": f"test -f {trace_path}" if trace_path else "(no run_id)",
        "exit_code": 0 if trace_exists else 1,
        "passed": trace_exists,
        "elapsed_s": 0.0,
        "trace_path": trace_path,
    }
    steps.append(s_trace)
    print(f"      {'PASS' if trace_exists else 'FAIL'}")

    # Step 4: Trace replay
    print("[4/6] Trace replay verification...")
    if trace_path and trace_exists:
        s = _run_step("trace_replay",
                      [sys.executable, "-m", "nodechain.cli.main", "trace-replay", "run",
                       "--trace", trace_path], timeout=30)
    else:
        s = {"name": "trace_replay", "command": "(skipped: no trace)", "exit_code": 1,
             "passed": False, "elapsed_s": 0.0}
    steps.append(s)
    print(f"      {'PASS' if s['passed'] else 'FAIL'} ({s['elapsed_s']}s)")

    # Step 5: Quickstart smoke tests
    print("[5/6] Quickstart smoke tests...")
    s = _run_step("quickstart_smoke_tests",
                  [sys.executable, "-m", "pytest", "tests/test_quickstart_smoke.py", "-q", "--tb=line"],
                  timeout=120)
    steps.append(s)
    print(f"      {'PASS' if s['passed'] else 'FAIL'} ({s['elapsed_s']}s)")

    # Step 6: Doc-link + characterization tests
    print("[6/6] Verification doc-link + CLI characterization tests...")
    s = _run_step("doc_link_and_characterization",
                  [sys.executable, "-m", "pytest",
                   "tests/test_external_verification_links.py",
                   "tests/test_cli_characterization.py", "-q", "--tb=line"],
                  timeout=60)
    steps.append(s)
    print(f"      {'PASS' if s['passed'] else 'FAIL'} ({s['elapsed_s']}s)")

    # Build evidence bundle
    all_passed = all(s["passed"] for s in steps)
    total_elapsed = sum(s["elapsed_s"] for s in steps)

    evidence = {
        "metadata": meta,
        "summary": {
            "all_passed": all_passed,
            "steps_passed": sum(1 for s in steps if s["passed"]),
            "steps_failed": sum(1 for s in steps if not s["passed"]),
            "total_steps": len(steps),
            "total_elapsed_s": round(total_elapsed, 1),
            "run_id": run_id,
            "trace_path": trace_path,
        },
        "steps": steps,
        "note": (
            "This evidence bundle is NOT a full release gate. It verifies the "
            "reviewer proof path (quickstart + trace + replay + smoke tests). "
            "For full release verification, run the complete test suite "
            "(pytest -q on Linux, or scripts/run_full_suite_sharded.py on Windows)."
        ),
    }

    # Write JSON
    json_path = output_dir / "evidence.json"
    with open(json_path, "w") as f:
        json.dump(evidence, f, indent=2, default=str)

    # Write Markdown
    md_path = output_dir / "evidence.md"
    with open(md_path, "w") as f:
        f.write("# NodeChain External Verification Evidence\n\n")
        f.write(f"**Generated:** {meta['timestamp']}\n")
        f.write(f"**Version:** {meta['version']}\n")
        f.write(f"**Commit:** `{meta['git_commit']}` on `{meta['git_branch']}`\n")
        f.write(f"**Platform:** {meta['platform']} {meta['platform_release']}\n")
        f.write(f"**Python:** {meta['python_version']}\n\n")
        f.write(f"**Result:** {'ALL PASSED' if all_passed else 'FAILURES PRESENT'}\n")
        f.write(f"**Steps:** {evidence['summary']['steps_passed']}/{evidence['summary']['total_steps']} passed\n")
        f.write(f"**Elapsed:** {total_elapsed:.1f}s\n\n")
        if run_id:
            f.write(f"**Run ID:** `{run_id}`\n")
            f.write(f"**Trace:** `{trace_path}`\n\n")
        f.write("## Steps\n\n")
        f.write("| # | Step | Result | Elapsed |\n")
        f.write("|---|------|--------|---------|\n")
        for i, s in enumerate(steps, 1):
            status = "PASS" if s["passed"] else "FAIL"
            f.write(f"| {i} | {s['name']} | {status} | {s['elapsed_s']}s |\n")
        f.write("\n## Note\n\n")
        f.write(evidence["note"])
        f.write("\n")

    print()
    print("=" * 60)
    print(f"EVIDENCE BUNDLE: {'ALL PASSED' if all_passed else 'FAILURES PRESENT'}")
    print(f"  Steps: {evidence['summary']['steps_passed']}/{evidence['summary']['total_steps']} passed")
    print(f"  Elapsed: {total_elapsed:.1f}s")
    print(f"  JSON:   {json_path}")
    print(f"  Markdown: {md_path}")
    print(f"\nNote: This is NOT a full release gate.")
    print(f"  For full verification: pytest -q (Linux) or run_full_suite_sharded.py (Windows)")

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
