#!/usr/bin/env python3
"""v2.84 — Sharded full-suite runner for Windows (and any host).

Runs the full test suite in shards to avoid tool/time ceilings on a single
pytest invocation. Each shard runs as a separate subprocess, and results are
aggregated into a single summary.

Usage:
    python scripts/run_full_suite_sharded.py            # 6 shards (default)
    python scripts/run_full_suite_sharded.py --shards 4  # custom shard count
    python scripts/run_full_suite_sharded.py --marker "not native_sandbox"  # deselect

The script exits non-zero if any shard has failures, making it suitable as a
release gate.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def collect_test_files() -> list[str]:
    """Collect all test files, sorted for deterministic sharding."""
    files = []
    for pattern in ("tests/test_*.py",):
        files.extend(sorted(p.relative_to(REPO_ROOT).as_posix() for p in REPO_ROOT.glob(pattern)))
    # Include invariant tests if they exist
    inv_dir = REPO_ROOT / "tests" / "invariants"
    if inv_dir.exists():
        files.extend(sorted(
            p.relative_to(REPO_ROOT).as_posix()
            for p in inv_dir.glob("test_*.py")
        ))
    return sorted(files)


def shard_list(items: list[str], n: int) -> list[list[str]]:
    """Split a list into n roughly-equal shards."""
    shards = [[] for _ in range(n)]
    for i, item in enumerate(items):
        shards[i % n].append(item)
    return [s for s in shards if s]


def run_shard(files: list[str], marker: str | None) -> dict:
    """Run pytest on a shard of test files. Returns result dict."""
    cmd = [sys.executable, "-m", "pytest", "--tb=short", "-q"] + files
    if marker:
        cmd.extend(["-m", marker])

    t0 = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=300)
    elapsed = time.time() - t0

    # Parse the summary line: "6191 passed, 83 skipped, 18 warnings in 594.72s"
    summary_line = ""
    for line in result.stdout.splitlines():
        if "passed" in line or "failed" in line or "error" in line:
            summary_line = line.strip()

    passed = failed = errors = skipped = 0
    m = re.search(r"(\d+) passed", summary_line)
    if m:
        passed = int(m.group(1))
    m = re.search(r"(\d+) failed", summary_line)
    if m:
        failed = int(m.group(1))
    m = re.search(r"(\d+) skipped", summary_line)
    if m:
        skipped = int(m.group(1))
    m = re.search(r"(\d+) error", summary_line)
    if m:
        errors = int(m.group(1))

    return {
        "files": len(files),
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "skipped": skipped,
        "exit_code": result.returncode,
        "elapsed_s": round(elapsed, 1),
        "summary_line": summary_line,
        "stdout_tail": "\n".join(result.stdout.splitlines()[-5:]) if result.stdout else "",
        "stderr_tail": "\n".join(result.stderr.splitlines()[-5:]) if result.stderr else "",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run full test suite in shards")
    parser.add_argument("--shards", type=int, default=6, help="Number of shards (default 6)")
    parser.add_argument("--marker", type=str, default=None, help="pytest -m marker expression")
    args = parser.parse_args()

    files = collect_test_files()
    if not files:
        print("ERROR: no test files found")
        return 1

    shards = shard_list(files, args.shards)
    print(f"Running {len(files)} test files in {len(shards)} shards")
    print(f"Marker: {args.marker or '(none)'}")
    print()

    totals = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0}
    total_elapsed = 0.0
    any_failed = False

    for i, shard in enumerate(shards, 1):
        print(f"--- Shard {i}/{len(shards)}: {len(shard)} files ---")
        result = run_shard(shard, args.marker)
        total_elapsed += result["elapsed_s"]

        status = "OK" if result["exit_code"] == 0 else "FAILED"
        print(f"  {status}  {result['passed']} passed, {result['skipped']} skipped, "
              f"{result['failed']} failed, {result['errors']} errors  "
              f"({result['elapsed_s']}s)")

        if result["failed"] > 0 or result["errors"] > 0 or result["exit_code"] != 0:
            any_failed = True
            if result["stdout_tail"]:
                print(f"  stdout tail: {result['stdout_tail'][:300]}")

        for key in totals:
            totals[key] += result[key]

    print()
    print("=" * 60)
    print(f"SHARDED SUITE COMPLETE ({len(shards)} shards, {total_elapsed:.0f}s total)")
    print(f"  passed:  {totals['passed']}")
    print(f"  skipped: {totals['skipped']}")
    print(f"  failed:  {totals['failed']}")
    print(f"  errors:  {totals['errors']}")
    print(f"  files:   {len(files)}")
    if any_failed:
        print("  RESULT:   FAILURES PRESENT")
        return 1
    else:
        print("  RESULT:   ALL GREEN")
        return 0


if __name__ == "__main__":
    sys.exit(main())
