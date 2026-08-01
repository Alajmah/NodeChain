#!/usr/bin/env python3
"""v2.89 — Optional Sandbox Verification Evidence Profile.

Runs native sandbox enforcement tests on eligible hosts and emits a compact
evidence bundle. Separate from the default external verification runner — this
profile requires Linux + root and probes host capabilities before attempting
enforcement.

What it does:
  1. Probe host capabilities (OS, uid, seccomp bindings, native_sandbox_supported)
  2. If eligible (Linux + root + NODECHAIN_NATIVE_RUNNER=1): run 4 enforcement tests
  3. If ineligible: emit explicit "unsupported on this host" evidence (not a failure)
  4. Emit sandbox-evidence.json + sandbox-evidence.md

What it does NOT do:
  - Does not change the default external verification runner
  - Does not claim hostile-code containment
  - Does not run the full test suite

Usage:
    # On the designated Linux verification host as root:
    NODECHAIN_NATIVE_RUNNER=1 python scripts/run_sandbox_verification.py

    # On any other host (produces unsupported-skip evidence):
    python scripts/run_sandbox_verification.py
"""
from __future__ import annotations

import json
import os
import platform
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


def probe_capabilities() -> dict:
    """Probe host capabilities for native sandbox enforcement."""
    caps = {
        "platform": platform.system(),
        "platform_release": platform.release(),
        "python_version": sys.version.split()[0],
        "uid": os.geteuid() if hasattr(os, "geteuid") else -1,
        "is_root": os.geteuid() == 0 if hasattr(os, "geteuid") else False,
        "is_linux": platform.system() == "Linux",
        "native_runner_flag": os.environ.get("NODECHAIN_NATIVE_RUNNER", "") == "1",
        "seccomp_importable": False,
        "native_sandbox_supported": False,
    }

    # Probe seccomp Python bindings
    try:
        import seccomp  # noqa: F401
        caps["seccomp_importable"] = True
    except Exception:
        pass

    # Probe NodeChain's native_sandbox_supported()
    if caps["is_linux"]:
        try:
            sys.path.insert(0, str(REPO_ROOT / "src"))
            from nodechain.runtime.sandbox_command_runner import native_sandbox_supported
            caps["native_sandbox_supported"] = native_sandbox_supported()
        except Exception:
            pass

    caps["eligible"] = (
        caps["is_linux"]
        and caps["is_root"]
        and caps["native_runner_flag"]
        and caps["seccomp_importable"]
    )
    return caps


def run_enforcement_tests() -> dict:
    """Run the 4 native sandbox enforcement tests."""
    t0 = time.time()
    result = subprocess.run(
        [sys.executable, "-m", "pytest",
         "tests/test_native_sandbox_enforcement.py",
         "-v", "--tb=short"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
        env={**os.environ, "NODECHAIN_NATIVE_RUNNER": "1"},
        timeout=120,
    )
    elapsed = round(time.time() - t0, 1)

    passed = failed = skipped = xfailed = 0
    for line in result.stdout.splitlines():
        if "PASSED" in line:
            passed += 1
        elif "FAILED" in line:
            failed += 1
        elif "SKIPPED" in line:
            skipped += 1
        elif "XFAIL" in line:
            xfailed += 1

    return {
        "exit_code": result.returncode,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "xfailed": xfailed,
        "elapsed_s": elapsed,
        "stdout_tail": "\n".join(result.stdout.splitlines()[-10:]) if result.stdout else "",
        "stderr_tail": "\n".join(result.stderr.splitlines()[-5:]) if result.stderr else "",
    }


def main() -> int:
    output_dir = Path("data/verification_evidence")
    output_dir.mkdir(parents=True, exist_ok=True)

    caps = probe_capabilities()

    meta = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "git_commit": _git_commit(),
        "profile": "sandbox",
    }

    print("Sandbox Verification Evidence Profile")
    print(f"  Platform: {caps['platform']} {caps['platform_release']}")
    print(f"  UID:      {caps['uid']} ({'root' if caps['is_root'] else 'non-root'})")
    print(f"  Linux:    {caps['is_linux']}")
    print(f"  Seccomp:  {'available' if caps['seccomp_importable'] else 'NOT available'}")
    print(f"  Native:   {'supported' if caps['native_sandbox_supported'] else 'NOT supported'}")
    print(f"  Flag:     NODECHAIN_NATIVE_RUNNER={'1' if caps['native_runner_flag'] else 'unset'}")
    print(f"  Eligible: {caps['eligible']}")
    print()

    evidence = {
        "metadata": {**meta, **caps},
        "summary": {},
        "steps": [],
    }

    if not caps["eligible"]:
        # Unsupported host — emit explicit skip evidence, NOT a failure.
        reason = "not eligible"
        reasons = []
        if not caps["is_linux"]:
            reasons.append(f"platform is {caps['platform']}, not Linux")
        if not caps["is_root"]:
            reasons.append(f"uid={caps['uid']}, not root (CAP_SYS_ADMIN/CAP_SYS_CHROOT required)")
        if not caps["seccomp_importable"]:
            reasons.append("seccomp Python bindings not importable")
        if not caps["native_runner_flag"]:
            reasons.append("NODECHAIN_NATIVE_RUNNER=1 not set")
        reason = "; ".join(reasons) if reasons else "unknown"

        evidence["summary"] = {
            "status": "unsupported_on_this_host",
            "reason": reason,
            "all_passed": None,
            "note": (
                "This host cannot execute native sandbox enforcement tests. "
                "This is NOT a failure — it is an explicit capability skip. "
                "To run enforcement: Linux + root + NODECHAIN_NATIVE_RUNNER=1 + "
                "python3-seccomp installed."
            ),
        }
        evidence["steps"] = [{
            "name": "host_capability_probe",
            "passed": True,
            "result": "unsupported",
            "reason": reason,
        }]

        _write_artifacts(output_dir, evidence)
        print(f"RESULT: UNSUPPORTED ON THIS HOST")
        print(f"  Reason: {reason}")
        print(f"  This is NOT a failure — it is an explicit capability skip.")
        print(f"  Evidence: {output_dir}/sandbox-evidence.json")
        return 0  # Unsupported is not a failure

    # Eligible host — run enforcement tests
    print("Host eligible. Running enforcement tests...")
    print()
    test_result = run_enforcement_tests()
    all_passed = test_result["failed"] == 0 and test_result["exit_code"] == 0

    evidence["summary"] = {
        "status": "enforcement_verified" if all_passed else "enforcement_failed",
        "all_passed": all_passed,
        "tests_passed": test_result["passed"],
        "tests_failed": test_result["failed"],
        "tests_xfailed": test_result["xfailed"],
        "tests_skipped": test_result["skipped"],
        "elapsed_s": test_result["elapsed_s"],
        "note": (
            "Native sandbox enforcement verified on this host under the "
            "privileged execution profile. This proves mount confinement, "
            "network namespace isolation, PID/procfs isolation, and seccomp "
            "syscall filtering through the integrated v2.76 command-runner "
            "path with child-observed evidence. It does NOT prove hostile-code "
            "containment, kernel-escape resistance, or unprivileged deployment."
        ),
    }
    evidence["steps"] = [{
        "name": "native_sandbox_enforcement_tests",
        "command": "NODECHAIN_NATIVE_RUNNER=1 pytest tests/test_native_sandbox_enforcement.py -v",
        "passed": all_passed,
        "result": test_result,
    }]

    _write_artifacts(output_dir, evidence)

    print(f"RESULT: {'ENFORCEMENT VERIFIED' if all_passed else 'ENFORCEMENT FAILED'}")
    print(f"  Tests: {test_result['passed']} passed, {test_result['failed']} failed, "
          f"{test_result['xfailed']} xfailed")
    print(f"  Elapsed: {test_result['elapsed_s']}s")
    print(f"  Evidence: {output_dir}/sandbox-evidence.json")
    print(f"             {output_dir}/sandbox-evidence.md")
    if all_passed:
        print(f"\nProven: mount confinement, network namespace, PID/procfs, seccomp (SIGSYS canary)")
        print(f"Not proven: hostile-code containment, kernel-escape resistance, unprivileged deployment")

    return 0 if all_passed else 1


def _write_artifacts(output_dir: Path, evidence: dict) -> None:
    """Write JSON + Markdown evidence artifacts."""
    json_path = output_dir / "sandbox-evidence.json"
    with open(json_path, "w") as f:
        json.dump(evidence, f, indent=2, default=str)

    md_path = output_dir / "sandbox-evidence.md"
    meta = evidence["metadata"]
    summary = evidence["summary"]
    with open(md_path, "w") as f:
        f.write("# NodeChain Sandbox Verification Evidence\n\n")
        f.write(f"**Generated:** {meta['timestamp']}\n")
        f.write(f"**Commit:** `{meta['git_commit']}`\n")
        f.write(f"**Platform:** {meta['platform']} {meta['platform_release']}\n")
        f.write(f"**UID:** {meta['uid']} ({'root' if meta.get('is_root') else 'non-root'})\n\n")
        status = summary.get("status", "unknown")
        if status == "unsupported_on_this_host":
            f.write(f"**Result:** UNSUPPORTED ON THIS HOST\n")
            f.write(f"**Reason:** {summary.get('reason', 'unknown')}\n\n")
            f.write(f"**Note:** {summary.get('note', '')}\n")
        elif status == "enforcement_verified":
            f.write(f"**Result:** ENFORCEMENT VERIFIED\n")
            f.write(f"**Tests:** {summary['tests_passed']} passed, {summary.get('tests_xfailed', 0)} xfailed\n")
            f.write(f"**Elapsed:** {summary.get('elapsed_s', 0)}s\n\n")
            f.write("## Proven\n\n")
            f.write("- Mount confinement (child-observed sentinel read)\n")
            f.write("- Network namespace (host positive-control + sandbox block)\n")
            f.write("- PID namespace + procfs isolation\n")
            f.write("- Seccomp syscall filtering (SIGSYS canary)\n\n")
            f.write("## Not proven\n\n")
            f.write("- Hostile-code containment / kernel-escape resistance\n")
            f.write("- Unprivileged/non-root deployment\n")
            f.write("- GHA-native execution (runner is non-root)\n\n")
            f.write(f"**Note:** {summary.get('note', '')}\n")
        else:
            f.write(f"**Result:** ENFORCEMENT FAILED\n")
            f.write(f"**Tests:** {summary.get('tests_passed', 0)} passed, {summary.get('tests_failed', 0)} failed\n\n")
        f.write("\n## Capability Probe\n\n")
        f.write(f"- Linux: {meta.get('is_linux')}\n")
        f.write(f"- Root: {meta.get('is_root')}\n")
        f.write(f"- Seccomp: {meta.get('seccomp_importable')}\n")
        f.write(f"- Native sandbox: {meta.get('native_sandbox_supported')}\n")
        f.write(f"- Runner flag: {meta.get('native_runner_flag')}\n")


if __name__ == "__main__":
    sys.exit(main())
