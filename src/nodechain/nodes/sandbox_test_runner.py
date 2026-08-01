"""Node 10: Sandbox Test Runner — governed temp-workspace test execution.

v2.73: THE governed-execution-proof node. Applies validated patches in an
isolated temp workspace (tracked-file export, not raw copy), runs pytest with
a bounded command profile, captures results, and cleans up.

v2.76: pytest execution now routes through SandboxCommandRunner, which selects
between the local_subprocess backend (v2.73/v2.75 behavior, default) and the
native_os_sandbox backend (opt-in, reuses NodeChain's existing namespace /
seccomp / cgroup / mount-confinement primitives). This node retains full
control of git-status integrity, workspace lifecycle, patch apply/not_run
truth, cleanup, and result classification — the runner owns ONLY command
execution. The node also produces a sandbox_event_log consumed by the runtime
trace layer (NodeEventEmitterMixin); it never writes trace events directly.

Per ChatGPT v2.73 design (conversation 6a4ae8e9):
  - Workspace: tracked-file export via `git archive` (excludes .git, .env,
    caches, untracked secrets)
  - Command: pytest profile only (shell=False, bounded timeout/output)
  - Per-patch isolation: separate workspace + verdict per patch
  - code_execution IS a side effect (not just capability)
  - Security claim: governed temp-workspace isolation; native backend adds
    bounded OS-level isolation but does NOT claim complete hostile-code
    containment
  - Trace truth: if patch apply fails, pytest is NOT RUN (not "failed")
  - Cleanup: always, failures traced not swallowed
"""
from __future__ import annotations

import hashlib
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import (
    EntryContract, ExitContract, NodeContract, Requirements, SideEffect,
)
from nodechain.core.manifest import NodeManifest
from nodechain.core.port import PortType
from nodechain.nodes.base_node import BaseNode
from nodechain.runtime.sandbox_command_runner import SandboxCommandRunner

logger = logging.getLogger(__name__)

SANDBOX_TEST_RUNNER_CONTRACT = NodeContract(
    contract_id="codereview.sandbox-test-runner.v1",
    node_id="sandbox_test_runner",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.CLASSIFIED_PATCHES,
        schema_ref="nodechain://schemas/semantic_types/classified_patches",
        required_fields=["classified_patches"],
    ),
    exit=ExitContract(
        output_type=PortType.SANDBOX_TEST_RESULTS,
        schema_ref="nodechain://schemas/semantic_types/sandbox_test_results",
        guaranteed_fields=["test_records", "execution_summary", "sandbox_event_log"],
    ),
    requirements=Requirements(
        model_required=False,
        trust_level="trusted",  # needs code execution + temp filesystem
    ),
    side_effects=[
        SideEffect(effect_type="code_execution", target="temp_workspace"),
        SideEffect(effect_type="external_call", target="temp_workspace_pytest"),  # process spawn
    ],
)

# v2.73: pytest command profile — no shell, bounded
PYTEST_PROFILE = {
    "command": [sys.executable, "-m", "pytest", "--tb=short", "-q", "--no-header"],
    "shell": False,
    "timeout_seconds": 120,
    "max_output_bytes": 50000,
}

# v2.76: ENV_ALLOWLIST now lives in SandboxCommandRunner (the single owner of
# command execution). Re-exported here so existing imports (e.g. tests) keep
# working — the allowlist itself is unchanged.
from nodechain.runtime.sandbox_command_runner import ENV_ALLOWLIST  # noqa: E402,F401


class SandboxTestRunnerNode(BaseNode):
    """Node 10: Run tests against validated patches in temp workspaces.

    Per-patch isolation: each patch gets its own workspace, its own pytest run,
    its own verdict. Workspaces are cleaned up after every run (success,
    failure, timeout). Cleanup failures are traced, never swallowed.
    """

    def __init__(
        self,
        repo_root: str = ".",
        base_revision: str = "HEAD",
        timeout_seconds: int = 120,
        max_output_bytes: int = 50000,
    ) -> None:
        self._repo_root = Path(repo_root).resolve()
        self._base_revision = base_revision
        self._timeout = timeout_seconds
        self._max_output = max_output_bytes

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="sandbox_test_runner",
            node_type="deterministic",
            name="Sandbox Test Runner",
            description="Runs pytest against validated patches in isolated temp workspaces. Governed, bounded execution.",
            contract=SANDBOX_TEST_RUNNER_CONTRACT,
        )

    def _export_tracked_files(self, dest: Path) -> str:
        """Export committed tracked files via git archive into dest.

        Excludes .git, .env, caches, untracked secrets. Returns the base
        revision used for the export.
        """
        result = subprocess.run(
            ["git", "archive", self._base_revision],
            cwd=str(self._repo_root),
            capture_output=True,
            timeout=30,
        )
        if result.returncode != 0:
            raise RuntimeError(f"git archive failed: {result.stderr.decode()[:200]}")

        # Extract the tar stream into dest
        import tarfile
        import io
        tar = tarfile.open(fileobj=io.BytesIO(result.stdout))
        # Security: filter extraction to prevent path traversal
        try:
            tar.extractall(path=str(dest), filter="data")
        except TypeError:
            # Python < 3.12 doesn't support filter argument
            tar.extractall(path=str(dest))
        tar.close()

        return self._base_revision

    def _apply_patch(self, workspace: Path, diff_text: str, target_file: str) -> tuple[bool, str]:
        """Apply a unified diff in the workspace. Returns (success, error_msg)."""
        diff_file = workspace / "patch.diff"
        diff_file.write_text(diff_text)
        result = subprocess.run(
            ["git", "apply", str(diff_file)],
            cwd=str(workspace),
            capture_output=True,
            text=True,
            timeout=10,
        )
        # Clean up the diff file regardless
        diff_file.unlink(missing_ok=True)
        if result.returncode == 0:
            return True, "applied cleanly"
        return False, result.stderr.strip()[:200]

    def _run_pytest(self, workspace: Path) -> dict:
        """Run pytest in the workspace. Returns execution record.

        v2.76: delegates to SandboxCommandRunner, which selects between
        local_subprocess (default, v2.73/v2.75 behavior) and native_os_sandbox
        (opt-in). The runner owns command execution only; this node retains
        control of all guards (git-status integrity, patch apply/not_run truth,
        workspace lifecycle, cleanup). The result dict has the same shape as
        before, plus ``backend`` and ``sandbox_event_log`` fields.
        """
        runner = SandboxCommandRunner(self.sandbox_backend)
        argv = PYTEST_PROFILE["command"].copy()
        return runner.run_command(
            argv=argv,
            cwd=workspace,
            timeout_seconds=self._timeout,
            max_output_bytes=self._max_output,
        )

    def _hash_git_status(self) -> str:
        """Hash git status output for before/after comparison."""
        result = subprocess.run(
            ["git", "status", "--short"],
            cwd=str(self._repo_root),
            capture_output=True,
            text=True,
            timeout=10,
        )
        return hashlib.sha256(result.stdout.encode()).hexdigest()[:16]

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        data = envelope.payload
        # v3.5.1 (#11): accept ONLY status == "validated". The v3.5.0
        # ``or "unified_diff" in p`` clause let a rejected/pending patch
        # execute whenever it carried a diff, bypassing validation status.
        classified_patches = [
            p for p in data.get("classified_patches", [])
            if p.get("status") == "validated"
        ]

        # Hash git status BEFORE
        status_before = self._hash_git_status()

        records = []
        event_log: list[dict[str, Any]] = []  # v2.76: structured events for the runtime trace layer
        workspaces_created = 0
        workspaces_cleaned = 0
        patches_applied = 0
        tests_run = 0
        tests_passed = 0
        tests_failed = 0
        tests_not_run = 0

        for patch in classified_patches:
            patch_id = patch.get("proposal_id", "?")
            target_file = patch.get("target_file", "")
            diff_text = patch.get("unified_diff", "")

            record: dict[str, Any] = {
                "patch_id": patch_id,
                "target_file": target_file,
                "workspace_strategy": "tracked_file_export",
                "base_revision": self._base_revision,
                "patch_apply_status": "pending",
                "test_status": "pending",
                "process_exit_code": None,
                "process_timed_out": False,
                "output_truncated": False,
                "duration_ms": 0,
                "cleanup_status": "pending",
                "stdout_preview": "",
                "stderr_preview": "",
            }

            workspace = None
            try:
                # Create temp workspace
                event_log.append({
                    "event_type": "sandbox_workspace_requested",
                    "metadata": {"patch_id": patch_id},
                })
                workspace = Path(tempfile.mkdtemp(prefix="nodechain_sandbox_"))
                workspaces_created += 1
                event_log.append({
                    "event_type": "sandbox_workspace_created",
                    "metadata": {"patch_id": patch_id, "workspace_strategy": "tracked_file_export"},
                })

                # Export tracked files
                try:
                    self._export_tracked_files(workspace)
                except Exception as e:
                    record["patch_apply_status"] = "workspace_export_failed"
                    record["test_status"] = "not_run"
                    record["stderr_preview"] = str(e)[:200]
                    tests_not_run += 1
                    event_log.append({
                        "event_type": "patch_apply_failed",
                        "metadata": {"patch_id": patch_id, "reason": "workspace_export_failed"},
                    })
                    records.append(record)
                    continue

                # Apply patch
                event_log.append({
                    "event_type": "patch_apply_started",
                    "metadata": {"patch_id": patch_id, "target_file": target_file},
                })
                applied, apply_msg = self._apply_patch(workspace, diff_text, target_file)
                if not applied:
                    record["patch_apply_status"] = "failed"
                    record["test_status"] = "not_run"  # TRACE TRUTH: not run, not failed
                    record["stderr_preview"] = apply_msg
                    tests_not_run += 1
                    event_log.append({
                        "event_type": "patch_apply_failed",
                        "metadata": {"patch_id": patch_id, "reason": apply_msg[:120]},
                    })
                    records.append(record)
                    continue

                record["patch_apply_status"] = "succeeded"
                patches_applied += 1
                event_log.append({
                    "event_type": "patch_apply_succeeded",
                    "metadata": {"patch_id": patch_id},
                })

                # v2.76: pytest is authorized under the bounded command profile.
                event_log.append({
                    "event_type": "test_command_authorized",
                    "metadata": {"patch_id": patch_id, "command_profile": "pytest"},
                })

                # Run pytest
                import time
                t0 = time.time()
                test_result = self._run_pytest(workspace)
                # Merge the command runner's per-command events into the node log.
                event_log.extend(test_result.get("sandbox_event_log", []))
                record["duration_ms"] = int((time.time() - t0) * 1000)
                record["process_exit_code"] = test_result["process_exit_code"]
                record["process_timed_out"] = test_result["process_timed_out"]
                record["output_truncated"] = test_result["output_truncated"]
                record["stdout_preview"] = test_result["stdout"][:2000]
                record["stderr_preview"] = test_result["stderr"][:500]

                interp = test_result["exit_code_interpretation"]
                if interp == "pass":
                    record["test_status"] = "passed"
                    tests_passed += 1
                elif interp == "timeout":
                    record["test_status"] = "timeout"
                    tests_failed += 1
                elif interp == "error":
                    record["test_status"] = "execution_error"
                    tests_failed += 1
                else:
                    record["test_status"] = "failed"
                    tests_failed += 1
                tests_run += 1
                event_log.append({
                    "event_type": "test_result_classified",
                    "metadata": {"patch_id": patch_id, "test_status": record["test_status"]},
                })

            except Exception as e:
                record["test_status"] = "execution_error"
                record["stderr_preview"] = f"{type(e).__name__}: {e}"[:200]
                tests_failed += 1
            finally:
                # CRITICAL: always clean up, trace failures
                if workspace is not None and workspace.exists():
                    event_log.append({
                        "event_type": "sandbox_cleanup_started",
                        "metadata": {"patch_id": patch_id},
                    })
                    try:
                        shutil.rmtree(workspace, ignore_errors=False)
                        record["cleanup_status"] = "succeeded"
                        workspaces_cleaned += 1
                        event_log.append({
                            "event_type": "sandbox_cleanup_succeeded",
                            "metadata": {"patch_id": patch_id},
                        })
                    except Exception as e:
                        record["cleanup_status"] = "failed"
                        record["cleanup_error"] = str(e)[:200]
                        logger.error("sandbox cleanup FAILED for workspace %s: %s", workspace, e)
                        event_log.append({
                            "event_type": "sandbox_cleanup_failed",
                            "metadata": {"patch_id": patch_id, "error": str(e)[:120]},
                        })
                        # Best-effort force cleanup
                        try:
                            shutil.rmtree(workspace, ignore_errors=True)
                        except Exception:
                            pass

            records.append(record)

        # Hash git status AFTER — must match
        status_after = self._hash_git_status()
        repo_clean = status_before == status_after

        output = {
            "test_records": records,
            "execution_summary": {
                "total_patches": len(classified_patches),
                "patches_applied": patches_applied,
                "tests_run": tests_run,
                "tests_passed": tests_passed,
                "tests_failed": tests_failed,
                "tests_not_run": tests_not_run,
                "workspaces_created": workspaces_created,
                "workspaces_cleaned": workspaces_cleaned,
                "repo_git_status_unchanged": repo_clean,
                "timeout_seconds": self._timeout,
                "command_profile": "pytest",
                "sandbox_backend": self.sandbox_backend,  # v2.76
            },
            # v2.76: structured event log consumed by NodeEventEmitterMixin to
            # emit the v2.73 sandbox/code-execution EventType constants. The node
            # never writes trace events directly — runtime retains trace authority.
            "sandbox_event_log": event_log,
        }

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="sandbox_test_runner",
            step_id=envelope.step_id,
            output=output,
            output_type=PortType.SANDBOX_TEST_RESULTS,
        )
