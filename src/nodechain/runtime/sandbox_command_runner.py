"""v2.76: Sandbox Command Runner — isolated command execution backends.

Provides a backend-selected command execution seam for governed test running.
The Code Review chain's ``sandbox_test_runner`` node uses this to run pytest
through one of two backends:

  - ``local_subprocess``   : existing v2.73/v2.75 behavior (subprocess.run,
                             shell=False, env allowlist, output cap). This is
                             the default and MUST be behaviorally identical to
                             the previous inline ``_run_pytest()``.
  - ``native_os_sandbox``  : opt-in v2.76 path that routes the command through
                             NodeChain's existing native OS sandbox stack
                             (namespaces, seccomp, cgroups, mount confinement).
                             Fail-closed when the host cannot enforce it.

Design contract
---------------
- The runner owns ONLY command execution. It does NOT own workspace lifecycle,
  patch application, git-status integrity guards, or trace-truth classification.
  Those remain in ``sandbox_test_runner.execute()``.
- The result dict shape is identical to the previous ``_run_pytest()`` return
  value, so ``execute()`` can consume it unchanged. It additionally carries a
  ``sandbox_event_log`` list (v2.76) consumed by the runtime trace layer.
- Native backend never silently falls back to local subprocess. If
  ``native_os_sandbox`` is explicitly requested but the host cannot enforce it,
  the result is ``exit_code_interpretation="error"`` with
  ``reason="native_sandbox_unavailable"`` and ``process_started=False``.

Security posture
----------------
This module does NOT claim complete hostile-code containment. The native
backend reuses existing OS primitives; enforcement strength varies by host
capability. See docs/native_sandbox_test_runner.md.
"""
from __future__ import annotations

import os
import platform
import subprocess
from pathlib import Path
from typing import Any

# Re-exported so callers can build a config without importing subprocess_runner
# by name (keeps the seam self-contained). Imported lazily inside the native
# backend to avoid pulling the full subprocess_runner import chain on every
# local-subprocess call.


# Env allowlist mirrored from sandbox_test_runner (v2.73). Kept here so the
# local backend is self-contained and the allowlist has exactly one owner.
ENV_ALLOWLIST = {
    "PATH", "PYTHONPATH", "SYSTEMROOT", "TEMP", "TMP",
    "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
    "OPENAI_API_KEY", "OPENAI_BASE_URL",  # needed by chain tests that mock adapters
    "OPENALEX_API_KEY", "OPENALEX_EMAIL",
}


class SandboxCommandRunner:
    """Backend-selected isolated command runner.

    The runner is instantiated with a backend name and delegates ``run_command``
    to the matching backend. Unknown backends fail closed.
    """

    def __init__(self, backend: str = "local_subprocess") -> None:
        if backend not in ("local_subprocess", "native_os_sandbox"):
            raise ValueError(
                f"unknown sandbox backend: {backend!r} "
                "(expected 'local_subprocess' or 'native_os_sandbox')"
            )
        self._backend_name = backend
        self._backend: _Backend
        if backend == "local_subprocess":
            self._backend = LocalSubprocessBackend()
        else:
            self._backend = NativeOsSandboxBackend()

    @property
    def backend_name(self) -> str:
        return self._backend_name

    def run_command(
        self,
        argv: list[str],
        cwd: Path,
        timeout_seconds: int,
        max_output_bytes: int,
        env_allowlist: set[str] | None = None,
    ) -> dict[str, Any]:
        """Run ``argv`` in ``cwd`` through the selected backend.

        Returns a dict with the same keys as the historical ``_run_pytest()``
        return value, plus a ``sandbox_event_log`` list (v2.76) and a
        ``backend`` field identifying which backend ran.
        """
        allowlist = env_allowlist if env_allowlist is not None else ENV_ALLOWLIST
        return self._backend.run(
            argv=argv,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
            env_allowlist=allowlist,
        )


class _Backend:
    """Base interface for command-execution backends."""

    backend_name: str = "abstract"

    def run(
        self,
        *,
        argv: list[str],
        cwd: Path,
        timeout_seconds: int,
        max_output_bytes: int,
        env_allowlist: set[str],
    ) -> dict[str, Any]:
        raise NotImplementedError


def _new_event_log() -> list[dict[str, Any]]:
    """Fresh per-run event log accumulator."""
    return []


def _normalize_local_result(
    *,
    returncode: int | None,
    stdout: str,
    stderr: str,
    timed_out: bool,
    started: bool,
    max_output_bytes: int,
    error_msg: str = "",
) -> dict[str, Any]:
    """Apply the v2.73 dual-cap + 3-way normalization.

    Mirrors sandbox_test_runner._run_pytest() exactly:
      - stdout/stderr each independently capped to max_output_bytes
      - single output_truncated flag
      - exit_code_interpretation in {pass, fail, timeout, error}
    """
    output_truncated = False
    if len(stdout) > max_output_bytes:
        stdout = stdout[:max_output_bytes]
        output_truncated = True
    if len(stderr) > max_output_bytes:
        stderr = stderr[:max_output_bytes]
        output_truncated = True

    if not started:
        interpretation = "error"
    elif timed_out:
        interpretation = "timeout"
    elif returncode == 0:
        interpretation = "pass"
    else:
        interpretation = "fail"

    return {
        "process_started": started,
        "process_exit_code": returncode,
        "process_timed_out": timed_out,
        "stdout": stdout,
        "stderr": stderr if not error_msg else (error_msg[:500]),
        "output_truncated": output_truncated,
        "exit_code_interpretation": interpretation,
    }


class LocalSubprocessBackend(_Backend):
    """Existing v2.73/v2.75 behavior: direct subprocess.run, shell=False.

    This MUST be behaviorally identical to the previous inline ``_run_pytest()``.
    The only addition is the ``sandbox_event_log`` and ``backend`` fields.
    """

    backend_name = "local_subprocess"

    def run(
        self,
        *,
        argv: list[str],
        cwd: Path,
        timeout_seconds: int,
        max_output_bytes: int,
        env_allowlist: set[str],
    ) -> dict[str, Any]:
        from nodechain.runtime.streaming_output import run_bounded_subprocess

        event_log = _new_event_log()
        clean_env = {k: v for k, v in os.environ.items() if k in env_allowlist}

        event_log.append({
            "event_type": "code_execution_started",
            "backend": self.backend_name,
            "metadata": {"cwd": str(cwd), "argv_head": argv[0] if argv else ""},
        })

        result = run_bounded_subprocess(
            argv,
            cwd=str(cwd),
            env=clean_env,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )

        if not result["process_started"]:
            event_log.append({
                "event_type": "code_execution_failed",
                "backend": self.backend_name,
                "metadata": {"reason": result.get("reason", "spawn_failed")},
            })
        elif result["process_timed_out"]:
            event_log.append({
                "event_type": "code_execution_timed_out",
                "backend": self.backend_name,
                "metadata": {"timeout_seconds": timeout_seconds},
            })
        elif result["exit_code_interpretation"] == "pass":
            event_log.append({
                "event_type": "code_execution_completed",
                "backend": self.backend_name,
                "metadata": {"exit_code": result["process_exit_code"]},
            })
        else:
            event_log.append({
                "event_type": "code_execution_failed",
                "backend": self.backend_name,
                "metadata": {
                    "exit_code": result["process_exit_code"],
                    "reason": result.get("reason"),
                },
            })

        if result["output_truncated"]:
            event_log.append({
                "event_type": "sandbox_output_capped",
                "backend": self.backend_name,
                "metadata": {"max_output_bytes": max_output_bytes},
            })

        result["backend"] = self.backend_name
        result["sandbox_event_log"] = event_log
        return result


def native_sandbox_supported() -> bool:
    """Return True iff the host can enforce the native OS sandbox path.

    The native path requires Linux (namespaces, seccomp, cgroups, mount
    confinement are Linux syscalls). On other hosts the native backend must
    fail closed rather than silently fall back.
    """
    return platform.system() == "Linux"


class NativeOsSandboxBackend(_Backend):
    """v2.76: run the command inside the existing native OS sandbox.

    Reuses NodeChain's existing namespace / seccomp / cgroup / mount-confinement
    primitives. Implementation delegates to the validated child-bootstrap path
    while accepting an arbitrary argv (unlike SubprocessRunner which is
    node-module oriented).

    On non-Linux hosts this backend fails closed: it returns an error result
    with ``reason="native_sandbox_unavailable"`` and does NOT fall back to the
    local subprocess backend.
    """

    backend_name = "native_os_sandbox"

    def run(
        self,
        *,
        argv: list[str],
        cwd: Path,
        timeout_seconds: int,
        max_output_bytes: int,
        env_allowlist: set[str],
    ) -> dict[str, Any]:
        event_log = _new_event_log()

        if not native_sandbox_supported():
            # Fail closed. Do NOT fall back to local subprocess.
            event_log.append({
                "event_type": "code_execution_failed",
                "backend": self.backend_name,
                "metadata": {"reason": "native_sandbox_unavailable"},
            })
            return {
                "process_started": False,
                "process_exit_code": None,
                "process_timed_out": False,
                "stdout": "",
                "stderr": "native_os_sandbox requested but host cannot enforce it",
                "output_truncated": False,
                "exit_code_interpretation": "error",
                "reason": "native_sandbox_unavailable",
                "backend": self.backend_name,
                "sandbox_event_log": event_log,
            }

        # On supported (Linux) hosts, route through the native bootstrap.
        # Imported lazily so non-Linux hosts and the local backend never pay
        # the import cost or trigger Linux-only import side effects.
        from nodechain.runtime import native_sandbox_exec
        return native_sandbox_exec.run_isolated(
            argv=argv,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
            env_allowlist=env_allowlist,
            backend_name=self.backend_name,
        )
