"""S1: Standalone kernel prototype for PTRACE_EVENT_EXEC handshake.

Proves the exact exec-observation mechanism on the target host:
  supervisor unshares PID namespace
  → forks direct bootstrap/PID 1
  → bootstrap performs PTRACE_TRACEME + raise(SIGSTOP)
  → supervisor arms PTRACE_O_TRACEEXEC
  → supervisor continues bootstrap
  → bootstrap calls execve
  → supervisor observes PTRACE_EVENT_EXEC

This test validates the mechanism ONLY — no namespace/seccomp/mount stack.
"""

from __future__ import annotations

import ctypes
import json
import os
import signal
import struct
import sys
import tempfile
import time
from pathlib import Path

import pytest


# Linux ptrace constants
PTRACE_TRACEME = 0
PTRACE_SETOPTIONS = 0x4200
PTRACE_O_TRACEEXEC = 0x10
PTRACE_CONT = 7
PTRACE_EVENT_EXEC = 4


def _libc():
    """Get libc with proper errno support."""
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_int,
                            ctypes.c_void_p, ctypes.c_void_p]
    libc.ptrace.restype = ctypes.c_long
    return libc


def _minimal_python_exec_env() -> dict[str, str]:
    """Build the minimal environment required to re-exec this interpreter.

    The bootstrap and workload processes re-exec ``sys.executable`` across two
    ``execve`` boundaries with an explicit (replaced) environment. If that
    environment omits ``LD_LIBRARY_PATH``, a relocated CPython (e.g. the
    ``actions/setup-python`` tool-cache build whose bundled ``libpython`` is
    not on the default system loader path) fails to resolve its shared
    libraries and cannot import ``ctypes`` — so the bootstrap dies before it
    can call ``ptrace``.

    Only ``PATH`` and ``LD_LIBRARY_PATH`` are carried: the loader path is the
    one variable the relocated interpreter genuinely needs. The complete
    ambient environment is deliberately NOT propagated — credentials, tokens,
    proxy variables, ``PYTHONPATH`` and unrelated runner state stay out of the
    spawned prototype.
    """
    env: dict[str, str] = {"PATH": "/usr/bin:/bin"}
    loader_path = os.environ.get("LD_LIBRARY_PATH")
    if loader_path:
        env["LD_LIBRARY_PATH"] = loader_path
    return env


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only ptrace test")
class TestS1ExecEventPrototype:
    """Prove PTRACE_EVENT_EXEC works in the supervisor topology."""

    def test_exec_event_observed(self, tmp_path):
        """Supervisor forks bootstrap, observes PTRACE_EVENT_EXEC.

        PID namespace unshare is attempted but not required — the test
        proves the ptrace exec-observation mechanism works regardless."""
        libc = _libc()

        # Create a simple workload that the bootstrap will exec into.
        workload = tmp_path / "workload.py"
        workload.write_text(
            "import os\n"
            "print(f'WORKLOAD_PID={os.getpid()}', flush=True)\n"
            "os._exit(0)\n"
        )

        # Create the bootstrap script.
        bootstrap = tmp_path / "bootstrap.py"
        workload_str = str(workload)
        exec_env = _minimal_python_exec_env()
        bootstrap.write_text(
            "import ctypes, os, signal, sys\n"
            "libc = ctypes.CDLL(None, use_errno=True)\n"
            "libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]\n"
            "libc.ptrace.restype = ctypes.c_long\n"
            f"r = libc.ptrace({PTRACE_TRACEME}, 0, None, None)\n"
            f"if r != 0:\n"
            f"    print(f'PTRACE_TRACEME failed errno={{ctypes.get_errno()}}', file=sys.stderr, flush=True)\n"
            f"    os._exit(126)\n"
            "os.kill(os.getpid(), signal.SIGSTOP)\n"
            f"os.execve(sys.executable, [sys.executable, '{workload_str}'], {exec_env!r})\n"
            "os._exit(127)\n"
        )

        # v3.5.1 H2 S2: no PID namespace unshare in the test process.
        # S1 validates the ptrace exec-observation mechanism ONLY. Namespace
        # topology is deferred to S3 (disposable supervisor process).

        pid = os.fork()
        if pid == 0:
            os.execve(sys.executable,
                      [sys.executable, str(bootstrap), str(workload)],
                      exec_env)
            os._exit(127)

        # === SUPERVISOR ===
        wpid, status = os.waitpid(pid, 0)
        assert os.WIFSTOPPED(status), f"bootstrap did not stop: status={status}"
        assert os.WSTOPSIG(status) == signal.SIGSTOP, (
            f"bootstrap stopped with unexpected signal {os.WSTOPSIG(status)}"
        )

        r = libc.ptrace(PTRACE_SETOPTIONS, pid, None, PTRACE_O_TRACEEXEC)
        assert r == 0, f"PTRACE_SETOPTIONS failed: errno={ctypes.get_errno()}"

        r = libc.ptrace(PTRACE_CONT, pid, None, 0)
        assert r == 0, f"PTRACE_CONT failed: errno={ctypes.get_errno()}"

        exec_confirmed = False
        workload_exit = None

        while True:
            try:
                wpid, status = os.waitpid(pid, 0)
            except ChildProcessError:
                break

            if os.WIFSTOPPED(status):
                stopsig = os.WSTOPSIG(status)
                event = status >> 16

                if stopsig == signal.SIGTRAP and event == PTRACE_EVENT_EXEC:
                    exec_confirmed = True
                    # Fix #8: check PTRACE_CONT result.
                    r2 = libc.ptrace(PTRACE_CONT, pid, None, 0)
                    assert r2 == 0, (
                        f"PTRACE_CONT after exec failed: errno={ctypes.get_errno()}"
                    )
                    continue
                else:
                    # Fix #8: check PTRACE_CONT result.
                    r2 = libc.ptrace(PTRACE_CONT, pid, None, stopsig)
                    assert r2 == 0, (
                        f"PTRACE_CONT signal-forward failed: errno={ctypes.get_errno()}"
                    )
                    continue
            elif os.WIFEXITED(status):
                workload_exit = os.WEXITSTATUS(status)
                break
            elif os.WIFSIGNALED(status):
                workload_exit = -os.WTERMSIG(status)
                break
            else:
                break

        assert exec_confirmed, (
            "PTRACE_EVENT_EXEC was NOT observed — exec confirmation failed"
        )
        assert workload_exit == 0, (
            f"workload exited with unexpected code: {workload_exit}"
        )

    def test_bootstrap_killed_before_exec(self, tmp_path):
        """If the bootstrap is killed before exec, no PTRACE_EVENT_EXEC fires."""
        libc = _libc()

        bootstrap = tmp_path / "slow_bootstrap.py"
        bootstrap.write_text(
            "import ctypes, os, signal, sys, time\n"
            "libc = ctypes.CDLL(None, use_errno=True)\n"
            "libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]\n"
            "libc.ptrace.restype = ctypes.c_long\n"
            f"r = libc.ptrace({PTRACE_TRACEME}, 0, None, None)\n"
            "if r != 0:\n"
            "    os._exit(126)\n"
            "os.kill(os.getpid(), signal.SIGSTOP)\n"
            "# Sleep forever — never exec\n"
            "time.sleep(999)\n"
        )

        # v3.5.1 H2 S2: PID namespace unshare removed from the test process.
        # S1 validates the ptrace exec-observation mechanism ONLY. Namespace
        # topology is deferred to S3 (disposable supervisor process).
        pid = os.fork()
        if pid == 0:
            os.execve(sys.executable,
                      [sys.executable, str(bootstrap)],
                      _minimal_python_exec_env())
            os._exit(127)

        # Wait for SIGSTOP.
        wpid, status = os.waitpid(pid, 0)
        assert os.WIFSTOPPED(status)

        # Arm exec tracing — assert success.
        r = libc.ptrace(PTRACE_SETOPTIONS, pid, None, PTRACE_O_TRACEEXEC)
        assert r == 0, f"PTRACE_SETOPTIONS failed: errno={ctypes.get_errno()}"

        r = libc.ptrace(PTRACE_CONT, pid, None, 0)
        assert r == 0, f"PTRACE_CONT failed: errno={ctypes.get_errno()}"

        # Kill the bootstrap before it can exec.
        time.sleep(0.5)
        os.kill(pid, signal.SIGKILL)

        # Wait for the death.
        exec_confirmed = False
        final_status = None
        while True:
            try:
                wpid, status = os.waitpid(pid, 0)
            except ChildProcessError:
                break
            if os.WIFSTOPPED(status):
                event = status >> 16
                if os.WSTOPSIG(status) == signal.SIGTRAP and event == PTRACE_EVENT_EXEC:
                    exec_confirmed = True
                # Fix #8: check PTRACE_CONT result.
                cont_r = libc.ptrace(PTRACE_CONT, pid, None, os.WSTOPSIG(status))
                assert cont_r == 0, (
                    f"PTRACE_CONT failed in wait loop: errno={ctypes.get_errno()}"
                )
                continue
            final_status = status
            break

        assert not exec_confirmed, (
            "PTRACE_EVENT_EXEC observed after SIGKILL — false positive!"
        )
        assert final_status is not None, "no final status from waitpid"
        assert os.WIFSIGNALED(final_status), (
            f"expected WIFSIGNALED, got status={final_status}"
        )
        assert os.WTERMSIG(final_status) == signal.SIGKILL, (
            f"expected SIGKILL, got signal {os.WTERMSIG(final_status)}"
        )


class TestMinimalPythonExecEnv:
    """CI-H1: the loader-path-preserving helper is hermetic on every platform.

    These cover the environment-stripping regression directly so the helper's
    contract is pinned independently of the (Linux-only) ptrace tests.
    """

    def test_ld_library_path_present_preserves_path_and_loader(self, monkeypatch):
        monkeypatch.setenv("LD_LIBRARY_PATH", "/opt/python/x64/lib")
        env = _minimal_python_exec_env()
        assert env["PATH"] == "/usr/bin:/bin"
        assert env["LD_LIBRARY_PATH"] == "/opt/python/x64/lib"

    def test_ld_library_path_present_excludes_unrelated_variables(self, monkeypatch):
        monkeypatch.setenv("LD_LIBRARY_PATH", "/opt/python/x64/lib")
        monkeypatch.setenv("PYTHONPATH", "/should/not/leak")
        monkeypatch.setenv("GH_TOKEN", "should_not_leak")
        monkeypatch.setenv("https_proxy", "http://should.not.leak:3128")
        env = _minimal_python_exec_env()
        assert env == {"PATH": "/usr/bin:/bin", "LD_LIBRARY_PATH": "/opt/python/x64/lib"}

    def test_ld_library_path_absent_is_exactly_path(self, monkeypatch):
        monkeypatch.delenv("LD_LIBRARY_PATH", raising=False)
        env = _minimal_python_exec_env()
        assert env == {"PATH": "/usr/bin:/bin"}
