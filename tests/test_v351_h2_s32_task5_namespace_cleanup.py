"""S3.2 Task 5: namespace-wide terminal cleanup tests.

Mocked unit tests for _cleanup_namespace + static source authority +
integration locks.
"""

from __future__ import annotations

import ast
import errno
import os
import signal
import sys
from unittest import mock

import pytest


# ===========================================================================
# Static source authority
# ===========================================================================

class TestTask5StaticSource:
    """The production code must have the right structure for Task 5."""

    def test_cleanup_namespace_defined(self):
        src = open("src/nodechain/runtime/exec_supervisor.py").read()
        assert "def _cleanup_namespace(" in src

    def test_no_cleanup_bootstrap_references(self):
        src = open("src/nodechain/runtime/exec_supervisor.py").read()
        assert "_cleanup_bootstrap" not in src, "old _cleanup_bootstrap must be fully removed"

    def test_kill_minus_one_used(self):
        src = open("src/nodechain/runtime/exec_supervisor.py").read()
        assert "kill(-1, " in src or "kill(-1," in src, "namespace-wide kill(-1) must be used"

    def test_safe_kill_minus_one_defined(self):
        src = open("src/nodechain/runtime/exec_supervisor.py").read()
        assert "def _safe_kill_minus_one" in src

    def test_owned_pid_fallback_defined(self):
        src = open("src/nodechain/runtime/exec_supervisor.py").read()
        assert "def _owned_pid_fallback" in src

    def test_supervisor_main_captures_identity(self):
        src = open("src/nodechain/runtime/exec_supervisor.py").read()
        sm_start = src.index("def supervisor_main(")
        sm_end = src.index("\ndef ", sm_start + 1)
        sm_src = src[sm_start:sm_end]
        assert "expected_pidns_dev" in sm_src
        assert "expected_pidns_ino" in sm_src

    def test_fail_and_cleanup_calls_cleanup_namespace(self):
        src = open("src/nodechain/runtime/exec_supervisor.py").read()
        sm_start = src.index("def supervisor_main(")
        sm_end = src.index("\ndef ", sm_start + 1)
        sm_src = src[sm_start:sm_end]
        fac_start = sm_src.index("def _fail_and_cleanup")
        fac_end = sm_src.index("\n        pipes.close_non_protocol()", fac_start)
        fac_src = sm_src[fac_start:fac_end]
        assert "_cleanup_namespace" in fac_src

    def test_supervisor_started_failure_routes_through_cleanup(self):
        src = open("src/nodechain/runtime/exec_supervisor.py").read()
        sm_start = src.index("def supervisor_main(")
        sm_end = src.index("\ndef ", sm_start + 1)
        sm_src = src[sm_start:sm_end]
        assert "_fail_and_cleanup" in sm_src

    def test_l8_ptrace_lock_preserved(self):
        """supervisor_main still has exactly 1 PTRACE_SETOPTIONS."""
        src = open("src/nodechain/runtime/exec_supervisor.py").read()
        node = [n for n in ast.parse(src).body
                if isinstance(n, ast.FunctionDef) and n.name == "supervisor_main"][0]
        ptrace_calls = [s for s in ast.walk(node)
                        if isinstance(s, ast.Call) and isinstance(s.func, ast.Attribute)
                        and s.func.attr == "ptrace"]
        setopts = [c for c in ptrace_calls
                   if isinstance(c.args[0], ast.Name) and c.args[0].id == "PTRACE_SETOPTIONS"]
        assert len(setopts) == 1

    def test_launcher_does_not_call_kill_minus_one(self):
        """S launcher path must never invoke kill(-1)."""
        src = open("src/nodechain/runtime/exec_supervisor.py").read()
        launcher_start = src.index("def launch_pid_namespace_supervisor(")
        launcher_end = src.index("\ndef ", launcher_start + 1)
        launcher_src = src[launcher_start:launcher_end]
        assert "kill(-1" not in launcher_src, (
            "S launcher must not call kill(-1) — only namespace-init I does"
        )


# ===========================================================================
# Mocked _cleanup_namespace tests
# ===========================================================================

@pytest.mark.skipif(sys.platform != "linux", reason="POSIX signal/waitpid semantics")
class TestCleanupNamespace:
    """Mocked tests for _cleanup_namespace using controlled waitpid sequences."""

    def test_already_echild_no_signals(self):
        """ECHILD on first drain → success, no kill(-1)."""
        from nodechain.runtime import exec_supervisor as es
        kill_calls = []
        with mock.patch.object(es.os, "getpid", return_value=1), \
             mock.patch.object(es.os, "getppid", return_value=0), \
             mock.patch.object(es.os, "stat",
                               return_value=mock.MagicMock(st_dev=4, st_ino=99)), \
             mock.patch.object(es.os, "waitpid", side_effect=ChildProcessError()), \
             mock.patch.object(es.os, "kill",
                               side_effect=lambda pid, sig: kill_calls.append((pid, sig))):
            result = es._cleanup_namespace(None, 4, 99)
        assert result is True
        assert len(kill_calls) == 0, "no kill(-1) when ECHILD proven initially"

    def test_oserror_echild_is_success(self):
        """OSError(errno.ECHILD) must be classified as ECHILD_PROVEN, not WAIT_ERROR."""
        from nodechain.runtime import exec_supervisor as es
        kill_calls = []
        def fake_waitpid(pid, flags=0):
            e = OSError()
            e.errno = errno.ECHILD
            raise e
        with mock.patch.object(es.os, "getpid", return_value=1), \
             mock.patch.object(es.os, "getppid", return_value=0), \
             mock.patch.object(es.os, "stat",
                               return_value=mock.MagicMock(st_dev=4, st_ino=99)), \
             mock.patch.object(es.os, "waitpid", side_effect=fake_waitpid), \
             mock.patch.object(es.os, "kill",
                               side_effect=lambda pid, sig: kill_calls.append((pid, sig))):
            result = es._cleanup_namespace(None, 4, 99)
        assert result is True, "OSError(ECHILD) must be ECHILD_PROVEN success"
        assert len(kill_calls) == 0

    def test_eintr_retried(self):
        """EINTR from waitpid must be retried, not treated as error."""
        from nodechain.runtime import exec_supervisor as es
        call_count = {"n": 0}
        def fake_waitpid(pid, flags=0):
            call_count["n"] += 1
            if call_count["n"] <= 3:
                e = OSError()
                e.errno = errno.EINTR
                raise e
            raise ChildProcessError()
        with mock.patch.object(es.os, "getpid", return_value=1), \
             mock.patch.object(es.os, "getppid", return_value=0), \
             mock.patch.object(es.os, "stat",
                               return_value=mock.MagicMock(st_dev=4, st_ino=99)), \
             mock.patch.object(es.os, "waitpid", side_effect=fake_waitpid), \
             mock.patch.object(es.os, "kill"):
            result = es._cleanup_namespace(None, 4, 99)
        assert result is True

    def test_non_echild_wait_error_returns_false(self):
        """A non-ECHILD OSError → WAIT_ERROR → result permanently False."""
        from nodechain.runtime import exec_supervisor as es
        def fake_waitpid(pid, flags=0):
            e = OSError()
            e.errno = errno.EACCES
            raise e
        with mock.patch.object(es.os, "getpid", return_value=1), \
             mock.patch.object(es.os, "getppid", return_value=0), \
             mock.patch.object(es.os, "stat",
                               return_value=mock.MagicMock(st_dev=4, st_ino=99)), \
             mock.patch.object(es.os, "waitpid", side_effect=fake_waitpid), \
             mock.patch.object(es.os, "kill"):
            result = es._cleanup_namespace(None, 4, 99)
        assert result is False

    def test_non_echild_error_then_echild_still_false(self):
        """Wait error followed by ECHILD → still False (wait_error_seen)."""
        from nodechain.runtime import exec_supervisor as es
        call_count = {"n": 0}
        def fake_waitpid(pid, flags=0):
            call_count["n"] += 1
            if call_count["n"] == 1:
                e = OSError()
                e.errno = errno.EACCES
                raise e
            raise ChildProcessError()  # ECHILD after error
        with mock.patch.object(es.os, "getpid", return_value=1), \
             mock.patch.object(es.os, "getppid", return_value=0), \
             mock.patch.object(es.os, "stat",
                               return_value=mock.MagicMock(st_dev=4, st_ino=99)), \
             mock.patch.object(es.os, "waitpid", side_effect=fake_waitpid), \
             mock.patch.object(es.os, "kill"):
            result = es._cleanup_namespace(None, 4, 99)
        assert result is False, "ECHILD after non-ECHILD error must still be False"

    def test_term_produces_echild_no_sigkill(self):
        """TERM phase produces ECHILD → no SIGKILL escalation."""
        from nodechain.runtime import exec_supervisor as es
        kill_calls = []
        phase = {"n": 0}
        def fake_waitpid(pid, flags=0):
            phase["n"] += 1
            if phase["n"] <= 1:
                return (0, 0)  # drain: children remain
            if phase["n"] <= 3:
                return (0, 0)  # TERM reap: children remain briefly
            raise ChildProcessError()  # ECHILD during TERM phase
        with mock.patch.object(es.os, "getpid", return_value=1), \
             mock.patch.object(es.os, "getppid", return_value=0), \
             mock.patch.object(es.os, "stat",
                               return_value=mock.MagicMock(st_dev=4, st_ino=99)), \
             mock.patch.object(es.os, "waitpid", side_effect=fake_waitpid), \
             mock.patch.object(es.os, "kill",
                               side_effect=lambda pid, sig: kill_calls.append((pid, sig))):
            result = es._cleanup_namespace(None, 4, 99)
        assert result is True
        # SIGKILL must not have been sent.
        assert not any(sig == signal.SIGKILL for _, sig in kill_calls), (
            "SIGKILL must not be sent when TERM produces ECHILD"
        )

    def test_sigcont_precedes_sigterm(self):
        """SIGCONT must be sent before SIGTERM. Both signals are required
        unconditionally — not wrapped in an if-guard."""
        from nodechain.runtime import exec_supervisor as es
        kill_calls = []
        phase = {"n": 0}
        def fake_waitpid(pid, flags=0):
            phase["n"] += 1
            if phase["n"] <= 1:
                return (0, 0)
            raise ChildProcessError()
        with mock.patch.object(es.os, "getpid", return_value=1), \
             mock.patch.object(es.os, "getppid", return_value=0), \
             mock.patch.object(es.os, "stat",
                               return_value=mock.MagicMock(st_dev=4, st_ino=99)), \
             mock.patch.object(es.os, "waitpid", side_effect=fake_waitpid), \
             mock.patch.object(es.os, "kill",
                               side_effect=lambda pid, sig: kill_calls.append((pid, sig))):
            es._cleanup_namespace(None, 4, 99)
        sigs = [sig for _, sig in kill_calls]
        # Both signals must be present — unconditionally.
        assert signal.SIGCONT in sigs, "SIGCONT must be sent"
        assert signal.SIGTERM in sigs, "SIGTERM must be sent"
        assert sigs.index(signal.SIGCONT) < sigs.index(signal.SIGTERM), (
            "SIGCONT must precede SIGTERM"
        )

    def test_guard_failure_returns_false_no_kill_minus_one(self):
        """Identity guard failure → no kill(-1), return False."""
        from nodechain.runtime import exec_supervisor as es
        kill_calls = []
        with mock.patch.object(es.os, "getpid", return_value=5), \
             mock.patch.object(es.os, "getppid", return_value=1), \
             mock.patch.object(es.os, "kill",
                               side_effect=lambda pid, sig: kill_calls.append((pid, sig))), \
             mock.patch.object(es.os, "waitpid", side_effect=ChildProcessError()):
            result = es._cleanup_namespace(None, 4, 99)
        assert result is False
        for pid, _ in kill_calls:
            assert pid != -1, "guard failure must not call kill(-1)"

    def test_guard_failure_with_owned_pid_fallback(self):
        """Guard failure with an owned unreaped child → fallback SIGKILL to
        that child, but result still False."""
        from nodechain.runtime import exec_supervisor as es
        kill_calls = []
        with mock.patch.object(es.os, "getpid", return_value=5), \
             mock.patch.object(es.os, "getppid", return_value=1), \
             mock.patch.object(es.os, "kill",
                               side_effect=lambda pid, sig: kill_calls.append((pid, sig))), \
             mock.patch.object(es.os, "waitpid", return_value=(0, 0)):
            result = es._cleanup_namespace(55555, 4, 99)
        assert result is False
        assert any(pid == 55555 and sig == signal.SIGKILL for pid, sig in kill_calls)

    def test_guard_failure_with_already_reaped_pid_no_signal(self):
        """Guard failure + primary PID already reaped → no signal to that PID."""
        from nodechain.runtime import exec_supervisor as es
        kill_calls = []
        with mock.patch.object(es.os, "getpid", return_value=5), \
             mock.patch.object(es.os, "getppid", return_value=1), \
             mock.patch.object(es.os, "kill",
                               side_effect=lambda pid, sig: kill_calls.append((pid, sig))), \
             mock.patch.object(es.os, "waitpid", return_value=(55555, 0)):
            result = es._cleanup_namespace(55555, 4, 99)
        assert result is False
        assert len(kill_calls) == 0

    def test_signal_target_always_minus_one(self):
        """All namespace-wide kills must target -1."""
        from nodechain.runtime import exec_supervisor as es
        kill_calls = []
        phase = {"n": 0}
        def fake_waitpid(pid, flags=0):
            phase["n"] += 1
            if phase["n"] > 10:
                raise ChildProcessError()
            return (0, 0)
        with mock.patch.object(es.os, "getpid", return_value=1), \
             mock.patch.object(es.os, "getppid", return_value=0), \
             mock.patch.object(es.os, "stat",
                               return_value=mock.MagicMock(st_dev=4, st_ino=99)), \
             mock.patch.object(es.os, "waitpid", side_effect=fake_waitpid), \
             mock.patch.object(es.os, "kill",
                               side_effect=lambda pid, sig: kill_calls.append((pid, sig))):
            es._cleanup_namespace(None, 4, 99)
        for pid, _ in kill_calls:
            assert pid == -1, f"namespace-wide signal must target -1, got {pid}"

    def test_kill_esrch_not_success_without_echild(self):
        """kill(-1, ...) returning ESRCH is not success — only ECHILD proves it."""
        from nodechain.runtime import exec_supervisor as es
        with mock.patch.object(es.os, "getpid", return_value=1), \
             mock.patch.object(es.os, "getppid", return_value=0), \
             mock.patch.object(es.os, "stat",
                               return_value=mock.MagicMock(st_dev=4, st_ino=99)), \
             mock.patch.object(es.os, "waitpid", return_value=(0, 0)), \
             mock.patch.object(es.os, "kill", side_effect=ProcessLookupError()):
            result = es._cleanup_namespace(None, 4, 99)
        assert result is False

    def test_zombies_drained_before_signaling(self):
        """Zombie children are drained before any kill(-1) is issued."""
        from nodechain.runtime import exec_supervisor as es
        kill_calls = []
        phase = {"n": 0}
        def fake_waitpid(pid, flags=0):
            phase["n"] += 1
            if phase["n"] == 1:
                return (100, 0)  # one zombie
            if phase["n"] == 2:
                return (101, 0)  # another zombie
            raise ChildProcessError()  # no more children
        with mock.patch.object(es.os, "getpid", return_value=1), \
             mock.patch.object(es.os, "getppid", return_value=0), \
             mock.patch.object(es.os, "stat",
                               return_value=mock.MagicMock(st_dev=4, st_ino=99)), \
             mock.patch.object(es.os, "waitpid", side_effect=fake_waitpid), \
             mock.patch.object(es.os, "kill",
                               side_effect=lambda pid, sig: kill_calls.append((pid, sig))):
            result = es._cleanup_namespace(None, 4, 99)
        assert result is True
        assert len(kill_calls) == 0, "zombies drained before any kill(-1)"


# ===========================================================================
# Real .28 descendant tests
# ===========================================================================

@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only: namespace + ptrace")
@pytest.mark.native_sandbox
class TestRealDescendantCleanup:
    """Real .28 descendant tests with deterministic barriers.

    Each descendant loops indefinitely after signaling ready. Only the
    workload leader observes the release file. This forces namespace
    cleanup to actually terminate the descendant — it cannot exit
    voluntarily.

    The harness captures the descendant host PID via /proc chain
    traversal (S → I → workload → descendant) while alive, then verifies
    it disappears after cleanup completes.
    """

    def _resolve_process_tree(self, sup_pid):
        """Resolve S → I → workload host PIDs from /proc.
        Returns (s_pid, i_pid, wl_pid)."""
        from pathlib import Path
        def _children(pid):
            try:
                raw = Path(f"/proc/{pid}/task/{pid}/children").read_text()
                return [int(x) for x in raw.split()]
            except (FileNotFoundError, ProcessLookupError, ValueError):
                return []
        # S → I
        i_children = _children(sup_pid)
        if not i_children:
            return (sup_pid, None, None)
        i_pid = i_children[0]
        # I → workload
        wl_children = _children(i_pid)
        return (sup_pid, i_pid, wl_children[0] if wl_children else None)

    def _capture_descendant(self, wl_pid):
        """Capture the first descendant of the workload via /proc."""
        from pathlib import Path
        try:
            raw = Path(f"/proc/{wl_pid}/task/{wl_pid}/children").read_text()
            pids = [int(x) for x in raw.split()]
            return pids[0] if pids else None
        except (FileNotFoundError, ProcessLookupError, ValueError):
            return None

    def _proc_absent(self, pid, deadline=10.0):
        """Poll /proc/<pid> absence until deadline."""
        import time
        from pathlib import Path
        end = time.monotonic() + deadline
        while time.monotonic() < end:
            if not Path(f"/proc/{pid}").exists():
                return True
            time.sleep(0.1)
        return not Path(f"/proc/{pid}").exists()

    def _run_descendant_scenario(self, tmp_path, workload_src, verify_fn,
                                  grandchild_fn=None):
        """Run a descendant scenario with proper barrier structure.

        The workload writes 'ready' when the descendant topology is
        established. Only the leader watches 'release'. The test observes
        the process tree, captures the descendant host PID, then releases
        the leader and verifies cleanup.

        For the double-fork case, ``grandchild_fn`` is called instead of
        ``verify_fn`` so the test can wait for the intermediate to exit
        and then capture the grandchild from I's children.

        Returns the ``run_isolated`` result dict and ``captures``.
        """
        import threading, time
        from pathlib import Path
        from nodechain.runtime.native_sandbox_exec import run_isolated
        from nodechain.runtime.supervised_exec_session import SupervisedExecSession
        from nodechain.runtime import native_sandbox_exec as nse

        ready_file = tmp_path / "ready"
        release_file = tmp_path / "release"

        captures = {}
        original_observe = SupervisedExecSession.observe
        def _cap(self, state):
            original_observe(self, state)
            if state == "supervisor_spawned":
                pid = getattr(self.proc, "pid", None)
                if pid:
                    captures.setdefault("sup_pid", pid)

        # Capture the evidence object by wrapping the result mapper.
        original_map = nse.map_supervisor_result
        def capture_map(evidence, bounded, **kwargs):
            captures["evidence"] = evidence
            return original_map(evidence, bounded, **kwargs)

        SupervisedExecSession.observe = _cap
        nse.map_supervisor_result = capture_map
        result_box = [None]
        def worker():
            result_box[0] = run_isolated(
                argv=[sys.executable, "-c", workload_src],
                cwd=tmp_path, timeout_seconds=30,
                max_output_bytes=100000, env_allowlist={"PATH"},
                use_supervisor=True,
            )
        try:
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            deadline = time.monotonic() + 20.0
            while not ready_file.exists() and time.monotonic() < deadline:
                time.sleep(0.05)
            assert ready_file.exists(), "workload did not signal ready within 20s"

            # Resolve process tree.
            sup_pid = captures.get("sup_pid")
            assert sup_pid, "observer did not capture supervisor PID"
            s_pid, i_pid, wl_pid = self._resolve_process_tree(sup_pid)
            assert i_pid, f"I not found in S children"
            assert wl_pid, f"workload not found in I children"

            if grandchild_fn:
                # Double-fork case: grandchild_fn resolves the grandchild
                # after the intermediate exits, and returns the grandchild PID.
                gc_pid = grandchild_fn(s_pid, i_pid, wl_pid)
                assert gc_pid, "grandchild not resolved after reparenting"
                target_pid = gc_pid
            else:
                # Standard case: capture the direct descendant of the workload.
                desc_pid = self._capture_descendant(wl_pid)
                assert desc_pid, (
                    f"descendant not found in workload children (wl_pid={wl_pid})"
                )
                target_pid = desc_pid
                # Scenario-specific verification while descendant is alive.
                verify_fn(s_pid, i_pid, wl_pid, desc_pid)

            # Release ONLY the workload leader so it exits and triggers cleanup.
            release_file.write_text("go")

            # Join with bounded wait.
            t.join(timeout=40)
            assert not t.is_alive(), "supervised run thread did not terminate"
            result = result_box[0]
            assert result is not None, "no result from run"

            # Verify the captured descendant host PID disappeared.
            assert self._proc_absent(target_pid), (
                f"descendant host PID {target_pid} survived cleanup"
            )

            # Verify cleanup succeeded via explicit evidence fields.
            assert result.get("process_exit_code") == 0, (
                f"workload exit code: {result.get('process_exit_code')}"
            )
            assert result.get("exit_code_interpretation") == "pass", (
                f"interpretation: {result.get('exit_code_interpretation')}"
            )

            # Verify the captured SupervisorExecutionEvidence.
            evidence = captures.get("evidence")
            assert evidence is not None, (
                "map_supervisor_result was not called — evidence not captured"
            )
            assert evidence.protocol_valid is True, (
                f"protocol_valid={evidence.protocol_valid}"
            )
            assert evidence.cleanup_succeeded is True, (
                f"cleanup_succeeded={evidence.cleanup_succeeded}"
            )
            assert evidence.supervisor_failure_reason is None, (
                f"supervisor_failure_reason={evidence.supervisor_failure_reason}"
            )
            assert evidence.protocol_failure_reason is None, (
                f"protocol_failure_reason={evidence.protocol_failure_reason}"
            )

            # Verify parent-side PGID quiescence via killpg.
            # S was spawned with start_new_session=True, so its PID == PGID.
            # killpg must raise ProcessLookupError with errno == ESRCH.
            try:
                os.killpg(sup_pid, 0)
                pytest.fail(
                    f"killpg({sup_pid}, 0) succeeded — process group not gone"
                )
            except ProcessLookupError as e:
                assert e.errno == errno.ESRCH, (
                    f"killpg raised ProcessLookupError but errno={e.errno}, "
                    f"expected ESRCH ({errno.ESRCH})"
                )
            except OSError as e:
                pytest.fail(
                    f"killpg raised {type(e).__name__}(errno={e.errno}), "
                    f"expected ProcessLookupError(ESRCH)"
                )
        finally:
            SupervisedExecSession.observe = original_observe
            nse.map_supervisor_result = original_map
        return result, captures

    def test_descendant_survives_leader_exit(self, tmp_path):
        """Workload forks a child that loops indefinitely; only the leader
        exits on release. Namespace cleanup must terminate the survivor."""
        ready = (tmp_path / "ready").as_posix()
        release = (tmp_path / "release").as_posix()
        workload = (
            f"import os, sys, time\n"
            f"pid = os.fork()\n"
            f"if pid == 0:\n"
            f"    open({ready!r},'w').close()\n"
            f"    while True: time.sleep(1)\n"  # descendant never exits
            f"else:\n"
            f"    while not os.path.exists({release!r}): time.sleep(0.05)\n"
            f"    sys.exit(0)\n"
        )
        def verify(s_pid, i_pid, wl_pid, desc_pid):
            # Descendant must be alive and a child of the workload.
            from pathlib import Path as _P; assert _P(f"/proc/{desc_pid}").exists(), "descendant not alive"
        self._run_descendant_scenario(tmp_path, workload, verify)

    def test_sigterm_ignoring_descendant(self, tmp_path):
        """SIGTERM-ignoring descendant loops indefinitely; SIGKILL must reap it."""
        ready = (tmp_path / "ready").as_posix()
        release = (tmp_path / "release").as_posix()
        workload = (
            f"import os, sys, signal, time\n"
            f"pid = os.fork()\n"
            f"if pid == 0:\n"
            f"    signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            f"    open({ready!r},'w').close()\n"
            f"    while True: time.sleep(1)\n"  # never exits, ignores TERM
            f"else:\n"
            f"    while not os.path.exists({release!r}): time.sleep(0.05)\n"
            f"    sys.exit(0)\n"
        )
        def verify(s_pid, i_pid, wl_pid, desc_pid):
            from pathlib import Path as _P; assert _P(f"/proc/{desc_pid}").exists()
        self._run_descendant_scenario(tmp_path, workload, verify)

    def test_sigstop_stopped_descendant(self, tmp_path):
        """SIGSTOP-stopped descendant; SIGCONT must precede TERM/KILL.
        The test polls for stopped state (T) and fails if not observed."""
        ready = (tmp_path / "ready").as_posix()
        release = (tmp_path / "release").as_posix()
        workload = (
            f"import os, sys, signal, time\n"
            f"pid = os.fork()\n"
            f"if pid == 0:\n"
            f"    open({ready!r},'w').close()\n"
            f"    os.kill(os.getpid(), signal.SIGSTOP)\n"
            f"    while True: time.sleep(1)\n"
            f"else:\n"
            f"    while not os.path.exists({release!r}): time.sleep(0.05)\n"
            f"    sys.exit(0)\n"
        )
        def verify(s_pid, i_pid, wl_pid, desc_pid):
            from pathlib import Path
            import time
            # Bounded poll for State: T (stopped).
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                try:
                    status = Path(f"/proc/{desc_pid}/status").read_text()
                    state_line = [l for l in status.splitlines() if l.startswith("State:")]
                    if state_line:
                        state_val = state_line[0].split()[1]
                        if state_val in ("T", "t"):
                            return  # Stopped state confirmed
                except (FileNotFoundError, ProcessLookupError):
                    pass
                time.sleep(0.1)
            pytest.fail(
                f"descendant {desc_pid} never reached stopped state T within 5s"
            )
        self._run_descendant_scenario(tmp_path, workload, verify)

    def test_double_fork_orphan(self, tmp_path):
        """Double-fork orphan: intermediate exits, grandchild reparented to I.
        The test waits for the intermediate to exit, then captures the
        grandchild from I's children and verifies PPid == I host PID."""
        ready = (tmp_path / "ready").as_posix()
        release = (tmp_path / "release").as_posix()
        workload = (
            f"import os, sys, time\n"
            f"pid = os.fork()\n"
            f"if pid == 0:\n"
            f"    gpid = os.fork()\n"
            f"    if gpid == 0:\n"
            f"        open({ready!r},'w').close()\n"
            f"        while True: time.sleep(1)\n"  # grandchild never exits
            f"    sys.exit(0)\n"  # intermediate exits → orphan reparents
            f"else:\n"
            f"    while not os.path.exists({release!r}): time.sleep(0.05)\n"
            f"    sys.exit(0)\n"
        )
        def resolve_grandchild(s_pid, i_pid, wl_pid):
            from pathlib import Path
            import time
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                i_children = []
                try:
                    raw = Path(f"/proc/{i_pid}/task/{i_pid}/children").read_text()
                    i_children = [int(x) for x in raw.split()]
                except (FileNotFoundError, ProcessLookupError, ValueError):
                    pass
                candidates = [p for p in i_children if p != wl_pid]
                for gc_pid in candidates:
                    try:
                        status = Path(f"/proc/{gc_pid}/status").read_text()
                        ppid_line = next(
                            line for line in status.splitlines()
                            if line.startswith("PPid:")
                        )
                        observed_ppid = int(ppid_line.split()[1])
                    except (FileNotFoundError, ProcessLookupError,
                            StopIteration, ValueError):
                        continue
                    if observed_ppid == i_pid:
                        return gc_pid
                time.sleep(0.1)
            pytest.fail(
                f"grandchild with PPid=={i_pid} not found in I children "
                f"within 5s (i_children={i_children})"
            )
        self._run_descendant_scenario(
            tmp_path, workload, verify_fn=None, grandchild_fn=resolve_grandchild
        )


# ===========================================================================
# Bounded-drain adversarial tests
# ===========================================================================

@pytest.mark.skipif(sys.platform != "linux", reason="POSIX signal/waitpid semantics")
class TestBoundedDrainAdversarial:
    """Tests proving the initial drain is bounded even when waitpid
    continuously returns positive PIDs or EINTR."""

    def test_continuous_positive_pid_exits_drain(self):
        """waitpid always returns positive PID → drain bounded by deadline,
        then signals fire with correct sequence."""
        from nodechain.runtime import exec_supervisor as es
        kill_calls = []
        phase = {"n": 0}
        def fake_waitpid(pid, flags=0):
            phase["n"] += 1
            return (phase["n"], 0)
        with mock.patch.object(es.os, "getpid", return_value=1), \
             mock.patch.object(es.os, "getppid", return_value=0), \
             mock.patch.object(es.os, "stat",
                               return_value=mock.MagicMock(st_dev=4, st_ino=99)), \
             mock.patch.object(es.os, "waitpid", side_effect=fake_waitpid), \
             mock.patch.object(es.os, "kill",
                               side_effect=lambda pid, sig: kill_calls.append((pid, sig))), \
             mock.patch.object(es.time, "monotonic",
                               side_effect=lambda: [0.0, 0.0, 0.0, 0.1, 0.2, 0.3, 0.4, 0.5,
                                                    0.6, 0.7, 0.8, 0.9, 1.0, 1.1, 1.2,
                                                    1.3, 1.4, 1.5, 2.0, 3.0, 4.0, 5.0,
                                                    6.0, 7.0, 8.0, 9.0, 10.0][min(phase["n"], 26)]):
            result = es._cleanup_namespace(None, 4, 99)
        assert result is False, "continuous positive PID must not produce success"
        assert len(kill_calls) >= 2, "SIGCONT+SIGTERM must fire after drain deadline"
        # First two namespace-wide signals must be (-1, SIGCONT) and (-1, SIGTERM).
        assert kill_calls[0] == (-1, signal.SIGCONT), (
            f"first signal must be (-1, SIGCONT), got {kill_calls[0]}"
        )
        assert kill_calls[1] == (-1, signal.SIGTERM), (
            f"second signal must be (-1, SIGTERM), got {kill_calls[1]}"
        )

    def test_continuous_eintr_exits_drain(self):
        """Continuous EINTR → drain bounded by deadline, then signals fire
        with correct sequence."""
        from nodechain.runtime import exec_supervisor as es
        kill_calls = []
        phase = {"n": 0}
        def fake_waitpid(pid, flags=0):
            phase["n"] += 1
            e = OSError()
            e.errno = errno.EINTR
            raise e
        time_idx = [0]
        time_seq = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9,
                    1.0, 1.5, 2.0, 3.0, 4.0, 5.0, 10.0]
        def fake_monotonic():
            v = time_seq[min(time_idx[0], len(time_seq) - 1)]
            time_idx[0] += 1
            return v
        with mock.patch.object(es.os, "getpid", return_value=1), \
             mock.patch.object(es.os, "getppid", return_value=0), \
             mock.patch.object(es.os, "stat",
                               return_value=mock.MagicMock(st_dev=4, st_ino=99)), \
             mock.patch.object(es.os, "waitpid", side_effect=fake_waitpid), \
             mock.patch.object(es.os, "kill",
                               side_effect=lambda pid, sig: kill_calls.append((pid, sig))), \
             mock.patch.object(es.time, "monotonic", side_effect=fake_monotonic):
            result = es._cleanup_namespace(None, 4, 99)
        assert result is False, "continuous EINTR must not produce success"
        assert len(kill_calls) >= 2, "SIGCONT+SIGTERM must fire after drain deadline"
        assert kill_calls[0] == (-1, signal.SIGCONT), (
            f"first signal must be (-1, SIGCONT), got {kill_calls[0]}"
        )
        assert kill_calls[1] == (-1, signal.SIGTERM), (
            f"second signal must be (-1, SIGTERM), got {kill_calls[1]}"
        )


# ===========================================================================
# Cross-task invariant: cleanup function never raises through supervisor_main
# ===========================================================================

class TestCleanupDoesNotRaise:
    """_cleanup_namespace must never raise — it must return bool."""

    def test_cleanup_returns_bool_on_all_outcomes(self):
        """Even on OSError/stat failure/getpid failure, returns bool."""
        from nodechain.runtime import exec_supervisor as es
        with mock.patch.object(es.os, "getpid", side_effect=OSError("fail")):
            result = es._cleanup_namespace(None, 4, 99)
        assert isinstance(result, bool)
        assert result is False  # guard failed


# ===========================================================================
# Bootstrap_pid == 0 path (correction #2) + protocol failure
# ===========================================================================

class TestBootstrapNotForkedCleanup:
    """Even when bootstrap_pid == 0, namespace cleanup must be invoked."""

    def test_supervisor_started_failure_invokes_cleanup(self):
        """When supervisor_started emit fails, _cleanup_namespace must still
        be called with primary_pid=None (bootstrap not forked yet)."""
        from nodechain.runtime import exec_supervisor as es

        cleanup_calls = []
        def capture_cleanup(primary, dev, ino):
            cleanup_calls.append((primary, dev, ino))
            return False

        with mock.patch.object(es, "_cleanup_namespace", side_effect=capture_cleanup), \
             mock.patch.object(es, "emit_protocol", side_effect=es.ProtocolChannelError("fail")), \
             mock.patch.object(es, "SupervisorPipeSet") as MockPipes:
            mock_pipes = MockPipes.return_value
            mock_pipes.close_non_protocol = mock.Mock()
            mock_pipes.close_protocol = mock.Mock()
            rc = es.supervisor_main(
                {"expected_pidns_dev": 4, "expected_pidns_ino": 99},
                999,
            )
        assert rc != 0
        # _cleanup_namespace must have been called with None primary.
        assert len(cleanup_calls) >= 1, "_cleanup_namespace must be called"
        assert cleanup_calls[0][0] is None, (
            "primary_pid must be None when bootstrap not forked"
        )
        assert cleanup_calls[0][1] == 4
        assert cleanup_calls[0][2] == 99

    def test_cleanup_false_carries_to_cleanup_completed(self):
        """When _cleanup_namespace returns False, cleanup_completed must
        carry cleanup_succeeded=False."""
        from nodechain.runtime import exec_supervisor as es
        from nodechain.runtime.exec_supervisor import ProtocolChannelError

        emit_calls = []
        def capture_emit(fd, record):
            emit_calls.append(record)

        with mock.patch.object(es, "_cleanup_namespace", return_value=False), \
             mock.patch.object(es, "emit_protocol", side_effect=capture_emit), \
             mock.patch.object(es, "SupervisorPipeSet") as MockPipes, \
             mock.patch.object(es.os, "fork", create=True, side_effect=OSError("no fork")), \
             mock.patch.object(es.os, "close"), \
             mock.patch.object(es.os, "pipe", side_effect=[(100,101),(102,103)]):
            mock_pipes = MockPipes.return_value
            mock_pipes.close_non_protocol = mock.Mock()
            mock_pipes.close_protocol = mock.Mock()
            mock_pipes.config_rfd = 100
            mock_pipes.config_wfd = 101
            mock_pipes.metadata_rfd = 102
            mock_pipes.metadata_wfd = 103
            mock_pipes.protocol_wfd = 999
            es.supervisor_main(
                {"expected_pidns_dev": 4, "expected_pidns_ino": 99},
                999,
            )
        # Find the cleanup_completed record.
        cleanup_records = [r for r in emit_calls if r.get("type") == "cleanup_completed"]
        assert len(cleanup_records) >= 1, "cleanup_completed must be emitted"
        assert cleanup_records[-1].get("cleanup_succeeded") is False, (
            "cleanup_succeeded must be False when cleanup fails"
        )
