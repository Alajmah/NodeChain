"""R3 lifecycle owner and reap authority tests.

Migrated from obsolete _SupervisedExecutionOwner/_terminalize_reap to
SupervisedExecSession and validate_terminal_proof.
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from unittest import mock

import pytest

from nodechain.runtime.supervised_exec_session import (
    SupervisedExecSession,
    ProcessTerminalProof,
    validate_terminal_proof,
    CleanupReport,
    ShutdownState,
    ShutdownReason,
    NATURAL_SHUTDOWN_GRACE,
    TERM_GRACE,
    KILL_GRACE,
)


class FakeTask:
    def __init__(self, done=True, cancelled=False, exc=None, result=0):
        self._done = done
        self._cancelled = cancelled
        self._exc = exc
        self._result = result
    def done(self): return self._done
    def cancelled(self): return self._cancelled
    def exception(self): return self._exc
    def result(self): return self._result


class FakeProc:
    def __init__(self, returncode=0):
        self.returncode = returncode
        self.pid = 99999
    async def wait(self): return self.returncode
    def kill(self): pass


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only: async lifecycle")
class TestTerminalProof:
    """Tests for validate_terminal_proof (R3-INV-004)."""

    def test_valid_wait_result_accepted(self):
        proof = validate_terminal_proof(FakeTask(done=True, result=0), FakeProc(0))
        assert proof.proven
        assert proof.returncode == 0

    def test_pending_task_rejected(self):
        proof = validate_terminal_proof(FakeTask(done=False), FakeProc())
        assert not proof.proven
        assert proof.reason == "proc_wait_pending"

    def test_cancelled_task_rejected(self):
        proof = validate_terminal_proof(FakeTask(cancelled=True), FakeProc())
        assert not proof.proven
        assert proof.reason == "proc_wait_cancelled"

    def test_exceptional_task_rejected(self):
        proof = validate_terminal_proof(FakeTask(exc=RuntimeError("fail")), FakeProc())
        assert not proof.proven
        assert proof.reason == "proc_wait_exception"

    def test_missing_returncode_rejected(self):
        proof = validate_terminal_proof(FakeTask(result=0), FakeProc(None))
        assert not proof.proven
        assert proof.reason == "proc_returncode_missing"

    def test_result_mismatch_rejected(self):
        proof = validate_terminal_proof(FakeTask(result=42), FakeProc(0))
        assert not proof.proven
        assert proof.reason == "proc_wait_result_mismatch"

    def test_repeated_validation_side_effect_free(self):
        task = FakeTask(done=True, result=0)
        proc = FakeProc(0)
        p1 = validate_terminal_proof(task, proc)
        p2 = validate_terminal_proof(task, proc)
        assert p1 == p2

    def test_exception_not_called_before_cancelled_check(self):
        class DangerousCancelledTask(FakeTask):
            def __init__(self):
                super().__init__(done=True, cancelled=True)
            def exception(self):
                raise AssertionError("exception() called on cancelled task!")
        proof = validate_terminal_proof(DangerousCancelledTask(), FakeProc())
        assert proof.reason == "proc_wait_cancelled"


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only: async lifecycle")
class TestSessionOwnership:
    """Tests for SupervisedExecSession ownership (R3-INV-002)."""

    def test_session_holds_all_state(self):
        session = SupervisedExecSession()
        assert session.proc is None
        assert session.pgid is None
        assert session.proc_exit_task is None
        assert session.transport is None
        assert session.config_task is None
        assert session.stdout_task is None
        assert session.stderr_task is None
        assert session.shutdown_state == ShutdownState.OPEN

    def test_observer_called(self):
        observed = []
        session = SupervisedExecSession(_observer=observed.append)
        session.observe("cleanup_started")
        session.observe("cleanup_completed")
        assert observed == ["cleanup_started", "cleanup_completed"]

    def test_owned_tasks_lists_correct_tasks(self):
        session = SupervisedExecSession(
            config_task=FakeTask(),
            stdout_task=FakeTask(),
            stderr_task=FakeTask(),
            proc_exit_task=FakeTask(),
        )
        owned = session.owned_tasks()
        assert len(owned) == 3

    def test_all_tasks_includes_proc_exit(self):
        session = SupervisedExecSession(
            config_task=FakeTask(),
            proc_exit_task=FakeTask(),
        )
        all_t = session.all_tasks()
        assert len(all_t) == 2

    def test_pgid_stored_not_rediscovered(self):
        session = SupervisedExecSession(pgid=12345)
        assert session.pgid == 12345

    def test_shutdown_state_starts_open(self):
        session = SupervisedExecSession()
        assert session.shutdown_state == ShutdownState.OPEN
