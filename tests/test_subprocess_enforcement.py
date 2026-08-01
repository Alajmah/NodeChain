"""Tests for subprocess policy enforcement at runtime.

AC1: subprocess.Popen blocked for local_trusted, local_untrusted, remote_untrusted.
AC2: subprocess.run/check_call/check_output blocked through same policy.
AC3: os.system blocked or mediated.
AC4: Importing subprocess alone is not the enforcement boundary.
AC5: SUBPROCESS_POLICY_BLOCKED records command, api, node_id, trust_level.
AC6: Built-in nodes retain existing subprocess behavior.
AC7: Concurrent branch execution remains safe.
AC8: Existing 974 tests remain green.
"""

import asyncio
import os
import subprocess
import sys

import pytest

from nodechain.sdk.trust import TrustLevel
from nodechain.sdk.subprocess_enforcer import (
    SubprocessEnforcer, SubprocessBlockedError, enforce_subprocess_for_node,
    _active_subprocess_enforcer,
)


class TestSubprocessPopen:
    """AC1: subprocess.Popen blocked for restricted levels."""

    def test_popen_blocked_local_trusted(self):
        """AC1: Popen blocked for local_trusted."""
        enforcer = enforce_subprocess_for_node(TrustLevel.LOCAL_TRUSTED, "pkg")
        with enforcer.enforce():
            with pytest.raises(SubprocessBlockedError) as exc_info:
                subprocess.Popen(["echo", "hello"])
            assert "Popen" in str(exc_info.value)

    def test_popen_blocked_local_untrusted(self):
        """AC1: Popen blocked for local_untrusted."""
        enforcer = enforce_subprocess_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(SubprocessBlockedError):
                subprocess.Popen(["ls"])

    def test_popen_blocked_remote_untrusted(self):
        """AC1: Popen blocked for remote_untrusted."""
        enforcer = enforce_subprocess_for_node(TrustLevel.REMOTE_UNTRUSTED, "remote")
        with enforcer.enforce():
            with pytest.raises(SubprocessBlockedError):
                subprocess.Popen(["whoami"])


class TestSubprocessRun:
    """AC2: subprocess.run/call/check_call/check_output blocked."""

    def test_run_blocked_untrusted(self):
        """AC2: run blocked for local_untrusted."""
        enforcer = enforce_subprocess_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(SubprocessBlockedError) as exc_info:
                subprocess.run(["echo", "test"])
            assert "run" in str(exc_info.value)

    def test_call_blocked_untrusted(self):
        """AC2: call blocked."""
        enforcer = enforce_subprocess_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(SubprocessBlockedError):
                subprocess.call(["echo", "test"])

    def test_check_call_blocked_untrusted(self):
        """AC2: check_call blocked."""
        enforcer = enforce_subprocess_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(SubprocessBlockedError):
                subprocess.check_call(["echo", "test"])

    def test_check_output_blocked_untrusted(self):
        """AC2: check_output blocked."""
        enforcer = enforce_subprocess_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(SubprocessBlockedError):
                subprocess.check_output(["echo", "test"])

    def test_run_blocked_local_trusted(self):
        """AC2: run blocked for local_trusted (no subprocess allowed)."""
        enforcer = enforce_subprocess_for_node(TrustLevel.LOCAL_TRUSTED, "pkg")
        with enforcer.enforce():
            with pytest.raises(SubprocessBlockedError):
                subprocess.run(["echo", "test"])


class TestOsSystem:
    """AC3: os.system blocked for restricted levels."""

    def test_os_system_blocked_untrusted(self):
        """AC3: os.system blocked for local_untrusted."""
        enforcer = enforce_subprocess_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(SubprocessBlockedError) as exc_info:
                os.system("echo test")
            assert "os.system" in str(exc_info.value)

    def test_os_popen_blocked_untrusted(self):
        """AC3: os.popen blocked for local_untrusted."""
        enforcer = enforce_subprocess_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(SubprocessBlockedError):
                os.popen("echo test")

    def test_os_system_blocked_local_trusted(self):
        """AC3: os.system blocked for local_trusted."""
        enforcer = enforce_subprocess_for_node(TrustLevel.LOCAL_TRUSTED, "pkg")
        with enforcer.enforce():
            with pytest.raises(SubprocessBlockedError):
                os.system("echo test")


class TestImportIsNotBoundary:
    """AC4: Importing subprocess alone is not enforcement."""

    def test_import_subprocess_allowed_when_not_enforcing(self):
        """AC4: Import works without enforcement active."""
        assert _active_subprocess_enforcer.get() is None
        import subprocess  # noqa: F401 — testing import works

    def test_import_allowed_during_enforcement(self):
        """AC4: Importing subprocess works even during enforcement (call is blocked)."""
        enforcer = enforce_subprocess_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            # Importing is fine
            import subprocess as sp  # noqa: F401
            # But calling is blocked
            with pytest.raises(SubprocessBlockedError):
                sp.run(["echo"])


class TestBuiltinSubprocess:
    """AC6: Built-in nodes retain subprocess behavior."""

    def test_builtin_popen_allowed(self):
        """AC6: Built-in can use Popen."""
        enforcer = enforce_subprocess_for_node(TrustLevel.BUILT_IN, "core")
        with enforcer.enforce():
            result = subprocess.run(
                [sys.executable, "-c", "print('ok')"],
                capture_output=True, text=True,
            )
            assert "ok" in result.stdout

    def test_builtin_os_system_allowed(self):
        """AC6: Built-in can use os.system."""
        enforcer = enforce_subprocess_for_node(TrustLevel.BUILT_IN, "core")
        with enforcer.enforce():
            ret = os.system(f"{sys.executable} -c \"print('ok')\"")
            # os.system on Windows passes through cmd.exe, which handles
            # the spaced interpreter path without extra quoting.
            assert ret == 0


class TestErrorFormat:
    """AC5: SUBPROCESS_POLICY_BLOCKED has all fields."""

    def test_error_has_all_fields(self):
        """AC5: Error includes command, api, trust, node."""
        err = SubprocessBlockedError(
            command="rm -rf /",
            api="subprocess.Popen",
            trust_level="local_untrusted",
            reason="subprocess blocked",
            node_id="suspicious_node",
        )
        msg = str(err)
        assert "SUBPROCESS_POLICY_BLOCKED" in msg
        assert "rm -rf /" in msg
        assert "Popen" in msg
        assert "local_untrusted" in msg
        assert "suspicious_node" in msg

    def test_error_fields_accessible(self):
        """AC5: Individual fields accessible."""
        err = SubprocessBlockedError("ls", "os.system", "remote", "blocked", "n1")
        assert err.command == "ls"
        assert err.api == "os.system"
        assert err.trust_level == "remote"
        assert err.node_id == "n1"


class TestEnforcementReport:
    """Report records subprocess policy result."""

    def test_report_after_block(self):
        enforcer = enforce_subprocess_for_node(TrustLevel.LOCAL_UNTRUSTED, "n")
        try:
            with enforcer.enforce():
                subprocess.run(["echo", "x"])
        except SubprocessBlockedError:
            pass
        report = enforcer.get_report()
        assert report["trust_level"] == "local_untrusted"
        assert report["violations"] >= 1
        assert report["allow_subprocess"] is False
        entry = report["blocked_commands"][0]
        assert "command" in entry
        assert "api" in entry

    def test_report_clean(self):
        enforcer = enforce_subprocess_for_node(TrustLevel.BUILT_IN, "core")
        with enforcer.enforce():
            subprocess.run([sys.executable, "-c", "print(1)"], capture_output=True)
        assert enforcer.get_report()["violations"] == 0


class TestHookRestoration:
    def test_cleared_after_exit(self):
        enforcer = enforce_subprocess_for_node(TrustLevel.LOCAL_TRUSTED, "t")
        with enforcer.enforce():
            assert _active_subprocess_enforcer.get() is enforcer
        assert _active_subprocess_enforcer.get() is None

    def test_cleared_after_exception(self):
        enforcer = enforce_subprocess_for_node(TrustLevel.LOCAL_UNTRUSTED, "t")
        try:
            with enforcer.enforce():
                subprocess.run(["x"])
        except SubprocessBlockedError:
            pass
        assert _active_subprocess_enforcer.get() is None


class TestConcurrentSubprocess:
    """AC7: Concurrent enforcement safe."""

    @pytest.mark.asyncio
    async def test_concurrent_different_trust_levels(self):
        results = {}

        async def restricted():
            enforcer = enforce_subprocess_for_node(TrustLevel.LOCAL_UNTRUSTED, "r")
            with enforcer.enforce():
                await asyncio.sleep(0.01)
                try:
                    subprocess.run(["echo", "x"])
                    results["restricted"] = "allowed"
                except SubprocessBlockedError:
                    results["restricted"] = "blocked"

        async def builtin():
            enforcer = enforce_subprocess_for_node(TrustLevel.BUILT_IN, "core")
            with enforcer.enforce():
                await asyncio.sleep(0.01)
                try:
                    subprocess.run([sys.executable, "-c", "print(1)"], capture_output=True)
                    results["builtin"] = "allowed"
                except SubprocessBlockedError:
                    results["builtin"] = "blocked"

        await asyncio.gather(restricted(), builtin())
        assert results["restricted"] == "blocked"
        assert results["builtin"] == "allowed"
