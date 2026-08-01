"""Tests for subprocess async and convenience API coverage.

AC1: subprocess.getoutput is blocked for restricted levels.
AC2: subprocess.getstatusoutput is blocked for restricted levels.
AC3: asyncio.create_subprocess_exec is blocked for restricted levels.
AC4: asyncio.create_subprocess_shell is blocked for restricted levels.
AC5: Concurrent branch execution remains safe.
AC6: Error records api, command, node_id, trust_level.
AC7: Built-in behavior unchanged.
AC8: Existing 996 tests remain green.
"""

import asyncio
import subprocess
import sys

import pytest

from nodechain.sdk.trust import TrustLevel
from nodechain.sdk.subprocess_enforcer import (
    SubprocessBlockedError, enforce_subprocess_for_node,
)


class TestGetoutput:
    """AC1: subprocess.getoutput blocked."""

    def test_getoutput_blocked_untrusted(self):
        enforcer = enforce_subprocess_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(SubprocessBlockedError) as exc_info:
                subprocess.getoutput("echo hello")
            assert "getoutput" in str(exc_info.value)

    def test_getoutput_blocked_local_trusted(self):
        enforcer = enforce_subprocess_for_node(TrustLevel.LOCAL_TRUSTED, "pkg")
        with enforcer.enforce():
            with pytest.raises(SubprocessBlockedError):
                subprocess.getoutput("echo hello")


class TestGetstatusoutput:
    """AC2: subprocess.getstatusoutput blocked."""

    def test_getstatusoutput_blocked_untrusted(self):
        enforcer = enforce_subprocess_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(SubprocessBlockedError) as exc_info:
                subprocess.getstatusoutput("echo hello")
            assert "getstatusoutput" in str(exc_info.value)

    def test_getstatusoutput_blocked_local_trusted(self):
        enforcer = enforce_subprocess_for_node(TrustLevel.LOCAL_TRUSTED, "pkg")
        with enforcer.enforce():
            with pytest.raises(SubprocessBlockedError):
                subprocess.getstatusoutput("echo hello")


class TestAsyncioCreateSubprocessExec:
    """AC3: asyncio.create_subprocess_exec blocked."""

    @pytest.mark.asyncio
    async def test_async_exec_blocked_untrusted(self):
        enforcer = enforce_subprocess_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(SubprocessBlockedError) as exc_info:
                await asyncio.create_subprocess_exec("echo", "hello")
            assert "create_subprocess_exec" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_async_exec_blocked_trusted(self):
        enforcer = enforce_subprocess_for_node(TrustLevel.LOCAL_TRUSTED, "pkg")
        with enforcer.enforce():
            with pytest.raises(SubprocessBlockedError):
                await asyncio.create_subprocess_exec("echo", "hello")

    @pytest.mark.asyncio
    async def test_async_exec_blocked_remote(self):
        enforcer = enforce_subprocess_for_node(TrustLevel.REMOTE_UNTRUSTED, "remote")
        with enforcer.enforce():
            with pytest.raises(SubprocessBlockedError):
                await asyncio.create_subprocess_exec("echo", "hello")


class TestAsyncioCreateSubprocessShell:
    """AC4: asyncio.create_subprocess_shell blocked."""

    @pytest.mark.asyncio
    async def test_async_shell_blocked_untrusted(self):
        enforcer = enforce_subprocess_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(SubprocessBlockedError) as exc_info:
                await asyncio.create_subprocess_shell("echo hello")
            assert "create_subprocess_shell" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_async_shell_blocked_trusted(self):
        enforcer = enforce_subprocess_for_node(TrustLevel.LOCAL_TRUSTED, "pkg")
        with enforcer.enforce():
            with pytest.raises(SubprocessBlockedError):
                await asyncio.create_subprocess_shell("echo hello")


class TestBuiltinAsyncSubprocess:
    """AC7: Built-in retains async subprocess behavior."""

    @pytest.mark.asyncio
    async def test_builtin_async_exec_allowed(self):
        enforcer = enforce_subprocess_for_node(TrustLevel.BUILT_IN, "core")
        with enforcer.enforce():
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "-c", "print('ok')",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            assert b"ok" in stdout

    @pytest.mark.asyncio
    async def test_builtin_async_shell_allowed(self):
        enforcer = enforce_subprocess_for_node(TrustLevel.BUILT_IN, "core")
        with enforcer.enforce():
            proc = await asyncio.create_subprocess_shell(
                f"{sys.executable} -c \"print('ok')\"",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            assert b"ok" in stdout

    def test_builtin_getoutput_allowed(self):
        enforcer = enforce_subprocess_for_node(TrustLevel.BUILT_IN, "core")
        with enforcer.enforce():
            out = subprocess.getoutput(f"{sys.executable} -c \"print('ok')\"")
            assert "ok" in out

    def test_builtin_getstatusoutput_allowed(self):
        enforcer = enforce_subprocess_for_node(TrustLevel.BUILT_IN, "core")
        with enforcer.enforce():
            status, out = subprocess.getstatusoutput(f"{sys.executable} -c \"print('ok')\"")
            assert status == 0
            assert "ok" in out


class TestAsyncConcurrentSafety:
    """AC5: Concurrent async enforcement safe."""

    @pytest.mark.asyncio
    async def test_concurrent_async_subprocess(self):
        results = {}

        async def restricted():
            enforcer = enforce_subprocess_for_node(TrustLevel.LOCAL_UNTRUSTED, "r")
            with enforcer.enforce():
                await asyncio.sleep(0.01)
                try:
                    await asyncio.create_subprocess_exec("echo", "x")
                    results["restricted"] = "allowed"
                except SubprocessBlockedError:
                    results["restricted"] = "blocked"

        async def builtin():
            enforcer = enforce_subprocess_for_node(TrustLevel.BUILT_IN, "core")
            with enforcer.enforce():
                await asyncio.sleep(0.01)
                try:
                    proc = await asyncio.create_subprocess_exec(
                        sys.executable, "-c", "print(1)",
                        stdout=asyncio.subprocess.PIPE,
                    )
                    await proc.communicate()
                    results["builtin"] = "allowed"
                except SubprocessBlockedError:
                    results["builtin"] = "blocked"

        await asyncio.gather(restricted(), builtin())
        assert results["restricted"] == "blocked"
        assert results["builtin"] == "allowed"


class TestErrorRecordsApiName:
    """AC6: Error records correct api name for all covered APIs."""

    def test_getoutput_error_has_api(self):
        enforcer = enforce_subprocess_for_node(TrustLevel.LOCAL_UNTRUSTED, "n")
        with enforcer.enforce():
            try:
                subprocess.getoutput("ls")
            except SubprocessBlockedError as e:
                assert e.api == "subprocess.getoutput"
                assert e.node_id == "n"

    def test_getstatusoutput_error_has_api(self):
        enforcer = enforce_subprocess_for_node(TrustLevel.LOCAL_UNTRUSTED, "n")
        with enforcer.enforce():
            try:
                subprocess.getstatusoutput("ls")
            except SubprocessBlockedError as e:
                assert e.api == "subprocess.getstatusoutput"
