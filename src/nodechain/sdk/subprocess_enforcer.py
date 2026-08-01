"""Subprocess policy enforcement at runtime.

Intercepts subprocess execution APIs during node execution to enforce
trust-level subprocess restrictions. Uses contextvars for per-coroutine
isolation, consistent with import and filesystem enforcement.

Covers:
  - subprocess.Popen, .run, .call, .check_call, .check_output
  - os.system, os.popen

Does NOT cover (documented boundary for v0.5.x):
  - os.exec* family (replaces process)
  - os.fork (Unix only)
  - os.spawn* family
  - ctypes/win32api direct calls
  - Already-captured Popen objects
"""

from __future__ import annotations

import contextlib
import os as _os
import subprocess as _subprocess
from contextvars import ContextVar
from typing import Any, Generator

from nodechain.sdk.trust import TrustLevel, get_execution_policy


# Per-coroutine enforcement state
_active_subprocess_enforcer: ContextVar["SubprocessEnforcer | None"] = ContextVar(
    "nodechain_subprocess_enforcer", default=None
)


class SubprocessBlockedError(RuntimeError):
    """Raised when subprocess execution is blocked by trust policy."""

    def __init__(
        self,
        command: str,
        api: str,
        trust_level: str,
        reason: str,
        node_id: str = "",
    ):
        self.command = command
        self.api = api
        self.trust_level = trust_level
        self.reason = reason
        self.node_id = node_id
        super().__init__(
            f"SUBPROCESS_POLICY_BLOCKED: '{command}' via {api} blocked by "
            f"{trust_level} trust policy (node={node_id}): {reason}"
        )


class SubprocessEnforcer:
    """
    Enforces subprocess policy during node execution.

    Uses contextvars for per-coroutine isolation.
    """

    def __init__(self, trust_level: TrustLevel, package_node_id: str = ""):
        self.trust_level = trust_level
        self.package_node_id = package_node_id
        self.policy = get_execution_policy(trust_level)
        self.blocked_commands: list[dict[str, str]] = []
        self._token = None

    def _check_subprocess(self, args: Any, api: str) -> None:
        """Check if subprocess execution is allowed. Raises if blocked."""
        if self.trust_level == TrustLevel.BUILT_IN:
            if self.policy.allow_subprocess:
                return

        if not self.policy.allow_subprocess:
            # Extract command string for reporting
            if isinstance(args, (list, tuple)):
                cmd_str = " ".join(str(a) for a in args)
            else:
                cmd_str = str(args)

            record = {
                "command": cmd_str,
                "api": api,
                "trust_level": self.trust_level.value,
                "node_id": self.package_node_id,
                "reason": f"subprocess blocked (allow_subprocess={self.policy.allow_subprocess})",
            }
            self.blocked_commands.append(record)
            raise SubprocessBlockedError(
                command=cmd_str,
                api=api,
                trust_level=self.trust_level.value,
                reason=f"subprocess blocked (trust={self.trust_level.value})",
                node_id=self.package_node_id,
            )

    @contextlib.contextmanager
    def enforce(self) -> Generator[None, None, None]:
        """Context manager that enforces subprocess policy."""
        if self.trust_level == TrustLevel.BUILT_IN and self.policy.allow_subprocess:
            yield
            return

        self._token = _active_subprocess_enforcer.set(self)
        try:
            yield
        finally:
            _active_subprocess_enforcer.reset(self._token)
            self._token = None

    @property
    def had_violations(self) -> bool:
        return len(self.blocked_commands) > 0

    def get_report(self) -> dict[str, Any]:
        return {
            "trust_level": self.trust_level.value,
            "node_id": self.package_node_id,
            "allow_subprocess": self.policy.allow_subprocess,
            "violations": len(self.blocked_commands),
            "blocked_commands": self.blocked_commands,
        }


# ── Global hooks for subprocess module ────────────────────────

_original_popen_init = _subprocess.Popen.__init__
_original_run = _subprocess.run
_original_call = _subprocess.call
_original_check_call = _subprocess.check_call
_original_check_output = _subprocess.check_output


def _extract_args(args, kwargs):
    """Extract the command from subprocess args."""
    if args:
        return args[0]
    return kwargs.get("args", kwargs.get("cmd", ""))


class _PatchedPopen(_subprocess.Popen):
    """Patched Popen that checks subprocess policy."""

    def __init__(self, args, **kwargs):
        enforcer = _active_subprocess_enforcer.get()
        if enforcer is not None:
            enforcer._check_subprocess(args, "subprocess.Popen")
        super().__init__(args, **kwargs)


def _patched_run(*args, **kwargs):
    enforcer = _active_subprocess_enforcer.get()
    if enforcer is not None:
        cmd = _extract_args(args, kwargs)
        enforcer._check_subprocess(cmd, "subprocess.run")
    return _original_run(*args, **kwargs)


def _patched_call(*args, **kwargs):
    enforcer = _active_subprocess_enforcer.get()
    if enforcer is not None:
        cmd = _extract_args(args, kwargs)
        enforcer._check_subprocess(cmd, "subprocess.call")
    return _original_call(*args, **kwargs)


def _patched_check_call(*args, **kwargs):
    enforcer = _active_subprocess_enforcer.get()
    if enforcer is not None:
        cmd = _extract_args(args, kwargs)
        enforcer._check_subprocess(cmd, "subprocess.check_call")
    return _original_check_call(*args, **kwargs)


def _patched_check_output(*args, **kwargs):
    enforcer = _active_subprocess_enforcer.get()
    if enforcer is not None:
        cmd = _extract_args(args, kwargs)
        enforcer._check_subprocess(cmd, "subprocess.check_output")
    return _original_check_output(*args, **kwargs)


# Install patches
_subprocess.Popen = _PatchedPopen  # type: ignore
_subprocess.run = _patched_run  # type: ignore
_subprocess.call = _patched_call  # type: ignore
_subprocess.check_call = _patched_check_call  # type: ignore
_subprocess.check_output = _patched_check_output  # type: ignore


# ── os.system / os.popen patches ──────────────────────────────

_original_os_system = _os.system
_original_os_popen = _os.popen


def _patched_os_system(command):
    enforcer = _active_subprocess_enforcer.get()
    if enforcer is not None:
        enforcer._check_subprocess(command, "os.system")
    return _original_os_system(command)


def _patched_os_popen(command, mode="r", buffering=-1):
    enforcer = _active_subprocess_enforcer.get()
    if enforcer is not None:
        enforcer._check_subprocess(command, "os.popen")
    return _original_os_popen(command, mode, buffering)


_os.system = _patched_os_system  # type: ignore
_os.popen = _patched_os_popen  # type: ignore


# ── subprocess convenience wrappers ──────────────────────────

_original_getoutput = getattr(_subprocess, "getoutput", None)
_original_getstatusoutput = getattr(_subprocess, "getstatusoutput", None)


def _patched_getoutput(cmd, **kwargs):
    enforcer = _active_subprocess_enforcer.get()
    if enforcer is not None:
        enforcer._check_subprocess(cmd, "subprocess.getoutput")
    return _original_getoutput(cmd, **kwargs)


def _patched_getstatusoutput(cmd, **kwargs):
    enforcer = _active_subprocess_enforcer.get()
    if enforcer is not None:
        enforcer._check_subprocess(cmd, "subprocess.getstatusoutput")
    return _original_getstatusoutput(cmd, **kwargs)


if _original_getoutput is not None:
    _subprocess.getoutput = _patched_getoutput  # type: ignore
if _original_getstatusoutput is not None:
    _subprocess.getstatusoutput = _patched_getstatusoutput  # type: ignore


# ── asyncio subprocess APIs ─────────────────────────────────

import asyncio as _asyncio

_original_create_subprocess_exec = getattr(_asyncio, "create_subprocess_exec", None)
_original_create_subprocess_shell = getattr(_asyncio, "create_subprocess_shell", None)


async def _patched_create_subprocess_exec(program, *args, **kwargs):
    enforcer = _active_subprocess_enforcer.get()
    if enforcer is not None:
        cmd_parts = [str(program)] + [str(a) for a in args]
        enforcer._check_subprocess(cmd_parts, "asyncio.create_subprocess_exec")
    return await _original_create_subprocess_exec(program, *args, **kwargs)


async def _patched_create_subprocess_shell(cmd, **kwargs):
    enforcer = _active_subprocess_enforcer.get()
    if enforcer is not None:
        enforcer._check_subprocess(cmd, "asyncio.create_subprocess_shell")
    return await _original_create_subprocess_shell(cmd, **kwargs)


if _original_create_subprocess_exec is not None:
    _asyncio.create_subprocess_exec = _patched_create_subprocess_exec  # type: ignore
if _original_create_subprocess_shell is not None:
    _asyncio.create_subprocess_shell = _patched_create_subprocess_shell  # type: ignore


def enforce_subprocess_for_node(
    trust_level: TrustLevel,
    node_id: str,
) -> SubprocessEnforcer:
    """Create a subprocess enforcer for a node execution."""
    return SubprocessEnforcer(trust_level, node_id)
