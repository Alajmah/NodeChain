"""Filesystem policy enforcement at runtime — hardened.

Intercepts Python file operations during node execution to enforce trust-level
filesystem restrictions. Uses contextvars for per-coroutine isolation.

Covers:
  - builtins.open() hooking
  - pathlib.Path.open() hooking (monkeypatched)
  - Mode checking (read vs write)
  - Path boundary checking against package directory
  - Path traversal protection (../, absolute paths, symlinks)
  - Concurrent enforcement safe via contextvars

Does NOT cover (documented boundary for v0.5.x):
  - os.open, os.fdopen (different call path)
  - shutil (calls open internally, partially covered)
  - Already-captured file handles from before enforcement
  - Threads/executors (contextvars not inherited automatically)
  - mmap, tempfile (different OS-level paths)
"""

from __future__ import annotations

import builtins
import contextlib
from contextvars import ContextVar
from pathlib import Path, PurePosixPath
from typing import Any, Generator

from nodechain.sdk.trust import (
    TrustLevel, FilesystemPolicy, get_execution_policy,
)


# Per-coroutine enforcement state
_active_fs_enforcer: ContextVar["FilesystemEnforcer | None"] = ContextVar(
    "nodechain_fs_enforcer", default=None
)


class FilesystemBlockedError(OSError):
    """Raised when filesystem access is blocked by trust policy."""

    def __init__(
        self,
        path: str,
        resolved_path: str,
        mode: str,
        trust_level: str,
        reason: str,
        node_id: str = "",
    ):
        self.path = path
        self.resolved_path = resolved_path
        self.mode = mode
        self.trust_level = trust_level
        self.reason = reason
        self.node_id = node_id
        super().__init__(
            f"FILESYSTEM_POLICY_BLOCKED: '{path}' (resolved='{resolved_path}', "
            f"mode={mode}) blocked by {trust_level} trust policy "
            f"(node={node_id}): {reason}"
        )


def _resolve_path(path: str | Path) -> Path:
    """Resolve a path, handling symlinks and traversal."""
    try:
        return Path(path).resolve()
    except Exception:
        return Path(path)


def _is_write_mode(mode: str) -> bool:
    """Check if a mode string indicates write intent."""
    # Standard file modes
    if any(c in mode for c in ("w", "a", "x", "+")):
        return True
    # OS-level mutation actions
    write_actions = {"remove", "unlink", "rename_src", "rename_dst",
                     "replace_src", "replace_dst", "mkdir", "makedirs", "rmdir"}
    return mode in write_actions


class FilesystemEnforcer:
    """
    Enforces filesystem policy during node execution.

    Uses contextvars for per-coroutine isolation.
    Handles path traversal, symlink escape, and mode enforcement.
    """

    def __init__(
        self,
        trust_level: TrustLevel,
        package_node_id: str = "",
        package_path: str | Path | None = None,
    ):
        self.trust_level = trust_level
        self.package_node_id = package_node_id
        self.package_path = Path(package_path).resolve() if package_path else None
        self.policy = get_execution_policy(trust_level)
        self.blocked_accesses: list[dict[str, str]] = []
        self._token = None

    def _check_access(self, path: str | Path, mode: str) -> None:
        """Check if filesystem access is allowed. Raises if blocked."""
        if self.trust_level == TrustLevel.BUILT_IN:
            return  # Built-in nodes unrestricted

        is_write = _is_write_mode(mode)
        resolved = _resolve_path(path)
        fs_policy = self.policy.filesystem

        # --- NONE: block everything ---
        if fs_policy == FilesystemPolicy.NONE:
            self._block(path, resolved, mode,
                        "filesystem access blocked (policy=none)")
            return  # unreachable but explicit

        # --- PACKAGE_READ_ONLY ---
        if fs_policy == FilesystemPolicy.PACKAGE_READ_ONLY:
            if self.package_path is None:
                self._block(path, resolved, mode,
                            "no package path for package_read_only policy")
                return

            # Resolve symlinks in the requested path
            # This prevents symlink escape from package root
            try:
                resolved.relative_to(self.package_path)
            except ValueError:
                self._block(path, resolved, mode,
                            "path outside package directory")
                return

            # Block writes even within package
            if is_write:
                self._block(path, resolved, mode,
                            "write blocked (policy=package_read_only)")
                return

        # --- WORKSPACE_READ ---
        if fs_policy == FilesystemPolicy.WORKSPACE_READ:
            if is_write:
                self._block(path, resolved, mode,
                            "write blocked (policy=workspace_read)")
                return

        # --- WORKSPACE_WRITE: allow everything ---
        pass

    def _block(self, path, resolved, mode, reason):
        """Record and raise a blocked access."""
        record = {
            "path": str(path),
            "resolved_path": str(resolved),
            "mode": mode,
            "trust_level": self.trust_level.value,
            "node_id": self.package_node_id,
            "reason": reason,
        }
        self.blocked_accesses.append(record)
        raise FilesystemBlockedError(
            path=str(path),
            resolved_path=str(resolved),
            mode=mode,
            trust_level=self.trust_level.value,
            reason=reason,
            node_id=self.package_node_id,
        )

    @contextlib.contextmanager
    def enforce(self) -> Generator[None, None, None]:
        """Context manager that enforces filesystem policy."""
        if self.trust_level == TrustLevel.BUILT_IN:
            yield
            return

        self._token = _active_fs_enforcer.set(self)
        try:
            yield
        finally:
            _active_fs_enforcer.reset(self._token)
            self._token = None

    @property
    def had_violations(self) -> bool:
        return len(self.blocked_accesses) > 0

    def get_report(self) -> dict[str, Any]:
        return {
            "trust_level": self.trust_level.value,
            "node_id": self.package_node_id,
            "filesystem_policy": self.policy.filesystem.value,
            "violations": len(self.blocked_accesses),
            "blocked_accesses": self.blocked_accesses,
        }


# ── Global hooks ──────────────────────────────────────────────

def _global_open_hook(*args: Any, **kwargs: Any) -> Any:
    """Global open() replacement. Installed once, reads from contextvars."""
    enforcer = _active_fs_enforcer.get()
    if enforcer is not None:
        path = args[0] if args else kwargs.get("file", "")
        mode = args[1] if len(args) > 1 else kwargs.get("mode", "r")
        mode = str(mode) if mode else "r"
        enforcer._check_access(path, mode)
    return _original_open(*args, **kwargs)


def _install_global_open_hook() -> Any:
    """Install the global open hook. Called once at module load."""
    global _original_open
    _original_open = builtins.open
    builtins.open = _global_open_hook  # type: ignore
    return _original_open


# Install once at module load
_original_open = _install_global_open_hook()


# ── pathlib.Path.open patch ───────────────────────────────────

_original_pathlib_open = Path.open


def _patched_pathlib_open(self, mode="r", *args: Any, **kwargs: Any) -> Any:
    """Patched Path.open that goes through enforcement."""
    enforcer = _active_fs_enforcer.get()
    if enforcer is not None:
        enforcer._check_access(str(self), str(mode))
    return _original_pathlib_open(self, mode, *args, **kwargs)


def _install_pathlib_patch() -> None:
    """Patch pathlib.Path.open to go through enforcement."""
    Path.open = _patched_pathlib_open  # type: ignore


_install_pathlib_patch()


# ── os-level filesystem API patches ───────────────────────────
import os as _os

_original_os_remove = _os.remove
_original_os_unlink = _os.unlink
_original_os_rename = _os.rename
_original_os_replace = _os.replace
_original_os_mkdir = _os.mkdir
_original_os_makedirs = _os.makedirs
_original_os_rmdir = _os.rmdir


def _check_os_path(path: str | bytes | Path, action: str) -> None:
    """Check filesystem policy for os-level operations."""
    enforcer = _active_fs_enforcer.get()
    if enforcer is not None:
        enforcer._check_access(str(path), action)


def _patched_os_remove(path, *args, **kwargs):
    _check_os_path(path, "remove")
    return _original_os_remove(path, *args, **kwargs)


def _patched_os_unlink(path, *args, **kwargs):
    _check_os_path(path, "unlink")
    return _original_os_unlink(path, *args, **kwargs)


def _patched_os_rename(src, dst, *args, **kwargs):
    _check_os_path(src, "rename_src")
    _check_os_path(dst, "rename_dst")
    return _original_os_rename(src, dst, *args, **kwargs)


def _patched_os_replace(src, dst, *args, **kwargs):
    _check_os_path(src, "replace_src")
    _check_os_path(dst, "replace_dst")
    return _original_os_replace(src, dst, *args, **kwargs)


def _patched_os_mkdir(path, *args, **kwargs):
    _check_os_path(path, "mkdir")
    return _original_os_mkdir(path, *args, **kwargs)


def _patched_os_makedirs(path, *args, **kwargs):
    _check_os_path(path, "makedirs")
    return _original_os_makedirs(path, *args, **kwargs)


def _patched_os_rmdir(path, *args, **kwargs):
    _check_os_path(path, "rmdir")
    return _original_os_rmdir(path, *args, **kwargs)


_os.remove = _patched_os_remove  # type: ignore
_os.unlink = _patched_os_unlink  # type: ignore
_os.rename = _patched_os_rename  # type: ignore
_os.replace = _patched_os_replace  # type: ignore
_os.mkdir = _patched_os_mkdir  # type: ignore
_os.makedirs = _patched_os_makedirs  # type: ignore
_os.rmdir = _patched_os_rmdir  # type: ignore


# ── os.open / os.fdopen patches ──────────────────────────────
_original_os_open = getattr(_os, "open", None)
_original_os_fdopen = getattr(_os, "fdopen", None)


def _patched_os_lowlevel_open(path, flags, *args, **kwargs):
    """Patch os.open — low-level file descriptor open."""
    # Determine mode from flags
    mode = "r"
    if flags & (_os.O_WRONLY | _os.O_RDWR | _os.O_CREAT | _os.O_APPEND | _os.O_TRUNC):
        mode = "w"
    _check_os_path(path, f"os_open({mode})")
    return _original_os_open(path, flags, *args, **kwargs)


def _patched_os_fdopen(fd, mode="r", *args, **kwargs):
    """Patch os.fdopen — wrap existing fd with file object.

    Note: os.fdopen operates on existing file descriptors, so
    we cannot check the path. We allow it but document the boundary.
    For restricted trust levels, fd-based access is a documented
    out-of-scope bypass for v0.5.x.
    """
    enforcer = _active_fs_enforcer.get()
    if enforcer is not None and enforcer.trust_level != TrustLevel.BUILT_IN:
        # Block fdopen for untrusted — they should not have fds
        enforcer._block(
            f"fd://{fd}", f"fd://{fd}", mode,
            "os.fdopen blocked for restricted trust (fd-based access out of scope)",
        )
    return _original_os_fdopen(fd, mode, *args, **kwargs)


if _original_os_open is not None:
    _os.open = _patched_os_lowlevel_open  # type: ignore
if _original_os_fdopen is not None:
    _os.fdopen = _patched_os_fdopen  # type: ignore


# ── Read-API patches (stat, listdir, exists) ──────────────────
# For NONE policy: block even metadata reads
# For PACKAGE_READ_ONLY: allow reads within package
# For WORKSPACE_READ/WRITE: allow all reads

import os.path as _os_path

_original_os_stat = _os.stat
_original_os_listdir = _os.listdir
_original_os_path_exists = _os_path.exists


def _check_read_access(path, action: str) -> None:
    """Check read-only filesystem access (stat, listdir, exists)."""
    enforcer = _active_fs_enforcer.get()
    if enforcer is None:
        return
    if enforcer.trust_level == TrustLevel.BUILT_IN:
        return
    fs_policy = enforcer.policy.filesystem
    if fs_policy == FilesystemPolicy.NONE:
        enforcer._block(str(path), str(_resolve_path(path)), action,
                        f"read access blocked (policy=none)")
    elif fs_policy == FilesystemPolicy.PACKAGE_READ_ONLY:
        if enforcer.package_path is not None:
            resolved = _resolve_path(path)
            try:
                resolved.relative_to(enforcer.package_path)
            except ValueError:
                enforcer._block(str(path), str(resolved), action,
                                "read outside package directory")


def _patched_os_stat(path, *args, **kwargs):
    _check_read_access(path, "stat")
    return _original_os_stat(path, *args, **kwargs)


def _patched_os_listdir(path=".", *args, **kwargs):
    _check_read_access(path, "listdir")
    return _original_os_listdir(path, *args, **kwargs)


def _patched_os_path_exists(path):
    _check_read_access(path, "exists")
    return _original_os_path_exists(path)


_os.stat = _patched_os_stat  # type: ignore
_os.listdir = _patched_os_listdir  # type: ignore
_os_path.exists = _patched_os_path_exists  # type: ignore


def enforce_filesystem_for_node(
    trust_level: TrustLevel,
    node_id: str,
    package_path: str | Path | None = None,
) -> FilesystemEnforcer:
    """Create a filesystem enforcer for a node execution."""
    return FilesystemEnforcer(trust_level, node_id, package_path)
