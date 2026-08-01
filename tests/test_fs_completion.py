"""Tests for filesystem boundary completion: os.open, os.fdopen, read APIs.

AC1: os.open is patched for restricted trust levels.
AC2: os.fdopen is blocked for restricted trust levels.
AC3: os.stat behavior defined per trust level.
AC4: os.listdir behavior defined per trust level.
AC5: os.path.exists behavior defined per trust level.
AC6: Concurrent branch execution remains safe.
AC7: Error records api, action, path, resolved_path, node_id, trust_level.
AC8: Existing 956 tests remain green.

Documented out of scope for v0.5.x:
  Already-captured file descriptors
  os.read/os.write on existing fds
  Threads/executors not inheriting contextvars
"""

import os
import pytest
from pathlib import Path

from nodechain.sdk.trust import TrustLevel
from nodechain.sdk.filesystem_enforcer import (
    FilesystemBlockedError, enforce_filesystem_for_node,
)


class TestOsOpen:
    """AC1: os.open is patched for restricted trust levels."""

    def test_os_open_blocked_untrusted(self, tmp_path):
        """AC1: os.open blocked for local_untrusted."""
        target = tmp_path / "x.txt"
        target.write_text("test")
        enforcer = enforce_filesystem_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError):
                os.open(target, os.O_RDONLY)

    def test_os_open_write_blocked_trusted(self, tmp_path):
        """AC1: os.open with O_WRONLY blocked for local_trusted outside package."""
        target = tmp_path / "x.txt"
        target.write_text("test")
        enforcer = enforce_filesystem_for_node(
            TrustLevel.LOCAL_TRUSTED, "pkg", "nodes/echo_node",
        )
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError):
                os.open(target, os.O_WRONLY)

    def test_os_open_allowed_builtin(self, tmp_path):
        """AC1: os.open allowed for built_in."""
        target = tmp_path / "x.txt"
        target.write_text("test")
        enforcer = enforce_filesystem_for_node(TrustLevel.BUILT_IN, "core")
        with enforcer.enforce():
            fd = os.open(target, os.O_RDONLY)
            os.close(fd)


class TestOsFdopen:
    """AC2: os.fdopen blocked for restricted trust levels."""

    def test_os_fdopen_blocked_untrusted(self, tmp_path):
        """AC2: os.fdopen blocked for local_untrusted."""
        target = tmp_path / "x.txt"
        target.write_text("test")
        fd = os.open(target, os.O_RDONLY)
        try:
            enforcer = enforce_filesystem_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
            with enforcer.enforce():
                with pytest.raises(FilesystemBlockedError):
                    os.fdopen(fd, "r")
        finally:
            try:
                os.close(fd)
            except OSError:
                pass

    def test_os_fdopen_blocked_trusted(self, tmp_path):
        """AC2: os.fdopen blocked for local_trusted (fd-based access out of scope)."""
        target = tmp_path / "x.txt"
        target.write_text("test")
        fd = os.open(target, os.O_RDONLY)
        try:
            enforcer = enforce_filesystem_for_node(TrustLevel.LOCAL_TRUSTED, "pkg")
            with enforcer.enforce():
                with pytest.raises(FilesystemBlockedError):
                    os.fdopen(fd, "r")
        finally:
            try:
                os.close(fd)
            except OSError:
                pass

    def test_os_fdopen_allowed_builtin(self, tmp_path):
        """AC2: os.fdopen allowed for built_in."""
        target = tmp_path / "x.txt"
        target.write_text("test")
        fd = os.open(target, os.O_RDONLY)
        try:
            enforcer = enforce_filesystem_for_node(TrustLevel.BUILT_IN, "core")
            with enforcer.enforce():
                f = os.fdopen(fd, "r")
                f.close()
        except OSError:
            pass


class TestOsStat:
    """AC3: os.stat behavior defined per trust level."""

    def test_os_stat_blocked_untrusted(self, tmp_path):
        """AC3: os.stat blocked for local_untrusted."""
        target = tmp_path / "x.txt"
        target.write_text("test")
        enforcer = enforce_filesystem_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError):
                os.stat(target)

    def test_os_stat_blocked_trusted_outside_package(self, tmp_path):
        """AC3: os.stat blocked outside package for local_trusted."""
        target = tmp_path / "x.txt"
        target.write_text("test")
        enforcer = enforce_filesystem_for_node(
            TrustLevel.LOCAL_TRUSTED, "pkg", "nodes/echo_node",
        )
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError):
                os.stat(target)

    def test_os_stat_allowed_trusted_in_package(self):
        """AC3: os.stat allowed within own package for local_trusted."""
        enforcer = enforce_filesystem_for_node(
            TrustLevel.LOCAL_TRUSTED, "echo_node", "nodes/echo_node",
        )
        with enforcer.enforce():
            st = os.stat("nodes/echo_node/node.yaml")
            assert st.st_size > 0

    def test_os_stat_allowed_builtin(self, tmp_path):
        """AC3: os.stat allowed for built_in."""
        target = tmp_path / "x.txt"
        target.write_text("test")
        enforcer = enforce_filesystem_for_node(TrustLevel.BUILT_IN, "core")
        with enforcer.enforce():
            st = os.stat(target)
            assert st.st_size > 0


class TestOsListdir:
    """AC4: os.listdir behavior defined per trust level."""

    def test_os_listdir_blocked_untrusted(self, tmp_path):
        """AC4: os.listdir blocked for local_untrusted."""
        enforcer = enforce_filesystem_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError):
                os.listdir(tmp_path)

    def test_os_listdir_blocked_trusted_outside_package(self, tmp_path):
        """AC4: os.listdir blocked outside package for local_trusted."""
        enforcer = enforce_filesystem_for_node(
            TrustLevel.LOCAL_TRUSTED, "pkg", "nodes/echo_node",
        )
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError):
                os.listdir(tmp_path)

    def test_os_listdir_allowed_trusted_in_package(self):
        """AC4: os.listdir allowed within own package for local_trusted."""
        enforcer = enforce_filesystem_for_node(
            TrustLevel.LOCAL_TRUSTED, "echo_node", "nodes/echo_node",
        )
        with enforcer.enforce():
            entries = os.listdir("nodes/echo_node")
            assert "node.yaml" in entries

    def test_os_listdir_allowed_builtin(self):
        """AC4: os.listdir allowed for built_in."""
        enforcer = enforce_filesystem_for_node(TrustLevel.BUILT_IN, "core")
        with enforcer.enforce():
            entries = os.listdir(".")
            assert len(entries) > 0


class TestOsPathExists:
    """AC5: os.path.exists behavior defined per trust level."""

    def test_exists_blocked_untrusted(self, tmp_path):
        """AC5: os.path.exists blocked for local_untrusted."""
        target = tmp_path / "x.txt"
        target.write_text("test")
        enforcer = enforce_filesystem_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError):
                os.path.exists(target)

    def test_exists_blocked_trusted_outside_package(self, tmp_path):
        """AC5: os.path.exists blocked outside package for local_trusted."""
        enforcer = enforce_filesystem_for_node(
            TrustLevel.LOCAL_TRUSTED, "pkg", "nodes/echo_node",
        )
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError):
                os.path.exists(tmp_path / "anything")

    def test_exists_allowed_trusted_in_package(self):
        """AC5: os.path.exists allowed within own package."""
        enforcer = enforce_filesystem_for_node(
            TrustLevel.LOCAL_TRUSTED, "echo_node", "nodes/echo_node",
        )
        with enforcer.enforce():
            assert os.path.exists("nodes/echo_node/node.yaml")

    def test_exists_allowed_builtin(self, tmp_path):
        """AC5: os.path.exists allowed for built_in."""
        target = tmp_path / "x.txt"
        target.write_text("test")
        enforcer = enforce_filesystem_for_node(TrustLevel.BUILT_IN, "core")
        with enforcer.enforce():
            assert os.path.exists(target)
