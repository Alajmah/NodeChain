"""Tests for OS-level filesystem boundary enforcement.

AC1: os.open blocked/mediated for restricted trust levels.
AC2: os.remove, os.unlink, os.rename, os.replace, os.mkdir, os.makedirs, os.rmdir blocked.
AC3: shutil operations blocked/mediated for restricted trust levels.
AC4: local_trusted can still read package files.
AC5: local_trusted cannot mutate package or workspace files.
AC6: Concurrent branch execution remains safe.
AC7: FILESYSTEM_POLICY_BLOCKED records api_name, path, resolved_path, action.
AC8: Existing 938 tests remain green.
"""

import asyncio
import os
import pytest
import shutil
from pathlib import Path

from nodechain.sdk.trust import TrustLevel
from nodechain.sdk.filesystem_enforcer import (
    FilesystemEnforcer, FilesystemBlockedError, enforce_filesystem_for_node,
)


class TestOsRemoveUnlink:
    """AC2: os.remove and os.unlink blocked for restricted levels."""

    def test_os_remove_blocked_untrusted(self, tmp_path):
        """AC2: os.remove blocked for local_untrusted."""
        target = tmp_path / "x.txt"
        target.write_text("test")
        enforcer = enforce_filesystem_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError) as exc_info:
                os.remove(target)
            assert "remove" in str(exc_info.value).lower()
        # File should still exist
        assert target.exists()

    def test_os_unlink_blocked_untrusted(self, tmp_path):
        """AC2: os.unlink blocked for local_untrusted."""
        target = tmp_path / "x.txt"
        target.write_text("test")
        enforcer = enforce_filesystem_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError):
                os.unlink(target)
        assert target.exists()

    def test_os_remove_blocked_trusted_outside_package(self, tmp_path):
        """AC5: os.remove blocked outside package for local_trusted."""
        target = tmp_path / "outside.txt"
        target.write_text("test")
        enforcer = enforce_filesystem_for_node(
            TrustLevel.LOCAL_TRUSTED, "pkg", "nodes/echo_node",
        )
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError):
                os.remove(target)

    def test_os_remove_blocked_trusted_in_package(self, tmp_path):
        """AC5: os.remove blocked even in own package (read-only)."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        target = pkg / "data.txt"
        target.write_text("test")
        enforcer = enforce_filesystem_for_node(
            TrustLevel.LOCAL_TRUSTED, "pkg", str(pkg),
        )
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError) as exc_info:
                os.remove(target)
            assert "write" in str(exc_info.value).lower() or "remove" in str(exc_info.value).lower()

    def test_os_remove_allowed_builtin(self, tmp_path):
        """AC4: os.remove allowed for built_in."""
        target = tmp_path / "temp.txt"
        target.write_text("test")
        enforcer = enforce_filesystem_for_node(TrustLevel.BUILT_IN, "core")
        with enforcer.enforce():
            os.remove(target)
        assert not target.exists()


class TestOsRenameReplace:
    """AC2: os.rename and os.replace blocked for restricted levels."""

    def test_os_rename_blocked_untrusted(self, tmp_path):
        """AC2: os.rename blocked for local_untrusted."""
        src = tmp_path / "a.txt"
        src.write_text("test")
        enforcer = enforce_filesystem_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError):
                os.rename(src, tmp_path / "b.txt")

    def test_os_replace_blocked_untrusted(self, tmp_path):
        """AC2: os.replace blocked for local_untrusted."""
        src = tmp_path / "a.txt"
        src.write_text("test")
        enforcer = enforce_filesystem_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError):
                os.replace(src, tmp_path / "b.txt")

    def test_os_rename_checks_both_paths(self, tmp_path):
        """AC2: os.rename checks both source and destination."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        src = pkg / "a.txt"
        src.write_text("test")
        dst = tmp_path / "b.txt"  # Outside package
        enforcer = enforce_filesystem_for_node(
            TrustLevel.LOCAL_TRUSTED, "pkg", str(pkg),
        )
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError):
                os.rename(src, dst)


class TestOsMkdirRmdir:
    """AC2: os.mkdir, os.makedirs, os.rmdir blocked for restricted levels."""

    def test_os_mkdir_blocked_untrusted(self, tmp_path):
        """AC2: os.mkdir blocked for local_untrusted."""
        enforcer = enforce_filesystem_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError):
                os.mkdir(tmp_path / "newdir")

    def test_os_makedirs_blocked_untrusted(self, tmp_path):
        """AC2: os.makedirs blocked for local_untrusted."""
        enforcer = enforce_filesystem_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError):
                os.makedirs(tmp_path / "a" / "b")

    def test_os_rmdir_blocked_untrusted(self, tmp_path):
        """AC2: os.rmdir blocked for local_untrusted."""
        d = tmp_path / "empty"
        d.mkdir()
        enforcer = enforce_filesystem_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError):
                os.rmdir(d)
        assert d.exists()

    def test_os_mkdir_blocked_trusted_outside_package(self, tmp_path):
        """AC5: local_trusted cannot mkdir outside package."""
        enforcer = enforce_filesystem_for_node(
            TrustLevel.LOCAL_TRUSTED, "pkg", "nodes/echo_node",
        )
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError):
                os.mkdir(tmp_path / "newdir")


class TestShutilOperations:
    """AC3: shutil operations blocked/mediated for restricted levels."""

    def test_shutil_copy_blocked_untrusted(self, tmp_path):
        """AC3: shutil.copy blocked for local_untrusted."""
        src = tmp_path / "src.txt"
        src.write_text("test")
        enforcer = enforce_filesystem_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError):
                shutil.copy(src, tmp_path / "dst.txt")

    def test_shutil_move_blocked_untrusted(self, tmp_path):
        """AC3: shutil.move blocked for local_untrusted."""
        src = tmp_path / "src.txt"
        src.write_text("test")
        enforcer = enforce_filesystem_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError):
                shutil.move(src, tmp_path / "dst.txt")

    def test_shutil_rmtree_blocked_untrusted(self, tmp_path):
        """AC3: shutil.rmtree blocked for local_untrusted."""
        d = tmp_path / "tree"
        d.mkdir()
        (d / "file.txt").write_text("test")
        enforcer = enforce_filesystem_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError):
                shutil.rmtree(d)
        assert d.exists()


class TestErrorIncludesApiName:
    """AC7: Error records api/action name."""

    def test_os_remove_records_action(self, tmp_path):
        """AC7: os.remove error includes action=remove."""
        enforcer = enforce_filesystem_for_node(TrustLevel.LOCAL_UNTRUSTED, "n")
        try:
            with enforcer.enforce():
                os.remove("x.txt")
        except FilesystemBlockedError:
            pass
        report = enforcer.get_report()
        assert report["violations"] >= 1
        modes = [e["mode"] for e in report["blocked_accesses"]]
        assert "remove" in modes

    def test_os_mkdir_records_action(self, tmp_path):
        """AC7: os.mkdir error includes action=mkdir."""
        enforcer = enforce_filesystem_for_node(TrustLevel.LOCAL_UNTRUSTED, "n")
        try:
            with enforcer.enforce():
                os.mkdir("newdir")
        except FilesystemBlockedError:
            pass
        report = enforcer.get_report()
        assert report["violations"] >= 1
        modes = [e["mode"] for e in report["blocked_accesses"]]
        assert "mkdir" in modes


class TestConcurrentOsBoundary:
    """AC6: Concurrent enforcement safe with os-level operations."""

    @pytest.mark.asyncio
    async def test_concurrent_os_operations(self, tmp_path):
        """AC6: Different trust levels don't interfere on os ops."""
        results = {}

        async def restricted():
            enforcer = enforce_filesystem_for_node(TrustLevel.LOCAL_UNTRUSTED, "r")
            with enforcer.enforce():
                await asyncio.sleep(0.01)
                try:
                    os.mkdir(tmp_path / "restricted_dir")
                    results["restricted"] = "allowed"
                except FilesystemBlockedError:
                    results["restricted"] = "blocked"

        async def builtin():
            enforcer = enforce_filesystem_for_node(TrustLevel.BUILT_IN, "core")
            with enforcer.enforce():
                await asyncio.sleep(0.01)
                try:
                    os.mkdir(tmp_path / "builtin_dir")
                    results["builtin"] = "allowed"
                except (FilesystemBlockedError, OSError):
                    results["builtin"] = "blocked"

        await asyncio.gather(restricted(), builtin())
        assert results["restricted"] == "blocked"
        assert results["builtin"] == "allowed"
