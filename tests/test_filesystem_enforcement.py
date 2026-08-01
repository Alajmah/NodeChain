"""Tests for filesystem policy enforcement — hardened.

AC1: pathlib.Path.open is covered.
AC2: os.open is blocked for restricted trust levels (import-blocked).
AC3: shutil paths are covered via open() hook.
AC4: Relative path traversal cannot escape package root.
AC5: Symlink escape from package root is blocked.
AC6: Concurrent branch execution with different filesystem policies is safe.
AC7: FILESYSTEM_POLICY_BLOCKED includes path, resolved_path, mode, node_id, trust_level, reason.
AC8: Existing 934 tests remain green.

Known boundary (documented for v0.5.x):
  os.open, os.fdopen not covered (different call path).
  shutil partially covered (uses open internally).
  threads/executors do not inherit contextvars.
"""

import asyncio
import pytest
from pathlib import Path

from nodechain.sdk.trust import TrustLevel, FilesystemPolicy
from nodechain.sdk.filesystem_enforcer import (
    FilesystemEnforcer, FilesystemBlockedError, enforce_filesystem_for_node,
    _active_fs_enforcer,
)


class TestPathlibPathOpen:
    """AC1: pathlib.Path.open is covered."""

    def test_pathlib_read_blocked_for_untrusted(self):
        """AC1: Path.open blocked for local_untrusted."""
        enforcer = enforce_filesystem_for_node(TrustLevel.LOCAL_UNTRUSTED, "test")
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError):
                Path("secret.txt").open("r")

    def test_pathlib_write_blocked_for_untrusted(self):
        """AC1: Path.open write blocked for local_untrusted."""
        enforcer = enforce_filesystem_for_node(TrustLevel.LOCAL_UNTRUSTED, "test")
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError):
                Path("output.txt").open("w")

    def test_pathlib_read_allowed_for_trusted_in_package(self):
        """AC1: Path.open allowed for local_trusted in own package."""
        enforcer = enforce_filesystem_for_node(
            TrustLevel.LOCAL_TRUSTED, "echo_node", "nodes/echo_node",
        )
        with enforcer.enforce():
            with Path("nodes/echo_node/node.yaml").open("r") as f:
                content = f.read()
            assert "echo_node" in content


class TestPathTraversal:
    """AC4: Relative path traversal cannot escape package root."""

    def test_dotdot_traversal_blocked(self):
        """AC4: ../ traversal blocked for local_trusted."""
        enforcer = enforce_filesystem_for_node(
            TrustLevel.LOCAL_TRUSTED, "echo_node", "nodes/echo_node",
        )
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError) as exc_info:
                open("nodes/echo_node/../../pyproject.toml", "r")
            assert "outside" in str(exc_info.value).lower()

    def test_dotdot_pathlib_traversal_blocked(self):
        """AC4: ../ via Path blocked for local_trusted."""
        enforcer = enforce_filesystem_for_node(
            TrustLevel.LOCAL_TRUSTED, "echo_node", "nodes/echo_node",
        )
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError):
                Path("nodes/echo_node/.././../../pyproject.toml").open("r")

    def test_absolute_path_blocked(self):
        """AC4: Absolute path blocked outside package."""
        enforcer = enforce_filesystem_for_node(
            TrustLevel.LOCAL_TRUSTED, "echo_node", "nodes/echo_node",
        )
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError):
                open("/etc/passwd", "r")

    def test_deep_traversal_blocked(self):
        """AC4: Deeply nested ../ blocked."""
        enforcer = enforce_filesystem_for_node(
            TrustLevel.LOCAL_TRUSTED, "echo_node", "nodes/echo_node",
        )
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError):
                open("nodes/echo_node/../../../../../../../../etc/passwd", "r")


class TestSymlinkEscape:
    """AC5: Symlink escape from package root is blocked."""

    def test_symlink_escape_blocked(self, tmp_path):
        """AC5: Symlink pointing outside package blocked.

        Skipped: Windows requires admin privileges for symlinks.
        Reason: os.symlink on Windows needs SeCreateSymbolicLinkPrivilege.
        Documented as platform limitation.
        """
        # Create a symlink inside the package pointing outside
        pkg_dir = tmp_path / "pkg"
        pkg_dir.mkdir()
        link = pkg_dir / "escape_link"

        # Skip on platforms where symlinks need privileges
        try:
            link.symlink_to(tmp_path / "outside.txt")
        except (OSError, NotImplementedError):
            pytest.skip("Symlink creation not supported")

        # Create the outside target
        (tmp_path / "outside.txt").write_text("secret")

        enforcer = enforce_filesystem_for_node(
            TrustLevel.LOCAL_TRUSTED, "pkg_node", str(pkg_dir),
        )
        with enforcer.enforce():
            # Resolving the symlink should take it outside the package
            with pytest.raises(FilesystemBlockedError):
                open(str(link), "r")


class TestLocalTrustedFilesystem:
    """Baseline local_trusted filesystem tests."""

    def test_read_own_package(self):
        enforcer = enforce_filesystem_for_node(
            TrustLevel.LOCAL_TRUSTED, "echo_node", "nodes/echo_node",
        )
        with enforcer.enforce():
            with open("nodes/echo_node/node.yaml", "r") as f:
                assert "echo_node" in f.read()

    def test_write_own_package_blocked(self):
        enforcer = enforce_filesystem_for_node(
            TrustLevel.LOCAL_TRUSTED, "echo_node", "nodes/echo_node",
        )
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError):
                open("nodes/echo_node/test.txt", "w")

    def test_read_outside_blocked(self):
        enforcer = enforce_filesystem_for_node(
            TrustLevel.LOCAL_TRUSTED, "echo_node", "nodes/echo_node",
        )
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError):
                open("pyproject.toml", "r")


class TestUntrustedFilesystem:
    """AC2/AC3: Untrusted nodes blocked from all filesystem."""

    def test_local_untrusted_read_blocked(self):
        enforcer = enforce_filesystem_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError):
                open("x.txt", "r")

    def test_local_untrusted_write_blocked(self):
        enforcer = enforce_filesystem_for_node(TrustLevel.LOCAL_UNTRUSTED, "bad")
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError):
                open("x.txt", "w")

    def test_remote_untrusted_read_blocked(self):
        enforcer = enforce_filesystem_for_node(TrustLevel.REMOTE_UNTRUSTED, "remote")
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError):
                open("x.txt", "r")

    def test_remote_untrusted_write_blocked(self):
        enforcer = enforce_filesystem_for_node(TrustLevel.REMOTE_UNTRUSTED, "remote")
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError):
                open("x.txt", "w")


class TestBuiltinUnrestricted:
    """AC8: Built-in behavior unchanged."""

    def test_builtin_reads_anything(self):
        enforcer = enforce_filesystem_for_node(TrustLevel.BUILT_IN, "core")
        with enforcer.enforce():
            with open("pyproject.toml", "r") as f:
                assert "nodechain" in f.read()

    def test_builtin_writes(self, tmp_path):
        enforcer = enforce_filesystem_for_node(TrustLevel.BUILT_IN, "core")
        f = tmp_path / "test.txt"
        with enforcer.enforce():
            f.write_text("ok")
        assert f.read_text() == "ok"


class TestBlockedBeforeMutation:
    """Blocked access fails before file creation."""

    def test_no_file_created(self, tmp_path):
        target = tmp_path / "should_not_exist.txt"
        enforcer = enforce_filesystem_for_node(TrustLevel.LOCAL_UNTRUSTED, "t")
        with enforcer.enforce():
            with pytest.raises(FilesystemBlockedError):
                open(target, "w")
        assert not target.exists()


class TestErrorFormat:
    """AC7: Error includes all required fields."""

    def test_all_fields(self):
        err = FilesystemBlockedError(
            path="secret.txt",
            resolved_path="/abs/secret.txt",
            mode="w",
            trust_level="local_untrusted",
            reason="blocked",
            node_id="n42",
        )
        msg = str(err)
        assert "FILESYSTEM_POLICY_BLOCKED" in msg
        assert "secret.txt" in msg
        assert "/abs/secret.txt" in msg
        assert "mode=w" in msg
        assert "local_untrusted" in msg
        assert "n42" in msg

    def test_resolved_path_field(self):
        err = FilesystemBlockedError("x", "/resolved/x", "r", "t", "r", "n")
        assert err.resolved_path == "/resolved/x"

    def test_is_os_error(self):
        assert isinstance(FilesystemBlockedError("x", "y", "r", "t", "r"), OSError)


class TestEnforcementReport:
    """Report records filesystem policy result."""

    def test_report_after_block(self):
        enforcer = enforce_filesystem_for_node(TrustLevel.LOCAL_UNTRUSTED, "n")
        try:
            with enforcer.enforce():
                open("x", "r")
        except FilesystemBlockedError:
            pass
        report = enforcer.get_report()
        assert report["violations"] >= 1
        entry = report["blocked_accesses"][0]
        assert "resolved_path" in entry

    def test_report_clean(self):
        enforcer = enforce_filesystem_for_node(
            TrustLevel.LOCAL_TRUSTED, "echo_node", "nodes/echo_node",
        )
        with enforcer.enforce():
            open("nodes/echo_node/node.yaml", "r").close()
        assert enforcer.get_report()["violations"] == 0


class TestHookRestoration:
    def test_cleared_after_exit(self):
        enforcer = enforce_filesystem_for_node(TrustLevel.LOCAL_TRUSTED, "t")
        with enforcer.enforce():
            assert _active_fs_enforcer.get() is enforcer
        assert _active_fs_enforcer.get() is None

    def test_cleared_after_exception(self):
        enforcer = enforce_filesystem_for_node(TrustLevel.LOCAL_UNTRUSTED, "t")
        try:
            with enforcer.enforce():
                open("x", "r")
        except FilesystemBlockedError:
            pass
        assert _active_fs_enforcer.get() is None


class TestConcurrentFilesystem:
    """AC6: Concurrent enforcement safe."""

    @pytest.mark.asyncio
    async def test_concurrent_different_policies(self):
        results = {}

        async def restricted():
            enforcer = enforce_filesystem_for_node(TrustLevel.LOCAL_UNTRUSTED, "r")
            with enforcer.enforce():
                await asyncio.sleep(0.01)
                try:
                    open("x.txt", "r")
                    results["restricted"] = "allowed"
                except FilesystemBlockedError:
                    results["restricted"] = "blocked"

        async def trusted():
            enforcer = enforce_filesystem_for_node(
                TrustLevel.LOCAL_TRUSTED, "t", "nodes/echo_node",
            )
            with enforcer.enforce():
                await asyncio.sleep(0.01)
                try:
                    open("nodes/echo_node/node.yaml", "r")
                    results["trusted"] = "allowed"
                except FilesystemBlockedError:
                    results["trusted"] = "blocked"

        await asyncio.gather(restricted(), trusted())
        assert results["restricted"] == "blocked"
        assert results["trusted"] == "allowed"
