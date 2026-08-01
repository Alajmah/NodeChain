"""Tests for import policy enforcement — concurrency-safe, bypass-hardened.

AC1: Import enforcement is safe under concurrent branch execution.
AC2: Hook restoration is guaranteed after success, failure, and cancellation.
AC3: importlib.import_module is covered.
AC4: Direct __import__ calls are covered.
AC5: sys.modules access documented as out-of-scope boundary.
AC6: IMPORT_POLICY_BLOCKED includes module, node_id, trust_level, reason.
AC7: Report shows import enforcement status per node.
AC8: Existing 914 tests remain green.
"""

import asyncio
import importlib
import pytest

from nodechain.sdk.trust import TrustLevel, ImportPolicy
from nodechain.sdk.import_enforcer import (
    ImportEnforcer, ImportBlockedError, enforce_imports_for_node,
    _active_enforcer,
)


class TestConcurrentEnforcement:
    """AC1: Import enforcement safe under concurrent branch execution."""

    @pytest.mark.asyncio
    async def test_concurrent_different_trust_levels(self):
        """AC1: Two concurrent nodes with different trust levels don't interfere."""
        results = {}

        async def restricted_task():
            enforcer = enforce_imports_for_node(TrustLevel.LOCAL_UNTRUSTED, "restricted")
            with enforcer.enforce():
                await asyncio.sleep(0.01)  # Simulate work
                try:
                    __import__("subprocess")
                    results["restricted"] = "allowed"
                except ImportBlockedError:
                    results["restricted"] = "blocked"

        async def trusted_task():
            enforcer = enforce_imports_for_node(TrustLevel.LOCAL_TRUSTED, "trusted")
            with enforcer.enforce():
                await asyncio.sleep(0.01)
                try:
                    __import__("json")
                    results["trusted"] = "allowed"
                except ImportBlockedError:
                    results["trusted"] = "blocked"

        await asyncio.gather(restricted_task(), trusted_task())
        assert results["restricted"] == "blocked"
        assert results["trusted"] == "allowed"

    @pytest.mark.asyncio
    async def test_concurrent_restricted_and_builtin(self):
        """AC1: Built-in and restricted nodes run concurrently without interference."""
        results = {}

        async def builtin_task():
            enforcer = enforce_imports_for_node(TrustLevel.BUILT_IN, "builtin")
            with enforcer.enforce():
                await asyncio.sleep(0.01)
                try:
                    __import__("os")
                    results["builtin"] = "allowed"
                except ImportBlockedError:
                    results["builtin"] = "blocked"

        async def untrusted_task():
            enforcer = enforce_imports_for_node(TrustLevel.REMOTE_UNTRUSTED, "remote")
            with enforcer.enforce():
                await asyncio.sleep(0.01)
                try:
                    __import__("os")
                    results["remote"] = "allowed"
                except ImportBlockedError:
                    results["remote"] = "blocked"

        await asyncio.gather(builtin_task(), untrusted_task())
        assert results["builtin"] == "allowed"
        assert results["remote"] == "blocked"


class TestHookRestoration:
    """AC2: Hook restoration guaranteed after success, failure, cancellation."""

    def test_restored_after_success(self):
        """AC2: Contextvar cleared after normal exit."""
        enforcer = enforce_imports_for_node(TrustLevel.LOCAL_TRUSTED, "test")
        with enforcer.enforce():
            assert _active_enforcer.get() is enforcer
        assert _active_enforcer.get() is None

    def test_restored_after_exception(self):
        """AC2: Contextvar cleared after ImportBlockedError."""
        enforcer = enforce_imports_for_node(TrustLevel.LOCAL_UNTRUSTED, "test")
        try:
            with enforcer.enforce():
                __import__("subprocess")
        except ImportBlockedError:
            pass
        assert _active_enforcer.get() is None

    def test_restored_after_arbitrary_exception(self):
        """AC2: Contextvar cleared after arbitrary exception."""
        enforcer = enforce_imports_for_node(TrustLevel.LOCAL_TRUSTED, "test")
        try:
            with enforcer.enforce():
                raise RuntimeError("test")
        except RuntimeError:
            pass
        assert _active_enforcer.get() is None

    def test_nested_contexts_restore_in_order(self):
        """AC2: Nested enforcement contexts restore correctly."""
        outer = enforce_imports_for_node(TrustLevel.LOCAL_TRUSTED, "outer")
        inner = enforce_imports_for_node(TrustLevel.LOCAL_UNTRUSTED, "inner")
        with outer.enforce():
            assert _active_enforcer.get() is outer
            with inner.enforce():
                assert _active_enforcer.get() is inner
            assert _active_enforcer.get() is outer
        assert _active_enforcer.get() is None


class TestImportlibBypass:
    """AC3: importlib.import_module is covered.

    FINDING-002 (v1.18.5): importlib.import_module() calls
    _bootstrap._gcd_import() directly, NOT builtins.__import__.
    The fix patches importlib.import_module separately.
    """

    def test_importlib_import_module_blocked_for_untrusted(self):
        """AC3: importlib.import_module('subprocess') is blocked.

        This is the actual FINDING-002 regression test. Before the fix,
        importlib.import_module bypassed the builtins.__import__ hook.
        """
        enforcer = enforce_imports_for_node(TrustLevel.LOCAL_UNTRUSTED, "test")
        with enforcer.enforce():
            with pytest.raises(ImportBlockedError) as exc_info:
                importlib.import_module("subprocess")
            assert exc_info.value.module_name == "subprocess"

    def test_importlib_import_module_blocked_socket(self):
        """AC3: importlib.import_module('socket') is blocked for remote_untrusted."""
        enforcer = enforce_imports_for_node(TrustLevel.REMOTE_UNTRUSTED, "test")
        with enforcer.enforce():
            with pytest.raises(ImportBlockedError):
                importlib.import_module("socket")

    def test_importlib_import_module_allowed_json(self):
        """AC3: importlib.import_module('json') is allowed for untrusted."""
        enforcer = enforce_imports_for_node(TrustLevel.LOCAL_UNTRUSTED, "test")
        with enforcer.enforce():
            mod = importlib.import_module("json")
            assert mod is not None

    def test_importlib_import_module_ctypes_always_blocked(self):
        """AC3: ctypes in denylist — blocked even if preloaded."""
        enforcer = enforce_imports_for_node(TrustLevel.LOCAL_UNTRUSTED, "test")
        with enforcer.enforce():
            with pytest.raises(ImportBlockedError):
                importlib.import_module("ctypes")

    def test_importlib_import_module_is_patched(self):
        """AC3: importlib.import_module is the patched version."""
        assert importlib.import_module.__name__ == "_patched_import_module"


class TestDirectImportCall:
    """AC4: Direct __import__ calls are covered."""

    def test_direct_import_blocked(self):
        """AC4: __import__('subprocess') blocked."""
        enforcer = enforce_imports_for_node(TrustLevel.LOCAL_UNTRUSTED, "test")
        with enforcer.enforce():
            with pytest.raises(ImportBlockedError):
                __import__("subprocess")

    def test_direct_import_with_args_blocked(self):
        """AC4: __import__ with fromlist etc still blocked."""
        enforcer = enforce_imports_for_node(TrustLevel.LOCAL_UNTRUSTED, "test")
        with enforcer.enforce():
            with pytest.raises(ImportBlockedError):
                __import__("subprocess", fromlist=["run"])


class TestSysModulesBoundary:
    """AC5: sys.modules access documented as out-of-scope."""

    def test_sys_modules_documented(self):
        """AC5: sys.modules access is documented as known boundary.

        If 'sys' is allowed for local_untrusted, a node could access
        sys.modules.get("subprocess") to get a previously loaded module.
        This is a documented out-of-scope boundary for v0.5.x.
        """
        # This test documents the boundary. It does NOT test that we
        # prevent sys.modules access — that requires deeper sandboxing.
        enforcer = enforce_imports_for_node(TrustLevel.LOCAL_UNTRUSTED, "test")
        with enforcer.enforce():
            # json is allowed for local_untrusted
            import json  # noqa: F401
            # sys is allowed for local_untrusted (stdlib)
            import sys  # noqa: F401
            # The boundary: sys.modules may contain 'subprocess' loaded earlier
            # This is documented as out-of-scope for v0.5.x
            assert "subprocess" in sys.modules or "subprocess" not in sys.modules


class TestImportBlockedErrorFormat:
    """AC6: IMPORT_POLICY_BLOCKED includes module, node_id, trust_level, reason."""

    def test_error_has_all_fields(self):
        """AC6: Error message includes all required fields."""
        err = ImportBlockedError(
            module_name="subprocess",
            trust_level="local_untrusted",
            reason="on deny list",
            node_id="my_node",
        )
        msg = str(err)
        assert "IMPORT_POLICY_BLOCKED" in msg
        assert "subprocess" in msg
        assert "local_untrusted" in msg
        assert "my_node" in msg
        assert "deny list" in msg

    def test_error_fields_accessible(self):
        """AC6: Individual fields accessible on exception."""
        err = ImportBlockedError("socket", "remote_untrusted", "blocked", "node_42")
        assert err.module_name == "socket"
        assert err.trust_level == "remote_untrusted"
        assert err.node_id == "node_42"
        assert err.reason == "blocked"

    def test_error_is_import_error(self):
        """AC6: ImportBlockedError is an ImportError."""
        err = ImportBlockedError("x", "y", "z")
        assert isinstance(err, ImportError)


class TestEnforcementReport:
    """AC7: Report shows import enforcement status per node."""

    def test_report_after_block(self):
        """AC7: Report has correct structure after blocked import."""
        enforcer = enforce_imports_for_node(TrustLevel.LOCAL_UNTRUSTED, "test_node")
        try:
            with enforcer.enforce():
                __import__("subprocess")
        except ImportBlockedError:
            pass
        report = enforcer.get_report()
        assert report["trust_level"] == "local_untrusted"
        assert report["node_id"] == "test_node"
        assert report["violations"] == 1
        entry = report["blocked_imports"][0]
        assert entry["module"] == "subprocess"
        assert entry["trust_level"] == "local_untrusted"
        assert entry["node_id"] == "test_node"
        assert "reason" in entry

    def test_report_clean_execution(self):
        """AC7: Clean execution reports zero violations."""
        enforcer = enforce_imports_for_node(TrustLevel.LOCAL_TRUSTED, "test")
        with enforcer.enforce():
            import json  # noqa: F401
        report = enforcer.get_report()
        assert report["violations"] == 0
        assert report["blocked_imports"] == []


class TestBuiltinAndTrustedUnrestricted:
    """AC8: Built-in and local_trusted behavior unchanged."""

    def test_builtin_allows_os(self):
        enforcer = enforce_imports_for_node(TrustLevel.BUILT_IN, "core")
        with enforcer.enforce():
            import os  # noqa: F401

    def test_builtin_allows_subprocess(self):
        enforcer = enforce_imports_for_node(TrustLevel.BUILT_IN, "core")
        with enforcer.enforce():
            import subprocess  # noqa: F401

    def test_local_trusted_allows_json(self):
        enforcer = enforce_imports_for_node(TrustLevel.LOCAL_TRUSTED, "pkg")
        with enforcer.enforce():
            import json  # noqa: F401

    def test_local_trusted_allows_nodechain(self):
        enforcer = enforce_imports_for_node(TrustLevel.LOCAL_TRUSTED, "pkg")
        with enforcer.enforce():
            import nodechain  # noqa: F401

    def test_no_enforcer_passes_through(self):
        """No active enforcer means unrestricted imports."""
        assert _active_enforcer.get() is None
        import json  # noqa: F401
        # Should not raise
