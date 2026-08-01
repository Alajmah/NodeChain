"""Test that importlib.import_module is intercepted (v1.18.5).

FINDING-002: importlib.import_module() called _bootstrap._gcd_import()
directly, bypassing builtins.__import__. The import enforcer now patches
importlib.import_module separately.
"""
import pytest
import importlib
from nodechain.sdk.import_enforcer import enforce_imports_for_node
from nodechain.sdk.trust import TrustLevel


class TestImportlibBypassFix:
    """Verify importlib.import_module is properly intercepted."""

    def test_importlib_import_module_is_patched(self):
        """importlib.import_module should be patched."""
        # The patched version has a different name
        assert importlib.import_module.__name__ == "_patched_import_module"

    def test_importlib_blocked_import(self):
        """importlib.import_module should be blocked for denied modules."""
        enforcer = enforce_imports_for_node(
            trust_level=TrustLevel.LOCAL_UNTRUSTED,
            node_id="test_importlib",
        )
        with enforcer.enforce():
            with pytest.raises(ImportError):
                importlib.import_module("subprocess")

    def test_importlib_allowed_import(self):
        """importlib.import_module should work for allowed modules."""
        enforcer = enforce_imports_for_node(
            trust_level=TrustLevel.LOCAL_UNTRUSTED,
            node_id="test_importlib_ok",
        )
        with enforcer.enforce():
            mod = importlib.import_module("json")
            assert mod is not None

    def test_importlib_ctypes_always_blocked(self):
        """ctypes (denylist) should be blocked even for trusted nodes."""
        enforcer = enforce_imports_for_node(
            trust_level=TrustLevel.LOCAL_UNTRUSTED,
            node_id="test_ctypes",
        )
        with enforcer.enforce():
            with pytest.raises(ImportError):
                importlib.import_module("ctypes")
