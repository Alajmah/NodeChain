"""Import policy enforcement at runtime — concurrency-safe.

Intercepts Python imports during node execution to enforce trust-level
import restrictions. Uses contextvars for per-coroutine isolation,
making it safe under concurrent branch execution.

Covers:
  - builtins.__import__ hooking
  - importlib.import_module interception
  - sys.modules access to denied modules (documented boundary)

Does NOT cover (out of scope for v0.5.x):
  - Module attributes already captured before enforcement
  - Dynamic loaders from importlib.machinery
  - C extensions that bypass Python import machinery
"""

from __future__ import annotations

import builtins
import contextlib
import sys as _sys
from contextvars import ContextVar
from typing import Any, Generator

from nodechain.sdk.trust import TrustLevel, ImportPolicy, get_execution_policy


# Per-coroutine enforcement state — safe under concurrent execution
_active_enforcer: ContextVar["ImportEnforcer | None"] = ContextVar(
    "nodechain_import_enforcer", default=None
)

# Framework dependencies that NodeChain SDK transitively needs.
# These are allowed regardless of trust policy because the SDK itself
# depends on them. Node-level import enforcement is defense-in-depth;
# the primary security boundary is seccomp + filesystem/subprocess/network
# enforcers.
_FRAMEWORK_DEPS = frozenset({
    "pydantic", "yaml", "click", "rich", "typing_extensions",
    "annotated_types", "pydantic_core", "pydantic_v2",
    "json_schema", "core_schema", "annotated_handlers",
    "typing_inspection",
})

# Sensitive modules that are ALWAYS denied to untrusted nodes, even if
# they happen to be in sys.modules (preloaded by trusted bootstrap).
# These provide escape hatches that bypass all other enforcement.
_PRELOADED_DENYLIST = frozenset({
    "ctypes", "ctypes.wintypes",
    "multiprocessing",
    "runpy",
    "code", "codeop",
    "pdb", "bdb",
    # v1.18.5: Network/subprocess modules are always blocked even if preloaded
    "subprocess",
    "socket",
})


class ImportBlockedError(ImportError):
    """Raised when an import is blocked by package trust policy."""

    def __init__(self, module_name: str, trust_level: str, reason: str, node_id: str = ""):
        self.module_name = module_name
        self.trust_level = trust_level
        self.reason = reason
        self.node_id = node_id
        super().__init__(
            f"IMPORT_POLICY_BLOCKED: '{module_name}' blocked by {trust_level} trust policy"
            f" (node={node_id}): {reason}"
        )


class ImportEnforcer:
    """
    Enforces import policy during node execution.

    Uses contextvars for per-coroutine isolation, so concurrent branches
    with different trust levels do not interfere with each other.

    allow_preloaded: When True (subprocess child), modules already in
        sys.modules bypass the policy check. This is correct because
        pre-loaded modules were imported by trusted bootstrap code.
        NEW imports of dangerous modules not in sys.modules are still
        blocked. Default False (in-process tests expect strict blocking).
    """

    def __init__(
        self,
        trust_level: TrustLevel,
        package_node_id: str = "",
        allow_preloaded: bool = False,
    ):
        self.trust_level = trust_level
        self.package_node_id = package_node_id
        self.policy = get_execution_policy(trust_level).import_policy
        self.blocked_imports: list[dict[str, str]] = []
        self.allow_preloaded = allow_preloaded
        self._token = None

    def _check_import(self, name: str) -> None:
        """Check if an import is allowed. Raises if blocked."""
        # Empty name = relative import (from . import X). Python resolves
        # the package internally via __package__/__name__. Allow it.
        if not name:
            return

        # Always allow Python internal C-extension modules (loaded by importlib)
        if name.startswith("_") and not name.startswith("__"):
            return
        if name in ("__future__",):
            return

        # Allow framework dependencies that NodeChain SDK transitively needs.
        # These are part of the trusted runtime; blocking them would break
        # the import machinery itself.
        top = name.split(".")[0]
        if top in _FRAMEWORK_DEPS:
            return

        # In subprocess child mode: allow modules already loaded by trusted
        # bootstrap code (pre-enforcement). Also handles relative imports
        # where __import__ gets called with just the last component name
        # (e.g., 'fields' for 'pydantic.fields').
        # BUT: Sensitive modules in the denylist are ALWAYS blocked.
        if self.allow_preloaded:
            if name in _sys.modules:
                # Check denylist — sensitive modules are never allowed
                top = name.split(".")[0]
                if top not in _PRELOADED_DENYLIST:
                    return
                # Fall through to policy check for denylisted modules
            else:
                # Name not directly in sys.modules. Check if it's a suffix
                # of a preloaded module (relative import case).
                # v1.18.5 FIX: Only match if the top-level package of the
                # matching module is NOT in the denylist. This prevents
                # false positives like 'asyncio.subprocess' matching 'subprocess'.
                suffix = "." + name
                for mod_name in _sys.modules:
                    if mod_name.endswith(suffix):
                        pkg_top = mod_name.split(".")[0]
                        if pkg_top not in _PRELOADED_DENYLIST:
                            return

        allowed, reason = self.policy.is_import_allowed(name)
        if not allowed:
            record = {
                "module": name,
                "trust_level": self.trust_level.value,
                "node_id": self.package_node_id,
                "reason": reason,
            }
            self.blocked_imports.append(record)
            raise ImportBlockedError(
                module_name=name,
                trust_level=self.trust_level.value,
                reason=reason,
                node_id=self.package_node_id,
            )

    @contextlib.contextmanager
    def enforce(self) -> Generator[None, None, None]:
        """
        Context manager that enforces import policy using contextvars.

        Safe for concurrent execution — each coroutine gets its own
        enforcement context via contextvars.
        """
        if self.trust_level == TrustLevel.BUILT_IN:
            # Built-in nodes have unrestricted imports
            yield
            return

        # Set this enforcer as active for the current coroutine
        self._token = _active_enforcer.set(self)
        try:
            yield
        finally:
            _active_enforcer.reset(self._token)
            self._token = None

    @property
    def had_violations(self) -> bool:
        return len(self.blocked_imports) > 0

    def get_report(self) -> dict[str, Any]:
        """Get import enforcement report for trace/report."""
        return {
            "trust_level": self.trust_level.value,
            "node_id": self.package_node_id,
            "violations": len(self.blocked_imports),
            "blocked_imports": self.blocked_imports,
        }


def _global_import_hook(name: str, *args: Any, **kwargs: Any) -> Any:
    """
    Global __import__ replacement that delegates to the active enforcer
    via contextvars. If no enforcer is active, passes through.

    This is installed once at module load and never removed.
    It reads from contextvars, so it's safe under concurrent execution.
    """
    enforcer = _active_enforcer.get()
    if enforcer is not None:
        enforcer._check_import(name)
    return _original_import(name, *args, **kwargs)


def _install_global_hook() -> Any:
    """Install the global import hook. Called once at module load."""
    global _original_import
    _original_import = builtins.__import__
    builtins.__import__ = _global_import_hook  # type: ignore
    return _original_import


# Install the hook once at module load
_original_import = _install_global_hook()


# ── Patch importlib.import_module (v1.18.5) ──────────────────────────────────
# importlib.import_module() calls _bootstrap._gcd_import() directly,
# bypassing builtins.__import__. We must patch it separately.
import importlib as _importlib

_original_import_module = _importlib.import_module


def _patched_import_module(name: str, package: str | None = None) -> Any:
    """Patched importlib.import_module that checks the active enforcer."""
    enforcer = _active_enforcer.get()
    if enforcer is not None:
        enforcer._check_import(name)
    return _original_import_module(name, package)


_importlib.import_module = _patched_import_module  # type: ignore


def check_import_for_enforcer(name: str) -> None:
    """
    Check import against the active enforcer (if any).

    Called by the importlib.import_module wrapper.
    """
    enforcer = _active_enforcer.get()
    if enforcer is not None:
        enforcer._check_import(name)


def enforce_imports_for_node(
    trust_level: TrustLevel,
    node_id: str,
    allow_preloaded: bool = False,
) -> ImportEnforcer:
    """Create an import enforcer for a node execution.

    Args:
        trust_level: The trust level for this node
        node_id: The node identifier
        allow_preloaded: When True, modules already in sys.modules
            bypass the policy. Used in subprocess child where trusted
            bootstrap code pre-loads framework dependencies.
    """
    return ImportEnforcer(trust_level, node_id, allow_preloaded=allow_preloaded)
