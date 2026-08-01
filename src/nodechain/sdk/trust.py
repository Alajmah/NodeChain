"""Package trust levels and execution-boundary policy.

Moves from load-boundary enforcement to execution-boundary enforcement:

  Trust levels:     built_in, local_trusted, local_untrusted, remote_untrusted
  Import policy:    allow/deny lists for package code imports
  Filesystem policy: none, package_read_only, workspace_read, workspace_write
  Subprocess:       enforcement strategy per trust level
  Network:          enforcement strategy per trust level
"""

from __future__ import annotations

import os
from enum import Enum
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class TrustLevel(Enum):
    """Package trust levels — determines execution isolation."""

    BUILT_IN = "built_in"               # Core NodeChain nodes, fully trusted
    LOCAL_TRUSTED = "local_trusted"     # Local registry, passed policy checks
    LOCAL_UNTRUSTED = "local_untrusted"  # Local registry, failed policy checks
    REMOTE_UNTRUSTED = "remote_untrusted"  # Remote registry (future)


class FilesystemPolicy(Enum):
    """Filesystem access policy for package execution."""

    NONE = "none"                      # No filesystem access
    PACKAGE_READ_ONLY = "package_read_only"  # Read own package directory only
    WORKSPACE_READ = "workspace_read"  # Read workspace directory
    WORKSPACE_WRITE = "workspace_write"  # Read and write workspace


@dataclass
class ImportPolicy:
    """Import allow/deny policy for package code."""

    allow_builtins: bool = True        # Allow Python builtins (os, sys, json, etc.)
    allow_stdlib: bool = True          # Allow standard library
    allow_nodechain: bool = True       # Allow nodechain.* imports
    allow_third_party: bool = True     # Allow third-party packages
    denied_modules: list[str] = field(default_factory=list)  # Explicit deny list
    allowed_modules: list[str] = field(default_factory=list)  # Explicit allow list (if set, deny all others)

    def is_import_allowed(self, module_name: str) -> tuple[bool, str]:
        """Check if an import is allowed.

        Returns (allowed, reason).
        """
        # Check deny list first
        for denied in self.denied_modules:
            if module_name == denied or module_name.startswith(denied + "."):
                return False, f"Module '{module_name}' is on deny list"

        # If allow list is set, only allow listed modules
        if self.allowed_modules:
            for allowed in self.allowed_modules:
                if module_name == allowed or module_name.startswith(allowed + "."):
                    return True, "On allow list"
            return False, f"Module '{module_name}' not on allow list"

        # Categorize the import
        top_level = module_name.split(".")[0]

        stdlib_modules = {
            "os", "sys", "json", "pathlib", "hashlib", "re", "asyncio",
            "dataclasses", "typing", "datetime", "collections", "functools",
            "importlib", "inspect", "math", "copy", "abc", "io", "contextlib",
            "traceback", "logging", "enum", "time", "uuid", "base64",
        }

        if top_level in stdlib_modules:
            if not self.allow_stdlib:
                return False, f"Standard library blocked: {module_name}"
            return True, "stdlib allowed"

        if top_level == "nodechain":
            if not self.allow_nodechain:
                return False, f"NodeChain imports blocked: {module_name}"
            return True, "nodechain allowed"

        # Known dangerous modules
        dangerous = {"subprocess", "socket", "http", "urllib", "requests", "httpx"}
        if top_level in dangerous:
            if not self.allow_third_party:
                return False, f"Network/subprocess module blocked: {module_name}"
            return True, "third_party allowed (dangerous)"

        if not self.allow_third_party:
            return False, f"Third-party imports blocked: {module_name}"

        return True, "allowed"


@dataclass
class ExecutionPolicy:
    """Full execution policy for a package at a given trust level."""

    trust_level: TrustLevel
    filesystem: FilesystemPolicy = FilesystemPolicy.PACKAGE_READ_ONLY
    allow_subprocess: bool = False
    allow_network: bool = False
    import_policy: ImportPolicy = field(default_factory=ImportPolicy)
    isolation_mode: str = "in_process"  # in_process, subprocess (future)

    def to_dict(self) -> dict[str, Any]:
        return {
            "trust_level": self.trust_level.value,
            "filesystem": self.filesystem.value,
            "allow_subprocess": self.allow_subprocess,
            "allow_network": self.allow_network,
            "isolation_mode": self.isolation_mode,
        }


# Default policies per trust level
DEFAULT_POLICIES: dict[TrustLevel, ExecutionPolicy] = {
    TrustLevel.BUILT_IN: ExecutionPolicy(
        trust_level=TrustLevel.BUILT_IN,
        filesystem=FilesystemPolicy.WORKSPACE_WRITE,
        allow_subprocess=True,
        allow_network=True,
        isolation_mode="in_process",
    ),
    TrustLevel.LOCAL_TRUSTED: ExecutionPolicy(
        trust_level=TrustLevel.LOCAL_TRUSTED,
        filesystem=FilesystemPolicy.PACKAGE_READ_ONLY,
        allow_subprocess=False,
        allow_network=False,
        isolation_mode="in_process",
    ),
    TrustLevel.LOCAL_UNTRUSTED: ExecutionPolicy(
        trust_level=TrustLevel.LOCAL_UNTRUSTED,
        filesystem=FilesystemPolicy.NONE,
        allow_subprocess=False,
        allow_network=False,
        isolation_mode="subprocess",  # Future: run in isolated process
        import_policy=ImportPolicy(
            allow_third_party=False,
            denied_modules=["subprocess", "socket", "http", "urllib"],
        ),
    ),
    TrustLevel.REMOTE_UNTRUSTED: ExecutionPolicy(
        trust_level=TrustLevel.REMOTE_UNTRUSTED,
        filesystem=FilesystemPolicy.NONE,
        allow_subprocess=False,
        allow_network=False,
        isolation_mode="subprocess",  # Future: run in isolated process
        import_policy=ImportPolicy(
            allow_third_party=False,
            allow_stdlib=False,
            denied_modules=["subprocess", "socket", "http", "urllib", "os", "sys"],
        ),
    ),
}


def resolve_trust_level(
    node_id: str,
    is_registry: bool = False,
    policy_allowed: bool = True,
    origin: str = "built_in",
) -> TrustLevel:
    """Resolve the trust level for a node.

    Args:
        node_id: The node to check
        is_registry: Whether the node is from local registry
        policy_allowed: Whether the node passed policy checks
        origin: "built_in", "local_registry", or "remote"

    Returns:
        The resolved TrustLevel
    """
    if origin == "built_in" or not is_registry:
        return TrustLevel.BUILT_IN

    if origin == "remote":
        return TrustLevel.REMOTE_UNTRUSTED

    # Local registry
    if policy_allowed:
        return TrustLevel.LOCAL_TRUSTED
    return TrustLevel.LOCAL_UNTRUSTED


def get_execution_policy(trust_level: TrustLevel) -> ExecutionPolicy:
    """Get the default execution policy for a trust level."""
    return DEFAULT_POLICIES.get(trust_level, DEFAULT_POLICIES[TrustLevel.LOCAL_UNTRUSTED])


def check_filesystem_access(
    trust_level: TrustLevel,
    requested_path: str | Path,
    package_path: str | Path | None = None,
) -> tuple[bool, str]:
    """Check if filesystem access is allowed for a trust level.

    Returns (allowed, reason).
    """
    policy = get_execution_policy(trust_level)
    requested = Path(requested_path).resolve()

    if policy.filesystem == FilesystemPolicy.NONE:
        return False, f"Filesystem access blocked (trust={trust_level.value}, policy=none)"

    if policy.filesystem == FilesystemPolicy.PACKAGE_READ_ONLY:
        if package_path is None:
            return False, "No package path for package_read_only policy"
        pkg = Path(package_path).resolve()
        try:
            requested.relative_to(pkg)
            return True, "Within package directory"
        except ValueError:
            return False, f"Path outside package directory (trust={trust_level.value})"

    if policy.filesystem == FilesystemPolicy.WORKSPACE_READ:
        return True, f"Workspace read allowed (trust={trust_level.value})"

    if policy.filesystem == FilesystemPolicy.WORKSPACE_WRITE:
        return True, f"Workspace write allowed (trust={trust_level.value})"

    return False, "Unknown filesystem policy"


def resolve_trust_from_package(
    node_id: str,
    package_path: Path | None = None,
) -> TrustLevel:
    """Resolve trust level by examining the package and checking policy."""
    if package_path is None:
        return TrustLevel.BUILT_IN

    # Check policy status
    try:
        from nodechain.sdk.policy_enforcer import PackagePolicyEnforcer, PolicyDecision
        enforcer = PackagePolicyEnforcer()
        result = enforcer.enforce_package(
            package_id=node_id,
            node_id=node_id,
            package_path=package_path,
        )
        policy_allowed = result.decision != PolicyDecision.BLOCK
    except Exception:
        policy_allowed = False

    return resolve_trust_level(
        node_id=node_id,
        is_registry=True,
        policy_allowed=policy_allowed,
        origin="local_registry",
    )
