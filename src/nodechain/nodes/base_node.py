"""Base node — abstract interface all Harness Nodes implement."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.manifest import NodeManifest


class BaseNode(ABC):
    """
    Abstract base for all Harness Nodes.
    Every node receives an InvocationEnvelope and returns an EnvelopeResponse.
    No exceptions. No bypasses.
    """

    # Optional metadata for isolation/trust (set by loader/runtime)
    _node_origin: str = "built_in"  # built_in, local_registry, remote
    _module_path: str = ""  # absolute path to implementation file
    _trust_level: str = "built_in"  # resolved trust level
    _package_root: str = ""  # package directory for filesystem policy

    @property
    def trust_level(self) -> str:
        return self._trust_level

    @property
    def is_registry_node(self) -> bool:
        return self._node_origin != "built_in"

    @property
    def isolation_config(self) -> dict[str, Any] | None:
        """Return isolation config if this node needs subprocess isolation."""
        if self._trust_level in ("local_untrusted", "remote_untrusted") and self._module_path:
            import os
            import platform
            enable_seccomp = False
            # Auto-enable seccomp on Linux when sandbox profile is os_profile
            if platform.system() == "Linux":
                sandbox_profile = os.environ.get("NODECHAIN_SANDBOX_PROFILE", "")
                if sandbox_profile in ("os_profile", ""):
                    enable_seccomp = True
            return {
                "module_path": self._module_path,
                "class_name": type(self).__name__,
                "package_root": self._package_root,
                "enable_seccomp": enable_seccomp,
            }
        return None

    @property
    def sandbox_backend(self) -> str:
        """v2.76: resolved sandbox command-execution backend for this node.

        Mirrors the NODECHAIN_SANDBOX_PROFILE precedent (read through a base-node
        property, not directly inside node modules) so env-derived sandbox
        configuration stays centralized. Available to all nodes regardless of
        trust level (unlike isolation_config, which is untrusted-only).

        Returns 'local_subprocess' (default) or 'native_os_sandbox' (opt-in).
        Unknown values fall back to 'local_subprocess' for safety — the native
        backend is explicit opt-in, never accidental.
        """
        import os
        backend = os.environ.get("NODECHAIN_SANDBOX_BACKEND", "local_subprocess")
        if backend not in ("local_subprocess", "native_os_sandbox"):
            return "local_subprocess"
        return backend

    @property
    @abstractmethod
    def manifest(self) -> NodeManifest:
        """Return this node's manifest (identity + contract)."""
        ...

    @abstractmethod
    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        """
        Execute the node's core logic.
        Receives a compiled invocation envelope.
        Returns a response envelope with the output.
        """
        ...

    def validate_input(self, envelope: InvocationEnvelope) -> list[str]:
        """
        Validate the envelope payload against the node's entry contract.
        Returns a list of validation errors. Empty list = valid.
        """
        errors: list[str] = []
        contract = self.manifest.contract

        for field in contract.entry.required_fields:
            if field not in envelope.payload:
                errors.append(
                    f"Missing required field '{field}' for node "
                    f"'{self.manifest.node_id}'"
                )

        return errors
