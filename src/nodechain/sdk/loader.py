"""NodeLoader — loads node implementations from the local registry.

Bridges the SDK/registry layer to the runtime orchestrator by:
  1. Scanning the local registry for packaged nodes
  2. Dynamically importing their implementation.py
  3. Instantiating the BaseNode subclass
  4. Returning a dict suitable for orchestrator construction
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

from nodechain.nodes.base_node import BaseNode
from nodechain.registry.local_registry import RegistryIndex
from nodechain.sdk.package import NodePackage


class NodeLoadError(Exception):
    """Raised when a node implementation cannot be loaded."""
    pass


class NodeLoader:
    """
    Loads node implementations from the local registry.

    Usage:
        loader = NodeLoader()
        registry_nodes = loader.load_all()
        # registry_nodes is dict[str, BaseNode]
        # Merge with built-in nodes and pass to orchestrator
    """

    def __init__(
        self,
        extra_paths: list[str | Path] | None = None,
        state_manager: Any = None,  # v2.45.2: durable admission recording
    ) -> None:
        # v2.45.2: create default StateManager if not provided
        if state_manager is None:
            from nodechain.core.state import StateManager as _SM
            state_manager = _SM()
        self._registry = RegistryIndex(
            extra_paths=extra_paths,
            state_manager=state_manager,
        )
        self._registry.scan()
        self._loaded: dict[str, BaseNode] = {}

    def load(self, node_id: str, skip_policy: bool = False, **kwargs: Any) -> BaseNode:
        """
        Load a single node from the registry.

        Args:
            node_id: The node to load
            skip_policy: Skip policy enforcement (for testing)
            **kwargs: Arguments passed to the node constructor

        Returns:
            Instantiated BaseNode subclass

        Raises:
            NodeLoadError: If the node cannot be found or loaded
        """
        if node_id in self._loaded:
            return self._loaded[node_id]

        pkg = self._registry.get_package(node_id)
        if pkg is None:
            raise NodeLoadError(f"Node '{node_id}' not found in registry")

        # AC1: Version gate — block if package requires newer runtime
        if skip_policy:
            # skip_policy: auditable bypass
            # Blocked in strict mode unless NODECHAIN_DEV_MODE is set
            import os
            strict = os.environ.get("NODECHAIN_GOVERNANCE_STRICT", "0") == "1"
            dev_mode = os.environ.get("NODECHAIN_DEV_MODE", "0") == "1"
            if strict and not dev_mode:
                raise NodeLoadError(
                    f"Cannot skip policy for '{node_id}' in strict governance mode"
                )
            # Record bypass for audit trail
            if not hasattr(self, '_policy_skips'):
                self._policy_skips: list[str] = []
            self._policy_skips.append(node_id)
        elif pkg.path:
            self._enforce_policy(node_id, pkg)

        impl_path = pkg.get_implementation_path()
        class_name_hint: str | None = None

        if impl_path is None and pkg.path:
            # Try explicit entrypoint from package.yaml
            pkg_yaml_path = Path(pkg.path) / "package.yaml"
            if pkg_yaml_path.exists():
                try:
                    import yaml as _yaml
                    raw = _yaml.safe_load(pkg_yaml_path.read_text())
                    for ep in raw.get("entrypoints", []):
                        if ep.get("node_id") == node_id:
                            impl_str = ep.get("implementation", "")
                            if ":" in impl_str:
                                module_part, cls_name = impl_str.rsplit(":", 1)
                                fs_path = Path(pkg.path) / module_part.replace(".", "/") + ".py"
                                if fs_path.exists():
                                    impl_path = fs_path
                                    class_name_hint = cls_name
                                break
                except Exception:
                    pass

            # Fallback: class-name search in implementations/
            if impl_path is None:
                impl_dir = Path(pkg.path) / "implementations"
                if impl_dir.exists():
                    class_name = class_name_hint or "".join(w.capitalize() for w in node_id.split("_"))
                    for py_file in impl_dir.glob("*.py"):
                        try:
                            content = py_file.read_text(encoding="utf-8")
                            if f"class {class_name}" in content:
                                impl_path = py_file
                                break
                        except Exception:
                            continue

            # Try explicit entrypoint from node.yaml
            if impl_path is None:
                node_yaml_path = Path(pkg.path) / "node.yaml"
                if node_yaml_path.exists():
                    try:
                        import yaml as _yaml
                        raw = _yaml.safe_load(node_yaml_path.read_text())
                        ep = raw.get("entrypoint", "")
                        if ":" in ep:
                            module_part, cls_name = ep.rsplit(":", 1)
                            fs_path = Path(pkg.path) / module_part.replace(".", "/") + ".py"
                            if fs_path.exists():
                                impl_path = fs_path
                    except Exception:
                        pass

        if impl_path is None:
            raise NodeLoadError(
                f"Node '{node_id}' has no implementation.py"
            )

        # Dynamic import
        try:
            spec = importlib.util.spec_from_file_location(
                f"nodechain.nodes.{node_id}",
                str(impl_path),
            )
            if spec is None or spec.loader is None:
                raise NodeLoadError(
                    f"Cannot create import spec for '{node_id}'"
                )

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        except Exception as e:
            raise NodeLoadError(
                f"Failed to import '{node_id}' from {impl_path}: {e}"
            ) from e

        # Find BaseNode subclass in the module
        node_class = None
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (
                isinstance(attr, type)
                and issubclass(attr, BaseNode)
                and attr is not BaseNode
            ):
                node_class = attr
                break

        if node_class is None:
            raise NodeLoadError(
                f"No BaseNode subclass found in '{node_id}' implementation"
            )

        # Instantiate
        try:
            instance = node_class(**kwargs)
        except Exception as e:
            raise NodeLoadError(
                f"Failed to instantiate '{node_id}': {e}"
            ) from e

        self._loaded[node_id] = instance

        # v2.45.0: set runtime-visible provenance on the instance
        # so the package-trust gate (v2.44.x) can consume it.
        instance._node_origin = "local_registry"

        # Resolve and record trust level
        try:
            from nodechain.sdk.trust import resolve_trust_from_package, TrustLevel
            if not hasattr(self, '_trust_levels'):
                self._trust_levels: dict[str, TrustLevel] = {}
            resolved = resolve_trust_from_package(
                node_id, Path(pkg.path) if pkg.path else None,
            )
            self._trust_levels[node_id] = resolved
            # v2.45.0: propagate resolved trust onto the instance
            instance._trust_level = resolved.value if hasattr(resolved, 'value') else str(resolved)
        except Exception:
            instance._trust_level = "local_untrusted"  # fail-safe

        # v2.45.0: set module path for digest derivation
        impl_path = pkg.get_implementation_path() if hasattr(pkg, 'get_implementation_path') else None
        if impl_path and Path(impl_path).exists():
            instance._module_path = str(impl_path)
            instance._package_root = str(Path(impl_path).parent)

        return instance

    def load_all(self, **kwargs: Any) -> dict[str, BaseNode]:
        """
        Load all registered node packages.

        Returns:
            Dict of node_id -> BaseNode instance
        """
        for pkg_info in self._registry.list_packages():
            node_id = pkg_info["node_id"]
            try:
                self.load(node_id, **kwargs)
            except NodeLoadError:
                continue  # Skip unloadable packages

        return dict(self._loaded)

    def load_blueprint_nodes(
        self,
        blueprint_node_ids: list[str],
        **kwargs: Any,
    ) -> dict[str, BaseNode]:
        """
        Load only nodes referenced by a blueprint.

        Args:
            blueprint_node_ids: Node IDs from the blueprint
            **kwargs: Arguments passed to node constructors

        Returns:
            Dict of node_id -> BaseNode for successfully loaded nodes
        """
        for node_id in blueprint_node_ids:
            if node_id in self._loaded:
                continue
            try:
                self.load(node_id, **kwargs)
            except NodeLoadError:
                pass  # Not in registry, may be a built-in

        return {
            nid: node
            for nid, node in self._loaded.items()
            if nid in blueprint_node_ids
        }

    @property
    def loaded_count(self) -> int:
        return len(self._loaded)

    @property
    def registry(self) -> RegistryIndex:
        return self._registry

    def _enforce_policy(self, node_id: str, pkg: NodePackage) -> None:
        """Run package policy checks before loading."""
        from nodechain.sdk.policy_enforcer import PackagePolicyEnforcer, PolicyDecision

        enforcer = PackagePolicyEnforcer()
        result = enforcer.enforce_package(
            package_id=pkg.manifest.node_id,
            node_id=node_id,
            package_path=Path(pkg.path) if pkg.path else None,
        )

        if result.decision == PolicyDecision.BLOCK:
            reasons = "; ".join(result.reasons)
            raise NodeLoadError(
                f"Package policy blocked '{node_id}': {reasons}"
            )

        # Store policy result for later report access
        if not hasattr(self, '_policy_results'):
            self._policy_results: dict[str, Any] = {}
        self._policy_results[node_id] = result

    @property
    def policy_results(self) -> dict[str, Any]:
        """Policy check results for loaded packages."""
        return getattr(self, '_policy_results', {})

    @property
    def policy_skips(self) -> list[str]:
        """Nodes that bypassed policy enforcement."""
        return getattr(self, '_policy_skips', [])

    @property
    def trust_levels(self) -> dict[str, Any]:
        """Trust level for each loaded node."""
        return getattr(self, '_trust_levels', {})
