"""Package capabilities, dependencies, and side-effect declarations.

Declares what a package needs and what it can do:
  - Python dependencies
  - NodeChain minimum version
  - Runtime capabilities (network, filesystem, memory, external API)
  - Node-level side effects
  - Explicit implementation entrypoints
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class PythonDependency(BaseModel):
    """A Python package dependency."""

    package: str  # e.g., "httpx"
    version_constraint: str = ""  # e.g., ">=0.24.0"


class PackageCapabilities(BaseModel):
    """What a package can do at runtime."""

    network: bool = False
    filesystem: str = "none"  # none, read_package_only, read, write, read_write
    memory_write: bool = False
    external_api: bool = False
    subprocess: bool = False
    gpu: bool = False


class PackageDependencies(BaseModel):
    """Package dependency declarations."""

    python: list[PythonDependency] = Field(default_factory=list)
    nodechain_min_version: str | None = None
    packages: list[str] = Field(default_factory=list)  # Other NodeChain packages


class NodeEntrypoint(BaseModel):
    """Explicit implementation entrypoint for a node."""

    node_id: str
    implementation: str  # e.g., "implementations.uppercase:UppercaseNode"
    side_effects: list[str] = Field(default_factory=list)


class PackageManifest(BaseModel):
    """
    Full package manifest with capabilities, dependencies, and entrypoints.

    This extends the basic package format with trust and policy surface.
    """

    package_id: str
    version: str = "1.0.0"
    nodechain_min_version: str | None = None
    capabilities: PackageCapabilities = Field(default_factory=PackageCapabilities)
    dependencies: PackageDependencies = Field(default_factory=PackageDependencies)
    entrypoints: list[NodeEntrypoint] = Field(default_factory=list)

    model_config = {"extra": "forbid"}

    def validate_capabilities(self) -> list[str]:
        """Validate capability declarations."""
        issues = []

        caps = self.capabilities
        if caps.filesystem not in ("none", "read_package_only", "read", "write", "read_write"):
            issues.append(f"Invalid filesystem capability: {caps.filesystem}")

        return issues

    def validate_dependencies(self) -> list[str]:
        """Validate dependency declarations."""
        import re
        issues = []

        semver_re = r"^\d+\.\d+\.\d+"

        if self.nodechain_min_version:
            if not re.match(semver_re, self.nodechain_min_version):
                issues.append(f"nodechain_min_version '{self.nodechain_min_version}' is not valid semver")

        for dep in self.dependencies.python:
            if not dep.package:
                issues.append("Python dependency has empty package name")

        return issues

    def get_node_entrypoint(self, node_id: str) -> NodeEntrypoint | None:
        """Get the explicit entrypoint for a node."""
        for ep in self.entrypoints:
            if ep.node_id == node_id:
                return ep
        return None

    def parse_entrypoint(self, node_id: str) -> tuple[str, str] | None:
        """
        Parse an entrypoint string into (module_path, class_name).

        Entry point format: "implementations.uppercase:UppercaseNode"
        Returns: ("implementations/uppercase.py", "UppercaseNode") or None
        """
        ep = self.get_node_entrypoint(node_id)
        if ep is None:
            return None

        impl = ep.implementation
        if ":" not in impl:
            return None

        module_path, class_name = impl.rsplit(":", 1)
        # Convert dotted path to filesystem path
        fs_path = module_path.replace(".", "/") + ".py"
        return (fs_path, class_name)
