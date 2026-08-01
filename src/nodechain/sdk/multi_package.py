"""Multi-node package support.

A multi-node package contains multiple Harness Nodes in a single directory.
Uses package.yaml with a nodes list instead of a single node.yaml.

Structure:
  nodes/my_package/
    package.yaml            # Package manifest with multiple node definitions
    implementations/
      node_a.py             # Implementation for node_a
      node_b.py             # Implementation for node_b
    schemas/
      input_a.json
      output_a.json
      input_b.json
      output_b.json
    tests/
      test_node_a.py
      test_node_b.py
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from nodechain.core.contract import (
    NodeContract, EntryContract, ExitContract,
    SideEffect, Requirements,
)
from nodechain.core.manifest import NodeManifest
from nodechain.sdk.package import NodePackage, NodePackageMeta


class MultiNodePackage(BaseModel):
    """
    A package containing multiple Harness Nodes.

    Loaded from a directory containing package.yaml.
    Each node entry produces a separate NodePackage.
    """

    package_id: str
    package_meta: NodePackageMeta
    node_packages: list[NodePackage]
    path: str | None = None

    model_config = {"extra": "forbid"}

    @classmethod
    def from_directory(cls, dir_path: str | Path) -> MultiNodePackage:
        """Load a multi-node package from a directory."""
        dir_path = Path(dir_path)
        pkg_yaml = dir_path / "package.yaml"

        if not pkg_yaml.exists():
            raise FileNotFoundError(
                f"No package.yaml found in {dir_path}"
            )

        with open(pkg_yaml) as f:
            raw = yaml.safe_load(f)

        package_id = raw["package_id"]
        meta_raw = raw.get("meta", {})

        package_meta = NodePackageMeta(
            author=meta_raw.get("author", "unknown"),
            license=meta_raw.get("license", "MIT"),
            repository=meta_raw.get("repository"),
            tags=meta_raw.get("tags", []),
            compatibility_version=meta_raw.get("compatibility_version", "1.0.0"),
            nodechain_min_version=meta_raw.get("nodechain_min_version"),
            origin=meta_raw.get("origin", "local_registry"),
        )

        node_packages = []
        for node_raw in raw.get("nodes", []):
            contract_raw = node_raw["contract"]
            entry_raw = contract_raw["entry"]
            exit_raw = contract_raw["exit"]
            se_raw = contract_raw.get("side_effects", [])
            req_raw = contract_raw.get("requirements", {})

            contract = NodeContract(
                contract_id=contract_raw["contract_id"],
                node_id=node_raw["manifest"]["node_id"],
                version=contract_raw.get("version", "1.0.0"),
                entry=EntryContract(**entry_raw),
                exit=ExitContract(**exit_raw),
                side_effects=[SideEffect(**se) for se in se_raw],
                requirements=Requirements(**req_raw),
            )

            manifest = NodeManifest(
                node_id=node_raw["manifest"]["node_id"],
                node_type=node_raw["manifest"]["node_type"],
                name=node_raw["manifest"]["name"],
                description=node_raw["manifest"]["description"],
                version=node_raw["manifest"].get("version", "1.0.0"),
                contract=contract,
                tags=node_raw["manifest"].get("tags", []),
            )

            impl_name = node_raw.get("implementation", f"{manifest.node_id}.py")
            impl_path = dir_path / "implementations" / impl_name
            test_name = node_raw.get("test", f"test_{manifest.node_id}.py")
            test_path = dir_path / "tests" / test_name

            # Create a synthetic NodePackage for each node
            pkg = NodePackage(
                manifest=manifest,
                package_meta=NodePackageMeta(
                    author=package_meta.author,
                    license=package_meta.license,
                    repository=package_meta.repository,
                    tags=manifest.tags,
                    compatibility_version=package_meta.compatibility_version,
                    origin=package_meta.origin,
                ),
                path=str(dir_path),
            )
            node_packages.append(pkg)

        return cls(
            package_id=package_id,
            package_meta=package_meta,
            node_packages=node_packages,
            path=str(dir_path),
        )

    def validate_package(self) -> list[str]:
        """Validate all nodes in the package."""
        issues = []
        root = Path(self.path) if self.path else None

        for pkg in self.node_packages:
            contract = pkg.manifest.contract
            if not contract.entry.input_type:
                issues.append(f"[{pkg.manifest.node_id}] Contract entry has no input_type")
            if not contract.exit.output_type:
                issues.append(f"[{pkg.manifest.node_id}] Contract exit has no output_type")
            if not pkg.manifest.name:
                issues.append(f"[{pkg.manifest.node_id}] Manifest has no name")

        # Check implementations directory
        if root:
            impl_dir = root / "implementations"
            if not impl_dir.exists():
                issues.append("Missing implementations/ directory")

        return issues

    def content_hash(self) -> str | None:
        """Compute hash over package.yaml + all implementations + schemas."""
        if self.path is None:
            return None

        import hashlib
        h = hashlib.sha256()

        root = Path(self.path)

        # Hash package.yaml
        pkg_yaml = root / "package.yaml"
        if pkg_yaml.exists():
            h.update(pkg_yaml.read_bytes())

        # Hash all implementations
        impl_dir = root / "implementations"
        if impl_dir.exists():
            for f in sorted(impl_dir.glob("*.py")):
                h.update(f.read_bytes())

        # Hash all schemas
        schemas_dir = root / "schemas"
        if schemas_dir.exists():
            for f in sorted(schemas_dir.glob("*.json")):
                h.update(f.read_bytes())

        return h.hexdigest()[:16]

    @property
    def node_ids(self) -> list[str]:
        """List all node IDs in this package."""
        return [pkg.manifest.node_id for pkg in self.node_packages]

    def get_node(self, node_id: str) -> NodePackage | None:
        """Get a specific node package by ID."""
        for pkg in self.node_packages:
            if pkg.manifest.node_id == node_id:
                return pkg
        return None
