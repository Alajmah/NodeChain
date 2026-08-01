"""Node Package — a self-contained, distributable Harness Node.

A NodePackage bundles:
  - node.yaml   (manifest + contract + metadata)
  - schemas/    (input/output JSON schemas)
  - implementation.py (the node logic)
  - tests/      (package-local tests)
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


class NodePackageMeta(BaseModel):
    """Metadata in node.yaml beyond manifest/contract."""

    author: str = "unknown"
    license: str = "MIT"
    repository: str | None = None
    tags: list[str] = Field(default_factory=list)
    compatibility_version: str = "1.0.0"
    nodechain_min_version: str | None = None
    origin: str = "local_registry"  # local_registry | built_in


class NodePackage(BaseModel):
    """
    A complete, distributable node package.

    Loaded from a directory containing node.yaml.
    """

    manifest: NodeManifest
    package_meta: NodePackageMeta = Field(default_factory=NodePackageMeta)
    path: str | None = None  # Root directory of the package

    model_config = {"extra": "forbid"}

    @classmethod
    def from_directory(cls, dir_path: str | Path) -> NodePackage:
        """Load a node package from a directory."""
        dir_path = Path(dir_path)
        yaml_path = dir_path / "node.yaml"

        if not yaml_path.exists():
            raise FileNotFoundError(
                f"No node.yaml found in {dir_path}"
            )

        with open(yaml_path) as f:
            raw = yaml.safe_load(f)

        # Parse contract
        entry_raw = raw["contract"]["entry"]
        exit_raw = raw["contract"]["exit"]
        side_effects_raw = raw["contract"].get("side_effects", [])
        requirements_raw = raw["contract"].get("requirements", {})

        contract = NodeContract(
            contract_id=raw["contract"]["contract_id"],
            node_id=raw["manifest"]["node_id"],
            version=raw["contract"].get("version", "1.0.0"),
            entry=EntryContract(**entry_raw),
            exit=ExitContract(**exit_raw),
            side_effects=[SideEffect(**se) for se in side_effects_raw],
            requirements=Requirements(**requirements_raw),
        )

        manifest = NodeManifest(
            node_id=raw["manifest"]["node_id"],
            node_type=raw["manifest"]["node_type"],
            name=raw["manifest"]["name"],
            description=raw["manifest"]["description"],
            version=raw["manifest"].get("version", "1.0.0"),
            contract=contract,
            tags=raw["manifest"].get("tags", []),
        )

        package_meta = NodePackageMeta(
            author=raw.get("meta", {}).get("author", "unknown"),
            license=raw.get("meta", {}).get("license", "MIT"),
            repository=raw.get("meta", {}).get("repository"),
            tags=raw.get("meta", {}).get("tags", []),
            compatibility_version=raw.get("meta", {}).get("compatibility_version", "1.0.0"),
        )

        return cls(
            manifest=manifest,
            package_meta=package_meta,
            path=str(dir_path),
        )

    @classmethod
    def from_yaml(cls, yaml_path: str | Path) -> NodePackage:
        """Load a node package from a node.yaml file."""
        return cls.from_directory(Path(yaml_path).parent)

    def validate_package(self) -> list[str]:
        """
        Validate the package structure.
        Returns a list of issues. Empty = valid.
        """
        issues: list[str] = []

        if self.path is None:
            issues.append("Package has no path (loaded from data, not directory)")
            return issues

        root = Path(self.path)

        # Check required files
        if not (root / "node.yaml").exists():
            issues.append("Missing node.yaml")

        if not (root / "implementation.py").exists():
            issues.append("Missing implementation.py")

        # Check contract completeness
        contract = self.manifest.contract

        if not contract.entry.input_type:
            issues.append("Contract entry has no input_type")

        if not contract.exit.output_type:
            issues.append("Contract exit has no output_type")

        if not contract.entry.required_fields:
            issues.append("Contract entry has no required_fields (warning: permissive)")

        # Check manifest
        if not self.manifest.name:
            issues.append("Manifest has no name")

        if not self.manifest.description:
            issues.append("Manifest has no description")

        return issues

    def content_hash(self) -> str | None:
        """Compute SHA-256 hash over all package files."""
        if self.path is None:
            return None

        import hashlib
        h = hashlib.sha256()

        # Hash node.yaml
        node_yaml = Path(self.path) / "node.yaml"
        if node_yaml.exists():
            h.update(node_yaml.read_bytes())

        # Hash package.yaml (multi-node packages)
        pkg_yaml = Path(self.path) / "package.yaml"
        if pkg_yaml.exists():
            h.update(pkg_yaml.read_bytes())

        # Hash implementation.py (single-node packages)
        impl = Path(self.path) / "implementation.py"
        if impl.exists():
            h.update(impl.read_bytes())

        # Hash implementations/ directory (multi-node packages)
        impl_dir = Path(self.path) / "implementations"
        if impl_dir.exists() and impl_dir.is_dir():
            for py_file in sorted(impl_dir.glob("*.py")):
                h.update(py_file.read_bytes())

        # Hash schemas
        schemas_dir = Path(self.path) / "schemas"
        if schemas_dir.exists():
            for sf in sorted(schemas_dir.glob("*.json")):
                h.update(sf.read_bytes())

        # Hash tests/ directory
        tests_dir = Path(self.path) / "tests"
        if tests_dir.exists():
            for tf in sorted(tests_dir.glob("*.py")):
                h.update(tf.read_bytes())

        return h.hexdigest()[:16]  # Short hash for display

    def content_digest(self) -> str | None:
        """Full-length deterministic SHA-256 for enforcement (v2.67.3).

        Stronger than content_hash(): the framing includes each file's
        relative path and a length prefix with null-byte separators, so the
        byte stream is unambiguous and cannot be reproduced by rearranging or
        concatenating files differently. Returns the full 64-char hexdigest.

        Use this (not content_hash()) for any fail-closed integrity check
        such as lockfile enforcement.
        """
        if self.path is None:
            return None

        import hashlib
        h = hashlib.sha256()
        base = Path(self.path)

        def _update(rel_path: str, data: bytes) -> None:
            h.update(str(rel_path).encode("utf-8"))
            h.update(b"\0")
            h.update(str(len(data)).encode("ascii"))
            h.update(b"\0")
            h.update(data)
            h.update(b"\0")

        # node.yaml (single-node) / package.yaml (multi-node)
        for fname in ("node.yaml", "package.yaml"):
            p = base / fname
            if p.exists():
                _update(fname, p.read_bytes())

        # implementation.py (single-node packages)
        impl = base / "implementation.py"
        if impl.exists():
            _update("implementation.py", impl.read_bytes())

        # implementations/ directory (multi-node packages)
        impl_dir = base / "implementations"
        if impl_dir.exists() and impl_dir.is_dir():
            for py_file in sorted(impl_dir.glob("*.py")):
                _update(str(py_file.relative_to(base)), py_file.read_bytes())

        # schemas/
        schemas_dir = base / "schemas"
        if schemas_dir.exists():
            for sf in sorted(schemas_dir.glob("*.json")):
                _update(str(sf.relative_to(base)), sf.read_bytes())

        # tests/
        tests_dir = base / "tests"
        if tests_dir.exists():
            for tf in sorted(tests_dir.glob("*.py")):
                _update(str(tf.relative_to(base)), tf.read_bytes())

        return h.hexdigest()  # full 64 chars — enforcement primitive

    def validate_semver(self) -> list[str]:
        """Validate version fields are parseable semver."""
        import re
        issues = []

        semver_re = r"^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?$"

        version = self.manifest.version
        if not re.match(semver_re, version):
            issues.append(f"Manifest version '{version}' is not valid semver")

        contract_version = self.manifest.contract.version
        if not re.match(semver_re, contract_version):
            issues.append(f"Contract version '{contract_version}' is not valid semver")

        min_ver = self.package_meta.nodechain_min_version
        if min_ver and not re.match(semver_re, min_ver):
            issues.append(f"nodechain_min_version '{min_ver}' is not valid semver")

        return issues

    def get_implementation_path(self) -> Path | None:
        """Get the path to the implementation file."""
        if self.path is None:
            return None
        impl = Path(self.path) / "implementation.py"
        return impl if impl.exists() else None

    def get_test_path(self) -> Path | None:
        """Get the path to the test file."""
        if self.path is None:
            return None
        test_dir = Path(self.path) / "tests"
        if test_dir.exists():
            test_files = list(test_dir.glob("test_*.py"))
            if test_files:
                return test_files[0]
        return None

    def get_schemas_dir(self) -> Path | None:
        """Get the path to the schemas directory."""
        if self.path is None:
            return None
        schemas_dir = Path(self.path) / "schemas"
        return schemas_dir if schemas_dir.exists() else None

    def load_input_schema(self) -> dict | None:
        """Load the input schema from the package's schemas/ directory."""
        import json
        schemas_dir = self.get_schemas_dir()
        if schemas_dir is None:
            return None
        input_path = schemas_dir / "input.json"
        if not input_path.exists():
            return None
        return json.loads(input_path.read_text())

    def load_output_schema(self) -> dict | None:
        """Load the output schema from the package's schemas/ directory."""
        import json
        schemas_dir = self.get_schemas_dir()
        if schemas_dir is None:
            return None
        output_path = schemas_dir / "output.json"
        if not output_path.exists():
            return None
        return json.loads(output_path.read_text())

    def load_schemas(self) -> dict[str, dict | None]:
        """Load all schemas from the package's schemas/ directory."""
        return {
            "input": self.load_input_schema(),
            "output": self.load_output_schema(),
        }
