"""Package policy enforcement.

Turns declared capabilities into enforceable policy decisions:
  - Version gate: blocks packages requiring newer runtime
  - Capability audit: strict mode blocks undeclared capabilities
  - Side-effect audit: strict mode blocks undeclared side effects
  - Policy decision recorded in report
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml


class PolicyDecision(Enum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


@dataclass
class PackagePolicyResult:
    """Result of a package policy check."""

    package_id: str
    node_id: str
    decision: PolicyDecision
    reasons: list[str] = field(default_factory=list)
    version_check: str = ""  # "ok", "blocked", "skipped"
    capability_audit: str = ""  # "clean", "undeclared", "skipped"
    side_effect_audit: str = ""  # "clean", "undeclared", "skipped"


def get_runtime_version() -> str:
    """Get the current NodeChain runtime version."""
    # Try to read from package metadata
    try:
        from nodechain import __version__
        return __version__
    except (ImportError, AttributeError):
        pass

    # Fallback: read from pyproject.toml
    try:
        pyproject = Path(__file__).parent.parent.parent.parent / "pyproject.toml"
        if pyproject.exists():
            import tomllib
            with open(pyproject, "rb") as f:
                data = tomllib.load(f)
            return data.get("project", {}).get("version", "0.0.0")
    except Exception:
        pass

    return "0.3.5"  # Development fallback


def parse_version(v: str) -> tuple[int, ...]:
    """Parse a version string into a comparable tuple."""
    parts = []
    for p in v.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    return tuple(parts)


class PackagePolicyEnforcer:
    """
    Enforces package policy based on declared capabilities.

    In normal mode:
      - Version gate blocks packages requiring newer runtime
      - Capability/side-effect audits produce warnings

    In strict mode (NODECHAIN_GOVERNANCE_STRICT=1):
      - Version gate blocks
      - Undeclared capabilities block
      - Undeclared side effects block
    """

    def __init__(self, strict: bool | None = None):
        if strict is None:
            strict = os.environ.get("NODECHAIN_GOVERNANCE_STRICT", "0") == "1"
        self.strict = strict
        self.runtime_version = get_runtime_version()

    def check_version(self, package_min_version: str) -> tuple[bool, str]:
        """
        Check if the runtime version satisfies the package's minimum version.

        Returns (ok, message).
        """
        if not package_min_version:
            return True, "no version requirement"

        rt = parse_version(self.runtime_version)
        req = parse_version(package_min_version)

        if rt >= req:
            return True, f"runtime {self.runtime_version} >= required {package_min_version}"
        else:
            return False, f"runtime {self.runtime_version} < required {package_min_version}"

    def check_capabilities(
        self,
        declared_caps: dict[str, Any],
        required_caps: dict[str, Any],
    ) -> tuple[PolicyDecision, list[str]]:
        """
        Check if required capabilities are declared.

        Returns (decision, reasons).
        """
        issues = []

        for cap_key, cap_value in required_caps.items():
            declared = declared_caps.get(cap_key)
            if declared is None:
                issues.append(f"Capability '{cap_key}' not declared")
            elif declared is False and cap_value is True:
                issues.append(f"Capability '{cap_key}' required but declared as false")

        if not issues:
            return PolicyDecision.ALLOW, []

        if self.strict:
            return PolicyDecision.BLOCK, issues
        return PolicyDecision.WARN, issues

    def check_side_effects(
        self,
        declared_side_effects: list[str],
        observed_side_effects: list[str],
    ) -> tuple[PolicyDecision, list[str]]:
        """
        Check if observed side effects are declared.

        Returns (decision, reasons).
        """
        issues = []
        declared_set = set(declared_side_effects)

        for se in observed_side_effects:
            if se not in declared_set:
                issues.append(f"Side effect '{se}' not declared")

        if not issues:
            return PolicyDecision.ALLOW, []

        if self.strict:
            return PolicyDecision.BLOCK, issues
        return PolicyDecision.WARN, issues

    def enforce_package(
        self,
        package_id: str,
        node_id: str,
        package_path: Path | None = None,
        package_yaml: dict | None = None,
    ) -> PackagePolicyResult:
        """
        Run all policy checks for a package node.

        Returns a PackagePolicyResult with the final decision.
        """
        result = PackagePolicyResult(
            package_id=package_id,
            node_id=node_id,
            decision=PolicyDecision.ALLOW,
        )

        # Load package yaml if not provided
        if package_yaml is None and package_path:
            yaml_path = package_path / "node.yaml" if (package_path / "node.yaml").exists() else package_path / "package.yaml"
            if yaml_path.exists():
                try:
                    package_yaml = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
                except Exception:
                    package_yaml = {}
            else:
                package_yaml = {}

        if not package_yaml:
            result.version_check = "skipped"
            result.capability_audit = "skipped"
            result.side_effect_audit = "skipped"
            return result

        # AC1: Version gate
        min_version = package_yaml.get("nodechain_min_version", "")
        if not min_version:
            # Check nested under meta
            meta = package_yaml.get("meta", {})
            min_version = meta.get("nodechain_min_version", "")
        if min_version:
            ok, msg = self.check_version(min_version)
            result.version_check = "ok" if ok else "blocked"
            if not ok:
                result.reasons.append(msg)
                result.decision = PolicyDecision.BLOCK
        else:
            result.version_check = "skipped"

        # AC5: Capability policy for network/subprocess/filesystem
        caps = package_yaml.get("capabilities", {})
        dangerous_caps = {
            "network": True,
            "subprocess": True,
            "filesystem": lambda v: v not in ("none", "read_package_only"),
        }

        # In strict mode, check if declared capabilities are acceptable
        if self.strict:
            cap_issues = []
            for cap_key, cap_check in dangerous_caps.items():
                declared = caps.get(cap_key, False)
                if callable(cap_check):
                    if cap_check(declared):
                        cap_issues.append(f"Capability '{cap_key}' blocked by policy (value: {declared})")
                elif declared:
                    cap_issues.append(f"Capability '{cap_key}' blocked by policy")

            if cap_issues:
                result.capability_audit = "blocked"
                result.reasons.extend(cap_issues)
                result.decision = PolicyDecision.BLOCK
            else:
                result.capability_audit = "clean"
        else:
            result.capability_audit = "clean"

        # AC3: Side-effect audit
        # For multi-node packages, find the node's entrypoint
        entrypoints = package_yaml.get("entrypoints", [])
        node_side_effects = []
        for ep in entrypoints:
            if ep.get("node_id") == node_id:
                node_side_effects = ep.get("side_effects", [])
                break

        # For single-node packages
        if not node_side_effects:
            node_side_effects = package_yaml.get("side_effects", [])

        # Check against contract-declared side effects
        contract_se = self._get_contract_side_effects(package_yaml, node_id)
        if contract_se is not None:
            dec, se_issues = self.check_side_effects(node_side_effects, contract_se)
            result.side_effect_audit = "clean" if dec == PolicyDecision.ALLOW else "blocked" if dec == PolicyDecision.BLOCK else "undeclared"
            if se_issues:
                result.reasons.extend(se_issues)
                if dec == PolicyDecision.BLOCK:
                    result.decision = PolicyDecision.BLOCK
        else:
            result.side_effect_audit = "clean"

        return result

    def _get_contract_side_effects(self, package_yaml: dict, node_id: str) -> list[str] | None:
        """Extract side effects from contract in package yaml."""
        nodes = package_yaml.get("nodes", [])
        for node_entry in nodes:
            manifest = node_entry.get("manifest", {})
            if manifest.get("node_id") == node_id:
                contract = node_entry.get("contract", {})
                return contract.get("side_effects", [])
        return None
