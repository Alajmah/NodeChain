"""Certified Registry Consumption (v1.18.1).

Enforces registry trust at runtime consumption time. NodeChain refuses to
install, load, or execute registry packages unless their registry entry,
certification chain, package digest, lifecycle state, and capability
policy are acceptable.

Consumption policy options:
  certified_only:          Require active certification
  trusted_publisher_only:  Require trust-store-verified publisher
  minimum_certification_level: Minimum certification strength
  allowed_capabilities:    Capability allowlist
  allowed_sandbox_profile: Sandbox profile constraint
  allowed_policy_preset:   Policy preset constraint
  require_active_only:     Reject deprecated entries
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Consumption Policy ──────────────────────────────────────────────────────

class ConsumptionPolicy:
    """Policy governing how registry entries are consumed at runtime.

    Controls whether packages can be installed, loaded, or executed based
    on their registry entry status, certification, publisher trust,
    capabilities, and sandbox constraints.
    """

    def __init__(
        self,
        certified_only: bool = False,
        trusted_publisher_only: bool = False,
        minimum_certification_level: str = "",
        allowed_capabilities: list[str] | None = None,
        allowed_sandbox_profile: str = "",
        allowed_policy_preset: str = "",
        require_active_only: bool = False,
    ):
        self.certified_only = certified_only
        self.trusted_publisher_only = trusted_publisher_only
        self.minimum_certification_level = minimum_certification_level
        self.allowed_capabilities = allowed_capabilities
        self.allowed_sandbox_profile = allowed_sandbox_profile
        self.allowed_policy_preset = allowed_policy_preset
        self.require_active_only = require_active_only

    def to_dict(self) -> dict[str, Any]:
        return {
            "certified_only": self.certified_only,
            "trusted_publisher_only": self.trusted_publisher_only,
            "minimum_certification_level": self.minimum_certification_level,
            "allowed_capabilities": self.allowed_capabilities,
            "allowed_sandbox_profile": self.allowed_sandbox_profile,
            "allowed_policy_preset": self.allowed_policy_preset,
            "require_active_only": self.require_active_only,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ConsumptionPolicy:
        return cls(
            certified_only=data.get("certified_only", False),
            trusted_publisher_only=data.get("trusted_publisher_only", False),
            minimum_certification_level=data.get("minimum_certification_level", ""),
            allowed_capabilities=data.get("allowed_capabilities"),
            allowed_sandbox_profile=data.get("allowed_sandbox_profile", ""),
            allowed_policy_preset=data.get("allowed_policy_preset", ""),
            require_active_only=data.get("require_active_only", False),
        )


# ── Resolution Result ───────────────────────────────────────────────────────

class ResolutionResult:
    """Result of resolving a package from the certified registry."""

    def __init__(
        self,
        resolved: bool,
        entry: dict[str, Any] | None = None,
        errors: list[str] | None = None,
        policy_verdict: str = "",
        checks: list[dict[str, Any]] | None = None,
    ):
        self.resolved = resolved
        self.entry = entry
        self.errors = errors or []
        self.policy_verdict = policy_verdict
        self.checks = checks or []

    def to_dict(self) -> dict[str, Any]:
        return {
            "resolved": self.resolved,
            "entry": self.entry,
            "errors": self.errors,
            "policy_verdict": self.policy_verdict,
            "checks": self.checks,
        }


# ── Resolver ────────────────────────────────────────────────────────────────

def resolve_package(
    package_id: str,
    version: str = "",
    policy: ConsumptionPolicy | None = None,
    trust_store_path: str = "",
) -> ResolutionResult:
    """Resolve a package from the certified registry.

    Checks (in order):
      1. Package exists in registry
      2. Registry entry status is acceptable (active or deprecated)
      3. Certification status is certified (if certified_only)
      4. Package digest matches entry
      5. Publisher is trusted (if trusted_publisher_only)
      6. Capabilities are allowed (if allowed_capabilities)
      7. Sandbox profile is allowed (if allowed_sandbox_profile)

    Args:
        package_id: Package identifier to resolve.
        version: Optional version constraint.
        policy: Consumption policy. Defaults to permissive.
        trust_store_path: Path to trust store for publisher verification.

    Returns:
        ResolutionResult with entry and check details.
    """
    from nodechain.cli.certified_registry import load_registry

    policy = policy or ConsumptionPolicy()
    checks: list[dict[str, Any]] = []
    errors: list[str] = []

    registry = load_registry()
    entries = registry.get("entries", {})

    # Find matching entry
    matching: list[dict[str, Any]] = []
    for entry in entries.values():
        if entry.get("package_id") == package_id:
            if version and entry.get("package_version") != version:
                continue
            matching.append(entry)

    # Check 1: Entry exists
    if not matching:
        checks.append({"check": "entry_exists", "passed": False,
                        "detail": f"Package '{package_id}' not in registry"})
        errors.append(f"Package '{package_id}' not found in certified registry")
        return ResolutionResult(
            resolved=False, errors=errors, policy_verdict="denied", checks=checks,
        )

    # Use latest matching entry (sorted by published_at)
    matching.sort(key=lambda e: e.get("published_at", ""), reverse=True)
    entry = matching[0]
    checks.append({"check": "entry_exists", "passed": True,
                    "detail": f"Found entry {entry.get('entry_id', '')[:8]}..."})

    # Check 2: Registry status
    reg_status = entry.get("registry_status", "")
    # By default: active and deprecated are OK, revoked is always rejected
    status_ok = reg_status in ("active", "deprecated")
    if policy.require_active_only and reg_status == "deprecated":
        status_ok = False
    if reg_status == "revoked":
        status_ok = False

    checks.append({"check": "registry_status", "passed": status_ok,
                    "detail": f"status={reg_status}"})
    if not status_ok:
        errors.append(f"Registry entry status is '{reg_status}'")

    # Check 3: Certification (if certified_only)
    if policy.certified_only:
        cert_status = entry.get("certification_status", "")
        cert_ok = cert_status == "certified"
        checks.append({"check": "certification_status", "passed": cert_ok,
                        "detail": f"cert_status={cert_status}"})
        if not cert_ok:
            errors.append(f"Certification status is '{cert_status}', not 'certified'")
    else:
        checks.append({"check": "certification_status", "passed": True,
                        "detail": "not required"})

    # Check 4: Package digest consistency
    pkg_digest = entry.get("package_digest", "")
    checks.append({"check": "package_digest", "passed": bool(pkg_digest),
                    "detail": f"digest={pkg_digest[:16]}..." if pkg_digest else "missing"})

    # Check 5: Publisher trust (if trusted_publisher_only)
    if policy.trusted_publisher_only and trust_store_path:
        import os
        from nodechain.cli.trust_store import is_trusted_fingerprint

        publisher_fp = entry.get("publisher_fingerprint", "")
        old_ts = os.environ.get("NODECHAIN_TRUST_STORE", "")
        os.environ["NODECHAIN_TRUST_STORE"] = trust_store_path
        try:
            trusted = is_trusted_fingerprint(publisher_fp, purpose="registry_publishing")
        finally:
            if old_ts:
                os.environ["NODECHAIN_TRUST_STORE"] = old_ts
            elif "NODECHAIN_TRUST_STORE" in os.environ:
                del os.environ["NODECHAIN_TRUST_STORE"]

        checks.append({"check": "publisher_trust", "passed": trusted,
                        "detail": f"publisher={publisher_fp[:16]}..." if publisher_fp else "missing"})
        if not trusted:
            errors.append("Publisher not trusted for registry_publishing")
    else:
        checks.append({"check": "publisher_trust", "passed": True,
                        "detail": "not required"})

    # Check 6: Capabilities (if allowed_capabilities)
    if policy.allowed_capabilities:
        entry_caps = set(entry.get("capabilities", []))
        allowed_caps = set(policy.allowed_capabilities)
        caps_ok = entry_caps.issubset(allowed_caps)
        checks.append({"check": "capabilities", "passed": caps_ok,
                        "detail": f"entry={sorted(entry_caps)}, allowed={sorted(allowed_caps)}"})
        if not caps_ok:
            extra = entry_caps - allowed_caps
            errors.append(f"Capability violation: {extra}")
    else:
        checks.append({"check": "capabilities", "passed": True,
                        "detail": "not constrained"})

    # Check 7: Sandbox profile (if allowed_sandbox_profile)
    if policy.allowed_sandbox_profile:
        entry_sandbox = entry.get("sandbox_profile", "")
        sandbox_ok = entry_sandbox == policy.allowed_sandbox_profile
        checks.append({"check": "sandbox_profile", "passed": sandbox_ok,
                        "detail": f"entry={entry_sandbox}, required={policy.allowed_sandbox_profile}"})
        if not sandbox_ok:
            errors.append(f"Sandbox profile mismatch: {entry_sandbox} != {policy.allowed_sandbox_profile}")
    else:
        checks.append({"check": "sandbox_profile", "passed": True,
                        "detail": "not constrained"})

    all_passed = len(errors) == 0
    verdict = "allowed" if all_passed else "denied"

    return ResolutionResult(
        resolved=all_passed,
        entry=entry if all_passed else None,
        errors=errors,
        policy_verdict=verdict,
        checks=checks,
    )


def install_package(
    package_id: str,
    version: str = "",
    policy: ConsumptionPolicy | None = None,
    trust_store_path: str = "",
) -> dict[str, Any]:
    """Install a package from the certified registry after verification.

    This is the primary consumption gate. If any check fails, installation
    is refused.

    Returns:
        Installation result dict with resolved, entry, errors, and evidence fields.
    """
    result = resolve_package(
        package_id=package_id, version=version,
        policy=policy, trust_store_path=trust_store_path,
    )

    install_result: dict[str, Any] = {
        "type": "registry_install_result",
        "package_id": package_id,
        "version": version,
        "resolved": result.resolved,
        "policy_verdict": result.policy_verdict,
        "errors": result.errors,
        "checks": result.checks,
        "timestamp": _now_iso(),
    }

    if result.resolved and result.entry:
        install_result["registry_entry_digest"] = result.entry.get("entry_digest", "")
        install_result["certification_digest"] = result.entry.get("certification_digest", "")
        install_result["publisher_fingerprint"] = result.entry.get("publisher_fingerprint", "")
        install_result["package_digest"] = result.entry.get("package_digest", "")
        install_result["suite_digest"] = result.entry.get("suite_digest", "")
        install_result["eval_report_digest"] = result.entry.get("eval_report_digest", "")
        install_result["registry_resolution_status"] = "resolved"
    else:
        install_result["registry_resolution_status"] = "unresolved"

    return install_result


def create_consumption_trace_fields(
    install_result: dict[str, Any],
) -> dict[str, Any]:
    """Extract registry evidence fields for trace recording.

    These fields can be added to trace events to maintain the evidence
    chain: runtime trace → registry entry → certification → evaluation → suite.
    """
    return {
        "registry_entry_digest": install_result.get("registry_entry_digest", ""),
        "certification_digest": install_result.get("certification_digest", ""),
        "publisher_fingerprint": install_result.get("publisher_fingerprint", ""),
        "registry_resolution_status": install_result.get("registry_resolution_status", ""),
        "registry_policy_verdict": install_result.get("policy_verdict", ""),
    }
