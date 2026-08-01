"""Local Registry — index of available node packages.

Scans directories for node packages and maintains an index.
Supports: list, inspect, search, load.

v2.45.0: Registry is now an admission boundary. scan() discovers
candidates, but only admitted packages enter the loadable index.
Denied packages remain visible in discovery/admission reports but
cannot be loaded or used by the runtime.
"""

from __future__ import annotations

import json
import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nodechain.sdk.package import NodePackage
from nodechain.core.contract import NodeContract, is_privileged_node


class AdmissionDecision:
    """Result of evaluating a package for registry admission (v2.45.0)."""

    def __init__(
        self,
        node_id: str,
        decision: str,  # "allow" | "deny"
        reason: str,
        rule_id: str = "",
        package_name: str = "",
        package_version: str = "",
        package_digest: str = "unknown",
        origin: str = "local_registry",
        manifest_hash: str = "",
        contract_hash: str = "",
        declared_privileged: bool = False,
        metadata: dict | None = None,
    ):
        self.admission_id = str(uuid.uuid4())
        self.node_id = node_id
        self.decision = decision
        self.reason = reason
        self.rule_id = rule_id
        self.package_name = package_name
        self.package_version = package_version
        self.package_digest = package_digest
        self.origin = origin
        self.manifest_hash = manifest_hash
        self.contract_hash = contract_hash
        self.declared_privileged = declared_privileged
        self.metadata = metadata or {}
        self.created_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "admission_id": self.admission_id,
            "node_id": self.node_id,
            "package_name": self.package_name,
            "package_version": self.package_version,
            "package_digest": self.package_digest,
            "origin": self.origin,
            "manifest_hash": self.manifest_hash,
            "contract_hash": self.contract_hash,
            "decision": self.decision,
            "reason": self.reason,
            "rule_id": self.rule_id,
            "declared_privileged": self.declared_privileged,
            "created_at": self.created_at,
            "metadata_json": json.dumps(self.metadata) if self.metadata else "",
        }


def _admit_package(pkg: NodePackage, existing_node_ids: set[str]) -> AdmissionDecision:
    """v2.45.0: Evaluate a NodePackage for registry admission.

    Returns an AdmissionDecision. Validation runs first; the decision
    is structured and audit-grade.
    """
    node_id = pkg.manifest.node_id
    package_name = pkg.manifest.name
    package_version = pkg.manifest.version

    # Derive digest
    try:
        package_digest = pkg.content_hash()
    except Exception:
        package_digest = "unknown"

    # Derive contract hash
    try:
        contract_json = pkg.manifest.contract.model_dump_json()
        contract_hash = hashlib.sha256(contract_json.encode()).hexdigest()[:16]
    except Exception:
        contract_hash = ""

    # Derive manifest hash
    try:
        manifest_json = pkg.manifest.model_dump_json()
        manifest_hash = hashlib.sha256(manifest_json.encode()).hexdigest()[:16]
    except Exception:
        manifest_hash = ""

    # Check privileged
    try:
        declared_privileged = is_privileged_node(pkg.manifest.contract)
    except Exception:
        declared_privileged = False

    # Validation 1: structural validation
    try:
        issues = pkg.validate_package()
        if issues:
            return AdmissionDecision(
                node_id=node_id, decision="deny",
                reason=f"Structural validation failed: {'; '.join(issues)}",
                rule_id="admission.structural_invalid",
                package_name=package_name, package_version=package_version,
                package_digest=package_digest,
                manifest_hash=manifest_hash, contract_hash=contract_hash,
                declared_privileged=declared_privileged,
                metadata={"issues": issues},
            )
    except Exception as e:
        return AdmissionDecision(
            node_id=node_id, decision="deny",
            reason=f"Validation error: {type(e).__name__}: {e}",
            rule_id="admission.validation_error",
            package_name=package_name, package_version=package_version,
            package_digest=package_digest,
            manifest_hash=manifest_hash, contract_hash=contract_hash,
            declared_privileged=declared_privileged,
        )

    # Validation 2: duplicate node_id
    if node_id in existing_node_ids:
        return AdmissionDecision(
            node_id=node_id, decision="deny",
            reason=f"Duplicate node_id '{node_id}' — already registered",
            rule_id="admission.duplicate_node_id",
            package_name=package_name, package_version=package_version,
            package_digest=package_digest,
            manifest_hash=manifest_hash, contract_hash=contract_hash,
            declared_privileged=declared_privileged,
        )

    # Validation 3: version compatibility (best-effort)
    try:
        min_ver = pkg.package_meta.nodechain_min_version
        if min_ver:
            from nodechain import __version__
            # Simple comparison — not full semver
            if __version__ < min_ver:
                return AdmissionDecision(
                    node_id=node_id, decision="deny",
                    reason=f"Requires nodechain >= {min_ver}, runtime is {__version__}",
                    rule_id="admission.version_incompatible",
                    package_name=package_name, package_version=package_version,
                    package_digest=package_digest,
                    manifest_hash=manifest_hash, contract_hash=contract_hash,
                    declared_privileged=declared_privileged,
                )
    except Exception:
        pass  # Best-effort — don't deny on version check errors

    # Validation 4: package policy enforcement (v2.45.2 fixed)
    try:
        from nodechain.sdk.policy_enforcer import PackagePolicyEnforcer, PolicyDecision
        enforcer = PackagePolicyEnforcer()
        # v2.45.2: pass Path, not str
        pkg_path = Path(pkg.path) if pkg.path else None
        result = enforcer.enforce_package(
            package_id=pkg.manifest.name,
            node_id=node_id,
            package_path=pkg_path,
            package_yaml=None,
        )
        # v2.45.2: fix enum comparison — PolicyDecision.BLOCK.value is "block"
        if result.decision == PolicyDecision.BLOCK:
            return AdmissionDecision(
                node_id=node_id, decision="deny",
                reason=f"Policy blocked: {'; '.join(result.reasons)}",
                rule_id="admission.policy_blocked",
                package_name=package_name, package_version=package_version,
                package_digest=package_digest,
                manifest_hash=manifest_hash, contract_hash=contract_hash,
                declared_privileged=declared_privileged,
                metadata={"policy_reasons": result.reasons},
            )
    except Exception as e:
        # v2.45.2: fail-closed for privileged packages
        if declared_privileged:
            return AdmissionDecision(
                node_id=node_id, decision="deny",
                reason=f"Policy enforcement error for privileged package: {type(e).__name__}: {e}",
                rule_id="admission.policy_enforcement_error",
                package_name=package_name, package_version=package_version,
                package_digest=package_digest,
                manifest_hash=manifest_hash, contract_hash=contract_hash,
                declared_privileged=declared_privileged,
            )

    # All validations passed
    return AdmissionDecision(
        node_id=node_id, decision="allow",
        reason="Package admitted",
        rule_id="admission.allow",
        package_name=package_name, package_version=package_version,
        package_digest=package_digest,
        manifest_hash=manifest_hash, contract_hash=contract_hash,
        declared_privileged=declared_privileged,
    )


class RegistryIndex:
    """
    Local registry of node packages.

    v2.45.0: Registry is an admission boundary. scan() discovers
    candidates in _discovered, evaluates admission, and only admitted
    packages enter _packages (the loadable index). Denied packages
    remain in _denied with their admission decisions.

    Search paths:
      1. Built-in nodes (src/nodechain/nodes/)
      2. User packages (nodes/ directory)
      3. Additional paths via add_path()
    """

    def __init__(
        self,
        extra_paths: list[str | Path] | None = None,
        state_manager: Any = None,  # v2.45.1: durable admission recording
    ) -> None:
        # v2.45.0: two-surface registry
        self._packages: dict[str, NodePackage] = {}  # admitted, loadable
        self._discovered: dict[str, NodePackage] = {}  # all scanned candidates
        self._denied: dict[str, AdmissionDecision] = {}  # denied admission decisions
        self._admission_decisions: dict[str, AdmissionDecision] = {}  # all decisions
        self._paths: list[Path] = []
        self._loaded = False

        # Default search paths
        self._paths.append(Path("nodes"))

        if extra_paths:
            for p in extra_paths:
                self._paths.append(Path(p))

        # v2.45.3: always create default StateManager if none provided
        # Admission must always be durable
        if state_manager is None:
            from nodechain.core.state import StateManager as _SM
            state_manager = _SM()
        self._state_manager = state_manager

    def add_path(self, path: str | Path) -> None:
        """Add a search path for node packages."""
        self._paths.append(Path(path))

    def _record_admission(self, decision: AdmissionDecision) -> bool:
        """v2.45.4: Record admission decision in durable storage first,
        then in memory. Returns True if durable recording succeeded.

        If durable write fails, the decision is NOT added to
        _admission_decisions. Caller must check the return value and
        create a separate failure decision if needed.
        """
        try:
            self._state_manager.record_registry_admission(decision.to_dict())
            self._admission_decisions[decision.admission_id] = decision
            return True
        except Exception:
            return False

    def scan(self) -> int:
        """
        Scan all search paths for node packages.
        v2.45.0: Discovers candidates, evaluates admission, and only
        admits allowed packages into the loadable index.

        Returns number of admitted packages.
        """
        self._packages.clear()
        self._discovered.clear()
        self._denied.clear()
        self._admission_decisions.clear()

        admitted_node_ids: set[str] = set()

        for search_path in self._paths:
            if not search_path.exists():
                continue

            # Scan for node.yaml files (single-node packages)
            for node_yaml in search_path.rglob("node.yaml"):
                try:
                    pkg = NodePackage.from_yaml(node_yaml)
                except Exception as e:
                    # v2.45.1: stable key for parse failures (not "unknown")
                    deny_key = f"parse_error:{node_yaml}"
                    decision = AdmissionDecision(
                        node_id="unknown",
                        decision="deny",
                        reason=f"Parse error: {type(e).__name__}: {e}",
                        rule_id="admission.parse_error",
                        metadata={"candidate_path": str(node_yaml)},
                    )
                    self._record_admission(decision)
                    self._denied[deny_key] = decision
                    continue

                node_id = pkg.manifest.node_id
                self._discovered[node_id] = pkg

                # v2.45.4: evaluate admission + fail-closed durable record
                decision = _admit_package(pkg, admitted_node_ids)
                recorded = self._record_admission(decision)

                if decision.decision == "allow" and recorded:
                    self._packages[node_id] = pkg
                    admitted_node_ids.add(node_id)
                elif decision.decision == "allow" and not recorded:
                    # v2.45.5: durable write failed — create deny decision.
                    # Always add to _admission_decisions in-memory so
                    # collect_health() can see the failure, even if the
                    # durable write for the failure itself also fails.
                    fail_decision = AdmissionDecision(
                        node_id=node_id, decision="deny",
                        reason="Durable admission recording failed — admission denied for safety",
                        rule_id="admission.durable_write_failed",
                        package_name=decision.package_name,
                        package_version=decision.package_version,
                        package_digest=decision.package_digest,
                        manifest_hash=decision.manifest_hash,
                        contract_hash=decision.contract_hash,
                        declared_privileged=decision.declared_privileged,
                    )
                    # v2.45.5: best-effort durable for the failure
                    self._record_admission(fail_decision)
                    # v2.45.5: ALWAYS add in-memory for health visibility
                    self._admission_decisions[fail_decision.admission_id] = fail_decision
                    self._denied[node_id] = fail_decision
                else:
                    # deny decision was already durably recorded by _record_admission
                    self._denied[node_id] = decision

            # Scan for package.yaml files (multi-node packages)
            for pkg_yaml in search_path.rglob("package.yaml"):
                try:
                    from nodechain.sdk.multi_package import MultiNodePackage
                    multi = MultiNodePackage.from_directory(pkg_yaml.parent)
                    for node_pkg in multi.node_packages:
                        node_id = node_pkg.manifest.node_id
                        self._discovered[node_id] = node_pkg

                        decision = _admit_package(node_pkg, admitted_node_ids)
                        recorded = self._record_admission(decision)

                        if decision.decision == "allow" and recorded:
                            self._packages[node_id] = node_pkg
                            admitted_node_ids.add(node_id)
                        elif decision.decision == "allow" and not recorded:
                            fail_decision = AdmissionDecision(
                                node_id=node_id, decision="deny",
                                reason="Durable admission recording failed",
                                rule_id="admission.durable_write_failed",
                            )
                            self._record_admission(fail_decision)
                            # v2.45.5: always in-memory for health visibility
                            self._admission_decisions[fail_decision.admission_id] = fail_decision
                            self._denied[node_id] = fail_decision
                        else:
                            self._denied[node_id] = decision
                except Exception as e:
                    deny_key = f"parse_error:{pkg_yaml}"
                    decision = AdmissionDecision(
                        node_id="unknown",
                        decision="deny",
                        reason=f"Multi-package parse error: {type(e).__name__}: {e}",
                        rule_id="admission.parse_error",
                        metadata={"candidate_path": str(pkg_yaml)},
                    )
                    self._record_admission(decision)
                    self._denied[deny_key] = decision
                    continue

        self._loaded = True
        return len(self._packages)

    def list_packages(self) -> list[dict[str, Any]]:
        """List all admitted packages with summary info."""
        if not self._loaded:
            self.scan()

        result = []
        for node_id, pkg in sorted(self._packages.items()):
            result.append({
                "node_id": node_id,
                "name": pkg.manifest.name,
                "type": pkg.manifest.node_type,
                "version": pkg.manifest.version,
                "description": pkg.manifest.description[:80],
                "tags": pkg.manifest.tags,
            })
        return result

    def inspect(self, node_id: str) -> dict[str, Any] | None:
        """Get detailed info about a specific admitted package."""
        if not self._loaded:
            self.scan()

        pkg = self._packages.get(node_id)
        if pkg is None:
            return None

        contract = pkg.manifest.contract
        return {
            "node_id": node_id,
            "name": pkg.manifest.name,
            "type": pkg.manifest.node_type,
            "version": pkg.manifest.version,
            "description": pkg.manifest.description,
            "tags": pkg.manifest.tags,
            "contract": {
                "contract_id": contract.contract_id,
                "version": contract.version,
                "entry": {
                    "input_type": contract.entry.input_type,
                    "schema_ref": contract.entry.schema_ref,
                    "required_fields": contract.entry.required_fields,
                    "optional_fields": contract.entry.optional_fields,
                },
                "exit": {
                    "output_type": contract.exit.output_type,
                    "schema_ref": contract.exit.schema_ref,
                    "guaranteed_fields": contract.exit.guaranteed_fields,
                    "possible_fields": contract.exit.possible_fields,
                },
                "side_effects": [
                    {
                        "effect_type": se.effect_type,
                        "target": se.target,
                        "optional": se.optional,
                    }
                    for se in contract.side_effects
                ],
                "requirements": {
                    "model_required": contract.requirements.model_required,
                    "tools_required": contract.requirements.tools_required,
                    "adapters_required": contract.requirements.adapters_required,
                    "memory_access": contract.requirements.memory_access,
                    "trust_level": contract.requirements.trust_level,
                },
            },
            "meta": {
                "author": pkg.package_meta.author,
                "license": pkg.package_meta.license,
                "repository": pkg.package_meta.repository,
            },
            "validation": pkg.validate_package(),
        }

    def get_contract(self, node_id: str) -> NodeContract | None:
        """Get the contract for an admitted node."""
        if not self._loaded:
            self.scan()

        pkg = self._packages.get(node_id)
        if pkg is None:
            return None
        return pkg.manifest.contract

    def get_package(self, node_id: str) -> NodePackage | None:
        """Get the full package for an admitted node.

        v2.45.0: Only returns admitted packages. Denied packages
        are not accessible through this method.
        """
        if not self._loaded:
            self.scan()

        return self._packages.get(node_id)

    def search(self, query: str) -> list[dict[str, Any]]:
        """Search admitted packages by name, description, or tags."""
        if not self._loaded:
            self.scan()

        query_lower = query.lower()
        results = []

        for node_id, pkg in self._packages.items():
            searchable = " ".join([
                pkg.manifest.name,
                pkg.manifest.description,
                " ".join(pkg.manifest.tags),
                node_id,
            ]).lower()

            if query_lower in searchable:
                results.append({
                    "node_id": node_id,
                    "name": pkg.manifest.name,
                    "type": pkg.manifest.node_type,
                    "description": pkg.manifest.description[:80],
                })

        return results

    def resolve_blueprint_contracts(
        self, blueprint_nodes: list[str],
    ) -> dict[str, dict[str, Any]]:
        """
        Check which blueprint nodes have registry contracts.
        Returns per-node resolution status.
        """
        if not self._loaded:
            self.scan()

        result = {}
        for node_id in blueprint_nodes:
            contract = self.get_contract(node_id)
            if contract:
                result[node_id] = {
                    "resolved": True,
                    "contract_id": contract.contract_id,
                    "entry_type": contract.entry.input_type,
                    "exit_type": contract.exit.output_type,
                }
            else:
                result[node_id] = {
                    "resolved": False,
                    "contract_id": None,
                }

        return result

    @property
    def package_count(self) -> int:
        if not self._loaded:
            self.scan()
        return len(self._packages)

    # ── v2.45.0: Admission surfaces ──────────────────────────────────

    def get_admission_decisions(self) -> list[dict[str, Any]]:
        """Return all admission decisions (allow + deny) as dicts."""
        if not self._loaded:
            self.scan()
        return [d.to_dict() for d in self._admission_decisions.values()]

    def get_denied_packages(self) -> list[dict[str, Any]]:
        """Return denied admission decisions as dicts."""
        if not self._loaded:
            self.scan()
        return [d.to_dict() for d in self._denied.values()]

    def get_latest_admission(self, node_id: str) -> AdmissionDecision | None:
        """Get the latest admission decision for a node_id."""
        if not self._loaded:
            self.scan()
        for d in reversed(list(self._admission_decisions.values())):
            if d.node_id == node_id:
                return d
        return None

    def collect_health(self) -> dict[str, Any]:
        """v2.45.0: Registry health report.

        Surfaces admitted, denied, invalid, missing digest, privileged
        declarations, and lockfile drift status.
        """
        if not self._loaded:
            self.scan()

        decisions = list(self._admission_decisions.values())
        allowed = [d for d in decisions if d.decision == "allow"]
        denied = [d for d in decisions if d.decision == "deny"]
        missing_digest = [d for d in allowed if d.package_digest == "unknown"]
        privileged = [d for d in allowed if d.declared_privileged]
        parse_errors = [d for d in denied if d.rule_id == "admission.parse_error"]

        # v2.45.1: lockfile drift
        lockfile_valid = True
        lockfile_mismatches = 0
        lockfile_missing = 0
        lockfile_extra = 0
        try:
            from nodechain.sdk.lockfile import verify_lockfile, LOCKFILE_NAME
            lockfile_path = Path(LOCKFILE_NAME)
            if lockfile_path.exists():
                result = verify_lockfile(registry=self)
                lockfile_valid = result.get("valid", False)
                lockfile_mismatches = len(result.get("mismatches", []))
                lockfile_missing = len(result.get("missing", []))
                lockfile_extra = len(result.get("extra", []))
            else:
                lockfile_valid = False
                lockfile_missing = -1  # no lockfile at all
        except Exception:
            pass  # best-effort — don't crash health on lockfile errors

        # v2.45.5: durable write failures
        durable_failures = [d for d in denied if d.rule_id == "admission.durable_write_failed"]

        return {
            "total_discovered": len(self._discovered),
            "total_admitted": len(allowed),
            "total_denied": len(denied),
            "parse_errors": len(parse_errors),
            "missing_digest": len(missing_digest),
            "privileged_declarations": len(privileged),
            "privileged_node_ids": [d.node_id for d in privileged],
            "durable_write_failures": len(durable_failures),
            "durable_write_failed_node_ids": [d.node_id for d in durable_failures],
            "lockfile_valid": lockfile_valid,
            "lockfile_mismatches": lockfile_mismatches,
            "lockfile_missing": lockfile_missing,
            "lockfile_extra": lockfile_extra,
            "latest_admissions": [
                {
                    "node_id": d.node_id,
                    "decision": d.decision,
                    "reason": d.reason[:100],
                    "rule_id": d.rule_id,
                }
                for d in sorted(decisions, key=lambda x: x.created_at, reverse=True)[:10]
            ],
        }
