"""Health Rule Engine and Stable JSON API (v1.20.1).

Formalizes health detection into structured, testable rules with:
  - Versioned JSON schema (dashboard_api_version)
  - Rule IDs for each check (HR-001 through HR-012)
  - Severity classification per rule
  - Recommendation strings for each issue
  - Stable contract for programmatic consumption

Rules:
  HR-001: Unsigned trust store snapshot
  HR-002: Legacy trust keys without purpose
  HR-003: Revoked registry entries present
  HR-004: Denied registry entries present
  HR-005: Expired certifications
  HR-006: Denied certifications
  HR-007: Failed evaluation reports
  HR-008: Broken evidence chains
  HR-009: Unresolved drift
  HR-010: Failed remediation receipts
  HR-011: Paused human reviews
  HR-012: Failed trace replays (detected from report files)
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nodechain.cli.dashboard import (
    HEALTHY, WARNING, DEGRADED, CRITICAL, UNKNOWN,
    worst_health, collect_runtime_status, collect_trust_status,
    collect_registry_status, collect_evidence_status,
    collect_operations_status, collect_evaluation_status,
    collect_review_workbench_status, collect_memory_status,
    collect_workflow_recovery_status, collect_memory_read_status,
    collect_reuse_status, collect_scorecards_status, _get_db_path,
)

# ── API Versioning ──────────────────────────────────────────────────────────

DASHBOARD_API_VERSION = "1.0.0"


# ── Health Rules ────────────────────────────────────────────────────────────

class HealthRule:
    """A single health rule with ID, severity, and detection logic."""

    def __init__(
        self,
        rule_id: str,
        name: str,
        severity: str,
        description: str,
        recommendation: str,
    ):
        self.rule_id = rule_id
        self.name = name
        self.severity = severity
        self.description = description
        self.recommendation = recommendation

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        """Evaluate the rule. Returns issue dict if triggered, None if healthy."""
        raise NotImplementedError


# ── Rule Implementations ────────────────────────────────────────────────────

class HR001UnsignedSnapshot(HealthRule):
    def __init__(self):
        super().__init__(
            rule_id="HR-001",
            name="unsigned_trust_snapshot",
            severity=WARNING,
            description="Trust store snapshot is not signed",
            recommendation="Sign the trust store snapshot using 'nodechain trust-store snapshot --sign'",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        trust = sections.get("trust", {})
        if trust.get("trust_store_exists") and not trust.get("snapshot_signed"):
            return {
                "rule_id": self.rule_id,
                "name": self.name,
                "severity": self.severity,
                "description": self.description,
                "recommendation": self.recommendation,
            }
        return None


class HR002LegacyKeys(HealthRule):
    def __init__(self):
        super().__init__(
            rule_id="HR-002",
            name="legacy_trust_keys",
            severity=WARNING,
            description="Trust store contains keys without purpose",
            recommendation="Migrate legacy keys to purpose-scoped entries or remove them",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        trust = sections.get("trust", {})
        if trust.get("legacy_keys", 0) > 0:
            return {
                "rule_id": self.rule_id,
                "name": self.name,
                "severity": self.severity,
                "description": f"{trust['legacy_keys']} legacy trust keys without purpose",
                "recommendation": self.recommendation,
            }
        return None


class HR003RevokedRegistry(HealthRule):
    def __init__(self):
        super().__init__(
            rule_id="HR-003",
            name="revoked_registry_entries",
            severity=WARNING,
            description="Registry contains revoked entries",
            recommendation="Review revoked entries and ensure they are not consumed",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        registry = sections.get("registry", {})
        if registry.get("revoked", 0) > 0:
            return {
                "rule_id": self.rule_id,
                "name": self.name,
                "severity": self.severity,
                "description": f"{registry['revoked']} revoked registry entries",
                "recommendation": self.recommendation,
            }
        return None


class HR004DeniedRegistry(HealthRule):
    def __init__(self):
        super().__init__(
            rule_id="HR-004",
            name="denied_registry_entries",
            severity=DEGRADED,
            description="Registry has denied entries (publication failures)",
            recommendation="Review denied entries and fix certification or digest issues",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        registry = sections.get("registry", {})
        if registry.get("denied", 0) > 0:
            return {
                "rule_id": self.rule_id,
                "name": self.name,
                "severity": self.severity,
                "description": f"{registry['denied']} denied registry entries",
                "recommendation": self.recommendation,
            }
        return None


class HR005ExpiredCerts(HealthRule):
    def __init__(self):
        super().__init__(
            rule_id="HR-005",
            name="expired_certifications",
            severity=DEGRADED,
            description="Certifications have expired",
            recommendation="Re-run evaluation suites and renew certifications",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        evaluation = sections.get("evaluation", {})
        if evaluation.get("expired_certs", 0) > 0:
            return {
                "rule_id": self.rule_id,
                "name": self.name,
                "severity": self.severity,
                "description": f"{evaluation['expired_certs']} expired certification(s)",
                "recommendation": self.recommendation,
            }
        return None


class HR006DeniedCerts(HealthRule):
    def __init__(self):
        super().__init__(
            rule_id="HR-006",
            name="denied_certifications",
            severity=DEGRADED,
            description="Certifications were denied (evaluation failed)",
            recommendation="Review denied certifications and address evaluation failures",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        evaluation = sections.get("evaluation", {})
        if evaluation.get("denied_certs", 0) > 0:
            return {
                "rule_id": self.rule_id,
                "name": self.name,
                "severity": self.severity,
                "description": f"{evaluation['denied_certs']} denied certification(s)",
                "recommendation": self.recommendation,
            }
        return None


class HR007FailedEvals(HealthRule):
    def __init__(self):
        super().__init__(
            rule_id="HR-007",
            name="failed_evaluations",
            severity=WARNING,
            description="Evaluation reports show failures",
            recommendation="Review failed evaluation reports and address issues",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        evaluation = sections.get("evaluation", {})
        if evaluation.get("failed_reports", 0) > 0:
            return {
                "rule_id": self.rule_id,
                "name": self.name,
                "severity": self.severity,
                "description": f"{evaluation['failed_reports']} failed evaluation(s)",
                "recommendation": self.recommendation,
            }
        return None


class HR008BrokenChains(HealthRule):
    def __init__(self):
        super().__init__(
            rule_id="HR-008",
            name="broken_evidence_chains",
            severity=WARNING,
            description="Evidence chains are broken or incomplete",
            recommendation="Re-index evidence and verify chain integrity",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        evidence = sections.get("evidence", {})
        if evidence.get("broken_chains", 0) > 0:
            return {
                "rule_id": self.rule_id,
                "name": self.name,
                "severity": self.severity,
                "description": f"{evidence['broken_chains']} broken evidence chain(s)",
                "recommendation": self.recommendation,
            }
        return None


class HR009UnresolvedDrift(HealthRule):
    def __init__(self):
        super().__init__(
            rule_id="HR-009",
            name="unresolved_drift",
            severity=WARNING,
            description="Configuration drift detected without remediation",
            recommendation="Review drift reports and apply remediation",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        operations = sections.get("operations", {})
        drift = operations.get("drift_detected", 0)
        remediations = operations.get("remediations", 0)
        if drift > 0 and remediations < drift:
            return {
                "rule_id": self.rule_id,
                "name": self.name,
                "severity": self.severity,
                "description": f"{drift} unresolved drift(s) ({remediations} remediated)",
                "recommendation": self.recommendation,
            }
        return None


class HR010FailedRemediation(HealthRule):
    def __init__(self):
        super().__init__(
            rule_id="HR-010",
            name="failed_remediation",
            severity=DEGRADED,
            description="Remediation receipts show failures",
            recommendation="Review failed remediation receipts and re-attempt",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        # Check data/ for failed remediation receipts
        data_dir = Path("data")
        failed_count = 0
        if data_dir.exists():
            for f in data_dir.glob("remediation_receipt*.json"):
                try:
                    receipt = json.loads(f.read_text(encoding="utf-8"))
                    status = receipt.get("remediation_status", "")
                    if status in ("failed", "unknown"):
                        failed_count += 1
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass

        if failed_count > 0:
            return {
                "rule_id": self.rule_id,
                "name": self.name,
                "severity": self.severity,
                "description": f"{failed_count} failed remediation(s)",
                "recommendation": self.recommendation,
            }
        return None


class HR011PausedReviews(HealthRule):
    def __init__(self):
        super().__init__(
            rule_id="HR-011",
            name="paused_human_reviews",
            severity=WARNING,
            description="Chain runs are paused awaiting human review",
            recommendation="Review and approve/reject paused chain runs",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        runtime = sections.get("runtime", {})
        if runtime.get("paused_reviews", 0) > 0:
            return {
                "rule_id": self.rule_id,
                "name": self.name,
                "severity": self.severity,
                "description": f"{runtime['paused_reviews']} paused human review(s)",
                "recommendation": self.recommendation,
            }
        return None


class HR012FailedTraceReplay(HealthRule):
    def __init__(self):
        super().__init__(
            rule_id="HR-012",
            name="failed_trace_replay",
            severity=WARNING,
            description="Trace replay verification failures detected",
            recommendation="Review failed trace replays and investigate chain integrity",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        evidence = sections.get("evidence", {})
        if evidence.get("replay_failures", 0) > 0:
            return {
                "rule_id": self.rule_id,
                "name": self.name,
                "severity": self.severity,
                "description": f"{evidence['replay_failures']} trace replay failure(s)",
                "recommendation": self.recommendation,
            }
        return None


# ── Rule Registry ───────────────────────────────────────────────────────────


class HR013RemoteRegistryUnready(HealthRule):
    """Warns if remote registry support might be enabled without proper trust."""
    def __init__(self):
        super().__init__(
            rule_id="HR-013",
            name="remote_registry_unready",
            severity=WARNING,
            description="Remote registry support may be enabled without signed registry metadata",
            recommendation="Initialize trust store, sign snapshots, and verify publisher keys before enabling remote registry",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        # Check if platform is ready for remote registry by examining trust section
        trust = sections.get("trust", {})
        issues_count = 0
        if not trust.get("trust_store_exists"):
            issues_count += 1
        if trust.get("trust_store_exists") and not trust.get("snapshot_signed"):
            issues_count += 1
        if trust.get("legacy_keys", 0) > 0:
            issues_count += 1
        registry = sections.get("registry", {})
        if registry.get("revoked", 0) > 0:
            issues_count += 1
        if issues_count > 0:
            return {
                "rule_id": self.rule_id,
                "name": self.name,
                "severity": self.severity,
                "description": f"Remote registry readiness: {issues_count} issue(s)",
                "recommendation": self.recommendation,
            }
        return None


class HR014BrokenTransparencyLog(HealthRule):
    """Warns if the transparency log chain is broken or has issues."""
    def __init__(self):
        super().__init__(
            rule_id="HR-014",
            name="transparency_log_broken",
            severity=WARNING,
            description="Transparency log chain integrity issues detected",
            recommendation="Verify transparency log and investigate any modified or missing entries",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        transparency = sections.get("transparency", {})
        if not transparency.get("enabled", False):
            return None  # Not configured
        if transparency.get("broken_chain", False):
            return {
                "rule_id": self.rule_id,
                "name": self.name,
                "severity": self.severity,
                "description": f"Transparency log chain broken: {transparency.get('error_count', 0)} error(s)",
                "recommendation": self.recommendation,
            }
        # Warn if packages installed but transparency log is empty
        registry = sections.get("registry", {})
        if registry.get("total_packages", 0) > 0 and transparency.get("total_entries", 0) == 0:
            return {
                "rule_id": self.rule_id,
                "name": "transparency_log_empty",
                "severity": self.severity,
                "description": "Registry has packages but transparency log is empty",
                "recommendation": "Log registry interactions to the transparency log",
            }
        # AC11: Remote installs without transparency entries
        remote_installs = registry.get("remote_installs", 0)
        install_events = transparency.get("install_events", 0)
        if remote_installs > 0 and install_events == 0:
            return {
                "rule_id": self.rule_id,
                "name": "transparency_install_missing",
                "severity": self.severity,
                "description": f"{remote_installs} remote install(s) without transparency log entries",
                "recommendation": "Log package_installed events to the transparency log",
            }
        # AC12: Dependency resolutions without transparency entries
        dep_resolutions = registry.get("dep_resolutions", 0)
        dep_graph_events = transparency.get("dep_graph_events", 0)
        if dep_resolutions > 0 and dep_graph_events == 0:
            return {
                "rule_id": self.rule_id,
                "name": "transparency_dep_graph_missing",
                "severity": self.severity,
                "description": f"{dep_resolutions} dependency resolution(s) without transparency log entries",
                "recommendation": "Log dependency_graph_resolved events to the transparency log",
            }
        # AC13: Revoked packages without revocation entries
        revoked_packages = registry.get("revoked_packages", 0)
        revoked_events = transparency.get("revoked_events", 0)
        if revoked_packages > 0 and revoked_events == 0:
            return {
                "rule_id": self.rule_id,
                "name": "transparency_revocation_missing",
                "severity": self.severity,
                "description": f"{revoked_packages} revoked package(s) without transparency log entries",
                "recommendation": "Log package_revoked events to the transparency log",
            }
        return None


class HR015PolicyDrift(HealthRule):
    """Warns if active policy profile has drift or no profile is set (v2.4.0)."""
    def __init__(self):
        super().__init__(
            rule_id="HR-015",
            name="policy_drift",
            severity=WARNING,
            description="Organization trust policy profile issues detected",
            recommendation="Apply or update the organization trust policy profile",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        policy_section = sections.get("policy", {})
        if not policy_section.get("enabled", False):
            return None
        # No active profile
        if not policy_section.get("active_profile"):
            return {
                "rule_id": self.rule_id,
                "name": "no_active_policy",
                "severity": self.severity,
                "description": "No active organization trust policy profile",
                "recommendation": self.recommendation,
            }
        # Stale profile
        if policy_section.get("stale", False):
            return {
                "rule_id": self.rule_id,
                "name": "stale_policy",
                "severity": self.severity,
                "description": f"Policy profile '{policy_section.get('active_profile')}' digest mismatch (stale)",
                "recommendation": "Re-apply the policy profile",
            }
        # Uncovered surfaces
        uncovered = policy_section.get("uncovered_surfaces", [])
        if uncovered:
            return {
                "rule_id": self.rule_id,
                "name": "uncovered_surfaces",
                "severity": self.severity,
                "description": f"Policy does not cover: {', '.join(uncovered)}",
                "recommendation": "Update policy profile to cover all surfaces",
            }
        return None


class HR016FederationIssues(HealthRule):
    """Warns about federation configuration issues (v2.5.0)."""
    def __init__(self):
        super().__init__(
            rule_id="HR-016",
            name="federation_issues",
            severity=WARNING,
            description="Multi-registry federation configuration issues detected",
            recommendation="Review federation configuration and resolve conflicts",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        federation = sections.get("federation", {})
        if not federation.get("enabled", False):
            return None
        # Disabled registries
        disabled = federation.get("disabled_count", 0)
        if disabled > 0:
            return {
                "rule_id": self.rule_id,
                "name": "disabled_registries",
                "severity": self.severity,
                "description": f"{disabled} federated registry/registries disabled",
                "recommendation": self.recommendation,
            }
        # Conflicts
        conflicts = federation.get("conflict_count", 0)
        if conflicts > 0:
            return {
                "rule_id": self.rule_id,
                "name": "federation_conflicts",
                "severity": self.severity,
                "description": f"{conflicts} federation conflict(s) detected",
                "recommendation": "Resolve package digest conflicts across registries",
            }
        # Policy-denied registries
        denied = federation.get("policy_denied_count", 0)
        if denied > 0:
            return {
                "rule_id": self.rule_id,
                "name": "policy_denied_registries",
                "severity": self.severity,
                "description": f"{denied} registry/registries denied by active policy",
                "recommendation": "Review organization policy or registry configuration",
            }
        # No registries configured
        if federation.get("total_registries", 0) == 0:
            return {
                "rule_id": self.rule_id,
                "name": "no_federated_registries",
                "severity": self.severity,
                "description": "Federation enabled but no registries configured",
                "recommendation": "Add registries to the federation configuration",
            }
        return None


class HR017RegistryReputation(HealthRule):
    """Warns about registry reputation issues (v2.6.0)."""
    def __init__(self):
        super().__init__(
            rule_id="HR-017",
            name="registry_reputation",
            severity=WARNING,
            description="Registry reputation issues detected",
            recommendation="Review registry reputation scores and evidence",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        rep = sections.get("reputation", {})
        if not rep.get("enabled", False):
            return None
        # Critical scores (grade F)
        critical = rep.get("critical_count", 0)
        if critical > 0:
            return {
                "rule_id": self.rule_id,
                "name": "critical_reputation_scores",
                "severity": CRITICAL,
                "description": f"{critical} registry/registries have critical reputation (F)",
                "recommendation": "Deny or quarantine registries with critical scores",
            }
        # Degraded scores (grade D)
        degraded = rep.get("degraded_count", 0)
        if degraded > 0:
            return {
                "rule_id": self.rule_id,
                "name": "degraded_reputation_scores",
                "severity": DEGRADED,
                "description": f"{degraded} registry/registries have degraded reputation (D)",
                "recommendation": "Investigate causes of degraded registry health",
            }
        # Stale scores
        stale = rep.get("stale_count", 0)
        if stale > 0:
            return {
                "rule_id": self.rule_id,
                "name": "stale_reputation_scores",
                "severity": self.severity,
                "description": f"{stale} reputation score(s) are stale",
                "recommendation": "Refresh stale reputation scores",
            }
        # Score/evidence mismatch
        mismatch = rep.get("mismatch_count", 0)
        if mismatch > 0:
            return {
                "rule_id": self.rule_id,
                "name": "reputation_evidence_mismatch",
                "severity": DEGRADED,
                "description": f"{mismatch} score(s) have evidence digest mismatch",
                "recommendation": "Recompute reputation scores from verified evidence",
            }
        return None


class HR018DiscoveryIssues(HealthRule):
    """Warns about public discovery issues (v2.7.0)."""
    def __init__(self):
        super().__init__(
            rule_id="HR-018",
            name="discovery_issues",
            severity=WARNING,
            description="Public discovery or marketplace issues detected",
            recommendation="Review discovery configuration and approve pending registries",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        disc = sections.get("discovery", {})
        if not disc.get("enabled", False):
            return None
        # Stale index
        stale = disc.get("stale_index_count", 0)
        if stale > 0:
            return {
                "rule_id": self.rule_id,
                "name": "stale_discovery_index",
                "severity": self.severity,
                "description": f"{stale} discovery index/indices are stale",
                "recommendation": "Refresh stale discovery indices",
            }
        # Unsigned index
        unsigned = disc.get("unsigned_index_count", 0)
        if unsigned > 0:
            return {
                "rule_id": self.rule_id,
                "name": "unsigned_discovery_index",
                "severity": self.severity,
                "description": f"{unsigned} discovery index/indices are unsigned",
                "recommendation": "Only use signed discovery indices in production",
            }
        # Discovered but not approved
        pending = disc.get("pending_approval_count", 0)
        if pending > 0:
            return {
                "rule_id": self.rule_id,
                "name": "pending_registry_approval",
                "severity": self.severity,
                "description": f"{pending} discovered registry/registries not yet approved",
                "recommendation": "Review and approve or reject discovered registries",
            }
        # Policy denials
        denied = disc.get("policy_denial_count", 0)
        if denied > 0:
            return {
                "rule_id": self.rule_id,
                "name": "marketplace_policy_denial",
                "severity": DEGRADED,
                "description": f"{denied} marketplace operation(s) denied by policy",
                "recommendation": "Review organization policy for marketplace restrictions",
            }
        return None


class HR019AttestationIssues(HealthRule):
    """Warns about supply chain attestation issues (v2.8.0)."""
    def __init__(self):
        super().__init__(
            rule_id="HR-019",
            name="attestation_issues",
            severity=WARNING,
            description="Supply chain attestation issues detected",
            recommendation="Review attestation configuration and missing attestations",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        att = sections.get("attestations", {})
        if not att.get("enabled", False):
            return None
        # Missing required attestations
        missing = att.get("missing_required_count", 0)
        if missing > 0:
            return {
                "rule_id": self.rule_id,
                "name": "missing_attestations",
                "severity": DEGRADED,
                "description": f"{missing} package(s) missing required attestations",
                "recommendation": "Obtain attestations from trusted issuers before installing",
            }
        # Expired attestations
        expired = att.get("expired_count", 0)
        if expired > 0:
            return {
                "rule_id": self.rule_id,
                "name": "expired_attestations",
                "severity": self.severity,
                "description": f"{expired} attestation(s) have expired",
                "recommendation": "Refresh expired attestations",
            }
        # Rejected attestations
        rejected = att.get("rejected_count", 0)
        if rejected > 0:
            return {
                "rule_id": self.rule_id,
                "name": "rejected_attestations",
                "severity": DEGRADED,
                "description": f"{rejected} attestation(s) failed verification",
                "recommendation": "Review rejected attestations and issuer configuration",
            }
        return None


class HR020EvidenceIndexIssues(HealthRule):
    """Warns about evidence index or artifact retention issues (v2.9.0)."""
    def __init__(self):
        super().__init__(
            rule_id="HR-020",
            name="evidence_index_issues",
            severity=DEGRADED,
            description="Evidence index or artifact retention issues detected",
            recommendation="Run evidence index verification and review missing/orphaned artifacts",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        ret = sections.get("retention", {})
        if not ret.get("enabled", False):
            return None
        # Missing artifacts
        missing = ret.get("missing_count", 0)
        if missing > 0:
            return {
                "rule_id": self.rule_id,
                "name": "missing_artifacts",
                "severity": DEGRADED,
                "description": f"{missing} indexed artifact(s) missing from storage",
                "recommendation": "Restore missing artifacts or update the evidence index",
            }
        # Index mismatch
        if ret.get("index_mismatch", False):
            return {
                "rule_id": self.rule_id,
                "name": "index_digest_mismatch",
                "severity": DEGRADED,
                "description": "Evidence index digest does not match content",
                "recommendation": "Investigate potential tampering or corruption",
            }
        # Orphaned artifacts
        orphaned = ret.get("orphaned_count", 0)
        if orphaned > 0:
            return {
                "rule_id": self.rule_id,
                "name": "orphaned_artifacts",
                "severity": self.severity,
                "description": f"{orphaned} artifact(s) not referenced by any index entry",
                "recommendation": "Run garbage collection or investigate unexpected artifacts",
            }
        return None


class HR021CheckpointChainIssues(HealthRule):
    """HR-021: Checkpoint chain broken or checkpoint verification failed."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="HR-021",
            name="checkpoint_chain_issues",
            severity=DEGRADED,
            description="Evidence checkpoint chain continuity or verification failure detected",
            recommendation="Review checkpoint chain and re-verify latest checkpoint against store state",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        cp = sections.get("checkpoints", {})
        if not cp.get("enabled", False):
            return None
        # Broken chain
        if cp.get("chain_broken", False):
            return {
                "rule_id": self.rule_id,
                "name": "checkpoint_chain_broken",
                "severity": DEGRADED,
                "description": f"Checkpoint chain broken at sequence #{cp.get('broken_at', '?')}",
                "recommendation": "Investigate checkpoint removal or reordering",
            }
        # Signature failure
        if cp.get("signature_failures", 0) > 0:
            return {
                "rule_id": self.rule_id,
                "name": "checkpoint_signature_failure",
                "severity": DEGRADED,
                "description": f"{cp['signature_failures']} checkpoint(s) with invalid signatures",
                "recommendation": "Verify signer key and investigate potential tampering",
            }
        # Rollback detected
        if cp.get("rollback_detected", False):
            return {
                "rule_id": self.rule_id,
                "name": "rollback_detected",
                "severity": CRITICAL,
                "description": "Store state does not match latest checkpoint (possible rollback)",
                "recommendation": "Compare store state against externally retained checkpoint",
            }
        return None


class HR022UnresolvedRecoveryIntervention(HealthRule):
    """HR-022: Unresolved recovery intervention required."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="HR-022",
            name="unresolved_recovery_intervention",
            severity=WARNING,
            description="Workflow recovery requires operator intervention for unresolved operations",
            recommendation="Review recovery receipt and manually resolve flagged operations",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        recovery = sections.get("workflow_recovery", {})
        if not recovery.get("enabled", False):
            return None
        if recovery.get("needs_intervention", False):
            # v2.37.0: fixed field mismatch — was 'unresolved_count' (nonexistent).
            # Uses unknown_side_effect_count (the actual intervention source).
            count = recovery.get("unknown_side_effect_count", 1)
            return {
                "rule_id": self.rule_id,
                "name": "recovery_needs_intervention",
                "severity": WARNING,
                "description": f"{count} operation(s) require manual intervention after recovery",
                "recommendation": "Review recovery receipt and resolve flagged operations before resuming",
            }
        return None


class HR023FailedCheckpointRestore(HealthRule):
    """HR-023: Failed checkpoint restore."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="HR-023",
            name="failed_checkpoint_restore",
            severity=CRITICAL,
            description="Checkpoint restore failed during workflow recovery",
            recommendation="Investigate checkpoint corruption or missing artifacts",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        recovery = sections.get("workflow_recovery", {})
        if not recovery.get("enabled", False):
            return None
        if recovery.get("restore_failed", False):
            reason = recovery.get("restore_error", "unknown")
            return {
                "rule_id": self.rule_id,
                "name": "checkpoint_restore_failed",
                "severity": CRITICAL,
                "description": f"Checkpoint restore failed: {reason}",
                "recommendation": "Investigate checkpoint corruption, missing artifacts, or chain breaks",
            }
        return None


class HR024ResumedChainChangedContext(HealthRule):
    """HR-024: Resumed chain with changed trust/policy context."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="HR-024",
            name="resumed_chain_changed_context",
            severity=DEGRADED,
            description="Chain resumed but trust, policy, or package context has changed since checkpoint",
            recommendation="Review environment binding changes and decide whether resume is safe",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        recovery = sections.get("workflow_recovery", {})
        if not recovery.get("enabled", False):
            return None
        changes = recovery.get("environment_binding_changes", [])
        if changes:
            return {
                "rule_id": self.rule_id,
                "name": "environment_binding_mismatch",
                "severity": DEGRADED,
                "description": f"Environment changed since checkpoint: {', '.join(changes)}",
                "recommendation": "Review changed bindings and decide whether resume is safe",
            }
        return None


class HR025UnresolvedSideEffectAmbiguity(HealthRule):
    """HR-025: Unresolved side-effect ambiguity after recovery."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="HR-025",
            name="unresolved_side_effect_ambiguity",
            severity=WARNING,
            description="Side effects with ambiguous state require operator review after recovery",
            recommendation="Review recovery receipt and resolve unknown/started side-effect decisions",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        recovery = sections.get("workflow_recovery", {})
        if not recovery.get("enabled", False):
            return None
        unknown_count = recovery.get("unknown_side_effect_count", 0)
        if unknown_count > 0:
            return {
                "rule_id": self.rule_id,
                "name": "side_effect_ambiguity",
                "severity": WARNING,
                "description": f"{unknown_count} side effect(s) have ambiguous state and require operator review",
                "recommendation": "Review recovery receipt and resolve unknown side-effect decisions before resuming",
            }
        return None


class HR026RemoteInstallConflict(HealthRule):
    """HR-026: Remote install identity conflict detected."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="HR-026",
            name="remote_install_conflict",
            severity=DEGRADED,
            description="Remote install conflict: existing registry entry identity does not match remote package",
            recommendation="Review install conflict receipt and resolve identity mismatch",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        install = sections.get("remote_install", {})
        if not install.get("enabled", False):
            return None
        if install.get("conflict_count", 0) > 0:
            return {
                "rule_id": self.rule_id,
                "name": "install_identity_conflict",
                "severity": DEGRADED,
                "description": f"{install['conflict_count']} install conflict(s) detected",
                "recommendation": "Review conflict receipts and resolve identity mismatches",
            }
        return None


class HR027RegistryMetadataExpired(HealthRule):
    """HR-027: Registry metadata expired or stale."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="HR-027",
            name="registry_metadata_expired",
            severity=WARNING,
            description="Remote registry metadata is expired or stale",
            recommendation="Refresh registry metadata or extend freshness policy",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        registry = sections.get("registry_trust", {})
        if not registry.get("enabled", False):
            return None
        expired = registry.get("expired_metadata_count", 0)
        stale = registry.get("stale_metadata_count", 0)
        if expired > 0 or stale > 0:
            count = expired + stale
            return {
                "rule_id": self.rule_id,
                "name": "metadata_freshness_issue",
                "severity": WARNING,
                "description": f"{count} registry metadata issue(s): {expired} expired, {stale} stale",
                "recommendation": "Refresh registry metadata or review freshness policy",
            }
        return None


class HR028RegistryEquivocation(HealthRule):
    """HR-028: Registry equivocation or rollback detected."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="HR-028",
            name="registry_equivocation",
            severity=CRITICAL,
            description="Registry equivocation or metadata rollback detected",
            recommendation="Investigate potential registry compromise or misconfiguration",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        registry = sections.get("registry_trust", {})
        if not registry.get("enabled", False):
            return None
        equivocation = registry.get("equivocation_count", 0)
        rollback = registry.get("rollback_count", 0)
        if equivocation > 0 or rollback > 0:
            return {
                "rule_id": self.rule_id,
                "name": "registry_trust_violation",
                "severity": CRITICAL,
                "description": f"Registry trust violation: {equivocation} equivocation(s), {rollback} rollback(s)",
                "recommendation": "Investigate potential registry compromise or metadata tampering",
            }
        return None


class HR029EndpointIdentityDrift(HealthRule):
    """HR-029: Endpoint identity drift detected."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="HR-029",
            name="endpoint_identity_drift",
            severity=DEGRADED,
            description="Registry endpoint is serving a different registry identity than previously observed",
            recommendation="Verify endpoint change is authorized or update endpoint identity record",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        registry = sections.get("registry_trust", {})
        if not registry.get("enabled", False):
            return None
        drift = registry.get("endpoint_drift_count", 0)
        if drift > 0:
            return {
                "rule_id": self.rule_id,
                "name": "endpoint_drift",
                "severity": DEGRADED,
                "description": f"{drift} endpoint(s) serving different registry identity",
                "recommendation": "Verify endpoint change is authorized",
            }
        return None


class HR030UnapprovedRegistrySigner(HealthRule):
    """HR-030: Unapproved registry signer detected."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="HR-030",
            name="unapproved_registry_signer",
            severity=WARNING,
            description="Registry metadata signed by unapproved signer",
            recommendation="Approve signer in registry trust store or reject registry",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        registry = sections.get("registry_trust", {})
        if not registry.get("enabled", False):
            return None
        unapproved = registry.get("unapproved_signer_count", 0)
        if unapproved > 0:
            return {
                "rule_id": self.rule_id,
                "name": "unapproved_signer",
                "severity": WARNING,
                "description": f"{unapproved} registry metadata item(s) signed by unapproved signer",
                "recommendation": "Approve signer in registry trust store or reject registry",
            }
        return None


class HR031RevokedTransitiveDependency(HealthRule):
    """HR-031: Revoked transitive dependency detected."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="HR-031",
            name="revoked_transitive_dependency",
            severity=CRITICAL,
            description="A dependency in the resolved graph is revoked, blocking the entire graph",
            recommendation="Remove or replace the revoked dependency, or update to a non-revoked version",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        deps = sections.get("dependency_graph", {})
        if not deps.get("enabled", False):
            return None
        revoked = deps.get("revoked_dependency_count", 0)
        if revoked > 0:
            return {
                "rule_id": self.rule_id,
                "name": "revoked_transitive_dependency",
                "severity": CRITICAL,
                "description": f"{revoked} revoked transitive dependency(ies) detected",
                "recommendation": "Remove or replace revoked dependencies — graph is not admissible",
            }
        return None


class HR032DeprecatedTransitiveDependency(HealthRule):
    """HR-032: Deprecated transitive dependency detected."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="HR-032",
            name="deprecated_transitive_dependency",
            severity=WARNING,
            description="A dependency in the resolved graph is deprecated",
            recommendation="Review deprecated dependencies and plan replacement",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        deps = sections.get("dependency_graph", {})
        if not deps.get("enabled", False):
            return None
        deprecated = deps.get("deprecated_dependency_count", 0)
        if deprecated > 0:
            return {
                "rule_id": self.rule_id,
                "name": "deprecated_transitive_dependency",
                "severity": WARNING,
                "description": f"{deprecated} deprecated transitive dependency(ies) detected",
                "recommendation": "Review deprecated dependencies and plan replacement",
            }
        return None


class HR033LockfileDrift(HealthRule):
    """HR-033: Lockfile drift detected."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="HR-033",
            name="lockfile_drift",
            severity=DEGRADED,
            description="Resolved dependency graph no longer matches the lockfile",
            recommendation="Re-resolve dependencies and update lockfile",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        deps = sections.get("dependency_graph", {})
        if not deps.get("enabled", False):
            return None
        if deps.get("lockfile_drift", False):
            return {
                "rule_id": self.rule_id,
                "name": "lockfile_drift",
                "severity": DEGRADED,
                "description": "Dependency graph has drifted from the lockfile",
                "recommendation": "Re-resolve dependencies and update lockfile before execution",
            }
        return None


class HR034UnresolvedDependencyConflict(HealthRule):
    """HR-034: Unresolved dependency conflict."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="HR-034",
            name="unresolved_dependency_conflict",
            severity=DEGRADED,
            description="Dependency graph has unresolved conflicts",
            recommendation="Resolve version conflicts or policy denials in the dependency graph",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        deps = sections.get("dependency_graph", {})
        if not deps.get("enabled", False):
            return None
        conflicts = deps.get("unresolved_conflict_count", 0)
        if conflicts > 0:
            return {
                "rule_id": self.rule_id,
                "name": "unresolved_dependency_conflict",
                "severity": DEGRADED,
                "description": f"{conflicts} unresolved dependency conflict(s)",
                "recommendation": "Resolve version conflicts or policy denials",
            }
        return None


class HR035UnresolvedCapabilityRequest(HealthRule):
    """HR-035: Unresolved capability request (no admissible candidates)."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="HR-035",
            name="unresolved_capability_request",
            severity=DEGRADED,
            description="Capability request has no admissible candidates",
            recommendation="Discover new packages or relax policy constraints",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        cap = sections.get("capability_resolution", {})
        if not cap.get("enabled", False):
            return None
        unresolved = cap.get("unresolved_requests", 0)
        if unresolved > 0:
            return {
                "rule_id": self.rule_id,
                "name": "unresolved_capability_request",
                "severity": DEGRADED,
                "description": f"{unresolved} unresolved capability request(s)",
                "recommendation": "Discover new packages or relax policy constraints",
            }
        return None


class HR036AmbiguousSelection(HealthRule):
    """HR-036: Ambiguous selection (narrow score margin)."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="HR-036",
            name="ambiguous_capability_selection",
            severity=WARNING,
            description="Capability selection has narrow score margin",
            recommendation="Review candidates or tighten policy thresholds",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        cap = sections.get("capability_resolution", {})
        if not cap.get("enabled", False):
            return None
        ambiguous = cap.get("ambiguous_selections", 0)
        if ambiguous > 0:
            return {
                "rule_id": self.rule_id,
                "name": "ambiguous_capability_selection",
                "severity": WARNING,
                "description": f"{ambiguous} ambiguous selection(s) requiring review",
                "recommendation": "Review candidates or tighten policy thresholds",
            }
        return None


class HR037HighRiskSelectedNode(HealthRule):
    """HR-037: High-risk node selected without explicit approval."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="HR-037",
            name="high_risk_selected_node",
            severity=WARNING,
            description="High-risk node was selected",
            recommendation="Review high-risk selections and approve explicitly",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        cap = sections.get("capability_resolution", {})
        if not cap.get("enabled", False):
            return None
        high_risk = cap.get("high_risk_selections", 0)
        if high_risk > 0:
            return {
                "rule_id": self.rule_id,
                "name": "high_risk_selected_node",
                "severity": WARNING,
                "description": f"{high_risk} high-risk node selection(s)",
                "recommendation": "Review and approve high-risk selections",
            }
        return None


class HR038SelectedDeprecatedNode(HealthRule):
    """HR-038: Selected node is deprecated."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="HR-038",
            name="selected_deprecated_node",
            severity=WARNING,
            description="Deprecated node was selected",
            recommendation="Migrate to a non-deprecated alternative",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        cap = sections.get("capability_resolution", {})
        if not cap.get("enabled", False):
            return None
        deprecated = cap.get("deprecated_selections", 0)
        if deprecated > 0:
            return {
                "rule_id": self.rule_id,
                "name": "selected_deprecated_node",
                "severity": WARNING,
                "description": f"{deprecated} deprecated node selection(s)",
                "recommendation": "Migrate to a non-deprecated alternative",
            }
        return None


class HR039SelectionDrift(HealthRule):
    """HR-039: Capability selection drift from pinned resolution."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="HR-039",
            name="capability_selection_drift",
            severity=DEGRADED,
            description="Capability selection drifted from pinned resolution",
            recommendation="Re-resolve capability or update blueprint pin",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        cap = sections.get("capability_resolution", {})
        if not cap.get("enabled", False):
            return None
        drift = cap.get("selection_drift_count", 0)
        if drift > 0:
            return {
                "rule_id": self.rule_id,
                "name": "capability_selection_drift",
                "severity": DEGRADED,
                "description": f"{drift} capability selection drift(s)",
                "recommendation": "Re-resolve capability or update blueprint pin",
            }
        return None


class HR040ActiveDeliberation(HealthRule):
    """HR-040: Active deliberation in progress."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="HR-040",
            name="active_deliberation",
            severity=DEGRADED,
            description="Active adaptive branching deliberation in progress",
            recommendation="Monitor deliberation completion or intervene if stalled",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        ab = sections.get("adaptive_branching", {})
        if not ab.get("enabled", False):
            return None
        active = ab.get("active_deliberations", 0)
        if active > 0:
            return {
                "rule_id": self.rule_id,
                "name": "active_deliberation",
                "severity": DEGRADED,
                "description": f"{active} active deliberation(s) in progress",
                "recommendation": "Monitor deliberation completion or intervene if stalled",
            }
        return None


class HR041ExhaustedBranchBudget(HealthRule):
    """HR-041: Branch budget exhausted."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="HR-041",
            name="exhausted_branch_budget",
            severity=DEGRADED,
            description="Branch budget exhausted during deliberation",
            recommendation="Increase branch budget or reduce branch scope",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        ab = sections.get("adaptive_branching", {})
        if not ab.get("enabled", False):
            return None
        exhausted = ab.get("budget_exhausted_count", 0)
        if exhausted > 0:
            return {
                "rule_id": self.rule_id,
                "name": "exhausted_branch_budget",
                "severity": DEGRADED,
                "description": f"{exhausted} branch(es) exhausted budget",
                "recommendation": "Increase branch budget or reduce branch scope",
            }
        return None


class HR042BranchPolicyViolation(HealthRule):
    """HR-042: Branch policy violation detected."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="HR-042",
            name="branch_policy_violation",
            severity=CRITICAL,
            description="Branch policy violation during deliberation",
            recommendation="Review branch policy and investigate violation",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        ab = sections.get("adaptive_branching", {})
        if not ab.get("enabled", False):
            return None
        violations = ab.get("policy_violation_count", 0)
        if violations > 0:
            return {
                "rule_id": self.rule_id,
                "name": "branch_policy_violation",
                "severity": UNHEALTHY,
                "description": f"{violations} branch policy violation(s)",
                "recommendation": "Review branch policy and investigate violation",
            }
        return None


class HR043UnresolvedMerge(HealthRule):
    """HR-043: Unresolved merge decision."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="HR-043",
            name="unresolved_merge",
            severity=DEGRADED,
            description="Deliberation with no resolved merge decision",
            recommendation="Review deliberation results or request operator intervention",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        ab = sections.get("adaptive_branching", {})
        if not ab.get("enabled", False):
            return None
        unresolved = ab.get("unresolved_merge_count", 0)
        if unresolved > 0:
            return {
                "rule_id": self.rule_id,
                "name": "unresolved_merge",
                "severity": DEGRADED,
                "description": f"{unresolved} unresolved merge decision(s)",
                "recommendation": "Review deliberation results or request operator intervention",
            }
        return None


class HR044HumanReviewPending(HealthRule):
    """HR-044: Human review pending for merge decision."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="HR-044",
            name="human_review_pending",
            severity=DEGRADED,
            description="Human review pending for adaptive branching merge",
            recommendation="Review and approve or reject the pending merge decision",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        ab = sections.get("adaptive_branching", {})
        if not ab.get("enabled", False):
            return None
        pending = ab.get("human_review_pending_count", 0)
        if pending > 0:
            return {
                "rule_id": self.rule_id,
                "name": "human_review_pending",
                "severity": DEGRADED,
                "description": f"{pending} merge decision(s) awaiting human review",
                "recommendation": "Review and approve or reject the pending merge decision",
            }
        return None


class HR045PendingReviewTooOld(HealthRule):
    """HR-045: Pending review request is too old (>72 hours)."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="HR-045",
            name="pending_review_too_old",
            severity=WARNING,
            description="A review request has been pending for more than 72 hours",
            recommendation="Review the stale request or expire it",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        review = sections.get("review_workbench", {})
        stale = review.get("stale_count", 0)
        if stale > 0:
            return {
                "rule_id": self.rule_id,
                "name": self.name,
                "severity": self.severity,
                "description": f"{stale} review request(s) pending >72 hours",
                "recommendation": self.recommendation,
            }
        return None


class HR046UnauthorizedDecision(HealthRule):
    """HR-046: Unauthorized decision attempt detected."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="HR-046",
            name="unauthorized_decision",
            severity=CRITICAL,
            description="A reviewer attempted a decision without sufficient authority",
            recommendation="Verify reviewer role and subject-type authorization",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        review = sections.get("review_workbench", {})
        unauthorized = review.get("unauthorized_attempts", 0)
        if unauthorized > 0:
            return {
                "rule_id": self.rule_id,
                "name": self.name,
                "severity": self.severity,
                "description": f"{unauthorized} unauthorized decision attempt(s) detected",
                "recommendation": self.recommendation,
            }
        return None


class HR047StaleDecision(HealthRule):
    """HR-047: Stale decision receipt (references expired request)."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="HR-047",
            name="stale_decision_receipt",
            severity=WARNING,
            description="A decision receipt references a stale or expired review request",
            recommendation="Re-evaluate the subject and produce a fresh decision if needed",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        review = sections.get("review_workbench", {})
        stale_decisions = review.get("stale_decision_count", 0)
        if stale_decisions > 0:
            return {
                "rule_id": self.rule_id,
                "name": self.name,
                "severity": self.severity,
                "description": f"{stale_decisions} decision receipt(s) referencing stale requests",
                "recommendation": self.recommendation,
            }
        return None


class HR048RejectedBlocking(HealthRule):
    """HR-048: Rejected decision blocking workflow."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="HR-048",
            name="rejected_blocking_workflow",
            severity=DEGRADED,
            description="A rejected operator decision is blocking a workflow",
            recommendation="Address the rejection or escalate to a higher authority",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        review = sections.get("review_workbench", {})
        blocking = review.get("rejected_blocking_count", 0)
        if blocking > 0:
            return {
                "rule_id": self.rule_id,
                "name": self.name,
                "severity": self.severity,
                "description": f"{blocking} rejected decision(s) blocking workflow",
                "recommendation": self.recommendation,
            }
        return None


class HR049OperatorRecoveryBacklog(HealthRule):
    """HR-049: Operator recovery backlog — non-terminal recovery-state runs (v2.46.0).

    Fires when one or more runs are in a non-terminal recovery state
    (anything except COMPLETED/CANCELLED). Binds the Operator Recovery Console
    into the dashboard so an operator scanning it sees recovery work, not just
    side-effect ambiguity (SE-001..006) or review gates (HR-044..048).
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="HR-049",
            name="operator_recovery_backlog",
            severity=DEGRADED,
            description="One or more runs require operator recovery action",
            recommendation="Use `nodechain recover list` to triage and act on blocked runs",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        recovery = sections.get("recovery", {})
        count = recovery.get("actionable_run_count", 0)
        if count > 0:
            return {
                "rule_id": self.rule_id,
                "name": self.name,
                "severity": self.severity,
                "description": f"{count} run(s) require operator recovery action",
                "recommendation": self.recommendation,
            }
        return None


# ── Memory Governance Health Rules (v2.30.0) ─────────────────────────────────


class MEM001MemoryErrors(HealthRule):
    """MEM-001: Memory write commit errors detected."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="MEM-001", name="memory_errors", severity=DEGRADED,
            description="Memory write commit errors detected",
            recommendation="Investigate ChromaDB connectivity or write failures",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        mem = sections.get("memory", {})
        errors = mem.get("memory_error_count", 0)
        if errors > 0:
            return {
                "rule_id": self.rule_id, "name": self.name, "severity": self.severity,
                "description": f"{errors} memory write error(s)",
                "recommendation": self.recommendation,
            }
        return None


class MEM002UncommittedAllowed(HealthRule):
    """MEM-002: Allowed write with no durable write_ref (data-loss risk)."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="MEM-002", name="uncommitted_allowed_write", severity=CRITICAL,
            description="A memory write was allowed by policy but has no durable write reference",
            recommendation="Investigate why allowed writes are not persisting to ChromaDB",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        mem = sections.get("memory", {})
        uncommitted = mem.get("memory_uncommitted_allowed_count", 0)
        if uncommitted > 0:
            return {
                "rule_id": self.rule_id, "name": self.name, "severity": self.severity,
                "description": f"{uncommitted} allowed write(s) with no write_ref (data-loss risk)",
                "recommendation": self.recommendation,
            }
        return None


class MEM003HighSensitivityDenied(HealthRule):
    """MEM-003: High-sensitivity content was denied (informational)."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="MEM-003", name="high_sensitivity_denied", severity=WARNING,
            description="High-sensitivity memory writes were blocked by policy",
            recommendation="Review if the sensitivity classification is correct",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        mem = sections.get("memory", {})
        denied = mem.get("memory_denied_high_sensitivity_count", 0)
        if denied > 0:
            return {
                "rule_id": self.rule_id, "name": self.name, "severity": self.severity,
                "description": f"{denied} high-sensitivity write(s) blocked",
                "recommendation": self.recommendation,
            }
        return None


class MEM004DecisionLogUnavailable(HealthRule):
    """MEM-004: Memory decision log is unavailable."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="MEM-004", name="memory_log_unavailable", severity=DEGRADED,
            description="Memory decision log is not available",
            recommendation="Ensure the chain state database is accessible",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        mem = sections.get("memory", {})
        # Only fire if the memory section is completely absent (not wired at all),
        # not when enabled=False due to an empty/missing DB (that's normal).
        if not mem:
            return {
                "rule_id": self.rule_id, "name": self.name, "severity": self.severity,
                "description": "Memory decision log unavailable — counters not derived",
                "recommendation": self.recommendation,
            }
        return None


class MEM005ChromaDBHealth(HealthRule):
    """MEM-005: ChromaDB health (unavailable in v2.30.0 — network dependency)."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="MEM-005", name="chromadb_health", severity=UNKNOWN,
            description="ChromaDB health check (not evaluated — network dependency)",
            recommendation="Run MemoryManager.health_check() separately if needed",
        )

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        # v2.30.0: ChromaDB heartbeat is a network call excluded from dashboard
        # collection to avoid hangs. This rule never fires from dashboard data.
        return None


# ── Side-Effect Governance Rules (v2.37.0) ──────────────────────────────────


class SE001UnknownSideEffects(HealthRule):
    """SE-001: Unknown side effects require operator review."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="SE-001",
            name="unknown_side_effects",
            severity=WARNING,
            description="Side effects with ambiguous state require operator review",
            recommendation="Review recovery receipt and resolve unknown side-effect decisions",
        )
        self.counter_source = "workflow_recovery.unknown_side_effect_count"

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        recovery = sections.get("workflow_recovery", {})
        if not recovery.get("enabled", False):
            return None
        count = recovery.get("unknown_side_effect_count", 0)
        if count > 0:
            return {
                "rule_id": self.rule_id,
                "name": self.name,
                "severity": WARNING,
                "description": f"{count} side effect(s) have unknown state (crash recovery required)",
                "recommendation": self.recommendation,
            }
        return None


class SE002FailedSideEffects(HealthRule):
    """SE-002: Failed side effects degrade chain health."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="SE-002",
            name="failed_side_effects",
            severity=DEGRADED,
            description="Side effects that failed during execution",
            recommendation="Investigate failed side effects and determine if retry or compensation is needed",
        )
        self.counter_source = "workflow_recovery.failed_side_effect_count"

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        recovery = sections.get("workflow_recovery", {})
        if not recovery.get("enabled", False):
            return None
        count = recovery.get("failed_side_effect_count", 0)
        if count > 0:
            return {
                "rule_id": self.rule_id,
                "name": self.name,
                "severity": DEGRADED,
                "description": f"{count} side effect(s) failed during execution",
                "recommendation": self.recommendation,
            }
        return None


class SE003UndeclaredSideEffects(HealthRule):
    """SE-003: Undeclared side effects are critical contract violations."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="SE-003",
            name="undeclared_side_effects",
            severity=CRITICAL,
            description="Side effects observed at runtime that were not declared by the node contract",
            recommendation="Audit node contracts and add missing side-effect declarations",
        )
        self.counter_source = "workflow_recovery.undeclared_side_effect_count"

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        recovery = sections.get("workflow_recovery", {})
        # v2.37.1: check counter directly — this can be trace-sourced
        # (passed by caller), so it should fire even when ledger is not
        # available (enabled=False).
        count = recovery.get("undeclared_side_effect_count", 0)
        if count > 0:
            return {
                "rule_id": self.rule_id,
                "name": self.name,
                "severity": CRITICAL,
                "description": f"{count} undeclared side effect(s) detected — contract violation",
                "recommendation": self.recommendation,
            }
        return None


class SE004BlockedSideEffects(HealthRule):
    """SE-004: Blocked side effects indicate policy enforcement is active."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="SE-004",
            name="blocked_side_effects",
            severity=WARNING,
            description="Side effects blocked by runtime policy gate",
            recommendation="Review blocked side-effect attempts and adjust policy if blocking is unexpected",
        )
        self.counter_source = "workflow_recovery.side_effect_blocked_count"

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        recovery = sections.get("workflow_recovery", {})
        if not recovery.get("enabled", False):
            return None
        count = recovery.get("side_effect_blocked_count", 0)
        if count > 0:
            return {
                "rule_id": self.rule_id,
                "name": self.name,
                "severity": WARNING,
                "description": f"{count} side effect(s) blocked by policy gate",
                "recommendation": self.recommendation,
            }
        return None


class SE005SideEffectLedgerUnavailable(HealthRule):
    """SE-005: Side-effect ledger unavailable — cannot assess health."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="SE-005",
            name="side_effect_ledger_unavailable",
            severity=DEGRADED,
            description="Side-effect ledger is not available for health assessment",
            recommendation="Ensure state_manager is wired and side_effect_ledger table is accessible",
        )
        self.counter_source = "workflow_recovery.ledger_lookup_failed"

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        # v2.37.0: this rule is intentionally conservative — it only fires
        # when the collector explicitly reported a lookup failure (available=False
        # after the section was populated). In normal environments without a DB,
        # the section is absent or enabled=False, which is not a degradation.
        # A real ledger-unavailable scenario needs a distinct signal from the
        # collector (e.g. a lookup_error field). Deferred until that signal exists.
        recovery = sections.get("workflow_recovery", {})
        if recovery.get("ledger_lookup_failed", False):
            return {
                "rule_id": self.rule_id,
                "name": self.name,
                "severity": DEGRADED,
                "description": "Side-effect ledger lookup failed — cannot assess side-effect health",
                "recommendation": self.recommendation,
            }
        return None


class SE006CompletedWithoutLedger(HealthRule):
    """SE-006: Completed trace events without ledger rows indicate audit gap."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="SE-006",
            name="completed_without_ledger",
            severity=CRITICAL,
            description="Completed side-effect trace events without matching ledger rows",
            recommendation="Investigate trace/ledger desynchronization and reconcile",
        )
        self.counter_source = "workflow_recovery.unreconciled_completed_count"

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        recovery = sections.get("workflow_recovery", {})
        # v2.37.1: trace-sourced counter — fire even when ledger unavailable
        count = recovery.get("unreconciled_completed_count", 0)
        if count > 0:
            return {
                "rule_id": self.rule_id,
                "name": self.name,
                "severity": CRITICAL,
                "description": f"{count} completed side effect(s) in trace without ledger row",
                "recommendation": self.recommendation,
            }
        return None


# ── Memory Read Governance Rules (v2.41.0) ──────────────────────────────────


class MR001MemoryReadDenied(HealthRule):
    """MR-001: Memory reads denied by policy gate."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="MR-001",
            name="memory_read_denied",
            severity=WARNING,
            description="Memory reads blocked by MEMORY_READ policy",
            recommendation="Review denied memory reads and adjust policy if blocking is unexpected",
        )
        self.counter_source = "memory_read.memory_read_denied_count"

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        mr = sections.get("memory_read", {})
        count = mr.get("memory_read_denied_count", 0)
        if count > 0:
            return {
                "rule_id": self.rule_id, "name": self.name,
                "severity": WARNING,
                "description": f"{count} memory read(s) denied by policy",
                "recommendation": self.recommendation,
            }
        return None


class MR002MemoryReadWithoutDecision(HealthRule):
    """MR-002: Memory exposure without durable allow decision (critical)."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="MR-002",
            name="memory_read_without_decision",
            severity=CRITICAL,
            description="Memory exposed without a durable MEMORY_READ allow decision",
            recommendation="Investigate memory exposure path — all exposure must reference a durable decision",
        )
        self.counter_source = "memory_read.memory_read_without_decision_count"

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        mr = sections.get("memory_read", {})
        count = mr.get("memory_read_without_decision_count", 0)
        if count > 0:
            return {
                "rule_id": self.rule_id, "name": self.name,
                "severity": CRITICAL,
                "description": f"{count} memory exposure(s) without durable allow decision",
                "recommendation": self.recommendation,
            }
        return None


class MR003MemoryReadPolicyMismatch(HealthRule):
    """MR-003: Memory read policy mismatch (critical)."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="MR-003",
            name="memory_read_policy_mismatch",
            severity=CRITICAL,
            description="Memory read policy mismatch detected",
            recommendation="Investigate policy mismatch between trace and durable decisions",
        )
        self.counter_source = "memory_read.memory_read_policy_mismatch_count"

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        mr = sections.get("memory_read", {})
        count = mr.get("memory_read_policy_mismatch_count", 0)
        if count > 0:
            return {
                "rule_id": self.rule_id, "name": self.name,
                "severity": CRITICAL,
                "description": f"{count} memory read policy mismatch(es)",
                "recommendation": self.recommendation,
            }
        return None


class MR004MemoryReadExposureDetected(HealthRule):
    """MR-004: Memory exposure detected (informational/warning)."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="MR-004",
            name="memory_read_exposure_detected",
            severity=WARNING,
            description="Nodes with memory exposure (authorized reads)",
            recommendation="Review which nodes have memory access to ensure exposure is intentional",
        )
        self.counter_source = "memory_read.memory_read_exposed_node_count"

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        mr = sections.get("memory_read", {})
        count = mr.get("memory_read_exposed_node_count", 0)
        if count > 0:
            return {
                "rule_id": self.rule_id, "name": self.name,
                "severity": WARNING,
                "description": f"{count} node(s) with memory exposure",
                "recommendation": self.recommendation,
            }
        return None


class MR005MemoryReadDecisionLogUnavailable(HealthRule):
    """MR-005: Memory read decision log unavailable."""

    def __init__(self) -> None:
        super().__init__(
            rule_id="MR-005",
            name="memory_read_decision_log_unavailable",
            severity=DEGRADED,
            description="Memory read decision log is not available",
            recommendation="Ensure state_manager is wired and memory_read_decisions table is accessible",
        )
        self.counter_source = "memory_read.enabled"

    def evaluate(self, sections: dict[str, Any]) -> dict[str, Any] | None:
        mr = sections.get("memory_read", {})
        # v2.41.0: conservative — only fires on explicit lookup failure,
        # not when no DB exists (normal in many environments).
        if mr.get("lookup_failed", False):
            return {
                "rule_id": self.rule_id, "name": self.name,
                "severity": DEGRADED,
                "description": "Memory read decision log lookup failed",
                "recommendation": self.recommendation,
            }
        return None


ALL_RULES: list[HealthRule] = [
    HR001UnsignedSnapshot(),
    HR002LegacyKeys(),
    HR003RevokedRegistry(),
    HR004DeniedRegistry(),
    HR005ExpiredCerts(),
    HR006DeniedCerts(),
    HR007FailedEvals(),
    HR008BrokenChains(),
    HR009UnresolvedDrift(),
    HR010FailedRemediation(),
    HR011PausedReviews(),
    HR012FailedTraceReplay(),
    HR013RemoteRegistryUnready(),
    HR014BrokenTransparencyLog(),
    HR015PolicyDrift(),
    HR016FederationIssues(),
    HR017RegistryReputation(),
    HR018DiscoveryIssues(),
    HR019AttestationIssues(),
    HR020EvidenceIndexIssues(),
    HR021CheckpointChainIssues(),
    HR022UnresolvedRecoveryIntervention(),
    HR023FailedCheckpointRestore(),
    HR024ResumedChainChangedContext(),
    HR025UnresolvedSideEffectAmbiguity(),
    HR026RemoteInstallConflict(),
    HR027RegistryMetadataExpired(),
    HR028RegistryEquivocation(),
    HR029EndpointIdentityDrift(),
    HR030UnapprovedRegistrySigner(),
    HR031RevokedTransitiveDependency(),
    HR032DeprecatedTransitiveDependency(),
    HR033LockfileDrift(),
    HR034UnresolvedDependencyConflict(),
    HR035UnresolvedCapabilityRequest(),
    HR036AmbiguousSelection(),
    HR037HighRiskSelectedNode(),
    HR038SelectedDeprecatedNode(),
    HR039SelectionDrift(),
    HR040ActiveDeliberation(),
    HR041ExhaustedBranchBudget(),
    HR042BranchPolicyViolation(),
    HR043UnresolvedMerge(),
    HR044HumanReviewPending(),
    HR045PendingReviewTooOld(),
    HR046UnauthorizedDecision(),
    HR047StaleDecision(),
    HR048RejectedBlocking(),
    HR049OperatorRecoveryBacklog(),
    MEM001MemoryErrors(),
    MEM002UncommittedAllowed(),
    MEM003HighSensitivityDenied(),
    MEM004DecisionLogUnavailable(),
    MEM005ChromaDBHealth(),
    SE001UnknownSideEffects(),
    SE002FailedSideEffects(),
    SE003UndeclaredSideEffects(),
    SE004BlockedSideEffects(),
    SE005SideEffectLedgerUnavailable(),
    SE006CompletedWithoutLedger(),
    MR001MemoryReadDenied(),
    MR002MemoryReadWithoutDecision(),
    MR003MemoryReadPolicyMismatch(),
    MR004MemoryReadExposureDetected(),
    MR005MemoryReadDecisionLogUnavailable(),
]

RULES_BY_ID: dict[str, HealthRule] = {r.rule_id: r for r in ALL_RULES}


def evaluate_all_rules(sections: dict[str, Any]) -> list[dict[str, Any]]:
    """Run all health rules against the dashboard sections.

    Returns list of triggered issues (empty if all healthy).
    """
    issues: list[dict[str, Any]] = []
    for rule in ALL_RULES:
        result = rule.evaluate(sections)
        if result is not None:
            issues.append(result)
    return issues


def compute_health_from_issues(issues: list[dict[str, Any]]) -> str:
    """Compute overall health from triggered issues."""
    if not issues:
        return HEALTHY
    severities = [i["severity"] for i in issues]
    return worst_health(*severities)


# ── Stable JSON API ─────────────────────────────────────────────────────────

def collect_dashboard_v2() -> dict[str, Any]:
    """Collect dashboard with versioned JSON API.

    Returns a dict with:
      - api_version: stable version string
      - overall_health: computed from rules
      - issues: structured list with rule_id, severity, recommendation
      - sections: raw section data
      - rule_summary: per-rule evaluation results
    """
    runtime = collect_runtime_status()
    trust = collect_trust_status()
    registry = collect_registry_status()
    evidence = collect_evidence_status()
    operations = collect_operations_status()
    evaluation = collect_evaluation_status()

    # v2.46.0: recovery collector + DB-path resolver (used below + for review_sm).
    from nodechain.cli.dashboard import collect_recovery_status, _get_db_path

    # v2.24.0: derive review-workbench counters from durable chain state using
    # the same DB resolution as runtime_status/inspect/reconcile. Only scan if
    # the DB file exists — avoids creating it on first call (preserves
    # deterministic-output guarantees for empty environments).
    from nodechain.core.state import StateManager as _StateManager
    from pathlib import Path as _Path
    _review_db = _get_db_path()
    if _Path(_review_db).exists():
        review_sm = _StateManager(db_path=_review_db)
    else:
        review_sm = None
    review_workbench = collect_review_workbench_status(state_manager=review_sm)
    # v2.30.0: memory governance dashboard.
    memory = collect_memory_status(state_manager=review_sm)
    # v2.33.0: workflow-recovery / side-effect lifecycle dashboard. Activates
    # the previously-dormant workflow_recovery section that HR-022..025 read.
    # v2.37.1: pass real counters when available
    workflow_recovery = collect_workflow_recovery_status(state_manager=review_sm)
    # v2.41.0: memory read governance dashboard
    memory_read = collect_memory_read_status(state_manager=review_sm)
    # v2.46.0: operator recovery backlog. Uses the same DB + trace-dir
    # resolution as the other sections so HR-049 fires through the real
    # versioned health path (collect_dashboard_v2), not just the legacy one.
    _trace_dir = os.environ.get("NODECHAIN_TRACE_DIR", "data/traces")
    recovery = collect_recovery_status(
        state_manager=review_sm, trace_dir=_trace_dir,
    )

    sections = {
        "runtime": runtime,
        "trust": trust,
        "registry": registry,
        "evidence": evidence,
        "operations": operations,
        "evaluation": evaluation,
        "review_workbench": review_workbench,
        "memory": memory,
        "workflow_recovery": workflow_recovery,
        "memory_read": memory_read,
        "recovery": recovery,
        "reuse": collect_reuse_status(),
        "scorecards": collect_scorecards_status(),
    }

    # Run all rules
    issues = evaluate_all_rules(sections)
    overall = compute_health_from_issues(issues)

    # Build rule summary
    triggered_ids = {i["rule_id"] for i in issues}
    rule_summary = []
    for rule in ALL_RULES:
        rule_summary.append({
            "rule_id": rule.rule_id,
            "name": rule.name,
            "severity": rule.severity,
            "triggered": rule.rule_id in triggered_ids,
        })

    return {
        "api_version": DASHBOARD_API_VERSION,
        "type": "nodechain_dashboard",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "overall_health": overall,
        "issue_count": len(issues),
        "issues": issues,
        "sections": sections,
        "rule_summary": rule_summary,
    }


def render_health_rules(dashboard: dict[str, Any]) -> str:
    """Render health rules in readable format."""
    lines: list[str] = []
    lines.append("")
    lines.append("  [bold]Health Rules[/]")
    lines.append(f"  {'─' * 50}")

    rule_summary = dashboard.get("rule_summary", [])
    for rule in rule_summary:
        triggered = rule["triggered"]
        rid = rule["rule_id"]
        name = rule["name"]
        severity = rule["severity"]

        if triggered:
            color = {"warning": "yellow", "degraded": "dark_yellow",
                     "critical": "red", "healthy": "green", "unknown": "dim"}.get(severity, "dim")
            lines.append(f"    [{color}]TRIGGERED[/] {rid} {name} ({severity})")
        else:
            lines.append(f"    [green]OK[/]       {rid} {name}")

    issues = dashboard.get("issues", [])
    if issues:
        lines.append("")
        lines.append(f"  [bold]Recommendations:[/]")
        for issue in issues:
            lines.append(f"    {issue['rule_id']}: {issue['recommendation']}")

    lines.append("")
    return "\n".join(lines)

