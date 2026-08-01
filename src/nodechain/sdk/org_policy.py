"""Organization Trust Policy Profiles (v2.4.0).

Named, enforceable trust policies that consolidate scattered governance
flags into a single declarative profile. Each profile controls:

  - allowed trust levels
  - required key purposes
  - remote registry allowance
  - required registry metadata signing
  - required package signing
  - required certification status
  - required transparency logging
  - dependency policy
  - sandbox minimum
  - deployment permission
  - evaluation suite requirements

NON-NEGOTIABLE RULE:
    profile declared ≠ profile enforced
    The profile must become an input to enforcement decisions.

Profiles are signed or digest-bound when applied. Application produces
a policy_profile_receipt that records what changed.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ── Trust levels (frozen ordering) ───────────────────────────────────────────

TRUST_LEVELS = ("built_in", "local_trusted", "local_untrusted", "remote_untrusted")

SANDBOX_STRENGTH: dict[str, int] = {
    "none": 0,
    "standard_untrusted": 2,
    "production_untrusted": 3,
    "hardened_untrusted": 4,
}


# ── Profile Model ────────────────────────────────────────────────────────────

@dataclass
class OrganizationTrustPolicyProfile:
    """Declarative trust policy for an organization.

    Every field is an enforcement directive, not documentation.
    When applied, the profile becomes an input to runtime gates.
    """
    name: str
    description: str
    version: str = "1.0.0"

    # Trust level controls
    allowed_trust_levels: list[str] = field(default_factory=lambda: list(TRUST_LEVELS))

    # Key/trust store controls
    required_key_purposes: list[str] = field(default_factory=list)

    # Remote registry controls
    allow_remote_registry: bool = True
    require_registry_metadata_signing: bool = False
    require_package_signing: bool = False

    # Certification controls
    require_certification: bool = False

    # Transparency controls
    require_transparency_logging: bool = False

    # Dependency controls
    allow_dependency_resolution: bool = True
    require_lockfile: bool = False

    # Sandbox controls
    sandbox_minimum: str = "standard_untrusted"

    # Deployment controls
    allow_deployment: bool = True

    # Evaluation controls
    required_eval_suites: list[str] = field(default_factory=list)

    # Reputation controls (v2.6.1 REP-FINDING-002: reputation is opt-in)
    use_registry_reputation: bool = False
    minimum_registry_grade: str = "C"

    # Discovery/marketplace controls (v2.7.0)
    allow_public_discovery: bool = True
    allowed_discovery_sources: list[str] = field(default_factory=list)
    require_signed_discovery_index: bool = False
    maximum_discovery_index_age: int = 0  # 0 = no limit
    allow_marketplace_registry_add: bool = True

    # Discovery signature controls (v2.7.2 + v2.7.3)
    # trusted_discovery_signers: fingerprints of keys authorized to sign
    #   discovery indexes. When require_discovery_signature_verification=True,
    #   the signer fingerprint must be in this list AND the signature must
    #   cryptographically verify against the matching public key.
    #   v2.7.3: Empty list fails closed unless allow_any_resolver_discovery_signer=True.
    trusted_discovery_signers: list[str] = field(default_factory=list)
    require_discovery_signature_verification: bool = False

    # v2.7.3: When True, any signer known to the resolver is accepted.
    # This is an explicit opt-in for resolver-wide trust.
    # Default False — strict profiles must define an explicit allowlist.
    allow_any_resolver_discovery_signer: bool = False

    # Supply chain attestation controls (v2.8.0)
    # Attestation is evidence. Attestation is not automatic trust.
    require_supply_chain_attestations: bool = False
    minimum_attestation_level: str = "none"  # none, source, build, provenance
    trusted_attestation_issuers: list[str] = field(default_factory=list)
    require_attestation_signature: bool = False
    # v2.8.1: When True, any issuer with a valid signature is accepted.
    # Default False — strict profiles must define an explicit issuer allowlist.
    allow_any_attestation_issuer: bool = False

    # Artifact retention controls (v2.9.0)
    require_evidence_index_verification: bool = False
    artifact_retention_policy_id: str = ""

    # Checkpoint signer controls (v2.10.3)
    # Empty list fails closed unless allow_any_checkpoint_signer=True.
    trusted_checkpoint_signers: list[str] = field(default_factory=list)
    require_checkpoint_signer_authorization: bool = False
    allow_any_checkpoint_signer: bool = False

    # Metadata
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "allowed_trust_levels": self.allowed_trust_levels,
            "required_key_purposes": self.required_key_purposes,
            "allow_remote_registry": self.allow_remote_registry,
            "require_registry_metadata_signing": self.require_registry_metadata_signing,
            "require_package_signing": self.require_package_signing,
            "require_certification": self.require_certification,
            "require_transparency_logging": self.require_transparency_logging,
            "allow_dependency_resolution": self.allow_dependency_resolution,
            "require_lockfile": self.require_lockfile,
            "sandbox_minimum": self.sandbox_minimum,
            "allow_deployment": self.allow_deployment,
            "required_eval_suites": self.required_eval_suites,
            "use_registry_reputation": self.use_registry_reputation,  # v2.6.2
            "minimum_registry_grade": self.minimum_registry_grade,  # v2.6.2
            "allow_public_discovery": self.allow_public_discovery,  # v2.7.0
            "allowed_discovery_sources": self.allowed_discovery_sources,  # v2.7.0
            "require_signed_discovery_index": self.require_signed_discovery_index,  # v2.7.0
            "maximum_discovery_index_age": self.maximum_discovery_index_age,  # v2.7.0
            "allow_marketplace_registry_add": self.allow_marketplace_registry_add,  # v2.7.0
            "trusted_discovery_signers": self.trusted_discovery_signers,  # v2.7.2
            "require_discovery_signature_verification": self.require_discovery_signature_verification,  # v2.7.2
            "allow_any_resolver_discovery_signer": self.allow_any_resolver_discovery_signer,  # v2.7.3
            "require_supply_chain_attestations": self.require_supply_chain_attestations,  # v2.8.0
            "minimum_attestation_level": self.minimum_attestation_level,  # v2.8.0
            "trusted_attestation_issuers": self.trusted_attestation_issuers,  # v2.8.0
            "require_attestation_signature": self.require_attestation_signature,  # v2.8.0
            "allow_any_attestation_issuer": self.allow_any_attestation_issuer,  # v2.8.1
            "require_evidence_index_verification": self.require_evidence_index_verification,  # v2.9.0
            "artifact_retention_policy_id": self.artifact_retention_policy_id,  # v2.9.0
            "trusted_checkpoint_signers": self.trusted_checkpoint_signers,  # v2.10.3
            "require_checkpoint_signer_authorization": self.require_checkpoint_signer_authorization,  # v2.10.3
            "allow_any_checkpoint_signer": self.allow_any_checkpoint_signer,  # v2.10.3
            "extra": self.extra,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> OrganizationTrustPolicyProfile:
        """Deserialize from dictionary."""
        return cls(
            name=d["name"],
            description=d.get("description", ""),
            version=d.get("version", "1.0.0"),
            allowed_trust_levels=d.get("allowed_trust_levels", list(TRUST_LEVELS)),
            required_key_purposes=d.get("required_key_purposes", []),
            allow_remote_registry=d.get("allow_remote_registry", True),
            require_registry_metadata_signing=d.get("require_registry_metadata_signing", False),
            require_package_signing=d.get("require_package_signing", False),
            require_certification=d.get("require_certification", False),
            require_transparency_logging=d.get("require_transparency_logging", False),
            allow_dependency_resolution=d.get("allow_dependency_resolution", True),
            require_lockfile=d.get("require_lockfile", False),
            sandbox_minimum=d.get("sandbox_minimum", "standard_untrusted"),
            allow_deployment=d.get("allow_deployment", True),
            required_eval_suites=d.get("required_eval_suites", []),
            use_registry_reputation=d.get("use_registry_reputation", False),  # v2.6.2
            minimum_registry_grade=d.get("minimum_registry_grade", "C"),  # v2.6.2
            allow_public_discovery=d.get("allow_public_discovery", True),  # v2.7.0
            allowed_discovery_sources=d.get("allowed_discovery_sources", []),  # v2.7.0
            require_signed_discovery_index=d.get("require_signed_discovery_index", False),  # v2.7.0
            maximum_discovery_index_age=d.get("maximum_discovery_index_age", 0),  # v2.7.0
            allow_marketplace_registry_add=d.get("allow_marketplace_registry_add", True),  # v2.7.0
            trusted_discovery_signers=d.get("trusted_discovery_signers", []),  # v2.7.2
            require_discovery_signature_verification=d.get("require_discovery_signature_verification", False),  # v2.7.2
            allow_any_resolver_discovery_signer=d.get("allow_any_resolver_discovery_signer", False),  # v2.7.3
            require_supply_chain_attestations=d.get("require_supply_chain_attestations", False),  # v2.8.0
            minimum_attestation_level=d.get("minimum_attestation_level", "none"),  # v2.8.0
            trusted_attestation_issuers=d.get("trusted_attestation_issuers", []),  # v2.8.0
            require_attestation_signature=d.get("require_attestation_signature", False),  # v2.8.0
            allow_any_attestation_issuer=d.get("allow_any_attestation_issuer", False),  # v2.8.1
            require_evidence_index_verification=d.get("require_evidence_index_verification", False),  # v2.9.0
            artifact_retention_policy_id=d.get("artifact_retention_policy_id", ""),  # v2.9.0
            trusted_checkpoint_signers=d.get("trusted_checkpoint_signers", []),  # v2.10.3
            require_checkpoint_signer_authorization=d.get("require_checkpoint_signer_authorization", False),  # v2.10.3
            allow_any_checkpoint_signer=d.get("allow_any_checkpoint_signer", False),  # v2.10.3
            extra=d.get("extra", {}),
        )

    def compute_digest(self) -> str:
        """Compute SHA-256 digest of the profile's canonical form."""
        canonical = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    # ── Enforcement checks ───────────────────────────────────────────────────

    def check_trust_level(self, trust_level: str) -> tuple[bool, str]:
        """Check if a trust level is allowed by this profile."""
        if trust_level in self.allowed_trust_levels:
            return True, ""
        return False, f"Trust level '{trust_level}' not in allowed: {self.allowed_trust_levels}"

    def check_remote_install(self) -> tuple[bool, str]:
        """Check if remote registry install is permitted."""
        if self.allow_remote_registry:
            return True, ""
        return False, "Remote registry install denied by policy profile"

    def check_registry_signing(self, signed: bool) -> tuple[bool, str]:
        """Check registry metadata signing requirement."""
        if not self.require_registry_metadata_signing:
            return True, ""
        if signed:
            return True, ""
        return False, "Registry metadata signing required but not present"

    def check_package_signing(self, signed: bool) -> tuple[bool, str]:
        """Check package signing requirement."""
        if not self.require_package_signing:
            return True, ""
        if signed:
            return True, ""
        return False, "Package signing required but not present"

    def check_certification(self, certified: bool) -> tuple[bool, str]:
        """Check certification requirement."""
        if not self.require_certification:
            return True, ""
        if certified:
            return True, ""
        return False, "Certification required but package is not certified"

    def check_transparency_logging(self, logged: bool) -> tuple[bool, str]:
        """Check transparency logging requirement."""
        if not self.require_transparency_logging:
            return True, ""
        if logged:
            return True, ""
        return False, "Transparency logging required but entry missing"

    def check_dependency_resolution(self) -> tuple[bool, str]:
        """Check if dependency resolution is permitted."""
        if self.allow_dependency_resolution:
            return True, ""
        return False, "Dependency resolution denied by policy profile"

    def check_lockfile(self, has_lockfile: bool) -> tuple[bool, str]:
        """Check if lockfile requirement is met."""
        if not self.require_lockfile:
            return True, ""
        if has_lockfile:
            return True, ""
        return False, "Lockfile required but not present"

    def check_key_purposes(self, available_purposes: list[str]) -> tuple[bool, str]:
        """Check if all required key purposes are available.

        Key purposes are strict — one purpose cannot satisfy another
        unless explicitly listed. This prevents key-purpose confusion.
        """
        if not self.required_key_purposes:
            return True, ""
        available = set(available_purposes)
        missing = [kp for kp in self.required_key_purposes if kp not in available]
        if not missing:
            return True, ""
        return False, f"Required key purposes missing: {missing}"

    def check_sandbox(self, sandbox_profile: str) -> tuple[bool, str]:
        """Check if sandbox profile meets the minimum requirement."""
        profile_strength = SANDBOX_STRENGTH.get(sandbox_profile, 0)
        minimum_strength = SANDBOX_STRENGTH.get(self.sandbox_minimum, 0)
        if profile_strength >= minimum_strength:
            return True, ""
        return False, (
            f"Sandbox '{sandbox_profile}' (strength {profile_strength}) "
            f"below minimum '{self.sandbox_minimum}' (strength {minimum_strength})"
        )

    def check_deployment(self) -> tuple[bool, str]:
        """Check if deployment is permitted."""
        if self.allow_deployment:
            return True, ""
        return False, "Deployment denied by policy profile"

    def check_eval_suites(self, completed_suites: list[str]) -> tuple[bool, str]:
        """Check if all required eval suites are completed."""
        if not self.required_eval_suites:
            return True, ""
        missing = [s for s in self.required_eval_suites if s not in completed_suites]
        if not missing:
            return True, ""
        return False, f"Required eval suites not completed: {missing}"

    def check_checkpoint_signer(
        self, signer_fingerprint: str,
    ) -> tuple[bool, str]:
        """Check if a checkpoint signer is authorized by this profile.

        v2.10.3: Organization-authorized checkpoint signing.
        Empty allowlist fails closed unless allow_any_checkpoint_signer=True.
        """
        if self.allow_any_checkpoint_signer:
            return True, ""

        if not self.trusted_checkpoint_signers:
            if self.require_checkpoint_signer_authorization:
                return False, (
                    "Checkpoint signer authorization required but no trusted "
                    "checkpoint signers configured"
                )
            return True, ""  # Not required

        if signer_fingerprint in self.trusted_checkpoint_signers:
            return True, ""

        return False, (
            f"Checkpoint signer fingerprint {signer_fingerprint} is not "
            f"in the trusted checkpoint signers list"
        )


# ── Built-in Profiles ────────────────────────────────────────────────────────

def _builtin_profiles() -> dict[str, OrganizationTrustPolicyProfile]:
    """Return all built-in profiles."""
    return {
        "permissive_local": OrganizationTrustPolicyProfile(
            name="permissive_local",
            description="Maximum flexibility for local development and experimentation. "
                        "All trust levels allowed, no signing required.",
            version="1.0.0",
            allowed_trust_levels=list(TRUST_LEVELS),
            allow_remote_registry=True,
            require_registry_metadata_signing=False,
            require_package_signing=False,
            require_certification=False,
            require_transparency_logging=False,
            allow_dependency_resolution=True,
            require_lockfile=False,
            sandbox_minimum="standard_untrusted",
            allow_deployment=True,
        ),
        "standard_team": OrganizationTrustPolicyProfile(
            name="standard_team",
            description="Balanced policy for team environments. "
                        "Remote registry allowed with signing requirements. "
                        "Certification recommended but not mandatory.",
            version="1.0.0",
            allowed_trust_levels=["built_in", "local_trusted", "local_untrusted", "remote_untrusted"],
            required_key_purposes=["registry_publishing"],
            allow_remote_registry=True,
            require_registry_metadata_signing=True,
            require_package_signing=False,
            require_certification=False,
            require_transparency_logging=True,
            allow_dependency_resolution=True,
            require_lockfile=True,
            sandbox_minimum="standard_untrusted",
            allow_deployment=True,
        ),
        "strict_enterprise": OrganizationTrustPolicyProfile(
            name="strict_enterprise",
            description="Strict policy for enterprise production. "
                        "All remote packages must be signed, certified, "
                        "and transparency-logged. Strong sandbox required.",
            version="1.0.0",
            allowed_trust_levels=["built_in", "local_trusted", "remote_untrusted"],
            required_key_purposes=[
                "registry_publishing", "certification_signing",
                "remote_registry_signing", "evidence_report_signing",
            ],
            allow_remote_registry=True,
            require_registry_metadata_signing=True,
            require_package_signing=True,
            require_certification=True,
            require_transparency_logging=True,
            allow_dependency_resolution=True,
            require_lockfile=True,
            sandbox_minimum="production_untrusted",
            allow_deployment=True,
            required_eval_suites=["trust_chain_eval"],
            use_registry_reputation=True,
            minimum_registry_grade="C",
            allow_public_discovery=True,
            require_signed_discovery_index=True,
            maximum_discovery_index_age=30,
            allow_marketplace_registry_add=False,
            require_discovery_signature_verification=True,
            require_supply_chain_attestations=True,
            minimum_attestation_level="build",
            require_attestation_signature=True,
            require_evidence_index_verification=True,
            require_checkpoint_signer_authorization=True,
        ),
        "airgapped_high_assurance": OrganizationTrustPolicyProfile(
            name="airgapped_high_assurance",
            description="Maximum assurance for airgapped or regulated environments. "
                        "No remote registry. No deployment from untrusted sources. "
                        "Strongest sandbox. Full signing and certification chain.",
            version="1.0.0",
            allowed_trust_levels=["built_in", "local_trusted"],
            required_key_purposes=[
                "registry_publishing", "certification_signing",
                "audit_bundle_signing", "attestation_signing",
                "evidence_report_signing", "evaluation_suite_signing",
            ],
            allow_remote_registry=False,
            require_registry_metadata_signing=True,
            require_package_signing=True,
            require_certification=True,
            require_transparency_logging=True,
            allow_dependency_resolution=False,
            require_lockfile=True,
            sandbox_minimum="hardened_untrusted",
            allow_deployment=False,
            required_eval_suites=[
                "trust_chain_eval", "sandbox_hardening_eval",
            ],
            use_registry_reputation=True,
            minimum_registry_grade="B",
            allow_public_discovery=False,
            require_signed_discovery_index=True,
            maximum_discovery_index_age=7,
            allow_marketplace_registry_add=False,
            require_discovery_signature_verification=True,
            require_supply_chain_attestations=True,
            minimum_attestation_level="provenance",
            require_attestation_signature=True,
            require_evidence_index_verification=True,
            require_checkpoint_signer_authorization=True,
        ),
    }


def get_builtin_profile(name: str) -> OrganizationTrustPolicyProfile | None:
    """Get a built-in profile by name. Returns None if not found."""
    return _builtin_profiles().get(name)


def list_builtin_profiles() -> list[str]:
    """List built-in profile names."""
    return sorted(_builtin_profiles().keys())


# ── Profile Application Receipt ──────────────────────────────────────────────

@dataclass
class PolicyProfileReceipt:
    """Receipt recording the application of a policy profile."""
    profile_name: str
    profile_digest: str
    applied_at: str
    applied_by: str = ""
    previous_profile_digest: str = ""
    affected_surfaces: list[str] = field(default_factory=list)
    receipt_digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = {
            "profile_name": self.profile_name,
            "profile_digest": self.profile_digest,
            "applied_at": self.applied_at,
            "applied_by": self.applied_by,
            "previous_profile_digest": self.previous_profile_digest,
            "affected_surfaces": self.affected_surfaces,
        }
        canonical = json.dumps(d, sort_keys=True, separators=(",", ":"))
        self.receipt_digest = hashlib.sha256(canonical.encode()).hexdigest()
        d["receipt_digest"] = self.receipt_digest
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> PolicyProfileReceipt:
        return cls(
            profile_name=d["profile_name"],
            profile_digest=d["profile_digest"],
            applied_at=d["applied_at"],
            applied_by=d.get("applied_by", ""),
            previous_profile_digest=d.get("previous_profile_digest", ""),
            affected_surfaces=d.get("affected_surfaces", []),
            receipt_digest=d.get("receipt_digest", ""),
        )


# ── Policy Surfaces ──────────────────────────────────────────────────────────

POLICY_SURFACES = [
    "trust_levels",
    "key_purposes",
    "remote_registry",
    "registry_signing",
    "package_signing",
    "certification",
    "transparency_logging",
    "dependency_resolution",
    "lockfile",
    "sandbox",
    "deployment",
    "evaluation_suites",
]


def get_affected_surfaces(
    old: OrganizationTrustPolicyProfile,
    new: OrganizationTrustPolicyProfile,
) -> list[str]:
    """Return list of policy surfaces that differ between old and new profiles."""
    affected = []
    if old.allowed_trust_levels != new.allowed_trust_levels:
        affected.append("trust_levels")
    if old.required_key_purposes != new.required_key_purposes:
        affected.append("key_purposes")
    if old.allow_remote_registry != new.allow_remote_registry:
        affected.append("remote_registry")
    if old.require_registry_metadata_signing != new.require_registry_metadata_signing:
        affected.append("registry_signing")
    if old.require_package_signing != new.require_package_signing:
        affected.append("package_signing")
    if old.require_certification != new.require_certification:
        affected.append("certification")
    if old.require_transparency_logging != new.require_transparency_logging:
        affected.append("transparency_logging")
    if old.allow_dependency_resolution != new.allow_dependency_resolution:
        affected.append("dependency_resolution")
    if old.require_lockfile != new.require_lockfile:
        affected.append("lockfile")
    if old.sandbox_minimum != new.sandbox_minimum:
        affected.append("sandbox")
    if old.allow_deployment != new.allow_deployment:
        affected.append("deployment")
    if old.required_eval_suites != new.required_eval_suites:
        affected.append("evaluation_suites")
    return affected


def diff_profiles(
    a: OrganizationTrustPolicyProfile,
    b: OrganizationTrustPolicyProfile,
) -> dict[str, dict[str, Any]]:
    """Return field-by-field diff between two profiles."""
    fields_to_compare = [
        "allowed_trust_levels", "required_key_purposes",
        "allow_remote_registry", "require_registry_metadata_signing",
        "require_package_signing", "require_certification",
        "require_transparency_logging", "allow_dependency_resolution",
        "require_lockfile", "sandbox_minimum", "allow_deployment",
        "required_eval_suites",
    ]
    diff = {}
    for f in fields_to_compare:
        va = getattr(a, f)
        vb = getattr(b, f)
        if va != vb:
            diff[f] = {"a": va, "b": vb}
    return diff


# ── Active Profile Store ─────────────────────────────────────────────────────

def get_active_profile_path() -> str:
    """Get the active profile path from env or default."""
    return os.environ.get(
        "NODECHAIN_ACTIVE_POLICY_PROFILE",
        os.path.join("data", "active_policy_profile.json"),
    )


def apply_profile(
    profile: OrganizationTrustPolicyProfile,
    applied_by: str = "",
    path: str | None = None,
) -> PolicyProfileReceipt:
    """Apply a profile and write the receipt.

    Returns the PolicyProfileReceipt.
    """
    path = path or get_active_profile_path()

    # Get previous profile digest if exists
    previous_digest = ""
    old_profile = None
    p = Path(path)
    if p.exists():
        try:
            old_data = json.loads(p.read_text(encoding="utf-8"))
            previous_digest = old_data.get("receipt", {}).get("profile_digest", "")
            if old_data.get("profile"):
                old_profile = OrganizationTrustPolicyProfile.from_dict(old_data["profile"])
        except Exception:
            pass

    profile_digest = profile.compute_digest()

    # Compute affected surfaces
    if old_profile:
        affected = get_affected_surfaces(old_profile, profile)
    else:
        affected = POLICY_SURFACES[:]  # All surfaces on initial apply

    receipt = PolicyProfileReceipt(
        profile_name=profile.name,
        profile_digest=profile_digest,
        applied_at=datetime.now(timezone.utc).isoformat(),
        applied_by=applied_by,
        previous_profile_digest=previous_digest,
        affected_surfaces=affected,
    )

    # Write active profile with receipt
    output = {
        "profile": profile.to_dict(),
        "receipt": receipt.to_dict(),
    }
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(p)

    return receipt


def get_active_profile(path: str | None = None) -> OrganizationTrustPolicyProfile | None:
    """Load the currently active policy profile. Returns None if not set."""
    path = path or get_active_profile_path()
    p = Path(path)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return OrganizationTrustPolicyProfile.from_dict(data.get("profile", {}))
    except Exception:
        return None


def get_active_profile_receipt(path: str | None = None) -> PolicyProfileReceipt | None:
    """Load the receipt for the currently active profile. Returns None if not set."""
    path = path or get_active_profile_path()
    p = Path(path)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        receipt_data = data.get("receipt", {})
        if not receipt_data:
            return None
        return PolicyProfileReceipt.from_dict(receipt_data)
    except Exception:
        return None


def validate_profile(profile: OrganizationTrustPolicyProfile) -> list[str]:
    """Validate a profile. Returns list of error strings (empty = valid)."""
    errors = []
    if not profile.name:
        errors.append("Profile name is required")
    if not profile.description:
        errors.append("Profile description is required")
    # Validate trust levels
    for tl in profile.allowed_trust_levels:
        if tl not in TRUST_LEVELS:
            errors.append(f"Invalid trust level: {tl}")
    # Validate sandbox minimum
    if profile.sandbox_minimum not in SANDBOX_STRENGTH:
        errors.append(f"Invalid sandbox minimum: {profile.sandbox_minimum}")
    return errors
