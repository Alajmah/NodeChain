"""Registry Reputation and Health Scoring (v2.6.0).

Local scoring signal for remote registries. Reputation informs selection
but does not create trust.

NON-NEGOTIABLE RULE:
    Reputation informs selection.
    Reputation does not create trust.

Score components (each explainable):
    availability
    metadata_freshness
    signature_validity
    transparency_consistency
    conflict_history
    revocation_responsiveness
    install_success_rate
    policy_compliance
    latency (optional)

Scoring grades:
    A: 90-100 (healthy)
    B: 75-89 (healthy with notes)
    C: 60-74 (warning)
    D: 40-59 (degraded)
    F: 0-39 (critical — deny in strict profiles)
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ── Constants ────────────────────────────────────────────────────────────────

REPUTATION_VERSION = "v1"

# Score component names
SCORE_COMPONENTS = frozenset({
    "availability",
    "metadata_freshness",
    "signature_validity",
    "transparency_consistency",
    "conflict_history",
    "revocation_responsiveness",
    "install_success_rate",
    "policy_compliance",
    "latency",  # optional
})

# Default weights (sum to 1.0)
DEFAULT_WEIGHTS: dict[str, float] = {
    "availability": 0.20,
    "metadata_freshness": 0.10,
    "signature_validity": 0.15,
    "transparency_consistency": 0.10,
    "conflict_history": 0.15,
    "revocation_responsiveness": 0.05,
    "install_success_rate": 0.15,
    "policy_compliance": 0.10,
}

# Grade thresholds
GRADE_A_MIN = 90
GRADE_B_MIN = 75
GRADE_C_MIN = 60
GRADE_D_MIN = 40


def grade_from_score(score: float) -> str:
    """Convert numeric score to letter grade."""
    if score >= GRADE_A_MIN:
        return "A"
    elif score >= GRADE_B_MIN:
        return "B"
    elif score >= GRADE_C_MIN:
        return "C"
    elif score >= GRADE_D_MIN:
        return "D"
    else:
        return "F"


class ReputationError(Exception):
    """Raised when reputation data is corrupt or invalid."""


# ── Score Component ──────────────────────────────────────────────────────────

@dataclass
class ScoreComponent:
    """A single explainable score component.

    Every component must have:
        value: 0-100 numeric score
        weight: 0.0-1.0 contribution to overall score
        reason: human-readable explanation
        evidence_reference: pointer to supporting evidence
    """
    name: str
    value: float  # 0-100
    weight: float  # 0.0-1.0
    reason: str
    evidence_reference: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "value": round(self.value, 2),
            "weight": self.weight,
            "reason": self.reason,
            "evidence_reference": self.evidence_reference,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ScoreComponent:
        return cls(
            name=d["name"],
            value=d["value"],
            weight=d["weight"],
            reason=d["reason"],
            evidence_reference=d["evidence_reference"],
        )


# ── Registry Health Score ────────────────────────────────────────────────────

@dataclass
class RegistryHealthScore:
    """Health score for a single registry.

    Attributes:
        registry_id: The registry this score applies to
        score: Weighted aggregate 0-100
        grade: Letter grade (A-F)
        last_checked: ISO timestamp
        components: List of ScoreComponent
        evidence_digest: SHA-256 of scoring inputs
        transparency_log_digest: SHA-256 of transparency log at scoring time
    """
    registry_id: str
    score: float
    grade: str
    last_checked: str
    components: list[ScoreComponent] = field(default_factory=list)
    evidence_digest: str = ""  # SHA-256 of raw ScoringInputs
    transparency_log_digest: str = ""
    score_digest: str = ""  # v2.6.1: SHA-256 of the score object itself (tamper seal)

    def to_dict(self) -> dict[str, Any]:
        return {
            "registry_id": self.registry_id,
            "score": round(self.score, 2),
            "grade": self.grade,
            "last_checked": self.last_checked,
            "components": [c.to_dict() for c in self.components],
            "evidence_digest": self.evidence_digest,
            "transparency_log_digest": self.transparency_log_digest,
            "score_digest": self.score_digest,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> RegistryHealthScore:
        return cls(
            registry_id=d["registry_id"],
            score=d["score"],
            grade=d["grade"],
            last_checked=d["last_checked"],
            components=[ScoreComponent.from_dict(c) for c in d.get("components", [])],
            evidence_digest=d.get("evidence_digest", ""),
            transparency_log_digest=d.get("transparency_log_digest", ""),
            score_digest=d.get("score_digest", ""),
        )

    def _digest_payload(self) -> dict[str, Any]:
        """Canonical fields covered by score_digest (excludes score_digest itself)."""
        return {
            "registry_id": self.registry_id,
            "score": round(self.score, 2),
            "grade": self.grade,
            "last_checked": self.last_checked,
            "components": [c.to_dict() for c in self.components],
            "evidence_digest": self.evidence_digest,
            "transparency_log_digest": self.transparency_log_digest,
        }

    def compute_digest(self) -> str:
        """Compute SHA-256 digest of this score for tamper detection.

        Covers all fields except score_digest itself.
        """
        canonical = json.dumps(self._digest_payload(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    def seal(self) -> None:
        """Compute and store the score_digest tamper seal."""
        self.score_digest = self.compute_digest()

    def round_score(self) -> None:
        """Round score to 2 decimal places in place."""
        self.score = round(self.score, 2)


# ── Scoring Inputs ───────────────────────────────────────────────────────────

@dataclass
class ScoringInputs:
    """Raw inputs for computing a registry health score.

    Each field maps to a score component. Values are 0-100 except where noted.
    """
    registry_id: str
    availability: float = 100.0
    metadata_freshness: float = 100.0
    signature_validity: float = 100.0
    transparency_consistency: float = 100.0
    conflict_history: float = 100.0  # 100 = no conflicts, 0 = many
    revocation_responsiveness: float = 100.0
    install_success_rate: float = 100.0
    policy_compliance: float = 100.0
    latency: float | None = None  # optional, 100 = fast, 0 = slow
    evidence_refs: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "registry_id": self.registry_id,
            "availability": self.availability,
            "metadata_freshness": self.metadata_freshness,
            "signature_validity": self.signature_validity,
            "transparency_consistency": self.transparency_consistency,
            "conflict_history": self.conflict_history,
            "revocation_responsiveness": self.revocation_responsiveness,
            "install_success_rate": self.install_success_rate,
            "policy_compliance": self.policy_compliance,
            "latency": self.latency,
            "evidence_refs": self.evidence_refs,
        }

    def compute_digest(self) -> str:
        """Compute SHA-256 digest of the raw inputs."""
        canonical = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()


def score_registry(inputs: ScoringInputs, transparency_log_digest: str = "") -> RegistryHealthScore:
    """Compute a registry health score from raw inputs.

    Every component is explainable: value, weight, reason, evidence_reference.
    """
    weights = dict(DEFAULT_WEIGHTS)

    # Build components
    components: list[ScoreComponent] = []

    def _ref(name: str) -> str:
        return inputs.evidence_refs.get(name, f"scoring:{inputs.registry_id}:{name}")

    def _add(name: str, value: float, weight: float, reason_template: str) -> None:
        if value >= 90:
            reason = reason_template.format(status="excellent")
        elif value >= 75:
            reason = reason_template.format(status="good")
        elif value >= 60:
            reason = reason_template.format(status="fair")
        elif value >= 40:
            reason = reason_template.format(status="poor")
        else:
            reason = reason_template.format(status="critical")
        components.append(ScoreComponent(
            name=name,
            value=value,
            weight=weight,
            reason=reason,
            evidence_reference=_ref(name),
        ))

    _add("availability", inputs.availability, weights["availability"],
         "Registry uptime is {status}")
    _add("metadata_freshness", inputs.metadata_freshness, weights["metadata_freshness"],
         "Metadata update recency is {status}")
    _add("signature_validity", inputs.signature_validity, weights["signature_validity"],
         "Metadata signature validity is {status}")
    _add("transparency_consistency", inputs.transparency_consistency,
         weights["transparency_consistency"],
         "Transparency log consistency is {status}")
    _add("conflict_history", inputs.conflict_history, weights["conflict_history"],
         "Cross-registry conflict rate is {status}")
    _add("revocation_responsiveness", inputs.revocation_responsiveness,
         weights["revocation_responsiveness"],
         "Revocation response time is {status}")
    _add("install_success_rate", inputs.install_success_rate,
         weights["install_success_rate"],
         "Installation success rate is {status}")
    _add("policy_compliance", inputs.policy_compliance, weights["policy_compliance"],
         "Policy compliance is {status}")

    if inputs.latency is not None:
        components.append(ScoreComponent(
            name="latency",
            value=inputs.latency,
            weight=0.0,  # optional, doesn't change weights
            reason=f"Response latency is {_qual(inputs.latency)}",
            evidence_reference=_ref("latency"),
        ))

    # Compute weighted score
    total_weight = sum(c.weight for c in components if c.weight > 0)
    if total_weight > 0:
        weighted_sum = sum(c.value * c.weight for c in components if c.weight > 0)
        score = weighted_sum / total_weight
    else:
        score = 0.0

    grade = grade_from_score(score)
    score = round(score, 2)

    result = RegistryHealthScore(
        registry_id=inputs.registry_id,
        score=score,
        grade=grade,
        last_checked=datetime.now(timezone.utc).isoformat(),
        components=components,
        evidence_digest=inputs.compute_digest(),
        transparency_log_digest=transparency_log_digest,
    )
    result.seal()  # v2.6.1: seal with score_digest
    return result


def _qual(value: float) -> str:
    """Qualitative label for a 0-100 value."""
    if value >= 90:
        return "excellent"
    elif value >= 75:
        return "good"
    elif value >= 60:
        return "fair"
    elif value >= 40:
        return "poor"
    else:
        return "critical"


# ── Reputation Store ─────────────────────────────────────────────────────────

class ReputationStore:
    """File-backed store for registry health scores."""

    def __init__(self, scores: dict[str, RegistryHealthScore] | None = None):
        self._scores: dict[str, RegistryHealthScore] = scores or {}

    def get(self, registry_id: str) -> RegistryHealthScore | None:
        return self._scores.get(registry_id)

    def set(self, score: RegistryHealthScore) -> None:
        self._scores[score.registry_id] = score

    def remove(self, registry_id: str) -> bool:
        return self._scores.pop(registry_id, None) is not None

    @property
    def all_scores(self) -> list[RegistryHealthScore]:
        return list(self._scores.values())

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": REPUTATION_VERSION,
            "scores": {k: v.to_dict() for k, v in self._scores.items()},
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ReputationStore:
        scores = {}
        for k, v in d.get("scores", {}).items():
            scores[k] = RegistryHealthScore.from_dict(v)
        return cls(scores=scores)


def get_reputation_store_path() -> str:
    """Get reputation store path from env or default."""
    return os.environ.get(
        "NODECHAIN_REPUTATION_STORE",
        os.path.join("data", "reputation_store.json"),
    )


def load_reputation_store(path: str | None = None) -> ReputationStore:
    """Load reputation store from file.

    Raises ReputationError if the file is corrupt.
    Returns empty store if file doesn't exist.
    """
    path = path or get_reputation_store_path()
    p = Path(path)
    if not p.exists():
        return ReputationStore()
    raw = p.read_text(encoding="utf-8")
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as e:
        raise ReputationError(
            f"Reputation store file is corrupt at {path}: {e}"
        ) from e
    if not isinstance(data, dict):
        raise ReputationError(
            f"Reputation store at {path} is not a valid JSON object"
        )
    return ReputationStore.from_dict(data)


def save_reputation_store(store: ReputationStore, path: str | None = None) -> str:
    """Save reputation store to file atomically."""
    path = path or get_reputation_store_path()
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(store.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(p)
    return str(p)


# ── Verification ─────────────────────────────────────────────────────────────

@dataclass
class ReputationVerifyResult:
    """Result of verifying a health score integrity."""
    valid: bool
    issues: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "issues": self.issues,
        }


def verify_health_score(score: RegistryHealthScore) -> ReputationVerifyResult:
    """Verify a health score's integrity.

    Checks:
    1. All required components present
    2. Weights sum to ~1.0
    3. Score matches weighted recomputation
    4. Grade matches score
    5. Evidence references are non-empty
    6. Digest matches content
    """
    issues: list[str] = []

    # Check required components
    present = {c.name for c in score.components}
    required = {c for c in SCORE_COMPONENTS if c != "latency"}
    missing = required - present
    if missing:
        issues.append(f"Missing required components: {', '.join(sorted(missing))}")

    # Check weights sum
    total_weight = sum(c.weight for c in score.components if c.weight > 0)
    if abs(total_weight - 1.0) > 0.01:
        issues.append(f"Weights sum to {total_weight:.4f}, expected ~1.0")

    # Check score matches recomputation
    if total_weight > 0:
        expected = sum(c.value * c.weight for c in score.components if c.weight > 0) / total_weight
        if abs(expected - score.score) > 1.0:
            issues.append(f"Score mismatch: computed {expected:.2f}, stored {score.score:.2f}")

    # Check grade
    expected_grade = grade_from_score(score.score)
    if expected_grade != score.grade:
        issues.append(f"Grade mismatch: computed {expected_grade}, stored {score.grade}")

    # Check evidence references
    for c in score.components:
        if not c.evidence_reference:
            issues.append(f"Component '{c.name}' has empty evidence_reference")
        if not c.reason:
            issues.append(f"Component '{c.name}' has empty reason")

    # v2.6.1 REP-FINDING-001: Verify score_digest tamper seal
    if not score.score_digest:
        issues.append("score_digest is missing (not sealed)")
    else:
        expected_score_digest = score.compute_digest()
        if expected_score_digest != score.score_digest:
            issues.append(
                f"score_digest mismatch: stored {score.score_digest[:16]}... "
                f"but recomputed {expected_score_digest[:16]}... (score tampered)"
            )

    return ReputationVerifyResult(
        valid=len(issues) == 0,
        issues=issues,
    )


def verify_reputation_store(store: ReputationStore) -> ReputationVerifyResult:
    """Verify all scores in a reputation store."""
    issues: list[str] = []
    for score in store.all_scores:
        result = verify_health_score(score)
        if not result.valid:
            issues.append(f"Registry '{score.registry_id}': {'; '.join(result.issues)}")
    return ReputationVerifyResult(valid=len(issues) == 0, issues=issues)


# ── Reputation Report ────────────────────────────────────────────────────────

@dataclass
class ReputationReport:
    """Aggregate reputation report across all registries."""
    version: str = REPUTATION_VERSION
    generated_at: str = ""
    scores: list[RegistryHealthScore] = field(default_factory=list)
    total_registries: int = 0
    healthy_count: int = 0
    warning_count: int = 0
    degraded_count: int = 0
    critical_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "generated_at": self.generated_at,
            "total_registries": self.total_registries,
            "healthy_count": self.healthy_count,
            "warning_count": self.warning_count,
            "degraded_count": self.degraded_count,
            "critical_count": self.critical_count,
            "scores": [s.to_dict() for s in self.scores],
        }


def generate_reputation_report(store: ReputationStore) -> ReputationReport:
    """Generate an aggregate reputation report from a store."""
    scores = store.all_scores
    report = ReputationReport(
        generated_at=datetime.now(timezone.utc).isoformat(),
        scores=scores,
        total_registries=len(scores),
    )
    for s in scores:
        if s.grade in ("A", "B"):
            report.healthy_count += 1
        elif s.grade == "C":
            report.warning_count += 1
        elif s.grade == "D":
            report.degraded_count += 1
        else:  # F
            report.critical_count += 1
    return report


# ── Federation Integration ───────────────────────────────────────────────────

def should_deny_by_reputation(
    score: RegistryHealthScore,
    org_profile: Any | None,
) -> tuple[bool, str]:
    """Check if a registry should be denied based on reputation + policy.

    Reputation is subordinate to hard verification gates.
    This function only applies AFTER signing, certification, digest,
    and conflict checks have already passed.

    Returns (deny, reason).
    """
    # F-grade registries are always deny-worthy
    if score.grade == "F":
        return True, f"Registry '{score.registry_id}' has critical reputation (F)"

    # Under strict profiles, D-grade may also deny
    if score.grade == "D" and org_profile:
        profile_name = getattr(org_profile, "name", "")
        if "strict" in profile_name.lower() or "airgapped" in profile_name.lower():
            return True, f"Registry '{score.registry_id}' degraded (D) under strict profile"

    return False, ""


def filter_by_reputation(
    candidates: list[Any],
    reputation_store: ReputationStore,
    org_profile: Any | None,
    min_grade: str = "C",
) -> tuple[list[Any], list[dict[str, str]]]:
    """Filter candidates by reputation score.

    NON-NEGOTIABLE: This is a ranking signal, not a trust gate.
    Candidates that pass hard verification are only filtered by
    reputation when the organization profile explicitly enables it.

    v2.6.1 REP-FINDING-002: filter is INACTIVE unless the active org
    profile has use_registry_reputation=True. Without that flag,
    all candidates are returned unchanged.

    Args:
        candidates: List of candidates with registry_id attribute.
        reputation_store: Store with health scores.
        org_profile: Organization policy profile.
        min_grade: Minimum acceptable grade.

    Returns:
        (filtered_candidates, rejected_with_reasons)
    """
    # v2.6.1 REP-FINDING-002: Reputation is opt-in via profile
    if org_profile is None:
        return list(candidates), []
    if not getattr(org_profile, "use_registry_reputation", False):
        return list(candidates), []

    # Read min grade from profile if available
    effective_min = getattr(org_profile, "minimum_registry_grade", min_grade)

    grade_order = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}

    filtered: list[Any] = []
    rejected: list[dict[str, str]] = []

    for c in candidates:
        score = reputation_store.get(c.registry_id)
        if score is None:
            # No score = no filtering by reputation (neutral)
            filtered.append(c)
            continue

        deny, reason = should_deny_by_reputation(score, org_profile)
        if deny:
            rejected.append({
                "registry_id": c.registry_id,
                "reason": f"Reputation: {reason} (score={score.score:.1f}, grade={score.grade})",
            })
            continue

        # Check minimum grade threshold
        if grade_order.get(score.grade, 4) > grade_order.get(effective_min, 2):
            rejected.append({
                "registry_id": c.registry_id,
                "reason": f"Reputation: grade {score.grade} below minimum {effective_min} (score={score.score:.1f})",
            })
            continue

        filtered.append(c)

    return filtered, rejected
