"""Capability Resolution and Governed Node Selection Tests (v2.21.3).

Tests CR-001 and the 10 non-negotiable rules, plus 13 acceptance criteria.
"""

from __future__ import annotations

import json
import pytest
from datetime import datetime, timezone

from nodechain.sdk.capability_resolver import (
    CapabilityRequest,
    CapabilityOffer,
    CapabilityResolutionPolicy,
    CapabilityResolver,
    CapabilitySelectionReceipt,
    CapabilityPin,
    CandidateScore,
    GovernedEvidence,
    pin_capability,
    check_capability_drift,
    save_selection_receipt,
    save_capability_pin,
    # Constants
    CAPABILITY_SCHEMA_VERSION,
    REJECT_CONTRACT_MISMATCH,
    REJECT_REVOKED,
    REJECT_DEPRECATED_DISALLOWED,
    REJECT_UNCERTIFIED,
    REJECT_UNTRUSTED_REGISTRY,
    REJECT_UNAPPROVED_PUBLISHER,
    REJECT_FORBIDDEN_CAPABILITY,
    REJECT_SANDBOX_DOWNGRADE,
    REJECT_DT001_FAILED,
    REJECT_RISK_TOO_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    RISK_HIGH,
    RISK_CRITICAL,
    TRUST_LEVEL_BUILT_IN,
    TRUST_LEVEL_LOCAL_TRUSTED,
    TRUST_LEVEL_LOCAL_UNTRUSTED,
    TRUST_LEVEL_REMOTE_UNTRUSTED,
)


# ── Helpers ─────────────────────────────────────────────────────────────────

def _offer(
    package_id: str,
    capability: str = "incident.severity.triage",
    version: str = "1.0.0",
    **kwargs,
) -> CapabilityOffer:
    defaults = dict(
        package_id=package_id,
        version=version,
        capabilities=[capability],
        input_contracts=["AnomalySet@1"],
        output_contracts=["SeverityAssessment@1"],
        risk_level=RISK_MEDIUM,
        sandbox_profile="hardened_untrusted",
        evaluation_score=0.9,
        certification_digest="sha256:cert",
        publisher_fingerprint="fp-publisher",
        registry_id="reg-001",
        trust_level=TRUST_LEVEL_LOCAL_TRUSTED,
        lifecycle="active",
        dependency_graph_admissible=True,
        dependency_graph_digest="sha256:graph",
    )
    defaults.update(kwargs)
    return CapabilityOffer(**defaults)


def _request(capability: str = "incident.severity.triage", **kwargs) -> CapabilityRequest:
    defaults = dict(
        capability=capability,
        input_contract="AnomalySet@1",
        output_contract="SeverityAssessment@1",
        certification_required=True,
        max_risk=RISK_HIGH,
        required_sandbox="hardened_untrusted",
    )
    defaults.update(kwargs)
    return CapabilityRequest(**defaults)


class MockOfferProvider:
    def __init__(self, offers: list[CapabilityOffer]):
        self._offers = offers

    def __call__(self, capability: str) -> list[CapabilityOffer]:
        return [o for o in self._offers if capability in o.capabilities]


def _evidence_for(offer: CapabilityOffer) -> GovernedEvidence:
    """Create governed evidence mirroring an offer's declared attributes.

    In production these values come from evaluation suites, registry attestations,
    and certification authorities — not from the package itself. In tests we
    use this to provide governed evidence so CR-002 is satisfied.
    """
    return GovernedEvidence(
        package_id=offer.package_id,
        version=offer.version,
        verified_evaluation_score=offer.evaluation_score,
        verified_trust_level=offer.trust_level,
        verified_certification_digest=offer.certification_digest,
        verified_risk_level=offer.risk_level,
        evidence_source="test_evidence_authority",
        evidence_digest=f"sha256:ev_{offer.package_id}_{offer.version}",
    )


class MockEvidenceProvider:
    """Evidence provider that returns governed evidence for known offers."""

    def __init__(self, offers: list[CapabilityOffer] | None = None):
        self._offers = offers or []

    def __call__(self, package_id: str, version: str) -> GovernedEvidence | None:
        for o in self._offers:
            if o.package_id == package_id and o.version == version:
                return _evidence_for(o)
        return None


def _make_resolver(offers, policy=None):
    """Create a resolver with evidence provider matching the given offers.

    CR-002 require_governed_evidence defaults to True, so all tests
    that expect scoring must supply governed evidence.
    """
    provider = MockOfferProvider(offers)
    ev_provider = MockEvidenceProvider(offers)
    return CapabilityResolver(
        offer_provider=provider,
        policy=policy,
        evidence_provider=ev_provider,
    )


# ── AC-1: Package manifests can declare CapabilityOffers ────────────────────

class TestAC1CapabilityOfferDeclaration:
    """AC-1: Package manifests can declare CapabilityOffers."""

    def test_offer_has_capabilities(self):
        o = _offer("pkg_a", capability="search.query")
        assert "search.query" in o.capabilities

    def test_offer_has_contracts(self):
        o = _offer("pkg_a")
        assert "AnomalySet@1" in o.input_contracts
        assert "SeverityAssessment@1" in o.output_contracts

    def test_offer_identity_key(self):
        o = _offer("pkg_a", version="2.0.0")
        assert o.identity_key() == "pkg_a@2.0.0"

    def test_offer_to_dict(self):
        o = _offer("pkg_a")
        d = o.to_dict()
        assert d["package_id"] == "pkg_a"
        assert d["version"] == "1.0.0"


# ── AC-2: Resolver accepts CapabilityRequest ────────────────────────────────

class TestAC2CapabilityRequest:
    """AC-2: Resolver accepts CapabilityRequest."""

    def test_request_has_capability(self):
        r = _request()
        assert r.capability == "incident.severity.triage"

    def test_request_digest_deterministic(self):
        r1 = _request()
        r2 = _request()
        assert r1.compute_digest() == r2.compute_digest()

    def test_request_digest_changes_with_capability(self):
        r1 = _request(capability="a.b.c")
        r2 = _request(capability="x.y.z")
        assert r1.compute_digest() != r2.compute_digest()


# ── AC-3: Candidate discovery across local and remote ───────────────────────

class TestAC3CandidateDiscovery:
    """AC-3: Candidate discovery works across local and remote registries."""

    def test_discovers_matching_capability(self):
        offers = [
            _offer("pkg_a", capability="search.query"),
            _offer("pkg_b", capability="search.query"),
            _offer("pkg_c", capability="different.cap"),
        ]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        scores, receipt = r.resolve(_request(capability="search.query"))
        assert len(scores) == 2  # Only matching capability

    def test_empty_discovery(self):
        provider = MockOfferProvider([])
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        scores, receipt = r.resolve(_request())
        assert len(scores) == 0
        assert receipt is not None
        assert not receipt.selected_package_id  # No selection


# ── AC-4: Every candidate evaluated through dependency trust resolver ───────

class TestAC4DependencyGraphCheck:
    """AC-4: Every candidate is evaluated through the dependency trust resolver."""

    def test_dt001_failed_rejected(self):
        offers = [_offer("pkg_a", dependency_graph_admissible=False)]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        scores, receipt = r.resolve(_request())
        assert not scores[0].passed_hard_filters
        assert REJECT_DT001_FAILED in scores[0].rejection_reasons

    def test_dt001_passed_admitted(self):
        offers = [_offer("pkg_a", dependency_graph_admissible=True)]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        scores, receipt = r.resolve(_request())
        assert scores[0].passed_hard_filters


# ── AC-5: Hard filters ──────────────────────────────────────────────────────

class TestAC5HardFilters:
    """AC-5: Hard filters reject all defined conditions."""

    def test_contract_mismatch_capability(self):
        # Provider that returns all offers regardless of capability filter
        offers = [_offer("pkg_a", capabilities=["different.cap"])]
        provider = lambda cap: offers  # Return all
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(offers))
        scores, _ = r.resolve(_request(capability="incident.severity.triage"))
        assert REJECT_CONTRACT_MISMATCH in scores[0].rejection_reasons

    def test_contract_mismatch_input(self):
        offers = [_offer("pkg_a", input_contracts=["WrongContract@1"])]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        scores, _ = r.resolve(_request())
        assert REJECT_CONTRACT_MISMATCH in scores[0].rejection_reasons

    def test_revoked_rejected(self):
        offers = [_offer("pkg_a", lifecycle="revoked")]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        scores, _ = r.resolve(_request())
        assert REJECT_REVOKED in scores[0].rejection_reasons

    def test_deprecated_disallowed(self):
        offers = [_offer("pkg_a", lifecycle="deprecated")]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        scores, _ = r.resolve(_request())
        assert REJECT_DEPRECATED_DISALLOWED in scores[0].rejection_reasons

    def test_uncertified_rejected(self):
        offers = [_offer("pkg_a", certification_digest="")]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        scores, _ = r.resolve(_request(certification_required=True))
        assert REJECT_UNCERTIFIED in scores[0].rejection_reasons

    def test_untrusted_registry_rejected(self):
        offers = [_offer("pkg_a", registry_id="reg-evil")]
        policy = CapabilityResolutionPolicy(trusted_registries=["reg-001"])
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, policy=policy, evidence_provider=MockEvidenceProvider(provider._offers))
        scores, _ = r.resolve(_request())
        assert REJECT_UNTRUSTED_REGISTRY in scores[0].rejection_reasons

    def test_unapproved_publisher_rejected(self):
        offers = [_offer("pkg_a", publisher_fingerprint="fp-evil")]
        policy = CapabilityResolutionPolicy(trusted_publishers=["fp-good"])
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, policy=policy, evidence_provider=MockEvidenceProvider(provider._offers))
        scores, _ = r.resolve(_request())
        assert REJECT_UNAPPROVED_PUBLISHER in scores[0].rejection_reasons

    def test_forbidden_capability_rejected(self):
        offers = [_offer("pkg_a", capabilities=["incident.severity.triage", "network.egress"])]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        scores, _ = r.resolve(_request(forbidden_capabilities=["network.egress"]))
        assert REJECT_FORBIDDEN_CAPABILITY in scores[0].rejection_reasons

    def test_sandbox_downgrade_rejected(self):
        offers = [_offer("pkg_a", sandbox_profile="none")]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        scores, _ = r.resolve(_request(required_sandbox="hardened_untrusted"))
        assert REJECT_SANDBOX_DOWNGRADE in scores[0].rejection_reasons

    def test_risk_too_high_rejected(self):
        offers = [_offer("pkg_a", risk_level=RISK_CRITICAL)]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        scores, _ = r.resolve(_request(max_risk=RISK_MEDIUM))
        assert REJECT_RISK_TOO_HIGH in scores[0].rejection_reasons

    def test_remote_untrusted_without_sandbox(self):
        offers = [_offer(
            "pkg_a",
            trust_level=TRUST_LEVEL_REMOTE_UNTRUSTED,
            sandbox_profile="none",
        )]
        policy = CapabilityResolutionPolicy(forbid_remote_untrusted_without_sandbox=True)
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, policy=policy, evidence_provider=MockEvidenceProvider(provider._offers))
        scores, _ = r.resolve(_request(required_sandbox=""))
        assert REJECT_SANDBOX_DOWNGRADE in scores[0].rejection_reasons


# ── AC-5b: CR-005: Score cannot override policy denial ──────────────────────

class TestAC5bScoreNotOverridePolicy:
    """CR-005: A higher score cannot override a policy denial."""

    def test_revoked_high_score_still_rejected(self):
        # High-scoring revoked package must still be rejected
        offers = [
            _offer("pkg_revoked", lifecycle="revoked", evaluation_score=0.99),
            _offer("pkg_ok", evaluation_score=0.5),
        ]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        scores, receipt = r.resolve(_request())
        # The ok package should be selected
        assert receipt.selected_package_id == "pkg_ok"

        # The revoked package should be rejected despite higher score
        revoked_score = [s for s in scores if s.offer.package_id == "pkg_revoked"][0]
        assert not revoked_score.passed_hard_filters


# ── AC-6: Scoring is deterministic and policy-defined ───────────────────────

class TestAC6DeterministicScoring:
    """AC-6: Scoring is deterministic and policy-defined."""

    def test_same_inputs_same_order(self):
        offers = [
            _offer("pkg_a", evaluation_score=0.95, risk_level=RISK_LOW),
            _offer("pkg_b", evaluation_score=0.5, risk_level=RISK_LOW),
        ]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))

        _, receipt1 = r.resolve(_request())
        _, receipt2 = r.resolve(_request())
        assert receipt1.selected_package_id == receipt2.selected_package_id
        assert receipt1.selected_package_id == "pkg_a"  # Higher score

    def test_score_dimensions_present(self):
        offers = [_offer("pkg_a")]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        scores, _ = r.resolve(_request())
        dims = scores[0].dimension_scores
        assert "contract_fit" in dims
        assert "evaluation_score" in dims
        assert "certification_recency" in dims
        assert "trust_level" in dims
        assert "risk" in dims
        assert "latency_cost" in dims

    def test_policy_weights_affect_scoring(self):
        offers = [_offer("pkg_a", evaluation_score=0.5)]
        policy = CapabilityResolutionPolicy(weights={"evaluation_score": 100.0})
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, policy=policy, evidence_provider=MockEvidenceProvider(provider._offers))
        scores, _ = r.resolve(_request())
        # With evaluation_score weighted 100%, score should be proportional
        assert scores[0].dimension_scores["evaluation_score"] > 0


# ── AC-7: Deterministic tie-breaking ────────────────────────────────────────

class TestAC7TieBreaking:
    """AC-7: Tie-breaking is deterministic."""

    def test_tiebreak_by_evaluation_score(self):
        offers = [
            _offer("pkg_a", evaluation_score=0.5, risk_level=RISK_LOW),
            _offer("pkg_b", evaluation_score=0.95, risk_level=RISK_LOW),  # Higher eval
        ]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        _, receipt = r.resolve(_request())
        assert receipt.selected_package_id == "pkg_b"

    def test_tiebreak_by_trust_level(self):
        offers = [
            _offer("pkg_a", trust_level=TRUST_LEVEL_LOCAL_TRUSTED, evaluation_score=0.5, risk_level=RISK_LOW),
            _offer("pkg_b", trust_level=TRUST_LEVEL_BUILT_IN, evaluation_score=0.5, risk_level=RISK_LOW),
        ]
        provider = MockOfferProvider(offers)
        policy = CapabilityResolutionPolicy(review_score_margin_below=0.0)
        r = CapabilityResolver(offer_provider=provider, policy=policy, evidence_provider=MockEvidenceProvider(provider._offers))
        _, receipt = r.resolve(_request())
        assert receipt.selected_package_id == "pkg_b"

    def test_tiebreak_by_identity(self):
        """When all else equal, stable identity ordering."""
        offers = [
            _offer("zzz_pkg", evaluation_score=0.9, risk_level=RISK_LOW),
            _offer("aaa_pkg", evaluation_score=0.9, risk_level=RISK_LOW),
        ]
        # When truly tied, the review margin trigger fires, but we check the top candidate
        # is the alphabetically-first one
        provider = MockOfferProvider(offers)
        policy = CapabilityResolutionPolicy(review_score_margin_below=0.0)  # Disable margin review
        r = CapabilityResolver(offer_provider=provider, policy=policy, evidence_provider=MockEvidenceProvider(provider._offers))
        _, receipt = r.resolve(_request())
        assert receipt.selected_package_id == "aaa_pkg"

    def test_preferred_publisher_overrides(self):
        offers = [
            _offer("pkg_a", publisher_fingerprint="fp-A", evaluation_score=0.9, risk_level=RISK_LOW),
            _offer("pkg_b", publisher_fingerprint="fp-B", evaluation_score=0.9, risk_level=RISK_LOW),
        ]
        policy = CapabilityResolutionPolicy(
            preferred_publishers=["fp-B"],
            review_score_margin_below=0.0,
        )
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, policy=policy, evidence_provider=MockEvidenceProvider(provider._offers))
        _, receipt = r.resolve(_request())
        assert receipt.selected_package_id == "pkg_b"


# ── AC-8: Human review requirements ─────────────────────────────────────────

class TestAC8HumanReview:
    """AC-8: Human review is required under specific conditions."""

    def test_high_risk_requires_review(self):
        offers = [_offer("pkg_a", risk_level=RISK_HIGH)]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        scores, receipt = r.resolve(_request())
        assert receipt.human_review_required
        assert receipt.human_review_status == "pending"
        assert not receipt.selected_package_id  # Not selected

    def test_external_publisher_requires_review(self):
        offers = [_offer("pkg_a", trust_level=TRUST_LEVEL_REMOTE_UNTRUSTED)]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        scores, receipt = r.resolve(_request())
        assert receipt.human_review_required

    def test_narrow_margin_requires_review(self):
        offers = [
            _offer("pkg_a", evaluation_score=0.90),
            _offer("pkg_b", evaluation_score=0.89),
        ]
        policy = CapabilityResolutionPolicy(review_score_margin_below=5.0)
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, policy=policy, evidence_provider=MockEvidenceProvider(provider._offers))
        _, receipt = r.resolve(_request())
        assert receipt.human_review_required

    def test_low_risk_local_no_review(self):
        offers = [_offer("pkg_a", risk_level=RISK_LOW, trust_level=TRUST_LEVEL_LOCAL_TRUSTED)]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        _, receipt = r.resolve(_request())
        assert not receipt.human_review_required
        assert receipt.selected_package_id == "pkg_a"


# ── AC-9: Selection receipt ─────────────────────────────────────────────────

class TestAC9SelectionReceipt:
    """AC-9: Selection receipt records all required fields."""

    def test_receipt_has_request_digest(self):
        offers = [_offer("pkg_a")]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        req = _request()
        _, receipt = r.resolve(req)
        assert receipt.request_digest == req.compute_digest()

    def test_receipt_has_selected_package(self):
        offers = [_offer("pkg_a")]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        _, receipt = r.resolve(_request())
        assert receipt.selected_package_id == "pkg_a"
        assert receipt.selected_version == "1.0.0"

    def test_receipt_has_policy_digest(self):
        offers = [_offer("pkg_a")]
        policy = CapabilityResolutionPolicy(policy_id="test-policy")
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, policy=policy, evidence_provider=MockEvidenceProvider(provider._offers))
        _, receipt = r.resolve(_request())
        assert receipt.policy_digest == policy.compute_digest()

    def test_receipt_has_candidate_scores(self):
        offers = [_offer("pkg_a"), _offer("pkg_b")]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        _, receipt = r.resolve(_request())
        assert len(receipt.candidate_scores) == 2

    def test_receipt_has_rejected_in_explain_mode(self):
        offers = [
            _offer("pkg_a"),
            _offer("pkg_revoked", lifecycle="revoked"),
        ]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        _, receipt = r.resolve(_request(), explain=True)
        assert len(receipt.rejected_candidates) > 0

    def test_receipt_has_signature(self):
        offers = [_offer("pkg_a")]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        _, receipt = r.resolve(_request())
        assert receipt.signature != ""
        assert len(receipt.signature) == 64  # SHA-256 hex

    def test_receipt_has_rationale(self):
        offers = [_offer("pkg_a")]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        _, receipt = r.resolve(_request())
        assert "Selected" in receipt.selection_rationale


# ── AC-10: Blueprint can pin selected capability resolution ────────────────

class TestAC10BlueprintPinning:
    """AC-10: Blueprint can pin selected capability resolution."""

    def test_pin_from_receipt(self):
        offers = [_offer("pkg_a")]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        _, receipt = r.resolve(_request())
        pin = pin_capability("incident.severity.triage", receipt)
        assert pin is not None
        assert pin.capability == "incident.severity.triage"
        assert pin.package_id == "pkg_a"
        assert pin.version == "1.0.0"

    def test_pin_none_when_no_selection(self):
        offers = [_offer("pkg_a", risk_level=RISK_HIGH)]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        _, receipt = r.resolve(_request())
        pin = pin_capability("test.cap", receipt)
        assert pin is None  # Review pending

    def test_pin_to_dict(self):
        pin = CapabilityPin(
            capability="test.cap",
            package_id="pkg",
            version="1.0.0",
            lockfile_digest="sha256:lf",
            receipt_digest="r-001",
        )
        d = pin.to_dict()
        assert d["capability"] == "test.cap"
        assert d["package_id"] == "pkg"


# ── AC-11: Drift detection ──────────────────────────────────────────────────

class TestAC11SelectionDrift:
    """AC-11: Selection drift from pinned resolution."""

    def test_no_drift_same_selection(self):
        pin = CapabilityPin(
            capability="test.cap",
            package_id="pkg_a",
            version="1.0.0",
            lockfile_digest="sha256:lf",
            receipt_digest="r-001",
        )
        receipt = CapabilitySelectionReceipt(
            selected_package_id="pkg_a",
            selected_version="1.0.0",
            selected_lockfile_digest="sha256:lf",
        )
        assert not check_capability_drift(pin, receipt)

    def test_drift_different_package(self):
        pin = CapabilityPin(
            capability="test.cap",
            package_id="pkg_a",
            version="1.0.0",
            lockfile_digest="sha256:lf",
            receipt_digest="r-001",
        )
        receipt = CapabilitySelectionReceipt(
            selected_package_id="pkg_b",  # Different!
            selected_version="1.0.0",
            selected_lockfile_digest="sha256:lf",
        )
        assert check_capability_drift(pin, receipt)

    def test_drift_different_version(self):
        pin = CapabilityPin(
            capability="test.cap",
            package_id="pkg_a",
            version="1.0.0",
            lockfile_digest="sha256:lf",
            receipt_digest="r-001",
        )
        receipt = CapabilitySelectionReceipt(
            selected_package_id="pkg_a",
            selected_version="2.0.0",  # Different!
            selected_lockfile_digest="sha256:lf",
        )
        assert check_capability_drift(pin, receipt)

    def test_drift_different_lockfile(self):
        pin = CapabilityPin(
            capability="test.cap",
            package_id="pkg_a",
            version="1.0.0",
            lockfile_digest="sha256:lf",
            receipt_digest="r-001",
        )
        receipt = CapabilitySelectionReceipt(
            selected_package_id="pkg_a",
            selected_version="1.0.0",
            selected_lockfile_digest="sha256:CHANGED",
        )
        assert check_capability_drift(pin, receipt)


# ── AC-12: Dashboard health rules ───────────────────────────────────────────

class TestAC12DashboardRules:
    """AC-12: Dashboard exposes capability resolution health rules."""

    def test_all_5_rules_registered(self):
        from nodechain.cli.dashboard_health import ALL_RULES, RULES_BY_ID
        for rid in ["HR-035", "HR-036", "HR-037", "HR-038", "HR-039"]:
            assert rid in RULES_BY_ID

    def test_total_rule_count(self):
        from nodechain.cli.dashboard_health import ALL_RULES
        assert len(ALL_RULES) == 65  # 49 HR + 5 MEM + 6 SE + 5 MR (v2.41.0)

    def test_hr035_unresolved_capability(self):
        from nodechain.cli.dashboard_health import HR035UnresolvedCapabilityRequest
        rule = HR035UnresolvedCapabilityRequest()
        result = rule.evaluate({
            "capability_resolution": {"enabled": True, "unresolved_requests": 1}
        })
        assert result is not None
        assert result["rule_id"] == "HR-035"

    def test_hr035_no_alert_when_ok(self):
        from nodechain.cli.dashboard_health import HR035UnresolvedCapabilityRequest
        rule = HR035UnresolvedCapabilityRequest()
        result = rule.evaluate({
            "capability_resolution": {"enabled": True, "unresolved_requests": 0}
        })
        assert result is None

    def test_hr036_ambiguous_selection(self):
        from nodechain.cli.dashboard_health import HR036AmbiguousSelection
        rule = HR036AmbiguousSelection()
        result = rule.evaluate({
            "capability_resolution": {"enabled": True, "ambiguous_selections": 2}
        })
        assert result is not None
        assert result["rule_id"] == "HR-036"

    def test_hr037_high_risk_selected(self):
        from nodechain.cli.dashboard_health import HR037HighRiskSelectedNode
        rule = HR037HighRiskSelectedNode()
        result = rule.evaluate({
            "capability_resolution": {"enabled": True, "high_risk_selections": 1}
        })
        assert result is not None

    def test_hr038_deprecated_selected(self):
        from nodechain.cli.dashboard_health import HR038SelectedDeprecatedNode
        rule = HR038SelectedDeprecatedNode()
        result = rule.evaluate({
            "capability_resolution": {"enabled": True, "deprecated_selections": 1}
        })
        assert result is not None

    def test_hr039_selection_drift(self):
        from nodechain.cli.dashboard_health import HR039SelectionDrift
        rule = HR039SelectionDrift()
        result = rule.evaluate({
            "capability_resolution": {"enabled": True, "selection_drift_count": 1}
        })
        assert result is not None


# ── CR-001: Trust does not flow transitively ────────────────────────────────

class TestCR001:
    """CR-001: Capability selection is admissible only among candidates whose
    complete package graph has already passed dependency trust resolution."""

    def test_candidate_with_failed_graph_rejected(self):
        offers = [
            _offer("pkg_good", dependency_graph_admissible=True, evaluation_score=0.5),
            _offer("pkg_bad", dependency_graph_admissible=False, evaluation_score=0.99),
        ]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        scores, receipt = r.resolve(_request())
        # High-score bad candidate rejected
        assert receipt.selected_package_id == "pkg_good"
        bad_score = [s for s in scores if s.offer.package_id == "pkg_bad"][0]
        assert not bad_score.passed_hard_filters

    def test_all_candidates_must_pass_dt001(self):
        offers = [
            _offer("pkg_a", dependency_graph_admissible=False),
            _offer("pkg_b", dependency_graph_admissible=False),
        ]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        _, receipt = r.resolve(_request())
        assert not receipt.selected_package_id  # No admissible candidate


# ── CR-003: Selection by resolver, not by candidate nodes ──────────────────

class TestCR003:
    """CR-003: Capability selection is performed by the resolver."""

    def test_resolver_makes_selection(self):
        offers = [_offer("pkg_a", evaluation_score=0.5, risk_level=RISK_LOW),
                  _offer("pkg_b", evaluation_score=0.95, risk_level=RISK_LOW)]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        _, receipt = r.resolve(_request())
        # Resolver selected the higher-scoring one
        assert receipt.selected_package_id == "pkg_b"

    def test_offer_cannot_self_select(self):
        """Offers are passive data; they cannot influence selection beyond their attributes."""
        offers = [_offer("pkg_a")]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        # The resolver is the only one making decisions
        scores, receipt = r.resolve(_request())
        assert receipt.selected_package_id == "pkg_a"
        # Score is computed by resolver, not by the offer
        assert scores[0].total_score > 0


# ── CR-009: Version-pinned selection ────────────────────────────────────────

class TestCR009:
    """CR-009: The chosen package must be version-pinned."""

    def test_selection_includes_version(self):
        offers = [_offer("pkg_a", version="3.2.1")]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        _, receipt = r.resolve(_request())
        assert receipt.selected_version == "3.2.1"

    def test_pin_includes_version(self):
        offers = [_offer("pkg_a", version="3.2.1")]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        _, receipt = r.resolve(_request())
        pin = pin_capability("test.cap", receipt)
        assert pin.version == "3.2.1"


# ── Persistence tests ───────────────────────────────────────────────────────

class TestPersistence:
    """Save/load selection receipts and capability pins."""

    def test_save_receipt(self, tmp_path):
        offers = [_offer("pkg_a")]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        _, receipt = r.resolve(_request())
        path = str(tmp_path / "receipt.json")
        save_selection_receipt(receipt, path)
        loaded = json.loads(open(path).read())
        assert loaded["selected_package_id"] == "pkg_a"

    def test_save_pin(self, tmp_path):
        pin = CapabilityPin(
            capability="test.cap",
            package_id="pkg",
            version="1.0.0",
            lockfile_digest="sha256:lf",
            receipt_digest="r-001",
        )
        path = str(tmp_path / "pin.json")
        save_capability_pin(pin, path)
        loaded = json.loads(open(path).read())
        assert loaded["package_id"] == "pkg"


# ── Multi-candidate scenario ────────────────────────────────────────────────

class TestMultiCandidateScenario:
    """Realistic multi-candidate resolution."""

    def test_three_candidates_picks_best(self):
        offers = [
            _offer("pkg_a", evaluation_score=0.5, risk_level=RISK_LOW),
            _offer("pkg_b", evaluation_score=0.95, risk_level=RISK_LOW),
            _offer("pkg_c", evaluation_score=0.6, risk_level=RISK_LOW),
        ]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        scores, receipt = r.resolve(_request())
        assert receipt.selected_package_id == "pkg_b"

    def test_rejected_candidate_in_explain(self):
        offers = [
            _offer("pkg_good"),
            _offer("pkg_revoked", lifecycle="revoked"),
            _offer("pkg_uncertified", certification_digest=""),
        ]
        provider = MockOfferProvider(offers)
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        scores, receipt = r.resolve(_request(), explain=True)
        assert receipt.selected_package_id == "pkg_good"
        assert len(receipt.rejected_candidates) == 2
        rejected_ids = [rc["package_id"] for rc in receipt.rejected_candidates]
        assert "pkg_revoked" in rejected_ids
        assert "pkg_uncertified" in rejected_ids
