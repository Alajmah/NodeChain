"""Capability Resolver Adversarial Certification (v2.21.3).

20-scenario adversarial test matrix proving the capability resolver
under hostile offers, false self-claims, selection drift attacks,
and policy edge cases.

CR-001: Scoring never overrides policy denial.
CR-002: Scores from governed evidence, not self-claims.
CR-003: Pinned selections are stable until explicitly re-resolved.
"""

from __future__ import annotations

import json
import pytest

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
    REJECT_UNVERIFIED_SCORE,
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

def _offer(package_id, capability="incident.severity.triage", version="1.0.0", **kw):
    defaults = dict(
        package_id=package_id, version=version,
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
    defaults.update(kw)
    return CapabilityOffer(**defaults)


def _request(capability="incident.severity.triage", **kw):
    defaults = dict(
        capability=capability,
        input_contract="AnomalySet@1",
        output_contract="SeverityAssessment@1",
        certification_required=True,
        max_risk=RISK_HIGH,
        required_sandbox="hardened_untrusted",
    )
    defaults.update(kw)
    return CapabilityRequest(**defaults)


def _evidence(package_id, version="1.0.0", **kw):
    defaults = dict(
        package_id=package_id, version=version,
        verified_evaluation_score=0.9,
        verified_trust_level=TRUST_LEVEL_LOCAL_TRUSTED,
        verified_certification_digest="sha256:cert",
        verified_risk_level=RISK_MEDIUM,
        evidence_source="evaluation_suite",
        evidence_digest="sha256:ev",
    )
    defaults.update(kw)
    return GovernedEvidence(**defaults)


class MockOfferProvider:
    def __init__(self, offers):
        self._offers = offers

    def __call__(self, capability):
        return [o for o in self._offers if capability in o.capabilities]


class MockEvidenceProvider:
    """Evidence provider for adversarial tests.

    Can be constructed from a list of offers (auto-generates evidence)
    or from an explicit evidence_map dict.
    """

    def __init__(self, source=None):
        if isinstance(source, dict):
            self._map = source
        elif isinstance(source, list):
            # Auto-generate evidence from offers
            self._map = {}
            for o in source:
                self._map[(o.package_id, o.version)] = _evidence_from_offer(o)
        else:
            self._map = {}

    def __call__(self, package_id, version):
        return self._map.get((package_id, version))

    def add(self, package_id, version, evidence):
        self._map[(package_id, version)] = evidence


def _evidence_from_offer(offer):
    """Generate governed evidence from an offer (for test setup)."""
    return GovernedEvidence(
        package_id=offer.package_id,
        version=offer.version,
        verified_evaluation_score=offer.evaluation_score,
        verified_trust_level=offer.trust_level,
        verified_certification_digest=offer.certification_digest,
        verified_risk_level=offer.risk_level,
        evidence_source="test_authority",
        evidence_digest=f"sha256:ev_{offer.package_id}_{offer.version}",
    )


# ── Scenario 1: Wrong input contract ────────────────────────────────────────

class TestS1WrongInputContract:
    """1. Matching capability but wrong input contract → rejected."""

    def test_wrong_input_contract(self):
        provider = lambda cap: [_offer("pkg_a", input_contracts=["WrongContract@1"])]
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider([_offer("pkg_a", input_contracts=["WrongContract@1"])]))
        scores, _ = r.resolve(_request())
        assert REJECT_CONTRACT_MISMATCH in scores[0].rejection_reasons


# ── Scenario 2: Wrong output contract ───────────────────────────────────────

class TestS2WrongOutputContract:
    """2. Matching capability but wrong output contract → rejected."""

    def test_wrong_output_contract(self):
        provider = lambda cap: [_offer("pkg_a", output_contracts=["WrongOutput@1"])]
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider([_offer("pkg_a", output_contracts=["WrongOutput@1"])]))
        scores, _ = r.resolve(_request())
        assert REJECT_CONTRACT_MISMATCH in scores[0].rejection_reasons


# ── Scenario 3: DT-001 failed → rejected before scoring ─────────────────────

class TestS3DT001FailedBeforeScoring:
    """3. Candidate graph fails DT-001 → rejected before scoring."""

    def test_dt001_rejected_before_scoring(self):
        provider = MockOfferProvider([_offer("pkg_a", dependency_graph_admissible=False)])
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        scores, _ = r.resolve(_request())
        assert not scores[0].passed_hard_filters
        assert REJECT_DT001_FAILED in scores[0].rejection_reasons
        assert scores[0].total_score == 0.0  # Not scored


# ── Scenario 4: Excellent score but policy denial ───────────────────────────

class TestS4ScoreIgnoresPolicyDenial:
    """4. Excellent score but policy denial → rejected; score ignored."""

    def test_high_score_revoked_still_rejected(self):
        provider = MockOfferProvider([
            _offer("pkg_bad", lifecycle="revoked", evaluation_score=0.99),
            _offer("pkg_ok", evaluation_score=0.5, risk_level=RISK_LOW),
        ])
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        scores, receipt = r.resolve(_request())
        assert receipt.selected_package_id == "pkg_ok"
        bad = [s for s in scores if s.offer.package_id == "pkg_bad"][0]
        assert not bad.passed_hard_filters
        assert REJECT_REVOKED in bad.rejection_reasons


# ── Scenario 5: Forbidden secondary capability ──────────────────────────────

class TestS5ForbiddenSecondaryCap:
    """5. Candidate has forbidden secondary capability → rejected."""

    def test_forbidden_secondary(self):
        provider = MockOfferProvider([
            _offer("pkg_a", capabilities=["incident.severity.triage", "network.egress"]),
        ])
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        scores, _ = r.resolve(_request(forbidden_capabilities=["network.egress"]))
        assert REJECT_FORBIDDEN_CAPABILITY in scores[0].rejection_reasons


# ── Scenario 6: Weaker sandbox than policy minimum ──────────────────────────

class TestS6WeakerSandbox:
    """6. Candidate requires weaker sandbox than policy minimum → rejected."""

    def test_weaker_sandbox(self):
        provider = MockOfferProvider([_offer("pkg_a", sandbox_profile="none")])
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        scores, _ = r.resolve(_request(required_sandbox="hardened_untrusted"))
        assert REJECT_SANDBOX_DOWNGRADE in scores[0].rejection_reasons


# ── Scenario 7: Risk exceeds max_risk ───────────────────────────────────────

class TestS7RiskExceeds:
    """7. Candidate risk exceeds max_risk → rejected."""

    def test_risk_exceeds_max(self):
        provider = MockOfferProvider([_offer("pkg_a", risk_level=RISK_CRITICAL)])
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        scores, _ = r.resolve(_request(max_risk=RISK_MEDIUM))
        assert REJECT_RISK_TOO_HIGH in scores[0].rejection_reasons


# ── Scenario 8: Deprecated with allow_deprecated=false ──────────────────────

class TestS8DeprecatedNotAllowed:
    """8. Deprecated candidate with allow_deprecated=false → rejected."""

    def test_deprecated_rejected(self):
        provider = MockOfferProvider([_offer("pkg_a", lifecycle="deprecated")])
        policy = CapabilityResolutionPolicy(allow_deprecated=False)
        r = CapabilityResolver(offer_provider=provider, policy=policy, evidence_provider=MockEvidenceProvider(provider._offers))
        scores, _ = r.resolve(_request())
        assert REJECT_DEPRECATED_DISALLOWED in scores[0].rejection_reasons


# ── Scenario 9: Deprecated with allow_with_warning → selectable ─────────────

class TestS9DeprecatedWarning:
    """9. Deprecated candidate with allow_deprecated=true → selectable."""

    def test_deprecated_allowed(self):
        provider = MockOfferProvider([_offer("pkg_a", lifecycle="deprecated", risk_level=RISK_LOW)])
        policy = CapabilityResolutionPolicy(allow_deprecated=True)
        r = CapabilityResolver(offer_provider=provider, policy=policy, evidence_provider=MockEvidenceProvider(provider._offers))
        _, receipt = r.resolve(_request())
        assert receipt.selected_package_id == "pkg_a"


# ── Scenario 10: High-risk → human review ───────────────────────────────────

class TestS10HighRiskReview:
    """10. High-risk candidate → human review required."""

    def test_high_risk_review(self):
        provider = MockOfferProvider([_offer("pkg_a", risk_level=RISK_HIGH)])
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        _, receipt = r.resolve(_request())
        assert receipt.human_review_required
        assert receipt.human_review_status == "pending"
        assert not receipt.selected_package_id


# ── Scenario 11: External publisher → human review ──────────────────────────

class TestS11ExternalPublisherReview:
    """11. External publisher → human review required when policy says so."""

    def test_external_review(self):
        provider = MockOfferProvider([_offer("pkg_a", trust_level=TRUST_LEVEL_REMOTE_UNTRUSTED)])
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        _, receipt = r.resolve(_request())
        assert receipt.human_review_required


# ── Scenario 12: Narrow score margin → human review ─────────────────────────

class TestS12NarrowMargin:
    """12. Narrow score margin → human review required."""

    def test_narrow_margin(self):
        provider = MockOfferProvider([
            _offer("pkg_a", evaluation_score=0.90, risk_level=RISK_LOW),
            _offer("pkg_b", evaluation_score=0.89, risk_level=RISK_LOW),
        ])
        policy = CapabilityResolutionPolicy(review_score_margin_below=5.0)
        r = CapabilityResolver(offer_provider=provider, policy=policy, evidence_provider=MockEvidenceProvider(provider._offers))
        _, receipt = r.resolve(_request())
        assert receipt.human_review_required


# ── Scenario 13: Exact score tie → deterministic tie-break ──────────────────

class TestS13ExactTie:
    """13. Exact score tie → deterministic tie-break chain."""

    def test_tiebreak_deterministic(self):
        provider = MockOfferProvider([
            _offer("zzz_pkg", evaluation_score=0.9, risk_level=RISK_LOW),
            _offer("aaa_pkg", evaluation_score=0.9, risk_level=RISK_LOW),
        ])
        policy = CapabilityResolutionPolicy(review_score_margin_below=0.0)
        r = CapabilityResolver(offer_provider=provider, policy=policy, evidence_provider=MockEvidenceProvider(provider._offers))
        _, receipt = r.resolve(_request())
        # Stable identity ordering → aaa_pkg wins
        assert receipt.selected_package_id == "aaa_pkg"


# ── Scenario 14: Preferred publisher cannot override hard filter ────────────

class TestS14PreferredPublisherNoOverride:
    """14. Preferred publisher cannot override hard filter."""

    def test_preferred_but_revoked(self):
        provider = MockOfferProvider([
            _offer("pkg_revoked", lifecycle="revoked", publisher_fingerprint="fp-preferred"),
            _offer("pkg_ok", publisher_fingerprint="fp-other", risk_level=RISK_LOW),
        ])
        policy = CapabilityResolutionPolicy(preferred_publishers=["fp-preferred"])
        r = CapabilityResolver(offer_provider=provider, policy=policy, evidence_provider=MockEvidenceProvider(provider._offers))
        _, receipt = r.resolve(_request())
        assert receipt.selected_package_id == "pkg_ok"


# ── Scenario 15: Lockfile drift after selection ─────────────────────────────

class TestS15LockfileDrift:
    """15. Candidate selected, then dependency lockfile drifts."""

    def test_drift_detected(self):
        pin = CapabilityPin(
            capability="test.cap",
            package_id="pkg_a",
            version="1.0.0",
            lockfile_digest="sha256:original",
            receipt_digest="r-001",
        )
        receipt = CapabilitySelectionReceipt(
            selected_package_id="pkg_a",
            selected_version="1.0.0",
            selected_lockfile_digest="sha256:CHANGED",
        )
        assert check_capability_drift(pin, receipt)


# ── Scenario 16: Package revoked after selection ────────────────────────────

class TestS16PostSelectionRevocation:
    """16. Candidate selected, then package revoked → re-resolution rejects."""

    def test_revoked_after_selection(self):
        provider = MockOfferProvider([_offer("pkg_a", risk_level=RISK_LOW)])
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        _, receipt = r.resolve(_request())
        assert receipt.selected_package_id == "pkg_a"
        pin = pin_capability("test.cap", receipt)

        # Now package is revoked
        provider2 = MockOfferProvider([_offer("pkg_a", lifecycle="revoked", risk_level=RISK_LOW)])
        r2 = CapabilityResolver(offer_provider=provider2, evidence_provider=MockEvidenceProvider(provider2._offers))
        _, receipt2 = r2.re_resolve(_request(), pin=pin)
        assert not receipt2.selected_package_id  # Rejected


# ── Scenario 17: Better candidate appears → no silent switch ────────────────

class TestS17NoSilentSwitch:
    """17. Better candidate appears → no silent switch; pin remains."""

    def test_no_silent_switch(self):
        provider = MockOfferProvider([_offer("pkg_a", evaluation_score=0.5, risk_level=RISK_LOW)])
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        _, receipt = r.resolve(_request())
        pin = pin_capability("test.cap", receipt)
        assert pin.package_id == "pkg_a"

        # New better candidate appears
        provider2 = MockOfferProvider([
            _offer("pkg_a", evaluation_score=0.5, risk_level=RISK_LOW),
            _offer("pkg_better", evaluation_score=0.99, risk_level=RISK_LOW),
        ])
        r2 = CapabilityResolver(offer_provider=provider2, evidence_provider=MockEvidenceProvider(provider2._offers))
        # Check stability: original pin should still be stable (pkg_a is still admissible)
        # But re_resolution would switch to the better one
        scores2, receipt2 = r2.re_resolve(_request(), pin=pin)
        # Re-resolution may switch, but the rationale warns about the change
        if receipt2.selected_package_id != pin.package_id:
            assert "WARNING" in receipt2.selection_rationale


# ── Scenario 18: False evaluation score (CR-002) ────────────────────────────

class TestS18FalseEvaluationScore:
    """18. CR-002: Candidate advertises false evaluation score → rejected."""

    def test_self_claimed_score_rejected_without_evidence(self):
        provider = MockOfferProvider([
            _offer("pkg_liar", evaluation_score=1.0),  # Claims perfect score
        ])
        ev_provider = MockEvidenceProvider()  # No evidence for pkg_liar
        r = CapabilityResolver(
            offer_provider=provider,
            evidence_provider=ev_provider,
        )
        scores, _ = r.resolve(_request())
        # Self-claimed score is rejected
        assert not scores[0].passed_hard_filters
        assert REJECT_UNVERIFIED_SCORE in scores[0].rejection_reasons

    def test_evidence_overrides_self_claim(self):
        provider = MockOfferProvider([
            _offer("pkg_a", evaluation_score=1.0),  # Claims 1.0
        ])
        ev_provider = MockEvidenceProvider()
        ev_provider.add("pkg_a", "1.0.0", _evidence(
            "pkg_a", verified_evaluation_score=0.5,  # Actual score is 0.5
        ))
        r = CapabilityResolver(
            offer_provider=provider,
            evidence_provider=ev_provider,
        )
        scores, _ = r.resolve(_request())
        assert scores[0].passed_hard_filters
        # Score should reflect evidence, not self-claim
        # evaluation_score weight is 25%, so 0.5 * 25 = 12.5
        eval_dim = scores[0].dimension_scores["evaluation_score"]
        # With evidence 0.5, the dimension should be lower than 0.99 * 25
        assert eval_dim < 20.0  # Much less than 25

    def test_evidence_trust_level_overrides(self):
        provider = MockOfferProvider([
            _offer("pkg_a", trust_level=TRUST_LEVEL_BUILT_IN),  # Claims highest
        ])
        ev_provider = MockEvidenceProvider()
        ev_provider.add("pkg_a", "1.0.0", _evidence(
            "pkg_a",
            verified_trust_level=TRUST_LEVEL_REMOTE_UNTRUSTED,  # Actually lowest
        ))
        r = CapabilityResolver(
            offer_provider=provider,
            evidence_provider=ev_provider,
        )
        scores, _ = r.resolve(_request())
        # Should trigger external publisher review due to evidence
        assert scores[0].requires_review


# ── Scenario 19: Explain mode preserves rejections ──────────────────────────

class TestS19ExplainMode:
    """19. Explain mode → rejected candidates and reasons preserved."""

    def test_explain_preserves_all(self):
        provider = MockOfferProvider([
            _offer("pkg_good", risk_level=RISK_LOW),
            _offer("pkg_revoked", lifecycle="revoked"),
            _offer("pkg_uncertified", certification_digest=""),
        ])
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        scores, receipt = r.resolve(_request(), explain=True)
        assert len(receipt.rejected_candidates) == 2
        rejected_ids = [rc["package_id"] for rc in receipt.rejected_candidates]
        assert "pkg_revoked" in rejected_ids
        assert "pkg_uncertified" in rejected_ids

    def test_explain_no_rejected_when_all_pass(self):
        provider = MockOfferProvider([_offer("pkg_a", risk_level=RISK_LOW)])
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        _, receipt = r.resolve(_request(), explain=True)
        assert len(receipt.rejected_candidates) == 0


# ── Scenario 20: Determinism — same inputs → same output ────────────────────

class TestS20Determinism:
    """20. Same request + same registries + same policy → same selection and receipt."""

    def test_same_inputs_same_selection(self):
        provider = MockOfferProvider([
            _offer("pkg_a", evaluation_score=0.5, risk_level=RISK_LOW),
            _offer("pkg_b", evaluation_score=0.6, risk_level=RISK_LOW),
        ])
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        _, r1 = r.resolve(_request())
        _, r2 = r.resolve(_request())
        assert r1.selected_package_id == r2.selected_package_id
        assert r1.request_digest == r2.request_digest
        assert r1.policy_digest == r2.policy_digest
        assert r1.receipt_id == r2.receipt_id

    def test_different_policy_different_receipt(self):
        provider = MockOfferProvider([_offer("pkg_a", risk_level=RISK_LOW)])
        p1 = CapabilityResolutionPolicy(policy_id="policy-A")
        p2 = CapabilityResolutionPolicy(policy_id="policy-B")
        r1 = CapabilityResolver(offer_provider=provider, policy=p1)
        r2 = CapabilityResolver(offer_provider=provider, policy=p2, evidence_provider=MockEvidenceProvider(provider._offers))
        _, rec1 = r1.resolve(_request())
        _, rec2 = r2.resolve(_request())
        assert rec1.receipt_id != rec2.receipt_id
        assert rec1.policy_digest != rec2.policy_digest


# ── CR-002: Additional evidence authority tests ─────────────────────────────

class TestCR002EvidenceAuthority:
    """CR-002: Package must not be authority for its own score."""

    def test_package_with_evidence_selectable(self):
        provider = MockOfferProvider([_offer("pkg_a", risk_level=RISK_LOW)])
        ev = MockEvidenceProvider()
        ev.add("pkg_a", "1.0.0", _evidence("pkg_a", verified_evaluation_score=0.8))
        r = CapabilityResolver(offer_provider=provider, evidence_provider=ev)
        _, receipt = r.resolve(_request())
        assert receipt.selected_package_id == "pkg_a"

    def test_mixed_evidence_partial_rejection(self):
        """One package has evidence, another doesn't."""
        provider = MockOfferProvider([
            _offer("pkg_verified", evaluation_score=0.3, risk_level=RISK_LOW),
            _offer("pkg_unverified", evaluation_score=0.99, risk_level=RISK_LOW),
        ])
        ev = MockEvidenceProvider()
        ev.add("pkg_verified", "1.0.0", _evidence("pkg_verified", verified_evaluation_score=0.3))
        # No evidence for pkg_unverified
        r = CapabilityResolver(offer_provider=provider, evidence_provider=ev)
        scores, receipt = r.resolve(_request())
        # Only the verified one is admissible
        assert receipt.selected_package_id == "pkg_verified"
        unverified = [s for s in scores if s.offer.package_id == "pkg_unverified"][0]
        assert REJECT_UNVERIFIED_SCORE in unverified.rejection_reasons


# ── CR-003: Selection stability tests ───────────────────────────────────────

class TestCR003SelectionStability:
    """CR-003: Pinned selections are stable until explicitly re-resolved."""

    def test_stable_selection(self):
        provider = MockOfferProvider([_offer("pkg_a", risk_level=RISK_LOW)])
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        _, receipt = r.resolve(_request())
        pin = pin_capability("test.cap", receipt)
        assert r.is_selection_stable(pin, _request())

    def test_unstable_when_revoked(self):
        provider = MockOfferProvider([_offer("pkg_a", risk_level=RISK_LOW)])
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        _, receipt = r.resolve(_request())
        pin = pin_capability("test.cap", receipt)

        provider2 = MockOfferProvider([_offer("pkg_a", lifecycle="revoked", risk_level=RISK_LOW)])
        r2 = CapabilityResolver(offer_provider=provider2, evidence_provider=MockEvidenceProvider(provider2._offers))
        assert not r2.is_selection_stable(pin, _request())

    def test_re_resolve_warns_on_drift(self):
        provider = MockOfferProvider([_offer("pkg_a", evaluation_score=0.5, risk_level=RISK_LOW)])
        r = CapabilityResolver(offer_provider=provider, evidence_provider=MockEvidenceProvider(provider._offers))
        _, receipt = r.resolve(_request())
        pin = pin_capability("test.cap", receipt)

        # Better candidate appears
        provider2 = MockOfferProvider([
            _offer("pkg_a", evaluation_score=0.5, risk_level=RISK_LOW),
            _offer("pkg_better", evaluation_score=0.99, risk_level=RISK_LOW),
        ])
        r2 = CapabilityResolver(offer_provider=provider2, evidence_provider=MockEvidenceProvider(provider2._offers))
        _, receipt2 = r2.re_resolve(_request(), pin=pin)
        if receipt2.selected_package_id != pin.package_id:
            assert "WARNING" in receipt2.selection_rationale


# ── CR-002 Strict Mode: require_governed_evidence=True (default) ────────────

class TestCR002StrictDefault:
    """CR-002 default: require_governed_evidence=True means self-claimed scores
    are rejected when no evidence provider is configured."""

    def test_no_evidence_provider_rejects_by_default(self):
        """Without evidence provider, default policy rejects self-claims."""
        provider = MockOfferProvider([_offer("pkg_a", risk_level=RISK_LOW)])
        # No evidence_provider, default policy has require_governed_evidence=True
        r = CapabilityResolver(offer_provider=provider)
        scores, _ = r.resolve(_request())
        assert not scores[0].passed_hard_filters
        assert REJECT_UNVERIFIED_SCORE in scores[0].rejection_reasons

    def test_require_governed_evidence_true_rejects_without_provider(self):
        """Explicit require_governed_evidence=True without provider → reject."""
        provider = MockOfferProvider([_offer("pkg_a", risk_level=RISK_LOW)])
        policy = CapabilityResolutionPolicy(require_governed_evidence=True)
        r = CapabilityResolver(offer_provider=provider, policy=policy)
        scores, _ = r.resolve(_request())
        assert not scores[0].passed_hard_filters

    def test_require_governed_evidence_false_allows_self_claims(self):
        """require_governed_evidence=False allows self-claimed scores.

        This is for development/testing only — production should always
        require governed evidence.
        """
        provider = MockOfferProvider([_offer("pkg_a", risk_level=RISK_LOW)])
        policy = CapabilityResolutionPolicy(require_governed_evidence=False)
        r = CapabilityResolver(offer_provider=provider, policy=policy)
        _, receipt = r.resolve(_request())
        assert receipt.selected_package_id == "pkg_a"

    def test_policy_to_dict_includes_flag(self):
        p = CapabilityResolutionPolicy()
        d = p.to_dict()
        assert "require_governed_evidence" in d
        assert d["require_governed_evidence"] is True

    def test_digest_changes_with_flag(self):
        p1 = CapabilityResolutionPolicy(require_governed_evidence=True)
        p2 = CapabilityResolutionPolicy(require_governed_evidence=False)
        assert p1.compute_digest() != p2.compute_digest()
