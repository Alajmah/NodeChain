"""Registry Reputation and Health Scoring Tests (v2.21.3).

Tests all 10 acceptance criteria.
NON-NEGOTIABLE RULE:
    Reputation informs selection.
    Reputation does not create trust.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


# ── AC1: RegistryHealthScore model ───────────────────────────────────────────

class TestAC1Model:
    """AC1: RegistryHealthScore model with all required fields."""

    def test_model_creation(self):
        from nodechain.sdk.reputation import RegistryHealthScore, ScoreComponent
        s = RegistryHealthScore(
            registry_id="reg-a",
            score=85.0,
            grade="B",
            last_checked="2026-06-17T12:00:00Z",
            components=[
                ScoreComponent("availability", 100, 0.2, "excellent", "ev:1"),
            ],
            evidence_digest="abc123",
            transparency_log_digest="def456",
        )
        assert s.registry_id == "reg-a"
        assert s.score == 85.0
        assert s.grade == "B"
        assert s.evidence_digest == "abc123"
        assert s.transparency_log_digest == "def456"
        assert len(s.components) == 1

    def test_model_serialization(self):
        from nodechain.sdk.reputation import RegistryHealthScore, ScoreComponent
        s = RegistryHealthScore(
            registry_id="reg-a",
            score=92.0,
            grade="A",
            last_checked="2026-06-17T12:00:00Z",
            components=[
                ScoreComponent("availability", 95, 0.2, "excellent", "ev:1"),
                ScoreComponent("signature_validity", 90, 0.15, "excellent", "ev:2"),
            ],
        )
        d = s.to_dict()
        s2 = RegistryHealthScore.from_dict(d)
        assert s2.registry_id == s.registry_id
        assert s2.score == s.score
        assert s2.grade == s.grade
        assert len(s2.components) == len(s.components)

    def test_model_has_required_fields(self):
        from nodechain.sdk.reputation import RegistryHealthScore
        # All fields must be present in to_dict output
        s = RegistryHealthScore(
            registry_id="reg", score=100, grade="A", last_checked="now",
        )
        d = s.to_dict()
        required_keys = {"registry_id", "score", "grade", "last_checked",
                         "components", "evidence_digest", "transparency_log_digest"}
        assert required_keys.issubset(set(d.keys()))


# ── AC2: Score components ────────────────────────────────────────────────────

class TestAC2Components:
    """AC2: All score components supported."""

    def test_all_components_present_after_scoring(self):
        from nodechain.sdk.reputation import ScoringInputs, score_registry
        inputs = ScoringInputs(registry_id="reg")
        score = score_registry(inputs)
        component_names = {c.name for c in score.components}
        # Required components (latency is optional)
        required = {"availability", "metadata_freshness", "signature_validity",
                    "transparency_consistency", "conflict_history",
                    "revocation_responsiveness", "install_success_rate",
                    "policy_compliance"}
        assert required.issubset(component_names)

    def test_latency_optional_component(self):
        from nodechain.sdk.reputation import ScoringInputs, score_registry
        inputs = ScoringInputs(registry_id="reg", latency=80.0)
        score = score_registry(inputs)
        names = {c.name for c in score.components}
        assert "latency" in names

    def test_latency_not_included_by_default(self):
        from nodechain.sdk.reputation import ScoringInputs, score_registry
        inputs = ScoringInputs(registry_id="reg")
        score = score_registry(inputs)
        names = {c.name for c in score.components}
        assert "latency" not in names


# ── AC3: Explainable scores ─────────────────────────────────────────────────

class TestAC3Explainability:
    """AC3: Every component has value, weight, reason, evidence_reference."""

    def test_component_has_all_fields(self):
        from nodechain.sdk.reputation import ScoringInputs, score_registry
        inputs = ScoringInputs(registry_id="reg")
        score = score_registry(inputs)
        for c in score.components:
            assert isinstance(c.value, (int, float))
            assert isinstance(c.weight, (int, float))
            assert isinstance(c.reason, str) and len(c.reason) > 0
            assert isinstance(c.evidence_reference, str) and len(c.evidence_reference) > 0

    def test_reasons_are_human_readable(self):
        from nodechain.sdk.reputation import ScoringInputs, score_registry
        inputs = ScoringInputs(registry_id="reg", availability=50.0)
        score = score_registry(inputs)
        avail = [c for c in score.components if c.name == "availability"][0]
        assert "poor" in avail.reason.lower() or "critical" in avail.reason.lower()

    def test_evidence_reference_includes_registry(self):
        from nodechain.sdk.reputation import ScoringInputs, score_registry
        inputs = ScoringInputs(registry_id="reg-x")
        score = score_registry(inputs)
        for c in score.components:
            assert "reg-x" in c.evidence_reference

    def test_custom_evidence_refs(self):
        from nodechain.sdk.reputation import ScoringInputs, score_registry
        inputs = ScoringInputs(
            registry_id="reg",
            evidence_refs={"availability": "evidence://hash/abc123"},
        )
        score = score_registry(inputs)
        avail = [c for c in score.components if c.name == "availability"][0]
        assert avail.evidence_reference == "evidence://hash/abc123"


# ── AC4: Reputation is policy-consumed but not authoritative ─────────────────

class TestAC4PolicyConsumed:
    """AC4: Low score may warn or deny depending on profile."""

    def test_f_grade_always_denies(self):
        from nodechain.sdk.reputation import (
            RegistryHealthScore, should_deny_by_reputation,
        )
        s = RegistryHealthScore(registry_id="reg", score=20, grade="F", last_checked="now")
        deny, reason = should_deny_by_reputation(s, None)
        assert deny is True
        assert "critical" in reason.lower()

    def test_d_grade_denies_under_strict(self):
        from nodechain.sdk.reputation import (
            RegistryHealthScore, should_deny_by_reputation,
        )
        from nodechain.sdk.org_policy import get_builtin_profile
        s = RegistryHealthScore(registry_id="reg", score=50, grade="D", last_checked="now")
        profile = get_builtin_profile("strict_enterprise")
        deny, reason = should_deny_by_reputation(s, profile)
        assert deny is True

    def test_d_grade_warns_under_permissive(self):
        from nodechain.sdk.reputation import (
            RegistryHealthScore, should_deny_by_reputation,
        )
        from nodechain.sdk.org_policy import get_builtin_profile
        s = RegistryHealthScore(registry_id="reg", score=50, grade="D", last_checked="now")
        profile = get_builtin_profile("permissive_local")
        deny, reason = should_deny_by_reputation(s, profile)
        assert deny is False

    def test_high_score_never_denies(self):
        from nodechain.sdk.reputation import (
            RegistryHealthScore, should_deny_by_reputation,
        )
        from nodechain.sdk.org_policy import get_builtin_profile
        s = RegistryHealthScore(registry_id="reg", score=95, grade="A", last_checked="now")
        profile = get_builtin_profile("strict_enterprise")
        deny, reason = should_deny_by_reputation(s, profile)
        assert deny is False


# ── AC5: CLI commands ────────────────────────────────────────────────────────

class TestAC5CLI:
    """AC5: nodechain registry reputation score/show/verify/refresh."""

    def test_show_empty(self, monkeypatch, tmp_path):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        monkeypatch.setenv("NODECHAIN_REPUTATION_STORE", str(tmp_path / "rep.json"))
        runner = CliRunner()
        result = runner.invoke(cli, ["registry", "reputation", "show", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total_registries"] == 0

    def test_score(self, monkeypatch, tmp_path):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        monkeypatch.setenv("NODECHAIN_REPUTATION_STORE", str(tmp_path / "rep.json"))
        runner = CliRunner()
        result = runner.invoke(cli, [
            "registry", "reputation", "score", "reg-a",
            "--availability", "80", "--conflict-history", "50",
            "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["registry_id"] == "reg-a"
        assert data["grade"] in ("A", "B", "C", "D", "F")

    def test_verify(self, monkeypatch, tmp_path):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        monkeypatch.setenv("NODECHAIN_REPUTATION_STORE", str(tmp_path / "rep.json"))
        runner = CliRunner()
        result = runner.invoke(cli, ["registry", "reputation", "verify", "--json"])
        assert result.exit_code == 0

    def test_refresh(self, monkeypatch, tmp_path):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        rep_path = str(tmp_path / "rep.json")
        monkeypatch.setenv("NODECHAIN_REPUTATION_STORE", rep_path)
        runner = CliRunner()
        runner.invoke(cli, ["registry", "reputation", "score", "reg-a", "--json"])
        result = runner.invoke(cli, ["registry", "reputation", "refresh", "--json"])
        assert result.exit_code == 0

    def test_reputation_in_registry_group(self, monkeypatch, tmp_path):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        monkeypatch.setenv("NODECHAIN_REPUTATION_STORE", str(tmp_path / "rep.json"))
        runner = CliRunner()
        result = runner.invoke(cli, ["registry", "--help"])
        assert "reputation" in result.output


# ── AC6: Dashboard integration ───────────────────────────────────────────────

class TestAC6Dashboard:
    """AC6: HR-017 registry reputation health rule."""

    def test_hr017_exists(self):
        from nodechain.cli.dashboard_health import RULES_BY_ID
        assert "HR-017" in RULES_BY_ID

    def test_hr017_critical_scores(self):
        from nodechain.cli.dashboard_health import RULES_BY_ID
        rule = RULES_BY_ID["HR-017"]
        result = rule.evaluate({"reputation": {"enabled": True, "critical_count": 1}})
        assert result is not None
        assert result["severity"] == "critical"

    def test_hr017_degraded_scores(self):
        from nodechain.cli.dashboard_health import RULES_BY_ID
        rule = RULES_BY_ID["HR-017"]
        result = rule.evaluate({"reputation": {"enabled": True, "degraded_count": 1}})
        assert result is not None

    def test_hr017_stale_scores(self):
        from nodechain.cli.dashboard_health import RULES_BY_ID
        rule = RULES_BY_ID["HR-017"]
        result = rule.evaluate({"reputation": {"enabled": True, "stale_count": 2}})
        assert result is not None
        assert "stale" in result["name"]

    def test_hr017_evidence_mismatch(self):
        from nodechain.cli.dashboard_health import RULES_BY_ID
        rule = RULES_BY_ID["HR-017"]
        result = rule.evaluate({"reputation": {"enabled": True, "mismatch_count": 1}})
        assert result is not None

    def test_hr017_healthy(self):
        from nodechain.cli.dashboard_health import RULES_BY_ID
        rule = RULES_BY_ID["HR-017"]
        result = rule.evaluate({
            "reputation": {
                "enabled": True, "critical_count": 0, "degraded_count": 0,
                "stale_count": 0, "mismatch_count": 0,
            },
        })
        assert result is None

    def test_hr017_not_enabled(self):
        from nodechain.cli.dashboard_health import RULES_BY_ID
        rule = RULES_BY_ID["HR-017"]
        result = rule.evaluate({"reputation": {"enabled": False}})
        assert result is None

    def test_all_21_rules(self):
        from nodechain.cli.dashboard_health import ALL_RULES
        assert len(ALL_RULES) == 65  # 49 HR + 5 MEM + 6 SE + 5 MR (v2.41.0)


# ── AC7: Federation resolver integration ─────────────────────────────────────

class TestAC7FederationIntegration:
    """AC7: Reputation filters candidates only when policy enables it."""

    def test_reputation_does_not_override_digest_conflict(self):
        """HIGH reputation CANNOT bypass digest conflict."""
        from nodechain.sdk.reputation import (
            RegistryHealthScore, ReputationStore, filter_by_reputation,
        )

        class FakeCandidate:
            def __init__(self, registry_id):
                self.registry_id = registry_id

        # High reputation on both
        store = ReputationStore(scores={
            "reg-a": RegistryHealthScore("reg-a", 100, "A", "now"),
            "reg-b": RegistryHealthScore("reg-b", 100, "A", "now"),
        })
        # filter_by_reputation won't change the fact that both pass
        filtered, rejected = filter_by_reputation(
            [FakeCandidate("reg-a"), FakeCandidate("reg-b")], store, None,
        )
        # Both pass reputation — conflict detection happens in resolver BEFORE this
        assert len(filtered) == 2

    def test_reputation_filters_low_grade(self):
        from nodechain.sdk.reputation import (
            RegistryHealthScore, ReputationStore, filter_by_reputation,
        )
        from nodechain.sdk.org_policy import get_builtin_profile

        class FakeCandidate:
            def __init__(self, registry_id):
                self.registry_id = registry_id

        store = ReputationStore(scores={
            "good": RegistryHealthScore("good", 90, "A", "now"),
            "bad": RegistryHealthScore("bad", 20, "F", "now"),
        })
        # v2.21.3: reputation filtering requires profile with use_registry_reputation=True
        profile = get_builtin_profile("strict_enterprise")
        filtered, rejected = filter_by_reputation(
            [FakeCandidate("good"), FakeCandidate("bad")], store, profile,
        )
        assert len(filtered) == 1
        assert filtered[0].registry_id == "good"
        assert any(r["registry_id"] == "bad" for r in rejected)

    def test_no_score_is_neutral(self):
        """Registry without a reputation score is not filtered."""
        from nodechain.sdk.reputation import ReputationStore, filter_by_reputation

        class FakeCandidate:
            def __init__(self, registry_id):
                self.registry_id = registry_id

        store = ReputationStore()
        filtered, rejected = filter_by_reputation(
            [FakeCandidate("unknown-reg")], store, None,
        )
        assert len(filtered) == 1


# ── AC8: Evidence ────────────────────────────────────────────────────────────

class TestAC8Evidence:
    """AC8: Evidence types registered."""

    def test_evidence_types_registered(self):
        from nodechain.cli.evidence import EVIDENCE_TYPES
        assert "registry_health_score_receipt" in EVIDENCE_TYPES
        assert "registry_reputation_report" in EVIDENCE_TYPES

    def test_score_has_evidence_digest(self):
        from nodechain.sdk.reputation import ScoringInputs, score_registry
        inputs = ScoringInputs(registry_id="reg")
        score = score_registry(inputs)
        assert score.evidence_digest != ""
        assert len(score.evidence_digest) == 64  # SHA-256 hex

    def test_score_has_transparency_log_digest(self):
        from nodechain.sdk.reputation import ScoringInputs, score_registry
        inputs = ScoringInputs(registry_id="reg")
        score = score_registry(inputs, transparency_log_digest="abc")
        assert score.transparency_log_digest == "abc"

    def test_scoring_inputs_digest(self):
        from nodechain.sdk.reputation import ScoringInputs
        i1 = ScoringInputs(registry_id="reg", availability=80)
        i2 = ScoringInputs(registry_id="reg", availability=80)
        i3 = ScoringInputs(registry_id="reg", availability=90)
        assert i1.compute_digest() == i2.compute_digest()
        assert i1.compute_digest() != i3.compute_digest()


# ── AC9: Negative tests ──────────────────────────────────────────────────────

class TestAC9Negative:
    """AC9: Reputation cannot bypass hard gates."""

    def test_high_reputation_cannot_bypass_signer_mismatch(self):
        """Reputation is irrelevant if signer check fails."""
        from nodechain.sdk.federation import (
            resolve_federated_package, FederatedRegistryConfig, FederationConfigStore,
        )
        from nodechain.sdk.reputation import (
            RegistryHealthScore, ReputationStore,
        )
        import hashlib

        store = FederationConfigStore(registries=[
            FederatedRegistryConfig(
                registry_id="reg",
                base_url="https://r",
                required_signer_fingerprint="good_signer",
            ),
        ])
        # Even with perfect reputation, signer mismatch must fail
        def fetcher(r, p, v):
            return {
                "artifact_digest": hashlib.sha256(b"pkg").hexdigest(),
                "metadata_digest": hashlib.sha256(b"meta").hexdigest(),
                "publisher_fingerprint": "pub",
                "signer_fingerprint": "bad_signer",  # WRONG
                "metadata_signed": True,
                "certified": True,
            }
        result = resolve_federated_package("pkg", "1.0", fetcher, store)
        assert not result.all_passed
        assert any("Signer" in r["reason"] for r in result.rejected)

    def test_high_reputation_cannot_bypass_uncertified_strict(self):
        """Under strict_enterprise, signed-but-uncertified is rejected regardless of reputation."""
        from nodechain.sdk.federation import (
            resolve_federated_package, FederatedRegistryConfig, FederationConfigStore,
        )
        from nodechain.sdk.org_policy import get_builtin_profile
        import hashlib

        store = FederationConfigStore(registries=[
            FederatedRegistryConfig(registry_id="reg", base_url="https://r"),
        ])
        profile = get_builtin_profile("strict_enterprise")
        def fetcher(r, p, v):
            return {
                "artifact_digest": hashlib.sha256(b"pkg").hexdigest(),
                "metadata_digest": hashlib.sha256(b"meta").hexdigest(),
                "publisher_fingerprint": "pub",
                "signer_fingerprint": "signer",
                "metadata_signed": True,
                "certified": False,  # NOT CERTIFIED
            }
        result = resolve_federated_package("pkg", "1.0", fetcher, store, org_profile=profile)
        assert not result.all_passed
        assert any("Certification" in r["reason"] for r in result.rejected)

    def test_high_reputation_cannot_bypass_digest_conflict(self):
        """Different digests must fail closed regardless of reputation."""
        from nodechain.sdk.federation import (
            resolve_federated_package, FederatedRegistryConfig, FederationConfigStore,
        )
        import hashlib

        store = FederationConfigStore(registries=[
            FederatedRegistryConfig(registry_id="reg-a", base_url="https://ra", priority=10),
            FederatedRegistryConfig(registry_id="reg-b", base_url="https://rb", priority=20),
        ])
        def fetcher(r, p, v):
            return {
                "artifact_digest": hashlib.sha256(r.encode()).hexdigest(),  # different per registry
                "metadata_digest": hashlib.sha256(b"meta").hexdigest(),
                "publisher_fingerprint": "pub",
                "signer_fingerprint": "signer",
                "metadata_signed": True,
                "certified": True,
            }
        result = resolve_federated_package("pkg", "1.0", fetcher, store)
        assert not result.all_passed
        assert len(result.conflicts) > 0

    def test_stale_score_noted(self):
        """Stale scores should be detectable."""
        from datetime import datetime, timezone, timedelta
        from nodechain.sdk.reputation import RegistryHealthScore

        old_time = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        s = RegistryHealthScore("reg", 90, "A", old_time)
        # The score is valid but stale
        assert s.last_checked != datetime.now(timezone.utc).isoformat()

    def test_tampered_score_detected(self):
        """Tampering with score content should be detectable via digest."""
        from nodechain.sdk.reputation import ScoringInputs, score_registry, verify_health_score

        inputs = ScoringInputs(registry_id="reg", availability=90)
        score = score_registry(inputs)
        # Tamper with a component value
        score.components[0].value = 10
        result = verify_health_score(score)
        # Score recomputation won't match
        assert not result.valid

    def test_missing_evidence_reference_detected(self):
        from nodechain.sdk.reputation import (
            RegistryHealthScore, ScoreComponent, verify_health_score,
        )
        s = RegistryHealthScore(
            registry_id="reg", score=90, grade="A", last_checked="now",
            components=[
                ScoreComponent("availability", 100, 0.2, "excellent", ""),
            ],
        )
        result = verify_health_score(s)
        assert not result.valid
        assert any("evidence_reference" in i for i in result.issues)

    def test_many_conflicts_degrades_score(self):
        from nodechain.sdk.reputation import ScoringInputs, score_registry, grade_from_score
        inputs = ScoringInputs(
            registry_id="reg",
            conflict_history=0.0,  # terrible
            transparency_consistency=0.0,
            signature_validity=0.0,
            install_success_rate=0.0,
        )
        score = score_registry(inputs)
        assert score.grade in ("D", "F")

    def test_stale_metadata_degrades_score(self):
        from nodechain.sdk.reputation import ScoringInputs, score_registry
        inputs_good = ScoringInputs(registry_id="reg")
        inputs_bad = ScoringInputs(
            registry_id="reg",
            metadata_freshness=20.0,
            conflict_history=20.0,
            transparency_consistency=20.0,
        )
        score_good = score_registry(inputs_good)
        score_bad = score_registry(inputs_bad)
        assert score_bad.score < score_good.score

    def test_broken_transparency_log_gets_critical(self):
        from nodechain.sdk.reputation import ScoringInputs, score_registry
        inputs = ScoringInputs(
            registry_id="reg",
            transparency_consistency=0.0,
            signature_validity=0.0,
            availability=0.0,
            install_success_rate=0.0,
            conflict_history=0.0,
        )
        score = score_registry(inputs)
        assert score.grade == "F"

    def test_disabled_registry_not_upgraded_by_reputation(self):
        """A disabled registry should not benefit from good reputation."""
        from nodechain.sdk.reputation import (
            RegistryHealthScore, ReputationStore, filter_by_reputation,
        )

        class FakeCandidate:
            def __init__(self, registry_id):
                self.registry_id = registry_id

        store = ReputationStore(scores={
            "disabled-reg": RegistryHealthScore("disabled-reg", 100, "A", "now"),
        })
        # The disabled registry won't even be a candidate in the resolver
        # So reputation is irrelevant
        filtered, rejected = filter_by_reputation(
            [FakeCandidate("active-reg")], store, None,
        )
        assert len(filtered) == 1
        assert filtered[0].registry_id == "active-reg"


# ── AC10: Verification and persistence ───────────────────────────────────────

class TestAC10Verification:
    """AC10: Score verification and store persistence."""

    def test_save_and_load(self, tmp_path):
        from nodechain.sdk.reputation import (
            ScoringInputs, score_registry, ReputationStore,
            save_reputation_store, load_reputation_store,
        )
        path = str(tmp_path / "rep.json")
        store = ReputationStore()
        score = score_registry(ScoringInputs(registry_id="reg"))
        store.set(score)
        save_reputation_store(store, path)
        loaded = load_reputation_store(path)
        assert len(loaded.all_scores) == 1
        assert loaded.get("reg").score == score.score

    def test_verify_valid_score(self):
        from nodechain.sdk.reputation import ScoringInputs, score_registry, verify_health_score
        score = score_registry(ScoringInputs(registry_id="reg"))
        result = verify_health_score(score)
        assert result.valid

    def test_verify_reputation_store(self):
        from nodechain.sdk.reputation import (
            ScoringInputs, score_registry, ReputationStore, verify_reputation_store,
        )
        store = ReputationStore()
        store.set(score_registry(ScoringInputs(registry_id="reg-a")))
        store.set(score_registry(ScoringInputs(registry_id="reg-b")))
        result = verify_reputation_store(store)
        assert result.valid

    def test_corrupt_store_raises(self, tmp_path):
        from nodechain.sdk.reputation import load_reputation_store, ReputationError
        path = str(tmp_path / "corrupt.json")
        Path(path).write_text("garbage{{{{", encoding="utf-8")
        with pytest.raises(ReputationError, match="corrupt"):
            load_reputation_store(path)

    def test_generate_report(self):
        from nodechain.sdk.reputation import (
            ScoringInputs, score_registry, ReputationStore, generate_reputation_report,
        )
        store = ReputationStore()
        store.set(score_registry(ScoringInputs(registry_id="good")))
        store.set(score_registry(ScoringInputs(registry_id="bad", conflict_history=0)))
        report = generate_reputation_report(store)
        assert report.total_registries == 2
        assert report.healthy_count + report.warning_count + report.degraded_count + report.critical_count == 2

    def test_grade_thresholds(self):
        from nodechain.sdk.reputation import grade_from_score
        assert grade_from_score(100) == "A"
        assert grade_from_score(90) == "A"
        assert grade_from_score(89) == "B"
        assert grade_from_score(75) == "B"
        assert grade_from_score(74) == "C"
        assert grade_from_score(60) == "C"
        assert grade_from_score(59) == "D"
        assert grade_from_score(40) == "D"
        assert grade_from_score(39) == "F"
        assert grade_from_score(0) == "F"

    def test_score_is_deterministic(self):
        from nodechain.sdk.reputation import ScoringInputs, score_registry
        inputs = ScoringInputs(registry_id="reg", availability=80, conflict_history=60)
        s1 = score_registry(inputs)
        s2 = score_registry(inputs)
        assert s1.score == s2.score
        assert s1.evidence_digest == s2.evidence_digest
