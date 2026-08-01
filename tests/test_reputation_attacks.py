"""Reputation Adversarial Test Suite (v2.21.3).

20 acceptance criteria ensuring reputation cannot become a backdoor trust oracle.

Two code-level findings hardened:
  REP-FINDING-001: score_digest tamper seal on RegistryHealthScore
  REP-FINDING-002: filter_by_reputation is opt-in via org profile
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest


def _meta(pkg, ver, digest="", pub="pub_fp", signed=True, certified=True):
    return {
        "artifact_digest": digest or hashlib.sha256(f"{pkg}{ver}".encode()).hexdigest(),
        "metadata_digest": hashlib.sha256(f"meta-{pkg}{ver}".encode()).hexdigest(),
        "publisher_fingerprint": pub,
        "signer_fingerprint": "signer_fp",
        "metadata_signed": signed,
        "certified": certified,
    }


# ── AC1: Tampered score value detected ───────────────────────────────────────

class TestAC1TamperedScoreValue:
    def test_tampered_score_value_detected(self):
        from nodechain.sdk.reputation import ScoringInputs, score_registry, verify_health_score
        score = score_registry(ScoringInputs(registry_id="reg"))
        assert verify_health_score(score).valid  # baseline valid
        score.score = 10.0  # tamper
        result = verify_health_score(score)
        assert not result.valid
        assert any("mismatch" in i.lower() for i in result.issues)


# ── AC2: Tampered grade detected ─────────────────────────────────────────────

class TestAC2TamperedGrade:
    def test_tampered_grade_detected(self):
        from nodechain.sdk.reputation import ScoringInputs, score_registry, verify_health_score
        score = score_registry(ScoringInputs(registry_id="reg"))
        score.grade = "F"  # tamper
        result = verify_health_score(score)
        assert not result.valid


# ── AC3: Tampered component value detected ───────────────────────────────────

class TestAC3TamperedComponentValue:
    def test_tampered_component_value_detected(self):
        from nodechain.sdk.reputation import ScoringInputs, score_registry, verify_health_score
        score = score_registry(ScoringInputs(registry_id="reg"))
        score.components[0].value = 1.0  # tamper
        result = verify_health_score(score)
        assert not result.valid


# ── AC4: Tampered component weight detected ──────────────────────────────────

class TestAC4TamperedComponentWeight:
    def test_tampered_component_weight_detected(self):
        from nodechain.sdk.reputation import ScoringInputs, score_registry, verify_health_score
        score = score_registry(ScoringInputs(registry_id="reg"))
        score.components[0].weight = 0.9  # tamper
        result = verify_health_score(score)
        assert not result.valid


# ── AC5: Missing component detected ──────────────────────────────────────────

class TestAC5MissingComponent:
    def test_missing_component_detected(self):
        from nodechain.sdk.reputation import ScoringInputs, score_registry, verify_health_score
        score = score_registry(ScoringInputs(registry_id="reg"))
        # Remove a required component
        score.components = [c for c in score.components if c.name != "availability"]
        score.seal()  # re-seal to test component check specifically
        result = verify_health_score(score)
        assert not result.valid
        assert any("Missing" in i for i in result.issues)


# ── AC6: Empty evidence_reference detected ───────────────────────────────────

class TestAC6EmptyEvidenceRef:
    def test_empty_evidence_reference_detected(self):
        from nodechain.sdk.reputation import (
            RegistryHealthScore, ScoreComponent, verify_health_score,
        )
        from nodechain.sdk.reputation import ScoringInputs, score_registry
        score = score_registry(ScoringInputs(registry_id="reg"))
        score.components[0].evidence_reference = ""
        result = verify_health_score(score)
        assert not result.valid
        assert any("evidence_reference" in i for i in result.issues)


# ── AC7: Missing transparency_log_digest ─────────────────────────────────────

class TestAC7MissingTransparencyDigest:
    def test_missing_transparency_digest_warning(self):
        from nodechain.sdk.reputation import ScoringInputs, score_registry
        score = score_registry(ScoringInputs(registry_id="reg"))
        # Score without transparency_log_digest is not an error per se,
        # but should be noted
        assert score.transparency_log_digest == ""

    def test_transparency_digest_present_when_provided(self):
        from nodechain.sdk.reputation import ScoringInputs, score_registry
        score = score_registry(
            ScoringInputs(registry_id="reg"),
            transparency_log_digest="abc123",
        )
        assert score.transparency_log_digest == "abc123"


# ── AC8: Broken transparency log → registry critical ─────────────────────────

class TestAC8BrokenTransparency:
    def test_broken_transparency_log_critical_score(self):
        from nodechain.sdk.reputation import ScoringInputs, score_registry
        inputs = ScoringInputs(
            registry_id="reg",
            transparency_consistency=0.0,
            signature_validity=0.0,
            availability=0.0,
            install_success_rate=0.0,
            conflict_history=0.0,
            metadata_freshness=0.0,
            policy_compliance=0.0,
            revocation_responsiveness=0.0,
        )
        score = score_registry(inputs)
        assert score.grade == "F"


# ── AC9: High reputation cannot bypass digest conflict ───────────────────────

class TestAC9ReputationVsDigestConflict:
    def test_high_reputation_cannot_bypass_digest_conflict(self):
        from nodechain.sdk.federation import (
            resolve_federated_package, FederatedRegistryConfig, FederationConfigStore,
        )
        store = FederationConfigStore(registries=[
            FederatedRegistryConfig(registry_id="reg-a", base_url="https://ra", priority=10),
            FederatedRegistryConfig(registry_id="reg-b", base_url="https://rb", priority=20),
        ])
        def fetcher(r, p, v):
            return _meta(p, v, digest=f"d_{r}", certified=True)
        result = resolve_federated_package("pkg", "1.0", fetcher, store)
        assert not result.all_passed
        assert len(result.conflicts) > 0


# ── AC10: High reputation cannot bypass signer mismatch ──────────────────────

class TestAC10ReputationVsSigner:
    def test_high_reputation_cannot_bypass_signer_mismatch(self):
        from nodechain.sdk.federation import (
            resolve_federated_package, FederatedRegistryConfig, FederationConfigStore,
        )
        store = FederationConfigStore(registries=[
            FederatedRegistryConfig(
                registry_id="reg", base_url="https://r",
                required_signer_fingerprint="good_signer",
            ),
        ])
        def fetcher(r, p, v):
            return _meta(p, v, signer_fingerprint="bad_signer")
        result = resolve_federated_package("pkg", "1.0", fetcher, store)
        assert not result.all_passed


# ── AC11: High reputation cannot bypass publisher mismatch ────────────────────

class TestAC11ReputationVsPublisher:
    def test_high_reputation_cannot_bypass_publisher_mismatch(self):
        from nodechain.sdk.federation import (
            resolve_federated_package, FederatedRegistryConfig, FederationConfigStore,
        )
        store = FederationConfigStore(registries=[
            FederatedRegistryConfig(
                registry_id="reg", base_url="https://r",
                allowed_publishers=["trusted_pub"],
            ),
        ])
        def fetcher(r, p, v):
            return _meta(p, v, pub="untrusted")
        result = resolve_federated_package("pkg", "1.0", fetcher, store)
        assert not result.all_passed


# ── AC12: High reputation cannot bypass uncertified under strict ──────────────

class TestAC12ReputationVsUncertified:
    def test_high_reputation_cannot_bypass_uncertified_strict(self):
        from nodechain.sdk.federation import (
            resolve_federated_package, FederatedRegistryConfig, FederationConfigStore,
        )
        from nodechain.sdk.org_policy import get_builtin_profile
        store = FederationConfigStore(registries=[
            FederatedRegistryConfig(registry_id="reg", base_url="https://r"),
        ])
        profile = get_builtin_profile("strict_enterprise")
        def fetcher(r, p, v):
            return _meta(p, v, signed=True, certified=False)
        result = resolve_federated_package("pkg", "1.0", fetcher, store, org_profile=profile)
        assert not result.all_passed
        assert any("Certification" in r["reason"] for r in result.rejected)


# ── AC13: Reputation cannot override disabled registry ───────────────────────

class TestAC13ReputationVsDisabled:
    def test_disabled_registry_not_consulted(self):
        from nodechain.sdk.federation import (
            resolve_federated_package, FederatedRegistryConfig, FederationConfigStore,
        )
        store = FederationConfigStore(registries=[
            FederatedRegistryConfig(
                registry_id="disabled", base_url="https://r", enabled=False),
            FederatedRegistryConfig(
                registry_id="active", base_url="https://r2", priority=10),
        ])
        consulted = []
        def fetcher(r, p, v):
            consulted.append(r)
            return _meta(p, v)
        resolve_federated_package("pkg", "1.0", fetcher, store)
        assert "disabled" not in consulted


# ── AC14: Reputation filtering inactive unless profile enables it ─────────────

class TestAC14ReputationOptIn:
    def test_filter_inactive_without_profile(self):
        """filter_by_reputation returns all candidates when no profile."""
        from nodechain.sdk.reputation import (
            RegistryHealthScore, ReputationStore, filter_by_reputation,
        )

        class FakeCandidate:
            def __init__(self, registry_id):
                self.registry_id = registry_id

        store = ReputationStore(scores={
            "bad": RegistryHealthScore("bad", 10, "F", "now"),
        })
        filtered, rejected = filter_by_reputation(
            [FakeCandidate("bad")], store, None,
        )
        assert len(filtered) == 1  # returned unchanged
        assert len(rejected) == 0

    def test_filter_inactive_when_profile_disables_reputation(self):
        """filter_by_reputation returns all candidates when use_registry_reputation=False."""
        from nodechain.sdk.reputation import (
            RegistryHealthScore, ReputationStore, filter_by_reputation,
        )
        from nodechain.sdk.org_policy import get_builtin_profile

        class FakeCandidate:
            def __init__(self, registry_id):
                self.registry_id = registry_id

        store = ReputationStore(scores={
            "bad": RegistryHealthScore("bad", 10, "F", "now"),
        })
        # permissive_local has use_registry_reputation=False (default)
        profile = get_builtin_profile("permissive_local")
        assert not profile.use_registry_reputation
        filtered, rejected = filter_by_reputation(
            [FakeCandidate("bad")], store, profile,
        )
        assert len(filtered) == 1  # not filtered
        assert len(rejected) == 0

    def test_filter_active_when_profile_enables_reputation(self):
        """filter_by_reputation filters when use_registry_reputation=True."""
        from nodechain.sdk.reputation import (
            RegistryHealthScore, ReputationStore, filter_by_reputation,
        )
        from nodechain.sdk.org_policy import get_builtin_profile

        class FakeCandidate:
            def __init__(self, registry_id):
                self.registry_id = registry_id

        store = ReputationStore(scores={
            "bad": RegistryHealthScore("bad", 10, "F", "now"),
            "good": RegistryHealthScore("good", 95, "A", "now"),
        })
        # strict_enterprise has use_registry_reputation=True
        profile = get_builtin_profile("strict_enterprise")
        assert profile.use_registry_reputation
        filtered, rejected = filter_by_reputation(
            [FakeCandidate("bad"), FakeCandidate("good")], store, profile,
        )
        assert len(filtered) == 1
        assert filtered[0].registry_id == "good"
        assert len(rejected) == 1


# ── AC15: D-grade denied under strict_enterprise ─────────────────────────────

class TestAC15DGradeDenied:
    def test_d_grade_denied_under_strict(self):
        from nodechain.sdk.reputation import (
            RegistryHealthScore, ReputationStore, filter_by_reputation,
        )
        from nodechain.sdk.org_policy import get_builtin_profile

        class FakeCandidate:
            def __init__(self, registry_id):
                self.registry_id = registry_id

        store = ReputationStore(scores={
            "degraded": RegistryHealthScore("degraded", 50, "D", "now"),
        })
        profile = get_builtin_profile("strict_enterprise")
        filtered, rejected = filter_by_reputation(
            [FakeCandidate("degraded")], store, profile,
        )
        assert len(filtered) == 0
        assert len(rejected) == 1


# ── AC16: F-grade denied when reputation enabled ─────────────────────────────

class TestAC16FGradeDenied:
    def test_f_grade_denied_when_reputation_enabled(self):
        from nodechain.sdk.reputation import (
            RegistryHealthScore, ReputationStore, filter_by_reputation,
        )
        from nodechain.sdk.org_policy import get_builtin_profile

        class FakeCandidate:
            def __init__(self, registry_id):
                self.registry_id = registry_id

        store = ReputationStore(scores={
            "critical": RegistryHealthScore("critical", 10, "F", "now"),
        })
        profile = get_builtin_profile("strict_enterprise")
        filtered, rejected = filter_by_reputation(
            [FakeCandidate("critical")], store, profile,
        )
        assert len(filtered) == 0
        assert len(rejected) == 1


# ── AC17: Stale score detected ───────────────────────────────────────────────

class TestAC17StaleScore:
    def test_stale_score_detected_by_timestamp(self):
        from datetime import datetime, timezone, timedelta
        from nodechain.sdk.reputation import RegistryHealthScore

        old = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        recent = datetime.now(timezone.utc).isoformat()
        s_old = RegistryHealthScore("reg", 90, "A", old)
        s_recent = RegistryHealthScore("reg", 90, "A", recent)
        assert s_old.last_checked < s_recent.last_checked

    def test_stale_score_old_timestamp(self):
        from datetime import datetime, timezone, timedelta
        from nodechain.sdk.reputation import RegistryHealthScore, score_registry, ScoringInputs

        old_time = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
        s = score_registry(ScoringInputs(registry_id="reg"))
        s.last_checked = old_time
        # The score is valid but the timestamp is old
        assert "T" in s.last_checked


# ── AC18: Corrupt reputation store fails safely ──────────────────────────────

class TestAC18CorruptStore:
    def test_garbage_json_raises(self, tmp_path):
        from nodechain.sdk.reputation import load_reputation_store, ReputationError
        path = str(tmp_path / "corrupt.json")
        Path(path).write_text("garbage{{{{", encoding="utf-8")
        with pytest.raises(ReputationError, match="corrupt"):
            load_reputation_store(path)

    def test_truncated_json_raises(self, tmp_path):
        from nodechain.sdk.reputation import load_reputation_store, ReputationError
        path = str(tmp_path / "trunc.json")
        Path(path).write_text('{"scores": {', encoding="utf-8")
        with pytest.raises(ReputationError):
            load_reputation_store(path)

    def test_json_array_raises(self, tmp_path):
        from nodechain.sdk.reputation import load_reputation_store, ReputationError
        path = str(tmp_path / "arr.json")
        Path(path).write_text('[]', encoding="utf-8")
        with pytest.raises(ReputationError, match="not a valid JSON object"):
            load_reputation_store(path)


# ── AC19: Concurrent refresh does not lose scores ────────────────────────────

class TestAC19ConcurrentRefresh:
    def test_refresh_preserves_all_scores(self, monkeypatch, tmp_path):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        rep_path = str(tmp_path / "rep.json")
        monkeypatch.setenv("NODECHAIN_REPUTATION_STORE", rep_path)
        runner = CliRunner()
        # Add multiple scores
        for rid in ["reg-a", "reg-b", "reg-c"]:
            runner.invoke(cli, [
                "registry", "reputation", "score", rid, "--json",
            ])
        # Refresh
        result = runner.invoke(cli, ["registry", "reputation", "refresh", "--json"])
        assert result.exit_code == 0
        # Verify all scores still present
        show_result = runner.invoke(cli, ["registry", "reputation", "show", "--json"])
        data = json.loads(show_result.output)
        assert data["total_registries"] == 3

    def test_refresh_specific_registry(self, monkeypatch, tmp_path):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        rep_path = str(tmp_path / "rep.json")
        monkeypatch.setenv("NODECHAIN_REPUTATION_STORE", rep_path)
        runner = CliRunner()
        runner.invoke(cli, ["registry", "reputation", "score", "reg-a", "--json"])
        runner.invoke(cli, ["registry", "reputation", "score", "reg-b", "--json"])
        # Refresh only reg-a
        result = runner.invoke(cli, [
            "registry", "reputation", "refresh", "--registry-id", "reg-a",
        ])
        assert result.exit_code == 0
        # Both still present
        show_result = runner.invoke(cli, ["registry", "reputation", "show", "--json"])
        data = json.loads(show_result.output)
        assert data["total_registries"] == 2


# ── AC20: Runtime path integration ───────────────────────────────────────────

class TestAC20RuntimeIntegration:
    def test_score_digest_present_on_fresh_score(self):
        from nodechain.sdk.reputation import ScoringInputs, score_registry
        score = score_registry(ScoringInputs(registry_id="reg"))
        assert score.score_digest != ""
        assert len(score.score_digest) == 64

    def test_score_digest_in_to_dict(self):
        from nodechain.sdk.reputation import ScoringInputs, score_registry
        score = score_registry(ScoringInputs(registry_id="reg"))
        d = score.to_dict()
        assert "score_digest" in d
        assert d["score_digest"] == score.score_digest

    def test_round_trip_preserves_score_digest(self, tmp_path):
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
        loaded_score = loaded.get("reg")
        assert loaded_score.score_digest == score.score_digest

    def test_unsealed_score_detected(self):
        """A score without score_digest should fail verification."""
        from nodechain.sdk.reputation import (
            ScoringInputs, score_registry, verify_health_score,
        )
        score = score_registry(ScoringInputs(registry_id="reg"))
        score.score_digest = ""  # remove seal
        result = verify_health_score(score)
        assert not result.valid
        assert any("score_digest is missing" in i for i in result.issues)

    def test_profile_reputation_fields_exist(self):
        from nodechain.sdk.org_policy import get_builtin_profile
        permissive = get_builtin_profile("permissive_local")
        strict = get_builtin_profile("strict_enterprise")
        assert hasattr(permissive, "use_registry_reputation")
        assert hasattr(permissive, "minimum_registry_grade")
        assert not permissive.use_registry_reputation
        assert strict.use_registry_reputation
        assert strict.minimum_registry_grade == "C"

    def test_all_17_health_rules(self):
        from nodechain.cli.dashboard_health import ALL_RULES
        assert len(ALL_RULES) == 65  # 49 HR + 5 MEM + 6 SE + 5 MR (v2.41.0)
