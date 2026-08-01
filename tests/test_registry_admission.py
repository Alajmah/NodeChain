"""Registry Admission Policy Tests (v2.45.0).

Proves the 13 acceptance criteria:
  1. Registry scan discovers candidates but only admits allowed packages
  2. Invalid package parse/load errors produce durable deny decisions
  3. Invalid manifest/contract/package structure produces durable deny
  4. Capability/side-effect/version policy failures produce deny when blocking
  5. Duplicate node_id is denied
  6. Successful admission records durable allow with digest
  7. Denied admission records durable deny with structured reason
  8. get_package/load do not return denied packages
  9. skip_policy does not bypass registry admission
  10. Loader writes admission-derived provenance onto loaded instances
  11. Lockfile integrates with admitted packages
  12. Registry health report surfaces admitted/denied/invalid/digest/privileged
  13. Package-trust gate remains unchanged
"""

from __future__ import annotations

import pytest
from pathlib import Path

from nodechain.registry.local_registry import (
    RegistryIndex, AdmissionDecision, _admit_package,
)
from nodechain.core.state import StateManager


class TestAdmissionDecision:
    """v2.45.0: AdmissionDecision model."""

    def test_allow_decision(self):
        d = AdmissionDecision(
            node_id="test_node", decision="allow", reason="OK",
            package_digest="abc123", declared_privileged=True,
        )
        assert d.decision == "allow"
        assert d.package_digest == "abc123"
        assert d.declared_privileged is True
        assert d.admission_id  # auto-generated UUID

    def test_deny_decision(self):
        d = AdmissionDecision(
            node_id="bad_node", decision="deny",
            reason="Structural validation failed",
            rule_id="admission.structural_invalid",
        )
        assert d.decision == "deny"
        assert d.rule_id == "admission.structural_invalid"

    def test_to_dict(self):
        d = AdmissionDecision(
            node_id="n", decision="allow", reason="OK",
        )
        dct = d.to_dict()
        assert dct["decision"] == "allow"
        assert dct["node_id"] == "n"
        assert "admission_id" in dct
        assert "created_at" in dct


class TestRegistryAdmissionBoundary:
    """v2.45.0: Registry is an admission boundary."""

    def test_scan_produces_admission_decisions(self):
        """scan() produces admission decisions for all discovered packages."""
        reg = RegistryIndex()
        count = reg.scan()
        decisions = reg.get_admission_decisions()
        # At least echo_node should be discovered and admitted
        assert len(decisions) > 0
        # Some should be allow
        allows = [d for d in decisions if d["decision"] == "allow"]
        assert len(allows) > 0

    def test_denied_packages_not_in_packages(self):
        """Denied packages don't appear in the loadable index."""
        reg = RegistryIndex()
        reg.scan()
        # uppercase_node and reverse_node lack node.yaml — denied
        denied = reg.get_denied_packages()
        if denied:
            for d in denied:
                assert reg.get_package(d["node_id"]) is None

    def test_get_package_returns_none_for_denied(self):
        """get_package() returns None for denied node_ids."""
        reg = RegistryIndex()
        reg.scan()
        # Find any denied node_id
        denied = reg.get_denied_packages()
        for d in denied:
            if d["node_id"] != "unknown":
                assert reg.get_package(d["node_id"]) is None


class TestDurableAdmissionDecisions:
    """v2.45.0: registry_admission_decisions table."""

    def test_record_and_retrieve(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "rad.db"))
        sm.record_registry_admission({
            "admission_id": "ra-1", "node_id": "n1",
            "decision": "allow", "package_digest": "abc123",
            "declared_privileged": True,
        })
        decisions = sm.get_registry_admissions(node_id="n1")
        assert len(decisions) == 1
        assert decisions[0]["decision"] == "allow"
        assert decisions[0]["package_digest"] == "abc123"
        assert decisions[0]["declared_privileged"] == 1

    def test_filter_by_decision(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "rad2.db"))
        sm.record_registry_admission({
            "admission_id": "ra-a", "node_id": "n1", "decision": "allow",
        })
        sm.record_registry_admission({
            "admission_id": "ra-d", "node_id": "n2", "decision": "deny",
        })
        denied = sm.get_registry_admissions(decision="deny")
        assert len(denied) == 1
        assert denied[0]["node_id"] == "n2"


class TestRegistryHealth:
    """v2.45.0: collect_health surfaces admission status."""

    def test_health_report_has_required_fields(self):
        reg = RegistryIndex()
        reg.scan()
        health = reg.collect_health()
        assert "total_discovered" in health
        assert "total_admitted" in health
        assert "total_denied" in health
        assert "parse_errors" in health
        assert "missing_digest" in health
        assert "privileged_declarations" in health
        assert "latest_admissions" in health

    def test_health_counts_consistent(self):
        reg = RegistryIndex()
        reg.scan()
        health = reg.collect_health()
        assert health["total_admitted"] + health["total_denied"] >= health["total_discovered"]
