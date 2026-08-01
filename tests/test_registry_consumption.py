"""Tests for v1.18.2 Certified Registry Consumption.

Tests cover all 8 acceptance criteria.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def _generate_key_pair(tmp_path, suffix=""):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_path = str(tmp_path / f"priv_consume{suffix}.pem")
    pub_path = str(tmp_path / f"pub_consume{suffix}.pem")
    Path(priv_path).write_bytes(priv_pem)
    Path(pub_path).write_bytes(pub_pem)
    return priv_path, pub_path


def _publish_package(tmp_path, monkeypatch, **pkg_overrides):
    from nodechain.cli.certified_registry import publish_package
    monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", str(tmp_path / "reg.json"))

    pkg = {
        "package_id": "test-node",
        "version": "1.0.0",
        "description": "Test node",
        "capabilities": ["search"],
        "sandbox_profile": "python_hooks",
        "trust_level": "untrusted",
        "content_hash": "a" * 64,
    }
    pkg.update(pkg_overrides)

    cert = {
        "type": "evaluation_certification",
        "certification_id": "cert-001",
        "certification_status": "certified",
        "target_digest": "a" * 64,
        "target_type": "node",
        "target_ref": "test-node",
        "suite_id": "test-suite",
        "suite_version": "1.0.0",
        "suite_digest": "b" * 64,
        "eval_report_digest": "c" * 64,
        "certification_digest": "d" * 64,
        "certifier_fingerprint": "",
        "certification_signature": "",
        "certification_signature_algorithm": "",
        "issued_at": "2026-06-17T00:00:00+00:00",
        "errors": [],
    }

    entry = publish_package(package_dict=pkg, certification=cert)
    return entry


def _setup_trust_store(tmp_path, pub_path, name="publisher", purposes=None):
    import os
    if purposes is None:
        purposes = ["registry_publishing"]
    ts_path = str(tmp_path / "ts.json")
    os.environ["NODECHAIN_TRUST_STORE"] = ts_path
    from nodechain.cli.trust_store import add_key
    add_key(public_key_path=pub_path, name=name, purposes=purposes)
    del os.environ["NODECHAIN_TRUST_STORE"]
    return ts_path


# ── AC1+AC2: Install and Resolve Commands ──────────────────────────────────

class TestInstallAndResolve:
    """AC1: install and resolve commands."""

    def test_resolve_existing_package(self, tmp_path, monkeypatch):
        _publish_package(tmp_path, monkeypatch)
        from nodechain.cli.registry_consumption import resolve_package
        result = resolve_package(package_id="test-node")
        assert result.resolved is True
        assert result.policy_verdict == "allowed"

    def test_resolve_nonexistent_package(self, tmp_path, monkeypatch):
        _publish_package(tmp_path, monkeypatch)
        from nodechain.cli.registry_consumption import resolve_package
        result = resolve_package(package_id="nonexistent")
        assert result.resolved is False
        assert result.policy_verdict == "denied"

    def test_resolve_with_version(self, tmp_path, monkeypatch):
        _publish_package(tmp_path, monkeypatch)
        from nodechain.cli.registry_consumption import resolve_package
        result = resolve_package(package_id="test-node", version="1.0.0")
        assert result.resolved is True

    def test_resolve_wrong_version(self, tmp_path, monkeypatch):
        _publish_package(tmp_path, monkeypatch)
        from nodechain.cli.registry_consumption import resolve_package
        result = resolve_package(package_id="test-node", version="99.0.0")
        assert result.resolved is False

    def test_install_package(self, tmp_path, monkeypatch):
        _publish_package(tmp_path, monkeypatch)
        from nodechain.cli.registry_consumption import install_package
        result = install_package(package_id="test-node")
        assert result["resolved"] is True
        assert result["registry_resolution_status"] == "resolved"

    def test_install_nonexistent(self, tmp_path, monkeypatch):
        _publish_package(tmp_path, monkeypatch)
        from nodechain.cli.registry_consumption import install_package
        result = install_package(package_id="nonexistent")
        assert result["resolved"] is False
        assert result["registry_resolution_status"] == "unresolved"


# ── AC3: Runtime Verification Checks ───────────────────────────────────────

class TestRuntimeChecks:
    """AC3: Runtime loading verifies registry entry, cert, digest."""

    def test_check_registry_status_active(self, tmp_path, monkeypatch):
        _publish_package(tmp_path, monkeypatch)
        from nodechain.cli.registry_consumption import resolve_package
        result = resolve_package(package_id="test-node")
        status_check = [c for c in result.checks if c["check"] == "registry_status"][0]
        assert status_check["passed"] is True

    def test_check_registry_status_revoked(self, tmp_path, monkeypatch):
        entry = _publish_package(tmp_path, monkeypatch)
        from nodechain.cli.certified_registry import revoke_entry
        from nodechain.cli.registry_consumption import resolve_package
        revoke_entry(entry["entry_id"])
        result = resolve_package(package_id="test-node")
        assert result.resolved is False

    def test_check_registry_status_deprecated_active_only(self, tmp_path, monkeypatch):
        entry = _publish_package(tmp_path, monkeypatch)
        from nodechain.cli.certified_registry import deprecate_entry
        from nodechain.cli.registry_consumption import resolve_package, ConsumptionPolicy
        deprecate_entry(entry["entry_id"])
        # Without require_active_only, deprecated is OK
        result = resolve_package(package_id="test-node")
        assert result.resolved is True
        # With require_active_only, deprecated is rejected
        result = resolve_package(
            package_id="test-node",
            policy=ConsumptionPolicy(require_active_only=True),
        )
        assert result.resolved is False

    def test_certified_only_rejects_uncertified(self, tmp_path, monkeypatch):
        from nodechain.cli.certified_registry import publish_package
        from nodechain.cli.registry_consumption import resolve_package, ConsumptionPolicy
        monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", str(tmp_path / "reg2.json"))
        # Publish without certification
        publish_package(
            package_dict={"package_id": "uncertified", "version": "1.0.0",
                          "content_hash": "z" * 64},
            require_certification=False,
        )
        result = resolve_package(
            package_id="uncertified",
            policy=ConsumptionPolicy(certified_only=True),
        )
        assert result.resolved is False

    def test_certification_status_check(self, tmp_path, monkeypatch):
        _publish_package(tmp_path, monkeypatch)
        from nodechain.cli.registry_consumption import resolve_package, ConsumptionPolicy
        result = resolve_package(
            package_id="test-node",
            policy=ConsumptionPolicy(certified_only=True),
        )
        cert_check = [c for c in result.checks if c["check"] == "certification_status"][0]
        assert cert_check["passed"] is True

    def test_has_7_checks(self, tmp_path, monkeypatch):
        _publish_package(tmp_path, monkeypatch)
        from nodechain.cli.registry_consumption import resolve_package
        result = resolve_package(package_id="test-node")
        assert len(result.checks) == 7


# ── AC4: Consumption Policy ────────────────────────────────────────────────

class TestConsumptionPolicy:
    """AC4: Policy can require various constraints."""

    def test_policy_defaults(self):
        from nodechain.cli.registry_consumption import ConsumptionPolicy
        p = ConsumptionPolicy()
        assert p.certified_only is False
        assert p.trusted_publisher_only is False
        assert p.require_active_only is False

    def test_policy_roundtrip(self):
        from nodechain.cli.registry_consumption import ConsumptionPolicy
        p = ConsumptionPolicy(
            certified_only=True, trusted_publisher_only=True,
            allowed_capabilities=["search", "transform"],
        )
        d = p.to_dict()
        p2 = ConsumptionPolicy.from_dict(d)
        assert p2.certified_only is True
        assert p2.allowed_capabilities == ["search", "transform"]

    def test_capability_violation(self, tmp_path, monkeypatch):
        _publish_package(tmp_path, monkeypatch, capabilities=["search", "network"])
        from nodechain.cli.registry_consumption import resolve_package, ConsumptionPolicy
        result = resolve_package(
            package_id="test-node",
            policy=ConsumptionPolicy(allowed_capabilities=["search"]),  # missing "network"
        )
        assert result.resolved is False
        caps_check = [c for c in result.checks if c["check"] == "capabilities"][0]
        assert caps_check["passed"] is False

    def test_capability_allowed(self, tmp_path, monkeypatch):
        _publish_package(tmp_path, monkeypatch, capabilities=["search"])
        from nodechain.cli.registry_consumption import resolve_package, ConsumptionPolicy
        result = resolve_package(
            package_id="test-node",
            policy=ConsumptionPolicy(allowed_capabilities=["search", "network"]),
        )
        assert result.resolved is True

    def test_sandbox_profile_mismatch(self, tmp_path, monkeypatch):
        _publish_package(tmp_path, monkeypatch, sandbox_profile="python_hooks")
        from nodechain.cli.registry_consumption import resolve_package, ConsumptionPolicy
        result = resolve_package(
            package_id="test-node",
            policy=ConsumptionPolicy(allowed_sandbox_profile="subprocess_isolated"),
        )
        assert result.resolved is False

    def test_trusted_publisher_check(self, tmp_path, monkeypatch):
        entry = _publish_package(tmp_path, monkeypatch)
        priv_path, pub_path = _generate_key_pair(tmp_path)
        from nodechain.cli.certified_registry import sign_registry_entry
        from nodechain.cli.registry_consumption import resolve_package, ConsumptionPolicy

        signed_entry = sign_registry_entry(entry, priv_path)
        # Need to update the registry entry with the signed version
        from nodechain.cli.certified_registry import load_registry, save_registry
        reg = load_registry()
        reg["entries"][signed_entry["entry_id"]] = signed_entry
        save_registry(reg)

        ts_path = _setup_trust_store(tmp_path, pub_path)
        result = resolve_package(
            package_id="test-node",
            policy=ConsumptionPolicy(trusted_publisher_only=True),
            trust_store_path=ts_path,
        )
        assert result.resolved is True
        trust_check = [c for c in result.checks if c["check"] == "publisher_trust"][0]
        assert trust_check["passed"] is True


# ── AC5: Strict Mode Refusals ──────────────────────────────────────────────

class TestStrictRefusals:
    """AC5: Strict mode refuses various bad conditions."""

    def test_revoked_refused(self, tmp_path, monkeypatch):
        entry = _publish_package(tmp_path, monkeypatch)
        from nodechain.cli.certified_registry import revoke_entry
        from nodechain.cli.registry_consumption import install_package, ConsumptionPolicy
        revoke_entry(entry["entry_id"])
        result = install_package(
            package_id="test-node",
            policy=ConsumptionPolicy(certified_only=True, require_active_only=True),
        )
        assert result["resolved"] is False

    def test_uncertified_refused(self, tmp_path, monkeypatch):
        from nodechain.cli.certified_registry import publish_package
        from nodechain.cli.registry_consumption import install_package, ConsumptionPolicy
        monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", str(tmp_path / "reg3.json"))
        publish_package(
            package_dict={"package_id": "uncertified", "version": "1.0.0",
                          "content_hash": "y" * 64},
            require_certification=False,
        )
        result = install_package(
            package_id="uncertified",
            policy=ConsumptionPolicy(certified_only=True),
        )
        assert result["resolved"] is False

    def test_capability_violation_refused(self, tmp_path, monkeypatch):
        _publish_package(tmp_path, monkeypatch, capabilities=["search", "dangerous"])
        from nodechain.cli.registry_consumption import install_package, ConsumptionPolicy
        result = install_package(
            package_id="test-node",
            policy=ConsumptionPolicy(allowed_capabilities=["search"]),
        )
        assert result["resolved"] is False


# ── AC6: Trace Evidence Fields ──────────────────────────────────────────────

class TestTraceEvidence:
    """AC6: Install result records registry evidence fields."""

    def test_install_has_evidence_fields(self, tmp_path, monkeypatch):
        _publish_package(tmp_path, monkeypatch)
        from nodechain.cli.registry_consumption import install_package
        result = install_package(package_id="test-node")
        assert "registry_entry_digest" in result
        assert "certification_digest" in result
        assert "publisher_fingerprint" in result
        assert "registry_resolution_status" in result
        assert "policy_verdict" in result  # registry_policy_verdict

    def test_create_trace_fields(self, tmp_path, monkeypatch):
        _publish_package(tmp_path, monkeypatch)
        from nodechain.cli.registry_consumption import install_package, create_consumption_trace_fields
        result = install_package(package_id="test-node")
        fields = create_consumption_trace_fields(result)
        assert "registry_entry_digest" in fields
        assert "certification_digest" in fields
        assert "publisher_fingerprint" in fields
        assert "registry_resolution_status" in fields
        assert "registry_policy_verdict" in fields


# ── AC7: Evidence Chain ────────────────────────────────────────────────────

class TestEvidenceChain:
    """AC7: Evidence index links runtime → registry → cert → eval → suite."""

    def test_install_result_has_chain_digests(self, tmp_path, monkeypatch):
        _publish_package(tmp_path, monkeypatch)
        from nodechain.cli.registry_consumption import install_package
        result = install_package(package_id="test-node")
        assert result["suite_digest"] == "b" * 64
        assert result["eval_report_digest"] == "c" * 64
        assert result["certification_digest"] == "d" * 64

    def test_registry_entry_is_indexable(self, tmp_path, monkeypatch):
        entry = _publish_package(tmp_path, monkeypatch)
        from nodechain.cli.evidence import _detect_artifact_type
        entry["type"] = "registry_entry"
        assert _detect_artifact_type(entry) == "registry_entry"


# ── Full Flow ──────────────────────────────────────────────────────────────

class TestFullConsumptionFlow:
    """End-to-end: publish → sign → install with full policy."""

    def test_full_flow(self, tmp_path, monkeypatch):
        entry = _publish_package(tmp_path, monkeypatch)
        priv_path, pub_path = _generate_key_pair(tmp_path)
        from nodechain.cli.certified_registry import sign_registry_entry, load_registry, save_registry
        from nodechain.cli.registry_consumption import install_package, ConsumptionPolicy

        # Sign entry
        signed = sign_registry_entry(entry, priv_path)
        reg = load_registry()
        reg["entries"][signed["entry_id"]] = signed
        save_registry(reg)

        # Setup trust store
        ts_path = _setup_trust_store(tmp_path, pub_path)

        # Install with full policy
        result = install_package(
            package_id="test-node",
            policy=ConsumptionPolicy(
                certified_only=True,
                trusted_publisher_only=True,
                allowed_capabilities=["search"],
            ),
            trust_store_path=ts_path,
        )
        assert result["resolved"] is True
        assert result["policy_verdict"] == "allowed"
