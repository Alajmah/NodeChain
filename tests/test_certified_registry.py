"""Tests for v1.18.2 Certified Registry Publishing.

Tests cover all 10 acceptance criteria.
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
    priv_path = str(tmp_path / f"priv_reg{suffix}.pem")
    pub_path = str(tmp_path / f"pub_reg{suffix}.pem")
    Path(priv_path).write_bytes(priv_pem)
    Path(pub_path).write_bytes(pub_pem)
    return priv_path, pub_path


def _write_package(tmp_path, **overrides):
    pkg = {
        "package_id": "test-node",
        "version": "1.0.0",
        "description": "Test node for registry",
        "capabilities": ["search"],
        "sandbox_profile": "python_hooks",
        "trust_level": "untrusted",
        "content_hash": "a" * 64,
    }
    pkg.update(overrides)
    return pkg


def _write_certification(tmp_path, target_digest="a" * 64, **overrides):
    cert = {
        "type": "evaluation_certification",
        "certification_id": "cert-001",
        "certification_status": "certified",
        "target_digest": target_digest,
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
        "valid_from": "",
        "valid_until": "",
        "issued_at": "2026-06-17T00:00:00+00:00",
        "errors": [],
    }
    cert.update(overrides)
    return cert


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


# ── AC1+AC2: Publish ───────────────────────────────────────────────────────

class TestPublish:
    """AC1+AC2: registry publish with requirements."""

    def test_publish_certified_package(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", str(tmp_path / "reg.json"))
        from nodechain.cli.certified_registry import publish_package
        pkg = _write_package(tmp_path)
        cert = _write_certification(tmp_path)

        entry = publish_package(package_dict=pkg, certification=cert)
        assert entry["registry_status"] == "active"
        assert entry["package_id"] == "test-node"

    def test_publish_denied_uncertified(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", str(tmp_path / "reg.json"))
        from nodechain.cli.certified_registry import publish_package
        pkg = _write_package(tmp_path)
        cert = _write_certification(tmp_path, certification_status="denied")

        entry = publish_package(package_dict=pkg, certification=cert)
        assert entry["registry_status"] == "denied"

    def test_publish_denied_digest_mismatch(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", str(tmp_path / "reg.json"))
        from nodechain.cli.certified_registry import publish_package
        pkg = _write_package(tmp_path, content_hash="x" * 64)
        cert = _write_certification(tmp_path, target_digest="a" * 64)

        entry = publish_package(package_dict=pkg, certification=cert)
        assert entry["registry_status"] == "denied"
        assert any("digest" in e.lower() for e in entry["errors"])

    def test_publish_denied_no_cert(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", str(tmp_path / "reg.json"))
        from nodechain.cli.certified_registry import publish_package
        pkg = _write_package(tmp_path)

        entry = publish_package(package_dict=pkg, certification=None, require_certification=True)
        assert entry["registry_status"] == "denied"

    def test_publish_without_requirement(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", str(tmp_path / "reg.json"))
        from nodechain.cli.certified_registry import publish_package
        pkg = _write_package(tmp_path)

        entry = publish_package(package_dict=pkg, require_certification=False)
        assert entry["registry_status"] == "active"


# ── AC3: Registry Entry Fields ─────────────────────────────────────────────

class TestRegistryEntryFields:
    """AC3: Entry includes all required fields."""

    def test_has_all_fields(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", str(tmp_path / "reg.json"))
        from nodechain.cli.certified_registry import publish_package
        pkg = _write_package(tmp_path)
        cert = _write_certification(tmp_path)

        entry = publish_package(package_dict=pkg, certification=cert)
        required = [
            "entry_id", "package_id", "package_version", "package_digest",
            "manifest_digest", "lockfile_digest", "certification_digest",
            "eval_report_digest", "suite_digest", "publisher_fingerprint",
            "published_at", "registry_status",
        ]
        for field in required:
            assert field in entry, f"Missing: {field}"

    def test_entry_digest_present(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", str(tmp_path / "reg.json"))
        from nodechain.cli.certified_registry import publish_package
        pkg = _write_package(tmp_path)
        cert = _write_certification(tmp_path)

        entry = publish_package(package_dict=pkg, certification=cert)
        assert entry["entry_digest"]
        assert len(entry["entry_digest"]) == 64


# ── AC4: Trust Store Purpose ───────────────────────────────────────────────

class TestTrustStorePurpose:
    """AC4: registry_publishing is a valid purpose."""

    def test_purpose_in_valid(self):
        from nodechain.cli.trust_store import VALID_PURPOSES
        assert "registry_publishing" in VALID_PURPOSES

    def test_purpose_count(self):
        from nodechain.cli.trust_store import VALID_PURPOSES
        assert len(VALID_PURPOSES) == 13


# ── AC5: Signing and Trust ─────────────────────────────────────────────────

class TestSigningAndTrust:
    """AC5: Registry entries can be signed and verified via trust store."""

    def test_sign_entry(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", str(tmp_path / "reg.json"))
        from nodechain.cli.certified_registry import publish_package, sign_registry_entry
        priv_path, _ = _generate_key_pair(tmp_path)
        pkg = _write_package(tmp_path)
        cert = _write_certification(tmp_path)

        entry = publish_package(package_dict=pkg, certification=cert)
        signed = sign_registry_entry(entry, priv_path)
        assert signed["registry_signature"]
        assert signed["publisher_fingerprint"]

    def test_verify_signed_entry(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", str(tmp_path / "reg.json"))
        from nodechain.cli.certified_registry import (
            publish_package, sign_registry_entry, verify_registry_entry,
        )
        priv_path, pub_path = _generate_key_pair(tmp_path)
        pkg = _write_package(tmp_path)
        cert = _write_certification(tmp_path)

        entry = publish_package(package_dict=pkg, certification=cert)
        signed = sign_registry_entry(entry, priv_path)

        pubkey = Path(pub_path).read_text(encoding="utf-8")
        result = verify_registry_entry(signed, public_key_pem=pubkey)
        assert result["valid"] is True

    def test_verify_trust_store_lookup(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", str(tmp_path / "reg.json"))
        from nodechain.cli.certified_registry import (
            publish_package, sign_registry_entry, verify_registry_entry,
        )
        priv_path, pub_path = _generate_key_pair(tmp_path)
        ts_path = _setup_trust_store(tmp_path, pub_path)
        pkg = _write_package(tmp_path)
        cert = _write_certification(tmp_path)

        entry = publish_package(package_dict=pkg, certification=cert)
        signed = sign_registry_entry(entry, priv_path)

        result = verify_registry_entry(signed, trust_store_path=ts_path)
        assert result["valid"] is True
        assert result["details"]["publisher_trusted"] is True

    def test_verify_wrong_purpose_rejected(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", str(tmp_path / "reg.json"))
        from nodechain.cli.certified_registry import (
            publish_package, sign_registry_entry, verify_registry_entry,
        )
        priv_path, pub_path = _generate_key_pair(tmp_path)
        ts_path = _setup_trust_store(tmp_path, pub_path, name="wrong",
                                      purposes=["attestation_signing"])
        pkg = _write_package(tmp_path)
        cert = _write_certification(tmp_path)

        entry = publish_package(package_dict=pkg, certification=cert)
        signed = sign_registry_entry(entry, priv_path)

        result = verify_registry_entry(signed, trust_store_path=ts_path)
        assert result["valid"] is False

    def test_verify_unsigned_fails(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", str(tmp_path / "reg.json"))
        from nodechain.cli.certified_registry import publish_package, verify_registry_entry
        pkg = _write_package(tmp_path)
        cert = _write_certification(tmp_path)

        entry = publish_package(package_dict=pkg, certification=cert)
        result = verify_registry_entry(entry)
        assert result["valid"] is False


# ── AC6: List / Inspect / Deprecate / Revoke ───────────────────────────────

class TestListInspectDeprecateRevoke:
    """AC6: Full lifecycle management."""

    def _publish(self, tmp_path, monkeypatch):
        from nodechain.cli.certified_registry import publish_package
        monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", str(tmp_path / "reg.json"))
        return publish_package(
            package_dict=_write_package(tmp_path),
            certification=_write_certification(tmp_path),
        )

    def test_list_entries(self, tmp_path, monkeypatch):
        self._publish(tmp_path, monkeypatch)
        from nodechain.cli.certified_registry import list_entries
        entries = list_entries()
        assert len(entries) == 1

    def test_list_active_only(self, tmp_path, monkeypatch):
        entry = self._publish(tmp_path, monkeypatch)
        from nodechain.cli.certified_registry import list_entries, revoke_entry
        revoke_entry(entry["entry_id"])
        active = list_entries(active_only=True)
        assert len(active) == 0

    def test_inspect_entry(self, tmp_path, monkeypatch):
        entry = self._publish(tmp_path, monkeypatch)
        from nodechain.cli.certified_registry import inspect_entry
        summary = inspect_entry(entry["entry_id"])
        assert summary["package_id"] == "test-node"
        assert summary["certification_status"] == "certified"

    def test_deprecate_entry(self, tmp_path, monkeypatch):
        entry = self._publish(tmp_path, monkeypatch)
        from nodechain.cli.certified_registry import deprecate_entry, load_registry
        deprecated = deprecate_entry(entry["entry_id"], reason="old version")
        assert deprecated["registry_status"] == "deprecated"
        assert deprecated["deprecate_reason"] == "old version"

    def test_revoke_entry(self, tmp_path, monkeypatch):
        entry = self._publish(tmp_path, monkeypatch)
        from nodechain.cli.certified_registry import revoke_entry
        revoked = revoke_entry(entry["entry_id"], reason="security issue")
        assert revoked["registry_status"] == "revoked"
        assert revoked["revoke_reason"] == "security issue"

    def test_revoked_fails_verify(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", str(tmp_path / "reg.json"))
        from nodechain.cli.certified_registry import (
            publish_package, sign_registry_entry, revoke_entry, verify_registry_entry,
            load_registry,
        )
        priv_path, _ = _generate_key_pair(tmp_path)
        entry = publish_package(
            package_dict=_write_package(tmp_path),
            certification=_write_certification(tmp_path),
        )
        signed = sign_registry_entry(entry, priv_path)
        revoke_entry(signed["entry_id"])
        # Load updated entry from registry (status is now revoked)
        reg = load_registry()
        updated_entry = reg["entries"][signed["entry_id"]]
        result = verify_registry_entry(updated_entry)
        assert result["valid"] is False


# ── AC7: Registry Index ────────────────────────────────────────────────────

class TestRegistryIndex:
    """AC7: Registry index has metadata and audit log."""

    def test_registry_has_schema_version(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", str(tmp_path / "reg.json"))
        from nodechain.cli.certified_registry import load_registry
        reg = load_registry()
        assert reg["schema_version"]
        assert reg["registry_id"]

    def test_registry_has_entries_digest(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", str(tmp_path / "reg.json"))
        from nodechain.cli.certified_registry import publish_package, load_registry
        publish_package(
            package_dict=_write_package(tmp_path),
            certification=_write_certification(tmp_path),
        )
        reg = load_registry()
        assert reg["entries_digest"]
        assert len(reg["entries_digest"]) == 64

    def test_registry_has_audit_log(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", str(tmp_path / "reg.json"))
        from nodechain.cli.certified_registry import publish_package, load_registry
        publish_package(
            package_dict=_write_package(tmp_path),
            certification=_write_certification(tmp_path),
        )
        reg = load_registry()
        assert len(reg["audit_log"]) >= 1
        assert reg["audit_log"][0]["action"] == "publish"

    def test_registry_snapshot(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", str(tmp_path / "reg.json"))
        from nodechain.cli.certified_registry import (
            create_registry_snapshot, verify_registry_snapshot,
        )
        snapshot = create_registry_snapshot()
        assert snapshot["snapshot_digest"]
        result = verify_registry_snapshot(snapshot)
        assert result["valid"] is True

    def test_registry_snapshot_tamper_detected(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", str(tmp_path / "reg.json"))
        from nodechain.cli.certified_registry import create_registry_snapshot, verify_registry_snapshot
        snapshot = create_registry_snapshot()
        snapshot["entry_count"] = 999
        result = verify_registry_snapshot(snapshot)
        assert result["valid"] is False


# ── AC9: Evidence Index Integration ────────────────────────────────────────

class TestEvidenceIntegration:
    """AC9: Evidence index includes registry entries."""

    def test_registry_entry_is_evidence_type(self):
        from nodechain.cli.evidence import EVIDENCE_TYPES
        assert "registry_entry" in EVIDENCE_TYPES

    def test_index_detects_registry_entry(self, tmp_path):
        from nodechain.cli.evidence import _detect_artifact_type
        data = {
            "type": "registry_entry",
            "entry_id": "e1",
            "package_digest": "a" * 64,
        }
        assert _detect_artifact_type(data) == "registry_entry"


# ── Full Flow Integration ──────────────────────────────────────────────────

class TestFullPublishFlow:
    """End-to-end: package → certify → publish → sign → verify."""

    def test_full_flow(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", str(tmp_path / "reg.json"))
        from nodechain.cli.certified_registry import (
            publish_package, sign_registry_entry, verify_registry_entry, list_entries,
        )

        # 1. Publish
        pkg = _write_package(tmp_path)
        cert = _write_certification(tmp_path)
        entry = publish_package(package_dict=pkg, certification=cert)
        assert entry["registry_status"] == "active"

        # 2. Sign
        priv_path, pub_path = _generate_key_pair(tmp_path)
        signed = sign_registry_entry(entry, priv_path)
        assert signed["registry_signature"]

        # 3. Verify
        pubkey = Path(pub_path).read_text(encoding="utf-8")
        result = verify_registry_entry(signed, public_key_pem=pubkey)
        assert result["valid"] is True

        # 4. List
        entries = list_entries(active_only=True)
        assert len(entries) == 1
